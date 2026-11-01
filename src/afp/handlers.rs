//! AFP volume, file, directory, fork and desktop database commands.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::buf::{Reader, Writer};
use super::consts::*;
use super::params::{self, OpenState};
use super::session::{Reply, Session, SetKind};
use crate::charset;
use crate::util::ct_eq;
use crate::vfs::adouble::{Meta, DATE_START, FINDER_FLAG_INVISIBLE};
use crate::vfs::desktop::Desktop;
use crate::vfs::fork::{self, Fork, AFP2_MAX_FORK, BYTELOCK_MAX};
use crate::vfs::fs::Fs;
use crate::vfs::{lstat, Obj, Volume};

const SETTABLE_FILE_ATTR: u16 =
    ATTR_INVISIBLE | ATTR_MULTIUSER | ATTR_SYSTEM | ATTR_NOWRITE | ATTR_BACKUP | ATTR_NORENAME | ATTR_NODELETE;
const SETTABLE_DIR_ATTR: u16 = ATTR_INVISIBLE | ATTR_SYSTEM | ATTR_BACKUP | ATTR_NORENAME | ATTR_NODELETE;
const SETTABLE_FILE_BITS: u16 = FIL_BIT_ATTR | FIL_BIT_CDATE | FIL_BIT_MDATE | FIL_BIT_BDATE | FIL_BIT_FINFO | FIL_BIT_PDINFO;
const SETTABLE_DIR_BITS: u16 = DIR_BIT_ATTR
    | DIR_BIT_CDATE
    | DIR_BIT_MDATE
    | DIR_BIT_BDATE
    | DIR_BIT_FINFO
    | DIR_BIT_UID
    | DIR_BIT_GID
    | DIR_BIT_ACCESS
    | DIR_BIT_PDINFO;
const MAX_RFORK_COPY: u64 = 64 * 1024 * 1024;

fn read_path<'a>(r: &mut Reader<'a>) -> AfpResult<(u8, &'a [u8])> {
    let t = r.u8()?;
    let p = r.pstring()?;
    Ok((t, p))
}

fn unix_name_of(mac: &[u8]) -> AfpResult<Vec<u8>> {
    charset::mac_to_unix(mac).map_err(|_| AfpError::ParamErr)
}

fn initial_dates(fs: &Fs, obj: &Obj) -> [u32; 4] {
    let c = fs.birth_time(&obj.path).unwrap_or(obj.st.mtime).min(obj.st.mtime);
    [unix_to_afp_date(c), unix_to_afp_date(obj.st.mtime), DATE_START, 0]
}

fn afp_to_unix_mode(rights: u32, old: u32) -> u32 {
    let bits = |b: u32| -> u32 {
        let mut m = 0;
        if b & AR_UREAD != 0 {
            m |= 4;
        }
        if b & AR_UWRITE != 0 {
            m |= 2;
        }
        if b & AR_USEARCH != 0 {
            m |= 1;
        }
        m
    };
    let owner = bits(rights & 0xFF);
    let group = bits((rights >> 8) & 0xFF);
    let world = bits((rights >> 16) & 0xFF);
    (old & !0o777) | (owner << 6) | (group << 3) | world
}

/// Remove a directory's metadata leftovers so that rmdir can succeed.
/// Returns false if the directory holds anything else.
fn clear_leftovers(vol: &Volume, dir: &Path) -> io::Result<bool> {
    let mut leftovers = Vec::new();
    for e in vol.fs.read_dir(dir)? {
        let e = e?;
        let name = e.file_name();
        let nb = name.as_bytes();
        if vol.backend.removable_leftover(nb) || (vol.opts.delete_veto_files && vol.vetoed(nb)) {
            leftovers.push(dir.join(&name));
        } else {
            return Ok(false);
        }
    }
    for p in leftovers {
        if vol.fs.lstat(&p)?.is_dir() {
            vol.fs.remove_tree(&p)?;
        } else {
            vol.fs.unlink(&p)?;
        }
    }
    Ok(true)
}

impl Session {
    fn vol(&mut self, vid: u16) -> AfpResult<&mut Volume> {
        self.vols.get_mut(&vid).ok_or(AfpError::ParamErr)
    }

    fn open_state(&self, vid: u16, id: u32) -> OpenState {
        let mut s = OpenState { data_open: false, rsrc_open: false };
        for f in self.forks.values() {
            if f.vid == vid && f.id == id {
                if f.is_rsrc {
                    s.rsrc_open = true;
                } else {
                    s.data_open = true;
                }
            }
        }
        s
    }

    fn busy(&self, vid: u16, obj: &Obj) -> bool {
        let s = self.open_state(vid, obj.id);
        if s.data_open || s.rsrc_open {
            return true;
        }
        match self.vols.get(&vid) {
            Some(v) => fork::fork_open_anywhere(&v.fs, &obj.path, false) || fork::fork_open_anywhere(&v.fs, &obj.path, true),
            None => false,
        }
    }

    fn pack_obj(&self, vid: u16, obj: &Obj, fbm: u16, dbm: u16, w: &mut Writer) -> AfpResult<()> {
        let vol = self.vols.get(&vid).ok_or(AfpError::ParamErr)?;
        if obj.st.is_dir() {
            params::pack_dir(vol, self.ctx(), obj, dbm, w);
        } else {
            let os = self.open_state(vid, obj.id);
            params::pack_file(vol, obj, fbm, &os, w);
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // volumes
    // ---------------------------------------------------------------

    pub(super) fn fp_open_vol(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let bitmap = r.u16()?;
        let name = r.pstring()?;
        if bitmap & !VOL_BITS_VALID != 0 {
            return Err(AfpError::BitmapErr);
        }
        let idx = self
            .voldefs
            .iter()
            .position(|d| charset::mac_eq_ci(&d.name_mac, name))
            .ok_or(AfpError::ObjectNotFound)?;
        let vid = self.voldefs[idx].vid;
        if let Some(pw) = &self.voldefs[idx].opts.password {
            r.align2();
            let given = r.bytes(8).map_err(|_| AfpError::AccessDenied)?;
            let mut want = [0u8; 8];
            want[..pw.len()].copy_from_slice(pw);
            if !ct_eq(&want, given) {
                log::warn!("session {}: wrong password for volume", self.peer);
                return Err(AfpError::AccessDenied);
            }
        }
        if !self.vols.contains_key(&vid) {
            let d = &self.voldefs[idx];
            let c = std::ffi::CString::new(d.path.as_os_str().as_bytes()).map_err(|_| AfpError::ParamErr)?;
            // SAFETY: valid C string; access(2) checks with our (dropped) ids.
            if unsafe { libc::access(c.as_ptr(), libc::X_OK) } != 0 {
                let e = io::Error::last_os_error();
                log::info!("volume {}: {}", d.path.display(), e);
                return Err(AfpError::from_io(&e));
            }
            let v = Volume::open(vid, d.name_mac.clone(), d.path.clone(), d.opts.clone(), d.read_only, self.extmap.clone())?;
            self.vols.insert(vid, v);
        }
        let vol = self.vols.get(&vid).unwrap();
        let root_mtime = lstat(&vol.root).map(|s| s.mtime).unwrap_or(0);
        let mut w = Writer::new();
        w.u16(bitmap);
        params::pack_vol(vol, bitmap, root_mtime, &mut w);
        Ok(w.into_vec())
    }

    pub(super) fn fp_close_vol(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        if self.vols.remove(&vid).is_none() {
            return Err(AfpError::ParamErr);
        }
        self.forks.retain(|_, f| f.vid != vid);
        self.dt_open.remove(&vid);
        Ok(Vec::new())
    }

    pub(super) fn fp_get_vol_parms(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let bitmap = r.u16()?;
        if bitmap & !VOL_BITS_VALID != 0 {
            return Err(AfpError::BitmapErr);
        }
        let vol = self.vol(vid)?;
        let root_mtime = lstat(&vol.root).map(|s| s.mtime).unwrap_or(0);
        let mut w = Writer::new();
        w.u16(bitmap);
        params::pack_vol(vol, bitmap, root_mtime, &mut w);
        Ok(w.into_vec())
    }

    pub(super) fn fp_set_vol_parms(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let bitmap = r.u16()?;
        let _date = r.u32()?;
        self.vol(vid)?;
        if bitmap != VOL_BIT_BDATE {
            return Err(AfpError::BitmapErr);
        }
        Ok(Vec::new())
    }

    pub(super) fn fp_flush(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        self.vol(vid)?;
        for f in self.forks.values() {
            if f.vid == vid && f.dirty {
                let _ = f.flush();
            }
        }
        Ok(Vec::new())
    }

    // ---------------------------------------------------------------
    // directories and parameters
    // ---------------------------------------------------------------

    pub(super) fn fp_open_dir(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let res = self.vol(vid)?.resolve(did, pt, path)?;
        let obj = res.existing()?;
        if !obj.st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        let mut w = Writer::new();
        w.u32(obj.id);
        Ok(w.into_vec())
    }

    pub(super) fn fp_get_file_dir_parms(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let fbm = r.u16()?;
        let dbm = r.u16()?;
        let (pt, path) = read_path(&mut r)?;
        if fbm & !FIL_BITS_VALID != 0 || dbm & !DIR_BITS_VALID != 0 {
            return Err(AfpError::BitmapErr);
        }
        let res = self.vol(vid)?.resolve(did, pt, path)?;
        let obj = res.existing()?.clone();
        let mut w = Writer::new();
        w.u16(fbm).u16(dbm);
        if obj.st.is_dir() {
            w.u8(0x80).u8(0);
        } else {
            w.u8(0).u8(0);
        }
        self.pack_obj(vid, &obj, fbm, dbm, &mut w)?;
        Ok(w.into_vec())
    }

    pub(super) fn fp_set_parms(&mut self, req: &[u8], kind: SetKind) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let bitmap = r.u16()?;
        let (pt, path) = read_path(&mut r)?;
        r.align2();
        let ctx_uid = self.ctx().uid;
        let vol = self.vol(vid)?;
        let res = vol.resolve(did, pt, path)?;
        let obj = res.existing()?.clone();
        let is_dir = obj.st.is_dir();
        match kind {
            SetKind::File if is_dir => return Err(AfpError::ObjectTypeErr),
            SetKind::Dir if !is_dir => return Err(AfpError::ObjectTypeErr),
            _ => {}
        }
        let allowed = match kind {
            SetKind::Either => SETTABLE_FILE_BITS & SETTABLE_DIR_BITS,
            _ if is_dir => SETTABLE_DIR_BITS,
            _ => SETTABLE_FILE_BITS,
        };
        if bitmap & !allowed != 0 {
            return Err(AfpError::BitmapErr);
        }
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let mut m = vol.meta_or_default(&obj);
        if m.dates.is_none() {
            m.dates = Some(initial_dates(&vol.fs, &obj));
        }
        let mut meta_dirty = false;
        let mut new_mtime = None;
        let mut new_uid = None;
        let mut new_gid = None;
        let mut new_rights = None;
        for bit in 0..16 {
            let b = 1u16 << bit;
            if bitmap & b == 0 {
                continue;
            }
            match b {
                FIL_BIT_ATTR => {
                    let a = r.u16()?;
                    let settable = if is_dir { SETTABLE_DIR_ATTR } else { SETTABLE_FILE_ATTR };
                    let bits = a & settable;
                    let mut cur = m.attr();
                    if a & ATTR_SETCLR != 0 {
                        cur |= bits;
                    } else {
                        cur &= !bits;
                    }
                    m.set_attr(cur);
                    if bits & ATTR_INVISIBLE != 0 {
                        let f = m.finder_flags();
                        m.set_finder_flags(if cur & ATTR_INVISIBLE != 0 { f | FINDER_FLAG_INVISIBLE } else { f & !FINDER_FLAG_INVISIBLE });
                    }
                    meta_dirty = true;
                }
                FIL_BIT_CDATE => {
                    let d = r.u32()?;
                    if let Some(ds) = m.dates.as_mut() {
                        ds[0] = d;
                    }
                    meta_dirty = true;
                }
                FIL_BIT_MDATE => {
                    let d = r.u32()?;
                    if let Some(ds) = m.dates.as_mut() {
                        ds[1] = d;
                    }
                    new_mtime = Some(afp_to_unix_date(d));
                    meta_dirty = true;
                }
                FIL_BIT_BDATE => {
                    let d = r.u32()?;
                    if let Some(ds) = m.dates.as_mut() {
                        ds[2] = d;
                    }
                    meta_dirty = true;
                }
                FIL_BIT_FINFO => {
                    let fi = r.array::<32>()?;
                    m.finder_info = fi;
                    let inv = m.finder_flags() & FINDER_FLAG_INVISIBLE != 0;
                    let a = m.attr();
                    m.set_attr(if inv { a | ATTR_INVISIBLE } else { a & !ATTR_INVISIBLE });
                    meta_dirty = true;
                }
                // FIL_BIT_PDINFO and DIR_BIT_PDINFO share bit 13
                FIL_BIT_PDINFO => {
                    r.skip(6)?;
                }
                DIR_BIT_UID => new_uid = Some(r.u32()?),
                DIR_BIT_GID => new_gid = Some(r.u32()?),
                DIR_BIT_ACCESS => new_rights = Some(r.u32()?),
                _ => return Err(AfpError::BitmapErr),
            }
        }
        if meta_dirty {
            vol.write_meta(&obj, &m)?;
        }
        if let Some(t) = new_mtime {
            if let Err(e) = vol.fs.set_mtime(&obj.path, t) {
                log::debug!("set mtime {}: {}", obj.path.display(), e);
            }
        }
        if new_uid.map(|u| u != obj.st.uid).unwrap_or(false) || new_gid.map(|g| g != obj.st.gid).unwrap_or(false) {
            let u = new_uid.filter(|&u| u != obj.st.uid);
            let g = new_gid.filter(|&g| g != obj.st.gid);
            vol.fs.lchown(&obj.path, u, g).map_err(|e| AfpError::from_io(&e))?;
        }
        if let Some(rights) = new_rights {
            if obj.st.uid == ctx_uid {
                let mode = afp_to_unix_mode(rights, obj.st.mode);
                if mode & 0o777 != obj.st.mode & 0o777 {
                    vol.fs.chmod(&obj.path, mode).map_err(|e| AfpError::from_io(&e))?;
                }
            }
        }
        vol.note_change();
        Ok(Vec::new())
    }

    pub(super) fn fp_enumerate(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let fbm = r.u16()?;
        let dbm = r.u16()?;
        let reqcount = r.u16()? as usize;
        let start = r.u16()? as usize;
        let maxreply = r.u16()? as usize;
        let (pt, path) = read_path(&mut r)?;
        if fbm == 0 && dbm == 0 {
            return Err(AfpError::BitmapErr);
        }
        if fbm & !FIL_BITS_VALID != 0 || dbm & !DIR_BITS_VALID != 0 {
            return Err(AfpError::BitmapErr);
        }
        if start == 0 || reqcount == 0 {
            return Err(AfpError::ParamErr);
        }
        let maxreply = maxreply.min(self.dsi.server_quantum as usize);
        let vol = self.vols.get_mut(&vid).ok_or(AfpError::ParamErr)?;
        let res = vol.resolve(did, pt, path)?;
        let dir = res.existing()?.clone();
        if !dir.st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        let names = vol.list_dir(dir.id, &dir.path, &dir.st, start == 1)?;

        // Collect the candidate objects for this page.
        let mut objs: Vec<Obj> = Vec::new();
        if fbm != 0 && dbm != 0 {
            for n in names.iter().skip(start - 1) {
                if objs.len() >= reqcount {
                    break;
                }
                if let Some(o) = vol.child(dir.id, &dir.path, n) {
                    objs.push(o);
                }
            }
        } else {
            let want_dirs = dbm != 0;
            let mut idx = 0usize;
            for n in names.iter() {
                if objs.len() >= reqcount {
                    break;
                }
                let o = match vol.child(dir.id, &dir.path, n) {
                    Some(o) => o,
                    None => continue,
                };
                if o.st.is_dir() != want_dirs {
                    continue;
                }
                idx += 1;
                if idx >= start {
                    objs.push(o);
                }
            }
        }
        if objs.is_empty() {
            return Err(AfpError::ObjectNotFound);
        }

        let mut w = Writer::with_capacity(maxreply.min(64 * 1024));
        w.u16(fbm).u16(dbm).u16(0);
        let mut count = 0u16;
        for o in &objs {
            let mut e = Writer::with_capacity(128);
            self.pack_obj(vid, o, fbm, dbm, &mut e)?;
            let mut len = 2 + e.len();
            if len & 1 == 1 {
                len += 1;
            }
            if len > 255 {
                continue;
            }
            if w.len() + len > maxreply {
                break;
            }
            w.u8(len as u8);
            w.u8(if o.st.is_dir() { 0x80 } else { 0 });
            w.bytes(&e.buf);
            w.pad_even();
            count += 1;
        }
        if count == 0 {
            // Not even one entry fits in the client's buffer.
            return Err(AfpError::ParamErr);
        }
        w.put_u16_at(4, count);
        Ok(w.into_vec())
    }

    pub(super) fn fp_create_dir(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let vol = self.vol(vid)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let res = vol.resolve(did, pt, path)?;
        if res.obj.is_some() {
            return Err(AfpError::ObjectExists);
        }
        let name = res.name.clone().ok_or(AfpError::ParamErr)?;
        let p = res.dir_path.join(std::ffi::OsStr::from_bytes(&name));
        vol.apply_umask();
        vol.fs.mkdir(&p, 0o777).map_err(|e| AfpError::from_io(&e))?;
        if let Some(perm) = vol.opts.directory_perm {
            if let Ok(st) = vol.fs.lstat(&p) {
                let _ = vol.fs.chmod(&p, (st.mode | perm) & 0o7777);
            }
        }
        let st = vol.fs.lstat(&p)?;
        let id = vol.ids.id_for(res.dir_id, &name, &st);
        vol.note_change();
        let mut w = Writer::new();
        w.u32(id);
        Ok(w.into_vec())
    }

    pub(super) fn fp_create_file(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        let _ = r.u8()?;
        let flag = r.u8()?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let hard = flag & 0x80 != 0;
        let res = {
            let vol = self.vol(vid)?;
            if vol.read_only {
                return Err(AfpError::VolLocked);
            }
            vol.resolve(did, pt, path)?
        };
        if let Some(obj) = &res.obj {
            if obj.st.is_dir() || !hard {
                return Err(AfpError::ObjectExists);
            }
            if self.busy(vid, obj) {
                return Err(AfpError::FileBusy);
            }
            let vol = self.vol(vid)?;
            let f = vol.fs.open(&obj.path, libc::O_WRONLY | libc::O_NONBLOCK, 0)?;
            if !f.metadata()?.is_file() {
                return Err(AfpError::ObjectTypeErr);
            }
            f.set_len(0)?;
            vol.backend.deleted(&vol.fs, &obj.path, false);
            let _ = vol.backend.write(&vol.fs, &obj.path, false, &Meta { dates: Some(initial_dates(&vol.fs, obj)), ..Meta::default() });
            vol.note_change();
            return Ok(Vec::new());
        }
        let vol = self.vol(vid)?;
        let name = res.name.clone().ok_or(AfpError::ParamErr)?;
        let p = res.dir_path.join(std::ffi::OsStr::from_bytes(&name));
        vol.apply_umask();
        vol.fs.create(&p, 0o666, false).map_err(|e| AfpError::from_io(&e))?;
        if let Some(perm) = vol.opts.file_perm {
            if let Ok(st) = vol.fs.lstat(&p) {
                let _ = vol.fs.chmod(&p, (st.mode | perm) & 0o7777);
            }
        }
        // Remove a stale sidecar left by some other tool.
        vol.backend.deleted(&vol.fs, &p, false);
        if let Ok(st) = vol.fs.lstat(&p) {
            vol.ids.id_for(res.dir_id, &name, &st);
        }
        vol.note_change();
        Ok(Vec::new())
    }

    pub(super) fn fp_delete(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let obj = {
            let vol = self.vol(vid)?;
            if vol.read_only {
                return Err(AfpError::VolLocked);
            }
            vol.resolve(did, pt, path)?.existing()?.clone()
        };
        if obj.id == DIRID_ROOT {
            return Err(AfpError::AccessDenied);
        }
        if !obj.st.is_dir() && self.busy(vid, &obj) {
            return Err(AfpError::FileBusy);
        }
        let vol = self.vol(vid)?;
        if let Some(m) = vol.read_meta(&obj) {
            if m.attr() & ATTR_NODELETE != 0 {
                return Err(AfpError::ObjectLocked);
            }
        }
        if obj.st.is_dir() {
            match clear_leftovers(vol, &obj.path) {
                Ok(true) => {}
                Ok(false) => return Err(AfpError::DirNotEmpty),
                Err(e) => return Err(AfpError::from_io(&e)),
            }
            vol.fs.rmdir(&obj.path).map_err(|e| AfpError::from_io(&e))?;
        } else {
            vol.fs.unlink(&obj.path).map_err(|e| AfpError::from_io(&e))?;
            vol.backend.deleted(&vol.fs, &obj.path, false);
        }
        vol.ids.remove(obj.id);
        vol.note_change();
        Ok(Vec::new())
    }

    pub(super) fn fp_rename(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let (_npt, newname) = read_path(&mut r)?;
        let vol = self.vol(vid)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let res = vol.resolve(did, pt, path)?;
        let obj = res.existing()?.clone();
        if obj.id == DIRID_ROOT {
            return Err(AfpError::CantRename);
        }
        if let Some(m) = vol.read_meta(&obj) {
            if m.attr() & ATTR_NORENAME != 0 {
                return Err(AfpError::ObjectLocked);
            }
        }
        let new_unix = unix_name_of(newname)?;
        if vol.hidden(&new_unix) {
            return Err(AfpError::ParamErr);
        }
        if new_unix == obj.unix_name {
            return Ok(Vec::new());
        }
        let (ppath, _) = vol.dir_path(obj.parent)?;
        let (_, existing) = vol.lookup(obj.parent, &ppath, newname)?;
        let same = matches!(&existing, Some(e) if e.id == obj.id);
        if existing.is_some() && !same {
            return Err(AfpError::ObjectExists);
        }
        let target = ppath.join(std::ffi::OsStr::from_bytes(&new_unix));
        let r = if same { vol.fs.rename(&obj.path, &target) } else { vol.fs.rename_noreplace(&obj.path, &target) };
        r.map_err(|e| AfpError::from_io(&e))?;
        vol.backend.renamed(&vol.fs, &obj.path, &target, obj.st.is_dir());
        vol.ids.moved(obj.id, obj.parent, &new_unix);
        vol.note_change();
        Ok(Vec::new())
    }

    pub(super) fn fp_move_and_rename(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let sdid = r.u32()?;
        let ddid = r.u32()?;
        let (spt, spath) = read_path(&mut r)?;
        let (dpt, dpath) = read_path(&mut r)?;
        let (_npt, newname) = read_path(&mut r)?;
        let vol = self.vol(vid)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let src = vol.resolve(sdid, spt, spath)?.existing()?.clone();
        if src.id == DIRID_ROOT {
            return Err(AfpError::CantMove);
        }
        let dst = vol.resolve(ddid, dpt, dpath)?.existing()?.clone();
        if !dst.st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        let new_unix = if newname.is_empty() { src.unix_name.clone() } else { unix_name_of(newname)? };
        if vol.hidden(&new_unix) {
            return Err(AfpError::ParamErr);
        }
        if src.st.is_dir() {
            // Refuse to move a directory into itself or a descendant.
            let mut cur = dst.id;
            let mut guard = 0;
            while cur != DIRID_PARENT_OF_ROOT && guard < 1024 {
                if cur == src.id {
                    return Err(AfpError::CantMove);
                }
                cur = match vol.ids.get(cur) {
                    Some(n) => n.parent,
                    None => break,
                };
                guard += 1;
            }
        }
        if new_unix != src.unix_name {
            if let Some(m) = vol.read_meta(&src) {
                if m.attr() & ATTR_NORENAME != 0 {
                    return Err(AfpError::ObjectLocked);
                }
            }
        }
        if dst.id == src.parent && new_unix == src.unix_name {
            return Ok(Vec::new());
        }
        let mac_new = charset::unix_to_mac(&new_unix, src.id);
        let (_, existing) = vol.lookup(dst.id, &dst.path, &mac_new)?;
        let same = matches!(&existing, Some(e) if e.id == src.id);
        if existing.is_some() && !same {
            return Err(AfpError::ObjectExists);
        }
        let target = dst.path.join(std::ffi::OsStr::from_bytes(&new_unix));
        let res = if same { vol.fs.rename(&src.path, &target) } else { vol.fs.rename_noreplace(&src.path, &target) };
        match res {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => return Err(AfpError::CantMove),
            Err(e) => return Err(AfpError::from_io(&e)),
        }
        vol.backend.renamed(&vol.fs, &src.path, &target, src.st.is_dir());
        vol.ids.moved(src.id, dst.id, &new_unix);
        vol.note_change();
        Ok(Vec::new())
    }

    pub(super) fn fp_copy_file(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let svid = r.u16()?;
        let sdid = r.u32()?;
        let dvid = r.u16()?;
        let ddid = r.u32()?;
        let (spt, spath) = read_path(&mut r)?;
        let (dpt, dpath) = read_path(&mut r)?;
        let (_npt, newname) = read_path(&mut r)?;

        let (src, src_meta, src_rfork, mut src_file) = {
            let svol = self.vol(svid)?;
            let src = svol.resolve(sdid, spt, spath)?.existing()?.clone();
            if src.st.is_dir() {
                return Err(AfpError::ObjectTypeErr);
            }
            let m = svol.read_meta(&src);
            let rf = svol.backend.rfork_path(&src.path).filter(|_| svol.backend.rfork_len(&svol.fs, &src.path) > 0);
            let f = svol.fs.open_read(&src.path).map_err(|e| AfpError::from_io(&e))?;
            if !f.metadata()?.is_file() {
                return Err(AfpError::ObjectTypeErr);
            }
            (src, m, rf, f)
        };
        let rfork_data = match src_rfork {
            Some(_) => Some(self.read_whole_rfork(svid, &src)?),
            None => None,
        };
        let dvol = self.vol(dvid)?;
        if dvol.read_only {
            return Err(AfpError::VolLocked);
        }
        let dst = dvol.resolve(ddid, dpt, dpath)?.existing()?.clone();
        if !dst.st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        let (new_unix, mac_new) = if newname.is_empty() {
            (src.unix_name.clone(), charset::unix_to_mac(&src.unix_name, src.id))
        } else {
            (unix_name_of(newname)?, newname.to_vec())
        };
        if dvol.hidden(&new_unix) {
            return Err(AfpError::ParamErr);
        }
        let (_, existing) = dvol.lookup(dst.id, &dst.path, &mac_new)?;
        if existing.is_some() {
            return Err(AfpError::ObjectExists);
        }
        let target = dst.path.join(std::ffi::OsStr::from_bytes(&new_unix));
        dvol.apply_umask();
        let mode = src.st.mode & 0o777;
        let result = (|| -> AfpResult<()> {
            let mut dst = dvol.fs.create(&target, mode, false).map_err(|e| AfpError::from_io(&e))?;
            io::copy(&mut src_file, &mut dst).map_err(|e| AfpError::from_io(&e))?;
            drop(dst);
            if let Some(perm) = dvol.opts.file_perm {
                if let Ok(st) = dvol.fs.lstat(&target) {
                    let _ = dvol.fs.chmod(&target, (st.mode | perm) & 0o7777);
                }
            }
            let m = src_meta.clone().unwrap_or_default();
            if src_meta.is_some() {
                dvol.backend.write(&dvol.fs, &target, false, &m).map_err(|e| AfpError::from_io(&e))?;
            }
            if let Some(data) = &rfork_data {
                dvol.backend.deleted(&dvol.fs, &target, false);
                dvol.backend.create_rfork(&dvol.fs, &target, &m, 0o666).map_err(|e| AfpError::from_io(&e))?;
                let mut f = Fork::open(&dvol.fs, 0, dvid, 0, &target, true, OPENACC_RD | OPENACC_WR, dvol.backend.rfork_path(&target), &|| Ok(()))?;
                f.write_at(data, 0)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            let _ = dvol.fs.unlink(&target);
            dvol.backend.deleted(&dvol.fs, &target, false);
            return Err(e);
        }
        if let Ok(st) = dvol.fs.lstat(&target) {
            dvol.ids.id_for(dst.id, &new_unix, &st);
        }
        dvol.note_change();
        Ok(Vec::new())
    }

    fn read_whole_rfork(&mut self, vid: u16, obj: &Obj) -> AfpResult<Vec<u8>> {
        let vol = self.vol(vid)?;
        let f = Fork::open(&vol.fs, 0, vid, obj.id, &obj.path, true, OPENACC_RD, vol.backend.rfork_path(&obj.path), &|| Ok(()))?;
        let len = f.len()?;
        if len > MAX_RFORK_COPY {
            return Err(AfpError::MiscErr);
        }
        let mut buf = vec![0u8; len as usize];
        let n = f.read_at(&mut buf, 0)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub(super) fn fp_exchange_files(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        let sdid = r.u32()?;
        let ddid = r.u32()?;
        let (spt, spath) = read_path(&mut r)?;
        let (dpt, dpath) = read_path(&mut r)?;
        let vol = self.vol(vid)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let a = vol.resolve(sdid, spt, spath)?.existing()?.clone();
        let b = vol.resolve(ddid, dpt, dpath)?.existing()?.clone();
        if a.st.is_dir() || b.st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        if a.id == b.id {
            return Err(AfpError::SameObjectErr);
        }
        let ma = vol.meta_or_default(&a);
        let mb = vol.meta_or_default(&b);
        if let Err(e) = vol.fs.exchange(&a.path, &b.path) {
            log::debug!("renameat2 exchange failed ({}), using renames", e);
            let tmp = a.path.with_file_name(format!(".afprust-xchg-{}", std::process::id()));
            vol.fs.rename_noreplace(&a.path, &tmp).map_err(|e| AfpError::from_io(&e))?;
            if let Err(e) = vol.fs.rename(&b.path, &a.path) {
                let _ = vol.fs.rename(&tmp, &a.path);
                return Err(AfpError::from_io(&e));
            }
            vol.fs.rename(&tmp, &b.path).map_err(|e| AfpError::from_io(&e))?;
        }
        if let Err(e) = vol.backend.swap_companions(&vol.fs, &a.path, &b.path) {
            log::warn!("exchange: resource forks not swapped: {}", e);
        }
        // Finder info, creation date and comment stay with the names; the
        // forks and modification dates move with the contents.
        let swap = |orig: &Meta, other: &Meta| -> Meta {
            let mut m = orig.clone();
            let od = other.dates.unwrap_or([0, 0, DATE_START, 0]);
            let mut d = orig.dates.unwrap_or([0, 0, DATE_START, 0]);
            d[1] = od[1];
            m.dates = Some(d);
            m
        };
        let na = swap(&ma, &mb);
        let nb = swap(&mb, &ma);
        let _ = vol.backend.write(&vol.fs, &a.path, false, &na);
        let _ = vol.backend.write(&vol.fs, &b.path, false, &nb);
        vol.ids.swap_inodes(a.id, b.id);
        vol.note_change();
        for f in self.forks.values_mut() {
            if f.vid == vid {
                if f.id == a.id {
                    f.id = b.id;
                    f.path = b.path.clone();
                } else if f.id == b.id {
                    f.id = a.id;
                    f.path = a.path.clone();
                }
            }
        }
        Ok(Vec::new())
    }

    // ---------------------------------------------------------------
    // forks
    // ---------------------------------------------------------------

    pub(super) fn fp_open_fork(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        let _ = r.u8()?;
        let flag = r.u8()?;
        let vid = r.u16()?;
        let did = r.u32()?;
        let bitmap = r.u16()?;
        let access = r.u16()?;
        let (pt, path) = read_path(&mut r)?;
        if bitmap & !FIL_BITS_VALID != 0 {
            return Err(AfpError::BitmapErr);
        }
        let is_rsrc = flag & 0x80 != 0;
        let refnum = self.alloc_fork_ref()?;
        let vol = self.vol(vid)?;
        let obj = vol.resolve(did, pt, path)?.existing()?.clone();
        if obj.st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        if access & OPENACC_WR != 0 {
            if vol.read_only {
                return Err(AfpError::VolLocked);
            }
            if let Some(m) = vol.read_meta(&obj) {
                if m.attr() & ATTR_NOWRITE != 0 {
                    return Err(AfpError::ObjectLocked);
                }
            }
        }
        let rpath = if is_rsrc { vol.backend.rfork_path(&obj.path) } else { None };
        let backend = vol.backend;
        let meta = vol.meta_or_default(&obj);
        vol.apply_umask();
        let mode = obj.st.mode;
        let vol: &Volume = vol;
        let create = || backend.create_rfork(&vol.fs, &obj.path, &meta, mode);
        let f = Fork::open(&vol.fs, refnum, vid, obj.id, &obj.path, is_rsrc, access, rpath, &create)?;
        self.forks.insert(refnum, f);
        let mut w = Writer::new();
        w.u16(bitmap).u16(refnum);
        let vol = self.vols.get(&vid).unwrap();
        let os = self.open_state(vid, obj.id);
        params::pack_file(vol, &obj, bitmap, &os, &mut w);
        Ok(w.into_vec())
    }

    pub(super) fn fp_close_fork(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let refnum = r.u16()?;
        let f = self.forks.remove(&refnum).ok_or(AfpError::ParamErr)?;
        if f.dirty {
            if let Some(vol) = self.vols.get_mut(&f.vid) {
                if f.is_rsrc {
                    // Resource fork writes do not touch the data file's
                    // mtime: record the modification in the metadata.
                    if let Ok(obj) = vol.obj_for_id(f.id) {
                        let mut m = vol.meta_or_default(&obj);
                        let mut d = m.dates.unwrap_or_else(|| initial_dates(&vol.fs, &obj));
                        d[1] = unix_to_afp_date(crate::util::now_unix());
                        m.dates = Some(d);
                        let _ = vol.write_meta(&obj, &m);
                    }
                }
                vol.note_change();
            }
        }
        Ok(Vec::new())
    }

    pub(super) fn fp_read(&mut self, req: &[u8]) -> Reply {
        let res = (|| -> AfpResult<(Vec<u8>, bool)> {
            let mut r = Reader::new(req);
            r.skip(2)?;
            let refnum = r.u16()?;
            let off = r.i32()?;
            let count = r.i32()?;
            let nl_mask = r.u8().unwrap_or(0);
            let nl_char = r.u8().unwrap_or(0);
            if off < 0 || count < 0 {
                return Err(AfpError::ParamErr);
            }
            let f = self.forks.get(&refnum).ok_or(AfpError::ParamErr)?;
            if f.access & OPENACC_RD == 0 {
                return Err(AfpError::AccessDenied);
            }
            let quantum = self.dsi.server_quantum as usize;
            let want = (count as usize).min(quantum);
            if want == 0 {
                return Ok((Vec::new(), false));
            }
            if f.range_conflicts(off as u64, want as u64, false) {
                return Err(AfpError::LockErr);
            }
            let mut buf = vec![0u8; want];
            let mut n = f.read_at(&mut buf, off as u64)?;
            let mut newline = false;
            if nl_mask != 0 {
                if let Some(i) = buf[..n].iter().position(|&b| b & nl_mask == nl_char) {
                    n = i + 1;
                    newline = true;
                }
            }
            buf.truncate(n);
            let eof = !newline && n < want;
            Ok((buf, eof))
        })();
        match res {
            Ok((data, eof)) => Reply { code: if eof { AfpError::EofErr.code() } else { 0 }, data },
            Err(e) => Reply::err(e),
        }
    }

    pub(super) fn fp_write(&mut self, req: &[u8], data: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        let _ = r.u8()?;
        let flag = r.u8()?;
        let refnum = r.u16()?;
        let off = r.i32()? as i64;
        let count = r.i32()?;
        if count < 0 {
            return Err(AfpError::ParamErr);
        }
        let n = (count as usize).min(data.len());
        let f = self.forks.get_mut(&refnum).ok_or(AfpError::ParamErr)?;
        if !f.writable() {
            return Err(AfpError::AccessDenied);
        }
        let base = if flag & 0x80 != 0 { f.len()? as i64 } else { 0 };
        let abs = base + off;
        if abs < 0 {
            return Err(AfpError::ParamErr);
        }
        if f.range_conflicts(abs as u64, n as u64, true) {
            return Err(AfpError::LockErr);
        }
        f.write_at(&data[..n], abs as u64)?;
        let end = (abs as u64 + n as u64).min(AFP2_MAX_FORK);
        let mut w = Writer::new();
        w.u32(end as u32);
        Ok(w.into_vec())
    }

    pub(super) fn fp_flush_fork(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let refnum = r.u16()?;
        let f = self.forks.get(&refnum).ok_or(AfpError::ParamErr)?;
        if f.dirty {
            f.flush()?;
        }
        Ok(Vec::new())
    }

    pub(super) fn fp_get_fork_parms(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let refnum = r.u16()?;
        let bitmap = r.u16()?;
        if bitmap & !FIL_BITS_VALID != 0 {
            return Err(AfpError::BitmapErr);
        }
        let (vid, id, is_rsrc) = {
            let f = self.forks.get(&refnum).ok_or(AfpError::ParamErr)?;
            (f.vid, f.id, f.is_rsrc)
        };
        if (is_rsrc && bitmap & FIL_BIT_DFLEN != 0) || (!is_rsrc && bitmap & FIL_BIT_RFLEN != 0) {
            return Err(AfpError::BitmapErr);
        }
        let obj = self.vol(vid)?.obj_for_id(id)?;
        let mut w = Writer::new();
        w.u16(bitmap);
        let vol = self.vols.get(&vid).unwrap();
        let os = self.open_state(vid, id);
        params::pack_file(vol, &obj, bitmap, &os, &mut w);
        Ok(w.into_vec())
    }

    pub(super) fn fp_set_fork_parms(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let refnum = r.u16()?;
        let bitmap = r.u16()?;
        let len = r.i32()?;
        let f = self.forks.get_mut(&refnum).ok_or(AfpError::ParamErr)?;
        let want = if f.is_rsrc { FIL_BIT_RFLEN } else { FIL_BIT_DFLEN };
        if bitmap != want {
            return Err(AfpError::BitmapErr);
        }
        if len < 0 {
            return Err(AfpError::ParamErr);
        }
        f.set_len(len as u64)?;
        Ok(Vec::new())
    }

    pub(super) fn fp_byte_range_lock(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        let _ = r.u8()?;
        let flags = r.u8()?;
        let refnum = r.u16()?;
        let off = r.i32()? as i64;
        let length = r.i32()? as i64;
        let unlock = flags & 0x01 != 0;
        let from_end = flags & 0x80 != 0;
        let f = self.forks.get_mut(&refnum).ok_or(AfpError::ParamErr)?;
        let base = if from_end { f.len()? as i64 } else { 0 };
        let start = base + off;
        if start < 0 {
            return Err(AfpError::ParamErr);
        }
        let start = start as u64;
        let len = match length {
            -1 => {
                if unlock {
                    u64::MAX
                } else {
                    BYTELOCK_MAX.saturating_sub(start)
                }
            }
            l if l > 0 => l as u64,
            _ => return Err(AfpError::ParamErr),
        };
        f.byte_lock(start, len, unlock)?;
        let mut w = Writer::new();
        w.u32(start.min(u32::MAX as u64) as u32);
        Ok(w.into_vec())
    }

    // ---------------------------------------------------------------
    // desktop database
    // ---------------------------------------------------------------

    fn desktop(&self, dtref: u16) -> AfpResult<Desktop<'_>> {
        let vol = self.vols.get(&dtref).ok_or(AfpError::ParamErr)?;
        Ok(Desktop::new(&vol.fs))
    }

    pub(super) fn fp_open_dt(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let vid = r.u16()?;
        self.vol(vid)?;
        self.dt_open.insert(vid);
        let mut w = Writer::new();
        w.u16(vid);
        Ok(w.into_vec())
    }

    pub(super) fn fp_close_dt(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        self.dt_open.remove(&dt);
        Ok(Vec::new())
    }

    pub(super) fn fp_add_icon(&mut self, req: &[u8], data: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let creator = r.array::<4>()?;
        let ftype = r.array::<4>()?;
        let itype = r.u8()?;
        r.skip(1)?;
        let tag = r.u32()?;
        let size = r.u16()? as usize;
        if data.len() < size {
            return Err(AfpError::ParamErr);
        }
        let vol = self.vols.get(&dt).ok_or(AfpError::ParamErr)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        self.desktop(dt)?.add_icon(&creator, &ftype, itype, tag, &data[..size]);
        Ok(Vec::new())
    }

    pub(super) fn fp_get_icon(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let creator = r.array::<4>()?;
        let ftype = r.array::<4>()?;
        let itype = r.u8()?;
        r.skip(1)?;
        let len = r.u16()? as usize;
        let (_tag, data) = self.desktop(dt)?.get_icon(&creator, &ftype, itype).ok_or(AfpError::ItemNotFound)?;
        Ok(data[..data.len().min(len)].to_vec())
    }

    pub(super) fn fp_get_icon_info(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let creator = r.array::<4>()?;
        let index = r.u16()?;
        let info = self.desktop(dt)?.icon_info(&creator, index).ok_or(AfpError::ItemNotFound)?;
        let mut w = Writer::new();
        w.u32(info.tag).bytes(&info.ftype).u8(info.itype).u8(0).u16(info.size);
        Ok(w.into_vec())
    }

    fn rel_path(vol: &Volume, obj: &Obj) -> AfpResult<Vec<u8>> {
        let rel = obj.path.strip_prefix(&vol.root).map_err(|_| AfpError::MiscErr)?;
        Ok(rel.as_os_str().as_bytes().to_vec())
    }

    pub(super) fn fp_add_appl(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let did = r.u32()?;
        let creator = r.array::<4>()?;
        let tag = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let vol = self.vol(dt)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let obj = vol.resolve(did, pt, path)?.existing()?.clone();
        if obj.st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        let rel = Self::rel_path(vol, &obj)?;
        Desktop::new(&vol.fs).add_appl(&creator, tag, &rel);
        Ok(Vec::new())
    }

    pub(super) fn fp_remove_appl(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let did = r.u32()?;
        let creator = r.array::<4>()?;
        let (pt, path) = read_path(&mut r)?;
        let vol = self.vol(dt)?;
        let obj = vol.resolve(did, pt, path)?.existing()?.clone();
        let rel = Self::rel_path(vol, &obj)?;
        if !Desktop::new(&vol.fs).remove_appl(&creator, &rel) {
            return Err(AfpError::ItemNotFound);
        }
        Ok(Vec::new())
    }

    /// Walk a volume-relative Unix path to an object.
    fn obj_from_rel(vol: &mut Volume, rel: &[u8]) -> Option<Obj> {
        let mut cur_id = DIRID_ROOT;
        let mut cur_path = vol.root.clone();
        let mut last = None;
        for comp in rel.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            if comp == b"." || comp == b".." || vol.hidden(comp) {
                return None;
            }
            let o = vol.child(cur_id, &cur_path, comp)?;
            cur_id = o.id;
            cur_path = o.path.clone();
            last = Some(o);
        }
        last
    }

    pub(super) fn fp_get_appl(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let creator = r.array::<4>()?;
        let index = r.u16()?.max(1) as usize;
        let bitmap = r.u16()?;
        if bitmap & !FIL_BITS_VALID != 0 {
            return Err(AfpError::BitmapErr);
        }
        let vol = self.vol(dt)?;
        let entries = Desktop::new(&vol.fs).appls(&creator);
        let mut n = 0;
        let mut found = None;
        for (tag, rel) in entries {
            if let Some(o) = Self::obj_from_rel(vol, &rel) {
                if o.st.is_file() {
                    n += 1;
                    if n == index {
                        found = Some((tag, o));
                        break;
                    }
                }
            }
        }
        let (tag, obj) = found.ok_or(AfpError::ItemNotFound)?;
        let mut w = Writer::new();
        w.u16(bitmap).u32(tag);
        let vol = self.vols.get(&dt).unwrap();
        let os = self.open_state(dt, obj.id);
        params::pack_file(vol, &obj, bitmap, &os, &mut w);
        Ok(w.into_vec())
    }

    pub(super) fn fp_add_comment(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        r.align2();
        let comment = r.pstring()?;
        let vol = self.vol(dt)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let obj = vol.resolve(did, pt, path)?.existing()?.clone();
        let mut m = vol.meta_or_default(&obj);
        if m.dates.is_none() {
            m.dates = Some(initial_dates(&vol.fs, &obj));
        }
        m.comment = comment[..comment.len().min(crate::vfs::adouble::MAX_COMMENT)].to_vec();
        vol.write_meta(&obj, &m)?;
        Ok(Vec::new())
    }

    pub(super) fn fp_remove_comment(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let vol = self.vol(dt)?;
        if vol.read_only {
            return Err(AfpError::VolLocked);
        }
        let obj = vol.resolve(did, pt, path)?.existing()?.clone();
        let mut m = vol.read_meta(&obj).ok_or(AfpError::ItemNotFound)?;
        if m.comment.is_empty() {
            return Err(AfpError::ItemNotFound);
        }
        m.comment.clear();
        vol.write_meta(&obj, &m)?;
        Ok(Vec::new())
    }

    pub(super) fn fp_get_comment(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let dt = r.u16()?;
        let did = r.u32()?;
        let (pt, path) = read_path(&mut r)?;
        let vol = self.vol(dt)?;
        let obj = vol.resolve(did, pt, path)?.existing()?.clone();
        let m = vol.read_meta(&obj).ok_or(AfpError::ItemNotFound)?;
        if m.comment.is_empty() {
            return Err(AfpError::ItemNotFound);
        }
        let mut w = Writer::new();
        w.pstring(&m.comment);
        Ok(w.into_vec())
    }
}

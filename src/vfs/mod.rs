//! Volume model: the mapping between AFP (volume, directory ID, Mac name)
//! triples and Unix paths.
//!
//! Directory and file IDs are derived from inode numbers so that they stay
//! the same across sessions without a shared database. Each session keeps
//! an ID map of every object it has shown the client; a collision (only
//! possible for inodes that do not fit in 30 bits or live on another
//! device) gets a session-unique ID instead.
//!
//! Path safety: every name from the client is converted with
//! [`charset::mac_to_unix`], which rejects `.`, `..`, empty names and
//! anything containing `/`. Symlinks are never followed unless the volume
//! sets `follow symlinks`, and then only when the target stays inside the
//! volume. All file system access happens with the logged-in user's
//! credentials.

pub mod adouble;
pub mod desktop;
pub mod fork;
pub mod fs;
pub mod meta;
pub mod sys;

use std::collections::HashMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirEntryExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use unicode_normalization::UnicodeNormalization;

use crate::afp::consts::*;
use crate::charset;
use crate::config::extmap::ExtMap;
use crate::config::VolumeOptions;
use adouble::Meta;
use meta::Backend;

#[derive(Debug, Clone, Copy)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
}

impl Stat {
    pub fn from_meta(m: &std::fs::Metadata) -> Stat {
        Stat {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            size: m.size(),
            mtime: m.mtime(),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
    }

    pub fn is_file(&self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFLNK as u32
    }
}

pub fn lstat(p: &Path) -> io::Result<Stat> {
    std::fs::symlink_metadata(p).map(|m| Stat::from_meta(&m))
}

#[derive(Debug, Clone)]
pub struct Node {
    pub parent: u32,
    pub name: Vec<u8>,
    pub dev: u64,
    pub ino: u64,
    pub is_dir: bool,
}

const FIRST_ID: u64 = 17;
const PLAIN_MAX: u64 = 0x3FFF_FFFF;
const HASH_BASE: u32 = 0x4000_0000;
const HASH_MASK: u32 = 0x1FFF_FFFF;
const TEMP_BASE: u32 = 0x6000_0000;
const TEMP_MAX: u32 = 0x7FFF_FFFF;
const MAX_NODES: usize = 400_000;

pub struct IdMap {
    nodes: HashMap<u32, Node>,
    by_inode: HashMap<(u64, u64), u32>,
    root_dev: u64,
    next_temp: u32,
}

impl IdMap {
    fn new(root: &Stat) -> IdMap {
        let mut m = IdMap { nodes: HashMap::new(), by_inode: HashMap::new(), root_dev: root.dev, next_temp: TEMP_BASE };
        m.nodes.insert(
            DIRID_ROOT,
            Node { parent: DIRID_PARENT_OF_ROOT, name: Vec::new(), dev: root.dev, ino: root.ino, is_dir: true },
        );
        m.by_inode.insert((root.dev, root.ino), DIRID_ROOT);
        m
    }

    pub fn get(&self, id: u32) -> Option<&Node> {
        self.nodes.get(&id)
    }

    fn derive(&self, dev: u64, ino: u64) -> u32 {
        if dev == self.root_dev && (FIRST_ID..=PLAIN_MAX).contains(&ino) {
            return ino as u32;
        }
        // FNV-1a over (dev, ino)
        let mut h: u32 = 0x811C_9DC5;
        for b in dev.to_le_bytes().iter().chain(ino.to_le_bytes().iter()) {
            h ^= *b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        HASH_BASE | (h & HASH_MASK)
    }

    fn alloc_temp(&mut self) -> u32 {
        loop {
            let id = self.next_temp;
            self.next_temp = if self.next_temp >= TEMP_MAX { TEMP_BASE } else { self.next_temp + 1 };
            if !self.nodes.contains_key(&id) {
                return id;
            }
        }
    }

    fn evict_files(&mut self) {
        let before = self.nodes.len();
        self.nodes.retain(|_, n| n.is_dir);
        let nodes = &self.nodes;
        self.by_inode.retain(|_, id| nodes.contains_key(id));
        log::debug!("ID map: evicted {} file entries", before - self.nodes.len());
    }

    /// Find or assign the ID of `name` in directory `parent`.
    pub fn id_for(&mut self, parent: u32, name: &[u8], st: &Stat) -> u32 {
        let key = (st.dev, st.ino);
        if let Some(&id) = self.by_inode.get(&key) {
            if id == DIRID_ROOT {
                return id;
            }
            if let Some(n) = self.nodes.get_mut(&id) {
                if n.parent != parent || n.name != name {
                    n.parent = parent;
                    n.name = name.to_vec();
                }
                n.is_dir = st.is_dir();
                return id;
            }
        }
        if self.nodes.len() >= MAX_NODES {
            self.evict_files();
        }
        let mut id = self.derive(st.dev, st.ino);
        if let Some(existing) = self.nodes.get(&id) {
            if (existing.dev, existing.ino) != key {
                id = self.alloc_temp();
            }
        }
        self.nodes.insert(id, Node { parent, name: name.to_vec(), dev: st.dev, ino: st.ino, is_dir: st.is_dir() });
        self.by_inode.insert(key, id);
        id
    }

    pub fn remove(&mut self, id: u32) {
        if id == DIRID_ROOT {
            return;
        }
        if let Some(n) = self.nodes.remove(&id) {
            if self.by_inode.get(&(n.dev, n.ino)) == Some(&id) {
                self.by_inode.remove(&(n.dev, n.ino));
            }
        }
    }

    pub fn moved(&mut self, id: u32, parent: u32, name: &[u8]) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.parent = parent;
            n.name = name.to_vec();
        }
    }

    /// After exchanging two files' contents, keep each ID with its name.
    pub fn swap_inodes(&mut self, a: u32, b: u32) {
        let (ka, kb) = match (self.nodes.get(&a), self.nodes.get(&b)) {
            (Some(x), Some(y)) => ((x.dev, x.ino), (y.dev, y.ino)),
            _ => return,
        };
        if let Some(n) = self.nodes.get_mut(&a) {
            n.dev = kb.0;
            n.ino = kb.1;
        }
        if let Some(n) = self.nodes.get_mut(&b) {
            n.dev = ka.0;
            n.ino = ka.1;
        }
        self.by_inode.insert(kb, a);
        self.by_inode.insert(ka, b);
    }
}

/// Credentials of the logged-in user, for access-rights reporting.
#[derive(Debug, Clone)]
pub struct UserCtx {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

fn unix_to_afp_bits(bits: u32) -> u32 {
    let mut m = 0;
    if bits & 4 != 0 {
        m |= AR_UREAD;
    }
    if bits & 2 != 0 {
        m |= AR_UWRITE;
    }
    if bits & 1 != 0 {
        m |= AR_USEARCH;
    }
    m
}

impl UserCtx {
    pub fn access_rights(&self, st: &Stat, read_only: bool) -> u32 {
        let owner = unix_to_afp_bits((st.mode >> 6) & 7);
        let group = unix_to_afp_bits((st.mode >> 3) & 7);
        let world = unix_to_afp_bits(st.mode & 7);
        let mut user = if self.uid == st.uid {
            owner | AR_UOWN
        } else if self.groups.contains(&st.gid) {
            group
        } else {
            world
        };
        let (mut o, mut g, mut w) = (owner, group, world);
        if read_only {
            user &= !AR_UWRITE;
            o &= !AR_UWRITE;
            g &= !AR_UWRITE;
            w &= !AR_UWRITE;
        }
        (user << 24) | (w << 16) | (g << 8) | o
    }

    /// Can this user write to an object with this stat (approximation of
    /// access(2) for display purposes)?
    pub fn can_write(&self, st: &Stat) -> bool {
        let bits = if self.uid == st.uid {
            (st.mode >> 6) & 7
        } else if self.groups.contains(&st.gid) {
            (st.mode >> 3) & 7
        } else {
            st.mode & 7
        };
        bits & 2 != 0
    }
}

/// A file system object located by a client request.
#[derive(Debug, Clone)]
pub struct Obj {
    pub id: u32,
    pub parent: u32,
    pub unix_name: Vec<u8>,
    pub path: PathBuf,
    pub st: Stat,
}

/// Result of resolving (dirID, path): either an existing object or a
/// name to be created in a directory.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub dir_id: u32,
    pub dir_path: PathBuf,
    /// Unix name of the last path element (None if the path ended at a
    /// directory).
    pub name: Option<Vec<u8>>,
    pub obj: Option<Obj>,
}

impl Resolved {
    pub fn existing(&self) -> AfpResult<&Obj> {
        self.obj.as_ref().ok_or(AfpError::ObjectNotFound)
    }
}

struct EnumCache {
    dir_id: u32,
    mtime: i64,
    names: Vec<Vec<u8>>,
}

pub struct Volume {
    pub vid: u16,
    pub name_mac: Vec<u8>,
    pub root: PathBuf,
    pub opts: VolumeOptions,
    pub read_only: bool,
    pub backend: Backend,
    pub ids: IdMap,
    pub extmap: Arc<ExtMap>,
    pub create_date: u32,
    pub last_change: i64,
    enum_cache: Option<EnumCache>,
    /// Confined file system access for everything below `root`.
    pub fs: fs::Fs,
}

const MAX_DEPTH: usize = 512;

impl Volume {
    pub fn open(
        vid: u16,
        name_mac: Vec<u8>,
        root: PathBuf,
        opts: VolumeOptions,
        read_only: bool,
        extmap: Arc<ExtMap>,
    ) -> AfpResult<Volume> {
        let st = lstat(&root).map_err(|e| {
            log::warn!("volume {}: {}", root.display(), e);
            AfpError::from_io(&e)
        })?;
        if !st.is_dir() {
            log::warn!("volume path {} is not a directory", root.display());
            return Err(AfpError::ObjectNotFound);
        }
        let vfs = fs::Fs::new(&root, opts.follow_symlinks).map_err(|e| AfpError::from_io(&e))?;
        let backend = match opts.meta {
            crate::config::MetaScheme::Ea => Backend::Ea,
            crate::config::MetaScheme::AppleDouble => Backend::AppleDouble,
            crate::config::MetaScheme::None => Backend::None,
            crate::config::MetaScheme::Auto => {
                if sys::xattrs_supported(&root) {
                    Backend::Ea
                } else {
                    log::info!("volume {}: no xattr support, using .AppleDouble", root.display());
                    Backend::AppleDouble
                }
            }
        };
        let mut v = Volume {
            vid,
            name_mac,
            root: root.clone(),
            opts,
            read_only,
            backend,
            ids: IdMap::new(&st),
            extmap,
            create_date: 0,
            last_change: 0,
            enum_cache: None,
            fs: vfs,
        };
        v.create_date = v.compute_create_date(&st);
        Ok(v)
    }

    /// Volume creation date: Mac clients use it to match aliases to
    /// volumes, so it must be stable.
    fn compute_create_date(&self, st: &Stat) -> u32 {
        if let Some(m) = self.backend.read(&self.fs, &self.root, true) {
            if let Some(d) = m.dates {
                if d[0] != 0 {
                    return d[0];
                }
            }
        }
        let t = self.fs.birth_time(&self.root).unwrap_or(st.mtime);
        unix_to_afp_date(t)
    }

    pub fn note_change(&mut self) {
        self.last_change = crate::util::now_unix();
        self.enum_cache = None;
    }

    /// Path of a known object ID (not validated).
    fn raw_path(&self, id: u32) -> AfpResult<PathBuf> {
        let mut comps: Vec<&[u8]> = Vec::new();
        let mut cur = id;
        while cur != DIRID_ROOT {
            let n = self.ids.get(cur).ok_or(AfpError::ObjectNotFound)?;
            comps.push(&n.name);
            cur = n.parent;
            if comps.len() > MAX_DEPTH {
                return Err(AfpError::MiscErr);
            }
        }
        let mut p = self.root.clone();
        for c in comps.iter().rev() {
            p.push(std::ffi::OsStr::from_bytes(c));
        }
        Ok(p)
    }

    /// Path and stat of a known ID, re-locating the object if it was
    /// renamed behind our back.
    pub fn path_of(&mut self, id: u32) -> AfpResult<(PathBuf, Stat)> {
        self.path_of_depth(id, 0)
    }

    fn path_of_depth(&mut self, id: u32, depth: usize) -> AfpResult<(PathBuf, Stat)> {
        if depth > MAX_DEPTH {
            return Err(AfpError::ObjectNotFound);
        }
        let node = self.ids.get(id).cloned().ok_or(AfpError::ObjectNotFound)?;
        let p = self.raw_path(id)?;
        if let Ok(st) = self.fs.lstat(&p) {
            if st.ino == node.ino && st.dev == node.dev {
                return Ok((p, st));
            }
        }
        if id == DIRID_ROOT {
            return Err(AfpError::ObjectNotFound);
        }
        // Moved or renamed outside of this session: look for the inode in
        // the (possibly also relocated) parent.
        let (ppath, _) = self.path_of_depth(node.parent, depth + 1)?;
        if let Ok(rd) = self.fs.read_dir(&ppath) {
            for e in rd.flatten().take(100_000) {
                if e.ino() == node.ino {
                    let name = e.file_name().as_bytes().to_vec();
                    let p = ppath.join(e.file_name());
                    if let Ok(st) = self.fs.lstat(&p) {
                        if st.dev == node.dev && st.ino == node.ino {
                            self.ids.moved(id, node.parent, &name);
                            return Ok((p, st));
                        }
                    }
                }
            }
        }
        self.ids.remove(id);
        Err(AfpError::ObjectNotFound)
    }

    pub fn dir_path(&mut self, id: u32) -> AfpResult<(PathBuf, Stat)> {
        let (p, st) = self.path_of(id).map_err(|_| AfpError::ObjectNotFound)?;
        if !st.is_dir() {
            return Err(AfpError::ObjectTypeErr);
        }
        Ok((p, st))
    }

    pub fn obj_for_id(&mut self, id: u32) -> AfpResult<Obj> {
        let (path, st) = self.path_of(id)?;
        let node = self.ids.get(id).cloned().ok_or(AfpError::ObjectNotFound)?;
        Ok(Obj { id, parent: node.parent, unix_name: node.name, path, st })
    }

    /// Is a directory entry hidden from clients?
    pub fn hidden(&self, name: &[u8]) -> bool {
        if Backend::is_reserved_name(name) {
            return true;
        }
        if name == b"lost+found" {
            return false;
        }
        self.vetoed(name)
    }

    pub fn vetoed(&self, name: &[u8]) -> bool {
        if self.opts.veto.is_empty() {
            return false;
        }
        let s = String::from_utf8_lossy(name);
        self.opts.veto.iter().any(|v| glob_match(v.as_bytes(), s.as_bytes()))
    }

    /// Stat a directory entry, applying the symlink policy.
    fn stat_entry(&self, p: &Path) -> io::Result<Option<Stat>> {
        let st = match self.fs.lstat(p) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => return Ok(None),
            Err(e) => return Err(e),
        };
        if st.is_symlink() {
            if !self.opts.follow_symlinks {
                return Ok(None);
            }
            // The kernel refuses targets outside the volume.
            let st = match self.fs.stat_follow(p) {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };
            if !st.is_dir() && !st.is_file() {
                return Ok(None);
            }
            return Ok(Some(st));
        }
        if !st.is_dir() && !st.is_file() {
            // devices, sockets, fifos are never exposed
            return Ok(None);
        }
        Ok(Some(st))
    }

    /// Look up a client-supplied (MacRoman) name in a directory.
    pub fn lookup(&mut self, dir_id: u32, dir_path: &Path, mac_name: &[u8]) -> AfpResult<(Vec<u8>, Option<Obj>)> {
        let unix = charset::mac_to_unix(mac_name).map_err(|_| AfpError::ParamErr)?;
        if self.hidden(&unix) {
            return Err(AfpError::ParamErr);
        }
        let p = dir_path.join(std::ffi::OsStr::from_bytes(&unix));
        if let Some(st) = self.stat_entry(&p)? {
            let id = self.ids.id_for(dir_id, &unix, &st);
            return Ok((unix.clone(), Some(Obj { id, parent: dir_id, unix_name: unix, path: p, st })));
        }
        // A mangled name: find the object by its embedded ID.
        if let Some(id) = charset::demangle_id(mac_name) {
            if let Some(n) = self.ids.get(id).cloned() {
                if n.parent == dir_id {
                    let p = dir_path.join(std::ffi::OsStr::from_bytes(&n.name));
                    if let Some(st) = self.stat_entry(&p)? {
                        if st.ino == n.ino {
                            let mangled = charset::unix_to_mac(&n.name, id);
                            if mangled == mac_name {
                                return Ok((n.name.clone(), Some(Obj { id, parent: dir_id, unix_name: n.name, path: p, st })));
                            }
                        }
                    }
                }
            }
        }
        // HFS is case-insensitive: fall back to a case-folded match.
        if let Some(found) = self.casefold_lookup(dir_path, &unix) {
            let p = dir_path.join(std::ffi::OsStr::from_bytes(&found));
            if let Some(st) = self.stat_entry(&p)? {
                let id = self.ids.id_for(dir_id, &found, &st);
                return Ok((found.clone(), Some(Obj { id, parent: dir_id, unix_name: found, path: p, st })));
            }
        }
        Ok((unix, None))
    }

    fn casefold_lookup(&self, dir: &Path, unix: &[u8]) -> Option<Vec<u8>> {
        let want = fold(unix);
        let rd = self.fs.read_dir(dir).ok()?;
        for e in rd.flatten().take(50_000) {
            let n = e.file_name();
            let nb = n.as_bytes();
            if self.hidden(nb) {
                continue;
            }
            if fold(nb) == want {
                return Some(nb.to_vec());
            }
        }
        None
    }

    /// Resolve an AFP (dirID, pathtype, path) into an object or a
    /// to-be-created name.
    pub fn resolve(&mut self, dir_id: u32, path_type: u8, path: &[u8]) -> AfpResult<Resolved> {
        if path_type != PATH_LONG && path_type != PATH_SHORT {
            return Err(AfpError::ParamErr);
        }
        let mut comps: Vec<Option<&[u8]>> = Vec::new(); // None = go to parent
        let mut i = 0;
        while i < path.len() {
            if path[i] == 0 {
                let mut n = 0;
                while i < path.len() && path[i] == 0 {
                    n += 1;
                    i += 1;
                }
                for _ in 1..n {
                    comps.push(None);
                }
                continue;
            }
            let start = i;
            while i < path.len() && path[i] != 0 {
                i += 1;
            }
            comps.push(Some(&path[start..i]));
        }

        let mut cur = dir_id;
        let mut idx = 0;
        if cur == DIRID_PARENT_OF_ROOT {
            // The only name valid below DID 1 is the volume name.
            match comps.first() {
                Some(Some(n)) if eq_fold_mac(n, &self.name_mac) => {
                    cur = DIRID_ROOT;
                    idx = 1;
                }
                _ => return Err(AfpError::ObjectNotFound),
            }
        }
        let (mut cur_path, mut cur_st) = self.dir_path(cur)?;
        while idx < comps.len() {
            let last = idx + 1 == comps.len();
            match comps[idx] {
                None => {
                    if cur != DIRID_ROOT {
                        let parent = self.ids.get(cur).map(|n| n.parent).ok_or(AfpError::ObjectNotFound)?;
                        cur = parent;
                        let (p, s) = self.dir_path(cur)?;
                        cur_path = p;
                        cur_st = s;
                    }
                }
                Some(name) => {
                    let (unix, obj) = self.lookup(cur, &cur_path, name)?;
                    match obj {
                        None => {
                            if last {
                                return Ok(Resolved { dir_id: cur, dir_path: cur_path, name: Some(unix), obj: None });
                            }
                            return Err(AfpError::ObjectNotFound);
                        }
                        Some(o) => {
                            if last {
                                return Ok(Resolved {
                                    dir_id: cur,
                                    dir_path: cur_path,
                                    name: Some(o.unix_name.clone()),
                                    obj: Some(o),
                                });
                            }
                            if !o.st.is_dir() {
                                return Err(AfpError::ObjectNotFound);
                            }
                            cur = o.id;
                            cur_path = o.path;
                            cur_st = o.st;
                        }
                    }
                }
            }
            idx += 1;
        }
        // Path ended at a directory: the object is that directory.
        let node = self.ids.get(cur).cloned().ok_or(AfpError::ObjectNotFound)?;
        let parent_path = if cur == DIRID_ROOT {
            cur_path.clone()
        } else {
            cur_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| self.root.clone())
        };
        Ok(Resolved {
            dir_id: node.parent,
            dir_path: parent_path,
            name: None,
            obj: Some(Obj { id: cur, parent: node.parent, unix_name: node.name, path: cur_path, st: cur_st }),
        })
    }

    /// The name shown to the client for an object.
    pub fn mac_name(&self, obj: &Obj) -> Vec<u8> {
        if obj.id == DIRID_ROOT {
            return self.name_mac.clone();
        }
        charset::unix_to_mac(&obj.unix_name, obj.id)
    }

    /// Visible entries of a directory, sorted for stable enumeration.
    pub fn list_dir(&mut self, dir_id: u32, path: &Path, st: &Stat, fresh: bool) -> AfpResult<Vec<Vec<u8>>> {
        if !fresh {
            if let Some(c) = &self.enum_cache {
                if c.dir_id == dir_id && c.mtime == st.mtime {
                    return Ok(c.names.clone());
                }
            }
        }
        let rd = self.fs.read_dir(path)?;
        let mut names = Vec::new();
        for e in rd.flatten() {
            let n = e.file_name().as_bytes().to_vec();
            if self.hidden(&n) {
                continue;
            }
            // Skip what `child` would reject anyway, so enumeration indexes
            // stay consistent between calls.
            match e.file_type() {
                Ok(ft) if ft.is_dir() || ft.is_file() => {}
                Ok(ft) if ft.is_symlink() && self.opts.follow_symlinks => {}
                _ => continue,
            }
            names.push(n);
            if names.len() > 65_535 {
                break;
            }
        }
        names.sort();
        self.enum_cache = Some(EnumCache { dir_id, mtime: st.mtime, names: names.clone() });
        Ok(names)
    }

    /// Stat a listed entry and register it in the ID map.
    pub fn child(&mut self, dir_id: u32, dir_path: &Path, name: &[u8]) -> Option<Obj> {
        let p = dir_path.join(std::ffi::OsStr::from_bytes(name));
        let st = self.stat_entry(&p).ok()??;
        let id = self.ids.id_for(dir_id, name, &st);
        Some(Obj { id, parent: dir_id, unix_name: name.to_vec(), path: p, st })
    }

    /// Number of visible entries in a directory.
    pub fn offspring(&self, path: &Path) -> u16 {
        let rd = match self.fs.read_dir(path) {
            Ok(r) => r,
            Err(_) => return 0,
        };
        let mut n: u32 = 0;
        for e in rd.flatten() {
            let name = e.file_name();
            if self.hidden(name.as_bytes()) {
                continue;
            }
            if let Ok(ft) = e.file_type() {
                if ft.is_symlink() && !self.opts.follow_symlinks {
                    continue;
                }
                if !(ft.is_dir() || ft.is_file() || ft.is_symlink()) {
                    continue;
                }
            }
            n += 1;
            if n >= 0xFFFF {
                break;
            }
        }
        n as u16
    }

    pub fn read_meta(&self, obj: &Obj) -> Option<Meta> {
        self.backend.read(&self.fs, &obj.path, obj.st.is_dir())
    }

    /// Metadata for display: stored metadata, or defaults (extension map
    /// for files).
    pub fn meta_or_default(&self, obj: &Obj) -> Meta {
        if let Some(m) = self.read_meta(obj) {
            return m;
        }
        let mut m = Meta::default();
        if obj.st.is_file() {
            if let Some((t, c)) = self.extmap.lookup(&obj.unix_name) {
                m.finder_info[0..4].copy_from_slice(&t);
                m.finder_info[4..8].copy_from_slice(&c);
            }
        }
        m
    }

    pub fn write_meta(&self, obj: &Obj, m: &Meta) -> AfpResult<()> {
        if self.read_only {
            return Err(AfpError::VolLocked);
        }
        self.backend.write(&self.fs, &obj.path, obj.st.is_dir(), m).map_err(|e| {
            log::debug!("metadata write {}: {}", obj.path.display(), e);
            AfpError::from_io(&e)
        })
    }

    pub fn space(&self) -> (u64, u64, u32) {
        let s = sys::statvfs(&self.root).unwrap_or(sys::FsSpace { total: 0, free: 0, block_size: 4096 });
        let mut total = s.total;
        let mut free = s.free;
        if let Some(lim) = self.opts.vol_size_limit_mib {
            let lim = lim.saturating_mul(1024 * 1024);
            if total > lim {
                let used = total - free;
                total = lim;
                free = lim.saturating_sub(used);
            }
        }
        (total, free, s.block_size.max(512))
    }

    /// Apply the volume's umask before creating something.
    pub fn apply_umask(&self) {
        sys::set_umask(self.opts.umask.unwrap_or(0o022));
    }
}

/// Case-fold a Unix name for HFS-style comparisons.
fn fold(name: &[u8]) -> String {
    String::from_utf8_lossy(name).nfc().flat_map(|c| c.to_lowercase()).collect()
}

fn eq_fold_mac(a: &[u8], b: &[u8]) -> bool {
    fold(charset::macroman_decode(a).as_bytes()) == fold(charset::macroman_decode(b).as_bytes())
}

/// Shell-style match supporting `*` and `?` (netatalk veto syntax).
pub fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            p += 1;
            mark = i;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match(b"*.tmp", b"a.tmp"));
        assert!(glob_match(b".DS_Store", b".DS_Store"));
        assert!(!glob_match(b"*.tmp", b"a.tmpx"));
        assert!(glob_match(b"a?c", b"abc"));
        assert!(glob_match(b"*", b""));
    }

    #[test]
    fn idmap_basics() {
        let root = Stat { dev: 1, ino: 100, mode: libc::S_IFDIR as u32 | 0o755, uid: 0, gid: 0, size: 0, mtime: 0 };
        let mut m = IdMap::new(&root);
        let f = Stat { ino: 5000, mode: libc::S_IFREG as u32 | 0o644, ..root };
        let id = m.id_for(DIRID_ROOT, b"a", &f);
        assert_eq!(id, 5000);
        assert_eq!(m.id_for(DIRID_ROOT, b"a", &f), 5000);
        // other device -> hashed range
        let g = Stat { dev: 2, ino: 5000, ..f };
        let id2 = m.id_for(DIRID_ROOT, b"b", &g);
        assert!(id2 >= HASH_BASE && id2 < TEMP_BASE);
        // small inode -> hashed, not colliding with reserved IDs
        let h = Stat { ino: 2, ..f };
        assert!(m.id_for(DIRID_ROOT, b"c", &h) >= HASH_BASE);
        // rename keeps ID
        assert_eq!(m.id_for(DIRID_ROOT, b"renamed", &f), 5000);
        assert_eq!(m.get(5000).unwrap().name, b"renamed");
    }

    #[test]
    fn access_rights() {
        let ctx = UserCtx { uid: 1000, gid: 1000, groups: vec![1000, 50] };
        let st = Stat { dev: 1, ino: 1, mode: libc::S_IFDIR as u32 | 0o750, uid: 1000, gid: 50, size: 0, mtime: 0 };
        let r = ctx.access_rights(&st, false);
        assert_eq!(r >> 24, AR_UOWN | AR_UREAD | AR_UWRITE | AR_USEARCH);
        assert_eq!(r & 0xFF, AR_UREAD | AR_UWRITE | AR_USEARCH);
        assert_eq!((r >> 8) & 0xFF, AR_UREAD | AR_USEARCH);
        assert_eq!((r >> 16) & 0xFF, 0);
        let other = UserCtx { uid: 2000, gid: 2000, groups: vec![2000] };
        assert_eq!(other.access_rights(&st, false) >> 24, 0);
        assert_eq!(ctx.access_rights(&st, true) >> 24 & AR_UWRITE, 0);
    }
}

//! Packing of volume, file and directory parameter blocks.

use super::buf::Writer;
use super::consts::*;
use crate::vfs::adouble::{Meta, DATE_START, FINDER_FLAG_INVISIBLE};
use crate::vfs::fork::AFP2_MAX_FORK;
use crate::vfs::{Obj, UserCtx, Volume};

const FILE_ATTR_MASK: u16 =
    ATTR_INVISIBLE | ATTR_MULTIUSER | ATTR_SYSTEM | ATTR_NOWRITE | ATTR_BACKUP | ATTR_NORENAME | ATTR_NODELETE | ATTR_NOCOPY;
const DIR_ATTR_MASK: u16 = ATTR_INVISIBLE | ATTR_SYSTEM | ATTR_BACKUP | ATTR_NORENAME | ATTR_NODELETE;

pub struct OpenState {
    pub data_open: bool,
    pub rsrc_open: bool,
}

fn date_max(a: u32, b: u32) -> u32 {
    if (a as i32) >= (b as i32) {
        a
    } else {
        b
    }
}

pub fn display_attr(vol: &Volume, obj: &Obj, m: &Meta, is_dir: bool) -> u16 {
    let mask = if is_dir { DIR_ATTR_MASK } else { FILE_ATTR_MASK };
    let mut a = m.attr() & mask;
    if m.finder_flags() & FINDER_FLAG_INVISIBLE != 0 {
        a |= ATTR_INVISIBLE;
    }
    if vol.opts.invisible_dots && obj.unix_name.first() == Some(&b'.') {
        a |= ATTR_INVISIBLE;
    }
    a
}

fn finder_info_out(m: &Meta, attr: u16) -> [u8; 32] {
    let mut fi = m.finder_info;
    if attr & ATTR_INVISIBLE != 0 {
        let f = u16::from_be_bytes([fi[8], fi[9]]) | FINDER_FLAG_INVISIBLE;
        fi[8..10].copy_from_slice(&f.to_be_bytes());
    }
    fi
}

fn create_date(vol: &Volume, obj: &Obj, m: &Meta) -> u32 {
    if let Some(d) = m.dates {
        if d[0] != 0 {
            return d[0];
        }
    }
    unix_to_afp_date(vol.fs.birth_time(&obj.path).unwrap_or(obj.st.mtime).min(obj.st.mtime))
}

fn mod_date(obj: &Obj, m: &Meta) -> u32 {
    let st = unix_to_afp_date(obj.st.mtime);
    match m.dates {
        Some(d) if d[1] != 0 => date_max(st, d[1]),
        _ => st,
    }
}

fn backup_date(m: &Meta) -> u32 {
    match m.dates {
        Some(d) if d[2] != 0 => d[2],
        _ => DATE_START,
    }
}

/// Short name for ProDOS/MS-DOS style clients: the long name cut to 12
/// bytes.
fn short_name(long: &[u8]) -> &[u8] {
    &long[..long.len().min(12)]
}

pub fn pack_file(vol: &Volume, obj: &Obj, bitmap: u16, open: &OpenState, w: &mut Writer) {
    let start = w.len();
    let need_meta = bitmap & (FIL_BIT_ATTR | FIL_BIT_CDATE | FIL_BIT_MDATE | FIL_BIT_BDATE | FIL_BIT_FINFO) != 0;
    let m = if need_meta { vol.meta_or_default(obj) } else { Meta::default() };
    let attr = display_attr(vol, obj, &m, false);
    let mut name_slots: Vec<(usize, Vec<u8>)> = Vec::new();
    let long = vol.mac_name(obj);
    for bit in 0..16 {
        let b = 1u16 << bit;
        if bitmap & b == 0 {
            continue;
        }
        match b {
            FIL_BIT_ATTR => {
                let mut a = attr;
                if open.data_open {
                    a |= ATTR_DOPEN;
                }
                if open.rsrc_open {
                    a |= ATTR_ROPEN;
                }
                w.u16(a);
            }
            FIL_BIT_PDID => {
                w.u32(obj.parent);
            }
            FIL_BIT_CDATE => {
                w.u32(create_date(vol, obj, &m));
            }
            FIL_BIT_MDATE => {
                w.u32(mod_date(obj, &m));
            }
            FIL_BIT_BDATE => {
                w.u32(backup_date(&m));
            }
            FIL_BIT_FINFO => {
                w.bytes(&finder_info_out(&m, attr));
            }
            FIL_BIT_LNAME => {
                name_slots.push((w.len(), long.clone()));
                w.u16(0);
            }
            FIL_BIT_SNAME => {
                name_slots.push((w.len(), short_name(&long).to_vec()));
                w.u16(0);
            }
            FIL_BIT_FNUM => {
                w.u32(obj.id);
            }
            FIL_BIT_DFLEN => {
                w.u32(obj.st.size.min(AFP2_MAX_FORK) as u32);
            }
            FIL_BIT_RFLEN => {
                w.u32(vol.backend.rfork_len(&vol.fs, &obj.path).min(AFP2_MAX_FORK) as u32);
            }
            FIL_BIT_PDINFO => {
                w.bytes(&[0u8; 6]);
            }
            _ => {}
        }
    }
    for (pos, name) in name_slots {
        let off = (w.len() - start) as u16;
        w.put_u16_at(pos, off);
        w.pstring(&name);
    }
}

pub fn pack_dir(vol: &Volume, ctx: &UserCtx, obj: &Obj, bitmap: u16, w: &mut Writer) {
    let start = w.len();
    let need_meta = bitmap & (DIR_BIT_ATTR | DIR_BIT_CDATE | DIR_BIT_MDATE | DIR_BIT_BDATE | DIR_BIT_FINFO) != 0;
    let m = if need_meta { vol.meta_or_default(obj) } else { Meta::default() };
    let attr = display_attr(vol, obj, &m, true);
    let mut name_slots: Vec<(usize, Vec<u8>)> = Vec::new();
    let long = vol.mac_name(obj);
    for bit in 0..16 {
        let b = 1u16 << bit;
        if bitmap & b == 0 {
            continue;
        }
        match b {
            DIR_BIT_ATTR => {
                w.u16(attr);
            }
            DIR_BIT_PDID => {
                w.u32(obj.parent);
            }
            DIR_BIT_CDATE => {
                let d = if obj.id == DIRID_ROOT { vol.create_date } else { create_date(vol, obj, &m) };
                w.u32(d);
            }
            DIR_BIT_MDATE => {
                w.u32(mod_date(obj, &m));
            }
            DIR_BIT_BDATE => {
                w.u32(backup_date(&m));
            }
            DIR_BIT_FINFO => {
                w.bytes(&finder_info_out(&m, attr));
            }
            DIR_BIT_LNAME => {
                name_slots.push((w.len(), long.clone()));
                w.u16(0);
            }
            DIR_BIT_SNAME => {
                name_slots.push((w.len(), short_name(&long).to_vec()));
                w.u16(0);
            }
            DIR_BIT_DID => {
                w.u32(obj.id);
            }
            DIR_BIT_OFFCNT => {
                w.u16(vol.offspring(&obj.path));
            }
            DIR_BIT_UID => {
                w.u32(obj.st.uid);
            }
            DIR_BIT_GID => {
                w.u32(obj.st.gid);
            }
            DIR_BIT_ACCESS => {
                w.u32(ctx.access_rights(&obj.st, vol.read_only));
            }
            DIR_BIT_PDINFO => {
                w.bytes(&[0u8; 6]);
            }
            _ => {}
        }
    }
    for (pos, name) in name_slots {
        let off = (w.len() - start) as u16;
        w.put_u16_at(pos, off);
        w.pstring(&name);
    }
}

pub fn pack_vol(vol: &Volume, bitmap: u16, root_mtime: i64, w: &mut Writer) {
    let start = w.len();
    let mut name_slot = None;
    let (total, free, bsize) = if bitmap & (VOL_BIT_BFREE | VOL_BIT_BTOTAL | VOL_BIT_XBFREE | VOL_BIT_XBTOTAL | VOL_BIT_BSIZE) != 0 {
        vol.space()
    } else {
        (0, 0, 4096)
    };
    let cap32 = if vol.opts.legacy_volume_size { 0x7FFF_FFFFu64 } else { 0xFFFF_FFFFu64 };
    for bit in 0..16 {
        let b = 1u16 << bit;
        if bitmap & b == 0 {
            continue;
        }
        match b {
            VOL_BIT_ATTR => {
                let mut a = 0u16;
                if vol.read_only {
                    a |= VOLATTR_RO;
                }
                if vol.opts.password.is_some() {
                    a |= VOLATTR_PASSWD;
                }
                w.u16(a);
            }
            VOL_BIT_SIG => {
                w.u16(2); // fixed directory IDs
            }
            VOL_BIT_CDATE => {
                w.u32(vol.create_date);
            }
            VOL_BIT_MDATE => {
                w.u32(unix_to_afp_date(root_mtime.max(vol.last_change)));
            }
            VOL_BIT_BDATE => {
                w.u32(DATE_START);
            }
            VOL_BIT_VID => {
                w.u16(vol.vid);
            }
            VOL_BIT_BFREE => {
                w.u32(free.min(cap32) as u32);
            }
            VOL_BIT_BTOTAL => {
                w.u32(total.min(cap32) as u32);
            }
            VOL_BIT_NAME => {
                name_slot = Some(w.len());
                w.u16(0);
            }
            VOL_BIT_XBFREE => {
                w.u64(free);
            }
            VOL_BIT_XBTOTAL => {
                w.u64(total);
            }
            VOL_BIT_BSIZE => {
                w.u32(bsize);
            }
            _ => {}
        }
    }
    if let Some(pos) = name_slot {
        let off = (w.len() - start) as u16;
        w.put_u16_at(pos, off);
        w.pstring(&vol.name_mac);
    }
}

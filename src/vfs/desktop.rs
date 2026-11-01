//! Desktop database (icons and application mappings) stored in
//! `.AppleDesktop` at the volume root.
//!
//! Layout:
//! - `.AppleDesktop/icons/CCCCCCCC-TTTTTTTT-II` (hex creator, type, icon
//!   type): 4-byte tag followed by the icon bitmap.
//! - `.AppleDesktop/appl/CCCCCCCC`: one line per application,
//!   `TAGHEX PATHHEX`, where PATHHEX is the hex-encoded path relative to
//!   the volume root.
//!
//! Writes are best effort: when the database is not writable by the
//! current user the operation is reported as successful, because the
//! Finder treats the desktop database as a cache.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use super::fs::Fs;

pub const DESKTOP_DIR: &str = ".AppleDesktop";
const MAX_ICON: usize = 4096;
const MAX_APPL_FILE: u64 = 256 * 1024;

fn hex4(b: &[u8; 4]) -> String {
    format!("{:02X}{:02X}{:02X}{:02X}", b[0], b[1], b[2], b[3])
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02X}", x)).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || s.len() > 8192 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub struct Desktop<'a> {
    fs: &'a Fs,
    base: PathBuf,
}

pub struct IconInfo {
    pub tag: u32,
    pub ftype: [u8; 4],
    pub itype: u8,
    pub size: u16,
}

impl<'a> Desktop<'a> {
    pub fn new(fs: &'a Fs) -> Desktop<'a> {
        Desktop { fs, base: fs.root.join(DESKTOP_DIR) }
    }

    fn ensure(&self, sub: &str) -> io::Result<PathBuf> {
        let d = self.base.join(sub);
        self.fs.ensure_dir(&self.base, 0o777)?;
        self.fs.ensure_dir(&d, 0o777)?;
        Ok(d)
    }

    fn write_file(&self, path: &std::path::Path, data: &[u8]) -> io::Result<()> {
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        let _ = self.fs.unlink(&tmp);
        {
            let mut f = self.fs.create(&tmp, 0o666, false)?;
            f.write_all(data)?;
        }
        self.fs.rename(&tmp, path)
    }

    fn read_file(&self, path: &std::path::Path, max: u64) -> Option<Vec<u8>> {
        let f = self.fs.open_read(path).ok()?;
        let md = f.metadata().ok()?;
        if !md.is_file() || md.len() > max {
            return None;
        }
        let mut buf = Vec::with_capacity(md.len() as usize);
        f.take(max).read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    pub fn add_icon(&self, creator: &[u8; 4], ftype: &[u8; 4], itype: u8, tag: u32, data: &[u8]) {
        if data.len() > MAX_ICON {
            return;
        }
        let res = self.ensure("icons").and_then(|d| {
            let mut buf = Vec::with_capacity(4 + data.len());
            buf.extend_from_slice(&tag.to_be_bytes());
            buf.extend_from_slice(data);
            self.write_file(&d.join(format!("{}-{}-{:02X}", hex4(creator), hex4(ftype), itype)), &buf)
        });
        if let Err(e) = res {
            log::debug!("desktop: cannot store icon: {}", e);
        }
    }

    pub fn get_icon(&self, creator: &[u8; 4], ftype: &[u8; 4], itype: u8) -> Option<(u32, Vec<u8>)> {
        let p = self.base.join("icons").join(format!("{}-{}-{:02X}", hex4(creator), hex4(ftype), itype));
        let b = self.read_file(&p, (MAX_ICON + 4) as u64)?;
        if b.len() < 4 {
            return None;
        }
        Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]), b[4..].to_vec()))
    }

    /// The `index`th (1-based) icon registered for a creator.
    pub fn icon_info(&self, creator: &[u8; 4], index: u16) -> Option<IconInfo> {
        let prefix = format!("{}-", hex4(creator));
        let mut names: Vec<String> = self
            .fs
            .read_dir(&self.base.join("icons"))
            .ok()?
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(&prefix) && n.len() == prefix.len() + 11)
            .collect();
        names.sort();
        let n = names.get((index as usize).checked_sub(1)?)?;
        let t = unhex(&n[9..17])?;
        let itype = u8::from_str_radix(&n[18..20], 16).ok()?;
        let mut ftype = [0u8; 4];
        ftype.copy_from_slice(&t);
        let (tag, data) = self.get_icon(creator, &ftype, itype)?;
        Some(IconInfo { tag, ftype, itype, size: data.len() as u16 })
    }

    fn appl_entries(&self, creator: &[u8; 4]) -> Vec<(u32, Vec<u8>)> {
        let p = self.base.join("appl").join(hex4(creator));
        let b = match self.read_file(&p, MAX_APPL_FILE) {
            Some(b) => b,
            None => return Vec::new(),
        };
        String::from_utf8_lossy(&b)
            .lines()
            .filter_map(|l| {
                let (t, p) = l.split_once(' ')?;
                Some((u32::from_str_radix(t, 16).ok()?, unhex(p.trim())?))
            })
            .collect()
    }

    fn store_appl(&self, creator: &[u8; 4], entries: &[(u32, Vec<u8>)]) {
        let res = self.ensure("appl").and_then(|d| {
            let mut s = String::new();
            for (t, p) in entries.iter().take(1024) {
                s.push_str(&format!("{:08X} {}\n", t, hex(p)));
            }
            self.write_file(&d.join(hex4(creator)), s.as_bytes())
        });
        if let Err(e) = res {
            log::debug!("desktop: cannot store APPL mapping: {}", e);
        }
    }

    /// `rel` is the application's path relative to the volume root.
    pub fn add_appl(&self, creator: &[u8; 4], tag: u32, rel: &[u8]) {
        let mut e = self.appl_entries(creator);
        e.retain(|(_, p)| p != rel);
        e.insert(0, (tag, rel.to_vec()));
        self.store_appl(creator, &e);
    }

    pub fn remove_appl(&self, creator: &[u8; 4], rel: &[u8]) -> bool {
        let mut e = self.appl_entries(creator);
        let before = e.len();
        e.retain(|(_, p)| p != rel);
        if e.len() == before {
            return false;
        }
        self.store_appl(creator, &e);
        true
    }

    pub fn appls(&self, creator: &[u8; 4]) -> Vec<(u32, Vec<u8>)> {
        self.appl_entries(creator)
    }
}

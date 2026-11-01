//! Metadata storage backends (where Finder info, comments, dates and
//! resource forks live). All file access goes through [`Fs`], so it is
//! confined to the volume.

use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::adouble::{self, Meta};
use super::fs::Fs;

pub const EA_META: &str = "org.netatalk.Metadata";
pub const APPLEDOUBLE_DIR: &str = ".AppleDouble";
pub const PARENT_NAME: &str = ".Parent";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ea,
    AppleDouble,
    None,
}

fn parent_and_name(p: &Path) -> Option<(&Path, &std::ffi::OsStr)> {
    Some((p.parent()?, p.file_name()?))
}

fn sidecar_osx(p: &Path) -> Option<PathBuf> {
    let (dir, name) = parent_and_name(p)?;
    let mut n = std::ffi::OsString::from("._");
    n.push(name);
    Some(dir.join(n))
}

fn sidecar_v2(p: &Path, is_dir: bool) -> Option<PathBuf> {
    if is_dir {
        return Some(p.join(APPLEDOUBLE_DIR).join(PARENT_NAME));
    }
    let (dir, name) = parent_and_name(p)?;
    Some(dir.join(APPLEDOUBLE_DIR).join(name))
}

fn read_prefix(fs: &Fs, p: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    let f = match fs.open_read(p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !f.metadata()?.is_file() {
        return Ok(None);
    }
    let mut buf = Vec::with_capacity(max);
    f.take(max as u64).read_to_end(&mut buf)?;
    Ok(Some(buf))
}

impl Backend {
    /// Names reserved for metadata, never shown to or creatable by clients.
    pub fn is_reserved_name(name: &[u8]) -> bool {
        name.starts_with(b"._")
            || name == b".AppleDouble"
            || name == b".AppleDB"
            || name == b".AppleDesktop"
            || name == b".Parent"
    }

    pub fn read(&self, fs: &Fs, p: &Path, is_dir: bool) -> Option<Meta> {
        match self {
            Backend::Ea => match fs.get_xattr(p, EA_META, 1024) {
                Ok(Some(b)) => adouble::parse_meta(&b),
                _ => None,
            },
            Backend::AppleDouble => {
                let sc = sidecar_v2(p, is_dir)?;
                match read_prefix(fs, &sc, 1024) {
                    Ok(Some(b)) => adouble::parse_meta(&b),
                    _ => None,
                }
            }
            Backend::None => None,
        }
    }

    pub fn write(&self, fs: &Fs, p: &Path, is_dir: bool, m: &Meta) -> io::Result<()> {
        match self {
            Backend::Ea => {
                fs.set_xattr(p, EA_META, &adouble::serialize_ea(m))?;
                if !is_dir {
                    // Keep Finder info in an existing ._ file in sync for
                    // Mac OS X clients and Samba.
                    if let Some(sc) = sidecar_osx(p) {
                        if let Ok(f) = fs.open(&sc, libc::O_RDWR, 0) {
                            let mut hdr = vec![0u8; 1024];
                            if let Ok(n) = f.read_at(&mut hdr, 0) {
                                hdr.truncate(n);
                                if let Some(h) = adouble::parse_header(&hdr) {
                                    if let Some(e) = h.entry(adouble::EID_FINDERI) {
                                        if e.len >= 32 && (e.off as usize) + 32 <= hdr.len() {
                                            let _ = f.write_at(&m.finder_info, e.off as u64);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
            Backend::AppleDouble => {
                let sc = sidecar_v2(p, is_dir).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
                fs.ensure_dir(sc.parent().unwrap(), 0o777)?;
                write_v2_header(fs, &sc, m)
            }
            Backend::None => Ok(()),
        }
    }

    /// Path of the file holding the resource fork of data file `p`.
    pub fn rfork_path(&self, p: &Path) -> Option<PathBuf> {
        match self {
            Backend::Ea => sidecar_osx(p),
            Backend::AppleDouble => sidecar_v2(p, false),
            Backend::None => None,
        }
    }

    /// Create a fresh sidecar holding an empty resource fork.
    pub fn create_rfork(&self, fs: &Fs, p: &Path, m: &Meta, mode: u32) -> io::Result<()> {
        let sc = self.rfork_path(p).ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTSUP))?;
        let hdr = match self {
            Backend::Ea => adouble::serialize_osx(&m.finder_info, 0),
            Backend::AppleDouble => {
                fs.ensure_dir(sc.parent().unwrap(), 0o777)?;
                adouble::serialize_v2(m, 0)
            }
            Backend::None => return Err(io::Error::from_raw_os_error(libc::ENOTSUP)),
        };
        let f = fs.create(&sc, mode & 0o666, false)?;
        f.write_all_at(&hdr, 0)
    }

    /// Size of the resource fork of `p` (0 if none).
    pub fn rfork_len(&self, fs: &Fs, p: &Path) -> u64 {
        let sc = match self.rfork_path(p) {
            Some(s) => s,
            None => return 0,
        };
        match read_prefix(fs, &sc, 1024) {
            Ok(Some(b)) => adouble::rfork_location(&b).map(|l| l.len).unwrap_or(0),
            _ => 0,
        }
    }

    /// Move companion files after the data file moved from `from` to `to`.
    pub fn renamed(&self, fs: &Fs, from: &Path, to: &Path, is_dir: bool) {
        if is_dir {
            return; // metadata lives in or on the directory itself
        }
        let (a, b) = match (self.rfork_path(from), self.rfork_path(to)) {
            (Some(a), Some(b)) => (a, b),
            _ => return,
        };
        if !fs.exists(&a) {
            return;
        }
        if *self == Backend::AppleDouble {
            if let Some(parent) = b.parent() {
                let _ = fs.ensure_dir(parent, 0o777);
            }
        }
        if let Err(e) = fs.rename(&a, &b) {
            log::warn!("could not move {} to {}: {}", a.display(), b.display(), e);
        }
    }

    /// Remove companion files of a deleted file.
    pub fn deleted(&self, fs: &Fs, p: &Path, is_dir: bool) {
        if is_dir {
            return;
        }
        if let Some(sc) = self.rfork_path(p) {
            match fs.unlink(&sc) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => log::warn!("could not remove {}: {}", sc.display(), e),
            }
        }
    }

    /// Swap companion files of two data files (FPExchangeFiles).
    pub fn swap_companions(&self, fs: &Fs, a: &Path, b: &Path) -> io::Result<()> {
        let (sa, sb) = match (self.rfork_path(a), self.rfork_path(b)) {
            (Some(x), Some(y)) => (x, y),
            _ => return Ok(()),
        };
        match (fs.exists(&sa), fs.exists(&sb)) {
            (false, false) => Ok(()),
            (true, false) => fs.rename(&sa, &sb),
            (false, true) => fs.rename(&sb, &sa),
            (true, true) => match fs.exchange(&sa, &sb) {
                Ok(()) => Ok(()),
                Err(_) => {
                    let tmp = sa.with_file_name(format!(".afprust-swap-{}", std::process::id()));
                    fs.rename(&sa, &tmp)?;
                    fs.rename(&sb, &sa)?;
                    fs.rename(&tmp, &sb)
                }
            },
        }
    }

    /// Entries that may remain in a directory being deleted and that we
    /// remove on the client's behalf.
    pub fn removable_leftover(&self, name: &[u8]) -> bool {
        name.starts_with(b"._") || name == b".AppleDouble" || name == b".AppleDB" || name == b".AppleDesktop"
    }
}

fn write_v2_header(fs: &Fs, sc: &Path, m: &Meta) -> io::Result<()> {
    let f = match fs.open(sc, libc::O_RDWR, 0) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs.create(sc, 0o666, true)?,
        Err(e) => return Err(e),
    };
    let mut hdr = vec![0u8; 1024];
    let n = f.read_at(&mut hdr, 0)?;
    hdr.truncate(n);
    match adouble::rfork_location(&hdr) {
        Some(l) if l.offset == adouble::RFORK_OFF_V2 => f.write_all_at(&adouble::serialize_v2(m, l.len), 0),
        Some(l) => {
            // Foreign layout: relocate the resource fork to offset 741.
            let len = l.len.min(64 * 1024 * 1024) as usize;
            let mut data = vec![0u8; len];
            f.read_exact_at(&mut data, l.offset)?;
            f.write_all_at(&adouble::serialize_v2(m, len as u64), 0)?;
            f.write_all_at(&data, adouble::RFORK_OFF_V2)?;
            f.set_len(adouble::RFORK_OFF_V2 + len as u64)
        }
        None => {
            f.set_len(0)?;
            f.write_all_at(&adouble::serialize_v2(m, 0), 0)
        }
    }
}

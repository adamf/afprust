//! Open forks (FPOpenFork and friends).
//!
//! Share modes (deny read / deny write) and byte-range locks are enforced
//! across sessions with Linux open-file-description locks. Share modes use
//! a band of lock offsets at the top of the data file, the same scheme as
//! netatalk, so they do not interfere with client byte-range locks.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::adouble::{self, RforkLoc};
use super::fs::Fs;
use super::sys::{self, LockKind};
use crate::afp::consts::*;

const LOCK_BASE: u64 = 0x7FFF_FFFF_FFFF_FFFF - 9;
const OPEN_WR: u64 = LOCK_BASE;
const OPEN_RD: u64 = LOCK_BASE + 1;
const RSRC_OPEN_WR: u64 = LOCK_BASE + 2;
const RSRC_OPEN_RD: u64 = LOCK_BASE + 3;
const DENY_WR: u64 = LOCK_BASE + 4;
const DENY_RD: u64 = LOCK_BASE + 5;
const RSRC_DENY_WR: u64 = LOCK_BASE + 6;
const RSRC_DENY_RD: u64 = LOCK_BASE + 7;
/// Client byte-range locks must stay below the share-mode band.
pub const BYTELOCK_MAX: u64 = LOCK_BASE - 1;
pub const MAX_LOCKS_PER_FORK: usize = 256;

/// Largest fork size AFP 2.x can express.
pub const AFP2_MAX_FORK: u64 = 0x7FFF_FFFF;

pub enum ForkIo {
    Data(File),
    Rsrc { file: File, loc: RforkLoc },
    /// Resource fork that does not exist and was opened read-only.
    EmptyRsrc,
}

pub struct Fork {
    pub refnum: u16,
    pub vid: u16,
    pub id: u32,
    pub path: PathBuf,
    pub is_rsrc: bool,
    pub access: u16,
    pub io: ForkIo,
    /// Descriptor on the data file that holds the share-mode locks.
    lock_fd: Option<File>,
    pub locks: Vec<(u64, u64)>,
    pub dirty: bool,
}

/// Open for I/O. O_NONBLOCK keeps a FIFO swapped in by someone else from
/// blocking the session; it has no effect on regular files.
fn open_for(fs: &Fs, p: &Path, write: bool) -> io::Result<File> {
    let acc = if write { libc::O_RDWR } else { libc::O_RDONLY };
    let f = fs.open(p, acc | libc::O_NONBLOCK, 0)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EISDIR));
    }
    Ok(f)
}

impl Fork {
    /// Open a fork. `rfork_path` is where the resource fork lives (None if
    /// the volume stores no resource forks).
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        fs: &Fs,
        refnum: u16,
        vid: u16,
        id: u32,
        path: &Path,
        is_rsrc: bool,
        access: u16,
        rfork_path: Option<PathBuf>,
        create_rfork: &dyn Fn() -> io::Result<()>,
    ) -> AfpResult<Fork> {
        let want_write = access & OPENACC_WR != 0;

        // Descriptor for share-mode locks. Write access is not needed for
        // read locks; failure (e.g. a write-only file) just skips them.
        let lock_fd = match open_for(fs, path, false) {
            Ok(f) => Some(f),
            Err(e) if e.raw_os_error() == Some(libc::EISDIR) => return Err(AfpError::ObjectTypeErr),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(AfpError::ObjectNotFound),
            Err(_) => None,
        };
        if let Some(f) = &lock_fd {
            check_share_modes(f, is_rsrc, access)?;
        }

        let io = if !is_rsrc {
            let f = match open_for(fs, path, want_write) {
                Ok(f) => f,
                Err(e) if e.raw_os_error() == Some(libc::EISDIR) => return Err(AfpError::ObjectTypeErr),
                Err(e) => return Err(AfpError::from_io(&e)),
            };
            ForkIo::Data(f)
        } else {
            match rfork_path {
                None => {
                    if want_write {
                        return Err(AfpError::AccessDenied);
                    }
                    ForkIo::EmptyRsrc
                }
                Some(rp) => match open_rsrc(fs, &rp, want_write) {
                    Ok(Some(x)) => x,
                    Ok(None) if !want_write => ForkIo::EmptyRsrc,
                    Ok(None) => {
                        // Writer and no sidecar yet: create one.
                        match create_rfork() {
                            Ok(()) => {}
                            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(e) => return Err(AfpError::from_io(&e)),
                        }
                        match open_rsrc(fs, &rp, true)? {
                            Some(x) => x,
                            None => return Err(AfpError::MiscErr),
                        }
                    }
                    Err(e) => return Err(e),
                },
            }
        };

        let fork = Fork {
            refnum,
            vid,
            id,
            path: path.to_path_buf(),
            is_rsrc,
            access,
            io,
            lock_fd,
            locks: Vec::new(),
            dirty: false,
        };
        fork.place_share_locks();
        Ok(fork)
    }

    fn place_share_locks(&self) {
        let f = match &self.lock_fd {
            Some(f) => f,
            None => return,
        };
        let fd = f.as_raw_fd();
        let (rd, wr, drd, dwr) = if self.is_rsrc {
            (RSRC_OPEN_RD, RSRC_OPEN_WR, RSRC_DENY_RD, RSRC_DENY_WR)
        } else {
            (OPEN_RD, OPEN_WR, DENY_RD, DENY_WR)
        };
        let set = |off: u64| {
            let _ = sys::lock_set(fd, LockKind::Read, off, 1);
        };
        if self.access & OPENACC_RD != 0 {
            set(rd);
        }
        if self.access & OPENACC_WR != 0 {
            set(wr);
        }
        if self.access & OPENACC_DRD != 0 {
            set(drd);
        }
        if self.access & OPENACC_DWR != 0 {
            set(dwr);
        }
    }

    pub fn writable(&self) -> bool {
        self.access & OPENACC_WR != 0
    }

    pub fn len(&self) -> io::Result<u64> {
        match &self.io {
            ForkIo::Data(f) => Ok(f.metadata()?.len()),
            ForkIo::Rsrc { loc, .. } => Ok(loc.len),
            ForkIo::EmptyRsrc => Ok(0),
        }
    }

    pub fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        match &self.io {
            ForkIo::Data(f) => read_full(f, buf, off),
            ForkIo::Rsrc { file, loc } => {
                if off >= loc.len {
                    return Ok(0);
                }
                let n = ((loc.len - off) as usize).min(buf.len());
                read_full(file, &mut buf[..n], loc.offset + off)
            }
            ForkIo::EmptyRsrc => Ok(0),
        }
    }

    pub fn write_at(&mut self, data: &[u8], off: u64) -> AfpResult<()> {
        if !self.writable() {
            return Err(AfpError::AccessDenied);
        }
        let end = off.checked_add(data.len() as u64).ok_or(AfpError::ParamErr)?;
        if end > AFP2_MAX_FORK + 1 {
            return Err(AfpError::DiskFull);
        }
        self.dirty = true;
        match &mut self.io {
            ForkIo::Data(f) => f.write_all_at(data, off).map_err(|e| AfpError::from_io(&e)),
            ForkIo::Rsrc { file, loc } => {
                file.write_all_at(data, loc.offset + off).map_err(|e| AfpError::from_io(&e))?;
                if end > loc.len {
                    loc.len = end;
                    write_len_field(file, loc)?;
                }
                Ok(())
            }
            ForkIo::EmptyRsrc => Err(AfpError::AccessDenied),
        }
    }

    pub fn set_len(&mut self, len: u64) -> AfpResult<()> {
        if !self.writable() {
            return Err(AfpError::AccessDenied);
        }
        if len > AFP2_MAX_FORK {
            return Err(AfpError::DiskFull);
        }
        self.dirty = true;
        match &mut self.io {
            ForkIo::Data(f) => f.set_len(len).map_err(|e| AfpError::from_io(&e)),
            ForkIo::Rsrc { file, loc } => {
                file.set_len(loc.offset + len).map_err(|e| AfpError::from_io(&e))?;
                loc.len = len;
                write_len_field(file, loc)
            }
            ForkIo::EmptyRsrc => Err(AfpError::AccessDenied),
        }
    }

    pub fn flush(&self) -> io::Result<()> {
        match &self.io {
            ForkIo::Data(f) | ForkIo::Rsrc { file: f, .. } => f.sync_data(),
            ForkIo::EmptyRsrc => Ok(()),
        }
    }

    fn io_fd(&self) -> Option<(i32, u64, bool)> {
        match &self.io {
            ForkIo::Data(f) => Some((f.as_raw_fd(), 0, self.writable())),
            ForkIo::Rsrc { file, loc } => Some((file.as_raw_fd(), loc.offset, self.writable())),
            ForkIo::EmptyRsrc => None,
        }
    }

    /// FPByteRangeLock lock/unlock. `start` and `len` are already resolved
    /// to absolute fork offsets.
    pub fn byte_lock(&mut self, start: u64, len: u64, unlock: bool) -> AfpResult<()> {
        if len == 0 {
            return Err(AfpError::ParamErr);
        }
        let end = start.checked_add(len).ok_or(AfpError::ParamErr)?;
        if end > BYTELOCK_MAX {
            return Err(AfpError::ParamErr);
        }
        if unlock {
            let pos = self.locks.iter().position(|&(s, l)| s == start && (l == len || len == u64::MAX))
                .ok_or(AfpError::RangeNotLocked)?;
            let (s, l) = self.locks.remove(pos);
            if let Some((fd, base, _)) = self.io_fd() {
                let _ = sys::lock_set(fd, LockKind::Unlock, base + s, l);
            }
            return Ok(());
        }
        if self.locks.iter().any(|&(s, l)| start < s + l && s < end) {
            return Err(AfpError::RangeOverlap);
        }
        if self.locks.len() >= MAX_LOCKS_PER_FORK {
            return Err(AfpError::NoMoreLocks);
        }
        if let Some((fd, base, writable)) = self.io_fd() {
            let kind = if writable { LockKind::Write } else { LockKind::Read };
            match sys::lock_set(fd, kind, base + start, len) {
                Ok(true) => {}
                Ok(false) => return Err(AfpError::LockErr),
                Err(e) => {
                    log::debug!("byte range lock: {}", e);
                    return Err(AfpError::LockErr);
                }
            }
        }
        self.locks.push((start, len));
        Ok(())
    }

    /// Is a range locked by another session (reads/writes must fail)?
    pub fn range_conflicts(&self, start: u64, len: u64, write: bool) -> bool {
        if len == 0 {
            return false;
        }
        if self.locks.iter().any(|&(s, l)| start < s + l && s < start + len) {
            return false; // our own lock
        }
        match self.io_fd() {
            Some((fd, base, _)) => {
                let kind = if write { LockKind::Write } else { LockKind::Read };
                sys::lock_conflicts(fd, kind, base + start, len.min(BYTELOCK_MAX - start)).unwrap_or(false)
            }
            None => false,
        }
    }
}

fn read_full(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match f.read_at(&mut buf[done..], off + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

fn write_len_field(f: &File, loc: &RforkLoc) -> AfpResult<()> {
    let v = (loc.len.min(u32::MAX as u64) as u32).to_be_bytes();
    f.write_all_at(&v, loc.len_field).map_err(|e| AfpError::from_io(&e))
}

/// Open an existing sidecar. Ok(None) if it does not exist.
fn open_rsrc(fs: &Fs, p: &Path, write: bool) -> AfpResult<Option<ForkIo>> {
    let file = match open_for(fs, p, write) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::EISDIR) => return Err(AfpError::MiscErr),
        Err(e) => return Err(AfpError::from_io(&e)),
    };
    let md = file.metadata()?;
    let mut hdr = vec![0u8; 1024];
    let n = read_full(&file, &mut hdr, 0)?;
    hdr.truncate(n);
    match adouble::rfork_location(&hdr) {
        Some(mut loc) => {
            // Clamp a length field that claims more than the file holds.
            let avail = md.len().saturating_sub(loc.offset);
            if loc.len > avail {
                loc.len = avail;
            }
            Ok(Some(ForkIo::Rsrc { file, loc }))
        }
        None => {
            if n < adouble::HEADER_LEN && write {
                // Empty/truncated sidecar: reinitialize it.
                let hdr = adouble::serialize_osx(&[0u8; 32], 0);
                file.set_len(0)?;
                file.write_all_at(&hdr, 0)?;
                let loc = adouble::rfork_location(&hdr).ok_or(AfpError::MiscErr)?;
                return Ok(Some(ForkIo::Rsrc { file, loc }));
            }
            log::warn!("{}: not a usable AppleDouble file", p.display());
            if write {
                Err(AfpError::MiscErr)
            } else {
                Ok(Some(ForkIo::EmptyRsrc))
            }
        }
    }
}

/// Check the requested access against share modes held by other forks.
fn check_share_modes(f: &File, is_rsrc: bool, access: u16) -> AfpResult<()> {
    let fd = f.as_raw_fd();
    let (rd, wr, drd, dwr) = if is_rsrc {
        (RSRC_OPEN_RD, RSRC_OPEN_WR, RSRC_DENY_RD, RSRC_DENY_WR)
    } else {
        (OPEN_RD, OPEN_WR, DENY_RD, DENY_WR)
    };
    let held = |off: u64| sys::lock_conflicts(fd, LockKind::Write, off, 1).unwrap_or(false);
    if access & OPENACC_RD != 0 && held(drd) {
        return Err(AfpError::DenyConflict);
    }
    if access & OPENACC_WR != 0 && held(dwr) {
        return Err(AfpError::DenyConflict);
    }
    if access & OPENACC_DRD != 0 && held(rd) {
        return Err(AfpError::DenyConflict);
    }
    if access & OPENACC_DWR != 0 && held(wr) {
        return Err(AfpError::DenyConflict);
    }
    Ok(())
}

/// Is the data or resource fork of `path` open anywhere (any session)?
pub fn fork_open_anywhere(fs: &Fs, path: &Path, rsrc: bool) -> bool {
    let f = match open_for(fs, path, false) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let fd = f.as_raw_fd();
    let (rd, wr) = if rsrc { (RSRC_OPEN_RD, RSRC_OPEN_WR) } else { (OPEN_RD, OPEN_WR) };
    sys::lock_conflicts(fd, LockKind::Write, rd, 1).unwrap_or(false)
        || sys::lock_conflicts(fd, LockKind::Write, wr, 1).unwrap_or(false)
}

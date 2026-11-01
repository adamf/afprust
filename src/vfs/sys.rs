//! Thin wrappers around platform syscalls not covered by std.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

#[cfg(target_os = "linux")]
fn xattr_name(name: &str) -> CString {
    CString::new(format!("user.{}", name)).unwrap()
}

#[cfg(target_os = "macos")]
fn xattr_name(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn is_noattr(e: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    {
        e.raw_os_error() == Some(libc::ENODATA)
    }
    #[cfg(target_os = "macos")]
    {
        e.raw_os_error() == Some(libc::ENOATTR)
    }
}

pub fn is_xattr_unsupported(e: &io::Error) -> bool {
    // ENOTSUP and EOPNOTSUPP are the same value on Linux but not on macOS.
    let code = e.raw_os_error();
    code == Some(libc::ENOTSUP) || code == Some(libc::EOPNOTSUPP)
}

/// Read an extended attribute without following symlinks. Ok(None) if the
/// attribute does not exist.
pub fn get_xattr(p: &Path, name: &str, max: usize) -> io::Result<Option<Vec<u8>>> {
    let cp = cpath(p)?;
    let cn = xattr_name(name);
    let mut buf = vec![0u8; max];
    // SAFETY: buf is valid for max bytes.
    #[cfg(target_os = "linux")]
    let r = unsafe { libc::lgetxattr(cp.as_ptr(), cn.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    #[cfg(target_os = "macos")]
    let r = unsafe {
        libc::getxattr(cp.as_ptr(), cn.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0, libc::XATTR_NOFOLLOW)
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        if is_noattr(&e) {
            return Ok(None);
        }
        if e.raw_os_error() == Some(libc::ERANGE) {
            // Larger than we are willing to read: treat as corrupt.
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        return Err(e);
    }
    buf.truncate(r as usize);
    Ok(Some(buf))
}

pub fn set_xattr(p: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let cp = cpath(p)?;
    let cn = xattr_name(name);
    // SAFETY: value is valid for its length.
    #[cfg(target_os = "linux")]
    let r = unsafe { libc::lsetxattr(cp.as_ptr(), cn.as_ptr(), value.as_ptr() as *const libc::c_void, value.len(), 0) };
    #[cfg(target_os = "macos")]
    let r = unsafe {
        libc::setxattr(cp.as_ptr(), cn.as_ptr(), value.as_ptr() as *const libc::c_void, value.len(), 0, libc::XATTR_NOFOLLOW)
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub struct FsSpace {
    pub total: u64,
    pub free: u64,
    pub block_size: u32,
}

pub fn statvfs(p: &Path) -> io::Result<FsSpace> {
    let cp = cpath(p)?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: s is a valid statvfs buffer.
    if unsafe { libc::statvfs(cp.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let frsize = if s.f_frsize > 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
    Ok(FsSpace {
        total: (s.f_blocks as u64).saturating_mul(frsize),
        free: (s.f_bavail as u64).saturating_mul(frsize),
        block_size: (s.f_bsize as u64).min(u32::MAX as u64) as u32,
    })
}

/// Set modification time (and leave atime) without following symlinks.
pub fn set_mtime(p: &Path, mtime: i64) -> io::Result<()> {
    let cp = cpath(p)?;
    let ts = [
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
        libc::timespec { tv_sec: mtime as libc::time_t, tv_nsec: 0 },
    ];
    // SAFETY: ts has two entries as required.
    let r = unsafe { libc::utimensat(libc::AT_FDCWD, cp.as_ptr(), ts.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// File birth time, if the filesystem records it.
pub fn birth_time(p: &Path) -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        let cp = cpath(p).ok()?;
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        // SAFETY: stx is a valid buffer.
        let r = unsafe {
            libc::statx(libc::AT_FDCWD, cp.as_ptr(), libc::AT_SYMLINK_NOFOLLOW, libc::STATX_BTIME, &mut stx)
        };
        if r == 0 && stx.stx_mask & libc::STATX_BTIME != 0 {
            return Some(stx.stx_btime.tv_sec);
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        std::fs::symlink_metadata(p).ok().map(|m| m.st_birthtime())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    Read,
    Write,
    Unlock,
}

/// Open-file-description locks (Linux): per open fd, not per process, so
/// closing another descriptor of the same file does not drop them, and two
/// forks opened by one session conflict with each other like they should.
#[cfg(target_os = "linux")]
mod locks {
    use super::*;
    const F_OFD_GETLK: libc::c_int = 36;
    const F_OFD_SETLK: libc::c_int = 37;

    fn flock(kind: LockKind, start: u64, len: u64) -> libc::flock {
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = match kind {
            LockKind::Read => libc::F_RDLCK,
            LockKind::Write => libc::F_WRLCK,
            LockKind::Unlock => libc::F_UNLCK,
        } as libc::c_short;
        fl.l_whence = libc::SEEK_SET as libc::c_short;
        fl.l_start = start.min(i64::MAX as u64) as libc::off_t;
        fl.l_len = len.min(i64::MAX as u64) as libc::off_t;
        fl.l_pid = 0;
        fl
    }

    /// Try to set a lock. Ok(false) if it conflicts with another holder.
    pub fn set(fd: RawFd, kind: LockKind, start: u64, len: u64) -> io::Result<bool> {
        let fl = flock(kind, start, len);
        // SAFETY: fl is a valid flock structure.
        let r = unsafe { libc::fcntl(fd, F_OFD_SETLK, &fl) };
        if r == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EACCES) => Ok(false),
            _ => Err(e),
        }
    }

    /// Would a lock of `kind` conflict with another holder?
    pub fn conflicts(fd: RawFd, kind: LockKind, start: u64, len: u64) -> io::Result<bool> {
        let mut fl = flock(kind, start, len);
        // SAFETY: fl is a valid flock structure.
        let r = unsafe { libc::fcntl(fd, F_OFD_GETLK, &mut fl) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fl.l_type != libc::F_UNLCK as libc::c_short)
    }
}

/// Without OFD locks (macOS development builds), cross-process locking is
/// not provided; in-session bookkeeping still applies.
#[cfg(not(target_os = "linux"))]
mod locks {
    use super::*;
    pub fn set(_fd: RawFd, _kind: LockKind, _start: u64, _len: u64) -> io::Result<bool> {
        Ok(true)
    }
    pub fn conflicts(_fd: RawFd, _kind: LockKind, _start: u64, _len: u64) -> io::Result<bool> {
        Ok(false)
    }
}

pub use locks::{conflicts as lock_conflicts, set as lock_set};

/// Probe whether user xattrs work on the filesystem holding `dir`.
pub fn xattrs_supported(dir: &Path) -> bool {
    match get_xattr(dir, "org.netatalk.Metadata", 1024) {
        Ok(_) => true,
        Err(e) if is_xattr_unsupported(&e) => false,
        // Permission problems etc. are not a lack of support.
        Err(_) => true,
    }
}

pub fn set_umask(m: u32) {
    // SAFETY: umask has no preconditions.
    unsafe {
        libc::umask(m as libc::mode_t);
    }
}

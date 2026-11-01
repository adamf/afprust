//! File system access confined to a volume.
//!
//! Every operation resolves its path relative to the volume root with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` (Linux 5.6+) and then
//! acts on the final component through a directory descriptor (`*at`
//! syscalls). The kernel therefore guarantees that no request can reach a
//! file outside the volume, even if another local user swaps a directory
//! for a symlink while the request is being processed.
//!
//! With `follow symlinks = yes`, symlinks are allowed as long as they
//! resolve inside the volume (`RESOLVE_BENEATH` alone).
//!
//! On systems without openat2 (and on macOS development builds) the same
//! API falls back to path-based calls with `O_NOFOLLOW`.

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use super::Stat;

static NO_OPENAT2: AtomicBool = AtomicBool::new(false);
static NO_PROCFD: AtomicBool = AtomicBool::new(false);

fn cstr(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn last_err<T>() -> io::Result<T> {
    Err(io::Error::last_os_error())
}

fn stat_from(st: &libc::stat) -> Stat {
    Stat {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        mode: st.st_mode as u32,
        uid: st.st_uid,
        gid: st.st_gid,
        size: st.st_size as u64,
        mtime: st.st_mtime as i64,
    }
}

pub struct Fs {
    pub root: PathBuf,
    pub follow: bool,
    root_fd: OwnedFd,
}

impl Fs {
    pub fn new(root: &Path, follow: bool) -> io::Result<Fs> {
        let c = cstr(root.as_os_str().as_bytes())?;
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        // SAFETY: valid C string.
        let fd = unsafe { libc::open(c.as_ptr(), flags) };
        if fd < 0 {
            return last_err();
        }
        let fs = Fs { root: root.to_path_buf(), follow, root_fd: unsafe { OwnedFd::from_raw_fd(fd) } };
        fs.probe_openat2();
        Ok(fs)
    }

    #[cfg(target_os = "linux")]
    fn probe_openat2(&self) {
        if NO_OPENAT2.load(Ordering::Relaxed) {
            return;
        }
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC) as u64, mode: 0, resolve: 0x08 };
        let dot = CString::new(".").unwrap();
        // SAFETY: syscall with a valid open_how structure.
        let fd = unsafe { libc::syscall(437, self.root_fd.as_raw_fd(), dot.as_ptr(), &how, std::mem::size_of::<OpenHow>()) } as i32;
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return;
        }
        let e = io::Error::last_os_error();
        if matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EPERM)) {
            log::error!(
                "openat2 is unavailable ({}); volume confinement falls back to weaker O_NOFOLLOW checks \
                 (if running under systemd, do not set RestrictSUIDSGID=)",
                e
            );
            NO_OPENAT2.store(true, Ordering::Relaxed);
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn probe_openat2(&self) {}

    /// Path relative to the root; rejects anything that is not a plain
    /// descendant.
    fn rel<'a>(&self, p: &'a Path) -> io::Result<&'a Path> {
        let r = p.strip_prefix(&self.root).map_err(|_| io::Error::from_raw_os_error(libc::EXDEV))?;
        if r.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        Ok(r)
    }

    #[cfg(target_os = "linux")]
    fn openat2(&self, rel: &Path, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const RESOLVE_BENEATH: u64 = 0x08;
        const SYS_OPENAT2: libc::c_long = 437;
        let target = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        let c = cstr(target.as_os_str().as_bytes())?;
        if !NO_OPENAT2.load(Ordering::Relaxed) {
            let mut resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
            if !self.follow {
                resolve |= RESOLVE_NO_SYMLINKS;
            }
            let how = OpenHow { flags: (flags | libc::O_CLOEXEC) as u64, mode: mode as u64, resolve };
            // SAFETY: syscall with a valid open_how structure.
            let fd = unsafe {
                libc::syscall(SYS_OPENAT2, self.root_fd.as_raw_fd(), c.as_ptr(), &how, std::mem::size_of::<OpenHow>())
            } as i32;
            if fd >= 0 {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                // Kernel without openat2 (< 5.6). (A seccomp filter that
                // answers EPERM is detected by the probe in `new`.)
                Some(libc::ENOSYS) => {
                    if !NO_OPENAT2.swap(true, Ordering::Relaxed) {
                        log::warn!("openat2 is unavailable ({}); falling back to O_NOFOLLOW path checks", e);
                    }
                }
                // A symlink or an escape attempt: report "not found".
                Some(libc::ELOOP) | Some(libc::EXDEV) => return Err(io::Error::from_raw_os_error(libc::ENOENT)),
                _ => return Err(e),
            }
        }
        self.open_fallback(target, flags, mode)
    }

    #[cfg(not(target_os = "linux"))]
    fn openat2(&self, rel: &Path, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        let target = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        self.open_fallback(target, flags, mode)
    }

    fn open_fallback(&self, rel: &Path, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        let c = cstr(rel.as_os_str().as_bytes())?;
        let nofollow = if self.follow { 0 } else { libc::O_NOFOLLOW };
        // SAFETY: openat relative to our root descriptor.
        let fd = unsafe { libc::openat(self.root_fd.as_raw_fd(), c.as_ptr(), flags | libc::O_CLOEXEC | nofollow, mode as libc::c_uint) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            return Err(e);
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn dir_flags() -> i32 {
        #[cfg(target_os = "linux")]
        {
            libc::O_PATH | libc::O_DIRECTORY
        }
        #[cfg(not(target_os = "linux"))]
        {
            libc::O_RDONLY | libc::O_DIRECTORY
        }
    }

    /// Descriptor of the parent directory and the final name of `p`.
    fn split(&self, p: &Path) -> io::Result<(OwnedFd, CString)> {
        let rel = self.rel(p)?;
        let name = rel.file_name().ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let parent = rel.parent().unwrap_or(Path::new(""));
        let dfd = self.openat2(parent, Self::dir_flags(), 0)?;
        Ok((dfd, cstr(name.as_bytes())?))
    }

    fn is_root(&self, p: &Path) -> bool {
        p == self.root
    }

    /// Path through /proc that names `name` inside an open directory,
    /// for calls (xattrs, opendir) that have no *at variant.
    fn proc_path(dfd: RawFd, name: Option<&CString>) -> PathBuf {
        let mut s = format!("/proc/self/fd/{}", dfd);
        if let Some(n) = name {
            s.push('/');
            s.push_str(&String::from_utf8_lossy(n.as_bytes()));
            // non-UTF-8 names: build from raw bytes instead
            if std::str::from_utf8(n.as_bytes()).is_err() {
                let mut v = format!("/proc/self/fd/{}/", dfd).into_bytes();
                v.extend_from_slice(n.as_bytes());
                return PathBuf::from(OsStr::from_bytes(&v));
            }
        }
        PathBuf::from(s)
    }

    fn procfd_ok() -> bool {
        if NO_PROCFD.load(Ordering::Relaxed) {
            return false;
        }
        if !cfg!(target_os = "linux") || !Path::new("/proc/self/fd").is_dir() {
            NO_PROCFD.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }

    // -----------------------------------------------------------------

    pub fn lstat(&self, p: &Path) -> io::Result<Stat> {
        if self.is_root(p) {
            return fs::symlink_metadata(p).map(|m| Stat::from_meta(&m));
        }
        let (dfd, name) = self.split(p)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid dirfd, name and stat buffer.
        if unsafe { libc::fstatat(dfd.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return last_err();
        }
        Ok(stat_from(&st))
    }

    /// Stat following symlinks, but only to targets inside the volume.
    pub fn stat_follow(&self, p: &Path) -> io::Result<Stat> {
        let rel = self.rel(p)?;
        #[cfg(target_os = "linux")]
        let fd = self.openat2(rel, libc::O_PATH, 0)?;
        #[cfg(not(target_os = "linux"))]
        let fd = self.openat2(rel, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd and stat buffer.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return last_err();
        }
        Ok(stat_from(&st))
    }

    /// Open a file. `flags` are open(2) flags (O_CLOEXEC is added).
    pub fn open(&self, p: &Path, flags: i32, mode: u32) -> io::Result<File> {
        let rel = self.rel(p)?;
        let fd = self.openat2(rel, flags, mode)?;
        Ok(File::from(fd))
    }

    pub fn open_read(&self, p: &Path) -> io::Result<File> {
        self.open(p, libc::O_RDONLY | libc::O_NONBLOCK, 0)
    }

    /// Create a new regular file (fails if it exists).
    pub fn create(&self, p: &Path, mode: u32, write: bool) -> io::Result<File> {
        let acc = if write { libc::O_RDWR } else { libc::O_WRONLY };
        self.open(p, acc | libc::O_CREAT | libc::O_EXCL, mode)
    }

    pub fn read_dir(&self, p: &Path) -> io::Result<fs::ReadDir> {
        if !Self::procfd_ok() {
            if !self.is_root(p) {
                // still refuse to traverse a symlinked directory
                if self.lstat(p)?.is_symlink() && !self.follow {
                    return Err(io::Error::from_raw_os_error(libc::ENOENT));
                }
            }
            return fs::read_dir(p);
        }
        let rel = self.rel(p)?;
        let fd = self.openat2(rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        // opendir on the /proc link reopens exactly the directory we hold.
        fs::read_dir(Self::proc_path(fd.as_raw_fd(), None))
    }

    pub fn mkdir(&self, p: &Path, mode: u32) -> io::Result<()> {
        let (dfd, name) = self.split(p)?;
        // SAFETY: valid dirfd and name.
        if unsafe { libc::mkdirat(dfd.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) } != 0 {
            return last_err();
        }
        Ok(())
    }

    pub fn unlink(&self, p: &Path) -> io::Result<()> {
        let (dfd, name) = self.split(p)?;
        if unsafe { libc::unlinkat(dfd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return last_err();
        }
        Ok(())
    }

    pub fn rmdir(&self, p: &Path) -> io::Result<()> {
        let (dfd, name) = self.split(p)?;
        if unsafe { libc::unlinkat(dfd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return last_err();
        }
        Ok(())
    }

    /// Remove a directory tree that holds only metadata (bounded depth).
    pub fn remove_tree(&self, p: &Path) -> io::Result<()> {
        self.remove_tree_depth(p, 0)
    }

    fn remove_tree_depth(&self, p: &Path, depth: usize) -> io::Result<()> {
        if depth > 8 {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        for e in self.read_dir(p)? {
            let e = e?;
            let child = p.join(e.file_name());
            let st = self.lstat(&child)?;
            if st.is_dir() {
                self.remove_tree_depth(&child, depth + 1)?;
            } else {
                self.unlink(&child)?;
            }
        }
        self.rmdir(p)
    }

    fn renameat2(&self, a: &Path, b: &Path, flags: libc::c_uint) -> io::Result<()> {
        let (da, na) = self.split(a)?;
        let (db, nb) = self.split(b)?;
        #[cfg(target_os = "linux")]
        {
            // SAFETY: valid descriptors and names.
            let r = unsafe {
                libc::syscall(libc::SYS_renameat2, da.as_raw_fd(), na.as_ptr(), db.as_raw_fd(), nb.as_ptr(), flags)
            };
            if r == 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if flags == 0 || !matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) {
                return Err(e);
            }
        }
        const RENAME_NOREPLACE: libc::c_uint = 1;
        if flags & RENAME_NOREPLACE != 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(db.as_raw_fd(), nb.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
        } else if flags != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        if unsafe { libc::renameat(da.as_raw_fd(), na.as_ptr(), db.as_raw_fd(), nb.as_ptr()) } != 0 {
            return last_err();
        }
        Ok(())
    }

    /// Rename, replacing an existing target (used for case-only renames
    /// and metadata sidecars).
    pub fn rename(&self, a: &Path, b: &Path) -> io::Result<()> {
        self.renameat2(a, b, 0)
    }

    pub fn rename_noreplace(&self, a: &Path, b: &Path) -> io::Result<()> {
        self.renameat2(a, b, 1)
    }

    /// Atomically exchange two names.
    pub fn exchange(&self, a: &Path, b: &Path) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.renameat2(a, b, 2)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (a, b);
            Err(io::Error::from_raw_os_error(libc::ENOTSUP))
        }
    }

    fn xattr_target(&self, p: &Path) -> io::Result<(Option<OwnedFd>, PathBuf)> {
        if self.is_root(p) || !Self::procfd_ok() {
            if !self.is_root(p) && self.lstat(p)?.is_symlink() {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            return Ok((None, p.to_path_buf()));
        }
        let (dfd, name) = self.split(p)?;
        let path = Self::proc_path(dfd.as_raw_fd(), Some(&name));
        Ok((Some(dfd), path))
    }

    pub fn get_xattr(&self, p: &Path, name: &str, max: usize) -> io::Result<Option<Vec<u8>>> {
        let (_keep, path) = self.xattr_target(p)?;
        super::sys::get_xattr(&path, name, max)
    }

    pub fn set_xattr(&self, p: &Path, name: &str, value: &[u8]) -> io::Result<()> {
        let (_keep, path) = self.xattr_target(p)?;
        super::sys::set_xattr(&path, name, value)
    }

    pub fn set_mtime(&self, p: &Path, mtime: i64) -> io::Result<()> {
        let ts = [
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
            libc::timespec { tv_sec: mtime as libc::time_t, tv_nsec: 0 },
        ];
        if self.is_root(p) {
            return super::sys::set_mtime(p, mtime);
        }
        let (dfd, name) = self.split(p)?;
        // SAFETY: valid dirfd, name and two timespecs.
        if unsafe { libc::utimensat(dfd.as_raw_fd(), name.as_ptr(), ts.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return last_err();
        }
        Ok(())
    }

    pub fn chmod(&self, p: &Path, mode: u32) -> io::Result<()> {
        // Open the object itself so a symlink swapped in cannot redirect
        // the change; then chmod through the descriptor.
        let f = self.open(p, libc::O_RDONLY | libc::O_NONBLOCK, 0);
        match f {
            Ok(f) => {
                // SAFETY: valid fd.
                if unsafe { libc::fchmod(f.as_raw_fd(), (mode & 0o7777) as libc::mode_t) } != 0 {
                    return last_err();
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn lchown(&self, p: &Path, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
        let u = uid.map(|u| u as libc::uid_t).unwrap_or(u32::MAX as libc::uid_t);
        let g = gid.map(|g| g as libc::gid_t).unwrap_or(u32::MAX as libc::gid_t);
        if self.is_root(p) {
            let c = cstr(p.as_os_str().as_bytes())?;
            if unsafe { libc::lchown(c.as_ptr(), u, g) } != 0 {
                return last_err();
            }
            return Ok(());
        }
        let (dfd, name) = self.split(p)?;
        // SAFETY: valid dirfd and name.
        if unsafe { libc::fchownat(dfd.as_raw_fd(), name.as_ptr(), u, g, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return last_err();
        }
        Ok(())
    }

    /// File birth time, if the filesystem records it.
    pub fn birth_time(&self, p: &Path) -> Option<i64> {
        #[cfg(target_os = "linux")]
        {
            let (dfd, name) = if self.is_root(p) {
                return super::sys::birth_time(p);
            } else {
                self.split(p).ok()?
            };
            let mut stx: libc::statx = unsafe { std::mem::zeroed() };
            // SAFETY: valid dirfd, name and statx buffer.
            let r = unsafe { libc::statx(dfd.as_raw_fd(), name.as_ptr(), libc::AT_SYMLINK_NOFOLLOW, libc::STATX_BTIME, &mut stx) };
            if r == 0 && stx.stx_mask & libc::STATX_BTIME != 0 {
                return Some(stx.stx_btime.tv_sec);
            }
            None
        }
        #[cfg(not(target_os = "linux"))]
        {
            super::sys::birth_time(p)
        }
    }

    /// Does the object exist (without following symlinks)?
    pub fn exists(&self, p: &Path) -> bool {
        self.lstat(p).is_ok()
    }

    /// Ensure `p` is a directory, creating it if needed.
    pub fn ensure_dir(&self, p: &Path, mode: u32) -> io::Result<()> {
        match self.lstat(p) {
            Ok(st) if st.is_dir() => Ok(()),
            Ok(_) => Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => match self.mkdir(p, mode) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    /// Copy the contents of a regular file to a new file.
    pub fn copy_file(&self, from: &Path, to: &Path) -> io::Result<u64> {
        let mut src = self.open_read(from)?;
        let md = src.metadata()?;
        if !md.is_file() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        use std::os::unix::fs::PermissionsExt;
        let mut dst = self.create(to, md.permissions().mode() & 0o777, false)?;
        io::copy(&mut src, &mut dst)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn confinement() {
        let base = std::env::temp_dir().join(format!("afprust-fs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("vol/sub")).unwrap();
        fs::write(base.join("secret"), b"top secret").unwrap();
        fs::write(base.join("vol/sub/f"), b"ok").unwrap();
        std::os::unix::fs::symlink(base.join("secret"), base.join("vol/abs")).unwrap();
        std::os::unix::fs::symlink("../secret", base.join("vol/rel")).unwrap();
        std::os::unix::fs::symlink("sub", base.join("vol/inside")).unwrap();
        std::os::unix::fs::symlink(&base, base.join("vol/up")).unwrap();
        let fs_ = Fs::new(&base.join("vol"), false).unwrap();
        let v = base.join("vol");
        assert!(fs_.open_read(&v.join("sub/f")).is_ok());
        for bad in ["abs", "rel", "inside/f", "up/secret"] {
            assert!(fs_.open_read(&v.join(bad)).is_err(), "{}", bad);
        }
        assert!(fs_.open_read(&base.join("secret")).is_err(), "outside the root");
        assert!(fs_.open_read(&v.join("sub/../../secret")).is_err(), "dot-dot");
        assert!(fs_.lstat(&v.join("up/secret")).is_err());
        assert!(fs_.read_dir(&v.join("up")).is_err());
        // with follow symlinks, links inside the volume work, escapes do not
        let ff = Fs::new(&v, true).unwrap();
        assert!(ff.open_read(&v.join("inside/f")).is_ok());
        assert!(ff.open_read(&v.join("abs")).is_err());
        assert!(ff.open_read(&v.join("rel")).is_err());
        assert!(ff.stat_follow(&v.join("up")).is_err());
        let _ = fs::remove_dir_all(&base);
    }
}

//! Async-signal-safe signal handling via flags and a self-pipe.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

pub static TERM: AtomicBool = AtomicBool::new(false);
pub static HUP: AtomicBool = AtomicBool::new(false);
pub static CHLD: AtomicBool = AtomicBool::new(false);
pub static USR1: AtomicBool = AtomicBool::new(false);
static PIPE_WR: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handler(sig: libc::c_int) {
    match sig {
        libc::SIGTERM | libc::SIGINT => TERM.store(true, Ordering::SeqCst),
        libc::SIGHUP => HUP.store(true, Ordering::SeqCst),
        libc::SIGCHLD => CHLD.store(true, Ordering::SeqCst),
        libc::SIGUSR1 => USR1.store(true, Ordering::SeqCst),
        _ => {}
    }
    let fd = PIPE_WR.load(Ordering::SeqCst);
    if fd >= 0 {
        let b = sig as u8;
        // SAFETY: write(2) is async-signal-safe; errors (EAGAIN) are ignored.
        unsafe {
            let saved = *errno_ptr();
            libc::write(fd, &b as *const u8 as *const libc::c_void, 1);
            *errno_ptr() = saved;
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn errno_ptr() -> *mut libc::c_int {
    libc::__errno_location()
}

#[cfg(target_os = "macos")]
unsafe fn errno_ptr() -> *mut libc::c_int {
    libc::__error()
}

fn set_handler(sig: libc::c_int, h: libc::sighandler_t, restart: bool) {
    // SAFETY: sigaction with a zeroed struct and a valid handler.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = h;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        if sig == libc::SIGCHLD {
            sa.sa_flags |= libc::SA_NOCLDSTOP;
        }
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

/// Create the self-pipe and install handlers. Returns the read end.
pub fn install_master() -> std::io::Result<RawFd> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds has room for two descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for &fd in &fds {
        set_cloexec_nonblock(fd);
    }
    PIPE_WR.store(fds[1], Ordering::SeqCst);
    let h = handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD, libc::SIGUSR1] {
        set_handler(s, h, true);
    }
    set_handler(libc::SIGPIPE, libc::SIG_IGN, true);
    Ok(fds[0])
}

/// Reset handlers in a freshly forked session process: TERM/USR1 set flags
/// and interrupt blocking calls; HUP and CHLD are ignored.
pub fn install_session() {
    PIPE_WR.store(-1, Ordering::SeqCst);
    TERM.store(false, Ordering::SeqCst);
    HUP.store(false, Ordering::SeqCst);
    CHLD.store(false, Ordering::SeqCst);
    USR1.store(false, Ordering::SeqCst);
    let h = handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
    set_handler(libc::SIGTERM, h, false);
    set_handler(libc::SIGINT, h, false);
    set_handler(libc::SIGUSR1, h, false);
    set_handler(libc::SIGHUP, libc::SIG_IGN, true);
    set_handler(libc::SIGCHLD, libc::SIG_DFL, true);
    set_handler(libc::SIGPIPE, libc::SIG_IGN, true);
}

pub fn drain_pipe(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: buf is valid for its length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

pub fn set_cloexec_nonblock(fd: RawFd) {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, fl | libc::FD_CLOEXEC);
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

pub fn terminating() -> bool {
    TERM.load(Ordering::SeqCst) || USR1.load(Ordering::SeqCst)
}

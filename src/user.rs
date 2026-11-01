//! User and group database access and privilege dropping.

use std::ffi::{CStr, CString};
use std::io;

#[derive(Debug, Clone)]
pub struct Passwd {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub dir: String,
    pub gecos: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub gid: u32,
}

const BUF_START: usize = 1024;
const BUF_MAX: usize = 1 << 20;

unsafe fn cstr(p: *const libc::c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

fn pw_lookup<F>(mut f: F) -> Option<Passwd>
where
    F: FnMut(*mut libc::passwd, *mut libc::c_char, usize, *mut *mut libc::passwd) -> libc::c_int,
{
    let mut size = BUF_START;
    loop {
        let mut buf = vec![0 as libc::c_char; size];
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let r = f(&mut pw, buf.as_mut_ptr(), buf.len(), &mut result);
        if r == libc::ERANGE && size < BUF_MAX {
            size *= 2;
            continue;
        }
        if r != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success the strings point into buf, which is alive.
        unsafe {
            return Some(Passwd {
                name: cstr(pw.pw_name),
                uid: pw.pw_uid,
                gid: pw.pw_gid,
                dir: cstr(pw.pw_dir),
                gecos: cstr(pw.pw_gecos),
            });
        }
    }
}

fn gr_lookup<F>(mut f: F) -> Option<Group>
where
    F: FnMut(*mut libc::group, *mut libc::c_char, usize, *mut *mut libc::group) -> libc::c_int,
{
    let mut size = BUF_START;
    loop {
        let mut buf = vec![0 as libc::c_char; size];
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let r = f(&mut gr, buf.as_mut_ptr(), buf.len(), &mut result);
        if r == libc::ERANGE && size < BUF_MAX {
            size *= 2;
            continue;
        }
        if r != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success the strings point into buf, which is alive.
        unsafe {
            return Some(Group { name: cstr(gr.gr_name), gid: gr.gr_gid });
        }
    }
}

pub fn getpwnam(name: &str) -> Option<Passwd> {
    let c = CString::new(name).ok()?;
    pw_lookup(|pw, buf, len, res| unsafe { libc::getpwnam_r(c.as_ptr(), pw, buf, len, res) })
}

pub fn getpwuid(uid: u32) -> Option<Passwd> {
    pw_lookup(|pw, buf, len, res| unsafe { libc::getpwuid_r(uid, pw, buf, len, res) })
}

pub fn getgrnam(name: &str) -> Option<Group> {
    let c = CString::new(name).ok()?;
    gr_lookup(|gr, buf, len, res| unsafe { libc::getgrnam_r(c.as_ptr(), gr, buf, len, res) })
}

pub fn getgrgid(gid: u32) -> Option<Group> {
    gr_lookup(|gr, buf, len, res| unsafe { libc::getgrgid_r(gid, gr, buf, len, res) })
}

/// Validate a login name supplied by a client.
pub fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name.chars().all(|c| !c.is_control() && c != ':' && c != '/' && c != '\\')
}

/// Look up a login name, falling back to its lowercase form (Mac users
/// often capitalize their short name).
pub fn lookup_login(name: &str) -> Option<Passwd> {
    if !valid_username(name) {
        return None;
    }
    getpwnam(name).or_else(|| {
        let lower = name.to_lowercase();
        if lower != name {
            getpwnam(&lower)
        } else {
            None
        }
    })
}

/// All group IDs of a user, including the primary group.
pub fn user_groups(name: &str, gid: u32) -> Vec<u32> {
    let c = match CString::new(name) {
        Ok(c) => c,
        Err(_) => return vec![gid],
    };
    let mut n: libc::c_int = 64;
    loop {
        let mut groups: Vec<libc::gid_t> = vec![0; n as usize];
        let mut count = n;
        // SAFETY: groups has room for `count` entries.
        #[cfg(target_os = "linux")]
        let r = unsafe { libc::getgrouplist(c.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
        #[cfg(target_os = "macos")]
        let r = unsafe {
            libc::getgrouplist(c.as_ptr(), gid as libc::c_int, groups.as_mut_ptr() as *mut libc::c_int, &mut count)
        };
        if r < 0 {
            if count > n && count < 65536 {
                n = count;
            } else if n < 65536 {
                n *= 2;
            } else {
                return vec![gid];
            }
            continue;
        }
        groups.truncate(count.max(0) as usize);
        let mut out: Vec<u32> = groups.into_iter().map(|g| g as u32).collect();
        if !out.contains(&gid) {
            out.insert(0, gid);
        }
        return out;
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

pub fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn current_gid() -> u32 {
    unsafe { libc::getegid() }
}

/// Permanently become `pw`: set supplementary groups, gid and uid, then
/// verify that root cannot be regained.
pub fn drop_privileges(pw: &Passwd) -> io::Result<()> {
    if !is_root() {
        // Development mode: we can only "become" ourselves.
        if pw.uid != current_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "not running as root; can only serve the current user",
            ));
        }
        return Ok(());
    }
    if pw.uid == 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "refusing to run a session as root"));
    }
    let groups: Vec<libc::gid_t> = user_groups(&pw.name, pw.gid).into_iter().map(|g| g as libc::gid_t).collect();
    // SAFETY: plain syscalls with valid arguments.
    unsafe {
        #[cfg(target_os = "linux")]
        let r = libc::setgroups(groups.len(), groups.as_ptr());
        #[cfg(target_os = "macos")]
        let r = libc::setgroups(groups.len() as libc::c_int, groups.as_ptr());
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setgid(pw.gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setuid(pw.uid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setuid(0) == 0 || libc::geteuid() == 0 || libc::getuid() == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "privilege drop failed: root regained"));
        }
        if libc::getegid() != pw.gid {
            return Err(io::Error::new(io::ErrorKind::Other, "privilege drop failed: gid mismatch"));
        }
        #[cfg(target_os = "linux")]
        {
            // Not dumpable: other processes of the same user cannot ptrace
            // or read the memory of the session (which held the password).
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
    Ok(())
}

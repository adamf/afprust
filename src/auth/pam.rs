//! Minimal PAM binding: authenticate a user name + password and run
//! account management.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_NEW_AUTHTOK_REQD: c_int = 12;
const PAM_ACCT_EXPIRED: c_int = 13;
const PAM_TTY: c_int = 3;
const PAM_RHOST: c_int = 4;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;
const PAM_SILENT: c_int = 0x8000;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int,
    appdata_ptr: *mut c_void,
}

#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(service: *const c_char, user: *const c_char, conv: *const PamConv, pamh: *mut *mut PamHandle) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_strerror(pamh: *mut PamHandle, errnum: c_int) -> *const c_char;
}

struct ConvData {
    user: CString,
    password: CString,
}

extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || num_msg > 32 || msg.is_null() || resp.is_null() || appdata.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: PAM passes num_msg valid message pointers and our appdata.
    unsafe {
        let data = &*(appdata as *const ConvData);
        let replies = libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if replies.is_null() {
            return PAM_BUF_ERR;
        }
        for i in 0..num_msg as usize {
            let m = *msg.add(i);
            if m.is_null() {
                continue;
            }
            let r = &mut *replies.add(i);
            r.resp_retcode = 0;
            r.resp = match (*m).msg_style {
                PAM_PROMPT_ECHO_OFF => libc::strdup(data.password.as_ptr()),
                PAM_PROMPT_ECHO_ON => libc::strdup(data.user.as_ptr()),
                _ => std::ptr::null_mut(),
            };
        }
        *resp = replies;
    }
    PAM_SUCCESS
}

#[derive(Debug, PartialEq, Eq)]
pub enum PamOutcome {
    Ok,
    Denied,
    Expired,
    Error(String),
}

unsafe fn errstr(h: *mut PamHandle, code: c_int) -> String {
    let p = pam_strerror(h, code);
    if p.is_null() {
        format!("PAM error {}", code)
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// Authenticate `user` with `password` against the PAM `service`.
pub fn authenticate(service: &str, user: &str, password: &[u8], rhost: &str) -> PamOutcome {
    let svc = match CString::new(service) {
        Ok(s) => s,
        Err(_) => return PamOutcome::Error("bad PAM service name".into()),
    };
    let user_c = match CString::new(user) {
        Ok(s) => s,
        Err(_) => return PamOutcome::Denied,
    };
    // Passwords end at the first NUL (they are NUL padded on the wire).
    let end = password.iter().position(|&b| b == 0).unwrap_or(password.len());
    let mut pw = password[..end].to_vec();
    if pw.is_empty() {
        return PamOutcome::Denied;
    }
    let pw_c = match CString::new(std::mem::take(&mut pw)) {
        Ok(s) => s,
        Err(_) => return PamOutcome::Denied,
    };
    let data = Box::new(ConvData { user: user_c.clone(), password: pw_c });
    let conv = PamConv { conv: conversation, appdata_ptr: &*data as *const ConvData as *mut c_void };
    let tty = CString::new("afprust").unwrap();
    let rhost_c = CString::new(rhost.replace('\0', "")).unwrap_or_default();
    let mut h: *mut PamHandle = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the PAM calls;
    // `data` and `conv` outlive pam_end.
    let outcome = unsafe {
        let r = pam_start(svc.as_ptr(), user_c.as_ptr(), &conv, &mut h);
        if r != PAM_SUCCESS || h.is_null() {
            return PamOutcome::Error(format!("pam_start failed ({})", r));
        }
        pam_set_item(h, PAM_TTY, tty.as_ptr() as *const c_void);
        pam_set_item(h, PAM_RHOST, rhost_c.as_ptr() as *const c_void);
        let mut r = pam_authenticate(h, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
        let out = if r != PAM_SUCCESS {
            log::debug!("PAM authenticate for {}: {}", user, errstr(h, r));
            PamOutcome::Denied
        } else {
            r = pam_acct_mgmt(h, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
            match r {
                PAM_SUCCESS => PamOutcome::Ok,
                PAM_NEW_AUTHTOK_REQD | PAM_ACCT_EXPIRED => PamOutcome::Expired,
                _ => {
                    log::debug!("PAM account check for {}: {}", user, errstr(h, r));
                    PamOutcome::Denied
                }
            }
        };
        pam_end(h, r);
        out
    };
    // Scrub the password copy.
    let mut bytes = data.password.into_bytes();
    for b in bytes.iter_mut() {
        // SAFETY: volatile write to an owned buffer prevents elision.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    outcome
}

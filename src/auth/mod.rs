//! User Authentication Methods (UAMs) for FPLogin / FPLoginCont.

pub mod dhx;
pub mod pam;

use crate::afp::buf::Reader;
use crate::afp::consts::AfpError;
use crate::charset::macroman_decode;
use crate::config::Uam;
use crate::user::{self, Passwd};
use crate::util::scrub;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub pw: Passwd,
    pub guest: bool,
}

pub enum LoginStep {
    Done(AuthUser),
    Continue(Vec<u8>),
}

/// Why a login failed (for logging and rate limiting).
#[derive(Debug)]
pub enum LoginFailure {
    /// Wrong password or unknown user.
    BadCredentials(String),
    Expired(String),
    /// Protocol error (malformed packet, unsupported UAM).
    Protocol(AfpError),
}

impl LoginFailure {
    pub fn afp_error(&self) -> AfpError {
        match self {
            LoginFailure::BadCredentials(_) => AfpError::UserNotAuth,
            LoginFailure::Expired(_) => AfpError::PwdExpiredErr,
            LoginFailure::Protocol(e) => *e,
        }
    }
}

pub struct Authenticator {
    pub uams: Vec<Uam>,
    pub guest_account: String,
    pub pam_service: String,
    pub rhost: String,
    dhx: Option<dhx::DhxState>,
}

fn read_username(r: &mut Reader) -> Result<String, LoginFailure> {
    let raw = r.pstring().map_err(LoginFailure::Protocol)?;
    if raw.is_empty() {
        return Err(LoginFailure::Protocol(AfpError::ParamErr));
    }
    let name = macroman_decode(raw);
    if !user::valid_username(&name) {
        return Err(LoginFailure::BadCredentials(crate::logging::sanitize(&name)));
    }
    Ok(name)
}

impl Authenticator {
    pub fn new(uams: Vec<Uam>, guest_account: String, pam_service: String, rhost: String) -> Self {
        Authenticator { uams, guest_account, pam_service, rhost, dhx: None }
    }

    pub fn find_uam(&self, name: &[u8]) -> Option<Uam> {
        self.uams.iter().copied().find(|u| u.afp_name().as_bytes().eq_ignore_ascii_case(name))
    }

    /// Run the first login step. `r` is positioned just after the UAM name
    /// in the FPLogin command block (so even-alignment is relative to the
    /// start of the command).
    pub fn login(&mut self, uam: Uam, r: &mut Reader) -> Result<LoginStep, LoginFailure> {
        self.dhx = None;
        match uam {
            Uam::Guest => {
                let pw = user::getpwnam(&self.guest_account).ok_or_else(|| {
                    log::error!("guest account '{}' does not exist", self.guest_account);
                    LoginFailure::Protocol(AfpError::MiscErr)
                })?;
                if pw.uid == 0 {
                    log::error!("guest account must not be root");
                    return Err(LoginFailure::Protocol(AfpError::MiscErr));
                }
                Ok(LoginStep::Done(AuthUser { pw, guest: true }))
            }
            Uam::ClearText => {
                let name = read_username(r)?;
                r.align2();
                let mut pwbuf = r.array::<8>().map_err(LoginFailure::Protocol)?;
                let res = self.check_password(&name, &pwbuf);
                scrub(&mut pwbuf);
                res.map(LoginStep::Done)
            }
            Uam::Dhx => {
                let name = read_username(r)?;
                r.align2();
                let ma = r.array::<16>().map_err(LoginFailure::Protocol)?;
                let (reply, state) = dhx::server_step1(name, &ma).ok_or(LoginFailure::Protocol(AfpError::ParamErr))?;
                self.dhx = Some(state);
                Ok(LoginStep::Continue(reply))
            }
        }
    }

    /// FPLoginCont: `r` is positioned after the command and pad bytes.
    pub fn login_cont(&mut self, r: &mut Reader) -> Result<LoginStep, LoginFailure> {
        let state = self.dhx.take().ok_or(LoginFailure::Protocol(AfpError::ParamErr))?;
        let id = r.u16().map_err(LoginFailure::Protocol)?;
        if id != state.id {
            return Err(LoginFailure::Protocol(AfpError::ParamErr));
        }
        let block = r.bytes(dhx::KEYSIZE + dhx::PASSWDLEN).map_err(LoginFailure::Protocol)?;
        let mut pw = match dhx::server_step2(&state, block) {
            Some(p) => p,
            None => return Err(LoginFailure::BadCredentials(crate::logging::sanitize(&state.user))),
        };
        let res = self.check_password(&state.user, &pw);
        scrub(&mut pw);
        res.map(LoginStep::Done)
    }

    fn check_password(&self, name: &str, password: &[u8]) -> Result<AuthUser, LoginFailure> {
        let display = crate::logging::sanitize(name);
        let pw = match user::lookup_login(name) {
            Some(p) => p,
            None => {
                // Still run PAM so unknown users take as long as bad passwords.
                let _ = pam::authenticate(&self.pam_service, name, password, &self.rhost);
                return Err(LoginFailure::BadCredentials(display));
            }
        };
        if pw.uid == 0 {
            log::warn!("refusing AFP login as root");
            return Err(LoginFailure::BadCredentials(display));
        }
        // Passwords arrive in MacRoman; Linux passwords are UTF-8.
        let end = password.iter().position(|&b| b == 0).unwrap_or(password.len());
        let mut utf8 = macroman_decode(&password[..end]).into_bytes();
        let outcome = pam::authenticate(&self.pam_service, &pw.name, &utf8, &self.rhost);
        scrub(&mut utf8);
        match outcome {
            pam::PamOutcome::Ok => Ok(AuthUser { pw, guest: false }),
            pam::PamOutcome::Expired => Err(LoginFailure::Expired(display)),
            pam::PamOutcome::Denied => Err(LoginFailure::BadCredentials(display)),
            pam::PamOutcome::Error(e) => {
                log::error!("PAM error: {}", e);
                Err(LoginFailure::BadCredentials(display))
            }
        }
    }
}

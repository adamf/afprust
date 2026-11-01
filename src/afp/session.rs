//! One client session: DSI loop, login, privilege drop and dispatch.
//!
//! A session runs in its own process (forked by the master). Until login
//! completes it is root but only parses DSI framing, FPGetSrvrInfo and the
//! login commands; every other command is rejected. After a successful
//! login the process permanently switches to the user's uid/gids before
//! touching any volume.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::buf::{Reader, Writer};
use super::consts::*;
use crate::auth::{AuthUser, Authenticator, LoginFailure, LoginStep};
use crate::charset;
use crate::config::{Config, Principal, VolumeOptions};
use crate::dsi::{self, Dsi, Frame, ReadError};
use crate::user::{self, Passwd};
use crate::vfs::fork::Fork;
use crate::vfs::{UserCtx, Volume};

/// Exit codes reported to the master.
pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
/// 20 + number of failed logins (capped at 9).
pub const EXIT_AUTH_BASE: i32 = 20;

const MAX_LOGIN_FAILURES: u32 = 3;
const PRELOGIN_MAX_PAYLOAD: usize = 4096;
const MAX_FORKS: usize = 1024;
/// AFP 2.x volume names are limited to 27 bytes.
const MAX_VOL_NAME: usize = 27;

pub struct VolDef {
    pub vid: u16,
    pub name_mac: Vec<u8>,
    pub path: PathBuf,
    pub opts: VolumeOptions,
    pub read_only: bool,
}

pub struct LoggedIn {
    pub pw: Passwd,
    pub guest: bool,
    pub ctx: UserCtx,
}

pub struct Session {
    pub dsi: Dsi,
    pub cfg: Arc<Config>,
    pub status: Vec<u8>,
    pub peer: SocketAddr,
    pub auth: Authenticator,
    pub login_failures: u32,
    pub user: Option<LoggedIn>,
    pub voldefs: Vec<VolDef>,
    pub vols: HashMap<u16, Volume>,
    pub forks: HashMap<u16, Fork>,
    pub next_fork: u16,
    pub dt_open: HashSet<u16>,
    pub extmap: Arc<crate::config::extmap::ExtMap>,
    opened: bool,
    logout: bool,
}

pub struct Reply {
    pub code: i32,
    pub data: Vec<u8>,
}

impl Reply {
    pub fn ok(data: Vec<u8>) -> Reply {
        Reply { code: 0, data }
    }
    pub fn empty() -> Reply {
        Reply { code: 0, data: Vec::new() }
    }
    pub fn err(e: AfpError) -> Reply {
        Reply { code: e.code(), data: Vec::new() }
    }
}

impl From<AfpResult<Vec<u8>>> for Reply {
    fn from(r: AfpResult<Vec<u8>>) -> Reply {
        match r {
            Ok(d) => Reply::ok(d),
            Err(e) => Reply::err(e),
        }
    }
}

/// Expand netatalk variables ($u, $h, ...) in a path or name.
pub fn expand_vars(s: &str, pw: Option<&Passwd>, cfg: &Config, peer: &SocketAddr, vol_name: &str, vol_path: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let v = match chars.next() {
            Some(v) => v,
            None => {
                out.push('$');
                break;
            }
        };
        match v {
            '$' => out.push('$'),
            'u' => out.push_str(pw.map(|p| p.name.as_str()).unwrap_or("")),
            'f' => out.push_str(pw.map(|p| p.gecos.split(',').next().unwrap_or("")).unwrap_or("")),
            'g' => {
                if let Some(g) = pw.and_then(|p| user::getgrgid(p.gid)) {
                    out.push_str(&g.name);
                }
            }
            'h' => out.push_str(&cfg.global.hostname),
            's' => out.push_str(&cfg.global.server_name),
            'i' => out.push_str(&crate::config::normalize_ip(peer.ip()).to_string()),
            'c' => out.push_str(&format!("{}:{}", crate::config::normalize_ip(peer.ip()), peer.port())),
            'v' => out.push_str(vol_name),
            'd' => out.push_str(vol_path),
            'b' => out.push_str(std::path::Path::new(vol_path).file_name().and_then(|n| n.to_str()).unwrap_or("")),
            other => {
                out.push('$');
                out.push(other);
            }
        }
    }
    out
}

fn principal_matches(list: &[Principal], pw: &Passwd, groups: &[u32]) -> bool {
    list.iter().any(|p| match p {
        Principal::User(u) => *u == pw.name,
        Principal::Group(g) => user::getgrnam(g).map(|gr| groups.contains(&gr.gid)).unwrap_or(false),
    })
}

fn path_is_safe(p: &str) -> bool {
    p.starts_with('/') && !p.split('/').any(|c| c == "..") && !p.contains('\0')
}

impl Session {
    pub fn new(dsi: Dsi, cfg: Arc<Config>, status: Vec<u8>, peer: SocketAddr) -> Session {
        let auth = Authenticator::new(
            cfg.global.uams.clone(),
            cfg.global.guest_account.clone(),
            cfg.global.pam_service.clone(),
            crate::config::normalize_ip(peer.ip()).to_string(),
        );
        let extmap = Arc::new(cfg.extmap.clone());
        Session {
            dsi,
            cfg,
            status,
            peer,
            auth,
            login_failures: 0,
            user: None,
            voldefs: Vec::new(),
            vols: HashMap::new(),
            forks: HashMap::new(),
            next_fork: 1,
            dt_open: HashSet::new(),
            extmap,
            opened: false,
            logout: false,
        }
    }

    fn exit_code(&self) -> i32 {
        if self.login_failures > 0 {
            EXIT_AUTH_BASE + self.login_failures.min(9) as i32
        } else {
            EXIT_OK
        }
    }

    /// Run until the client disconnects. Returns the process exit code.
    pub fn run(mut self) -> i32 {
        let tickle = Duration::from_secs(self.cfg.global.tickleval as u64);
        let max_idle = self.cfg.global.timeout.max(1);
        let login_deadline = Instant::now() + Duration::from_secs(self.cfg.global.login_timeout as u64);
        let mut idle = 0u32;
        self.dsi.max_payload = PRELOGIN_MAX_PAYLOAD;
        loop {
            if crate::signals::terminating() {
                log::info!("session {}: server shutting down", self.peer);
                let _ = self.dsi.send_attention(dsi::ATTN_SHUTDOWN);
                let _ = self.dsi.send_close();
                self.close_all();
                return self.exit_code();
            }
            if self.user.is_none() && Instant::now() > login_deadline {
                log::info!("session {}: no login within {}s, closing", self.peer, self.cfg.global.login_timeout);
                return self.exit_code();
            }
            let wait = if self.user.is_none() { tickle.min(Duration::from_secs(5)) } else { tickle };
            match self.dsi.read_frame(wait) {
                Ok(frame) => {
                    idle = 0;
                    match self.handle_frame(frame) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(e) => {
                            log::info!("session {}: write error: {}", self.peer, e);
                            break;
                        }
                    }
                }
                Err(ReadError::Idle) => {
                    if self.user.is_none() {
                        continue;
                    }
                    idle += 1;
                    if idle > max_idle {
                        log::info!("session {}: client timed out", self.peer);
                        break;
                    }
                    if self.dsi.send_tickle().is_err() {
                        break;
                    }
                }
                Err(ReadError::Interrupted) => continue,
                Err(ReadError::Closed) => break,
                Err(ReadError::Protocol(m)) => {
                    log::warn!("session {}: protocol error: {}", self.peer, m);
                    break;
                }
                Err(ReadError::Io(e)) => {
                    log::info!("session {}: {}", self.peer, e);
                    break;
                }
            }
            if self.logout {
                break;
            }
        }
        self.close_all();
        if let Some(u) = &self.user {
            log::info!("session {}: {} logged out", self.peer, u.pw.name);
        }
        self.exit_code()
    }

    fn close_all(&mut self) {
        let refs: Vec<u16> = self.forks.keys().copied().collect();
        for r in refs {
            if let Some(f) = self.forks.remove(&r) {
                if f.dirty {
                    let _ = f.flush();
                }
            }
        }
        self.vols.clear();
    }

    fn handle_frame(&mut self, frame: Frame) -> std::io::Result<bool> {
        let h = frame.header;
        if h.flags == dsi::FLAG_REPLY {
            // reply to one of our attentions
            return Ok(true);
        }
        match h.command {
            dsi::CMD_GET_STATUS => {
                let s = self.status.clone();
                self.dsi.reply(&h, 0, &s)?;
                Ok(true)
            }
            dsi::CMD_OPEN_SESSION => {
                if self.opened {
                    return Ok(false);
                }
                self.opened = true;
                self.dsi.open_session(&h, &frame.payload)?;
                Ok(true)
            }
            dsi::CMD_TICKLE => Ok(true),
            dsi::CMD_CLOSE_SESSION => Ok(false),
            dsi::CMD_ATTENTION => Ok(true),
            dsi::CMD_COMMAND | dsi::CMD_WRITE => {
                if !self.opened {
                    log::warn!("session {}: command before DSIOpenSession", self.peer);
                    return Ok(false);
                }
                let (cmd_buf, data) = if h.command == dsi::CMD_WRITE {
                    let off = h.code as usize;
                    if off > frame.payload.len() {
                        log::warn!("session {}: bad DSIWrite data offset", self.peer);
                        return Ok(false);
                    }
                    let (a, b) = frame.payload.split_at(off);
                    (a.to_vec(), b.to_vec())
                } else {
                    (frame.payload, Vec::new())
                };
                if cmd_buf.is_empty() {
                    self.dsi.reply(&h, AfpError::ParamErr.code(), &[])?;
                    return Ok(true);
                }
                let cmd = cmd_buf[0];
                let reply = self.dispatch(cmd, &cmd_buf, &data);
                if reply.code != 0 && reply.code != AfpError::EofErr.code() {
                    log::debug!("{} -> {}", command_name(cmd), reply.code);
                }
                self.dsi.reply(&h, reply.code, &reply.data)?;
                if self.user.is_none() && self.login_failures >= MAX_LOGIN_FAILURES {
                    return Ok(false);
                }
                Ok(true)
            }
            other => {
                log::warn!("session {}: unknown DSI command {}", self.peer, other);
                Ok(false)
            }
        }
    }

    fn dispatch(&mut self, cmd: u8, req: &[u8], data: &[u8]) -> Reply {
        if self.user.is_none() {
            return match cmd {
                FP_GET_SRVR_INFO => Reply::ok(self.status.clone()),
                FP_LOGIN => self.fp_login(req),
                FP_LOGIN_CONT => self.fp_login_cont(req),
                _ => Reply::err(AfpError::UserNotAuth),
            };
        }
        let r: AfpResult<Vec<u8>> = match cmd {
            FP_GET_SRVR_INFO => Ok(self.status.clone()),
            FP_LOGIN | FP_LOGIN_CONT => Err(AfpError::MiscErr),
            FP_LOGOUT => {
                self.logout = true;
                Ok(Vec::new())
            }
            FP_GET_SRVR_PARMS => self.fp_get_srvr_parms(),
            FP_GET_SRVR_MSG => self.fp_get_srvr_msg(req),
            FP_GET_USER_INFO => self.fp_get_user_info(req),
            FP_MAP_ID => self.fp_map_id(req),
            FP_MAP_NAME => self.fp_map_name(req),
            FP_ZZZZZ => Ok(Vec::new()),
            FP_CHANGE_PASSWORD | FP_CAT_SEARCH | FP_CREATE_ID | FP_DELETE_ID | FP_RESOLVE_ID => {
                Err(AfpError::CallNotSupported)
            }
            FP_OPEN_VOL => self.fp_open_vol(req),
            FP_CLOSE_VOL => self.fp_close_vol(req),
            FP_GET_VOL_PARMS => self.fp_get_vol_parms(req),
            FP_SET_VOL_PARMS => self.fp_set_vol_parms(req),
            FP_FLUSH => self.fp_flush(req),
            FP_OPEN_DIR => self.fp_open_dir(req),
            FP_CLOSE_DIR => Ok(Vec::new()),
            FP_GET_FILE_DIR_PARMS => self.fp_get_file_dir_parms(req),
            FP_SET_FILE_PARMS => self.fp_set_parms(req, SetKind::File),
            FP_SET_DIR_PARMS => self.fp_set_parms(req, SetKind::Dir),
            FP_SET_FILE_DIR_PARMS => self.fp_set_parms(req, SetKind::Either),
            FP_ENUMERATE => self.fp_enumerate(req),
            FP_CREATE_DIR => self.fp_create_dir(req),
            FP_CREATE_FILE => self.fp_create_file(req),
            FP_DELETE => self.fp_delete(req),
            FP_RENAME => self.fp_rename(req),
            FP_MOVE_AND_RENAME => self.fp_move_and_rename(req),
            FP_COPY_FILE => self.fp_copy_file(req),
            FP_EXCHANGE_FILES => self.fp_exchange_files(req),
            FP_OPEN_FORK => self.fp_open_fork(req),
            FP_CLOSE_FORK => self.fp_close_fork(req),
            FP_READ => return self.fp_read(req),
            FP_WRITE => self.fp_write(req, data),
            FP_FLUSH_FORK => self.fp_flush_fork(req),
            FP_GET_FORK_PARMS => self.fp_get_fork_parms(req),
            FP_SET_FORK_PARMS => self.fp_set_fork_parms(req),
            FP_BYTE_RANGE_LOCK => self.fp_byte_range_lock(req),
            FP_OPEN_DT => self.fp_open_dt(req),
            FP_CLOSE_DT => self.fp_close_dt(req),
            FP_ADD_ICON => self.fp_add_icon(req, data),
            FP_GET_ICON => self.fp_get_icon(req),
            FP_GET_ICON_INFO => self.fp_get_icon_info(req),
            FP_ADD_APPL => self.fp_add_appl(req),
            FP_REMOVE_APPL => self.fp_remove_appl(req),
            FP_GET_APPL => self.fp_get_appl(req),
            FP_ADD_COMMENT => self.fp_add_comment(req),
            FP_REMOVE_COMMENT => self.fp_remove_comment(req),
            FP_GET_COMMENT => self.fp_get_comment(req),
            _ => {
                log::debug!("unsupported AFP command {}", cmd);
                Err(AfpError::CallNotSupported)
            }
        };
        r.into()
    }

    // ---------------------------------------------------------------
    // login
    // ---------------------------------------------------------------

    fn fp_login(&mut self, req: &[u8]) -> Reply {
        let mut r = Reader::new(req);
        let _ = r.u8();
        let version = match r.pstring() {
            Ok(v) => v,
            Err(_) => return Reply::err(AfpError::BadVersNum),
        };
        if !super::status::AFP_LOGIN_VERSIONS.iter().any(|v| v.as_bytes() == version) {
            log::info!(
                "session {}: client asked for unsupported AFP version '{}'",
                self.peer,
                crate::logging::sanitize(&String::from_utf8_lossy(version))
            );
            return Reply::err(AfpError::BadVersNum);
        }
        let uam_name = match r.pstring() {
            Ok(u) => u,
            Err(_) => return Reply::err(AfpError::BadUam),
        };
        let uam = match self.auth.find_uam(uam_name) {
            Some(u) => u,
            None => {
                log::info!(
                    "session {}: UAM '{}' not enabled",
                    self.peer,
                    crate::logging::sanitize(&String::from_utf8_lossy(uam_name))
                );
                return Reply::err(AfpError::BadUam);
            }
        };
        let res = self.auth.login(uam, &mut r);
        self.login_result(res)
    }

    fn fp_login_cont(&mut self, req: &[u8]) -> Reply {
        let mut r = Reader::new(req);
        let _ = r.u8();
        let _ = r.u8();
        let res = self.auth.login_cont(&mut r);
        self.login_result(res)
    }

    fn login_result(&mut self, res: Result<LoginStep, LoginFailure>) -> Reply {
        match res {
            Ok(LoginStep::Continue(data)) => Reply { code: AfpError::AuthContinue.code(), data },
            Ok(LoginStep::Done(au)) => match self.complete_login(au) {
                Ok(()) => Reply::empty(),
                Err(e) => {
                    self.logout = true;
                    Reply::err(e)
                }
            },
            Err(f) => {
                match &f {
                    LoginFailure::BadCredentials(u) | LoginFailure::Expired(u) => {
                        self.login_failures += 1;
                        log::warn!("session {}: login failed for '{}'", self.peer, u);
                        // Slow down password guessing.
                        std::thread::sleep(Duration::from_secs(2));
                    }
                    LoginFailure::Protocol(e) => {
                        log::info!("session {}: login error {:?}", self.peer, e);
                    }
                }
                Reply::err(f.afp_error())
            }
        }
    }

    fn complete_login(&mut self, au: AuthUser) -> AfpResult<()> {
        let pw = au.pw;
        if let Err(e) = user::drop_privileges(&pw) {
            log::error!("cannot switch to user {}: {}", pw.name, e);
            return Err(AfpError::MiscErr);
        }
        let groups = user::user_groups(&pw.name, pw.gid);
        let ctx = UserCtx { uid: pw.uid, gid: pw.gid, groups };
        log::info!(
            "session {}: {} logged in{}",
            self.peer,
            pw.name,
            if au.guest { " as guest" } else { "" }
        );
        self.user = Some(LoggedIn { pw, guest: au.guest, ctx });
        self.dsi.max_payload = self.cfg.global.server_quantum as usize + 64;
        self.build_volumes();
        Ok(())
    }

    fn build_volumes(&mut self) {
        let u = match &self.user {
            Some(u) => u,
            None => return,
        };
        let cfg = self.cfg.clone();
        let ip = crate::config::normalize_ip(self.peer.ip());
        let mut defs: Vec<VolDef> = Vec::new();
        let mut candidates: Vec<(String, String, VolumeOptions)> = Vec::new();

        if let (Some(h), false) = (&cfg.homes, u.guest) {
            let re = regex::Regex::new(&h.basedir_regex);
            let home = u.pw.dir.trim_end_matches('/').to_string();
            match re {
                Ok(re) if !home.is_empty() && re.find(&home).map(|m| m.start() == 0).unwrap_or(false) => {
                    let mut path = home.clone();
                    if let Some(sp) = &h.subpath {
                        path = format!("{}/{}", path, expand_vars(sp, Some(&u.pw), &cfg, &self.peer, "", &home));
                    }
                    let name = expand_vars(&h.opts.name, Some(&u.pw), &cfg, &self.peer, "Homes", &path);
                    candidates.push((name, path, h.opts.clone()));
                }
                _ => {}
            }
        }
        for v in &cfg.volumes {
            let path = expand_vars(&v.path, Some(&u.pw), &cfg, &self.peer, &v.name, &v.path);
            let name = expand_vars(&v.name, Some(&u.pw), &cfg, &self.peer, &v.name, &path);
            candidates.push((name, path, v.clone()));
        }

        for (name, path, opts) in candidates {
            if !path_is_safe(&path) {
                log::warn!("volume '{}': unsafe path '{}' skipped", name, path);
                continue;
            }
            if !opts.hosts_allow.is_empty() && !opts.hosts_allow.iter().any(|n| n.contains(ip)) {
                continue;
            }
            if opts.hosts_deny.iter().any(|n| n.contains(ip)) {
                continue;
            }
            if !opts.valid_users.is_empty() && !principal_matches(&opts.valid_users, &u.pw, &u.ctx.groups) {
                continue;
            }
            if principal_matches(&opts.invalid_users, &u.pw, &u.ctx.groups) {
                continue;
            }
            let mut ro = opts.read_only;
            if principal_matches(&opts.rolist, &u.pw, &u.ctx.groups) {
                ro = true;
            }
            if !opts.rwlist.is_empty() && !principal_matches(&opts.rwlist, &u.pw, &u.ctx.groups) {
                ro = true;
            }
            let name_mac = charset::config_to_mac(&name, MAX_VOL_NAME);
            if name_mac.is_empty() {
                continue;
            }
            let folded = charset::macroman_decode(&name_mac).to_lowercase();
            if defs.iter().any(|d| charset::macroman_decode(&d.name_mac).to_lowercase() == folded) {
                log::warn!("duplicate volume name '{}' skipped", name);
                continue;
            }
            let vid = defs.len() as u16 + 1;
            defs.push(VolDef { vid, name_mac, path: PathBuf::from(path), opts, read_only: ro });
        }
        self.voldefs = defs;
    }

    pub fn ctx(&self) -> &UserCtx {
        &self.user.as_ref().expect("logged in").ctx
    }

    pub fn alloc_fork_ref(&mut self) -> AfpResult<u16> {
        if self.forks.len() >= MAX_FORKS {
            return Err(AfpError::TooManyFilesOpen);
        }
        for _ in 0..=u16::MAX as u32 {
            let r = self.next_fork;
            self.next_fork = self.next_fork.wrapping_add(1);
            if self.next_fork == 0 {
                self.next_fork = 1;
            }
            if r != 0 && !self.forks.contains_key(&r) {
                return Ok(r);
            }
        }
        Err(AfpError::TooManyFilesOpen)
    }

    // ---------------------------------------------------------------
    // server-level commands
    // ---------------------------------------------------------------

    fn fp_get_srvr_parms(&mut self) -> AfpResult<Vec<u8>> {
        let mut w = Writer::new();
        w.u32(unix_to_afp_date(crate::util::now_unix()));
        w.u8(self.voldefs.len().min(255) as u8);
        for d in self.voldefs.iter().take(255) {
            let flags = if d.opts.password.is_some() { 0x80 } else { 0 };
            w.u8(flags);
            w.pstring(&d.name_mac);
        }
        Ok(w.into_vec())
    }

    fn fp_get_srvr_msg(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(2)?;
        let typ = r.u16()?;
        let bitmap = r.u16()?;
        let msg = match typ {
            0 => self.cfg.global.login_message.clone().unwrap_or_default(),
            1 => String::new(),
            _ => return Err(AfpError::ParamErr),
        };
        let mut w = Writer::new();
        w.u16(typ).u16(bitmap);
        w.pstring(&charset::config_to_mac(&msg, 199));
        Ok(w.into_vec())
    }

    fn fp_get_user_info(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(1)?;
        let flags = r.u8()?;
        let _uid = r.u32()?;
        let bitmap = r.u16()?;
        if flags & 1 == 0 {
            return Err(AfpError::ParamErr);
        }
        if bitmap & !0x3 != 0 {
            return Err(AfpError::BitmapErr);
        }
        let u = self.user.as_ref().unwrap();
        let mut w = Writer::new();
        w.u16(bitmap);
        if bitmap & 1 != 0 {
            w.u32(u.pw.uid);
        }
        if bitmap & 2 != 0 {
            w.u32(u.pw.gid);
        }
        Ok(w.into_vec())
    }

    fn fp_map_id(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(1)?;
        let sub = r.u8()?;
        let id = r.u32()?;
        let name = match sub {
            1 => {
                if id == 0 {
                    String::new()
                } else {
                    user::getpwuid(id).map(|p| p.name).ok_or(AfpError::ItemNotFound)?
                }
            }
            2 => {
                if id == 0 {
                    String::new()
                } else {
                    user::getgrgid(id).map(|g| g.name).ok_or(AfpError::ItemNotFound)?
                }
            }
            _ => return Err(AfpError::ParamErr),
        };
        let mut w = Writer::new();
        w.pstring(&charset::config_to_mac(&name, 255));
        Ok(w.into_vec())
    }

    fn fp_map_name(&mut self, req: &[u8]) -> AfpResult<Vec<u8>> {
        let mut r = Reader::new(req);
        r.skip(1)?;
        let sub = r.u8()?;
        let name = charset::macroman_decode(r.pstring()?);
        if name.is_empty() {
            let mut w = Writer::new();
            w.u32(0);
            return Ok(w.into_vec());
        }
        if !user::valid_username(&name) {
            return Err(AfpError::ItemNotFound);
        }
        let id = match sub {
            3 => user::getpwnam(&name).map(|p| p.uid).ok_or(AfpError::ItemNotFound)?,
            4 => user::getgrnam(&name).map(|g| g.gid).ok_or(AfpError::ItemNotFound)?,
            _ => return Err(AfpError::ParamErr),
        };
        let mut w = Writer::new();
        w.u32(id);
        Ok(w.into_vec())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    File,
    Dir,
    Either,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vars() {
        let cfg = Config::parse_ini("[Global]\nserver name = S\nhostname = h.example\n").unwrap();
        let pw = Passwd { name: "bob".into(), uid: 1, gid: 99999, dir: "/home/bob".into(), gecos: "Bob B,,,".into() };
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        assert_eq!(expand_vars("/srv/$u/x", Some(&pw), &cfg, &peer, "V", "/p"), "/srv/bob/x");
        assert_eq!(expand_vars("$f on $s ($i) $$", Some(&pw), &cfg, &peer, "V", "/p"), "Bob B on S (10.0.0.2) $");
        assert!(!path_is_safe("/srv/../etc"));
        assert!(path_is_safe("/srv/bob"));
    }
}

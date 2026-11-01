//! The master process: listens for connections and forks one session
//! process per client.
//!
//! The master is single-threaded, so `fork()` is safe. It never parses
//! client data itself: a connection is handed to a child immediately.
//! It enforces connection limits and blocks addresses that keep failing
//! to log in.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::afp::session::{Session, EXIT_AUTH_BASE};
use crate::afp::status::{self, NetAddr, ServerInfo};
use crate::config::{normalize_ip, Config};
use crate::dsi::Dsi;
use crate::signals;

const FAIL_WINDOW: Duration = Duration::from_secs(600);
const FAIL_LIMIT: u32 = 10;
const BLOCK_TIME: Duration = Duration::from_secs(900);

struct Child {
    ip: IpAddr,
}

struct FailRecord {
    count: u32,
    first: Instant,
    blocked_until: Option<Instant>,
}

pub struct Master {
    cfg: Arc<Config>,
    cfg_path: Option<PathBuf>,
    listeners: Vec<TcpListener>,
    children: HashMap<libc::pid_t, Child>,
    per_ip: HashMap<IpAddr, usize>,
    failures: HashMap<IpAddr, FailRecord>,
    info: ServerInfo,
    sig_fd: RawFd,
    helper_pids: Vec<libc::pid_t>,
}

fn load_signature(cfg: &Config) -> [u8; 16] {
    let mut sig = [0u8; 16];
    if let Some(s) = &cfg.global.signature {
        let b = s.as_bytes();
        let n = b.len().min(16);
        sig[..n].copy_from_slice(&b[..n]);
        return sig;
    }
    let path = cfg.global.state_dir.join("afp_signature");
    if let Ok(t) = fs::read_to_string(&path) {
        let t = t.trim();
        if t.len() == 32 {
            let mut ok = true;
            for i in 0..16 {
                match u8::from_str_radix(&t[i * 2..i * 2 + 2], 16) {
                    Ok(v) => sig[i] = v,
                    Err(_) => ok = false,
                }
            }
            if ok {
                return sig;
            }
        }
    }
    getrandom::getrandom(&mut sig).expect("random number generator");
    let hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
    let saved = fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&cfg.global.state_dir)
        .and_then(|_| {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            writeln!(f, "{}", hex)
        });
    if let Err(e) = saved {
        log::warn!("could not save server signature to {}: {}", path.display(), e);
        // Fall back to something stable: derive from the host name.
        sig = [0u8; 16];
        for (i, b) in cfg.global.hostname.bytes().chain(cfg.global.server_name.bytes()).enumerate() {
            sig[i % 16] = sig[i % 16].rotate_left(3) ^ b;
        }
    }
    sig
}

pub fn server_info(cfg: &Config) -> ServerInfo {
    ServerInfo {
        name: crate::charset::config_to_mac(&cfg.global.server_name, 31),
        uams: cfg.global.uams.iter().map(|u| u.afp_name()).collect(),
        signature: load_signature(cfg),
        save_password: cfg.global.save_password,
        icon: Some(crate::icon::SERVER_ICON),
    }
}

/// Tell systemd about our state (Type=notify).
pub fn sd_notify(msg: &str) {
    let path = match std::env::var_os("NOTIFY_SOCKET") {
        Some(p) => p,
        None => return,
    };
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_bytes();
    let sock = match std::os::unix::net::UnixDatagram::unbound() {
        Ok(s) => s,
        Err(_) => return,
    };
    if bytes.first() == Some(&b'@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(&bytes[1..]) {
                let _ = sock.send_to_addr(msg.as_bytes(), &addr);
            }
        }
    } else {
        let _ = sock.send_to(msg.as_bytes(), Path::new(&path));
    }
}

/// Bind a TCP listener. IPv6 sockets are made IPv6-only when IPv4
/// addresses are listed too (`afp listen = 0.0.0.0 ::`); a lone `::` keeps
/// the Linux default and also accepts IPv4 connections.
fn bind_one(a: &SocketAddr, v6only: bool) -> io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    let (family, v6) = match a {
        SocketAddr::V4(_) => (libc::AF_INET, false),
        SocketAddr::V6(_) => (libc::AF_INET6, true),
    };
    // SAFETY: plain socket calls; the descriptor is owned by the listener
    // on success and closed on every error path.
    unsafe {
        let fd = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fail = |fd: libc::c_int| {
            let e = io::Error::last_os_error();
            libc::close(fd);
            Err(e)
        };
        let on: libc::c_int = 1;
        let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &on as *const _ as *const libc::c_void, sz) != 0 {
            return fail(fd);
        }
        if v6 && v6only
            && libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &on as *const _ as *const libc::c_void, sz) != 0
        {
            return fail(fd);
        }
        let r = match a {
            SocketAddr::V4(v4) => {
                let mut sin: libc::sockaddr_in = std::mem::zeroed();
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = v4.port().to_be();
                sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                libc::bind(fd, &sin as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(v6a) => {
                let mut sin6: libc::sockaddr_in6 = std::mem::zeroed();
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = v6a.port().to_be();
                sin6.sin6_addr.s6_addr = v6a.ip().octets();
                sin6.sin6_scope_id = v6a.scope_id();
                libc::bind(fd, &sin6 as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        };
        if r != 0 || libc::listen(fd, 128) != 0 {
            return fail(fd);
        }
        Ok(TcpListener::from_raw_fd(fd))
    }
}

fn bind(addrs: &[SocketAddr]) -> io::Result<Vec<TcpListener>> {
    let mut out = Vec::new();
    let any_v4 = addrs.iter().any(|a| a.is_ipv4());
    for a in addrs {
        let l = bind_one(a, any_v4).map_err(|e| io::Error::new(e.kind(), format!("cannot listen on {}: {}", a, e)))?;
        l.set_nonblocking(true)?;
        signals::set_cloexec_nonblock(l.as_raw_fd());
        log::info!("listening on {}", a);
        out.push(l);
    }
    Ok(out)
}

impl Master {
    pub fn new(cfg: Config, cfg_path: Option<PathBuf>) -> io::Result<Master> {
        let listeners = bind(&cfg.global.listen)?;
        let info = server_info(&cfg);
        let sig_fd = signals::install_master()?;
        Ok(Master {
            cfg: Arc::new(cfg),
            cfg_path,
            listeners,
            children: HashMap::new(),
            per_ip: HashMap::new(),
            failures: HashMap::new(),
            info,
            sig_fd,
            helper_pids: Vec::new(),
        })
    }

    pub fn add_helper(&mut self, pid: libc::pid_t) {
        self.helper_pids.push(pid);
    }

    pub fn server_info(&self) -> &ServerInfo {
        &self.info
    }

    fn reap(&mut self) {
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid with a valid status pointer.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            if self.helper_pids.contains(&pid) {
                log::warn!("helper process {} exited (status {})", pid, status);
                self.helper_pids.retain(|&p| p != pid);
                continue;
            }
            if let Some(c) = self.children.remove(&pid) {
                if let Some(n) = self.per_ip.get_mut(&c.ip) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.per_ip.remove(&c.ip);
                    }
                }
                if libc::WIFEXITED(status) {
                    let code = libc::WEXITSTATUS(status);
                    if (EXIT_AUTH_BASE..EXIT_AUTH_BASE + 10).contains(&code) {
                        self.record_failures(c.ip, (code - EXIT_AUTH_BASE) as u32);
                    }
                } else if libc::WIFSIGNALED(status) {
                    let sig = libc::WTERMSIG(status);
                    if sig != libc::SIGTERM && sig != libc::SIGKILL {
                        log::error!("session {} for {} died with signal {}", pid, c.ip, sig);
                    }
                }
            }
        }
    }

    fn record_failures(&mut self, ip: IpAddr, n: u32) {
        if n == 0 {
            return;
        }
        let now = Instant::now();
        let rec = self.failures.entry(ip).or_insert(FailRecord { count: 0, first: now, blocked_until: None });
        if now.duration_since(rec.first) > FAIL_WINDOW {
            rec.count = 0;
            rec.first = now;
        }
        rec.count += n;
        if rec.count >= FAIL_LIMIT && rec.blocked_until.is_none() {
            log::warn!("{}: {} failed logins, blocking for {} minutes", ip, rec.count, BLOCK_TIME.as_secs() / 60);
            rec.blocked_until = Some(now + BLOCK_TIME);
        }
    }

    fn blocked(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.failures.retain(|_, r| match r.blocked_until {
            Some(t) => t > now,
            None => now.duration_since(r.first) <= FAIL_WINDOW,
        });
        self.failures.get(&ip).and_then(|r| r.blocked_until).map(|t| t > now).unwrap_or(false)
    }

    fn reload(&mut self) {
        let path = self.cfg_path.clone().or_else(|| {
            if self.cfg.source.as_os_str().is_empty() {
                None
            } else {
                Some(self.cfg.source.clone())
            }
        });
        match Config::load(path.as_deref()) {
            Ok(c) => {
                for w in &c.warnings {
                    log::warn!("config: {}", w);
                }
                if c.global.listen != self.cfg.global.listen {
                    log::warn!("listen addresses changed; restart the service to apply");
                }
                crate::logging::set_level(c.global.log_level);
                let mut info = server_info(&c);
                info.signature = self.info.signature;
                self.info = info;
                self.cfg = Arc::new(c);
                log::info!("configuration reloaded ({} volumes)", self.cfg.volumes.len());
            }
            Err(e) => log::error!("reload failed, keeping old configuration: {}", e),
        }
    }

    fn accept(&mut self, idx: usize) {
        loop {
            let (stream, peer) = match self.listeners[idx].accept() {
                Ok(x) => x,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn!("accept: {}", e);
                    return;
                }
            };
            let ip = normalize_ip(peer.ip());
            if self.blocked(ip) {
                log::info!("rejecting {}: too many failed logins", ip);
                continue;
            }
            if self.children.len() >= self.cfg.global.max_connections {
                log::warn!("rejecting {}: connection limit reached", ip);
                continue;
            }
            if self.per_ip.get(&ip).copied().unwrap_or(0) >= self.cfg.global.max_connections_per_ip {
                log::warn!("rejecting {}: per-address connection limit reached", ip);
                continue;
            }
            self.spawn_session(stream, peer, ip);
        }
    }

    fn spawn_session(&mut self, stream: TcpStream, peer: SocketAddr, ip: IpAddr) {
        // SAFETY: the master is single-threaded, so fork is safe.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            log::error!("fork: {}", io::Error::last_os_error());
            return;
        }
        if pid == 0 {
            // child
            for l in &self.listeners {
                // SAFETY: closing our copies of the listening sockets.
                unsafe { libc::close(l.as_raw_fd()) };
            }
            unsafe { libc::close(self.sig_fd) };
            signals::install_session();
            let code = run_session(stream, peer, self.cfg.clone(), &self.info);
            std::process::exit(code);
        }
        drop(stream);
        log::debug!("connection from {} -> session {}", peer, pid);
        self.children.insert(pid, Child { ip });
        *self.per_ip.entry(ip).or_insert(0) += 1;
    }

    fn shutdown(&mut self) {
        log::info!("shutting down, {} sessions", self.children.len());
        for &pid in self.children.keys().chain(self.helper_pids.iter()) {
            // SAFETY: signalling our own children.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while (!self.children.is_empty() || !self.helper_pids.is_empty()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            self.reap();
        }
        for &pid in self.children.keys().chain(self.helper_pids.iter()) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        self.reap();
    }

    pub fn run(&mut self) -> i32 {
        sd_notify("READY=1\nSTATUS=Serving AFP");
        loop {
            let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(self.listeners.len() + 1);
            pfds.push(libc::pollfd { fd: self.sig_fd, events: libc::POLLIN, revents: 0 });
            for l in &self.listeners {
                pfds.push(libc::pollfd { fd: l.as_raw_fd(), events: libc::POLLIN, revents: 0 });
            }
            // SAFETY: pfds is a valid array.
            let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 30_000) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    log::error!("poll: {}", e);
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
            if pfds[0].revents != 0 {
                signals::drain_pipe(self.sig_fd);
            }
            use std::sync::atomic::Ordering;
            if signals::CHLD.swap(false, Ordering::SeqCst) {
                self.reap();
            }
            if signals::TERM.load(Ordering::SeqCst) {
                sd_notify("STOPPING=1");
                self.shutdown();
                return 0;
            }
            if signals::HUP.swap(false, Ordering::SeqCst) {
                sd_notify("RELOADING=1");
                self.reload();
                sd_notify("READY=1");
            }
            for i in 0..self.listeners.len() {
                if pfds[i + 1].revents & libc::POLLIN != 0 {
                    self.accept(i);
                }
            }
            // Catch any SIGCHLD that raced with poll.
            self.reap();
            let n = self.children.len();
            sd_notify(&format!("STATUS=Serving AFP, {} session{}", n, if n == 1 { "" } else { "s" }));
        }
    }
}

fn run_session(stream: TcpStream, peer: SocketAddr, cfg: Arc<Config>, info: &ServerInfo) -> i32 {
    if let Err(e) = stream.set_nonblocking(false) {
        log::warn!("session {}: {}", peer, e);
        return 1;
    }
    let _ = socket_keepalive(&stream);
    let local = stream.local_addr().ok();
    let addrs: Vec<NetAddr> = local.into_iter().filter(|a| !a.ip().is_unspecified()).map(NetAddr::Ip).collect();
    let status = status::build(info, &addrs);
    let dsi = match Dsi::new(stream, 4096, cfg.global.server_quantum) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("session {}: {}", peer, e);
            return 1;
        }
    };
    Session::new(dsi, cfg, status, peer).run()
}

fn socket_keepalive(s: &TcpStream) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: setsockopt with a valid int option.
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_on_ipv4_and_ipv6_wildcards() {
        // Find a free port, then bind both wildcards on it, as
        // "afp listen = 0.0.0.0 ::" does.
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let v4 = SocketAddr::from(([0, 0, 0, 0], port));
        let v6: SocketAddr = format!("[::]:{}", port).parse().unwrap();
        if TcpListener::bind("[::1]:0").is_err() {
            eprintln!("no IPv6 here, skipping");
            return;
        }
        let ls = bind(&[v4, v6]).expect("both wildcards bind");
        assert_eq!(ls.len(), 2);
        drop(ls);
        // a lone "::" accepts IPv4 connections too
        let ls = bind(&[v6]).unwrap();
        ls[0].set_nonblocking(false).unwrap();
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("IPv4 via dual-stack ::");
    }
}

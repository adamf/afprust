//! Minimal AppleTalk presence so the server shows up in the Mac OS Chooser.
//!
//! This is not a full AppleTalk stack and does not serve AFP over ASP. It:
//!
//! 1. gives the Ethernet interface an EtherTalk Phase 2 address using the
//!    Linux kernel's DDP implementation (module `appletalk`), in the
//!    router-less configuration (cable range 0-65534, startup range node);
//! 2. answers NBP lookups for `<server name>:AFPServer@*`;
//! 3. answers ASP SPGetStatus with the server information block, which
//!    lists the server's TCP/IP address.
//!
//! AppleShare Client 3.7.4 and later (Mac OS 8.1+) then connect over
//! TCP/IP. ASP session requests are refused with "server busy".
//!
//! The responder runs in its own process, which drops to the `nobody`
//! account after binding its sockets.

use crate::afp::status::ServerInfo;
use crate::config::AppleTalkConfig;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::afp::status::{self, NetAddr};
    use std::io;
    use std::net::{IpAddr, SocketAddr};

    const AF_APPLETALK: libc::c_int = 5;
    const SIOCGIFADDR: libc::c_ulong = 0x8915;
    const SIOCSIFADDR: libc::c_ulong = 0x8916;
    const DDP_NBP: u8 = 2;
    const DDP_ATP: u8 = 3;
    const NBP_SOCKET: u8 = 2;
    const NBP_LKUP: u8 = 2;
    const NBP_LKUP_REPLY: u8 = 3;
    const ATP_TREQ: u8 = 0x40;
    const ATP_TRESP: u8 = 0x80;
    const ATP_FUNC_MASK: u8 = 0xC0;
    const ATP_XO: u8 = 0x20;
    const ATP_EOM: u8 = 0x10;
    const ATP_MAX_DATA: usize = 578;
    const ASP_GET_STATUS: u8 = 3;
    const ASP_OPEN_SESS: u8 = 4;
    const ASP_SERVER_BUSY: i16 = -1071;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrAt {
        family: u16,
        port: u8,
        _pad: u8,
        net: u16, // network byte order
        node: u8,
        _pad2: u8,
        zero: [u8; 8],
    }

    impl SockaddrAt {
        fn new(net: u16, node: u8, port: u8) -> SockaddrAt {
            SockaddrAt { family: AF_APPLETALK as u16, port, _pad: 0, net: net.to_be(), node, _pad2: 0, zero: [0; 8] }
        }
    }

    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        addr: SockaddrAt,
        _rest: [u8; 8],
    }

    struct Sock(libc::c_int);

    impl Drop for Sock {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    fn ddp_socket() -> io::Result<Sock> {
        // SAFETY: plain socket(2) call.
        let fd = unsafe { libc::socket(AF_APPLETALK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EAFNOSUPPORT) {
                return Err(io::Error::new(e.kind(), "kernel has no AppleTalk support (try: modprobe appletalk)"));
            }
            return Err(e);
        }
        Ok(Sock(fd))
    }

    fn ifreq(name: &str) -> io::Result<IfReq> {
        if name.is_empty() || name.len() >= 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad interface name"));
        }
        let mut r = IfReq { name: [0; 16], addr: SockaddrAt::new(0, 0, 0), _rest: [0; 8] };
        r.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(r)
    }

    fn pick_interface(cfg: &AppleTalkConfig) -> io::Result<String> {
        if let Some(i) = &cfg.interface {
            return Ok(i.clone());
        }
        let mut best: Option<String> = None;
        for e in std::fs::read_dir("/sys/class/net")?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let typ = std::fs::read_to_string(e.path().join("type")).unwrap_or_default();
            if typ.trim() != "1" || name == "lo" {
                continue;
            }
            if e.path().join("wireless").exists() {
                continue;
            }
            if name == "eth0" || name == "end0" {
                return Ok(name);
            }
            if best.is_none() {
                best = Some(name);
            }
        }
        best.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no wired Ethernet interface found; set 'ddp interface'"))
    }

    fn random_u8() -> u8 {
        let mut b = [0u8; 1];
        let _ = getrandom::getrandom(&mut b);
        b[0]
    }

    /// Configure the interface for router-less EtherTalk Phase 2 and return
    /// the address the kernel settled on.
    fn configure(s: &Sock, ifname: &str, cfg: &AppleTalkConfig) -> io::Result<(u16, u8)> {
        let mut r = ifreq(ifname)?;
        // Existing address (e.g. configured by atalkd)? Use it.
        // SAFETY: ioctl with a properly sized ifreq.
        if unsafe { libc::ioctl(s.0, SIOCGIFADDR as _, &mut r) } == 0 && r.addr.node != 0 {
            return Ok((u16::from_be(r.addr.net), r.addr.node));
        }
        let (net, node) = cfg.address.unwrap_or_else(|| (0xFF00 + (random_u8() as u16 % 0xFE), 1 + random_u8() % 253));
        let mut r = ifreq(ifname)?;
        r.addr = SockaddrAt::new(net, node, 0);
        // atalk_netrange inside sat_zero: phase, pad, first (be16), last (be16)
        r.addr.zero[0] = 2;
        r.addr.zero[2..4].copy_from_slice(&0u16.to_be_bytes());
        r.addr.zero[4..6].copy_from_slice(&0xFFFEu16.to_be_bytes());
        // SAFETY: ioctl with a properly sized ifreq.
        if unsafe { libc::ioctl(s.0, SIOCSIFADDR as _, &r) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut g = ifreq(ifname)?;
        if unsafe { libc::ioctl(s.0, SIOCGIFADDR as _, &mut g) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((u16::from_be(g.addr.net), g.addr.node))
    }

    fn bind(s: &Sock, net: u16, node: u8, port: u8) -> io::Result<u8> {
        let a = SockaddrAt::new(net, node, port);
        // SAFETY: bind with a correctly sized sockaddr_at.
        let r = unsafe {
            libc::bind(s.0, &a as *const _ as *const libc::sockaddr, std::mem::size_of::<SockaddrAt>() as libc::socklen_t)
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = SockaddrAt::new(0, 0, 0);
        let mut len = std::mem::size_of::<SockaddrAt>() as libc::socklen_t;
        unsafe { libc::getsockname(s.0, &mut out as *mut _ as *mut libc::sockaddr, &mut len) };
        Ok(out.port)
    }

    fn recv(s: &Sock, buf: &mut [u8]) -> io::Result<(usize, SockaddrAt)> {
        let mut from = SockaddrAt::new(0, 0, 0);
        let mut len = std::mem::size_of::<SockaddrAt>() as libc::socklen_t;
        // SAFETY: buf and from are valid for their sizes.
        let n = unsafe {
            libc::recvfrom(s.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0, &mut from as *mut _ as *mut libc::sockaddr, &mut len)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((n as usize, from))
    }

    fn send(s: &Sock, data: &[u8], to: &SockaddrAt) {
        // SAFETY: data and to are valid.
        unsafe {
            libc::sendto(s.0, data.as_ptr() as *const libc::c_void, data.len(), 0, to as *const _ as *const libc::sockaddr, std::mem::size_of::<SockaddrAt>() as libc::socklen_t);
        }
    }

    fn fold(b: &[u8]) -> String {
        crate::charset::macroman_decode(b).to_lowercase()
    }

    /// NBP name matching with '=' (anything) and '≈' (0xC5, partial).
    fn nbp_match(pattern: &[u8], name: &[u8]) -> bool {
        if pattern == b"=" {
            return true;
        }
        if let Some(pos) = pattern.iter().position(|&b| b == 0xC5) {
            let pre = fold(&pattern[..pos]);
            let post = fold(&pattern[pos + 1..]);
            let n = fold(name);
            return n.len() >= pre.len() + post.len() && n.starts_with(&pre) && n.ends_with(&post);
        }
        fold(pattern) == fold(name)
    }

    fn read_pstr(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
        let len = *buf.get(*pos)? as usize;
        let s = buf.get(*pos + 1..*pos + 1 + len)?.to_vec();
        *pos += 1 + len;
        Some(s)
    }

    /// Protocol logic, separate from the sockets so it can be tested.
    struct Logic {
        net: u16,
        node: u8,
        atp_port: u8,
        name: Vec<u8>,
        zone: Option<Vec<u8>>,
        status: Vec<u8>,
    }

    struct Responder {
        nbp: Sock,
        atp: Sock,
        logic: Logic,
    }

    impl Logic {
        /// Answer an NBP lookup: the reply packet and where to send it.
        fn nbp(&self, pkt: &[u8], from: &SockaddrAt) -> Option<(Vec<u8>, SockaddrAt)> {
            // pkt[0] is the DDP type
            if pkt.len() < 3 || pkt[0] != DDP_NBP {
                return None;
            }
            let func = pkt[1] >> 4;
            let count = pkt[1] & 0x0F;
            let id = pkt[2];
            if func != NBP_LKUP || count < 1 {
                return None;
            }
            let mut pos = 3;
            if pkt.len() < pos + 5 {
                return None;
            }
            let rnet = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
            let rnode = pkt[pos + 2];
            let rsock = pkt[pos + 3];
            pos += 5;
            let (obj, typ, zone) = match (read_pstr(pkt, &mut pos), read_pstr(pkt, &mut pos), read_pstr(pkt, &mut pos)) {
                (Some(o), Some(t), Some(z)) => (o, t, z),
                _ => return None,
            };
            if rnet == self.net && rnode == self.node {
                return None;
            }
            if !nbp_match(&obj, &self.name) || !nbp_match(&typ, b"AFPServer") {
                return None;
            }
            let zone_ok = zone.is_empty()
                || zone == b"*"
                || self.zone.as_ref().map(|z| fold(z) == fold(&zone)).unwrap_or(true);
            if !zone_ok {
                return None;
            }
            let mut out = Vec::with_capacity(64);
            out.push(DDP_NBP);
            out.push((NBP_LKUP_REPLY << 4) | 1);
            out.push(id);
            out.extend_from_slice(&self.net.to_be_bytes());
            out.push(self.node);
            out.push(self.atp_port);
            out.push(0); // enumerator
            out.push(self.name.len() as u8);
            out.extend_from_slice(&self.name);
            out.push(9);
            out.extend_from_slice(b"AFPServer");
            out.push(1);
            out.push(b'*');
            // Reply to the address in the tuple (normally the requester).
            let to = if rnode != 0 { SockaddrAt::new(rnet, rnode, rsock) } else { *from };
            log::debug!("NBP lookup from {}.{}: replying", rnet, rnode);
            Some((out, to))
        }

        /// Answer an ATP request: the response packets.
        fn atp(&self, pkt: &[u8], from: &SockaddrAt) -> Vec<Vec<u8>> {
            let mut replies = Vec::new();
            if pkt.len() < 9 || pkt[0] != DDP_ATP {
                return replies;
            }
            let ctl = pkt[1];
            if ctl & ATP_FUNC_MASK != ATP_TREQ {
                return replies; // TRel and stray responses
            }
            let bitmap = pkt[2];
            let tid = [pkt[3], pkt[4]];
            let user = &pkt[5..9];
            match user[0] {
                ASP_GET_STATUS => {
                    let chunks: Vec<&[u8]> = if self.status.is_empty() {
                        vec![&[][..]]
                    } else {
                        self.status.chunks(ATP_MAX_DATA).take(8).collect()
                    };
                    let last = chunks.len() - 1;
                    for (seq, c) in chunks.iter().enumerate() {
                        if bitmap & (1 << seq) == 0 {
                            continue;
                        }
                        let mut out = Vec::with_capacity(9 + c.len());
                        out.push(DDP_ATP);
                        out.push(ATP_TRESP | if seq == last { ATP_EOM } else { 0 });
                        out.push(seq as u8);
                        out.extend_from_slice(&tid);
                        out.extend_from_slice(&[0, 0, 0, 0]);
                        out.extend_from_slice(c);
                        replies.push(out);
                    }
                    log::debug!("ASP GetStatus from {}.{}", u16::from_be(from.net), from.node);
                }
                ASP_OPEN_SESS => {
                    log::info!(
                        "AppleTalk client {}.{} asked for an ASP session; only AFP over TCP/IP is served",
                        u16::from_be(from.net),
                        from.node
                    );
                    let mut out = vec![DDP_ATP, ATP_TRESP | ATP_EOM | (ctl & ATP_XO), 0, tid[0], tid[1], 0, 0];
                    out.extend_from_slice(&ASP_SERVER_BUSY.to_be_bytes());
                    replies.push(out);
                }
                _ => {}
            }
            replies
        }
    }

    impl Responder {
        fn run(&self) -> ! {
            let mut buf = [0u8; 1024];
            loop {
                if crate::signals::terminating() {
                    std::process::exit(0);
                }
                let mut pfds = [
                    libc::pollfd { fd: self.nbp.0, events: libc::POLLIN, revents: 0 },
                    libc::pollfd { fd: self.atp.0, events: libc::POLLIN, revents: 0 },
                ];
                // SAFETY: valid pollfd array.
                let r = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 5000) };
                if r <= 0 {
                    continue;
                }
                if pfds[0].revents & libc::POLLIN != 0 {
                    if let Ok((n, from)) = recv(&self.nbp, &mut buf) {
                        if let Some((reply, to)) = self.logic.nbp(&buf[..n], &from) {
                            send(&self.nbp, &reply, &to);
                        }
                    }
                }
                if pfds[1].revents & libc::POLLIN != 0 {
                    if let Ok((n, from)) = recv(&self.atp, &mut buf) {
                        for reply in self.logic.atp(&buf[..n], &from) {
                            send(&self.atp, &reply, &from);
                        }
                    }
                }
            }
        }
    }

    fn interface_ipv4(ifname: &str) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs allocates a list we free below.
        if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
            return out;
        }
        let mut p = ifap;
        while !p.is_null() {
            unsafe {
                let ifa = &*p;
                if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                    if name == ifname {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                    }
                }
                p = ifa.ifa_next;
            }
        }
        unsafe { libc::freeifaddrs(ifap) };
        out
    }

    fn drop_to_nobody() {
        if let Some(pw) = crate::user::getpwnam("nobody") {
            // SAFETY: plain credential syscalls.
            unsafe {
                libc::setgroups(0, std::ptr::null());
                libc::setgid(pw.gid);
                libc::setuid(pw.uid);
            }
        }
    }

    pub fn spawn(cfg: &AppleTalkConfig, info: &ServerInfo, tcp_port: u16) -> io::Result<libc::pid_t> {
        let ifname = pick_interface(cfg)?;
        let ctl = ddp_socket()?;
        let (net, node) = configure(&ctl, &ifname, cfg)
            .map_err(|e| io::Error::new(e.kind(), format!("cannot configure AppleTalk on {}: {}", ifname, e)))?;
        let nbp = ddp_socket()?;
        bind(&nbp, net, node, NBP_SOCKET).map_err(|e| io::Error::new(e.kind(), format!("cannot bind NBP socket: {}", e)))?;
        let atp = ddp_socket()?;
        let atp_port = bind(&atp, net, node, 0)?;
        let mut addrs: Vec<NetAddr> = interface_ipv4(&ifname)
            .into_iter()
            .map(|ip| NetAddr::Ip(SocketAddr::new(ip, tcp_port)))
            .collect();
        if addrs.is_empty() {
            log::warn!("AppleTalk: {} has no IPv4 address; Macs will not be able to connect over TCP", ifname);
        }
        addrs.push(NetAddr::Ddp { net, node, socket: atp_port });
        let mut ainfo = info.clone();
        // Keep the ASP status small: ATP responses carry at most 8 x 578 bytes.
        if status::build(&ainfo, &addrs).len() > 8 * ATP_MAX_DATA {
            ainfo.icon = None;
        }
        let status = status::build(&ainfo, &addrs);
        let responder = Responder {
            nbp,
            atp,
            logic: Logic {
                net,
                node,
                atp_port,
                name: info.name.clone(),
                zone: cfg.zone.as_ref().map(|z| crate::charset::config_to_mac(z, 32)),
                status,
            },
        };
        log::info!(
            "AppleTalk: {} is {}.{}, registered {}:AFPServer@* on socket {}",
            ifname,
            net,
            node,
            crate::charset::macroman_decode(&info.name),
            atp_port
        );
        drop(ctl);
        // SAFETY: called from the single-threaded master before it starts
        // serving.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            crate::signals::install_session();
            // Exit when the master goes away.
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
            drop_to_nobody();
            responder.run();
        }
        Ok(pid)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn logic() -> Logic {
            Logic { net: 0xFF10, node: 42, atp_port: 200, name: b"Pi".to_vec(), zone: None, status: vec![7u8; 700] }
        }

        fn lookup(obj: &[u8], typ: &[u8], zone: &[u8]) -> Vec<u8> {
            let mut p = vec![DDP_NBP, (NBP_LKUP << 4) | 1, 0x33];
            p.extend_from_slice(&0xFF20u16.to_be_bytes());
            p.extend_from_slice(&[9, 253, 0]); // node 9, socket 253, enum 0
            for s in [obj, typ, zone] {
                p.push(s.len() as u8);
                p.extend_from_slice(s);
            }
            p
        }

        #[test]
        fn nbp_lookup_reply() {
            let l = logic();
            let from = SockaddrAt::new(0xFF20, 9, 2);
            let (r, to) = l.nbp(&lookup(b"=", b"AFPServer", b"*"), &from).expect("reply");
            assert_eq!((u16::from_be(to.net), to.node, to.port), (0xFF20, 9, 253));
            let mut want = vec![DDP_NBP, (NBP_LKUP_REPLY << 4) | 1, 0x33, 0xFF, 0x10, 42, 200, 0];
            want.extend_from_slice(b"\x02Pi\x09AFPServer\x01*");
            assert_eq!(r, want);
            // case-insensitive, partial match, wrong type, truncated packet
            assert!(l.nbp(&lookup(b"pi", b"afpserver", b""), &from).is_some());
            assert!(l.nbp(&lookup(b"P\xC5", b"AFPServer", b"*"), &from).is_some());
            assert!(l.nbp(&lookup(b"=", b"LaserWriter", b"*"), &from).is_none());
            let p = lookup(b"=", b"AFPServer", b"*");
            for n in 0..p.len() {
                assert!(l.nbp(&p[..n], &from).is_none());
            }
        }

        #[test]
        fn asp_get_status() {
            let l = logic();
            let from = SockaddrAt::new(0xFF20, 9, 253);
            let req = [DDP_ATP, ATP_TREQ, 0xFF, 0x12, 0x34, ASP_GET_STATUS, 0, 0, 0];
            let r = l.atp(&req, &from);
            assert_eq!(r.len(), 2, "700 bytes need two ATP packets");
            assert_eq!(&r[0][..5], &[DDP_ATP, ATP_TRESP, 0, 0x12, 0x34]);
            assert_eq!(r[0].len(), 9 + ATP_MAX_DATA);
            assert_eq!(&r[1][..3], &[DDP_ATP, ATP_TRESP | ATP_EOM, 1]);
            assert_eq!(r[1].len(), 9 + 700 - ATP_MAX_DATA);
            // only the packets in the bitmap are sent
            let req = [DDP_ATP, ATP_TREQ, 0x02, 0x12, 0x34, ASP_GET_STATUS, 0, 0, 0];
            assert_eq!(l.atp(&req, &from).len(), 1);
            // session requests are refused with "server busy"
            let req = [DDP_ATP, ATP_TREQ | ATP_XO, 0x01, 0, 1, ASP_OPEN_SESS, 5, 0, 0];
            let r = l.atp(&req, &from);
            assert_eq!(&r[0][7..9], &ASP_SERVER_BUSY.to_be_bytes());
            assert!(l.atp(&req[..5], &from).is_empty());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn spawn(cfg: &AppleTalkConfig, info: &ServerInfo, tcp_port: u16) -> std::io::Result<libc::pid_t> {
    imp::spawn(cfg, info, tcp_port)
}

#[cfg(not(target_os = "linux"))]
pub fn spawn(_cfg: &AppleTalkConfig, _info: &ServerInfo, _tcp_port: u16) -> std::io::Result<libc::pid_t> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "AppleTalk is only supported on Linux"))
}

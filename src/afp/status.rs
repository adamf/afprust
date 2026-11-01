//! FPGetSrvrInfo / DSIGetStatus reply block.
//!
//! Layout (AFP 2.2):
//! ```text
//!  0  u16 offset of machine type
//!  2  u16 offset of AFP version list
//!  4  u16 offset of UAM list
//!  6  u16 offset of volume icon (0 = none)
//!  8  u16 flags
//! 10  pstring server name, padded to even length
//!     u16 offset of server signature      (kSupportsSrvrSig)
//!     u16 offset of network address list  (kSupportsTCP)
//!     ... machine type, versions, UAMs, icon, signature, addresses
//! ```

use std::net::{IpAddr, SocketAddr};

use super::buf::Writer;
use super::consts::*;

pub const AFP_VERSIONS: &[&str] = &["AFP2.2"];
/// Version strings accepted at login (AppleShare clients may ask for 2.1
/// over TCP in rare configurations).
pub const AFP_LOGIN_VERSIONS: &[&str] = &["AFP2.2", "AFPVersion 2.1"];

pub const MACHINE_TYPE: &str = "AFPRust";

#[derive(Debug, Clone)]
pub enum NetAddr {
    Ip(SocketAddr),
    Ddp { net: u16, node: u8, socket: u8 },
}

#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// Server name in MacRoman, at most 31 bytes.
    pub name: Vec<u8>,
    pub uams: Vec<&'static str>,
    pub signature: [u8; 16],
    pub save_password: bool,
    pub icon: Option<[u8; 256]>,
}

pub fn build(info: &ServerInfo, addrs: &[NetAddr]) -> Vec<u8> {
    let mut w = Writer::with_capacity(512);
    w.u16(0).u16(0).u16(0).u16(0); // offsets filled in below
    let mut flags = SRVR_SUPPORTS_COPYFILE | SRVR_SUPPORTS_SRVR_MSG | SRVR_SUPPORTS_SRVR_SIG;
    if !info.save_password {
        flags |= SRVR_NO_SAVE_PASSWORD;
    }
    let has_ip = addrs.iter().any(|a| matches!(a, NetAddr::Ip(_)));
    if has_ip {
        flags |= SRVR_SUPPORTS_TCP;
    }
    w.u16(flags);
    let name = &info.name[..info.name.len().min(31)];
    w.pstring(name);
    w.pad_even();
    let sig_off_pos = w.len();
    w.u16(0);
    let addr_off_pos = if has_ip { Some(w.len()) } else { None };
    if has_ip {
        w.u16(0);
    }

    let mach = w.len();
    w.put_u16_at(0, mach as u16);
    w.pstring(MACHINE_TYPE.as_bytes());

    let vers = w.len();
    w.put_u16_at(2, vers as u16);
    w.u8(AFP_VERSIONS.len() as u8);
    for v in AFP_VERSIONS {
        w.pstring(v.as_bytes());
    }

    let uams = w.len();
    w.put_u16_at(4, uams as u16);
    w.u8(info.uams.len() as u8);
    for u in &info.uams {
        w.pstring(u.as_bytes());
    }

    if let Some(icon) = &info.icon {
        let off = w.len();
        w.put_u16_at(6, off as u16);
        w.bytes(icon);
    }

    let sig = w.len();
    w.put_u16_at(sig_off_pos, sig as u16);
    w.bytes(&info.signature);

    if let Some(pos) = addr_off_pos {
        let off = w.len();
        w.put_u16_at(pos, off as u16);
        let entries: Vec<Vec<u8>> = addrs.iter().map(encode_addr).collect();
        w.u8(entries.len() as u8);
        for e in entries {
            w.bytes(&e);
        }
    }
    w.into_vec()
}

fn encode_addr(a: &NetAddr) -> Vec<u8> {
    let mut e = Vec::new();
    match a {
        NetAddr::Ip(sa) => match crate::config::normalize_ip(sa.ip()) {
            IpAddr::V4(v4) => {
                if sa.port() == 548 {
                    e.push(6);
                    e.push(0x01);
                    e.extend_from_slice(&v4.octets());
                } else {
                    e.push(8);
                    e.push(0x02);
                    e.extend_from_slice(&v4.octets());
                    e.extend_from_slice(&sa.port().to_be_bytes());
                }
            }
            IpAddr::V6(v6) => {
                if sa.port() == 548 {
                    e.push(18);
                    e.push(0x06);
                    e.extend_from_slice(&v6.octets());
                } else {
                    e.push(20);
                    e.push(0x07);
                    e.extend_from_slice(&v6.octets());
                    e.extend_from_slice(&sa.port().to_be_bytes());
                }
            }
        },
        NetAddr::Ddp { net, node, socket } => {
            e.push(6);
            e.push(0x03);
            e.extend_from_slice(&net.to_be_bytes());
            e.push(*node);
            e.push(*socket);
        }
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afp::buf::Reader;

    fn at(b: &[u8], off: usize) -> usize {
        u16::from_be_bytes([b[off], b[off + 1]]) as usize
    }

    #[test]
    fn layout() {
        let info = ServerInfo {
            name: b"Pi".to_vec(),
            uams: vec!["DHCAST128", "Cleartxt Passwrd"],
            signature: [7u8; 16],
            save_password: false,
            icon: None,
        };
        let addr: SocketAddr = "192.168.1.5:548".parse().unwrap();
        let b = build(&info, &[NetAddr::Ip(addr)]);
        let flags = at(&b, 8) as u16;
        assert_ne!(flags & SRVR_SUPPORTS_TCP, 0);
        assert_ne!(flags & SRVR_NO_SAVE_PASSWORD, 0);
        assert_eq!(b[10], 2);
        assert_eq!(&b[11..13], b"Pi");
        // name "Pi" (3 bytes incl. length) is odd -> one pad byte, offsets at 14
        let sig = at(&b, 14);
        assert_eq!(&b[sig..sig + 16], &[7u8; 16]);
        let addrs = at(&b, 16);
        assert_eq!(&b[addrs..addrs + 7], &[1, 6, 1, 192, 168, 1, 5]);
        let mut r = Reader::new(&b[at(&b, 2)..]);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.pstring().unwrap(), b"AFP2.2");
        let mut r = Reader::new(&b[at(&b, 4)..]);
        assert_eq!(r.u8().unwrap(), 2);
        assert_eq!(r.pstring().unwrap(), b"DHCAST128");
        assert_eq!(at(&b, 6), 0);
    }
}

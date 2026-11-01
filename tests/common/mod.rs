//! A small AFP-over-DSI client for integration tests.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use afprust::auth::dhx;

pub const OK: i32 = 0;

pub struct Client {
    pub s: TcpStream,
    id: u16,
}

pub fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

pub fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn pstr(s: &[u8]) -> Vec<u8> {
    let mut v = vec![s.len() as u8];
    v.extend_from_slice(s);
    v
}

/// Long-name path: type byte 2 + Pascal string.
pub fn path(s: &[u8]) -> Vec<u8> {
    let mut v = vec![2u8];
    v.extend(pstr(s));
    v
}

pub struct Req(pub Vec<u8>);

impl Req {
    pub fn new(cmd: u8) -> Req {
        Req(vec![cmd])
    }
    pub fn u8(mut self, v: u8) -> Req {
        self.0.push(v);
        self
    }
    pub fn u16(mut self, v: u16) -> Req {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(mut self, v: u32) -> Req {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(mut self, b: &[u8]) -> Req {
        self.0.extend_from_slice(b);
        self
    }
    pub fn path(self, p: &[u8]) -> Req {
        self.bytes(&path(p))
    }
    pub fn align(mut self) -> Req {
        if self.0.len() % 2 == 1 {
            self.0.push(0);
        }
        self
    }
}

impl Client {
    pub fn connect(port: u16) -> Client {
        let s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        Client { s, id: 0 }
    }

    pub fn raw_send(&mut self, cmd: u8, offset: u32, payload: &[u8]) -> u16 {
        self.id = self.id.wrapping_add(1);
        let mut h = vec![0u8, cmd];
        h.extend_from_slice(&self.id.to_be_bytes());
        h.extend_from_slice(&offset.to_be_bytes());
        h.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]);
        h.extend_from_slice(payload);
        self.s.write_all(&h).expect("write");
        self.id
    }

    /// Read frames until the reply to `id` arrives.
    pub fn read_reply(&mut self, id: u16) -> Option<(i32, Vec<u8>)> {
        loop {
            let mut h = [0u8; 16];
            if self.s.read_exact(&mut h).is_err() {
                return None;
            }
            let len = be32(&h, 8) as usize;
            let mut data = vec![0u8; len];
            if self.s.read_exact(&mut data).is_err() {
                return None;
            }
            if h[0] == 1 && be16(&h, 2) == id {
                return Some((be32(&h, 4) as i32, data));
            }
            // server-initiated tickle / attention: ignore
        }
    }

    pub fn dsi(&mut self, cmd: u8, offset: u32, payload: &[u8]) -> Option<(i32, Vec<u8>)> {
        let id = self.raw_send(cmd, offset, payload);
        self.read_reply(id)
    }

    pub fn get_status(&mut self) -> Vec<u8> {
        self.dsi(3, 0, &[]).expect("status").1
    }

    pub fn open_session(&mut self) {
        let (code, data) = self.dsi(4, 0, &[0x01, 4, 0, 0, 0, 2]).expect("open session");
        assert_eq!(code, 0);
        assert_eq!(data[0], 0x00);
        assert!(be32(&data, 2) >= 32000);
    }

    pub fn cmd(&mut self, r: Req) -> (i32, Vec<u8>) {
        self.dsi(2, 0, &r.0).expect("connection closed")
    }

    pub fn write_cmd(&mut self, r: Req, data: &[u8]) -> (i32, Vec<u8>) {
        let off = r.0.len() as u32;
        let mut p = r.0;
        p.extend_from_slice(data);
        self.dsi(6, off, &p).expect("connection closed")
    }

    pub fn login_guest(&mut self) -> i32 {
        let r = Req::new(18).bytes(&pstr(b"AFP2.2")).bytes(&pstr(b"No User Authent"));
        self.cmd(r).0
    }

    pub fn login_clear(&mut self, user: &str, pass: &str) -> i32 {
        let mut pw = [0u8; 8];
        pw[..pass.len().min(8)].copy_from_slice(&pass.as_bytes()[..pass.len().min(8)]);
        let r = Req::new(18)
            .bytes(&pstr(b"AFP2.2"))
            .bytes(&pstr(b"Cleartxt Passwrd"))
            .bytes(&pstr(user.as_bytes()))
            .align()
            .bytes(&pw);
        self.cmd(r).0
    }

    pub fn login_dhx(&mut self, user: &str, pass: &str) -> i32 {
        let ra = u128::from_be_bytes(dhx::random_bytes::<16>()) % (dhx::P - 1);
        let ma = dhx::powmod(dhx::G, ra, dhx::P);
        let r = Req::new(18)
            .bytes(&pstr(b"AFP2.2"))
            .bytes(&pstr(b"DHCAST128"))
            .bytes(&pstr(user.as_bytes()))
            .align()
            .bytes(&ma.to_be_bytes());
        let (code, data) = self.cmd(r);
        if code != -5001 {
            return code;
        }
        assert_eq!(data.len(), 50);
        let id = be16(&data, 0);
        let mut mb = [0u8; 16];
        mb.copy_from_slice(&data[2..18]);
        let k = dhx::powmod(u128::from_be_bytes(mb), ra, dhx::P).to_be_bytes();
        let mut enc = [0u8; 32];
        enc.copy_from_slice(&data[18..50]);
        dhx::cbc_decrypt(&k, &dhx::S2C_IV, &mut enc);
        let mut nb = [0u8; 16];
        nb.copy_from_slice(&enc[..16]);
        let nonce = u128::from_be_bytes(nb).wrapping_add(1);
        let mut blk = [0u8; 80];
        blk[..16].copy_from_slice(&nonce.to_be_bytes());
        blk[16..16 + pass.len()].copy_from_slice(pass.as_bytes());
        dhx::cbc_encrypt(&k, &dhx::C2S_IV, &mut blk);
        let r = Req::new(19).u8(0).u16(id).bytes(&blk);
        self.cmd(r).0
    }

    pub fn open_vol(&mut self, name: &[u8]) -> (i32, u16) {
        let (code, data) = self.cmd(Req::new(24).u8(0).u16(1 << 5).bytes(&pstr(name)));
        if code != 0 {
            return (code, 0);
        }
        (code, be16(&data, 2))
    }

    pub fn create_file(&mut self, vid: u16, did: u32, name: &[u8]) -> i32 {
        self.cmd(Req::new(7).u8(0).u16(vid).u32(did).path(name)).0
    }

    pub fn create_dir(&mut self, vid: u16, did: u32, name: &[u8]) -> (i32, u32) {
        let (c, d) = self.cmd(Req::new(6).u8(0).u16(vid).u32(did).path(name));
        (c, if c == 0 { be32(&d, 0) } else { 0 })
    }

    /// Returns (code, refnum).
    pub fn open_fork(&mut self, vid: u16, did: u32, name: &[u8], rsrc: bool, access: u16) -> (i32, u16) {
        let (c, d) = self.cmd(Req::new(26).u8(if rsrc { 0x80 } else { 0 }).u16(vid).u32(did).u16(0).u16(access).path(name));
        (c, if c == 0 { be16(&d, 2) } else { 0 })
    }

    pub fn write(&mut self, refnum: u16, off: u32, data: &[u8]) -> (i32, u32) {
        let (c, d) = self.write_cmd(Req::new(33).u8(0).u16(refnum).u32(off).u32(data.len() as u32), data);
        (c, if c == 0 { be32(&d, 0) } else { 0 })
    }

    pub fn read(&mut self, refnum: u16, off: u32, count: u32) -> (i32, Vec<u8>) {
        self.cmd(Req::new(27).u8(0).u16(refnum).u32(off).u32(count).u8(0).u8(0))
    }

    pub fn close_fork(&mut self, refnum: u16) -> i32 {
        self.cmd(Req::new(4).u8(0).u16(refnum)).0
    }

    /// FPGetFileDirParms; returns (code, reply).
    pub fn get_parms(&mut self, vid: u16, did: u32, name: &[u8], fbm: u16, dbm: u16) -> (i32, Vec<u8>) {
        self.cmd(Req::new(34).u8(0).u16(vid).u32(did).u16(fbm).u16(dbm).path(name))
    }

    pub fn set_finder_info(&mut self, vid: u16, did: u32, name: &[u8], fi: &[u8; 32]) -> i32 {
        self.cmd(Req::new(30).u8(0).u16(vid).u32(did).u16(1 << 5).path(name).align().bytes(fi)).0
    }

    /// Enumerate a directory; returns the long names.
    pub fn enumerate(&mut self, vid: u16, did: u32, name: &[u8]) -> (i32, Vec<(bool, Vec<u8>)>) {
        let mut out = Vec::new();
        let mut start = 1u16;
        loop {
            let (c, d) = self.cmd(
                Req::new(9).u8(0).u16(vid).u32(did).u16(1 << 6).u16(1 << 6).u16(20).u16(start).u16(4096).path(name),
            );
            if c == -5018 {
                return (0, out);
            }
            if c != 0 {
                return (c, out);
            }
            let count = be16(&d, 4) as usize;
            let mut pos = 6;
            for _ in 0..count {
                let len = d[pos] as usize;
                let is_dir = d[pos + 1] & 0x80 != 0;
                let p = pos + 2;
                let off = be16(&d, p) as usize;
                let nl = d[p + off] as usize;
                out.push((is_dir, d[p + off + 1..p + off + 1 + nl].to_vec()));
                pos += len;
            }
            start += count as u16;
        }
    }

    pub fn delete(&mut self, vid: u16, did: u32, name: &[u8]) -> i32 {
        self.cmd(Req::new(8).u8(0).u16(vid).u32(did).path(name)).0
    }

    pub fn logout(&mut self) -> i32 {
        self.cmd(Req::new(20)).0
    }
}

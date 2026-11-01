//! Smoke test against a running afprustd:
//!
//!     cargo run --example smoke -- <port> <user> <password> [cleartext]
//!
//! Logs in, opens the first volume, writes and reads back a file with a
//! resource fork and Finder info, then deletes it.

#[path = "../tests/common/mod.rs"]
mod common;

use common::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: smoke <port> <user> <password> [cleartext]");
        std::process::exit(2);
    }
    let port: u16 = args[1].parse().expect("port");
    let (user, pass) = (&args[2], &args[3]);
    let mut c = Client::connect(port);
    let st = c.get_status();
    println!("server: {}", String::from_utf8_lossy(&st[11..11 + st[10] as usize]));
    c.open_session();
    let code = if args.get(4).map(|s| s == "cleartext").unwrap_or(false) { c.login_clear(user, pass) } else { c.login_dhx(user, pass) };
    assert_eq!(code, OK, "login");
    println!("login: ok");
    let (code, d) = c.cmd(Req::new(16));
    assert_eq!(code, OK);
    let n = d[4] as usize;
    let mut pos = 5;
    let mut vols = Vec::new();
    for _ in 0..n {
        pos += 1;
        let l = d[pos] as usize;
        vols.push(d[pos + 1..pos + 1 + l].to_vec());
        pos += 1 + l;
    }
    println!("volumes: {:?}", vols.iter().map(|v| String::from_utf8_lossy(v).to_string()).collect::<Vec<_>>());
    let (code, vid) = c.open_vol(&vols[0]);
    assert_eq!(code, OK, "open volume");
    let name = b"afprust smoke test";
    let _ = c.delete(vid, 2, name);
    assert_eq!(c.create_file(vid, 2, name), OK, "create");
    let (code, r) = c.open_fork(vid, 2, name, false, 3);
    assert_eq!(code, OK);
    assert_eq!(c.write(r, 0, b"data fork").0, OK);
    c.close_fork(r);
    let (code, r) = c.open_fork(vid, 2, name, true, 3);
    assert_eq!(code, OK);
    assert_eq!(c.write(r, 0, b"resource fork").0, OK);
    c.close_fork(r);
    let mut fi = [0u8; 32];
    fi[..8].copy_from_slice(b"TEXTttxt");
    assert_eq!(c.set_finder_info(vid, 2, name, &fi), OK);
    let (code, d) = c.get_parms(vid, 2, name, (1 << 5) | (1 << 9) | (1 << 10), 0);
    assert_eq!(code, OK);
    assert_eq!(&d[6..14], b"TEXTttxt");
    assert_eq!((be32(&d, 38), be32(&d, 42)), (9, 13));
    let (code, list) = c.enumerate(vid, 2, b"");
    assert_eq!(code, OK);
    println!("entries in volume: {}", list.len());
    assert_eq!(c.delete(vid, 2, name), OK);
    c.logout();
    println!("smoke test passed");
}

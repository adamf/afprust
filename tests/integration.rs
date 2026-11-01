//! End-to-end tests against a real afprustd process.
//!
//! These need root (to exercise fork + setuid + PAM) and a test account.
//! Run them with `scripts/integration-test.sh`, which sets up a Debian
//! container, or manually:
//!
//! ```text
//! AFPRUST_IT=1 AFPRUST_IT_USER=macuser AFPRUST_IT_PASS=secret cargo test --test integration
//! ```

mod common;

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

const PORT: u16 = 15480;

struct Server {
    child: Child,
    pub base: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
    }
}

fn chown(p: &Path, uid: u32, gid: u32) {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::chown(c.as_ptr(), uid, gid) }, 0, "chown {}", p.display());
}

fn start_server(user: &afprust::user::Passwd) -> Server {
    let base = PathBuf::from(std::env::var("AFPRUST_IT_DIR").unwrap_or_else(|_| "/tmp/afprust-it".into()));
    fs::create_dir_all(&base).unwrap();
    for e in fs::read_dir(&base).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() && !p.is_symlink() {
            fs::remove_dir_all(&p).unwrap();
        } else {
            fs::remove_file(&p).unwrap();
        }
    }
    for d in ["vol", "v2vol", "ro", "state", "guest"] {
        fs::create_dir_all(base.join(d)).unwrap();
    }
    for d in ["vol", "v2vol", "ro"] {
        chown(&base.join(d), user.uid, user.gid);
        fs::set_permissions(base.join(d), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::set_permissions(base.join("guest"), fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
    let conf = format!(
        r#"
[Global]
server name = Test Server
afp listen = 127.0.0.1:{port}
uam list = uams_dhx.so uams_clrtxt.so uams_guest.so
guest account = nobody
state directory = {base}/state
log level = default:debug
login message = Welcome to the test server
tickleval = 5

[Mac Files]
path = {base}/vol
invisible dots = yes

[Old Style]
path = {base}/v2vol
appledouble = v2

[Read Only]
path = {base}/ro
read only = yes

[Guest]
path = {base}/guest

[Not For You]
path = {base}/vol
valid users = @nonexistentgroup
"#,
        port = PORT,
        base = base.display()
    );
    fs::write(base.join("afp.conf"), conf).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_afprustd"))
        .arg("-F")
        .arg(base.join("afp.conf"))
        .stdout(Stdio::null())
        .stderr(fs::File::create(base.join("server.log")).unwrap())
        .spawn()
        .expect("start afprustd");
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", PORT)).is_err() {
        assert!(Instant::now() < deadline, "server did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    Server { child, base }
}

fn env() -> Option<(String, String)> {
    if std::env::var("AFPRUST_IT").is_err() {
        eprintln!("skipping: set AFPRUST_IT=1 (and run as root) to run integration tests");
        return None;
    }
    assert!(afprust::user::is_root(), "integration tests must run as root");
    Some((std::env::var("AFPRUST_IT_USER").unwrap(), std::env::var("AFPRUST_IT_PASS").unwrap()))
}

fn session(user: &str, pass: &str) -> Client {
    let mut c = Client::connect(PORT);
    c.open_session();
    assert_eq!(c.login_dhx(user, pass), OK, "DHX login");
    c
}

fn finder_info(t: &[u8; 4], c: &[u8; 4]) -> [u8; 32] {
    let mut fi = [0u8; 32];
    fi[..4].copy_from_slice(t);
    fi[4..8].copy_from_slice(c);
    fi
}

fn file_info(c: &mut Client, vid: u16, did: u32, name: &[u8]) -> ([u8; 32], u32, u32, u32) {
    // FinderInfo, file number, data len, rsrc len
    let bm = (1 << 5) | (1 << 8) | (1 << 9) | (1 << 10);
    let (code, d) = c.get_parms(vid, did, name, bm, 0);
    assert_eq!(code, OK, "get parms of {:?}", String::from_utf8_lossy(name));
    assert_eq!(d[4], 0, "expected a file");
    let p = &d[6..];
    let mut fi = [0u8; 32];
    fi.copy_from_slice(&p[..32]);
    (fi, be32(p, 32), be32(p, 36), be32(p, 40))
}

#[test]
fn full_session() {
    let (user, pass) = match env() {
        Some(x) => x,
        None => return,
    };
    let pw = afprust::user::getpwnam(&user).expect("test user exists");
    let server = start_server(&pw);
    let base = server.base.clone();
    let vol = base.join("vol");

    // --- server info, before login ---------------------------------
    let mut c = Client::connect(PORT);
    let st = c.get_status();
    let name_len = st[10] as usize;
    assert_eq!(&st[11..11 + name_len], b"Test Server");
    let flags = be16(&st, 8);
    assert_ne!(flags & (1 << 5), 0, "TCP flag");
    let uams_off = be16(&st, 4) as usize;
    assert_eq!(st[uams_off], 3);
    c.open_session();
    // nothing but login is allowed before authentication
    assert_eq!(c.cmd(Req::new(16)).0, -5023, "FPGetSrvrParms before login");
    assert_eq!(c.open_vol(b"Mac Files").0, -5023);
    // wrong password, wrong UAM, wrong version
    assert_eq!(c.login_dhx(&user, "wrong-password"), -5023);
    assert_eq!(c.cmd(Req::new(18).bytes(&pstr(b"AFP3.4")).bytes(&pstr(b"DHCAST128"))).0, -5003);
    assert_eq!(c.cmd(Req::new(18).bytes(&pstr(b"AFP2.2")).bytes(&pstr(b"Bogus UAM"))).0, -5002);
    drop(c);

    // oversized pre-login frame: the server must drop the connection
    let mut c = Client::connect(PORT);
    c.open_session();
    let big = vec![0u8; 10_000];
    let id = c.raw_send(2, 0, &big);
    assert!(c.read_reply(id).is_none(), "oversized frame accepted");

    // cleartext login works too
    let mut c = Client::connect(PORT);
    c.open_session();
    assert_eq!(c.login_clear(&user, &pass), OK, "cleartext login");
    c.logout();

    // --- main session ----------------------------------------------
    let mut c = session(&user, &pass);

    // the session process must have dropped root (earlier, unauthenticated
    // connections may take a moment to exit)
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let ps = Command::new("ps").args(["-o", "uid=", "--ppid", &server.child.id().to_string()]).output().unwrap();
        let out = String::from_utf8_lossy(&ps.stdout).to_string();
        let uids: Vec<&str> = out.split_whitespace().collect();
        let as_user = uids.iter().any(|u| *u == pw.uid.to_string());
        let as_root = uids.iter().any(|u| *u == "0");
        if as_user && !as_root {
            break;
        }
        assert!(Instant::now() < deadline, "session processes: {:?} (want uid {} and no root)", uids, pw.uid);
        std::thread::sleep(Duration::from_millis(200));
    }

    // volume list honours valid users
    let (code, d) = c.cmd(Req::new(16));
    assert_eq!(code, OK);
    let n = d[4] as usize;
    let mut names = Vec::new();
    let mut pos = 5;
    for _ in 0..n {
        pos += 1;
        let l = d[pos] as usize;
        names.push(String::from_utf8_lossy(&d[pos + 1..pos + 1 + l]).to_string());
        pos += 1 + l;
    }
    assert!(names.contains(&"Mac Files".to_string()), "{:?}", names);
    assert!(!names.contains(&"Not For You".to_string()), "{:?}", names);
    assert_eq!(c.open_vol(b"Not For You").0, -5018);

    // login message
    let (code, d) = c.cmd(Req::new(38).u8(0).u16(0).u16(1));
    assert_eq!(code, OK);
    assert_eq!(&d[5..5 + d[4] as usize], b"Welcome to the test server");

    let (code, vid) = c.open_vol(b"mac files"); // case-insensitive
    assert_eq!(code, OK);

    // volume parameters: name and fixed-ID signature
    let (code, d) = c.cmd(Req::new(17).u8(0).u16(vid).u16((1 << 1) | (1 << 8) | (1 << 9)));
    assert_eq!(code, OK);
    assert_eq!(be16(&d, 2), 2);
    let noff = be16(&d, 4) as usize;
    assert_eq!(&d[2 + noff + 1..2 + noff + 1 + d[2 + noff] as usize], b"Mac Files");

    // directories and files
    let (code, folder) = c.create_dir(vid, 2, b"Folder");
    assert_eq!(code, OK);
    assert!(folder > 16);
    assert_eq!(c.create_dir(vid, 2, b"Folder").0, -5017, "duplicate dir");
    assert_eq!(c.create_dir(vid, 2, b"folder").0, -5017, "case-insensitive duplicate");
    assert_eq!(c.create_file(vid, 2, b"Folder\0Doc"), OK);
    assert!(vol.join("Folder/Doc").is_file());
    assert_eq!(fs::metadata(vol.join("Folder/Doc")).unwrap().uid(), pw.uid, "file owned by the user");

    // data fork
    let (code, r) = c.open_fork(vid, folder, b"Doc", false, 0x3);
    assert_eq!(code, OK);
    assert_eq!(c.write(r, 0, b"hello world"), (OK, 11));
    let (code, d) = c.read(r, 0, 100);
    assert_eq!(code, -5009, "short read reports EOF");
    assert_eq!(d, b"hello world");
    let (code, d) = c.read(r, 6, 5);
    assert_eq!(code, OK);
    assert_eq!(d, b"world");
    assert_eq!(c.close_fork(r), OK);

    // resource fork
    let rsrc: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let (code, r) = c.open_fork(vid, folder, b"Doc", true, 0x3);
    assert_eq!(code, OK);
    assert_eq!(c.write(r, 0, &rsrc).0, OK);
    assert_eq!(c.close_fork(r), OK);
    let (code, r) = c.open_fork(vid, folder, b"Doc", true, 0x1);
    assert_eq!(code, OK);
    let (_, d) = c.read(r, 0, 2000);
    assert_eq!(d, rsrc);
    c.close_fork(r);
    assert!(vol.join("Folder/._Doc").is_file(), "resource fork sidecar");

    // finder info
    assert_eq!(c.set_finder_info(vid, folder, b"Doc", &finder_info(b"TEXT", b"ttxt")), OK);
    let (fi, fnum, dlen, rlen) = file_info(&mut c, vid, folder, b"Doc");
    assert_eq!(&fi[..8], b"TEXTttxt");
    assert_eq!((dlen, rlen), (11, 1000));
    assert_eq!(fnum as u64, fs::metadata(vol.join("Folder/Doc")).unwrap().ino());
    let ea = afprust::vfs::sys::get_xattr(&vol.join("Folder/Doc"), "org.netatalk.Metadata", 1024).unwrap().unwrap();
    assert_eq!(ea.len(), 402, "netatalk-compatible metadata EA");
    assert_eq!(&ea[122..130], b"TEXTttxt");

    // enumeration hides metadata files
    let (code, list) = c.enumerate(vid, folder, b"");
    assert_eq!(code, OK);
    assert_eq!(list, vec![(false, b"Doc".to_vec())]);

    // extension mapping for files without metadata
    fs::write(vol.join("photo.jpg"), b"x").unwrap();
    let (fi, ..) = file_info(&mut c, vid, 2, b"photo.jpg");
    assert_eq!(&fi[..4], b"JPEG");

    // rename keeps the ID and moves the sidecar
    assert_eq!(c.cmd(Req::new(28).u8(0).u16(vid).u32(folder).path(b"Doc").path(b"Doc 2")).0, OK);
    assert!(vol.join("Folder/._Doc 2").is_file());
    assert!(!vol.join("Folder/._Doc").exists());
    let (_, fnum2, _, rlen) = file_info(&mut c, vid, folder, b"Doc 2");
    assert_eq!((fnum2, rlen), (fnum, 1000));

    // move to the root under a new name
    assert_eq!(c.cmd(Req::new(23).u8(0).u16(vid).u32(folder).u32(2).path(b"Doc 2").path(b"").path(b"Moved")).0, OK);
    assert!(vol.join("Moved").is_file() && vol.join("._Moved").is_file());
    // a directory cannot be moved into itself
    let (_, sub) = c.create_dir(vid, folder, b"Sub");
    assert_eq!(c.cmd(Req::new(23).u8(0).u16(vid).u32(2).u32(sub).path(b"Folder").path(b"").path(b"")).0, -5005);

    // server-side copy keeps both forks and Finder info
    assert_eq!(c.cmd(Req::new(5).u8(0).u16(vid).u32(2).u16(vid).u32(folder).path(b"Moved").path(b"").path(b"Copy")).0, OK);
    let (fi, _, dlen, rlen) = file_info(&mut c, vid, folder, b"Copy");
    assert_eq!((&fi[..8], dlen, rlen), (&b"TEXTttxt"[..], 11, 1000));

    // exchange files: contents swap, Finder info stays with the name
    for (n, data, t) in [(&b"A"[..], &b"AAA"[..], b"AAAA"), (&b"B"[..], &b"BBBBB"[..], b"BBBB")] {
        assert_eq!(c.create_file(vid, 2, n), OK);
        let (_, r) = c.open_fork(vid, 2, n, false, 3);
        c.write(r, 0, data);
        c.close_fork(r);
        assert_eq!(c.set_finder_info(vid, 2, n, &finder_info(t, b"crea")), OK);
    }
    let (_, ida, _, _) = file_info(&mut c, vid, 2, b"A");
    assert_eq!(c.cmd(Req::new(42).u8(0).u16(vid).u32(2).u32(2).path(b"A").path(b"B")).0, OK);
    assert_eq!(fs::read(vol.join("A")).unwrap(), b"BBBBB");
    assert_eq!(fs::read(vol.join("B")).unwrap(), b"AAA");
    let (fi, ida2, dlen, _) = file_info(&mut c, vid, 2, b"A");
    assert_eq!((&fi[..4], ida2, dlen), (&b"AAAA"[..], ida, 5));

    // comments
    assert_eq!(c.cmd(Req::new(48).u8(0).u16(vid)).0, OK);
    assert_eq!(c.cmd(Req::new(56).u8(0).u16(vid).u32(2).path(b"A").align().bytes(&pstr(b"a comment"))).0, OK);
    let (code, d) = c.cmd(Req::new(58).u8(0).u16(vid).u32(2).path(b"A"));
    assert_eq!((code, &d[1..]), (OK, &b"a comment"[..]));

    // desktop database: icons and APPL mappings
    let icon = [0x55u8; 256];
    assert_eq!(c.write_cmd(Req::new(192).u8(0).u16(vid).bytes(b"crea").bytes(b"APPL").u8(1).u8(0).u32(7).u16(256), &icon).0, OK);
    let (code, d) = c.cmd(Req::new(51).u8(0).u16(vid).bytes(b"crea").bytes(b"APPL").u8(1).u8(0).u16(256));
    assert_eq!((code, d.len()), (OK, 256));
    let (code, d) = c.cmd(Req::new(52).u8(0).u16(vid).bytes(b"crea").u16(1));
    assert_eq!((code, be32(&d, 0), &d[4..8]), (OK, 7, &b"APPL"[..]));
    assert_eq!(c.cmd(Req::new(53).u8(0).u16(vid).u32(2).bytes(b"crea").u32(99).path(b"A")).0, OK);
    let (code, d) = c.cmd(Req::new(55).u8(0).u16(vid).bytes(b"crea").u16(1).u16(1 << 6));
    assert_eq!((code, be32(&d, 2)), (OK, 99));

    // MacRoman names are stored as UTF-8 on disk
    assert_eq!(c.create_file(vid, 2, b"Caf\x8E"), OK);
    assert!(vol.join("Café").is_file());
    // '/' in a Mac name becomes ':' on disk
    assert_eq!(c.create_file(vid, 2, b"either/or"), OK);
    assert!(vol.join("either:or").is_file());

    // long and unmappable Unix names are mangled and still reachable
    let long = "A file name that is much longer than thirty-one characters.txt";
    fs::write(vol.join(long), b"long").unwrap();
    fs::write(vol.join("日本語.txt"), b"cjk").unwrap();
    let (_, list) = c.enumerate(vid, 2, b"");
    let mangled: Vec<Vec<u8>> = list.iter().map(|(_, n)| n.clone()).filter(|n| n.contains(&b'#')).collect();
    assert_eq!(mangled.len(), 2, "{:?}", list);
    for m in &mangled {
        assert!(m.len() <= 31);
        let (_, _, dlen, _) = file_info(&mut c, vid, 2, m);
        assert!(dlen == 4 || dlen == 3);
    }

    // dot files are invisible when "invisible dots" is set
    fs::write(vol.join(".hidden"), b"").unwrap();
    let (code, d) = c.get_parms(vid, 2, b".hidden", 1, 0);
    assert_eq!(code, OK);
    assert_ne!(be16(&d, 6) & 1, 0, "invisible attribute");

    // --- path safety ------------------------------------------------
    assert_eq!(c.create_file(vid, 2, b".."), -5019);
    assert_eq!(c.create_file(vid, 2, b"."), -5019);
    assert_eq!(c.create_file(vid, 2, b"._evil"), -5019);
    assert_eq!(c.create_dir(vid, 2, b".AppleDouble").0, -5019);
    // double NUL means "parent": it must never climb above the volume
    assert_eq!(c.create_file(vid, folder, b"\0\0\0\0\0escape"), OK);
    assert!(vol.join("escape").is_file());
    assert!(!base.join("escape").exists());
    // DID 1 accepts only the volume name
    assert_eq!(c.get_parms(vid, 1, b"Mac Files", 0, 1 << 8).0, OK);
    assert_eq!(c.get_parms(vid, 1, b"etc", 0, 1 << 8).0, -5018);
    // symlinks pointing out of the volume are invisible and unusable
    symlink("/etc", vol.join("etc-link")).unwrap();
    symlink("/etc/passwd", vol.join("passwd-link")).unwrap();
    let (_, list) = c.enumerate(vid, 2, b"");
    assert!(!list.iter().any(|(_, n)| n.starts_with(b"etc-link") || n.starts_with(b"passwd-link")), "{:?}", list);
    assert_eq!(c.open_fork(vid, 2, b"passwd-link", false, 1).0, -5018);
    assert_eq!(c.get_parms(vid, 2, b"etc-link\0passwd", 1, 0).0, -5018);
    // unknown directory IDs
    assert_eq!(c.get_parms(vid, 0x7777_7777, b"x", 1, 0).0, -5018);
    // a malformed request (truncated) is rejected, not fatal
    assert_eq!(c.cmd(Req::new(34).u8(0).u16(vid)).0, -5019);
    // bad volume id
    assert_eq!(c.get_parms(999, 2, b"A", 1, 0).0, -5019);

    // --- two sessions: share modes and byte-range locks --------------
    let mut c2 = session(&user, &pass);
    let (_, vid2) = c2.open_vol(b"Mac Files");
    let (code, r1) = c.open_fork(vid, 2, b"B", false, 0x1 | 0x20); // read, deny write
    assert_eq!(code, OK);
    assert_eq!(c2.open_fork(vid2, 2, b"B", false, 0x3).0, -5006, "deny-write conflict");
    let (code, r2) = c2.open_fork(vid2, 2, b"B", false, 0x1);
    assert_eq!(code, OK, "read is still allowed");
    c.close_fork(r1);
    c2.close_fork(r2);
    let (_, r1) = c.open_fork(vid, 2, b"B", false, 0x3);
    let (_, r2) = c2.open_fork(vid2, 2, b"B", false, 0x3);
    assert_eq!(c.cmd(Req::new(1).u8(0).u16(r1).u32(0).u32(2)).0, OK);
    assert_eq!(c2.cmd(Req::new(1).u8(0).u16(r2).u32(1).u32(2)).0, -5013, "lock conflict");
    assert_eq!(c2.write(r2, 0, b"zz").0, -5013, "write into a locked range");
    assert_eq!(c.cmd(Req::new(1).u8(1).u16(r1).u32(0).u32(2)).0, OK, "unlock");
    assert_eq!(c2.cmd(Req::new(1).u8(0).u16(r2).u32(1).u32(2)).0, OK);
    c.close_fork(r1);
    c2.close_fork(r2);
    // deleting an open file fails
    let (_, r2) = c2.open_fork(vid2, 2, b"B", false, 0x1);
    assert_eq!(c.delete(vid, 2, b"B"), -5010);
    c2.close_fork(r2);
    assert_eq!(c.delete(vid, 2, b"B"), OK);
    c2.logout();

    // directory delete: refuses non-empty, cleans metadata leftovers
    assert_eq!(c.delete(vid, 2, b"Folder"), -5007);
    assert_eq!(c.delete(vid, folder, b"Copy"), OK);
    assert_eq!(c.delete(vid, folder, b"Sub"), OK);
    fs::write(vol.join("Folder/._stale"), b"junk").unwrap();
    assert_eq!(c.delete(vid, 2, b"Folder"), OK);
    assert!(!vol.join("Folder").exists());

    // --- other volumes ------------------------------------------------
    let (code, rvid) = c.open_vol(b"Read Only");
    assert_eq!(code, OK);
    assert_eq!(c.create_file(rvid, 2, b"nope"), -5031);

    let (code, v2) = c.open_vol(b"Old Style");
    assert_eq!(code, OK);
    assert_eq!(c.create_file(v2, 2, b"Legacy"), OK);
    assert_eq!(c.set_finder_info(v2, 2, b"Legacy", &finder_info(b"WDBN", b"MSWD")), OK);
    let (_, r) = c.open_fork(v2, 2, b"Legacy", true, 3);
    c.write(r, 0, b"resource data");
    c.close_fork(r);
    let ad = fs::read(base.join("v2vol/.AppleDouble/Legacy")).unwrap();
    assert_eq!(&ad[0..8], &[0, 5, 0x16, 0x07, 0, 2, 0, 0]);
    assert_eq!(&ad[741..], b"resource data");
    let (fi, _, _, rlen) = file_info(&mut c, v2, 2, b"Legacy");
    assert_eq!((&fi[..8], rlen), (&b"WDBNMSWD"[..], 13));
    let (_, list) = c.enumerate(v2, 2, b"");
    assert_eq!(list, vec![(false, b"Legacy".to_vec())], ".AppleDouble is hidden");

    assert_eq!(c.logout(), OK);

    // --- guest -----------------------------------------------------------
    let mut g = Client::connect(PORT);
    g.open_session();
    assert_eq!(g.login_guest(), OK);
    let (_, gv) = g.open_vol(b"Mac Files");
    assert_eq!(g.create_file(gv, 2, b"guest was here"), -5000, "guest cannot write to the user's files");
    let (_, gv2) = g.open_vol(b"Guest");
    assert_eq!(g.create_file(gv2, 2, b"guest file"), OK);
    let nobody = afprust::user::getpwnam("nobody").unwrap();
    assert_eq!(fs::metadata(base.join("guest/guest file")).unwrap().uid(), nobody.uid);
    g.logout();

    let log = fs::read_to_string(base.join("server.log")).unwrap();
    assert!(log.contains("login failed"), "failed logins are logged");
    assert!(!log.contains(&pass), "the password must never be logged");
}

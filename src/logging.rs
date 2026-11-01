//! Logger writing to stderr (captured by the systemd journal) or a file.
//!
//! When stderr is connected to the journal (`JOURNAL_STREAM` is set), each
//! line carries a `<N>` syslog priority prefix so journald records the
//! correct severity. The log file, if any, is opened once at startup so
//! session processes can keep writing after dropping privileges.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use log::{Level, LevelFilter, Log, Metadata, Record};

struct Logger {
    level: LevelFilter,
    journal: bool,
    file: Option<Mutex<File>>,
}

fn priority(l: Level) -> u8 {
    match l {
        Level::Error => 3,
        Level::Warn => 4,
        Level::Info => 6,
        Level::Debug | Level::Trace => 7,
    }
}

/// Strip control characters so client-supplied strings cannot forge
/// log lines.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= self.level
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let msg = sanitize(&r.args().to_string());
        let pid = std::process::id();
        if let Some(f) = &self.file {
            let ts = timestamp();
            if let Ok(mut f) = f.lock() {
                let _ = writeln!(f, "{} afprustd[{}] {}: {}", ts, pid, r.level(), msg);
            }
            return;
        }
        let stderr = std::io::stderr();
        let mut e = stderr.lock();
        if self.journal {
            let _ = writeln!(e, "<{}>{}", priority(r.level()), msg);
        } else {
            let _ = writeln!(e, "{} afprustd[{}] {}: {}", timestamp(), pid, r.level(), msg);
        }
    }

    fn flush(&self) {}
}

fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r writes into tm, both pointers are valid.
    unsafe { libc::localtime_r(&now, &mut tm) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn init(level: LevelFilter, file: Option<&Path>) -> Result<(), String> {
    let journal = std::env::var_os("JOURNAL_STREAM").is_some();
    let file = match file {
        Some(p) => Some(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o640)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(p)
                .map_err(|e| format!("cannot open log file {}: {}", p.display(), e))?,
        )),
        None => None,
    };
    let logger = Logger { level, journal, file };
    log::set_boxed_logger(Box::new(logger)).map_err(|e| e.to_string())?;
    log::set_max_level(level);
    Ok(())
}

pub fn set_level(level: LevelFilter) {
    log::set_max_level(level);
}

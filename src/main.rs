//! afprustd: an AFP 2.2 (AppleShare over TCP/IP) server for classic Mac OS.

use std::path::PathBuf;
use std::process::ExitCode;

use afprust::config::{Config, Uam};
use afprust::{atalk, logging, master, user};

const USAGE: &str = "\
Usage: afprustd [options]

Options:
  -F, --config PATH   configuration file (default: /etc/afprust/afp.conf,
                      then /etc/netatalk/afp.conf, then netatalk 2
                      /etc/netatalk/afpd.conf + AppleVolumes.default)
  -t, --test          check the configuration, print a summary and exit
  -v, --verbose       log debug messages
  -d, --foreground    run in the foreground (always the case; for netatalk
                      compatibility)
  -V, --version       print the version and exit
  -h, --help          show this help
";

struct Args {
    config: Option<PathBuf>,
    test: bool,
    verbose: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args { config: None, test: false, verbose: false };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-F" | "--config" | "-c" => {
                a.config = Some(PathBuf::from(it.next().ok_or_else(|| format!("{} needs a path", arg))?));
            }
            "-t" | "--test" => a.test = true,
            "-v" | "--verbose" => a.verbose = true,
            "-d" | "--foreground" => {}
            "-V" | "--version" => {
                println!("afprustd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("unknown option '{}'\n\n{}", other, USAGE)),
        }
    }
    Ok(a)
}

fn print_summary(cfg: &Config) {
    println!("configuration: {}", if cfg.source.as_os_str().is_empty() { "-".into() } else { cfg.source.display().to_string() });
    println!("server name:   {}", cfg.global.server_name);
    println!(
        "listen:        {}",
        cfg.global.listen.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
    );
    println!("UAMs:          {}", cfg.global.uams.iter().map(|u| u.afp_name()).collect::<Vec<_>>().join(", "));
    println!("guest account: {}", cfg.global.guest_account);
    println!("PAM service:   {}", cfg.global.pam_service);
    println!("AppleTalk:     {}", if cfg.global.appletalk.enabled { "enabled" } else { "disabled" });
    if let Some(h) = &cfg.homes {
        println!("homes:         basedir regex '{}', name '{}'", h.basedir_regex, h.opts.name);
    }
    for v in &cfg.volumes {
        println!(
            "volume:        '{}' -> {} ({:?}{})",
            v.name,
            v.path,
            v.meta,
            if v.read_only { ", read only" } else { "" }
        );
    }
    println!("extension map: {} entries", cfg.extmap.len());
    for w in &cfg.warnings {
        println!("warning:       {}", w);
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("afprustd: {}", e);
            return ExitCode::from(2);
        }
    };
    let cfg = match Config::load(args.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("afprustd: {}", e);
            return ExitCode::from(1);
        }
    };
    if args.test {
        print_summary(&cfg);
        return ExitCode::SUCCESS;
    }
    let level = if args.verbose { log::LevelFilter::Debug } else { cfg.global.log_level };
    if let Err(e) = logging::init(level, cfg.global.log_file.as_deref()) {
        eprintln!("afprustd: {}", e);
        return ExitCode::from(1);
    }
    log::info!("afprustd {} starting, server name '{}'", env!("CARGO_PKG_VERSION"), cfg.global.server_name);
    for w in &cfg.warnings {
        log::warn!("config: {}", w);
    }
    if cfg.global.uams.contains(&Uam::ClearText) {
        log::warn!("the Cleartxt Passwrd UAM is enabled: passwords cross the network unencrypted");
    }
    if cfg.global.uams.contains(&Uam::Guest) {
        log::info!("guest access is enabled (account '{}')", cfg.global.guest_account);
    }
    if !user::is_root() {
        log::warn!("not running as root: only the current user can log in and file access uses its permissions");
    }
    if cfg.volumes.is_empty() && cfg.homes.is_none() {
        log::warn!("no volumes are configured");
    }
    // Start the AppleTalk responder before binding any TCP listener so the
    // helper process inherits no listening sockets.
    let mut helper = None;
    if cfg.global.appletalk.enabled {
        match atalk::spawn(&cfg.global.appletalk, &master::server_info(&cfg), &cfg.global.listen) {
            Ok(pid) => helper = Some(pid),
            Err(e) => log::error!("AppleTalk disabled: {}", e),
        }
    }
    let cfg_path = args.config.clone();
    let mut m = match master::Master::new(cfg, cfg_path) {
        Ok(m) => m,
        Err(e) => {
            log::error!("{}", e);
            if let Some(pid) = helper {
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
            return ExitCode::from(1);
        }
    };
    if let Some(pid) = helper {
        m.add_helper(pid);
    }
    let code = m.run();
    log::info!("afprustd stopped");
    ExitCode::from(code as u8)
}

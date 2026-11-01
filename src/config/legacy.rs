//! netatalk 2.x configuration: `afpd.conf` and `AppleVolumes.default`.

use std::path::{Path, PathBuf};

use super::ini::{parse_octal, split_list};
use super::{
    extmap, parse_listen, parse_log_level, Config, ConfigError, Global, HomesConfig, IpNet,
    MetaScheme, Principal, Uam, VolumeOptions,
};

/// Split a line into tokens, honoring double quotes and backslash escapes.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut have = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    have = true;
                }
            }
            '"' => {
                in_quote = !in_quote;
                have = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            c => {
                cur.push(c);
                have = true;
            }
        }
    }
    if have {
        out.push(cur);
    }
    out
}

/// Join continuation lines and strip comments.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut acc = String::new();
    for raw in text.lines() {
        let l = raw.trim_end_matches('\r');
        if let Some(s) = l.strip_suffix('\\') {
            acc.push_str(s);
            acc.push(' ');
            continue;
        }
        acc.push_str(l);
        let full = std::mem::take(&mut acc);
        let t = full.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.push(t.to_string());
    }
    out
}

const VALUED_OPTIONS: &[&str] = &[
    "-uamlist", "-port", "-ipaddr", "-loginmesg", "-guestname", "-tickleval", "-timeout",
    "-server_quantum", "-signature", "-setuplog", "-hostname", "-fqdn", "-defaultvol",
    "-systemvol", "-uservol", "-maccodepage", "-unixcodepage", "-admingroup", "-mimicmodel",
    "-passwdfile", "-passwdminlen", "-k5keytab", "-k5service", "-k5realm", "-ddpaddr",
    "-cnidserver", "-dsireadbuf", "-sleep", "-client_polling", "-uampath", "-icon",
    "-authprintdir", "-loginmaxfail", "-unsetuplog", "-ntdomain", "-ntseparator",
    "-dircachesize", "-tcpsndbuf", "-tcprcvbuf", "-fcelistener", "-fceevents",
    "-fcecoalesce", "-fceholdfmod", "-closevol", "-volnamelen",
];

struct LegacyServer {
    global: Global,
    volumes_file: Option<PathBuf>,
    system_file: Option<PathBuf>,
}

fn parse_afpd_conf(text: &str, w: &mut Vec<String>) -> Result<LegacyServer, ConfigError> {
    let mut g = Global::default();
    g.uams = vec![Uam::Dhx, Uam::ClearText];
    let mut volumes_file = None;
    let mut system_file = None;
    let lines = logical_lines(text);
    let line = match lines.first() {
        Some(l) => l.clone(),
        None => return Ok(LegacyServer { global: g, volumes_file, system_file }),
    };
    if lines.len() > 1 {
        w.push("afpd.conf defines several servers; only the first is used".into());
    }
    let toks = tokenize(&line);
    let mut it = toks.into_iter();
    if let Some(name) = it.next() {
        if name != "-" && !name.starts_with('-') {
            g.server_name = name;
        }
    }
    let mut port = 548u16;
    let mut ip: Option<String> = None;
    let rest: Vec<String> = it.collect();
    let mut i = 0;
    while i < rest.len() {
        let opt = rest[i].to_ascii_lowercase();
        let val = if VALUED_OPTIONS.contains(&opt.as_str()) {
            i += 1;
            rest.get(i).cloned()
        } else {
            None
        };
        i += 1;
        match (opt.as_str(), val) {
            ("-tcp", _) | ("-notcp", _) | ("-transall", _) => {}
            ("-ddp", _) => g.appletalk.enabled = true,
            ("-noddp", _) => g.appletalk.enabled = false,
            ("-uamlist", Some(v)) => {
                g.uams.clear();
                for m in split_list(&v) {
                    match Uam::from_module(&m) {
                        Ok(Some(u)) if !g.uams.contains(&u) => g.uams.push(u),
                        Ok(_) => {}
                        Err(e) => w.push(e),
                    }
                }
                if g.uams.is_empty() {
                    return Err(ConfigError("afpd.conf: -uamlist has no usable UAMs".into()));
                }
            }
            ("-nosavepassword", _) => g.save_password = false,
            ("-savepassword", _) => g.save_password = true,
            ("-port", Some(v)) => port = v.parse().map_err(|_| ConfigError(format!("afpd.conf: bad -port '{}'", v)))?,
            ("-ipaddr", Some(v)) => ip = Some(v),
            ("-loginmesg", Some(v)) => g.login_message = Some(v),
            ("-guestname", Some(v)) => g.guest_account = v,
            ("-tickleval", Some(v)) => g.tickleval = v.parse().unwrap_or(30).clamp(5, 600),
            ("-timeout", Some(v)) => g.timeout = v.parse().unwrap_or(4).clamp(1, 100),
            ("-server_quantum", Some(v)) => {
                g.server_quantum = v.parse::<u32>().unwrap_or(g.server_quantum).clamp(32_000, 8 * 1024 * 1024)
            }
            ("-signature", Some(v)) => {
                if let Some(s) = v.strip_prefix("user:") {
                    g.signature = Some(s.to_string());
                }
            }
            ("-setuplog", Some(v)) => {
                // e.g. "default log_info /var/log/afpd.log"
                let parts: Vec<&str> = v.split_whitespace().collect();
                if let Some(l) = parts.get(1) {
                    if let Some(lf) = parse_log_level(l.trim_start_matches("log_")) {
                        g.log_level = lf;
                    }
                }
                if let Some(f) = parts.get(2) {
                    g.log_file = Some(PathBuf::from(f));
                }
            }
            ("-hostname", Some(v)) => g.hostname = v,
            ("-defaultvol", Some(v)) => volumes_file = Some(PathBuf::from(v)),
            ("-systemvol", Some(v)) => system_file = Some(PathBuf::from(v)),
            ("-ddpaddr", Some(v)) => {
                if let Some((n, h)) = v.split_once('.') {
                    if let (Ok(n), Ok(h)) = (n.parse(), h.parse()) {
                        g.appletalk.address = Some((n, h));
                    }
                }
            }
            (o, _) if o.starts_with('-') => {
                // accepted and ignored
            }
            (o, _) => w.push(format!("afpd.conf: unexpected token '{}'", o)),
        }
    }
    let addr = match ip {
        Some(ip) => parse_listen(&ip, port).ok_or_else(|| ConfigError(format!("afpd.conf: bad -ipaddr '{}'", ip)))?,
        None => std::net::SocketAddr::from(([0, 0, 0, 0], port)),
    };
    g.listen = vec![addr];
    Ok(LegacyServer { global: g, volumes_file, system_file })
}

fn principals(v: &str) -> Vec<Principal> {
    Principal::parse_list(v)
}

fn apply_option(o: &mut VolumeOptions, key: &str, val: &str, w: &mut Vec<String>) {
    match key {
        "allow" => o.valid_users = principals(val),
        "deny" => o.invalid_users = principals(val),
        "rwlist" => o.rwlist = principals(val),
        "rolist" => o.rolist = principals(val),
        "password" => {
            let mut b = val.as_bytes().to_vec();
            b.truncate(8);
            o.password = Some(b);
        }
        "options" => {
            for f in val.split(',') {
                match f.trim() {
                    "ro" => o.read_only = true,
                    "invisibledots" => o.invisible_dots = true,
                    "followsymlinks" => o.follow_symlinks = true,
                    "" => {}
                    _ => {}
                }
            }
        }
        "perm" => {
            if let Some(m) = parse_octal(val) {
                o.file_perm = Some(m);
                o.directory_perm = Some(m);
            }
        }
        "fperm" => o.file_perm = parse_octal(val),
        "dperm" => o.directory_perm = parse_octal(val),
        "umask" => o.umask = parse_octal(val),
        "veto" => o.veto = val.split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect(),
        "allowed_hosts" => o.hosts_allow = val.split(',').filter_map(IpNet::parse).collect(),
        "denied_hosts" => o.hosts_deny = val.split(',').filter_map(IpNet::parse).collect(),
        "volsizelimit" => o.vol_size_limit_mib = val.parse().ok(),
        "adouble" => {
            o.meta = match val {
                "v2" => MetaScheme::AppleDouble,
                "ea" | "osx" => MetaScheme::Ea,
                _ => o.meta,
            }
        }
        "cnidscheme" | "dbpath" | "volcharset" | "maccharset" | "casefold" | "ea" | "preexec"
        | "postexec" | "root_preexec" | "root_postexec" | "cnidserver" | "ignore" => {}
        other => w.push(format!("AppleVolumes: option '{}' is not supported and was ignored", other)),
    }
}

fn parse_volumes(text: &str, w: &mut Vec<String>) -> (Vec<VolumeOptions>, Option<HomesConfig>) {
    let mut defaults = VolumeOptions { meta: MetaScheme::AppleDouble, ..Default::default() };
    let mut volumes = Vec::new();
    let mut homes = None;
    for line in logical_lines(text) {
        let toks = tokenize(&line);
        if toks.is_empty() {
            continue;
        }
        let path = toks[0].clone();
        let mut idx = 1;
        let mut name = None;
        if let Some(t) = toks.get(1) {
            if !t.contains(':') || t.starts_with('"') {
                name = Some(t.clone());
                idx = 2;
            }
        }
        if path == ":DEFAULT:" {
            for t in &toks[1..] {
                if let Some((k, v)) = t.split_once(':') {
                    apply_option(&mut defaults, k, v, w);
                }
            }
            continue;
        }
        let mut o = defaults.clone();
        for t in &toks[idx..] {
            match t.split_once(':') {
                Some((k, v)) => apply_option(&mut o, k, v, w),
                None => w.push(format!("AppleVolumes: unexpected token '{}'", t)),
            }
        }
        if path == "~" || path.starts_with("~/") {
            o.name = name.unwrap_or_else(|| "$u's home".into());
            let sub = path.trim_start_matches('~').trim_matches('/').to_string();
            homes = Some(HomesConfig {
                basedir_regex: "^/".into(),
                subpath: if sub.is_empty() { None } else { Some(sub) },
                opts: o,
            });
            continue;
        }
        o.name = name.unwrap_or_else(|| {
            Path::new(&path).file_name().and_then(|n| n.to_str()).unwrap_or("Volume").to_string()
        });
        o.path = path;
        volumes.push(o);
    }
    (volumes, homes)
}

pub fn load(afpd_conf: &Path, volumes: &Path) -> Result<Config, ConfigError> {
    let mut warnings = Vec::new();
    let server = if afpd_conf.exists() {
        let t = super::read_config_file(afpd_conf)?;
        parse_afpd_conf(&t, &mut warnings)?
    } else {
        let mut g = Global::default();
        g.uams = vec![Uam::Dhx, Uam::ClearText];
        LegacyServer { global: g, volumes_file: None, system_file: None }
    };
    let vol_path = server.volumes_file.clone().unwrap_or_else(|| volumes.to_path_buf());
    let (vols, homes) = if vol_path.exists() {
        let t = super::read_config_file(&vol_path)?;
        parse_volumes(&t, &mut warnings)
    } else {
        warnings.push(format!("{} not found; no volumes configured", vol_path.display()));
        (Vec::new(), None)
    };
    let sys = server.system_file.clone().unwrap_or_else(|| PathBuf::from(super::LEGACY_EXTMAP));
    let extmap = if sys.exists() {
        extmap::ExtMap::load(&sys).unwrap_or_else(|e| {
            warnings.push(format!("{}: {}", sys.display(), e));
            extmap::ExtMap::builtin()
        })
    } else {
        extmap::ExtMap::builtin()
    };
    Ok(Config {
        global: server.global,
        volumes: vols,
        homes,
        extmap,
        source: afpd_conf.to_path_buf(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn afpd_conf_line() {
        let mut w = Vec::new();
        let s = parse_afpd_conf(
            "# comment\n\"My Pi\" -tcp -noddp -uamlist uams_dhx.so,uams_clrtxt.so -nosavepassword -port 5480 -loginmesg \"Hello there\"\n",
            &mut w,
        )
        .unwrap();
        assert_eq!(s.global.server_name, "My Pi");
        assert_eq!(s.global.uams, vec![Uam::Dhx, Uam::ClearText]);
        assert!(!s.global.save_password);
        assert_eq!(s.global.listen[0].port(), 5480);
        assert_eq!(s.global.login_message.as_deref(), Some("Hello there"));
    }

    #[test]
    fn apple_volumes() {
        let mut w = Vec::new();
        let (v, h) = parse_volumes(
            ":DEFAULT: options:upriv,usedots\n~ \"$u Home\"\n/srv/mac \"Mac Files\" allow:@staff,bob options:ro\n/srv/other\n",
            &mut w,
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "Mac Files");
        assert!(v[0].read_only);
        assert_eq!(v[0].meta, MetaScheme::AppleDouble);
        assert_eq!(v[0].valid_users.len(), 2);
        assert_eq!(v[1].name, "other");
        assert_eq!(h.unwrap().opts.name, "$u Home");
    }
}

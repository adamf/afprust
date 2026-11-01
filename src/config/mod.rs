//! Server configuration.
//!
//! The primary format is netatalk 3/4 `afp.conf` (INI). Netatalk 2.x
//! `afpd.conf` + `AppleVolumes.default` are also understood (see
//! [`legacy`]). Unknown options are logged and ignored so that an existing
//! netatalk configuration can be reused unchanged.

pub mod extmap;
pub mod ini;
pub mod legacy;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use ini::{parse_bool, parse_octal, split_list, Ini, Section};

pub const DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/afprust/afp.conf", "/etc/netatalk/afp.conf"];
pub const LEGACY_AFPD_CONF: &str = "/etc/netatalk/afpd.conf";
pub const LEGACY_VOLUMES: &str = "/etc/netatalk/AppleVolumes.default";
pub const LEGACY_EXTMAP: &str = "/etc/netatalk/AppleVolumes.system";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/afprust";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uam {
    Guest,
    ClearText,
    Dhx,
}

impl Uam {
    pub fn afp_name(self) -> &'static str {
        match self {
            Uam::Guest => "No User Authent",
            Uam::ClearText => "Cleartxt Passwrd",
            Uam::Dhx => "DHCAST128",
        }
    }

    /// Map a netatalk UAM module name (e.g. `uams_dhx.so`) to a UAM.
    pub fn from_module(m: &str) -> Result<Option<Uam>, String> {
        let m = m.trim().to_ascii_lowercase();
        let m = m.rsplit('/').next().unwrap_or(&m).to_string();
        let base = m.trim_end_matches(".so");
        match base {
            "uams_guest" => Ok(Some(Uam::Guest)),
            "uams_clrtxt" | "uams_pam" | "uams_passwd" => Ok(Some(Uam::ClearText)),
            "uams_dhx" | "uams_dhx_pam" | "uams_dhx_passwd" => Ok(Some(Uam::Dhx)),
            // Not usable by classic Mac OS or not implemented: skip with a note.
            "uams_dhx2" | "uams_dhx2_pam" | "uams_dhx2_passwd" | "uams_gss" | "uams_srp"
            | "uams_randnum" => Ok(None),
            _ => Err(format!("unknown UAM module '{}'", m)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaScheme {
    /// netatalk 3 default: `user.org.netatalk.Metadata` xattr + `._name`
    /// resource fork files.
    Ea,
    /// netatalk 2 default: `.AppleDouble/name` files.
    AppleDouble,
    /// No metadata storage (type/creator from extension map only).
    None,
    /// Use `Ea` if the filesystem supports user xattrs, else `AppleDouble`.
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    User(String),
    Group(String),
}

impl Principal {
    pub fn parse_list(v: &str) -> Vec<Principal> {
        split_list(v)
            .into_iter()
            .map(|s| {
                if let Some(g) = s.strip_prefix('@').or_else(|| s.strip_prefix('+')) {
                    Principal::Group(g.to_string())
                } else {
                    Principal::User(s)
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    pub fn parse(s: &str) -> Option<IpNet> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let a = a.trim_start_matches('[').trim_end_matches(']');
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => {
                // netatalk also accepts dotted netmasks
                if let Ok(std::net::IpAddr::V4(m)) = p.parse::<IpAddr>() {
                    u32::from(m).count_ones() as u8
                } else {
                    p.parse::<u8>().ok().filter(|&x| x <= max)?
                }
            }
            None => max,
        };
        Some(IpNet { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix as u32);
                (u32::from(n) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix as u32);
                (u128::from(n) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }
}

/// Map IPv4-mapped IPv6 addresses to plain IPv4.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        _ => ip,
    }
}

#[derive(Debug, Clone)]
pub struct VolumeOptions {
    /// Path, may contain `$u` style variables.
    pub path: String,
    /// Volume name as shown to the client, may contain variables.
    pub name: String,
    pub valid_users: Vec<Principal>,
    pub invalid_users: Vec<Principal>,
    pub rolist: Vec<Principal>,
    pub rwlist: Vec<Principal>,
    pub read_only: bool,
    pub password: Option<Vec<u8>>,
    pub meta: MetaScheme,
    pub file_perm: Option<u32>,
    pub directory_perm: Option<u32>,
    pub umask: Option<u32>,
    pub invisible_dots: bool,
    pub follow_symlinks: bool,
    pub veto: Vec<String>,
    pub hosts_allow: Vec<IpNet>,
    pub hosts_deny: Vec<IpNet>,
    pub vol_size_limit_mib: Option<u64>,
    pub legacy_volume_size: bool,
    pub delete_veto_files: bool,
}

impl Default for VolumeOptions {
    fn default() -> Self {
        VolumeOptions {
            path: String::new(),
            name: String::new(),
            valid_users: Vec::new(),
            invalid_users: Vec::new(),
            rolist: Vec::new(),
            rwlist: Vec::new(),
            read_only: false,
            password: None,
            meta: MetaScheme::Auto,
            file_perm: None,
            directory_perm: None,
            umask: None,
            invisible_dots: false,
            follow_symlinks: false,
            veto: Vec::new(),
            hosts_allow: Vec::new(),
            hosts_deny: Vec::new(),
            vol_size_limit_mib: None,
            legacy_volume_size: false,
            delete_veto_files: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HomesConfig {
    pub basedir_regex: String,
    /// Optional subdirectory of the home directory to share.
    pub subpath: Option<String>,
    pub opts: VolumeOptions,
}

#[derive(Debug, Clone)]
pub struct AppleTalkConfig {
    pub enabled: bool,
    pub interface: Option<String>,
    pub address: Option<(u16, u8)>,
    pub zone: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Global {
    pub server_name: String,
    pub hostname: String,
    pub listen: Vec<SocketAddr>,
    pub uams: Vec<Uam>,
    pub guest_account: String,
    pub login_message: Option<String>,
    pub save_password: bool,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub tickleval: u32,
    pub timeout: u32,
    pub server_quantum: u32,
    pub log_level: log::LevelFilter,
    pub log_file: Option<PathBuf>,
    pub signature: Option<String>,
    pub state_dir: PathBuf,
    pub extmap_file: Option<PathBuf>,
    pub pam_service: String,
    pub appletalk: AppleTalkConfig,
    pub login_timeout: u32,
}

impl Default for Global {
    fn default() -> Self {
        let host = system_hostname();
        Global {
            server_name: host.clone(),
            hostname: host,
            listen: vec![
                SocketAddr::from(([0, 0, 0, 0], 548)),
            ],
            uams: vec![Uam::Dhx],
            guest_account: "nobody".into(),
            login_message: None,
            save_password: true,
            max_connections: 200,
            max_connections_per_ip: 16,
            tickleval: 30,
            timeout: 4,
            server_quantum: 0x10_0000,
            log_level: log::LevelFilter::Info,
            log_file: None,
            signature: None,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            extmap_file: None,
            pam_service: "afprust".into(),
            appletalk: AppleTalkConfig { enabled: false, interface: None, address: None, zone: None },
            login_timeout: 60,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub global: Global,
    pub volumes: Vec<VolumeOptions>,
    pub homes: Option<HomesConfig>,
    pub extmap: extmap::ExtMap,
    pub source: PathBuf,
    pub warnings: Vec<String>,
}

pub fn system_hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates
    // on success when the name fits.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r != 0 {
        return "afprust".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let full = String::from_utf8_lossy(&buf[..end]).to_string();
    // Use the short host name, like netatalk.
    full.split('.').next().unwrap_or("afprust").to_string()
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Config {
    /// Locate and load the configuration. `explicit` overrides the search.
    pub fn load(explicit: Option<&Path>) -> Result<Config, ConfigError> {
        if let Some(p) = explicit {
            return Self::load_path(p);
        }
        for p in DEFAULT_CONFIG_PATHS {
            let p = Path::new(p);
            if p.exists() {
                return Self::load_path(p);
            }
        }
        if Path::new(LEGACY_AFPD_CONF).exists() || Path::new(LEGACY_VOLUMES).exists() {
            return legacy::load(Path::new(LEGACY_AFPD_CONF), Path::new(LEGACY_VOLUMES));
        }
        Err(ConfigError(format!(
            "no configuration found (looked for {} and netatalk 2 {})",
            DEFAULT_CONFIG_PATHS.join(", "),
            LEGACY_AFPD_CONF
        )))
    }

    pub fn load_path(p: &Path) -> Result<Config, ConfigError> {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "afpd.conf" || name.starts_with("AppleVolumes") {
            let dir = p.parent().unwrap_or(Path::new("/etc/netatalk"));
            return legacy::load(&dir.join("afpd.conf"), &dir.join("AppleVolumes.default"));
        }
        let text = read_config_file(p)?;
        let mut cfg = Self::parse_ini(&text)?;
        cfg.source = p.to_path_buf();
        Ok(cfg)
    }

    pub fn parse_ini(text: &str) -> Result<Config, ConfigError> {
        let ini = Ini::parse(text).map_err(|e| ConfigError(format!("afp.conf: {}", e)))?;
        let mut warnings = Vec::new();
        let empty = Section::default();
        let gsec = ini.section("Global").unwrap_or(&empty);
        let global = parse_global(gsec, &mut warnings)?;

        let mut volumes = Vec::new();
        let mut homes = None;
        for sec in &ini.sections {
            let lname = sec.name.to_lowercase();
            if lname == "global" {
                continue;
            }
            let preset = sec
                .get("vol preset")
                .or_else(|| gsec.get("vol preset"))
                .and_then(|p| ini.section(p));
            let lookup = Lookup { sec, preset, global: gsec };
            if lname == "homes" {
                let basedir = match lookup.get("basedir regex") {
                    Some(b) => b.to_string(),
                    None => {
                        warnings.push("[Homes] has no 'basedir regex'; home volumes disabled".into());
                        continue;
                    }
                };
                if let Err(e) = regex::Regex::new(&basedir) {
                    return Err(ConfigError(format!("[Homes] invalid basedir regex: {}", e)));
                }
                let mut opts = parse_volume_opts(&lookup, &mut warnings)?;
                opts.name = lookup.get("home name").unwrap_or("$u's home").to_string();
                let subpath = sec.get("path").map(|s| s.trim_matches('/').to_string()).filter(|s| !s.is_empty());
                if let Some(sp) = &subpath {
                    if sp.split('/').any(|c| c == ".." || c == ".") {
                        return Err(ConfigError("[Homes] path must not contain '.' or '..'".into()));
                    }
                }
                homes = Some(HomesConfig { basedir_regex: basedir, subpath, opts });
                continue;
            }
            // sections without a path are presets / templates
            if sec.get("path").is_none() {
                continue;
            }
            let mut opts = parse_volume_opts(&lookup, &mut warnings)?;
            opts.name = sec.get("volume name").unwrap_or(&sec.name).to_string();
            volumes.push(opts);
        }

        let extmap = match &global.extmap_file {
            Some(p) => extmap::ExtMap::load(p).unwrap_or_else(|e| {
                warnings.push(format!("extmap file {}: {}", p.display(), e));
                extmap::ExtMap::builtin()
            }),
            None => {
                let default = Path::new("/etc/afprust/extmap.conf");
                if default.exists() {
                    extmap::ExtMap::load(default).unwrap_or_else(|e| {
                        warnings.push(format!("extmap file {}: {}", default.display(), e));
                        extmap::ExtMap::builtin()
                    })
                } else {
                    extmap::ExtMap::builtin()
                }
            }
        };

        Ok(Config { global, volumes, homes, extmap, source: PathBuf::new(), warnings })
    }
}

pub fn read_config_file(p: &Path) -> Result<String, ConfigError> {
    let meta = std::fs::metadata(p).map_err(|e| ConfigError(format!("{}: {}", p.display(), e)))?;
    if meta.len() > 4 * 1024 * 1024 {
        return Err(ConfigError(format!("{}: file too large", p.display())));
    }
    let bytes = std::fs::read(p).map_err(|e| ConfigError(format!("{}: {}", p.display(), e)))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Option lookup with netatalk precedence: volume section, then its preset,
/// then [Global].
struct Lookup<'a> {
    sec: &'a Section,
    preset: Option<&'a Section>,
    global: &'a Section,
}

impl<'a> Lookup<'a> {
    fn get(&self, k: &str) -> Option<&'a str> {
        self.sec
            .get(k)
            .or_else(|| self.preset.and_then(|p| p.get(k)))
            .or_else(|| self.global.get(k))
    }
}

fn bool_opt(l: &Lookup, k: &str, default: bool, w: &mut Vec<String>) -> bool {
    match l.get(k) {
        Some(v) => parse_bool(v).unwrap_or_else(|| {
            w.push(format!("[{}] {}: '{}' is not a boolean", l.sec.name, k, v));
            default
        }),
        None => default,
    }
}

fn parse_volume_opts(l: &Lookup, w: &mut Vec<String>) -> Result<VolumeOptions, ConfigError> {
    let mut o = VolumeOptions::default();
    o.path = l.sec.get("path").unwrap_or("").to_string();
    o.valid_users = l.get("valid users").map(Principal::parse_list).unwrap_or_default();
    o.invalid_users = l.get("invalid users").map(Principal::parse_list).unwrap_or_default();
    o.rolist = l.get("rolist").map(Principal::parse_list).unwrap_or_default();
    o.rwlist = l.get("rwlist").map(Principal::parse_list).unwrap_or_default();
    o.read_only = bool_opt(l, "read only", false, w);
    if let Some(pw) = l.sec.get("password") {
        // AFP 2.x volume passwords are at most 8 bytes.
        let mut b = pw.as_bytes().to_vec();
        b.truncate(8);
        o.password = Some(b);
    }
    let appledouble = l.get("appledouble").unwrap_or("ea").to_ascii_lowercase();
    let ea = l.get("ea").unwrap_or("auto").to_ascii_lowercase();
    o.meta = match (appledouble.as_str(), ea.as_str()) {
        ("v2", _) => MetaScheme::AppleDouble,
        (_, "none") => MetaScheme::None,
        (_, "ad") => MetaScheme::AppleDouble,
        (_, "sys") | (_, "samba") => MetaScheme::Ea,
        (_, "auto") => MetaScheme::Auto,
        (a, e) => {
            w.push(format!("[{}] unknown appledouble/ea combination '{}'/'{}', using auto", l.sec.name, a, e));
            MetaScheme::Auto
        }
    };
    o.file_perm = l.get("file perm").and_then(parse_octal);
    o.directory_perm = l.get("directory perm").and_then(parse_octal);
    o.umask = l.get("umask").and_then(parse_octal);
    o.invisible_dots = bool_opt(l, "invisible dots", false, w);
    o.follow_symlinks = bool_opt(l, "follow symlinks", false, w);
    o.delete_veto_files = bool_opt(l, "delete veto files", false, w);
    o.legacy_volume_size = bool_opt(l, "legacy volume size", false, w);
    if let Some(v) = l.get("veto files") {
        o.veto = v.split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
    }
    o.hosts_allow = parse_hosts(l.get("hosts allow"), &l.sec.name, w);
    o.hosts_deny = parse_hosts(l.get("hosts deny"), &l.sec.name, w);
    o.vol_size_limit_mib = l.get("vol size limit").and_then(|v| v.trim().parse().ok());

    for (k, _) in &l.sec.entries {
        if !KNOWN_VOLUME_OPTIONS.contains(&k.as_str()) {
            w.push(format!("[{}] option '{}' is not supported and was ignored", l.sec.name, k));
        }
    }
    Ok(o)
}

fn parse_hosts(v: Option<&str>, sec: &str, w: &mut Vec<String>) -> Vec<IpNet> {
    let mut out = Vec::new();
    if let Some(v) = v {
        for h in split_list(v) {
            match IpNet::parse(&h) {
                Some(n) => out.push(n),
                None => w.push(format!("[{}] invalid host/network '{}'", sec, h)),
            }
        }
    }
    out
}

const KNOWN_VOLUME_OPTIONS: &[&str] = &[
    "path", "volume name", "home name", "basedir regex", "vol preset", "valid users",
    "invalid users", "rolist", "rwlist", "read only", "password", "appledouble", "ea",
    "file perm", "directory perm", "umask", "invisible dots", "follow symlinks", "veto files",
    "hosts allow", "hosts deny", "vol size limit", "legacy volume size", "delete veto files",
    // accepted for compatibility, no effect for AFP 2.x clients
    "cnid scheme", "cnid server", "vol dbpath", "time machine", "convert appledouble",
    "mac charset", "vol charset", "casefold", "prodos", "unix priv", "acls", "stat vol",
    "spotlight", "search db", "network ids", "case sensitive", "volume uuid", "preexec",
    "postexec", "root preexec", "root postexec", "preexec close", "root preexec close",
    "ignored attributes", "illegal seq", "rights", "force xattr with sticky bit",
    "chmod request", "nodev", "nostat", "upriv", "usedots", "cnid dev", "home path",
];

fn parse_global(g: &Section, w: &mut Vec<String>) -> Result<Global, ConfigError> {
    let mut gl = Global::default();
    if let Some(h) = g.get("hostname") {
        gl.hostname = h.to_string();
        gl.server_name = h.split('.').next().unwrap_or(h).to_string();
    }
    if let Some(s) = g.get("server name") {
        gl.server_name = s.to_string();
    }
    let port: u16 = match g.get("afp port") {
        Some(p) => p.trim().parse().map_err(|_| ConfigError(format!("invalid afp port '{}'", p)))?,
        None => 548,
    };
    if let Some(l) = g.get("afp listen") {
        gl.listen.clear();
        for item in split_list(l) {
            gl.listen.push(parse_listen(&item, port).ok_or_else(|| ConfigError(format!("invalid afp listen address '{}'", item)))?);
        }
    } else {
        gl.listen = vec![SocketAddr::from(([0, 0, 0, 0], port))];
    }
    if let Some(list) = g.get("uam list") {
        gl.uams.clear();
        for m in split_list(list) {
            match Uam::from_module(&m) {
                Ok(Some(u)) => {
                    if !gl.uams.contains(&u) {
                        gl.uams.push(u)
                    }
                }
                Ok(None) => w.push(format!("UAM '{}' is not available to classic Mac OS clients and was skipped", m)),
                Err(e) => w.push(e),
            }
        }
        if gl.uams.is_empty() {
            return Err(ConfigError("uam list contains no usable UAMs (use uams_dhx.so, uams_clrtxt.so or uams_guest.so)".into()));
        }
    }
    if let Some(v) = g.get("guest account") {
        gl.guest_account = v.to_string();
    }
    if let Some(v) = g.get("login message") {
        gl.login_message = Some(v.to_string());
    }
    if let Some(v) = g.get("save password") {
        gl.save_password = parse_bool(v).unwrap_or(true);
    }
    if let Some(v) = g.get("max connections") {
        gl.max_connections = v.trim().parse().unwrap_or(gl.max_connections).clamp(1, 10_000);
    }
    if let Some(v) = g.get("max connections per ip") {
        gl.max_connections_per_ip = v.trim().parse().unwrap_or(gl.max_connections_per_ip).clamp(1, 10_000);
    }
    if let Some(v) = g.get("tickleval") {
        gl.tickleval = v.trim().parse().unwrap_or(30).clamp(5, 600);
    }
    if let Some(v) = g.get("timeout") {
        gl.timeout = v.trim().parse().unwrap_or(4).clamp(1, 100);
    }
    if let Some(v) = g.get("login timeout") {
        gl.login_timeout = v.trim().parse().unwrap_or(60).clamp(5, 600);
    }
    if let Some(v) = g.get("server quantum") {
        let q: u32 = parse_number(v).unwrap_or(gl.server_quantum);
        // netatalk limits: 32000 .. 256 MiB; we cap at 8 MiB to bound memory.
        gl.server_quantum = q.clamp(32_000, 8 * 1024 * 1024);
    }
    if let Some(v) = g.get("log level") {
        gl.log_level = parse_log_level(v).unwrap_or_else(|| {
            w.push(format!("unknown log level '{}'", v));
            log::LevelFilter::Info
        });
    }
    if let Some(v) = g.get("log file") {
        gl.log_file = Some(PathBuf::from(v));
    }
    if let Some(v) = g.get("signature") {
        gl.signature = Some(v.to_string());
    }
    if let Some(v) = g.get("state directory") {
        gl.state_dir = PathBuf::from(v);
    }
    if let Some(v) = g.get("extmap file") {
        gl.extmap_file = Some(PathBuf::from(v));
    }
    if let Some(v) = g.get("pam service") {
        gl.pam_service = v.to_string();
    }
    if let Some(v) = g.get("mac charset") {
        let n = v.to_ascii_uppercase().replace('-', "_");
        if n != "MAC_ROMAN" && n != "MACROMAN" {
            w.push(format!("mac charset '{}' is not supported, using MAC_ROMAN", v));
        }
    }
    gl.appletalk.enabled = g.get("appletalk").and_then(parse_bool).unwrap_or(false);
    gl.appletalk.interface = g.get("ddp interface").map(|s| s.to_string());
    gl.appletalk.zone = g.get("ddp zone").map(|s| s.to_string());
    if let Some(a) = g.get("ddp address") {
        gl.appletalk.address = parse_ddp_address(a);
        if gl.appletalk.address.is_none() {
            w.push(format!("invalid ddp address '{}', expected net.node", a));
        }
    }
    for (k, _) in &g.entries {
        if !KNOWN_GLOBAL_OPTIONS.contains(&k.as_str()) && !KNOWN_VOLUME_OPTIONS.contains(&k.as_str()) {
            w.push(format!("[Global] option '{}' is not supported and was ignored", k));
        }
    }
    Ok(gl)
}

const KNOWN_GLOBAL_OPTIONS: &[&str] = &[
    "hostname", "server name", "afp port", "afp listen", "uam list", "guest account",
    "login message", "save password", "max connections", "max connections per ip", "tickleval",
    "timeout", "login timeout", "server quantum", "log level", "log file", "signature",
    "state directory", "extmap file", "pam service", "mac charset", "appletalk", "ddp interface",
    "ddp zone", "ddp address",
    // accepted for compatibility, no effect
    "uam path", "set password", "zeroconf", "zeroconf name", "mimic model", "legacy icon",
    "unix charset", "dsireadbuf", "tcprcvbuf", "tcpsndbuf", "use sendfile", "recvfile",
    "splice size", "dircachesize", "dircache size", "dircache mode", "sleep time",
    "disconnect time", "client polling", "close vol", "afpstats", "fqdn", "advertise ssh",
    "admin group", "admin auth user", "force user", "force group", "spotlight", "k5 keytab",
    "k5 service", "k5 realm", "nt domain", "ad domain", "fce listener", "fce events",
    "fce coalesce", "fce holdfmod", "map acls", "cnid listen", "cnid mysql host",
    "afp interfaces", "passwd file", "passwd minlen", "valid shellcheck", "veto message",
    "volnamelen", "vol dbnest", "server notifications", "afpstats group", "sqlite",
    "solaris share reservations", "strict locking", "vol preset", "ldap auth method",
];

fn parse_number(v: &str) -> Option<u32> {
    let v = v.trim();
    if let Some(h) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).ok()
    } else {
        v.parse().ok()
    }
}

pub fn parse_listen(item: &str, default_port: u16) -> Option<SocketAddr> {
    if let Ok(sa) = item.parse::<SocketAddr>() {
        return Some(sa);
    }
    let bare = item.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    // "1.2.3.4:548" handled above; hostname-like values are not supported
    None
}

fn parse_ddp_address(a: &str) -> Option<(u16, u8)> {
    let (n, h) = a.trim().split_once('.')?;
    Some((n.parse().ok()?, h.parse().ok()?))
}

pub fn parse_log_level(v: &str) -> Option<log::LevelFilter> {
    // netatalk syntax: "default:info afpdaemon:debug" or just "info"
    let mut chosen = None;
    for item in v.split_whitespace() {
        let (typ, lvl) = item.split_once(':').unwrap_or(("default", item));
        let lf = match lvl.to_ascii_lowercase().as_str() {
            "severe" | "error" => log::LevelFilter::Error,
            "warn" | "warning" => log::LevelFilter::Warn,
            "note" | "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            l if l.starts_with("debug") || l == "maxdebug" => log::LevelFilter::Trace,
            _ => return None,
        };
        if typ == "default" || chosen.is_none() {
            chosen = Some(lf);
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netatalk3_config() {
        let t = r#"
[Global]
server name = Pi Server
uam list = uams_dhx.so uams_dhx2.so uams_clrtxt.so uams_guest.so
afp listen = 192.168.1.10 [::1]:5480
log level = default:debug

[Homes]
basedir regex = /home

[Shared]
path = /srv/shared
valid users = @staff bob
read only = yes
appledouble = v2

[template]
file perm = 0640

[Media]
vol preset = template
path = /srv/media
volume name = Media Files
hosts allow = 192.168.1.0/24
"#;
        let c = Config::parse_ini(t).unwrap();
        assert_eq!(c.global.server_name, "Pi Server");
        assert_eq!(c.global.uams, vec![Uam::Dhx, Uam::ClearText, Uam::Guest]);
        assert_eq!(c.global.listen.len(), 2);
        assert_eq!(c.global.listen[1].port(), 5480);
        assert_eq!(c.global.log_level, log::LevelFilter::Debug);
        assert!(c.homes.is_some());
        assert_eq!(c.volumes.len(), 2);
        let s = &c.volumes[0];
        assert_eq!(s.name, "Shared");
        assert!(s.read_only);
        assert_eq!(s.meta, MetaScheme::AppleDouble);
        assert_eq!(s.valid_users, vec![Principal::Group("staff".into()), Principal::User("bob".into())]);
        let m = &c.volumes[1];
        assert_eq!(m.name, "Media Files");
        assert_eq!(m.file_perm, Some(0o640));
        assert!(m.hosts_allow[0].contains("192.168.1.77".parse().unwrap()));
        assert!(!m.hosts_allow[0].contains("192.168.2.77".parse().unwrap()));
        assert!(m.hosts_allow[0].contains("::ffff:192.168.1.5".parse().unwrap()));
    }

    #[test]
    fn bad_regex_rejected() {
        assert!(Config::parse_ini("[Homes]\nbasedir regex = (\n").is_err());
    }
}

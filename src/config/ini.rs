//! Minimal INI parser with netatalk/iniparser semantics.
//!
//! - Section names keep their case (they become volume names), lookups are
//!   case-insensitive.
//! - Keys are case-insensitive and internal whitespace is collapsed, so
//!   `Valid  Users` and `valid users` are the same key.
//! - `;` and `#` start comment lines; an unquoted ` ;` or ` #` starts a
//!   trailing comment.
//! - A trailing backslash continues a line.
//! - Values may be wrapped in double quotes.

use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Section {
    pub name: String,
    pub entries: Vec<(String, String)>,
    pub line: usize,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&str> {
        let k = normalize_key(key);
        // later entries override earlier ones
        self.entries
            .iter()
            .rev()
            .find(|(ek, _)| *ek == k)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ini {
    pub sections: Vec<Section>,
    index: HashMap<String, usize>,
}

#[derive(Debug)]
pub struct IniError {
    pub line: usize,
    pub msg: String,
}

impl std::fmt::Display for IniError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

pub fn normalize_key(k: &str) -> String {
    k.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn strip_value(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        return v[1..v.len() - 1].to_string();
    }
    // strip trailing comments introduced by whitespace + ; or #
    let bytes = v.as_bytes();
    let mut in_quote = false;
    for i in 0..bytes.len() {
        match bytes[i] {
            b'"' => in_quote = !in_quote,
            b';' | b'#' if !in_quote && i > 0 && bytes[i - 1].is_ascii_whitespace() => {
                return v[..i].trim().to_string();
            }
            _ => {}
        }
    }
    v.to_string()
}

impl Ini {
    pub fn parse(text: &str) -> Result<Ini, IniError> {
        let mut ini = Ini::default();
        let mut current: Option<usize> = None;
        let mut pending = String::new();
        let mut pending_start = 0usize;

        for (idx, raw) in text.lines().enumerate() {
            let lineno = idx + 1;
            let line = raw.trim_end_matches('\r');
            if pending.is_empty() {
                pending_start = lineno;
            }
            if let Some(stripped) = line.strip_suffix('\\') {
                pending.push_str(stripped);
                continue;
            }
            pending.push_str(line);
            let full = std::mem::take(&mut pending);
            let l = full.trim();
            if l.is_empty() || l.starts_with(';') || l.starts_with('#') {
                continue;
            }
            if l.starts_with('[') {
                let end = l.find(']').ok_or(IniError {
                    line: pending_start,
                    msg: "unterminated section header".into(),
                })?;
                let name = l[1..end].trim().to_string();
                if name.is_empty() {
                    return Err(IniError { line: pending_start, msg: "empty section name".into() });
                }
                let key = name.to_lowercase();
                if let Some(&i) = ini.index.get(&key) {
                    // duplicate section: merge, like iniparser
                    current = Some(i);
                } else {
                    ini.sections.push(Section { name, entries: Vec::new(), line: pending_start });
                    let i = ini.sections.len() - 1;
                    ini.index.insert(key, i);
                    current = Some(i);
                }
                continue;
            }
            let eq = match l.find('=') {
                Some(p) => p,
                None => {
                    return Err(IniError {
                        line: pending_start,
                        msg: format!("expected 'key = value', got '{}'", l),
                    })
                }
            };
            let key = normalize_key(&l[..eq]);
            let value = strip_value(&l[eq + 1..]);
            let sec = match current {
                Some(i) => i,
                None => {
                    return Err(IniError {
                        line: pending_start,
                        msg: "option outside of a section".into(),
                    })
                }
            };
            ini.sections[sec].entries.push((key, value));
        }
        Ok(ini)
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.index.get(&name.to_lowercase()).map(|&i| &self.sections[i])
    }
}

pub fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Some(true),
        "no" | "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// Parse an octal permission value such as `0660`.
pub fn parse_octal(v: &str) -> Option<u32> {
    let v = v.trim();
    let v = v.strip_prefix("0o").unwrap_or(v);
    u32::from_str_radix(v, 8).ok().filter(|&m| m <= 0o7777)
}

/// Split a list value on commas and/or whitespace, honoring double quotes.
pub fn split_list(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in v.chars() {
        match c {
            '"' => in_quote = !in_quote,
            ',' | ' ' | '\t' if !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let t = "; comment\n[Global]\nserver name = My Server\nuam list = uams_dhx.so, uams_clrtxt.so ; trailing\n\n[My Volume]\npath = /srv/share\nValid  Users = alice @staff\n";
        let ini = Ini::parse(t).unwrap();
        let g = ini.section("global").unwrap();
        assert_eq!(g.get("Server Name"), Some("My Server"));
        assert_eq!(g.get("uam list"), Some("uams_dhx.so, uams_clrtxt.so"));
        let v = ini.section("my volume").unwrap();
        assert_eq!(v.name, "My Volume");
        assert_eq!(v.get("valid users"), Some("alice @staff"));
    }

    #[test]
    fn continuation_and_quotes() {
        let t = "[a]\nk = one \\\ntwo\nq = \"x ; y\"\n";
        let ini = Ini::parse(t).unwrap();
        let a = ini.section("a").unwrap();
        assert_eq!(a.get("k"), Some("one two"));
        assert_eq!(a.get("q"), Some("x ; y"));
    }

    #[test]
    fn errors() {
        assert!(Ini::parse("k = v\n").is_err());
        assert!(Ini::parse("[x\n").is_err());
        assert!(Ini::parse("[x]\njunk\n").is_err());
    }

    #[test]
    fn lists() {
        assert_eq!(split_list("a, b  c,\"d e\""), vec!["a", "b", "c", "d e"]);
    }
}

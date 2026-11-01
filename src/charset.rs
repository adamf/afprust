//! Mac OS Roman <-> UTF-8 conversion and AFP 2.x name mangling.
//!
//! Classic Mac OS clients speak MacRoman with names of at most 31 bytes.
//! Server-side names are UTF-8 (NFC). Like netatalk 3, a '/' in a Mac name
//! is stored as ':' on disk and vice versa. Unix names that cannot be shown
//! to the client (too long, unmappable characters, invalid UTF-8) are
//! "mangled" to `prefix#HEXID.ext`, in the same style as netatalk.

use unicode_normalization::UnicodeNormalization;

/// Unicode code points for MacRoman bytes 0x80..=0xFF.
const MACROMAN_HIGH: [u16; 128] = [
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, // 80
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E8, // 88
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3, // 90
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC, // 98
    0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6, 0x00DF, // A0
    0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6, 0x00D8, // A8
    0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202, 0x2211, // B0
    0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x00E6, 0x00F8, // B8
    0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB, // C0
    0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152, 0x0153, // C8
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x25CA, // D0
    0x00FF, 0x0178, 0x2044, 0x20AC, 0x2039, 0x203A, 0xFB01, 0xFB02, // D8
    0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA, 0x00C1, // E0
    0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3, 0x00D4, // E8
    0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6, 0x02DC, // F0
    0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB, 0x02C7, // F8
];

/// Maximum length of an AFP 2.x long name.
pub const MAX_MAC_NAME: usize = 31;

pub fn macroman_to_char(b: u8) -> char {
    if b < 0x80 {
        b as char
    } else {
        // All table entries are valid scalar values (no surrogates).
        char::from_u32(MACROMAN_HIGH[(b - 0x80) as usize] as u32).unwrap_or('?')
    }
}

pub fn char_to_macroman(c: char) -> Option<u8> {
    let cp = c as u32;
    if cp < 0x80 {
        return Some(cp as u8);
    }
    if cp == 0x00A4 {
        // Pre-Mac OS 8.5 mapping of 0xDB (currency sign).
        return Some(0xDB);
    }
    MACROMAN_HIGH
        .iter()
        .position(|&u| u as u32 == cp)
        .map(|i| 0x80 + i as u8)
}

/// Decode MacRoman bytes to a String.
pub fn macroman_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| macroman_to_char(b)).collect()
}

/// Encode a string as MacRoman. Fails if any character has no mapping.
pub fn macroman_encode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.nfc() {
        out.push(char_to_macroman(c)?);
    }
    Some(out)
}

/// Encode as MacRoman, replacing unmappable characters with '_' and
/// truncating to `max` bytes.
pub fn macroman_encode_lossy(s: &str, max: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len().min(max));
    for c in s.nfc() {
        if out.len() >= max {
            break;
        }
        out.push(char_to_macroman(c).unwrap_or(b'_'));
    }
    out
}

/// Errors converting a client-supplied name.
#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    Invalid,
}

/// Convert a Mac (MacRoman) file name from the client to a Unix name.
///
/// Rejects names that could escape the current directory or are otherwise
/// unsafe as a single path component.
pub fn mac_to_unix(mac: &[u8]) -> Result<Vec<u8>, NameError> {
    if mac.is_empty() {
        return Err(NameError::Empty);
    }
    let mut s = String::with_capacity(mac.len() * 2);
    for &b in mac {
        match b {
            0 => return Err(NameError::Invalid),
            b'/' => s.push(':'),
            _ => s.push(macroman_to_char(b)),
        }
    }
    let s: String = s.nfc().collect();
    if s == "." || s == ".." || s.contains('/') || s.contains('\0') {
        return Err(NameError::Invalid);
    }
    if s.len() > 255 {
        return Err(NameError::Invalid);
    }
    Ok(s.into_bytes())
}

/// Convert a Unix name to its MacRoman form if it is representable
/// without mangling.
pub fn unix_to_mac_exact(unix: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(unix).ok()?;
    let mut out = Vec::with_capacity(s.len());
    for c in s.nfc() {
        let c = if c == ':' { '/' } else { c };
        out.push(char_to_macroman(c)?);
    }
    if out.is_empty() || out.len() > MAX_MAC_NAME {
        return None;
    }
    Some(out)
}

/// Produce the name shown to the client for a Unix name: the exact MacRoman
/// form if possible, otherwise a mangled name embedding the object ID.
pub fn unix_to_mac(unix: &[u8], id: u32) -> Vec<u8> {
    if let Some(m) = unix_to_mac_exact(unix) {
        return m;
    }
    mangle(unix, id)
}

/// Build a mangled name `prefix#HEXID.ext` of at most 31 bytes.
pub fn mangle(unix: &[u8], id: u32) -> Vec<u8> {
    let s = String::from_utf8_lossy(unix).replace(':', "/");
    let (stem, ext) = match s.rfind('.') {
        Some(i) if i > 0 && s.len() - i <= 6 => (&s[..i], &s[i..]),
        _ => (&s[..], ""),
    };
    let tag = format!("#{:X}", id);
    let ext_bytes = macroman_encode_lossy(ext, 6);
    let room = MAX_MAC_NAME.saturating_sub(tag.len() + ext_bytes.len());
    let mut out = macroman_encode_lossy(stem, room);
    if out.is_empty() && room > 0 {
        out.push(b'_');
    }
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&ext_bytes);
    out
}

/// If `mac` looks like a mangled name, return the embedded ID.
pub fn demangle_id(mac: &[u8]) -> Option<u32> {
    let hash = mac.iter().rposition(|&b| b == b'#')?;
    let rest = &mac[hash + 1..];
    let hex_len = rest.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if hex_len == 0 || hex_len > 8 {
        return None;
    }
    let tail = &rest[hex_len..];
    if !tail.is_empty() && tail[0] != b'.' {
        return None;
    }
    let hex = std::str::from_utf8(&rest[..hex_len]).ok()?;
    u32::from_str_radix(hex, 16).ok()
}

/// Case-insensitive comparison of two MacRoman names.
pub fn mac_eq_ci(a: &[u8], b: &[u8]) -> bool {
    let fa: String = macroman_decode(a).nfc().flat_map(|c| c.to_lowercase()).collect();
    let fb: String = macroman_decode(b).nfc().flat_map(|c| c.to_lowercase()).collect();
    fa == fb
}

/// Convert a UTF-8 configuration string (server or volume name) to MacRoman.
pub fn config_to_mac(s: &str, max: usize) -> Vec<u8> {
    macroman_encode_lossy(s, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_bytes() {
        for b in 0x20u8..=0xFF {
            if b == 0x7F || b == b'/' || b == b':' {
                continue;
            }
            let c = macroman_to_char(b);
            assert_eq!(char_to_macroman(c), Some(b), "byte {:02X}", b);
        }
    }

    #[test]
    fn slash_colon_swap() {
        assert_eq!(mac_to_unix(b"a/b").unwrap(), b"a:b".to_vec());
        assert_eq!(unix_to_mac_exact(b"a:b").unwrap(), b"a/b".to_vec());
    }

    #[test]
    fn rejects_dot_names() {
        assert!(mac_to_unix(b".").is_err());
        assert!(mac_to_unix(b"..").is_err());
        assert!(mac_to_unix(b"").is_err());
        assert!(mac_to_unix(b"a\0b").is_err());
    }

    #[test]
    fn accents() {
        // "Café" with MacRoman 0x8E for é
        let unix = mac_to_unix(b"Caf\x8E").unwrap();
        assert_eq!(String::from_utf8(unix.clone()).unwrap(), "Café");
        assert_eq!(unix_to_mac_exact(&unix).unwrap(), b"Caf\x8E".to_vec());
        // decomposed input should still map
        let nfd = "Cafe\u{301}".as_bytes();
        assert_eq!(unix_to_mac_exact(nfd).unwrap(), b"Caf\x8E".to_vec());
    }

    #[test]
    fn mangling() {
        let long = "This is a very long file name that exceeds the limit.txt";
        let m = unix_to_mac(long.as_bytes(), 0x1A2B);
        assert!(m.len() <= MAX_MAC_NAME);
        assert!(m.ends_with(b"#1A2B.txt"));
        assert_eq!(demangle_id(&m), Some(0x1A2B));
        let cjk = "日本語.doc";
        let m = unix_to_mac(cjk.as_bytes(), 0x99);
        assert_eq!(demangle_id(&m), Some(0x99));
        assert_eq!(demangle_id(b"plain name"), None);
        assert_eq!(demangle_id(b"price #1 list"), None);
    }

    #[test]
    fn icon_cr() {
        let unix = mac_to_unix(b"Icon\r").unwrap();
        assert_eq!(unix, b"Icon\r".to_vec());
        assert_eq!(unix_to_mac_exact(&unix).unwrap(), b"Icon\r".to_vec());
    }
}

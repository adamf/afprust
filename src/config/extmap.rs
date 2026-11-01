//! File extension -> Mac type/creator mapping (netatalk `extmap.conf` /
//! `AppleVolumes.system` format):
//!
//! ```text
//! .txt   "TEXT"  "ttxt"   ASCII Text   SimpleText   text/plain
//! ```
//!
//! The mapping is only used for files that have no stored Finder info.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct ExtMap {
    map: HashMap<String, ([u8; 4], [u8; 4])>,
    default: Option<([u8; 4], [u8; 4])>,
}

const BUILTIN: &str = r#"
.txt  "TEXT" "ttxt"
.text "TEXT" "ttxt"
.me   "TEXT" "ttxt"
.1st  "TEXT" "ttxt"
.c    "TEXT" "ttxt"
.h    "TEXT" "ttxt"
.md   "TEXT" "ttxt"
.csv  "TEXT" "XCEL"
.htm  "TEXT" "MOSS"
.html "TEXT" "MOSS"
.rtf  "TEXT" "MSWD"
.doc  "WDBN" "MSWD"
.xls  "XLS8" "XCEL"
.ppt  "SLD8" "PPT3"
.pdf  "PDF " "CARO"
.ps   "TEXT" "vgrd"
.eps  "EPSF" "vgrd"
.jpg  "JPEG" "ogle"
.jpeg "JPEG" "ogle"
.gif  "GIFf" "ogle"
.png  "PNGf" "ogle"
.tif  "TIFF" "ogle"
.tiff "TIFF" "ogle"
.bmp  "BMPp" "ogle"
.pct  "PICT" "ttxt"
.pict "PICT" "ttxt"
.psd  "8BPS" "8BIM"
.mov  "MooV" "TVOD"
.qt   "MooV" "TVOD"
.mpg  "MPEG" "TVOD"
.mpeg "MPEG" "TVOD"
.avi  "VfW " "TVOD"
.mp3  "MPG3" "TVOD"
.aif  "AIFF" "TVOD"
.aiff "AIFF" "TVOD"
.wav  "WAVE" "TVOD"
.mid  "Midi" "TVOD"
.midi "Midi" "TVOD"
.mod  "STrk" "SCPL"
.sit  "SIT!" "SITx"
.sitx "SITX" "SITx"
.sea  "APPL" "aust"
.hqx  "TEXT" "SITx"
.bin  "SIT!" "SITx"
.cpt  "PACT" "SITx"
.zip  "ZIP " "SITx"
.gz   "Gzip" "SITx"
.tgz  "Gzip" "SITx"
.tar  "TARF" "SITx"
.z    "ZIVU" "SITx"
.dmg  "devi" "ddsk"
.img  "rohd" "ddsk"
.smi  "APPL" "oneb"
.iso  "rohd" "ddsk"
.toast "CDr3" "Vmgd"
.dsk  "dImg" "dCpy"
.ttf  "tfil" "movr"
.wri  "WORD" "MSWD"
"#;

fn four(s: &str) -> Option<[u8; 4]> {
    let mac = crate::charset::macroman_encode(s)?;
    if mac.len() != 4 {
        return None;
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&mac);
    Some(a)
}

/// Pull the next double-quoted field out of `s`.
fn quoted(s: &str) -> Option<(&str, &str)> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some((&rest[..end], &rest[end + 1..]))
}

impl ExtMap {
    pub fn builtin() -> ExtMap {
        Self::parse(BUILTIN)
    }

    pub fn load(p: &Path) -> std::io::Result<ExtMap> {
        let meta = std::fs::metadata(p)?;
        if meta.len() > 4 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too large"));
        }
        let bytes = std::fs::read(p)?;
        Ok(Self::parse(&String::from_utf8_lossy(&bytes)))
    }

    pub fn parse(text: &str) -> ExtMap {
        let mut m = ExtMap::default();
        for line in text.lines() {
            let l = line.trim();
            if !l.starts_with('.') {
                continue;
            }
            let (ext, rest) = match l.find(|c: char| c.is_whitespace()) {
                Some(i) => (&l[..i], &l[i..]),
                None => continue,
            };
            let (t, rest) = match quoted(rest) {
                Some(x) => x,
                None => continue,
            };
            let (c, _) = match quoted(rest) {
                Some(x) => x,
                None => continue,
            };
            let (t, c) = match (four(t), four(c)) {
                (Some(t), Some(c)) => (t, c),
                _ => continue,
            };
            if ext == "." {
                m.default = Some((t, c));
            } else {
                m.map.insert(ext[1..].to_lowercase(), (t, c));
            }
        }
        m
    }

    /// Type and creator for a Unix file name.
    pub fn lookup(&self, name: &[u8]) -> Option<([u8; 4], [u8; 4])> {
        let s = std::str::from_utf8(name).ok();
        if let Some(s) = s {
            if let Some(dot) = s.rfind('.') {
                if dot > 0 {
                    if let Some(tc) = self.map.get(&s[dot + 1..].to_lowercase()) {
                        return Some(*tc);
                    }
                }
            }
        }
        self.default
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines() {
        let m = ExtMap::parse("# c\n.txt \"TEXT\" \"ttxt\" ASCII\n.   \"????\" \"????\"\n#.x \"AAAA\" \"BBBB\"\n");
        assert_eq!(m.lookup(b"a.TXT"), Some((*b"TEXT", *b"ttxt")));
        assert_eq!(m.lookup(b"foo"), Some((*b"????", *b"????")));
        assert_eq!(m.lookup(b"a.x"), Some((*b"????", *b"????")));
        assert!(ExtMap::builtin().lookup(b"photo.jpg").is_some());
    }
}

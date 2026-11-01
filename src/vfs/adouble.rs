//! AppleDouble metadata formats, byte-compatible with netatalk:
//!
//! - `EA`: netatalk 3+ metadata blob stored in the
//!   `org.netatalk.Metadata` extended attribute (402 bytes).
//! - `V2`: netatalk 2 `.AppleDouble/name` files (741-byte header followed
//!   by the resource fork).
//! - `OSX`: `._name` sidecar files holding Finder info and the resource fork
//!   (as written by netatalk 3 and Mac OS X).
//!
//! All parsing is bounds checked; malformed headers are ignored.

pub const MAGIC: u32 = 0x0005_1607;
pub const VERSION2: u32 = 0x0002_0000;
pub const VERSION_EA: u32 = 0x0002_0002;
pub const FILLER_NETATALK: &[u8; 16] = b"Netatalk        ";

pub const HEADER_LEN: usize = 26;
pub const ENTRY_LEN: usize = 12;

pub const EID_RFORK: u32 = 2;
pub const EID_NAME: u32 = 3;
pub const EID_COMMENT: u32 = 4;
pub const EID_FILEDATESI: u32 = 8;
pub const EID_FINDERI: u32 = 9;
pub const EID_SHORTNAME: u32 = 13;
pub const EID_AFPFILEI: u32 = 14;
pub const EID_DID: u32 = 15;
pub const EID_PRODOSFILEI: u32 = 11;
pub const EID_PRIVDEV: u32 = 16;
pub const EID_PRIVINO: u32 = 17;
pub const EID_PRIVSYN: u32 = 18;
pub const EID_PRIVID: u32 = 19;

pub const LEN_COMMENT: usize = 200;
pub const MAX_COMMENT: usize = 199;
pub const DATASZ_EA: usize = 402;
pub const DATASZ_V2: usize = 741;
pub const DATASZ_OSX: usize = 82;
/// Offset of the resource fork in a netatalk-written `._` file.
pub const RFORK_OFF_OSX: u64 = 82;
pub const RFORK_OFF_V2: u64 = 741;

/// netatalk's AFP "never" date for backups.
pub const DATE_START: u32 = 0x8000_0000;

/// FinderInfo fdFlags kIsInvisible (big-endian u16 at offset 8).
pub const FINDER_FLAG_INVISIBLE: u16 = 1 << 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub finder_info: [u8; 32],
    pub comment: Vec<u8>,
    /// AFP dates: create, modify, backup, access.
    pub dates: Option<[u32; 4]>,
    pub afpfilei: [u8; 4],
    /// PRIVDEV, PRIVINO, PRIVSYN, PRIVID, preserved for netatalk.
    pub private: [u8; 28],
}

impl Default for Meta {
    fn default() -> Self {
        Meta { finder_info: [0; 32], comment: Vec::new(), dates: None, afpfilei: [0; 4], private: [0; 28] }
    }
}

impl Meta {
    pub fn attr(&self) -> u16 {
        u16::from_be_bytes([self.afpfilei[2], self.afpfilei[3]])
    }

    pub fn set_attr(&mut self, a: u16) {
        self.afpfilei[2..4].copy_from_slice(&a.to_be_bytes());
    }

    pub fn finder_flags(&self) -> u16 {
        u16::from_be_bytes([self.finder_info[8], self.finder_info[9]])
    }

    pub fn set_finder_flags(&mut self, f: u16) {
        self.finder_info[8..10].copy_from_slice(&f.to_be_bytes());
    }

    pub fn type_creator(&self) -> ([u8; 4], [u8; 4]) {
        let mut t = [0u8; 4];
        let mut c = [0u8; 4];
        t.copy_from_slice(&self.finder_info[0..4]);
        c.copy_from_slice(&self.finder_info[4..8]);
        (t, c)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub id: u32,
    pub off: u32,
    pub len: u32,
    /// Position of this entry's descriptor within the header.
    pub desc_pos: usize,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub entries: Vec<Entry>,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn parse_header(buf: &[u8]) -> Option<Header> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    if be32(buf, 0) != MAGIC {
        return None;
    }
    let version = be32(buf, 4);
    if version != VERSION2 && version != VERSION_EA {
        return None;
    }
    let n = u16::from_be_bytes([buf[24], buf[25]]) as usize;
    if n == 0 || n > 64 || HEADER_LEN + n * ENTRY_LEN > buf.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let p = HEADER_LEN + i * ENTRY_LEN;
        entries.push(Entry { id: be32(buf, p), off: be32(buf, p + 4), len: be32(buf, p + 8), desc_pos: p });
    }
    Some(Header { version, entries })
}

impl Header {
    pub fn entry(&self, id: u32) -> Option<Entry> {
        self.entries.iter().copied().find(|e| e.id == id)
    }
}

fn entry_data<'a>(buf: &'a [u8], h: &Header, id: u32) -> Option<&'a [u8]> {
    let e = h.entry(id)?;
    let start = e.off as usize;
    let end = start.checked_add(e.len as usize)?;
    if end > buf.len() {
        return None;
    }
    Some(&buf[start..end])
}

/// Parse metadata from an EA blob or the header region of a v2 file.
pub fn parse_meta(buf: &[u8]) -> Option<Meta> {
    let h = parse_header(buf)?;
    let mut m = Meta::default();
    if let Some(fi) = entry_data(buf, &h, EID_FINDERI) {
        let n = fi.len().min(32);
        m.finder_info[..n].copy_from_slice(&fi[..n]);
    }
    if let Some(c) = entry_data(buf, &h, EID_COMMENT) {
        let c = &c[..c.len().min(MAX_COMMENT)];
        // Treat an all-zero comment area as empty.
        let end = c.iter().rposition(|&b| b != 0).map(|p| p + 1).unwrap_or(0);
        m.comment = c[..end].to_vec();
    }
    if let Some(d) = entry_data(buf, &h, EID_FILEDATESI) {
        if d.len() >= 16 {
            m.dates = Some([be32(d, 0), be32(d, 4), be32(d, 8), be32(d, 12)]);
        }
    }
    if let Some(a) = entry_data(buf, &h, EID_AFPFILEI) {
        if a.len() >= 4 {
            m.afpfilei.copy_from_slice(&a[..4]);
        }
    }
    let privs = [(EID_PRIVDEV, 0usize, 8usize), (EID_PRIVINO, 8, 8), (EID_PRIVSYN, 16, 8), (EID_PRIVID, 24, 4)];
    for (id, at, len) in privs {
        if let Some(d) = entry_data(buf, &h, id) {
            if d.len() >= len {
                m.private[at..at + len].copy_from_slice(&d[..len]);
            }
        }
    }
    Some(m)
}

struct Layout {
    id: u32,
    off: usize,
    len: usize,
}

fn write_header(out: &mut [u8], version: u32, layout: &[Layout], lens: &dyn Fn(u32, usize) -> usize) {
    out[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    out[4..8].copy_from_slice(&version.to_be_bytes());
    out[8..24].copy_from_slice(FILLER_NETATALK);
    out[24..26].copy_from_slice(&(layout.len() as u16).to_be_bytes());
    for (i, l) in layout.iter().enumerate() {
        let p = HEADER_LEN + i * ENTRY_LEN;
        out[p..p + 4].copy_from_slice(&l.id.to_be_bytes());
        out[p + 4..p + 8].copy_from_slice(&(l.off as u32).to_be_bytes());
        out[p + 8..p + 12].copy_from_slice(&(lens(l.id, l.len) as u32).to_be_bytes());
    }
}

fn fill_entries(out: &mut [u8], layout: &[Layout], m: &Meta) {
    for l in layout {
        let dst = &mut out[l.off..l.off + l.len];
        match l.id {
            EID_FINDERI => dst.copy_from_slice(&m.finder_info),
            EID_COMMENT => {
                let c = &m.comment[..m.comment.len().min(MAX_COMMENT)];
                dst[..c.len()].copy_from_slice(c);
            }
            EID_FILEDATESI => {
                let d = m.dates.unwrap_or([0, 0, DATE_START, 0]);
                for (i, v) in d.iter().enumerate() {
                    dst[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
                }
            }
            EID_AFPFILEI => dst.copy_from_slice(&m.afpfilei),
            EID_PRIVDEV => dst.copy_from_slice(&m.private[0..8]),
            EID_PRIVINO => dst.copy_from_slice(&m.private[8..16]),
            EID_PRIVSYN => dst.copy_from_slice(&m.private[16..24]),
            EID_PRIVID => dst.copy_from_slice(&m.private[24..28]),
            _ => {}
        }
    }
}

const fn ea_layout() -> [Layout; 8] {
    // Offsets match netatalk's entry_order_ea.
    [
        Layout { id: EID_FINDERI, off: 122, len: 32 },
        Layout { id: EID_COMMENT, off: 154, len: 200 },
        Layout { id: EID_FILEDATESI, off: 354, len: 16 },
        Layout { id: EID_AFPFILEI, off: 370, len: 4 },
        Layout { id: EID_PRIVDEV, off: 374, len: 8 },
        Layout { id: EID_PRIVINO, off: 382, len: 8 },
        Layout { id: EID_PRIVSYN, off: 390, len: 8 },
        Layout { id: EID_PRIVID, off: 398, len: 4 },
    ]
}

const fn v2_layout() -> [Layout; 12] {
    // Offsets match netatalk's entry_order2 (the RFORK entry is added
    // separately because its length is the fork length).
    [
        Layout { id: EID_NAME, off: 182, len: 255 },
        Layout { id: EID_COMMENT, off: 437, len: 200 },
        Layout { id: EID_FILEDATESI, off: 637, len: 16 },
        Layout { id: EID_FINDERI, off: 653, len: 32 },
        Layout { id: EID_DID, off: 685, len: 4 },
        Layout { id: EID_AFPFILEI, off: 689, len: 4 },
        Layout { id: EID_SHORTNAME, off: 693, len: 12 },
        Layout { id: EID_PRODOSFILEI, off: 705, len: 8 },
        Layout { id: EID_PRIVDEV, off: 713, len: 8 },
        Layout { id: EID_PRIVINO, off: 721, len: 8 },
        Layout { id: EID_PRIVSYN, off: 729, len: 8 },
        Layout { id: EID_PRIVID, off: 737, len: 4 },
    ]
}

fn comment_len(id: u32, default: usize, m: &Meta) -> usize {
    match id {
        EID_COMMENT => m.comment.len().min(MAX_COMMENT),
        EID_NAME | EID_SHORTNAME => 0,
        _ => default,
    }
}

/// Serialize metadata as a netatalk EA blob.
pub fn serialize_ea(m: &Meta) -> Vec<u8> {
    let layout = ea_layout();
    let mut out = vec![0u8; DATASZ_EA];
    write_header(&mut out, VERSION_EA, &layout, &|id, d| comment_len(id, d, m));
    fill_entries(&mut out, &layout, m);
    out
}

/// Serialize the 741-byte header of a v2 AppleDouble file whose resource
/// fork (at offset 741) has `rfork_len` bytes.
pub fn serialize_v2(m: &Meta, rfork_len: u64) -> Vec<u8> {
    let layout = v2_layout();
    let mut out = vec![0u8; DATASZ_V2];
    // 13 entries: the 12 above plus the resource fork.
    out[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    out[4..8].copy_from_slice(&VERSION2.to_be_bytes());
    out[8..24].copy_from_slice(FILLER_NETATALK);
    out[24..26].copy_from_slice(&13u16.to_be_bytes());
    for (i, l) in layout.iter().enumerate() {
        let p = HEADER_LEN + i * ENTRY_LEN;
        out[p..p + 4].copy_from_slice(&l.id.to_be_bytes());
        out[p + 4..p + 8].copy_from_slice(&(l.off as u32).to_be_bytes());
        out[p + 8..p + 12].copy_from_slice(&(comment_len(l.id, l.len, m) as u32).to_be_bytes());
    }
    let p = HEADER_LEN + 12 * ENTRY_LEN;
    out[p..p + 4].copy_from_slice(&EID_RFORK.to_be_bytes());
    out[p + 4..p + 8].copy_from_slice(&(RFORK_OFF_V2 as u32).to_be_bytes());
    out[p + 8..p + 12].copy_from_slice(&(rfork_len.min(u32::MAX as u64) as u32).to_be_bytes());
    fill_entries(&mut out, &layout, m);
    out
}

/// Serialize the 82-byte header of a `._` file.
pub fn serialize_osx(finder_info: &[u8; 32], rfork_len: u64) -> Vec<u8> {
    let mut out = vec![0u8; DATASZ_OSX];
    out[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    out[4..8].copy_from_slice(&VERSION2.to_be_bytes());
    out[8..24].copy_from_slice(FILLER_NETATALK);
    out[24..26].copy_from_slice(&2u16.to_be_bytes());
    let p = HEADER_LEN;
    out[p..p + 4].copy_from_slice(&EID_FINDERI.to_be_bytes());
    out[p + 4..p + 8].copy_from_slice(&50u32.to_be_bytes());
    out[p + 8..p + 12].copy_from_slice(&32u32.to_be_bytes());
    let p = HEADER_LEN + ENTRY_LEN;
    out[p..p + 4].copy_from_slice(&EID_RFORK.to_be_bytes());
    out[p + 4..p + 8].copy_from_slice(&(RFORK_OFF_OSX as u32).to_be_bytes());
    out[p + 8..p + 12].copy_from_slice(&(rfork_len.min(u32::MAX as u64) as u32).to_be_bytes());
    out[50..82].copy_from_slice(finder_info);
    out
}

/// Location of the resource fork within a sidecar file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RforkLoc {
    pub offset: u64,
    pub len: u64,
    /// Byte position of the RFORK entry's length field in the header.
    pub len_field: u64,
}

/// Find the resource fork in a sidecar header. The fork must be the last
/// entry in the file for us to be able to grow it.
pub fn rfork_location(buf: &[u8]) -> Option<RforkLoc> {
    let h = parse_header(buf)?;
    let e = h.entry(EID_RFORK)?;
    // The fork must not overlap the header or any other entry.
    let start = e.off as u64;
    let hdr_end = (HEADER_LEN + h.entries.len() * ENTRY_LEN) as u64;
    if start < hdr_end {
        return None;
    }
    for o in &h.entries {
        if o.id == EID_RFORK {
            continue;
        }
        let os = o.off as u64;
        let oe = os + o.len as u64;
        if oe > start && os < start + e.len as u64 {
            return None;
        }
        if os > start {
            // Another entry after the fork: we cannot resize safely.
            return None;
        }
    }
    Some(RforkLoc { offset: start, len: e.len as u64, len_field: (e.desc_pos + 8) as u64 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Meta {
        let mut m = Meta::default();
        m.finder_info[..8].copy_from_slice(b"TEXTttxt");
        m.set_finder_flags(FINDER_FLAG_INVISIBLE);
        m.comment = b"hello".to_vec();
        m.dates = Some([1, 2, DATE_START, 4]);
        m.set_attr(0x0100);
        m.private[27] = 9;
        m
    }

    #[test]
    fn ea_roundtrip() {
        let m = sample();
        let b = serialize_ea(&m);
        assert_eq!(b.len(), DATASZ_EA);
        assert_eq!(parse_meta(&b).unwrap(), m);
    }

    #[test]
    fn v2_roundtrip() {
        let m = sample();
        let b = serialize_v2(&m, 1234);
        assert_eq!(b.len(), DATASZ_V2);
        assert_eq!(parse_meta(&b).unwrap(), m);
        let loc = rfork_location(&b).unwrap();
        assert_eq!(loc.offset, 741);
        assert_eq!(loc.len, 1234);
    }

    #[test]
    fn osx_rfork() {
        let fi = [1u8; 32];
        let b = serialize_osx(&fi, 77);
        let loc = rfork_location(&b).unwrap();
        assert_eq!(loc, RforkLoc { offset: 82, len: 77, len_field: (HEADER_LEN + ENTRY_LEN + 8) as u64 });
        assert_eq!(parse_meta(&b).unwrap().finder_info, fi);
    }

    #[test]
    fn hostile_headers() {
        // entry pointing beyond the buffer
        let mut b = serialize_ea(&sample());
        b[HEADER_LEN + 4..HEADER_LEN + 8].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        let m = parse_meta(&b).unwrap();
        assert_eq!(m.finder_info, [0u8; 32]);
        // absurd entry count
        let mut b = serialize_ea(&sample());
        b[24..26].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(parse_meta(&b).is_none());
        assert!(parse_meta(&[0u8; 10]).is_none());
    }
}

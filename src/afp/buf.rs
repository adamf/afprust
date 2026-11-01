//! Bounds-checked big-endian readers and writers for AFP packets.
//!
//! Every read checks the remaining length and fails with `kFPParmErr`
//! instead of panicking, so malformed client packets can never cause
//! out-of-bounds access.

use super::consts::AfpError;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], AfpError> {
        if self.remaining() < n {
            return Err(AfpError::ParamErr);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), AfpError> {
        self.bytes(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Result<u8, AfpError> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, AfpError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, AfpError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32(&mut self) -> Result<i32, AfpError> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> Result<u64, AfpError> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], AfpError> {
        let b = self.bytes(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// Pascal string: one length byte followed by that many bytes.
    pub fn pstring(&mut self) -> Result<&'a [u8], AfpError> {
        let len = self.u8()? as usize;
        self.bytes(len)
    }

    /// Skip one byte if the current offset is odd (AFP pads to even offsets
    /// relative to the start of the command block).
    pub fn align2(&mut self) {
        if self.pos & 1 == 1 && self.pos < self.buf.len() {
            self.pos += 1;
        }
    }
}

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::with_capacity(256) }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer { buf: Vec::with_capacity(n) }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Write a Pascal string, truncating to 255 bytes.
    pub fn pstring(&mut self, s: &[u8]) -> &mut Self {
        let n = s.len().min(255);
        self.buf.push(n as u8);
        self.buf.extend_from_slice(&s[..n]);
        self
    }

    pub fn pad_even(&mut self) -> &mut Self {
        if self.buf.len() & 1 == 1 {
            self.buf.push(0);
        }
        self
    }

    pub fn put_u16_at(&mut self, at: usize, v: u16) {
        self.buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_bounds() {
        let data = [1u8, 2, 3];
        let mut r = Reader::new(&data);
        assert_eq!(r.u16().unwrap(), 0x0102);
        assert!(r.u16().is_err());
        assert_eq!(r.u8().unwrap(), 3);
        assert!(r.u8().is_err());
    }

    #[test]
    fn pstring_overrun() {
        let data = [5u8, b'a', b'b'];
        let mut r = Reader::new(&data);
        assert!(r.pstring().is_err());
    }
}

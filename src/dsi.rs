//! DSI (Data Stream Interface): AFP over TCP framing.
//!
//! Each message is a 16-byte header followed by `length` payload bytes.
//! Frame sizes are bounded (much more tightly before login), reads use an
//! overall deadline so a slow client cannot pin a session forever, and all
//! header fields are validated before use.

use std::io::{self, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

pub const HEADER_LEN: usize = 16;

pub const FLAG_REQUEST: u8 = 0;
pub const FLAG_REPLY: u8 = 1;

pub const CMD_CLOSE_SESSION: u8 = 1;
pub const CMD_COMMAND: u8 = 2;
pub const CMD_GET_STATUS: u8 = 3;
pub const CMD_OPEN_SESSION: u8 = 4;
pub const CMD_TICKLE: u8 = 5;
pub const CMD_WRITE: u8 = 6;
pub const CMD_ATTENTION: u8 = 8;

const OPT_SERVER_QUANTUM: u8 = 0x00;
const OPT_ATTN_QUANTUM: u8 = 0x01;

/// Attention codes (high bits) sent with DSIAttention.
pub const ATTN_SHUTDOWN: u16 = 0x8000;
pub const ATTN_SERVER_MSG: u16 = 0x2000;

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub flags: u8,
    pub command: u8,
    pub request_id: u16,
    /// Error code in replies; data offset in DSIWrite requests.
    pub code: u32,
    pub length: u32,
}

impl Header {
    fn parse(b: &[u8; HEADER_LEN]) -> Header {
        Header {
            flags: b[0],
            command: b[1],
            request_id: u16::from_be_bytes([b[2], b[3]]),
            code: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            length: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        }
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = self.flags;
        b[1] = self.command;
        b[2..4].copy_from_slice(&self.request_id.to_be_bytes());
        b[4..8].copy_from_slice(&self.code.to_be_bytes());
        b[8..12].copy_from_slice(&self.length.to_be_bytes());
        b
    }
}

pub struct Frame {
    pub header: Header,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum ReadError {
    /// No data within the poll interval.
    Idle,
    /// The peer closed the connection.
    Closed,
    /// A signal interrupted the wait.
    Interrupted,
    /// Malformed or oversized frame.
    Protocol(String),
    Io(io::Error),
}

pub struct Dsi {
    pub stream: TcpStream,
    server_request_id: u16,
    pub max_payload: usize,
    pub server_quantum: u32,
    pub attention_quantum: u32,
    frame_timeout: Duration,
}

/// Wait for readability. Returns Ok(true) if readable, Ok(false) on
/// timeout, Err(Interrupted) on EINTR.
fn poll_readable(fd: i32, timeout: Duration) -> Result<bool, ReadError> {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: pfd is a valid pollfd array of length 1.
    let r = unsafe { libc::poll(&mut pfd, 1, ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Err(ReadError::Interrupted);
        }
        return Err(ReadError::Io(e));
    }
    Ok(r > 0)
}

impl Dsi {
    pub fn new(stream: TcpStream, max_payload: usize, server_quantum: u32) -> io::Result<Dsi> {
        stream.set_nodelay(true)?;
        stream.set_write_timeout(Some(Duration::from_secs(120)))?;
        Ok(Dsi {
            stream,
            server_request_id: 0,
            max_payload,
            server_quantum,
            attention_quantum: 2,
            frame_timeout: Duration::from_secs(60),
        })
    }

    fn read_exact_deadline(&mut self, buf: &mut [u8], deadline: Instant) -> Result<(), ReadError> {
        let fd = self.stream.as_raw_fd();
        let mut off = 0;
        while off < buf.len() {
            let now = Instant::now();
            if now >= deadline {
                return Err(ReadError::Protocol("timed out reading frame".into()));
            }
            match poll_readable(fd, deadline - now) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(ReadError::Interrupted) => {
                    if crate::signals::terminating() {
                        return Err(ReadError::Interrupted);
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
            // SAFETY: reading into the unfilled tail of buf.
            let n = unsafe {
                libc::recv(
                    fd,
                    buf[off..].as_mut_ptr() as *mut libc::c_void,
                    buf.len() - off,
                    0,
                )
            };
            if n == 0 {
                return Err(ReadError::Closed);
            }
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                    io::ErrorKind::ConnectionReset => return Err(ReadError::Closed),
                    _ => return Err(ReadError::Io(e)),
                }
            }
            off += n as usize;
        }
        Ok(())
    }

    /// Wait up to `idle` for the next frame and read it completely.
    pub fn read_frame(&mut self, idle: Duration) -> Result<Frame, ReadError> {
        let fd = self.stream.as_raw_fd();
        if !poll_readable(fd, idle)? {
            return Err(ReadError::Idle);
        }
        let deadline = Instant::now() + self.frame_timeout;
        let mut hb = [0u8; HEADER_LEN];
        self.read_exact_deadline(&mut hb, deadline)?;
        let header = Header::parse(&hb);
        if header.flags > FLAG_REPLY {
            return Err(ReadError::Protocol(format!("bad DSI flags {}", header.flags)));
        }
        let len = header.length as usize;
        if len > self.max_payload {
            return Err(ReadError::Protocol(format!(
                "DSI frame of {} bytes exceeds limit of {}",
                len, self.max_payload
            )));
        }
        let mut payload = vec![0u8; len];
        self.read_exact_deadline(&mut payload, deadline)?;
        Ok(Frame { header, payload })
    }

    fn send(&mut self, h: Header, payload: &[u8]) -> io::Result<()> {
        let hb = h.encode();
        if payload.len() <= 8192 {
            let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
            buf.extend_from_slice(&hb);
            buf.extend_from_slice(payload);
            self.stream.write_all(&buf)
        } else {
            self.stream.write_all(&hb)?;
            self.stream.write_all(payload)
        }
    }

    pub fn reply(&mut self, req: &Header, code: i32, payload: &[u8]) -> io::Result<()> {
        let h = Header {
            flags: FLAG_REPLY,
            command: req.command,
            request_id: req.request_id,
            code: code as u32,
            length: payload.len() as u32,
        };
        self.send(h, payload)
    }

    fn next_id(&mut self) -> u16 {
        let id = self.server_request_id;
        self.server_request_id = self.server_request_id.wrapping_add(1);
        id
    }

    pub fn send_tickle(&mut self) -> io::Result<()> {
        let id = self.next_id();
        self.send(
            Header { flags: FLAG_REQUEST, command: CMD_TICKLE, request_id: id, code: 0, length: 0 },
            &[],
        )
    }

    pub fn send_attention(&mut self, code: u16) -> io::Result<()> {
        let id = self.next_id();
        self.send(
            Header { flags: FLAG_REQUEST, command: CMD_ATTENTION, request_id: id, code: 0, length: 2 },
            &code.to_be_bytes(),
        )
    }

    pub fn send_close(&mut self) -> io::Result<()> {
        let id = self.next_id();
        self.send(
            Header { flags: FLAG_REQUEST, command: CMD_CLOSE_SESSION, request_id: id, code: 0, length: 0 },
            &[],
        )
    }

    /// Handle DSIOpenSession: parse client options, reply with ours.
    pub fn open_session(&mut self, req: &Header, payload: &[u8]) -> io::Result<()> {
        let mut i = 0;
        while i + 1 < payload.len() {
            let opt = payload[i];
            let len = payload[i + 1] as usize;
            i += 2;
            if i + len > payload.len() {
                break;
            }
            if opt == OPT_ATTN_QUANTUM && len == 4 {
                let q = u32::from_be_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]]);
                self.attention_quantum = q.min(1024);
            }
            i += len;
        }
        // Only the server request quantum: the replay-cache option is an
        // AFP 3 feature that AppleShare Client 3.x does not know about.
        let mut out = Vec::with_capacity(6);
        out.push(OPT_SERVER_QUANTUM);
        out.push(4);
        out.extend_from_slice(&self.server_quantum.to_be_bytes());
        self.reply(req, 0, &out)
    }
}

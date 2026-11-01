//! afprust: an AFP 2.2 file server for classic Mac OS clients.
//!
//! The binary is `afprustd`; the library exists so integration tests and
//! tools can reuse the protocol code.

pub mod afp;
pub mod atalk;
pub mod auth;
pub mod charset;
pub mod config;
pub mod dsi;
pub mod icon;
pub mod logging;
pub mod master;
pub mod signals;
pub mod user;
pub mod util;
pub mod vfs;

//! Stub for platforms without `AF_PACKET`.
//!
//! The type exists so that code naming it still compiles; every operation
//! reports `Unsupported`.

use super::Config;
use crate::{Frame, L2Device, L2Handler, MacAddr, Result};
use std::io;
use std::sync::Arc;

/// An `AF_PACKET` socket. Not available on this platform.
#[derive(Debug)]
pub struct Socket(());

impl Socket {
    /// Always fails with [`io::ErrorKind::Unsupported`] off Linux.
    pub fn open(_cfg: Config) -> Result<Arc<Socket>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AF_PACKET sockets are Linux-only",
        ))
    }

    /// The interface this socket is bound to.
    pub fn interface(&self) -> &str {
        ""
    }

    /// The interface MTU.
    pub fn mtu(&self) -> usize {
        0
    }
}

impl L2Device for Socket {
    fn set_handler(&self, _h: L2Handler) {}

    fn send(&self, _frame: &Frame) -> Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AF_PACKET sockets are Linux-only",
        ))
    }

    fn hw_addr(&self) -> MacAddr {
        MacAddr::zero()
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

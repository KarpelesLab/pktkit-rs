//! Virtual TCP listener (IPv6).
//!
//! See [`listener`](super::listener) for the same caveat: full inbound
//! TCP requires the in-tree `vtcp` engine, which isn't ported yet.
//!
//! TODO(slirp): wire `Listener6::accept` to the vtcp engine.

use crate::Result;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub(crate) struct ListenerKey6 {
    pub(crate) ip: [u8; 16],
    pub(crate) port: u16,
}

#[derive(Debug)]
pub struct Listener6 {
    pub(crate) addr: SocketAddrV6,
    pub(crate) closed: Arc<AtomicBool>,
}

impl Listener6 {
    pub(crate) fn new(addr: SocketAddrV6) -> Listener6 {
        Listener6 {
            addr,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn addr(&self) -> SocketAddrV6 {
        self.addr
    }

    pub fn accept(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Other, "listener closed"));
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "virtual TCP6 accept needs vtcp; not yet ported",
        ))
    }

    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        Ok(())
    }
}

pub(crate) fn resolve_v6(address: &str) -> Result<SocketAddrV6> {
    if let Ok(sa) = address.parse::<SocketAddrV6>() {
        return Ok(sa);
    }
    if let Some(rest) = address.strip_prefix("[]:") {
        if let Ok(port) = rest.parse::<u16>() {
            return Ok(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid address"))
}

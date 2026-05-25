//! Virtual TCP listener (IPv4).
//!
//! Mirrors `slirp/listener.go`. Full integration with a virtual-side TCP
//! engine is gated on the in-tree `vtcp` crate landing; for now we expose
//! the public type and registration plumbing so consumers can register
//! listening sockets the stack will know about, but actually accepting an
//! incoming connection returns a "not implemented" error. The stack's
//! TCP NAT path is unaffected — only the "inbound virtual TCP" surface
//! is gated.
//!
//! TODO(slirp): when vtcp lands, plumb `Listener::accept` through to the
//! virtual TCP accept queue.

use crate::Result;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Key used to find a listener by (IP, port). Wildcard IP is `0.0.0.0`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub(crate) struct ListenerKey {
    pub(crate) ip: [u8; 4],
    pub(crate) port: u16,
}

/// A virtual TCP listener bound to a (virtual IP, port) inside a slirp stack.
#[derive(Debug)]
pub struct Listener {
    pub(crate) addr: SocketAddrV4,
    pub(crate) closed: Arc<AtomicBool>,
    // TODO(slirp): once vtcp.Conn is available, an `accept_ch: Receiver<...>`
    // will live here, fed by the stack's segment dispatcher.
}

impl Listener {
    pub(crate) fn new(addr: SocketAddrV4) -> Listener {
        Listener {
            addr,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The address this listener is bound to.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// Block until a connection is available. Currently returns
    /// `ErrorKind::Unsupported` — virtual inbound TCP requires a vtcp
    /// engine that isn't yet ported.
    pub fn accept(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Other, "listener closed"));
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "virtual TCP accept needs vtcp; not yet ported",
        ))
    }

    /// Close the listener.
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        Ok(())
    }
}

/// Convert a parsed socket-address-like string ("ip:port") to a `SocketAddrV4`.
pub(crate) fn resolve_v4(address: &str) -> Result<SocketAddrV4> {
    if let Ok(sa) = address.parse::<SocketAddrV4>() {
        return Ok(sa);
    }
    // Allow ":port" form (wildcard IPv4 address).
    if let Some(rest) = address.strip_prefix(':') {
        if let Ok(port) = rest.parse::<u16>() {
            return Ok(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid address"))
}

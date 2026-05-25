//! High-level virtual client built on top of [`vtcp`](crate::vtcp).
//!
//! See the module-level doc for the porting status. This file lays out the
//! type surface so callers can hold a `Client` and ask it for DNS / TCP
//! handles; the actual wire-level integration with `vtcp::Conn` lands once
//! the TCP engine settles.

use crate::{IpPrefix, L3Device, L3Handler, Packet, Result};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Knobs for [`Client`].
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// IPv4/IPv6 prefix assigned to the client.
    pub prefix: Option<IpPrefix>,
    /// DNS servers to use (overrides anything learned via DHCP).
    pub dns: Vec<IpAddr>,
}

/// A virtual network client. Implements [`L3Device`] so it plugs into
/// `slirp::Stack`, `wg::Adapter`, or any other [`L3Connector`](crate::L3Connector).
pub struct Client {
    cfg: Mutex<ClientConfig>,
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("vclient::Client").field("addr", &self.addr()).finish()
    }
}

impl Client {
    /// Build a new client.
    pub fn new(cfg: ClientConfig) -> Arc<Client> {
        let addr = cfg.prefix.unwrap_or_default();
        Arc::new(Client {
            cfg: Mutex::new(cfg),
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
        })
    }

    /// Open a TCP connection to `addr`.
    ///
    /// **TODO(vclient):** wires through to `vtcp::Conn`. Currently returns
    /// `Unsupported`.
    pub fn dial_tcp(&self, _addr: std::net::SocketAddr) -> Result<TcpConn> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TODO(vclient): TCP dial needs vtcp::Conn integration",
        ))
    }

    /// Configure DNS servers (overrides DHCP-learned values).
    pub fn set_dns(&self, dns: Vec<IpAddr>) {
        self.cfg.lock().unwrap().dns = dns;
    }
}

impl L3Device for Client {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, _pkt: &Packet) -> Result<()> {
        // Packets arriving from the L3 network. The full implementation
        // will demultiplex them to vtcp::Conn / UDP / ICMP. For now we drop.
        Ok(())
    }
    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = p;
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// TCP connection handle returned by [`Client::dial_tcp`].
///
/// **TODO(vclient):** placeholder. Will wrap `vtcp::Conn`.
#[derive(Debug)]
pub struct TcpConn {
    _private: (),
}

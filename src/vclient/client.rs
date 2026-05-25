//! High-level virtual client built on top of [`vtcp`](crate::vtcp).
//!
//! `Client` implements [`L3Device`], so it plugs into `slirp::Stack`,
//! `wg::Adapter`, or any [`L3Connector`](crate::L3Connector). Outbound TCP
//! connections opened via [`Client::dial_tcp`] are driven by a per-client
//! [`TcpStack`](super::tcp); inbound IP packets the client receives are
//! demultiplexed to the matching connection.

use super::tcp::{self, TcpConn, TcpStack};
use crate::{IpPrefix, L3Device, L3Handler, Packet, Result};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Knobs for [`Client`].
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// IPv4/IPv6 prefix assigned to the client.
    pub prefix: Option<IpPrefix>,
    /// DNS servers to use (overrides anything learned via DHCP).
    pub dns: Vec<IpAddr>,
}

/// A virtual network client. Implements [`L3Device`].
pub struct Client {
    cfg: Mutex<ClientConfig>,
    handler: Arc<Mutex<Option<L3Handler>>>,
    addr: Mutex<IpPrefix>,
    tcp: Arc<TcpStack>,
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
        let handler: Arc<Mutex<Option<L3Handler>>> = Arc::new(Mutex::new(None));

        // The TCP stack pushes fully-framed IP packets back out the client's
        // installed L3 handler.
        let h = handler.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |bytes: &[u8]| {
            let handler = h.lock().unwrap().clone();
            if let Some(handler) = handler {
                let _ = handler(Packet::from_slice(bytes));
            }
        });
        let tcp = TcpStack::new(sink);

        Arc::new(Client {
            cfg: Mutex::new(cfg),
            handler,
            addr: Mutex::new(addr),
            tcp,
        })
    }

    /// Open a TCP connection to `addr`, blocking until the handshake
    /// completes (or `timeout` elapses).
    pub fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpConn> {
        self.dial_tcp_timeout(addr, Duration::from_secs(10))
    }

    /// Like [`dial_tcp`](Self::dial_tcp) with an explicit connect timeout.
    pub fn dial_tcp_timeout(&self, addr: SocketAddr, timeout: Duration) -> Result<TcpConn> {
        let prefix = self.addr();
        let local_ip = tcp::local_ip_for(prefix, addr.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no local address in the right family for this destination",
            )
        })?;
        self.tcp.dial(local_ip, addr, timeout)
    }

    /// Configure DNS servers (overrides DHCP-learned values).
    pub fn set_dns(&self, dns: Vec<IpAddr>) {
        self.cfg.lock().unwrap().dns = dns;
    }

    /// Resolve `host` using the configured DNS servers (via the host's real
    /// UDP sockets — see [`Resolver`](super::Resolver)).
    pub fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let dns = self.cfg.lock().unwrap().dns.clone();
        if dns.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no DNS servers configured",
            ));
        }
        super::Resolver::from_servers(dns).resolve(host)
    }
}

impl L3Device for Client {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, pkt: &Packet) -> Result<()> {
        // Inbound from the L3 network. Demux to a TCP connection; UDP/ICMP
        // demux is TODO(vclient).
        let _ = self.tcp.handle_inbound(pkt);
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
        self.tcp.shutdown();
        Ok(())
    }
}

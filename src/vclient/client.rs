//! High-level virtual client built on top of [`vtcp`](crate::vtcp).
//!
//! `Client` implements [`L3Device`], so it plugs into `slirp::Stack`,
//! `wg::Adapter`, or any [`L3Connector`](crate::L3Connector). Outbound TCP
//! connections opened via [`Client::dial_tcp`] are driven by a per-client
//! [`TcpStack`](super::tcp); inbound IP packets the client receives are
//! demultiplexed to the matching connection.
//!
//! On `wasm32` there are no threads to wait on or to run timers from: the
//! blocking calls are absent, the handles never block, and the caller runs
//! the timers with [`Client::tick`].

use super::tcp::{self, TcpConn, TcpStack};
use super::udp::{UdpConn, UdpStack};
use crate::defrag::Reassembler;
use crate::time::Instant;
use crate::{IpPrefix, L3Device, L3Handler, Packet, Result};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
#[cfg(not(target_family = "wasm"))]
use std::time::Duration;

/// Knobs for [`Client`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ClientConfig {
    /// IPv4/IPv6 prefix assigned to the client.
    pub prefix: Option<IpPrefix>,
    /// DNS servers [`Client::resolve`] queries, from the host's own sockets.
    /// The client learns none by itself; empty means `resolve` fails.
    pub dns: Vec<IpAddr>,
}

setters! {
    ClientConfig {
        some prefix: IpPrefix;
        set dns: Vec<IpAddr>;
    }
}

/// A virtual network client. Implements [`L3Device`].
pub struct Client {
    cfg: Mutex<ClientConfig>,
    handler: Arc<Mutex<Option<L3Handler>>>,
    /// Shared with the listeners bound to the client's own address, so that
    /// they report it as it is now, not as it was when they were opened.
    addr: Arc<Mutex<IpPrefix>>,
    tcp: Arc<TcpStack>,
    udp: Arc<UdpStack>,
    /// Inbound fragments awaiting the rest of their datagram.
    defrag: Mutex<Reassembler>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("vclient::Client")
            .field("addr", &self.addr())
            .finish()
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
        let tcp = TcpStack::new(sink.clone());
        let udp = UdpStack::new(sink);

        Arc::new(Client {
            cfg: Mutex::new(cfg),
            handler,
            addr: Arc::new(Mutex::new(addr)),
            tcp,
            udp,
            defrag: Mutex::new(Reassembler::default()),
        })
    }

    /// Listen for inbound virtual TCP connections on `port` at the client's
    /// own address: whatever that is when each connection arrives, so the
    /// listener follows the client through a change of address
    /// ([`set_addr`](L3Device::set_addr), DHCP) rather than keep answering
    /// for the old one. [`Listener::accept`](super::Listener::accept)
    /// yields each connection once its handshake completes.
    pub fn listen_tcp(&self, port: u16) -> Result<super::Listener> {
        self.tcp.listen(self.addr.clone(), port)
    }

    /// Open a connected UDP socket to `addr` over the virtual network.
    pub fn dial_udp(&self, addr: SocketAddr) -> Result<UdpConn> {
        let local_ip = self.local_ip_for(addr)?;
        self.udp.dial(local_ip, addr)
    }

    /// Open a TCP connection to `addr` without waiting for the handshake.
    ///
    /// The returned [`TcpConn`] is in non-blocking mode; check
    /// [`TcpConn::poll_connect`] (or just try to write) to find out when it is
    /// up. This is how to connect on `wasm32`, where
    /// [`dial_tcp`](Self::dial_tcp) is not available.
    pub fn dial_tcp_nonblocking(&self, addr: SocketAddr) -> Result<TcpConn> {
        let local_ip = self.local_ip_for(addr)?;
        self.tcp.dial_nonblocking(local_ip, addr)
    }

    /// Run the TCP timers: retransmission, persist, keepalive, TIME-WAIT,
    /// and delayed ACKs.
    ///
    /// Where threads exist a background thread already does this every
    /// 100 ms, and calling it as well is harmless. On `wasm32` nothing else
    /// will, so call it on a timer — every 100 ms or so, as that thread does.
    pub fn tick(&self) {
        self.tcp.tick_all();
    }

    fn local_ip_for(&self, addr: SocketAddr) -> Result<IpAddr> {
        tcp::local_ip_for(self.addr(), addr.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no local address in the right family for this destination",
            )
        })
    }

    /// Open a TCP connection to `addr`, blocking until the handshake
    /// completes (or `timeout` elapses).
    #[cfg(not(target_family = "wasm"))]
    pub fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpConn> {
        self.dial_tcp_timeout(addr, Duration::from_secs(10))
    }

    /// Like [`dial_tcp`](Self::dial_tcp) with an explicit connect timeout.
    #[cfg(not(target_family = "wasm"))]
    pub fn dial_tcp_timeout(&self, addr: SocketAddr, timeout: Duration) -> Result<TcpConn> {
        let local_ip = self.local_ip_for(addr)?;
        self.tcp.dial(local_ip, addr, timeout)
    }

    /// Replace the DNS servers [`resolve`](Self::resolve) queries.
    pub fn set_dns(&self, dns: Vec<IpAddr>) {
        self.cfg.lock().unwrap().dns = dns;
    }

    /// Resolve `host` using the configured DNS servers (via the host's real
    /// UDP sockets — see [`Resolver`](super::Resolver)). Absent on `wasm32`,
    /// which has no host sockets.
    #[cfg(not(target_family = "wasm"))]
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
        // Fragments are put back together before anything reads a transport
        // header: past the first fragment there is none, only data.
        let whole = self
            .defrag
            .lock()
            .unwrap()
            .reassemble(Instant::now(), 0, pkt.as_bytes());
        let Some(whole) = whole else {
            return Ok(());
        };
        let pkt = Packet::from_slice(&whole);
        // Inbound from the L3 network: demux to a TCP connection, then a UDP
        // socket. Unmatched packets (e.g. ICMP) are dropped.
        if self.tcp.handle_inbound(pkt, self.addr().addr()) {
            return Ok(());
        }
        let _ = self.udp.handle_inbound(pkt);
        Ok(())
    }
    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = p;
        Ok(())
    }
    /// Close the client: every connection is reset, listeners and UDP
    /// sockets are closed, blocked calls on any of them return an error, and
    /// nothing new can be opened.
    fn close(&self) -> Result<()> {
        self.tcp.shutdown();
        self.udp.shutdown();
        Ok(())
    }
}

impl Drop for Client {
    /// The last reference is gone, so nothing can deliver another packet to
    /// a connection, listener or UDP socket: their handles outlive the
    /// client, and a thread blocked on one without a timeout would wait for
    /// ever. Closing wakes them with an error, resets the peers rather than
    /// leaving them talking to no one, and stops the tick thread, as
    /// `close` does.
    fn drop(&mut self) {
        let _ = L3Device::close(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Handles outlive the client, and a thread blocked on one must not wait
    /// for ever once nothing is left to wake it.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn dropping_the_client_wakes_blocked_handles() {
        let client = Client::new(
            ClientConfig::default()
                .prefix(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24)),
        );
        let peer = SocketAddr::from(([10, 0, 0, 1], 53));
        let listener = client.listen_tcp(80).unwrap();
        let udp = client.dial_udp(peer).unwrap();
        let tcp = client.dial_tcp_nonblocking(peer).unwrap();
        tcp.set_nonblocking(false);

        let (tx, rx) = std::sync::mpsc::channel();
        let t = tx.clone();
        std::thread::spawn(move || t.send(("accept", listener.accept().is_err())).unwrap());
        let t = tx.clone();
        std::thread::spawn(move || t.send(("recv", udp.recv(&mut [0; 16]).is_err())).unwrap());
        std::thread::spawn(move || tx.send(("read", tcp.read(&mut [0; 16]).is_err())).unwrap());
        std::thread::sleep(Duration::from_millis(50));
        drop(client);
        for _ in 0..3 {
            let (what, failed) = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("a handle stayed blocked");
            assert!(failed, "{what} returned success");
        }
    }

    /// A listener on the client's own address follows it when it changes.
    #[test]
    fn listener_follows_the_clients_address() {
        use crate::vtcp::segment::{Segment, flags};
        let (old, new) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let client = Client::new(ClientConfig::default().prefix(IpPrefix::new(old.into(), 24)));
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let s = sent.clone();
        client.set_handler(Arc::new(move |p: &Packet| {
            s.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let listener = client.listen_tcp(80).unwrap();
        client.set_addr(IpPrefix::new(new.into(), 24)).unwrap();
        assert_eq!(listener.local_addr(), SocketAddr::from((new, 80)));

        // Replies to a SYN from port `src_port` to `dst`:80.
        let syn = |dst: Ipv4Addr, src_port: u16| {
            let seg = Segment {
                src_port,
                dst_port: 80,
                seq: 1,
                flags: flags::SYN,
                ..Default::default()
            };
            let mut ip = crate::build::build_ipv4(
                Ipv4Addr::new(10, 0, 0, 1),
                dst,
                crate::Protocol::TCP,
                64,
                &seg.marshal(),
            );
            Packet::from_mut(&mut ip).recompute_transport_checksum();
            sent.lock().unwrap().clear();
            client.send(Packet::from_slice(&ip)).unwrap();
            let replies = sent.lock().unwrap().clone();
            replies
                .iter()
                .map(|p| {
                    let p = Packet::from_slice(p);
                    (
                        p.src_addr().unwrap(),
                        Segment::parse(p.payload()).unwrap().flags,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(syn(new, 4000), [(IpAddr::V4(new), flags::SYN | flags::ACK)]);
        // The old address is no longer the client's to answer for.
        assert!(syn(old, 4001).is_empty());
    }
}

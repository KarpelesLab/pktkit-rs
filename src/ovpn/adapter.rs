//! High-level adapter: bridges OpenVPN peers to a pktkit network.
//!
//! Each peer that completes the TLS handshake and authenticates gets a
//! per-peer device wired to the configured connector:
//!
//! - **tun** + [`L3Connector`]: a per-peer [`L3Device`]. Decrypted IP packets
//!   flow from the tunnel into the connector (e.g. a NAT/slirp stack); packets
//!   the connector sends are encrypted and shipped to the peer.
//! - **tap** + [`L2Connector`]: a per-peer [`L2Device`] on a shared broadcast
//!   domain (e.g. an [`L2Hub`](crate::L2Hub)).
//!
//! Ported from the Go `adapter.go`. The auth hook maps credentials to a
//! [`PeerConfig`]; the adapter then sets up the device and connector wiring.
//!
//! In tun mode a client's packets are passed on only if their source is
//! the address it was given or lies in one of its
//! [`iroutes`](PeerConfig::iroutes); the rest are dropped. The adapter does
//! no routing towards clients: each has its own device, and what the
//! connector sends to it goes to that client.
//!
//! In tap mode each client is held to one source MAC address: the first
//! unicast one it sends from, unless another client of the adapter already
//! uses it. Frames from any other source MAC are dropped, as are VLAN-stacked
//! frames. Its ARP must claim that MAC and the address it was given (or none,
//! for an address probe), and its IPv6 neighbour discovery the same: a
//! neighbour advertisement only for the given address, a solicitation only
//! from it or from `::`, and no router advertisement or redirect at all. So
//! a client given an IPv4 address takes no part in IPv6 neighbour discovery,
//! link-local addresses included. Other traffic is not checked for its IP
//! source, as OpenVPN does not check it in tap mode either; a client
//! bridging a network of its own behind it (several MACs) is not supported.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use super::addr::PeerKey;
use super::peer::{OnAuth, PeerConfig, PeerTimers};
use super::server::{Server, ServerConfig};
use crate::accept::{Cleanup, L2Connector, L3Connector};
use crate::iface::{L2Device, L2Handler, L3Device, L3Handler};
use crate::{IpPrefix, MacAddr, Result};

/// Connector target: exactly one of these is configured.
pub enum Connector {
    /// tun mode: per-peer L3 device joins this connector.
    L3(Arc<dyn L3Connector + Send + Sync>),
    /// tap mode: per-peer L2 device joins this connector.
    L2(Arc<dyn L2Connector + Send + Sync>),
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Connector::L3(_) => f.write_str("Connector::L3"),
            Connector::L2(_) => f.write_str("Connector::L2"),
        }
    }
}

/// Configuration for an [`Adapter`].
#[non_exhaustive]
pub struct AdapterConfig {
    /// TLS config for the control channel (identity: cert chain + key).
    pub tls_config: Arc<purecrypto::tls::Config>,
    /// Listen address (UDP + TCP).
    pub listen_addr: SocketAddr,
    /// Connector wiring per-peer devices to the network.
    pub connector: Connector,
    /// Auth hook returning the per-peer IP config.
    pub on_auth: OnAuth,
    /// Most peers held at once; see [`ServerConfig::max_peers`].
    pub max_peers: usize,
    /// Most peers held at once that have not authenticated; see
    /// [`ServerConfig::max_unauthenticated_peers`].
    pub max_unauthenticated_peers: Option<usize>,
    /// Most of those from one source; see
    /// [`ServerConfig::max_unauthenticated_peers_per_source`].
    pub max_unauthenticated_peers_per_source: usize,
    /// How much of an IPv6 address names its source for the per-source
    /// limits; see [`ServerConfig::source_prefix_v6`].
    pub source_prefix_v6: u8,
    /// New peers per period from one source, or `None` (the default) for
    /// no limit; see [`ServerConfig::connect_freq`].
    pub connect_freq: Option<(u32, Duration)>,
    /// Most TCP connections served at once; see
    /// [`ServerConfig::max_tcp_connections`].
    pub max_tcp_connections: usize,
    /// Most of those from one source; see
    /// [`ServerConfig::max_tcp_connections_per_source`].
    pub max_tcp_connections_per_source: usize,
    /// Each peer's timers; see [`ServerConfig::timers`].
    pub timers: PeerTimers,
    /// Answers to UDP clients' first packets per period and source; see
    /// [`ServerConfig::connect_freq_initial`].
    pub connect_freq_initial: (u32, Duration),
    /// Most `on_auth` calls running at once; see
    /// [`ServerConfig::max_auth_threads`].
    pub max_auth_threads: usize,
}

setters! {
    AdapterConfig {
        set max_peers: usize;
        some max_unauthenticated_peers: usize;
        set max_unauthenticated_peers_per_source: usize;
        set source_prefix_v6: u8;
        some connect_freq: (u32, Duration);
        set max_tcp_connections: usize;
        set max_tcp_connections_per_source: usize;
        set timers: PeerTimers;
        set connect_freq_initial: (u32, Duration);
        set max_auth_threads: usize;
    }
}

impl AdapterConfig {
    /// The required fields; the limits and timers take the server's
    /// defaults (see [`ServerConfig`]).
    pub fn new(
        tls_config: Arc<purecrypto::tls::Config>,
        listen_addr: SocketAddr,
        connector: Connector,
        on_auth: OnAuth,
    ) -> AdapterConfig {
        AdapterConfig {
            tls_config,
            listen_addr,
            connector,
            on_auth,
            max_peers: super::server::DEFAULT_MAX_PEERS,
            max_unauthenticated_peers: None,
            max_unauthenticated_peers_per_source:
                super::server::DEFAULT_MAX_UNAUTHENTICATED_PER_SOURCE,
            source_prefix_v6: super::server::DEFAULT_SOURCE_PREFIX_V6,
            connect_freq: None,
            max_tcp_connections: super::server::DEFAULT_MAX_TCP_CONNECTIONS,
            max_tcp_connections_per_source: super::server::DEFAULT_MAX_TCP_CONNECTIONS_PER_SOURCE,
            timers: PeerTimers::default(),
            connect_freq_initial: super::server::DEFAULT_CONNECT_FREQ_INITIAL,
            max_auth_threads: super::server::DEFAULT_MAX_AUTH_THREADS,
        }
    }
}

impl std::fmt::Debug for AdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterConfig")
            .field("listen_addr", &self.listen_addr)
            .field("connector", &self.connector)
            .field("max_peers", &self.max_peers)
            .field("max_unauthenticated_peers", &self.max_unauthenticated_peers)
            .field(
                "max_unauthenticated_peers_per_source",
                &self.max_unauthenticated_peers_per_source,
            )
            .field("source_prefix_v6", &self.source_prefix_v6)
            .field("connect_freq", &self.connect_freq)
            .field("max_tcp_connections", &self.max_tcp_connections)
            .field(
                "max_tcp_connections_per_source",
                &self.max_tcp_connections_per_source,
            )
            .field("timers", &self.timers)
            .field("connect_freq_initial", &self.connect_freq_initial)
            .field("max_auth_threads", &self.max_auth_threads)
            .finish()
    }
}

/// A peer's place in the adapter. It is taken before the device is
/// connected -- with `l3` / `l2` and `cleanup` still empty -- so that of two
/// on_connect calls for one key only one connects a device; `id` tells the
/// one that took it whether it is still its own once connected.
struct OvpnPeer {
    id: u64,
    l3: Option<Arc<PeerL3Device>>,
    l2: Option<Arc<PeerL2Device>>,
    cleanup: Mutex<Option<Cleanup>>,
}

impl OvpnPeer {
    fn take_cleanup(&self) -> Option<Cleanup> {
        self.cleanup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// Bridges OpenVPN peers to a pktkit network.
pub struct Adapter {
    server: Mutex<Option<Arc<Server>>>,
    connector: Connector,
    peers: Mutex<HashMap<PeerKey, OvpnPeer>>,
    /// For [`OvpnPeer::id`].
    next_id: AtomicU64,
    /// Held while a tap client's MAC is learned, so two clients cannot
    /// both take one MAC. Taken before `peers`.
    learning: Mutex<()>,
    me: Weak<Adapter>,
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter").finish()
    }
}

impl Adapter {
    /// Create the adapter and start its server.
    pub fn new(cfg: AdapterConfig) -> Result<Arc<Adapter>> {
        let adapter = Arc::new_cyclic(|me| Adapter {
            server: Mutex::new(None),
            connector: cfg.connector,
            peers: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            learning: Mutex::new(()),
            me: me.clone(),
        });

        let on_data: super::server::OnData = {
            let a = adapter.me.clone();
            Arc::new(move |key, layer, payload| {
                if let Some(a) = a.upgrade() {
                    a.deliver(key, layer, payload);
                }
            })
        };
        let mut server_cfg =
            ServerConfig::new(cfg.tls_config, cfg.listen_addr, cfg.on_auth, on_data)
                .max_peers(cfg.max_peers)
                .max_unauthenticated_peers_per_source(cfg.max_unauthenticated_peers_per_source)
                .source_prefix_v6(cfg.source_prefix_v6)
                .max_tcp_connections(cfg.max_tcp_connections)
                .max_tcp_connections_per_source(cfg.max_tcp_connections_per_source)
                .timers(cfg.timers)
                .connect_freq_initial(cfg.connect_freq_initial)
                .max_auth_threads(cfg.max_auth_threads)
                .on_connect({
                    let a = adapter.me.clone();
                    Arc::new(move |key, cfg| {
                        if let Some(a) = a.upgrade() {
                            a.on_connect(key, cfg);
                        }
                    })
                })
                .on_disconnect({
                    let a = adapter.me.clone();
                    Arc::new(move |key| {
                        if let Some(a) = a.upgrade() {
                            a.on_disconnect(key);
                        }
                    })
                });
        server_cfg.max_unauthenticated_peers = cfg.max_unauthenticated_peers;
        server_cfg.connect_freq = cfg.connect_freq;

        let server = Server::new(server_cfg)?;
        *adapter.server.lock().unwrap() = Some(server);
        Ok(adapter)
    }

    /// The bound UDP address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.server
            .lock()
            .unwrap()
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "server not started"))?
            .local_addr()
    }

    /// The bound TCP address. The same as [`local_addr`](Self::local_addr)
    /// unless the configured port was 0, in which case each transport got
    /// its own ephemeral port.
    pub fn tcp_local_addr(&self) -> Result<SocketAddr> {
        self.server
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.tcp_local_addr())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "server not started"))
    }

    /// Shut down the adapter and its server.
    pub fn close(&self) {
        // Not under the lock: Server::close waits for the UDP reader, whose
        // callbacks may send to a peer, which takes it (see `server()`).
        let server = self.server.lock().unwrap().take();
        if let Some(s) = server {
            s.close();
        }
        // Cleanups run with no lock held: a connector's may call back into
        // the adapter. One that panics must not stop the others, nor escape
        // from Drop.
        let peers: Vec<OvpnPeer> = self.peers().drain().map(|(_, p)| p).collect();
        for p in peers {
            if let Some(c) = p.take_cleanup() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(c));
            }
        }
    }

    /// The peer table. Nothing that can panic runs under its lock, but a
    /// poisoned one would leave every later call panicking -- close() from
    /// Drop included -- so poison is shrugged off.
    fn peers(&self) -> MutexGuard<'_, HashMap<PeerKey, OvpnPeer>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn server(&self) -> Option<Arc<Server>> {
        self.server.lock().unwrap().clone()
    }

    fn on_connect(&self, key: PeerKey, cfg: &PeerConfig) {
        // Take the key before connecting, under the lock: checked and
        // taken apart, two calls for one key would both connect a device,
        // and the second one's insert would drop the first's cleanup,
        // leaving that device attached for good.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut peers = self.peers();
            if peers.contains_key(&key) {
                return;
            }
            peers.insert(
                key,
                OvpnPeer {
                    id,
                    l3: None,
                    l2: None,
                    cleanup: Mutex::new(None),
                },
            );
        }
        // Determine layer from the connector type (the server tracks the peer's
        // dev-type, but here we wire based on what the operator configured).
        // The connector runs with no lock held: it may call back into the
        // adapter.
        let (l3, l2, connected) = match &self.connector {
            Connector::L3(conn) => {
                let prefix = IpPrefix::new(cfg.ip, cfg.prefix_len);
                let dev = PeerL3Device::new(&self.me, key, prefix, cfg.iroutes.clone());
                let res = conn.connect_l3(dev.clone() as Arc<dyn L3Device>);
                (Some(dev), None, res)
            }
            Connector::L2(conn) => {
                let dev = PeerL2Device::new(&self.me, key, cfg.ip);
                let res = conn.connect_l2(dev.clone() as Arc<dyn L2Device>);
                (None, Some(dev), res)
            }
        };
        let leftover = {
            let mut peers = self.peers();
            let ours = peers.get_mut(&key).filter(|p| p.id == id);
            match (ours, connected) {
                (Some(p), Ok(cleanup)) => {
                    p.l3 = l3;
                    p.l2 = l2;
                    *p.cleanup.get_mut().unwrap_or_else(PoisonError::into_inner) = Some(cleanup);
                    None
                }
                (Some(_), Err(_)) => {
                    peers.remove(&key);
                    None
                }
                // on_disconnect or close() let go of the key while the
                // device was being connected: nothing but this call is left
                // to detach it. With no lock held, as in on_disconnect.
                (None, Ok(cleanup)) => Some(cleanup),
                (None, Err(_)) => None,
            }
        };
        if let Some(c) = leftover {
            let _ = c();
        }
    }

    fn on_disconnect(&self, key: PeerKey) {
        // The cleanup runs after the lock is released: it is the
        // connector's code, which may call back into the adapter.
        let peer = self.peers().remove(&key);
        if let Some(c) = peer.and_then(|p| p.take_cleanup()) {
            let _ = c();
        }
    }

    /// Deliver a decrypted payload from the peer into its device handler.
    fn deliver(&self, key: PeerKey, _layer: u8, payload: &[u8]) {
        // The handler runs with no lock held: it may send to a peer, which
        // can remove one and so come back here for the lock.
        let (l3, l2) = match self.peers().get(&key) {
            Some(p) => (p.l3.clone(), p.l2.clone()),
            None => return,
        };
        if let Some(dev) = l3 {
            dev.deliver(payload);
        } else if let Some(dev) = l2 {
            dev.deliver(payload);
        }
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.close();
    }
}

// --- per-peer L3 device -----------------------------------------------------

struct PeerL3Device {
    adapter: Weak<Adapter>,
    key: PeerKey,
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
    /// The tunnel address pushed to the client: a source its packets may
    /// carry.
    client_ip: IpAddr,
    /// Networks behind the client, whose addresses its packets may carry
    /// too (OpenVPN's `iroute`).
    iroutes: Vec<IpPrefix>,
}

impl PeerL3Device {
    fn new(
        adapter: &Weak<Adapter>,
        key: PeerKey,
        addr: IpPrefix,
        iroutes: Vec<IpPrefix>,
    ) -> Arc<Self> {
        Arc::new(PeerL3Device {
            adapter: adapter.clone(),
            key,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            client_ip: addr.addr(),
            iroutes,
        })
    }

    /// The handler, cloned out so it is called with no lock held.
    fn handler(&self) -> Option<L3Handler> {
        self.handler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn deliver(&self, data: &[u8]) {
        let packet = crate::Packet::from_slice(data);
        // A client may only speak for the address it was given, and for
        // the networks routed through it (multi.c
        // multi_process_incoming_link, "bad source address from client"):
        // otherwise it could pass for another client, or for any host at
        // all, to whatever the connector leads to. An IPv6 packet from a
        // client given an IPv4 address and no IPv6 iroute, link-local ones
        // included, has no address of its own to come from either.
        if !packet.is_valid() {
            return;
        }
        let Some(src) = packet.src_addr() else {
            return;
        };
        if src != self.client_ip && !self.iroutes.iter().any(|r| r.contains(src)) {
            return;
        }
        let h = self.handler();
        if let Some(h) = h {
            let _ = h(packet);
        }
    }
}

impl L3Device for PeerL3Device {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap_or_else(PoisonError::into_inner) = Some(h);
    }

    fn send(&self, packet: &crate::Packet) -> Result<()> {
        let Some(adapter) = self.adapter.upgrade() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "adapter dropped",
            ));
        };
        let Some(server) = adapter.server() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "server stopped",
            ));
        };
        server.send_to_peer(&self.key, packet.as_bytes())
    }

    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }

    fn set_addr(&self, prefix: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = prefix;
        Ok(())
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

// --- per-peer L2 device -----------------------------------------------------

struct PeerL2Device {
    adapter: Weak<Adapter>,
    key: PeerKey,
    handler: Mutex<Option<L2Handler>>,
    mac: MacAddr,
    /// The address pushed to the client: the only one its ARP and
    /// neighbour discovery may claim.
    client_ip: IpAddr,
    /// The source MAC the client sends from, learned from its first frame.
    client_mac: Mutex<Option<MacAddr>>,
}

impl PeerL2Device {
    fn new(adapter: &Weak<Adapter>, key: PeerKey, client_ip: IpAddr) -> Arc<Self> {
        // Derive a stable locally-administered MAC from the peer key bytes.
        let mut octets = [0u8; 6];
        let s = key.socket_addr();
        let ip = match s.ip() {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        octets[0] = 0x02; // locally administered, unicast
        for (i, b) in ip.iter().rev().take(3).enumerate() {
            octets[3 + i] = *b;
        }
        octets[1] = (s.port() >> 8) as u8;
        octets[2] = (s.port() & 0xff) as u8;
        Arc::new(PeerL2Device {
            adapter: adapter.clone(),
            key,
            handler: Mutex::new(None),
            mac: MacAddr(octets),
            client_ip,
            client_mac: Mutex::new(None),
        })
    }

    fn learned_mac(&self) -> Option<MacAddr> {
        *self
            .client_mac
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the client may send from `src`: the MAC it was pinned to,
    /// or, for its first frame, one no other client of the adapter uses.
    fn source_mac_ok(&self, src: MacAddr) -> bool {
        if src.is_multicast() || src == MacAddr([0; 6]) {
            return false;
        }
        if let Some(mac) = self.learned_mac() {
            return mac == src;
        }
        let Some(adapter) = self.adapter.upgrade() else {
            return false;
        };
        let _learning = adapter
            .learning
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let taken = adapter.peers().iter().any(|(k, p)| {
            *k != self.key && p.l2.as_ref().is_some_and(|d| d.learned_mac() == Some(src))
        });
        if taken {
            return false;
        }
        let mut mine = self
            .client_mac
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *mine.get_or_insert(src) == src
    }

    /// The handler, cloned out so it is called with no lock held.
    fn handler(&self) -> Option<L2Handler> {
        self.handler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn deliver(&self, data: &[u8]) {
        let frame = crate::Frame::from_slice(data);
        // Without these checks a client could take another's MAC, or answer
        // ARP and neighbour discovery for any address on the segment, and
        // so draw other hosts' traffic to itself.
        let Some(src) = frame.src_mac() else {
            return;
        };
        if !self.source_mac_ok(src) || !claims_only(frame, src, self.client_ip) {
            return;
        }
        let h = self.handler();
        if let Some(h) = h {
            let _ = h(frame);
        }
    }
}

/// Whether the ARP or neighbour discovery in `frame`, from a client pinned
/// to `mac` and given `ip`, claims no more than those; true for other
/// traffic. A frame that cannot be parsed far enough to tell is refused.
fn claims_only(frame: &crate::Frame, mac: MacAddr, ip: IpAddr) -> bool {
    use crate::EtherType;
    let payload = frame.payload();
    match frame.ether_type() {
        // A further tag would hide the frame's real type.
        EtherType::VLAN | EtherType(0x88a8) => false,
        EtherType::ARP => {
            // htype 1 (Ethernet), ptype IPv4, 6-byte and 4-byte addresses.
            if payload.len() < 28 || payload[..6] != [0, 1, 8, 0, 6, 4] {
                return false;
            }
            let sender_ip =
                std::net::Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);
            payload[8..14] == mac.0 && (IpAddr::V4(sender_ip) == ip || sender_ip.is_unspecified())
        }
        EtherType::IPV6 => ndp_claims_only(payload, mac, ip),
        _ => true,
    }
}

/// [`claims_only`] for an IPv6 packet: its neighbour discovery.
fn ndp_claims_only(pkt: &[u8], mac: MacAddr, ip: IpAddr) -> bool {
    if pkt.len() < 40 {
        return false;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    let src = std::net::Ipv6Addr::from(src);
    // Past the extension headers that may come before ICMPv6.
    let (mut next, mut at) = (pkt[6], 40);
    loop {
        match next {
            // Hop-by-hop, routing, destination options: length in 8-byte
            // units, not counting the first 8.
            0 | 43 | 60 => {
                let Some(hdr) = pkt.get(at..at + 2) else {
                    return false;
                };
                next = hdr[0];
                at += (usize::from(hdr[1]) + 1) * 8;
            }
            // Fragment: neighbour discovery must not be fragmented (RFC
            // 6980), and a later fragment has no ICMPv6 header to check.
            44 => {
                let Some(hdr) = pkt.get(at..at + 8) else {
                    return false;
                };
                return hdr[0] != 58;
            }
            58 => break,
            _ => return true,
        }
    }
    let Some(icmp) = pkt.get(at..) else {
        return false;
    };
    let Some(&kind) = icmp.first() else {
        return false;
    };
    let target = |icmp: &[u8]| {
        let mut t = [0u8; 16];
        t.copy_from_slice(&icmp[8..24]);
        IpAddr::V6(std::net::Ipv6Addr::from(t))
    };
    let options = match kind {
        // Router solicitation: asks, claims nothing but its source MAC.
        133 => icmp.get(8..),
        // Router advertisement, redirect: a client is no router.
        134 | 137 => return false,
        // Neighbour solicitation: tells the target who the source is.
        135 => {
            if icmp.len() < 24 || !(src.is_unspecified() || IpAddr::V6(src) == ip) {
                return false;
            }
            icmp.get(24..)
        }
        // Neighbour advertisement: claims the target.
        136 => {
            if icmp.len() < 24 || target(icmp) != ip {
                return false;
            }
            icmp.get(24..)
        }
        _ => return true,
    };
    // Any link-layer address option must name the client's own MAC.
    let mut opts = options.unwrap_or(&[]);
    while opts.len() >= 2 {
        let len = usize::from(opts[1]) * 8;
        if len == 0 || opts.len() < len {
            return false;
        }
        if matches!(opts[0], 1 | 2) && (len < 8 || opts[2..8] != mac.0) {
            return false;
        }
        opts = &opts[len..];
    }
    true
}

impl L2Device for PeerL2Device {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.lock().unwrap_or_else(PoisonError::into_inner) = Some(h);
    }

    fn send(&self, frame: &crate::Frame) -> Result<()> {
        let Some(adapter) = self.adapter.upgrade() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "adapter dropped",
            ));
        };
        let Some(server) = adapter.server() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "server stopped",
            ));
        };
        server.send_to_peer(&self.key, frame.as_bytes())
    }

    fn hw_addr(&self) -> MacAddr {
        self.mac
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ovpn::Opcode;
    use crate::ovpn::packet_ctrl::ControlPacket;
    use std::net::UdpSocket;

    /// Counts attached devices; detaching is a no-op.
    #[derive(Default)]
    struct CountingConnector {
        connects: std::sync::atomic::AtomicUsize,
    }

    impl L3Connector for CountingConnector {
        fn connect_l3(&self, _dev: Arc<dyn L3Device>) -> Result<Cleanup> {
            self.connects
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(|| Ok(())))
        }
    }

    fn config(connector: Arc<CountingConnector>) -> AdapterConfig {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        AdapterConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            Connector::L3(connector),
            on_auth,
        )
    }

    fn client_reset(sid: [u8; 8]) -> Vec<u8> {
        let mut p = ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, sid, [0; 8]);
        p.set_pid(0);
        p.to_bytes(&[])
    }

    /// Whether a client from a fresh address gets a peer: the server's
    /// first answer is stateless, so the client completes the three-way
    /// handshake, then repeats its reset -- which only a peer that holds
    /// it as its packet 0 answers with a bare ACK.
    fn answers(s: &UdpSocket, sid: [u8; 8]) -> bool {
        let mut buf = [0u8; 2048];
        s.send(&client_reset(sid)).unwrap();
        let n = s.recv(&mut buf).unwrap();
        let reply = ControlPacket::parse(&buf[..n]).unwrap();
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, sid, reply.session_id);
        s.send(&ack.to_bytes(&[0])).unwrap();
        s.send(&client_reset(sid)).unwrap();
        let n = s.recv(&mut buf).unwrap();
        ControlPacket::parse(&buf[..n]).unwrap().opcode == Opcode::ACK_V1
    }

    /// A client socket for `adapter`. Tests keep theirs open to the end: a
    /// port given back could go to a later client, which would then hear
    /// the first one's traffic.
    fn udp_client(adapter: &Adapter) -> UdpSocket {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect(adapter.local_addr().unwrap()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s
    }

    /// A tun client may only send from the address it was given: anything
    /// else -- another client's address, one outside the tunnel, IPv6 when
    /// it was given none, a truncated packet -- is dropped, as OpenVPN
    /// drops it ("bad source address from client").
    #[test]
    fn packets_from_a_foreign_source_are_dropped() {
        let key = PeerKey::new(
            "192.0.2.1:1194".parse().unwrap(),
            crate::ovpn::Transport::Udp,
        );
        let prefix = IpPrefix::new("10.8.0.2".parse().unwrap(), 24);
        let dev = PeerL3Device::new(&Weak::new(), key, prefix, Vec::new());
        let seen = Arc::new(Mutex::new(Vec::new()));
        {
            let seen = seen.clone();
            dev.set_handler(Arc::new(move |p: &crate::Packet| {
                seen.lock().unwrap().push(p.as_bytes().to_vec());
                Ok(())
            }));
        }
        let v4 = |src: [u8; 4]| {
            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[3] = 20;
            p[12..16].copy_from_slice(&src);
            p[16..20].copy_from_slice(&[10, 8, 0, 1]);
            p
        };
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[8] = 0xfe;
        v6[9] = 0x80;
        v6[23] = 1;
        for p in [
            v4([10, 8, 0, 3]),
            v4([192, 0, 2, 1]),
            v6,
            vec![0x45, 0, 0, 20],
            Vec::new(),
        ] {
            dev.deliver(&p);
        }
        assert!(seen.lock().unwrap().is_empty());
        dev.deliver(&v4([10, 8, 0, 2]));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// A tap adapter, and a device of its for a client given `ip`, listed
    /// in its peer table as on_connect would list it.
    fn tap_device(adapter: &Arc<Adapter>, port: u16, ip: &str) -> Arc<PeerL2Device> {
        let key = PeerKey::new(
            SocketAddr::from(([192, 0, 2, 1], port)),
            crate::ovpn::Transport::Udp,
        );
        let dev = PeerL2Device::new(&adapter.me, key, ip.parse().unwrap());
        adapter.peers().insert(
            key,
            OvpnPeer {
                id: u64::from(port),
                l3: None,
                l2: Some(dev.clone()),
                cleanup: Mutex::new(None),
            },
        );
        dev
    }

    fn tap_adapter() -> Arc<Adapter> {
        struct Nowhere;
        impl L2Connector for Nowhere {
            fn connect_l2(&self, _dev: Arc<dyn L2Device>) -> Result<Cleanup> {
                Ok(Box::new(|| Ok(())))
            }
        }
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        Adapter::new(AdapterConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            Connector::L2(Arc::new(Nowhere)),
            on_auth,
        ))
        .unwrap()
    }

    /// Frames a device passes on.
    fn passed(dev: &PeerL2Device) -> Arc<Mutex<Vec<Vec<u8>>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        dev.set_handler(Arc::new(move |f: &crate::Frame| {
            s.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));
        seen
    }

    fn arp(mac: MacAddr, sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0, 1, 8, 0, 6, 4, 0, 1];
        p.extend_from_slice(&sender_mac);
        p.extend_from_slice(&sender_ip);
        p.extend_from_slice(&[0; 6]);
        p.extend_from_slice(&[10, 8, 0, 1]);
        crate::build_frame(MacAddr([0xff; 6]), mac, crate::EtherType::ARP, &p)
    }

    /// An ICMPv6 neighbour discovery message of `kind` from `src`, about
    /// `target`, with a link-layer address option naming `ll`.
    fn ndp(mac: MacAddr, kind: u8, src: &str, target: &str, ll: [u8; 6]) -> Vec<u8> {
        let src: std::net::Ipv6Addr = src.parse().unwrap();
        let target: std::net::Ipv6Addr = target.parse().unwrap();
        let mut icmp = vec![kind, 0, 0, 0, 0, 0, 0, 0];
        if kind != 133 {
            icmp.extend_from_slice(&target.octets());
        }
        icmp.extend_from_slice(&[if kind == 136 { 2 } else { 1 }, 1]);
        icmp.extend_from_slice(&ll);
        let mut p = vec![0x60, 0, 0, 0, 0, 0, 58, 255];
        p[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&[0xff; 16]);
        p.extend_from_slice(&icmp);
        crate::build_frame(MacAddr([0x33; 6]), mac, crate::EtherType::IPV6, &p)
    }

    /// A tap client is pinned to the first source MAC it sends from, and
    /// its ARP and neighbour discovery may claim only that MAC and the
    /// address it was given. Before, anything went: a client could answer
    /// for any address on the segment, or send as any MAC.
    #[test]
    fn tap_clients_claim_only_their_own_mac_and_address() {
        let adapter = tap_adapter();
        let dev = tap_device(&adapter, 1, "10.8.0.2");
        let seen = passed(&dev);
        let me = MacAddr([2, 0, 0, 0, 0, 1]);
        let other = MacAddr([2, 0, 0, 0, 0, 2]);
        let ip = crate::build_frame(MacAddr([0xff; 6]), me, crate::EtherType::IPV4, &[0x45; 20]);
        dev.deliver(&ip);
        assert_eq!(seen.lock().unwrap().len(), 1, "first frame dropped");
        let before = seen.lock().unwrap().len();
        for bad in [
            // Another source MAC.
            crate::build_frame(
                MacAddr([0xff; 6]),
                other,
                crate::EtherType::IPV4,
                &[0x45; 20],
            ),
            // ARP for another address, or naming another MAC.
            arp(me, me.0, [10, 8, 0, 3]),
            arp(me, other.0, [10, 8, 0, 2]),
            // Truncated ARP.
            crate::build_frame(MacAddr([0xff; 6]), me, crate::EtherType::ARP, &[0, 1, 8, 0]),
            // Neighbour discovery: advertising any address (the client has
            // no IPv6 one), advertising a router, soliciting from a
            // link-local source.
            ndp(me, 136, "fe80::1", "fe80::1", me.0),
            ndp(me, 134, "fe80::1", "::", me.0),
            ndp(me, 135, "fe80::1", "fe80::99", me.0),
            // Stacked VLAN tags.
            crate::build_frame(
                MacAddr([0xff; 6]),
                me,
                crate::EtherType::VLAN,
                &[0, 1, 0x81, 0, 0, 2, 8, 6],
            ),
        ] {
            dev.deliver(&bad);
        }
        assert_eq!(
            seen.lock().unwrap().len(),
            before,
            "a spoofing frame passed"
        );
        for good in [
            arp(me, me.0, [10, 8, 0, 2]),
            // An address probe (RFC 5227).
            arp(me, me.0, [0, 0, 0, 0]),
            // Duplicate address detection.
            ndp(me, 135, "::", "fe80::99", me.0),
            ndp(me, 133, "::", "::", me.0),
        ] {
            dev.deliver(&good);
        }
        assert_eq!(seen.lock().unwrap().len(), before + 4);

        // With an IPv6 address, the client advertises that one only, and
        // with its own MAC.
        let dev6 = tap_device(&adapter, 2, "2001:db8::2");
        let seen6 = passed(&dev6);
        dev6.deliver(&ndp(other, 136, "2001:db8::2", "2001:db8::2", other.0));
        dev6.deliver(&ndp(other, 136, "2001:db8::2", "2001:db8::3", other.0));
        dev6.deliver(&ndp(other, 136, "2001:db8::2", "2001:db8::2", me.0));
        dev6.deliver(&ndp(other, 135, "2001:db8::2", "2001:db8::9", other.0));
        assert_eq!(seen6.lock().unwrap().len(), 2);
        adapter.close();
    }

    /// A MAC another tap client sends from is not learned for a second
    /// one: it would draw the first one's traffic to itself.
    #[test]
    fn tap_clients_cannot_share_a_mac() {
        let adapter = tap_adapter();
        let first = tap_device(&adapter, 1, "10.8.0.2");
        let second = tap_device(&adapter, 2, "10.8.0.3");
        let (seen1, seen2) = (passed(&first), passed(&second));
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let frame =
            crate::build_frame(MacAddr([0xff; 6]), mac, crate::EtherType::IPV4, &[0x45; 20]);
        first.deliver(&frame);
        second.deliver(&frame);
        assert_eq!(seen1.lock().unwrap().len(), 1);
        assert!(seen2.lock().unwrap().is_empty());
        // Once the first client is gone, its MAC is free.
        adapter.on_disconnect(first.key);
        second.deliver(&frame);
        assert_eq!(seen2.lock().unwrap().len(), 1);
        adapter.close();
    }

    /// The server's limits are the adapter's to set: here, a one-peer cap
    /// turns the second client away.
    #[test]
    fn server_limits_are_configurable() {
        let adapter = Adapter::new(
            config(Arc::default())
                .max_peers(1)
                .max_tcp_connections(1)
                .timers(crate::ovpn::PeerTimers::default().keepalive_interval(Duration::ZERO)),
        )
        .unwrap();
        let clients = [udp_client(&adapter), udp_client(&adapter)];
        assert!(answers(&clients[0], *b"CLIENT01"));
        assert!(!answers(&clients[1], *b"CLIENT02"), "peer cap not applied");
        adapter.close();
    }

    /// Bound to port 0, the TCP listener gets a port of its own, which the
    /// caller must be able to learn to connect to it.
    #[test]
    fn the_tcp_port_is_reported() {
        let adapter = Adapter::new(config(Arc::default())).unwrap();
        let tcp = adapter.tcp_local_addr().unwrap();
        assert_ne!(tcp.port(), 0);
        std::net::TcpStream::connect(tcp).expect("TCP listener at the reported address");
        adapter.close();
    }

    /// So is the limit on answers to strangers: here, one per minute.
    #[test]
    fn connect_freq_initial_is_configurable() {
        let adapter =
            Adapter::new(config(Arc::default()).connect_freq_initial((1, Duration::from_secs(60))))
                .unwrap();
        let answered = |s: &UdpSocket, sid: [u8; 8]| {
            s.send(&client_reset(sid)).unwrap();
            s.recv(&mut [0u8; 2048]).is_ok()
        };
        let clients = [udp_client(&adapter), udp_client(&adapter)];
        assert!(answered(&clients[0], *b"CLIENT01"));
        assert!(
            !answered(&clients[1], *b"CLIENT02"),
            "rate limit not applied"
        );
        adapter.close();
    }

    fn test_key(n: u8) -> PeerKey {
        PeerKey::new(
            std::net::SocketAddr::from(([192, 0, 2, n], 1194)),
            crate::ovpn::Transport::Udp,
        )
    }

    fn test_config() -> PeerConfig {
        PeerConfig::new(
            "10.8.0.2".parse().unwrap(),
            "10.8.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            24,
        )
    }

    fn packet_from(src: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[3] = 20;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&[10, 8, 0, 1]);
        p
    }

    /// Gives every device a handler that runs `f`.
    struct HandlerConnector<F>(F);

    impl<F: Fn() + Send + Sync + Clone + 'static> L3Connector for HandlerConnector<F> {
        fn connect_l3(&self, dev: Arc<dyn L3Device>) -> Result<Cleanup> {
            let f = self.0.clone();
            dev.set_handler(Arc::new(move |_: &crate::Packet| {
                f();
                Ok(())
            }));
            Ok(Box::new(|| Ok(())))
        }
    }

    fn adapter_with(connector: Arc<dyn L3Connector + Send + Sync>) -> Arc<Adapter> {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        Adapter::new(AdapterConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            Connector::L3(connector),
            on_auth,
        ))
        .unwrap()
    }

    /// A connector handler that panics (the server catches it) must not
    /// take the adapter down with it: other peers still connect, and
    /// close() -- which Drop runs -- still works.
    #[test]
    fn a_panicking_handler_does_not_break_the_adapter() {
        let adapter = adapter_with(Arc::new(HandlerConnector(|| {
            panic!("connector handler panics (expected)")
        })));
        adapter.on_connect(test_key(1), &test_config());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            adapter.deliver(test_key(1), 3, &packet_from([10, 8, 0, 2]))
        }));
        assert!(r.is_err());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            adapter.on_connect(test_key(2), &test_config());
            adapter.deliver(test_key(2), 3, &packet_from([10, 8, 0, 2]));
        }));
        assert!(r.is_err(), "the second peer's handler ran");
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            adapter.on_disconnect(test_key(2));
            adapter.close();
        }));
        assert!(r.is_ok(), "adapter unusable after a handler panicked");
    }

    /// A client with iroutes may also send from the networks behind it,
    /// and still from nowhere else.
    #[test]
    fn packets_from_an_iroute_are_accepted() {
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = adapter_with(Arc::new(HandlerConnector({
            let seen = seen.clone();
            move || {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })));
        let cfg = test_config().iroutes(vec![IpPrefix::new("192.168.5.0".parse().unwrap(), 24)]);
        adapter.on_connect(test_key(1), &cfg);
        for src in [[10, 8, 0, 2], [192, 168, 5, 77]] {
            adapter.deliver(test_key(1), 3, &packet_from(src));
        }
        for src in [[192, 168, 6, 1], [10, 8, 0, 3]] {
            adapter.deliver(test_key(1), 3, &packet_from(src));
        }
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A connector whose first connect_l3 waits for a release; it counts
    /// devices connected and cleaned up.
    struct SlowConnector {
        first: std::sync::atomic::AtomicBool,
        connects: std::sync::atomic::AtomicUsize,
        cleanups: Arc<std::sync::atomic::AtomicUsize>,
        entered: Mutex<std::sync::mpsc::Sender<()>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl L3Connector for SlowConnector {
        fn connect_l3(&self, _dev: Arc<dyn L3Device>) -> Result<Cleanup> {
            use std::sync::atomic::Ordering::SeqCst;
            self.connects.fetch_add(1, SeqCst);
            if self.first.swap(false, SeqCst) {
                let _ = self.entered.lock().unwrap().send(());
                let _ = self
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5));
            }
            let c = self.cleanups.clone();
            Ok(Box::new(move || {
                c.fetch_add(1, SeqCst);
                Ok(())
            }))
        }
    }

    /// An adapter over a [`SlowConnector`], with its first on_connect for
    /// `key` started and stuck in the connector; release it with the
    /// sender.
    fn slow_connect(
        key: PeerKey,
    ) -> (
        Arc<Adapter>,
        Arc<SlowConnector>,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let conn = Arc::new(SlowConnector {
            first: std::sync::atomic::AtomicBool::new(true),
            connects: Default::default(),
            cleanups: Default::default(),
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
        });
        let adapter = adapter_with(conn.clone());
        let a = adapter.clone();
        let t = std::thread::spawn(move || a.on_connect(key, &test_config()));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        (adapter, conn, release, t)
    }

    /// Two on_connect calls for one key at once connect one device, not
    /// two -- the second would overwrite the first's cleanup, and leave
    /// its device attached to the connector for good.
    #[test]
    fn concurrent_connects_for_a_key_attach_one_device() {
        use std::sync::atomic::Ordering::SeqCst;
        let (adapter, conn, release, slow) = slow_connect(test_key(1));
        adapter.on_connect(test_key(1), &test_config());
        release.send(()).unwrap();
        slow.join().unwrap();
        assert_eq!(conn.connects.load(SeqCst), 1);
        adapter.on_disconnect(test_key(1));
        adapter.close();
        assert_eq!(conn.cleanups.load(SeqCst), conn.connects.load(SeqCst));
    }

    /// A peer that disconnects while its device is being connected has
    /// that device detached once connected: nothing else would.
    #[test]
    fn a_disconnect_during_connect_detaches_the_device() {
        use std::sync::atomic::Ordering::SeqCst;
        let (adapter, conn, release, slow) = slow_connect(test_key(1));
        adapter.on_disconnect(test_key(1));
        release.send(()).unwrap();
        slow.join().unwrap();
        assert!(adapter.peers().is_empty());
        assert_eq!(conn.cleanups.load(SeqCst), 1);
        adapter.close();
    }

    /// A handler may call back into the adapter -- sending to a peer can
    /// remove it, which runs its cleanup -- without deadlocking.
    #[test]
    fn a_handler_may_reenter_the_adapter() {
        let slot: Arc<std::sync::OnceLock<Weak<Adapter>>> = Arc::default();
        let adapter = adapter_with(Arc::new(HandlerConnector({
            let slot = slot.clone();
            move || {
                if let Some(a) = slot.get().and_then(Weak::upgrade) {
                    a.on_disconnect(test_key(1));
                }
            }
        })));
        slot.set(Arc::downgrade(&adapter)).unwrap();
        adapter.on_connect(test_key(1), &test_config());
        let (tx, rx) = std::sync::mpsc::channel();
        let a = adapter.clone();
        std::thread::spawn(move || {
            a.deliver(test_key(1), 3, &packet_from([10, 8, 0, 2]));
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "deadlocked"
        );
        assert!(adapter.peers.lock().unwrap().is_empty());
    }
}

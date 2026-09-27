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

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

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
    /// Most TCP connections served at once; see
    /// [`ServerConfig::max_tcp_connections`].
    pub max_tcp_connections: usize,
    /// Each peer's timers; see [`ServerConfig::timers`].
    pub timers: PeerTimers,
}

setters! {
    AdapterConfig {
        set max_peers: usize;
        set max_tcp_connections: usize;
        set timers: PeerTimers;
    }
}

impl AdapterConfig {
    /// The required fields; the limits and timers take the server's
    /// defaults.
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
            max_tcp_connections: super::server::DEFAULT_MAX_TCP_CONNECTIONS,
            timers: PeerTimers::default(),
        }
    }
}

impl std::fmt::Debug for AdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterConfig")
            .field("listen_addr", &self.listen_addr)
            .field("connector", &self.connector)
            .field("max_peers", &self.max_peers)
            .field("max_tcp_connections", &self.max_tcp_connections)
            .field("timers", &self.timers)
            .finish()
    }
}

struct OvpnPeer {
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
        let server_cfg = ServerConfig::new(cfg.tls_config, cfg.listen_addr, cfg.on_auth, on_data)
            .max_peers(cfg.max_peers)
            .max_tcp_connections(cfg.max_tcp_connections)
            .timers(cfg.timers)
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
        // Avoid double-setup if we already wired this peer.
        if self.peers().contains_key(&key) {
            return;
        }
        let prefix = IpPrefix::new(cfg.ip, cfg.prefix_len);

        // Determine layer from the connector type (the server tracks the peer's
        // dev-type, but here we wire based on what the operator configured).
        match &self.connector {
            Connector::L3(conn) => {
                let dev = PeerL3Device::new(&self.me, key, prefix);
                let cleanup = match conn.connect_l3(dev.clone() as Arc<dyn L3Device>) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                self.peers().insert(
                    key,
                    OvpnPeer {
                        l3: Some(dev),
                        l2: None,
                        cleanup: Mutex::new(Some(cleanup)),
                    },
                );
            }
            Connector::L2(conn) => {
                let dev = PeerL2Device::new(&self.me, key);
                let cleanup = match conn.connect_l2(dev.clone() as Arc<dyn L2Device>) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                self.peers().insert(
                    key,
                    OvpnPeer {
                        l3: None,
                        l2: Some(dev),
                        cleanup: Mutex::new(Some(cleanup)),
                    },
                );
            }
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
    /// The tunnel address pushed to the client: the only source its
    /// packets may carry.
    client_ip: IpAddr,
}

impl PeerL3Device {
    fn new(adapter: &Weak<Adapter>, key: PeerKey, addr: IpPrefix) -> Arc<Self> {
        Arc::new(PeerL3Device {
            adapter: adapter.clone(),
            key,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            client_ip: addr.addr(),
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
        // A client may only speak for the address it was given (multi.c
        // multi_process_incoming_link, "bad source address from client"):
        // otherwise it could pass for another client, or for any host at
        // all, to whatever the connector leads to. An IPv6 packet from a
        // client given an IPv4 address, link-local ones included, has no
        // address of its own to come from either.
        if !packet.is_valid() || packet.src_addr() != Some(self.client_ip) {
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
}

impl PeerL2Device {
    fn new(adapter: &Weak<Adapter>, key: PeerKey) -> Arc<Self> {
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
        })
    }

    /// The handler, cloned out so it is called with no lock held.
    fn handler(&self) -> Option<L2Handler> {
        self.handler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn deliver(&self, data: &[u8]) {
        let h = self.handler();
        if let Some(h) = h {
            let _ = h(crate::Frame::from_slice(data));
        }
    }
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
    use std::time::Duration;

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
    fn answers(adapter: &Adapter, sid: [u8; 8]) -> bool {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect(adapter.local_addr().unwrap()).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
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
        let dev = PeerL3Device::new(&Weak::new(), key, prefix);
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
        assert!(answers(&adapter, *b"CLIENT01"));
        assert!(!answers(&adapter, *b"CLIENT02"), "peer cap not applied");
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

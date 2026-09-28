//! High-level [`Adapter`]: bridges WireGuard peers to a pktkit network.
//!
//! Each peer that completes a handshake gets a per-peer [`L3Device`] which
//! is connected to the configured [`L3Connector`]. Packets to the peer are
//! encrypted and pushed onto the UDP socket; packets from the peer are
//! decrypted and delivered through the device handler installed by the
//! connector (typically a NAT engine for namespace isolation).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock, Weak};
use std::thread;

use crate::accept::{Cleanup, L3Connector};
use crate::iface::{L3Device, L3Handler};
use crate::wg::handler::{Config as HandlerConfig, Handler};
use crate::wg::multihandler::MultiHandler;
use crate::wg::server::{OnPacketFn, OnPeerConnectedFn, Server, ServerConfig};
use crate::wg::{NoisePresharedKey, NoisePrivateKey, NoisePublicKey};
use crate::{IpPrefix, Packet, Result};

/// Configuration for a [`WireGuard Adapter`](Adapter).
#[derive(Clone)]
#[non_exhaustive]
pub struct AdapterConfig {
    /// Local WireGuard identity. Ignored if `multi_handler` is set.
    pub private_key: NoisePrivateKey,
    /// Multi-identity handler; mutually exclusive with `private_key`.
    pub multi_handler: Option<Arc<MultiHandler>>,
    /// Per-peer L3 connector. **Required** — see crate-level docs.
    pub connector: Arc<dyn L3Connector + Send + Sync>,
    /// Address advertised by each peer device. The connector typically uses
    /// this to seed routing decisions.
    pub addr: IpPrefix,
    /// Optional callback for unauthorized peers.
    pub on_unknown_peer: Option<crate::wg::handler::UnknownPeerFn>,
    /// Most peers [`Adapter::accept_unknown_peer`] takes the handler to; see
    /// [`Config::unknown_peer_limit`](crate::wg::Config::unknown_peer_limit).
    /// `None` uses the default (10000). Ignored if `multi_handler` is set:
    /// its handlers carry their own.
    pub unknown_peer_limit: Option<usize>,
}

setters! {
    AdapterConfig {
        some multi_handler: Arc<MultiHandler>;
        some on_unknown_peer: crate::wg::handler::UnknownPeerFn;
        some unknown_peer_limit: usize;
    }
}

impl AdapterConfig {
    /// An adapter with identity `private_key`, joining each peer's device to
    /// `connector` with address `addr`.
    pub fn new(
        private_key: NoisePrivateKey,
        connector: Arc<dyn L3Connector + Send + Sync>,
        addr: IpPrefix,
    ) -> AdapterConfig {
        AdapterConfig {
            private_key,
            multi_handler: None,
            connector,
            addr,
            on_unknown_peer: None,
            unknown_peer_limit: None,
        }
    }
}

impl std::fmt::Debug for AdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterConfig")
            .field("multi_handler", &self.multi_handler.is_some())
            .field("addr", &self.addr)
            .finish()
    }
}

/// Bridges WireGuard peers to a pktkit network.
pub struct Adapter {
    handler: Option<Arc<Handler>>,
    multi_handler: Option<Arc<MultiHandler>>,
    server: Arc<Server>,
    connector: Arc<dyn L3Connector + Send + Sync>,
    addr: IpPrefix,
    peers: RwLock<std::collections::HashMap<NoisePublicKey, WgPeer>>,
    closed: AtomicBool,
}

impl Drop for Adapter {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter").field("addr", &self.addr).finish()
    }
}

struct WgPeer {
    #[allow(dead_code)]
    key: NoisePublicKey,
    dev: Arc<PeerL3Device>,
    cleanup: Mutex<Option<Cleanup>>,
}

/// Per-peer L3 device. Sends call back into the adapter to encrypt and ship
/// through the UDP socket; received packets are delivered to whatever handler
/// the [`L3Connector`] installed.
pub(crate) struct PeerL3Device {
    adapter: Weak<Adapter>,
    key: NoisePublicKey,
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
}

impl std::fmt::Debug for PeerL3Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerL3Device")
            .field("key", &self.key)
            .finish()
    }
}

impl PeerL3Device {
    fn new(adapter: &Arc<Adapter>, key: NoisePublicKey, addr: IpPrefix) -> Arc<Self> {
        Arc::new(PeerL3Device {
            adapter: Arc::downgrade(adapter),
            key,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
        })
    }

    fn deliver(&self, data: &[u8]) {
        // Not under the lock: the guard of an `if let` scrutinee lives
        // through its block, and a handler that calls set_handler (or
        // anything that does) would wait on itself.
        let h = self.handler.lock().expect("handler lock").clone();
        if let Some(h) = h {
            let p = Packet::from_slice(data);
            let _ = h(p);
        }
    }
}

impl L3Device for PeerL3Device {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().expect("handler lock") = Some(h);
    }

    fn send(&self, packet: &Packet) -> Result<()> {
        let Some(adapter) = self.adapter.upgrade() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "adapter dropped",
            ));
        };
        adapter.server.send(packet.as_bytes(), &self.key)
    }

    fn addr(&self) -> IpPrefix {
        *self.addr.lock().expect("addr lock")
    }

    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().expect("addr lock") = p;
        Ok(())
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

impl Adapter {
    /// Build a new adapter from `cfg`. Call [`Adapter::serve`] to run.
    pub fn new(cfg: AdapterConfig) -> Result<Arc<Self>> {
        // The server's callbacks reach the adapter, built after the server,
        // through a Weak set once it exists. Set once and read without a
        // lock: a lock taken here would be held through the connector and
        // the device handlers, caller code that may re-enter (a connector
        // accepting a pending peer deadlocked) or panic (poisoning it for
        // every later packet).
        let weak_for_cb: Arc<OnceLock<Weak<Adapter>>> = Arc::new(OnceLock::new());
        let weak_for_cb_pkt = weak_for_cb.clone();
        let weak_for_cb_conn = weak_for_cb.clone();

        // OnPacket: deliver decrypted bytes to the matching peer device.
        let on_packet: OnPacketFn =
            Arc::new(move |data: &[u8], key: NoisePublicKey, _h: &Arc<Handler>| {
                if let Some(a) = weak_for_cb_pkt.get().and_then(Weak::upgrade) {
                    a.on_packet(data, key);
                }
            });
        // OnPeerConnected: wire up the per-peer device.
        let on_connected: OnPeerConnectedFn =
            Arc::new(move |key: NoisePublicKey, _h: &Arc<Handler>| {
                if let Some(a) = weak_for_cb_conn.get().and_then(Weak::upgrade) {
                    a.on_peer_connected(key);
                }
            });

        let server_cfg = if let Some(mh) = cfg.multi_handler.clone() {
            // Apply the unknown-peer callback to every handler already in the
            // multiplexer. Handlers added later via MultiHandler::add_handler
            // should be configured by the caller before they are added.
            if let Some(cb) = cfg.on_unknown_peer.clone() {
                for h in mh.handlers() {
                    h.set_on_unknown_peer(cb.clone());
                }
            }
            ServerConfig {
                handler: None,
                multi_handler: Some(mh),
                on_packet,
                on_peer_connected: Some(on_connected),
                maintenance_interval: None,
                read_buffer_size: 65535,
            }
        } else {
            let h = Handler::new(HandlerConfig {
                private_key: cfg.private_key.clone(),
                on_unknown_peer: cfg.on_unknown_peer.clone(),
                load_threshold: None,
                unknown_peer_limit: cfg.unknown_peer_limit,
            })?;
            ServerConfig {
                handler: Some(h),
                multi_handler: None,
                on_packet,
                on_peer_connected: Some(on_connected),
                maintenance_interval: None,
                read_buffer_size: 65535,
            }
        };
        let handler = server_cfg.handler.clone();
        let multi = server_cfg.multi_handler.clone();
        let server = Server::new(server_cfg)?;

        let me = Arc::new(Adapter {
            handler,
            multi_handler: multi,
            server,
            connector: cfg.connector,
            addr: cfg.addr,
            peers: RwLock::new(std::collections::HashMap::new()),
            closed: AtomicBool::new(false),
        });
        let _ = weak_for_cb.set(Arc::downgrade(&me));
        Ok(me)
    }

    /// Run the UDP server loop on the provided socket. Blocks until
    /// [`Adapter::close`] is called.
    pub fn serve(self: &Arc<Self>, conn: UdpSocket) -> Result<()> {
        self.server.serve(Arc::new(conn))
    }

    /// Spawn the server loop in a background thread. Returns a join handle.
    /// The thread exits cleanly once [`Adapter::close`] is called, or the
    /// adapter is dropped.
    pub fn spawn_serve(self: &Arc<Self>, conn: UdpSocket) -> thread::JoinHandle<Result<()>> {
        // Only the server: holding the adapter would keep it alive, and so
        // the thread and socket, however long after the caller let go.
        let server = self.server.clone();
        thread::spawn(move || server.serve(Arc::new(conn)))
    }

    /// Authorize (or refresh) a peer. In multi-handler mode this authorizes
    /// on every member identity.
    ///
    /// This is [`Handler::add_peer`] on each: a peer already known keeps
    /// its preshared key, and any [expiry](Handler::set_peer_expiry) is
    /// cleared, so a lapsed peer is authorized again.
    pub fn add_peer(&self, key: NoisePublicKey) {
        if let Some(mh) = self.multi_handler.as_ref() {
            for h in mh.handlers() {
                h.add_peer(key);
            }
        } else if let Some(h) = self.handler.as_ref() {
            h.add_peer(key);
        }
    }

    /// Authorize a peer on a specific handler (multi mode).
    pub fn add_peer_to(&self, key: NoisePublicKey, handler: &Arc<Handler>) {
        handler.add_peer(key);
    }

    /// Authorize a peer with a preshared key (single mode only).
    pub fn add_peer_with_psk(&self, key: NoisePublicKey, psk: NoisePresharedKey) -> Result<()> {
        if let Some(h) = self.handler.as_ref() {
            h.add_peer_with_psk(key, psk);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "add_peer_with_psk requires single-handler mode",
            ))
        }
    }

    /// Authorize an unknown peer's handshake (call from `on_unknown_peer`)
    /// and complete it: the response goes out, the peer's address is
    /// recorded and `on_peer_connected` fires, as for any other handshake.
    ///
    /// A new peer is refused once the handler has
    /// [`unknown_peer_limit`](AdapterConfig::unknown_peer_limit) peers,
    /// none of them past its expiry: the one expired longest is otherwise
    /// removed to make room.
    pub fn accept_unknown_peer(
        &self,
        key: NoisePublicKey,
        packet: &[u8],
        addr: SocketAddr,
    ) -> Result<()> {
        let h = if let Some(mh) = self.multi_handler.as_ref() {
            let h = mh
                .handlers()
                .into_iter()
                .find(|h| crate::wg::handshake::check_mac1(h.public_key().as_bytes(), packet))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no handler matched MAC1")
                })?;
            h.add_unknown_peer(key)?;
            h
        } else if let Some(h) = self.handler.as_ref() {
            h.add_unknown_peer(key)?;
            h.clone()
        } else {
            return Err(io::Error::other("no handler"));
        };
        // Handling the packet for a peer still unauthorized (removed or
        // expired again meanwhile) would only invoke on_unknown_peer again,
        // from inside the call that got us here.
        if !h.is_authorized_peer(&key) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer not authorized after adding it",
            ));
        }
        crate::wg::handler::replay_accepted(|| self.server.handle_packet(packet, addr))
    }

    /// Remove a peer and tear down its plumbing.
    pub fn remove_peer(&self, key: &NoisePublicKey) {
        if let Some(mh) = self.multi_handler.as_ref() {
            for h in mh.handlers() {
                h.remove_peer(key);
            }
        } else if let Some(h) = self.handler.as_ref() {
            h.remove_peer(key);
        }
        self.server.forget_peer(key);
        self.teardown_peer(key);
    }

    /// Initiate a handshake to a peer (single mode).
    pub fn connect(&self, key: &NoisePublicKey, addr: SocketAddr) -> Result<()> {
        self.server.connect(key, addr)
    }

    /// Initiate a handshake with a specific handler (multi mode).
    pub fn connect_with(
        &self,
        key: &NoisePublicKey,
        addr: SocketAddr,
        handler: &Arc<Handler>,
    ) -> Result<()> {
        self.server.connect_with(key, addr, handler)
    }

    /// Local public key (single mode). Panics in multi mode.
    pub fn public_key(&self) -> NoisePublicKey {
        self.handler
            .as_ref()
            .expect("public_key requires single-handler mode")
            .public_key()
    }

    /// The handler, in single-handler mode; `None` in multi-handler mode.
    pub fn handler(&self) -> Option<Arc<Handler>> {
        self.handler.clone()
    }

    /// The multi-handler, in multi-handler mode; `None` otherwise.
    pub fn multi_handler(&self) -> Option<Arc<MultiHandler>> {
        self.multi_handler.clone()
    }

    /// Tear down everything: stop the server, drop all peer plumbing.
    pub fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let _ = self.server.close();
        let peers: Vec<_> = {
            let mut g = self.peers.write().expect("peers lock");
            g.drain().map(|(_, p)| p).collect()
        };
        // Cleanups are caller code, and this may run from Drop, on the
        // server's read loop: one that panics must not skip the rest.
        for p in peers {
            let cleanup = p
                .cleanup
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(cleanup) = cleanup {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup));
            }
        }
        if let Some(mh) = self.multi_handler.as_ref() {
            return mh.close();
        }
        if let Some(h) = self.handler.as_ref() {
            return h.close();
        }
        Ok(())
    }

    // --- callbacks fired by the server -----------------------------------

    fn on_peer_connected(self: &Arc<Self>, key: NoisePublicKey) {
        if self.peers.read().expect("peers lock").contains_key(&key) {
            // Already wired (this is a rekey). Nothing else to do.
            return;
        }

        // The connector is caller code and may call back into the adapter
        // (remove_peer, close) while it wires the device, so it runs
        // without the peers lock held.
        let dev = PeerL3Device::new(self, key, self.addr);
        let dev_dyn: Arc<dyn L3Device> = dev.clone();
        let cleanup = match self.connector.connect_l3(dev_dyn) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut peers = self.peers.write().expect("peers lock");
        // Meanwhile the peer may have been removed (remove_peer deauthorizes
        // before tearing down, so either it sees our entry or we see the
        // peer gone), the adapter closed (close sets the flag before
        // draining), or a concurrent connect wired it first.
        let keep = !self.closed.load(Ordering::SeqCst)
            && self.is_authorized(&key)
            && !peers.contains_key(&key);
        if keep {
            peers.insert(
                key,
                WgPeer {
                    key,
                    dev,
                    cleanup: Mutex::new(Some(cleanup)),
                },
            );
            return;
        }
        drop(peers);
        let _ = cleanup();
    }

    fn is_authorized(&self, key: &NoisePublicKey) -> bool {
        if let Some(mh) = self.multi_handler.as_ref() {
            mh.handlers().iter().any(|h| h.is_authorized_peer(key))
        } else {
            self.handler
                .as_ref()
                .is_some_and(|h| h.is_authorized_peer(key))
        }
    }

    fn on_packet(&self, data: &[u8], key: NoisePublicKey) {
        let peer = {
            let g = self.peers.read().expect("peers lock");
            g.get(&key).map(|p| p.dev.clone())
        };
        if let Some(dev) = peer {
            dev.deliver(data);
        }
    }

    fn teardown_peer(&self, key: &NoisePublicKey) {
        let removed = self.peers.write().expect("peers lock").remove(key);
        if let Some(p) = removed
            && let Some(cleanup) = p.cleanup.lock().expect("cleanup lock").take()
        {
            let _ = cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::L3Hub;

    /// A peer device's handler may replace itself from inside a delivery.
    #[test]
    fn device_handler_may_replace_itself() {
        let dev = Arc::new(PeerL3Device {
            adapter: Weak::new(),
            key: NoisePublicKey([1; 32]),
            handler: Mutex::new(None),
            addr: Mutex::new("10.0.0.1/24".parse().unwrap()),
        });
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let weak = Arc::downgrade(&dev);
        dev.set_handler(Arc::new(move |_p: &Packet| {
            if let Some(d) = weak.upgrade() {
                d.set_handler(Arc::new(|_p: &Packet| Ok(())));
            }
            let _ = tx.lock().unwrap().send(());
            Ok(())
        }));
        let d = dev.clone();
        thread::spawn(move || d.deliver(&[0x45; 20]));
        rx.recv_timeout(Duration::from_secs(10))
            .expect("deadlocked in the device handler");
    }
    use crate::wg::handler::PacketType;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    type Hook = Box<dyn Fn(&Arc<Adapter>) + Send + Sync>;

    /// A connector that calls back into the adapter while wiring a device,
    /// and counts the cleanups it hands out that have run.
    struct Reentrant {
        adapter: Mutex<Option<Weak<Adapter>>>,
        hook: Mutex<Option<Hook>>,
        cleaned: Arc<AtomicUsize>,
    }

    impl L3Connector for Reentrant {
        fn connect_l3(&self, _dev: Arc<dyn L3Device>) -> Result<Cleanup> {
            let a = self
                .adapter
                .lock()
                .unwrap()
                .as_ref()
                .and_then(Weak::upgrade);
            // Taken, so a nested connect does not run it again.
            let hook = self.hook.lock().unwrap().take();
            if let (Some(a), Some(hook)) = (a, hook) {
                hook(&a);
            }
            let c = self.cleaned.clone();
            Ok(Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }))
        }
    }

    fn reentrant_adapter(hook: Hook) -> (Arc<Adapter>, Arc<AtomicUsize>) {
        let cleaned = Arc::new(AtomicUsize::new(0));
        let conn = Arc::new(Reentrant {
            adapter: Mutex::new(None),
            hook: Mutex::new(Some(hook)),
            cleaned: cleaned.clone(),
        });
        let a = Adapter::new(AdapterConfig::new(
            crate::wg::generate_private_key().unwrap(),
            conn.clone(),
            "10.0.0.1/24".parse().unwrap(),
        ))
        .unwrap();
        *conn.adapter.lock().unwrap() = Some(Arc::downgrade(&a));
        (a, cleaned)
    }

    fn connect_in_thread(a: &Arc<Adapter>, key: NoisePublicKey) {
        let (tx, rx) = std::sync::mpsc::channel();
        let a2 = a.clone();
        thread::spawn(move || {
            a2.on_peer_connected(key);
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(10))
            .expect("deadlocked in the connector");
    }

    /// The connector runs outside the peers lock: one that removes the peer
    /// (or closes the adapter) while wiring it must not deadlock, and the
    /// device it was handing over is torn down rather than kept for a peer
    /// that is gone.
    #[test]
    fn a_connector_may_remove_the_peer_it_is_wiring() {
        let key = NoisePublicKey([9; 32]);
        let (a, cleaned) = reentrant_adapter(Box::new(move |a| a.remove_peer(&key)));
        a.add_peer(key);
        connect_in_thread(&a, key);
        assert!(!a.peers.read().unwrap().contains_key(&key));
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);

        let (a, cleaned) = reentrant_adapter(Box::new(|a| {
            let _ = a.close();
        }));
        a.add_peer(key);
        connect_in_thread(&a, key);
        assert!(a.peers.read().unwrap().is_empty());
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);
    }

    /// Two connects for one peer at once wire one device; the other's is
    /// cleaned up.
    #[test]
    fn a_duplicate_connect_keeps_one_device() {
        let key = NoisePublicKey([9; 32]);
        let (a, cleaned) = reentrant_adapter(Box::new(move |a| a.on_peer_connected(key)));
        a.add_peer(key);
        connect_in_thread(&a, key);
        assert!(a.peers.read().unwrap().contains_key(&key));
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);
        a.close().unwrap();
        assert_eq!(cleaned.load(Ordering::SeqCst), 2);
    }

    /// An unknown peer accepted from `on_unknown_peer` gets its handshake
    /// response, over the wire, without having to retry.
    #[test]
    fn accepted_unknown_peer_gets_its_response() {
        accept_from_callback(false);
    }

    /// The same for a peer whose authorization expired: accepting it again
    /// authorizes it again. Before, it stayed expired, and handling the
    /// initiation again invoked on_unknown_peer again, which accepted it
    /// again, until the stack overflowed.
    #[test]
    fn an_expired_peer_can_be_accepted_again() {
        accept_from_callback(true);
    }

    fn accept_from_callback(expired: bool) {
        let hub = L3Hub::new();
        let slot: Arc<Mutex<Option<Weak<Adapter>>>> = Arc::new(Mutex::new(None));
        let s = slot.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let on_unknown: crate::wg::handler::UnknownPeerFn =
            Arc::new(move |key, addr, pkt: &[u8]| {
                // Stop short of a stack overflow, which would take the whole
                // test binary down.
                if c.fetch_add(1, Ordering::SeqCst) > 20 {
                    return;
                }
                let a = s.lock().unwrap().as_ref().and_then(Weak::upgrade);
                if let Some(a) = a {
                    a.accept_unknown_peer(key, pkt, addr).unwrap();
                }
            });
        let server_key = crate::wg::generate_private_key().unwrap();
        let adapter = Adapter::new(
            AdapterConfig::new(
                server_key,
                Arc::new(Arc::new(hub)),
                "10.0.0.1/24".parse().unwrap(),
            )
            .on_unknown_peer(on_unknown),
        )
        .unwrap();
        *slot.lock().unwrap() = Some(Arc::downgrade(&adapter));
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = sock.local_addr().unwrap();
        let _t = adapter.spawn_serve(sock);

        let client = Handler::new(HandlerConfig::default()).unwrap();
        let server = adapter.handler.as_ref().unwrap();
        let server_pub = server.public_key();
        client.add_peer(server_pub);
        if expired {
            server.add_peer(client.public_key());
            let past = crate::time::Instant::now() - Duration::from_secs(1);
            server.set_peer_expiry(&client.public_key(), past);
        }
        let csock = UdpSocket::bind("127.0.0.1:0").unwrap();
        csock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let init = client.initiate_handshake(&server_pub).unwrap();
        csock.send_to(&init, server_addr).unwrap();

        let mut buf = [0u8; 256];
        let (n, from) = csock.recv_from(&mut buf).expect("no handshake response");
        let res = client.process_packet(&buf[..n], &from).unwrap();
        assert_eq!(res.ty, PacketType::HandshakeResponse);
        assert_eq!(
            adapter.server.peer_addr(&client.public_key()),
            Some(csock.local_addr().unwrap())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        adapter.close().unwrap();
    }

    /// A connector may accept a pending unknown peer, whose handshake then
    /// completes, and connects, from inside the call that runs it.
    #[test]
    fn a_connector_may_accept_a_pending_peer() {
        type Pending = (NoisePublicKey, Vec<u8>, SocketAddr);
        let pending: Arc<Mutex<Option<Pending>>> = Arc::default();
        let (p, done) = (pending.clone(), Arc::new(AtomicUsize::new(0)));
        let d = done.clone();
        let (a, _) = reentrant_adapter(Box::new(move |a| {
            let item = p.lock().unwrap().take();
            if let Some((k, pkt, addr)) = item {
                let _ = a.accept_unknown_peer(k, &pkt, addr);
            }
            d.fetch_add(1, Ordering::SeqCst);
        }));
        let p = pending.clone();
        a.handler()
            .unwrap()
            .set_on_unknown_peer(Arc::new(move |k, addr, pkt: &[u8]| {
                *p.lock().unwrap() = Some((k, pkt.to_vec(), addr));
            }));
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let saddr = sock.local_addr().unwrap();
        let _t = a.spawn_serve(sock);
        let spub = a.public_key();

        // An unknown peer, parked by on_unknown_peer.
        let stranger = Handler::new(HandlerConfig::default()).unwrap();
        stranger.add_peer(spub);
        let ssock = UdpSocket::bind("127.0.0.1:0").unwrap();
        ssock
            .send_to(&stranger.initiate_handshake(&spub).unwrap(), saddr)
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while pending.lock().unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline, "never parked");
            thread::sleep(Duration::from_millis(5));
        }
        // A known one, whose connect runs the connector.
        let known = Handler::new(HandlerConfig::default()).unwrap();
        known.add_peer(spub);
        a.add_peer(known.public_key());
        let ksock = UdpSocket::bind("127.0.0.1:0").unwrap();
        ksock
            .send_to(&known.initiate_handshake(&spub).unwrap(), saddr)
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while done.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "deadlocked in the connector"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let peers = a.peers.read().unwrap();
        assert!(peers.contains_key(&known.public_key()));
        assert!(peers.contains_key(&stranger.public_key()));
        drop(peers);
        a.close().unwrap();
    }

    /// A device handler that panics costs the packet it was handed; the
    /// next one is still delivered.
    #[test]
    fn a_panicking_device_handler_does_not_break_the_adapter() {
        struct PanicOnce(Arc<AtomicUsize>);
        impl L3Connector for PanicOnce {
            fn connect_l3(&self, dev: Arc<dyn L3Device>) -> Result<Cleanup> {
                let n = self.0.clone();
                dev.set_handler(Arc::new(move |_p: &Packet| {
                    if n.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("caller bug");
                    }
                    Ok(())
                }));
                Ok(Box::new(|| Ok(())))
            }
        }
        let n = Arc::new(AtomicUsize::new(0));
        let a = Adapter::new(AdapterConfig::new(
            crate::wg::generate_private_key().unwrap(),
            Arc::new(PanicOnce(n.clone())),
            "10.0.0.1/24".parse().unwrap(),
        ))
        .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let saddr = sock.local_addr().unwrap();
        let _t = a.spawn_serve(sock);
        let spub = a.public_key();
        let c = Handler::new(HandlerConfig::default()).unwrap();
        c.add_peer(spub);
        a.add_peer(c.public_key());
        let cs = UdpSocket::bind("127.0.0.1:0").unwrap();
        cs.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        cs.send_to(&c.initiate_handshake(&spub).unwrap(), saddr)
            .unwrap();
        let mut buf = [0u8; 256];
        let (k, from) = cs.recv_from(&mut buf).unwrap();
        c.process_packet(&buf[..k], &from).unwrap();
        for _ in 0..2 {
            cs.send_to(&c.encrypt(&[0x45; 40], &spub).unwrap(), saddr)
                .unwrap();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while n.load(Ordering::SeqCst) < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "second packet never delivered"
            );
            thread::sleep(Duration::from_millis(5));
        }
        a.close().unwrap();
    }

    /// Dropping the adapter without close() still stops the thread
    /// spawn_serve started, and lets go of the server and its socket.
    #[test]
    fn dropping_the_adapter_stops_serving() {
        let hub = L3Hub::new();
        let a = Adapter::new(AdapterConfig::new(
            crate::wg::generate_private_key().unwrap(),
            Arc::new(Arc::new(hub)),
            "10.0.0.1/24".parse().unwrap(),
        ))
        .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let t = a.spawn_serve(sock);
        let server = Arc::downgrade(&a.server);
        let adapter = Arc::downgrade(&a);
        drop(a);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !t.is_finished() || server.upgrade().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "still serving after the adapter was dropped"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(adapter.upgrade().is_none());
        t.join().unwrap().unwrap();
    }

    /// A cleanup that panics does not keep the others from running when
    /// the adapter closes (which dropping it now does, possibly on the
    /// server's read loop).
    #[test]
    fn a_panicking_cleanup_does_not_skip_the_others() {
        struct PanickyCleanup(Arc<AtomicUsize>);
        impl L3Connector for PanickyCleanup {
            fn connect_l3(&self, _dev: Arc<dyn L3Device>) -> Result<Cleanup> {
                let n = self.0.clone();
                Ok(Box::new(move || {
                    n.fetch_add(1, Ordering::SeqCst);
                    panic!("caller bug");
                }))
            }
        }
        let n = Arc::new(AtomicUsize::new(0));
        let a = Adapter::new(AdapterConfig::new(
            crate::wg::generate_private_key().unwrap(),
            Arc::new(PanickyCleanup(n.clone())),
            "10.0.0.1/24".parse().unwrap(),
        ))
        .unwrap();
        for i in 1..=2 {
            let key = NoisePublicKey([i; 32]);
            a.add_peer(key);
            a.on_peer_connected(key);
        }
        drop(a);
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }
}

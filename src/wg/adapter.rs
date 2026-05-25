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
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread;

use crate::iface::{L3Device, L3Handler};
use crate::namespace::{Cleanup, L3Connector};
use crate::wg::handler::{Config as HandlerConfig, Handler};
use crate::wg::multihandler::MultiHandler;
use crate::wg::server::{OnPacketFn, OnPeerConnectedFn, Server, ServerConfig};
use crate::wg::{NoisePresharedKey, NoisePrivateKey, NoisePublicKey};
use crate::{IpPrefix, Packet, Result};

/// Configuration for a [`WireGuard Adapter`](Adapter).
#[derive(Clone)]
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
        if let Some(h) = self.handler.lock().expect("handler lock").clone() {
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
        // We pre-allocate the Arc<Self> via Arc::new_cyclic so the per-peer
        // devices can hold a Weak<Adapter>.
        let weak_for_cb: Mutex<Option<Weak<Adapter>>> = Mutex::new(None);
        let weak_for_cb = Arc::new(weak_for_cb);
        let weak_for_cb_pkt = weak_for_cb.clone();
        let weak_for_cb_conn = weak_for_cb.clone();

        // OnPacket: deliver decrypted bytes to the matching peer device.
        let on_packet: OnPacketFn =
            Arc::new(move |data: &[u8], key: NoisePublicKey, _h: &Arc<Handler>| {
                if let Some(a) = weak_for_cb_pkt
                    .lock()
                    .expect("weak lock")
                    .as_ref()
                    .and_then(|w| w.upgrade())
                {
                    a.on_packet(data, key);
                }
            });
        // OnPeerConnected: wire up the per-peer device.
        let on_connected: OnPeerConnectedFn =
            Arc::new(move |key: NoisePublicKey, _h: &Arc<Handler>| {
                if let Some(a) = weak_for_cb_conn
                    .lock()
                    .expect("weak lock")
                    .as_ref()
                    .and_then(|w| w.upgrade())
                {
                    a.on_peer_connected(key);
                }
            });

        let server_cfg = if let Some(mh) = cfg.multi_handler.clone() {
            if let Some(cb) = cfg.on_unknown_peer.clone() {
                // TODO(wg): set per-handler unknown-peer callbacks. We can't
                // mutate Handler.on_unknown_peer after construction without a
                // setter; for now the callback set via AdapterConfig is only
                // honoured in single-handler mode.
                let _ = cb;
            }
            ServerConfig {
                handler: None,
                multi_handler: Some(mh),
                on_packet,
                on_peer_connected: Some(on_connected),
                maintenance_interval: None,
                read_buffer_size: 2048,
            }
        } else {
            let h = Handler::new(HandlerConfig {
                private_key: cfg.private_key.clone(),
                on_unknown_peer: cfg.on_unknown_peer.clone(),
                load_threshold: None,
            })?;
            ServerConfig {
                handler: Some(h),
                multi_handler: None,
                on_packet,
                on_peer_connected: Some(on_connected),
                maintenance_interval: None,
                read_buffer_size: 2048,
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
        *weak_for_cb.lock().expect("weak lock") = Some(Arc::downgrade(&me));
        Ok(me)
    }

    /// Run the UDP server loop on the provided socket. Blocks until
    /// [`Adapter::close`] is called.
    pub fn serve(self: &Arc<Self>, conn: UdpSocket) -> Result<()> {
        self.server.serve(Arc::new(conn))
    }

    /// Spawn the server loop in a background thread. Returns a join handle.
    /// The thread exits cleanly once [`Adapter::close`] is called.
    pub fn spawn_serve(self: &Arc<Self>, conn: UdpSocket) -> thread::JoinHandle<Result<()>> {
        let me = self.clone();
        thread::spawn(move || me.server.serve(Arc::new(conn)))
    }

    /// Authorize a peer. In multi-handler mode this authorizes on every
    /// member identity.
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

    /// Authorize an unknown peer's handshake (call from `on_unknown_peer`).
    pub fn accept_unknown_peer(
        &self,
        key: NoisePublicKey,
        packet: &[u8],
        addr: SocketAddr,
    ) -> Result<()> {
        if let Some(mh) = self.multi_handler.as_ref() {
            for h in mh.handlers() {
                if crate::wg::handshake::check_mac1(h.public_key().as_bytes(), packet) {
                    let _ = h.accept_unknown_peer(key, packet, &addr)?;
                    return Ok(());
                }
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no handler matched MAC1",
            ))
        } else if let Some(h) = self.handler.as_ref() {
            let _ = h.accept_unknown_peer(key, packet, &addr)?;
            Ok(())
        } else {
            Err(io::Error::other("no handler"))
        }
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

    pub fn handler(&self) -> Option<Arc<Handler>> {
        self.handler.clone()
    }

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
        for p in peers {
            if let Some(cleanup) = p.cleanup.lock().expect("cleanup lock").take() {
                let _ = cleanup();
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
        let mut peers = self.peers.write().expect("peers lock");
        if peers.contains_key(&key) {
            // Already wired (this is a rekey). Nothing else to do.
            return;
        }

        let dev = PeerL3Device::new(self, key, self.addr);
        let dev_dyn: Arc<dyn L3Device> = dev.clone();
        let cleanup = match self.connector.connect_l3(dev_dyn) {
            Ok(c) => c,
            Err(_) => return,
        };
        peers.insert(
            key,
            WgPeer {
                key,
                dev,
                cleanup: Mutex::new(Some(cleanup)),
            },
        );
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
        if let Some(p) = removed {
            if let Some(cleanup) = p.cleanup.lock().expect("cleanup lock").take() {
                let _ = cleanup();
            }
        }
    }
}

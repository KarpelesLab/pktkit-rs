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
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};

use super::addr::PeerKey;
use super::peer::{OnAuth, PeerConfig};
use super::server::{Server, ServerConfig};
use crate::iface::{L2Device, L2Handler, L3Device, L3Handler};
use crate::namespace::{Cleanup, L2Connector, L3Connector};
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
pub struct AdapterConfig {
    /// rustls server config (cert + key).
    pub tls_config: Arc<rustls::ServerConfig>,
    /// Listen address (UDP + TCP).
    pub listen_addr: SocketAddr,
    /// Connector wiring per-peer devices to the network.
    pub connector: Connector,
    /// Auth hook returning the per-peer IP config.
    pub on_auth: OnAuth,
}

impl std::fmt::Debug for AdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterConfig")
            .field("listen_addr", &self.listen_addr)
            .field("connector", &self.connector)
            .finish()
    }
}

struct OvpnPeer {
    l3: Option<Arc<PeerL3Device>>,
    l2: Option<Arc<PeerL2Device>>,
    cleanup: Mutex<Option<Cleanup>>,
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

        let server_cfg = ServerConfig {
            tls_config: cfg.tls_config,
            listen_addr: cfg.listen_addr,
            on_auth: cfg.on_auth,
            on_data: {
                let a = adapter.me.clone();
                Arc::new(move |key, layer, payload| {
                    if let Some(a) = a.upgrade() {
                        a.deliver(key, layer, payload);
                    }
                })
            },
            on_connect: Some({
                let a = adapter.me.clone();
                Arc::new(move |key, cfg| {
                    if let Some(a) = a.upgrade() {
                        a.on_connect(key, cfg);
                    }
                })
            }),
            on_disconnect: Some({
                let a = adapter.me.clone();
                Arc::new(move |key| {
                    if let Some(a) = a.upgrade() {
                        a.on_disconnect(key);
                    }
                })
            }),
        };

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
        if let Some(s) = self.server.lock().unwrap().take() {
            s.close();
        }
        let mut peers = self.peers.lock().unwrap();
        for (_, p) in peers.drain() {
            if let Some(c) = p.cleanup.lock().unwrap().take() {
                let _ = c();
            }
        }
    }

    fn server(&self) -> Option<Arc<Server>> {
        self.server.lock().unwrap().clone()
    }

    fn on_connect(&self, key: PeerKey, cfg: &PeerConfig) {
        // Avoid double-setup if we already wired this peer.
        if self.peers.lock().unwrap().contains_key(&key) {
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
                self.peers.lock().unwrap().insert(
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
                self.peers.lock().unwrap().insert(
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
        if let Some(p) = self.peers.lock().unwrap().remove(&key) {
            if let Some(c) = p.cleanup.lock().unwrap().take() {
                let _ = c();
            }
        }
    }

    /// Deliver a decrypted payload from the peer into its device handler.
    fn deliver(&self, key: PeerKey, _layer: u8, payload: &[u8]) {
        let peers = self.peers.lock().unwrap();
        if let Some(p) = peers.get(&key) {
            if let Some(dev) = &p.l3 {
                dev.deliver(payload);
            } else if let Some(dev) = &p.l2 {
                dev.deliver(payload);
            }
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
}

impl PeerL3Device {
    fn new(adapter: &Weak<Adapter>, key: PeerKey, addr: IpPrefix) -> Arc<Self> {
        Arc::new(PeerL3Device {
            adapter: adapter.clone(),
            key,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
        })
    }

    fn deliver(&self, data: &[u8]) {
        if let Some(h) = self.handler.lock().unwrap().clone() {
            let _ = h(crate::Packet::from_slice(data));
        }
    }
}

impl L3Device for PeerL3Device {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }

    fn send(&self, packet: &crate::Packet) -> Result<()> {
        let Some(adapter) = self.adapter.upgrade() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "adapter dropped"));
        };
        let Some(server) = adapter.server() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "server stopped"));
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

    fn deliver(&self, data: &[u8]) {
        if let Some(h) = self.handler.lock().unwrap().clone() {
            let _ = h(crate::Frame::from_slice(data));
        }
    }
}

impl L2Device for PeerL2Device {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }

    fn send(&self, frame: &crate::Frame) -> Result<()> {
        let Some(adapter) = self.adapter.upgrade() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "adapter dropped"));
        };
        let Some(server) = adapter.server() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "server stopped"));
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

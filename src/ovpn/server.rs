//! OpenVPN server: accepts peers over UDP and TCP.
//!
//! Ported from the Go `server.go` / `server-udp.go` / `server-tcp.go`. The
//! server owns the listening sockets and a map of active peers keyed by
//! transport+address. Each inbound datagram is routed to its peer's state
//! machine ([`Peer::handle_packet`]); the resulting outbound datagrams are
//! written back on the same socket, and any decrypted data-channel payload is
//! handed to the configured callbacks.
//!
//! Concurrency follows the crate conventions: one reader thread for UDP and one
//! acceptor thread for TCP (plus a thread per TCP connection). Peers live in
//! `Arc<Mutex<Peer>>` so the reader threads and the adapter's send path can
//! both reach them.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, RwLock};
use std::thread::{self, JoinHandle};

use super::addr::{PeerKey, Transport};
use super::peer::{OnAuth, Peer, PeerConfig};

/// Callback fired for each decrypted data-channel payload. Receives the peer
/// key, the peer's layer (2=tap, 3=tun), and the payload bytes.
pub type OnData = Arc<dyn Fn(PeerKey, u8, &[u8]) + Send + Sync>;

/// Callback fired once a peer completes authentication, with its pushed config.
pub type OnConnect = Arc<dyn Fn(PeerKey, &PeerConfig) + Send + Sync>;

/// Callback fired when a peer disconnects / is reaped.
pub type OnDisconnect = Arc<dyn Fn(PeerKey) + Send + Sync>;

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// rustls server configuration (must carry a certificate + key).
    pub tls_config: Arc<rustls::ServerConfig>,
    /// Address to listen on (both UDP and TCP), e.g. `0.0.0.0:1194`.
    pub listen_addr: SocketAddr,
    /// Authentication hook.
    pub on_auth: OnAuth,
    /// Decrypted-payload sink.
    pub on_data: OnData,
    /// Optional connect notification.
    pub on_connect: Option<OnConnect>,
    /// Optional disconnect notification.
    pub on_disconnect: Option<OnDisconnect>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen_addr", &self.listen_addr)
            .finish()
    }
}

static PROVIDER_INIT: Once = Once::new();

/// Install the ring crypto provider for rustls exactly once. Safe to call from
/// anywhere; subsequent calls are no-ops.
pub fn install_crypto_provider() {
    PROVIDER_INIT.call_once(|| {
        // Ignore the error: if a provider is already installed, that's fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct PeerEntry {
    peer: Mutex<Peer>,
    transport: Transport,
    addr: SocketAddr,
    // For TCP peers, the write half (length-prefixed). For UDP, None (the
    // server writes via the shared UDP socket).
    tcp: Option<Mutex<TcpStream>>,
}

/// An OpenVPN server.
pub struct Server {
    cfg: ServerConfig,
    udp: Arc<UdpSocket>,
    peers: RwLock<HashMap<PeerKey, Arc<PeerEntry>>>,
    closed: Arc<AtomicBool>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("listen_addr", &self.cfg.listen_addr)
            .finish()
    }
}

impl Server {
    /// Bind the UDP and TCP listeners and start the accept/read loops.
    pub fn new(cfg: ServerConfig) -> io::Result<Arc<Server>> {
        install_crypto_provider();

        let udp = Arc::new(UdpSocket::bind(cfg.listen_addr)?);
        let tcp = TcpListener::bind(cfg.listen_addr)?;

        let server = Arc::new(Server {
            cfg,
            udp,
            peers: RwLock::new(HashMap::new()),
            closed: Arc::new(AtomicBool::new(false)),
            threads: Mutex::new(Vec::new()),
        });

        let mut threads = server.threads.lock().unwrap();

        // UDP reader.
        {
            let s = server.clone();
            threads.push(thread::spawn(move || s.udp_loop()));
        }
        // TCP acceptor.
        {
            let s = server.clone();
            threads.push(thread::spawn(move || s.tcp_loop(tcp)));
        }
        drop(threads);

        Ok(server)
    }

    /// Local UDP address the server is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// Shut the server down: stop the loops and drop all peers.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Closing the UDP socket isn't directly possible; instead we rely on
        // the closed flag and let the read loop exit on its next error/timeout.
        // Set a short read timeout so the loop notices.
        let _ = self.udp.set_read_timeout(Some(std::time::Duration::from_millis(100)));

        let mut peers = self.peers.write().unwrap();
        for (k, _) in peers.drain() {
            if let Some(cb) = &self.cfg.on_disconnect {
                cb(k);
            }
        }
    }

    fn udp_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let (n, src) = match self.udp.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    continue;
                }
                Err(_) => return,
            };
            let key = PeerKey::new(src, Transport::Udp);
            let entry = self.get_or_create_peer(key, Transport::Udp, src, None);
            self.dispatch(&entry, &buf[..n]);
        }
    }

    fn tcp_loop(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming() {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let stream = match stream {
                Ok(s) => s,
                Err(_) => return,
            };
            let peer_addr = match stream.peer_addr() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let _ = stream.set_nodelay(true);
            let s = self.clone();
            thread::spawn(move || s.tcp_conn(stream, peer_addr));
        }
    }

    fn tcp_conn(self: Arc<Self>, stream: TcpStream, peer_addr: SocketAddr) {
        let key = PeerKey::new(peer_addr, Transport::Tcp);
        let write_half = match stream.try_clone() {
            Ok(w) => w,
            Err(_) => return,
        };
        let entry = self.get_or_create_peer(key, Transport::Tcp, peer_addr, Some(write_half));

        let mut reader = io::BufReader::new(stream);
        loop {
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
            let mut len_buf = [0u8; 2];
            if reader.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; len];
            if reader.read_exact(&mut data).is_err() {
                break;
            }
            self.dispatch(&entry, &data);
        }

        // Connection closed: drop the peer.
        self.remove_peer(key);
    }

    fn get_or_create_peer(
        &self,
        key: PeerKey,
        transport: Transport,
        addr: SocketAddr,
        tcp: Option<TcpStream>,
    ) -> Arc<PeerEntry> {
        if let Some(e) = self.peers.read().unwrap().get(&key) {
            return e.clone();
        }
        let mut peers = self.peers.write().unwrap();
        if let Some(e) = peers.get(&key) {
            return e.clone();
        }
        let mut local_id = [0u8; 8];
        let _ = super::peer::fill_random(&mut local_id);
        let peer = Peer::new(self.cfg.tls_config.clone(), local_id, self.cfg.on_auth.clone())
            .expect("peer creation");
        let entry = Arc::new(PeerEntry {
            peer: Mutex::new(peer),
            transport,
            addr,
            tcp: tcp.map(Mutex::new),
        });
        peers.insert(key, entry.clone());
        entry
    }

    fn remove_peer(&self, key: PeerKey) {
        let removed = self.peers.write().unwrap().remove(&key).is_some();
        if removed {
            if let Some(cb) = &self.cfg.on_disconnect {
                cb(key);
            }
        }
    }

    /// Run one inbound datagram through the peer and act on the output.
    fn dispatch(&self, entry: &Arc<PeerEntry>, data: &[u8]) {
        let key = PeerKey::new(entry.addr, entry.transport);
        let out = {
            let mut peer = entry.peer.lock().unwrap();
            match peer.handle_packet(data) {
                Ok(o) => o,
                Err(_) => {
                    drop(peer);
                    self.remove_peer(key);
                    return;
                }
            }
        };

        for dgram in &out.send {
            let _ = self.send_raw(entry, dgram);
        }

        if out.authenticated {
            if let Some(cb) = &self.cfg.on_connect {
                let peer = entry.peer.lock().unwrap();
                if let Some(cfg) = peer.peer_config() {
                    cb(key, cfg);
                }
            }
        }

        if let Some(payload) = out.deliver {
            let layer = entry.peer.lock().unwrap().layer();
            (self.cfg.on_data)(key, layer, &payload);
        }

        if out.close {
            self.remove_peer(key);
        }
    }

    /// Encrypt and send a data-channel payload to a peer identified by `key`.
    pub fn send_to_peer(&self, key: &PeerKey, payload: &[u8]) -> io::Result<()> {
        let entry = self
            .peers
            .read()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "unknown peer"))?;
        let dgram = entry.peer.lock().unwrap().send_data(payload)?;
        self.send_raw(&entry, &dgram)
    }

    /// Write a raw datagram to the peer's transport.
    fn send_raw(&self, entry: &Arc<PeerEntry>, dgram: &[u8]) -> io::Result<()> {
        match entry.transport {
            Transport::Udp => {
                self.udp.send_to(dgram, entry.addr)?;
                Ok(())
            }
            Transport::Tcp => {
                if let Some(w) = &entry.tcp {
                    let mut w = w.lock().unwrap();
                    let len = (dgram.len() as u16).to_be_bytes();
                    w.write_all(&len)?;
                    w.write_all(dgram)?;
                    Ok(())
                } else {
                    Err(io::Error::new(io::ErrorKind::NotConnected, "no tcp stream"))
                }
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

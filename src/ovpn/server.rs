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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::addr::{PeerKey, Transport};
use super::peer::{OnAuth, Peer, PeerConfig, PeerTimers};

/// Callback fired for each decrypted data-channel payload. Receives the peer
/// key, the peer's layer (2=tap, 3=tun), and the payload bytes.
pub type OnData = Arc<dyn Fn(PeerKey, u8, &[u8]) + Send + Sync>;

/// Callback fired once a peer completes authentication, with its pushed config.
/// A client that reconnects from the same address is reported as a
/// disconnect followed by a new connect.
pub type OnConnect = Arc<dyn Fn(PeerKey, &PeerConfig) + Send + Sync>;

/// Callback fired when a peer disconnects / is reaped.
pub type OnDisconnect = Arc<dyn Fn(PeerKey) + Send + Sync>;

/// Server configuration.
#[derive(Clone)]
#[non_exhaustive]
pub struct ServerConfig {
    /// TLS configuration for the control channel.
    ///
    /// Must carry an identity (certificate chain + signing key) and an entropy
    /// source, since this is the server side and the TLS core is sans-I/O:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use purecrypto::tls::{Config, ProtocolVersion, SigningKey};
    /// # fn build(chain: Vec<Vec<u8>>, key: SigningKey) -> Config {
    /// Config::builder()
    ///     .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_2)
    ///     .rng(Arc::new(purecrypto::rng::OsRng))
    ///     .identity(chain, key)
    ///     .build()
    /// # }
    /// ```
    pub tls_config: Arc<purecrypto::tls::Config>,
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
    /// Most peers (UDP and TCP together) held at once; a client hard reset
    /// beyond it is dropped. Default 1024.
    pub max_peers: usize,
    /// Most TCP connections served at once; each has a thread. Default 256.
    pub max_tcp_connections: usize,
    /// How long a client has to complete the TLS handshake and key
    /// exchange (OpenVPN's `hand-window`). Default 60s.
    pub handshake_window: Duration,
    /// Keepalive ping interval (first argument of OpenVPN's `--keepalive`):
    /// pushed to clients as `ping`, and the server pings an idle client this
    /// often. Zero disables. Default 10s.
    pub keepalive_interval: Duration,
    /// Keepalive timeout (second argument of `--keepalive`): pushed to
    /// clients as `ping-restart`; the server drops a client it has not heard
    /// from for twice this, as OpenVPN's server does. Zero disables.
    /// Default 60s.
    pub keepalive_timeout: Duration,
}

setters! {
    ServerConfig {
        some on_connect: OnConnect;
        some on_disconnect: OnDisconnect;
        set max_peers: usize;
        set max_tcp_connections: usize;
        set handshake_window: Duration;
        set keepalive_interval: Duration;
        set keepalive_timeout: Duration;
    }
}

impl ServerConfig {
    /// A server with no connect/disconnect hooks.
    pub fn new(
        tls_config: Arc<purecrypto::tls::Config>,
        listen_addr: SocketAddr,
        on_auth: OnAuth,
        on_data: OnData,
    ) -> ServerConfig {
        let timers = PeerTimers::default();
        ServerConfig {
            tls_config,
            listen_addr,
            on_auth,
            on_data,
            on_connect: None,
            on_disconnect: None,
            max_peers: 1024,
            max_tcp_connections: 256,
            handshake_window: timers.handshake_window,
            keepalive_interval: timers.keepalive_interval,
            keepalive_timeout: timers.keepalive_timeout,
        }
    }

    fn timers(&self) -> PeerTimers {
        PeerTimers {
            handshake_window: self.handshake_window,
            keepalive_interval: self.keepalive_interval,
            keepalive_timeout: self.keepalive_timeout,
        }
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen_addr", &self.listen_addr)
            .finish()
    }
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
    tcp_addr: SocketAddr,
    peers: RwLock<HashMap<PeerKey, Arc<PeerEntry>>>,
    /// TCP connections currently being served.
    tcp_conns: AtomicUsize,
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
        let udp = Arc::new(UdpSocket::bind(cfg.listen_addr)?);
        let tcp = TcpListener::bind(cfg.listen_addr)?;
        let tcp_addr = tcp.local_addr()?;

        let server = Arc::new(Server {
            cfg,
            udp,
            tcp_addr,
            peers: RwLock::new(HashMap::new()),
            tcp_conns: AtomicUsize::new(0),
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
        // Maintenance loop: drives control-channel retransmission timers.
        {
            let s = server.clone();
            threads.push(thread::spawn(move || s.maintenance_loop()));
        }
        drop(threads);

        Ok(server)
    }

    /// Local UDP address the server is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// Local TCP address the server listens on. The same as
    /// [`local_addr`](Self::local_addr) unless the configured port was 0, in
    /// which case each transport got its own ephemeral port.
    pub fn tcp_local_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// Shut the server down: stop the loops and drop all peers.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Closing the UDP socket isn't directly possible; instead we rely on
        // the closed flag and let the read loop exit on its next error/timeout.
        // Set a short read timeout so the loop notices.
        let _ = self
            .udp
            .set_read_timeout(Some(std::time::Duration::from_millis(100)));

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
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => return,
            };
            let data = &buf[..n];
            let key = PeerKey::new(src, Transport::Udp);
            let entry = match self.get_peer(&key) {
                Some(e) => e,
                // Only a client hard reset may allocate state for a new
                // address; anything else from a stranger is dropped.
                None if Peer::is_session_start(data) => {
                    match self.create_peer(key, Transport::Udp, src, None) {
                        Some(e) => e,
                        None => continue,
                    }
                }
                None => continue,
            };
            self.dispatch(&entry, data);
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
            // Each connection costs a thread: refuse (close) past the cap.
            if self.tcp_conns.fetch_add(1, Ordering::SeqCst) >= self.cfg.max_tcp_connections {
                self.tcp_conns.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let _ = stream.set_nodelay(true);
            let s = self.clone();
            thread::spawn(move || {
                s.tcp_conn(stream, peer_addr);
                s.tcp_conns.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    fn tcp_conn(&self, stream: TcpStream, peer_addr: SocketAddr) {
        let key = PeerKey::new(peer_addr, Transport::Tcp);
        let write_half = match stream.try_clone() {
            Ok(w) => w,
            Err(_) => return,
        };
        // The client must open with a hard reset within the handshake
        // window; after that, it pings at least every keepalive interval, so
        // a read blocked past the ping-restart timeout means it is gone.
        let timers = self.cfg.timers();
        let _ = stream.set_read_timeout(Some(timers.handshake_window));
        let mut reader = io::BufReader::new(stream);
        let Some(first) = read_frame(&mut reader) else {
            return;
        };
        if !Peer::is_session_start(&first) {
            return;
        }
        let Some(entry) = self.create_peer(key, Transport::Tcp, peer_addr, Some(write_half)) else {
            return;
        };
        let idle = (timers.keepalive_timeout * 2).max(timers.handshake_window);
        let _ = reader.get_ref().set_read_timeout(Some(idle));

        self.dispatch(&entry, &first);
        while !self.closed.load(Ordering::SeqCst) {
            let Some(data) = read_frame(&mut reader) else {
                break;
            };
            self.dispatch(&entry, &data);
        }

        // Connection closed: drop the peer.
        self.remove_entry(&entry);
    }

    /// Periodically drive each peer's control-channel retransmission timers.
    ///
    /// OpenVPN's reliable layer re-sends unacknowledged `P_CONTROL` packets on
    /// a per-packet timer. The peer state machine is caller-driven
    /// ([`Peer::tick`]), so this loop ticks every live peer on a fixed cadence
    /// and ships whatever datagrams the tick produces. A peer whose retries are
    /// exhausted (`PeerOutput::close`) is reaped.
    fn maintenance_loop(self: Arc<Self>) {
        // Tick at the base retransmit interval; finer granularity buys nothing
        // since deadlines are at least RETRANSMIT_INITIAL apart.
        let interval = super::reliable::RETRANSMIT_INITIAL;
        loop {
            thread::sleep(interval);
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let now = crate::time::Instant::now();
            // Snapshot the entries so we don't hold the peers lock while
            // ticking (which takes each peer's own lock and may send).
            let entries: Vec<Arc<PeerEntry>> =
                self.peers.read().unwrap().values().cloned().collect();
            for entry in entries {
                let out = entry.peer.lock().unwrap().tick(now);
                let Ok(out) = out else {
                    self.remove_entry(&entry);
                    continue;
                };
                for dgram in &out.send {
                    let _ = self.send_raw(&entry, dgram);
                }
                if out.close {
                    self.remove_entry(&entry);
                }
            }
        }
    }

    fn get_peer(&self, key: &PeerKey) -> Option<Arc<PeerEntry>> {
        self.peers.read().unwrap().get(key).cloned()
    }

    /// Add a peer for `key`, or return the one already there. `None` when
    /// the peer table is full.
    fn create_peer(
        &self,
        key: PeerKey,
        transport: Transport,
        addr: SocketAddr,
        tcp: Option<TcpStream>,
    ) -> Option<Arc<PeerEntry>> {
        let mut peers = self.peers.write().unwrap();
        if let Some(e) = peers.get(&key) {
            return Some(e.clone());
        }
        if peers.len() >= self.cfg.max_peers {
            return None;
        }
        let mut local_id = [0u8; 8];
        let _ = super::peer::fill_random(&mut local_id);
        let peer = Peer::new(
            self.cfg.tls_config.clone(),
            local_id,
            self.cfg.on_auth.clone(),
        )
        .expect("peer creation")
        .with_timers(self.cfg.timers());
        let entry = Arc::new(PeerEntry {
            peer: Mutex::new(peer),
            transport,
            addr,
            tcp: tcp.map(Mutex::new),
        });
        peers.insert(key, entry.clone());
        Some(entry)
    }

    /// Drop `entry` from the peer table -- only if it is still the entry
    /// for its key, as a caller may hold a stale one -- and close its TCP
    /// connection, which ends the thread serving it.
    fn remove_entry(&self, entry: &Arc<PeerEntry>) {
        let key = PeerKey::new(entry.addr, entry.transport);
        let removed = {
            let mut peers = self.peers.write().unwrap();
            let current = peers.get(&key).is_some_and(|e| Arc::ptr_eq(e, entry));
            current && peers.remove(&key).is_some()
        };
        if !removed {
            return;
        }
        if let Some(w) = &entry.tcp {
            let _ = w.lock().unwrap().shutdown(std::net::Shutdown::Both);
        }
        if let Some(cb) = &self.cfg.on_disconnect {
            cb(key);
        }
    }

    /// Run one inbound datagram through the peer and act on the output.
    fn dispatch(&self, entry: &Arc<PeerEntry>, data: &[u8]) {
        let key = PeerKey::new(entry.addr, entry.transport);
        let out = {
            let mut peer = entry.peer.lock().unwrap();
            match peer.handle_packet(data) {
                Ok(o) => o,
                // A dropped datagram; only `out.close` ends the session.
                Err(_) => return,
            }
        };

        for dgram in &out.send {
            let _ = self.send_raw(entry, dgram);
        }

        // Callbacks run without the peer's lock held: they may well call
        // back into the server for this peer (send_to_peer, say).
        if let Some(cfg) = &out.connected {
            if out.replaced
                && let Some(cb) = &self.cfg.on_disconnect
            {
                cb(key);
            }
            if let Some(cb) = &self.cfg.on_connect {
                cb(key, cfg);
            }
        }

        if let Some(payload) = out.deliver {
            let layer = entry.peer.lock().unwrap().layer();
            (self.cfg.on_data)(key, layer, &payload);
        }

        if out.close {
            self.remove_entry(entry);
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

/// Read one length-prefixed OpenVPN-over-TCP frame. `None` on EOF, error or
/// timeout, all of which end the connection.
fn read_frame(reader: &mut impl Read) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).ok()?;
    let mut data = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    reader.read_exact(&mut data).ok()?;
    Some(data)
}

impl Drop for Server {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ovpn::Opcode;
    use crate::ovpn::keys::PeerKeys;
    use crate::ovpn::packet_ctrl::ControlPacket;
    use crate::ovpn::tests::{TestClient, connect_via};
    use std::time::Duration;

    fn test_server() -> Arc<Server> {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        );
        Server::new(cfg).unwrap()
    }

    fn udp_client(server: &Server) -> UdpSocket {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect(server.local_addr().unwrap()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s
    }

    fn client_reset(sid: [u8; 8]) -> Vec<u8> {
        let mut p = ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, sid, [0; 8]);
        p.set_pid(0);
        p.to_bytes(&[])
    }

    fn recv_ctrl(s: &UdpSocket) -> ControlPacket {
        let mut buf = [0u8; 2048];
        let n = s.recv(&mut buf).expect("server reply");
        ControlPacket::parse(&buf[..n]).unwrap()
    }

    /// Junk from a peer's address -- a truncated control packet, a data
    /// packet before any key exists, a control packet far outside the
    /// receive window, an unknown opcode -- is dropped. It must not tear
    /// down the peer's session, or anyone able to send one datagram could
    /// disconnect any client.
    #[test]
    fn junk_datagrams_do_not_tear_down_a_peer() {
        let server = test_server();
        let c = udp_client(&server);
        let sid = *b"CLIENT01";
        c.send(&client_reset(sid)).unwrap();
        let first = recv_ctrl(&c);
        assert_eq!(first.opcode, Opcode::CONTROL_HARD_RESET_SERVER_V2);
        let server_sid = first.session_id;

        let mut far = ControlPacket::new(Opcode::CONTROL_V1, 0, sid, [0; 8]);
        far.set_pid(1000);
        let junk: Vec<Vec<u8>> = vec![
            vec![Opcode::CONTROL_V1.to_byte(0), 1, 2],
            vec![Opcode::DATA_V1.to_byte(0), 0, 0, 0, 1, 2, 3],
            far.to_bytes(&[]),
            vec![0xff; 13],
        ];
        for j in &junk {
            c.send(j).unwrap();
        }
        // A repeated hard reset is answered by the session that owns it; a
        // fresh peer would answer with a different server session id.
        c.send(&client_reset(sid)).unwrap();
        loop {
            let p = recv_ctrl(&c);
            assert_eq!(p.session_id, server_sid, "peer was torn down by junk");
            if p.acked_pids.contains(&0) {
                break;
            }
        }
        server.close();
    }

    /// Only a client hard reset opens a peer: anything else from an unknown
    /// address -- an ACK, a data packet, an unknown opcode, a control packet
    /// -- is dropped without allocating state.
    #[test]
    fn only_a_hard_reset_creates_a_peer() {
        let server = test_server();
        let stranger = udp_client(&server);
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, *b"STRANGER", [0; 8]);
        let mut ctl = ControlPacket::new(Opcode::CONTROL_V1, 0, *b"STRANGER", [0; 8]);
        ctl.set_pid(0);
        let mut late_reset = ControlPacket::new(
            Opcode::CONTROL_HARD_RESET_CLIENT_V2,
            0,
            *b"STRANGER",
            [0; 8],
        );
        late_reset.set_pid(5);
        for d in [
            ack.to_bytes(&[1]),
            ctl.to_bytes(&[]),
            late_reset.to_bytes(&[]),
            vec![Opcode::DATA_V1.to_byte(0); 40],
            vec![0x00; 20],
            vec![Opcode(10).to_byte(0); 20],
        ] {
            stranger.send(&d).unwrap();
        }
        // Sync on a real client being answered: the datagrams above were
        // read before its reset.
        let c = udp_client(&server);
        c.send(&client_reset(*b"CLIENT01")).unwrap();
        recv_ctrl(&c);
        assert_eq!(server.peers.read().unwrap().len(), 1);
        server.close();
    }

    fn tcp_client(server: &Server) -> TcpStream {
        let s = TcpStream::connect(server.tcp_local_addr()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s
    }

    fn tcp_send(s: &mut TcpStream, dgram: &[u8]) {
        s.write_all(&(dgram.len() as u16).to_be_bytes()).unwrap();
        s.write_all(dgram).unwrap();
    }

    fn tcp_recv(s: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 2];
        s.read_exact(&mut len)?;
        let mut d = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut d)?;
        Ok(d)
    }

    /// A TCP connection has to open with a hard reset; anything else closes
    /// it without a peer being created.
    #[test]
    fn tcp_connection_must_open_with_a_hard_reset() {
        let server = test_server();
        let mut c = tcp_client(&server);
        tcp_send(&mut c, &[Opcode::ACK_V1.to_byte(0); 20]);
        let mut b = [0u8; 1];
        assert_eq!(c.read(&mut b).unwrap(), 0, "server should close");
        assert_eq!(server.peers.read().unwrap().len(), 0);
        server.close();
    }

    /// When the server drops a TCP peer (here: its handshake window runs
    /// out), it closes the connection instead of leaving a thread serving a
    /// peer that no longer exists.
    #[test]
    fn removing_a_tcp_peer_closes_its_connection() {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .handshake_window(Duration::from_millis(500));
        let server = Server::new(cfg).unwrap();
        let mut c = tcp_client(&server);
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp_send(&mut c, &client_reset(*b"CLIENT01"));
        loop {
            match tcp_recv(&mut c) {
                Ok(_) => continue, // the reset and its retransmissions
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                Err(e) => panic!("connection was left open: {e}"),
            }
        }
        assert_eq!(server.peers.read().unwrap().len(), 0);
        server.close();
    }

    #[test]
    fn tcp_connections_are_capped() {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .max_tcp_connections(1);
        let server = Server::new(cfg).unwrap();
        let mut first = tcp_client(&server);
        tcp_send(&mut first, &client_reset(*b"CLIENT01"));
        tcp_recv(&mut first).expect("first connection is served");

        let mut second = tcp_client(&server);
        let mut b = [0u8; 1];
        match second.read(&mut b) {
            Ok(0) => {}
            Err(e)
                if !matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            other => panic!("second connection must be refused, got {other:?}"),
        }
        server.close();
    }

    /// Connect a test client to `server` over UDP from `sock`.
    fn connect_udp(sock: &UdpSocket, client: &mut TestClient) -> (PeerKeys, Vec<Vec<u8>>) {
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let s2 = sock.try_clone().unwrap();
        let r = connect_via(
            client,
            &mut |d| {
                sock.send(d).unwrap();
            },
            &mut || {
                let mut buf = [0u8; 4096];
                s2.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
            },
        );
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        r
    }

    /// Pump `client` until `done` holds or the server goes quiet, returning
    /// the data-channel packets that arrived meanwhile.
    fn pump_udp(
        sock: &UdpSocket,
        client: &mut TestClient,
        done: impl Fn(&TestClient) -> bool,
    ) -> Vec<Vec<u8>> {
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut buf = [0u8; 4096];
        let mut data = Vec::new();
        while !done(client) {
            let Ok(n) = sock.recv(&mut buf) else {
                break;
            };
            if Opcode::from_byte(buf[0]).0 == Opcode::DATA_V1 {
                data.push(buf[..n].to_vec());
                continue;
            }
            for d in client.handle_any(&buf[..n]) {
                sock.send(&d).unwrap();
            }
        }
        data
    }

    /// on_connect fires once per session, and outside the peer's lock: a
    /// callback that sends to the peer straight away must not deadlock.
    #[test]
    fn on_connect_fires_once_and_may_send() {
        let server_slot: Arc<Mutex<Option<std::sync::Weak<Server>>>> = Arc::default();
        let connects = Arc::new(AtomicUsize::new(0));
        let on_auth: OnAuth = Arc::new(|_| {
            Ok(PeerConfig::new(
                "10.8.0.2".parse().unwrap(),
                "10.8.0.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                24,
            ))
        });
        let on_data: OnData = Arc::new(|_, _, _| {});
        let on_connect: OnConnect = {
            let slot = server_slot.clone();
            let connects = connects.clone();
            Arc::new(move |key, _cfg| {
                connects.fetch_add(1, Ordering::SeqCst);
                let server = slot.lock().unwrap().as_ref().and_then(|w| w.upgrade());
                if let Some(s) = server {
                    s.send_to_peer(&key, b"welcome").unwrap();
                }
            })
        };
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .on_connect(on_connect);
        let server = Server::new(cfg).unwrap();
        *server_slot.lock().unwrap() = Some(Arc::downgrade(&server));

        let sock = udp_client(&server);
        let mut client = TestClient::new(*b"CLIENTID");
        let (keys, mut data) = connect_udp(&sock, &mut client);

        // The client asks for its config; more control traffic after the
        // session is up must not count as another connect.
        for d in client.send_control(b"PUSH_REQUEST\0") {
            sock.send(&d).unwrap();
        }
        data.extend(pump_udp(&sock, &mut client, |c| {
            c.control_text().windows(10).any(|w| w == b"PUSH_REPLY")
        }));
        assert_eq!(connects.load(Ordering::SeqCst), 1);

        // The callback's packet arrives.
        if data.is_empty() {
            let mut buf = [0u8; 4096];
            let n = sock.recv(&mut buf).expect("welcome packet");
            data.push(buf[..n].to_vec());
        }
        let mut pkt = data.remove(0);
        let dec = crate::ovpn::data::decrypt(&crate::ovpn::tests::gcm_opts(), &keys, &mut pkt)
            .unwrap()
            .unwrap();
        assert_eq!(dec.payload, b"welcome");
        server.close();
    }

    #[test]
    fn peer_table_is_capped() {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .max_peers(2);
        let server = Server::new(cfg).unwrap();
        let clients: Vec<UdpSocket> = (0..3).map(|_| udp_client(&server)).collect();
        for (i, c) in clients.iter().take(2).enumerate() {
            c.send(&client_reset([b'A' + i as u8; 8])).unwrap();
            recv_ctrl(c);
        }
        let third = &clients[2];
        third
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        third.send(&client_reset(*b"CCCCCCCC")).unwrap();
        let mut buf = [0u8; 2048];
        assert!(third.recv(&mut buf).is_err(), "third peer must be refused");
        assert_eq!(server.peers.read().unwrap().len(), 2);
        server.close();
    }
}

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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread;
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

/// Callback fired when a peer disconnects / is reaped. It pairs with
/// [`OnConnect`]: a peer that never authenticated is dropped silently.
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
    /// Each peer's timers: handshake window, keepalive, renegotiation.
    /// Defaults to OpenVPN's (see [`PeerTimers`]).
    pub timers: PeerTimers,
}

/// Default [`ServerConfig::max_peers`].
pub(super) const DEFAULT_MAX_PEERS: usize = 1024;
/// Default [`ServerConfig::max_tcp_connections`].
pub(super) const DEFAULT_MAX_TCP_CONNECTIONS: usize = 256;

setters! {
    ServerConfig {
        some on_connect: OnConnect;
        some on_disconnect: OnDisconnect;
        set max_peers: usize;
        set max_tcp_connections: usize;
        set timers: PeerTimers;
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
        ServerConfig {
            tls_config,
            listen_addr,
            on_auth,
            on_data,
            on_connect: None,
            on_disconnect: None,
            max_peers: DEFAULT_MAX_PEERS,
            max_tcp_connections: DEFAULT_MAX_TCP_CONNECTIONS,
            timers: PeerTimers::default(),
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
    /// Whether on_connect was fired for the peer and not yet matched by an
    /// on_disconnect: the callbacks pair, so only such a peer is reported
    /// gone.
    connected: AtomicBool,
}

/// An OpenVPN server.
///
/// Its threads hold only a weak reference to it, so dropping the last
/// `Arc<Server>` shuts it down just as [`close`](Self::close) does.
pub struct Server {
    cfg: ServerConfig,
    udp: Arc<UdpSocket>,
    tcp_addr: SocketAddr,
    peers: RwLock<HashMap<PeerKey, Arc<PeerEntry>>>,
    /// Every open TCP connection by id, so close() can shut them down --
    /// including those that have not sent a hard reset yet.
    tcp_streams: Mutex<HashMap<u64, TcpStream>>,
    next_tcp_id: AtomicU64,
    closed: AtomicBool,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("listen_addr", &self.cfg.listen_addr)
            .finish()
    }
}

/// How often the socket threads look up from a blocking read or an idle
/// accept to notice that the server was closed or dropped.
const POLL: Duration = Duration::from_millis(100);

/// The server, if it still exists and is not closed.
fn live(server: &Weak<Server>) -> Option<Arc<Server>> {
    server
        .upgrade()
        .filter(|s| !s.closed.load(Ordering::SeqCst))
}

impl Server {
    /// Bind the UDP and TCP listeners and start the accept/read loops.
    ///
    /// Fails if a socket cannot be bound, or if `tls_config` cannot make a
    /// TLS server connection (no identity, say) -- found out now rather than
    /// when the first client arrives.
    pub fn new(cfg: ServerConfig) -> io::Result<Arc<Server>> {
        purecrypto::tls::Connection::server(&cfg.tls_config).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TLS config cannot make a server connection: {e:?}"),
            )
        })?;
        let udp = Arc::new(UdpSocket::bind(cfg.listen_addr)?);
        udp.set_read_timeout(Some(POLL))?;
        let tcp = TcpListener::bind(cfg.listen_addr)?;
        let tcp_addr = tcp.local_addr()?;
        // A blocking accept cannot be interrupted portably; poll instead.
        tcp.set_nonblocking(true)?;

        let server = Arc::new(Server {
            cfg,
            udp: udp.clone(),
            tcp_addr,
            peers: RwLock::new(HashMap::new()),
            tcp_streams: Mutex::new(HashMap::new()),
            next_tcp_id: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        });

        let weak = Arc::downgrade(&server);
        {
            let weak = weak.clone();
            thread::spawn(move || udp_loop(weak, udp));
        }
        {
            let weak = weak.clone();
            thread::spawn(move || tcp_loop(weak, tcp));
        }
        thread::spawn(move || maintenance_loop(weak));

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

    /// Shut the server down: stop the loops, close every TCP connection and
    /// the listener, and drop all peers. The threads exit within a short poll
    /// interval; the UDP port is released when the `Server` is dropped.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // A thread blocked reading a TCP connection wakes up to the shutdown
        // and exits; the socket loops notice `closed` on their next poll.
        for (_, s) in self.tcp_streams.lock().unwrap().drain() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        // Callbacks run after the table lock is released: they may call
        // back into the server.
        let peers: Vec<PeerKey> = self
            .peers
            .write()
            .unwrap()
            .drain()
            .filter(|(_, e)| e.connected.swap(false, Ordering::SeqCst))
            .map(|(k, _)| k)
            .collect();
        if let Some(cb) = &self.cfg.on_disconnect {
            for k in peers {
                cb(k);
            }
        }
    }

    fn handle_udp(&self, data: &[u8], src: SocketAddr) {
        let key = PeerKey::new(src, Transport::Udp);
        let entry = match self.get_peer(&key) {
            Some(e) => e,
            // Only a client hard reset may allocate state for a new
            // address; anything else from a stranger is dropped.
            None if Peer::is_session_start(data) => {
                match self.create_peer(key, Transport::Udp, src, None) {
                    Some(e) => e,
                    None => return,
                }
            }
            None => return,
        };
        self.dispatch(&entry, data);
    }

    fn accept_tcp(&self, weak: &Weak<Server>, stream: TcpStream, addr: SocketAddr) {
        // Some platforms hand out accepted sockets with the listener's
        // non-blocking flag; the connection thread wants blocking reads.
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        let Ok(handle) = stream.try_clone() else {
            return;
        };
        {
            // Each connection costs a thread: refuse (close) past the cap.
            let mut streams = self.tcp_streams.lock().unwrap();
            if streams.len() >= self.cfg.max_tcp_connections {
                return;
            }
            let id = self.next_tcp_id.fetch_add(1, Ordering::Relaxed);
            streams.insert(id, handle);
            let _ = stream.set_nodelay(true);
            let weak = weak.clone();
            thread::spawn(move || {
                tcp_conn(&weak, stream, addr);
                if let Some(s) = weak.upgrade() {
                    s.tcp_streams.lock().unwrap().remove(&id);
                }
            });
        }
    }

    fn tick_peers(&self) {
        let now = crate::time::Instant::now();
        // Snapshot the entries so we don't hold the peers lock while
        // ticking (which takes each peer's own lock and may send).
        let entries: Vec<Arc<PeerEntry>> = self.peers.read().unwrap().values().cloned().collect();
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
        // Server::new checked the TLS config, so this does not fail in
        // practice; if it does, the client is just not served.
        let peer = Peer::new(
            self.cfg.tls_config.clone(),
            local_id,
            self.cfg.on_auth.clone(),
        )
        .ok()?
        .with_timers(self.cfg.timers);
        let entry = Arc::new(PeerEntry {
            peer: Mutex::new(peer),
            transport,
            addr,
            tcp: tcp.map(Mutex::new),
            connected: AtomicBool::new(false),
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
        if entry.connected.swap(false, Ordering::SeqCst)
            && let Some(cb) = &self.cfg.on_disconnect
        {
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
            // A new session taking over from one that was reported
            // connected ends that connection first. The flag, not
            // `out.replaced`, decides: the old session may have failed on
            // its own before this one authenticated.
            if entry.connected.swap(true, Ordering::SeqCst)
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
                    // The frame length is 16 bits; a truncated one would
                    // desynchronise the stream for good.
                    let len = u16::try_from(dgram.len()).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "packet too large for a TCP frame",
                        )
                    })?;
                    let mut frame = Vec::with_capacity(2 + dgram.len());
                    frame.extend_from_slice(&len.to_be_bytes());
                    frame.extend_from_slice(dgram);
                    w.lock().unwrap().write_all(&frame)
                } else {
                    Err(io::Error::new(io::ErrorKind::NotConnected, "no tcp stream"))
                }
            }
        }
    }
}

fn udp_loop(server: Weak<Server>, udp: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let res = udp.recv_from(&mut buf);
        let Some(server) = live(&server) else {
            return;
        };
        match res {
            Ok((n, src)) => server.handle_udp(&buf[..n], src),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            // Not fatal: Windows, for one, reports an ICMP port unreachable
            // for an earlier send to any client as WSAECONNRESET here. Back
            // off in case the error persists.
            Err(_) => {
                drop(server);
                thread::sleep(POLL);
            }
        }
    }
}

fn tcp_loop(server: Weak<Server>, listener: TcpListener) {
    loop {
        let res = listener.accept();
        let Some(s) = live(&server) else {
            return;
        };
        match res {
            Ok((stream, addr)) => s.accept_tcp(&server, stream, addr),
            // Nothing pending, or a transient failure (a connection reset
            // before we accepted it, out of descriptors, ...): wait a little.
            Err(_) => {
                drop(s);
                thread::sleep(POLL);
            }
        }
    }
}

/// Serve one TCP connection. The server is only borrowed while handling a
/// frame, never while blocked reading.
fn tcp_conn(server: &Weak<Server>, stream: TcpStream, addr: SocketAddr) {
    let Some(s) = live(server) else {
        return;
    };
    let key = PeerKey::new(addr, Transport::Tcp);
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    // The client must open with a hard reset within the handshake window;
    // after that, it pings at least every keepalive interval, so a read
    // blocked past the ping-restart timeout means it is gone.
    let timers = s.cfg.timers;
    drop(s);
    let _ = stream.set_read_timeout(Some(timers.handshake_window));
    let mut reader = io::BufReader::new(stream);
    let Some(first) = read_frame(&mut reader) else {
        return;
    };
    if !Peer::is_session_start(&first) {
        return;
    }
    let Some(s) = live(server) else {
        return;
    };
    let Some(entry) = s.create_peer(key, Transport::Tcp, addr, Some(write_half)) else {
        return;
    };
    s.dispatch(&entry, &first);
    drop(s);
    let idle = (timers.keepalive_timeout * 2).max(timers.handshake_window);
    let _ = reader.get_ref().set_read_timeout(Some(idle));

    while let Some(data) = read_frame(&mut reader) {
        let Some(s) = live(server) else {
            break;
        };
        s.dispatch(&entry, &data);
    }

    // Connection closed: drop the peer.
    if let Some(s) = server.upgrade() {
        s.remove_entry(&entry);
    }
}

/// Periodically drive each peer's timers ([`Peer::tick`]): control-channel
/// retransmission, handshake window, keepalive. Ticking at the base
/// retransmit interval is enough, since deadlines are at least that far
/// apart.
fn maintenance_loop(server: Weak<Server>) {
    loop {
        thread::sleep(super::reliable::RETRANSMIT_INITIAL);
        let Some(s) = live(&server) else {
            return;
        };
        s.tick_peers();
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
        self.close();
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
        .timers(PeerTimers::default().handshake_window(Duration::from_millis(500)));
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

    fn expect_eof(c: &mut TcpStream) {
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        loop {
            match tcp_recv(c) {
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return,
                Err(e) => panic!("connection was left open: {e}"),
            }
        }
    }

    /// close() ends everything: established TCP connections, connections
    /// still opening, and the listener.
    #[test]
    fn close_shuts_tcp_down() {
        let server = test_server();
        let mut peer = tcp_client(&server);
        tcp_send(&mut peer, &client_reset(*b"CLIENT01"));
        tcp_recv(&mut peer).unwrap();
        let mut silent = tcp_client(&server);
        // Let the acceptor pick the silent connection up.
        std::thread::sleep(Duration::from_millis(100));

        server.close();
        expect_eof(&mut peer);
        expect_eof(&mut silent);
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(mut late) = TcpStream::connect(server.tcp_local_addr()) {
            expect_eof(&mut late);
        }
    }

    /// The server's threads must not keep it alive: dropping the last
    /// handle stops it.
    #[test]
    fn dropping_the_server_stops_it() {
        let server = test_server();
        let mut peer = tcp_client(&server);
        tcp_send(&mut peer, &client_reset(*b"CLIENT01"));
        tcp_recv(&mut peer).unwrap();
        let weak = Arc::downgrade(&server);
        drop(server);
        expect_eof(&mut peer);
        for _ in 0..30 {
            if weak.upgrade().is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("server threads kept the server alive");
    }

    /// OpenVPN over TCP frames each packet with a 16-bit length. A larger
    /// packet cannot be framed; truncating its length would desync the
    /// stream, so it is refused and the stream stays usable.
    #[test]
    fn oversized_tcp_frame_is_refused() {
        let server = test_server();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (s, addr) = l.accept().unwrap();
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("unused")));
        let peer = Peer::new(crate::ovpn::tests::server_config(), [1; 8], on_auth).unwrap();
        let entry = Arc::new(PeerEntry {
            peer: Mutex::new(peer),
            transport: Transport::Tcp,
            addr,
            tcp: Some(Mutex::new(s)),
            connected: AtomicBool::new(false),
        });
        assert!(server.send_raw(&entry, &vec![0u8; 70_000]).is_err());
        server.send_raw(&entry, b"ok").unwrap();
        assert_eq!(tcp_recv(&mut client).unwrap(), b"ok");
        server.close();
    }

    /// A TLS config that cannot make a server connection (here: no
    /// identity) is reported by Server::new, rather than panicking the
    /// reader thread when the first client arrives.
    #[test]
    fn unusable_tls_config_fails_server_creation() {
        let tls = Arc::new(
            purecrypto::tls::Config::builder()
                .rng(Arc::new(purecrypto::rng::OsRng))
                .build(),
        );
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("unused")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(tls, "127.0.0.1:0".parse().unwrap(), on_auth, on_data);
        let err = Server::new(cfg).expect_err("server without an identity");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
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
        let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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

    /// on_disconnect pairs with on_connect: a peer that never authenticated
    /// was never reported connected, so its removal is not reported either.
    #[test]
    fn on_disconnect_only_follows_on_connect() {
        let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let disconnects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let on_auth: OnAuth = Arc::new(|_| {
            Ok(PeerConfig::new(
                "10.8.0.2".parse().unwrap(),
                "10.8.0.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                24,
            ))
        });
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .on_connect({
            let c = connects.clone();
            Arc::new(move |_, _| {
                c.fetch_add(1, Ordering::SeqCst);
            })
        })
        .on_disconnect({
            let d = disconnects.clone();
            Arc::new(move |_| {
                d.fetch_add(1, Ordering::SeqCst);
            })
        });
        let server = Server::new(cfg).unwrap();

        // One client authenticates; another only opens a session.
        let sock = udp_client(&server);
        let mut client = TestClient::new(*b"CLIENTID");
        connect_udp(&sock, &mut client);
        let half = udp_client(&server);
        half.send(&client_reset(*b"HALFOPEN")).unwrap();
        recv_ctrl(&half);
        assert_eq!(server.peers.read().unwrap().len(), 2);
        assert_eq!(connects.load(Ordering::SeqCst), 1);

        server.close();
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
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

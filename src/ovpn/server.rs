//! OpenVPN server: accepts peers over UDP and TCP.
//!
//! Ported from the Go `server.go` / `server-udp.go` / `server-tcp.go`. The
//! server owns the listening sockets and a map of active peers keyed by
//! transport+address. Each inbound datagram is routed to its peer's state
//! machine ([`Peer::handle_packet`]); the resulting outbound datagrams are
//! written back on the same socket, and any decrypted data-channel payload is
//! handed to the configured callbacks.
//!
//! Over UDP, a client's first packet is answered statelessly, as OpenVPN 2.6
//! does: its peer only comes into being once it echoes the session id that
//! answer carried (see the `cookie` module).
//!
//! Concurrency follows the crate conventions: one reader thread for UDP and one
//! acceptor thread for TCP (plus a reader and a writer thread per TCP
//! connection, and a bounded pool of threads calling `on_auth`). Peers live
//! in `Arc<Mutex<Peer>>` so the reader threads and the adapter's send path
//! can both reach them. Nothing but a connection's own writer ever blocks on
//! a TCP socket.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock, Weak, mpsc};
use std::thread::{self, ThreadId};
use std::time::Duration;

use super::addr::{PeerKey, Transport};
use super::cookie::{Cookies, RateLimit, SourceRateLimit};
use super::packet_ctrl::ControlPacket;
use super::peer::{AuthRequest, OnAuth, Peer, PeerConfig, PeerOutput, PeerTimers};

/// Callback fired for each decrypted data-channel payload. Receives the peer
/// key, the peer's layer (2=tap, 3=tun), and the payload bytes.
pub type OnData = Arc<dyn Fn(PeerKey, u8, &[u8]) + Send + Sync>;

/// Callback fired once a peer completes authentication, with its pushed config.
/// A client that reconnects from the same address is reported as a
/// disconnect followed by a new connect. See [`ServerConfig::on_connect`]
/// for how the calls for one key are ordered.
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
    ///
    /// For any one [`PeerKey`], on_connect and on_disconnect calls never
    /// overlap and always alternate: connect, disconnect, connect, ...
    /// -- whichever sessions they are for, and however those sessions
    /// come and go. So a caller keeping state per key (as [`Adapter`]
    /// does) never sees a late on_disconnect for an old session after the
    /// on_connect of the one that took the key over.
    ///
    /// To keep that order without holding one client's thread up while
    /// another callback for the same key runs, a call that would overlap is
    /// queued, and made by the thread running the current one once it
    /// returns: a callback may be made on another thread than the one that
    /// handled the client's packet, and after the call that caused it has
    /// returned. That includes a callback calling back into the server --
    /// removing the peer from inside on_connect reports it gone once
    /// on_connect returns. For the same reason on_data may see a session's
    /// first payloads before its on_connect has been made.
    ///
    /// [`Adapter`]: super::Adapter
    pub on_connect: Option<OnConnect>,
    /// Optional disconnect notification; ordered with on_connect as
    /// described there.
    pub on_disconnect: Option<OnDisconnect>,
    /// Most peers (UDP and TCP together) held at once; a client beyond it is
    /// not served. Default 1024.
    pub max_peers: usize,
    /// Most peers held at once that have no authenticated session: clients
    /// still in their handshake, or anyone at all who got as far as a
    /// session id. Past it, a new client is not served until one of those
    /// authenticates or gives up, but clients that have authenticated keep
    /// their places. `None`, the default: half of
    /// [`max_peers`](Self::max_peers), rounded up.
    pub max_unauthenticated_peers: Option<usize>,
    /// Most such peers from one source: an IPv4 address, or an IPv6 /64
    /// (what one host is typically given). Keeps one source from taking
    /// every place the whole server has for clients handshaking. Default 16.
    pub max_unauthenticated_peers_per_source: usize,
    /// At most this many new peers per period from one source (an IPv4
    /// address or an IPv6 /64, as for
    /// [`max_unauthenticated_peers_per_source`](Self::max_unauthenticated_peers_per_source)),
    /// UDP and TCP together. Unlike
    /// [`connect_freq_initial`](Self::connect_freq_initial), it counts the
    /// clients that complete the three-way handshake and get a peer.
    ///
    /// `None`, the default: no limit, as with OpenVPN's `connect-freq`
    /// unless configured. Unlike OpenVPN's, it is kept per source, so that
    /// one host opening peers as fast as it can uses up its own budget,
    /// not every other client's; it bounds how fast one source makes the
    /// server run handshakes, where the caps on unauthenticated peers bound
    /// how many it runs at once.
    pub connect_freq: Option<(u32, Duration)>,
    /// Most TCP connections served at once; each has two threads, a reader
    /// and a writer. Default 256.
    pub max_tcp_connections: usize,
    /// Most TCP connections served at once from one source (an IPv4
    /// address or an IPv6 /64, as for
    /// [`max_unauthenticated_peers_per_source`](Self::max_unauthenticated_peers_per_source))
    /// whose client has not authenticated, so that one source cannot take
    /// them all. A connection whose client authenticates gives its place
    /// back: clients behind one NAT address are not limited to this many,
    /// only [`max_tcp_connections`](Self::max_tcp_connections) bounds
    /// them. Default 16.
    pub max_tcp_connections_per_source: usize,
    /// Each peer's timers: handshake window, keepalive, renegotiation.
    /// Defaults to OpenVPN's (see [`PeerTimers`]).
    pub timers: PeerTimers,
    /// At most this many answers to UDP clients' first packets per period
    /// (OpenVPN's `connect-freq-initial`, default 100 per 10 s). The first
    /// answer goes to an address nobody has vouched for yet, so this bounds
    /// how much the server can be made to reflect at a spoofed victim.
    /// Clients that complete the handshake are not counted.
    pub connect_freq_initial: (u32, Duration),
    /// Most `on_auth` calls running at once, each on a thread of its own.
    /// Clients beyond it wait their turn, within their handshake window;
    /// one client's authentications never run side by side. At least 1;
    /// default 16.
    pub max_auth_threads: usize,
}

/// Default [`ServerConfig::max_peers`].
pub(super) const DEFAULT_MAX_PEERS: usize = 1024;
/// Default [`ServerConfig::max_unauthenticated_peers_per_source`].
pub(super) const DEFAULT_MAX_UNAUTHENTICATED_PER_SOURCE: usize = 16;
/// Default [`ServerConfig::max_tcp_connections`].
pub(super) const DEFAULT_MAX_TCP_CONNECTIONS: usize = 256;
/// Default [`ServerConfig::max_tcp_connections_per_source`].
pub(super) const DEFAULT_MAX_TCP_CONNECTIONS_PER_SOURCE: usize = 16;
/// Default [`ServerConfig::connect_freq_initial`].
pub(super) const DEFAULT_CONNECT_FREQ_INITIAL: (u32, Duration) = (100, Duration::from_secs(10));
/// Default [`ServerConfig::max_auth_threads`].
pub(super) const DEFAULT_MAX_AUTH_THREADS: usize = 16;

setters! {
    ServerConfig {
        some on_connect: OnConnect;
        some on_disconnect: OnDisconnect;
        set max_peers: usize;
        some max_unauthenticated_peers: usize;
        set max_unauthenticated_peers_per_source: usize;
        some connect_freq: (u32, Duration);
        set max_tcp_connections: usize;
        set max_tcp_connections_per_source: usize;
        set timers: PeerTimers;
        set connect_freq_initial: (u32, Duration);
        set max_auth_threads: usize;
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
            max_unauthenticated_peers: None,
            max_unauthenticated_peers_per_source: DEFAULT_MAX_UNAUTHENTICATED_PER_SOURCE,
            connect_freq: None,
            max_tcp_connections: DEFAULT_MAX_TCP_CONNECTIONS,
            max_tcp_connections_per_source: DEFAULT_MAX_TCP_CONNECTIONS_PER_SOURCE,
            timers: PeerTimers::default(),
            connect_freq_initial: DEFAULT_CONNECT_FREQ_INITIAL,
            max_auth_threads: DEFAULT_MAX_AUTH_THREADS,
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
    // For TCP peers, the connection's outbound queue. For UDP, None (the
    // server writes via the shared UDP socket).
    tcp: Option<TcpOut>,
    /// What on_connect / on_disconnect are to say of the peer. One lock for
    /// removal and the connect transition, so a verdict landing as the
    /// peer is removed either reports it connected before the removal
    /// sees it, or not at all. The calls are queued (see `Server::post`)
    /// under it, so they are queued in the order they were decided.
    link: Mutex<Link>,
    /// Authentications waiting for an on_auth call.
    auth: Mutex<PeerAuth>,
    /// The peer's last output said it has an authenticated session: it
    /// does not count against the limits on unauthenticated peers.
    authenticated: AtomicBool,
}

/// A peer's authentications. They run one at a time -- a client restarting
/// while its on_auth is stuck must not multiply the calls -- so while one
/// runs, those after it wait here.
#[derive(Default)]
struct PeerAuth {
    queued: VecDeque<AuthRequest>,
    /// In the server's run queue, or an auth worker is serving the peer.
    scheduled: bool,
}

#[derive(Default)]
struct Link {
    /// Out of the peer table: never reported connected again.
    removed: bool,
    /// on_connect was queued and not yet matched by an on_disconnect: the
    /// callbacks pair, so only such a peer is reported gone.
    connected: bool,
}

impl PeerEntry {
    fn new(peer: Peer, transport: Transport, addr: SocketAddr, tcp: Option<TcpOut>) -> PeerEntry {
        PeerEntry {
            peer: Mutex::new(peer),
            transport,
            addr,
            tcp,
            link: Mutex::default(),
            auth: Mutex::default(),
            authenticated: AtomicBool::new(false),
        }
    }

    fn key(&self) -> PeerKey {
        PeerKey::new(self.addr, self.transport)
    }
}

/// A callback owed for a key.
enum Event {
    Connect(PeerConfig),
    Disconnect,
}

/// The on_connect / on_disconnect calls owed for one key, made one at a
/// time and in order -- by whichever thread finds none running. A key's
/// sessions may be served by different threads (a slow on_connect on an
/// auth worker, the next session's removal on the UDP reader): made where
/// they were decided, a replaced session's on_disconnect could come after
/// the on_connect of the one replacing it.
#[derive(Default)]
struct KeyEvents {
    queue: VecDeque<Event>,
    /// A thread is making this key's calls.
    running: bool,
    /// on_connect was made and not yet matched by an on_disconnect. Once
    /// the server is closed, a connect is no longer reported; this keeps
    /// the disconnect queued behind it from being reported either.
    up: bool,
}

/// The callers' code running on the server's threads -- on_auth, on_data,
/// and the making of a key's on_connect / on_disconnect calls -- so close()
/// can wait for it, and none starts once close() has begun. Shared by the
/// calls under way rather than borrowed from the server: an auth worker
/// holds no reference to the server while on_auth runs.
#[derive(Default)]
struct Calls {
    state: Mutex<CallState>,
    /// Signalled as each call ends.
    ended: Condvar,
}

#[derive(Default)]
struct CallState {
    closed: bool,
    /// The thread of each call under way, once per call: a callback may
    /// cause another on its own thread.
    running: Vec<ThreadId>,
}

impl Calls {
    fn state(&self) -> std::sync::MutexGuard<'_, CallState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count a call in, unless the server is closed. `even_closed` is for
    /// the calls close() itself causes: the on_disconnect of each peer.
    fn begin(self: &Arc<Self>, even_closed: bool) -> Option<CallGuard> {
        let mut st = self.state();
        if st.closed && !even_closed {
            return None;
        }
        st.running.push(thread::current().id());
        Some(CallGuard(self.clone()))
    }

    fn is_closed(&self) -> bool {
        self.state().closed
    }

    /// Wait until no call is under way on another thread than this one --
    /// whose calls, if close() was called from one, only go on once it
    /// returns -- or until `deadline`.
    fn wait(&self, deadline: crate::time::Instant) {
        let me = thread::current().id();
        let mut st = self.state();
        while st.running.iter().any(|t| *t != me) {
            let left = deadline.saturating_duration_since(crate::time::Instant::now());
            if left.is_zero() {
                return;
            }
            st = self
                .ended
                .wait_timeout(st, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// A call under way, counted out when dropped.
struct CallGuard(Arc<Calls>);

impl Drop for CallGuard {
    fn drop(&mut self) {
        let me = thread::current().id();
        let mut st = self.0.state();
        if let Some(i) = st.running.iter().position(|t| *t == me) {
            st.running.swap_remove(i);
        }
        drop(st);
        self.0.ended.notify_all();
    }
}

/// Most frames queued for one TCP connection; past it, frames are dropped
/// (OpenVPN's `tcp-queue-limit`, default 64). Control packets lost that way
/// are retransmitted, data packets are the tunnel's own business.
const TCP_QUEUE_LIMIT: usize = 64;

/// The sending side of a TCP connection: a bounded queue drained by a
/// writer thread of its own.
///
/// Senders -- the maintenance thread ticking every peer, the UDP reader
/// running callbacks that send to peers, the connection's own reader -- must
/// never block on the socket (OpenVPN never blocks its event loop on a
/// write either): one client that stops reading would stall them all. So a
/// frame is only queued, and dropped when the queue is full.
struct TcpOut {
    queue: mpsc::SyncSender<Vec<u8>>,
    /// The connection's id in `Server::tcp_streams`.
    id: u64,
    /// For shutting the connection down.
    stream: TcpStream,
}

impl TcpOut {
    /// Start the writer for `stream`. A write blocked past `write_timeout`
    /// means the client has stopped reading for good: the writer then
    /// closes the connection, which ends its reader and the peer.
    fn spawn(stream: TcpStream, id: u64, write_timeout: Option<Duration>) -> io::Result<TcpOut> {
        stream.set_write_timeout(write_timeout)?;
        let w = stream.try_clone()?;
        let (queue, rx) = mpsc::sync_channel::<Vec<u8>>(TCP_QUEUE_LIMIT);
        // Ends when the entry, and with it the queue, is dropped, or when
        // a write fails (after the connection was shut down, for one).
        thread::Builder::new()
            .name("ovpn-tcp-writer".into())
            .spawn(move || {
                while let Ok(frame) = rx.recv() {
                    if (&w).write_all(&frame).is_err() {
                        let _ = w.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
            })?;
        Ok(TcpOut { queue, id, stream })
    }
}

/// An OpenVPN server.
///
/// Its threads hold only a weak reference to it, so dropping the last
/// `Arc<Server>` shuts it down just as [`close`](Self::close) does.
pub struct Server {
    cfg: ServerConfig,
    /// Taken by close(), which releases the port. The reader borrows the
    /// socket one read at a time, so it does not keep it open either.
    udp: RwLock<Option<Arc<UdpSocket>>>,
    tcp_addr: SocketAddr,
    peers: RwLock<HashMap<PeerKey, Arc<PeerEntry>>>,
    /// Every open TCP connection by id, so close() can shut them down --
    /// including those that have not sent a hard reset yet.
    tcp_streams: Mutex<HashMap<u64, TcpConn>>,
    next_tcp_id: AtomicU64,
    closed: AtomicBool,
    /// The UDP reader and the TCP acceptor, which close() waits for: the
    /// listening sockets are released by the time they exit.
    loops: Mutex<Vec<SocketLoop>>,
    /// The server itself, for the threads it starts along the way.
    me: Weak<Server>,
    /// Session ids for stateless answers to UDP clients' first packets.
    cookies: Cookies,
    /// Bounds those answers (`connect_freq_initial`).
    initial_limit: Mutex<RateLimit>,
    /// Bounds new peers per source (`connect_freq`), if configured.
    connect_limit: Option<Mutex<SourceRateLimit>>,
    /// Peers with authentications to run, and the workers running them.
    auth: Mutex<AuthPool>,
    /// on_connect / on_disconnect calls owed, by key. A key is here only
    /// while it has calls queued or running, or was reported connected.
    /// Taken under a peer's `link` lock, never the other way round.
    events: Mutex<HashMap<PeerKey, KeyEvents>>,
    /// Callbacks under way, for close() to wait for.
    calls: Arc<Calls>,
}

/// The threads calling on_auth: at most `max_auth_threads`, started as
/// work arrives and gone once there is none. A peer is queued at most once
/// (see [`PeerAuth`]), and peers gone from the table are pruned each time
/// one is queued, so the queue holds at most one entry per live peer.
/// Without the pruning, peers coming and going while every worker is stuck
/// in a slow on_auth would each leave an entry behind.
#[derive(Default)]
struct AuthPool {
    ready: VecDeque<Weak<PeerEntry>>,
    workers: usize,
}

/// Most sources `connect_freq` keeps a count for. Past it, the stalest
/// count is forgotten -- that source's limit starts over -- rather than
/// anyone refused: many sources each proving its address is what the caps
/// on peers are for.
const CONNECT_FREQ_SOURCES: usize = 4096;

/// A thread serving a listening socket.
struct SocketLoop {
    thread: ThreadId,
    /// Disconnects when the thread exits.
    done: mpsc::Receiver<()>,
}

impl SocketLoop {
    fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> io::Result<SocketLoop> {
        let (tx, done) = mpsc::channel::<()>();
        let handle = thread::Builder::new().name(name.into()).spawn(move || {
            let _signal = tx;
            // `f` and everything it owns are dropped before `_signal`.
            f();
        })?;
        Ok(SocketLoop {
            thread: handle.thread().id(),
            done,
        })
    }
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

/// How long close() waits for a socket thread to exit. It normally takes at
/// most one POLL; this only bounds the wait when a callback running on the
/// UDP reader is itself stuck -- on a lock close()'s caller holds, say.
const LOOP_EXIT_WAIT: Duration = Duration::from_secs(1);

/// How long close() waits for callbacks under way on other threads: an
/// on_auth waiting on its backend, an on_connect stuck on a lock close()'s
/// caller holds.
const CALL_EXIT_WAIT: Duration = Duration::from_secs(1);

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
        let udp = UdpSocket::bind(cfg.listen_addr)?;
        udp.set_read_timeout(Some(POLL))?;
        let tcp = TcpListener::bind(cfg.listen_addr)?;
        let tcp_addr = tcp.local_addr()?;
        // A blocking accept cannot be interrupted portably; poll instead.
        tcp.set_nonblocking(true)?;

        let cookies = Cookies::new(cfg.timers.handshake_window);
        let (max, period) = cfg.connect_freq_initial;
        let initial_limit = Mutex::new(RateLimit::new(max, period));
        let connect_limit = cfg.connect_freq.map(|(max, period)| {
            Mutex::new(SourceRateLimit::new(max, period, CONNECT_FREQ_SOURCES))
        });
        let server = Arc::new_cyclic(|me| Server {
            me: me.clone(),
            cookies,
            initial_limit,
            connect_limit,
            cfg,
            udp: RwLock::new(Some(Arc::new(udp))),
            tcp_addr,
            peers: RwLock::new(HashMap::new()),
            tcp_streams: Mutex::new(HashMap::new()),
            next_tcp_id: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            loops: Mutex::new(Vec::new()),
            auth: Mutex::default(),
            events: Mutex::default(),
            calls: Arc::default(),
        });

        // Should a thread fail to start, returning drops the server, which
        // closes it: whatever did start stops.
        let weak = Arc::downgrade(&server);
        let w = weak.clone();
        let udp_loop = SocketLoop::spawn("ovpn-udp", move || udp_loop(w))?;
        server.loops.lock().unwrap().push(udp_loop);
        let w = weak.clone();
        let tcp_loop = SocketLoop::spawn("ovpn-tcp-accept", move || tcp_loop(w, tcp))?;
        server.loops.lock().unwrap().push(tcp_loop);
        thread::Builder::new()
            .name("ovpn-maintenance".into())
            .spawn(move || maintenance_loop(weak))?;

        Ok(server)
    }

    /// Local UDP address the server is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp
            .read()
            .unwrap()
            .as_ref()
            .ok_or_else(closed_error)?
            .local_addr()
    }

    /// Local TCP address the server listens on. The same as
    /// [`local_addr`](Self::local_addr) unless the configured port was 0, in
    /// which case each transport got its own ephemeral port.
    pub fn tcp_local_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// Shut the server down: stop the loops, close every TCP connection and
    /// both listening sockets, and drop all peers. The UDP and TCP ports are
    /// free for reuse once this returns.
    ///
    /// No callback starts once close() has begun, but for the on_disconnect
    /// of each peer reported connected, which close() makes itself. It
    /// waits for the callbacks already running -- on_auth, on_data,
    /// on_connect, on_disconnect, and the UDP reader with whatever it is
    /// doing -- so that once it returns, none runs any more.
    ///
    /// Do not call it holding a lock a callback takes: each wait then gives
    /// up after a second, the callback finishing after close() returned
    /// (and the ports only released once it has). Called from a callback,
    /// it does not wait for that callback, nor for those queued behind it
    /// on its thread -- such as the on_disconnect of the peer an
    /// on_connect is for, made once on_connect returns.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.calls.state().closed = true;
        // The reader only borrows the socket for a read, so this leaves it
        // open until that read returns, within a poll interval.
        self.udp.write().unwrap().take();
        // A thread blocked reading a TCP connection wakes up to the shutdown
        // and exits; the socket loops notice `closed` on their next poll.
        for (_, c) in self.tcp_streams.lock().unwrap().drain() {
            let _ = c.stream.shutdown(std::net::Shutdown::Both);
        }
        // The loop calling close() -- from a callback, or dropping the last
        // handle -- lets go of its socket as soon as it returns.
        let me = thread::current().id();
        for l in std::mem::take(&mut *self.loops.lock().unwrap()) {
            if l.thread != me {
                let _ = l.done.recv_timeout(LOOP_EXIT_WAIT);
            }
        }
        // Callbacks run after the table lock is released: they may call
        // back into the server.
        let peers: Vec<PeerKey> = self
            .peers
            .write()
            .unwrap()
            .drain()
            .map(|(k, e)| {
                self.mark_removed(&e);
                k
            })
            .collect();
        for k in peers {
            self.run_events(k);
        }
        self.calls
            .wait(crate::time::Instant::now() + CALL_EXIT_WAIT);
    }

    fn handle_udp(&self, data: &[u8], src: SocketAddr) {
        let key = PeerKey::new(src, Transport::Udp);
        let entry = match self.get_peer(&key) {
            Some(e) => e,
            None => match self.handle_stranger(data, src) {
                Some(e) => e,
                None => return,
            },
        };
        self.dispatch(&entry, data);
    }

    /// A datagram from an address without a peer (mudp.c
    /// do_pre_decrypt_check). A client hard reset is answered without
    /// keeping any state (see [`super::cookie`]); the peer is only created
    /// -- and returned, for the datagram to be dispatched to -- when the
    /// client echoes the session id that answer gave it. Anything else is
    /// dropped.
    fn handle_stranger(&self, data: &[u8], src: SocketAddr) -> Option<Arc<PeerEntry>> {
        let now = crate::time::Instant::now();
        if Peer::is_session_start(data) {
            let reset = ControlPacket::parse(data).ok()?;
            if self.initial_limit.lock().unwrap().allow(now) {
                let reply = self.cookies.reply(&reset, src, now);
                if let Some(udp) = self.udp.read().unwrap().as_ref() {
                    let _ = udp.send_to(&reply, src);
                }
            }
            return None;
        }
        let pkt = ControlPacket::parse(data).ok()?;
        if !self.cookies.check(&pkt, src, now) {
            return None;
        }
        let key = PeerKey::new(src, Transport::Udp);
        let ids = (pkt.remote_id, pkt.session_id);
        let entry = self.create_peer(key, Transport::Udp, src, None, Some(ids))?;
        // A completed three-way handshake does not count against the
        // limit on replies to strangers -- only one that got a peer: an
        // echo refused one (a full table) can be replayed at will.
        self.initial_limit.lock().unwrap().refund();
        Some(entry)
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
        let id = {
            // Each connection costs two threads: refuse (close) past the
            // caps.
            let mut streams = self.tcp_streams.lock().unwrap();
            // close() sets `closed`, then shuts down every stream in this
            // table under its lock: checked under the same lock, a
            // connection accepted as it runs is either shut down there or
            // refused here, never left open.
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let source = source_of(addr.ip());
            let here = streams
                .values()
                .filter(|c| c.source == source && !c.authenticated)
                .count();
            if streams.len() >= self.cfg.max_tcp_connections
                || here >= self.cfg.max_tcp_connections_per_source
            {
                return;
            }
            let id = self.next_tcp_id.fetch_add(1, Ordering::Relaxed);
            let conn = TcpConn {
                source,
                authenticated: false,
                stream: handle,
            };
            streams.insert(id, conn);
            id
        };
        // The slot is given back however the connection ends: the thread
        // not starting, or unwinding from a panicking callback.
        let slot = TcpSlot {
            server: weak.clone(),
            id,
        };
        let _ = stream.set_nodelay(true);
        let weak = weak.clone();
        let _ = thread::Builder::new()
            .name("ovpn-tcp".into())
            .spawn(move || {
                let _slot = slot;
                tcp_conn(&weak, stream, id, addr);
            });
    }

    /// Run `f` on the peer of `entry`, under its lock. A panic in it, or a
    /// lock some earlier panic poisoned, means the peer's state can no
    /// longer be trusted: the peer is removed, and `None` returned. Either
    /// way the thread goes on -- the UDP reader and the maintenance thread
    /// serve every client, and must not die with one.
    fn with_peer<R>(&self, entry: &Arc<PeerEntry>, f: impl FnOnce(&mut Peer) -> R) -> Option<R> {
        let res = match entry.peer.lock() {
            Ok(mut peer) => {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut peer))).ok()
            }
            Err(_) => None,
        };
        // Not under the peer's lock: removal may fire on_disconnect, which
        // may call back into the server for this peer.
        if res.is_none() {
            self.remove_entry(entry);
        }
        res
    }

    fn tick_peers(&self) {
        let now = crate::time::Instant::now();
        // Snapshot the entries so we don't hold the peers lock while
        // ticking (which takes each peer's own lock and may send).
        let entries: Vec<Arc<PeerEntry>> = self.peers.read().unwrap().values().cloned().collect();
        for entry in entries {
            let Some(out) = self.with_peer(&entry, |p| p.tick(now)) else {
                continue;
            };
            let Ok(out) = out else {
                self.remove_entry(&entry);
                continue;
            };
            self.set_authenticated(&entry, out.authenticated);
            for dgram in &out.send {
                let _ = self.send_raw(&entry, dgram);
            }
            if out.close {
                self.remove_entry(&entry);
            }
        }
    }

    /// Record whether the peer's last output said it has an authenticated
    /// session. The first time it does, its TCP connection, if any, leaves
    /// the per-source cap for good: the client has proved who it is.
    fn set_authenticated(&self, entry: &PeerEntry, authenticated: bool) {
        let was = entry.authenticated.swap(authenticated, Ordering::Relaxed);
        if authenticated
            && !was
            && let Some(out) = &entry.tcp
            && let Some(c) = self.tcp_streams.lock().unwrap().get_mut(&out.id)
        {
            c.authenticated = true;
        }
    }

    fn get_peer(&self, key: &PeerKey) -> Option<Arc<PeerEntry>> {
        self.peers.read().unwrap().get(key).cloned()
    }

    /// Add a peer for `key`, or return the one already there. `None` when
    /// the peer table is full -- or has no room for another peer that has
    /// not authenticated, from this source or at all -- or when new peers
    /// are coming from its source faster than `connect_freq` allows.
    ///
    /// `stateless` is for a UDP client whose hard reset was answered
    /// statelessly: our session id from that answer and the client's.
    fn create_peer(
        &self,
        key: PeerKey,
        transport: Transport,
        addr: SocketAddr,
        tcp: Option<TcpOut>,
        stateless: Option<([u8; 8], [u8; 8])>,
    ) -> Option<Arc<PeerEntry>> {
        let max_unauthenticated = self
            .cfg
            .max_unauthenticated_peers
            .unwrap_or(self.cfg.max_peers.div_ceil(2));
        let source = source_of(addr.ip());
        let admit = |peers: &HashMap<PeerKey, Arc<PeerEntry>>| {
            if let Some(e) = peers.get(&key) {
                return Err(Some(e.clone()));
            }
            if peers.len() >= self.cfg.max_peers {
                return Err(None);
            }
            // A walk of the table, at most max_peers long, only for a
            // client that proved its address to get this far: a few
            // microseconds, about what checking the proof took.
            let (mut all, mut here) = (0, 0);
            for e in peers.values() {
                if !e.authenticated.load(Ordering::Relaxed) {
                    all += 1;
                    here += usize::from(source_of(e.addr.ip()) == source);
                }
            }
            if all >= max_unauthenticated || here >= self.cfg.max_unauthenticated_peers_per_source {
                return Err(None);
            }
            Ok(())
        };
        if let Err(found) = admit(&self.peers.read().unwrap()) {
            return found;
        }
        // Built with no lock held: a panic under the table's write lock
        // would poison it for every client. A panic costs this client only.
        let peer =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.build_peer(stateless)))
                .ok()??;
        // Another thread may have added this peer, or filled the table,
        // meanwhile; the peer just built is then dropped.
        let mut peers = self.peers.write().unwrap();
        if let Err(found) = admit(&peers) {
            return found;
        }
        // Charged only for a peer about to be added: a client turned away
        // for want of room, or finding its peer there already, has not
        // cost a handshake.
        if let Some(limit) = &self.connect_limit
            && !limit
                .lock()
                .unwrap()
                .allow(source, crate::time::Instant::now())
        {
            return None;
        }
        let entry = Arc::new(PeerEntry::new(peer, transport, addr, tcp));
        peers.insert(key, entry.clone());
        Some(entry)
    }

    /// A new peer, as [`create_peer`](Self::create_peer) adds it.
    fn build_peer(&self, stateless: Option<([u8; 8], [u8; 8])>) -> Option<Peer> {
        #[cfg(test)]
        if tests::PANIC_BUILDING_PEER.with(std::cell::Cell::get) {
            panic!("building the peer panics (test)");
        }
        let local_id = match stateless {
            Some((ours, _)) => ours,
            None => {
                let mut id = [0u8; 8];
                let _ = super::peer::fill_random(&mut id);
                id
            }
        };
        // Server::new checked the TLS config.
        let mut peer = Peer::with_checked_config(
            self.cfg.tls_config.clone(),
            local_id,
            self.cfg.on_auth.clone(),
        )
        .with_timers(self.cfg.timers)
        // on_auth runs on an auth worker: see start_auth.
        .deferred_auth();
        if let Some((_, theirs)) = stateless {
            peer.open_after_stateless_reset(theirs).ok()?;
        }
        Some(peer)
    }

    /// Drop `entry` from the peer table -- only if it is still the entry
    /// for its key, as a caller may hold a stale one -- and close its TCP
    /// connection, which ends the thread serving it.
    fn remove_entry(&self, entry: &Arc<PeerEntry>) {
        let key = entry.key();
        {
            let mut peers = self.peers.write().unwrap();
            let current = peers.get(&key).is_some_and(|e| Arc::ptr_eq(e, entry));
            if !current || peers.remove(&key).is_none() {
                return;
            }
            // Under the table's lock, as close() does: once the lock is
            // released, a new session for the key can be created and
            // authenticate on another thread, and its on_connect must be
            // queued behind this one's on_disconnect, not ahead of it.
            self.mark_removed(entry);
        }
        #[cfg(test)]
        if let Some(hook) = tests::AFTER_UNLINK.with(std::cell::Cell::get) {
            hook(self, key);
        }
        if let Some(w) = &entry.tcp {
            let _ = w.stream.shutdown(std::net::Shutdown::Both);
        }
        self.run_events(key);
    }

    /// Mark the entry removed, queueing its on_disconnect if it was
    /// reported connected. The caller then runs the key's events.
    fn mark_removed(&self, entry: &PeerEntry) {
        let mut l = entry.link.lock().unwrap();
        l.removed = true;
        if std::mem::take(&mut l.connected) {
            self.post(entry.key(), [Event::Disconnect]);
        }
    }

    /// Queue callbacks for `key`. Called under the peer's `link` lock, so
    /// that they are queued in the order they were decided.
    fn post(&self, key: PeerKey, events: impl IntoIterator<Item = Event>) {
        let mut all = self.events.lock().unwrap();
        all.entry(key).or_default().queue.extend(events);
    }

    /// Make the calls queued for `key`, unless another thread is making
    /// them already: it then makes these too, once its current one
    /// returns. So a callback that comes back into the server for its own
    /// key -- removing the peer from inside on_connect -- finds its call
    /// queued behind the running one, rather than deadlocking or cutting
    /// in.
    fn run_events(&self, key: PeerKey) {
        // Counted in before looking at the queue, so that close() waits for
        // a thread that is about to make calls it queued.
        let _call = self.calls.begin(true);
        let mut all = self.events.lock().unwrap();
        match all.get_mut(&key) {
            Some(k) if !k.running => k.running = true,
            _ => return,
        }
        loop {
            let k = all.get_mut(&key).expect("a running key stays queued");
            let Some(ev) = k.queue.pop_front() else {
                k.running = false;
                if !k.up {
                    all.remove(&key);
                }
                return;
            };
            let run = match ev {
                Event::Connect(_) => !self.calls.is_closed(),
                Event::Disconnect => k.up,
            };
            if !run {
                continue;
            }
            k.up = matches!(ev, Event::Connect(_));
            // With no lock held: a callback may call back into the server.
            drop(all);
            match ev {
                Event::Connect(cfg) => {
                    if let Some(cb) = &self.cfg.on_connect {
                        callback(|| cb(key, &cfg));
                    }
                }
                Event::Disconnect => {
                    if let Some(cb) = &self.cfg.on_disconnect {
                        callback(|| cb(key));
                    }
                }
            }
            all = self.events.lock().unwrap();
        }
    }

    /// Run one inbound datagram through the peer and act on the output.
    fn dispatch(&self, entry: &Arc<PeerEntry>, data: &[u8]) {
        // An `Err` is a dropped datagram; only `out.close` ends the session.
        if let Some(Ok(out)) = self.with_peer(entry, |p| p.handle_packet(data)) {
            self.apply(entry, out);
        }
    }

    /// Check credentials the peer handed out, then complete its
    /// authentication.
    ///
    /// on_auth may be slow (an auth backend round trip) and may call back
    /// into the server, so it runs on an auth worker, without the peer's
    /// lock: on the thread that read the packet it would hold up every
    /// client behind it, and under the lock it would deadlock calling
    /// send_to_peer. OpenVPN defers authentication the same way
    /// (KS_AUTH_DEFERRED).
    fn start_auth(&self, entry: &Arc<PeerEntry>, req: AuthRequest) {
        let schedule = self.with_peer(entry, |peer| {
            let mut auth = entry.auth.lock().unwrap();
            // Credentials no longer awaited -- a client restarting drops
            // the key exchange that presented them -- need no call. Pruned
            // here, a peer's queue holds only its live key exchanges.
            auth.queued.retain(|r| peer.awaits(r));
            auth.queued.push_back(req);
            !std::mem::replace(&mut auth.scheduled, true)
        });
        if schedule == Some(true) {
            self.schedule_auth(entry);
        }
    }

    /// Queue a peer for an auth worker, starting one if fewer than
    /// max_auth_threads are running.
    fn schedule_auth(&self, entry: &Arc<PeerEntry>) {
        let spawn = {
            let mut pool = self.auth.lock().unwrap();
            // A removed peer is never served (run_auth skips it), so it
            // need not wait for its turn either.
            pool.ready.retain(|w| {
                w.upgrade().is_some_and(|e| {
                    !e.link
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .removed
                })
            });
            pool.ready.push_back(Arc::downgrade(entry));
            let more = pool.workers < self.cfg.max_auth_threads.max(1);
            pool.workers += usize::from(more);
            more
        };
        if !spawn {
            return;
        }
        let server = self.me.clone();
        let started = thread::Builder::new()
            .name("ovpn-auth".into())
            .spawn(move || auth_worker(&server));
        if started.is_ok() {
            return;
        }
        // With no worker left either, nothing would ever take the queued
        // peers: refuse them now rather than leave them to time out.
        let stranded = {
            let mut pool = self.auth.lock().unwrap();
            pool.workers -= 1;
            if pool.workers > 0 {
                return;
            }
            std::mem::take(&mut pool.ready)
        };
        for entry in stranded.iter().filter_map(Weak::upgrade) {
            let reqs = {
                let mut auth = entry.auth.lock().unwrap();
                auth.scheduled = false;
                std::mem::take(&mut auth.queued)
            };
            for req in reqs {
                let refused = Err(io::Error::other("no thread to check credentials on"));
                if let Some(out) = self.with_peer(&entry, |p| p.complete_auth(&req, refused)) {
                    self.apply(&entry, out);
                }
            }
        }
    }

    /// Act on what the peer produced: send, report, deliver, close.
    fn apply(&self, entry: &Arc<PeerEntry>, mut out: PeerOutput) {
        let key = entry.key();
        self.set_authenticated(entry, out.authenticated);
        for dgram in &out.send {
            let _ = self.send_raw(entry, dgram);
        }

        // Callbacks run without the peer's lock held: they may well call
        // back into the server for this peer (send_to_peer, say).
        if let Some(cfg) = &out.connected {
            self.announce(entry, key, cfg);
        }

        if let Some(payload) = out.deliver
            && let Some(layer) = self.with_peer(entry, |p| p.layer())
            && let Some(_call) = self.calls.begin(false)
        {
            callback(|| (self.cfg.on_data)(key, layer, &payload));
        }

        if out.close {
            self.remove_entry(entry);
        } else if let Some(req) = out.auth.take() {
            self.start_auth(entry, req);
        }
    }

    /// Report a session that has just authenticated: on_connect, unless the
    /// peer was removed meanwhile.
    fn announce(&self, entry: &PeerEntry, key: PeerKey, cfg: &PeerConfig) {
        {
            let mut l = entry.link.lock().unwrap();
            if l.removed {
                return;
            }
            // A new session taking over from one that was reported
            // connected ends that connection first. The flag, not
            // `out.replaced`, decides: the old session may have failed on
            // its own before this one authenticated.
            let replaced = std::mem::replace(&mut l.connected, true);
            let gone = replaced.then_some(Event::Disconnect);
            self.post(key, gone.into_iter().chain([Event::Connect(cfg.clone())]));
        }
        self.run_events(key);
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
        let dgram = self
            .with_peer(&entry, |p| p.send_data(payload))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "peer failed"))??;
        self.send_raw(&entry, &dgram)
    }

    /// Write a raw datagram to the peer's transport.
    fn send_raw(&self, entry: &Arc<PeerEntry>, dgram: &[u8]) -> io::Result<()> {
        match entry.transport {
            Transport::Udp => {
                let udp = self.udp.read().unwrap();
                udp.as_ref()
                    .ok_or_else(closed_error)?
                    .send_to(dgram, entry.addr)?;
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
                    match w.queue.try_send(frame) {
                        Ok(()) => Ok(()),
                        Err(mpsc::TrySendError::Full(_)) => Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "TCP send queue full, packet dropped",
                        )),
                        Err(mpsc::TrySendError::Disconnected(_)) => Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "TCP connection closed",
                        )),
                    }
                } else {
                    Err(io::Error::new(io::ErrorKind::NotConnected, "no tcp stream"))
                }
            }
        }
    }
}

/// The source a client counts against for
/// [`max_unauthenticated_peers_per_source`](ServerConfig::max_unauthenticated_peers_per_source):
/// its IPv4 address, or its IPv6 /64, which one host typically has all of.
fn source_of(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip.to_canonical() {
        std::net::IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !(u128::from(u64::MAX));
            std::net::IpAddr::V6(bits.into())
        }
        v4 => v4,
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "server closed")
}

fn udp_loop(server: Weak<Server>) {
    let mut buf = vec![0u8; 65536];
    loop {
        // Hold the socket for one read only, so that once close() has
        // taken it the port is released as soon as the read returns.
        let Some(udp) = live(&server).and_then(|s| s.udp.read().unwrap().clone()) else {
            return;
        };
        let res = udp.recv_from(&mut buf);
        drop(udp);
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
fn tcp_conn(server: &Weak<Server>, stream: TcpStream, id: u64, addr: SocketAddr) {
    let Some(s) = live(server) else {
        return;
    };
    let key = PeerKey::new(addr, Transport::Tcp);
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    // The client must open with a hard reset within the handshake window
    // -- all of it, not just some byte of it: a client dripping a byte at a
    // time would otherwise hold its connection, and its two threads, for
    // good. After that, it pings at least every keepalive interval, so a
    // read blocked past the ping-restart timeout means it is gone.
    let timers = s.cfg.timers;
    drop(s);
    let deadline = crate::time::Instant::now().checked_add(timers.handshake_window);
    let _ = stream.set_read_timeout(Some(timers.handshake_window));
    let mut reader = io::BufReader::new(stream);
    let Some(first) = read_frame_by(&mut reader, deadline) else {
        return;
    };
    if !Peer::is_session_start(&first) {
        return;
    }
    let Some(s) = live(server) else {
        return;
    };
    // Only one connection holds an address and port at a time, so an entry
    // already there is left over from a dead one -- its thread not done
    // yet, say. Answering through its socket would reach nobody: this
    // connection gets a peer of its own.
    if let Some(stale) = s.get_peer(&key) {
        s.remove_entry(&stale);
    }
    // From here the peer's own timers decide when the client is gone -- the
    // handshake window before it authenticates, ping-restart after -- and
    // dropping the peer closes the connection. The read timeout is only a
    // backstop, and there is none without keepalive: a quiet client may
    // then stay as long as it likes, as with OpenVPN. A write blocked that
    // long means a client that stopped reading: it has given up on us too.
    let idle = (!timers.keepalive_timeout.is_zero()).then(|| {
        timers
            .keepalive_timeout
            .saturating_mul(2)
            .max(timers.handshake_window)
    });
    let Ok(out) = TcpOut::spawn(write_half, id, idle) else {
        return;
    };
    let Some(entry) = s.create_peer(key, Transport::Tcp, addr, Some(out), None) else {
        return;
    };
    s.dispatch(&entry, &first);
    drop(s);
    let _ = reader.get_ref().set_read_timeout(idle);

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

/// Run a caller's callback, containing a panic in it. The panic hook has
/// reported it already; unwinding further would take down whichever thread
/// ran it -- the UDP reader serves every client -- or leave the server's
/// own bookkeeping half done.
fn callback(f: impl FnOnce()) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
}

/// An auth worker: serve queued peers, one authentication at a time, until
/// none is left.
fn auth_worker(server: &Weak<Server>) {
    let _count = WorkerCount(server.clone());
    while let Some(next) = next_auth(server) {
        run_auth(server, &next);
        let (Some(s), Some(entry)) = (live(server), next.upgrade()) else {
            continue;
        };
        // A peer with more to check goes back in line, behind those
        // already waiting.
        let more = {
            let mut auth = entry.auth.lock().unwrap();
            auth.scheduled = !auth.queued.is_empty();
            auth.scheduled
        };
        if more {
            s.auth.lock().unwrap().ready.push_back(next);
        }
    }
}

/// The next peer to serve; `None` once there is none, the worker then
/// counted out -- under the same lock that queues work, so no peer is
/// queued with no worker left to see it.
fn next_auth(server: &Weak<Server>) -> Option<Weak<PeerEntry>> {
    let s = live(server)?;
    let mut pool = s.auth.lock().unwrap();
    let next = pool.ready.pop_front();
    if next.is_none() {
        pool.workers -= 1;
    }
    next
}

/// Counts an auth worker out should it unwind (a callback panicking in
/// apply): otherwise the pool would shrink for good.
struct WorkerCount(Weak<Server>);

impl Drop for WorkerCount {
    fn drop(&mut self) {
        if thread::panicking()
            && let Some(s) = self.0.upgrade()
        {
            let mut pool = s.auth.lock().unwrap_or_else(PoisonError::into_inner);
            pool.workers = pool.workers.saturating_sub(1);
        }
    }
}

/// Run the peer's next authentication: on_auth, then its verdict.
fn run_auth(server: &Weak<Server>, next: &Weak<PeerEntry>) {
    let (Some(s), Some(entry)) = (live(server), next.upgrade()) else {
        return;
    };
    let Some(req) = entry.auth.lock().unwrap().queued.pop_front() else {
        return;
    };
    let removed = entry.link.lock().unwrap().removed;
    if removed || s.with_peer(&entry, |p| p.awaits(&req)) != Some(true) {
        return;
    }
    let on_auth = s.cfg.on_auth.clone();
    let Some(_call) = s.calls.begin(false) else {
        return;
    };
    // Only weak references while on_auth runs: the entry holds a TCP
    // connection's queue, whose writer thread and socket live as long as
    // it does, and a stuck on_auth must not keep a peer that has gone
    // meanwhile. The request carries all on_auth needs.
    drop((s, entry));
    // A panicking on_auth refuses the client, and the worker goes on to
    // the next.
    let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_auth(&req.info)))
        .unwrap_or_else(|_| Err(io::Error::other("on_auth panicked")));
    let (Some(s), Some(entry)) = (live(server), next.upgrade()) else {
        return;
    };
    // A peer dropped meanwhile stays dropped.
    if entry.link.lock().unwrap().removed {
        return;
    }
    if let Some(out) = s.with_peer(&entry, |p| p.complete_auth(&req, verdict)) {
        s.apply(&entry, out);
    }
}

/// An open TCP connection, as the caps count it.
struct TcpConn {
    /// The source it counts against.
    source: std::net::IpAddr,
    /// Its client authenticated: it no longer counts against the
    /// per-source cap.
    authenticated: bool,
    stream: TcpStream,
}

/// A TCP connection's place in `tcp_streams`, given back when dropped.
struct TcpSlot {
    server: Weak<Server>,
    id: u64,
}

impl Drop for TcpSlot {
    fn drop(&mut self) {
        if let Some(s) = self.server.upgrade() {
            s.tcp_streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.id);
        }
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

/// [`read_frame`], all of it by `deadline` (none: a read timeout already
/// set on the stream bounds each read, as for `read_frame`).
fn read_frame_by(
    reader: &mut io::BufReader<TcpStream>,
    deadline: Option<crate::time::Instant>,
) -> Option<Vec<u8>> {
    let Some(deadline) = deadline else {
        return read_frame(reader);
    };
    let mut read_exact = |buf: &mut [u8]| -> Option<()> {
        let mut done = 0;
        while done < buf.len() {
            let left = deadline.saturating_duration_since(crate::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            reader.get_ref().set_read_timeout(Some(left)).ok()?;
            match reader.read(&mut buf[done..]) {
                Ok(0) => return None,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        Some(())
    };
    let mut len_buf = [0u8; 2];
    read_exact(&mut len_buf)?;
    let mut data = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    read_exact(&mut data)?;
    Some(data)
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

    /// Open a session from `c` as a client does: a hard reset, then the ACK
    /// of the server's (stateless) answer. Then repeat the reset, which a
    /// peer holding the session answers with a bare ACK. Returns the
    /// server's session id, and whether a peer answered.
    fn open_udp(c: &UdpSocket, sid: [u8; 8]) -> ([u8; 8], bool) {
        c.send(&client_reset(sid)).unwrap();
        let first = recv_ctrl(c);
        assert_eq!(first.opcode, Opcode::CONTROL_HARD_RESET_SERVER_V2);
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, sid, first.session_id);
        c.send(&ack.to_bytes(&[0])).unwrap();
        c.send(&client_reset(sid)).unwrap();
        let again = recv_ctrl(c);
        (first.session_id, again.opcode == Opcode::ACK_V1)
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
        let (server_sid, served) = open_udp(&c, sid);
        assert!(served);

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

    /// A client's first packet is answered without keeping any state
    /// (OpenVPN 2.6's HMAC session-id cookie): anyone can send one from any
    /// address, so it must cost neither a peer slot nor a TLS connection.
    /// The peer only comes into being once the client proves it received
    /// the answer by echoing our session id -- a forged echo does nothing.
    #[test]
    fn first_packet_is_answered_statelessly() {
        let server = test_server();
        let c = udp_client(&server);
        c.send(&client_reset(*b"CLIENT01")).unwrap();
        let reply = recv_ctrl(&c);
        assert_eq!(reply.opcode, Opcode::CONTROL_HARD_RESET_SERVER_V2);
        assert_eq!(reply.pid, Some(0));
        assert_eq!(reply.acked_pids, vec![0]);
        assert_eq!(reply.remote_id, *b"CLIENT01");
        assert_eq!(server.peers.read().unwrap().len(), 0);

        // An echo of a session id we did not hand out.
        let bogus = ControlPacket::new(Opcode::ACK_V1, 0, *b"CLIENT01", *b"GUESSED!");
        c.send(&bogus.to_bytes(&[0])).unwrap();
        // The same client with a different session id is answered with a
        // different server session id: it cannot reuse the one it got.
        c.send(&client_reset(*b"CLIENT02")).unwrap();
        let other = recv_ctrl(&c);
        assert_ne!(other.session_id, reply.session_id);
        let reuse = ControlPacket::new(Opcode::ACK_V1, 0, *b"CLIENT02", reply.session_id);
        c.send(&reuse.to_bytes(&[0])).unwrap();
        c.send(&client_reset(*b"CLIENT03")).unwrap();
        recv_ctrl(&c);
        assert_eq!(server.peers.read().unwrap().len(), 0);

        // The real echo: the ACK of our reset, naming our session id.
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, *b"CLIENT01", reply.session_id);
        c.send(&ack.to_bytes(&[0])).unwrap();
        c.send(&client_reset(*b"CLIENT04")).unwrap();
        recv_ctrl(&c);
        assert_eq!(server.peers.read().unwrap().len(), 1);
        server.close();
    }

    /// Stateless answers are rate-limited (connect-freq-initial), so the
    /// server cannot be made to reflect a flood of spoofed resets; a client
    /// that completes the handshake gives its answer back to the budget.
    #[test]
    fn stateless_answers_are_rate_limited() {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .connect_freq_initial((2, Duration::from_secs(600)));
        let server = Server::new(cfg).unwrap();
        let answered = |sid: [u8; 8]| {
            let c = udp_client(&server);
            c.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            c.send(&client_reset(sid)).unwrap();
            let mut buf = [0u8; 2048];
            c.recv(&mut buf).is_ok()
        };
        // Kept open: dropped, its port could be handed to a later client
        // below, which would then hear the real peer's retransmissions.
        let real = udp_client(&server);
        assert!(open_udp(&real, *b"REALPEER").1);
        assert!(answered(*b"SPOOF-01"));
        assert!(answered(*b"SPOOF-02"));
        assert!(!answered(*b"SPOOF-03"), "over the limit");
        server.close();
    }

    /// An echo that does not lead to a peer -- the table is full -- gives
    /// nothing back to the budget: replaying it would otherwise refund an
    /// answer each time, and lift the limit on reflected answers.
    #[test]
    fn an_echo_refused_a_peer_is_not_refunded() {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .max_peers(1)
        .connect_freq_initial((2, Duration::from_secs(600)));
        let server = Server::new(cfg).unwrap();
        // Kept open, so its port is not reused by a client below.
        let real = udp_client(&server);
        assert!(open_udp(&real, *b"REALPEER").1);

        // A valid echo, replayed, while the table is full.
        let c = udp_client(&server);
        c.send(&client_reset(*b"REFUSED!")).unwrap();
        let reply = recv_ctrl(&c);
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, *b"REFUSED!", reply.session_id);
        for _ in 0..5 {
            c.send(&ack.to_bytes(&[0])).unwrap();
        }
        let answered = |sid: [u8; 8]| {
            let c = udp_client(&server);
            c.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            c.send(&client_reset(sid)).unwrap();
            let mut buf = [0u8; 2048];
            c.recv(&mut buf).is_ok()
        };
        assert!(answered(*b"SPOOF-01"));
        assert!(!answered(*b"SPOOF-02"), "over the limit");
        assert_eq!(server.peers.read().unwrap().len(), 1);
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
        assert!(open_udp(&c, *b"CLIENT01").1);
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

    /// A connection the acceptor takes as close() runs is refused, not
    /// kept: close() shuts down only the streams it finds.
    #[test]
    fn a_connection_accepted_during_close_is_not_kept() {
        let server = test_server();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (accepted, addr) = l.accept().unwrap();
        server.close();
        server.accept_tcp(&Arc::downgrade(&server), accepted, addr);
        assert!(server.tcp_streams.lock().unwrap().is_empty());
        expect_eof(&mut client);
    }

    /// close() gives the UDP port back, so a new server can bind it right
    /// away, even while the old `Server` is still held.
    #[test]
    fn close_releases_the_udp_port() {
        let server = test_server();
        let addr = server.local_addr().unwrap();
        // A client in flight, so the reader has had work to do.
        let c = udp_client(&server);
        c.send(&client_reset(*b"CLIENT01")).unwrap();
        recv_ctrl(&c);

        server.close();
        UdpSocket::bind(addr).expect("UDP port still bound after close()");
        assert!(server.local_addr().is_err());
        assert!(
            server
                .send_to_peer(&PeerKey::new(c.local_addr().unwrap(), Transport::Udp), b"x")
                .is_err()
        );
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
        let tcp = Some(TcpOut::spawn(s, u64::MAX, None).unwrap());
        let entry = Arc::new(PeerEntry::new(peer, Transport::Tcp, addr, tcp));
        assert!(server.send_raw(&entry, &vec![0u8; 70_000]).is_err());
        server.send_raw(&entry, b"ok").unwrap();
        assert_eq!(tcp_recv(&mut client).unwrap(), b"ok");
        server.close();
    }

    /// Sending to a TCP client that has stopped reading must not block:
    /// the maintenance thread (every peer's timers) and the UDP reader
    /// (through callbacks sending to peers) write to TCP peers too, so one
    /// stalled client would freeze everybody.
    #[test]
    fn a_tcp_client_that_stops_reading_does_not_block_senders() {
        let server = test_server();
        let mut c = tcp_client(&server);
        tcp_send(&mut c, &client_reset(*b"CLIENT01"));
        tcp_recv(&mut c).unwrap();
        let addr = c.local_addr().unwrap();
        let entry = server
            .get_peer(&PeerKey::new(addr, Transport::Tcp))
            .unwrap();

        // Far more than any socket buffers hold, which the client never
        // reads.
        let (tx, rx) = mpsc::channel();
        let s = server.clone();
        thread::spawn(move || {
            let frame = vec![0u8; 60_000];
            for _ in 0..2000 {
                let _ = s.send_raw(&entry, &frame);
            }
            let _ = tx.send(());
        });
        let done = rx.recv_timeout(Duration::from_secs(10));
        server.close();
        assert!(done.is_ok(), "send_raw blocked on a stalled TCP client");
    }

    /// A TCP connection is its own peer: only one connection can hold an
    /// address and port at a time, so a new one from the same address
    /// means any entry still there belongs to a dead connection. It must
    /// not answer through that connection's closed socket.
    #[test]
    fn new_tcp_connection_replaces_a_stale_entry() {
        let server = test_server();
        let mut c = tcp_client(&server);
        let addr = c.local_addr().unwrap();

        // What an earlier connection from the same address left behind.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let _old_client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (old, _) = l.accept().unwrap();
        let old = TcpOut::spawn(old, u64::MAX, None).unwrap();
        old.stream.shutdown(std::net::Shutdown::Both).unwrap();
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("unused")));
        let peer = Peer::new(crate::ovpn::tests::server_config(), [1; 8], on_auth).unwrap();
        let stale = Arc::new(PeerEntry::new(peer, Transport::Tcp, addr, Some(old)));
        server
            .peers
            .write()
            .unwrap()
            .insert(PeerKey::new(addr, Transport::Tcp), stale.clone());

        tcp_send(&mut c, &client_reset(*b"CLIENT01"));
        let reply = tcp_recv(&mut c).expect("the new connection is answered");
        let p = ControlPacket::parse(&reply).unwrap();
        assert_eq!(p.opcode, Opcode::CONTROL_HARD_RESET_SERVER_V2);
        let current = server
            .get_peer(&PeerKey::new(addr, Transport::Tcp))
            .unwrap();
        assert!(!Arc::ptr_eq(&current, &stale));
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

    /// A client that drips its first frame a byte at a time, each well
    /// within the handshake window of the last, still has only the window
    /// to send it all: then its connection is closed, and its place goes
    /// to someone else.
    #[test]
    fn a_slow_first_frame_does_not_hold_a_tcp_connection() {
        let server = server_configured(auth_ok(), |c| {
            c.timers(PeerTimers::default().handshake_window(Duration::from_secs(1)))
                .max_tcp_connections(2)
        });
        let mut drips: Vec<TcpStream> = (0..2).map(|_| tcp_client(&server)).collect();
        for c in &mut drips {
            // The first byte of a length of 0x40xx.
            c.write_all(&[0x40]).unwrap();
        }
        // Drip on, well past the window, noting when the server hangs up.
        let is_closed = |c: &mut TcpStream| {
            // Fails on a socket already shut down, on some platforms.
            if c.set_read_timeout(Some(Duration::from_millis(10))).is_err() {
                return true;
            }
            match c.read(&mut [0u8; 1]) {
                Ok(0) => true,
                Ok(_) => false,
                Err(e) => !matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
            }
        };
        let start = std::time::Instant::now();
        let mut closed = [false; 2];
        while start.elapsed() < Duration::from_secs(4) && closed.contains(&false) {
            thread::sleep(Duration::from_millis(300));
            for (c, closed) in drips.iter_mut().zip(&mut closed) {
                *closed = *closed || c.write_all(&[0]).is_err() || is_closed(c);
            }
        }
        assert_eq!(closed, [true; 2], "a dripping connection was kept");
        assert!(wait_for(|| server.tcp_streams.lock().unwrap().is_empty()));
        let mut late = tcp_client(&server);
        tcp_send(&mut late, &client_reset(*b"LATECOME"));
        tcp_recv(&mut late).expect("a place freed up");
        server.close();
    }

    /// One source gets at most max_tcp_connections_per_source of the TCP
    /// connections.
    #[test]
    fn tcp_connections_are_capped_per_source() {
        let server = server_configured(auth_ok(), |c| c.max_tcp_connections_per_source(2));
        // All kept open for the whole test.
        let mut conns: Vec<TcpStream> = (0..3).map(|_| tcp_client(&server)).collect();
        for (i, c) in conns.iter_mut().take(2).enumerate() {
            tcp_send(c, &client_reset([b'A' + i as u8; 8]));
            tcp_recv(c).expect("served");
        }
        let mut b = [0u8; 1];
        match conns[2].read(&mut b) {
            Ok(0) => {}
            Err(e)
                if !matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            other => panic!("third connection must be refused, got {other:?}"),
        }
        server.close();
    }

    /// The per-source cap is on connections still handshaking: clients
    /// that authenticated leave their places to the next from the same
    /// source (a NAT gateway, say), which the total cap still bounds.
    #[test]
    fn authenticated_tcp_connections_leave_the_per_source_cap() {
        let server = server_configured(auth_ok(), |c| c.max_tcp_connections_per_source(2));
        // All kept open for the whole test.
        let mut clients = [TestClient::new(*b"CLIENT-A"), TestClient::new(*b"CLIENT-B")];
        let conns: Vec<TcpStream> = clients
            .iter_mut()
            .map(|c| connect_tcp(&server, c))
            .collect();
        let mut third = tcp_client(&server);
        tcp_send(&mut third, &client_reset(*b"CLIENT-C"));
        tcp_recv(&mut third).expect("a third client from the source is served");
        assert_eq!(conns.len(), 2);
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

    /// A callback that panics is contained: on_data runs on the UDP
    /// reader, which serves every client, and must not take it down.
    #[test]
    fn a_panicking_callback_does_not_stop_the_server() {
        let on_auth: OnAuth = Arc::new(|_| {
            Ok(PeerConfig::new(
                "10.8.0.2".parse().unwrap(),
                "10.8.0.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                24,
            ))
        });
        let on_data: OnData = Arc::new(|_, _, payload| {
            if payload == b"boom" {
                panic!("on_data panics (expected by this test)");
            }
        });
        let on_connect: OnConnect = Arc::new(|_, _| panic!("on_connect panics (expected)"));
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .on_connect(on_connect);
        let server = Server::new(cfg).unwrap();

        let sock = udp_client(&server);
        let mut client = TestClient::new(*b"CLIENTID");
        let (keys, _) = connect_udp(&sock, &mut client);
        let pkt = crate::ovpn::data::encrypt(
            &crate::ovpn::tests::gcm_opts(),
            &keys,
            0,
            1,
            b"boom",
            |b| {
                b.fill(0);
                Ok(())
            },
        )
        .unwrap();
        sock.send(&pkt).unwrap();

        // Another client is still served.
        let other = udp_client(&server);
        let (_, held) = open_udp(&other, *b"OTHERCID");
        assert!(held, "the UDP service died with the callback");
        assert_eq!(server.peers.read().unwrap().len(), 2);
        server.close();
    }

    /// on_auth may be slow -- an auth backend round trip -- and may call
    /// back into the server: it runs without the peer's lock and off the
    /// UDP reader, so neither deadlocks nor stalls other clients (OpenVPN
    /// defers authentication the same way, KS_AUTH_DEFERRED).
    #[test]
    fn slow_on_auth_does_not_stall_the_server() {
        type Slot = Arc<Mutex<Option<(std::sync::Weak<Server>, PeerKey)>>>;
        let slot: Slot = Arc::default();
        let (entered_tx, entered) = mpsc::channel::<()>();
        let (release, release_rx) = mpsc::channel::<()>();
        let entered_tx = Mutex::new(entered_tx);
        let release_rx = Mutex::new(release_rx);
        let on_auth: OnAuth = {
            let slot = slot.clone();
            let ok = auth_ok();
            Arc::new(move |info| {
                let target = slot.lock().unwrap().clone();
                if let Some((w, key)) = target
                    && let Some(s) = w.upgrade()
                {
                    // Not ready to carry data yet, but it must not hang.
                    let _ = s.send_to_peer(&key, b"hello");
                }
                let _ = entered_tx.lock().unwrap().send(());
                let _ = release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10));
                ok(info)
            })
        };
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        );
        let server = Server::new(cfg).unwrap();

        let sock = udp_client(&server);
        let key = PeerKey::new(sock.local_addr().unwrap(), Transport::Udp);
        *slot.lock().unwrap() = Some((Arc::downgrade(&server), key));
        let a = thread::spawn(move || {
            let mut client = TestClient::new(*b"CLIENT-A");
            connect_udp(&sock, &mut client);
        });
        let in_auth = entered.recv_timeout(Duration::from_secs(10));

        // While A's authentication is under way, B is served.
        let b = udp_client(&server);
        b.send(&client_reset(*b"CLIENT-B")).unwrap();
        let mut buf = [0u8; 2048];
        let answered = b.recv(&mut buf);
        let _ = release.send(());
        let _ = a.join();
        server.close();
        assert!(in_auth.is_ok(), "on_auth deadlocked calling send_to_peer");
        assert!(answered.is_ok(), "server stalled while on_auth ran");
    }

    /// Start connecting a test client over TCP on a thread of its own; the
    /// returned handle shuts the connection down.
    fn connect_tcp_in_background(server: &Server) -> (TcpStream, thread::JoinHandle<()>) {
        let sock = tcp_client(server);
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let handle = sock.try_clone().unwrap();
        let t = thread::spawn(move || {
            let (mut w, mut r) = (sock.try_clone().unwrap(), sock);
            let mut client = TestClient::new(*b"CLIENTID");
            // The test closes the connection mid-handshake.
            let mut send = |d: &[u8]| {
                let _ = w.write_all(&(d.len() as u16).to_be_bytes());
                let _ = w.write_all(d);
            };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                connect_via(&mut client, &mut send, &mut || tcp_recv(&mut r).ok())
            }));
        });
        (handle, t)
    }

    /// A stuck on_auth must not keep a gone peer alive: once its TCP
    /// connection closes, the entry -- and with it the connection's writer
    /// thread and socket -- goes, verdict or not.
    #[test]
    fn a_stuck_on_auth_does_not_keep_a_removed_peer() {
        let (entered_tx, entered) = mpsc::channel::<()>();
        let (release, release_rx) = mpsc::channel::<()>();
        let entered_tx = Mutex::new(entered_tx);
        let release_rx = Mutex::new(release_rx);
        let ok = auth_ok();
        let on_auth: OnAuth = Arc::new(move |info| {
            let _ = entered_tx.lock().unwrap().send(());
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
            ok(info)
        });
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        );
        let server = Server::new(cfg).unwrap();
        let (sock, client) = connect_tcp_in_background(&server);
        let key = PeerKey::new(sock.local_addr().unwrap(), Transport::Tcp);
        entered
            .recv_timeout(Duration::from_secs(10))
            .expect("on_auth called");
        let entry = Arc::downgrade(&server.get_peer(&key).unwrap());

        sock.shutdown(std::net::Shutdown::Both).unwrap();
        let _ = client.join();
        let mut gone = false;
        for _ in 0..50 {
            if server.get_peer(&key).is_none() && entry.upgrade().is_none() {
                gone = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = release.send(());
        server.close();
        assert!(gone, "the auth thread kept the removed peer alive");
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
        assert!(open_udp(&half, *b"HALFOPEN").1);
        assert_eq!(server.peers.read().unwrap().len(), 2);
        assert_eq!(connects.load(Ordering::SeqCst), 1);

        server.close();
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
    }

    /// An on_auth that holds every call until released, counting them.
    #[derive(Default)]
    struct Gate {
        entered: std::sync::atomic::AtomicUsize,
        released: AtomicBool,
    }

    impl Gate {
        fn on_auth(self: &Arc<Self>) -> OnAuth {
            let gate = self.clone();
            let ok = auth_ok();
            Arc::new(move |info| {
                gate.entered.fetch_add(1, Ordering::SeqCst);
                for _ in 0..1000 {
                    if gate.released.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                ok(info)
            })
        }

        fn entered(&self) -> usize {
            self.entered.load(Ordering::SeqCst)
        }
    }

    /// Drive `client` over `sock` -- which other clients may share -- to
    /// its key exchange, then on for `linger`, or until `stop` holds.
    fn drive_to_auth(
        sock: &UdpSocket,
        client: &mut TestClient,
        linger: Duration,
        stop: &dyn Fn() -> bool,
    ) {
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        sock.send(&client.hard_reset()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut kx_sent: Option<std::time::Instant> = None;
        let mut buf = [0u8; 4096];
        while std::time::Instant::now() < deadline && !stop() {
            let mut out = Vec::new();
            client.pump_tls(&mut out);
            for d in out {
                sock.send(&d).unwrap();
            }
            if kx_sent.is_some_and(|t| t.elapsed() >= linger) {
                break;
            }
            if client.handshake_done() && kx_sent.is_none() {
                crate::ovpn::tests::send_client_key_material(client);
                kx_sent = Some(std::time::Instant::now());
                continue;
            }
            if let Ok(n) = sock.recv(&mut buf)
                && client.owns(&buf[..n])
            {
                for d in client.handle_any(&buf[..n]) {
                    sock.send(&d).unwrap();
                }
            }
        }
        assert!(kx_sent.is_some(), "client did not reach its key exchange");
    }

    fn gated_server(
        gate: &Arc<Gate>,
        connects: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> ServerConfig {
        let on_data: OnData = Arc::new(|_, _, _| {});
        let c = connects.clone();
        ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            gate.on_auth(),
            on_data,
        )
        .on_connect(Arc::new(move |_, _| {
            c.fetch_add(1, Ordering::SeqCst);
        }))
    }

    fn wait_for(cond: impl Fn() -> bool) -> bool {
        for _ in 0..300 {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// on_auth calls are bounded: clients authenticating while
    /// max_auth_threads calls are already running wait their turn, rather
    /// than each costing another thread for as long as the auth backend
    /// takes.
    #[test]
    fn concurrent_on_auth_calls_are_capped() {
        let gate = Arc::new(Gate::default());
        let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = Server::new(gated_server(&gate, &connects).max_auth_threads(1)).unwrap();
        let a = udp_client(&server);
        drive_to_auth(
            &a,
            &mut TestClient::new(*b"CLIENT-A"),
            Duration::ZERO,
            &|| gate.entered() >= 1,
        );
        assert!(wait_for(|| gate.entered() == 1));
        let b = udp_client(&server);
        drive_to_auth(
            &b,
            &mut TestClient::new(*b"CLIENT-B"),
            Duration::from_millis(500),
            &|| gate.entered() >= 2,
        );
        let concurrent = gate.entered();
        gate.released.store(true, Ordering::SeqCst);
        // B's turn comes once A's call returns.
        let both = wait_for(|| connects.load(Ordering::SeqCst) == 2);
        server.close();
        assert_eq!(concurrent, 1, "a second on_auth ran past the cap");
        assert!(both, "a waiting client was never authenticated");
    }

    /// A client that restarts -- a fresh session id from the same address
    /// -- while its on_auth is stuck does not get another on_auth running
    /// beside it: its authentications run one at a time, so restarting
    /// cannot multiply them.
    #[test]
    fn a_peer_has_one_on_auth_running_at_a_time() {
        let gate = Arc::new(Gate::default());
        let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = Server::new(gated_server(&gate, &connects)).unwrap();
        let sock = udp_client(&server);
        drive_to_auth(
            &sock,
            &mut TestClient::new(*b"SESSION1"),
            Duration::ZERO,
            &|| gate.entered() >= 1,
        );
        assert!(wait_for(|| gate.entered() == 1));
        drive_to_auth(
            &sock,
            &mut TestClient::new(*b"SESSION2"),
            Duration::from_millis(500),
            &|| gate.entered() >= 2,
        );
        let concurrent = gate.entered();
        gate.released.store(true, Ordering::SeqCst);
        // The restarted session is authenticated once the first call
        // returns; the first session's verdict has nothing left to apply to.
        let connected = wait_for(|| connects.load(Ordering::SeqCst) == 1);
        server.close();
        assert_eq!(concurrent, 1, "a second on_auth ran for the same peer");
        assert!(connected, "the restarted session was never authenticated");
    }

    type Events = Arc<Mutex<Vec<&'static str>>>;

    /// A server recording its on_connect / on_disconnect calls; `during`
    /// runs inside on_connect.
    fn recording_server(
        events: &Events,
        during: impl Fn(PeerKey) + Send + Sync + 'static,
    ) -> Arc<Server> {
        let on_data: OnData = Arc::new(|_, _, _| {});
        let (c, d) = (events.clone(), events.clone());
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            auth_ok(),
            on_data,
        )
        .on_connect(Arc::new(move |key, _| {
            c.lock().unwrap().push("connect");
            during(key);
        }))
        .on_disconnect(Arc::new(move |_| d.lock().unwrap().push("disconnect")));
        Server::new(cfg).unwrap()
    }

    fn connected_output() -> PeerOutput {
        PeerOutput {
            connected: Some(PeerConfig::new(
                "10.8.0.2".parse().unwrap(),
                "10.8.0.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                24,
            )),
            ..PeerOutput::default()
        }
    }

    /// A verdict can arrive for a peer removed meanwhile (its handshake
    /// window ran out, close() ran): it must not be reported connected,
    /// as nothing would ever report it gone.
    #[test]
    fn a_removed_peer_is_not_reported_connected() {
        let events = Events::default();
        let server = recording_server(&events, |_| {});
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let entry = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        server.remove_entry(&entry);
        server.apply(&entry, connected_output());
        server.close();
        assert_eq!(*events.lock().unwrap(), Vec::<&str>::new());
    }

    /// A peer removed while its on_connect runs is reported gone once
    /// that returns, not before: the callbacks pair, in order.
    #[test]
    fn a_peer_removed_during_on_connect_is_reported_after_it() {
        let events = Events::default();
        let slot: Arc<Mutex<std::sync::Weak<Server>>> = Arc::default();
        let s2 = slot.clone();
        let e2 = events.clone();
        let server = recording_server(&events, move |key| {
            let s = s2.lock().unwrap().upgrade().unwrap();
            let entry = s.get_peer(&key).unwrap();
            s.remove_entry(&entry);
            e2.lock().unwrap().push("removed");
        });
        *slot.lock().unwrap() = Arc::downgrade(&server);
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let entry = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        server.apply(&entry, connected_output());
        server.close();
        assert_eq!(
            *events.lock().unwrap(),
            vec!["connect", "removed", "disconnect"]
        );
    }

    /// A client reconnecting from the same address while its old session's
    /// on_connect is still running (a slow one, on an auth worker): the old
    /// session's on_disconnect comes before the new one's on_connect, not
    /// after it -- a caller keeping state per key would otherwise drop the
    /// new session's on the late disconnect.
    #[test]
    fn a_key_is_reported_gone_before_its_next_session_connects() {
        let events = Events::default();
        let (entered_tx, entered) = mpsc::channel::<()>();
        let (release, release_rx) = mpsc::channel::<()>();
        let (entered_tx, release_rx) = (Mutex::new(entered_tx), Mutex::new(release_rx));
        let first = AtomicBool::new(true);
        let server = recording_server(&events, move |_| {
            if first.swap(false, Ordering::SeqCst) {
                let _ = entered_tx.lock().unwrap().send(());
                let _ = release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5));
            }
        });
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let old = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        let (s, e) = (server.clone(), old.clone());
        let slow = thread::spawn(move || s.apply(&e, connected_output()));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        server.remove_entry(&old);
        let new = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        server.apply(&new, connected_output());
        release.send(()).unwrap();
        slow.join().unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            vec!["connect", "disconnect", "connect"]
        );
        server.close();
        assert_eq!(
            *events.lock().unwrap(),
            vec!["connect", "disconnect", "connect", "disconnect"]
        );
    }

    /// A new session for a key can authenticate the moment the old one is
    /// out of the table. The old one's on_disconnect is queued with its
    /// removal, so it still comes first.
    #[test]
    fn a_removed_session_is_reported_gone_before_its_successor_connects() {
        let events = Events::default();
        let server = recording_server(&events, |_| {});
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let old = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        server.apply(&old, connected_output());
        AFTER_UNLINK.with(|h| {
            h.set(Some(|s, key| {
                let addr = "127.0.0.1:9".parse().unwrap();
                let new = s
                    .create_peer(key, Transport::Udp, addr, None, None)
                    .unwrap();
                s.apply(&new, connected_output());
            }))
        });
        server.remove_entry(&old);
        AFTER_UNLINK.with(|h| h.set(None));
        assert_eq!(
            *events.lock().unwrap(),
            vec!["connect", "disconnect", "connect"]
        );
        server.close();
    }

    /// close() waits for an on_connect running on another thread, and
    /// makes that peer's on_disconnect before returning: a caller tearing
    /// down what the callbacks set up once close() returns finds nothing
    /// still arriving.
    #[test]
    fn close_waits_for_a_running_on_connect() {
        let events = Events::default();
        let (entered_tx, entered) = mpsc::channel::<()>();
        let entered_tx = Mutex::new(entered_tx);
        let server = recording_server(&events, move |_| {
            let _ = entered_tx.lock().unwrap().send(());
            thread::sleep(Duration::from_millis(300));
        });
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let entry = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        let (s, e) = (server.clone(), entry.clone());
        let t = thread::spawn(move || s.apply(&e, connected_output()));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        server.close();
        let at_close = events.lock().unwrap().clone();
        t.join().unwrap();
        assert_eq!(at_close, vec!["connect", "disconnect"]);
    }

    /// Nothing reaches on_data once close() has returned.
    #[test]
    fn no_data_is_delivered_after_close() {
        let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let d = delivered.clone();
        let on_data: OnData = Arc::new(move |_, _, _| {
            d.fetch_add(1, Ordering::SeqCst);
        });
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            auth_ok(),
            on_data,
        );
        let server = Server::new(cfg).unwrap();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let entry = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        let data = || PeerOutput {
            deliver: Some(vec![0x45; 20]),
            ..PeerOutput::default()
        };
        server.apply(&entry, data());
        assert_eq!(delivered.load(Ordering::SeqCst), 1);
        // A connection thread still dispatching what it read before
        // close() shut it down.
        server.close();
        server.apply(&entry, data());
        assert_eq!(delivered.load(Ordering::SeqCst), 1);
    }

    /// close() waits for an on_auth under way, so that no verdict of the
    /// auth backend lands after it returned.
    #[test]
    fn close_waits_for_a_running_on_auth() {
        let entered = Arc::new(AtomicBool::new(false));
        let returned = Arc::new(AtomicBool::new(false));
        let (e, r) = (entered.clone(), returned.clone());
        let ok = auth_ok();
        let on_auth: OnAuth = Arc::new(move |info| {
            e.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(300));
            r.store(true, Ordering::SeqCst);
            ok(info)
        });
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        );
        let server = Server::new(cfg).unwrap();
        let sock = udp_client(&server);
        drive_to_auth(
            &sock,
            &mut TestClient::new(*b"CLIENTID"),
            Duration::ZERO,
            &|| entered.load(Ordering::SeqCst),
        );
        assert!(wait_for(|| entered.load(Ordering::SeqCst)));
        server.close();
        assert!(
            returned.load(Ordering::SeqCst),
            "close() returned during on_auth"
        );
    }

    /// close() called from a callback does not wait for that callback --
    /// it would wait for itself -- and the peer the callback is for is
    /// still reported gone, once the callback returns.
    #[test]
    fn close_from_a_callback_does_not_wait_for_it() {
        let events = Events::default();
        let slot: Arc<Mutex<Weak<Server>>> = Arc::default();
        let s2 = slot.clone();
        let server = recording_server(&events, move |_| {
            if let Some(s) = s2.lock().unwrap().upgrade() {
                s.close();
            }
        });
        *slot.lock().unwrap() = Arc::downgrade(&server);
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let entry = server
            .create_peer(key, Transport::Udp, addr, None, None)
            .unwrap();
        let start = std::time::Instant::now();
        server.apply(&entry, connected_output());
        assert!(
            start.elapsed() < CALL_EXIT_WAIT,
            "close() waited for itself"
        );
        assert_eq!(*events.lock().unwrap(), vec!["connect", "disconnect"]);
    }

    fn auth_ok() -> OnAuth {
        Arc::new(|_| {
            Ok(PeerConfig::new(
                "10.8.0.2".parse().unwrap(),
                "10.8.0.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
                24,
            ))
        })
    }

    /// Connect a test client to `server` over TCP.
    fn connect_tcp(server: &Server, client: &mut TestClient) -> TcpStream {
        let sock = tcp_client(server);
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let (mut w, mut r) = (sock.try_clone().unwrap(), sock.try_clone().unwrap());
        connect_via(client, &mut |d| tcp_send(&mut w, d), &mut || {
            tcp_recv(&mut r).ok()
        });
        sock
    }

    /// With keepalive disabled (a zero timeout, which is documented to
    /// disable it), nothing says when a quiet client is gone: an
    /// authenticated TCP client that just has nothing to send stays
    /// connected, however long the handshake window is.
    #[test]
    fn idle_tcp_client_stays_when_keepalive_is_off() {
        let on_data: OnData = Arc::new(|_, _, _| {});
        let timers = PeerTimers::default()
            .keepalive_interval(Duration::ZERO)
            .keepalive_timeout(Duration::ZERO)
            .handshake_window(Duration::from_secs(1));
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            auth_ok(),
            on_data,
        )
        .timers(timers);
        let server = Server::new(cfg).unwrap();
        let mut client = TestClient::new(*b"CLIENTID");
        let mut sock = connect_tcp(&server, &mut client);
        let key = PeerKey::new(sock.local_addr().unwrap(), Transport::Tcp);

        std::thread::sleep(Duration::from_millis(2500));
        server.send_to_peer(&key, b"still here").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        loop {
            let d = tcp_recv(&mut sock).expect("connection still open");
            if Opcode::from_byte(d[0]).0 == Opcode::DATA_V1 {
                break;
            }
        }
        server.close();
    }

    thread_local! {
        /// Makes create_peer panic while building the peer, on this thread.
        pub(super) static PANIC_BUILDING_PEER: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
        /// Runs in remove_entry once the entry is out of the table and the
        /// table's lock released, on this thread: what another thread may
        /// do right then.
        pub(super) static AFTER_UNLINK: std::cell::Cell<Option<fn(&Server, PeerKey)>> =
            const { std::cell::Cell::new(None) };
    }

    /// Building a peer runs the TLS library on a caller-supplied config; a
    /// panic there must cost that one client only, not poison the peer
    /// table for every other.
    #[test]
    fn a_panic_building_a_peer_does_not_poison_the_table() {
        let server = test_server();
        let key = |port| PeerKey::new(SocketAddr::from(([192, 0, 2, 1], port)), Transport::Udp);
        let create = |port| {
            server.create_peer(
                key(port),
                Transport::Udp,
                key(port).socket_addr(),
                None,
                None,
            )
        };
        PANIC_BUILDING_PEER.with(|p| p.set(true));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| create(1)));
        PANIC_BUILDING_PEER.with(|p| p.set(false));
        assert!(matches!(r, Ok(None)), "the panic escaped");
        assert!(!server.peers.is_poisoned());
        assert!(create(2).is_some());
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
        .max_peers(2)
        .max_unauthenticated_peers(2);
        let server = Server::new(cfg).unwrap();
        let clients: Vec<UdpSocket> = (0..3).map(|_| udp_client(&server)).collect();
        for (i, c) in clients.iter().take(2).enumerate() {
            assert!(open_udp(c, [b'A' + i as u8; 8]).1);
        }
        assert!(
            !open_udp(&clients[2], *b"CCCCCCCC").1,
            "third peer must be refused"
        );
        assert_eq!(server.peers.read().unwrap().len(), 2);
        server.close();
    }

    /// A server whose peers need no authentication to be refused, with
    /// `cfg` applied to its config.
    fn server_configured(
        on_auth: OnAuth,
        cfg: impl FnOnce(ServerConfig) -> ServerConfig,
    ) -> Arc<Server> {
        let on_data: OnData = Arc::new(|_, _, _| {});
        let base = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        );
        Server::new(cfg(base)).unwrap()
    }

    /// Peers that have not authenticated are capped per source address --
    /// one source must not take every place the table has -- and in all,
    /// so clients that did authenticate keep theirs. A client that has
    /// authenticated no longer counts.
    #[test]
    fn unauthenticated_peers_are_capped_per_source_and_in_all() {
        let server = server_configured(auth_ok(), |c| c.max_unauthenticated_peers_per_source(2));
        // All kept open for the whole test, so no port is reused.
        let clients: Vec<UdpSocket> = (0..4).map(|_| udp_client(&server)).collect();
        let mut authed = TestClient::new(*b"AUTHED!!");
        connect_udp(&clients[0], &mut authed);
        assert!(wait_for(|| {
            server
                .peers
                .read()
                .unwrap()
                .values()
                .all(|e| e.authenticated.load(Ordering::Relaxed))
        }));
        assert!(open_udp(&clients[1], *b"PENDING1").1);
        assert!(open_udp(&clients[2], *b"PENDING2").1);
        assert!(
            !open_udp(&clients[3], *b"PENDING3").1,
            "over the per-source cap"
        );
        assert_eq!(server.peers.read().unwrap().len(), 3);
        server.close();

        let server = server_configured(auth_ok(), |c| c.max_peers(10).max_unauthenticated_peers(2));
        let clients: Vec<UdpSocket> = (0..3).map(|_| udp_client(&server)).collect();
        assert!(open_udp(&clients[0], *b"PENDING1").1);
        assert!(open_udp(&clients[1], *b"PENDING2").1);
        assert!(!open_udp(&clients[2], *b"PENDING3").1, "over the total cap");
        server.close();
    }

    /// With a default config, one source cannot fill the table: half of it
    /// is for clients that have not authenticated, and one source gets 16
    /// places of those.
    #[test]
    fn one_source_cannot_fill_the_peer_table() {
        let server = server_configured(auth_ok(), |c| c.max_peers(64));
        let clients: Vec<UdpSocket> = (0..20).map(|_| udp_client(&server)).collect();
        let served = clients
            .iter()
            .enumerate()
            .filter(|(i, c)| {
                open_udp(
                    c,
                    [
                        b'P',
                        b'E',
                        b'E',
                        b'R',
                        b'-',
                        b'0',
                        b'0' + *i as u8 / 10,
                        b'0' + *i as u8 % 10,
                    ],
                )
                .1
            })
            .count();
        assert_eq!(served, 16);
        server.close();
    }

    /// Create a peer for `addr` over UDP, marked authenticated so that the
    /// caps on unauthenticated peers stay out of the way.
    fn create_authenticated(server: &Server, addr: &str) -> bool {
        let addr: SocketAddr = addr.parse().unwrap();
        let key = PeerKey::new(addr, Transport::Udp);
        let entry = server.create_peer(key, Transport::Udp, addr, None, None);
        if let Some(e) = &entry {
            e.authenticated.store(true, Ordering::Relaxed);
        }
        entry.is_some()
    }

    /// connect-freq is off unless configured, as in OpenVPN: one host
    /// opening peers as fast as it can -- all unspoofed, each proving its
    /// address -- must not use up a server-wide budget and so lock out
    /// every other new client.
    #[test]
    fn new_peers_are_not_rate_limited_by_default() {
        let server = test_server();
        for port in 1..=150u16 {
            assert!(
                create_authenticated(&server, &format!("192.0.2.1:{port}")),
                "peer {port} refused"
            );
        }
        assert!(create_authenticated(&server, "192.0.2.2:1"));
        server.close();
    }

    /// Configured, connect-freq limits each source on its own: one using up
    /// its budget does not use up another's.
    #[test]
    fn connect_freq_is_per_source() {
        let server =
            server_configured(auth_ok(), |c| c.connect_freq((2, Duration::from_secs(600))));
        assert!(create_authenticated(&server, "192.0.2.1:1"));
        assert!(create_authenticated(&server, "192.0.2.1:2"));
        assert!(
            !create_authenticated(&server, "192.0.2.1:3"),
            "over the limit"
        );
        // The same /64 is the same source.
        assert!(create_authenticated(&server, "[2001:db8::1]:1"));
        assert!(create_authenticated(&server, "[2001:db8::2]:1"));
        assert!(!create_authenticated(&server, "[2001:db8::3]:1"));
        assert!(
            create_authenticated(&server, "192.0.2.2:1"),
            "another source"
        );
        assert!(create_authenticated(&server, "[2001:db8:0:1::1]:1"));
        server.close();
    }

    /// A client refused for want of room is not charged: connect-freq
    /// counts the peers made.
    #[test]
    fn a_client_refused_a_peer_is_not_charged_connect_freq() {
        let server = server_configured(auth_ok(), |c| {
            c.connect_freq((2, Duration::from_secs(600))).max_peers(1)
        });
        assert!(create_authenticated(&server, "192.0.2.1:1"));
        assert!(!create_authenticated(&server, "192.0.2.1:2"), "table full");
        assert!(!create_authenticated(&server, "192.0.2.1:3"), "table full");
        let first = server
            .get_peer(&PeerKey::new(
                "192.0.2.1:1".parse().unwrap(),
                Transport::Udp,
            ))
            .unwrap();
        server.remove_entry(&first);
        assert!(create_authenticated(&server, "192.0.2.1:4"));
        server.close();
    }

    /// New peers are rate-limited (connect-freq): a client that echoes our
    /// stateless answer gets its answer refunded, so that limit alone does
    /// not bound how fast peers are made.
    #[test]
    fn new_peers_are_rate_limited() {
        let server =
            server_configured(auth_ok(), |c| c.connect_freq((2, Duration::from_secs(600))));
        let clients: Vec<UdpSocket> = (0..3).map(|_| udp_client(&server)).collect();
        assert!(open_udp(&clients[0], *b"CLIENT-1").1);
        assert!(open_udp(&clients[1], *b"CLIENT-2").1);
        assert!(!open_udp(&clients[2], *b"CLIENT-3").1, "over the limit");
        server.close();
    }

    #[test]
    fn sources_are_addresses_or_ipv6_64s() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(source_of(ip("192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(source_of(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(source_of(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
    }

    /// While every auth worker is busy -- a slow on_auth -- peers that come
    /// and go must not pile up in the run queue: only live peers wait there.
    #[test]
    fn the_auth_run_queue_holds_only_live_peers() {
        let server = test_server();
        // As if the one worker allowed were stuck in on_auth.
        let max = server.cfg.max_auth_threads;
        server.auth.lock().unwrap().workers = max;
        let entry = || {
            let peer = Peer::new(
                crate::ovpn::tests::server_config(),
                *b"SERVERID",
                server.cfg.on_auth.clone(),
            )
            .unwrap();
            let addr = "192.0.2.1:1194".parse().unwrap();
            Arc::new(PeerEntry::new(peer, Transport::Udp, addr, None))
        };
        let removed = entry();
        server.mark_removed(&removed);
        server.schedule_auth(&removed);
        for _ in 0..20 {
            server.schedule_auth(&entry());
        }
        let live = entry();
        server.schedule_auth(&live);
        let queued = server.auth.lock().unwrap().ready.len();
        assert_eq!(queued, 1, "dead peers left in the queue");
        let mut pool = server.auth.lock().unwrap();
        pool.workers = 0;
        pool.ready.clear();
        drop(pool);
        server.close();
    }

    fn server_with(timers: PeerTimers) -> Arc<Server> {
        let on_auth: OnAuth = Arc::new(|_| Err(io::Error::other("no auth in this test")));
        let on_data: OnData = Arc::new(|_, _, _| {});
        let cfg = ServerConfig::new(
            crate::ovpn::tests::server_config(),
            "127.0.0.1:0".parse().unwrap(),
            on_auth,
            on_data,
        )
        .timers(timers);
        Server::new(cfg).unwrap()
    }

    /// Timers too long for a deadline to be computed from them mean
    /// "never": they must not panic the threads serving every client.
    #[test]
    fn huge_timers_do_not_stop_the_server() {
        let server = server_with(
            PeerTimers::default()
                .handshake_window(Duration::MAX)
                .keepalive_interval(Duration::MAX)
                .keepalive_timeout(Duration::MAX)
                .renegotiate_interval(Duration::MAX)
                .transition_window(Duration::MAX),
        );
        assert!(open_udp(&udp_client(&server), *b"CLIENT01").1);

        let mut tcp = tcp_client(&server);
        tcp_send(&mut tcp, &client_reset(*b"CLIENT02"));
        let reply = tcp_recv(&mut tcp).expect("TCP client answered");
        assert_eq!(
            ControlPacket::parse(&reply).unwrap().opcode,
            Opcode::CONTROL_HARD_RESET_SERVER_V2
        );

        // Let the maintenance thread tick everyone, then check the UDP
        // reader still serves.
        thread::sleep(Duration::from_millis(1500));
        assert!(open_udp(&udp_client(&server), *b"CLIENT03").1);
        server.close();
    }

    /// A peer whose lock was poisoned -- something panicked holding it --
    /// is dropped; the threads that serve every client carry on.
    #[test]
    fn a_poisoned_peer_is_dropped_and_the_server_survives() {
        let server = server_with(PeerTimers::default());
        let clients = [udp_client(&server), udp_client(&server)];
        assert!(open_udp(&clients[0], *b"CLIENT01").1);
        assert!(open_udp(&clients[1], *b"CLIENT02").1);
        let entries: Vec<Arc<PeerEntry>> = server.peers.read().unwrap().values().cloned().collect();
        for e in &entries {
            let e = e.clone();
            let _ = thread::spawn(move || {
                let _held = e.peer.lock().unwrap();
                panic!("poisoning the peer's lock");
            })
            .join();
        }

        // The maintenance tick meets them...
        server.tick_peers();
        assert_eq!(server.peers.read().unwrap().len(), 0);
        // ...or the UDP reader does, dispatching a datagram to one.
        let e = &entries[1];
        let key = PeerKey::new(e.addr, e.transport);
        server.peers.write().unwrap().insert(key, e.clone());
        server.handle_udp(&client_reset(*b"CLIENT02"), e.addr);
        assert_eq!(server.peers.read().unwrap().len(), 0);
        assert!(open_udp(&udp_client(&server), *b"CLIENT03").1);
        server.close();
    }
}

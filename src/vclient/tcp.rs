//! TCP connections over the virtual network, backed by [`vtcp::Conn`].
//!
//! A [`TcpConn`] is a blocking, `std::net::TcpStream`-flavoured handle. The
//! per-connection state lives in a [`ConnState`] shared with the owning
//! [`Client`](super::Client): inbound IP packets the client receives are
//! demultiplexed to the matching `ConnState`, fed into the `vtcp::Conn`, and
//! the segments the engine emits are wrapped back into IP and pushed out the
//! client's L3 handler. A single tick thread per client drives RTO / keepalive
//! timers for every connection.
//!
//! Without threads (`wasm32`) nothing can block and nothing runs in the
//! background: every handle behaves as if non-blocking, returning
//! [`WouldBlock`](io::ErrorKind::WouldBlock) where it would have waited, and
//! the timers run when the caller invokes [`Client::tick`](super::Client::tick).

use crate::time::Instant;
use crate::vtcp::segment::flags;
use crate::vtcp::{Conn, ConnConfig, segment::Segment};
use crate::{IpPrefix, Packet, Protocol, checksum};
use std::collections::{HashMap, VecDeque};
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// 4-tuple identifying a connection from the client's point of view.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct ConnKey {
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// Shared per-connection state. The `Client` holds an `Arc<ConnState>` in its
/// table; the user holds a [`TcpConn`] wrapping the same `Arc`.
pub(crate) struct ConnState {
    pub key: ConnKey,
    pub local_ip: IpAddr,
    conn: Mutex<Conn>,
    /// Notified whenever the connection's readable/writable/closed status may
    /// have changed (inbound data, state transition).
    signal: Condvar,
    /// Sink for fully-framed IP packets the engine wants to transmit.
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    /// Set once the handshake has completed, so a connection that later
    /// closes is not mistaken for one that was refused.
    connected: AtomicBool,
    /// For a passively opened connection, the listener whose accept queue it
    /// joins when the handshake completes.
    pending_accept: Mutex<Option<Arc<ListenerState>>>,
    /// Why the connection ended, when that was not a clean close: reads
    /// report it instead of an end of stream.
    error: Mutex<Option<io::ErrorKind>>,
}

impl ConnState {
    fn new(
        key: ConnKey,
        local_ip: IpAddr,
        conn: Conn,
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
        pending_accept: Option<Arc<ListenerState>>,
    ) -> Arc<ConnState> {
        Arc::new(ConnState {
            key,
            local_ip,
            conn: Mutex::new(conn),
            signal: Condvar::new(),
            sink,
            connected: AtomicBool::new(false),
            pending_accept: Mutex::new(pending_accept),
            error: Mutex::new(None),
        })
    }

    /// Record why the connection failed; the first reason sticks.
    fn fail(&self, kind: io::ErrorKind) {
        self.error.lock().unwrap().get_or_insert(kind);
    }

    fn wrap_and_send(&self, segments: Vec<Vec<u8>>) {
        for seg in segments {
            let pkt = wrap_segment(self.local_ip, self.key.remote, &seg);
            (self.sink)(&pkt);
        }
    }

    /// For an inbound connection whose handshake has completed, hand it to
    /// its listener. Called after every segment, without the conn lock.
    ///
    /// Returns `false` if the listener could not take the connection (closed,
    /// or its queue full): nobody could ever accept it, so it has been reset
    /// and the caller must drop it from the table.
    fn after_segment(self: &Arc<Self>) -> bool {
        if !self.connected.load(Ordering::Acquire) {
            return true;
        }
        let Some(listener) = self.pending_accept.lock().unwrap().take() else {
            return true;
        };
        // Checked under the queue lock, which `Listener::close` also takes
        // to drain the queue, so nothing is queued on a closed listener.
        let mut q = listener.queue.lock().unwrap();
        if listener.closed.load(Ordering::Acquire) || q.len() >= ACCEPT_QUEUE_CAP {
            drop(q);
            self.abort();
            return false;
        }
        q.push_back(TcpConn::new(self.clone()));
        listener.signal.notify_one();
        true
    }

    /// Send a RST, close, and wake anyone waiting on the connection.
    fn abort(&self) {
        let segs = self.conn.lock().unwrap().abort();
        self.wrap_and_send(segs);
        self.signal.notify_all();
    }
}

/// Whether `state` comes after a FIN of ours, so no data can be sent.
fn closed_for_writing(state: crate::vtcp::State) -> bool {
    use crate::vtcp::State::*;
    matches!(state, FinWait1 | FinWait2 | Closing | LastAck | TimeWait)
}

/// Whether a handle may wait. On targets without threads nothing could ever
/// wake it, so it never does.
#[inline]
fn may_block(nonblocking: &AtomicBool) -> bool {
    !cfg!(target_family = "wasm") && !nonblocking.load(Ordering::Relaxed)
}

fn would_block(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, what)
}

/// A TCP stream over the virtual network, blocking by default.
///
/// Dropping the handle initiates a graceful close.
pub struct TcpConn {
    state: Arc<ConnState>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    nonblocking: AtomicBool,
}

impl core::fmt::Debug for TcpConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("vclient::TcpConn")
            .field("key", &self.state.key)
            .finish()
    }
}

impl TcpConn {
    pub(crate) fn new(state: Arc<ConnState>) -> TcpConn {
        TcpConn {
            state,
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            nonblocking: AtomicBool::new(false),
        }
    }

    /// Local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.local_ip, self.state.key.local_port)
    }

    /// Remote socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.key.remote, self.state.key.remote_port)
    }

    /// Set a read timeout. `None` blocks indefinitely.
    pub fn set_read_timeout(&self, t: Option<Duration>) {
        *self.read_timeout.lock().unwrap() = t;
    }

    /// Set a write timeout: how long a blocking [`write`](Self::write) waits
    /// for the peer to open its window. `None` waits indefinitely.
    pub fn set_write_timeout(&self, t: Option<Duration>) {
        *self.write_timeout.lock().unwrap() = t;
    }

    /// Switch between blocking and non-blocking mode, as
    /// [`std::net::TcpStream::set_nonblocking`]. In non-blocking mode
    /// [`read`](Self::read) and [`write`](Self::write) return
    /// [`WouldBlock`](io::ErrorKind::WouldBlock) instead of waiting. On
    /// `wasm32` the handle never waits, whatever this is set to.
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    /// Check on a connection opened with
    /// [`Client::dial_tcp_nonblocking`](super::Client::dial_tcp_nonblocking):
    /// `Ok(true)` once the handshake has completed, `Ok(false)` while it is
    /// still in progress, and `ConnectionRefused` if it failed.
    pub fn poll_connect(&self) -> io::Result<bool> {
        if self.state.connected.load(Ordering::Acquire) {
            return Ok(true);
        }
        if self.state.conn.lock().unwrap().is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection reset during handshake",
            ));
        }
        Ok(false)
    }

    /// Write `buf`. In blocking mode this waits until the engine has accepted
    /// all of it and returns `buf.len()`; in non-blocking mode it takes what
    /// the send buffer has room for, and returns
    /// [`WouldBlock`](io::ErrorKind::WouldBlock) if that is nothing (including
    /// while the handshake is still in progress). A blocking write that hits
    /// the [write timeout](Self::set_write_timeout) returns what it had
    /// written, or `WouldBlock` if nothing.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let deadline = self
            .write_timeout
            .lock()
            .unwrap()
            .map(|t| Instant::now() + t);
        let mut written = 0;
        while written < buf.len() {
            let mut conn = self.state.conn.lock().unwrap();
            // Past our own FIN the engine takes no more data, and never
            // will: waiting for room would only spin until the timeout.
            if conn.is_closed() || closed_for_writing(conn.state()) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed",
                ));
            }
            let (n, segs) = conn.write(&buf[written..]);
            drop(conn);
            if n > 0 {
                self.state.wrap_and_send(segs);
                written += n;
            } else if !may_block(&self.nonblocking) || deadline.is_some_and(|d| Instant::now() >= d)
            {
                break;
            } else {
                // Send window full — wait for an ACK to open it.
                let conn = self.state.conn.lock().unwrap();
                let _ = self
                    .state
                    .signal
                    .wait_timeout(conn, Duration::from_millis(100))
                    .unwrap();
            }
        }
        if written == 0 && !buf.is_empty() {
            return Err(would_block("send buffer full"));
        }
        Ok(written)
    }

    /// Read into `buf`, blocking until data is available or the peer closes.
    /// Returns 0 at end of stream. In non-blocking mode, returns
    /// [`WouldBlock`](io::ErrorKind::WouldBlock) when nothing is buffered.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self
            .read_timeout
            .lock()
            .unwrap()
            .map(|t| Instant::now() + t);
        let mut conn = self.state.conn.lock().unwrap();
        loop {
            let n = conn.read(buf);
            if n > 0 {
                // Reading can open the receive window; tell the peer now
                // rather than on the next tick, which on wasm is whenever
                // the caller gets round to it.
                let segs = conn.take_outgoing();
                drop(conn);
                self.state.wrap_and_send(segs);
                return Ok(n);
            }
            if conn.fin_received() || conn.is_closed() {
                if let Some(kind) = *self.state.error.lock().unwrap() {
                    return Err(io::Error::new(kind, "connection failed"));
                }
                return Ok(0); // clean EOF
            }
            if !may_block(&self.nonblocking) {
                return Err(would_block("no data buffered"));
            }
            // Block until inbound data arrives or we time out.
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Err(would_block("read timeout"));
                    }
                    let (c, _) = self.state.signal.wait_timeout(conn, d - now).unwrap();
                    conn = c;
                }
                None => {
                    conn = self.state.signal.wait(conn).unwrap();
                }
            }
        }
    }

    /// Initiate a graceful close (sends FIN).
    pub fn close(&self) -> io::Result<()> {
        let mut conn = self.state.conn.lock().unwrap();
        let segs = conn.close();
        drop(conn);
        self.state.wrap_and_send(segs);
        Ok(())
    }
}

impl io::Read for TcpConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TcpConn::read(self, buf)
    }
}

impl io::Write for TcpConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TcpConn::write(self, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Shared state for a listening socket: an accept queue fed by the stack's
/// inbound dispatcher when a SYN completes its handshake.
pub(crate) struct ListenerState {
    local_ip: IpAddr,
    local_port: u16,
    queue: Mutex<VecDeque<TcpConn>>,
    signal: Condvar,
    closed: AtomicBool,
}

const ACCEPT_QUEUE_CAP: usize = 128;

/// Connections a listener holds in SYN-RECEIVED at once, as a listen
/// backlog bounds them: each SYN would otherwise mint a connection that
/// lives until its SYN-ACKs give up.
const HALF_OPEN_CAP: usize = 128;

impl ListenerState {
    /// Mark closed, reset what was waiting to be accepted, and wake `accept`.
    fn shut(&self) {
        let pending: Vec<TcpConn> = {
            let mut q = self.queue.lock().unwrap();
            self.closed.store(true, Ordering::Release);
            q.drain(..).collect()
        };
        // Connections nobody will accept now: reset them rather than leave
        // the peer talking to no one.
        for c in pending {
            c.state.abort();
        }
        self.signal.notify_all();
    }
}

/// A virtual TCP listener. [`accept`](Self::accept) blocks until an inbound
/// connection completes its handshake.
pub struct Listener {
    state: Arc<ListenerState>,
    stack: std::sync::Weak<TcpStack>,
    nonblocking: AtomicBool,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("vclient::Listener")
            .field("local", &self.local_addr())
            .finish()
    }
}

impl Listener {
    /// The address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.local_ip, self.state.local_port)
    }

    /// Switch between blocking and non-blocking [`accept`](Self::accept). On
    /// `wasm32` accept never waits, whatever this is set to.
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    /// Block until an inbound connection completes its handshake and return
    /// it. In non-blocking mode, returns [`WouldBlock`](io::ErrorKind::WouldBlock)
    /// when none is waiting.
    pub fn accept(&self) -> io::Result<TcpConn> {
        let mut q = self.state.queue.lock().unwrap();
        loop {
            if let Some(conn) = q.pop_front() {
                return Ok(conn);
            }
            if self.state.closed.load(Ordering::Acquire) {
                return Err(io::Error::other("listener closed"));
            }
            if !may_block(&self.nonblocking) {
                return Err(would_block("no pending connection"));
            }
            q = self.state.signal.wait(q).unwrap();
        }
    }

    /// Stop listening. Pending unaccepted connections are reset.
    pub fn close(&self) {
        self.state.shut();
        if let Some(stack) = self.stack.upgrade() {
            let mut listeners = stack.listeners.lock().unwrap();
            // Only our own entry: once closed, the port may belong to a newer
            // listener, which dropping this handle must leave alone.
            if listeners
                .get(&self.state.local_port)
                .is_some_and(|l| Arc::ptr_eq(l, &self.state))
            {
                listeners.remove(&self.state.local_port);
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.close();
    }
}

/// TCP connection table + tick thread owned by a [`Client`](super::Client).
pub(crate) struct TcpStack {
    conns: Mutex<HashMap<ConnKey, Arc<ConnState>>>,
    listeners: Mutex<HashMap<u16, Arc<ListenerState>>>,
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    next_port: Mutex<u16>,
    /// Set by `shutdown`: stops the tick thread and refuses new work.
    stop: Arc<Mutex<bool>>,
}

impl TcpStack {
    pub fn new(sink: Arc<dyn Fn(&[u8]) + Send + Sync>) -> Arc<TcpStack> {
        let stack = Arc::new(TcpStack {
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            sink,
            next_port: Mutex::new(EPHEMERAL_FIRST),
            stop: Arc::new(Mutex::new(false)),
        });
        // Tick thread: drive timers for all connections every 100ms. Without
        // threads the caller drives them through `Client::tick`.
        #[cfg(not(target_family = "wasm"))]
        {
            let weak = Arc::downgrade(&stack);
            let stop = stack.stop.clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                    if *stop.lock().unwrap() {
                        return;
                    }
                    let Some(stack) = weak.upgrade() else { return };
                    stack.tick_all();
                }
            });
        }
        stack
    }

    pub fn tick_all(&self) {
        let conns: Vec<Arc<ConnState>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut dead = Vec::new();
        for cs in conns {
            let mut conn = cs.conn.lock().unwrap();
            let ended = conn.fin_received();
            let segs = conn.tick();
            let closed = conn.is_closed();
            drop(conn);
            if closed && !ended {
                // Retransmissions or keepalives went unanswered.
                cs.fail(io::ErrorKind::TimedOut);
            }
            if !segs.is_empty() {
                cs.wrap_and_send(segs);
            }
            cs.signal.notify_all();
            if closed {
                dead.push(cs.key);
            }
        }
        if !dead.is_empty() {
            let mut map = self.conns.lock().unwrap();
            for k in dead {
                map.remove(&k);
            }
        }
    }

    /// Open a connection and send the SYN, without waiting for the answer.
    pub fn start_dial(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<Arc<ConnState>> {
        self.check_open()?;
        // The port is picked and the connection registered under the one
        // lock, so two dials cannot pick the same 4-tuple.
        let mut conns = self.conns.lock().unwrap();
        let listeners = self.listeners.lock().unwrap();
        let local_port = pick_port(&mut self.next_port.lock().unwrap(), |p| {
            listeners.contains_key(&p)
                || conns.contains_key(&ConnKey {
                    local_port: p,
                    remote: remote.ip(),
                    remote_port: remote.port(),
                })
        })?;
        drop(listeners);
        let mss = if remote.is_ipv6() { 1440 } else { 1460 };
        let cfg = ConnConfig {
            local_addr: Some(SocketAddr::new(local_ip, local_port)),
            remote_addr: Some(remote),
            local_port,
            remote_port: remote.port(),
            mss,
            keepalive: true,
            ..Default::default()
        };
        let conn = Conn::new(cfg);
        let key = ConnKey {
            local_port,
            remote: remote.ip(),
            remote_port: remote.port(),
        };
        let state = ConnState::new(key, local_ip, conn, self.sink.clone(), None);
        conns.insert(key, state.clone());
        drop(conns);

        // Send SYN.
        let segs = {
            let mut conn = state.conn.lock().unwrap();
            conn.connect()
        };
        state.wrap_and_send(segs);
        Ok(state)
    }

    /// Open a connection and hand it back at once, still handshaking.
    pub fn dial_nonblocking(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<TcpConn> {
        let conn = TcpConn::new(self.start_dial(local_ip, remote)?);
        conn.set_nonblocking(true);
        Ok(conn)
    }

    /// Dial a remote endpoint, blocking until the handshake completes or fails.
    #[cfg(not(target_family = "wasm"))]
    pub fn dial(
        &self,
        local_ip: IpAddr,
        remote: SocketAddr,
        connect_timeout: Duration,
    ) -> io::Result<TcpConn> {
        let state = self.start_dial(local_ip, remote)?;
        let key = state.key;

        // Wait for the handshake. The peer may have sent data or even closed
        // by the time we look, so any synchronized state (or a completed
        // handshake since torn down) counts, not just ESTABLISHED.
        let deadline = Instant::now() + connect_timeout;
        let mut conn = state.conn.lock().unwrap();
        loop {
            if state.connected.load(Ordering::Acquire) || conn.state().is_synchronized() {
                return Ok(TcpConn::new(state.clone()));
            }
            if conn.is_closed() {
                drop(conn);
                self.conns.lock().unwrap().remove(&key);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "connection reset during handshake",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                self.conns.lock().unwrap().remove(&key);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
            }
            let (c, _) = state.signal.wait_timeout(conn, deadline - now).unwrap();
            conn = c;
        }
    }

    /// Register a listening socket on `local_ip:port`. Returns a [`Listener`]
    /// whose `accept` yields completed inbound connections.
    pub fn listen(self: &Arc<Self>, local_ip: IpAddr, port: u16) -> io::Result<Listener> {
        self.check_open()?;
        let mut listeners = self.listeners.lock().unwrap();
        if listeners.contains_key(&port) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "port already has a listener",
            ));
        }
        let state = Arc::new(ListenerState {
            local_ip,
            local_port: port,
            queue: Mutex::new(VecDeque::new()),
            signal: Condvar::new(),
            closed: AtomicBool::new(false),
        });
        listeners.insert(port, state.clone());
        Ok(Listener {
            state,
            stack: Arc::downgrade(self),
            nonblocking: AtomicBool::new(false),
        })
    }

    /// Demultiplex an inbound TCP packet to the matching connection, or accept
    /// it against a registered listener if it's an opening SYN.
    /// Returns `true` if the packet was consumed.
    pub fn handle_inbound(self: &Arc<Self>, pkt: &Packet, ours: IpAddr) -> bool {
        if pkt.ip_protocol() != Protocol::TCP {
            return false;
        }
        if *self.stop.lock().unwrap() {
            return true; // closed: nothing here to deliver to
        }
        let (src, dst) = match (pkt.src_addr(), pkt.dst_addr()) {
            (Some(s), Some(d)) => (s, d),
            _ => return false,
        };
        let payload = pkt.payload();
        let seg = match Segment::parse(payload) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Inbound: packet src=remote, dst=us. Key uses remote = src.
        let key = ConnKey {
            local_port: seg.dst_port,
            remote: src,
            remote_port: seg.src_port,
        };

        // Existing connection (dialed or previously accepted)? One in
        // TIME-WAIT gives way to a new connection's SYN on its 4-tuple.
        let mut existing = self.conns.lock().unwrap().get(&key).cloned();
        if existing
            .as_ref()
            .is_some_and(|st| st.conn.lock().unwrap().accepts_new_syn(&seg))
        {
            self.conns.lock().unwrap().remove(&key);
            existing = None;
        }
        if let Some(state) = existing {
            let segs = {
                let mut conn = state.conn.lock().unwrap();
                // Closing marks the FIN as received too, so this tells a
                // stream that had ended from one cut short.
                let ended = conn.fin_received();
                let segs = conn.handle_segment(&seg);
                // Noted under the lock, before sending anything: the reply
                // can loop back through a synchronous link and close the
                // connection before this function returns.
                if conn.state().is_synchronized() {
                    state.connected.store(true, Ordering::Release);
                }
                if seg.has_flag(flags::RST) && conn.is_closed() && !ended {
                    state.fail(io::ErrorKind::ConnectionReset);
                }
                segs
            };
            state.wrap_and_send(segs);
            if !state.after_segment() {
                self.conns.lock().unwrap().remove(&key);
            }
            state.signal.notify_all();
            return true;
        }

        // No connection yet: a bare SYN to a registered listener opens one.
        if seg.has_flag(flags::SYN) && !seg.has_flag(flags::ACK) {
            let listener = self.listeners.lock().unwrap().get(&seg.dst_port).cloned();
            if let Some(listener) = listener {
                // A full backlog drops the SYN, as Linux does: the peer
                // retransmits, and by then a slot may have freed up.
                if self.half_open(&listener) < HALF_OPEN_CAP {
                    self.accept_syn(listener, dst, src, &seg);
                }
                return true;
            }
        }

        // Nothing here for it: say so with a RST (RFC 9293 §3.10.7.1), so
        // a dialer is refused at once and a stale peer stops, but never in
        // answer to a RST, nor for an address that is not ours to speak for.
        if seg.has_flag(flags::RST) || dst != ours || ours.is_unspecified() {
            return false;
        }
        let rst = if seg.has_flag(flags::ACK) {
            Segment {
                src_port: seg.dst_port,
                dst_port: seg.src_port,
                seq: seg.ack,
                flags: flags::RST,
                ..Default::default()
            }
        } else {
            // SEG.LEN counts the SYN and FIN as well as the data.
            let len =
                seg.data_len() + seg.has_flag(flags::SYN) as u32 + seg.has_flag(flags::FIN) as u32;
            Segment {
                src_port: seg.dst_port,
                dst_port: seg.src_port,
                ack: seg.seq.wrapping_add(len),
                flags: flags::RST | flags::ACK,
                ..Default::default()
            }
        };
        (self.sink)(&wrap_segment(dst, src, &rst.marshal()));
        true
    }

    /// Connections `listener` holds whose handshake has not completed.
    fn half_open(&self, listener: &Arc<ListenerState>) -> usize {
        self.conns
            .lock()
            .unwrap()
            .values()
            .filter(|c| {
                !c.connected.load(Ordering::Acquire)
                    && c.pending_accept
                        .lock()
                        .unwrap()
                        .as_ref()
                        .is_some_and(|l| Arc::ptr_eq(l, listener))
            })
            .count()
    }

    /// Passively open a connection for an inbound SYN and send the SYN-ACK.
    /// The connection joins `listener`'s accept queue once the handshake
    /// completes (see [`ConnState::after_segment`]).
    fn accept_syn(
        self: &Arc<Self>,
        listener: Arc<ListenerState>,
        local_ip: IpAddr,
        remote: IpAddr,
        syn: &Segment,
    ) {
        let mss = if remote.is_ipv6() { 1440 } else { 1460 };
        let cfg = ConnConfig {
            local_addr: Some(SocketAddr::new(local_ip, syn.dst_port)),
            remote_addr: Some(SocketAddr::new(remote, syn.src_port)),
            local_port: syn.dst_port,
            remote_port: syn.src_port,
            mss,
            keepalive: true,
            ..Default::default()
        };
        let key = ConnKey {
            local_port: syn.dst_port,
            remote,
            remote_port: syn.src_port,
        };
        let mut conn = Conn::new(cfg);
        let synack = conn.accept_syn(syn);
        let state = ConnState::new(key, local_ip, conn, self.sink.clone(), Some(listener));
        self.conns.lock().unwrap().insert(key, state.clone());
        state.wrap_and_send(synack);
    }

    /// Close everything: listeners stop, connections are reset, and every
    /// waiter wakes with an error. Afterwards nothing new can be opened.
    pub fn shutdown(&self) {
        *self.stop.lock().unwrap() = true;
        let listeners: Vec<_> = self.listeners.lock().unwrap().drain().collect();
        for (_, l) in listeners {
            l.shut();
        }
        let conns: Vec<_> = self.conns.lock().unwrap().drain().collect();
        for (_, c) in conns {
            c.fail(io::ErrorKind::ConnectionAborted);
            c.abort();
        }
    }

    fn check_open(&self) -> io::Result<()> {
        if *self.stop.lock().unwrap() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "client is closed",
            ));
        }
        Ok(())
    }
}

// --- IP framing ------------------------------------------------------------

/// Wrap a marshaled TCP segment in an IPv4 or IPv6 header with a correct TCP
/// checksum.
fn wrap_segment(src: IpAddr, dst: IpAddr, seg: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => wrap_v4(s, d, seg),
        (IpAddr::V6(s), IpAddr::V6(d)) => wrap_v6(s, d, seg),
        // Mismatched families shouldn't happen for a single connection.
        _ => Vec::new(),
    }
}

fn tcp_checksum(src: IpAddr, dst: IpAddr, seg: &[u8]) -> u16 {
    let pseudo = checksum::pseudo_header_checksum(Protocol::TCP, src, dst, seg.len() as u16);
    let body = !checksum::checksum(seg); // raw (un-complemented) sum of the segment
    !checksum::combine_checksums(pseudo, body)
}

fn wrap_v4(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> Vec<u8> {
    let total = 20 + seg.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::TCP.as_u8();
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cs = checksum::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    ip[20..].copy_from_slice(seg);
    // Patch the TCP checksum into the segment region.
    let tcp_cs = tcp_checksum(IpAddr::V4(src), IpAddr::V4(dst), seg);
    ip[20 + 16..20 + 18].copy_from_slice(&tcp_cs.to_be_bytes());
    ip
}

fn wrap_v6(src: Ipv6Addr, dst: Ipv6Addr, seg: &[u8]) -> Vec<u8> {
    let total = 40 + seg.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(seg.len() as u16).to_be_bytes());
    ip[6] = Protocol::TCP.as_u8();
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip[40..].copy_from_slice(seg);
    let tcp_cs = tcp_checksum(IpAddr::V6(src), IpAddr::V6(dst), seg);
    ip[40 + 16..40 + 18].copy_from_slice(&tcp_cs.to_be_bytes());
    ip
}

/// First and last port of the ephemeral range (RFC 6335 dynamic ports).
pub(crate) const EPHEMERAL_FIRST: u16 = 49152;
const EPHEMERAL_LAST: u16 = 65535;

/// Pick the next ephemeral port, starting at `*next`, that `in_use` does not
/// claim. Once the counter wraps, ports still held by live sockets come round
/// again, and reusing one would hijack its connection.
pub(crate) fn pick_port(next: &mut u16, in_use: impl Fn(u16) -> bool) -> io::Result<u16> {
    for _ in EPHEMERAL_FIRST..=EPHEMERAL_LAST {
        let port = *next;
        *next = if port == EPHEMERAL_LAST {
            EPHEMERAL_FIRST
        } else {
            port + 1
        };
        if !in_use(port) {
            return Ok(port);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no free ephemeral port",
    ))
}

/// Compute the local IP for a connection from the client's prefix.
pub(crate) fn local_ip_for(prefix: IpPrefix, remote: IpAddr) -> Option<IpAddr> {
    match (prefix.addr(), remote) {
        (IpAddr::V4(_), IpAddr::V4(_)) if prefix.is_v4() => Some(prefix.addr()),
        (IpAddr::V6(_), IpAddr::V6(_)) if prefix.is_v6() => Some(prefix.addr()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::segment::flags;

    #[test]
    fn wrap_v4_has_valid_ip_checksum() {
        // minimal SYN segment
        let mut seg = vec![0u8; 20];
        seg[12] = 5 << 4;
        seg[13] = flags::SYN;
        let pkt = wrap_v4(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), &seg);
        // IP header checksum should validate (sum over header == 0xFFFF).
        assert_eq!(checksum::checksum(&pkt[..20]), 0);
        assert_eq!(pkt[9], Protocol::TCP.as_u8());
        // TCP checksum field is non-zero now.
        let tcp_cs = u16::from_be_bytes([pkt[20 + 16], pkt[20 + 17]]);
        assert_ne!(tcp_cs, 0);
    }

    #[test]
    fn tcp_checksum_validates_at_receiver() {
        // Build a segment, wrap it, then verify the receiver-side checksum
        // (pseudo-header + full segment including checksum) folds to zero.
        let mut seg = vec![0u8; 24];
        seg[12] = 5 << 4;
        seg[13] = flags::ACK;
        seg[0..2].copy_from_slice(&1234u16.to_be_bytes());
        seg[2..4].copy_from_slice(&80u16.to_be_bytes());
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = wrap_v4(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), &seg);
        let recv_seg = &pkt[20..];
        // Verify: pseudo + full segment (with checksum filled) == 0xFFFF complement 0.
        let pseudo =
            checksum::pseudo_header_checksum(Protocol::TCP, src, dst, recv_seg.len() as u16);
        let body = !checksum::checksum(recv_seg);
        assert_eq!(checksum::combine_checksums(pseudo, body), 0xFFFF);
    }

    #[test]
    fn port_wrap_skips_connections_still_open() {
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(|_b: &[u8]| {});
        let stack = TcpStack::new(sink);
        let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let remote = SocketAddr::from(([10, 0, 0, 1], 80));
        let first = stack.start_dial(local, remote).unwrap();
        *stack.next_port.lock().unwrap() = first.key.local_port;
        let second = stack.start_dial(local, remote).unwrap();
        assert_ne!(second.key.local_port, first.key.local_port);
        let conns = stack.conns.lock().unwrap();
        assert!(Arc::ptr_eq(&conns[&first.key], &first));
        assert!(Arc::ptr_eq(&conns[&second.key], &second));
    }

    fn capturing_stack() -> (Arc<TcpStack>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let o = out.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> =
            Arc::new(move |b: &[u8]| o.lock().unwrap().push(b.to_vec()));
        (TcpStack::new(sink), out)
    }

    const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const US: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn inbound(seg: Segment) -> Vec<u8> {
        wrap_v4(PEER, US, &seg.marshal())
    }

    #[test]
    fn segments_to_no_connection_are_reset() {
        let (stack, out) = capturing_stack();
        let seg = |flags, seq, ack| Segment {
            src_port: 4000,
            dst_port: 5555,
            seq,
            ack,
            flags,
            ..Default::default()
        };
        let reply = |pkt: Vec<u8>| {
            out.lock().unwrap().clear();
            stack.handle_inbound(Packet::from_slice(&pkt), IpAddr::V4(US));
            let sent = out.lock().unwrap().clone();
            sent.iter()
                .map(|p| Segment::parse(Packet::from_slice(p).payload()).unwrap())
                .collect::<Vec<_>>()
        };

        // With an ACK: RST numbered from it.
        let r = reply(inbound(seg(flags::ACK, 100, 777)));
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].flags, r[0].seq), (flags::RST, 777));
        assert_eq!((r[0].src_port, r[0].dst_port), (5555, 4000));

        // A SYN to a port nobody listens on: RST+ACK of the SYN.
        let r = reply(inbound(seg(flags::SYN, 100, 0)));
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].flags, r[0].ack), (flags::RST | flags::ACK, 101));

        // Never a RST for a RST, nor on behalf of another address.
        assert!(reply(inbound(seg(flags::RST, 100, 0))).is_empty());
        let elsewhere = wrap_v4(
            PEER,
            Ipv4Addr::new(10, 0, 0, 9),
            &seg(flags::ACK, 1, 1).marshal(),
        );
        assert!(reply(elsewhere).is_empty());
    }

    #[test]
    fn half_open_connections_per_listener_are_capped() {
        let (stack, _out) = capturing_stack();
        let _listener = stack.listen(IpAddr::V4(US), 80).unwrap();
        for port in 0..(HALF_OPEN_CAP as u16 + 50) {
            let syn = Segment {
                src_port: 10000 + port,
                dst_port: 80,
                seq: 1,
                flags: flags::SYN,
                ..Default::default()
            };
            stack.handle_inbound(Packet::from_slice(&inbound(syn)), IpAddr::V4(US));
        }
        assert_eq!(stack.conns.lock().unwrap().len(), HALF_OPEN_CAP);
    }

    #[test]
    fn pick_port_wraps_and_reports_exhaustion() {
        let mut next = EPHEMERAL_LAST;
        assert_eq!(pick_port(&mut next, |_| false).unwrap(), EPHEMERAL_LAST);
        assert_eq!(next, EPHEMERAL_FIRST);
        assert_eq!(
            pick_port(&mut next, |_| true).unwrap_err().kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }
}

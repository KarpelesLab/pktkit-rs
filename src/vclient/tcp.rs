//! TCP connections over the virtual network, backed by [`vtcp::Conn`].
//!
//! A [`TcpConn`] is a blocking, `std::net::TcpStream`-flavoured handle. The
//! per-connection state lives in a [`ConnState`] shared with the owning
//! [`Client`](super::Client): inbound IP packets the client receives are
//! demultiplexed to the matching `ConnState`, fed into the `vtcp::Conn`, and
//! the segments the engine emits are wrapped back into IP and pushed out the
//! client's L3 handler. A single tick thread per client drives RTO / keepalive
//! timers for every connection, sleeping until the earliest is due.
//!
//! Without threads (`wasm32`) nothing can block and nothing runs in the
//! background: every handle behaves as if non-blocking, returning
//! [`WouldBlock`](io::ErrorKind::WouldBlock) where it would have waited, and
//! the timers run when the caller invokes [`Client::tick`](super::Client::tick),
//! which [`Client::next_timer`](super::Client::next_timer) says when to do.

use crate::time::Instant;
use crate::vtcp::ecn::IpEcn;
use crate::vtcp::fastopen::{self, Gate};
use crate::vtcp::segment::flags;
use crate::vtcp::syncookie::SynCookies;
use crate::vtcp::{Conn, ConnConfig, State, Tuning, segment::Segment};
use crate::{IpPrefix, Packet, Protocol, checksum};
use std::collections::{HashMap, VecDeque};
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[cfg(not(target_family = "wasm"))]
use crate::vtcp::alarm::Alarm;

/// Without threads there is no tick thread to wake: the caller polls
/// [`Client::next_timer`](super::Client::next_timer) instead.
#[cfg(target_family = "wasm")]
#[derive(Debug)]
struct Alarm;

#[cfg(target_family = "wasm")]
impl Alarm {
    fn new() -> Self {
        Alarm
    }
    fn arm(&self, _: Option<Instant>) {}
}

/// Longest the tick thread sleeps: the half-open and TIME-WAIT caps are
/// checked when it wakes, not on a deadline of their own.
#[cfg(not(target_family = "wasm"))]
const HOUSEKEEPING: Duration = Duration::from_millis(100);

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
    /// The stack's tick thread, woken when this connection's next timer
    /// comes due before it would otherwise look.
    alarm: Arc<Alarm>,
    /// Packets on their way to `sink`, in the order the engine made them.
    /// See [`ConnState::queue`].
    outbox: Mutex<Outbox>,
    /// Set once the handshake has completed, so a connection that later
    /// closes is not mistaken for one that was refused.
    connected: AtomicBool,
    /// For a passively opened connection, the listener whose accept queue it
    /// joins when the handshake completes.
    pending_accept: Mutex<Option<PendingAccept>>,
    /// Why the connection ended, when that was not a clean close: reads
    /// report it instead of an end of stream.
    error: Mutex<Option<io::ErrorKind>>,
    /// When the connection was opened: bounds how long a passive one may
    /// sit in SYN-RECEIVED (see [`SYN_RECEIVED_TIMEOUT`]).
    opened: Instant,
    /// For a passively opened connection not yet accepted, what it has
    /// taken of its listener's [`UNACCEPTED_BYTES`] budget.
    charge: Mutex<Option<Charge>>,
    /// When the tick first found the connection in TIME-WAIT: the oldest
    /// go first once there are more than [`MAX_TIME_WAIT`].
    time_wait_since: Mutex<Option<Instant>>,
}

/// A connection's packets waiting for the sink.
#[derive(Default)]
struct Outbox {
    queue: VecDeque<Vec<u8>>,
    /// Someone is sending from `queue`, and will send whatever joins it.
    emitting: bool,
}

impl ConnState {
    fn new(
        key: ConnKey,
        local_ip: IpAddr,
        conn: Conn,
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
        alarm: Arc<Alarm>,
        pending_accept: Option<PendingAccept>,
    ) -> Arc<ConnState> {
        Arc::new(ConnState {
            key,
            local_ip,
            conn: Mutex::new(conn),
            signal: Condvar::new(),
            sink,
            alarm,
            outbox: Mutex::default(),
            connected: AtomicBool::new(false),
            error: Mutex::new(None),
            opened: Instant::now(),
            charge: Mutex::new(pending_accept.as_ref().map(|p| Charge {
                listener: Arc::downgrade(&p.listener),
                bytes: 0,
            })),
            pending_accept: Mutex::new(pending_accept),
            time_wait_since: Mutex::new(None),
        })
    }

    /// Whether `seg`'s data may go into the connection. Once accepted, it
    /// always may: the receive window bounds it. Until then, it counts
    /// against the listener's budget, and data past it is dropped, for the
    /// peer to send again once the application has taken the connection.
    /// Retransmissions are charged again, so this errs towards dropping.
    fn admit(&self, seg: &Segment) -> bool {
        let len = seg.payload.len();
        if len == 0 {
            return true;
        }
        let mut charge = self.charge.lock().unwrap();
        let Some(c) = charge.as_mut() else {
            return true;
        };
        let Some(listener) = c.listener.upgrade() else {
            return true;
        };
        let taken = crate::stats::add_within(&listener.unaccepted_bytes, len, UNACCEPTED_BYTES);
        if taken {
            c.bytes += len;
        }
        taken
    }

    /// Record why the connection failed; the first reason sticks.
    fn fail(&self, kind: io::ErrorKind) {
        self.error.lock().unwrap().get_or_insert(kind);
    }

    /// Put what the engine just produced through `conn` in line to go out.
    /// Call it under the conn lock, before letting go of it, and
    /// [`flush`](Self::flush) once that is released: the order segments
    /// reach the queue is then the order the engine made them in,
    /// whichever threads made them. Whatever made them may also have moved
    /// the connection's next timer, which the tick thread learns here.
    fn queue(&self, conn: &Conn, segments: Vec<Vec<u8>>) {
        self.alarm.arm(conn.next_deadline());
        if segments.is_empty() {
            return;
        }
        // Each goes out with the ECN codepoint the engine asked for.
        let marks = conn.ecn_marks(&segments);
        let mut out = self.outbox.lock().unwrap();
        for (seg, ecn) in segments.iter().zip(marks) {
            let mut pkt = wrap_segment(self.local_ip, self.key.remote, seg);
            if ecn != IpEcn::NOT_ECT {
                crate::packet::set_ip_ecn(&mut pkt, ecn.0);
            }
            out.queue.push_back(pkt);
        }
    }

    /// Send what is queued, unless someone is already at it; they will
    /// send it too, after what was queued before it.
    ///
    /// Over a synchronous link a send runs the peer, whose ACK comes back
    /// on this very stack, into this connection, and opens the window for
    /// more data before the rest of the burst has gone out. Sent there and
    /// then, the new segments would overtake the old ones, and the peer,
    /// seeing holes everywhere, would ACK its way into a retransmission
    /// storm. Here the nested call only queues them, behind the burst, and
    /// the outermost sender goes on to send them in order. It also keeps
    /// such a ping-pong from recursing once per segment.
    fn flush(&self) {
        let mut out = self.outbox.lock().unwrap();
        if out.emitting {
            return;
        }
        out.emitting = true;
        // Unset if the sink panics: the connection must not be left with
        // nobody ever sending again. What it had not sent yet goes out
        // with whatever is sent next.
        struct Unwinding<'a>(&'a Mutex<Outbox>);
        impl Drop for Unwinding<'_> {
            fn drop(&mut self) {
                if let Ok(mut out) = self.0.lock() {
                    out.emitting = false;
                }
            }
        }
        while let Some(pkt) = out.queue.pop_front() {
            drop(out);
            let unwinding = Unwinding(&self.outbox);
            (self.sink)(&pkt);
            std::mem::forget(unwinding);
            out = self.outbox.lock().unwrap();
        }
        // Still under the lock, so nothing can be queued between finding
        // the queue empty and a sender that would then leave it there.
        out.emitting = false;
    }

    /// [`queue`](Self::queue) and [`flush`](Self::flush), for segments
    /// made where no other could be made at the same time.
    fn wrap_and_send(&self, segments: Vec<Vec<u8>>) {
        let conn = self.conn.lock().unwrap();
        self.queue(&conn, segments);
        drop(conn);
        self.flush();
    }

    /// Whether this connection is waiting for its listener, and that
    /// listener's accept queue is full.
    fn accept_queue_full(&self) -> bool {
        self.pending_accept
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|p| p.listener.queue_full())
    }

    /// For an inbound connection whose handshake has completed, hand it to
    /// its listener. Called after every segment, without the conn lock.
    ///
    /// Returns `false` if the listener could not take the connection
    /// because it has closed: nobody could ever accept it, so it has been
    /// reset and the caller must drop it from the table.
    ///
    /// A full queue does not count: the handshake's ACK is not let in while
    /// it is (see `handle_inbound`). Only handshakes completing on several
    /// threads at once can each find the last free place, and they may take
    /// the queue that many past its cap, rather than reset a connection the
    /// application would have accepted.
    fn after_segment(self: &Arc<Self>) -> bool {
        if !self.connected.load(Ordering::Acquire) {
            return true;
        }
        // Dropped on the way out, which frees its half-open slot.
        let Some(pending) = self.pending_accept.lock().unwrap().take() else {
            return true;
        };
        let listener = &pending.listener;
        // Checked under the queue lock, which `Listener::close` also takes
        // to drain the queue, so nothing is queued on a closed listener.
        let mut q = listener.queue.lock().unwrap();
        if listener.closed.load(Ordering::Acquire) {
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
        let mut conn = self.conn.lock().unwrap();
        let segs = conn.abort();
        self.queue(&conn, segs);
        drop(conn);
        self.flush();
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
/// Dropping the handle closes the connection gracefully, unless received
/// data was left unread: then, as a host stack does (RFC 2525 §2.17), the
/// peer gets a reset.
///
/// After the drop nobody is left to read, so the peer is reset if it sends
/// more data, or if it ACKs our FIN but then goes quiet without sending its
/// own for vtcp's FIN-WAIT-2 timeout (60 s; see
/// [`ConnConfig::fin_wait2_timeout`](crate::vtcp::ConnConfig::fin_wait2_timeout)),
/// as Linux does for an orphaned socket. [`close`](Self::close) alone is a
/// half-close: the handle can still read, and the peer may take as long as
/// it likes.
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

    /// Turn the Nagle algorithm off (`true`) or back on, as
    /// [`std::net::TcpStream::set_nodelay`]. With it off, a write shorter
    /// than a segment goes out at once even while earlier data is still
    /// unacknowledged; turning it off also sends whatever it was holding.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        let mut conn = self.state.conn.lock().unwrap();
        let segs = conn.set_nodelay(nodelay);
        self.state.queue(&conn, segs);
        drop(conn);
        self.state.flush();
        Ok(())
    }

    /// Whether the Nagle algorithm is off (see [`set_nodelay`](Self::set_nodelay)).
    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(self.state.conn.lock().unwrap().nodelay())
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
        // A timeout that runs past what an Instant can hold (such as
        // `Duration::MAX`) would panic when added; it is no deadline at all.
        let deadline = self
            .write_timeout
            .lock()
            .unwrap()
            .and_then(|t| Instant::now().checked_add(t));
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
            self.state.queue(&conn, segs);
            drop(conn);
            if n > 0 {
                self.state.flush();
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
    /// Returns 0 at end of stream, and at once for an empty `buf`. In
    /// non-blocking mode, returns [`WouldBlock`](io::ErrorKind::WouldBlock)
    /// when nothing is buffered.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Nothing could fill it, so waiting for data would wait for ever,
        // and `Read` has an empty buffer read return 0.
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = self
            .read_timeout
            .lock()
            .unwrap()
            .and_then(|t| Instant::now().checked_add(t));
        let mut conn = self.state.conn.lock().unwrap();
        loop {
            let n = conn.read(buf);
            if n > 0 {
                // Reading can open the receive window; tell the peer now
                // rather than on the next tick, which on wasm is whenever
                // the caller gets round to it.
                let segs = conn.take_outgoing();
                self.state.queue(&conn, segs);
                drop(conn);
                self.state.flush();
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
        self.state.queue(&conn, segs);
        drop(conn);
        self.state.flush();
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
        // Unlike close() (a half-close: we may still read), dropping the
        // handle means nobody will read or write again. Releasing lets the
        // engine time out a peer that never finishes, and reset one that
        // keeps sending or whose data was left unread, as Linux does for an
        // orphaned socket.
        let mut conn = self.state.conn.lock().unwrap();
        let segs = conn.release();
        self.state.queue(&conn, segs);
        drop(conn);
        self.state.flush();
    }
}

/// Shared state for a listening socket: an accept queue fed by the stack's
/// inbound dispatcher when a SYN completes its handshake.
pub(crate) struct ListenerState {
    /// The client's address, in the cell the client keeps it in. A
    /// listener is bound to the client's own address, whatever that is
    /// when each SYN arrives, not to the one it had when the listener was
    /// opened: after a renumbering (DHCP, `set_addr`) it would otherwise
    /// refuse connections to the new address and answer for the old.
    own: Arc<Mutex<IpPrefix>>,
    local_port: u16,
    queue: Mutex<VecDeque<TcpConn>>,
    signal: Condvar,
    closed: AtomicBool,
    /// Connections to this listener still in SYN-RECEIVED, bounded by
    /// [`HALF_OPEN_CAP`]. Kept as a count because each SYN checks it: walking
    /// the whole connection table instead would make a SYN flood cost time
    /// in proportion to every connection the client holds.
    half_open: AtomicUsize,
    /// Answers SYNs statelessly once the half-open backlog is full.
    cookies: SynCookies,
    /// When the last cookie went out. Only an ACK arriving soon enough after
    /// that is checked for one (as Linux does): otherwise any stray ACK to
    /// the port would be a guess at a 24-bit MAC, and a lucky one would open
    /// a connection nobody asked for.
    cookie_sent: Mutex<Option<Instant>>,
    /// Data held by this listener's connections that have not been
    /// accepted, bounded by [`UNACCEPTED_BYTES`].
    unaccepted_bytes: AtomicUsize,
}

/// What a connection not yet accepted has taken of its listener's
/// [`UNACCEPTED_BYTES`] budget, given back when it is accepted or goes.
/// The listener is held weakly: a queued connection holding it strongly
/// would keep a listener nobody closed alive through its own queue.
struct Charge {
    listener: std::sync::Weak<ListenerState>,
    bytes: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        if let Some(l) = self.listener.upgrade() {
            l.unaccepted_bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

/// A passively opened connection's claim on its listener: the accept queue
/// it joins once its handshake completes and, until then, one of the
/// listener's half-open slots, which dropping this gives back. Dropping it
/// covers every way out of SYN-RECEIVED alike: the handshake completing,
/// the peer resetting, the SYN-ACKs giving up, the client shutting down.
pub(crate) struct PendingAccept {
    listener: Arc<ListenerState>,
    /// False for a connection opened from a SYN cookie, which skipped
    /// SYN-RECEIVED and so never held a slot.
    half_open: bool,
}

impl Drop for PendingAccept {
    fn drop(&mut self) {
        if self.half_open {
            self.listener.half_open.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

const ACCEPT_QUEUE_CAP: usize = 128;

/// Data a listener's connections may hold between them before they are
/// accepted. Each may be sent a full receive window (vtcp's 1 MiB) before
/// the application has so much as seen it, and with 128 queued and 128
/// half open, a peer could park a quarter of a gigabyte on a listener
/// whose application is slow to accept. Past this, their data is dropped
/// until they are accepted; a few connections with a window's worth each
/// still fit.
const UNACCEPTED_BYTES: usize = if cfg!(test) { 64 * 1024 } else { 8 << 20 };

/// Connections a listener holds in SYN-RECEIVED at once, as a listen
/// backlog bounds them: each SYN would otherwise mint a connection that
/// lives until its SYN-ACKs give up.
const HALF_OPEN_CAP: usize = 128;

/// Half-open connections a listener holds counting those rebuilt from a
/// SYN cookie whose ACK came in while the accept queue was full. The
/// backlog is full then (or the SYN would not have had a cookie), mostly
/// with handshakes waiting on the same queue, and without this headroom
/// the cookie's peer would be reset as soon as it sent a second segment.
/// Such a peer has shown it receives at its address, which a SYN flood
/// does not, but a bound is still needed against one that opens and
/// abandons connections on purpose.
const COOKIE_HALF_OPEN_CAP: usize = 2 * HALF_OPEN_CAP;

/// How long a passively opened connection may stay in SYN-RECEIVED. vtcp
/// retransmits a SYN-ACK up to its full retry count, doubling from 1 s to
/// its 60 s ceiling, which holds a half-open slot for about four minutes
/// and sends nine SYN-ACKs to whatever address a SYN claimed to come from:
/// a spoofed SYN flood would lock the listener out and use it as a
/// reflector. 63 s is what Linux's `tcp_synack_retries` default of 5 gives
/// (retransmissions at 1, 3, 7, 15 and 31 s, then one more RTO), so a real
/// peer whose ACKs are being lost still gets as long as it would there.
const SYN_RECEIVED_TIMEOUT: Duration = Duration::from_secs(63);

/// Connections a client keeps in TIME-WAIT. Each holds its table entry
/// for a minute after it closes, and a server that closes first can be
/// made to close them as fast as peers connect; past this the oldest are
/// dropped early, as Linux does past `tcp_max_tw_buckets` (and slirp at the
/// same number). Early is still safe for a later connection on the same
/// 4-tuple: vtcp's ISNs advance with the clock (RFC 6528), so its sequence
/// numbers start beyond anything the old one used, which is what RFC 6191
/// asks of a SYN taking over a 4-tuple from TIME-WAIT.
const MAX_TIME_WAIT: usize = if cfg!(test) { 4 } else { 8192 };

/// How long after the last cookie went out an ACK is still checked for one:
/// a cookie is valid for 64 to 128 s (two counter periods of vtcp's
/// `SynCookies`).
const COOKIE_WINDOW: Duration = Duration::from_secs(128);

impl ListenerState {
    /// Whether a SYN to `dst` is for this listener: only if it is to the
    /// client's address as it is now (`ours`, read from the same cell for
    /// this packet). Anything else would answer for addresses that are not
    /// ours, and hand the application connections it never listened for.
    fn accepts(&self, dst: IpAddr, ours: IpAddr) -> bool {
        dst == ours && !ours.is_unspecified()
    }

    fn local_ip(&self) -> IpAddr {
        self.own.lock().unwrap().addr()
    }

    /// Take a half-open slot for a new connection, if the backlog has one.
    /// Checked and taken in one step, so SYNs racing on several threads
    /// cannot overrun the cap between them.
    fn reserve_half_open(self: &Arc<Self>) -> Option<PendingAccept> {
        self.reserve_half_open_within(HALF_OPEN_CAP)
    }

    /// [`reserve_half_open`](Self::reserve_half_open) up to `cap`.
    fn reserve_half_open_within(self: &Arc<Self>, cap: usize) -> Option<PendingAccept> {
        if !crate::stats::add_within(&self.half_open, 1, cap) {
            return None;
        }
        Some(PendingAccept {
            listener: self.clone(),
            half_open: true,
        })
    }

    /// Whether an ACK arriving now might complete a cookie handshake.
    fn cookies_recent(&self) -> bool {
        self.cookie_sent
            .lock()
            .unwrap()
            .is_some_and(|t| Instant::now().saturating_duration_since(t) < COOKIE_WINDOW)
    }

    fn queue_full(&self) -> bool {
        self.queue.lock().unwrap().len() >= ACCEPT_QUEUE_CAP
    }

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
    /// The address this listener is bound to. For one opened with
    /// [`Client::listen_tcp`](super::Client::listen_tcp), that is the
    /// client's address as it is now.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.local_ip(), self.state.local_port)
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
                // Accepted: its window alone bounds it from now on.
                conn.state.charge.lock().unwrap().take();
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
    /// The link MTU connections size their segments for (see
    /// [`ClientConfig::mtu`](super::ClientConfig::mtu)).
    mtu: u32,
    /// The TCP settings of every connection (see
    /// [`ClientConfig::tcp`](super::ClientConfig::tcp)).
    tuning: Tuning,
    /// Accepted connections with Fast Open data whose handshake has not
    /// completed, bounded as RFC 7413 §5.1 asks.
    fast_open_gate: Arc<Gate>,
    /// Fast Open cookies from the servers dialed, by address.
    fast_open_cache: Mutex<HashMap<IpAddr, FastOpenEntry>>,
    /// Set by `shutdown`: stops the tick thread and refuses new work.
    stop: Arc<Mutex<bool>>,
    /// Wakes the tick thread when a timer comes due.
    alarm: Arc<Alarm>,
}

impl TcpStack {
    #[cfg(test)]
    pub fn new(sink: Arc<dyn Fn(&[u8]) + Send + Sync>) -> Arc<TcpStack> {
        Self::with_config(sink, DEFAULT_MTU, Tuning::default())
    }

    /// A stack whose connections size their segments for a link MTU of
    /// `mtu` bytes, and take `tuning`.
    pub fn with_config(
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
        mtu: u32,
        tuning: Tuning,
    ) -> Arc<TcpStack> {
        let stack = Arc::new(TcpStack {
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            sink,
            next_port: Mutex::new(0),
            mtu,
            tuning,
            fast_open_gate: Gate::new(fastopen::MAX_PENDING),
            fast_open_cache: Mutex::new(HashMap::new()),
            stop: Arc::new(Mutex::new(false)),
            alarm: Arc::new(Alarm::new()),
        });
        // Tick thread: drive the timers of all connections as they come
        // due. Each connection arms the alarm with its next deadline as it
        // is ticked, and again whenever its traffic moves that earlier, so
        // a retransmission or a delayed ACK goes out on time rather than on
        // the next of a fixed interval's polls. Without threads the caller
        // drives them through `Client::tick`.
        #[cfg(not(target_family = "wasm"))]
        {
            let weak = Arc::downgrade(&stack);
            let stop = stack.stop.clone();
            let alarm = stack.alarm.clone();
            std::thread::spawn(move || {
                loop {
                    alarm.sleep_until(Instant::now() + HOUSEKEEPING);
                    if *stop.lock().unwrap() {
                        return;
                    }
                    let Some(stack) = weak.upgrade() else { return };
                    alarm.begin();
                    stack.tick_all();
                }
            });
        }
        stack
    }

    /// When [`tick_all`](Self::tick_all) next has something to do: the
    /// earliest connection timer, or a half-open connection's expiry.
    pub fn next_deadline(&self) -> Option<Instant> {
        let conns: Vec<Arc<ConnState>> = self.conns.lock().unwrap().values().cloned().collect();
        conns
            .iter()
            .filter_map(|cs| {
                let conn = cs.conn.lock().unwrap();
                let expiry = (conn.state() == State::SynReceived)
                    .then(|| cs.opened.checked_add(SYN_RECEIVED_TIMEOUT))
                    .flatten();
                match (conn.next_deadline(), expiry) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                }
            })
            .min()
    }

    pub fn tick_all(&self) {
        self.tick_at(Instant::now());
    }

    /// Run the timers, with `now` deciding which half-open connections have
    /// run out of time (the engine's own timers read the clock themselves).
    fn tick_at(&self, now: Instant) {
        let conns: Vec<Arc<ConnState>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut time_wait = Vec::new();
        for cs in conns {
            let mut conn = cs.conn.lock().unwrap();
            if conn.state() == State::SynReceived
                && now.saturating_duration_since(cs.opened) >= SYN_RECEIVED_TIMEOUT
            {
                // Given up silently, as Linux drops an expired request: a
                // RST would be one more packet to an address that may well
                // be spoofed, and nobody has seen this connection yet,
                // unless it came with Fast Open data: then the application
                // has, and learns why it ended.
                let _ = conn.abort();
                cs.fail(io::ErrorKind::TimedOut);
                drop(conn);
                cs.signal.notify_all();
                self.forget(&cs);
                continue;
            }
            let ended = conn.fin_received();
            let segs = conn.tick();
            cs.queue(&conn, segs);
            let closed = conn.is_closed();
            let state = conn.state();
            if closed && !ended {
                // Retransmissions or keepalives went unanswered. Recorded
                // under the conn lock, as `handle_inbound` records a reset:
                // a reader that took the lock in between would find the
                // connection closed with no error, and report a clean end
                // of stream for one that timed out.
                cs.fail(io::ErrorKind::TimedOut);
            }
            drop(conn);
            cs.flush();
            cs.signal.notify_all();
            if closed {
                self.forget(&cs);
            } else if state == State::TimeWait {
                let since = *cs.time_wait_since.lock().unwrap().get_or_insert(now);
                time_wait.push((since, cs));
            }
        }
        if time_wait.len() > MAX_TIME_WAIT {
            time_wait.sort_by_key(|(since, _)| *since);
            let excess = time_wait.len() - MAX_TIME_WAIT;
            for (_, cs) in time_wait.drain(..excess) {
                // Silently, as TIME-WAIT itself ends: the peer has closed.
                let _ = cs.conn.lock().unwrap().abort();
                self.forget(&cs);
            }
        }
    }

    /// Drop `state` from the table, and only it: by now a newer connection
    /// may hold its 4-tuple, having taken it over from TIME-WAIT.
    fn forget(&self, state: &Arc<ConnState>) {
        let mut conns = self.conns.lock().unwrap();
        if conns.get(&state.key).is_some_and(|c| Arc::ptr_eq(c, state)) {
            conns.remove(&state.key);
        }
        drop(conns);
        // A connection that never completed its handshake gives its
        // half-open slot back now, not whenever the last clone of it goes.
        state.pending_accept.lock().unwrap().take();
        state.charge.lock().unwrap().take();
    }

    /// Open a connection and send the SYN, without waiting for the answer.
    pub fn start_dial(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<Arc<ConnState>> {
        self.start_dial_with(local_ip, remote, None).map(|(s, _)| s)
    }

    /// [`start_dial`](Self::start_dial), and with `data`, and Fast Open
    /// on, the SYN carries what of it the server may take (see
    /// [`Client::dial_tcp_with_data`](super::Client::dial_tcp_with_data)),
    /// or asks for a cookie. Returns how much of `data` the connection
    /// took, the rest being the caller's to write once it is up.
    fn start_dial_with(
        &self,
        local_ip: IpAddr,
        remote: SocketAddr,
        data: Option<&[u8]>,
    ) -> io::Result<(Arc<ConnState>, usize)> {
        // The port is picked and the connection registered under the one
        // lock, so two dials cannot pick the same 4-tuple. `stop` is checked
        // under it too, as `shutdown` drains the table after setting it: a
        // dial checked before the lock could register after the drain and
        // be left open on a stack that will never serve it.
        let mut conns = self.conns.lock().unwrap();
        self.check_open()?;
        let listeners = self.listeners.lock().unwrap();
        let local_port = pick_port(&mut self.next_port.lock().unwrap(), local_ip, remote, |p| {
            listeners.contains_key(&p)
                || conns.contains_key(&ConnKey {
                    local_port: p,
                    remote: remote.ip(),
                    remote_port: remote.port(),
                })
        })?;
        drop(listeners);
        let cfg = ConnConfig {
            local_addr: Some(SocketAddr::new(local_ip, local_port)),
            remote_addr: Some(remote),
            local_port,
            remote_port: remote.port(),
            mss: self.mss_for(remote.ip()),
            keepalive: true,
            ..Default::default()
        };
        let conn = Conn::new(self.tuning.apply(cfg));
        let key = ConnKey {
            local_port,
            remote: remote.ip(),
            remote_port: remote.port(),
        };
        let state = ConnState::new(
            key,
            local_ip,
            conn,
            self.sink.clone(),
            self.alarm.clone(),
            None,
        );
        conns.insert(key, state.clone());
        drop(conns);

        // Send SYN.
        let mut conn = state.conn.lock().unwrap();
        let (taken, segs) = match data.filter(|_| self.tuning.fast_open) {
            Some(data) => {
                let entry = self
                    .fast_open_cache
                    .lock()
                    .unwrap()
                    .get(&remote.ip())
                    .cloned()
                    .unwrap_or_default();
                if entry.resting(Instant::now()) {
                    (0, conn.connect())
                } else {
                    conn.connect_fast_open(entry.cookie.as_deref(), entry.mss, data)
                }
            }
            None => (0, conn.connect()),
        };
        state.queue(&conn, segs);
        drop(conn);
        state.flush();
        Ok((state, taken))
    }

    /// Keep what a Fast Open dial's handshake taught about its server: the
    /// cookie it gave, and whether a SYN with data went unanswered.
    #[cfg(not(target_family = "wasm"))]
    fn learn_fast_open(&self, remote: IpAddr, conn: &Conn) {
        let mut cache = self.fast_open_cache.lock().unwrap();
        if !cache.contains_key(&remote) && cache.len() >= FAST_OPEN_CACHE {
            // Any will do: a server forgotten costs a round trip once.
            if let Some(&k) = cache.keys().next() {
                cache.remove(&k);
            }
        }
        let e = cache.entry(remote).or_default();
        if let Some(c) = conn.fast_open_cookie() {
            e.cookie = Some(c.to_vec());
            e.mss = Some(conn.mss());
        }
        if conn.fast_open_syn_lost() {
            e.syn_losses = e.syn_losses.saturating_add(1);
            e.last_loss = Some(Instant::now());
        } else if conn.state().is_synchronized() {
            e.syn_losses = 0;
        }
    }

    /// Open a connection and hand it back at once, still handshaking.
    pub fn dial_nonblocking(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<TcpConn> {
        let conn = TcpConn::new(self.start_dial(local_ip, remote)?);
        conn.set_nonblocking(true);
        Ok(conn)
    }

    /// Dial a remote endpoint, blocking until the handshake completes or
    /// fails, and write `data` (see [`start_dial`](Self::start_dial)).
    #[cfg(not(target_family = "wasm"))]
    pub fn dial(
        &self,
        local_ip: IpAddr,
        remote: SocketAddr,
        connect_timeout: Duration,
        data: Option<&[u8]>,
    ) -> io::Result<TcpConn> {
        let (state, taken) = self.start_dial_with(local_ip, remote, data)?;
        let conn = self.await_handshake(&state, connect_timeout)?;
        if let Some(data) = data {
            if self.tuning.fast_open {
                self.learn_fast_open(remote.ip(), &state.conn.lock().unwrap());
            }
            let mut rest = &data[taken..];
            while !rest.is_empty() {
                let n = conn.write(rest)?;
                rest = &rest[n..];
            }
        }
        Ok(conn)
    }

    /// Wait for `state`'s handshake, as [`dial`](Self::dial) does.
    #[cfg(not(target_family = "wasm"))]
    fn await_handshake(
        &self,
        state: &Arc<ConnState>,
        connect_timeout: Duration,
    ) -> io::Result<TcpConn> {
        // Wait for the handshake. The peer may have sent data or even closed
        // by the time we look, so any synchronized state (or a completed
        // handshake since torn down) counts, not just ESTABLISHED.
        // No deadline for a timeout past what an Instant can hold: the SYN
        // retransmissions giving up still end the wait.
        let deadline = Instant::now().checked_add(connect_timeout);
        let mut conn = state.conn.lock().unwrap();
        loop {
            if state.connected.load(Ordering::Acquire) || conn.state().is_synchronized() {
                return Ok(TcpConn::new(state.clone()));
            }
            if conn.is_closed() {
                drop(conn);
                self.forget(state);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "connection reset during handshake",
                ));
            }
            let Some(deadline) = deadline else {
                conn = state.signal.wait(conn).unwrap();
                continue;
            };
            let now = Instant::now();
            if now >= deadline {
                drop(conn);
                self.forget(state);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
            }
            let (c, _) = state.signal.wait_timeout(conn, deadline - now).unwrap();
            conn = c;
        }
    }

    /// Register a listening socket on `port` at the client's own address,
    /// kept in `own`. Returns a [`Listener`] whose `accept` yields completed
    /// inbound connections.
    pub fn listen(self: &Arc<Self>, own: Arc<Mutex<IpPrefix>>, port: u16) -> io::Result<Listener> {
        // Under the table lock, which `shutdown` drains after setting
        // `stop`: see `start_dial`.
        let mut listeners = self.listeners.lock().unwrap();
        self.check_open()?;
        if listeners.contains_key(&port) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "port already has a listener",
            ));
        }
        let state = Arc::new(ListenerState {
            own,
            local_port: port,
            queue: Mutex::new(VecDeque::new()),
            signal: Condvar::new(),
            closed: AtomicBool::new(false),
            half_open: AtomicUsize::new(0),
            cookies: SynCookies::new(),
            cookie_sent: Mutex::new(None),
            unaccepted_bytes: AtomicUsize::new(0),
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
        // A segment damaged on the way is dropped unread (RFC 9293 §3.1):
        // what its bits say now may be anything, a RST included.
        if pkt.verify_transport_checksum() != Some(true) {
            return true;
        }
        let payload = pkt.payload();
        let seg = match Segment::parse(payload) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // The congestion marks the network put on it, for the engine.
        let ecn = IpEcn::from_bits(crate::packet::ip_ecn(pkt));
        // Inbound: packet src=remote, dst=us. Key uses remote = src.
        let key = ConnKey {
            local_port: seg.dst_port,
            remote: src,
            remote_port: seg.src_port,
        };

        // Existing connection (dialed or previously accepted)? One in
        // TIME-WAIT gives way to a new connection's SYN on its 4-tuple.
        let mut existing = self.conns.lock().unwrap().get(&key).cloned();
        if let Some(st) = existing.as_ref()
            && st.conn.lock().unwrap().accepts_new_syn(&seg)
        {
            self.forget(st);
            existing = None;
        }
        if let Some(state) = existing {
            {
                let mut conn = state.conn.lock().unwrap();
                // The ACK completing a handshake while the accept queue is
                // full is dropped, and the connection stays in
                // SYN-RECEIVED, as Linux does unless told to abort on
                // overflow: our SYN-ACK is retransmitted, the peer answers
                // it (or resends its data), and the handshake completes
                // once the application has made room. A reset would fail a
                // connection that is merely early; and if the application
                // never makes room, the half-open timeout ends it.
                if conn.state() == State::SynReceived
                    && seg.flags & (flags::ACK | flags::SYN | flags::RST) == flags::ACK
                    && state.accept_queue_full()
                {
                    return true;
                }
                // Closing marks the FIN as received too, so this tells a
                // stream that had ended from one cut short.
                let ended = conn.fin_received();
                let segs = if state.admit(&seg) {
                    conn.handle_segment_ecn(&seg, ecn)
                } else {
                    // Its ACK and window still count; the data, and a FIN
                    // that follows it, the peer sends again.
                    let bare = Segment {
                        payload: Vec::new(),
                        flags: seg.flags & !(flags::FIN | flags::PSH),
                        ..seg.clone()
                    };
                    conn.handle_segment_ecn(&bare, ecn)
                };
                // Noted under the lock, before sending anything: the reply
                // can loop back through a synchronous link and close the
                // connection before this function returns.
                if conn.state().is_synchronized() {
                    state.connected.store(true, Ordering::Release);
                }
                if seg.has_flag(flags::RST) && conn.is_closed() && !ended {
                    state.fail(io::ErrorKind::ConnectionReset);
                }
                state.queue(&conn, segs);
            }
            // The client's sink contains a panicking handler, but a sink
            // that does not must still not cost this connection its accept
            // or its readers their wakeup: settle first, then let it go on.
            let sent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.flush()));
            if !state.after_segment() {
                self.forget(&state);
            }
            state.signal.notify_all();
            if let Err(panic) = sent {
                std::panic::resume_unwind(panic);
            }
            return true;
        }

        // No connection yet: a bare SYN to a registered listener opens one.
        if seg.has_flag(flags::SYN) && !seg.has_flag(flags::ACK) {
            let listener = self
                .listeners
                .lock()
                .unwrap()
                .get(&seg.dst_port)
                .filter(|l| l.accepts(dst, ours))
                .cloned();
            if let Some(listener) = listener {
                if listener.queue_full() {
                    // A full accept queue drops the SYN, as Linux does
                    // (`tcp_conn_request`): a handshake started now could
                    // only wait in SYN-RECEIVED for room, holding a
                    // half-open slot and retransmitting SYN-ACKs, and a
                    // cookie would lead to a reset. The peer retransmits
                    // its SYN, and by then the application may have made
                    // room.
                } else if let Some(pending) = listener.reserve_half_open() {
                    self.accept_syn(pending, dst, src, &seg, ecn);
                } else {
                    // The backlog is full, which is what a SYN flood looks
                    // like: answer with a cookie and keep no state, so the
                    // flood cannot lock out peers that really connect.
                    let synack =
                        listener
                            .cookies
                            .generate_syn_ack(&seg, dst, src, self.mss_for(src));
                    *listener.cookie_sent.lock().unwrap() = Some(Instant::now());
                    (self.sink)(&wrap_segment(dst, src, &synack.marshal()));
                }
                return true;
            }
        }

        // No connection, but maybe the ACK completing a cookie handshake.
        if seg.has_flag(flags::ACK) && !seg.has_flag(flags::SYN) && !seg.has_flag(flags::RST) {
            let listener = self
                .listeners
                .lock()
                .unwrap()
                .get(&seg.dst_port)
                .filter(|l| l.accepts(dst, ours) && l.cookies_recent())
                .cloned();
            if let Some(listener) = listener
                && let Some((mss, _)) = listener.cookies.validate_ack(&seg, dst, src)
            {
                if !listener.queue_full() {
                    self.accept_cookie(listener, dst, src, &seg, mss);
                } else if let Some(pending) =
                    listener.reserve_half_open_within(COOKIE_HALF_OPEN_CAP)
                {
                    // No room to accept it yet: the ACK is dropped, as
                    // Linux drops it, but the SYN-RECEIVED state the cookie
                    // stood for is kept from here on, as for a SYN that got
                    // a half-open slot. Dropped with no state, the peer's
                    // next segments, which carry no cookie, would be reset.
                    self.park_cookie(pending, dst, src, &seg, mss);
                }
                // Past even that, the ACK is simply dropped, as Linux does.
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

    /// Passively open a connection for an inbound SYN and send the SYN-ACK.
    /// The connection joins `pending`'s listener's accept queue once the
    /// handshake completes (see [`ConnState::after_segment`]).
    fn accept_syn(
        self: &Arc<Self>,
        pending: PendingAccept,
        local_ip: IpAddr,
        remote: IpAddr,
        syn: &Segment,
        ecn: IpEcn,
    ) {
        let conn = Conn::new(self.passive_config(local_ip, remote, syn));
        let key = passive_key(remote, syn);
        let state = ConnState::new(
            key,
            local_ip,
            conn,
            self.sink.clone(),
            self.alarm.clone(),
            Some(pending),
        );
        let mut conn = state.conn.lock().unwrap();
        if self.tuning.fast_open {
            // Fast Open data is the listener's to hold until accepted, as
            // any data before then, and counts against the same budget:
            // with no room left, it waits for the handshake instead.
            let offered = matches!(
                fastopen::offer(&syn.options),
                Some(fastopen::Offer::Cookie(_))
            );
            let room = offered && !syn.payload.is_empty() && state.admit(syn);
            conn.set_fast_open_gate(Some(self.fast_open_gate.clone()), !room);
        }
        let synack = conn.accept_syn_ecn(syn, ecn);
        // With Fast Open data in, the application may take the connection
        // now, before the handshake completes, and answer.
        let early = conn.fast_open_accepted();
        drop(conn);
        if !self.register(key, &state) {
            return;
        }
        if early {
            state.connected.store(true, Ordering::Release);
        }
        state.wrap_and_send(synack);
        if early && !state.after_segment() {
            self.forget(&state);
        }
    }

    /// Open a connection from the ACK completing a cookie handshake, which
    /// [`SynCookies::validate_ack`] accepted with `mss`, and hand it to
    /// `listener` at once: the handshake is already over.
    fn accept_cookie(
        self: &Arc<Self>,
        listener: Arc<ListenerState>,
        local_ip: IpAddr,
        remote: IpAddr,
        ack: &Segment,
        mss: u16,
    ) {
        let conn = Conn::new(self.passive_config(local_ip, remote, ack));
        let key = passive_key(remote, ack);
        let pending = PendingAccept {
            listener,
            half_open: false,
        };
        let state = ConnState::new(
            key,
            local_ip,
            conn,
            self.sink.clone(),
            self.alarm.clone(),
            Some(pending),
        );
        // Data riding on the ACK counts against the listener's budget like
        // any other before the connection is accepted. Past it, the
        // handshake still completes, but the data, and a FIN after it, are
        // left for the peer to send again, as `handle_inbound` leaves them.
        let bare;
        let ack = if state.admit(ack) {
            ack
        } else {
            bare = Segment {
                payload: Vec::new(),
                flags: ack.flags & !(flags::FIN | flags::PSH),
                ..ack.clone()
            };
            &bare
        };
        let segs = state
            .conn
            .lock()
            .unwrap()
            .accept_cookie(ack, ack.ack.wrapping_sub(1), mss);
        state.connected.store(true, Ordering::Release);
        if !self.register(key, &state) {
            return;
        }
        state.wrap_and_send(segs);
        if !state.after_segment() {
            self.forget(&state);
        }
    }

    /// Open a connection in SYN-RECEIVED from the ACK completing a cookie
    /// handshake that its listener has no room to accept yet. The ACK is
    /// not taken: the connection waits in SYN-RECEIVED, holding `pending`'s
    /// half-open slot, for the next one (see [`Conn::accept_cookie_syn_received`]).
    fn park_cookie(
        self: &Arc<Self>,
        pending: PendingAccept,
        local_ip: IpAddr,
        remote: IpAddr,
        ack: &Segment,
        mss: u16,
    ) {
        let mut conn = Conn::new(self.passive_config(local_ip, remote, ack));
        conn.accept_cookie_syn_received(ack, ack.ack.wrapping_sub(1), mss);
        let key = passive_key(remote, ack);
        let state = ConnState::new(
            key,
            local_ip,
            conn,
            self.sink.clone(),
            self.alarm.clone(),
            Some(pending),
        );
        self.register(key, &state);
    }

    /// Put a passively opened connection in the table. A SYN racing
    /// `shutdown` past `handle_inbound`'s own check must not leave a
    /// connection behind once the table has been drained.
    fn register(&self, key: ConnKey, state: &Arc<ConnState>) -> bool {
        let mut conns = self.conns.lock().unwrap();
        if self.check_open().is_err() {
            return false;
        }
        conns.insert(key, state.clone());
        true
    }

    /// Close everything: listeners stop, connections are reset, and every
    /// waiter wakes with an error. Afterwards nothing new can be opened.
    pub fn shutdown(&self) {
        *self.stop.lock().unwrap() = true;
        #[cfg(not(target_family = "wasm"))]
        self.alarm.ring();
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

    /// The MSS connections to `remote` advertise, and send with at most.
    fn mss_for(&self, remote: IpAddr) -> u16 {
        mss_for_mtu(self.mtu, remote)
    }

    /// Configuration for a connection opened by `seg`, the peer's SYN or
    /// the ACK completing a cookie handshake.
    fn passive_config(&self, local_ip: IpAddr, remote: IpAddr, seg: &Segment) -> ConnConfig {
        self.tuning.apply(ConnConfig {
            local_addr: Some(SocketAddr::new(local_ip, seg.dst_port)),
            remote_addr: Some(SocketAddr::new(remote, seg.src_port)),
            local_port: seg.dst_port,
            remote_port: seg.src_port,
            mss: self.mss_for(remote),
            keepalive: true,
            ..Default::default()
        })
    }

    /// Take an ICMP message about a packet we sent. A Fragmentation Needed
    /// (ICMPv4 type 3 code 4) or Packet Too Big (ICMPv6 type 2) quoting one
    /// of our TCP segments lowers that connection's path MTU, and what no
    /// longer fits is sent again cut to size (RFC 1191, RFC 8201). Returns
    /// `true` if the message was one of those, whether or not it was acted
    /// on.
    ///
    /// Nothing on the path is authenticated, so the quote has to match (RFC
    /// 5927 §4.1): our address and a connection's ports and peer, and a
    /// SEQ the connection has sent and not had acknowledged, which vtcp
    /// checks.
    pub fn handle_icmp(&self, pkt: &Packet) -> bool {
        let v6 = match (pkt.version(), pkt.ip_protocol()) {
            (4, Protocol::ICMP) => false,
            (6, Protocol::ICMPV6) => true,
            _ => return false,
        };
        let msg = pkt.payload();
        if msg.len() < 8 {
            return false;
        }
        let mtu = match (v6, msg[0], msg[1]) {
            (false, 3, 4) => u32::from(u16::from_be_bytes([msg[6], msg[7]])),
            (true, 2, _) => u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            _ => return false,
        };
        if pkt.verify_transport_checksum() != Some(true) {
            return true;
        }
        let inner = Packet::from_slice(&msg[8..]);
        if inner.version() != pkt.version() || inner.ip_protocol() != Protocol::TCP {
            return true;
        }
        let off = inner.transport_offset();
        let (Some(ours), Some(remote), Some(tcp)) = (
            inner.src_addr(),
            inner.dst_addr(),
            inner.as_bytes().get(off..off + 8),
        ) else {
            return true;
        };
        let key = ConnKey {
            local_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            remote,
            remote_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        };
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let Some(state) = self.conns.lock().unwrap().get(&key).cloned() else {
            return true;
        };
        if state.local_ip != ours || pkt.dst_addr() != Some(ours) {
            return true;
        }
        let mut conn = state.conn.lock().unwrap();
        let segs = conn.on_icmp_too_big(mtu, seq);
        state.queue(&conn, segs);
        drop(conn);
        state.flush();
        true
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

/// The link MTU when [`ClientConfig::mtu`](super::ClientConfig::mtu) is unset.
pub(crate) const DEFAULT_MTU: u32 = 1500;

/// The MSS for a link MTU of `mtu` to `remote`: the MTU less the IP and TCP
/// headers (RFC 9293 §3.7.1), never below vtcp's floor.
fn mss_for_mtu(mtu: u32, remote: IpAddr) -> u16 {
    let headers = if remote.is_ipv6() { 60 } else { 40 };
    mtu.saturating_sub(headers).clamp(
        u32::from(crate::vtcp::options::MIN_MSS),
        u32::from(u16::MAX),
    ) as u16
}

/// Servers whose Fast Open cookies a client keeps.
#[cfg(not(target_family = "wasm"))]
const FAST_OPEN_CACHE: usize = 1024;

/// What a client knows of a server's Fast Open.
#[derive(Debug, Clone, Default)]
struct FastOpenEntry {
    /// The cookie the server gave.
    cookie: Option<Vec<u8>>,
    /// The MSS the connection that got it sent with: what the SYN's data is
    /// sized for.
    mss: Option<u16>,
    /// SYNs with data in a row that went unanswered, and when the last did.
    syn_losses: u32,
    last_loss: Option<Instant>,
}

impl FastOpenEntry {
    /// Whether Fast Open to this server rests for now, as on Linux: after
    /// two SYNs with data went unanswered in a row, for two minutes,
    /// doubling with each further one, up to an hour. One loss may be the
    /// network's; more say something on the way drops such SYNs, or the
    /// server does, and each costs the connection a SYN timeout.
    fn resting(&self, now: Instant) -> bool {
        let Some(last) = self.last_loss else {
            return false;
        };
        if self.syn_losses < 2 {
            return false;
        }
        let rest =
            Duration::from_secs(60 << (self.syn_losses - 1).min(6)).min(Duration::from_secs(3600));
        now.saturating_duration_since(last) < rest
    }
}

fn passive_key(remote: IpAddr, seg: &Segment) -> ConnKey {
    ConnKey {
        local_port: seg.dst_port,
        remote,
        remote_port: seg.src_port,
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
    ip[4..6].copy_from_slice(&super::next_ipv4_id().to_be_bytes());
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
const EPHEMERAL_FIRST: u16 = 49152;
const EPHEMERAL_LAST: u16 = 65535;

/// Pick an ephemeral port for a socket from `local` to `remote` that
/// `in_use` does not claim, by RFC 6056 §3.3.3 (Algorithm 3): a secret
/// per-destination offset plus the shared counter `next`. Handed out in
/// plain sequence, ports tell an off-path attacker which one the next
/// connection uses, halving the guesswork of blind injection (RFC 5961) or
/// a spoofed DNS answer; the keyed offset hides that, while each
/// destination still sees ports go round the whole range before any
/// repeats. Ports still held by live sockets are skipped: reusing one would
/// hijack its connection.
pub(crate) fn pick_port(
    next: &mut u16,
    local: IpAddr,
    remote: SocketAddr,
    in_use: impl Fn(u16) -> bool,
) -> io::Result<u16> {
    const RANGE: u32 = (EPHEMERAL_LAST - EPHEMERAL_FIRST) as u32 + 1;
    let offset = crate::vtcp::secret::keyed_hash(("port", local, remote)) as u32;
    for _ in 0..RANGE {
        let port = EPHEMERAL_FIRST + (offset.wrapping_add(u32::from(*next)) % RANGE) as u16;
        *next = next.wrapping_add(1);
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
        let before = *stack.next_port.lock().unwrap();
        let first = stack.start_dial(local, remote).unwrap();
        // Wind the counter back: the same port comes round again.
        *stack.next_port.lock().unwrap() = before;
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
    fn forgetting_a_connection_leaves_its_successor_alone() {
        let (stack, _out) = capturing_stack();
        let old = stack
            .start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
            .unwrap();
        // A newer connection takes the 4-tuple over, as a SYN does one in
        // TIME-WAIT.
        let new = ConnState::new(
            old.key,
            old.local_ip,
            Conn::new(ConnConfig::default()),
            stack.sink.clone(),
            stack.alarm.clone(),
            None,
        );
        stack.conns.lock().unwrap().insert(old.key, new.clone());
        stack.forget(&old);
        assert!(Arc::ptr_eq(&stack.conns.lock().unwrap()[&old.key], &new));
        stack.forget(&new);
        assert!(stack.conns.lock().unwrap().is_empty());
    }

    #[test]
    fn half_open_connections_per_listener_are_capped() {
        let (stack, _out) = capturing_stack();
        let _listener = stack.listen(own(US), 80).unwrap();
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

    /// The half-open count is kept per listener, not recounted from the
    /// connection table: every way out of SYN-RECEIVED must give the slot
    /// back, or the listener would lock itself out.
    #[test]
    fn half_open_slots_are_given_back() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let syn = |port: u16| Segment {
            src_port: port,
            dst_port: 80,
            seq: 1,
            flags: flags::SYN,
            window: 65535,
            ..Default::default()
        };
        let feed = |seg: Segment| {
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
        };
        let last_sent = || {
            Segment::parse(Packet::from_slice(out.lock().unwrap().last().unwrap()).payload())
                .unwrap()
        };
        // A handshake that completes frees its slot.
        feed(syn(4000));
        assert_eq!(listener.state.half_open.load(Ordering::Acquire), 1);
        let synack = last_sent();
        feed(Segment {
            src_port: 4000,
            dst_port: 80,
            seq: 2,
            ack: synack.seq.wrapping_add(1),
            flags: flags::ACK,
            window: 65535,
            ..Default::default()
        });
        assert!(listener.accept().is_ok());
        assert_eq!(listener.state.half_open.load(Ordering::Acquire), 0);
        // So does one the peer resets.
        feed(syn(4001));
        assert_eq!(listener.state.half_open.load(Ordering::Acquire), 1);
        feed(Segment {
            src_port: 4001,
            dst_port: 80,
            seq: 2,
            flags: flags::RST,
            ..Default::default()
        });
        stack.tick_all();
        assert_eq!(listener.state.half_open.load(Ordering::Acquire), 0);
        // And every one the client drops when it shuts down.
        feed(syn(4002));
        stack.shutdown();
        assert_eq!(listener.state.half_open.load(Ordering::Acquire), 0);
    }

    /// `ClientConfig::tcp` reaches every connection, dialed or accepted.
    #[test]
    fn tuning_applies_to_dialed_and_accepted_connections() {
        use crate::vtcp::{CongestionKind, EcnMode, MtuProbing};
        let tuning = Tuning::default()
            .congestion(CongestionKind::Bbr)
            .ecn(EcnMode::Accurate)
            .pacing(false)
            .send_buf_max(3 << 20)
            .recv_buf_max(5 << 20)
            .fast_open(true)
            .mtu_probing(MtuProbing::Always);
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(|_: &[u8]| {});
        let stack = TcpStack::with_config(sink, DEFAULT_MTU, tuning);
        let dialed = stack
            .start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
            .unwrap();
        let _listener = stack.listen(own(US), 80).unwrap();
        stack.handle_inbound(Packet::from_slice(&inbound(syn_from(4000))), IpAddr::V4(US));
        let accepted = stack
            .conns
            .lock()
            .unwrap()
            .values()
            .find(|c| c.key.local_port == 80)
            .cloned()
            .expect("SYN not accepted");
        for cs in [dialed, accepted] {
            let conn = cs.conn.lock().unwrap();
            let c = conn.config();
            assert_eq!(c.congestion, CongestionKind::Bbr);
            assert_eq!(c.ecn, EcnMode::Accurate);
            assert!(!c.pacing && c.fast_open);
            assert_eq!((c.send_buf_max, c.recv_buf_max), (3 << 20, 5 << 20));
            assert_eq!(c.mtu_probing, MtuProbing::Always);
            assert!(c.keepalive, "the driver's own settings stay");
        }
    }

    /// Fast Open to a server rests after SYNs with data keep going
    /// unanswered, for longer each time.
    #[test]
    fn fast_open_rests_after_lost_syns() {
        let now = Instant::now();
        let mut e = FastOpenEntry {
            cookie: Some(vec![1; 8]),
            ..Default::default()
        };
        assert!(!e.resting(now));
        e.syn_losses = 1;
        e.last_loss = Some(now);
        assert!(!e.resting(now), "one loss may be the network's");
        e.syn_losses = 2;
        assert!(e.resting(now + Duration::from_secs(119)));
        assert!(!e.resting(now + Duration::from_secs(120)));
        e.syn_losses = 30;
        assert!(e.resting(now + Duration::from_secs(3599)));
        assert!(!e.resting(now + Duration::from_secs(3600)));
    }

    fn syn_from(port: u16) -> Segment {
        Segment {
            src_port: port,
            dst_port: 80,
            seq: 1,
            flags: flags::SYN,
            window: 65535,
            ..Default::default()
        }
    }

    fn last_sent(out: &Mutex<Vec<Vec<u8>>>) -> Segment {
        let out = out.lock().unwrap();
        Segment::parse(Packet::from_slice(out.last().unwrap()).payload()).unwrap()
    }

    /// A SYN flood that fills the backlog must not lock real peers out:
    /// past it, SYNs are answered with cookies, and a cookie's ACK opens
    /// the connection.
    #[test]
    fn a_full_backlog_answers_with_syn_cookies() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let feed = |seg: Segment| {
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
        };
        for port in 0..HALF_OPEN_CAP as u16 {
            feed(syn_from(10000 + port));
        }
        out.lock().unwrap().clear();

        feed(syn_from(20000));
        assert_eq!(out.lock().unwrap().len(), 1, "the SYN went unanswered");
        let synack = last_sent(&out);
        assert_eq!(synack.flags, flags::SYN | flags::ACK);
        assert_eq!(synack.dst_port, 20000);
        assert_eq!(stack.conns.lock().unwrap().len(), HALF_OPEN_CAP);

        // An ACK that does not carry the cookie is refused.
        out.lock().unwrap().clear();
        feed(Segment {
            src_port: 20000,
            dst_port: 80,
            seq: 2,
            ack: synack.seq.wrapping_add(2),
            flags: flags::ACK,
            window: 65535,
            ..Default::default()
        });
        assert_eq!(last_sent(&out).flags, flags::RST);
        assert!(listener.accept().is_err());

        // The one that does opens the connection, data and all.
        feed(Segment {
            src_port: 20000,
            dst_port: 80,
            seq: 2,
            ack: synack.seq.wrapping_add(1),
            flags: flags::ACK | flags::PSH,
            window: 65535,
            payload: b"hello".to_vec(),
            ..Default::default()
        });
        let conn = listener
            .accept()
            .expect("the cookie's ACK was not accepted");
        assert_eq!(conn.peer_addr().port(), 20000);
        let mut buf = [0; 8];
        conn.set_nonblocking(true);
        assert_eq!(conn.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(
            listener.state.half_open.load(Ordering::Acquire),
            HALF_OPEN_CAP
        );
    }

    /// A handshake that completes while the accept queue is full is held
    /// in SYN-RECEIVED, not reset, and completes once there is room; one
    /// completed from a SYN cookie is too, and the peer's later segments,
    /// which carry no cookie, find it there.
    #[test]
    fn a_full_accept_queue_holds_handshakes_back() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let feed = |seg: Segment| {
            out.lock().unwrap().clear();
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
            let sent = out.lock().unwrap().clone();
            sent.iter()
                .map(|p| Segment::parse(Packet::from_slice(p).payload()).unwrap())
                .collect::<Vec<_>>()
        };
        let ack = |port: u16, seq: u32, ack: u32, payload: &[u8]| Segment {
            src_port: port,
            dst_port: 80,
            seq,
            ack,
            flags: flags::ACK,
            window: 65535,
            payload: payload.to_vec(),
            ..Default::default()
        };
        let state_of = |port: u16| {
            let key = ConnKey {
                local_port: 80,
                remote: IpAddr::V4(PEER),
                remote_port: port,
            };
            let conns = stack.conns.lock().unwrap();
            conns.get(&key).map(|c| c.conn.lock().unwrap().state())
        };
        // Fill the queue, but for one place.
        for port in 0..ACCEPT_QUEUE_CAP as u16 - 1 {
            let synack = feed(syn_from(10000 + port)).remove(0);
            feed(ack(10000 + port, 2, synack.seq.wrapping_add(1), b""));
        }
        // A half-open backlog, so the next SYN gets a cookie...
        let mut isn = Vec::new();
        for port in 0..HALF_OPEN_CAP as u16 {
            isn.push(feed(syn_from(20000 + port)).remove(0).seq);
        }
        let cookie = feed(syn_from(30000)).remove(0).seq;
        assert_eq!(state_of(30000), None, "no cookie was sent");
        // ...and the last place goes before its ACK comes back.
        feed(ack(20000, 2, isn[0].wrapping_add(1), b""));
        assert!(listener.state.queue_full());

        // The ACK completing a handshake is ignored, not reset.
        assert!(feed(ack(20001, 2, isn[1].wrapping_add(1), b"x")).is_empty());
        assert_eq!(state_of(20001), Some(State::SynReceived));
        // So is the cookie's, but the connection is kept from then on: a
        // segment beyond the cookie's does not find the port empty.
        assert!(feed(ack(30000, 2, cookie.wrapping_add(1), b"ab")).is_empty());
        assert_eq!(state_of(30000), Some(State::SynReceived));
        assert!(feed(ack(30000, 4, cookie.wrapping_add(1), b"cd")).is_empty());

        // Once the application makes room, the next ACK gets in.
        drop(listener.accept().unwrap());
        drop(listener.accept().unwrap());
        feed(ack(20001, 2, isn[1].wrapping_add(1), b"x"));
        feed(ack(30000, 2, cookie.wrapping_add(1), b"abcd"));
        let mut got = Vec::new();
        while let Ok(c) = listener.accept() {
            let mut buf = [0; 8];
            c.set_nonblocking(true);
            let n = c.read(&mut buf).unwrap_or(0);
            got.push((c.peer_addr().port(), buf[..n].to_vec()));
        }
        let tail = &got[got.len() - 2..];
        assert_eq!(tail[0], (20001, b"x".to_vec()));
        assert_eq!(tail[1], (30000, b"abcd".to_vec()));
    }

    /// A SYN arriving while the accept queue is full is dropped, as Linux
    /// drops it, rather than answered with a SYN-ACK for a handshake that
    /// could only wait for room; retransmitted once there is room, it is
    /// answered.
    #[test]
    fn a_full_accept_queue_drops_new_syns() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let feed = |seg: Segment| {
            out.lock().unwrap().clear();
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
            out.lock().unwrap().len()
        };
        for port in 0..ACCEPT_QUEUE_CAP as u16 {
            feed(syn_from(10000 + port));
            let synack = last_sent(&out);
            feed(Segment {
                src_port: 10000 + port,
                dst_port: 80,
                seq: 2,
                ack: synack.seq.wrapping_add(1),
                flags: flags::ACK,
                window: 65535,
                ..Default::default()
            });
        }
        assert!(listener.state.queue_full());
        assert_eq!(feed(syn_from(30000)), 0, "answered a SYN");
        assert_eq!(listener.state.half_open.load(Ordering::Acquire), 0);
        assert_eq!(stack.conns.lock().unwrap().len(), ACCEPT_QUEUE_CAP);

        drop(listener.accept().unwrap());
        assert_eq!(feed(syn_from(30000)), 1);
        assert_eq!(last_sent(&out).flags, flags::SYN | flags::ACK);
    }

    /// A Fragmentation Needed lowers the MSS of the connection it quotes,
    /// and only if the quote is of a segment that connection sent.
    #[test]
    fn frag_needed_must_quote_one_of_our_segments() {
        let (stack, out) = capturing_stack();
        let state = stack
            .start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
            .unwrap();
        let syn = out.lock().unwrap().remove(0);
        let router = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254));
        let mss = || state.conn.lock().unwrap().mss();
        let ptb = |quoted: &[u8], mtu: u32| {
            crate::icmp::packet_too_big(Packet::from_slice(quoted), router, mtu).unwrap()
        };
        let handled = |icmp: &[u8]| stack.handle_icmp(Packet::from_slice(icmp));

        // Another port, another peer, another SEQ, a bad checksum, another
        // source address: all ignored.
        let mut other = syn.clone();
        other[20] ^= 1;
        assert!(handled(&ptb(&other, 1300)));
        let mut other = syn.clone();
        other[19] ^= 1;
        assert!(handled(&ptb(&other, 1300)));
        let mut other = syn.clone();
        other[20 + 4] ^= 0x80;
        assert!(handled(&ptb(&other, 1300)));
        let mut bad = ptb(&syn, 1300);
        bad[20 + 6] ^= 1;
        assert!(handled(&bad));
        let mut other = syn.clone();
        other[15] ^= 1;
        assert!(handled(&ptb(&other, 1300)));
        assert_eq!(mss(), 1460);

        assert!(handled(&ptb(&syn, 1300)));
        assert_eq!(mss(), 1260);
    }

    /// A SYN-RECEIVED connection gives up after Linux's five SYN-ACK
    /// retransmissions' worth of time, not vtcp's full retry count: a
    /// spoofed SYN would otherwise hold its slot for four minutes.
    #[test]
    fn half_open_connections_expire() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        stack.handle_inbound(Packet::from_slice(&inbound(syn_from(4000))), IpAddr::V4(US));
        assert_eq!(stack.conns.lock().unwrap().len(), 1);
        let start = Instant::now();
        stack.tick_at(start + Duration::from_secs(62));
        assert_eq!(stack.conns.lock().unwrap().len(), 1);
        out.lock().unwrap().clear();
        stack.tick_at(start + Duration::from_secs(64));
        assert!(stack.conns.lock().unwrap().is_empty(), "still half open");
        assert_eq!(listener.state.half_open.load(Ordering::Acquire), 0);
        assert!(
            out.lock().unwrap().is_empty(),
            "sent a RST to a SYN's source"
        );
    }

    /// Connections nobody has accepted yet share a small data budget: a
    /// listener whose application is slow to accept must not let peers
    /// park a full receive window on each of 128 queued connections.
    #[test]
    fn unaccepted_connections_share_a_data_budget() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let feed = |seg: Segment| {
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
        };
        feed(syn_from(4000));
        let our_seq = last_sent(&out).seq.wrapping_add(1);
        let data = |seq: u32, len: usize| Segment {
            src_port: 4000,
            dst_port: 80,
            seq,
            ack: our_seq,
            flags: flags::ACK,
            window: 65535,
            payload: vec![7; len],
            ..Default::default()
        };
        // Twice the budget, in order and well inside the receive window.
        let mut seq = 2u32;
        for _ in 0..2 * UNACCEPTED_BYTES / 1000 {
            feed(data(seq, 1000));
            seq = seq.wrapping_add(1000);
        }
        assert_eq!(
            listener.state.unaccepted_bytes.load(Ordering::Acquire),
            65_000
        );
        let conn = listener.accept().unwrap();
        assert_eq!(listener.state.unaccepted_bytes.load(Ordering::Acquire), 0);
        conn.set_nonblocking(true);
        let mut total = 0;
        let mut buf = [0; 4096];
        while let Ok(n) = conn.read(&mut buf) {
            total += n;
        }
        assert_eq!(total, 65_000, "held more than the budget before accept");

        // Accepted, it takes data again: what was dropped comes back.
        feed(data(2 + 65_000, 1000));
        assert_eq!(conn.read(&mut buf).unwrap(), 1000);
    }

    /// Data on the ACK completing a SYN-cookie handshake counts against the
    /// same budget: past it, the connection opens without the data (or the
    /// FIN after it), which the peer sends again.
    #[test]
    fn cookie_data_counts_against_the_budget() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let feed = |seg: Segment| {
            out.lock().unwrap().clear();
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
        };
        for port in 0..HALF_OPEN_CAP as u16 {
            feed(syn_from(10000 + port));
        }
        let len = UNACCEPTED_BYTES * 3 / 4;
        for port in [20000, 20001] {
            feed(syn_from(port));
            let cookie = last_sent(&out).seq;
            feed(Segment {
                src_port: port,
                dst_port: 80,
                seq: 2,
                ack: cookie.wrapping_add(1),
                flags: flags::ACK | flags::PSH | flags::FIN,
                window: 65535,
                payload: vec![7; len],
                ..Default::default()
            });
            // The first fits the budget; the second's data and FIN do not,
            // and its ACK says so.
            let acked = if port == 20000 { 2 + len as u32 } else { 2 };
            assert_eq!(last_sent(&out).ack, acked, "port {port}");
        }
        assert_eq!(listener.state.unaccepted_bytes.load(Ordering::Acquire), len);
        let mut held = Vec::new();
        while let Ok(c) = listener.accept() {
            c.set_nonblocking(true);
            let mut buf = vec![0; UNACCEPTED_BYTES];
            let n = c.read(&mut buf).unwrap_or(0);
            held.push((c.peer_addr().port(), n));
        }
        assert_eq!(held, [(20000, len), (20001, 0)]);
    }

    /// Past [`MAX_TIME_WAIT`], the connections longest in TIME-WAIT are
    /// dropped early rather than let a server that closes first fill the
    /// table with them.
    #[test]
    fn time_wait_is_capped() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let feed = |seg: Segment| {
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
        };
        let seg = |port: u16, seq: u32, ack: u32, flags: u8| Segment {
            src_port: port,
            dst_port: 80,
            seq,
            ack,
            flags,
            window: 65535,
            ..Default::default()
        };
        let ports: Vec<u16> = (4000..4000 + MAX_TIME_WAIT as u16 + 2).collect();
        let mut handles = Vec::new();
        for &port in &ports {
            feed(syn_from(port));
            let iss = last_sent(&out).seq;
            feed(seg(port, 2, iss.wrapping_add(1), flags::ACK));
            let conn = listener.accept().unwrap();
            // We close first, then the peer: TIME-WAIT is ours.
            conn.close().unwrap();
            feed(seg(port, 2, iss.wrapping_add(2), flags::ACK | flags::FIN));
            handles.push(conn);
            stack.tick_all();
        }
        let conns = stack.conns.lock().unwrap();
        assert_eq!(conns.len(), MAX_TIME_WAIT);
        for (i, &port) in ports.iter().enumerate() {
            let key = ConnKey {
                local_port: 80,
                remote: IpAddr::V4(PEER),
                remote_port: port,
            };
            assert_eq!(conns.contains_key(&key), i >= 2, "port {port}");
        }
    }

    #[test]
    fn listener_answers_only_for_its_own_address() {
        let (stack, out) = capturing_stack();
        let _listener = stack.listen(own(US), 80).unwrap();
        let syn = Segment {
            src_port: 4000,
            dst_port: 80,
            seq: 1,
            flags: flags::SYN,
            ..Default::default()
        };
        for dst in [Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::BROADCAST] {
            let pkt = wrap_v4(PEER, dst, &syn.marshal());
            stack.handle_inbound(Packet::from_slice(&pkt), IpAddr::V4(US));
        }
        assert!(stack.conns.lock().unwrap().is_empty());
        assert!(
            out.lock().unwrap().is_empty(),
            "answered for another address"
        );
        stack.handle_inbound(Packet::from_slice(&inbound(syn.clone())), IpAddr::V4(US));
        assert_eq!(stack.conns.lock().unwrap().len(), 1);

        // A client with no address yet answers for none.
        let (stack, out) = capturing_stack();
        let _listener = stack.listen(own(Ipv4Addr::UNSPECIFIED), 80).unwrap();
        let unspec = wrap_v4(PEER, Ipv4Addr::UNSPECIFIED, &syn.marshal());
        let ours = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        stack.handle_inbound(Packet::from_slice(&unspec), ours);
        stack.handle_inbound(Packet::from_slice(&inbound(syn)), ours);
        assert!(stack.conns.lock().unwrap().is_empty());
        assert!(out.lock().unwrap().is_empty());
    }

    /// A sink that panics on the reply to the segment completing a
    /// handshake must not cost the connection its place in the accept queue.
    #[test]
    fn a_panicking_sink_still_settles_the_segment() {
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let panicking = Arc::new(AtomicBool::new(false));
        let (o, p) = (out.clone(), panicking.clone());
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |b: &[u8]| {
            assert!(!p.load(Ordering::Relaxed), "sink panics");
            o.lock().unwrap().push(b.to_vec());
        });
        let stack = TcpStack::new(sink);
        let listener = stack.listen(own(US), 80).unwrap();
        listener.set_nonblocking(true);
        let syn = Segment {
            src_port: 4000,
            dst_port: 80,
            seq: 1,
            flags: flags::SYN,
            window: 65535,
            ..Default::default()
        };
        stack.handle_inbound(Packet::from_slice(&inbound(syn)), IpAddr::V4(US));
        let synack = Segment::parse(Packet::from_slice(&out.lock().unwrap()[0]).payload()).unwrap();
        assert_eq!(synack.flags, flags::SYN | flags::ACK);

        // The handshake's ACK carries data and a FIN, which we acknowledge
        // at once: that reply is what the sink panics on.
        panicking.store(true, Ordering::Relaxed);
        let ack = Segment {
            src_port: 4000,
            dst_port: 80,
            seq: 2,
            ack: synack.seq.wrapping_add(1),
            flags: flags::ACK | flags::PSH | flags::FIN,
            window: 65535,
            payload: b"hi".to_vec(),
            ..Default::default()
        };
        let pkt = inbound(ack);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stack.handle_inbound(Packet::from_slice(&pkt), IpAddr::V4(US))
        }));
        panicking.store(false, Ordering::Relaxed);
        assert!(r.is_err(), "nothing was sent for the sink to panic on");
        assert!(listener.accept().is_ok(), "the connection was never queued");
    }

    /// The cell a client keeps its address in, holding `ip`.
    fn own(ip: Ipv4Addr) -> Arc<Mutex<IpPrefix>> {
        Arc::new(Mutex::new(IpPrefix::new(IpAddr::V4(ip), 24)))
    }

    #[test]
    fn segments_with_a_bad_checksum_are_dropped() {
        let (stack, out) = capturing_stack();
        let _listener = stack.listen(own(US), 80).unwrap();
        let syn = Segment {
            src_port: 4000,
            dst_port: 80,
            seq: 1,
            flags: flags::SYN,
            ..Default::default()
        };
        let mut pkt = inbound(syn);
        pkt[20 + 16] ^= 0x40;
        stack.handle_inbound(Packet::from_slice(&pkt), IpAddr::V4(US));
        assert!(stack.conns.lock().unwrap().is_empty());
        assert!(out.lock().unwrap().is_empty());
        pkt[20 + 16] ^= 0x40;
        stack.handle_inbound(Packet::from_slice(&pkt), IpAddr::V4(US));
        assert_eq!(stack.conns.lock().unwrap().len(), 1);
    }

    /// A listener or dial racing `shutdown` either fails or is closed by it:
    /// none is left registered on a stack that will never serve it.
    #[test]
    fn nothing_opened_during_shutdown_outlives_it() {
        // The interleaving is forced: the opener is held at the table lock,
        // past any check it makes before it, while `shutdown` sets `stop`
        // and drains that table, as it does when it gets there first.
        let (stack, _out) = capturing_stack();
        let listeners = stack.listeners.lock().unwrap();
        let s = stack.clone();
        let t = std::thread::spawn(move || s.listen(own(US), 80).map(drop));
        std::thread::sleep(Duration::from_millis(50));
        *stack.stop.lock().unwrap() = true;
        drop(listeners);
        assert!(t.join().unwrap().is_err(), "listened on a closed stack");
        assert!(stack.listeners.lock().unwrap().is_empty());

        let (stack, _out) = capturing_stack();
        let conns = stack.conns.lock().unwrap();
        let s = stack.clone();
        let t = std::thread::spawn(move || {
            s.start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
                .map(drop)
        });
        std::thread::sleep(Duration::from_millis(50));
        *stack.stop.lock().unwrap() = true;
        drop(conns);
        assert!(t.join().unwrap().is_err(), "dialled on a closed stack");
        assert!(stack.conns.lock().unwrap().is_empty());
    }

    #[test]
    fn empty_read_returns_at_once() {
        let (stack, _out) = capturing_stack();
        let state = stack
            .start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
            .unwrap();
        let conn = TcpConn::new(state);
        conn.set_read_timeout(Some(Duration::from_secs(60)));
        let start = std::time::Instant::now();
        assert_eq!(conn.read(&mut []).unwrap(), 0);
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    /// A timeout too long for an `Instant` to reach means no deadline; it
    /// must not panic computing one.
    #[test]
    fn huge_timeouts_mean_no_deadline() {
        let (stack, _out) = capturing_stack();
        let state = stack
            .start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
            .unwrap();
        let conn = TcpConn::new(state);
        conn.set_nonblocking(true);
        conn.set_read_timeout(Some(Duration::MAX));
        conn.set_write_timeout(Some(Duration::MAX));
        let err = conn.read(&mut [0; 4]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        let err = conn.write(b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // A dial with no deadline waits until the connection ends.
        let s = stack.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            s.shutdown();
        });
        let err = stack
            .dial(
                IpAddr::V4(US),
                SocketAddr::from((PEER, 81)),
                Duration::MAX,
                None,
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn pick_port_covers_the_range_and_reports_exhaustion() {
        let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let remote = SocketAddr::from(([10, 0, 0, 1], 80));
        // From any counter value, one destination sees every port once
        // before a repeat -- the counter wrapping included.
        let mut next = u16::MAX - 100;
        let mut seen = std::collections::HashSet::new();
        for _ in EPHEMERAL_FIRST..=EPHEMERAL_LAST {
            let p = pick_port(&mut next, local, remote, |_| false).unwrap();
            assert!(p >= EPHEMERAL_FIRST);
            assert!(seen.insert(p), "port {p} repeated");
        }
        assert_eq!(
            pick_port(&mut next, local, remote, |_| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }

    #[test]
    fn ports_are_not_handed_out_in_sequence() {
        // Consecutive dials to different destinations: an observer of one
        // learns nothing of the port the next one uses (RFC 6056).
        let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut next = 0;
        let ports: Vec<u16> = (1..=8u8)
            .map(|i| {
                let remote = SocketAddr::from(([10, 0, 0, i], 80));
                pick_port(&mut next, local, remote, |_| false).unwrap()
            })
            .collect();
        let sequential = ports
            .windows(2)
            .filter(|w| w[1] == w[0].wrapping_add(1))
            .count();
        assert!(sequential < 2, "{ports:?}");
    }

    /// An off-path attacker who knows a dial's local port sends a SYN
    /// ahead of the server's SYN-ACK. The SYN-ACK then must not complete
    /// the handshake on the attacker's sequence space: data at the
    /// attacker's sequence numbers never reaches the reader.
    #[test]
    fn blind_syn_during_dial_cannot_inject() {
        let (stack, out) = capturing_stack();
        let st = stack
            .start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
            .unwrap();
        let lport = st.key.local_port;
        let iss = last_sent(&out).seq;
        let feed = |seg: Segment| {
            stack.handle_inbound(Packet::from_slice(&inbound(seg)), IpAddr::V4(US));
        };
        let seg = |seq: u32, ack: u32, flags: u8, payload: &[u8]| Segment {
            src_port: 80,
            dst_port: lport,
            seq,
            ack,
            flags,
            window: 65535,
            payload: payload.to_vec(),
            ..Default::default()
        };
        const EVIL: u32 = 0x4141_0000;
        const REAL: u32 = 0x1000_0000;
        feed(seg(EVIL, 0, flags::SYN, b""));
        feed(seg(REAL, iss.wrapping_add(1), flags::SYN | flags::ACK, b""));
        assert_ne!(st.conn.lock().unwrap().state(), State::Established);
        feed(seg(
            EVIL.wrapping_add(1),
            // Blind: an ACK a little behind ours, as any acceptable one is.
            iss,
            flags::ACK | flags::PSH,
            b"EVIL",
        ));
        let mut buf = [0u8; 64];
        assert_eq!(st.conn.lock().unwrap().read(&mut buf), 0);
    }

    /// Dial a peer that completes the handshake and then goes silent, and
    /// send it some data. Returns the stack, the connection, and what the
    /// stack sent, each with when.
    #[cfg(not(target_family = "wasm"))]
    #[allow(clippy::type_complexity)]
    fn silent_peer() -> (
        Arc<TcpStack>,
        Arc<ConnState>,
        Arc<Mutex<Vec<(Instant, Segment)>>>,
    ) {
        let out: Arc<Mutex<Vec<(Instant, Segment)>>> = Arc::default();
        let o = out.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |b: &[u8]| {
            let ihl = usize::from(b[0] & 0x0f) * 4;
            let seg = Segment::parse(&b[ihl..]).unwrap();
            o.lock().unwrap().push((Instant::now(), seg));
        });
        let stack = TcpStack::new(sink);
        let st = stack
            .start_dial(IpAddr::V4(US), SocketAddr::from((PEER, 80)))
            .unwrap();
        let syn = out.lock().unwrap()[0].1.clone();
        let synack = Segment {
            src_port: 80,
            dst_port: syn.src_port,
            seq: 0x1000_0000,
            ack: syn.seq.wrapping_add(1),
            flags: flags::SYN | flags::ACK,
            window: 65535,
            ..Default::default()
        };
        stack.handle_inbound(Packet::from_slice(&inbound(synack)), IpAddr::V4(US));
        assert_eq!(st.conn.lock().unwrap().state(), State::Established);
        TcpConn::new(st.clone()).write(b"hello").unwrap();
        (stack, st, out)
    }

    /// Whatever arms a timer arms the tick thread's alarm with it.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn sending_data_arms_the_alarm_with_the_rto() {
        let (stack, st, _out) = silent_peer();
        let rto = st.conn.lock().unwrap().next_deadline().unwrap();
        // The thread may have been ticking meanwhile, and its alarm set
        // for another connection or its housekeeping, but not for later.
        stack.tick_all();
        assert_eq!(stack.next_deadline(), Some(rto));
    }

    /// The tick thread retransmits as each backed-off RTO runs out: never
    /// early. How promptly is not measured here: a loaded CI runner wakes
    /// threads late by more than any bound worth asserting.
    /// `sending_data_arms_the_alarm_with_the_rto` checks, without a clock,
    /// that the thread is woken for the deadline rather than a fixed poll;
    /// the bound below only catches timers that do not fire at all.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn retransmissions_go_out_when_the_rto_runs_out() {
        let (_stack, _st, out) = silent_peer();
        let sends = || -> Vec<Instant> {
            out.lock()
                .unwrap()
                .iter()
                .filter(|(_, s)| !s.payload.is_empty())
                .map(|(t, _)| *t)
                .collect()
        };
        let start = Instant::now();
        while sends().len() < 4 {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "no retransmissions"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let t = sends();
        // After a round trip of next to nothing, the RTO starts from its
        // 200 ms floor and doubles with each timeout.
        for (i, rto) in [200, 400, 800].into_iter().enumerate() {
            let gap = t[i + 1] - t[i];
            let rto = Duration::from_millis(rto);
            assert!(gap >= rto, "retransmission {i} early: {gap:?}");
            assert!(
                gap < rto + Duration::from_secs(1),
                "retransmission {i} not sent when due: {gap:?}"
            );
        }
    }

    /// A peer asking for ECN gets it: the SYN-ACK accepts, our data goes
    /// out ECN-capable, and a CE mark on the peer's data comes back as
    /// ECN-Echo.
    #[test]
    fn a_peer_asking_for_ecn_gets_it() {
        let (stack, out) = capturing_stack();
        let listener = stack.listen(own(US), 80).unwrap();
        let feed = |seg: Segment, ecn: u8| {
            let mut pkt = inbound(seg);
            crate::packet::set_ip_ecn(&mut pkt, ecn);
            stack.handle_inbound(Packet::from_slice(&pkt), IpAddr::V4(US));
        };
        let mut syn = syn_from(4002);
        syn.flags |= flags::ECE | flags::CWR;
        feed(syn, 0);
        let synack = last_sent(&out);
        assert_eq!(synack.flags, flags::SYN | flags::ACK | flags::ECE);
        let ack = |seq: u32, payload: Vec<u8>| Segment {
            src_port: 4002,
            dst_port: 80,
            seq,
            ack: synack.seq.wrapping_add(1),
            flags: flags::ACK,
            window: 65535,
            payload,
            ..Default::default()
        };
        feed(ack(2, Vec::new()), 0);
        let conn = listener.accept().unwrap();
        out.lock().unwrap().clear();
        conn.write(&[9; 100]).unwrap();
        {
            let out = out.lock().unwrap();
            let pkt = Packet::from_slice(out.last().unwrap());
            assert_eq!(pkt.payload().len(), 20 + 100);
            assert_eq!(pkt.ipv4_ecn(), 2, "data not ECT(0)");
            assert_eq!(crate::checksum::checksum(&pkt[..20]), 0);
            assert_eq!(pkt.verify_transport_checksum(), Some(true));
        }
        out.lock().unwrap().clear();
        feed(ack(2, vec![1; 50]), 3);
        assert!(last_sent(&out).has_flag(flags::ECE), "no ECN-Echo");
    }
}

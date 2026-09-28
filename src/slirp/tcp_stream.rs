//! Server-side accepted TCP connections, backed by [`vtcp::Conn`].
//!
//! When an inbound SYN arrives for a registered [`Listener`](super::Listener),
//! the stack mints a server-side `vtcp::Conn` (via `accept_syn`), drives it to
//! ESTABLISHED, and hands the application a [`TcpStream`]. This mirrors
//! `vclient::TcpConn` but for the *inbound* (accept) direction: the connection
//! is passive-opened rather than dialed.
//!
//! Segments the engine emits are wrapped back into IP via the slirp
//! `build_packet4` / `build_packet6` helpers (which fill IP + TCP checksums)
//! and pushed into the virtual network through the stack's dispatch sink.

use crate::time::Instant;
use crate::vtcp::segment::Segment;
use crate::vtcp::{Conn, State};
use std::collections::VecDeque;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// Endpoint addressing for an accepted virtual connection. The "local" side is
/// the listener (our virtual IP:port); the "remote" side is the peer inside the
/// virtual network that connected to us.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Endpoints {
    V4 {
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    },
    V6 {
        local_ip: Ipv6Addr,
        local_port: u16,
        remote_ip: Ipv6Addr,
        remote_port: u16,
    },
}

impl Endpoints {
    /// Wrap a marshaled TCP segment in IP with correct checksums. The segment
    /// travels local→remote (server→client).
    pub(crate) fn wrap(&self, seg: &[u8]) -> Vec<u8> {
        match self {
            Endpoints::V4 {
                local_ip,
                remote_ip,
                ..
            } => crate::slirp::packet::build_packet4(*local_ip, *remote_ip, seg),
            Endpoints::V6 {
                local_ip,
                remote_ip,
                ..
            } => crate::slirp::packet::build_packet6(*local_ip, *remote_ip, seg),
        }
    }

    /// `(local_port, remote_port)`.
    pub(crate) fn ports(&self) -> (u16, u16) {
        match *self {
            Endpoints::V4 {
                local_port,
                remote_port,
                ..
            }
            | Endpoints::V6 {
                local_port,
                remote_port,
                ..
            } => (local_port, remote_port),
        }
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        match self {
            Endpoints::V4 {
                local_ip,
                local_port,
                ..
            } => SocketAddr::new(IpAddr::V4(*local_ip), *local_port),
            Endpoints::V6 {
                local_ip,
                local_port,
                ..
            } => SocketAddr::new(IpAddr::V6(*local_ip), *local_port),
        }
    }

    pub(crate) fn peer_addr(&self) -> SocketAddr {
        match self {
            Endpoints::V4 {
                remote_ip,
                remote_port,
                ..
            } => SocketAddr::new(IpAddr::V4(*remote_ip), *remote_port),
            Endpoints::V6 {
                remote_ip,
                remote_port,
                ..
            } => SocketAddr::new(IpAddr::V6(*remote_ip), *remote_port),
        }
    }
}

/// Shared per-connection state. The stack holds an `Arc<ConnState>` in its
/// `virt_tcp` table; the application holds a [`TcpStream`] wrapping the same
/// `Arc`. The same `Arc` is enqueued onto the listener's accept queue.
pub(crate) struct ConnState {
    pub(crate) endpoints: Endpoints,
    /// The namespace the connection belongs to (see [`TcpStream::namespace`]).
    ns: u64,
    pub(crate) conn: Mutex<Conn>,
    /// Notified whenever readable/writable/closed status may have changed
    /// (inbound data, state transition, timer tick).
    pub(crate) signal: Condvar,
    /// Sink for fully-framed IP packets the engine wants to transmit back into
    /// the virtual network. Provided by the stack (wraps `Stack::dispatch`).
    pub(crate) sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    /// Segments on their way to the sink, in the order the engine made them.
    outbox: Mutex<Outbox>,
    /// For a passively opened connection: hands it to its listener once the
    /// handshake completes, unless the deadline passes first.
    pending_accept: Mutex<Option<PendingAccept>>,
    /// The latest segment that would have completed the handshake had the
    /// listener had room (see [`held_back`](Self::held_back)), delivered
    /// once it has.
    held: Mutex<Option<Segment>>,
    /// Why the connection ended, if not by an orderly close: a reset from
    /// the peer, or our timers giving up. Reads report it instead of a clean
    /// end of stream, so a truncated transfer is not mistaken for a whole one.
    error: Mutex<Option<io::ErrorKind>>,
}

/// See [`ConnState::emit`].
#[derive(Default)]
struct Outbox {
    segs: VecDeque<Vec<u8>>,
    /// A thread is feeding the sink from `segs`.
    emitting: bool,
}

/// What a listener made of a connection offered to its accept queue.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Offer {
    /// Queued for `accept`.
    Taken,
    /// No room yet: offer it again once the application has accepted more.
    Full,
    /// Closed: the connection will never be accepted.
    Refused,
}

/// Offers an established connection to a listener. Dropped once the
/// listener has taken or refused it (freeing what it holds, such as a
/// half-open slot), or when the handshake runs out of time.
pub(crate) type AcceptFn = Box<dyn FnMut(&Arc<ConnState>) -> Offer + Send>;

/// Whether the listener's accept queue is full; if it is, the listener
/// also lists the connection to be offered the room `accept` makes.
pub(crate) type HoldFn = Box<dyn Fn(&Arc<ConnState>) -> bool + Send>;

/// A passively opened connection's way into its listener's accept queue.
pub(crate) struct PendingAccept {
    /// When the handshake, and the wait for room, run out of time.
    deadline: Instant,
    accept: AcceptFn,
    hold: HoldFn,
}

/// How long a passively opened connection may take to complete its
/// handshake, and to find room in the listener's accept queue, before it is
/// dropped.
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl ConnState {
    pub(crate) fn new(
        endpoints: Endpoints,
        conn: Conn,
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    ) -> Arc<ConnState> {
        Self::new_in(0, endpoints, conn, sink)
    }

    /// A connection of namespace `ns`.
    pub(crate) fn new_in(
        ns: u64,
        endpoints: Endpoints,
        conn: Conn,
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    ) -> Arc<ConnState> {
        Arc::new(ConnState {
            endpoints,
            ns,
            conn: Mutex::new(conn),
            signal: Condvar::new(),
            sink,
            outbox: Mutex::new(Outbox::default()),
            pending_accept: Mutex::new(None),
            held: Mutex::new(None),
            error: Mutex::new(None),
        })
    }

    fn fail(&self, kind: io::ErrorKind) {
        self.error.lock().expect("poisoned").get_or_insert(kind);
    }

    fn error(&self) -> Option<io::Error> {
        let kind = (*self.error.lock().expect("poisoned"))?;
        Some(io::Error::new(kind, "connection ended abnormally"))
    }

    /// Queue the connection on a listener, through `accept`, once its
    /// handshake completes (see [`complete_accept`](Self::complete_accept)).
    pub(crate) fn set_pending_accept(&self, accept: AcceptFn, hold: HoldFn) {
        *self.pending_accept.lock().expect("poisoned") = Some(PendingAccept {
            deadline: Instant::now() + ACCEPT_HANDSHAKE_TIMEOUT,
            accept,
            hold,
        });
    }

    /// Whether `seg` is the ACK that would complete the handshake of a
    /// connection whose listener has no room to accept it, and so must not
    /// go in yet. Linux drops that ACK (unless told to abort on overflow),
    /// which keeps the connection in SYN-RECEIVED: nothing the peer sends
    /// is acknowledged while nobody could read it, and a reset would fail a
    /// connection that is merely early. If the application never makes
    /// room, the handshake deadline ends it.
    ///
    /// Linux then waits for the peer's next segment, prompted by a
    /// retransmitted SYN-ACK, to complete the handshake. With a queue as
    /// short as a slirp listener's, a burst of clients would spend most of
    /// that deadline waiting on backed-off retransmissions while `accept`
    /// sat idle, so the segment is kept (the latest one, which a later one
    /// replaces) and delivered as soon as `accept` makes room.
    fn held_back(self: &Arc<Self>, seg: &Segment) -> bool {
        use crate::vtcp::segment::flags;
        if seg.flags & (flags::ACK | flags::SYN | flags::RST) != flags::ACK {
            return false;
        }
        let pending = self.pending_accept.lock().expect("poisoned");
        let Some(p) = pending.as_ref() else {
            return false;
        };
        let hold =
            self.conn.lock().expect("poisoned").state() == State::SynReceived && (p.hold)(self);
        // Let in, this one completes the handshake, and one held earlier
        // would only come after it as a stale duplicate.
        *self.held.lock().expect("poisoned") = hold.then(|| seg.clone());
        hold
    }

    /// Hand a passively opened connection to its listener if its handshake
    /// has completed, first delivering the segment that would have
    /// completed it had the listener had room (see
    /// [`held_back`](Self::held_back)). Call it after every inbound
    /// segment, and on every tick: a connection the full accept queue had
    /// no room for waits to be offered again.
    ///
    /// A handshake does not complete while the queue is full, but one
    /// completing just as another thread takes the last place can find no
    /// room. It then waits, established, rather than being reset, as a
    /// connection the application would have accepted a moment later: the
    /// half-open slot it keeps meanwhile bounds how many can wait, and the
    /// handshake deadline how long.
    ///
    /// Returns `false` when the connection is finished with: the listener
    /// refused it, so it has been aborted and the caller should drop it from
    /// its table.
    pub(crate) fn complete_accept(self: &Arc<Self>) -> bool {
        // Taken before the pending lock, which delivering it takes. Held
        // back again if there is still no room.
        let held = self.held.lock().expect("poisoned").take();
        if let Some(seg) = held {
            self.deliver(&seg);
        }
        // The offer is made under the lock, which the tick also takes to
        // expire the handshake, so the listener never gets a connection that
        // is being reset for running out of time.
        let mut pending = self.pending_accept.lock().expect("poisoned");
        let Some(PendingAccept { accept, .. }) = pending.as_mut() else {
            return true;
        };
        if !self
            .conn
            .lock()
            .expect("poisoned")
            .state()
            .is_synchronized()
        {
            return true;
        }
        match accept(self) {
            Offer::Full => true,
            Offer::Taken => {
                pending.take();
                true
            }
            Offer::Refused => {
                pending.take();
                drop(pending);
                self.abort();
                false
            }
        }
    }

    /// Send a RST and close.
    pub(crate) fn abort(&self) {
        let mut conn = self.conn.lock().expect("poisoned");
        let segs = conn.abort();
        self.emit(conn, segs);
        self.signal.notify_all();
    }

    /// Transmit segments the engine has just produced through `conn`, the
    /// held lock on it, which this releases.
    ///
    /// The segments join the outbox before the lock is released, so the
    /// outbox holds them in the order the engine made them, and one thread at
    /// a time feeds it to the sink. On an in-process link the sink runs the
    /// peer synchronously, and its ACK re-enters `deliver`, which makes more
    /// segments: sent from inside the sink call, those would overtake the
    /// rest of the batch still waiting in the caller's hands, and the peer,
    /// seeing a hole and then data from beyond it, would answer every
    /// segment with a duplicate ACK and fast-retransmit its way through the
    /// transfer. The re-entrant call only queues; the outermost sender sends.
    pub(crate) fn emit(&self, conn: MutexGuard<'_, Conn>, segs: Vec<Vec<u8>>) {
        let mut out = self.outbox.lock().expect("poisoned");
        out.segs.extend(segs);
        drop(conn);
        if out.emitting {
            return;
        }
        out.emitting = true;
        while let Some(seg) = out.segs.pop_front() {
            drop(out);
            let pkt = self.endpoints.wrap(&seg);
            (self.sink)(&pkt);
            out = self.outbox.lock().expect("poisoned");
        }
        out.emitting = false;
    }

    /// Transmit segments made without the engine (or before anything else
    /// could reach it), after whatever it has queued already.
    pub(crate) fn send(&self, segs: Vec<Vec<u8>>) {
        self.emit(self.conn.lock().expect("poisoned"), segs);
    }

    /// Feed an inbound segment to the engine, transmit its replies, and wake
    /// any blocked reader/writer.
    pub(crate) fn deliver(self: &Arc<Self>, seg: &Segment) {
        if self.held_back(seg) {
            return;
        }
        let mut conn = self.conn.lock().expect("poisoned");
        // A FIN before the RST means the stream had already ended whole.
        let ended = conn.fin_received();
        let segs = conn.handle_segment(seg);
        if seg.has_flag(crate::vtcp::segment::flags::RST) && conn.is_closed() && !ended {
            self.fail(io::ErrorKind::ConnectionReset);
        }
        self.emit(conn, segs);
        self.signal.notify_all();
    }
}

/// A blocking, accepted TCP stream over the virtual network.
///
/// Returned by [`Listener::accept`](super::Listener::accept). Implements
/// [`std::io::Read`] + [`std::io::Write`]. Dropping it closes the
/// connection gracefully, unless received data was left unread: then, as a
/// host stack does (RFC 2525 §2.17), the peer gets a reset.
///
/// After the drop nobody is left to read, so the peer is reset if it sends
/// more data, or if it ACKs our FIN but then goes quiet without sending its
/// own for vtcp's FIN-WAIT-2 timeout (60 s; see
/// [`ConnConfig::fin_wait2_timeout`](crate::vtcp::ConnConfig::fin_wait2_timeout)),
/// as Linux does for an orphaned socket. [`close`](Self::close) alone is a
/// half-close: the handle can still read, and the peer may take as long as
/// it likes.
pub struct TcpStream {
    state: Arc<ConnState>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
}

impl core::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("slirp::TcpStream")
            .field("local", &self.local_addr())
            .field("peer", &self.peer_addr())
            .field("namespace", &self.namespace())
            .finish()
    }
}

impl TcpStream {
    pub(crate) fn new(state: Arc<ConnState>) -> TcpStream {
        TcpStream {
            state,
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
        }
    }

    /// Local (listener) socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.state.endpoints.local_addr()
    }

    /// Remote (connecting peer) socket address.
    ///
    /// This is whatever address the peer put in its packets. Peers in
    /// different namespaces may use the same one, and nothing stops a peer
    /// from claiming another's, so it says nothing about who connected on
    /// its own: pair it with [`namespace`](Self::namespace) before
    /// trusting it for anything like access control.
    pub fn peer_addr(&self) -> SocketAddr {
        self.state.endpoints.peer_addr()
    }

    /// The namespace the connection came from: the id
    /// [`Stack::attach`](super::Stack::attach) returned for the peer
    /// attached there, or 0 for the stack's own peer (its `send` and
    /// `set_handler`). Unlike [`peer_addr`](Self::peer_addr), a peer cannot
    /// choose it.
    pub fn namespace(&self) -> u64 {
        self.state.ns
    }

    /// Turn the Nagle algorithm off (`true`) or back on, as
    /// [`std::net::TcpStream::set_nodelay`]. With it off, a write shorter
    /// than a segment goes out at once even while earlier data is still
    /// unacknowledged; turning it off also sends whatever it was holding.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        let mut conn = self.state.conn.lock().expect("poisoned");
        let segs = conn.set_nodelay(nodelay);
        self.state.emit(conn, segs);
        Ok(())
    }

    /// Whether the Nagle algorithm is off (see [`set_nodelay`](Self::set_nodelay)).
    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(self.state.conn.lock().expect("poisoned").nodelay())
    }

    /// Set a read timeout. `None` blocks indefinitely.
    pub fn set_read_timeout(&self, t: Option<Duration>) {
        *self.read_timeout.lock().expect("poisoned") = t;
    }

    /// Set a write timeout: how long a blocking [`write`](Self::write) waits
    /// for the peer to open its window. `None` waits indefinitely.
    pub fn set_write_timeout(&self, t: Option<Duration>) {
        *self.write_timeout.lock().expect("poisoned") = t;
    }

    /// Write all of `buf`, blocking until the engine accepts it. Returns the
    /// number of bytes queued: `buf.len()`, or what was written before the
    /// [write timeout](Self::set_write_timeout) (`WouldBlock` if nothing).
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let deadline = deadline_after(*self.write_timeout.lock().expect("poisoned"));
        let mut written = 0;
        while written < buf.len() {
            let mut conn = self.state.conn.lock().expect("poisoned");
            // Past our own FIN the engine takes no more data, and never
            // will: waiting for room would only spin until the timeout.
            let after_fin = matches!(
                conn.state(),
                State::FinWait1
                    | State::FinWait2
                    | State::Closing
                    | State::LastAck
                    | State::TimeWait
            );
            if conn.is_closed() || after_fin {
                return Err(self.state.error().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")
                }));
            }
            let (n, segs) = conn.write(&buf[written..]);
            self.state.emit(conn, segs);
            if n > 0 {
                written += n;
            } else {
                // Send window full (or not yet established) — wait for an ACK
                // to open it, or for a state transition.
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    if written > 0 {
                        break;
                    }
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "write timeout"));
                }
                let conn = self.state.conn.lock().expect("poisoned");
                let _ = self
                    .state
                    .signal
                    .wait_timeout(conn, Duration::from_millis(100))
                    .expect("poisoned");
            }
        }
        Ok(written)
    }

    /// Read into `buf`, blocking until data is available or the peer closes.
    /// Returns 0 at end of stream, and at once for an empty `buf`.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Nothing can fill an empty buffer, so waiting for data would block
        // until the peer closes; std's streams return 0 at once instead.
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = deadline_after(*self.read_timeout.lock().expect("poisoned"));
        let mut conn = self.state.conn.lock().expect("poisoned");
        loop {
            let n = conn.read(buf);
            if n > 0 {
                // Reading can reopen a window the peer is waiting on: tell it
                // now, not on the next tick up to 100 ms later, which would
                // stall a sender at every buffer-full.
                let segs = conn.take_outgoing();
                self.state.emit(conn, segs);
                return Ok(n);
            }
            if conn.fin_received() || conn.is_closed() {
                return match self.state.error() {
                    Some(e) => Err(e),
                    None => Ok(0), // clean EOF
                };
            }
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "read timeout"));
                    }
                    let (c, _) = self
                        .state
                        .signal
                        .wait_timeout(conn, d - now)
                        .expect("poisoned");
                    conn = c;
                }
                None => {
                    conn = self.state.signal.wait(conn).expect("poisoned");
                }
            }
        }
    }

    /// Initiate a graceful close (sends FIN).
    pub fn close(&self) -> io::Result<()> {
        let mut conn = self.state.conn.lock().expect("poisoned");
        let segs = conn.close();
        self.state.emit(conn, segs);
        self.state.signal.notify_all();
        Ok(())
    }
}

impl io::Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TcpStream::read(self, buf)
    }
}

impl io::Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TcpStream::write(self, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Unlike close() (a half-close: we may still read), dropping the
        // stream means nobody will read or write again. Releasing lets the
        // engine time out a peer that never finishes, and reset one that
        // keeps sending or whose data was left unread, as Linux does for an
        // orphaned socket.
        let mut conn = self.state.conn.lock().expect("poisoned");
        let segs = conn.release();
        self.state.emit(conn, segs);
        self.state.signal.notify_all();
    }
}

/// The deadline `timeout` from now, or `None` (no deadline) for no timeout
/// or one too long for an `Instant` to hold: `Instant + Duration` panics on
/// overflow, and a caller passing `Duration::MAX` means "wait forever".
fn deadline_after(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|t| Instant::now().checked_add(t))
}

/// Helper used by the stack's tick thread: drive timers for one connection and
/// wake its waiters if that changed its state. Returns `true` if the
/// connection is now closed (so the caller can drop it from the table).
pub(crate) fn tick_conn(state: &Arc<ConnState>) -> bool {
    // A handshake that has not completed in time is abandoned, as a listen
    // queue would drop a stale embryonic connection. Checked and taken under
    // one lock: the final ACK may complete the handshake at the same time,
    // and `complete_accept` takes the accept under that lock too, so exactly
    // one of them gets it. Taken on a stale check, it could be gone to the
    // listener already, and the reset would hit a connection just accepted.
    let expired = {
        let mut pending = state.pending_accept.lock().expect("poisoned");
        match &*pending {
            Some(p) if Instant::now() >= p.deadline => pending.take(),
            _ => None,
        }
    };
    if let Some(p) = expired {
        // Dropped, which gives the listener's backlog slot back.
        drop(p);
        state.abort();
    } else {
        // Offer again a connection the accept queue had no room for.
        state.complete_accept();
    }
    let mut conn = state.conn.lock().expect("poisoned");
    let ended = conn.fin_received();
    let before = (conn.state(), conn.is_closed());
    let segs = conn.tick();
    let closed = conn.is_closed();
    if closed && !ended {
        // Retransmissions or keepalives went unanswered.
        state.fail(io::ErrorKind::TimedOut);
    }
    let changed = (conn.state(), closed) != before;
    state.emit(conn, segs);
    // Timers never make data readable or free send buffer space: only
    // segments from the peer do, and `deliver` wakes the waiters for those.
    // What a timer can do is end the connection, or move it on to another
    // state; waking every waiter on every tick regardless would wake each
    // thread blocked on any connection of the stack ten times a second.
    if changed {
        state.signal.notify_all();
    }
    closed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::ConnConfig;

    /// A slirp-side connection accepted from `peer`, with everything it
    /// sends collected (as TCP segments, the 20-byte IPv4 header stripped).
    fn accepted(peer: &mut Conn) -> (Arc<ConnState>, Arc<Mutex<Vec<Vec<u8>>>>) {
        accepted_with(peer, ConnConfig::default())
    }

    /// As [`accepted`], the slirp side's engine configured by `cfg`.
    fn accepted_with(
        peer: &mut Conn,
        cfg: ConnConfig,
    ) -> (Arc<ConnState>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let o = out.clone();
        let state = ConnState::new(
            Endpoints::V4 {
                local_ip: Ipv4Addr::new(10, 0, 0, 1),
                local_port: 80,
                remote_ip: Ipv4Addr::new(10, 0, 0, 5),
                remote_port: 5000,
            },
            Conn::new(cfg.local_port(80).remote_port(5000)),
            Arc::new(move |p: &[u8]| o.lock().unwrap().push(p[20..].to_vec())),
        );
        let syn = Segment::parse(&peer.connect()[0]).unwrap();
        let synack = state.conn.lock().unwrap().accept_syn(&syn);
        state.send(synack);
        pump(&state, &out, peer);
        (state, out)
    }

    fn pump(state: &Arc<ConnState>, out: &Mutex<Vec<Vec<u8>>>, peer: &mut Conn) {
        loop {
            let sent = std::mem::take(&mut *out.lock().unwrap());
            if sent.is_empty() {
                return;
            }
            for seg in sent {
                for r in peer.handle_segment(&Segment::parse(&seg).unwrap()) {
                    state.deliver(&Segment::parse(&r).unwrap());
                }
            }
        }
    }

    fn peer() -> Conn {
        Conn::new(ConnConfig::default().local_port(5000).remote_port(80))
    }

    /// While the listener's accept queue is full, the ACK completing a
    /// handshake is not let in, as on Linux: the connection stays in
    /// SYN-RECEIVED and acknowledges none of the peer's data. Once
    /// `accept` makes room, the handshake completes and the data is taken.
    #[test]
    fn a_full_accept_queue_holds_the_handshake_back() {
        use crate::slirp::listener::{ACCEPT_QUEUE_CAP, Listener};
        let listener = Arc::new(Listener::new("10.0.0.1:80".parse().unwrap()));
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let o = out.clone();
        let endpoints = Endpoints::V4 {
            local_ip: Ipv4Addr::new(10, 0, 0, 1),
            local_port: 80,
            remote_ip: Ipv4Addr::new(10, 0, 0, 5),
            remote_port: 5000,
        };
        let filler = || {
            ConnState::new(
                endpoints,
                Conn::new(ConnConfig::default()),
                Arc::new(|_: &[u8]| {}),
            )
        };
        for _ in 0..ACCEPT_QUEUE_CAP {
            assert_eq!(listener.enqueue(&filler()), Offer::Taken);
        }
        let state = ConnState::new(
            endpoints,
            Conn::new(ConnConfig::default().local_port(80).remote_port(5000)),
            Arc::new(move |p: &[u8]| o.lock().unwrap().push(p[20..].to_vec())),
        );
        let (l1, l2) = (Arc::downgrade(&listener), Arc::downgrade(&listener));
        state.set_pending_accept(
            Box::new(move |s| l1.upgrade().map_or(Offer::Refused, |l| l.enqueue(s))),
            Box::new(move |s| l2.upgrade().is_some_and(|l| l.hold(s))),
        );
        let mut peer = peer();
        let syn = Segment::parse(&peer.connect()[0]).unwrap();
        let synack = state.conn.lock().unwrap().accept_syn(&syn);
        state.send(synack);
        // The peer takes the SYN-ACK, ACKs it and sends data at once.
        let synack = Segment::parse(&out.lock().unwrap().remove(0)).unwrap();
        let mut from_peer = peer.handle_segment(&synack);
        from_peer.extend(peer.write(b"hello").1);
        assert!(!from_peer.is_empty());
        for seg in &from_peer {
            state.deliver(&Segment::parse(seg).unwrap());
            assert!(state.complete_accept());
        }
        assert_eq!(state.conn.lock().unwrap().state(), State::SynReceived);
        assert!(
            out.lock().unwrap().is_empty(),
            "answered a held-back segment"
        );

        // Room made: the handshake completes, and the stream is queued.
        let first = listener.accept().unwrap();
        drop(first);
        assert!(state.conn.lock().unwrap().state().is_synchronized());
        let mut accepted = None;
        for _ in 0..ACCEPT_QUEUE_CAP {
            let s = listener.accept().unwrap();
            if s.peer_addr().port() == 5000 && Arc::ptr_eq(&s.state, &state) {
                accepted = Some(s);
            }
        }
        let accepted = accepted.expect("the held-back connection was not queued");
        // The held segment carried the data, which a retransmission would
        // bring in any case.
        let mut buf = [0; 8];
        let n = accepted.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    /// A handshake that completes just as its deadline passes is either
    /// handed to the listener or dropped, never both: the tick must not
    /// reset a connection the listener has just accepted.
    #[test]
    fn a_handshake_timing_out_as_it_completes_is_not_reset_once_accepted() {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicBool, Ordering};
        for round in 0..20_000 {
            let mut peer = peer();
            let (state, _out) = accepted(&mut peer);
            let accepted = Arc::new(AtomicBool::new(false));
            let a = accepted.clone();
            // Already due, as when the tick and the final ACK meet.
            *state.pending_accept.lock().unwrap() = Some(PendingAccept {
                deadline: Instant::now(),
                accept: Box::new(move |_| {
                    a.store(true, Ordering::SeqCst);
                    Offer::Taken
                }),
                hold: Box::new(|_| false),
            });
            let barrier = Arc::new(Barrier::new(2));
            let ticked = Arc::new(AtomicBool::new(false));
            let (s2, b2, t2) = (state.clone(), barrier.clone(), ticked.clone());
            let ticker = std::thread::spawn(move || {
                b2.wait();
                // A start swept across the rounds, so that the tick's look at
                // the pending accept meets the ACK's at every offset: the
                // window is a few instructions wide.
                for _ in 0..round % 400 {
                    std::hint::spin_loop();
                }
                tick_conn(&s2);
                t2.store(true, Ordering::SeqCst);
            });
            barrier.wait();
            // The final ACK, delivered until one of the two has settled it.
            while !ticked.load(Ordering::SeqCst) && !accepted.load(Ordering::SeqCst) {
                state.complete_accept();
            }
            ticker.join().unwrap();
            if accepted.load(Ordering::SeqCst) {
                assert!(
                    !state.conn.lock().unwrap().is_closed(),
                    "reset a connection the listener had accepted"
                );
            }
        }
    }

    /// A reset cuts the stream short: reading reports it rather than a
    /// clean end of stream, and so does writing.
    #[test]
    fn a_reset_reads_as_an_error() {
        let mut peer = peer();
        let (state, _out) = accepted(&mut peer);
        let stream = TcpStream::new(state.clone());
        for seg in peer.write(b"partial").1.into_iter().chain(peer.abort()) {
            state.deliver(&Segment::parse(&seg).unwrap());
        }
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"partial");
        assert_eq!(
            stream.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            stream.write(b"x").unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }

    /// An orderly close still reads as end of stream.
    #[test]
    fn a_fin_reads_as_end_of_stream() {
        let mut peer = peer();
        let (state, out) = accepted(&mut peer);
        let stream = TcpStream::new(state.clone());
        let mut segs = peer.write(b"whole").1;
        segs.extend(peer.close());
        for seg in segs {
            state.deliver(&Segment::parse(&seg).unwrap());
        }
        pump(&state, &out, &mut peer);
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"whole");
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    /// An empty read returns at once, as std's does, rather than waiting
    /// for data it has no room for.
    #[test]
    fn an_empty_read_does_not_block() {
        let mut peer = peer();
        let (state, _out) = accepted(&mut peer);
        let stream = TcpStream::new(state);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(stream.read(&mut []).map_err(|e| e.kind()));
        });
        let got = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("read(&mut []) blocked");
        assert_eq!(got, Ok(0));
    }

    /// A read that reopens a closed receive window advertises it at once,
    /// rather than leaving the sender stalled until the next tick.
    #[test]
    fn a_read_after_a_zero_window_updates_it_at_once() {
        let mut peer = peer();
        let (state, out) = accepted_with(&mut peer, ConnConfig::default().recv_buf_size(4096));
        let stream = TcpStream::new(state.clone());
        let (_, segs) = peer.write(&[7u8; 16384]);
        for seg in segs {
            state.deliver(&Segment::parse(&seg).unwrap());
        }
        pump(&state, &out, &mut peer);
        assert!(out.lock().unwrap().is_empty());
        let mut buf = vec![0u8; 8192];
        assert_eq!(stream.read(&mut buf).unwrap(), 4096);
        let sent = out.lock().unwrap().clone();
        let update = sent.last().expect("no window update after the read");
        assert!(Segment::parse(update).unwrap().window > 0);
    }

    /// A peer on an in-process link answers from inside the sink, and its
    /// ACKs make the engine send more from there: the segments still reach
    /// the wire in sequence, not with the newer ones ahead of the batch the
    /// outer call was sending, and the nesting does not grow the stack by a
    /// frame per segment (it overflowed it before).
    #[test]
    fn segments_leave_in_order_when_the_peer_answers_synchronously() {
        use std::sync::{OnceLock, Weak};
        let peer = Arc::new(Mutex::new(peer()));
        let this: Arc<OnceLock<Weak<ConnState>>> = Arc::new(OnceLock::new());
        // (seq, len) of each data segment, in wire order.
        let wire: Arc<Mutex<Vec<(u32, u32)>>> = Arc::default();
        let (p, t, w) = (peer.clone(), this.clone(), wire.clone());
        let state = ConnState::new(
            Endpoints::V4 {
                local_ip: Ipv4Addr::new(10, 0, 0, 1),
                local_port: 80,
                remote_ip: Ipv4Addr::new(10, 0, 0, 5),
                remote_port: 5000,
            },
            Conn::new(ConnConfig::default().local_port(80).remote_port(5000)),
            Arc::new(move |pkt: &[u8]| {
                let seg = Segment::parse(&pkt[20..]).unwrap();
                if seg.data_len() > 0 {
                    w.lock().unwrap().push((seg.seq, seg.data_len()));
                }
                let replies = {
                    let mut peer = p.lock().unwrap();
                    let mut r = peer.handle_segment(&seg);
                    let mut sink = [0u8; 65536];
                    while peer.read(&mut sink) > 0 {}
                    r.extend(peer.take_outgoing());
                    r
                };
                let state = t.get().and_then(Weak::upgrade).unwrap();
                for r in replies {
                    state.deliver(&Segment::parse(&r).unwrap());
                }
            }),
        );
        this.set(Arc::downgrade(&state)).unwrap();
        let syn = Segment::parse(&peer.lock().unwrap().connect()[0]).unwrap();
        let synack = state.conn.lock().unwrap().accept_syn(&syn);
        state.send(synack);
        assert_eq!(state.conn.lock().unwrap().state(), State::Established);

        let stream = TcpStream::new(state.clone());
        stream.set_write_timeout(Some(Duration::from_secs(10)));
        let data = vec![7u8; 1 << 20];
        let mut sent = 0;
        while sent < data.len() {
            sent += stream.write(&data[sent..]).unwrap();
        }
        let wire = wire.lock().unwrap();
        let mut next = wire[0].0;
        for &(seq, len) in wire.iter() {
            assert_eq!(seq, next, "segment sent out of order (or resent)");
            next = seq.wrapping_add(len);
        }
        assert_eq!(next.wrapping_sub(wire[0].0) as usize, data.len());
    }

    /// A timeout too long for an `Instant` means no deadline, not a panic.
    #[test]
    fn a_huge_timeout_waits_instead_of_panicking() {
        let mut peer = peer();
        let (state, out) = accepted(&mut peer);
        let stream = TcpStream::new(state.clone());
        stream.set_read_timeout(Some(Duration::MAX));
        stream.set_write_timeout(Some(Duration::MAX));
        assert_eq!(stream.write(b"ping").unwrap(), 4);
        pump(&state, &out, &mut peer);
        let mut got = [0u8; 8];
        assert_eq!(peer.read(&mut got), 4);
        for seg in peer.write(b"pong").1 {
            state.deliver(&Segment::parse(&seg).unwrap());
        }
        let mut buf = [0u8; 8];
        assert_eq!(stream.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"pong");
    }

    /// A write that the peer's closed window holds back gives up at the
    /// write timeout instead of blocking forever.
    #[test]
    fn a_write_into_a_closed_window_times_out() {
        let mut peer = Conn::new(
            ConnConfig::default()
                .local_port(5000)
                .remote_port(80)
                .recv_buf_size(1000),
        );
        let (state, out) = accepted(&mut peer);
        let stream = TcpStream::new(state.clone());
        stream.set_write_timeout(Some(Duration::from_millis(200)));
        // The peer never reads: its 1000-byte window fills and stays shut.
        // More than the stack's own 1 MiB send buffer can hold.
        let big = vec![7u8; 2 << 20];
        let started = Instant::now();
        let n = std::thread::scope(|s| {
            let w = s.spawn(|| stream.write(&big));
            while !w.is_finished() {
                pump(&state, &out, &mut peer);
                std::thread::sleep(Duration::from_millis(5));
            }
            w.join().unwrap()
        })
        .unwrap();
        assert!(n < big.len(), "wrote {n}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A tick that changes nothing a waiter could act on wakes nobody: the
    /// tick visits every connection of the stack ten times a second, and
    /// would otherwise wake every thread blocked on one of them as often.
    #[test]
    fn an_idle_tick_wakes_no_waiter() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mut peer = peer();
        let (state, out) =
            accepted_with(&mut peer, ConnConfig::default().time_wait(Duration::ZERO));
        let ready = Arc::new(AtomicBool::new(false));
        let (s2, r2) = (state.clone(), ready.clone());
        let waiter = std::thread::spawn(move || {
            let conn = s2.conn.lock().unwrap();
            r2.store(true, Ordering::SeqCst);
            let (_conn, r) = s2
                .signal
                .wait_timeout(conn, Duration::from_millis(500))
                .unwrap();
            !r.timed_out()
        });
        while !ready.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        // Taken only once the waiter is waiting, as waiting releases it.
        drop(state.conn.lock().unwrap());
        for _ in 0..5 {
            assert!(!tick_conn(&state));
        }
        assert!(!waiter.join().unwrap(), "an idle tick woke the waiter");

        // One that closes the connection does wake it: here, the end of a
        // TIME-WAIT that the engine's own timer ends.
        let fin = state.conn.lock().unwrap().close();
        state.send(fin);
        pump(&state, &out, &mut peer);
        for seg in peer.close() {
            state.deliver(&Segment::parse(&seg).unwrap());
        }
        assert_eq!(state.conn.lock().unwrap().state(), State::TimeWait);
        let ready = Arc::new(AtomicBool::new(false));
        let (s2, r2) = (state.clone(), ready.clone());
        let waiter = std::thread::spawn(move || {
            let conn = s2.conn.lock().unwrap();
            r2.store(true, Ordering::SeqCst);
            let (conn, _) = s2
                .signal
                .wait_timeout_while(conn, Duration::from_secs(5), |c| !c.is_closed())
                .unwrap();
            conn.is_closed()
        });
        while !ready.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        drop(state.conn.lock().unwrap());
        assert!(tick_conn(&state));
        assert!(waiter.join().unwrap());
    }
}

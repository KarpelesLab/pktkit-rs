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
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
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
    fn wrap(&self, seg: &[u8]) -> Vec<u8> {
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

    fn local_addr(&self) -> SocketAddr {
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

    fn peer_addr(&self) -> SocketAddr {
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
    pub(crate) conn: Mutex<Conn>,
    /// Notified whenever readable/writable/closed status may have changed
    /// (inbound data, state transition, timer tick).
    pub(crate) signal: Condvar,
    /// Sink for fully-framed IP packets the engine wants to transmit back into
    /// the virtual network. Provided by the stack (wraps `Stack::dispatch`).
    pub(crate) sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    /// For a passively opened connection: hands it to its listener once the
    /// handshake completes, unless the deadline passes first.
    pending_accept: Mutex<Option<(Instant, AcceptFn)>>,
    /// Why the connection ended, if not by an orderly close: a reset from
    /// the peer, or our timers giving up. Reads report it instead of a clean
    /// end of stream, so a truncated transfer is not mistaken for a whole one.
    error: Mutex<Option<io::ErrorKind>>,
}

/// Offers an established connection to a listener; `false` means the
/// listener refused it (closed, or its queue is full).
pub(crate) type AcceptFn = Box<dyn FnOnce(Arc<ConnState>) -> bool + Send>;

/// How long a passively opened connection may take to complete its
/// handshake before it is dropped.
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl ConnState {
    pub(crate) fn new(
        endpoints: Endpoints,
        conn: Conn,
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    ) -> Arc<ConnState> {
        Arc::new(ConnState {
            endpoints,
            conn: Mutex::new(conn),
            signal: Condvar::new(),
            sink,
            pending_accept: Mutex::new(None),
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
    pub(crate) fn set_pending_accept(&self, accept: AcceptFn) {
        *self.pending_accept.lock().expect("poisoned") =
            Some((Instant::now() + ACCEPT_HANDSHAKE_TIMEOUT, accept));
    }

    /// Hand a passively opened connection to its listener if its handshake
    /// has just completed. Call it after every inbound segment.
    ///
    /// Returns `false` when the connection is finished with: the listener
    /// refused it, so it has been aborted and the caller should drop it from
    /// its table.
    pub(crate) fn complete_accept(self: &Arc<Self>) -> bool {
        let mut pending = self.pending_accept.lock().expect("poisoned");
        if pending.is_none()
            || !self
                .conn
                .lock()
                .expect("poisoned")
                .state()
                .is_synchronized()
        {
            return true;
        }
        let (_, accept) = pending.take().expect("checked above");
        drop(pending);
        if accept(self.clone()) {
            return true;
        }
        self.abort();
        false
    }

    /// Send a RST and close.
    fn abort(&self) {
        let segs = self.conn.lock().expect("poisoned").abort();
        self.wrap_and_send(segs);
        self.signal.notify_all();
    }

    /// Wrap each segment in IP and push it into the virtual network.
    pub(crate) fn wrap_and_send(&self, segments: Vec<Vec<u8>>) {
        for seg in segments {
            let pkt = self.endpoints.wrap(&seg);
            (self.sink)(&pkt);
        }
    }

    /// Feed an inbound segment to the engine, transmit its replies, and wake
    /// any blocked reader/writer.
    pub(crate) fn deliver(&self, seg: &Segment) {
        let segs = {
            let mut conn = self.conn.lock().expect("poisoned");
            // A FIN before the RST means the stream had already ended whole.
            let ended = conn.fin_received();
            let segs = conn.handle_segment(seg);
            if seg.has_flag(crate::vtcp::segment::flags::RST) && conn.is_closed() && !ended {
                self.fail(io::ErrorKind::ConnectionReset);
            }
            segs
        };
        self.wrap_and_send(segs);
        self.signal.notify_all();
    }
}

/// A blocking, accepted TCP stream over the virtual network.
///
/// Returned by [`Listener::accept`](super::Listener::accept). Implements
/// [`std::io::Read`] + [`std::io::Write`]. Dropping it closes the
/// connection gracefully, unless received data was left unread: then, as a
/// host stack does (RFC 2525 §2.17), the peer gets a reset.
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
    pub fn peer_addr(&self) -> SocketAddr {
        self.state.endpoints.peer_addr()
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
        let deadline = self
            .write_timeout
            .lock()
            .expect("poisoned")
            .map(|t| Instant::now() + t);
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
            drop(conn);
            if n > 0 {
                self.state.wrap_and_send(segs);
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
    /// Returns 0 at end of stream.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self
            .read_timeout
            .lock()
            .expect("poisoned")
            .map(|t| Instant::now() + t);
        let mut conn = self.state.conn.lock().expect("poisoned");
        loop {
            let n = conn.read(buf);
            if n > 0 {
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
        let segs = {
            let mut conn = self.state.conn.lock().expect("poisoned");
            conn.close()
        };
        self.state.wrap_and_send(segs);
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
        let segs = self.state.conn.lock().expect("poisoned").release();
        self.state.wrap_and_send(segs);
        self.state.signal.notify_all();
    }
}

/// Helper used by the stack's tick thread: drive timers for one connection and
/// wake any waiters. Returns `true` if the connection is now closed (so the
/// caller can drop it from the table).
pub(crate) fn tick_conn(state: &Arc<ConnState>) -> bool {
    // A handshake that has not completed in time is abandoned, as a listen
    // queue would drop a stale embryonic connection.
    let expired = matches!(
        &*state.pending_accept.lock().expect("poisoned"),
        Some((deadline, _)) if Instant::now() >= *deadline
    );
    if expired {
        state.pending_accept.lock().expect("poisoned").take();
        state.abort();
    }
    let (segs, closed) = {
        let mut conn = state.conn.lock().expect("poisoned");
        let ended = conn.fin_received();
        let segs = conn.tick();
        let closed = conn.is_closed();
        if closed && !ended {
            // Retransmissions or keepalives went unanswered.
            state.fail(io::ErrorKind::TimedOut);
        }
        (segs, closed)
    };
    if !segs.is_empty() {
        state.wrap_and_send(segs);
    }
    state.signal.notify_all();
    closed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::ConnConfig;

    /// A slirp-side connection accepted from `peer`, with everything it
    /// sends collected (as TCP segments, the 20-byte IPv4 header stripped).
    fn accepted(peer: &mut Conn) -> (Arc<ConnState>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let o = out.clone();
        let state = ConnState::new(
            Endpoints::V4 {
                local_ip: Ipv4Addr::new(10, 0, 0, 1),
                local_port: 80,
                remote_ip: Ipv4Addr::new(10, 0, 0, 5),
                remote_port: 5000,
            },
            Conn::new(ConnConfig::default().local_port(80).remote_port(5000)),
            Arc::new(move |p: &[u8]| o.lock().unwrap().push(p[20..].to_vec())),
        );
        let syn = Segment::parse(&peer.connect()[0]).unwrap();
        let synack = state.conn.lock().unwrap().accept_syn(&syn);
        state.wrap_and_send(synack);
        pump(&state, &out, peer);
        (state, out)
    }

    fn pump(state: &ConnState, out: &Mutex<Vec<Vec<u8>>>, peer: &mut Conn) {
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
}

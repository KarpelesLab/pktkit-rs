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

use crate::vtcp::segment::Segment;
use crate::vtcp::Conn;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Endpoint addressing for an accepted virtual connection. The "local" side is
/// the listener (our virtual IP:port); the "remote" side is the peer inside the
/// virtual network that connected to us.
///
/// The `V6` variant is plumbed end-to-end (wrap / addrs) but not yet wired into
/// the dispatcher — see `TODO(slirp)` for v6 accept in `usernat`.
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
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
}

impl ConnState {
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
            conn.handle_segment(seg)
        };
        self.wrap_and_send(segs);
        self.signal.notify_all();
    }
}

/// A blocking, accepted TCP stream over the virtual network.
///
/// Returned by [`Listener::accept`](super::Listener::accept). Implements
/// [`std::io::Read`] + [`std::io::Write`]; dropping it initiates a graceful
/// close.
pub struct TcpStream {
    state: Arc<ConnState>,
    read_timeout: Mutex<Option<Duration>>,
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

    /// Write all of `buf`, blocking until the engine accepts it. Returns the
    /// number of bytes queued (always `buf.len()` on success).
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let mut conn = self.state.conn.lock().expect("poisoned");
            if conn.is_closed() {
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
            } else {
                // Send window full (or not yet established) — wait for an ACK
                // to open it, or for a state transition.
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
                return Ok(0); // clean EOF
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
        let _ = self.close();
    }
}

/// Helper used by the stack's tick thread: drive timers for one connection and
/// wake any waiters. Returns `true` if the connection is now closed (so the
/// caller can drop it from the table).
pub(crate) fn tick_conn(state: &Arc<ConnState>) -> bool {
    let (segs, closed) = {
        let mut conn = state.conn.lock().expect("poisoned");
        let segs = conn.tick();
        (segs, conn.is_closed())
    };
    if !segs.is_empty() {
        state.wrap_and_send(segs);
    }
    state.signal.notify_all();
    closed
}

/// True once the connection has reached the terminal CLOSED state.
pub(crate) fn is_closed(state: &Arc<ConnState>) -> bool {
    state.conn.lock().expect("poisoned").is_closed()
}

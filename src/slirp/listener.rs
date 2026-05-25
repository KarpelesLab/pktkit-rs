//! Virtual TCP listener (IPv4).
//!
//! Mirrors `slirp/listener.go`. Wired through the in-tree `vtcp` engine: when
//! an inbound SYN arrives for a registered (IP, port), the stack mints a
//! server-side [`vtcp::Conn`](crate::vtcp::Conn), drives the handshake, and
//! enqueues the resulting [`TcpStream`](super::TcpStream) onto this listener's
//! bounded accept queue. [`Listener::accept`] blocks on that queue.

use crate::slirp::tcp_stream::{ConnState, TcpStream};
use crate::Result;
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// Bounded accept-queue depth; mirrors the Go `acceptCh` buffer of 10.
pub(crate) const ACCEPT_QUEUE_CAP: usize = 10;

/// Key used to find a listener by (IP, port). Wildcard IP is `0.0.0.0`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub(crate) struct ListenerKey {
    pub(crate) ip: [u8; 4],
    pub(crate) port: u16,
}

/// A virtual TCP listener bound to a (virtual IP, port) inside a slirp stack.
pub struct Listener {
    pub(crate) addr: SocketAddrV4,
    pub(crate) closed: Arc<AtomicBool>,
    /// Accepted-but-not-yet-returned connections, fed by the stack's packet
    /// dispatcher once a handshake completes.
    queue: Mutex<VecDeque<Arc<ConnState>>>,
    /// Signalled when a connection is enqueued or the listener is closed.
    signal: Condvar,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.addr)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl Listener {
    pub(crate) fn new(addr: SocketAddrV4) -> Listener {
        Listener {
            addr,
            closed: Arc::new(AtomicBool::new(false)),
            queue: Mutex::new(VecDeque::new()),
            signal: Condvar::new(),
        }
    }

    /// The address this listener is bound to.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// Enqueue a freshly-established connection. Returns `false` if the queue
    /// is full or the listener is closed (the caller should abort the conn).
    pub(crate) fn enqueue(&self, state: Arc<ConnState>) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let mut q = self.queue.lock().expect("poisoned");
        if q.len() >= ACCEPT_QUEUE_CAP {
            return false;
        }
        q.push_back(state);
        drop(q);
        self.signal.notify_one();
        true
    }

    /// How close the accept queue is to full; used by the stack to decide
    /// whether to fall back to a stateless SYN-cookie response.
    pub(crate) fn queue_full(&self) -> bool {
        self.queue.lock().expect("poisoned").len() >= ACCEPT_QUEUE_CAP.saturating_sub(1)
    }

    /// Block until a connection is available, returning the accepted stream.
    /// Errors if the listener is closed.
    pub fn accept(&self) -> Result<TcpStream> {
        let mut q = self.queue.lock().expect("poisoned");
        loop {
            if let Some(state) = q.pop_front() {
                return Ok(TcpStream::new(state));
            }
            if self.closed.load(Ordering::Acquire) {
                return Err(io::Error::other("listener closed"));
            }
            q = self.signal.wait(q).expect("poisoned");
        }
    }

    /// Close the listener and abort any queued-but-unaccepted connections.
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        // Abort connections still sitting in the queue.
        let drained: Vec<Arc<ConnState>> = {
            let mut q = self.queue.lock().expect("poisoned");
            q.drain(..).collect()
        };
        for state in drained {
            let segs = state.conn.lock().expect("poisoned").abort();
            state.wrap_and_send(segs);
        }
        self.signal.notify_all();
        Ok(())
    }
}

/// Convert a parsed socket-address-like string ("ip:port") to a `SocketAddrV4`.
pub(crate) fn resolve_v4(address: &str) -> Result<SocketAddrV4> {
    if let Ok(sa) = address.parse::<SocketAddrV4>() {
        return Ok(sa);
    }
    // Allow ":port" form (wildcard IPv4 address).
    if let Some(rest) = address.strip_prefix(':') {
        if let Ok(port) = rest.parse::<u16>() {
            return Ok(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid address",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::{Conn, ConnConfig};

    fn dummy_state() -> Arc<ConnState> {
        Arc::new(ConnState {
            endpoints: crate::slirp::tcp_stream::Endpoints::V4 {
                local_ip: Ipv4Addr::new(10, 0, 0, 1),
                local_port: 80,
                remote_ip: Ipv4Addr::new(10, 0, 0, 5),
                remote_port: 5000,
            },
            conn: Mutex::new(Conn::new(ConnConfig::default())),
            signal: Condvar::new(),
            sink: Arc::new(|_p: &[u8]| {}),
        })
    }

    #[test]
    fn enqueue_then_accept_returns_stream() {
        let l = Listener::new("10.0.0.1:80".parse().unwrap());
        assert!(l.enqueue(dummy_state()));
        let s = l.accept().expect("accept should yield the queued conn");
        assert_eq!(s.local_addr().port(), 80);
        assert_eq!(s.peer_addr().port(), 5000);
    }

    #[test]
    fn queue_respects_capacity() {
        let l = Listener::new("10.0.0.1:80".parse().unwrap());
        for _ in 0..ACCEPT_QUEUE_CAP {
            assert!(l.enqueue(dummy_state()));
        }
        // One past capacity is rejected.
        assert!(!l.enqueue(dummy_state()));
    }

    #[test]
    fn accept_after_close_errors() {
        let l = Listener::new("10.0.0.1:80".parse().unwrap());
        l.close().unwrap();
        assert!(l.accept().is_err());
    }
}

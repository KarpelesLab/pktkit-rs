//! Virtual TCP listener (IPv4).
//!
//! Mirrors `slirp/listener.go`. Wired through the in-tree `vtcp` engine: when
//! an inbound SYN arrives for a registered (IP, port), the stack mints a
//! server-side [`vtcp::Conn`](crate::vtcp::Conn), drives the handshake, and
//! enqueues the resulting [`TcpStream`](super::TcpStream) onto this listener's
//! bounded accept queue. [`Listener::accept`] blocks on that queue.

use crate::Result;
use crate::slirp::tcp_stream::{ConnState, TcpStream};
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// Bounded accept-queue depth; mirrors the Go `acceptCh` buffer of 10.
pub(crate) const ACCEPT_QUEUE_CAP: usize = 10;

/// Connections a listener holds in SYN-RECEIVED at once, as a listen backlog
/// bounds them. Each SYN would otherwise mint a connection that lives until
/// its handshake times out, and a flood at one listener could fill the
/// stack-wide table of virtual connections that every listener shares.
pub(crate) const HALF_OPEN_CAP: usize = 128;

/// One of a listener's [`HALF_OPEN_CAP`] half-open slots, held by a
/// connection until its handshake completes or it is dropped.
#[derive(Debug)]
pub(crate) struct HalfOpenSlot(Arc<AtomicUsize>);

impl HalfOpenSlot {
    /// Take a slot from `count`, unless all are in use.
    pub(crate) fn take(count: &Arc<AtomicUsize>) -> Option<HalfOpenSlot> {
        crate::stats::add_within(count, 1, HALF_OPEN_CAP).then(|| HalfOpenSlot(count.clone()))
    }
}

impl Drop for HalfOpenSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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
    /// Removes this listener from the stack's table; taken by the first close.
    unregister: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Connections still in their handshake; see [`HalfOpenSlot`].
    half_open: Arc<AtomicUsize>,
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
            unregister: Mutex::new(None),
            half_open: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Install the hook that frees the address in the stack once this
    /// listener is closed or dropped.
    pub(crate) fn set_unregister(&self, f: Box<dyn FnOnce() + Send>) {
        *self.unregister.lock().expect("poisoned") = Some(f);
    }

    /// The address this listener is bound to.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// Enqueue a freshly-established connection. Returns `false` if the queue
    /// is full or the listener is closed (the caller should abort the conn).
    pub(crate) fn enqueue(&self, state: Arc<ConnState>) -> bool {
        // Checked under the queue lock, which `close` also takes to set the
        // flag and drain the queue: checked before it, a close could slip in
        // between and leave this connection queued where nobody will ever
        // accept or reset it.
        let mut q = self.queue.lock().expect("poisoned");
        if self.closed.load(Ordering::Acquire) || q.len() >= ACCEPT_QUEUE_CAP {
            return false;
        }
        q.push_back(state);
        drop(q);
        self.signal.notify_one();
        true
    }

    /// A half-open slot for a new connection, or `None` when the listener
    /// already has [`HALF_OPEN_CAP`] handshakes under way.
    pub(crate) fn half_open_slot(&self) -> Option<HalfOpenSlot> {
        HalfOpenSlot::take(&self.half_open)
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

    /// Close the listener, free its address in the stack, and abort any
    /// queued-but-unaccepted connections. Dropping the last handle does the
    /// same.
    pub fn close(&self) -> Result<()> {
        // Abort connections still sitting in the queue. The flag is set
        // under the queue lock, so `enqueue` either sees it or has already
        // queued what is drained here.
        let drained: Vec<Arc<ConnState>> = {
            let mut q = self.queue.lock().expect("poisoned");
            self.closed.store(true, Ordering::Release);
            q.drain(..).collect()
        };
        let unregister = self.unregister.lock().expect("poisoned").take();
        if let Some(f) = unregister {
            f();
        }
        for state in drained {
            state.abort();
        }
        self.signal.notify_all();
        Ok(())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Convert a parsed socket-address-like string ("ip:port") to a `SocketAddrV4`.
pub(crate) fn resolve_v4(address: &str) -> Result<SocketAddrV4> {
    if let Ok(sa) = address.parse::<SocketAddrV4>() {
        return Ok(sa);
    }
    // Allow ":port" form (wildcard IPv4 address).
    if let Some(rest) = address.strip_prefix(':')
        && let Ok(port) = rest.parse::<u16>()
    {
        return Ok(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
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
        ConnState::new(
            crate::slirp::tcp_stream::Endpoints::V4 {
                local_ip: Ipv4Addr::new(10, 0, 0, 1),
                local_port: 80,
                remote_ip: Ipv4Addr::new(10, 0, 0, 5),
                remote_port: 5000,
            },
            Conn::new(ConnConfig::default()),
            Arc::new(|_p: &[u8]| {}),
        )
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

    /// A close landing while `enqueue` waits for the queue lock must stop
    /// it: `close` drains the queue only once, so anything queued after
    /// that is never accepted nor reset.
    #[test]
    fn enqueue_checks_closed_under_the_queue_lock() {
        let l = Arc::new(Listener::new("10.0.0.1:80".parse().unwrap()));
        let held = l.queue.lock().unwrap();
        let l2 = l.clone();
        let t = std::thread::spawn(move || l2.enqueue(dummy_state()));
        std::thread::sleep(std::time::Duration::from_millis(50));
        l.closed.store(true, Ordering::Release);
        drop(held);
        assert!(!t.join().unwrap(), "queued on a closed listener");
        assert!(l.queue.lock().unwrap().is_empty());
    }
}

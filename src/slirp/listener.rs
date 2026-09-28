//! Virtual TCP listener (IPv4).
//!
//! Mirrors `slirp/listener.go`. Wired through the in-tree `vtcp` engine: when
//! an inbound SYN arrives for a registered (IP, port), the stack mints a
//! server-side [`vtcp::Conn`](crate::vtcp::Conn), drives the handshake, and
//! enqueues the resulting [`TcpStream`](super::TcpStream) onto this listener's
//! bounded accept queue. [`Listener::accept`] blocks on that queue.

use crate::Result;
use crate::slirp::tcp_stream::{ConnState, Offer, TcpStream};
use crate::time::Instant;
use crate::vtcp::Segment;
use crate::vtcp::syncookie::SynCookies;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

/// Bounded accept-queue depth; mirrors the Go `acceptCh` buffer of 10.
pub(crate) const ACCEPT_QUEUE_CAP: usize = 10;

/// Connections a listener holds in SYN-RECEIVED at once, as a listen backlog
/// bounds them. Each SYN would otherwise mint a connection that lives until
/// its handshake times out, and a flood at one listener could fill the
/// stack-wide table of virtual connections that every listener shares.
///
/// Like the stack's other caps, it is shared out between namespaces (see
/// `usernat::NS_SHARE`): one guest sending SYNs it never completes would
/// otherwise keep the backlog full for every guest. SYNs past it are
/// answered with a SYN cookie (see [`CookieJar`]).
pub(crate) const HALF_OPEN_CAP: usize = 128;

/// Half-open connections a listener holds counting those rebuilt from a
/// SYN cookie whose ACK came in while the accept queue was full. The
/// backlog is full then (or the SYN would not have had a cookie), and
/// without this headroom the cookie's peer would be reset as soon as it
/// sent a second segment. Such a peer has shown it receives at its
/// address, which a flood of SYNs does not, but a bound is still needed
/// against one that opens and abandons connections on purpose.
pub(crate) const COOKIE_HALF_OPEN_CAP: usize = 2 * HALF_OPEN_CAP;

/// How long after the last cookie went out an ACK is still checked for one:
/// a cookie is valid for 64 to 128 s (two counter periods of vtcp's
/// `SynCookies`).
const COOKIE_WINDOW: Duration = Duration::from_secs(128);

/// A listener's SYN cookies: past its backlog, a SYN is answered with a
/// SYN-ACK that carries the handshake's state in its sequence number and
/// keeps none here, so SYNs that are never completed cannot lock out the
/// peers that do complete theirs.
#[derive(Debug, Default)]
pub(crate) struct CookieJar {
    cookies: SynCookies,
    /// When the last cookie went out. Only an ACK arriving soon enough
    /// after is checked for one, so stray ACKs are not hashed otherwise.
    sent: Mutex<Option<Instant>>,
}

impl CookieJar {
    /// The SYN-ACK answering `syn`, received at `local` from `remote`, with
    /// a cookie for its ISS. `mss` is the MSS we advertise.
    pub(crate) fn syn_ack(
        &self,
        syn: &Segment,
        local: IpAddr,
        remote: IpAddr,
        mss: u16,
    ) -> Segment {
        *self.sent.lock().expect("poisoned") = Some(Instant::now());
        self.cookies.generate_syn_ack(syn, local, remote, mss)
    }

    /// The MSS to send with, if `ack`, received at `local` from `remote`,
    /// completes a cookie handshake.
    pub(crate) fn validate(&self, ack: &Segment, local: IpAddr, remote: IpAddr) -> Option<u16> {
        let recent = self
            .sent
            .lock()
            .expect("poisoned")
            .is_some_and(|t| Instant::now().saturating_duration_since(t) < COOKIE_WINDOW);
        if !recent {
            return None;
        }
        let (mss, _) = self.cookies.validate_ack(ack, local, remote)?;
        Some(mss)
    }
}

/// What the stack's accept path needs of a listener, IPv4 or IPv6.
pub(crate) trait Backlog: Send + Sync + 'static {
    /// Enqueue a connection whose handshake has completed.
    fn enqueue(&self, state: &Arc<ConnState>) -> Offer;
    /// Whether the accept queue has no room for `state`, listing it to be
    /// offered room once it has.
    fn hold(&self, state: &Arc<ConnState>) -> bool;
    /// Whether the accept queue is full.
    fn queue_full(&self) -> bool;
    /// A half-open slot for namespace `ns`, unless the listener has `cap`
    /// in use, or `ns` has `ns_cap`.
    fn half_open_slot(&self, ns: u64, cap: usize, ns_cap: usize) -> Option<HalfOpenSlot>;
    fn cookies(&self) -> &CookieJar;
}

/// A listener's half-open connections, in all and per namespace.
#[derive(Debug, Default)]
pub(crate) struct HalfOpen {
    all: usize,
    per_ns: HashMap<u64, usize>,
}

/// One of a listener's [`HALF_OPEN_CAP`] half-open slots, held by a
/// connection until its handshake completes or it is dropped.
#[derive(Debug)]
pub(crate) struct HalfOpenSlot {
    table: Arc<Mutex<HalfOpen>>,
    ns: u64,
}

impl HalfOpenSlot {
    /// Take a slot for namespace `ns` from `table`, unless the listener has
    /// `cap` in use or `ns` already holds `ns_cap`.
    pub(crate) fn take(
        table: &Arc<Mutex<HalfOpen>>,
        ns: u64,
        cap: usize,
        ns_cap: usize,
    ) -> Option<HalfOpenSlot> {
        let mut t = table.lock().expect("poisoned");
        let mine = t.per_ns.get(&ns).copied().unwrap_or(0);
        if t.all >= cap || mine >= ns_cap {
            return None;
        }
        t.all += 1;
        t.per_ns.insert(ns, mine + 1);
        Some(HalfOpenSlot {
            table: table.clone(),
            ns,
        })
    }
}

impl Drop for HalfOpenSlot {
    fn drop(&mut self) {
        let mut t = self.table.lock().expect("poisoned");
        t.all -= 1;
        if let Some(n) = t.per_ns.get_mut(&self.ns) {
            *n -= 1;
            if *n == 0 {
                t.per_ns.remove(&self.ns);
            }
        }
    }
}

/// Connections a full accept queue had no room for, in the order they
/// found it full, offered again as `accept` makes room (see
/// `ConnState::complete_accept`): handshakes held back in SYN-RECEIVED
/// (`ConnState::held_back`), and ones that completed just as another took
/// the last place.
///
/// Every tick offers each of them again, up to [`HALF_OPEN_CAP`] per
/// listener, so the check that one is already listed is a set lookup rather
/// than a walk of the list. An entry goes stale when its connection is
/// dropped (its handshake ran out of time, or the peer reset it) or taken
/// by a later offer; stale entries are skipped when room is offered and
/// swept out once they make up most of the list, which keeps it within a
/// small multiple of the live entries, themselves bounded by the half-open
/// slots each holds.
#[derive(Debug, Default)]
pub(crate) struct Waiting {
    order: VecDeque<Weak<ConnState>>,
    /// The connections listed in `order`, by address. The `Weak` in
    /// `order` keeps the allocation, so an address is not reused while it
    /// is here.
    listed: HashSet<usize>,
    /// The length of `order` at which stale entries are next swept out.
    sweep_at: usize,
}

impl Waiting {
    fn id(state: &Weak<ConnState>) -> usize {
        state.as_ptr() as usize
    }

    /// List `state`, unless it already is.
    pub(crate) fn add(&mut self, state: &Arc<ConnState>) {
        let weak = Arc::downgrade(state);
        if !self.listed.insert(Self::id(&weak)) {
            return;
        }
        self.order.push_back(weak);
        if self.order.len() >= self.sweep_at.max(2 * HALF_OPEN_CAP) {
            self.sweep();
        }
    }

    /// Unlist `state`: its listener has taken or refused it.
    pub(crate) fn remove(&mut self, state: &Arc<ConnState>) {
        self.listed.remove(&(Arc::as_ptr(state) as usize));
    }

    /// The listed connection that has waited longest and is still alive.
    pub(crate) fn pop(&mut self) -> Option<Arc<ConnState>> {
        while let Some(weak) = self.order.pop_front() {
            if !self.listed.remove(&Self::id(&weak)) {
                continue;
            }
            if let Some(state) = weak.upgrade() {
                return Some(state);
            }
        }
        None
    }

    /// Drop the entries of connections that are gone or no longer listed.
    fn sweep(&mut self) {
        let listed = &mut self.listed;
        self.order.retain(|w| {
            let live = w.strong_count() > 0;
            let id = Self::id(w);
            if !live {
                listed.remove(&id);
            }
            live && listed.contains(&id)
        });
        // Swept again only once the list has doubled: a sweep costs the
        // list's length, so this keeps each addition's share constant.
        self.sweep_at = 2 * self.order.len();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.order.len()
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
    /// Connections the full queue had no room for.
    waiting: Mutex<Waiting>,
    /// Removes this listener from the stack's table; taken by the first close.
    unregister: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Connections still in their handshake; see [`HalfOpenSlot`].
    half_open: Arc<Mutex<HalfOpen>>,
    cookies: CookieJar,
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
            waiting: Mutex::new(Waiting::default()),
            unregister: Mutex::new(None),
            half_open: Arc::default(),
            cookies: CookieJar::default(),
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

    /// Enqueue a freshly-established connection, unless the queue is full or
    /// the listener closed.
    pub(crate) fn enqueue(&self, state: &Arc<ConnState>) -> Offer {
        // Checked under the queue lock, which `close` also takes to set the
        // flag and drain the queue: checked before it, a close could slip in
        // between and leave this connection queued where nobody will ever
        // accept or reset it.
        let mut q = self.queue.lock().expect("poisoned");
        if self.closed.load(Ordering::Acquire) {
            return Offer::Refused;
        }
        if q.len() >= ACCEPT_QUEUE_CAP {
            // Offered again on every tick until room appears: listed once.
            self.waiting.lock().expect("poisoned").add(state);
            return Offer::Full;
        }
        q.push_back(state.clone());
        drop(q);
        self.waiting.lock().expect("poisoned").remove(state);
        self.signal.notify_one();
        Offer::Taken
    }

    /// Whether the accept queue has no room for `state`; if it has none,
    /// `state` is listed to be offered the room `accept` makes (see
    /// `ConnState::held_back`).
    pub(crate) fn hold(&self, state: &Arc<ConnState>) -> bool {
        let q = self.queue.lock().expect("poisoned");
        if q.len() < ACCEPT_QUEUE_CAP || self.closed.load(Ordering::Acquire) {
            return false;
        }
        self.waiting.lock().expect("poisoned").add(state);
        true
    }

    fn queue_full(&self) -> bool {
        self.queue.lock().expect("poisoned").len() >= ACCEPT_QUEUE_CAP
    }

    /// Block until a connection is available, returning the accepted stream.
    /// Errors if the listener is closed.
    pub fn accept(&self) -> Result<TcpStream> {
        let mut q = self.queue.lock().expect("poisoned");
        loop {
            if let Some(state) = q.pop_front() {
                drop(q);
                self.offer_waiting();
                return Ok(TcpStream::new(state));
            }
            if self.closed.load(Ordering::Acquire) {
                return Err(io::Error::other("listener closed"));
            }
            q = self.signal.wait(q).expect("poisoned");
        }
    }

    /// Offer the room `accept` has just made to the connection that has
    /// waited longest for it, rather than leave it to the next tick.
    fn offer_waiting(&self) {
        let next = self.waiting.lock().expect("poisoned").pop();
        if let Some(state) = next {
            state.complete_accept();
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

impl Backlog for Listener {
    fn enqueue(&self, state: &Arc<ConnState>) -> Offer {
        Listener::enqueue(self, state)
    }
    fn hold(&self, state: &Arc<ConnState>) -> bool {
        Listener::hold(self, state)
    }
    fn queue_full(&self) -> bool {
        Listener::queue_full(self)
    }
    fn half_open_slot(&self, ns: u64, cap: usize, ns_cap: usize) -> Option<HalfOpenSlot> {
        HalfOpenSlot::take(&self.half_open, ns, cap, ns_cap)
    }
    fn cookies(&self) -> &CookieJar {
        &self.cookies
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
        assert_eq!(l.enqueue(&dummy_state()), Offer::Taken);
        let s = l.accept().expect("accept should yield the queued conn");
        assert_eq!(s.local_addr().port(), 80);
        assert_eq!(s.peer_addr().port(), 5000);
    }

    #[test]
    fn queue_respects_capacity() {
        let l = Listener::new("10.0.0.1:80".parse().unwrap());
        for _ in 0..ACCEPT_QUEUE_CAP {
            assert_eq!(l.enqueue(&dummy_state()), Offer::Taken);
        }
        // One past capacity waits for room.
        assert_eq!(l.enqueue(&dummy_state()), Offer::Full);
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
        let t = std::thread::spawn(move || l2.enqueue(&dummy_state()));
        std::thread::sleep(std::time::Duration::from_millis(50));
        l.closed.store(true, Ordering::Release);
        drop(held);
        assert_eq!(
            t.join().unwrap(),
            Offer::Refused,
            "queued on a closed listener"
        );
        assert!(l.queue.lock().unwrap().is_empty());
    }

    /// Connections that waited for room and then went, whether dropped or
    /// taken by a later offer, must not stay on the waiting list: a full
    /// queue meeting a stream of handshakes would otherwise grow it, and
    /// the walk that each offer made of it, without bound.
    #[test]
    fn the_waiting_list_forgets_connections_that_went() {
        let l = Listener::new("10.0.0.1:80".parse().unwrap());
        let queued: Vec<_> = (0..ACCEPT_QUEUE_CAP).map(|_| dummy_state()).collect();
        for s in &queued {
            assert_eq!(l.enqueue(s), Offer::Taken);
        }
        // Handshakes that found the queue full and then timed out.
        for _ in 0..20_000 {
            assert_eq!(l.enqueue(&dummy_state()), Offer::Full);
        }
        assert!(l.waiting.lock().unwrap().len() <= 2 * HALF_OPEN_CAP);
        // Ones still alive, offered again on every tick: listed once.
        let alive: Vec<_> = (0..HALF_OPEN_CAP).map(|_| dummy_state()).collect();
        for _ in 0..3 {
            for s in &alive {
                assert_eq!(l.enqueue(s), Offer::Full);
            }
        }
        assert!(l.waiting.lock().unwrap().len() <= 2 * HALF_OPEN_CAP);
        // Room made on the side, and every one of them taken by an offer.
        l.queue.lock().unwrap().clear();
        for s in alive.iter().take(ACCEPT_QUEUE_CAP) {
            assert_eq!(l.enqueue(s), Offer::Taken);
        }
        // The rest are the only ones left to offer room to.
        let mut w = l.waiting.lock().unwrap();
        let mut left = 0;
        while let Some(s) = w.pop() {
            assert!(alive[ACCEPT_QUEUE_CAP..].iter().any(|a| Arc::ptr_eq(a, &s)));
            left += 1;
        }
        assert_eq!(left, HALF_OPEN_CAP - ACCEPT_QUEUE_CAP);
    }
}

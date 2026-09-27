//! Link impairment: delay, jitter, loss, duplication, corruption and rate limits.
//!
//! A virtual topology is a perfect network — packets arrive instantly, in
//! order, uncorrupted. Real ones do not, and code that has only ever run on a
//! perfect link tends to discover its retransmit path in production. Wrapping a
//! device in [`ImpairL2`] or [`ImpairL3`] puts a specific, reproducible amount
//! of badness on the wire.
//!
//! ```
//! # use std::sync::Arc;
//! # use std::time::Duration;
//! # use pktkit::{L2Device, MacAddr, PipeL2};
//! # use pktkit::impair::{ImpairL2, Impairment};
//! let inner: Arc<dyn L2Device> = Arc::new(PipeL2::new(MacAddr::zero()));
//! let link = ImpairL2::new(
//!     inner,
//!     Impairment::default()
//!         .delay(Duration::from_millis(50))
//!         .jitter(Duration::from_millis(10))
//!         .loss(0.01)
//!         .rate_bps(10_000_000),
//! );
//! # let _ = link.hw_addr();
//! ```
//!
//! Impairment applies in **both** directions: what the device sends and what it
//! receives. The wrapper takes over the wrapped device's handler when its own
//! is first set; until then, what the wrapped device receives stays with it,
//! as if no handler were set at all. Set [`Impairment::seed`] to make a run reproducible — the same
//! seed drops and delays the same packets, which is what turns a flaky failure
//! into a test case.
//!
//! # Ordering
//!
//! Packets are released in deadline order, so jitter reorders traffic exactly
//! as a real link does: a packet drawn a short delay overtakes one drawn a long
//! one. With `jitter` at zero, order is preserved.
//!
//! # Without threads
//!
//! Delayed messages are normally released by a background thread. `wasm32`
//! has no threads, so there nothing leaves the delay queue until
//! [`ImpairL2::poll`] / [`ImpairL3::poll`] is called; each call returns how
//! long until the next message is due, which is when to call it again.

use crate::time::Instant;
use crate::{
    DeviceStats, Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Result,
};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

/// How badly to treat traffic crossing a link.
///
/// The default is a perfect link: no delay, no loss, unlimited rate. Every
/// probability is in `0.0..=1.0` and is drawn per message, per direction.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Impairment {
    /// Base one-way latency added to every message.
    pub delay: Duration,
    /// Extra latency drawn uniformly from `0..jitter` on top of `delay`.
    /// Non-zero jitter reorders traffic.
    pub jitter: Duration,
    /// Probability a message is dropped outright.
    pub loss: f64,
    /// Probability a message is delivered twice.
    pub duplicate: f64,
    /// Probability a single random bit is flipped in the payload.
    pub corrupt: f64,
    /// Link rate in bits per second; 0 means unlimited. Messages are
    /// serialized at this rate, so a burst queues behind itself the way it
    /// would on a real link.
    pub rate_bps: u64,
    /// Maximum messages held in the delay queue per direction. Further
    /// messages are dropped, modelling a finite transmit buffer.
    pub queue_limit: usize,
    /// Seed for the impairment RNG. Zero picks an arbitrary seed; any other
    /// value makes the run reproducible.
    pub seed: u64,
}

setters! {
    Impairment {
        set delay: Duration;
        set jitter: Duration;
        set loss: f64;
        set duplicate: f64;
        set corrupt: f64;
        set rate_bps: u64;
        set queue_limit: usize;
        set seed: u64;
    }
}

impl Default for Impairment {
    fn default() -> Impairment {
        Impairment {
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss: 0.0,
            duplicate: 0.0,
            corrupt: 0.0,
            rate_bps: 0,
            queue_limit: 1024,
            seed: 0,
        }
    }
}

impl Impairment {
    /// True if this configuration would leave every message untouched.
    pub fn is_perfect(&self) -> bool {
        self.delay.is_zero()
            && self.jitter.is_zero()
            && self.loss == 0.0
            && self.duplicate == 0.0
            && self.corrupt == 0.0
            && self.rate_bps == 0
    }
}

/// Which way a message is travelling through the impaired link.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Direction {
    /// From the wrapper's user out to the wrapped device.
    Tx,
    /// From the wrapped device in to the wrapper's handler.
    Rx,
}

/// Deterministic xorshift64*, so a seeded run repeats exactly.
#[derive(Debug)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(if seed == 0 {
            // Any non-zero seed will do when the caller does not care.
            crate::rand::u64() | 1
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A float in `[0, 1)`.
    fn next_f64(&mut self) -> f64 {
        // 53 bits of mantissa is the most an f64 can hold exactly.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A value in `[0, n)`; zero when `n` is zero.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// One message waiting for its release time.
struct Queued {
    at: Instant,
    /// Tie-breaker so messages with the same deadline keep arrival order.
    seq: u64,
    dir: Direction,
    data: Vec<u8>,
}

impl PartialEq for Queued {
    fn eq(&self, other: &Queued) -> bool {
        (self.at, self.seq) == (other.at, other.seq)
    }
}
impl Eq for Queued {}
impl PartialOrd for Queued {
    fn partial_cmp(&self, other: &Queued) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Queued {
    fn cmp(&self, other: &Queued) -> std::cmp::Ordering {
        (self.at, self.seq).cmp(&(other.at, other.seq))
    }
}

#[derive(Default)]
struct Queue {
    heap: BinaryHeap<Reverse<Queued>>,
    seq: u64,
    running: bool,
    /// Messages taken off the heap but not yet handed over. They are no
    /// longer queued, yet the link is not idle until they are out.
    in_flight: usize,
    /// When each direction's link finishes serializing what it already has.
    free_at: [Option<Instant>; 2],
}

impl Queue {
    fn len(&self) -> usize {
        self.heap.len()
    }
}

/// The impairment machinery, shared between the wrapper and its worker thread.
struct Engine {
    cfg: Mutex<Impairment>,
    rng: Mutex<Rng>,
    queue: Mutex<Queue>,
    wake: Condvar,
    /// Held while taking due messages off the queue *and* delivering them,
    /// by the release thread and by `poll` alike, so that deliveries from the
    /// two never interleave out of order.
    delivering: DeliveryLock,
    stats: DeviceStats,
}

/// A lock a thread cannot take twice: the second, nested attempt is told so
/// instead of deadlocking. A handler that calls `poll` from inside a delivery
/// is the nested case. `poll` never waits for it at all (see
/// [`try_acquire`](Self::try_acquire)).
#[derive(Default)]
struct DeliveryLock {
    owner: Mutex<Option<std::thread::ThreadId>>,
    free: Condvar,
}

struct DeliveryGuard<'a>(&'a DeliveryLock);

impl DeliveryLock {
    /// Take the lock if nobody holds it; `None` otherwise, without waiting.
    ///
    /// For `poll`: the release thread holds this while running handlers, and
    /// a handler may want a lock the thread calling `poll` already holds.
    /// Waiting would be a deadlock; and while the release thread is
    /// delivering there is nothing for `poll` to do, since that thread goes
    /// on to deliver whatever else has come due before it sleeps again.
    fn try_acquire(&self) -> Option<DeliveryGuard<'_>> {
        let mut owner = self.owner.lock().unwrap();
        if owner.is_some() {
            return None;
        }
        *owner = Some(std::thread::current().id());
        Some(DeliveryGuard(self))
    }

    /// Wait for the lock; `None` if this thread already holds it.
    #[cfg(not(target_family = "wasm"))]
    fn acquire(&self) -> Option<DeliveryGuard<'_>> {
        let me = std::thread::current().id();
        let mut owner = self.owner.lock().unwrap();
        loop {
            match *owner {
                None => {
                    *owner = Some(me);
                    return Some(DeliveryGuard(self));
                }
                Some(t) if t == me => return None,
                // Only reachable with threads: without them nobody else can
                // be holding it.
                Some(_) => owner = self.free.wait(owner).unwrap(),
            }
        }
    }
}

impl DeliveryLock {
    /// Whether this thread is inside a delivery: a handler, further up.
    #[cfg(not(target_family = "wasm"))]
    fn held_here(&self) -> bool {
        *self.owner.lock().unwrap() == Some(std::thread::current().id())
    }
}

impl Drop for DeliveryGuard<'_> {
    fn drop(&mut self) {
        *self.0.owner.lock().unwrap() = None;
        self.0.free.notify_one();
    }
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("queued", &self.queue.lock().map(|q| q.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl Engine {
    fn new(cfg: Impairment) -> Arc<Engine> {
        let rng = Rng::new(cfg.seed);
        Arc::new(Engine {
            cfg: Mutex::new(cfg),
            rng: Mutex::new(rng),
            queue: Mutex::new(Queue {
                running: true,
                ..Default::default()
            }),
            wake: Condvar::new(),
            delivering: DeliveryLock::default(),
            stats: DeviceStats::new(),
        })
    }

    /// Spawn the release thread. `deliver` is called once per message, at or
    /// after its deadline, from that thread.
    #[cfg(not(target_family = "wasm"))]
    fn spawn<F>(self: &Arc<Self>, deliver: F) -> JoinHandle<()>
    where
        F: Fn(Direction, &[u8]) + Send + 'static,
    {
        let engine = self.clone();
        std::thread::spawn(move || engine.run(deliver))
    }

    #[cfg(not(target_family = "wasm"))]
    fn run<F>(&self, deliver: F)
    where
        F: Fn(Direction, &[u8]),
    {
        loop {
            {
                let mut q = self.queue.lock().unwrap();
                loop {
                    if !q.running {
                        return;
                    }
                    let now = Instant::now();
                    match q.heap.peek() {
                        Some(Reverse(head)) if head.at <= now => break,
                        Some(Reverse(head)) => {
                            let wait = head.at - now;
                            q = self.wake.wait_timeout(q, wait).unwrap().0;
                        }
                        None => q = self.wake.wait(q).unwrap(),
                    }
                }
            }
            // Take everything that has come due in one pass so a burst does
            // not pay for a lock round-trip per message, and deliver it
            // outside the queue lock -- a handler may well send again, which
            // would deadlock if we still held it -- but under the delivery
            // lock, so a concurrent `poll` cannot slip later messages in
            // ahead of this batch. The worker is never inside a delivery
            // here, so this always gets the lock.
            let Some(_delivering) = self.delivering.acquire() else {
                continue;
            };
            // A handler that panics has already had the panic reported by
            // the hook; there is nobody here to hand it to, and letting it
            // end this thread would silently strand every later message.
            let _ = self.deliver_due(&deliver);
        }
    }

    /// Deliver everything that has come due, in release order. Each message
    /// is delivered in isolation: one whose handler panics does not take the
    /// rest of the batch with it. The first panic's payload is returned for
    /// the caller to re-raise or drop.
    fn deliver_due(
        &self,
        deliver: &dyn Fn(Direction, &[u8]),
    ) -> Option<Box<dyn std::any::Any + Send>> {
        let mut first_panic = None;
        for item in self.take_due() {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                deliver(item.dir, &item.data)
            }));
            self.queue.lock().unwrap().in_flight -= 1;
            if let Err(p) = r {
                first_panic.get_or_insert(p);
            }
        }
        first_panic
    }

    /// Apply the impairment to one message and either deliver it inline or
    /// schedule it. Returns `Some(data)` when the caller should deliver it
    /// immediately — the fast path for an unimpaired link.
    fn submit(&self, dir: Direction, data: &[u8]) -> Option<Vec<u8>> {
        match dir {
            Direction::Tx => self.stats.record_tx(data.len()),
            Direction::Rx => self.stats.record_rx(data.len()),
        }
        let cfg = self.cfg.lock().unwrap().clone();
        if cfg.is_perfect() {
            let mut q = self.queue.lock().unwrap();
            // A closed link delivers nothing, however perfect.
            if !q.running {
                return None;
            }
            if q.heap.is_empty() && q.in_flight == 0 {
                return Some(data.to_vec());
            }
            // Still releasing what an earlier impairment queued: delivered
            // inline, this message would overtake it. It goes behind the
            // last one queued its way instead, and leaves with them.
            let now = Instant::now();
            let at = q
                .heap
                .iter()
                .filter(|Reverse(m)| m.dir == dir)
                .map(|Reverse(m)| m.at)
                .max()
                .map_or(now, |last| last.max(now));
            if q.len() >= cfg.queue_limit.max(1) {
                drop(q);
                self.record_drop(dir);
                return None;
            }
            push(&mut q, at, dir, data.to_vec());
            drop(q);
            self.wake.notify_one();
            return None;
        }

        let mut rng = self.rng.lock().unwrap();
        if cfg.loss > 0.0 && rng.next_f64() < cfg.loss {
            drop(rng);
            self.record_drop(dir);
            return None;
        }

        let mut buf = data.to_vec();
        if cfg.corrupt > 0.0 && !buf.is_empty() && rng.next_f64() < cfg.corrupt {
            let byte = rng.below(buf.len() as u64) as usize;
            let bit = rng.below(8) as u8;
            buf[byte] ^= 1 << bit;
        }

        let jitter = if cfg.jitter.is_zero() {
            Duration::ZERO
        } else {
            Duration::from_nanos(rng.below(cfg.jitter.as_nanos().min(u64::MAX as u128) as u64))
        };
        let duplicate = cfg.duplicate > 0.0 && rng.next_f64() < cfg.duplicate;
        drop(rng);

        let now = Instant::now();

        let mut q = self.queue.lock().unwrap();
        if !q.running {
            return None;
        }
        let limit = cfg.queue_limit.max(1);
        if q.len() >= limit {
            drop(q);
            self.record_drop(dir);
            return None;
        }

        // Serialization: the link cannot start this message until it has
        // finished the previous one, which is what makes a burst queue.
        let slot = dir as usize;
        let ready = match q.free_at[slot] {
            Some(t) if t > now => t,
            _ => now,
        };
        // Time to clock this many bits onto the link; an unset rate is
        // instantaneous.
        let serialize = (buf.len() as u64)
            .saturating_mul(8 * 1_000_000_000)
            .checked_div(cfg.rate_bps)
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        // A delay (or a backlog) too long for the clock to represent is a
        // message that never arrives, not a panic in the caller's `send`.
        let Some((done, at)) = ready.checked_add(serialize).and_then(|done| {
            let at = done.checked_add(cfg.delay.checked_add(jitter)?)?;
            Some((done, at))
        }) else {
            drop(q);
            self.record_drop(dir);
            return None;
        };
        q.free_at[slot] = Some(done);

        push(&mut q, at, dir, buf.clone());
        // A duplicate arrives just behind the original, not on top of it,
        // and only if the buffer has room for it too.
        if duplicate
            && q.len() < limit
            && let Some(dup_at) = at.checked_add(Duration::from_micros(1))
        {
            push(&mut q, dup_at, dir, buf);
        }
        drop(q);
        self.wake.notify_one();
        None
    }

    fn record_drop(&self, dir: Direction) {
        match dir {
            Direction::Tx => self.stats.record_tx_drop(),
            Direction::Rx => self.stats.record_rx_drop(),
        }
    }

    /// Stop the release thread, discarding anything still queued.
    fn stop(&self) {
        let mut q = self.queue.lock().unwrap();
        q.running = false;
        q.heap.clear();
        drop(q);
        self.wake.notify_all();
    }

    fn queued(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Queued or being delivered: zero only once the link is really idle.
    #[cfg(not(target_family = "wasm"))]
    fn pending(&self) -> usize {
        let q = self.queue.lock().unwrap();
        q.len() + q.in_flight
    }

    /// Pop every message whose deadline has passed, in release order.
    fn take_due(&self) -> Vec<Queued> {
        let now = Instant::now();
        let mut q = self.queue.lock().unwrap();
        let mut due = Vec::new();
        while matches!(q.heap.peek(), Some(Reverse(h)) if h.at <= now) {
            due.push(q.heap.pop().unwrap().0);
        }
        q.in_flight += due.len();
        due
    }

    /// How long until the next queued message is due.
    fn until_next(&self) -> Option<Duration> {
        let q = self.queue.lock().unwrap();
        q.heap
            .peek()
            .map(|Reverse(h)| h.at.saturating_duration_since(Instant::now()))
    }
}

fn push(q: &mut Queue, at: Instant, dir: Direction, data: Vec<u8>) {
    q.seq += 1;
    let seq = q.seq;
    q.heap.push(Reverse(Queued { at, seq, dir, data }));
}

/// Wait for the queue to drain and the last delivery to finish, up to
/// `timeout`.
#[cfg(not(target_family = "wasm"))]
fn drain(engine: &Engine, timeout: Duration) -> bool {
    // From inside a handler the link cannot drain: the delivery in progress,
    // and the rest of its batch, wait for this very call to return, and no
    // other thread may deliver meanwhile. Waiting would only use up the
    // timeout.
    if engine.delivering.held_here() {
        return engine.pending() == 0;
    }
    // No deadline the clock can represent means no deadline.
    let deadline = Instant::now().checked_add(timeout);
    while deadline.is_none_or(|d| Instant::now() < d) {
        if engine.pending() == 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    engine.pending() == 0
}

/// Join the release thread, unless this *is* the release thread.
///
/// The worker delivers through a `Weak` it upgrades per message, so when every
/// other reference goes away mid-delivery, the wrapper's last `Arc` is dropped
/// on the worker itself. Joining there would be a thread joining itself, which
/// std turns into a panic (`EDEADLK`). The worker is on its way out anyway:
/// `stop` has cleared `running`, so it returns once the delivery is done.
#[cfg(not(target_family = "wasm"))]
fn join_unless_current(w: JoinHandle<()>) {
    if w.thread().id() != std::thread::current().id() {
        let _ = w.join();
    }
}

/// Without threads there is never a worker to join.
#[cfg(target_family = "wasm")]
fn join_unless_current(_w: JoinHandle<()>) {}

macro_rules! impaired_device {
    (
        $name:ident, $device:ident, $handler:ident, $msg:ident, $doc:literal
    ) => {
        #[doc = $doc]
        pub struct $name {
            inner: Arc<dyn $device>,
            handler: Mutex<Option<$handler>>,
            engine: Arc<Engine>,
            worker: Mutex<Option<JoinHandle<()>>>,
            /// Ourselves, for the handler installed on `inner`.
            this: Weak<$name>,
            /// Whether that handler has been installed yet.
            hooked: std::sync::Once,
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("queued", &self.engine.queued())
                    .finish_non_exhaustive()
            }
        }

        impl $name {
            /// Wrap `inner`, impairing traffic in both directions.
            pub fn new(inner: Arc<dyn $device>, cfg: Impairment) -> Arc<$name> {
                let engine = Engine::new(cfg);
                let me = Arc::new_cyclic(|this| $name {
                    inner,
                    handler: Mutex::new(None),
                    engine: engine.clone(),
                    worker: Mutex::new(None),
                    this: this.clone(),
                    hooked: std::sync::Once::new(),
                });

                // The release thread and the wrapped device's handler both
                // reach back into the wrapper. Weak references keep that from
                // becoming a cycle that leaks the whole chain.
                #[cfg(not(target_family = "wasm"))]
                {
                    let weak: Weak<$name> = Arc::downgrade(&me);
                    let worker = engine.spawn(move |dir, data| {
                        if let Some(me) = weak.upgrade() {
                            me.deliver(dir, data);
                        }
                    });
                    *me.worker.lock().unwrap() = Some(worker);
                }

                me
            }

            /// Install the handler, and on the first call take over the
            /// wrapped device's.
            ///
            /// Taking it over only now, rather than in `new`, leaves whatever
            /// the wrapped device receives before then with that device, to
            /// hold or drop as it does when it has no handler, instead of
            /// being impaired only to be discarded here for want of one.
            fn install_handler(&self, h: $handler) {
                *self.handler.lock().unwrap() = Some(h);
                self.hooked.call_once(|| {
                    let weak = self.this.clone();
                    self.inner.set_handler(Arc::new(move |m: &$msg| {
                        if let Some(me) = weak.upgrade() {
                            if let Some(now) = me.engine.submit(Direction::Rx, m.as_bytes()) {
                                me.deliver(Direction::Rx, &now);
                            }
                        }
                        Ok(())
                    }));
                });
            }

            /// Replace the impairment. Messages already queued keep the
            /// deadlines they were given.
            pub fn set_impairment(&self, cfg: Impairment) {
                *self.engine.cfg.lock().unwrap() = cfg;
            }

            /// The impairment currently in force.
            pub fn impairment(&self) -> Impairment {
                self.engine.cfg.lock().unwrap().clone()
            }

            /// How many messages are waiting for their release time.
            pub fn queued(&self) -> usize {
                self.engine.queued()
            }

            /// Deliver every message whose release time has passed, and
            /// return how long until the next one is due (`None` when the
            /// queue is empty).
            ///
            /// Where threads exist the release thread does this on its own.
            /// On `wasm32` it is the only way messages leave the queue:
            /// call it again after the returned delay.
            ///
            /// Messages leave in release order even while the release thread
            /// is delivering too. While a delivery is in progress -- on the
            /// release thread, or further up this thread's stack when called
            /// from a handler -- it delivers nothing and does not wait: that
            /// delivery would otherwise be overtaken, and waiting for it could
            /// deadlock against a handler that wants a lock the caller holds.
            /// The delivery in progress picks up what has come due.
            pub fn poll(&self) -> Option<Duration> {
                if let Some(delivering) = self.engine.delivering.try_acquire() {
                    let panicked = self
                        .engine
                        .deliver_due(&|dir, data| self.deliver(dir, data));
                    drop(delivering);
                    // The caller's own handler panicked: that is the caller's
                    // to see, but only once the rest of the batch is out.
                    if let Some(p) = panicked {
                        std::panic::resume_unwind(p);
                    }
                }
                self.engine.until_next()
            }

            /// Block until the delay queue is empty and every message taken
            /// off it has been delivered, or `timeout` elapses. Returns
            /// whether it drained. Intended for tests, which otherwise
            /// have to guess how long a delayed packet needs.
            ///
            /// Called from a handler during a delivery, it returns `false`
            /// at once: nothing more can be delivered until that handler
            /// returns.
            #[cfg(not(target_family = "wasm"))]
            pub fn wait_idle(&self, timeout: Duration) -> bool {
                drain(&self.engine, timeout)
            }

            fn deliver(&self, dir: Direction, data: &[u8]) {
                match dir {
                    Direction::Tx => {
                        let _ = self.inner.send($msg::from_slice(data));
                    }
                    Direction::Rx => {
                        // Always set by now: nothing is received before it is.
                        let h = self.handler.lock().unwrap().clone();
                        match h {
                            Some(h) => {
                                let _ = h($msg::from_slice(data));
                            }
                            None => self.engine.stats.record_rx_drop(),
                        }
                    }
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // Stop first, then join: the worker holds an `Arc<Engine>`, so
                // without this the thread would outlive the wrapper.
                self.engine.stop();
                if let Some(w) = self.worker.lock().unwrap().take() {
                    join_unless_current(w);
                }
            }
        }
    };
}

impaired_device!(
    ImpairL2,
    L2Device,
    L2Handler,
    Frame,
    "An [`L2Device`] that applies an [`Impairment`] to every frame crossing it."
);

impaired_device!(
    ImpairL3,
    L3Device,
    L3Handler,
    Packet,
    "An [`L3Device`] that applies an [`Impairment`] to every packet crossing it."
);

impl L2Device for ImpairL2 {
    fn set_handler(&self, h: L2Handler) {
        self.install_handler(h);
    }

    fn send(&self, frame: &Frame) -> Result<()> {
        if let Some(now) = self.engine.submit(Direction::Tx, frame.as_bytes()) {
            self.deliver(Direction::Tx, &now);
        }
        Ok(())
    }

    fn hw_addr(&self) -> MacAddr {
        self.inner.hw_addr()
    }

    fn close(&self) -> Result<()> {
        self.engine.stop();
        self.inner.close()
    }

    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.engine.stats)
    }

    // A wrapper lives exactly as long as the connection it wraps.
    fn done_signal(&self) -> Option<Arc<dyn crate::DoneSignal + Send + Sync>> {
        self.inner.done_signal()
    }
}

impl L3Device for ImpairL3 {
    fn set_handler(&self, h: L3Handler) {
        self.install_handler(h);
    }

    fn send(&self, packet: &Packet) -> Result<()> {
        if let Some(now) = self.engine.submit(Direction::Tx, packet.as_bytes()) {
            self.deliver(Direction::Tx, &now);
        }
        Ok(())
    }

    fn addr(&self) -> IpPrefix {
        self.inner.addr()
    }

    fn set_addr(&self, prefix: IpPrefix) -> Result<()> {
        self.inner.set_addr(prefix)
    }

    fn close(&self) -> Result<()> {
        self.engine.stop();
        self.inner.close()
    }

    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.engine.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EtherType, build_frame};

    /// Records what it is asked to send; delivers inbound frames on demand.
    #[derive(Default)]
    struct Wire {
        sent: Mutex<Vec<Vec<u8>>>,
        handler: Mutex<Option<L2Handler>>,
    }

    impl Wire {
        fn deliver(&self, f: &Frame) {
            let h = self.handler.lock().unwrap().clone();
            if let Some(h) = h {
                h(f).unwrap();
            }
        }
        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    impl L2Device for Wire {
        fn set_handler(&self, h: L2Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, f: &Frame) -> Result<()> {
            self.sent.lock().unwrap().push(f.to_vec());
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            MacAddr::zero()
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    fn frame(tag: u8) -> Vec<u8> {
        build_frame(
            MacAddr::broadcast(),
            MacAddr::zero(),
            EtherType::IPV4,
            &[tag; 40],
        )
    }

    fn wrap(cfg: Impairment) -> (Arc<Wire>, Arc<ImpairL2>) {
        let wire = Arc::new(Wire::default());
        let link = ImpairL2::new(wire.clone(), cfg);
        (wire, link)
    }

    #[test]
    fn perfect_link_passes_through_synchronously() {
        let (wire, link) = wrap(Impairment::default());
        let f = frame(1);
        link.send(Frame::from_slice(&f)).unwrap();
        // No queue, no thread hop: the frame is already on the far side.
        assert_eq!(wire.count(), 1);
        assert_eq!(wire.sent.lock().unwrap()[0], f);
        assert_eq!(link.queued(), 0);
    }

    #[test]
    fn delay_defers_delivery() {
        let (wire, link) = wrap(Impairment {
            delay: Duration::from_millis(30),
            ..Default::default()
        });
        let f = frame(2);
        let start = Instant::now();
        link.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(wire.count(), 0, "must not be delivered inline");

        assert!(link.wait_idle(Duration::from_secs(5)));
        assert_eq!(wire.count(), 1);
        assert!(
            start.elapsed() >= Duration::from_millis(30),
            "delivered after {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn poll_reports_the_next_deadline_and_releases_due_messages() {
        let (wire, link) = wrap(Impairment {
            delay: Duration::from_millis(40),
            ..Default::default()
        });
        assert_eq!(link.poll(), None, "nothing queued");
        link.send(Frame::from_slice(&frame(3))).unwrap();
        let wait = link.poll().expect("one message pending");
        assert!(wait <= Duration::from_millis(40), "{wait:?}");

        std::thread::sleep(Duration::from_millis(60));
        // The release thread may have got there first; either way, once poll
        // has run the message is out and nothing remains.
        assert_eq!(link.poll(), None);
        assert_eq!(wire.count(), 1);
    }

    #[test]
    fn total_loss_drops_everything_and_counts_it() {
        let (wire, link) = wrap(Impairment {
            loss: 1.0,
            seed: 42,
            ..Default::default()
        });
        for i in 0..10 {
            link.send(Frame::from_slice(&frame(i))).unwrap();
        }
        assert_eq!(wire.count(), 0);
        let s = link.stats().unwrap().snapshot();
        assert_eq!(s.tx_packets, 10);
        assert_eq!(s.tx_dropped, 10);
    }

    #[test]
    fn loss_is_reproducible_for_a_given_seed() {
        let run = || {
            let (wire, link) = wrap(Impairment {
                loss: 0.5,
                seed: 0x5EED,
                ..Default::default()
            });
            for i in 0..64 {
                link.send(Frame::from_slice(&frame(i))).unwrap();
            }
            link.wait_idle(Duration::from_secs(5));
            wire.count()
        };
        let a = run();
        let b = run();
        assert_eq!(a, b, "same seed must drop the same packets");
        assert!(
            a > 0 && a < 64,
            "half loss should land in between, got {}",
            a
        );
    }

    #[test]
    fn impairment_applies_to_received_frames_too() {
        let wire = Arc::new(Wire::default());
        let link = ImpairL2::new(
            wire.clone(),
            Impairment {
                loss: 1.0,
                seed: 7,
                ..Default::default()
            },
        );
        let seen = Arc::new(Mutex::new(0usize));
        let seen2 = seen.clone();
        link.set_handler(Arc::new(move |_f: &Frame| {
            *seen2.lock().unwrap() += 1;
            Ok(())
        }));

        let f = frame(3);
        wire.deliver(Frame::from_slice(&f));
        assert_eq!(*seen.lock().unwrap(), 0, "inbound loss applies as well");
        assert_eq!(link.stats().unwrap().snapshot().rx_dropped, 1);
    }

    #[test]
    fn the_wrapped_device_keeps_its_traffic_until_a_handler_is_set() {
        let (wire, link) = wrap(Impairment::default());
        // Nothing to hand received frames to yet, so the wrapper has not
        // claimed them: the wrapped device still has no handler.
        assert!(wire.handler.lock().unwrap().is_none());

        let seen = Arc::new(Mutex::new(0usize));
        let seen2 = seen.clone();
        link.set_handler(Arc::new(move |_f: &Frame| {
            *seen2.lock().unwrap() += 1;
            Ok(())
        }));
        assert!(wire.handler.lock().unwrap().is_some());
        wire.deliver(Frame::from_slice(&frame(1)));
        assert_eq!(*seen.lock().unwrap(), 1);

        // A replacement handler takes over without re-hooking.
        let seen3 = seen.clone();
        link.set_handler(Arc::new(move |_f: &Frame| {
            *seen3.lock().unwrap() += 10;
            Ok(())
        }));
        wire.deliver(Frame::from_slice(&frame(2)));
        assert_eq!(*seen.lock().unwrap(), 11);
    }

    #[test]
    fn duplication_delivers_twice() {
        let (wire, link) = wrap(Impairment {
            duplicate: 1.0,
            seed: 11,
            ..Default::default()
        });
        link.send(Frame::from_slice(&frame(4))).unwrap();
        assert!(link.wait_idle(Duration::from_secs(5)));
        // One guard: locking `sent` twice in a single expression would
        // deadlock, since std's Mutex is not reentrant.
        let sent = wire.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1]);
    }

    #[test]
    fn corruption_flips_exactly_one_bit() {
        let (wire, link) = wrap(Impairment {
            corrupt: 1.0,
            seed: 99,
            ..Default::default()
        });
        let f = frame(5);
        link.send(Frame::from_slice(&f)).unwrap();
        assert!(link.wait_idle(Duration::from_secs(5)));

        let got = wire.sent.lock().unwrap()[0].clone();
        assert_eq!(got.len(), f.len());
        let differing: u32 = got
            .iter()
            .zip(f.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert_eq!(differing, 1, "exactly one bit should differ");
    }

    #[test]
    fn rate_limit_serializes_a_burst() {
        // 64 kbit/s: a 54-byte frame takes ~6.75 ms to clock out.
        let (wire, link) = wrap(Impairment {
            rate_bps: 64_000,
            ..Default::default()
        });
        let start = Instant::now();
        for i in 0..4 {
            link.send(Frame::from_slice(&frame(i))).unwrap();
        }
        assert!(link.wait_idle(Duration::from_secs(5)));

        assert_eq!(wire.count(), 4);
        let bits = 4 * frame(0).len() as u64 * 8;
        let expected = Duration::from_nanos(bits * 1_000_000_000 / 64_000);
        assert!(
            start.elapsed() >= expected,
            "burst finished in {:?}, faster than the {:?} the link allows",
            start.elapsed(),
            expected
        );
    }

    #[test]
    fn queue_limit_bounds_memory() {
        let (wire, link) = wrap(Impairment {
            delay: Duration::from_secs(30),
            queue_limit: 4,
            ..Default::default()
        });
        for i in 0..20 {
            link.send(Frame::from_slice(&frame(i))).unwrap();
        }
        assert_eq!(link.queued(), 4);
        assert_eq!(link.stats().unwrap().snapshot().tx_dropped, 16);
        assert_eq!(wire.count(), 0);
        // Dropping the link must not block on the 30-second deadline.
        drop(link);
    }

    #[test]
    fn a_duplicate_does_not_overflow_the_queue_limit() {
        let (_wire, link) = wrap(
            Impairment::default()
                .delay(Duration::from_secs(30))
                .duplicate(1.0)
                .queue_limit(3)
                .seed(5),
        );
        link.send(Frame::from_slice(&frame(0))).unwrap();
        assert_eq!(link.queued(), 2, "original and duplicate");
        // Room for the original only.
        link.send(Frame::from_slice(&frame(1))).unwrap();
        assert_eq!(link.queued(), 3);
        link.send(Frame::from_slice(&frame(2))).unwrap();
        assert_eq!(link.queued(), 3);
    }

    #[test]
    fn an_unrepresentable_delay_drops_instead_of_panicking() {
        let (wire, link) = wrap(Impairment::default().delay(Duration::MAX).seed(1));
        link.send(Frame::from_slice(&frame(0))).unwrap();
        let (wire2, link2) = wrap(
            Impairment::default()
                .delay(Duration::MAX - Duration::from_secs(1))
                .jitter(Duration::from_secs(10))
                .seed(1),
        );
        link2.send(Frame::from_slice(&frame(0))).unwrap();
        assert_eq!(link.queued() + link2.queued(), 0);
        assert_eq!(link.stats().unwrap().snapshot().tx_dropped, 1);
        assert_eq!(wire.count() + wire2.count(), 0);
        // Waiting forever is spelled Duration::MAX, and must not panic either.
        assert!(link.wait_idle(Duration::MAX));
    }

    #[test]
    fn polling_alongside_the_release_thread_keeps_order() {
        // A slow far side keeps the release thread inside a batch while the
        // caller polls; whoever delivers, the wire must see send order.
        struct SlowWire(Mutex<Vec<u8>>);
        impl L2Device for SlowWire {
            fn set_handler(&self, _h: L2Handler) {}
            fn send(&self, f: &Frame) -> Result<()> {
                std::thread::sleep(Duration::from_micros(300));
                self.0.lock().unwrap().push(f.as_bytes()[14]);
                Ok(())
            }
            fn hw_addr(&self) -> MacAddr {
                MacAddr::zero()
            }
            fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let wire = Arc::new(SlowWire(Mutex::new(Vec::new())));
        let link = ImpairL2::new(
            wire.clone(),
            Impairment::default().delay(Duration::from_millis(2)),
        );
        const N: u8 = 60;
        for i in 0..N {
            link.send(Frame::from_slice(&frame(i))).unwrap();
            std::thread::sleep(Duration::from_micros(50));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while wire.0.lock().unwrap().len() < N as usize && Instant::now() < deadline {
            link.poll();
        }
        let got = wire.0.lock().unwrap().clone();
        assert_eq!(got, (0..N).collect::<Vec<_>>());
    }

    #[test]
    fn ordering_is_preserved_without_jitter() {
        let (wire, link) = wrap(Impairment {
            delay: Duration::from_millis(5),
            ..Default::default()
        });
        for i in 0..16 {
            link.send(Frame::from_slice(&frame(i))).unwrap();
        }
        assert!(link.wait_idle(Duration::from_secs(5)));

        let sent = wire.sent.lock().unwrap();
        assert_eq!(sent.len(), 16);
        for (i, f) in sent.iter().enumerate() {
            assert_eq!(f[14], i as u8, "frame {} arrived out of order", i);
        }
    }

    #[test]
    fn worker_stops_when_the_link_is_dropped() {
        let before = std::thread::available_parallelism().is_ok();
        assert!(before);
        let (_wire, link) = wrap(Impairment {
            delay: Duration::from_millis(10),
            ..Default::default()
        });
        link.send(Frame::from_slice(&frame(0))).unwrap();
        // Drop returns only once the worker has joined; a leaked thread would
        // hang this test rather than fail it.
        drop(link);
    }

    #[test]
    fn the_release_thread_does_not_join_itself() {
        // What the release thread does when it turns out to hold the
        // wrapper's last reference: drop its own handle, not join it.
        let (handle_tx, handle_rx) = std::sync::mpsc::channel::<JoinHandle<()>>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            join_unless_current(handle_rx.recv().unwrap());
            done_tx.send(()).unwrap();
        });
        handle_tx.send(t).unwrap();
        // A self-join panics the thread, which drops `done_tx` unsent.
        assert!(done_rx.recv_timeout(Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn a_wrapper_dropped_during_its_own_delivery_shuts_down_cleanly() {
        // The wrapper's last `Arc` goes away while the release thread is
        // delivering, so the release thread runs `Drop`.
        struct Slow {
            entered: std::sync::mpsc::Sender<()>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
            done: std::sync::mpsc::Sender<()>,
        }
        impl L2Device for Slow {
            fn set_handler(&self, _h: L2Handler) {}
            fn send(&self, _f: &Frame) -> Result<()> {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
                Ok(())
            }
            fn hw_addr(&self) -> MacAddr {
                MacAddr::zero()
            }
            fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        impl Drop for Slow {
            fn drop(&mut self) {
                let _ = self.done.send(());
            }
        }
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let link = ImpairL2::new(
            Arc::new(Slow {
                entered: entered_tx,
                release: Mutex::new(release_rx),
                done: done_tx,
            }),
            Impairment::default().delay(Duration::from_millis(1)),
        );
        link.send(Frame::from_slice(&frame(0))).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(link);
        release_tx.send(()).unwrap();
        // The wrapped device goes with the wrapper, on the release thread.
        assert!(done_rx.recv_timeout(Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn poll_does_not_wait_for_the_release_thread_to_finish_delivering() {
        // The far side wants a lock the application holds while it polls --
        // an application-wide state mutex, say. Were poll to wait for the
        // release thread's delivery, each would wait on the other forever.
        struct Locking {
            app: Arc<Mutex<()>>,
            entered: Mutex<std::sync::mpsc::Sender<()>>,
        }
        impl L2Device for Locking {
            fn set_handler(&self, _h: L2Handler) {}
            fn send(&self, _f: &Frame) -> Result<()> {
                let _ = self.entered.lock().unwrap().send(());
                drop(self.app.lock().unwrap());
                Ok(())
            }
            fn hw_addr(&self) -> MacAddr {
                MacAddr::zero()
            }
            fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let app = Arc::new(Mutex::new(()));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let link = ImpairL2::new(
            Arc::new(Locking {
                app: app.clone(),
                entered: Mutex::new(entered_tx),
            }),
            Impairment::default().delay(Duration::from_millis(1)),
        );
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let held = app.lock().unwrap();
            link.send(Frame::from_slice(&frame(0))).unwrap();
            // The release thread is now inside the delivery, blocked on us.
            entered_rx.recv().unwrap();
            link.poll();
            drop(held);
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "poll deadlocked against the release thread"
        );
    }

    /// Panics on a frame tagged 0xAA; records the rest.
    struct Fussy(Mutex<Vec<u8>>);
    impl L2Device for Fussy {
        fn set_handler(&self, _h: L2Handler) {}
        fn send(&self, f: &Frame) -> Result<()> {
            let tag = f.as_bytes()[14];
            assert_ne!(tag, 0xAA, "far side panics (expected by the test)");
            self.0.lock().unwrap().push(tag);
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            MacAddr::zero()
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_panicking_handler_does_not_stop_the_release_thread() {
        let wire = Arc::new(Fussy(Mutex::new(Vec::new())));
        let link = ImpairL2::new(
            wire.clone(),
            Impairment::default().delay(Duration::from_millis(1)),
        );
        link.send(Frame::from_slice(&frame(0xAA))).unwrap();
        // In the same batch as the panic, and in a later one.
        link.send(Frame::from_slice(&frame(1))).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        link.send(Frame::from_slice(&frame(2))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while wire.0.lock().unwrap().len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*wire.0.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn wait_idle_waits_for_the_delivery_in_progress() {
        struct Slow(Mutex<usize>);
        impl L2Device for Slow {
            fn set_handler(&self, _h: L2Handler) {}
            fn send(&self, _f: &Frame) -> Result<()> {
                std::thread::sleep(Duration::from_millis(100));
                *self.0.lock().unwrap() += 1;
                Ok(())
            }
            fn hw_addr(&self) -> MacAddr {
                MacAddr::zero()
            }
            fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let wire = Arc::new(Slow(Mutex::new(0)));
        let link = ImpairL2::new(
            wire.clone(),
            Impairment::default().delay(Duration::from_millis(1)),
        );
        link.send(Frame::from_slice(&frame(0))).unwrap();
        link.send(Frame::from_slice(&frame(1))).unwrap();
        assert!(link.wait_idle(Duration::from_secs(5)));
        assert_eq!(*wire.0.lock().unwrap(), 2, "returned mid-delivery");
    }

    #[test]
    fn impairment_can_be_changed_at_runtime() {
        let (wire, link) = wrap(Impairment::default());
        link.send(Frame::from_slice(&frame(0))).unwrap();
        assert_eq!(wire.count(), 1);

        link.set_impairment(Impairment {
            loss: 1.0,
            seed: 1,
            ..Default::default()
        });
        assert_eq!(link.impairment().loss, 1.0);
        link.send(Frame::from_slice(&frame(1))).unwrap();
        assert_eq!(wire.count(), 1, "the second frame was lost");
    }

    #[test]
    fn a_closed_perfect_link_delivers_nothing() {
        let (wire, link) = wrap(Impairment::default());
        link.close().unwrap();
        link.send(Frame::from_slice(&frame(1))).unwrap();
        assert_eq!(wire.count(), 0, "delivered on a closed link");
    }

    #[test]
    fn turning_impairment_off_does_not_reorder_what_is_queued() {
        let (wire, link) = wrap(Impairment::default().delay(Duration::from_millis(50)));
        link.send(Frame::from_slice(&frame(1))).unwrap();
        link.set_impairment(Impairment::default());
        link.send(Frame::from_slice(&frame(2))).unwrap();
        assert!(link.wait_idle(Duration::from_secs(5)));
        let tags: Vec<u8> = wire.sent.lock().unwrap().iter().map(|f| f[14]).collect();
        assert_eq!(tags, vec![1, 2], "the new frame overtook the queued one");

        // Once drained, the fast path is back.
        link.send(Frame::from_slice(&frame(3))).unwrap();
        assert_eq!(wire.count(), 3);
    }

    #[test]
    fn wait_idle_from_a_handler_does_not_wait_out_the_timeout() {
        let (wire, link) = wrap(Impairment::default().delay(Duration::from_millis(1)));
        let took = Arc::new(Mutex::new(None));
        let (l, t) = (Arc::downgrade(&link), took.clone());
        link.set_handler(Arc::new(move |_f: &Frame| {
            if let Some(l) = l.upgrade() {
                let start = Instant::now();
                let idle = l.wait_idle(Duration::from_secs(5));
                *t.lock().unwrap() = Some((idle, start.elapsed()));
            }
            Ok(())
        }));
        wire.deliver(Frame::from_slice(&frame(0)));
        assert!(link.wait_idle(Duration::from_secs(5)));
        let (idle, elapsed) = took.lock().unwrap().expect("handler ran");
        assert!(!idle, "idle while its own delivery was in progress");
        assert!(elapsed < Duration::from_secs(1), "waited {elapsed:?}");
    }
}

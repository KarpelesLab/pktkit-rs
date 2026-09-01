use crate::{Frame, HubCounters, HubStats, L2Device, Result};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

/// How long a learned address survives without being seen again.
const MAC_AGING: Duration = Duration::from_secs(5 * 60);

/// Total entries across all ports, a backstop on memory.
const MAC_TABLE_MAX_SIZE: usize = 8192;

/// Default per-port cap on learned addresses. An edge port carries one station
/// (or a handful, for a VM with several interfaces), so this is generous; the
/// point is that a port spraying random source addresses exhausts its own
/// budget instead of the whole table. Ports marked as uplinks are exempt --
/// see [`L2Hub::set_port_mac_limit`].
const DEFAULT_PORT_MAC_LIMIT: usize = 1024;

/// Maximum depth of nested forwarding on one thread.
///
/// Forwarding is a synchronous call chain: a hub calls `send` on a port, whose
/// handler may be another hub, which calls `send` again. A cycle in the
/// topology is therefore unbounded *recursion*, not a broadcast storm -- it
/// overflows the stack and aborts the process rather than merely wasting
/// bandwidth. This bounds the chain instead.
const DEFAULT_MAX_FORWARD_DEPTH: u32 = 16;

static PORT_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline]
fn next_port_id() -> u64 {
    PORT_ID_COUNTER.fetch_add(1, Ordering::Relaxed) + 1
}

thread_local! {
    /// Nested forwarding depth for the current thread, across every hub.
    ///
    /// Global rather than per-hub on purpose: a loop that runs A -> B -> A is
    /// caught by the same counter as one that runs A -> B -> C -> A.
    static FORWARD_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Increments the thread's forwarding depth and restores it on drop, so a
/// panicking handler cannot leave the counter stuck high.
struct DepthGuard;

impl DepthGuard {
    /// Enter one level of forwarding, or `None` if `max` is already reached.
    fn enter(max: u32) -> Option<DepthGuard> {
        FORWARD_DEPTH.with(|d| {
            if d.get() >= max {
                None
            } else {
                d.set(d.get() + 1);
                Some(DepthGuard)
            }
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        FORWARD_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

#[derive(Clone)]
struct Port {
    dev: Arc<dyn L2Device>,
    id: u64,
    /// `None` means unlimited -- the right setting for an uplink to another
    /// switch, which legitimately has every downstream station behind it.
    mac_limit: Option<usize>,
}

#[derive(Clone)]
struct MacEntry {
    /// The device to hand the frame to.
    ///
    /// Holding the device here is what makes a known unicast O(1): the old
    /// design stored a port id and then scanned the port list to turn it back
    /// into something sendable, which cost time proportional to the number of
    /// ports the frame was *not* going to. `Weak` so a disconnected port's
    /// entries do not keep the device alive.
    dev: Weak<dyn L2Device>,
    port_id: u64,
    expires: Instant,
}

/// MAC table key. The VLAN identifier is part of it so the same address seen
/// on two VLANs is learned as two separate stations rather than one that keeps
/// moving ports. Untagged frames use VLAN 0.
type MacKey = (u16, [u8; 6]);

/// The learning table and the per-port counts that bound it, under one lock so
/// they cannot disagree.
#[derive(Default)]
struct MacTable {
    entries: HashMap<MacKey, MacEntry>,
    per_port: HashMap<u64, usize>,
}

impl MacTable {
    fn insert(&mut self, key: MacKey, entry: MacEntry) {
        let new_port = entry.port_id;
        if let Some(old) = self.entries.insert(key, entry) {
            decrement(&mut self.per_port, old.port_id);
        }
        *self.per_port.entry(new_port).or_insert(0) += 1;
    }

    fn remove(&mut self, key: &MacKey) {
        if let Some(old) = self.entries.remove(key) {
            decrement(&mut self.per_port, old.port_id);
        }
    }

    /// Drop every entry pointing at `port_id`.
    fn purge_port(&mut self, port_id: u64) {
        self.entries.retain(|_, e| e.port_id != port_id);
        self.per_port.remove(&port_id);
    }

    fn port_count(&self, port_id: u64) -> usize {
        self.per_port.get(&port_id).copied().unwrap_or(0)
    }
}

fn decrement(counts: &mut HashMap<u64, usize>, port_id: u64) {
    if let Some(n) = counts.get_mut(&port_id) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            counts.remove(&port_id);
        }
    }
}

/// A learning Ethernet switch.
///
/// `L2Hub` forwards Ethernet frames between connected devices: it learns
/// source MAC addresses, sends unicast frames only to the port associated with
/// the destination MAC, and floods unknown unicast / broadcast / multicast to
/// every port except the source.
///
/// Learning is VLAN-aware: entries are keyed on (VLAN id, MAC), so one address
/// appearing on two VLANs does not look like a station flapping between ports.
/// Flooding still reaches every port -- ports have no VLAN membership to filter
/// on, so the hub does not pretend to segregate traffic.
///
/// # Topologies
///
/// A port may be another switch, and hubs nest to any depth. Two consequences
/// are worth knowing about:
///
/// - An uplink port has every downstream station behind it, so the per-port
///   learning limit that protects against address flooding would strangle it.
///   Mark such ports with [`set_port_mac_limit(handle, None)`](Self::set_port_mac_limit).
/// - Forwarding is a synchronous call chain, so a **cycle in the topology is
///   unbounded recursion**, which overflows the stack rather than merely
///   flooding. The chain is bounded at [`max_forward_depth`](Self::set_max_forward_depth)
///   levels and frames beyond it are dropped and counted by
///   [`loop_drops`](Self::loop_drops). That contains the damage; it does not
///   make a looped topology work.
///
/// # Aging and limits
///
/// Entries age out after five minutes without traffic, and are refreshed once
/// they are more than halfway there -- so a busy station stays learned without
/// taking the table's write lock on every frame. The table holds at most 8192
/// entries overall and, by default, 1024 per port.
///
/// [`stats`](Self::stats) reports what the hub did with each frame.
///
/// ```
/// # use std::sync::Arc;
/// # use pktkit::{L2Hub, PipeL2, MacAddr};
/// let hub = Arc::new(L2Hub::new());
/// let a = Arc::new(PipeL2::new("02:00:00:00:00:01".parse().unwrap()));
/// let _h = hub.connect(a.clone());
/// ```
pub struct L2Hub {
    /// The port list is swapped wholesale rather than mutated, so the
    /// forwarding path clones one `Arc` instead of copying a vector and
    /// touching every port's refcount.
    ports: RwLock<Arc<Vec<Port>>>,
    /// `RwLock` rather than `Mutex`: the common case is an address that is
    /// already learned and has not moved, which needs no write at all.
    mac_table: RwLock<MacTable>,
    stats: HubStats,
    loop_drops: AtomicU64,
    max_depth: AtomicUsize,
}

impl Default for L2Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for L2Hub {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.ports.read().map(|p| p.len()).unwrap_or(0);
        f.debug_struct("L2Hub").field("ports", &n).finish()
    }
}

impl L2Hub {
    /// Create an empty learning switch.
    pub fn new() -> L2Hub {
        L2Hub {
            ports: RwLock::new(Arc::new(Vec::new())),
            mac_table: RwLock::new(MacTable::default()),
            stats: HubStats::new(),
            loop_drops: AtomicU64::new(0),
            max_depth: AtomicUsize::new(DEFAULT_MAX_FORWARD_DEPTH as usize),
        }
    }

    /// Forwarding counters — received, forwarded, flooded and dropped.
    pub fn stats(&self) -> HubCounters {
        self.stats.snapshot()
    }

    /// Frames dropped because the forwarding chain was already
    /// [`max_forward_depth`](Self::set_max_forward_depth) levels deep.
    ///
    /// Any non-zero value means there is a cycle in the topology: without the
    /// depth bound those frames would have recursed until the stack ran out.
    pub fn loop_drops(&self) -> u64 {
        self.loop_drops.load(Ordering::Relaxed)
    }

    /// Set how deeply frames may be forwarded through nested hubs on one
    /// thread before being dropped. See [`loop_drops`](Self::loop_drops).
    ///
    /// Raise this only if a legitimate topology is genuinely deeper than the
    /// default of 16 switches.
    pub fn set_max_forward_depth(&self, depth: u32) {
        self.max_depth
            .store(depth.max(1) as usize, Ordering::Relaxed);
    }

    /// Cap how many addresses may be learned on one port; `None` lifts the cap.
    ///
    /// Lift it for uplinks to other switches, which have every downstream
    /// station behind them. Leave it in place on edge ports, where it bounds
    /// what a single misbehaving station can do to the table.
    pub fn set_port_mac_limit(&self, handle: &L2HubHandle, limit: Option<usize>) {
        let mut guard = self.ports.write().unwrap();
        let mut ports = (**guard).clone();
        for p in ports.iter_mut() {
            if p.id == handle.id {
                p.mac_limit = limit;
            }
        }
        *guard = Arc::new(ports);
    }

    /// Number of live entries in the MAC table. Useful as a gauge next to
    /// [`stats`](Self::stats); expired entries are counted until they are
    /// looked up and evicted.
    pub fn mac_table_len(&self) -> usize {
        self.mac_table.read().unwrap().entries.len()
    }

    /// Attach a device to the switch. The device's handler is installed to
    /// route received frames through the switch's learning logic. Returns a
    /// handle whose [`L2HubHandle::close`] disconnects the device.
    pub fn connect<D>(self: &Arc<Self>, dev: D) -> L2HubHandle
    where
        D: L2Device + 'static,
    {
        self.connect_arc(Arc::new(dev))
    }

    /// Same as [`connect`](Self::connect) but for devices already wrapped in `Arc`.
    pub fn connect_arc(self: &Arc<Self>, dev: Arc<dyn L2Device>) -> L2HubHandle {
        let id = next_port_id();
        self.add_port(Port {
            dev: dev.clone(),
            id,
            mac_limit: Some(DEFAULT_PORT_MAC_LIMIT),
        });

        let hub = Arc::downgrade(self);
        dev.set_handler(Arc::new(move |f: &Frame| {
            if let Some(hub) = hub.upgrade() {
                hub.forward(f, id);
            }
            Ok(())
        }));

        L2HubHandle {
            hub: Arc::downgrade(self),
            id,
            closed: Mutex::new(false),
        }
    }

    fn add_port(&self, port: Port) {
        let mut guard = self.ports.write().unwrap();
        let mut ports = (**guard).clone();
        ports.push(port);
        *guard = Arc::new(ports);
    }

    /// Snapshot the port list. One refcount bump, no allocation.
    #[inline]
    fn ports(&self) -> Arc<Vec<Port>> {
        self.ports.read().unwrap().clone()
    }

    fn forward(&self, f: &Frame, source_id: u64) {
        self.stats.record_received();

        // Bound the call chain before doing anything else: past this depth the
        // topology has a cycle and continuing would grow the stack.
        let max = self.max_depth.load(Ordering::Relaxed) as u32;
        let _depth = match DepthGuard::enter(max) {
            Some(g) => g,
            None => {
                self.loop_drops.fetch_add(1, Ordering::Relaxed);
                self.stats.record_dropped();
                return;
            }
        };

        let bytes = f.as_bytes();
        if bytes.len() < 14 {
            self.stats.record_dropped();
            return;
        }

        let vlan = f.vlan_id();
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes[6..12]);
        self.learn((vlan, mac), source_id);

        // Broadcast / multicast → flood to all ports except source.
        if bytes[0] & 1 != 0 {
            self.flood(f, source_id);
            return;
        }

        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&bytes[0..6]);
        if let Some(dev) = self.lookup((vlan, dst_mac), source_id) {
            let _ = dev.send(f);
            self.stats.record_forwarded(1);
            return;
        }

        self.flood(f, source_id);
    }

    /// Record that `key` lives on `source_id`.
    ///
    /// The fast path takes only a read lock: an address that is already
    /// learned, has not moved, and is not near expiry needs no write at all,
    /// which is the overwhelmingly common case on a busy link.
    fn learn(&self, key: MacKey, source_id: u64) {
        let now = Instant::now();
        {
            let table = self.mac_table.read().unwrap();
            if let Some(e) = table.entries.get(&key)
                && e.port_id == source_id
                && e.expires.saturating_duration_since(now) > MAC_AGING / 2
            {
                return;
            }
        }

        // Either new, moved, or past halfway to expiry: take the write lock.
        let ports = self.ports();
        let Some(port) = ports.iter().find(|p| p.id == source_id) else {
            return;
        };

        let mut table = self.mac_table.write().unwrap();
        let known = table.entries.get(&key).map(|e| e.port_id);
        if known.is_none() {
            // A new address has to fit both budgets. The per-port limit is
            // what keeps one port spraying random sources from crowding every
            // other port out of the table.
            if table.entries.len() >= MAC_TABLE_MAX_SIZE {
                return;
            }
            if let Some(limit) = port.mac_limit
                && table.port_count(source_id) >= limit
            {
                return;
            }
        }
        table.insert(
            key,
            MacEntry {
                dev: Arc::downgrade(&port.dev),
                port_id: source_id,
                expires: now + MAC_AGING,
            },
        );
    }

    /// Resolve `key` to a device to send to, or `None` to flood.
    fn lookup(&self, key: MacKey, source_id: u64) -> Option<Arc<dyn L2Device>> {
        let now = Instant::now();
        let stale = {
            let table = self.mac_table.read().unwrap();
            match table.entries.get(&key) {
                // Never hairpin a frame back out of the port it arrived on.
                Some(e) if e.port_id == source_id => return None,
                Some(e) if e.expires <= now => true,
                Some(e) => match e.dev.upgrade() {
                    Some(dev) => return Some(dev),
                    // The port went away; the entry is dead too.
                    None => true,
                },
                None => false,
            }
        };
        if stale {
            self.mac_table.write().unwrap().remove(&key);
        }
        None
    }

    /// Send `f` out every port but the source, counting the frame as flooded.
    /// A flood with nowhere to go is a drop: it means the hub is holding the
    /// only copy.
    fn flood(&self, f: &Frame, source_id: u64) {
        let ports = self.ports();
        let mut sent = 0u64;
        for p in ports.iter() {
            if p.id != source_id {
                let _ = p.dev.send(f);
                sent += 1;
            }
        }
        if sent == 0 {
            self.stats.record_dropped();
        } else {
            self.stats.record_flooded();
        }
    }

    fn disconnect(&self, id: u64) {
        {
            let mut guard = self.ports.write().unwrap();
            let mut ports = (**guard).clone();
            ports.retain(|p| p.id != id);
            *guard = Arc::new(ports);
        }
        self.mac_table.write().unwrap().purge_port(id);
    }
}

/// Implements [`L2Connector`](crate::L2Connector). Devices attached this way
/// always join the shared hub; the returned cleanup detaches them.
impl crate::L2Connector for Arc<L2Hub> {
    fn connect_l2(&self, dev: Arc<dyn L2Device>) -> Result<crate::Cleanup> {
        let handle = self.connect_arc(dev);
        let mut taken = Some(handle);
        Ok(Box::new(move || {
            if let Some(h) = taken.take() {
                h.close();
            }
            Ok(())
        }))
    }
}

/// Returned by [`L2Hub::connect`]; dropping or calling [`close`](Self::close)
/// detaches the device.
pub struct L2HubHandle {
    hub: std::sync::Weak<L2Hub>,
    id: u64,
    closed: Mutex<bool>,
}

impl core::fmt::Debug for L2HubHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("L2HubHandle").field("id", &self.id).finish()
    }
}

impl L2HubHandle {
    /// Detach the device from the hub. Idempotent.
    pub fn close(&self) {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            return;
        }
        if let Some(hub) = self.hub.upgrade() {
            hub.disconnect(self.id);
        }
        *closed = true;
    }
}

impl Drop for L2HubHandle {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EtherType, L2Handler, MacAddr, build_frame};
    use std::sync::Mutex;

    #[derive(Default, Clone)]
    struct Sink {
        inner: Arc<Mutex<Vec<Vec<u8>>>>,
        mac: MacAddr,
    }
    impl L2Device for Sink {
        fn set_handler(&self, _h: L2Handler) {}
        fn send(&self, f: &Frame) -> Result<()> {
            self.inner.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            self.mac
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn broadcast_floods_to_all_except_source() {
        let hub = Arc::new(L2Hub::new());
        let a_mac: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let b = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let c = Sink {
            mac: "02:00:00:00:00:03".parse().unwrap(),
            ..Default::default()
        };

        let a = Arc::new(crate::PipeL2::new(a_mac));
        let _ha = hub.connect_arc(a.clone() as Arc<dyn L2Device>);
        let _hb = hub.connect(b.clone());
        let _hc = hub.connect(c.clone());

        let buf = build_frame(MacAddr::broadcast(), a_mac, EtherType::IPV4, &[1, 2, 3]);
        a.inject(Frame::from_slice(&buf)).unwrap();

        assert_eq!(b.inner.lock().unwrap().len(), 1);
        assert_eq!(c.inner.lock().unwrap().len(), 1);
    }

    // A spy is a Sink-like device that we can also "inject" frames into — the
    // injection calls whatever handler the hub installed on this port, while
    // `send` just records (without firing the handler). This mirrors the Go
    // `l2Spy` pattern and avoids the mutual recursion you'd get from wiring
    // two PipeL2s into a hub.
    #[derive(Default, Clone)]
    struct Spy {
        inner: Arc<Mutex<Vec<Vec<u8>>>>,
        handler: Arc<Mutex<Option<L2Handler>>>,
        mac: MacAddr,
    }
    impl L2Device for Spy {
        fn set_handler(&self, h: L2Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, f: &Frame) -> Result<()> {
            self.inner.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            self.mac
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }
    impl Spy {
        fn inject(&self, f: &Frame) {
            let h = self.handler.lock().unwrap().clone();
            if let Some(h) = h {
                let _ = h(f);
            }
        }
        fn count(&self) -> usize {
            self.inner.lock().unwrap().len()
        }
    }

    #[test]
    fn learned_unicast_goes_to_one_port() {
        let hub = Arc::new(L2Hub::new());
        let a_mac: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let b_mac: MacAddr = "02:00:00:00:00:02".parse().unwrap();
        let c_mac: MacAddr = "02:00:00:00:00:03".parse().unwrap();

        let a = Spy {
            mac: a_mac,
            ..Default::default()
        };
        let b = Spy {
            mac: b_mac,
            ..Default::default()
        };
        let c = Spy {
            mac: c_mac,
            ..Default::default()
        };

        let _ha = hub.connect(a.clone());
        let _hb = hub.connect(b.clone());
        let _hc = hub.connect(c.clone());

        // Teach the hub where b is by having b inject a frame.
        let bf = build_frame(MacAddr::broadcast(), b_mac, EtherType::IPV4, &[0]);
        b.inject(Frame::from_slice(&bf));
        assert_eq!(c.count(), 1);
        assert_eq!(a.count(), 1);

        // a → b directly — only b's port should receive.
        let ab = build_frame(b_mac, a_mac, EtherType::IPV4, &[1]);
        a.inject(Frame::from_slice(&ab));
        assert_eq!(b.count(), 1);
        assert_eq!(c.count(), 1); // unchanged
    }

    #[test]
    fn disconnect_removes_port() {
        let hub = Arc::new(L2Hub::new());
        let a = Arc::new(crate::PipeL2::new("02:00:00:00:00:01".parse().unwrap()));
        let b = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let _ha = hub.connect_arc(a.clone() as Arc<dyn L2Device>);
        let hb = hub.connect(b.clone());
        hb.close();

        // Broadcast from a should now have no recipients.
        let bf = build_frame(MacAddr::broadcast(), MacAddr::zero(), EtherType::IPV4, &[]);
        a.inject(Frame::from_slice(&bf)).unwrap();
        assert_eq!(b.inner.lock().unwrap().len(), 0);
    }

    #[test]
    fn stats_track_flood_forward_and_drop() {
        let hub = Arc::new(L2Hub::new());
        let a_mac: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let b_mac: MacAddr = "02:00:00:00:00:02".parse().unwrap();
        let a = Sink {
            mac: a_mac,
            ..Default::default()
        };
        let b = Sink {
            mac: b_mac,
            ..Default::default()
        };
        let ha = hub.connect(a.clone());
        let hb = hub.connect(b.clone());

        // A broadcast from A floods to B.
        let bcast = build_frame(MacAddr::broadcast(), a_mac, EtherType::IPV4, &[0; 20]);
        hub.forward(Frame::from_slice(&bcast), ha.id);
        let s = hub.stats();
        assert_eq!((s.received, s.flooded, s.forwarded), (1, 1, 0));

        // B answers A. A's MAC was learned from the broadcast, so this is a
        // targeted forward rather than a flood.
        let unicast = build_frame(a_mac, b_mac, EtherType::IPV4, &[0; 20]);
        hub.forward(Frame::from_slice(&unicast), hb.id);
        let s = hub.stats();
        assert_eq!((s.received, s.flooded, s.forwarded), (2, 1, 1));

        // A runt is dropped outright.
        hub.forward(Frame::from_slice(&[0u8; 4]), ha.id);
        assert_eq!(hub.stats().dropped, 1);
    }

    #[test]
    fn learning_is_vlan_aware() {
        let hub = Arc::new(L2Hub::new());
        let station: MacAddr = "02:00:00:00:00:aa".parse().unwrap();
        let other: MacAddr = "02:00:00:00:00:bb".parse().unwrap();
        let a = Sink {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let b = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let ha = hub.connect(a.clone());
        let hb = hub.connect(b.clone());
        let (a_id, b_id) = (ha.id, hb.id);

        // The station is untagged on port A...
        let untagged = build_frame(other, station, EtherType::IPV4, &[0; 20]);
        hub.forward(Frame::from_slice(&untagged), a_id);

        // ...and the same MAC appears on VLAN 5 on port B. Without VLAN-aware
        // keys this would look like the station moving ports.
        let tagged = crate::build::push_vlan(Frame::from_slice(&untagged), 5, 0);
        hub.forward(Frame::from_slice(&tagged), b_id);

        assert_eq!(hub.mac_table_len(), 2, "two VLANs, two entries");

        // An untagged frame for the station must still go to port A only.
        a.inner.lock().unwrap().clear();
        b.inner.lock().unwrap().clear();
        let reply = build_frame(station, other, EtherType::IPV4, &[0; 20]);
        hub.forward(Frame::from_slice(&reply), b_id);
        assert_eq!(a.inner.lock().unwrap().len(), 1);
        assert_eq!(b.inner.lock().unwrap().len(), 0);

        // A tagged frame for the station goes to port B only.
        let tagged_reply = crate::build::push_vlan(Frame::from_slice(&reply), 5, 0);
        a.inner.lock().unwrap().clear();
        hub.forward(Frame::from_slice(&tagged_reply), a_id);
        assert_eq!(a.inner.lock().unwrap().len(), 0);
        assert_eq!(b.inner.lock().unwrap().len(), 1);
    }

    // --- Nested switches ---------------------------------------------------

    /// A patch cable between two hubs: whatever is sent into one end comes out
    /// of the other end's handler, which is how a real uplink behaves and how
    /// a topology gets more than one switch deep.
    #[derive(Default)]
    struct Cable {
        handler: Mutex<Option<L2Handler>>,
        peer: Mutex<Option<Arc<Cable>>>,
        mac: MacAddr,
    }

    impl Cable {
        fn pair() -> (Arc<Cable>, Arc<Cable>) {
            let a = Arc::new(Cable {
                mac: "02:00:00:00:0c:01".parse().unwrap(),
                ..Default::default()
            });
            let b = Arc::new(Cable {
                mac: "02:00:00:00:0c:02".parse().unwrap(),
                ..Default::default()
            });
            *a.peer.lock().unwrap() = Some(b.clone());
            *b.peer.lock().unwrap() = Some(a.clone());
            (a, b)
        }
    }

    impl L2Device for Cable {
        fn set_handler(&self, h: L2Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, f: &Frame) -> Result<()> {
            // Deliver out the far end, synchronously — this is the call chain
            // that a topology cycle turns into recursion.
            let peer = self.peer.lock().unwrap().clone();
            if let Some(peer) = peer {
                let h = peer.handler.lock().unwrap().clone();
                if let Some(h) = h {
                    let _ = h(f);
                }
            }
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            self.mac
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn frames_cross_a_chain_of_switches() {
        // A -- B -- C, with a station at each end. Nothing here is a loop, so
        // the depth guard must stay out of the way.
        let (a, b, c) = (
            Arc::new(L2Hub::new()),
            Arc::new(L2Hub::new()),
            Arc::new(L2Hub::new()),
        );
        let (ab, ba) = Cable::pair();
        let (bc, cb) = Cable::pair();
        let _h1 = a.connect_arc(ab);
        let _h2 = b.connect_arc(ba);
        let _h3 = b.connect_arc(bc);
        let _h4 = c.connect_arc(cb);

        let left = Sink {
            mac: "02:00:00:00:00:0a".parse().unwrap(),
            ..Default::default()
        };
        let right = Sink {
            mac: "02:00:00:00:00:0c".parse().unwrap(),
            ..Default::default()
        };
        let hl = a.connect(left.clone());
        let _hr = c.connect(right.clone());

        // Right announces itself so every hub learns where it lives.
        let announce = build_frame(MacAddr::broadcast(), right.mac, EtherType::IPV4, &[0; 40]);
        c.forward(Frame::from_slice(&announce), u64::MAX);
        assert!(
            !left.inner.lock().unwrap().is_empty(),
            "a broadcast must reach across three switches"
        );

        // Now a unicast the other way, which each hub should forward rather
        // than flood.
        right.inner.lock().unwrap().clear();
        let unicast = build_frame(right.mac, left.mac, EtherType::IPV4, &[0; 40]);
        a.forward(Frame::from_slice(&unicast), hl.id);
        assert_eq!(right.inner.lock().unwrap().len(), 1);

        assert_eq!(a.loop_drops(), 0, "a chain is not a loop");
        assert_eq!(b.loop_drops(), 0);
        assert_eq!(c.loop_drops(), 0);
    }

    #[test]
    fn a_topology_cycle_is_bounded_instead_of_overflowing_the_stack() {
        // Two hubs joined by *two* cables: a broadcast entering one goes round
        // and round. Forwarding is a synchronous call chain, so without a
        // bound this recurses until the stack is gone and the process aborts.
        let (a, b) = (Arc::new(L2Hub::new()), Arc::new(L2Hub::new()));
        for _ in 0..2 {
            let (x, y) = Cable::pair();
            let _hx = a.connect_arc(x);
            let _hy = b.connect_arc(y);
            std::mem::forget((_hx, _hy));
        }

        let victim = Sink {
            mac: "02:00:00:00:00:99".parse().unwrap(),
            ..Default::default()
        };
        let hv = a.connect(victim.clone());

        let bcast = build_frame(MacAddr::broadcast(), victim.mac, EtherType::IPV4, &[0; 40]);
        // Terminates. Before the depth bound this was a stack overflow: raising
        // the bound to 400 still hits it, so the cycle really is unbounded.
        a.forward(Frame::from_slice(&bcast), hv.id);

        assert!(
            a.loop_drops() + b.loop_drops() > 0,
            "the cycle should have been detected and cut"
        );
    }

    #[test]
    fn forward_depth_is_configurable_and_restored_after_each_frame() {
        let hub = Arc::new(L2Hub::new());
        hub.set_max_forward_depth(1);
        let s = Sink {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let h = hub.connect(s.clone());
        let f = build_frame(MacAddr::broadcast(), s.mac, EtherType::IPV4, &[0; 40]);

        // Depth is per-frame, so consecutive frames each get a fresh budget.
        for _ in 0..3 {
            hub.forward(Frame::from_slice(&f), h.id);
        }
        assert_eq!(hub.loop_drops(), 0, "a depth of one is enough for one hop");
    }

    // --- Learning limits ---------------------------------------------------

    fn spray(hub: &Arc<L2Hub>, port: u64, n: u16) {
        for i in 0..n {
            let b = i.to_be_bytes();
            let src = MacAddr::new([0x02, 0xff, 0, 0, b[0], b[1]]);
            let f = build_frame(MacAddr::broadcast(), src, EtherType::IPV4, &[0; 40]);
            hub.forward(Frame::from_slice(&f), port);
        }
    }

    #[test]
    fn one_port_flooding_addresses_cannot_starve_another() {
        let hub = Arc::new(L2Hub::new());
        let noisy = Sink {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let quiet = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let hn = hub.connect(noisy.clone());
        let hq = hub.connect(quiet.clone());

        // The noisy port invents far more addresses than its budget allows.
        spray(&hub, hn.id, 4000);
        let after_spray = hub.mac_table_len();
        assert!(
            after_spray <= DEFAULT_PORT_MAC_LIMIT + 1,
            "the per-port cap should have held the table to ~{DEFAULT_PORT_MAC_LIMIT}, got {after_spray}"
        );

        // The quiet port can still be learned, which is the whole point: with
        // only a global cap, the noisy port would have taken every slot.
        let f = build_frame(MacAddr::broadcast(), quiet.mac, EtherType::IPV4, &[0; 40]);
        hub.forward(Frame::from_slice(&f), hq.id);

        let unicast = build_frame(quiet.mac, noisy.mac, EtherType::IPV4, &[0; 40]);
        quiet.inner.lock().unwrap().clear();
        hub.forward(Frame::from_slice(&unicast), hn.id);
        assert_eq!(
            quiet.inner.lock().unwrap().len(),
            1,
            "the quiet station was never learned"
        );
        assert_eq!(hub.stats().forwarded, 1, "should be a forward, not a flood");
    }

    #[test]
    fn an_uplink_can_learn_without_limit() {
        // An uplink has every downstream station behind it, so the per-port cap
        // has to be liftable or a nested topology stops working.
        let hub = Arc::new(L2Hub::new());
        let uplink = Sink {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let h = hub.connect(uplink.clone());
        hub.set_port_mac_limit(&h, None);

        spray(&hub, h.id, 3000);
        assert!(
            hub.mac_table_len() > DEFAULT_PORT_MAC_LIMIT,
            "an unlimited port should learn past the per-port cap, got {}",
            hub.mac_table_len()
        );
    }

    #[test]
    fn disconnecting_a_port_drops_its_learned_addresses() {
        let hub = Arc::new(L2Hub::new());
        let a = Sink {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let b = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let ha = hub.connect(a.clone());
        let _hb = hub.connect(b.clone());

        spray(&hub, ha.id, 50);
        assert!(hub.mac_table_len() >= 50);
        ha.close();
        assert_eq!(
            hub.mac_table_len(),
            0,
            "entries pointing at a removed port must go with it"
        );
    }

    #[test]
    fn a_station_that_moves_ports_is_relearned() {
        let hub = Arc::new(L2Hub::new());
        let left = Sink {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let right = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let observer = Sink {
            mac: "02:00:00:00:00:03".parse().unwrap(),
            ..Default::default()
        };
        let hl = hub.connect(left.clone());
        let hr = hub.connect(right.clone());
        let ho = hub.connect(observer.clone());

        let station: MacAddr = "02:00:00:00:aa:aa".parse().unwrap();
        let announce = build_frame(MacAddr::broadcast(), station, EtherType::IPV4, &[0; 40]);

        // Seen on the left, then the same address appears on the right.
        hub.forward(Frame::from_slice(&announce), hl.id);
        hub.forward(Frame::from_slice(&announce), hr.id);
        assert_eq!(hub.mac_table_len(), 1, "a move replaces, it does not add");

        // Traffic for it now goes right, not left.
        left.inner.lock().unwrap().clear();
        right.inner.lock().unwrap().clear();
        let to_station = build_frame(station, observer.mac, EtherType::IPV4, &[0; 40]);
        hub.forward(Frame::from_slice(&to_station), ho.id);
        assert_eq!(right.inner.lock().unwrap().len(), 1);
        assert_eq!(left.inner.lock().unwrap().len(), 0);
    }

    #[test]
    fn a_frame_is_never_sent_back_out_of_the_port_it_arrived_on() {
        let hub = Arc::new(L2Hub::new());
        let a = Sink {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let ha = hub.connect(a.clone());

        let station: MacAddr = "02:00:00:00:aa:aa".parse().unwrap();
        let announce = build_frame(MacAddr::broadcast(), station, EtherType::IPV4, &[0; 40]);
        hub.forward(Frame::from_slice(&announce), ha.id);

        // The station is learned on port A; a frame for it arriving on A must
        // not be hairpinned straight back.
        a.inner.lock().unwrap().clear();
        let f = build_frame(station, MacAddr::broadcast(), EtherType::IPV4, &[0; 40]);
        hub.forward(Frame::from_slice(&f), ha.id);
        assert_eq!(a.inner.lock().unwrap().len(), 0);
    }
}

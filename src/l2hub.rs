use crate::{Frame, HubCounters, HubStats, L2Device, Result};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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

/// A set of VLAN identifiers.
///
/// Backed by a 4096-bit bitmap, so membership is a shift and a mask rather
/// than a hash — this is consulted once per port per flooded frame.
#[derive(Clone, PartialEq, Eq)]
pub struct VlanSet(VlanSetInner);

/// The bitmap is boxed so that "every VLAN" -- much the commonest setting --
/// costs a discriminant rather than 512 bytes, and so [`PortMode`] stays small
/// enough to store inline in every port.
#[derive(Clone, PartialEq, Eq)]
enum VlanSetInner {
    All,
    Bits(Box<[u64; 64]>),
}

impl VlanSet {
    /// Every VLAN, 0 through 4095.
    pub fn all() -> VlanSet {
        VlanSet(VlanSetInner::All)
    }

    /// No VLANs.
    pub fn none() -> VlanSet {
        VlanSet(VlanSetInner::Bits(Box::new([0; 64])))
    }

    /// The bitmap, replacing an `All` set with an explicit full one so that a
    /// removal has something to clear.
    fn bits_mut(&mut self) -> &mut [u64; 64] {
        if matches!(self.0, VlanSetInner::All) {
            let mut bits = Box::new([0u64; 64]);
            // 0..=4095 is every representable id.
            bits.fill(u64::MAX);
            self.0 = VlanSetInner::Bits(bits);
        }
        match &mut self.0 {
            VlanSetInner::Bits(b) => b,
            VlanSetInner::All => unreachable!("just replaced"),
        }
    }

    /// The given VLAN ids. Values above 4095 are not valid 802.1Q identifiers
    /// and are ignored.
    pub fn from_ids(ids: impl IntoIterator<Item = u16>) -> VlanSet {
        let mut set = VlanSet::none();
        for id in ids {
            set.insert(id);
        }
        set
    }

    /// Add one VLAN. Ids above 4095 are ignored.
    pub fn insert(&mut self, vlan: u16) {
        if vlan > 4095 {
            return;
        }
        self.bits_mut()[(vlan / 64) as usize] |= 1 << (vlan % 64);
    }

    /// Remove one VLAN. Ids above 4095 are ignored.
    pub fn remove(&mut self, vlan: u16) {
        if vlan > 4095 {
            return;
        }
        self.bits_mut()[(vlan / 64) as usize] &= !(1 << (vlan % 64));
    }

    /// True if `vlan` is in the set.
    #[inline]
    pub fn contains(&self, vlan: u16) -> bool {
        if vlan > 4095 {
            return false;
        }
        match &self.0 {
            VlanSetInner::All => true,
            VlanSetInner::Bits(b) => b[(vlan / 64) as usize] & (1 << (vlan % 64)) != 0,
        }
    }
}

impl core::fmt::Debug for VlanSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if matches!(self.0, VlanSetInner::All) {
            return f.write_str("VlanSet(all)");
        }
        let ids: Vec<u16> = (0u16..=4095).filter(|v| self.contains(*v)).collect();
        write!(f, "VlanSet({ids:?})")
    }
}

/// How a port treats VLAN tags on the way in and on the way out.
///
/// The default is [`PortMode::transparent`]: every VLAN passes and tags are
/// left exactly as they arrived, which is how the switch behaves before any
/// port is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortMode {
    /// An edge port belonging to a single VLAN.
    ///
    /// Frames arriving untagged are treated as belonging to `vlan`; a frame
    /// tagged with `vlan` is also accepted, and any other tag is dropped as
    /// misconfiguration. Frames leaving are always untagged, so the station
    /// behind the port never sees 802.1Q at all.
    Access { vlan: u16 },
    /// An uplink carrying several VLANs, tagged.
    ///
    /// A frame arriving tagged is accepted if its VLAN is in `allowed`.
    /// A frame arriving untagged belongs to `native`, if set, and is dropped
    /// otherwise. On the way out, frames are tagged, except those on the
    /// native VLAN which leave untagged.
    Trunk {
        allowed: VlanSet,
        native: Option<u16>,
    },
}

impl PortMode {
    /// Pass every VLAN through untouched, treating untagged frames as VLAN 0.
    ///
    /// This is the default, and it makes the switch behave as though VLANs
    /// were not modelled at all.
    pub fn transparent() -> PortMode {
        PortMode::Trunk {
            allowed: VlanSet::all(),
            native: Some(0),
        }
    }

    /// The VLAN a frame arriving on this port belongs to, or `None` if the
    /// port should not have received it.
    fn ingress_vlan(&self, tagged: Option<u16>) -> Option<u16> {
        match (self, tagged) {
            (PortMode::Access { vlan }, None) => Some(*vlan),
            // A tag matching the port's own VLAN is redundant but harmless.
            (PortMode::Access { vlan }, Some(t)) if t == *vlan => Some(*vlan),
            (PortMode::Access { .. }, Some(_)) => None,
            (PortMode::Trunk { allowed, .. }, Some(t)) if allowed.contains(t) => Some(t),
            (PortMode::Trunk { .. }, Some(_)) => None,
            (PortMode::Trunk { allowed, native }, None) => native.filter(|n| allowed.contains(*n)),
        }
    }

    /// How a frame on `vlan` should leave this port, or `None` if it must not.
    fn egress(&self, vlan: u16) -> Option<TagAction> {
        match self {
            PortMode::Access { vlan: v } if *v == vlan => Some(TagAction::Untagged),
            PortMode::Access { .. } => None,
            PortMode::Trunk { allowed, native } => {
                if !allowed.contains(vlan) {
                    return None;
                }
                if *native == Some(vlan) {
                    Some(TagAction::Untagged)
                } else {
                    Some(TagAction::Tagged(vlan))
                }
            }
        }
    }
}

impl Default for PortMode {
    fn default() -> PortMode {
        PortMode::transparent()
    }
}

/// What a frame's tag should look like leaving a port.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TagAction {
    Untagged,
    Tagged(u16),
}

/// The forms of one frame needed on the way out, each built at most once.
///
/// A flood to twenty access ports on the same VLAN strips the tag once, not
/// twenty times; a frame that already has the right shape is passed through
/// untouched and stays zero-copy.
struct Egress<'a> {
    original: &'a Frame,
    pcp: u8,
    untagged: Option<Vec<u8>>,
    tagged: Option<(u16, Vec<u8>)>,
}

impl<'a> Egress<'a> {
    fn new(original: &'a Frame) -> Egress<'a> {
        Egress {
            pcp: original.vlan_pcp(),
            original,
            untagged: None,
            tagged: None,
        }
    }

    fn apply(&mut self, action: TagAction) -> &Frame {
        match action {
            TagAction::Untagged => {
                if !self.original.has_vlan() {
                    return self.original;
                }
                let buf = self
                    .untagged
                    .get_or_insert_with(|| crate::build::pop_vlan(self.original));
                Frame::from_slice(buf)
            }
            TagAction::Tagged(vlan) => {
                if self.original.has_vlan() && self.original.vlan_id() == vlan {
                    return self.original;
                }
                if !matches!(&self.tagged, Some((v, _)) if *v == vlan) {
                    // Build from the untagged form so a re-tag replaces rather
                    // than stacks.
                    let base = if self.original.has_vlan() {
                        crate::build::pop_vlan(self.original)
                    } else {
                        self.original.to_vec()
                    };
                    let out = crate::build::push_vlan(Frame::from_slice(&base), vlan, self.pcp);
                    self.tagged = Some((vlan, out));
                }
                let (_, buf) = self.tagged.as_ref().expect("just built");
                Frame::from_slice(buf)
            }
        }
    }
}

/// A connected device and the policy applied to it.
///
/// Immutable once published, so the forwarding path reads a port's mode with
/// no lock and no refcounting. Changing a port's configuration publishes a
/// whole new [`PortTable`].
struct Port {
    dev: Arc<dyn L2Device>,
    id: u64,
    /// `None` means unlimited -- the right setting for an uplink to another
    /// switch, which has an unknowable number of stations behind it.
    mac_limit: Option<usize>,
    mode: PortMode,
}

/// The configurable half of a [`Port`], handed to [`L2Hub::reconfigure`].
struct PortSettings {
    mac_limit: Option<usize>,
    mode: PortMode,
}

/// The connected ports, in both the shapes the forwarding path needs.
///
/// Published as a single immutable `Arc`, so a frame pays one lock and one
/// refcount for its whole journey: the list drives flooding, and the index
/// resolves the ingress port and learned destinations in O(1). Resolving by
/// id rather than by holding a `Weak<Port>` means reconfiguring a port cannot
/// leave a stale reference behind.
struct PortTable {
    list: Vec<Arc<Port>>,
    by_id: HashMap<u64, Arc<Port>>,
}

impl PortTable {
    fn from_list(list: Vec<Arc<Port>>) -> Arc<PortTable> {
        let by_id = list.iter().map(|p| (p.id, p.clone())).collect();
        Arc::new(PortTable { list, by_id })
    }

    #[inline]
    fn get(&self, id: u64) -> Option<&Arc<Port>> {
        self.by_id.get(&id)
    }
}

#[derive(Clone)]
struct MacEntry {
    /// The port the address was learned on, resolved through
    /// [`PortTable::get`]. That index is what makes a known unicast O(1): the
    /// original design scanned the port list to turn this id into something
    /// sendable, which cost time proportional to the number of ports the frame
    /// was *not* going to.
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
/// # Learning
///
/// There is no way to enumerate what sits behind a port -- least of all behind
/// an uplink to another switch -- so learning from source addresses is the only
/// discovery mechanism there is, and flooding on a miss is how the switch finds
/// something rather than a fallback for when it fails. Entries are keyed on
/// (VLAN id, MAC), so one address appearing on two VLANs is two stations rather
/// than one that keeps moving.
///
/// # VLANs
///
/// Ports start [`transparent`](PortMode::transparent) -- every VLAN passes and
/// tags are untouched -- so a switch that is never configured behaves as though
/// VLANs were not modelled. Give a port a [`PortMode`] and they become real:
/// an [`Access`](PortMode::Access) port belongs to one VLAN and never sees a
/// tag, a [`Trunk`](PortMode::Trunk) carries several and tags them, flooding
/// reaches only the ports that carry the frame's VLAN, and a learned address is
/// only a hit on the VLAN it was learned on.
///
/// Tagging is applied lazily and at most once per form, so a flood to twenty
/// access ports on one VLAN strips the tag once. A frame that already has the
/// shape a port needs is passed through untouched and stays zero-copy.
///
/// # Topologies
///
/// A port may be another switch, and hubs nest to any depth. Two consequences
/// are worth knowing about:
///
/// - An uplink port has an unknowable number of stations behind it, so the
///   per-port learning limit that protects against address flooding would
///   eventually strangle it. Lift it with
///   [`set_port_mac_limit(handle, None)`](Self::set_port_mac_limit).
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
    ports: RwLock<Arc<PortTable>>,
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
        let n = self.ports.read().map(|p| p.list.len()).unwrap_or(0);
        f.debug_struct("L2Hub").field("ports", &n).finish()
    }
}

impl L2Hub {
    /// Create an empty learning switch.
    pub fn new() -> L2Hub {
        L2Hub {
            ports: RwLock::new(PortTable::from_list(Vec::new())),
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
    /// Lift it for uplinks to other switches. There is no way to enumerate
    /// what is behind a port — learning from source addresses is the only
    /// discovery mechanism there is — so an uplink's true station count is
    /// unknowable in advance and any fixed cap would eventually truncate it.
    /// Leave the cap in place on edge ports, where it bounds what a single
    /// misbehaving station can do to the table.
    pub fn set_port_mac_limit(&self, handle: &L2HubHandle, limit: Option<usize>) {
        self.reconfigure(handle.id, |p| p.mac_limit = limit);
    }

    /// Set how a port handles VLAN tags. See [`PortMode`].
    ///
    /// Ports start [`transparent`](PortMode::transparent), passing every VLAN
    /// through with tags untouched. Addresses already learned against this
    /// port are forgotten, since the VLAN they were learned under may no
    /// longer apply; they are relearned from the next frame.
    pub fn set_port_mode(&self, handle: &L2HubHandle, mode: PortMode) {
        self.reconfigure(handle.id, |p| p.mode = mode);
        // The addresses on this port were learned under the VLAN mapping that
        // just changed, so they no longer mean what they did.
        self.mac_table.write().unwrap().purge_port(handle.id);
    }

    /// The VLAN configuration of a port, or `None` if it is not connected.
    pub fn port_mode(&self, handle: &L2HubHandle) -> Option<PortMode> {
        self.ports().get(handle.id).map(|p| p.mode.clone())
    }

    /// Publish a new port table with one port's configuration changed.
    ///
    /// Ports are immutable so that reading one costs nothing on the hot path;
    /// the price is paid here instead, on an operation that happens once per
    /// configuration change rather than once per frame.
    fn reconfigure(&self, port_id: u64, edit: impl FnOnce(&mut PortSettings)) {
        let mut guard = self.ports.write().unwrap();
        let mut list = guard.list.clone();
        let mut edit = Some(edit);
        for slot in list.iter_mut() {
            if slot.id != port_id {
                continue;
            }
            let mut cfg = PortSettings {
                mac_limit: slot.mac_limit,
                mode: slot.mode.clone(),
            };
            if let Some(edit) = edit.take() {
                edit(&mut cfg);
            }
            *slot = Arc::new(Port {
                dev: slot.dev.clone(),
                id: slot.id,
                mac_limit: cfg.mac_limit,
                mode: cfg.mode,
            });
            break;
        }
        *guard = PortTable::from_list(list);
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
        {
            let mut guard = self.ports.write().unwrap();
            let mut list = guard.list.clone();
            list.push(Arc::new(Port {
                dev: dev.clone(),
                id,
                mac_limit: Some(DEFAULT_PORT_MAC_LIMIT),
                mode: PortMode::transparent(),
            }));
            *guard = PortTable::from_list(list);
        }

        // The handler carries only the port id: it is resolved through the
        // table's index, which is O(1) and always current, so reconfiguring a
        // port cannot leave the handler pointing at a stale copy.
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

    /// Snapshot the port table. One refcount bump, no allocation.
    #[inline]
    fn ports(&self) -> Arc<PortTable> {
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

        // One snapshot serves the whole frame: the ingress port, the learned
        // destination, and the flood list all come out of it.
        let ports = self.ports();
        let Some(source) = ports.get(source_id) else {
            self.stats.record_dropped();
            return;
        };

        // Which VLAN this frame belongs to is a property of the port it
        // arrived on, not only of the tag it carries.
        let tag = f.has_vlan().then(|| f.vlan_id());
        let Some(vlan) = source.mode.ingress_vlan(tag) else {
            self.stats.record_dropped();
            return;
        };

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes[6..12]);
        self.learn((vlan, mac), source);

        let mut egress = Egress::new(f);

        // Broadcast / multicast → flood to every port that carries this VLAN.
        if bytes[0] & 1 != 0 {
            self.flood(&ports, &mut egress, vlan, source_id);
            return;
        }

        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&bytes[0..6]);
        if let Some(dst) = self.lookup(&ports, (vlan, dst_mac), source_id) {
            // The destination is known, but it still has to be reachable on
            // this VLAN — a learned address on another VLAN is not a hit.
            if let Some(action) = dst.mode.egress(vlan) {
                let _ = dst.dev.send(egress.apply(action));
                self.stats.record_forwarded(1);
            } else {
                self.stats.record_dropped();
            }
            return;
        }

        self.flood(&ports, &mut egress, vlan, source_id);
    }

    /// Record that `key` lives on `source`.
    ///
    /// The fast path takes only a read lock: an address that is already
    /// learned, has not moved, and is not near expiry needs no write at all,
    /// which is the overwhelmingly common case on a busy link.
    fn learn(&self, key: MacKey, source: &Arc<Port>) {
        let now = Instant::now();
        {
            let table = self.mac_table.read().unwrap();
            if let Some(e) = table.entries.get(&key)
                && e.port_id == source.id
                && e.expires.saturating_duration_since(now) > MAC_AGING / 2
            {
                return;
            }
        }

        // Either new, moved, or past halfway to expiry: take the write lock.
        let mut table = self.mac_table.write().unwrap();
        let known = table.entries.get(&key).map(|e| e.port_id);
        if known.is_none() {
            // A new address has to fit both budgets. The per-port limit is
            // what keeps one port spraying random sources from crowding every
            // other port out of the table.
            if table.entries.len() >= MAC_TABLE_MAX_SIZE {
                return;
            }
            if let Some(limit) = source.mac_limit
                && table.port_count(source.id) >= limit
            {
                return;
            }
        }
        table.insert(
            key,
            MacEntry {
                port_id: source.id,
                expires: now + MAC_AGING,
            },
        );
    }

    /// Resolve `key` to the port to send out of, or `None` to flood.
    fn lookup<'a>(
        &self,
        ports: &'a PortTable,
        key: MacKey,
        source_id: u64,
    ) -> Option<&'a Arc<Port>> {
        let now = Instant::now();
        let stale = {
            let table = self.mac_table.read().unwrap();
            match table.entries.get(&key) {
                // Never hairpin a frame back out of the port it arrived on.
                Some(e) if e.port_id == source_id => return None,
                Some(e) if e.expires <= now => true,
                Some(e) => match ports.get(e.port_id) {
                    Some(port) => return Some(port),
                    // The port is gone; so is the entry.
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

    /// Send out every port that carries `vlan`, except the source.
    ///
    /// A flood with nowhere to go is a drop: it means the hub is holding the
    /// only copy.
    fn flood(&self, ports: &PortTable, egress: &mut Egress<'_>, vlan: u16, source_id: u64) {
        let mut sent = 0u64;
        for p in ports.list.iter() {
            if p.id == source_id {
                continue;
            }
            if let Some(action) = p.mode.egress(vlan) {
                let _ = p.dev.send(egress.apply(action));
                sent += 1;
            }
        }
        if sent == 0 {
            self.stats.record_dropped();
        } else {
            self.stats.record_flooded();
        }
    }

    /// Drive a frame in as though it arrived on `port_id`. Tests only: the
    /// real entry point is the handler installed by `connect_arc`, which
    /// already holds the port.
    #[cfg(test)]
    fn forward_from(&self, f: &Frame, port_id: u64) {
        self.forward(f, port_id);
    }

    fn disconnect(&self, id: u64) {
        {
            let mut guard = self.ports.write().unwrap();
            let mut list = guard.list.clone();
            list.retain(|p| p.id != id);
            *guard = PortTable::from_list(list);
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
        hub.forward_from(Frame::from_slice(&bcast), ha.id);
        let s = hub.stats();
        assert_eq!((s.received, s.flooded, s.forwarded), (1, 1, 0));

        // B answers A. A's MAC was learned from the broadcast, so this is a
        // targeted forward rather than a flood.
        let unicast = build_frame(a_mac, b_mac, EtherType::IPV4, &[0; 20]);
        hub.forward_from(Frame::from_slice(&unicast), hb.id);
        let s = hub.stats();
        assert_eq!((s.received, s.flooded, s.forwarded), (2, 1, 1));

        // A runt is dropped outright.
        hub.forward_from(Frame::from_slice(&[0u8; 4]), ha.id);
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
        hub.forward_from(Frame::from_slice(&untagged), a_id);

        // ...and the same MAC appears on VLAN 5 on port B. Without VLAN-aware
        // keys this would look like the station moving ports.
        let tagged = crate::build::push_vlan(Frame::from_slice(&untagged), 5, 0);
        hub.forward_from(Frame::from_slice(&tagged), b_id);

        assert_eq!(hub.mac_table_len(), 2, "two VLANs, two entries");

        // An untagged frame for the station must still go to port A only.
        a.inner.lock().unwrap().clear();
        b.inner.lock().unwrap().clear();
        let reply = build_frame(station, other, EtherType::IPV4, &[0; 20]);
        hub.forward_from(Frame::from_slice(&reply), b_id);
        assert_eq!(a.inner.lock().unwrap().len(), 1);
        assert_eq!(b.inner.lock().unwrap().len(), 0);

        // A tagged frame for the station goes to port B only.
        let tagged_reply = crate::build::push_vlan(Frame::from_slice(&reply), 5, 0);
        a.inner.lock().unwrap().clear();
        hub.forward_from(Frame::from_slice(&tagged_reply), a_id);
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
        let hr = c.connect(right.clone());

        // Right announces itself so every hub learns where it lives.
        let announce = build_frame(MacAddr::broadcast(), right.mac, EtherType::IPV4, &[0; 40]);
        c.forward_from(Frame::from_slice(&announce), hr.id);
        assert!(
            !left.inner.lock().unwrap().is_empty(),
            "a broadcast must reach across three switches"
        );

        // Now a unicast the other way, which each hub should forward rather
        // than flood.
        right.inner.lock().unwrap().clear();
        let unicast = build_frame(right.mac, left.mac, EtherType::IPV4, &[0; 40]);
        a.forward_from(Frame::from_slice(&unicast), hl.id);
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
        a.forward_from(Frame::from_slice(&bcast), hv.id);

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
            hub.forward_from(Frame::from_slice(&f), h.id);
        }
        assert_eq!(hub.loop_drops(), 0, "a depth of one is enough for one hop");
    }

    // --- Learning limits ---------------------------------------------------

    fn spray(hub: &Arc<L2Hub>, port: u64, n: u16) {
        for i in 0..n {
            let b = i.to_be_bytes();
            let src = MacAddr::new([0x02, 0xff, 0, 0, b[0], b[1]]);
            let f = build_frame(MacAddr::broadcast(), src, EtherType::IPV4, &[0; 40]);
            hub.forward_from(Frame::from_slice(&f), port);
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
        hub.forward_from(Frame::from_slice(&f), hq.id);

        let unicast = build_frame(quiet.mac, noisy.mac, EtherType::IPV4, &[0; 40]);
        quiet.inner.lock().unwrap().clear();
        hub.forward_from(Frame::from_slice(&unicast), hn.id);
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
        hub.forward_from(Frame::from_slice(&announce), hl.id);
        hub.forward_from(Frame::from_slice(&announce), hr.id);
        assert_eq!(hub.mac_table_len(), 1, "a move replaces, it does not add");

        // Traffic for it now goes right, not left.
        left.inner.lock().unwrap().clear();
        right.inner.lock().unwrap().clear();
        let to_station = build_frame(station, observer.mac, EtherType::IPV4, &[0; 40]);
        hub.forward_from(Frame::from_slice(&to_station), ho.id);
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
        hub.forward_from(Frame::from_slice(&announce), ha.id);

        // The station is learned on port A; a frame for it arriving on A must
        // not be hairpinned straight back.
        a.inner.lock().unwrap().clear();
        let f = build_frame(station, MacAddr::broadcast(), EtherType::IPV4, &[0; 40]);
        hub.forward_from(Frame::from_slice(&f), ha.id);
        assert_eq!(a.inner.lock().unwrap().len(), 0);
    }

    // --- VLANs -------------------------------------------------------------

    fn access(vlan: u16) -> PortMode {
        PortMode::Access { vlan }
    }

    fn trunk(ids: &[u16], native: Option<u16>) -> PortMode {
        PortMode::Trunk {
            allowed: VlanSet::from_ids(ids.iter().copied()),
            native,
        }
    }

    /// Connect `n` sinks and return them with their handles.
    fn sinks(hub: &Arc<L2Hub>, n: u16) -> Vec<(Sink, L2HubHandle)> {
        (0..n)
            .map(|i| {
                let b = i.to_be_bytes();
                let s = Sink {
                    mac: MacAddr::new([0x02, 0, 0, 0, b[0], b[1]]),
                    ..Default::default()
                };
                let h = hub.connect(s.clone());
                (s, h)
            })
            .collect()
    }

    #[test]
    fn vlan_set_membership() {
        let all = VlanSet::all();
        assert!(all.contains(0) && all.contains(4095));
        assert!(!all.contains(4096), "4095 is the largest 802.1Q id");

        let mut set = VlanSet::from_ids([1, 100, 4095]);
        assert!(set.contains(1) && set.contains(100) && set.contains(4095));
        assert!(!set.contains(2) && !set.contains(0));
        set.remove(100);
        assert!(!set.contains(100));
        // Out-of-range ids are ignored rather than corrupting a neighbour.
        set.insert(9999);
        assert!(!set.contains(9999 & 4095));

        // Removing from an "all" set materialises it rather than silently
        // doing nothing.
        let mut all = VlanSet::all();
        all.remove(7);
        assert!(!all.contains(7));
        assert!(all.contains(6) && all.contains(8) && all.contains(4095));
    }

    #[test]
    fn access_ports_on_different_vlans_are_isolated() {
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 3);
        hub.set_port_mode(&ports[0].1, access(10));
        hub.set_port_mode(&ports[1].1, access(10));
        hub.set_port_mode(&ports[2].1, access(20));

        let f = build_frame(
            MacAddr::broadcast(),
            ports[0].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        hub.forward_from(Frame::from_slice(&f), ports[0].1.id);

        assert_eq!(
            ports[1].0.inner.lock().unwrap().len(),
            1,
            "same VLAN should receive"
        );
        assert_eq!(
            ports[2].0.inner.lock().unwrap().len(),
            0,
            "a different VLAN must not"
        );
    }

    #[test]
    fn an_access_port_receives_untagged_and_a_trunk_receives_tagged() {
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 3);
        hub.set_port_mode(&ports[0].1, access(10));
        hub.set_port_mode(&ports[1].1, access(10));
        hub.set_port_mode(&ports[2].1, trunk(&[10, 20], None));

        let f = build_frame(
            MacAddr::broadcast(),
            ports[0].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        hub.forward_from(Frame::from_slice(&f), ports[0].1.id);

        let at_access = ports[1].0.inner.lock().unwrap()[0].clone();
        let seen = Frame::from_slice(&at_access);
        assert!(!seen.has_vlan(), "an access port must never see a tag");
        assert_eq!(seen.ether_type(), EtherType::IPV4);
        assert_eq!(seen.payload(), &[0u8; 40]);

        let at_trunk = ports[2].0.inner.lock().unwrap()[0].clone();
        let seen = Frame::from_slice(&at_trunk);
        assert!(seen.has_vlan(), "a trunk carries the tag");
        assert_eq!(seen.vlan_id(), 10);
        assert_eq!(seen.ether_type(), EtherType::IPV4);
        assert_eq!(seen.payload(), &[0u8; 40]);
    }

    #[test]
    fn a_trunk_drops_vlans_it_does_not_carry() {
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 2);
        hub.set_port_mode(&ports[0].1, trunk(&[10, 20], None));
        hub.set_port_mode(&ports[1].1, trunk(&[10], None));

        let base = build_frame(
            MacAddr::broadcast(),
            ports[0].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        let on_20 = crate::build::push_vlan(Frame::from_slice(&base), 20, 0);
        hub.forward_from(Frame::from_slice(&on_20), ports[0].1.id);
        assert_eq!(
            ports[1].0.inner.lock().unwrap().len(),
            0,
            "VLAN 20 is not allowed on that trunk"
        );

        let on_10 = crate::build::push_vlan(Frame::from_slice(&base), 10, 0);
        hub.forward_from(Frame::from_slice(&on_10), ports[0].1.id);
        assert_eq!(ports[1].0.inner.lock().unwrap().len(), 1);
    }

    #[test]
    fn untagged_frames_on_a_trunk_need_a_native_vlan() {
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 2);
        hub.set_port_mode(&ports[1].1, access(10));

        // No native VLAN: an untagged frame has no VLAN to belong to.
        hub.set_port_mode(&ports[0].1, trunk(&[10], None));
        let f = build_frame(
            MacAddr::broadcast(),
            ports[0].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        hub.forward_from(Frame::from_slice(&f), ports[0].1.id);
        assert_eq!(ports[1].0.inner.lock().unwrap().len(), 0);
        assert!(hub.stats().dropped >= 1);

        // With native 10 it belongs to VLAN 10 and reaches the access port.
        hub.set_port_mode(&ports[0].1, trunk(&[10], Some(10)));
        hub.forward_from(Frame::from_slice(&f), ports[0].1.id);
        assert_eq!(ports[1].0.inner.lock().unwrap().len(), 1);

        // And a frame for the native VLAN leaves the trunk untagged again.
        let back = build_frame(
            MacAddr::broadcast(),
            ports[1].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        hub.forward_from(Frame::from_slice(&back), ports[1].1.id);
        let at_trunk = ports[0].0.inner.lock().unwrap().last().unwrap().clone();
        assert!(
            !Frame::from_slice(&at_trunk).has_vlan(),
            "native is untagged"
        );
    }

    #[test]
    fn an_access_port_rejects_a_foreign_tag() {
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 2);
        hub.set_port_mode(&ports[0].1, access(10));
        hub.set_port_mode(&ports[1].1, trunk(&[10, 20], None));

        let base = build_frame(
            MacAddr::broadcast(),
            ports[0].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        let tagged_20 = crate::build::push_vlan(Frame::from_slice(&base), 20, 0);
        hub.forward_from(Frame::from_slice(&tagged_20), ports[0].1.id);
        assert_eq!(
            ports[1].0.inner.lock().unwrap().len(),
            0,
            "an access port claiming VLAN 10 cannot inject VLAN 20"
        );

        // Its own VLAN, redundantly tagged, is accepted.
        let tagged_10 = crate::build::push_vlan(Frame::from_slice(&base), 10, 0);
        hub.forward_from(Frame::from_slice(&tagged_10), ports[0].1.id);
        assert_eq!(ports[1].0.inner.lock().unwrap().len(), 1);
    }

    #[test]
    fn two_switches_trunked_together_keep_vlans_apart() {
        // The topology this is all for: two switches joined by one trunk,
        // each with an access port in VLAN 10 and one in VLAN 20. Traffic
        // must cross the trunk and still stay inside its VLAN.
        let (left, right) = (Arc::new(L2Hub::new()), Arc::new(L2Hub::new()));
        let (cable_l, cable_r) = Cable::pair();
        let hl_trunk = left.connect_arc(cable_l);
        let hr_trunk = right.connect_arc(cable_r);
        left.set_port_mode(&hl_trunk, trunk(&[10, 20], None));
        right.set_port_mode(&hr_trunk, trunk(&[10, 20], None));
        // An uplink has an unknowable number of stations behind it.
        left.set_port_mac_limit(&hl_trunk, None);
        right.set_port_mac_limit(&hr_trunk, None);

        let l10 = Sink {
            mac: "02:00:00:00:10:01".parse().unwrap(),
            ..Default::default()
        };
        let r10 = Sink {
            mac: "02:00:00:00:10:02".parse().unwrap(),
            ..Default::default()
        };
        let r20 = Sink {
            mac: "02:00:00:00:20:02".parse().unwrap(),
            ..Default::default()
        };
        let h_l10 = left.connect(l10.clone());
        let h_r10 = right.connect(r10.clone());
        let h_r20 = right.connect(r20.clone());
        left.set_port_mode(&h_l10, access(10));
        right.set_port_mode(&h_r10, access(10));
        right.set_port_mode(&h_r20, access(20));

        let f = build_frame(MacAddr::broadcast(), l10.mac, EtherType::IPV4, &[0; 40]);
        left.forward_from(Frame::from_slice(&f), h_l10.id);

        // Crossed the trunk, arrived untagged at the far access port...
        assert_eq!(r10.inner.lock().unwrap().len(), 1, "VLAN 10 must cross");
        let arrived = r10.inner.lock().unwrap()[0].clone();
        assert!(!Frame::from_slice(&arrived).has_vlan());
        // ...and did not leak into VLAN 20.
        assert_eq!(
            r20.inner.lock().unwrap().len(),
            0,
            "VLAN 20 must not see it"
        );

        // The far switch learned the station through its trunk, so the reply
        // is forwarded rather than flooded.
        r10.inner.lock().unwrap().clear();
        let reply = build_frame(l10.mac, r10.mac, EtherType::IPV4, &[0; 40]);
        let before = right.stats().forwarded;
        right.forward_from(Frame::from_slice(&reply), h_r10.id);
        assert_eq!(
            right.stats().forwarded,
            before + 1,
            "the trunk should be a learned destination, not a flood"
        );
        assert_eq!(l10.inner.lock().unwrap().len(), 1, "the reply came back");
    }

    #[test]
    fn the_same_address_on_two_vlans_is_two_stations() {
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 4);
        hub.set_port_mode(&ports[0].1, access(10));
        hub.set_port_mode(&ports[1].1, access(20));
        hub.set_port_mode(&ports[2].1, access(10));
        hub.set_port_mode(&ports[3].1, access(20));

        // One address, announced on both VLANs from different ports.
        let station: MacAddr = "02:00:00:00:aa:aa".parse().unwrap();
        let announce = build_frame(MacAddr::broadcast(), station, EtherType::IPV4, &[0; 40]);
        hub.forward_from(Frame::from_slice(&announce), ports[0].1.id);
        hub.forward_from(Frame::from_slice(&announce), ports[1].1.id);
        assert_eq!(hub.mac_table_len(), 2, "one per VLAN, not a port flap");

        // Traffic on VLAN 10 goes to the VLAN 10 port, and vice versa.
        for (sender, expect, other) in [(2usize, 0usize, 1usize), (3, 1, 0)] {
            for (s, _) in ports.iter() {
                s.inner.lock().unwrap().clear();
            }
            let f = build_frame(station, ports[sender].0.mac, EtherType::IPV4, &[0; 40]);
            hub.forward_from(Frame::from_slice(&f), ports[sender].1.id);
            assert_eq!(ports[expect].0.inner.lock().unwrap().len(), 1);
            assert_eq!(ports[other].0.inner.lock().unwrap().len(), 0);
        }
    }

    #[test]
    fn transparent_ports_pass_tags_through_untouched() {
        // The default, and what every pre-VLAN caller relies on.
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 2);
        assert_eq!(hub.port_mode(&ports[0].1), Some(PortMode::transparent()));

        let base = build_frame(
            MacAddr::broadcast(),
            ports[0].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        let tagged = crate::build::push_vlan(Frame::from_slice(&base), 77, 5);
        hub.forward_from(Frame::from_slice(&tagged), ports[0].1.id);

        let out = ports[1].0.inner.lock().unwrap()[0].clone();
        assert_eq!(out, tagged, "byte-identical, tag and priority included");

        // And an untagged frame stays untagged.
        hub.forward_from(Frame::from_slice(&base), ports[0].1.id);
        let out = ports[1].0.inner.lock().unwrap()[1].clone();
        assert_eq!(out, base);
    }

    #[test]
    fn a_reconfigured_port_still_forwards() {
        // Regression: configuration used to be applied by publishing a
        // replacement `Arc<Port>`, which dangled the `Weak<Port>` held by the
        // device's handler. The port then went silently dead — it accepted
        // frames and forwarded nothing, with no error anywhere.
        let hub = Arc::new(L2Hub::new());
        let a = Spy {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        };
        let b = Spy {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let ha = hub.connect(a.clone());
        let hb = hub.connect(b.clone());
        hub.set_port_mode(&ha, access(10));
        hub.set_port_mode(&hb, access(10));
        hub.set_port_mac_limit(&ha, None);

        // Inject through the device's own handler — the path the dangling weak
        // reference broke — rather than the test-only entry point.
        let f = build_frame(MacAddr::broadcast(), a.mac, EtherType::IPV4, &[0; 40]);
        a.inject(Frame::from_slice(&f));
        assert_eq!(
            b.count(),
            1,
            "a port that has been reconfigured must still forward"
        );
    }

    #[test]
    fn changing_a_port_mode_forgets_what_it_learned() {
        let hub = Arc::new(L2Hub::new());
        let ports = sinks(&hub, 2);
        let f = build_frame(
            MacAddr::broadcast(),
            ports[0].0.mac,
            EtherType::IPV4,
            &[0; 40],
        );
        hub.forward_from(Frame::from_slice(&f), ports[0].1.id);
        assert_eq!(hub.mac_table_len(), 1);

        // The VLAN those addresses were learned under no longer applies.
        hub.set_port_mode(&ports[0].1, access(10));
        assert_eq!(hub.mac_table_len(), 0);
        assert_eq!(hub.port_mode(&ports[0].1), Some(access(10)));
    }
}

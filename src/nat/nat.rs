//! IPv4 5-tuple NAT.
//!
//! Port of `nat.go`. Inside faces the private network (gateway role); outside
//! faces the upstream network and carries a public IP.
//!
//! Connection tracking is keyed by `(namespace, proto, src_ip, src_port)` for
//! TCP/UDP, with `src_port` substituted by the ICMP identifier for ICMP echo.
//! Reverse lookup is keyed by `(proto, outside_port)`.

use crate::nat::defrag::{Defragger, FragMax};
use crate::nat::frag::FragTable;
use crate::nat::helper::{
    Expectation, Helper, LocalHelper, NatMapping, PROTO_ICMP, PROTO_TCP, PROTO_UDP, PacketHelper,
    PortForward,
};
use crate::nat::ports::{PortKey, PortMap, PortUse};
use crate::nat::track::{HostQuota, MappingHold, NatLimits, PeerQuotas, Peers, Quota, SeqAdj};
use crate::time::Instant;
use crate::{
    IpPrefix, L3Connector, L3Device, L3Handler, Packet, Result, checksum, connect_l3,
    incremental_update,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const NAT_PORT_MIN: u16 = 10000;
const NAT_PORT_MAX: u16 = 65535;
/// How often packet handling sweeps idle mappings, lapsed expectations and
/// forwards, so they go even if nobody calls [`Nat::sweep`]. A mapping thus
/// outlives its timeout by at most this much.
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Cap on pending expectations. ALGs add them on packets remote peers
/// control (TFTP requests, SDP offers), so the table must not grow unbounded.
const MAX_EXPECTATIONS: usize = 1024;
/// How long an ALG's [`Nat::create_mapping`] keeps an existing outbound
/// mapping open to any remote: as long as the longest expectation an ALG
/// registers alongside it (SIP and H.323 media), by which time the remote
/// it announced the port to has connected, and is tracked, or never will.
const ALG_OPEN_WINDOW: Duration = Duration::from_secs(120);
/// ICMP errors the NAT originates, per second and in a burst (RFC 1812
/// §4.3.2.8 wants them rate-limited).
const ICMP_RATE: u32 = 100;
const ICMP_BURST: u32 = 50;
/// Shortest time between two reclaims of idle mappings for want of a free
/// port (see [`Nat::alloc_port_locked`]). Each walks the whole table; with
/// the pool full of live mappings, every new flow would otherwise pay for
/// one, under the lock every packet takes.
pub(crate) const RECLAIM_INTERVAL: Duration = Duration::from_secs(1);

/// Key into the forward connection table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct NatKey {
    ns: u64,
    proto: u8,
    ip: Ipv4Addr,
    port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct NatRevKey {
    proto: u8,
    port: u16,
}

impl PortKey for NatRevKey {
    fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug)]
struct Mapping {
    key: NatKey,
    outside_port: u16,
    last_active: Instant,
    peers: Peers,
    /// Set for mappings made to receive connections (port forwards,
    /// expectations, ALG-opened media ports): any remote's traffic keeps
    /// them alive and is tracked. A plain outbound mapping is kept alive
    /// only by remotes its inside host has talked to (RFC 4787 REQ-6 lets
    /// inbound refresh be off); otherwise anyone could hold every mapping,
    /// and with them the whole port pool, open forever by spraying packets
    /// at it.
    open: bool,
    /// Until when an ALG opened a plain outbound mapping as `open` would
    /// (see [`ALG_OPEN_WINDOW`]).
    open_until: Option<Instant>,
    /// Counts the mapping against its inside host's quota while it lives.
    _hold: MappingHold,
}

impl Mapping {
    fn new(
        key: NatKey,
        outside_port: u16,
        now: Instant,
        hold: MappingHold,
        peers: Peers,
    ) -> Mapping {
        Mapping {
            key,
            outside_port,
            last_active: now,
            peers,
            open: false,
            open_until: None,
            _hold: hold,
        }
    }

    /// Whether any remote's traffic keeps the mapping alive (see `open`).
    fn is_open(&self, now: Instant) -> bool {
        self.open || self.open_until.is_some_and(|t| now <= t)
    }

    /// Open the mapping for a remote an ALG announced it to. One made for
    /// that is open for good, like a forward's; one the inside host was
    /// already using for its own traffic only for [`ALG_OPEN_WINDOW`], so
    /// that a single ALG message does not leave it open to anyone for as
    /// long as it lives.
    fn alg_open(&mut self, created: bool, now: Instant) {
        if created {
            self.open = true;
        } else if !self.open {
            let until = now + ALG_OPEN_WINDOW;
            self.open_until = Some(self.open_until.map_or(until, |t| t.max(until)));
        }
    }

    /// Account for an inbound packet from `peer`. Returns whether the
    /// remote is tracked.
    fn note_inbound(&mut self, peer: SocketAddrV4, tcp_flags: Option<u8>, now: Instant) -> bool {
        if self.is_open(now) || self.peers.contains(&peer) {
            self.last_active = now;
            self.peers.note(peer, false, tcp_flags, now);
        }
        self.peers.contains(&peer)
    }
}

/// The main NAT type. See [module docs](crate::nat) for the design.
pub struct Nat {
    /// Inside L3 device — packets from here are translated outbound.
    inside: Arc<NatSide>,
    /// Outside L3 device — packets here are translated inbound.
    outside: Arc<NatSide>,

    inner: Mutex<NatInner>,
    /// `None` until `enable_defrag()` is called.
    defragger: Mutex<Option<Arc<Defragger>>>,

    /// Allocates IDs for namespace-isolated inside sides.
    ns_counter: AtomicU64,
    ns_sides: Mutex<HashMap<u64, Arc<NatNsSide>>>,

    /// Self-reference held in the `Arc` returned by `new`. The side
    /// devices need to find their parent without taking an `Arc<Nat>`
    /// directly (avoids a reference cycle through `Arc<Self>`).
    self_ref: Weak<Nat>,

    /// Set once an ALG has resized a TCP payload; until then no segment
    /// needs its sequence numbers looked at.
    seqadj_used: AtomicBool,

    /// Networks behind a router on the inside, whose hosts may be
    /// translated too (see [`set_inside_routes`](Self::set_inside_routes)).
    inside_routes: std::sync::RwLock<Vec<IpPrefix>>,

    /// Inbound fragmented datagrams (when not reassembling): which inside
    /// host each one's first fragment went to, keyed by source, IP ID and
    /// protocol, so the rest can follow.
    frags: Mutex<FragTable<(Ipv4Addr, u16, u8), (u64, Ipv4Addr)>>,
    /// Outbound fragmented datagrams whose first fragment was translated,
    /// so the rest may follow it out (see [`OutFragKey`]).
    out_frags: Mutex<FragTable<OutFragKey, ()>>,

    /// When packet handling next sweeps (see [`SWEEP_INTERVAL`]).
    next_sweep: Mutex<Instant>,

    /// Gates the ICMP errors the NAT sends itself.
    icmp_limit: crate::icmp::RateLimiter,
    /// Gates the echo replies the NAT sends to pings from outside, apart
    /// from the errors, so that a ping flood cannot silence those.
    echo_limit: crate::icmp::RateLimiter,
}

struct NatInner {
    mappings: HashMap<NatKey, Mapping>,
    reverse: PortMap<NatRevKey, NatKey>,
    /// Which outside ports the reverse table, forwards and expectations
    /// hold.
    ports: Arc<PortUse>,
    next_port: u16,
    /// When a full pool may next reclaim idle mappings (see
    /// [`RECLAIM_INTERVAL`]).
    next_reclaim: Instant,
    helpers: Vec<Arc<dyn HelperKind>>,
    forwards: Forwards,
    /// The last [`PortForward::id`] handed out.
    forward_id: u64,
    expectations: Expectations,
    /// What each inside host, by namespace and address, holds; an entry
    /// goes once nothing refers to it.
    hosts: HashMap<(u64, Ipv4Addr), Arc<HostQuota>>,
    /// Remotes tracked over all mappings.
    peer_quota: Arc<Quota>,
    limits: NatLimits,
}

/// Port forwards, by outside port and by the inside endpoint each leads to
/// (one per endpoint: see [`Nat::add_port_forward`]). The outbound path asks
/// for every new mapping whether its endpoint is forwarded, and UPnP lets
/// inside hosts add forwards by the hundred, so that must not be a scan.
struct Forwards {
    by_port: PortMap<NatRevKey, PortForward>,
    by_endpoint: HashMap<NatKey, NatRevKey>,
}

impl Forwards {
    fn new(ports: Arc<PortUse>) -> Forwards {
        Forwards {
            by_port: PortMap::new(ports),
            by_endpoint: HashMap::new(),
        }
    }

    fn endpoint(pf: &PortForward) -> NatKey {
        NatKey {
            ns: pf.namespace,
            proto: pf.proto,
            ip: pf.inside_ip,
            port: pf.inside_port,
        }
    }

    fn get(&self, rk: &NatRevKey) -> Option<&PortForward> {
        self.by_port.get(rk)
    }

    fn contains_key(&self, rk: &NatRevKey) -> bool {
        self.by_port.contains_key(rk)
    }

    /// The forward leading to inside endpoint `k`, if any.
    fn for_endpoint(&self, k: &NatKey) -> Option<(NatRevKey, &PortForward)> {
        let rk = *self.by_endpoint.get(k)?;
        Some((rk, self.by_port.get(&rk)?))
    }

    fn insert(&mut self, rk: NatRevKey, pf: PortForward) {
        self.remove(&rk);
        self.by_endpoint.insert(Self::endpoint(&pf), rk);
        self.by_port.insert(rk, pf);
    }

    fn remove(&mut self, rk: &NatRevKey) -> Option<PortForward> {
        let pf = self.by_port.remove(rk)?;
        let ep = Self::endpoint(&pf);
        if self.by_endpoint.get(&ep) == Some(rk) {
            self.by_endpoint.remove(&ep);
        }
        Some(pf)
    }

    fn iter(&self) -> impl Iterator<Item = (&NatRevKey, &PortForward)> {
        self.by_port.iter()
    }

    fn values(&self) -> impl Iterator<Item = &PortForward> {
        self.by_port.values()
    }

    fn retain(&mut self, mut keep: impl FnMut(&PortForward) -> bool) {
        self.by_port.retain(|_, pf| keep(pf));
        let by_port = &self.by_port;
        self.by_endpoint.retain(|_, rk| by_port.contains_key(rk));
    }
}

/// Pending expectations, each holding its outside port while listed.
/// Read through `Deref`; changed only through the methods, which keep the
/// port counts right.
struct Expectations {
    list: Vec<Expectation>,
    ports: Arc<PortUse>,
}

impl std::ops::Deref for Expectations {
    type Target = [Expectation];
    fn deref(&self) -> &[Expectation] {
        &self.list
    }
}

impl Expectations {
    fn new(ports: Arc<PortUse>) -> Expectations {
        Expectations {
            list: Vec::new(),
            ports,
        }
    }

    fn push(&mut self, e: Expectation) {
        self.ports.acquire(e.outside_port);
        self.list.push(e);
    }

    fn remove(&mut self, i: usize) -> Expectation {
        let e = self.list.remove(i);
        self.ports.release(e.outside_port);
        e
    }

    fn swap_remove(&mut self, i: usize) {
        let e = self.list.swap_remove(i);
        self.ports.release(e.outside_port);
    }

    fn retain(&mut self, mut keep: impl FnMut(&Expectation) -> bool) {
        let ports = &self.ports;
        self.list.retain(|e| {
            let kept = keep(e);
            if !kept {
                ports.release(e.outside_port);
            }
            kept
        });
    }

    /// Keep expectation `i` until at least `expires`.
    fn extend(&mut self, i: usize, expires: Instant) {
        let e = &mut self.list[i];
        e.expires = e.expires.max(expires);
    }
}

/// Object-safe enum-like trait so the helper vector can hold both packet and
/// local helpers in one place.
trait HelperKind: Helper {
    fn as_packet(&self) -> Option<&dyn PacketHelper> {
        None
    }
    fn as_local(&self) -> Option<&dyn LocalHelper> {
        None
    }
}

impl std::fmt::Debug for Nat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nat")
            .field("inside", &self.inside_addr())
            .field("outside", &self.outside_addr())
            .finish()
    }
}

impl Nat {
    /// Construct a new NAT with the given inside (private) and outside (public)
    /// prefixes.
    pub fn new(inside_addr: IpPrefix, outside_addr: IpPrefix) -> Arc<Nat> {
        // Built cyclic so each side holds its parent from the start, with
        // no lock to take on the packet path: a lock held there would be
        // held through delivery, deadlocking a handler that replies from
        // inside it and poisoned by one that panics.
        let ports = PortUse::new(NAT_PORT_MIN, NAT_PORT_MAX);
        Arc::new_cyclic(|me: &Weak<Nat>| Nat {
            inside: Arc::new(NatSide::new(true, inside_addr, me.clone())),
            outside: Arc::new(NatSide::new(false, outside_addr, me.clone())),
            inner: Mutex::new(NatInner {
                mappings: HashMap::new(),
                reverse: PortMap::new(ports.clone()),
                next_port: NAT_PORT_MIN,
                next_reclaim: Instant::now(),
                helpers: Vec::new(),
                forwards: Forwards::new(ports.clone()),
                forward_id: 0,
                expectations: Expectations::new(ports.clone()),
                ports,
                hosts: HashMap::new(),
                peer_quota: Arc::new(Quota::new(NatLimits::default().max_peers)),
                limits: NatLimits::default(),
            }),
            defragger: Mutex::new(None),
            ns_counter: AtomicU64::new(0),
            ns_sides: Mutex::new(HashMap::new()),
            self_ref: me.clone(),
            seqadj_used: AtomicBool::new(false),
            inside_routes: std::sync::RwLock::new(Vec::new()),
            frags: Mutex::new(FragTable::default()),
            out_frags: Mutex::new(FragTable::default()),
            next_sweep: Mutex::new(Instant::now() + SWEEP_INTERVAL),
            icmp_limit: crate::icmp::RateLimiter::new(ICMP_RATE, ICMP_BURST),
            echo_limit: crate::icmp::RateLimiter::new(ICMP_RATE, ICMP_BURST),
        })
    }

    /// Returns the inside L3 device (faces the private network).
    pub fn inside(&self) -> Arc<dyn L3Device> {
        self.inside.clone()
    }

    /// Returns the outside L3 device (faces the upstream).
    pub fn outside(&self) -> Arc<dyn L3Device> {
        self.outside.clone()
    }

    /// IPv4 address bound to the inside interface.
    pub fn inside_addr(&self) -> Option<Ipv4Addr> {
        match self.inside.addr().addr() {
            IpAddr::V4(a) => Some(a),
            _ => None,
        }
    }

    /// Whether `ip` is the inside network's directed broadcast address
    /// (RFC 919), which like the limited one never leaves that network.
    /// /31 and /32 have none (RFC 3021).
    fn is_inside_broadcast(&self, ip: Ipv4Addr) -> bool {
        let prefix = self.inside.addr();
        match prefix.addr() {
            IpAddr::V4(a) if (1..=30).contains(&prefix.bits()) => {
                let host = u32::MAX >> prefix.bits();
                u32::from(ip) == u32::from(a) | host
            }
            _ => false,
        }
    }

    /// IPv4 address bound to the outside interface.
    pub fn outside_addr(&self) -> Option<Ipv4Addr> {
        match self.outside.addr().addr() {
            IpAddr::V4(a) => Some(a),
            _ => None,
        }
    }

    /// Set the caps on what inside hosts may hold (see [`NatLimits`]).
    /// Lowering one takes nothing away; it holds back what comes next.
    pub fn set_limits(&self, limits: NatLimits) {
        let mut inner = self.inner.lock().unwrap();
        inner.peer_quota.set_max(limits.max_peers);
        for h in inner.hosts.values() {
            h.set_limits(&limits);
        }
        inner.limits = limits;
    }

    /// Whether `ip` may be translated as the source of an inside host:
    /// one on the inside network (or a network routed behind it), and not
    /// the NAT itself nor a broadcast address. Anything else is spoofed, or
    /// from a network the NAT was not set up to serve.
    fn inside_source_ok(&self, ip: Ipv4Addr) -> bool {
        let ip_addr = IpAddr::V4(ip);
        let known = self.inside.addr().contains(ip_addr)
            || self
                .inside_routes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|r| r.contains(ip_addr));
        known && Some(ip) != self.inside_addr() && !self.is_inside_broadcast(ip)
    }

    /// Networks reached through a router on the inside, whose hosts the NAT
    /// translates as well as those on the inside network itself.
    ///
    /// Outbound packets are translated only from sources the NAT serves;
    /// any other source is spoofed, and is dropped. Hosts behind an inside
    /// router -- a VPN's clients with addresses of their own, say -- have
    /// sources outside the inside prefix: list their networks here. Replaces
    /// any list set before; empty (the default) serves the inside network
    /// alone. IPv6 prefixes are ignored.
    pub fn set_inside_routes(&self, routes: Vec<IpPrefix>) {
        let v4: Vec<IpPrefix> = routes.into_iter().filter(|r| r.is_v4()).collect();
        *self
            .inside_routes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = v4;
    }

    /// Enable IPv4 defragmentation (off by default).
    ///
    /// Fragmented datagrams are then translated whole, so ALGs see complete
    /// messages, and sent on cut into fragments no larger than the largest
    /// one they arrived in (keeping Don't Fragment if that one had it), as
    /// Linux conntrack does.
    pub fn enable_defrag(&self) {
        let mut d = self.defragger.lock().unwrap();
        *d = Some(Arc::new(Defragger::new()));
    }

    /// Register a packet-level helper (FTP, SIP, …).
    pub fn add_packet_helper<H: PacketHelper + 'static>(&self, h: Arc<H>) {
        struct PacketKind<H: PacketHelper>(Arc<H>);
        impl<H: PacketHelper + 'static> Helper for PacketKind<H> {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn close(&self) -> Result<()> {
                self.0.close()
            }
        }
        impl<H: PacketHelper + 'static> HelperKind for PacketKind<H> {
            fn as_packet(&self) -> Option<&dyn PacketHelper> {
                Some(&*self.0)
            }
        }
        let kind: Arc<dyn HelperKind> = Arc::new(PacketKind(h));
        self.inner.lock().unwrap().helpers.push(kind);
    }

    /// Register a local-traffic helper (UPnP, SSDP, …).
    pub fn add_local_helper<H: LocalHelper + 'static>(&self, h: Arc<H>) {
        struct LocalKind<H: LocalHelper>(Arc<H>);
        impl<H: LocalHelper + 'static> Helper for LocalKind<H> {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn close(&self) -> Result<()> {
                self.0.close()
            }
        }
        impl<H: LocalHelper + 'static> HelperKind for LocalKind<H> {
            fn as_local(&self) -> Option<&dyn LocalHelper> {
                Some(&*self.0)
            }
        }
        let kind: Arc<dyn HelperKind> = Arc::new(LocalKind(h));
        self.inner.lock().unwrap().helpers.push(kind);
    }

    /// Register an expectation for an upcoming related connection (e.g. FTP
    /// data channel). Removed on match.
    ///
    /// Ignored if `e.outside_port` already belongs to a different inside
    /// endpoint (a live mapping or a port forward): the connection could never
    /// reach the expected host. Registering the same expectation again only
    /// extends its lifetime.
    pub fn add_expectation(&self, e: Expectation) {
        let rk = NatRevKey {
            proto: e.proto,
            port: e.outside_port,
        };
        let target = NatKey {
            ns: e.namespace,
            proto: e.proto,
            ip: e.inside_ip,
            port: e.inside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        Self::add_expectation_locked(&mut inner, e, rk, target);
    }

    fn add_expectation_locked(inner: &mut NatInner, e: Expectation, rk: NatRevKey, target: NatKey) {
        Self::expire_port_locked(inner, rk, Instant::now());
        if inner.reverse.get(&rk).is_some_and(|k| *k != target) || inner.forwards.contains_key(&rk)
        {
            return;
        }
        if let Some(old) = inner.expectations.iter().position(|o| {
            o.proto == e.proto
                && o.outside_port == e.outside_port
                && o.namespace == e.namespace
                && o.inside_ip == e.inside_ip
                && o.inside_port == e.inside_port
                && o.remote_ip == e.remote_ip
                && o.remote_port == e.remote_port
        }) {
            inner.expectations.extend(old, e.expires);
            return;
        }
        // ALGs add expectations on what inside hosts send, so one host
        // could otherwise fill the table and push everyone else's out. It
        // makes room from its own when at its cap; only when the table
        // itself is full does the busiest host give one up.
        let host = (e.namespace, e.inside_ip);
        let of_host = |x: &Expectation| (x.namespace, x.inside_ip) == host;
        let per_host = inner.limits.max_expectations_per_host;
        let full_for_host =
            per_host != 0 && inner.expectations.iter().filter(|x| of_host(x)).count() >= per_host;
        if full_for_host || inner.expectations.len() >= MAX_EXPECTATIONS {
            let now = Instant::now();
            inner.expectations.retain(|e| now <= e.expires);
        }
        let mine = inner.expectations.iter().filter(|x| of_host(x)).count();
        let victim = if per_host != 0 && mine >= per_host {
            Some(host)
        } else if inner.expectations.len() >= MAX_EXPECTATIONS {
            let mut counts: HashMap<(u64, Ipv4Addr), usize> = HashMap::new();
            for x in inner.expectations.iter() {
                *counts.entry((x.namespace, x.inside_ip)).or_default() += 1;
            }
            counts.into_iter().max_by_key(|&(_, n)| n).map(|(h, _)| h)
        } else {
            None
        };
        // Of the victim's, the one closest to lapsing is the least likely
        // to be used.
        if let Some(victim) = victim
            && let Some(pos) = (0..inner.expectations.len())
                .filter(|&i| {
                    let x = &inner.expectations[i];
                    (x.namespace, x.inside_ip) == victim
                })
                .min_by_key(|&i| inner.expectations[i].expires)
        {
            inner.expectations.swap_remove(pos);
        }
        inner.expectations.push(e);
    }

    /// Find and remove the first non-expired expectation matching the given
    /// inside target `(proto, inside_ip, inside_port)`, returning it.
    ///
    /// Lets an ALG withdraw an expectation it registered, and tests assert
    /// that one was registered.
    pub fn take_expectation(
        &self,
        proto: u8,
        inside_ip: Ipv4Addr,
        inside_port: u16,
    ) -> Option<Expectation> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let pos = inner.expectations.iter().position(|e| {
            now <= e.expires
                && e.proto == proto
                && e.inside_ip == inside_ip
                && e.inside_port == inside_port
        })?;
        Some(inner.expectations.remove(pos))
    }

    /// Add or update a static port forward.
    ///
    /// Fails with `AlreadyExists` if the port is forwarded to another host,
    /// and with `AddrInUse` if a live dynamic mapping or a pending expectation
    /// holds it: taking the port over would hand that session's traffic to
    /// the forward's host. A dynamic mapping of the forward's own inside
    /// endpoint is no conflict, and becomes the forward's, sessions and
    /// all. Also fails with `AddrInUse` if another port is already
    /// forwarded to the same inside endpoint: the NAT gives each inside
    /// endpoint a single public port, from which all its traffic leaves.
    pub fn add_port_forward(&self, pf: PortForward) -> Result<()> {
        self.add_port_forward_id(pf).map(|_| ())
    }

    /// [`add_port_forward`](Self::add_port_forward), returning the id the
    /// forward got (see [`PortForward::id`]). Each call gets a new one, a
    /// renewal of the same forward included.
    pub(crate) fn add_port_forward_id(&self, mut pf: PortForward) -> Result<u64> {
        let rk = NatRevKey {
            proto: pf.proto,
            port: pf.outside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        let now = Instant::now();
        // A lapsed forward holds neither its port nor its endpoint.
        Self::expire_port_locked(inner, rk, now);
        if let Some((other, f)) = inner.forwards.for_endpoint(&Forwards::endpoint(&pf))
            && f.expires.is_some_and(|e| e < now)
        {
            inner.forwards.remove(&other);
            Self::remove_mapping_at_locked(inner, other);
        }
        if let Some(existing) = inner.forwards.get(&rk)
            && (existing.inside_ip != pf.inside_ip || existing.namespace != pf.namespace)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "port already forwarded to another host",
            ));
        }
        let reserved = inner
            .expectations
            .iter()
            .any(|e| e.proto == pf.proto && e.outside_port == pf.outside_port && now <= e.expires);
        // A dynamic mapping of the forward's own inside endpoint is no
        // conflict: a host that sends from its listening port, which the
        // NAT preserved, then asks UPnP to forward that port to itself
        // wants exactly what it has. The forward takes the mapping over.
        let endpoint = Forwards::endpoint(&pf);
        let own = inner.reverse.get(&rk) == Some(&endpoint);
        let dynamic = inner.reverse.contains_key(&rk) && !inner.forwards.contains_key(&rk) && !own;
        // An inside endpoint has one mapping, so one public port (RFC 5382
        // REQ-1: endpoint-independent mapping). A second forward to it
        // would move that mapping to whichever port saw traffic last,
        // resetting its sessions and sending every reply from that port.
        let taken = inner
            .forwards
            .for_endpoint(&Forwards::endpoint(&pf))
            .is_some_and(|(k, _)| k != rk);
        if reserved || dynamic || taken {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "port in use by another session",
            ));
        }
        // An updated forward may point somewhere else: drop the session the
        // old one set up, and let the next packet build the new one. The
        // same forward again (a UPnP lease renewal) only moves its expiry;
        // dropping the session would move the host's replies to a fresh
        // port and lose its connections.
        let same = inner.forwards.get(&rk).is_some_and(|old| {
            old.namespace == pf.namespace
                && old.inside_ip == pf.inside_ip
                && old.inside_port == pf.inside_port
        });
        if own {
            // Opened as a forward's is, sessions and port kept.
            if let Some(m) = inner.mappings.get_mut(&endpoint) {
                m.open = true;
            }
        } else if !same {
            Self::remove_mapping_at_locked(inner, rk);
        }
        inner.forward_id += 1;
        pf.id = inner.forward_id;
        inner.forwards.insert(rk, pf);
        Ok(inner.forward_id)
    }

    /// Remove a previously-added port forward, and the session it carried.
    /// No-op if absent.
    pub fn remove_port_forward(&self, proto: u8, outside_port: u16) {
        let rk = NatRevKey {
            proto,
            port: outside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        if inner.forwards.remove(&rk).is_some() {
            Self::remove_mapping_at_locked(&mut inner, rk);
        }
    }

    /// Snapshot of active port forwards (expired ones filtered out).
    pub fn list_port_forwards(&self) -> Vec<PortForward> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        inner
            .forwards
            .values()
            .filter(|pf| pf.expires.is_none_or(|e| e > now))
            .cloned()
            .collect()
    }

    /// The live forward at position `idx` among those
    /// [`list_port_forwards`](Self::list_port_forwards) would list, in the
    /// same order while the table is unchanged, without copying out the
    /// rest.
    pub(crate) fn port_forward_at(&self, idx: usize) -> Option<PortForward> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        inner
            .forwards
            .values()
            .filter(|pf| pf.expires.is_none_or(|e| e > now))
            .nth(idx)
            .cloned()
    }

    /// The live forward on `(proto, outside_port)`, if any: what
    /// [`list_port_forwards`](Self::list_port_forwards) would find there,
    /// without copying out the whole table.
    pub(crate) fn port_forward(&self, proto: u8, outside_port: u16) -> Option<PortForward> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        inner
            .forwards
            .get(&NatRevKey {
                proto,
                port: outside_port,
            })
            .filter(|pf| pf.expires.is_none_or(|e| e > now))
            .cloned()
    }

    /// Create (or reuse) a mapping for a helper-managed connection on the
    /// NAT's own inside interface. Returns the outside port, or `None` if the
    /// port pool is exhausted.
    ///
    /// The mapping is made for a remote to connect to, which the inside host
    /// may not have contacted, so any remote's traffic keeps it alive and is
    /// tracked. A new mapping stays that way; an existing one the host was
    /// already using for its own traffic only for the next two minutes,
    /// after which only remotes it has exchanged traffic with count again.
    pub fn create_mapping(&self, proto: u8, inside_ip: Ipv4Addr, inside_port: u16) -> Option<u16> {
        self.create_mapping_in(0, proto, inside_ip, inside_port)
    }

    /// Choose the outside port for a connection an ALG expects from one
    /// known remote, `remote_ip`, to inside endpoint
    /// `inside_ip:inside_port`, and register the expectation on it. Returns
    /// the port, or `None` if the pool is exhausted.
    ///
    /// Unlike [`create_mapping_in`](Self::create_mapping_in) this opens
    /// nothing yet: a mapping delivers whatever reaches its port, so one
    /// made now would let any Internet host that finds the port connect
    /// before the expected remote does. The pending expectation holds the
    /// port meanwhile (see `port_in_use_locked`), and the mapping is made
    /// when the expected remote connects. An endpoint that is already
    /// mapped, or has one pending already (a retransmitted command), keeps
    /// its port.
    pub(crate) fn expect_from_in(
        &self,
        namespace: u64,
        proto: u8,
        (inside_ip, inside_port): (Ipv4Addr, u16),
        remote_ip: Ipv4Addr,
        expires: Instant,
    ) -> Option<u16> {
        let k = NatKey {
            ns: namespace,
            proto,
            ip: inside_ip,
            port: inside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        let now = Instant::now();
        Self::expire_mapping_locked(inner, k, now);
        let pending = || {
            inner.expectations.iter().find(|e| {
                now <= e.expires
                    && e.proto == proto
                    && e.namespace == namespace
                    && e.inside_ip == inside_ip
                    && e.inside_port == inside_port
            })
        };
        let port = match inner.mappings.get(&k) {
            Some(m) => m.outside_port,
            None => match pending().map(|e| e.outside_port) {
                Some(p) => p,
                None => match Self::forward_port_for_locked(inner, k, now) {
                    Some(p) => p,
                    None => Self::alloc_port_locked(inner, proto, inside_port)?,
                },
            },
        };
        let e = Expectation::new(proto, inside_ip, inside_port, port, expires)
            .remote_ip(remote_ip)
            .namespace(namespace);
        Self::add_expectation_locked(inner, e, NatRevKey { proto, port }, k);
        Some(port)
    }

    /// [`create_mapping`](Self::create_mapping) for a host in inside
    /// namespace `namespace` (see [`NatMapping::namespace`]).
    pub fn create_mapping_in(
        &self,
        namespace: u64,
        proto: u8,
        inside_ip: Ipv4Addr,
        inside_port: u16,
    ) -> Option<u16> {
        let k = NatKey {
            ns: namespace,
            proto,
            ip: inside_ip,
            port: inside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        Self::expire_mapping_locked(&mut inner, k, now);
        let created = !inner.mappings.contains_key(&k);
        let m = Self::get_or_create_mapping_locked(&mut inner, k)?;
        m.alg_open(created, now);
        Some(m.outside_port)
    }

    /// Map two endpoints of one inside host to consecutive outside ports,
    /// the first even, and return that first port: RTP and its RTCP, which
    /// peers send to the RTP port + 1 unless told otherwise (RFC 3550 §11,
    /// RFC 3605). An existing pair laid out that way is reused. `None` if
    /// either endpoint already holds some other port, or no pair is free.
    pub(crate) fn create_mapping_pair_in(
        &self,
        namespace: u64,
        proto: u8,
        inside_ip: Ipv4Addr,
        (first, second): (u16, u16),
    ) -> Option<u16> {
        let key = |port| NatKey {
            ns: namespace,
            proto,
            ip: inside_ip,
            port,
        };
        let (k1, k2) = (key(first), key(second));
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        match (inner.mappings.get(&k1), inner.mappings.get(&k2)) {
            (Some(a), Some(b))
                if a.outside_port % 2 == 0 && b.outside_port == a.outside_port + 1 =>
            {
                let p = a.outside_port;
                for k in [k1, k2] {
                    let m = inner.mappings.get_mut(&k).unwrap();
                    m.last_active = now;
                    m.alg_open(false, now);
                }
                return Some(p);
            }
            (None, None) => {}
            _ => return None,
        }
        let p = Self::alloc_pair_locked(&mut inner)?;
        let m1 = Self::new_mapping_locked(&mut inner, k1, p, now, false)?;
        let m2 = Self::new_mapping_locked(&mut inner, k2, p + 1, now, false)?;
        for mut m in [m1, m2] {
            inner.reverse.insert(
                NatRevKey {
                    proto,
                    port: m.outside_port,
                },
                m.key,
            );
            m.open = true;
            inner.mappings.insert(m.key, m);
        }
        Some(p)
    }

    /// Inject a packet onto the inside interface (used by helpers that
    /// synthesize traffic destined for an inside host).
    pub fn send_inside(&self, pkt: &Packet) {
        self.inside.deliver(pkt);
    }

    /// Inject a packet into inside namespace `namespace` (see
    /// [`NatMapping::namespace`]); 0 is the inside interface.
    pub fn send_inside_in(&self, namespace: u64, pkt: &Packet) {
        self.send_ns(namespace, pkt);
    }

    // -- Internal --------------------------------------------------------

    /// A new mapping of inside endpoint `k` to outside port `port`,
    /// counted against its host's quotas. Refused if the host is at its
    /// cap, unless `force`: a port forward or an expectation is a mapping
    /// the NAT was told to make.
    fn new_mapping_locked(
        inner: &mut NatInner,
        k: NatKey,
        port: u16,
        now: Instant,
        force: bool,
    ) -> Option<Mapping> {
        let limits = &inner.limits;
        let host = inner
            .hosts
            .entry((k.ns, k.ip))
            .or_insert_with(|| Arc::new(HostQuota::new(limits)))
            .clone();
        let hold = MappingHold::take(&host, force)?;
        let peers = Peers::new(PeerQuotas {
            global: inner.peer_quota.clone(),
            host,
        });
        Some(Mapping::new(k, port, now, hold, peers))
    }

    /// Drop whatever mapping owns outside port `rk`, in both tables.
    fn remove_mapping_at_locked(inner: &mut NatInner, rk: NatRevKey) {
        if let Some(k) = inner.reverse.remove(&rk)
            && inner
                .mappings
                .get(&k)
                .is_some_and(|m| m.outside_port == rk.port)
        {
            inner.mappings.remove(&k);
        }
    }

    /// Drop mapping `k` if it has been idle past its timeout. Sweeps are
    /// lazy, so one can linger; where it would decide something, it must not
    /// count as live.
    fn expire_mapping_locked(inner: &mut NatInner, k: NatKey, now: Instant) {
        let Some(m) = inner.mappings.get_mut(&k) else {
            return;
        };
        if m.peers.expire(k.proto, m.last_active, now) {
            let rk = NatRevKey {
                proto: k.proto,
                port: m.outside_port,
            };
            inner.mappings.remove(&k);
            if inner.reverse.get(&rk) == Some(&k) {
                inner.reverse.remove(&rk);
            }
        }
    }

    /// Free outside port `rk` of whatever holds it only until the next
    /// sweep: a lapsed forward (with its session) or an idle mapping.
    fn expire_port_locked(inner: &mut NatInner, rk: NatRevKey, now: Instant) {
        if inner
            .forwards
            .get(&rk)
            .is_some_and(|f| f.expires.is_some_and(|e| e < now))
        {
            inner.forwards.remove(&rk);
            Self::remove_mapping_at_locked(inner, rk);
        }
        if let Some(k) = inner.reverse.get(&rk).copied() {
            Self::expire_mapping_locked(inner, k, now);
        }
    }

    /// Bind inside endpoint `k` to outside port `rk.port`, which must be free.
    ///
    /// The tables hold one mapping per inside endpoint. If `k` already has one
    /// on another port, `displace` decides: a port forward is the endpoint's
    /// configured public identity and replaces it (old reverse entry
    /// included); an expectation must not break a live session and is
    /// refused. (Mappings made while a forward exists already use its port,
    /// so only one from before the forward was added gets displaced.)
    fn install_mapping_locked(
        inner: &mut NatInner,
        k: NatKey,
        rk: NatRevKey,
        displace: bool,
    ) -> bool {
        if let Some(old) = inner.mappings.get(&k) {
            if !displace {
                return false;
            }
            let old_rk = NatRevKey {
                proto: k.proto,
                port: old.outside_port,
            };
            inner.reverse.remove(&old_rk);
        }
        let Some(mut m) = Self::new_mapping_locked(inner, k, rk.port, Instant::now(), true) else {
            return false;
        };
        m.open = true;
        inner.mappings.insert(k, m);
        inner.reverse.insert(rk, k);
        true
    }

    fn get_or_create_mapping_locked(inner: &mut NatInner, k: NatKey) -> Option<&mut Mapping> {
        let now = Instant::now();
        if inner.mappings.contains_key(&k) {
            let m = inner.mappings.get_mut(&k).unwrap();
            m.last_active = now;
            return Some(m);
        }

        // A forward is the endpoint's public identity for all its traffic,
        // not only what arrives: a host that speaks first (or again, after
        // its forwarded session idled out) must leave from the forwarded
        // port. From a dynamic one, the first packet in on the forward would
        // move the mapping there and strand that dynamic session's replies.
        if let Some(port) = Self::forward_port_for_locked(inner, k, now) {
            let mut m = Self::new_mapping_locked(inner, k, port, now, true)?;
            m.open = true;
            inner.reverse.insert(
                NatRevKey {
                    proto: k.proto,
                    port,
                },
                k,
            );
            inner.mappings.insert(k, m);
            return inner.mappings.get_mut(&k);
        }

        // The host's quota first: a host at its cap must not cost the
        // others a reclaim sweep.
        let mut m = Self::new_mapping_locked(inner, k, 0, now, false)?;
        let port = Self::alloc_port_locked(inner, k.proto, k.port)?;
        m.outside_port = port;
        inner.reverse.insert(
            NatRevKey {
                proto: k.proto,
                port,
            },
            k,
        );
        inner.mappings.insert(k, m);
        inner.mappings.get_mut(&k)
    }

    /// The outside port of a live forward to inside endpoint `k`, if that
    /// port is free. There is at most one: `add_port_forward` refuses a
    /// second forward to the same endpoint.
    fn forward_port_for_locked(inner: &NatInner, k: NatKey, now: Instant) -> Option<u16> {
        let (rk, f) = inner.forwards.for_endpoint(&k)?;
        (f.expires.is_none_or(|e| e >= now) && !inner.reverse.contains_key(&rk)).then_some(rk.port)
    }

    /// A free outside port for a new mapping of inside source port (or
    /// ICMP identifier) `want`, chosen as [`PortUse::choose`] says. When
    /// none is left, idle mappings are reclaimed first, so a caller that
    /// never sweeps does not lose the pool to them.
    ///
    /// A port is free when nothing holds it for any protocol: ports a
    /// forward or a pending expectation will receive traffic on count too,
    /// or that traffic would reach a new session.
    fn alloc_port_locked(inner: &mut NatInner, proto: u8, want: u16) -> Option<u16> {
        Self::scan_port_locked(inner, proto, want).or_else(|| {
            Self::reclaim_locked(inner).then(|| Self::scan_port_locked(inner, proto, want))?
        })
    }

    fn scan_port_locked(inner: &mut NatInner, proto: u8, want: u16) -> Option<u16> {
        let p = inner
            .ports
            .choose(proto != PROTO_ICMP, want, inner.next_port)?;
        if p != want && (NAT_PORT_MIN..=NAT_PORT_MAX).contains(&p) {
            inner.next_port = if p == NAT_PORT_MAX {
                NAT_PORT_MIN
            } else {
                p + 1
            };
        }
        Some(p)
    }

    /// An even outside port that is free along with the next one, reclaiming
    /// idle mappings if there is none.
    fn alloc_pair_locked(inner: &mut NatInner) -> Option<u16> {
        Self::scan_pair_locked(inner)
            .or_else(|| Self::reclaim_locked(inner).then(|| Self::scan_pair_locked(inner))?)
    }

    fn scan_pair_locked(inner: &mut NatInner) -> Option<u16> {
        if inner.ports.pool_free(Some(false)) == 0 || inner.ports.pool_free(Some(true)) == 0 {
            return None;
        }
        let p = inner
            .ports
            .find_pair((NAT_PORT_MIN, NAT_PORT_MAX), inner.next_port)?;
        inner.next_port = p.checked_add(2).unwrap_or(NAT_PORT_MIN);
        Some(p)
    }

    /// Drop idle mappings (and lapsed expectations and forwards) for want
    /// of a free port, unless that was done less than
    /// [`RECLAIM_INTERVAL`] ago. Returns whether it ran.
    fn reclaim_locked(inner: &mut NatInner) -> bool {
        let now = Instant::now();
        if now < inner.next_reclaim {
            return false;
        }
        inner.next_reclaim = now + RECLAIM_INTERVAL;
        Self::expire_locked(inner, now);
        true
    }

    fn match_expectation_locked(
        inner: &mut NatInner,
        proto: u8,
        outside_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<Expectation> {
        let now = Instant::now();
        let pos = inner.expectations.iter().position(|e| {
            expectation_matches(e, now, proto, outside_port, remote_ip, remote_port)
        })?;
        Some(inner.expectations.remove(pos))
    }

    /// Whether an inbound TCP/UDP packet from `remote` to outside port
    /// `rk` would be translated: whether the NAT would forward it, rather
    /// than be its destination. Changes nothing.
    fn would_translate_locked(inner: &NatInner, rk: NatRevKey, remote: SocketAddrV4) -> bool {
        let now = Instant::now();
        inner.reverse.contains_key(&rk)
            || inner
                .forwards
                .get(&rk)
                .is_some_and(|f| f.expires.is_none_or(|e| e >= now))
            || inner.expectations.iter().any(|e| {
                expectation_matches(e, now, rk.proto, rk.port, *remote.ip(), remote.port())
            })
    }

    /// Answer `pkt`, whose TTL ran out here, with a Time Exceeded from
    /// `from`, handed to `send`, unless RFC 1812 forbids one or the rate
    /// limit is spent.
    fn time_exceeded(&self, pkt: &[u8], from: Ipv4Addr, send: impl Fn(&Packet)) {
        if let Some(err) = crate::icmp::time_exceeded(Packet::from_slice(pkt), IpAddr::V4(from))
            && self.icmp_limit.allow()
        {
            send(Packet::from_slice(&err));
        }
    }

    /// [`time_exceeded`](Self::time_exceeded) for a packet from outside.
    fn time_exceeded_outside(&self, pkt: &[u8]) {
        if let Some(me) = self.outside_addr() {
            self.time_exceeded(pkt, me, |p| self.outside.deliver(p));
        }
    }

    fn match_forward(inner: &mut NatInner, proto: u8, outside_port: u16) -> Option<&PortForward> {
        let rk = NatRevKey {
            proto,
            port: outside_port,
        };
        let now = Instant::now();
        let expired = inner
            .forwards
            .get(&rk)
            .and_then(|pf| pf.expires)
            .is_some_and(|e| e < now);
        if expired {
            inner.forwards.remove(&rk);
            Self::remove_mapping_at_locked(inner, rk);
            return None;
        }
        inner.forwards.get(&rk)
    }

    /// Iterate helpers and let any [`LocalHelper`] consume the packet.
    fn handle_local(&self, ns: u64, pkt: &Packet) -> bool {
        let helpers: Vec<_> = {
            let inner = self.inner.lock().unwrap();
            inner.helpers.clone()
        };
        for h in helpers {
            if let Some(lh) = h.as_local()
                && lh.handle_local_in(self, ns, pkt)
            {
                return true;
            }
        }
        false
    }

    fn helper_outbound(&self, pkt: Vec<u8>, m: &NatMapping, proto: u8, dst_port: u16) -> Vec<u8> {
        let helpers: Vec<_> = {
            let inner = self.inner.lock().unwrap();
            if inner.helpers.is_empty() {
                return pkt;
            }
            inner.helpers.clone()
        };
        let mut out = pkt;
        for h in helpers {
            if let Some(ph) = h.as_packet()
                && ph.match_outbound(proto, dst_port)
            {
                out = ph.process_outbound(self, out, m);
            }
        }
        out
    }

    fn helper_inbound(&self, pkt: Vec<u8>, m: &NatMapping, proto: u8, remote_port: u16) -> Vec<u8> {
        let helpers: Vec<_> = {
            let inner = self.inner.lock().unwrap();
            if inner.helpers.is_empty() {
                return pkt;
            }
            inner.helpers.clone()
        };
        let mut out = pkt;
        for h in helpers {
            if let Some(ph) = h.as_packet()
                && ph.match_outbound(proto, remote_port)
            {
                out = ph.process_inbound(self, out, m);
            }
        }
        out
    }

    /// Keep TCP sequence numbers consistent after a helper changed the
    /// length of a segment's payload (`before` bytes on the way in).
    ///
    /// A resize shifts every later byte of that direction's stream, so the
    /// NAT has to shift the sequence numbers of later segments to match, and
    /// shift back the acknowledgements and SACK blocks the other side sends;
    /// otherwise both ends lose sync and the connection stalls or corrupts
    /// data.
    fn tcp_seq_fixup(
        &self,
        k: NatKey,
        peer: SocketAddrV4,
        outbound: bool,
        before: Option<usize>,
        out: &mut [u8],
        ihl: usize,
    ) {
        let (Some(before), Some(after)) = (before, tcp_payload_len(out, ihl)) else {
            return;
        };
        let delta = after as i64 - before as i64;
        if delta == 0 && !self.seqadj_used.load(Ordering::Relaxed) {
            return;
        }
        let seq = u32::from_be_bytes([out[ihl + 4], out[ihl + 5], out[ihl + 6], out[ihl + 7]]);
        let adj = {
            let mut inner = self.inner.lock().unwrap();
            let Some(m) = inner.mappings.get_mut(&k) else {
                return;
            };
            if delta != 0 {
                m.peers.record_resize(&peer, outbound, seq, delta as i32);
                self.seqadj_used.store(true, Ordering::Relaxed);
            }
            m.peers.seq_adjust(&peer, outbound)
        };
        if let Some((this, other)) = adj {
            adjust_tcp_seq(out, ihl, this, other);
        }
    }

    /// Drop idle mappings, lapsed expectations and port forwards, and stale
    /// fragment state.
    ///
    /// Optional: packet handling sweeps every 30 seconds anyway, and port
    /// allocation reclaims idle mappings when the pool runs out. Call it on a
    /// timer to release state while no traffic flows, or to expire entries
    /// closer to their timeouts.
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    /// Sweep if [`SWEEP_INTERVAL`] has passed since the last time.
    fn maybe_sweep(&self) {
        let now = Instant::now();
        {
            let mut next = self.next_sweep.lock().unwrap();
            if now < *next {
                return;
            }
            *next = now + SWEEP_INTERVAL;
        }
        self.sweep_at(now);
    }

    fn sweep_at(&self, now: Instant) {
        Self::expire_locked(&mut self.inner.lock().unwrap(), now);
        self.frags.lock().unwrap().expire(now);
        self.out_frags.lock().unwrap().expire(now);
        // Also sweep the defragger if enabled.
        if let Some(d) = self.defragger.lock().unwrap().clone() {
            d.sweep();
        }
    }

    /// Drop idle mappings, and lapsed expectations and forwards, which all
    /// hold outside ports.
    fn expire_locked(inner: &mut NatInner, now: Instant) {
        inner.mappings.retain(|k, m| {
            if m.peers.expire(k.proto, m.last_active, now) {
                inner.reverse.remove(&NatRevKey {
                    proto: k.proto,
                    port: m.outside_port,
                });
                false
            } else {
                true
            }
        });
        inner.expectations.retain(|e| now <= e.expires);
        let lapsed: Vec<NatRevKey> = inner
            .forwards
            .iter()
            .filter(|(_, pf)| pf.expires.is_some_and(|e| e < now))
            .map(|(rk, _)| *rk)
            .collect();
        for rk in lapsed {
            inner.forwards.remove(&rk);
            Self::remove_mapping_at_locked(inner, rk);
        }
        // A host nothing counts against any more.
        inner.hosts.retain(|_, h| Arc::strong_count(h) > 1);
    }

    fn cleanup_namespace(&self, ns: u64) {
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        // Namespace IDs are never reused, so anything aimed at this one is
        // dead weight from now on.
        inner.expectations.retain(|e| e.namespace != ns);
        inner.forwards.retain(|pf| pf.namespace != ns);
        inner.mappings.retain(|k, m| {
            if k.ns == ns {
                inner.reverse.remove(&NatRevKey {
                    proto: k.proto,
                    port: m.outside_port,
                });
                false
            } else {
                true
            }
        });
    }

    fn send_ns(&self, ns: u64, pkt: &Packet) {
        if ns == 0 {
            self.inside.deliver(pkt);
            return;
        }
        let side = self.ns_sides.lock().unwrap().get(&ns).cloned();
        if let Some(side) = side {
            side.deliver(pkt);
        }
    }

    // ---------- Outbound (inside -> outside) ----------

    fn handle_outbound(&self, ns: u64, pkt_in: &[u8]) {
        self.maybe_sweep();
        let owned;
        let (pkt, fmax): (&[u8], _) = if let Some(d) = self.defragger.lock().unwrap().clone() {
            match d.reassemble(pkt_in) {
                Some((v, fmax)) => {
                    owned = v;
                    (&owned, fmax)
                }
                None => return,
            }
        } else {
            (pkt_in, None)
        };

        let Some((pkt, ihl)) = ipv4_datagram(pkt) else {
            return;
        };

        // Local helper interception: packets to the NAT's own inside IP, and
        // multicast and broadcast (SSDP discovery goes to 239.255.255.250).
        // The latter are scoped to the inside network and are never
        // translated out.
        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let group =
            dst_ip.is_multicast() || dst_ip.is_broadcast() || self.is_inside_broadcast(dst_ip);
        let local = group || Some(dst_ip) == self.inside_addr();
        // Without reassembly each fragment is translated on its own. Only
        // the first carries the transport header; reading the others' data
        // as ports would translate garbage. Local helpers want whole
        // messages, so fragments for them are dropped.
        let (more, offset) = frag_info(pkt);
        let fragment = more || offset != 0;
        if local && (fragment || self.handle_local(ns, Packet::from_slice(pkt))) {
            return;
        }
        if group {
            return;
        }
        if local {
            // Addressed to the NAT itself and no helper wanted it. Translated,
            // it would leave upstream from the public address to a private
            // one, reaching nobody (or the wrong host). The NAT answers pings
            // like any host (RFC 1122 §3.2.2.6) and drops the rest.
            if pkt[9] == PROTO_ICMP
                && pkt.len() >= ihl + 8
                && pkt[ihl] == 8
                && let Some(reply) = echo_reply(pkt, ihl)
            {
                emit(&reply, fmax, |p| self.send_ns(ns, p));
            }
            return;
        }
        if !self.inside_source_ok(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])) {
            return;
        }

        // The NAT forwards what it translates, so, as any router must (RFC
        // 1812 §5.3.1), it spends a hop of it, and owes the sender a Time
        // Exceeded when none is left. A ping to the public address is the
        // NAT's own to answer (see `outbound_icmp`), so forwards nothing.
        // Hairpinned traffic spends its hop on the way back in.
        let own_ping =
            pkt[9] == PROTO_ICMP && pkt.get(ihl) == Some(&8) && Some(dst_ip) == self.outside_addr();
        if pkt[8] <= 1 && !own_ping {
            if let Some(me) = self.inside_addr() {
                self.time_exceeded(pkt, me, |p| self.send_ns(ns, p));
            }
            return;
        }

        // A later fragment has no ports to find a mapping by. It may only
        // follow a first fragment that was translated; otherwise any inside
        // host could send anything out from the public address, with no
        // mapping behind it. Like inbound, one that overtakes its first
        // fragment is held until that arrives.
        if offset != 0 {
            let key = out_frag_key(ns, pkt);
            let ok = self
                .out_frags
                .lock()
                .unwrap()
                .later(key, pkt, Instant::now());
            if ok.is_some() {
                self.outbound_later_fragment(pkt);
            }
            return;
        }
        let whole = !more;

        let proto = pkt[9];
        let translated = match proto {
            PROTO_TCP | PROTO_UDP if pkt.len() >= ihl + 4 => {
                self.outbound_tcpudp(ns, pkt, ihl, proto, whole, fmax)
            }
            PROTO_ICMP if pkt.len() >= ihl + 8 => self.outbound_icmp(ns, pkt, ihl, whole, fmax),
            _ => false,
        };
        if !whole && translated {
            let held =
                self.out_frags
                    .lock()
                    .unwrap()
                    .resolve(out_frag_key(ns, pkt), (), Instant::now());
            for f in held {
                self.outbound_later_fragment(&f);
            }
        }
    }

    /// A non-first fragment going out, after its first one: it only needs
    /// the source address that one got. (A fragment to the NAT's own address
    /// is hairpinned like the rest of its datagram.)
    fn outbound_later_fragment(&self, pkt: &[u8]) {
        let Some(outside_ip) = self.outside_addr() else {
            return;
        };
        let mut out = pkt.to_vec();
        let old: [u8; 4] = out[12..16].try_into().unwrap();
        out[12..16].copy_from_slice(&outside_ip.octets());
        update_ip_checksum(&mut out, old, outside_ip.octets());
        if out[16..20] == outside_ip.octets() {
            self.inbound(&out, None);
            return;
        }
        spend_hop(&mut out);
        self.outside.deliver(Packet::from_slice(&out));
    }

    /// Translate an outbound TCP/UDP datagram, or the first fragment of one
    /// (`whole` false). `fmax` is set if it was reassembled. Returns whether
    /// it went out through a mapping, which the rest of a fragmented
    /// datagram may then follow.
    fn outbound_tcpudp(
        &self,
        ns: u64,
        pkt: &[u8],
        ihl: usize,
        proto: u8,
        whole: bool,
        fmax: Option<FragMax>,
    ) -> bool {
        if !whole && !l4_header_in(pkt, ihl, proto) {
            return false;
        }
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let k = NatKey {
            ns,
            proto,
            ip: src_ip,
            port: src_port,
        };
        let (outside_port, mapping_key, tracked) = {
            let mut inner = self.inner.lock().unwrap();
            let m = match Self::get_or_create_mapping_locked(&mut inner, k) {
                Some(m) => m,
                None => return false,
            };
            let peer = SocketAddrV4::new(
                Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
                u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
            );
            let flags = tcp_flags(pkt, ihl, proto);
            m.peers.note(peer, true, flags, m.last_active);
            (m.outside_port, m.key, m.peers.contains(&peer))
        };

        let outside_ip = match self.outside_addr() {
            Some(a) => a,
            None => return false,
        };

        let mut out = pkt.to_vec();
        let old_src_ip: [u8; 4] = out[12..16].try_into().unwrap();
        let new_src_ip = outside_ip.octets();
        out[12..16].copy_from_slice(&new_src_ip);

        let old_port = u16::from_be_bytes([out[ihl], out[ihl + 1]]);
        out[ihl..ihl + 2].copy_from_slice(&outside_port.to_be_bytes());

        update_ip_checksum(&mut out, old_src_ip, new_src_ip);

        if proto == PROTO_TCP && out.len() >= ihl + 18 {
            update_l4_checksum(
                &mut out,
                ihl + 16,
                old_src_ip,
                new_src_ip,
                old_port,
                outside_port,
            );
        } else if proto == PROTO_UDP && out.len() >= ihl + 8 {
            let csum_off = ihl + 6;
            let cur = u16::from_be_bytes([out[csum_off], out[csum_off + 1]]);
            if cur != 0 {
                update_l4_checksum(
                    &mut out,
                    csum_off,
                    old_src_ip,
                    new_src_ip,
                    old_port,
                    outside_port,
                );
                udp_nonzero_checksum(&mut out, csum_off);
            }
        }

        let dst_port = u16::from_be_bytes([out[ihl + 2], out[ihl + 3]]);
        let nm = NatMapping {
            proto: mapping_key.proto,
            inside_ip: IpAddr::V4(mapping_key.ip),
            inside_port: mapping_key.port,
            outside_port,
            namespace: mapping_key.ns,
        };
        // ALGs rewrite whole messages; a fragment is only part of one.
        let before = tcp_payload_len(&out, ihl);
        let orig = untracked_original(&out, proto, whole, tracked);
        let mut out = if whole {
            self.helper_outbound(out, &nm, proto, dst_port)
        } else {
            out
        };
        if let Some(orig) = orig
            && tcp_payload_len(&out, ihl) != before
        {
            out = orig;
        }
        // A first fragment still carries the whole TCP header, so its
        // sequence numbers shift with the rest of the stream.
        if proto == PROTO_TCP {
            let peer =
                SocketAddrV4::new(Ipv4Addr::new(out[16], out[17], out[18], out[19]), dst_port);
            self.tcp_seq_fixup(mapping_key, peer, true, before, &mut out, ihl);
        }
        // Hairpinning (RFC 4787 REQ-9, RFC 5382 REQ-8): an inside host
        // reaching another one through the NAT's public address. The packet,
        // already carrying the sender's public source, turns around as if it
        // had arrived from outside, so the receiver sees that public address
        // too.
        if out[16..20] == outside_ip.octets() {
            self.inbound(&out, fmax);
            return true;
        }
        spend_hop(&mut out);
        emit(&out, fmax, |p| self.outside.deliver(p));
        true
    }

    /// Translate an outbound echo request, or the first fragment of one, or
    /// an ICMP error. Returns whether an echo request went out through a
    /// mapping, as [`outbound_tcpudp`](Self::outbound_tcpudp) does.
    fn outbound_icmp(
        &self,
        ns: u64,
        pkt: &[u8],
        ihl: usize,
        whole: bool,
        fmax: Option<FragMax>,
    ) -> bool {
        match pkt[ihl] {
            8 => {}
            // Errors are small; a fragmented one is not worth reassembling.
            3 | 11 | 12 if whole => {
                self.outbound_icmp_error(ns, pkt, ihl);
                return false;
            }
            _ => return false,
        }
        let Some(outside_ip) = self.outside_addr() else {
            return false;
        };
        // An echo request to the NAT's public address, the one TCP and UDP
        // are hairpinned on. Under NAPT no inside host owns it for ICMP (an
        // echo request names no port to forward by), so it is the NAT's own
        // address, and the NAT answers as any host must (RFC 1122
        // §3.2.2.6). Sent out, it would only reach the upstream, addressed
        // back to the NAT.
        if pkt[16..20] == outside_ip.octets() {
            if whole && let Some(reply) = echo_reply(pkt, ihl) {
                emit(&reply, fmax, |p| self.send_ns(ns, p));
            }
            return false;
        }
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let id = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
        let k = NatKey {
            ns,
            proto: PROTO_ICMP,
            ip: src_ip,
            port: id,
        };
        let outside_port = {
            let mut inner = self.inner.lock().unwrap();
            match Self::get_or_create_mapping_locked(&mut inner, k) {
                Some(m) => {
                    let peer =
                        SocketAddrV4::new(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]), 0);
                    m.peers.note(peer, true, None, m.last_active);
                    m.outside_port
                }
                None => return false,
            }
        };

        let mut out = pkt.to_vec();
        let old_src_ip: [u8; 4] = out[12..16].try_into().unwrap();
        let new_src_ip = outside_ip.octets();
        out[12..16].copy_from_slice(&new_src_ip);

        let old_id = u16::from_be_bytes([out[ihl + 4], out[ihl + 5]]);
        out[ihl + 4..ihl + 6].copy_from_slice(&outside_port.to_be_bytes());

        update_ip_checksum(&mut out, old_src_ip, new_src_ip);
        update_icmp_checksum(&mut out, ihl, old_id, outside_port);
        spend_hop(&mut out);

        emit(&out, fmax, |p| self.outside.deliver(p));
        true
    }

    /// Translate an ICMP error an inside host, or a router on the inside,
    /// sends about a packet that came in through this NAT (RFC 5508 §4.2):
    /// the outer source and the embedded packet's destination go back to
    /// the public endpoint, with every checksum that covers them patched.
    fn outbound_icmp_error(&self, ns: u64, pkt: &[u8], outer_ihl: usize) {
        let emb_off = outer_ihl + 8;
        if pkt.len() < emb_off + 20 {
            return;
        }
        // The outer checksum is recomputed below; check it first, so a
        // corrupted error is not passed on as a valid one.
        if checksum(&pkt[outer_ihl..]) != 0 {
            return;
        }
        let emb_ihl = (pkt[emb_off] & 0x0F) as usize * 4;
        if emb_ihl < 20 || pkt.len() < emb_off + emb_ihl + 8 {
            return;
        }
        let emb = &pkt[emb_off..];
        let emb_proto = emb[9];
        // Only TCP and UDP reach inside hosts from outside; echo requests
        // are answered by no one behind the NAT.
        if emb_proto != PROTO_TCP && emb_proto != PROTO_UDP {
            return;
        }
        let l4 = &emb[emb_ihl..];
        let remote_ip = Ipv4Addr::new(emb[12], emb[13], emb[14], emb[15]);
        let remote = SocketAddrV4::new(remote_ip, u16::from_be_bytes([l4[0], l4[1]]));
        // An error goes back to whoever sent the packet it quotes.
        if pkt[16..20] != remote_ip.octets() {
            return;
        }
        let k = NatKey {
            ns,
            proto: emb_proto,
            ip: Ipv4Addr::new(emb[16], emb[17], emb[18], emb[19]),
            port: u16::from_be_bytes([l4[2], l4[3]]),
        };
        // RFC 5508 REQ-4: only for a live mapping, and only about traffic
        // it actually carried from that remote; otherwise an inside host
        // could tear down any session through the NAT, its own or not.
        let outside_port = {
            let inner = self.inner.lock().unwrap();
            match inner.mappings.get(&k) {
                Some(m) if m.peers.contains(&remote) => m.outside_port,
                _ => return,
            }
        };
        let Some(outside_ip) = self.outside_addr() else {
            return;
        };
        let public = outside_ip.octets();

        let mut out = pkt.to_vec();
        let old_outer_src: [u8; 4] = out[12..16].try_into().unwrap();
        out[12..16].copy_from_slice(&public);
        update_ip_checksum(&mut out, old_outer_src, public);

        let old_dst = k.ip.octets();
        {
            let emb = &mut out[emb_off..];
            emb[16..20].copy_from_slice(&public);
            update_ip_checksum(emb, old_dst, public);
        }
        let l4_off = emb_off + emb_ihl;
        out[l4_off + 2..l4_off + 4].copy_from_slice(&outside_port.to_be_bytes());
        let csum_off = l4_off + if emb_proto == PROTO_TCP { 16 } else { 6 };
        let present = out.len() >= csum_off + 2;
        let unused = emb_proto == PROTO_UDP && present && out[csum_off..csum_off + 2] == [0, 0];
        if present && !unused {
            update_l4_checksum(&mut out, csum_off, old_dst, public, k.port, outside_port);
            if emb_proto == PROTO_UDP {
                udp_nonzero_checksum(&mut out, csum_off);
            }
        }

        out[outer_ihl + 2..outer_ihl + 4].copy_from_slice(&[0, 0]);
        let csum = checksum(&out[outer_ihl..]);
        out[outer_ihl + 2..outer_ihl + 4].copy_from_slice(&csum.to_be_bytes());

        // About hairpinned traffic: the remote is another inside host.
        if out[16..20] == public {
            self.inbound(&out, None);
            return;
        }
        spend_hop(&mut out);
        self.outside.deliver(Packet::from_slice(&out));
    }

    // ---------- Inbound (outside -> inside) ----------

    fn handle_inbound(&self, pkt_in: &[u8]) {
        self.maybe_sweep();
        let owned;
        let (pkt, fmax): (&[u8], _) = if let Some(d) = self.defragger.lock().unwrap().clone() {
            match d.reassemble(pkt_in) {
                Some((v, fmax)) => {
                    owned = v;
                    (&owned, fmax)
                }
                None => return,
            }
        } else {
            (pkt_in, None)
        };

        self.inbound(pkt, fmax);
    }

    /// Translate one inbound datagram (or fragment of one). `fmax` is set if
    /// it was reassembled.
    fn inbound(&self, pkt: &[u8], fmax: Option<FragMax>) {
        let Some((pkt, ihl)) = ipv4_datagram(pkt) else {
            return;
        };
        // Mappings are found by port alone, so only traffic addressed to
        // the NAT itself may use them; anything else on the outside link
        // (another host's, or broadcast) is not for the inside to see.
        // Hairpinned packets carry the public address too.
        if self
            .outside_addr()
            .is_none_or(|a| pkt[16..20] != a.octets())
        {
            return;
        }
        let (more, offset) = frag_info(pkt);
        if offset != 0 {
            // Out of hops, it goes no further; only the first fragment of a
            // datagram is answered (RFC 1812 §4.3.2.7).
            if pkt[8] <= 1 {
                return;
            }
            let key = frag_key(pkt);
            let target = self.frags.lock().unwrap().later(key, pkt, Instant::now());
            if let Some(target) = target {
                self.inbound_later_fragment(pkt, target);
            }
            return;
        }
        let whole = !more;
        let proto = pkt[9];
        let target = match proto {
            PROTO_TCP | PROTO_UDP if pkt.len() >= ihl + 4 => {
                self.inbound_tcpudp(pkt, ihl, proto, whole, fmax)
            }
            PROTO_ICMP if pkt.len() >= ihl + 8 => self.inbound_icmp(pkt, ihl, whole, fmax),
            _ => None,
        };
        if !whole && let Some(target) = target {
            let held = self
                .frags
                .lock()
                .unwrap()
                .resolve(frag_key(pkt), target, Instant::now());
            for f in held {
                self.inbound_later_fragment(&f, target);
            }
        }
    }

    /// A non-first inbound fragment, sent where its first fragment went.
    fn inbound_later_fragment(&self, pkt: &[u8], (ns, inside_ip): (u64, Ipv4Addr)) {
        let mut out = pkt.to_vec();
        let old: [u8; 4] = out[16..20].try_into().unwrap();
        out[16..20].copy_from_slice(&inside_ip.octets());
        update_ip_checksum(&mut out, old, inside_ip.octets());
        spend_hop(&mut out);
        self.send_ns(ns, Packet::from_slice(&out));
    }

    /// Translate an inbound TCP/UDP datagram, or the first fragment of one
    /// (`whole` false). Returns where it went.
    fn inbound_tcpudp(
        &self,
        pkt: &[u8],
        ihl: usize,
        proto: u8,
        whole: bool,
        fmax: Option<FragMax>,
    ) -> Option<(u64, Ipv4Addr)> {
        if !whole && !l4_header_in(pkt, ihl, proto) {
            return None;
        }
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);

        let rk = NatRevKey {
            proto,
            port: dst_port,
        };
        // Out of hops: if the NAT would have forwarded it, the sender is
        // owed a Time Exceeded, as from any router; otherwise the packet
        // was for the NAT itself, which has nothing to say.
        if pkt[8] <= 1 {
            let remote = SocketAddrV4::new(src_ip, src_port);
            if Self::would_translate_locked(&self.inner.lock().unwrap(), rk, remote) {
                self.time_exceeded_outside(pkt);
            }
            return None;
        }
        let now = Instant::now();
        let (mapping_key, outside_port, tracked) = {
            let mut inner = self.inner.lock().unwrap();
            // Existing mapping?
            let k = if let Some(k) = inner.reverse.get(&rk).copied() {
                k
            } else if let Some(e) =
                Self::match_expectation_locked(&mut inner, proto, dst_port, src_ip, src_port)
            {
                let k = NatKey {
                    ns: e.namespace,
                    proto,
                    ip: e.inside_ip,
                    port: e.inside_port,
                };
                Self::expire_mapping_locked(&mut inner, k, now);
                if !Self::install_mapping_locked(&mut inner, k, rk, false) {
                    return None;
                }
                // Made for one remote: only its traffic keeps the mapping
                // alive, as on a mapping the host opened itself.
                if !e.remote_ip.is_unspecified()
                    && let Some(m) = inner.mappings.get_mut(&k)
                {
                    m.open = false;
                    let peer = SocketAddrV4::new(src_ip, src_port);
                    m.peers.note(peer, false, tcp_flags(pkt, ihl, proto), now);
                }
                k
            } else {
                let pf = Self::match_forward(&mut inner, proto, dst_port)?;
                let k = NatKey {
                    ns: pf.namespace,
                    proto,
                    ip: pf.inside_ip,
                    port: pf.inside_port,
                };
                Self::install_mapping_locked(&mut inner, k, rk, true);
                k
            };
            let peer = SocketAddrV4::new(src_ip, src_port);
            let tracked = inner
                .mappings
                .get_mut(&k)
                .is_some_and(|m| m.note_inbound(peer, tcp_flags(pkt, ihl, proto), now));
            (k, dst_port, tracked)
        };

        let mut out = pkt.to_vec();
        spend_hop(&mut out);
        let old_dst_ip: [u8; 4] = out[16..20].try_into().unwrap();
        let new_dst_ip = mapping_key.ip.octets();
        out[16..20].copy_from_slice(&new_dst_ip);

        let old_port = u16::from_be_bytes([out[ihl + 2], out[ihl + 3]]);
        out[ihl + 2..ihl + 4].copy_from_slice(&mapping_key.port.to_be_bytes());

        update_ip_checksum(&mut out, old_dst_ip, new_dst_ip);

        if proto == PROTO_TCP && out.len() >= ihl + 18 {
            update_l4_checksum(
                &mut out,
                ihl + 16,
                old_dst_ip,
                new_dst_ip,
                old_port,
                mapping_key.port,
            );
        } else if proto == PROTO_UDP && out.len() >= ihl + 8 {
            let csum_off = ihl + 6;
            let cur = u16::from_be_bytes([out[csum_off], out[csum_off + 1]]);
            if cur != 0 {
                update_l4_checksum(
                    &mut out,
                    csum_off,
                    old_dst_ip,
                    new_dst_ip,
                    old_port,
                    mapping_key.port,
                );
                udp_nonzero_checksum(&mut out, csum_off);
            }
        }

        // Helpers are chosen by the service port, which on a reply to an
        // outbound connection is the remote's source port.
        let nm = NatMapping {
            proto: mapping_key.proto,
            inside_ip: IpAddr::V4(mapping_key.ip),
            inside_port: mapping_key.port,
            outside_port,
            namespace: mapping_key.ns,
        };
        let before = tcp_payload_len(&out, ihl);
        let orig = untracked_original(&out, proto, whole, tracked);
        let mut out = if whole {
            self.helper_inbound(out, &nm, proto, src_port)
        } else {
            out
        };
        if let Some(orig) = orig
            && tcp_payload_len(&out, ihl) != before
        {
            out = orig;
        }
        if proto == PROTO_TCP {
            let peer = SocketAddrV4::new(src_ip, src_port);
            self.tcp_seq_fixup(mapping_key, peer, false, before, &mut out, ihl);
        }
        emit(&out, fmax, |p| self.send_ns(mapping_key.ns, p));
        Some((mapping_key.ns, mapping_key.ip))
    }

    /// Translate an inbound ICMP message, or the first fragment of an echo
    /// reply (`whole` false). Returns where it went.
    fn inbound_icmp(
        &self,
        pkt: &[u8],
        ihl: usize,
        whole: bool,
        fmax: Option<FragMax>,
    ) -> Option<(u64, Ipv4Addr)> {
        let icmp_type = pkt[ihl];
        match icmp_type {
            0 => {
                let id = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
                let rk = NatRevKey {
                    proto: PROTO_ICMP,
                    port: id,
                };
                let mapping_key = {
                    let mut inner = self.inner.lock().unwrap();
                    let k = inner.reverse.get(&rk).copied()?;
                    if pkt[8] <= 1 {
                        drop(inner);
                        self.time_exceeded_outside(pkt);
                        return None;
                    }
                    if let Some(m) = inner.mappings.get_mut(&k) {
                        let peer =
                            SocketAddrV4::new(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]), 0);
                        m.note_inbound(peer, None, Instant::now());
                    }
                    k
                };
                let mut out = pkt.to_vec();
                spend_hop(&mut out);
                let old_dst_ip: [u8; 4] = out[16..20].try_into().unwrap();
                let new_dst_ip = mapping_key.ip.octets();
                out[16..20].copy_from_slice(&new_dst_ip);

                let old_id = u16::from_be_bytes([out[ihl + 4], out[ihl + 5]]);
                out[ihl + 4..ihl + 6].copy_from_slice(&mapping_key.port.to_be_bytes());
                update_ip_checksum(&mut out, old_dst_ip, new_dst_ip);
                update_icmp_checksum(&mut out, ihl, old_id, mapping_key.port);
                emit(&out, fmax, |p| self.send_ns(mapping_key.ns, p));
                Some((mapping_key.ns, mapping_key.ip))
            }
            // Errors are small; a fragmented one is not worth reassembling.
            3 | 11 | 12 if whole => {
                self.inbound_icmp_error(pkt, ihl, fmax);
                None
            }
            // A ping to the public address is for the NAT: no inside host
            // owns that address for ICMP (a request names no port to
            // forward by), and every host answers pings (RFC 1122
            // §3.2.2.6). Replies are rate-limited, so the NAT cannot be
            // made to spend unbounded effort on them.
            8 if whole => {
                if let Some(reply) = echo_reply(pkt, ihl)
                    && self.echo_limit.allow()
                {
                    emit(&reply, fmax, |p| self.outside.deliver(p));
                }
                None
            }
            _ => None,
        }
    }

    /// Translate an ICMP error about a packet this NAT sent out (RFC 5508
    /// §7): the outer destination and the embedded packet's source go back to
    /// the inside endpoint, with every checksum that covers them patched.
    fn inbound_icmp_error(&self, pkt: &[u8], outer_ihl: usize, fmax: Option<FragMax>) {
        let emb_off = outer_ihl + 8;
        // Out of hops it goes no further, and no error answers an error.
        if pkt.len() < emb_off + 20 || pkt[8] <= 1 {
            return;
        }
        // The outer checksum is recomputed below; check it first, so a
        // corrupted error is not passed on as a valid one.
        if checksum(&pkt[outer_ihl..]) != 0 {
            return;
        }
        let emb_ihl = (pkt[emb_off] & 0x0F) as usize * 4;
        if emb_ihl < 20 || pkt.len() < emb_off + emb_ihl + 8 {
            return;
        }
        let emb = &pkt[emb_off..];
        let emb_proto = emb[9];
        let l4 = &emb[emb_ihl..];
        let (emb_port, remote) = match emb_proto {
            PROTO_TCP | PROTO_UDP => (
                u16::from_be_bytes([l4[0], l4[1]]),
                SocketAddrV4::new(
                    Ipv4Addr::new(emb[16], emb[17], emb[18], emb[19]),
                    u16::from_be_bytes([l4[2], l4[3]]),
                ),
            ),
            // Only an echo request can have left through this NAT.
            PROTO_ICMP if l4[0] == 8 => (
                u16::from_be_bytes([l4[4], l4[5]]),
                SocketAddrV4::new(Ipv4Addr::new(emb[16], emb[17], emb[18], emb[19]), 0),
            ),
            _ => return,
        };
        if Some(Ipv4Addr::new(emb[12], emb[13], emb[14], emb[15])) != self.outside_addr() {
            return;
        }
        let rk = NatRevKey {
            proto: emb_proto,
            port: emb_port,
        };
        let mapping_key = {
            let inner = self.inner.lock().unwrap();
            let k = match inner.reverse.get(&rk).copied() {
                Some(k) => k,
                None => return,
            };
            // The error must be about traffic this mapping actually sent;
            // anyone can otherwise forge errors that tear down or confuse
            // an inside host's sessions.
            match inner.mappings.get(&k) {
                Some(m) if m.peers.contains(&remote) => {}
                _ => return,
            }
            k
        };

        let mut out = pkt.to_vec();
        spend_hop(&mut out);
        let old_outer_dst: [u8; 4] = out[16..20].try_into().unwrap();
        let inside_ip = mapping_key.ip.octets();
        out[16..20].copy_from_slice(&inside_ip);
        update_ip_checksum(&mut out, old_outer_dst, inside_ip);

        // Embedded packet: source back to the inside endpoint, fixing its IP
        // header checksum and, where the quoted bytes include it, its
        // transport checksum, so the inside stack can match the error to
        // its own packet.
        let old_src: [u8; 4] = out[emb_off + 12..emb_off + 16].try_into().unwrap();
        {
            let emb = &mut out[emb_off..];
            emb[12..16].copy_from_slice(&inside_ip);
            update_ip_checksum(emb, old_src, inside_ip);
        }
        let l4_off = emb_off + emb_ihl;
        let new_port = mapping_key.port;
        match emb_proto {
            PROTO_TCP | PROTO_UDP => {
                out[l4_off..l4_off + 2].copy_from_slice(&new_port.to_be_bytes());
                let csum_off = l4_off + if emb_proto == PROTO_TCP { 16 } else { 6 };
                let present = out.len() >= csum_off + 2;
                let unused =
                    emb_proto == PROTO_UDP && present && out[csum_off..csum_off + 2] == [0, 0];
                if present && !unused {
                    update_l4_checksum(&mut out, csum_off, old_src, inside_ip, emb_port, new_port);
                    if emb_proto == PROTO_UDP {
                        udp_nonzero_checksum(&mut out, csum_off);
                    }
                }
            }
            _ => {
                out[l4_off + 4..l4_off + 6].copy_from_slice(&new_port.to_be_bytes());
                update_icmp_checksum(&mut out, l4_off, emb_port, new_port);
            }
        }

        out[outer_ihl + 2..outer_ihl + 4].copy_from_slice(&[0, 0]);
        let csum = checksum(&out[outer_ihl..]);
        out[outer_ihl + 2..outer_ihl + 4].copy_from_slice(&csum.to_be_bytes());

        emit(&out, fmax, |p| self.send_ns(mapping_key.ns, p));
    }
}

impl L3Connector for Nat {
    fn connect_l3(&self, dev: Arc<dyn L3Device>) -> Result<crate::Cleanup> {
        let ns = self.ns_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let side = Arc::new(NatNsSide::new(
            ns,
            self.inside.addr(),
            self.self_ref.clone(),
        ));

        // Bidirectional wire-up.
        connect_l3(side.clone() as Arc<dyn L3Device>, dev);

        self.ns_sides.lock().unwrap().insert(ns, side);

        let self_ref = self.self_ref.clone();
        Ok(Box::new(move || -> Result<()> {
            if let Some(nat) = self_ref.upgrade() {
                nat.ns_sides.lock().unwrap().remove(&ns);
                nat.cleanup_namespace(ns);
            }
            Ok(())
        }))
    }
}

// L3Device on the Nat itself = outside-facing (matches "the NAT is the
// upstream edge" intuition; callers can also grab inside()/outside() handles).
impl L3Device for Nat {
    fn set_handler(&self, h: L3Handler) {
        self.outside.set_handler(h);
    }
    fn send(&self, p: &Packet) -> Result<()> {
        self.outside.send(p)
    }
    fn addr(&self) -> IpPrefix {
        self.outside.addr()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        self.outside.set_addr(p)
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

// ===== NatSide =====

pub(crate) struct NatSide {
    is_inside: bool,
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
    parent: Weak<Nat>,
}

impl NatSide {
    fn new(is_inside: bool, addr: IpPrefix, parent: Weak<Nat>) -> NatSide {
        NatSide {
            is_inside,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            parent,
        }
    }

    /// Deliver a packet to whoever is listening on this side.
    fn deliver(&self, pkt: &Packet) {
        let h = self.handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(pkt);
        }
    }
}

impl L3Device for NatSide {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }

    fn send(&self, packet: &Packet) -> Result<()> {
        let bytes = packet.as_bytes();
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return Ok(());
        }
        if let Some(nat) = self.parent.upgrade() {
            if self.is_inside {
                nat.handle_outbound(0, bytes);
            } else {
                nat.handle_inbound(bytes);
            }
        }
        Ok(())
    }

    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = p;
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

// ===== Namespace-isolated inside side =====

struct NatNsSide {
    ns: u64,
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
    parent: Weak<Nat>,
}

impl NatNsSide {
    fn new(ns: u64, addr: IpPrefix, parent: Weak<Nat>) -> NatNsSide {
        NatNsSide {
            ns,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            parent,
        }
    }
    fn deliver(&self, pkt: &Packet) {
        let h = self.handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(pkt);
        }
    }
}

impl L3Device for NatNsSide {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, packet: &Packet) -> Result<()> {
        let bytes = packet.as_bytes();
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return Ok(());
        }
        if let Some(nat) = self.parent.upgrade() {
            nat.handle_outbound(self.ns, bytes);
        }
        Ok(())
    }
    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = p;
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Hand a translated datagram to `send`, cut back into fragments no larger
/// than the ones it was reassembled from (`fmax`), since the path it came
/// by could not carry it whole.
fn emit(out: &[u8], fmax: Option<FragMax>, send: impl Fn(&Packet)) {
    match fmax.and_then(|m| m.refragment(out)) {
        Some(parts) => parts.iter().for_each(|p| send(Packet::from_slice(p))),
        None => send(Packet::from_slice(out)),
    }
}

// ===== Incremental checksum helpers =====
// RFC 1624: c' = ~(~c + ~m + m'), folded.

fn checksum_adjust(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum: u32 = (!old_csum) as u32 + (!old_val) as u32 + new_val as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn update_ip_checksum(pkt: &mut [u8], old_ip: [u8; 4], new_ip: [u8; 4]) {
    let mut csum = u16::from_be_bytes([pkt[10], pkt[11]]);
    csum = checksum_adjust(
        csum,
        u16::from_be_bytes([old_ip[0], old_ip[1]]),
        u16::from_be_bytes([new_ip[0], new_ip[1]]),
    );
    csum = checksum_adjust(
        csum,
        u16::from_be_bytes([old_ip[2], old_ip[3]]),
        u16::from_be_bytes([new_ip[2], new_ip[3]]),
    );
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
}

pub(crate) fn update_l4_checksum(
    pkt: &mut [u8],
    csum_off: usize,
    old_ip: [u8; 4],
    new_ip: [u8; 4],
    old_port: u16,
    new_port: u16,
) {
    let mut csum = u16::from_be_bytes([pkt[csum_off], pkt[csum_off + 1]]);
    csum = checksum_adjust(
        csum,
        u16::from_be_bytes([old_ip[0], old_ip[1]]),
        u16::from_be_bytes([new_ip[0], new_ip[1]]),
    );
    csum = checksum_adjust(
        csum,
        u16::from_be_bytes([old_ip[2], old_ip[3]]),
        u16::from_be_bytes([new_ip[2], new_ip[3]]),
    );
    csum = checksum_adjust(csum, old_port, new_port);
    pkt[csum_off..csum_off + 2].copy_from_slice(&csum.to_be_bytes());
}

/// Take one off an IPv4 packet's TTL, which the caller has checked is more
/// than one, patching the header checksum to match (RFC 1624).
fn spend_hop(pkt: &mut [u8]) {
    let old = u16::from_be_bytes([pkt[8], pkt[9]]);
    pkt[8] = pkt[8].saturating_sub(1);
    let new = u16::from_be_bytes([pkt[8], pkt[9]]);
    let csum = checksum_adjust(u16::from_be_bytes([pkt[10], pkt[11]]), old, new);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
}

/// Whether expectation `e` is live and admits a connection from
/// `remote_ip:remote_port` to outside port `outside_port`.
fn expectation_matches(
    e: &Expectation,
    now: Instant,
    proto: u8,
    outside_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> bool {
    now <= e.expires
        && e.proto == proto
        && e.outside_port == outside_port
        && (e.remote_ip.is_unspecified() || e.remote_ip == remote_ip)
        && (e.remote_port == 0 || e.remote_port == remote_port)
}

/// The More Fragments flag and fragment offset (in bytes) of an IPv4 packet.
pub(crate) fn frag_info(pkt: &[u8]) -> (bool, usize) {
    let v = u16::from_be_bytes([pkt[6], pkt[7]]);
    (v & 0x2000 != 0, (v & 0x1FFF) as usize * 8)
}

/// What the fragments of one outbound datagram share, before translation
/// (RFC 791): inside namespace, source, destination, IP ID and protocol.
type OutFragKey = (u64, Ipv4Addr, Ipv4Addr, u16, u8);

fn out_frag_key(ns: u64, pkt: &[u8]) -> OutFragKey {
    (
        ns,
        Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        u16::from_be_bytes([pkt[4], pkt[5]]),
        pkt[9],
    )
}

/// What the fragments of one inbound datagram share: source, IP ID and
/// protocol (the destination is always the NAT itself).
fn frag_key(pkt: &[u8]) -> (Ipv4Addr, u16, u8) {
    (
        Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        u16::from_be_bytes([pkt[4], pkt[5]]),
        pkt[9],
    )
}

/// Validate an IPv4 header and return the datagram, cut to its total length
/// (anything after it is link-layer padding, which no checksum covers),
/// along with its header length.
fn ipv4_datagram(pkt: &[u8]) -> Option<(&[u8], usize)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if ihl < 20 || total < ihl || pkt.len() < total {
        return None;
    }
    Some((&pkt[..total], ihl))
}

/// A copy of a TCP datagram to fall back on if an ALG changes its payload
/// length on a connection the mapping could not track (its table of
/// remotes being full): the sequence adjustment every later segment needs
/// would have nowhere to be recorded, and the two ends would fall out of
/// step. Better the ALG's rewrite be lost than the connection.
fn untracked_original(pkt: &[u8], proto: u8, whole: bool, tracked: bool) -> Option<Vec<u8>> {
    (proto == PROTO_TCP && whole && !tracked).then(|| pkt.to_vec())
}

/// The Echo Reply to an ICMP Echo Request `pkt`, from its destination back
/// to its source (RFC 792), or `None` if the request is corrupt. Options are
/// left out: the reply's route is not the request's.
fn echo_reply(pkt: &[u8], ihl: usize) -> Option<Vec<u8>> {
    let icmp = &pkt[ihl..];
    if checksum(icmp) != 0 {
        return None;
    }
    let mut r = vec![0u8; 20];
    r[0] = 0x45;
    r[1] = pkt[1];
    r[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    r[8] = 64;
    r[9] = PROTO_ICMP;
    r[12..16].copy_from_slice(&pkt[16..20]);
    r[16..20].copy_from_slice(&pkt[12..16]);
    let ic = checksum(&r);
    r[10..12].copy_from_slice(&ic.to_be_bytes());
    let at = r.len();
    r.extend_from_slice(icmp);
    r[at] = 0;
    r[at + 2..at + 4].copy_from_slice(&[0, 0]);
    let cs = checksum(&r[at..]);
    r[at + 2..at + 4].copy_from_slice(&cs.to_be_bytes());
    Some(r)
}

/// Whether a first fragment holds its whole transport header. The NAT
/// patches the ports and checksum there for the whole datagram, and for TCP
/// the sequence numbers, acknowledgement and SACK blocks when an ALG has
/// resized the stream; RFC 6146 §3.4 lets a translator insist on the header
/// being in the first fragment, and one split across fragments is the tiny
/// fragment attack of RFC 1858.
fn l4_header_in(pkt: &[u8], ihl: usize, proto: u8) -> bool {
    if proto != PROTO_TCP {
        return pkt.len() >= ihl + 8;
    }
    let Some(&b) = pkt.get(ihl + 12) else {
        return false;
    };
    let doff = (b >> 4) as usize * 4;
    doff >= 20 && pkt.len() >= ihl + doff
}

/// Length of a TCP segment's payload, `None` if the header is malformed.
fn tcp_payload_len(pkt: &[u8], ihl: usize) -> Option<usize> {
    let doff = (*pkt.get(ihl + 12)? >> 4) as usize * 4;
    if doff < 20 {
        return None;
    }
    pkt.len().checked_sub(ihl + doff)
}

/// Overwrite `new.len()` bytes at `off` inside the TCP segment of `pkt` and
/// patch its checksum to match.
fn patch_tcp(pkt: &mut [u8], ihl: usize, off: usize, new: &[u8]) {
    // The checksum runs over 16-bit words counted from the TCP header,
    // which starts at an even offset, so widen the patch to even bounds.
    let start = off & !1;
    let end = (off + new.len() + 1) & !1;
    let old = pkt[start..end].to_vec();
    pkt[off..off + new.len()].copy_from_slice(new);
    let csum = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);
    let csum = incremental_update(csum, &old, &pkt[start..end]);
    pkt[ihl + 16..ihl + 18].copy_from_slice(&csum.to_be_bytes());
}

/// Apply sequence corrections to a TCP segment: `this` to its sequence
/// number, `other` (the opposite direction's) to its acknowledgement and
/// SACK blocks (RFC 2018), which count the other side's bytes.
fn adjust_tcp_seq(pkt: &mut [u8], ihl: usize, this: SeqAdj, other: SeqAdj) {
    let read = |pkt: &[u8], at: usize| {
        u32::from_be_bytes([pkt[at], pkt[at + 1], pkt[at + 2], pkt[at + 3]])
    };
    let seq = read(pkt, ihl + 4);
    patch_tcp(pkt, ihl, ihl + 4, &this.seq(seq).to_be_bytes());
    if pkt[ihl + 13] & 0x10 != 0 {
        let ack = read(pkt, ihl + 8);
        patch_tcp(pkt, ihl, ihl + 8, &other.ack(ack).to_be_bytes());
    }
    let end = ihl + (pkt[ihl + 12] >> 4) as usize * 4;
    let mut i = ihl + 20;
    while i < end {
        match pkt[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = pkt.get(i + 1) else { break };
                let len = len as usize;
                if len < 2 || i + len > end {
                    break;
                }
                if kind == 5 {
                    let mut edge = i + 2;
                    while edge + 4 <= i + len {
                        let v = read(pkt, edge);
                        patch_tcp(pkt, ihl, edge, &other.ack(v).to_be_bytes());
                        edge += 4;
                    }
                }
                i += len;
            }
        }
    }
}

/// The TCP flags byte of a TCP packet, `None` for anything else (or a
/// header too short to carry it).
fn tcp_flags(pkt: &[u8], ihl: usize, proto: u8) -> Option<u8> {
    (proto == PROTO_TCP)
        .then(|| pkt.get(ihl + 13).copied())
        .flatten()
}

/// RFC 768: a UDP checksum that computes to zero is sent as all ones, since a
/// zero field means the sender did not compute one. An incremental update can
/// land on zero like any other value, and must not silently switch the
/// receiver's checksum verification off.
fn udp_nonzero_checksum(pkt: &mut [u8], csum_off: usize) {
    if pkt[csum_off..csum_off + 2] == [0, 0] {
        pkt[csum_off..csum_off + 2].copy_from_slice(&[0xFF, 0xFF]);
    }
}

fn update_icmp_checksum(pkt: &mut [u8], ihl: usize, old_id: u16, new_id: u16) {
    let csum_off = ihl + 2;
    let csum = u16::from_be_bytes([pkt[csum_off], pkt[csum_off + 1]]);
    let csum = checksum_adjust(csum, old_id, new_id);
    pkt[csum_off..csum_off + 2].copy_from_slice(&csum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::track::UDP_TIMEOUT;
    use crate::{IpPrefix, L3Device, Packet};
    use std::sync::Mutex as StdMutex;

    fn pfx(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    /// Build a minimal IPv4+TCP packet from src:sport to dst:dport.
    fn build_tcp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, flags: u8) -> Vec<u8> {
        let total = 20 + 20; // IP + minimal TCP header
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ip_csum = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        // seq, ack are zero, data offset = 5 (5 32-bit words)
        p[32] = 0x50;
        p[33] = flags;
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        p
    }

    fn build_udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ip_csum = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        // Optional UDP checksum left zero for simplicity.
        p
    }

    fn build_icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
        let total = 20 + 8;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_ICMP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ip_csum = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        // ICMP echo request: type 8, code 0
        p[20] = 8;
        p[22..24].copy_from_slice(&[0, 0]);
        p[24..26].copy_from_slice(&id.to_be_bytes());
        p[26..28].copy_from_slice(&seq.to_be_bytes());
        let csum = checksum(&p[20..]);
        p[22..24].copy_from_slice(&csum.to_be_bytes());
        p
    }

    /// Set up a NAT and capture every packet that leaves either side.
    fn setup() -> (
        Arc<Nat>,
        Arc<StdMutex<Vec<Vec<u8>>>>,
        Arc<StdMutex<Vec<Vec<u8>>>>,
    ) {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let inside_out = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let outside_out = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));

        let i = inside_out.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            i.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let o = outside_out.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            o.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        (nat, inside_out, outside_out)
    }

    #[test]
    fn outbound_tcp_rewrites_src() {
        let (nat, _i, o) = setup();
        let p = build_tcp(
            Ipv4Addr::new(10, 0, 0, 5),
            33333,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            0x02, // SYN
        );
        nat.inside().send(Packet::from_slice(&p)).unwrap();

        let outbound = o.lock().unwrap();
        assert_eq!(outbound.len(), 1);
        let out = &outbound[0];
        // Source should be rewritten to outside addr.
        assert_eq!(&out[12..16], &[203, 0, 113, 1]);
        // Source port should be ≥ NAT_PORT_MIN.
        let new_sport = u16::from_be_bytes([out[20], out[21]]);
        assert!(new_sport >= NAT_PORT_MIN);
    }

    #[test]
    fn round_trip_tcp_inbound_to_inside() {
        let (nat, i, o) = setup();
        let p = build_tcp(
            Ipv4Addr::new(10, 0, 0, 5),
            44444,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            0x02,
        );
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let outbound = o.lock().unwrap();
        let outpkt = &outbound[0];
        let mapped_port = u16::from_be_bytes([outpkt[20], outpkt[21]]);
        drop(outbound);

        // Simulate a reply from 8.8.8.8:80 -> outside_ip:mapped_port.
        let reply = build_tcp(
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            Ipv4Addr::new(203, 0, 113, 1),
            mapped_port,
            0x12, // SYN|ACK
        );
        nat.outside().send(Packet::from_slice(&reply)).unwrap();

        let inbound = i.lock().unwrap();
        assert_eq!(inbound.len(), 1);
        let r = &inbound[0];
        // Destination rewritten back to 10.0.0.5.
        assert_eq!(&r[16..20], &[10, 0, 0, 5]);
        let new_dport = u16::from_be_bytes([r[22], r[23]]);
        assert_eq!(new_dport, 44444);
    }

    #[test]
    fn outbound_udp_rewrites_src_no_csum() {
        let (nat, _i, o) = setup();
        let p = build_udp(
            Ipv4Addr::new(10, 0, 0, 5),
            55555,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            &[0xde, 0xad, 0xbe, 0xef],
        );
        nat.inside().send(Packet::from_slice(&p)).unwrap();

        let outbound = o.lock().unwrap();
        assert_eq!(outbound.len(), 1);
        let out = &outbound[0];
        assert_eq!(&out[12..16], &[203, 0, 113, 1]);
        // UDP checksum was zero on input; should remain zero.
        let cs = u16::from_be_bytes([out[26], out[27]]);
        assert_eq!(cs, 0);
    }

    #[test]
    fn icmp_echo_round_trip() {
        let (nat, i, o) = setup();
        let p = build_icmp_echo(
            Ipv4Addr::new(10, 0, 0, 7),
            Ipv4Addr::new(1, 1, 1, 1),
            0xAA,
            1,
        );
        nat.inside().send(Packet::from_slice(&p)).unwrap();

        let outbound = o.lock().unwrap();
        assert_eq!(outbound.len(), 1);
        let out = &outbound[0];
        assert_eq!(&out[12..16], &[203, 0, 113, 1]);
        let mapped_id = u16::from_be_bytes([out[24], out[25]]);
        drop(outbound);

        // Reply (type 0) coming in.
        let mut reply = vec![0u8; 28];
        reply[0] = 0x45;
        reply[2..4].copy_from_slice(&28u16.to_be_bytes());
        reply[8] = 64;
        reply[9] = PROTO_ICMP;
        reply[12..16].copy_from_slice(&[1, 1, 1, 1]);
        reply[16..20].copy_from_slice(&[203, 0, 113, 1]);
        let ic = checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&ic.to_be_bytes());
        reply[20] = 0; // echo reply
        reply[24..26].copy_from_slice(&mapped_id.to_be_bytes());
        reply[26..28].copy_from_slice(&1u16.to_be_bytes());
        let cs = checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&cs.to_be_bytes());
        nat.outside().send(Packet::from_slice(&reply)).unwrap();

        let inbound = i.lock().unwrap();
        assert_eq!(inbound.len(), 1);
        assert_eq!(&inbound[0][16..20], &[10, 0, 0, 7]);
        let id = u16::from_be_bytes([inbound[0][24], inbound[0][25]]);
        assert_eq!(id, 0xAA);
    }

    #[test]
    fn port_forward_inbound_creates_mapping() {
        let (nat, i, _o) = setup();
        nat.add_port_forward(
            PortForward::new(PROTO_TCP, 8080, Ipv4Addr::new(10, 0, 0, 50), 80)
                .description("webserver"),
        )
        .unwrap();

        let p = build_tcp(
            Ipv4Addr::new(198, 51, 100, 5),
            12345,
            Ipv4Addr::new(203, 0, 113, 1),
            8080,
            0x02,
        );
        nat.outside().send(Packet::from_slice(&p)).unwrap();

        let inbound = i.lock().unwrap();
        assert_eq!(inbound.len(), 1);
        let r = &inbound[0];
        assert_eq!(&r[16..20], &[10, 0, 0, 50]);
        let dport = u16::from_be_bytes([r[22], r[23]]);
        assert_eq!(dport, 80);
    }

    #[test]
    fn tuple_key_reuses_mapping() {
        let (nat, _i, o) = setup();
        let p1 = build_tcp(
            Ipv4Addr::new(10, 0, 0, 5),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            443,
            0x02,
        );
        let p2 = build_tcp(
            Ipv4Addr::new(10, 0, 0, 5),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            443,
            0x10, // ACK
        );
        nat.inside().send(Packet::from_slice(&p1)).unwrap();
        nat.inside().send(Packet::from_slice(&p2)).unwrap();

        let outbound = o.lock().unwrap();
        assert_eq!(outbound.len(), 2);
        let p1 = u16::from_be_bytes([outbound[0][20], outbound[0][21]]);
        let p2 = u16::from_be_bytes([outbound[1][20], outbound[1][21]]);
        assert_eq!(p1, p2);
    }

    #[test]
    fn alloc_port_in_range() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        for i in 0..16 {
            let port = nat
                .create_mapping(PROTO_TCP, Ipv4Addr::new(10, 0, 0, 2 + i), 1234)
                .unwrap();
            // The first keeps its port; the others get one from the pool,
            // as even.
            if i == 0 {
                assert_eq!(port, 1234);
            } else {
                assert!((NAT_PORT_MIN..=NAT_PORT_MAX).contains(&port));
                assert_eq!(port % 2, 0);
            }
        }
    }

    /// Records which packets a helper was asked to process.
    #[derive(Default)]
    struct Recorder {
        outbound: StdMutex<Vec<u16>>,
        inbound: StdMutex<Vec<u16>>,
    }

    impl Helper for Recorder {
        fn name(&self) -> &str {
            "recorder"
        }
    }

    impl PacketHelper for Recorder {
        fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
            proto == PROTO_TCP && dst_port == 21
        }
        fn process_outbound(&self, _nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
            self.outbound.lock().unwrap().push(m.outside_port);
            pkt
        }
        fn process_inbound(&self, _nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
            self.inbound.lock().unwrap().push(m.outside_port);
            pkt
        }
    }

    #[test]
    fn helpers_see_replies_from_the_service_port() {
        let (nat, _i, o) = setup();
        let rec = Arc::new(Recorder::default());
        nat.add_packet_helper(rec.clone());
        let p = build_tcp(
            Ipv4Addr::new(10, 0, 0, 5),
            40000,
            Ipv4Addr::new(198, 51, 100, 9),
            21,
            0x02,
        );
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let mapped = {
            let o = o.lock().unwrap();
            u16::from_be_bytes([o[0][20], o[0][21]])
        };
        let reply = build_tcp(
            Ipv4Addr::new(198, 51, 100, 9),
            21,
            Ipv4Addr::new(203, 0, 113, 1),
            mapped,
            0x12,
        );
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        assert_eq!(*rec.outbound.lock().unwrap(), vec![mapped]);
        assert_eq!(*rec.inbound.lock().unwrap(), vec![mapped]);
    }

    #[test]
    fn list_port_forwards_filters_expired() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_port_forward(
            PortForward::new(PROTO_TCP, 8080, Ipv4Addr::new(10, 0, 0, 5), 80).description("alive"),
        )
        .unwrap();
        nat.add_port_forward(
            PortForward::new(PROTO_TCP, 8081, Ipv4Addr::new(10, 0, 0, 6), 80)
                .description("dead")
                .expires(Instant::now() - Duration::from_secs(1)),
        )
        .unwrap();
        let live = nat.list_port_forwards();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].outside_port, 8080);
    }

    /// A UDP datagram from `src` whose checksum, once its source has become
    /// `xlat_src:xlat_sport`, sums to zero: the value an incremental update
    /// would store as 0x0000.
    fn udp_zero_after_xlat(
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        xlat: (Ipv4Addr, u16, Ipv4Addr, u16),
    ) -> Vec<u8> {
        let mut p = build_udp(src, sport, dst, dport, &[0, 0]);
        let mut t = build_udp(xlat.0, xlat.1, xlat.2, xlat.3, &[0, 0]);
        // Choose the payload word so the translated datagram sums to all
        // ones, i.e. its checksum computes to zero.
        let c = crate::transport_checksum(
            crate::Protocol::UDP,
            IpAddr::V4(xlat.0),
            IpAddr::V4(xlat.2),
            &t[20..],
        );
        p[28..30].copy_from_slice(&c.to_be_bytes());
        t[28..30].copy_from_slice(&c.to_be_bytes());
        assert_eq!(
            crate::transport_checksum(
                crate::Protocol::UDP,
                IpAddr::V4(xlat.0),
                IpAddr::V4(xlat.2),
                &t[20..]
            ),
            0
        );
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        p
    }

    #[test]
    fn udp_checksum_never_becomes_zero_outbound() {
        let (nat, _i, o) = setup();
        let (inside, remote, outside) = (
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(203, 0, 113, 1),
        );
        // A fresh NAT keeps the host's port, which is free.
        let p = udp_zero_after_xlat(
            inside,
            NAT_PORT_MIN,
            remote,
            53,
            (outside, NAT_PORT_MIN, remote, 53),
        );
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let out = o.lock().unwrap();
        assert_eq!(u16::from_be_bytes([out[0][20], out[0][21]]), NAT_PORT_MIN);
        assert_eq!(u16::from_be_bytes([out[0][26], out[0][27]]), 0xFFFF);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&out[0], 20));
    }

    #[test]
    fn udp_checksum_never_becomes_zero_inbound() {
        let (nat, i, _o) = setup();
        let (inside, remote, outside) = (
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(203, 0, 113, 1),
        );
        let p = build_udp(inside, NAT_PORT_MIN, remote, 53, &[1]);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let reply = udp_zero_after_xlat(
            remote,
            53,
            outside,
            NAT_PORT_MIN,
            (remote, 53, inside, NAT_PORT_MIN),
        );
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        let got = i.lock().unwrap();
        assert_eq!(u16::from_be_bytes([got[0][26], got[0][27]]), 0xFFFF);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&got[0], 20));
    }

    const INSIDE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn dst_port(p: &[u8]) -> u16 {
        u16::from_be_bytes([p[22], p[23]])
    }

    fn src_port(p: &[u8]) -> u16 {
        u16::from_be_bytes([p[20], p[21]])
    }

    #[test]
    fn expectation_only_matches_its_outside_port() {
        let (nat, i, _o) = setup();
        // An expectation open to any remote, as H.323 and IRC register.
        nat.add_expectation(Expectation::new(PROTO_UDP, INSIDE, 5004, 30000, soon()));

        let stray = build_udp(REMOTE, 1234, PUBLIC, 31000, b"x");
        nat.outside().send(Packet::from_slice(&stray)).unwrap();
        assert!(
            i.lock().unwrap().is_empty(),
            "unrelated port reached inside"
        );

        let good = build_udp(REMOTE, 1234, PUBLIC, 30000, b"x");
        nat.outside().send(Packet::from_slice(&good)).unwrap();
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0][16..20], &INSIDE.octets());
        assert_eq!(dst_port(&got[0]), 5004);
    }

    #[test]
    fn expectation_does_not_clobber_a_live_mapping() {
        let (nat, i, o) = setup();
        let p = build_udp(INSIDE, 5004, REMOTE, 9, b"x");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let live = src_port(&o.lock().unwrap()[0]);

        nat.add_expectation(Expectation::new(PROTO_UDP, INSIDE, 5004, 30000, soon()));
        let q = build_udp(REMOTE, 1234, PUBLIC, 30000, b"x");
        nat.outside().send(Packet::from_slice(&q)).unwrap();
        assert!(i.lock().unwrap().is_empty());

        // The live session is intact in both directions.
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(src_port(&o.lock().unwrap()[1]), live);
        let r = build_udp(REMOTE, 9, PUBLIC, live, b"y");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 1);
    }

    #[test]
    fn forward_replacing_a_mapping_leaves_no_stale_reverse_entry() {
        let (nat, i, o) = setup();
        let server = Ipv4Addr::new(10, 0, 0, 50);
        let p = build_tcp(server, 80, REMOTE, 5555, 0x02);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let old = src_port(&o.lock().unwrap()[0]);

        nat.add_port_forward(PortForward::new(PROTO_TCP, 8080, server, 80))
            .unwrap();
        let syn = build_tcp(REMOTE, 4444, PUBLIC, 8080, 0x02);
        nat.outside().send(Packet::from_slice(&syn)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 1);

        // The displaced port no longer leads anywhere.
        let stale = build_tcp(REMOTE, 5555, PUBLIC, old, 0x10);
        nat.outside().send(Packet::from_slice(&stale)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 1);
    }

    #[test]
    fn dynamic_ports_skip_forwarded_ones() {
        let (nat, _i, o) = setup();
        nat.add_port_forward(PortForward::new(PROTO_UDP, NAT_PORT_MIN, INSIDE, 53))
            .unwrap();
        nat.add_expectation(Expectation::new(
            PROTO_TCP,
            INSIDE,
            21000,
            NAT_PORT_MIN + 1,
            soon(),
        ));
        let p = build_tcp(Ipv4Addr::new(10, 0, 0, 6), 1000, REMOTE, 80, 0x02);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        assert_ne!(port, NAT_PORT_MIN, "handed out a forwarded port");
        assert_ne!(port, NAT_PORT_MIN + 1, "handed out an expected port");
    }

    #[test]
    fn forward_cannot_take_a_port_in_dynamic_use() {
        let (nat, _i, o) = setup();
        let p = build_tcp(INSIDE, 1000, REMOTE, 80, 0x02);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        let err = nat
            .add_port_forward(PortForward::new(
                PROTO_TCP,
                port,
                Ipv4Addr::new(10, 0, 0, 9),
                22,
            ))
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[test]
    fn host_may_forward_the_port_its_own_mapping_holds() {
        let (nat, i, o) = setup();
        let other = Ipv4Addr::new(10, 0, 0, 9);
        // A BitTorrent client sends from its listening port, which the NAT
        // preserves, then asks (UPnP) for that same port to be forwarded
        // to itself.
        let p = build_udp(INSIDE, 40000, REMOTE, 6881, b"dht");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(src_port(&o.lock().unwrap()[0]), 40000);
        nat.add_port_forward(PortForward::new(PROTO_UDP, 40000, INSIDE, 40000))
            .unwrap();
        // The mapping is the forward's now: open to anyone, and its
        // session with REMOTE kept.
        let p = build_udp(Ipv4Addr::new(192, 0, 2, 77), 1234, PUBLIC, 40000, b"hi");
        nat.outside().send(Packet::from_slice(&p)).unwrap();
        let p = build_udp(REMOTE, 6881, PUBLIC, 40000, b"re");
        nat.outside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 2);
        assert_eq!(mapped(&nat), 1);
        // Another host's mapping still keeps its port.
        let p = build_udp(other, 40002, REMOTE, 6881, b"dht");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let err = nat
            .add_port_forward(PortForward::new(PROTO_UDP, 40002, INSIDE, 40002))
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[test]
    fn removing_a_forward_closes_its_session() {
        let (nat, i, _o) = setup();
        nat.add_port_forward(PortForward::new(PROTO_TCP, 8080, INSIDE, 80))
            .unwrap();
        let syn = build_tcp(REMOTE, 4444, PUBLIC, 8080, 0x02);
        nat.outside().send(Packet::from_slice(&syn)).unwrap();
        nat.remove_port_forward(PROTO_TCP, 8080);
        nat.outside().send(Packet::from_slice(&syn)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 1);
    }

    #[test]
    fn second_forward_to_one_inside_endpoint_is_refused() {
        let (nat, _i, _o) = setup();
        let server = Ipv4Addr::new(10, 0, 0, 50);
        nat.add_port_forward(PortForward::new(PROTO_TCP, 8080, server, 80))
            .unwrap();
        let err = nat
            .add_port_forward(PortForward::new(PROTO_TCP, 8081, server, 80))
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        // Another protocol, port or namespace is another endpoint.
        nat.add_port_forward(PortForward::new(PROTO_UDP, 8081, server, 80))
            .unwrap();
        nat.add_port_forward(PortForward::new(PROTO_TCP, 8082, server, 81))
            .unwrap();
        nat.add_port_forward(PortForward::new(PROTO_TCP, 8083, server, 80).namespace(7))
            .unwrap();
        // Once the first is gone, the endpoint is free again.
        nat.remove_port_forward(PROTO_TCP, 8080);
        nat.add_port_forward(PortForward::new(PROTO_TCP, 8081, server, 80))
            .unwrap();
        // And a lapsed forward does not hold it either.
        let past = Instant::now() - Duration::from_secs(1);
        nat.add_port_forward(PortForward::new(PROTO_TCP, 9000, server, 22).expires(past))
            .unwrap();
        nat.add_port_forward(PortForward::new(PROTO_TCP, 9001, server, 22))
            .unwrap();
    }

    #[test]
    fn renewing_a_forward_keeps_its_session() {
        let (nat, i, o) = setup();
        let server = Ipv4Addr::new(10, 0, 0, 50);
        let pf = PortForward::new(PROTO_TCP, 8080, server, 80);
        nat.add_port_forward(pf.clone().expires(soon())).unwrap();
        let syn = build_tcp(REMOTE, 4444, PUBLIC, 8080, 0x02);
        nat.outside().send(Packet::from_slice(&syn)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 1);

        // A UPnP client renews its lease with the same mapping.
        nat.add_port_forward(pf.expires(soon() + Duration::from_secs(60)))
            .unwrap();
        let synack = build_tcp(server, 80, REMOTE, 4444, 0x12);
        nat.inside().send(Packet::from_slice(&synack)).unwrap();
        assert_eq!(src_port(&o.lock().unwrap()[0]), 8080);
    }

    /// A stand-in for a namespace-attached device: records what the NAT
    /// delivers, and injects packets as if the attached host sent them.
    #[derive(Default)]
    struct Tap {
        handler: StdMutex<Option<L3Handler>>,
        got: StdMutex<Vec<Vec<u8>>>,
    }

    impl L3Device for Tap {
        fn set_handler(&self, h: L3Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, p: &Packet) -> Result<()> {
            self.got.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }
        fn addr(&self) -> IpPrefix {
            pfx("10.0.0.1/24")
        }
        fn set_addr(&self, _p: IpPrefix) -> Result<()> {
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    impl Tap {
        fn inject(&self, p: &[u8]) {
            let h = self.handler.lock().unwrap().clone().unwrap();
            h(Packet::from_slice(p)).unwrap();
        }
    }

    #[test]
    fn alg_mappings_stay_in_the_sessions_namespace() {
        let (nat, i, _o) = setup();
        nat.add_packet_helper(Arc::new(crate::nat::FtpHelper::new()));
        let tap = Arc::new(Tap::default());
        let _cleanup = nat.connect_l3(tap.clone()).unwrap();

        let mut cmd = build_tcp(INSIDE, 45000, REMOTE, 21, 0x18);
        cmd.extend_from_slice(b"PORT 10,0,0,5,4,210\r\n");
        let total = cmd.len() as u16;
        cmd[2..4].copy_from_slice(&total.to_be_bytes());
        cmd[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&cmd[..20]);
        cmd[10..12].copy_from_slice(&ic.to_be_bytes());
        crate::nat::l4::fill_v4_l4_checksum(&mut cmd, 20);
        tap.inject(&cmd);

        let e = nat.take_expectation(PROTO_TCP, INSIDE, 1234).unwrap();
        assert_ne!(e.namespace, 0);
        nat.add_expectation(e.clone());

        // The data connection reaches the namespace, not the default inside
        // (where 10.0.0.5 may be a different host).
        let syn = build_tcp(REMOTE, 20, PUBLIC, e.outside_port, 0x02);
        nat.outside().send(Packet::from_slice(&syn)).unwrap();
        assert!(i.lock().unwrap().is_empty());
        let got = tap.got.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(dst_port(&got[0]), 1234);
    }

    #[test]
    fn expectation_table_is_bounded() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        for i in 0..(MAX_EXPECTATIONS as u16 + 500) {
            nat.add_expectation(Expectation::new(PROTO_UDP, INSIDE, i, 20000 + i, soon()));
        }
        assert!(nat.inner.lock().unwrap().expectations.len() <= MAX_EXPECTATIONS);
    }

    #[test]
    fn one_host_cannot_push_out_others_expectations() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.set_limits(NatLimits::default().max_expectations_per_host(4));
        let other = Ipv4Addr::new(10, 0, 0, 6);
        nat.add_expectation(Expectation::new(PROTO_UDP, other, 1, 30000, soon()));
        for i in 0..100 {
            let e = Expectation::new(PROTO_UDP, INSIDE, i, 20000 + i, soon());
            nat.add_expectation(e);
        }
        let inner = nat.inner.lock().unwrap();
        let of = |ip| {
            inner
                .expectations
                .iter()
                .filter(|e| e.inside_ip == ip)
                .count()
        };
        assert_eq!((of(INSIDE), of(other)), (4, 1));
        // The newest were kept.
        assert!(inner.expectations.iter().any(|e| e.inside_port == 99));
        drop(inner);

        // With no cap per host, the busiest host still pays for a full
        // table.
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.set_limits(NatLimits::default().max_expectations_per_host(0));
        nat.add_expectation(Expectation::new(PROTO_UDP, other, 1, 30000, soon()));
        for i in 0..(MAX_EXPECTATIONS as u16 + 10) {
            let e = Expectation::new(PROTO_UDP, INSIDE, i, 20000 + i, soon());
            nat.add_expectation(e);
        }
        let inner = nat.inner.lock().unwrap();
        assert_eq!(inner.expectations.len(), MAX_EXPECTATIONS);
        assert!(inner.expectations.iter().any(|e| e.inside_ip == other));
    }

    #[test]
    fn sweep_purges_expired_expectations_and_forwards() {
        let (nat, i, _o) = setup();
        let past = Instant::now() - Duration::from_secs(1);
        nat.add_expectation(Expectation::new(PROTO_UDP, INSIDE, 5004, 30000, past));
        nat.add_port_forward(PortForward::new(PROTO_TCP, 8080, INSIDE, 80).expires(soon()))
            .unwrap();
        let syn = build_tcp(REMOTE, 4444, PUBLIC, 8080, 0x02);
        nat.outside().send(Packet::from_slice(&syn)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 1);
        nat.inner
            .lock()
            .unwrap()
            .forwards
            .by_port
            .values_mut()
            .for_each(|pf| pf.expires = Some(past));

        nat.sweep();
        let inner = nat.inner.lock().unwrap();
        assert!(inner.expectations.is_empty());
        assert!(inner.forwards.by_port.is_empty());
        assert!(inner.forwards.by_endpoint.is_empty());
        // The session the lapsed forward carried is gone as well.
        assert!(inner.reverse.is_empty());
    }

    /// Open a TCP connection INSIDE:40000 -> REMOTE:80 and return the mapped port.
    fn open_tcp(nat: &Nat, o: &StdMutex<Vec<Vec<u8>>>) -> u16 {
        let syn = build_tcp(INSIDE, 40000, REMOTE, 80, 0x02);
        nat.inside().send(Packet::from_slice(&syn)).unwrap();
        let port = src_port(o.lock().unwrap().last().unwrap());
        let synack = build_tcp(REMOTE, 80, PUBLIC, port, 0x12);
        nat.outside().send(Packet::from_slice(&synack)).unwrap();
        port
    }

    fn mapped(nat: &Nat) -> usize {
        nat.inner.lock().unwrap().mappings.len()
    }

    #[test]
    fn half_closed_tcp_keeps_its_mapping() {
        let (nat, _i, o) = setup();
        open_tcp(&nat, &o);
        let fin = build_tcp(INSIDE, 40000, REMOTE, 80, 0x11);
        nat.inside().send(Packet::from_slice(&fin)).unwrap();
        // The remote may keep sending for as long as it likes.
        nat.sweep_at(Instant::now() + Duration::from_secs(3600));
        assert_eq!(mapped(&nat), 1);
    }

    #[test]
    fn reset_from_another_host_does_not_end_the_session() {
        let (nat, _i, o) = setup();
        let port = open_tcp(&nat, &o);
        let rst = build_tcp(Ipv4Addr::new(192, 0, 2, 66), 80, PUBLIC, port, 0x04);
        nat.outside().send(Packet::from_slice(&rst)).unwrap();
        nat.sweep_at(Instant::now() + Duration::from_secs(3600));
        assert_eq!(mapped(&nat), 1);
    }

    #[test]
    fn established_tcp_meets_rfc5382_timeout() {
        let (nat, _i, o) = setup();
        open_tcp(&nat, &o);
        nat.sweep_at(Instant::now() + Duration::from_secs(2 * 3600));
        assert_eq!(mapped(&nat), 1);
        nat.sweep_at(Instant::now() + Duration::from_secs(2 * 3600 + 5 * 60));
        assert_eq!(mapped(&nat), 0);
    }

    #[test]
    fn udp_meets_rfc4787_timeout() {
        let (nat, _i, _o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        nat.sweep_at(Instant::now() + Duration::from_secs(4 * 60));
        assert_eq!(mapped(&nat), 1);
    }

    /// Backdate every mapping's activity by `by`, returning the new time.
    fn age_mappings(nat: &Nat, by: Duration) -> Instant {
        let then = Instant::now() - by;
        for m in nat.inner.lock().unwrap().mappings.values_mut() {
            m.last_active = then;
            m.peers.backdate(by);
        }
        then
    }

    #[test]
    fn exhausted_pool_reclaims_idle_mappings_without_sweep() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.set_limits(NatLimits::default().max_mappings_per_host(0));
        fill_pool(&nat);
        // A port of the pool's is taken, so the pool it is, and that is full.
        let want = NAT_PORT_MIN;
        assert!(
            nat.create_mapping(PROTO_UDP, REMOTE, want).is_none(),
            "full"
        );
        // Every mapping has been idle past its timeout; nobody swept.
        age_mappings(&nat, UDP_TIMEOUT + Duration::from_secs(1));
        // And the last reclaim, which found nothing, was long enough ago.
        nat.inner.lock().unwrap().next_reclaim = Instant::now();
        assert!(nat.create_mapping(PROTO_UDP, REMOTE, want).is_some());
        assert!(
            nat.create_mapping_pair_in(0, PROTO_UDP, REMOTE, (2, 3))
                .is_some()
        );
        assert_eq!(mapped(&nat), 3);
    }

    /// Map one inside host's UDP ports to every port of the pool, each
    /// keeping its number.
    fn fill_pool(nat: &Nat) {
        for port in NAT_PORT_MIN..=NAT_PORT_MAX {
            assert_eq!(nat.create_mapping(PROTO_UDP, INSIDE, port), Some(port));
        }
    }

    #[test]
    fn ports_keep_what_they_can_of_the_hosts_choice() {
        let (nat, _i, o) = setup();
        let other = Ipv4Addr::new(10, 0, 0, 6);
        let out_port = |src: Ipv4Addr, sport: u16| {
            let p = build_udp(src, sport, REMOTE, 53, b"q");
            nat.inside().send(Packet::from_slice(&p)).unwrap();
            src_port(o.lock().unwrap().last().unwrap())
        };
        // Preserved when free, in the pool or not.
        assert_eq!(out_port(INSIDE, 40001), 40001);
        assert_eq!(out_port(INSIDE, 5060), 5060);
        assert_eq!(out_port(INSIDE, 123), 123);
        // Taken: same range and parity (RFC 4787 REQ-3, REQ-4).
        let p = out_port(other, 40001);
        assert!(p >= NAT_PORT_MIN && p % 2 == 1, "{p}");
        let p = out_port(other, 5060);
        assert!(p >= NAT_PORT_MIN && p % 2 == 0, "{p}");
        let p = out_port(other, 123);
        assert!((1..512).contains(&p) && p % 2 == 1, "{p}");
        let p = out_port(other, 1022);
        assert_eq!(p, 1022);
        let q = out_port(Ipv4Addr::new(10, 0, 0, 7), 1022);
        assert!((600..1024).contains(&q) && q % 2 == 0, "{q}");
    }

    #[test]
    fn a_full_pool_refuses_new_flows_cheaply() {
        let (nat, _i, o) = setup();
        nat.set_limits(NatLimits::default().max_mappings_per_host(0));
        fill_pool(&nat);
        // Every mapping is live: nothing can be reclaimed. Each new flow
        // used to rescan the pool and walk the whole table under the lock,
        // some 5 ms apiece; now the free count refuses it, and a reclaim
        // runs at most once a second. The bound is loose enough for a slow
        // debug build.
        let start = std::time::Instant::now();
        for sport in NAT_PORT_MIN..NAT_PORT_MIN + 2000 {
            let p = build_udp(Ipv4Addr::new(10, 0, 0, 200), sport, REMOTE, 53, b"q");
            nat.inside().send(Packet::from_slice(&p)).unwrap();
        }
        let took = start.elapsed();
        assert!(o.lock().unwrap().is_empty());
        assert!(took < Duration::from_millis(500), "{took:?} for 2000 flows");

        // As ports come free, they are found again.
        {
            let mut inner = nat.inner.lock().unwrap();
            let k = NatKey {
                ns: 0,
                proto: PROTO_UDP,
                ip: INSIDE,
                port: NAT_PORT_MIN,
            };
            let port = inner.mappings[&k].outside_port;
            Nat::remove_mapping_at_locked(
                &mut inner,
                NatRevKey {
                    proto: PROTO_UDP,
                    port,
                },
            );
        }
        let sport = NAT_PORT_MIN + 1;
        let p = build_udp(Ipv4Addr::new(10, 0, 0, 200), sport, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(src_port(&o.lock().unwrap()[0]), NAT_PORT_MIN);
    }

    #[test]
    fn one_host_cannot_take_every_port() {
        let (nat, _i, o) = setup();
        nat.set_limits(NatLimits::default().max_mappings_per_host(3));
        let other = Ipv4Addr::new(10, 0, 0, 6);
        for port in 1..=4 {
            let p = build_udp(INSIDE, port, REMOTE, 53, b"q");
            nat.inside().send(Packet::from_slice(&p)).unwrap();
        }
        assert_eq!(
            o.lock().unwrap().len(),
            3,
            "the fourth flow is over the cap"
        );
        // Another host is not held back, and a forward to the capped host
        // still gets its mapping.
        let p = build_udp(other, 1, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        nat.add_port_forward(PortForward::new(PROTO_UDP, 7000, INSIDE, 7000))
            .unwrap();
        let p = build_udp(REMOTE, 53, PUBLIC, 7000, b"in");
        nat.outside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(mapped(&nat), 5);
        assert_eq!(o.lock().unwrap().len(), 4);

        // Once the host's mappings idle out, it may open new ones.
        nat.remove_port_forward(PROTO_UDP, 7000);
        age_mappings(&nat, UDP_TIMEOUT + Duration::from_secs(1));
        nat.sweep();
        let p = build_udp(INSIDE, 9, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(o.lock().unwrap().len(), 5);
        // Hosts with nothing left are forgotten.
        assert_eq!(nat.inner.lock().unwrap().hosts.len(), 1);
    }

    #[test]
    fn tracked_remotes_are_capped_across_mappings() {
        let (nat, _i, o) = setup();
        nat.set_limits(NatLimits::default().max_peers(10).max_peers_per_host(6));
        let other = Ipv4Addr::new(10, 0, 0, 6);
        for host in [INSIDE, other] {
            for sport in [1000, 1001] {
                for r in 0..8u8 {
                    let dst = Ipv4Addr::new(198, 51, 100, r);
                    let p = build_udp(host, sport, dst, 53, b"q");
                    nat.inside().send(Packet::from_slice(&p)).unwrap();
                }
            }
        }
        // Every datagram went out; only 6 + 4 remotes are tracked.
        assert_eq!(o.lock().unwrap().len(), 32);
        let inner = nat.inner.lock().unwrap();
        assert_eq!(inner.peer_quota.used(), 10);
        let per_host: Vec<usize> = [INSIDE, other]
            .iter()
            .map(|ip| inner.hosts[&(0, *ip)].peers.used())
            .collect();
        assert_eq!(per_host, [6, 4]);
    }

    #[test]
    fn spoofed_inside_sources_are_not_translated() {
        let (nat, _i, o) = setup();
        for src in [
            Ipv4Addr::new(192, 168, 7, 7),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 255),
        ] {
            let p = build_udp(src, 1000, REMOTE, 53, b"q");
            nat.inside().send(Packet::from_slice(&p)).unwrap();
        }
        assert!(o.lock().unwrap().is_empty());
        assert_eq!(mapped(&nat), 0);
    }

    #[test]
    fn hosts_on_a_routed_inside_network_are_translated() {
        let (nat, _i, o) = setup();
        let behind = Ipv4Addr::new(192, 168, 7, 7);
        let p = build_udp(behind, 1000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert!(o.lock().unwrap().is_empty(), "not served until routed");

        nat.set_inside_routes(vec![pfx("192.168.7.0/24")]);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(o.lock().unwrap().len(), 1);
        // Other networks are still refused.
        let p = build_udp(Ipv4Addr::new(192, 168, 8, 7), 1000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(o.lock().unwrap().len(), 1);
    }

    #[test]
    fn packet_handling_sweeps_periodically() {
        let (nat, _i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        age_mappings(&nat, UDP_TIMEOUT + Duration::from_secs(1));
        *nat.next_sweep.lock().unwrap() = Instant::now();
        let p = build_udp(INSIDE, 5001, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(o.lock().unwrap().len(), 2);
        // Only the new mapping is left.
        assert_eq!(mapped(&nat), 1);
        assert_eq!(nat.inner.lock().unwrap().reverse.len(), 1);
    }

    #[test]
    fn unsolicited_inbound_does_not_keep_a_mapping_alive() {
        let (nat, i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        let then = age_mappings(&nat, Duration::from_secs(100));
        let stranger = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 66), 4444);
        let r = build_udp(*stranger.ip(), stranger.port(), PUBLIC, port, b"x");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        // Still let through (endpoint-independent filtering) ...
        assert_eq!(i.lock().unwrap().len(), 1);
        {
            let inner = nat.inner.lock().unwrap();
            let m = inner.mappings.values().next().unwrap();
            // ... but neither refreshing the mapping nor taking a peer slot.
            assert_eq!(m.last_active, then);
            assert!(!m.peers.contains(&stranger));
        }
        // The remote the host talked to does refresh it.
        let r = build_udp(REMOTE, 53, PUBLIC, port, b"a");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        let inner = nat.inner.lock().unwrap();
        assert!(inner.mappings.values().next().unwrap().last_active > then);
    }

    #[test]
    fn any_remote_keeps_a_forward_alive() {
        let (nat, i, _o) = setup();
        nat.add_port_forward(PortForward::new(PROTO_UDP, 8080, INSIDE, 80))
            .unwrap();
        let first = build_udp(REMOTE, 1000, PUBLIC, 8080, b"x");
        nat.outside().send(Packet::from_slice(&first)).unwrap();
        let then = age_mappings(&nat, Duration::from_secs(100));
        let other = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 66), 4444);
        let r = build_udp(*other.ip(), other.port(), PUBLIC, 8080, b"y");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 2);
        let inner = nat.inner.lock().unwrap();
        let m = inner.mappings.values().next().unwrap();
        assert!(m.last_active > then);
        assert!(m.peers.contains(&other));
    }

    #[test]
    fn reopened_connection_is_tracked_afresh() {
        let (nat, _i, o) = setup();
        let port = open_tcp(&nat, &o);
        let fin_out = build_tcp(INSIDE, 40000, REMOTE, 80, 0x11);
        nat.inside().send(Packet::from_slice(&fin_out)).unwrap();
        let fin_in = build_tcp(REMOTE, 80, PUBLIC, port, 0x11);
        nat.outside().send(Packet::from_slice(&fin_in)).unwrap();
        // Same endpoints, new connection.
        open_tcp(&nat, &o);
        nat.sweep_at(Instant::now() + Duration::from_secs(3600));
        assert_eq!(mapped(&nat), 1);
    }

    /// An ICMP error from `from` quoting `quoted` in full.
    fn icmp_error(from: Ipv4Addr, quoted: &[u8]) -> Vec<u8> {
        icmp_error_to(from, PUBLIC, quoted)
    }

    /// An ICMP port unreachable from `from` to `to` quoting `quoted`.
    fn icmp_error_to(from: Ipv4Addr, to: Ipv4Addr, quoted: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + quoted.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_ICMP;
        p[12..16].copy_from_slice(&from.octets());
        p[16..20].copy_from_slice(&to.octets());
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p[20] = 3; // destination unreachable
        p[21] = 3; // port unreachable
        p[28..].copy_from_slice(quoted);
        let cs = checksum(&p[20..]);
        p[22..24].copy_from_slice(&cs.to_be_bytes());
        p
    }

    #[test]
    fn icmp_error_is_translated_with_valid_checksums() {
        let (nat, i, o) = setup();
        let mut p = build_udp(INSIDE, 5000, REMOTE, 53, b"query");
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let sent = o.lock().unwrap()[0].clone();

        nat.outside()
            .send(Packet::from_slice(&icmp_error(REMOTE, &sent)))
            .unwrap();
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 1);
        let e = &got[0];
        assert_eq!(&e[16..20], &INSIDE.octets());
        assert_eq!(checksum(&e[20..]), 0, "outer ICMP checksum");
        let inner = &e[28..];
        // The quoted datagram is what the inside host sent, less the hop
        // the NAT took from it on the way out.
        let mut want = p.clone();
        spend_hop(&mut want);
        assert_eq!(inner, &want[..]);
        assert_eq!(checksum(&inner[..20]), 0, "inner IP checksum");
        assert!(
            crate::nat::l4::v4_l4_checksum_ok(inner, 20),
            "inner UDP checksum"
        );
    }

    #[test]
    fn forwarding_spends_a_hop_each_way() {
        let (nat, i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"query");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let sent = o.lock().unwrap()[0].clone();
        assert_eq!(sent[8], 63);
        assert_eq!(checksum(&sent[..20]), 0, "IP checksum");

        let mut r = build_udp(REMOTE, 53, PUBLIC, src_port(&sent), b"answer");
        r[8] = 2;
        r[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&r[..20]);
        r[10..12].copy_from_slice(&ic.to_be_bytes());
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        let got = i.lock().unwrap()[0].clone();
        assert_eq!(got[8], 1);
        assert_eq!(checksum(&got[..20]), 0, "IP checksum");
    }

    /// Set a packet's TTL, keeping its header checksum valid.
    fn with_ttl(mut p: Vec<u8>, ttl: u8) -> Vec<u8> {
        p[8] = ttl;
        p[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p
    }

    #[test]
    fn expiring_ttl_is_answered_not_forwarded() {
        let (nat, i, o) = setup();
        // Outbound: the inside host hears back from the NAT's inside
        // address.
        let p = with_ttl(build_udp(INSIDE, 5000, REMOTE, 53, b"query"), 1);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert!(o.lock().unwrap().is_empty());
        {
            let got = i.lock().unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(&got[0][12..16], &[10, 0, 0, 1]);
            assert_eq!(&got[0][16..20], &INSIDE.octets());
            assert_eq!((got[0][20], got[0][21]), (11, 0), "Time Exceeded");
        }
        i.lock().unwrap().clear();

        // Inbound, on a mapping: the remote hears back from the public
        // address.
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"query");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        o.lock().unwrap().clear();
        let r = with_ttl(build_udp(REMOTE, 53, PUBLIC, port, b"answer"), 1);
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert!(i.lock().unwrap().is_empty());
        {
            let got = o.lock().unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(&got[0][12..16], &PUBLIC.octets());
            assert_eq!(&got[0][16..20], &REMOTE.octets());
            assert_eq!((got[0][20], got[0][21]), (11, 0), "Time Exceeded");
        }
        o.lock().unwrap().clear();

        // Inbound to a port nothing is behind: the NAT was the destination,
        // not a router on the way, and says nothing.
        let r = with_ttl(build_udp(REMOTE, 53, PUBLIC, port ^ 1, b"answer"), 1);
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert!(o.lock().unwrap().is_empty());
        assert!(i.lock().unwrap().is_empty());

        // A ping to the NAT itself with one hop left is still answered.
        let ping = with_ttl(build_icmp_echo(INSIDE, PUBLIC, 7, 1), 1);
        nat.inside().send(Packet::from_slice(&ping)).unwrap();
        assert_eq!(i.lock().unwrap()[0][20], 0, "Echo Reply");
    }

    #[test]
    fn time_exceeded_is_rate_limited() {
        let (nat, i, _o) = setup();
        let p = with_ttl(build_udp(INSIDE, 5000, REMOTE, 53, b"query"), 1);
        for _ in 0..(ICMP_BURST * 4) {
            nat.inside().send(Packet::from_slice(&p)).unwrap();
        }
        let n = i.lock().unwrap().len();
        assert!(n >= 1 && n < (ICMP_BURST * 2) as usize, "{n} errors sent");
    }

    #[test]
    fn ping_to_the_public_address_from_outside_is_answered() {
        let (nat, i, o) = setup();
        let ping = build_icmp_echo(REMOTE, PUBLIC, 0x1234, 7);
        nat.outside().send(Packet::from_slice(&ping)).unwrap();
        assert!(i.lock().unwrap().is_empty(), "no inside host owns it");
        let got = o.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        let r = &got[0];
        assert_eq!(&r[12..16], &PUBLIC.octets());
        assert_eq!(&r[16..20], &REMOTE.octets());
        assert_eq!(r[20], 0, "Echo Reply");
        assert_eq!(&r[24..28], &ping[24..28], "identifier and sequence");
        assert_eq!(checksum(&r[..20]), 0);
        assert_eq!(checksum(&r[20..]), 0);

        // A flood is answered only up to the rate limit.
        o.lock().unwrap().clear();
        for _ in 0..(ICMP_BURST * 4) {
            nat.outside().send(Packet::from_slice(&ping)).unwrap();
        }
        let n = o.lock().unwrap().len();
        assert!(n < (ICMP_BURST * 2) as usize, "{n} replies");
    }

    #[test]
    fn forged_icmp_error_is_dropped() {
        let (nat, i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"query");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let sent = o.lock().unwrap()[0].clone();

        // An error quoting a packet to a host the mapping never talked to.
        let other = Ipv4Addr::new(192, 0, 2, 66);
        let mut forged = sent.clone();
        forged[16..20].copy_from_slice(&other.octets());
        forged[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&forged[..20]);
        forged[10..12].copy_from_slice(&ic.to_be_bytes());
        nat.outside()
            .send(Packet::from_slice(&icmp_error(other, &forged)))
            .unwrap();
        assert!(i.lock().unwrap().is_empty());

        // A corrupted error is not laundered into a valid one either.
        let mut bad = icmp_error(REMOTE, &sent);
        bad[30] ^= 0xFF;
        nat.outside().send(Packet::from_slice(&bad)).unwrap();
        assert!(i.lock().unwrap().is_empty());
    }

    #[test]
    fn icmp_error_from_the_inside_is_translated_out() {
        let (nat, i, o) = setup();
        let mut p = build_udp(INSIDE, 5000, REMOTE, 53, b"query");
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        o.lock().unwrap().clear();

        // The remote's answer reaches the inside host, which has closed
        // the socket and says so. So does a router on the inside.
        let mut r = build_udp(REMOTE, 53, PUBLIC, port, b"answer");
        crate::nat::l4::fill_v4_l4_checksum(&mut r, 20);
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        let delivered = i.lock().unwrap()[0].clone();
        let router = Ipv4Addr::new(10, 0, 0, 254);
        for from in [INSIDE, router] {
            let err = icmp_error_to(from, REMOTE, &delivered);
            nat.inside().send(Packet::from_slice(&err)).unwrap();
        }

        let out = o.lock().unwrap();
        assert_eq!(out.len(), 2);
        let mut want = r.clone();
        spend_hop(&mut want);
        for e in out.iter() {
            assert_eq!(&e[12..16], &PUBLIC.octets(), "outer source");
            assert_eq!(&e[16..20], &REMOTE.octets());
            assert_eq!(checksum(&e[..20]), 0, "outer IP checksum");
            assert_eq!(checksum(&e[20..]), 0, "outer ICMP checksum");
            // The quoted datagram is what the remote sent, as it reached
            // the inside, a hop shorter.
            assert_eq!(&e[28..], &want[..]);
        }
    }

    #[test]
    fn inside_cannot_forge_errors_about_other_sessions() {
        let (nat, _i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"query");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        o.lock().unwrap().clear();

        // No packet from this remote ever reached the mapping.
        let other = Ipv4Addr::new(192, 0, 2, 66);
        let mut q = build_udp(other, 53, INSIDE, 5000, b"never sent");
        crate::nat::l4::fill_v4_l4_checksum(&mut q, 20);
        let err = icmp_error_to(INSIDE, other, &q);
        nat.inside().send(Packet::from_slice(&err)).unwrap();
        // Nor did anything reach an endpoint without a mapping.
        let q = build_udp(REMOTE, 53, INSIDE, 5001, b"x");
        let err = icmp_error_to(INSIDE, REMOTE, &q);
        nat.inside().send(Packet::from_slice(&err)).unwrap();
        assert!(o.lock().unwrap().is_empty());
    }

    /// A TCP segment with explicit sequence numbers, options and payload.
    #[allow(clippy::too_many_arguments)]
    fn tcp_seg(
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        opts: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let doff = 20 + opts.len();
        let total = 20 + doff + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[28..32].copy_from_slice(&ack.to_be_bytes());
        p[32] = ((doff / 4) as u8) << 4;
        p[33] = flags;
        p[40..40 + opts.len()].copy_from_slice(opts);
        p[20 + doff..].copy_from_slice(payload);
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        p
    }

    fn seq_of(p: &[u8]) -> u32 {
        u32::from_be_bytes([p[24], p[25], p[26], p[27]])
    }

    fn ack_of(p: &[u8]) -> u32 {
        u32::from_be_bytes([p[28], p[29], p[30], p[31]])
    }

    #[test]
    fn alg_resize_keeps_tcp_sequence_numbers_in_sync() {
        let (nat, i, o) = setup();
        nat.add_packet_helper(Arc::new(crate::nat::FtpHelper::new()));
        let cmd: &[u8] = b"PORT 10,0,0,5,4,210\r\n";
        let seg = tcp_seg(INSIDE, 45000, REMOTE, 21, 0x18, 1000, 7000, &[], cmd);
        nat.inside().send(Packet::from_slice(&seg)).unwrap();
        let (mapped, grown) = {
            let out = o.lock().unwrap();
            let rewritten = out[0].len() - 40;
            assert_ne!(rewritten, cmd.len(), "test needs a length-changing rewrite");
            (src_port(&out[0]), rewritten as u32)
        };
        let orig = cmd.len() as u32;

        // The next segment from the client follows the rewritten command.
        let next = tcp_seg(
            INSIDE,
            45000,
            REMOTE,
            21,
            0x18,
            1000 + orig,
            7000,
            &[],
            b"LIST\r\n",
        );
        nat.inside().send(Packet::from_slice(&next)).unwrap();
        {
            let out = o.lock().unwrap();
            assert_eq!(seq_of(&out[0]), 1000);
            assert_eq!(seq_of(&out[1]), 1000 + grown);
            assert!(crate::nat::l4::v4_l4_checksum_ok(&out[1], 20));
        }

        // The server acknowledges the rewritten stream, with a SACK block
        // (NOP, NOP, SACK) covering the LIST segment.
        let right = 1000 + grown + 6;
        let mut opts = vec![1, 1, 5, 10];
        opts.extend_from_slice(&(1000 + grown).to_be_bytes());
        opts.extend_from_slice(&right.to_be_bytes());
        let reply = tcp_seg(
            REMOTE,
            21,
            PUBLIC,
            mapped,
            0x10,
            7000,
            1000 + grown,
            &opts,
            &[],
        );
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        let got = i.lock().unwrap();
        let r = &got[0];
        assert_eq!(ack_of(r), 1000 + orig);
        let sack = |at: usize| u32::from_be_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
        assert_eq!(sack(44), 1000 + orig);
        assert_eq!(sack(48), 1000 + orig + 6);
        assert!(crate::nat::l4::v4_l4_checksum_ok(r, 20));
    }

    #[test]
    fn ping_to_the_public_address_from_inside_is_answered() {
        let (nat, i, o) = setup();
        let p = build_icmp_echo(INSIDE, PUBLIC, 0x77, 3);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert!(o.lock().unwrap().is_empty(), "sent out to the upstream");
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 1);
        let r = &got[0];
        assert_eq!(&r[12..16], &PUBLIC.octets());
        assert_eq!(&r[16..20], &INSIDE.octets());
        assert_eq!(r[20], 0, "echo reply");
        assert_eq!(&r[24..], &p[24..], "identifier, sequence and data");
        assert_eq!(checksum(&r[..20]), 0);
        assert_eq!(checksum(&r[20..]), 0);
    }

    #[test]
    fn traffic_to_the_inside_address_is_not_translated_out() {
        let (nat, i, o) = setup();
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let p = build_icmp_echo(INSIDE, gw, 0x78, 1);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let p = build_udp(INSIDE, 5000, gw, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let p = build_tcp(INSIDE, 5001, gw, 80, 0x02);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert!(o.lock().unwrap().is_empty(), "sent out to the upstream");
        assert_eq!(mapped(&nat), 0);
        // The ping is answered from the inside address.
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 1);
        let r = &got[0];
        assert_eq!(&r[12..16], &gw.octets());
        assert_eq!(&r[16..20], &INSIDE.octets());
        assert_eq!(r[20], 0, "echo reply");
        assert_eq!(checksum(&r[20..]), 0);
    }

    #[test]
    fn a_directed_broadcast_stays_inside() {
        let (nat, _i, o) = setup();
        let p = build_udp(INSIDE, 5000, Ipv4Addr::new(10, 0, 0, 255), 137, b"nb");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert!(o.lock().unwrap().is_empty(), "broadcast sent upstream");
        assert_eq!(mapped(&nat), 0);
        // Another network's broadcast address is just an address.
        let p = build_udp(INSIDE, 5000, Ipv4Addr::new(10, 0, 1, 255), 137, b"nb");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(o.lock().unwrap().len(), 1);
    }

    #[test]
    fn inbound_traffic_must_be_addressed_to_the_nat() {
        let (nat, i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        // Same port, another address on the outside network.
        let elsewhere = Ipv4Addr::new(203, 0, 113, 99);
        let r = build_udp(REMOTE, 53, elsewhere, port, b"a");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert!(i.lock().unwrap().is_empty());
        let r = build_udp(REMOTE, 53, PUBLIC, port, b"a");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 1);
    }

    #[test]
    fn no_resizing_rewrite_without_room_to_track_it() {
        let (nat, _i, o) = setup();
        nat.add_packet_helper(Arc::new(crate::nat::FtpHelper::new()));
        // The mapping already tracks as many remotes as it may.
        for n in 0..1024u32 {
            let [_, _, a, b] = n.to_be_bytes();
            let server = Ipv4Addr::new(198, 18, a, b);
            let syn = tcp_seg(INSIDE, 45000, server, 21, 0x02, 1, 0, &[], &[]);
            nat.inside().send(Packet::from_slice(&syn)).unwrap();
        }
        o.lock().unwrap().clear();
        let cmd: &[u8] = b"PORT 10,0,0,5,4,210\r\n";
        let seg = tcp_seg(INSIDE, 45000, REMOTE, 21, 0x18, 1000, 7000, &[], cmd);
        nat.inside().send(Packet::from_slice(&seg)).unwrap();
        // No sequence adjustment could be recorded for this connection, so
        // the command must not change length: it goes out as it was.
        let out = o.lock().unwrap();
        assert_eq!(&out[0][40..], cmd);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&out[0], 20));
    }

    #[test]
    fn first_fragments_get_the_sequence_adjustment_too() {
        let (nat, i, o) = setup();
        nat.add_packet_helper(Arc::new(crate::nat::FtpHelper::new()));
        let cmd: &[u8] = b"PORT 10,0,0,5,4,210\r\n";
        let seg = tcp_seg(INSIDE, 45000, REMOTE, 21, 0x18, 1000, 7000, &[], cmd);
        nat.inside().send(Packet::from_slice(&seg)).unwrap();
        let (mapped, grown) = {
            let out = o.lock().unwrap();
            (src_port(&out[0]), (out[0].len() - 40) as u32)
        };
        let orig = cmd.len() as u32;
        o.lock().unwrap().clear();

        // The next segment leaves in two fragments.
        let next = tcp_seg(
            INSIDE,
            45000,
            REMOTE,
            21,
            0x18,
            1000 + orig,
            7000,
            &[],
            b"STOR a-long-file-name\r\n",
        );
        let (f1, f2) = split(&next, 24, 0x3131);
        nat.inside().send(Packet::from_slice(&f1)).unwrap();
        nat.inside().send(Packet::from_slice(&f2)).unwrap();
        {
            let out = o.lock().unwrap();
            assert_eq!(out.len(), 2);
            assert_eq!(seq_of(&out[0]), 1000 + grown);
            assert!(crate::nat::l4::v4_l4_checksum_ok(
                &join(&out[0], &out[1]),
                20
            ));
        }

        // And so do the server's, the other way.
        let reply = tcp_seg(
            REMOTE,
            21,
            PUBLIC,
            mapped,
            0x18,
            7000,
            1000 + grown,
            &[],
            b"150 Opening data connection\r\n",
        );
        let (r1, r2) = split(&reply, 24, 0x3232);
        nat.outside().send(Packet::from_slice(&r1)).unwrap();
        nat.outside().send(Packet::from_slice(&r2)).unwrap();
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(ack_of(&got[0]), 1000 + orig);
        assert!(crate::nat::l4::v4_l4_checksum_ok(
            &join(&got[0], &got[1]),
            20
        ));
    }

    #[test]
    fn hairpinning_reaches_a_forwarded_inside_host() {
        let (nat, i, o) = setup();
        let server = Ipv4Addr::new(10, 0, 0, 50);
        nat.add_port_forward(PortForward::new(PROTO_TCP, 8080, server, 80))
            .unwrap();

        let syn = build_tcp(INSIDE, 40000, PUBLIC, 8080, 0x02);
        nat.inside().send(Packet::from_slice(&syn)).unwrap();
        assert!(o.lock().unwrap().is_empty(), "hairpinned packet went out");
        let (from_port, fwd) = {
            let got = i.lock().unwrap();
            assert_eq!(got.len(), 1);
            let p = got[0].clone();
            // Delivered to the server, from the client's public endpoint.
            assert_eq!(&p[16..20], &server.octets());
            assert_eq!(dst_port(&p), 80);
            assert_eq!(&p[12..16], &PUBLIC.octets());
            (src_port(&p), p)
        };
        assert_eq!(checksum(&fwd[..20]), 0);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&fwd, 20));

        // And the answer finds its way back the same way.
        let synack = build_tcp(server, 80, PUBLIC, from_port, 0x12);
        nat.inside().send(Packet::from_slice(&synack)).unwrap();
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(&got[1][16..20], &INSIDE.octets());
        assert_eq!(dst_port(&got[1]), 40000);
        assert_eq!(&got[1][12..16], &PUBLIC.octets());
        assert_eq!(src_port(&got[1]), 8080);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&got[1], 20));
    }

    /// Split an IPv4 datagram (20-byte header) into two fragments, the first
    /// carrying `first` bytes of its payload.
    fn split(dgram: &[u8], first: usize, id: u16) -> (Vec<u8>, Vec<u8>) {
        let mk = |data: &[u8], off: usize, more: bool| {
            let mut p = dgram[..20].to_vec();
            p.extend_from_slice(data);
            let total = p.len() as u16;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            p[4..6].copy_from_slice(&id.to_be_bytes());
            let flags = (off / 8) as u16 | if more { 0x2000 } else { 0 };
            p[6..8].copy_from_slice(&flags.to_be_bytes());
            p[10..12].copy_from_slice(&[0, 0]);
            let ic = checksum(&p[..20]);
            p[10..12].copy_from_slice(&ic.to_be_bytes());
            p
        };
        (
            mk(&dgram[20..20 + first], 0, true),
            mk(&dgram[20 + first..], first, false),
        )
    }

    /// Put two fragments back together (payloads only), for checking.
    fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut d = a.to_vec();
        d.extend_from_slice(&b[20..]);
        let total = d.len() as u16;
        d[2..4].copy_from_slice(&total.to_be_bytes());
        d[6..8].copy_from_slice(&[0, 0]);
        d
    }

    #[test]
    fn fragments_are_translated_one_by_one() {
        let (nat, i, o) = setup();
        // The second fragment's data looks like a UDP header on purpose.
        let mut payload = vec![0xAA; 8];
        payload.extend_from_slice(&[0x13, 0x88, 0x00, 0x35, 0, 0, 0, 0]);
        let mut d = build_udp(INSIDE, 5000, REMOTE, 53, &payload);
        crate::nat::l4::fill_v4_l4_checksum(&mut d, 20);
        let (f1, f2) = split(&d, 16, 0x4242);
        nat.inside().send(Packet::from_slice(&f1)).unwrap();
        nat.inside().send(Packet::from_slice(&f2)).unwrap();

        let (port, whole) = {
            let out = o.lock().unwrap();
            assert_eq!(out.len(), 2);
            assert_eq!(&out[1][12..16], &PUBLIC.octets());
            assert_eq!(&out[1][20..], &f2[20..], "later fragment data untouched");
            assert_eq!(checksum(&out[1][..20]), 0);
            (src_port(&out[0]), join(&out[0], &out[1]))
        };
        assert!(
            crate::nat::l4::v4_l4_checksum_ok(&whole, 20),
            "datagram checksum"
        );

        // The reply comes back fragmented and out of order.
        let mut r = build_udp(REMOTE, 53, PUBLIC, port, &payload);
        crate::nat::l4::fill_v4_l4_checksum(&mut r, 20);
        let (r1, r2) = split(&r, 16, 0x5151);
        nat.outside().send(Packet::from_slice(&r2)).unwrap();
        assert!(
            i.lock().unwrap().is_empty(),
            "held until the first fragment"
        );
        nat.outside().send(Packet::from_slice(&r1)).unwrap();
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 2);
        let (a, b) = if frag_info(&got[0]).1 == 0 {
            (&got[0], &got[1])
        } else {
            (&got[1], &got[0])
        };
        assert_eq!(&b[16..20], &INSIDE.octets());
        assert_eq!(&b[20..], &r2[20..]);
        let whole = join(a, b);
        assert_eq!(dst_port(&whole), 5000);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&whole, 20));
    }

    #[test]
    fn stray_later_fragment_is_not_read_as_ports() {
        let (nat, i, _o) = setup();
        // A mapping exists on the port the fragment's data would name.
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let mut r = build_udp(REMOTE, 53, PUBLIC, NAT_PORT_MIN, &[0; 16]);
        let fake = [
            0,
            53,
            NAT_PORT_MIN.to_be_bytes()[0],
            NAT_PORT_MIN.to_be_bytes()[1],
        ];
        r[36..40].copy_from_slice(&fake);
        let (_, r2) = split(&r, 8, 0x6161);
        nat.outside().send(Packet::from_slice(&r2)).unwrap();
        assert!(i.lock().unwrap().is_empty());
    }

    /// `dgram` cut into fragments of at most `mtu` bytes, with DF set on
    /// each if `df`.
    fn fragments_of(dgram: &[u8], mtu: usize, id: u16, df: bool) -> Vec<Vec<u8>> {
        let mut d = dgram.to_vec();
        d[4..6].copy_from_slice(&id.to_be_bytes());
        d[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&d[..20]);
        d[10..12].copy_from_slice(&ic.to_be_bytes());
        let crate::fragment::Fragmentation::Fragments(mut parts) =
            crate::fragment::fragment_ipv4(Packet::from_slice(&d), mtu)
        else {
            panic!("not fragmented");
        };
        for p in parts.iter_mut().filter(|_| df) {
            p[6] |= 0x40;
            p[10..12].copy_from_slice(&[0, 0]);
            let ic = checksum(&p[..20]);
            p[10..12].copy_from_slice(&ic.to_be_bytes());
        }
        parts
    }

    /// Reassemble what the NAT sent, checking every piece's header.
    fn reassembled(pieces: &[Vec<u8>], mtu: usize, df: bool) -> Vec<u8> {
        let d = Defragger::new();
        let mut whole = None;
        for p in pieces {
            assert!(p.len() <= mtu, "{} byte piece over {}", p.len(), mtu);
            assert_eq!(checksum(&p[..20]), 0);
            assert_eq!(p[6] & 0x40 != 0, df, "DF carried over");
            whole = d.process(p);
        }
        whole.expect("pieces make a whole datagram")
    }

    #[test]
    fn reassembled_datagrams_are_refragmented_to_their_fragment_size() {
        let (nat, i, o) = setup();
        nat.enable_defrag();
        let payload: Vec<u8> = (0..3000u32).map(|n| n as u8).collect();
        let mut d = build_udp(INSIDE, 5000, REMOTE, 53, &payload);
        crate::nat::l4::fill_v4_l4_checksum(&mut d, 20);
        for f in fragments_of(&d, 1500, 0x7070, false) {
            nat.inside().send(Packet::from_slice(&f)).unwrap();
        }
        let sent = o.lock().unwrap().clone();
        assert_eq!(sent.len(), 3, "sent as three fragments again");
        let whole = reassembled(&sent, 1500, false);
        assert_eq!(&whole[12..16], &PUBLIC.octets());
        assert_eq!(&whole[28..], &payload[..]);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&whole, 20));
        let port = src_port(&whole);

        // Inbound, with the smallest fragments deciding, and DF on all of
        // them: the pieces keep it.
        let mut r = build_udp(REMOTE, 53, PUBLIC, port, &payload);
        crate::nat::l4::fill_v4_l4_checksum(&mut r, 20);
        for f in fragments_of(&r, 576, 0x7171, true) {
            nat.outside().send(Packet::from_slice(&f)).unwrap();
        }
        let got = i.lock().unwrap().clone();
        assert!(got.len() > 1);
        let whole = reassembled(&got, 576, true);
        assert_eq!(&whole[16..20], &INSIDE.octets());
        assert_eq!(dst_port(&whole), 5000);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&whole, 20));
    }

    #[test]
    fn a_forwarded_host_speaking_first_leaves_from_the_forwarded_port() {
        let (nat, i, o) = setup();
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20000, INSIDE, 5000))
            .unwrap();
        let p = build_udp(INSIDE, 5000, REMOTE, 7, b"x");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(src_port(&o.lock().unwrap()[0]), 20000);

        // Another remote reaching the forward, then the first one's reply:
        // both arrive, as the session was never moved.
        let q = build_udp(Ipv4Addr::new(192, 0, 2, 66), 9, PUBLIC, 20000, b"y");
        nat.outside().send(Packet::from_slice(&q)).unwrap();
        let r = build_udp(REMOTE, 7, PUBLIC, 20000, b"z");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert_eq!(i.lock().unwrap().len(), 2);

        // Once the forwarded session idles out, the host comes back on the
        // forwarded port too.
        age_mappings(&nat, UDP_TIMEOUT + Duration::from_secs(1));
        nat.sweep();
        assert_eq!(mapped(&nat), 0);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        assert_eq!(src_port(&o.lock().unwrap()[1]), 20000);
    }

    #[test]
    fn outbound_later_fragments_need_a_translated_first_one() {
        let (nat, _i, o) = setup();
        let mut d = build_udp(INSIDE, 5000, REMOTE, 53, &[0x55; 24]);
        crate::nat::l4::fill_v4_l4_checksum(&mut d, 20);

        // A later fragment with no first one ahead of it goes nowhere,
        // however long it waits.
        let (_, stray) = split(&d, 16, 0x0101);
        nat.inside().send(Packet::from_slice(&stray)).unwrap();
        nat.sweep_at(Instant::now() + Duration::from_secs(60));
        assert!(o.lock().unwrap().is_empty(), "stray fragment sent");

        // Nor does one whose first fragment could not be translated (too
        // short to hold the whole TCP header).
        let t = build_tcp(INSIDE, 40000, REMOTE, 80, 0x02);
        let (bad1, bad2) = split(&t, 8, 0x0202);
        nat.inside().send(Packet::from_slice(&bad1)).unwrap();
        nat.inside().send(Packet::from_slice(&bad2)).unwrap();
        assert!(o.lock().unwrap().is_empty(), "orphaned fragment sent");

        // One that overtakes its first fragment waits for it.
        let (f1, f2) = split(&d, 16, 0x0303);
        nat.inside().send(Packet::from_slice(&f2)).unwrap();
        assert!(o.lock().unwrap().is_empty());
        nat.inside().send(Packet::from_slice(&f1)).unwrap();
        let out = o.lock().unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(frag_info(&out[0]).1, 0);
        assert_eq!(&out[1][12..16], &PUBLIC.octets());
        assert_eq!(&out[1][20..], &f2[20..]);
        assert!(crate::nat::l4::v4_l4_checksum_ok(
            &join(&out[0], &out[1]),
            20
        ));
    }

    #[test]
    fn an_idle_mapping_not_yet_swept_does_not_hold_its_port() {
        let (nat, i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        age_mappings(&nat, UDP_TIMEOUT + Duration::from_secs(1));

        // Nothing has swept, but the mapping is over: the port is free.
        let server = Ipv4Addr::new(10, 0, 0, 50);
        nat.add_port_forward(PortForward::new(PROTO_UDP, port, server, 53))
            .unwrap();
        let q = build_udp(REMOTE, 53, PUBLIC, port, b"a");
        nat.outside().send(Packet::from_slice(&q)).unwrap();
        assert_eq!(&i.lock().unwrap()[0][16..20], &server.octets());
    }

    #[test]
    fn an_idle_mapping_not_yet_swept_does_not_block_an_expectation() {
        let (nat, i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        age_mappings(&nat, UDP_TIMEOUT + Duration::from_secs(1));

        // For another host, on the idle mapping's port...
        let other = Ipv4Addr::new(10, 0, 0, 6);
        nat.add_expectation(Expectation::new(PROTO_UDP, other, 7000, port, soon()));
        // ... and for the idle mapping's own endpoint, on another port.
        nat.add_expectation(Expectation::new(PROTO_UDP, INSIDE, 5000, 30000, soon()));
        let q = build_udp(REMOTE, 53, PUBLIC, port, b"a");
        nat.outside().send(Packet::from_slice(&q)).unwrap();
        let r = build_udp(REMOTE, 53, PUBLIC, 30000, b"b");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        let got = i.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            (&got[0][16..20], dst_port(&got[0])),
            (&other.octets()[..], 7000)
        );
        assert_eq!(
            (&got[1][16..20], dst_port(&got[1])),
            (&INSIDE.octets()[..], 5000)
        );
    }

    #[test]
    fn an_alg_opens_an_existing_outbound_mapping_only_for_a_while() {
        let (nat, _i, o) = setup();
        let p = build_udp(INSIDE, 5000, REMOTE, 53, b"q");
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let port = src_port(&o.lock().unwrap()[0]);
        assert_eq!(nat.create_mapping(PROTO_UDP, INSIDE, 5000), Some(port));

        // The remote the ALG announced the port to is tracked.
        let callee = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 4000);
        let r = build_udp(*callee.ip(), callee.port(), PUBLIC, port, b"m");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        let k = |nat: &Nat, a: &SocketAddrV4| {
            let inner = nat.inner.lock().unwrap();
            inner.mappings.values().next().unwrap().peers.contains(a)
        };
        assert!(k(&nat, &callee));

        // Past the window, a stranger no longer is.
        nat.inner
            .lock()
            .unwrap()
            .mappings
            .values_mut()
            .for_each(|m| m.open_until = Some(Instant::now() - Duration::from_secs(1)));
        let stranger = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 66), 4444);
        let r = build_udp(*stranger.ip(), stranger.port(), PUBLIC, port, b"x");
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert!(!k(&nat, &stranger), "mapping left open for good");

        // A mapping the ALG made itself is open for good, as before.
        nat.create_mapping(PROTO_UDP, INSIDE, 6000).unwrap();
        let inner = nat.inner.lock().unwrap();
        let m = inner
            .mappings
            .values()
            .find(|m| m.key.port == 6000)
            .unwrap();
        assert!(m.open);
    }

    #[test]
    fn the_endpoint_index_follows_forwards() {
        let (nat, _i, o) = setup();
        let first_port = |nat: &Nat, o: &StdMutex<Vec<Vec<u8>>>| {
            let p = build_udp(INSIDE, 53, REMOTE, 9, b"x");
            nat.inside().send(Packet::from_slice(&p)).unwrap();
            src_port(&o.lock().unwrap().pop().unwrap())
        };
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20000, INSIDE, 53))
            .unwrap();
        assert_eq!(first_port(&nat, &o), 20000);

        // Moved to another port: the endpoint follows.
        nat.remove_port_forward(PROTO_UDP, 20000);
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20001, INSIDE, 53))
            .unwrap();
        assert_eq!(first_port(&nat, &o), 20001);

        // A lapsed forward no longer claims the endpoint.
        nat.remove_port_forward(PROTO_UDP, 20001);
        let past = Instant::now() - Duration::from_secs(1);
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20002, INSIDE, 53).expires(past))
            .unwrap();
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20003, INSIDE, 53))
            .unwrap();
        assert_eq!(first_port(&nat, &o), 20003);

        // Handed to another endpoint: this one is free again.
        nat.remove_port_forward(PROTO_UDP, 20003);
        let other = Ipv4Addr::new(10, 0, 0, 9);
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20004, INSIDE, 53))
            .unwrap();
        nat.remove_port_forward(PROTO_UDP, 20004);
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20004, other, 53))
            .unwrap();
        nat.add_port_forward(PortForward::new(PROTO_UDP, 20005, INSIDE, 53))
            .unwrap();
        let inner = nat.inner.lock().unwrap();
        assert_eq!(
            inner.forwards.by_endpoint.len(),
            inner.forwards.by_port.len()
        );
    }

    /// Run `f` on its own thread and fail if it does not return: a
    /// deadlock would otherwise hang the test run.
    fn within_3s(f: impl FnOnce() + Send + 'static) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).is_ok(),
            "deadlocked"
        );
    }

    #[test]
    fn hairpin_to_a_synchronously_answering_host_does_not_deadlock() {
        within_3s(|| {
            let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
            let server = Ipv4Addr::new(10, 0, 0, 50);
            nat.add_port_forward(PortForward::new(PROTO_TCP, 8080, server, 80))
                .unwrap();
            // The inside network answers the forwarded server's SYN from
            // within the delivery, as a virtual host on the same thread would.
            let got = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
            let (w, g) = (Arc::downgrade(&nat), got.clone());
            nat.inside().set_handler(Arc::new(move |p| {
                let p = p.as_bytes().to_vec();
                g.lock().unwrap().push(p.clone());
                if p[16..20] == server.octets() {
                    let synack = build_tcp(server, 80, PUBLIC, src_port(&p), 0x12);
                    w.upgrade()
                        .unwrap()
                        .inside()
                        .send(Packet::from_slice(&synack))?;
                }
                Ok(())
            }));
            let syn = build_tcp(INSIDE, 40000, PUBLIC, 8080, 0x02);
            nat.inside().send(Packet::from_slice(&syn)).unwrap();
            let got = got.lock().unwrap();
            assert_eq!(got.len(), 2);
            assert_eq!(&got[1][16..20], &INSIDE.octets());
            assert_eq!(dst_port(&got[1]), 40000);
        });
    }

    #[test]
    fn a_panicking_handler_does_not_break_later_sends() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let n = Arc::new(AtomicU64::new(0));
        let n2 = n.clone();
        nat.outside().set_handler(Arc::new(move |_| {
            if n2.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("handler bug");
            }
            Ok(())
        }));
        let p = build_udp(INSIDE, 1000, Ipv4Addr::new(8, 8, 8, 8), 53, b"x");
        let send = || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                nat.inside().send(Packet::from_slice(&p))
            }))
        };
        // The panic is the caller's to see; it just must not poison anything.
        assert!(send().is_err());
        assert!(send().is_ok());
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }
}

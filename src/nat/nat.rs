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
use crate::nat::track::{Peers, SeqAdj};
use crate::time::Instant;
use crate::{
    IpPrefix, L3Connector, L3Device, L3Handler, Packet, Result, checksum, connect_l3,
    incremental_update,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

const NAT_PORT_MIN: u16 = 10000;
const NAT_PORT_MAX: u16 = 65535;
/// Cap on pending expectations. ALGs add them on packets remote peers
/// control (TFTP requests, SDP offers), so the table must not grow unbounded.
const MAX_EXPECTATIONS: usize = 1024;

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

#[derive(Debug)]
struct Mapping {
    key: NatKey,
    outside_port: u16,
    last_active: Instant,
    peers: Peers,
}

impl Mapping {
    fn new(key: NatKey, outside_port: u16, now: Instant) -> Mapping {
        Mapping {
            key,
            outside_port,
            last_active: now,
            peers: Peers::default(),
        }
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

    /// Self-reference held in the `Arc` returned by `new`. The two side
    /// devices need to find their parent without taking an `Arc<Nat>`
    /// directly (avoids a reference cycle through `Arc<Self>`).
    self_ref: Mutex<Weak<Nat>>,

    /// Set once an ALG has resized a TCP payload; until then no segment
    /// needs its sequence numbers looked at.
    seqadj_used: AtomicBool,

    /// Inbound fragmented datagrams (when not reassembling): which inside
    /// host each one's first fragment went to, keyed by source, IP ID and
    /// protocol, so the rest can follow.
    frags: Mutex<FragTable<(Ipv4Addr, u16, u8), (u64, Ipv4Addr)>>,
}

struct NatInner {
    mappings: HashMap<NatKey, Mapping>,
    reverse: HashMap<NatRevKey, NatKey>,
    next_port: u16,
    helpers: Vec<Arc<dyn HelperKind>>,
    forwards: HashMap<NatRevKey, PortForward>,
    expectations: Vec<Expectation>,
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
        let inside = Arc::new(NatSide::new(true, inside_addr));
        let outside = Arc::new(NatSide::new(false, outside_addr));
        let nat = Arc::new(Nat {
            inside: inside.clone(),
            outside: outside.clone(),
            inner: Mutex::new(NatInner {
                mappings: HashMap::new(),
                reverse: HashMap::new(),
                next_port: NAT_PORT_MIN,
                helpers: Vec::new(),
                forwards: HashMap::new(),
                expectations: Vec::new(),
            }),
            defragger: Mutex::new(None),
            ns_counter: AtomicU64::new(0),
            ns_sides: Mutex::new(HashMap::new()),
            self_ref: Mutex::new(Weak::new()),
            seqadj_used: AtomicBool::new(false),
            frags: Mutex::new(FragTable::default()),
        });
        *nat.self_ref.lock().unwrap() = Arc::downgrade(&nat);
        // Wire each side back to the NAT.
        inside.set_parent(Arc::downgrade(&nat));
        outside.set_parent(Arc::downgrade(&nat));
        nat
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

    /// IPv4 address bound to the outside interface.
    pub fn outside_addr(&self) -> Option<Ipv4Addr> {
        match self.outside.addr().addr() {
            IpAddr::V4(a) => Some(a),
            _ => None,
        }
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
        if inner.reverse.get(&rk).is_some_and(|k| *k != target) || inner.forwards.contains_key(&rk)
        {
            return;
        }
        if let Some(old) = inner.expectations.iter_mut().find(|o| {
            o.proto == e.proto
                && o.outside_port == e.outside_port
                && o.namespace == e.namespace
                && o.inside_ip == e.inside_ip
                && o.inside_port == e.inside_port
                && o.remote_ip == e.remote_ip
                && o.remote_port == e.remote_port
        }) {
            old.expires = old.expires.max(e.expires);
            return;
        }
        if inner.expectations.len() >= MAX_EXPECTATIONS {
            let now = Instant::now();
            inner.expectations.retain(|e| now <= e.expires);
            // Still full: the one closest to lapsing is the least likely to
            // be used, so it makes room.
            if inner.expectations.len() >= MAX_EXPECTATIONS
                && let Some(pos) =
                    (0..inner.expectations.len()).min_by_key(|&i| inner.expectations[i].expires)
            {
                inner.expectations.swap_remove(pos);
            }
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
    /// the forward's host. Also fails with `AddrInUse` if another port is
    /// already forwarded to the same inside endpoint: the NAT gives each
    /// inside endpoint a single public port, from which all its traffic
    /// leaves.
    pub fn add_port_forward(&self, pf: PortForward) -> Result<()> {
        let rk = NatRevKey {
            proto: pf.proto,
            port: pf.outside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        let now = Instant::now();
        // Lapsed forwards are purged first, so they hold no port or endpoint.
        let lapsed: Vec<NatRevKey> = inner
            .forwards
            .iter()
            .filter(|(_, f)| f.expires.is_some_and(|e| e < now))
            .map(|(k, _)| *k)
            .collect();
        for k in lapsed {
            inner.forwards.remove(&k);
            Self::remove_mapping_at_locked(inner, k);
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
        let dynamic = inner.reverse.contains_key(&rk) && !inner.forwards.contains_key(&rk);
        // An inside endpoint has one mapping, so one public port (RFC 5382
        // REQ-1: endpoint-independent mapping). A second forward to it
        // would move that mapping to whichever port saw traffic last,
        // resetting its sessions and sending every reply from that port.
        let taken = inner.forwards.iter().any(|(k, f)| {
            *k != rk
                && f.proto == pf.proto
                && f.namespace == pf.namespace
                && f.inside_ip == pf.inside_ip
                && f.inside_port == pf.inside_port
        });
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
        if !same {
            Self::remove_mapping_at_locked(inner, rk);
        }
        inner.forwards.insert(rk, pf);
        Ok(())
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

    /// Create (or reuse) a mapping for a helper-managed connection on the
    /// NAT's own inside interface. Returns the outside port, or `None` if the
    /// port pool is exhausted.
    pub fn create_mapping(&self, proto: u8, inside_ip: Ipv4Addr, inside_port: u16) -> Option<u16> {
        self.create_mapping_in(0, proto, inside_ip, inside_port)
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
        Some(Self::get_or_create_mapping_locked(&mut inner, k)?.outside_port)
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
                    inner.mappings.get_mut(&k).unwrap().last_active = now;
                }
                return Some(p);
            }
            (None, None) => {}
            _ => return None,
        }
        let p = Self::alloc_pair_locked(&mut inner)?;
        for (k, port) in [(k1, p), (k2, p + 1)] {
            inner.reverse.insert(NatRevKey { proto, port }, k);
            inner.mappings.insert(k, Mapping::new(k, port, now));
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

    /// Bind inside endpoint `k` to outside port `rk.port`, which must be free.
    ///
    /// The tables hold one mapping per inside endpoint. If `k` already has one
    /// on another port, `displace` decides: a port forward is the endpoint's
    /// configured public identity and replaces it (old reverse entry
    /// included); an expectation must not break a live session and is
    /// refused.
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
        inner
            .mappings
            .insert(k, Mapping::new(k, rk.port, Instant::now()));
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

        let port = Self::alloc_port_locked(inner)?;
        let m = Mapping::new(k, port, now);
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

    fn alloc_port_locked(inner: &mut NatInner) -> Option<u16> {
        let now = Instant::now();
        let start = inner.next_port;
        loop {
            let p = inner.next_port;
            inner.next_port = if inner.next_port == NAT_PORT_MAX {
                NAT_PORT_MIN
            } else {
                inner.next_port + 1
            };
            if !Self::port_in_use_locked(inner, p, now) {
                return Some(p);
            }
            if inner.next_port == start {
                return None;
            }
        }
    }

    /// An even outside port that is free along with the next one.
    fn alloc_pair_locked(inner: &mut NatInner) -> Option<u16> {
        let now = Instant::now();
        let pairs = (NAT_PORT_MAX - NAT_PORT_MIN).div_ceil(2);
        // Start at the next even port; the range starts even, so a pair
        // never straddles its end.
        let mut p = inner.next_port.saturating_add(1) & !1;
        for _ in 0..pairs {
            if !(NAT_PORT_MIN..NAT_PORT_MAX).contains(&p) {
                p = NAT_PORT_MIN;
            }
            if !Self::port_in_use_locked(inner, p, now)
                && !Self::port_in_use_locked(inner, p + 1, now)
            {
                inner.next_port = p.checked_add(2).unwrap_or(NAT_PORT_MIN);
                return Some(p);
            }
            p = p.saturating_add(2);
        }
        None
    }

    /// Whether outside port `p` is taken, for any protocol. Ports a forward
    /// or a pending expectation will receive traffic on count too, or that
    /// traffic would reach a new session.
    fn port_in_use_locked(inner: &NatInner, p: u16, now: Instant) -> bool {
        [PROTO_TCP, PROTO_UDP, PROTO_ICMP].iter().any(|&proto| {
            let rk = NatRevKey { proto, port: p };
            inner.reverse.contains_key(&rk) || inner.forwards.contains_key(&rk)
        }) || inner
            .expectations
            .iter()
            .any(|e| e.outside_port == p && now <= e.expires)
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
            now <= e.expires
                && e.proto == proto
                && e.outside_port == outside_port
                && (e.remote_ip.is_unspecified() || e.remote_ip == remote_ip)
                && (e.remote_port == 0 || e.remote_port == remote_port)
        })?;
        Some(inner.expectations.remove(pos))
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

    /// Sweep stale entries — call on a timer if you want strict TTL behaviour.
    /// (We omit the maintenance thread; callers can spawn one if needed.)
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    fn sweep_at(&self, now: Instant) {
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
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
        self.frags.lock().unwrap().expire(now);
        // Also sweep the defragger if enabled.
        if let Some(d) = self.defragger.lock().unwrap().clone() {
            d.sweep();
        }
    }

    fn cleanup_namespace(&self, ns: u64) {
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        // Namespace IDs are never reused, so anything aimed at this one is
        // dead weight from now on.
        inner.expectations.retain(|e| e.namespace != ns);
        inner.forwards.retain(|_, pf| pf.namespace != ns);
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
        let group = dst_ip.is_multicast() || dst_ip.is_broadcast();
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

        if offset != 0 {
            self.outbound_later_fragment(pkt);
            return;
        }
        let whole = !more;

        let proto = pkt[9];
        match proto {
            PROTO_TCP | PROTO_UDP => {
                if pkt.len() < ihl + 4 {
                    return;
                }
                self.outbound_tcpudp(ns, pkt, ihl, proto, whole, fmax);
            }
            PROTO_ICMP => {
                if pkt.len() < ihl + 8 {
                    return;
                }
                self.outbound_icmp(ns, pkt, ihl, whole, fmax);
            }
            _ => {}
        }
    }

    /// A non-first fragment going out: it only needs the source address the
    /// first fragment got. (A fragment to the NAT's own address is hairpinned
    /// like the rest of its datagram.)
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
        self.outside.deliver(Packet::from_slice(&out));
    }

    /// Translate an outbound TCP/UDP datagram, or the first fragment of one
    /// (`whole` false). `fmax` is set if it was reassembled.
    fn outbound_tcpudp(
        &self,
        ns: u64,
        pkt: &[u8],
        ihl: usize,
        proto: u8,
        whole: bool,
        fmax: Option<FragMax>,
    ) {
        if !whole && !l4_header_in(pkt, ihl, proto) {
            return;
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
                None => return,
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
            None => return,
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
            return;
        }
        emit(&out, fmax, |p| self.outside.deliver(p));
    }

    fn outbound_icmp(&self, ns: u64, pkt: &[u8], ihl: usize, whole: bool, fmax: Option<FragMax>) {
        match pkt[ihl] {
            8 => {}
            // Errors are small; a fragmented one is not worth reassembling.
            3 | 11 | 12 if whole => return self.outbound_icmp_error(ns, pkt, ihl),
            _ => return,
        }
        let Some(outside_ip) = self.outside_addr() else {
            return;
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
            return;
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
                None => return,
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

        emit(&out, fmax, |p| self.outside.deliver(p));
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
        self.outside.deliver(Packet::from_slice(&out));
    }

    // ---------- Inbound (outside -> inside) ----------

    fn handle_inbound(&self, pkt_in: &[u8]) {
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
                if !Self::install_mapping_locked(&mut inner, k, rk, false) {
                    return None;
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
            let tracked = inner.mappings.get_mut(&k).is_some_and(|m| {
                m.last_active = now;
                m.peers.note(peer, false, tcp_flags(pkt, ihl, proto), now);
                m.peers.contains(&peer)
            });
            (k, dst_port, tracked)
        };

        let mut out = pkt.to_vec();
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
                    if let Some(m) = inner.mappings.get_mut(&k) {
                        m.last_active = Instant::now();
                        let peer =
                            SocketAddrV4::new(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]), 0);
                        m.peers.note(peer, false, None, m.last_active);
                    }
                    k
                };
                let mut out = pkt.to_vec();
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
            _ => None,
        }
    }

    /// Translate an ICMP error about a packet this NAT sent out (RFC 5508
    /// §7): the outer destination and the embedded packet's source go back to
    /// the inside endpoint, with every checksum that covers them patched.
    fn inbound_icmp_error(&self, pkt: &[u8], outer_ihl: usize, fmax: Option<FragMax>) {
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
        let side = Arc::new(NatNsSide::new(ns, self.inside.addr()));
        side.set_parent(self.self_ref.lock().unwrap().clone());

        // Bidirectional wire-up.
        connect_l3(side.clone() as Arc<dyn L3Device>, dev);

        self.ns_sides.lock().unwrap().insert(ns, side);

        let self_ref = self.self_ref.lock().unwrap().clone();
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
    parent: Mutex<Weak<Nat>>,
}

impl NatSide {
    fn new(is_inside: bool, addr: IpPrefix) -> NatSide {
        NatSide {
            is_inside,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            parent: Mutex::new(Weak::new()),
        }
    }

    fn set_parent(&self, w: Weak<Nat>) {
        *self.parent.lock().unwrap() = w;
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
        if let Some(nat) = self.parent.lock().unwrap().upgrade() {
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
    parent: Mutex<Weak<Nat>>,
}

impl NatNsSide {
    fn new(ns: u64, addr: IpPrefix) -> NatNsSide {
        NatNsSide {
            ns,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            parent: Mutex::new(Weak::new()),
        }
    }
    fn set_parent(&self, w: Weak<Nat>) {
        *self.parent.lock().unwrap() = w;
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
        if let Some(nat) = self.parent.lock().unwrap().upgrade() {
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

/// The More Fragments flag and fragment offset (in bytes) of an IPv4 packet.
pub(crate) fn frag_info(pkt: &[u8]) -> (bool, usize) {
    let v = u16::from_be_bytes([pkt[6], pkt[7]]);
    (v & 0x2000 != 0, (v & 0x1FFF) as usize * 8)
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
    use crate::{IpPrefix, L3Device, Packet};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

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
        for _ in 0..16 {
            let port = nat
                .create_mapping(PROTO_TCP, Ipv4Addr::new(10, 0, 0, 2), 1234)
                .unwrap();
            assert!((NAT_PORT_MIN..=NAT_PORT_MAX).contains(&port));
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
        // A fresh NAT hands out its first port.
        let p = udp_zero_after_xlat(
            inside,
            5000,
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
        let p = build_udp(inside, 5000, remote, 53, &[1]);
        nat.inside().send(Packet::from_slice(&p)).unwrap();
        let reply = udp_zero_after_xlat(
            remote,
            53,
            outside,
            NAT_PORT_MIN,
            (remote, 53, inside, 5000),
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
            .values_mut()
            .for_each(|pf| pf.expires = Some(past));

        nat.sweep();
        let inner = nat.inner.lock().unwrap();
        assert!(inner.expectations.is_empty());
        assert!(inner.forwards.is_empty());
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
        // The quoted datagram is exactly what the inside host sent.
        assert_eq!(inner, &p[..]);
        assert_eq!(checksum(&inner[..20]), 0, "inner IP checksum");
        assert!(
            crate::nat::l4::v4_l4_checksum_ok(inner, 20),
            "inner UDP checksum"
        );
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
        for e in out.iter() {
            assert_eq!(&e[12..16], &PUBLIC.octets(), "outer source");
            assert_eq!(&e[16..20], &REMOTE.octets());
            assert_eq!(checksum(&e[..20]), 0, "outer IP checksum");
            assert_eq!(checksum(&e[20..]), 0, "outer ICMP checksum");
            // The quoted datagram is what the remote sent.
            assert_eq!(&e[28..], &r[..]);
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
}

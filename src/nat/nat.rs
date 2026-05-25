//! IPv4 5-tuple NAT.
//!
//! Port of `nat.go`. Inside faces the private network (gateway role); outside
//! faces the upstream network and carries a public IP.
//!
//! Connection tracking is keyed by `(namespace, proto, src_ip, src_port)` for
//! TCP/UDP, with `src_port` substituted by the ICMP identifier for ICMP echo.
//! Reverse lookup is keyed by `(proto, outside_port)`.

use crate::nat::defrag::Defragger;
use crate::nat::helper::{
    Expectation, Helper, LocalHelper, NatMapping, PacketHelper, PortForward, PROTO_ICMP,
    PROTO_TCP, PROTO_UDP,
};
use crate::{
    checksum, connect_l3, IpPrefix, L3Connector, L3Device, L3Handler, Packet, Result,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

const NAT_PORT_MIN: u16 = 10000;
const NAT_PORT_MAX: u16 = 65535;
pub(crate) const NAT_TCP_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const NAT_UDP_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const NAT_ICMP_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const NAT_TCP_FIN_GRACE: Duration = Duration::from_secs(30);

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
    fin_seen: bool,
    fin_time: Option<Instant>,
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
    pub fn add_expectation(&self, e: Expectation) {
        self.inner.lock().unwrap().expectations.push(e);
    }

    /// Find and remove the first non-expired expectation matching the given
    /// inside target `(proto, inside_ip, inside_port)`, returning it.
    ///
    /// Used by ALGs whose related traffic is not keyed by the inbound 5-tuple
    /// matched in [`Self::add_expectation`]'s normal path — notably the PPTP
    /// GRE marker, where the NAT core does not yet forward protocol 47. Tests
    /// also use it to assert that an expectation was registered.
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
    pub fn add_port_forward(&self, pf: PortForward) -> Result<()> {
        let rk = NatRevKey {
            proto: pf.proto,
            port: pf.outside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner.forwards.get(&rk) {
            if existing.inside_ip != pf.inside_ip {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "port already forwarded to another host",
                ));
            }
        }
        inner.forwards.insert(rk, pf);
        Ok(())
    }

    /// Remove a previously-added port forward. No-op if absent.
    pub fn remove_port_forward(&self, proto: u8, outside_port: u16) {
        let rk = NatRevKey {
            proto,
            port: outside_port,
        };
        self.inner.lock().unwrap().forwards.remove(&rk);
    }

    /// Snapshot of active port forwards (expired ones filtered out).
    pub fn list_port_forwards(&self) -> Vec<PortForward> {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap();
        inner
            .forwards
            .values()
            .filter(|pf| pf.expires.map_or(true, |e| e > now))
            .cloned()
            .collect()
    }

    /// Create (or reuse) a mapping for a helper-managed connection. Returns
    /// the outside port, or `None` if the port pool is exhausted.
    pub fn create_mapping(&self, proto: u8, inside_ip: Ipv4Addr, inside_port: u16) -> Option<u16> {
        let k = NatKey {
            ns: 0,
            proto,
            ip: inside_ip,
            port: inside_port,
        };
        let mut inner = self.inner.lock().unwrap();
        Some(Self::get_or_create_mapping_locked(&mut inner, k)?.outside_port)
    }

    /// Inject a packet onto the inside interface (used by helpers that
    /// synthesize traffic destined for an inside host).
    pub fn send_inside(&self, pkt: &Packet) {
        self.inside.deliver(pkt);
    }

    // -- Internal --------------------------------------------------------

    fn get_or_create_mapping_locked<'a>(
        inner: &'a mut NatInner,
        k: NatKey,
    ) -> Option<&'a mut Mapping> {
        let now = Instant::now();
        if inner.mappings.contains_key(&k) {
            let m = inner.mappings.get_mut(&k).unwrap();
            m.last_active = now;
            return Some(m);
        }

        let port = Self::alloc_port_locked(inner)?;
        let m = Mapping {
            key: k,
            outside_port: port,
            last_active: now,
            fin_seen: false,
            fin_time: None,
        };
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
        let start = inner.next_port;
        loop {
            let p = inner.next_port;
            inner.next_port = if inner.next_port >= NAT_PORT_MAX {
                NAT_PORT_MIN
            } else {
                inner.next_port + 1
            };
            let in_use = [PROTO_TCP, PROTO_UDP, PROTO_ICMP]
                .iter()
                .any(|&proto| inner.reverse.contains_key(&NatRevKey { proto, port: p }));
            if !in_use {
                return Some(p);
            }
            if inner.next_port == start {
                return None;
            }
        }
    }

    fn match_expectation_locked(
        inner: &mut NatInner,
        proto: u8,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<Expectation> {
        let now = Instant::now();
        let pos = inner.expectations.iter().position(|e| {
            now <= e.expires
                && e.proto == proto
                && (e.remote_ip.is_unspecified() || e.remote_ip == remote_ip)
                && (e.remote_port == 0 || e.remote_port == remote_port)
        })?;
        Some(inner.expectations.remove(pos))
    }

    fn match_forward<'a>(
        inner: &'a mut NatInner,
        proto: u8,
        outside_port: u16,
    ) -> Option<&'a PortForward> {
        let rk = NatRevKey {
            proto,
            port: outside_port,
        };
        let now = Instant::now();
        let expired = inner
            .forwards
            .get(&rk)
            .and_then(|pf| pf.expires)
            .map_or(false, |e| e < now);
        if expired {
            inner.forwards.remove(&rk);
            return None;
        }
        inner.forwards.get(&rk)
    }

    /// Iterate helpers and let any [`LocalHelper`] consume the packet.
    fn handle_local(&self, pkt: &Packet) -> bool {
        let helpers: Vec<_> = {
            let inner = self.inner.lock().unwrap();
            inner.helpers.clone()
        };
        for h in helpers {
            if let Some(lh) = h.as_local() {
                if lh.handle_local(self, pkt) {
                    return true;
                }
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
            if let Some(ph) = h.as_packet() {
                if ph.match_outbound(proto, dst_port) {
                    out = ph.process_outbound(self, out, m);
                }
            }
        }
        out
    }

    fn helper_inbound(&self, pkt: Vec<u8>, m: &NatMapping, proto: u8, dst_port: u16) -> Vec<u8> {
        let helpers: Vec<_> = {
            let inner = self.inner.lock().unwrap();
            if inner.helpers.is_empty() {
                return pkt;
            }
            inner.helpers.clone()
        };
        let mut out = pkt;
        for h in helpers {
            if let Some(ph) = h.as_packet() {
                if ph.match_outbound(proto, dst_port) {
                    out = ph.process_inbound(self, out, m);
                }
            }
        }
        out
    }

    /// Sweep stale entries — call on a timer if you want strict TTL behaviour.
    /// (We omit the maintenance thread; callers can spawn one if needed.)
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        inner.mappings.retain(|k, m| {
            let timeout = match k.proto {
                PROTO_TCP => {
                    if m.fin_seen && m.fin_time.map_or(false, |t| now - t > NAT_TCP_FIN_GRACE) {
                        Duration::from_secs(0)
                    } else {
                        NAT_TCP_TIMEOUT
                    }
                }
                PROTO_UDP => NAT_UDP_TIMEOUT,
                PROTO_ICMP => NAT_ICMP_TIMEOUT,
                _ => NAT_UDP_TIMEOUT,
            };
            if timeout.is_zero() || now - m.last_active > timeout {
                inner.reverse.remove(&NatRevKey {
                    proto: k.proto,
                    port: m.outside_port,
                });
                false
            } else {
                true
            }
        });
        // Also sweep the defragger if enabled.
        if let Some(d) = self.defragger.lock().unwrap().clone() {
            d.sweep();
        }
    }

    fn cleanup_namespace(&self, ns: u64) {
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
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
        let pkt: &[u8] = if let Some(d) = self.defragger.lock().unwrap().clone() {
            match d.process(pkt_in) {
                Some(v) => {
                    owned = v;
                    &owned
                }
                None => return,
            }
        } else {
            pkt_in
        };

        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return;
        }

        // Local helper interception (packets to the NAT's own inside IP).
        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        if Some(dst_ip) == self.inside_addr() && self.handle_local(Packet::from_slice(pkt)) {
            return;
        }

        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 {
            return;
        }
        let proto = pkt[9];
        match proto {
            PROTO_TCP | PROTO_UDP => {
                if pkt.len() < ihl + 4 {
                    return;
                }
                self.outbound_tcpudp(ns, pkt, ihl, proto);
            }
            PROTO_ICMP => {
                if pkt.len() < ihl + 8 {
                    return;
                }
                self.outbound_icmp(ns, pkt, ihl);
            }
            _ => {}
        }
    }

    fn outbound_tcpudp(&self, ns: u64, pkt: &[u8], ihl: usize, proto: u8) {
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let k = NatKey {
            ns,
            proto,
            ip: src_ip,
            port: src_port,
        };
        let (outside_port, mapping_key) = {
            let mut inner = self.inner.lock().unwrap();
            let m = match Self::get_or_create_mapping_locked(&mut inner, k) {
                Some(m) => m,
                None => return,
            };
            if proto == PROTO_TCP && pkt.len() >= ihl + 14 {
                let flags = pkt[ihl + 13];
                if flags & 0x05 != 0 && !m.fin_seen {
                    m.fin_seen = true;
                    m.fin_time = Some(Instant::now());
                }
            }
            (m.outside_port, m.key)
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
            update_l4_checksum(&mut out, ihl + 16, old_src_ip, new_src_ip, old_port, outside_port);
        } else if proto == PROTO_UDP && out.len() >= ihl + 8 {
            let csum_off = ihl + 6;
            let cur = u16::from_be_bytes([out[csum_off], out[csum_off + 1]]);
            if cur != 0 {
                update_l4_checksum(&mut out, csum_off, old_src_ip, new_src_ip, old_port, outside_port);
            }
        }

        let dst_port = u16::from_be_bytes([out[ihl + 2], out[ihl + 3]]);
        let nm = NatMapping {
            proto: mapping_key.proto,
            inside_ip: IpAddr::V4(mapping_key.ip),
            inside_port: mapping_key.port,
            outside_port,
        };
        let out = self.helper_outbound(out, &nm, proto, dst_port);
        self.outside.deliver(Packet::from_slice(&out));
    }

    fn outbound_icmp(&self, ns: u64, pkt: &[u8], ihl: usize) {
        let icmp_type = pkt[ihl];
        if icmp_type != 8 {
            return; // outbound: only Echo Request
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
                Some(m) => m.outside_port,
                None => return,
            }
        };

        let outside_ip = match self.outside_addr() {
            Some(a) => a,
            None => return,
        };

        let mut out = pkt.to_vec();
        let old_src_ip: [u8; 4] = out[12..16].try_into().unwrap();
        let new_src_ip = outside_ip.octets();
        out[12..16].copy_from_slice(&new_src_ip);

        let old_id = u16::from_be_bytes([out[ihl + 4], out[ihl + 5]]);
        out[ihl + 4..ihl + 6].copy_from_slice(&outside_port.to_be_bytes());

        update_ip_checksum(&mut out, old_src_ip, new_src_ip);
        update_icmp_checksum(&mut out, ihl, old_id, outside_port);

        self.outside.deliver(Packet::from_slice(&out));
    }

    // ---------- Inbound (outside -> inside) ----------

    fn handle_inbound(&self, pkt_in: &[u8]) {
        let owned;
        let pkt: &[u8] = if let Some(d) = self.defragger.lock().unwrap().clone() {
            match d.process(pkt_in) {
                Some(v) => {
                    owned = v;
                    &owned
                }
                None => return,
            }
        } else {
            pkt_in
        };

        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return;
        }
        if self.handle_local(Packet::from_slice(pkt)) {
            return;
        }
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 {
            return;
        }
        let proto = pkt[9];
        match proto {
            PROTO_TCP | PROTO_UDP => {
                if pkt.len() < ihl + 4 {
                    return;
                }
                self.inbound_tcpudp(pkt, ihl, proto);
            }
            PROTO_ICMP => {
                if pkt.len() < ihl + 8 {
                    return;
                }
                self.inbound_icmp(pkt, ihl);
            }
            _ => {}
        }
    }

    fn inbound_tcpudp(&self, pkt: &[u8], ihl: usize, proto: u8) {
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);

        let rk = NatRevKey {
            proto,
            port: dst_port,
        };
        let now = Instant::now();
        let (mapping_key, outside_port) = {
            let mut inner = self.inner.lock().unwrap();
            // Existing mapping?
            if let Some(k) = inner.reverse.get(&rk).copied() {
                if let Some(m) = inner.mappings.get_mut(&k) {
                    m.last_active = now;
                }
                (k, dst_port)
            } else if let Some(e) = Self::match_expectation_locked(&mut inner, proto, src_ip, src_port) {
                let k = NatKey {
                    ns: 0,
                    proto,
                    ip: e.inside_ip,
                    port: e.inside_port,
                };
                inner.mappings.insert(
                    k,
                    Mapping {
                        key: k,
                        outside_port: dst_port,
                        last_active: now,
                        fin_seen: false,
                        fin_time: None,
                    },
                );
                inner.reverse.insert(rk, k);
                (k, dst_port)
            } else if let Some(pf) = Self::match_forward(&mut inner, proto, dst_port) {
                let pf = pf.clone();
                let k = NatKey {
                    ns: 0,
                    proto,
                    ip: pf.inside_ip,
                    port: pf.inside_port,
                };
                inner.mappings.insert(
                    k,
                    Mapping {
                        key: k,
                        outside_port: dst_port,
                        last_active: now,
                        fin_seen: false,
                        fin_time: None,
                    },
                );
                inner.reverse.insert(rk, k);
                (k, dst_port)
            } else {
                return;
            }
        };

        if proto == PROTO_TCP && pkt.len() >= ihl + 14 {
            let flags = pkt[ihl + 13];
            if flags & 0x05 != 0 {
                let mut inner = self.inner.lock().unwrap();
                if let Some(m) = inner.mappings.get_mut(&mapping_key) {
                    if !m.fin_seen {
                        m.fin_seen = true;
                        m.fin_time = Some(Instant::now());
                    }
                }
            }
        }

        let mut out = pkt.to_vec();
        let old_dst_ip: [u8; 4] = out[16..20].try_into().unwrap();
        let new_dst_ip = mapping_key.ip.octets();
        out[16..20].copy_from_slice(&new_dst_ip);

        let old_port = u16::from_be_bytes([out[ihl + 2], out[ihl + 3]]);
        out[ihl + 2..ihl + 4].copy_from_slice(&mapping_key.port.to_be_bytes());

        update_ip_checksum(&mut out, old_dst_ip, new_dst_ip);

        if proto == PROTO_TCP && out.len() >= ihl + 18 {
            update_l4_checksum(&mut out, ihl + 16, old_dst_ip, new_dst_ip, old_port, mapping_key.port);
        } else if proto == PROTO_UDP && out.len() >= ihl + 8 {
            let csum_off = ihl + 6;
            let cur = u16::from_be_bytes([out[csum_off], out[csum_off + 1]]);
            if cur != 0 {
                update_l4_checksum(&mut out, csum_off, old_dst_ip, new_dst_ip, old_port, mapping_key.port);
            }
        }

        // Helpers see the original (pre-NAT) destination port.
        let nm = NatMapping {
            proto: mapping_key.proto,
            inside_ip: IpAddr::V4(mapping_key.ip),
            inside_port: mapping_key.port,
            outside_port,
        };
        let out = self.helper_inbound(out, &nm, proto, dst_port);
        self.send_ns(mapping_key.ns, Packet::from_slice(&out));
    }

    fn inbound_icmp(&self, pkt: &[u8], ihl: usize) {
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
                    let k = match inner.reverse.get(&rk).copied() {
                        Some(k) => k,
                        None => return,
                    };
                    if let Some(m) = inner.mappings.get_mut(&k) {
                        m.last_active = Instant::now();
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
                self.send_ns(mapping_key.ns, Packet::from_slice(&out));
            }
            3 | 11 | 12 => self.inbound_icmp_error(pkt, ihl),
            _ => {}
        }
    }

    fn inbound_icmp_error(&self, pkt: &[u8], outer_ihl: usize) {
        let emb_off = outer_ihl + 8;
        if pkt.len() < emb_off + 20 {
            return;
        }
        let emb_ihl = (pkt[emb_off] & 0x0F) as usize * 4;
        if emb_ihl < 20 || pkt.len() < emb_off + emb_ihl + 4 {
            return;
        }
        let emb_proto = pkt[emb_off + 9];
        let emb_port = match emb_proto {
            PROTO_TCP | PROTO_UDP => {
                u16::from_be_bytes([pkt[emb_off + emb_ihl], pkt[emb_off + emb_ihl + 1]])
            }
            PROTO_ICMP => {
                if pkt.len() < emb_off + emb_ihl + 6 {
                    return;
                }
                u16::from_be_bytes([pkt[emb_off + emb_ihl + 4], pkt[emb_off + emb_ihl + 5]])
            }
            _ => return,
        };
        let rk = NatRevKey {
            proto: emb_proto,
            port: emb_port,
        };
        let mapping_key = {
            let mut inner = self.inner.lock().unwrap();
            let k = match inner.reverse.get(&rk).copied() {
                Some(k) => k,
                None => return,
            };
            if let Some(m) = inner.mappings.get_mut(&k) {
                m.last_active = Instant::now();
            }
            k
        };

        let mut out = pkt.to_vec();
        let old_outer_dst: [u8; 4] = out[16..20].try_into().unwrap();
        let new_outer_dst = mapping_key.ip.octets();
        out[16..20].copy_from_slice(&new_outer_dst);
        update_ip_checksum(&mut out, old_outer_dst, new_outer_dst);

        // Rewrite embedded source IP → inside client.
        out[emb_off + 12..emb_off + 16].copy_from_slice(&new_outer_dst);

        // Rewrite embedded source port.
        match emb_proto {
            PROTO_TCP | PROTO_UDP => {
                out[emb_off + emb_ihl..emb_off + emb_ihl + 2]
                    .copy_from_slice(&mapping_key.port.to_be_bytes());
            }
            PROTO_ICMP => {
                out[emb_off + emb_ihl + 4..emb_off + emb_ihl + 6]
                    .copy_from_slice(&mapping_key.port.to_be_bytes());
            }
            _ => unreachable!(),
        }

        // Recompute outer ICMP checksum from scratch (it covers modified bytes).
        out[outer_ihl + 2..outer_ihl + 4].copy_from_slice(&[0, 0]);
        let csum = checksum(&out[outer_ihl..]);
        out[outer_ihl + 2..outer_ihl + 4].copy_from_slice(&csum.to_be_bytes());

        self.send_ns(mapping_key.ns, Packet::from_slice(&out));
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
    use std::net::IpAddr;
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
        // TCP checksum: pseudo-header + segment
        let ph = crate::pseudo_header_checksum(crate::Protocol::TCP, IpAddr::V4(src), IpAddr::V4(dst), 20);
        let seg = crate::checksum(&p[20..]);
        let mut sum: u32 = (!ph) as u32 + (!seg) as u32;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let tcsum = !(sum as u16);
        p[36..38].copy_from_slice(&tcsum.to_be_bytes());
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
        let p = build_icmp_echo(Ipv4Addr::new(10, 0, 0, 7), Ipv4Addr::new(1, 1, 1, 1), 0xAA, 1);
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
        nat.add_port_forward(PortForward {
            proto: PROTO_TCP,
            outside_port: 8080,
            inside_ip: Ipv4Addr::new(10, 0, 0, 50),
            inside_port: 80,
            description: "webserver".into(),
            expires: None,
        })
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
            let port = nat.create_mapping(PROTO_TCP, Ipv4Addr::new(10, 0, 0, 2), 1234).unwrap();
            assert!((NAT_PORT_MIN..=NAT_PORT_MAX).contains(&port));
        }
    }

    #[test]
    fn list_port_forwards_filters_expired() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_port_forward(PortForward {
            proto: PROTO_TCP,
            outside_port: 8080,
            inside_ip: Ipv4Addr::new(10, 0, 0, 5),
            inside_port: 80,
            description: "alive".into(),
            expires: None,
        })
        .unwrap();
        nat.add_port_forward(PortForward {
            proto: PROTO_TCP,
            outside_port: 8081,
            inside_ip: Ipv4Addr::new(10, 0, 0, 6),
            inside_port: 80,
            description: "dead".into(),
            expires: Some(Instant::now() - Duration::from_secs(1)),
        })
        .unwrap();
        let live = nat.list_port_forwards();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].outside_port, 8080);
    }
}

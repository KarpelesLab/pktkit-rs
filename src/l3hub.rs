use crate::icmp::{self, RateLimiter};
use crate::l2hub::{DEFAULT_MAX_FORWARD_DEPTH, DepthGuard};
use crate::{Cleanup, HubCounters, HubStats, L3Device, L3Handler, Packet, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// RFC 4443 §2.4(f) wants generated errors rate-limited; this is a modest
/// ceiling for a software router.
const ICMP_RATE: u32 = 100;
const ICMP_BURST: u32 = 50;

struct Port {
    dev: Arc<dyn L3Device>,
    id: u64,
}

static PORT_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline]
fn next_port_id() -> u64 {
    PORT_ID_COUNTER.fetch_add(1, Ordering::Relaxed) + 1
}

/// A routing hub that forwards IP packets between connected devices.
///
/// `L3Hub` looks at each packet's destination address: the connected device
/// owning the longest prefix containing the destination gets the packet, and
/// no other device does. Broadcast and multicast are flooded to every port except the
/// source. A default route may be configured to absorb packets that don't
/// match any connected prefix.
///
/// A packet that matches no prefix and has no default route is dropped, and
/// [`stats`](Self::stats) is where that shows up.
///
/// Like a router, the hub decrements the TTL / hop limit of every packet it
/// routes to one port and drops those that run out, answering with ICMP Time
/// Exceeded once [`set_icmp_source`](Self::set_icmp_source) gives it an
/// address. Flooded broadcast and multicast pass unchanged, as on a link.
pub struct L3Hub {
    ports: RwLock<Vec<Arc<Port>>>,
    default_route: Mutex<Option<u64>>,
    stats: HubStats,
    icmp_source: Mutex<(Option<Ipv4Addr>, Option<Ipv6Addr>)>,
    icmp_limit: RateLimiter,
}

impl Default for L3Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for L3Hub {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.ports.read().map(|p| p.len()).unwrap_or(0);
        f.debug_struct("L3Hub").field("ports", &n).finish()
    }
}

impl L3Hub {
    /// Create an empty L3 routing hub.
    pub fn new() -> L3Hub {
        L3Hub {
            ports: RwLock::new(Vec::new()),
            default_route: Mutex::new(None),
            stats: HubStats::new(),
            icmp_source: Mutex::new((None, None)),
            icmp_limit: RateLimiter::new(ICMP_RATE, ICMP_BURST),
        }
    }

    /// Routing counters — received, forwarded, flooded and dropped.
    pub fn stats(&self) -> HubCounters {
        self.stats.snapshot()
    }

    /// Attach a device, installing its handler to route via the hub.
    pub fn connect<D>(self: &Arc<Self>, dev: D) -> L3HubHandle
    where
        D: L3Device + 'static,
    {
        self.connect_arc(Arc::new(dev))
    }

    /// Same as [`connect`](Self::connect) for already-shared devices.
    pub fn connect_arc(self: &Arc<Self>, dev: Arc<dyn L3Device>) -> L3HubHandle {
        let id = next_port_id();
        let port = Arc::new(Port {
            dev: dev.clone(),
            id,
        });
        self.ports.write().unwrap().push(port);

        let hub = Arc::downgrade(self);
        let h: L3Handler = Arc::new(move |p: &Packet| {
            if let Some(hub) = hub.upgrade() {
                hub.route(p, id);
            }
            Ok(())
        });
        dev.set_handler(h);

        L3HubHandle {
            hub: Arc::downgrade(self),
            id,
            closed: Mutex::new(false),
        }
    }

    /// Designate `dev` as the default route. Packets that don't match any
    /// connected prefix are sent to this device. The device must already be
    /// attached via [`connect`](Self::connect) or [`connect_arc`](Self::connect_arc).
    pub fn set_default_route(&self, dev: &Arc<dyn L3Device>) {
        let ports = self.ports.read().unwrap();
        for p in ports.iter() {
            if Arc::ptr_eq(&p.dev, dev) {
                *self.default_route.lock().unwrap() = Some(p.id);
                return;
            }
        }
    }

    /// Source address for the ICMP Time Exceeded the hub sends when a
    /// packet's TTL / hop limit runs out in it, one per address family.
    ///
    /// The hub owns no address of its own, so until one is set here an
    /// expiring packet is dropped without a word: `traceroute` then sees a
    /// silent hop rather than a reply from an address nobody configured.
    pub fn set_icmp_source(&self, addr: IpAddr) {
        let mut src = self.icmp_source.lock().unwrap();
        match addr {
            IpAddr::V4(a) => src.0 = Some(a),
            IpAddr::V6(a) => src.1 = Some(a),
        }
    }

    fn route(&self, pkt: &Packet, source_id: u64) {
        self.stats.record_received();

        // Forwarding is a synchronous call chain, so a routing loop between
        // hubs is recursion. The TTL bounds it too, but only at up to 255
        // frames deep, which is enough to overflow a small thread stack.
        let _depth = match DepthGuard::enter(DEFAULT_MAX_FORWARD_DEPTH) {
            Some(g) => g,
            None => {
                self.stats.record_dropped();
                return;
            }
        };

        if !pkt.is_valid() {
            self.stats.record_dropped();
            return;
        }
        let dst = match pkt.dst_addr() {
            Some(d) => d,
            None => {
                self.stats.record_dropped();
                return;
            }
        };

        let ports: Vec<Arc<Port>> = self.ports.read().unwrap().clone();

        // A detached device may still hold the handler it was given; what
        // it sends is no longer the hub's to route.
        if !ports.iter().any(|p| p.id == source_id) {
            self.stats.record_dropped();
            return;
        }

        // Flooding makes the hub the ports' shared link, not a router
        // between them: broadcast and multicast go out as they came in. A
        // decrement would break Neighbor Discovery, which insists on hop
        // limit 255 (RFC 4861 §7.1), and drop everything sent with TTL 1
        // to stay on the link (IGMP, OSPF hellos). The depth guard above
        // still ends a flooding loop.
        if pkt.is_broadcast() || pkt.is_multicast() {
            let mut sent = 0u64;
            for p in &ports {
                if p.id != source_id {
                    let _ = p.dev.send(pkt);
                    sent += 1;
                }
            }
            if sent == 0 {
                self.stats.record_dropped();
            } else {
                self.stats.record_flooded();
            }
            return;
        }

        // RFC 1812 §5.3.1 / RFC 8200 §3: a router decrements the TTL / hop
        // limit of what it forwards, and discards what reaches zero -- that
        // is what finally ends a routing loop.
        let mut buf = pkt.to_vec();
        let fwd = Packet::from_mut(&mut buf);
        if !fwd.decrement_hop_limit() {
            self.stats.record_dropped();
            self.time_exceeded(pkt, &ports, source_id);
            return;
        }
        let pkt: &Packet = fwd;

        // Longest prefix wins, so a narrower network inside a wider one is
        // reachable whatever order the ports were attached in. A device with
        // no address owns nothing: its unspecified 0.0.0.0/0 would otherwise
        // match every destination. Catch-alls go through the default route.
        let best = ports
            .iter()
            .filter(|p| p.id != source_id)
            .filter_map(|p| {
                let prefix = p.dev.addr();
                (prefix.is_valid() && prefix.contains(dst)).then_some((prefix.bits(), p))
            })
            .max_by_key(|(bits, _)| *bits);
        if let Some((_, p)) = best {
            let _ = p.dev.send(pkt);
            self.stats.record_forwarded(1);
            return;
        }

        // Copied out rather than matched on the guard: the send below may
        // re-enter this hub, which would then deadlock on the lock.
        let default_route = *self.default_route.lock().unwrap();
        if let Some(default_id) = default_route {
            for p in &ports {
                if p.id == default_id && p.id != source_id {
                    let _ = p.dev.send(pkt);
                    self.stats.record_forwarded(1);
                    return;
                }
            }
        }

        // Nowhere to send it: no matching prefix and no usable default route.
        self.stats.record_dropped();
    }

    /// Tell the sender of an expired packet, if the hub has an address to
    /// speak from. `icmp::time_exceeded` refuses the cases RFC 1812 §4.3.2.7
    /// and RFC 4443 §2.4 forbid (errors about errors, multicast, ...).
    fn time_exceeded(&self, orig: &Packet, ports: &[Arc<Port>], source_id: u64) {
        let src = *self.icmp_source.lock().unwrap();
        let from: IpAddr = match orig.version() {
            4 => match src.0 {
                Some(a) => a.into(),
                None => return,
            },
            _ => match src.1 {
                Some(a) => a.into(),
                None => return,
            },
        };
        let Some(reply) = icmp::time_exceeded(orig, from) else {
            return;
        };
        if !self.icmp_limit.allow() {
            return;
        }
        if let Some(p) = ports.iter().find(|p| p.id == source_id) {
            let _ = p.dev.send(Packet::from_slice(&reply));
        }
    }

    fn disconnect(&self, id: u64) {
        self.ports.write().unwrap().retain(|p| p.id != id);
        let mut dr = self.default_route.lock().unwrap();
        if *dr == Some(id) {
            *dr = None;
        }
    }
}

/// `L3Connector` impl: every device is added to the hub; cleanup detaches it.
impl crate::L3Connector for Arc<L3Hub> {
    fn connect_l3(&self, dev: Arc<dyn L3Device>) -> Result<Cleanup> {
        let handle = self.connect_arc(dev);
        Ok(Box::new(move || {
            handle.close();
            Ok(())
        }))
    }
}

/// Returned by [`L3Hub::connect`]; dropping or calling [`close`](Self::close)
/// detaches the device.
pub struct L3HubHandle {
    hub: std::sync::Weak<L3Hub>,
    id: u64,
    closed: Mutex<bool>,
}

impl core::fmt::Debug for L3HubHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("L3HubHandle").field("id", &self.id).finish()
    }
}

impl L3HubHandle {
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

impl Drop for L3HubHandle {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IpPrefix, L3Handler, PipeL3};
    use std::sync::Mutex;

    #[derive(Default, Clone)]
    struct Sink {
        inner: Arc<Mutex<Vec<Vec<u8>>>>,
        prefix: Arc<Mutex<IpPrefix>>,
    }
    impl L3Device for Sink {
        fn set_handler(&self, _h: L3Handler) {}
        fn send(&self, p: &Packet) -> Result<()> {
            self.inner.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }
        fn addr(&self) -> IpPrefix {
            *self.prefix.lock().unwrap()
        }
        fn set_addr(&self, p: IpPrefix) -> Result<()> {
            *self.prefix.lock().unwrap() = p;
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    fn v4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[8] = 64;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn routes_by_prefix() {
        let hub = Arc::new(L3Hub::new());
        let a = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let b_sink = Sink::default();
        b_sink.set_addr("10.0.1.1/24".parse().unwrap()).unwrap();

        let _ha = hub.connect_arc(a.clone() as Arc<dyn L3Device>);
        let _hb = hub.connect(b_sink.clone());

        // a sends to 10.0.1.5 (in b's prefix)
        let buf = v4([10, 0, 0, 1], [10, 0, 1, 5]);
        a.inject(Packet::from_slice(&buf)).unwrap();
        assert_eq!(b_sink.inner.lock().unwrap().len(), 1);
    }

    fn sink(prefix: &str) -> Sink {
        let s = Sink::default();
        s.set_addr(prefix.parse().unwrap()).unwrap();
        s
    }

    fn count(s: &Sink) -> usize {
        s.inner.lock().unwrap().len()
    }

    #[test]
    fn default_route_catches_misses() {
        let hub = Arc::new(L3Hub::new());
        let a = sink("10.0.0.1/24");
        let ha = hub.connect(a.clone());
        // Unconfigured: owns no prefix, so it must not look like a /0.
        let unconfigured = Sink::default();
        let _hu = hub.connect(unconfigured.clone());
        let gw = sink("172.16.0.1/16");
        let gw_arc: Arc<dyn L3Device> = Arc::new(gw.clone());
        let _hg = hub.connect_arc(gw_arc.clone());
        hub.set_default_route(&gw_arc);

        let buf = v4([10, 0, 0, 1], [8, 8, 8, 8]);
        hub.route(Packet::from_slice(&buf), ha.id);
        assert_eq!(
            count(&gw),
            1,
            "the default route takes what nothing else owns"
        );
        assert_eq!(count(&unconfigured), 0);
    }

    #[test]
    fn the_longest_matching_prefix_wins() {
        let hub = Arc::new(L3Hub::new());
        let a = sink("192.168.0.1/24");
        let wide = sink("10.0.0.1/8");
        let narrow = sink("10.1.0.1/16");
        let ha = hub.connect(a.clone());
        let _hw = hub.connect(wide.clone());
        let _hn = hub.connect(narrow.clone());

        let buf = v4([192, 168, 0, 1], [10, 1, 0, 9]);
        hub.route(Packet::from_slice(&buf), ha.id);
        assert_eq!((count(&wide), count(&narrow)), (0, 1));

        let buf = v4([192, 168, 0, 1], [10, 2, 0, 9]);
        hub.route(Packet::from_slice(&buf), ha.id);
        assert_eq!((count(&wide), count(&narrow)), (1, 1));
    }

    #[test]
    fn a_detached_port_cannot_inject() {
        let hub = Arc::new(L3Hub::new());
        let a = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let b = sink("10.0.1.1/24");
        let ha = hub.connect_arc(a.clone() as Arc<dyn L3Device>);
        let _hb = hub.connect(b.clone());
        ha.close();

        // The device still holds the handler the hub gave it.
        let buf = v4([10, 0, 0, 1], [10, 0, 1, 5]);
        a.inject(Packet::from_slice(&buf)).unwrap();
        assert_eq!(count(&b), 0);
    }

    #[test]
    fn disconnect_removes_port() {
        let hub = Arc::new(L3Hub::new());
        let a = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let b = Sink::default();
        b.set_addr("10.0.1.1/24".parse().unwrap()).unwrap();
        let _ha = hub.connect_arc(a.clone() as Arc<dyn L3Device>);
        let hb = hub.connect(b.clone());
        hb.close();

        let buf = v4([10, 0, 0, 1], [10, 0, 1, 5]);
        a.inject(Packet::from_slice(&buf)).unwrap();
        assert_eq!(b.inner.lock().unwrap().len(), 0);
    }

    #[test]
    fn stats_count_an_unroutable_packet_as_dropped() {
        let hub = Arc::new(L3Hub::new());
        let a = Sink::default();
        a.set_addr("10.0.0.1/24".parse().unwrap()).unwrap();
        let ha = hub.connect(a.clone());

        // Nothing owns 192.0.2.1 and no default route is set.
        let pkt = crate::build::build_ipv4(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(192, 0, 2, 1),
            crate::Protocol::UDP,
            64,
            &[0; 8],
        );
        hub.route(Packet::from_slice(&pkt), ha.id);

        let s = hub.stats();
        assert_eq!(s.received, 1);
        assert_eq!(s.forwarded, 0);
        assert_eq!(s.dropped, 1, "no route and no default route");
    }

    #[test]
    fn stats_count_a_routed_packet_as_forwarded() {
        // A `Sink` rather than a `PipeL3`: a pipe loops whatever the hub sends
        // it straight back into the hub's own handler, which would count the
        // packet twice.
        let hub = Arc::new(L3Hub::new());
        let a = Sink::default();
        a.set_addr("10.0.0.1/24".parse().unwrap()).unwrap();
        let b = Sink::default();
        b.set_addr("192.0.2.1/24".parse().unwrap()).unwrap();
        let ha = hub.connect(a.clone());
        let _hb = hub.connect(b.clone());

        let pkt = crate::build::build_ipv4(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(192, 0, 2, 9),
            crate::Protocol::UDP,
            64,
            &[0; 8],
        );
        hub.route(Packet::from_slice(&pkt), ha.id);

        let s = hub.stats();
        assert_eq!((s.received, s.forwarded, s.dropped), (1, 1, 0));
        assert_eq!(b.inner.lock().unwrap().len(), 1);
    }

    /// One end of a cable between two hubs: what it is asked to send comes out
    /// of the other end's handler, synchronously, as a link between two
    /// in-process routers does.
    #[derive(Default)]
    struct CableEnd {
        handler: Mutex<Option<L3Handler>>,
        peer: Mutex<std::sync::Weak<CableEnd>>,
        sent: AtomicU64,
    }
    impl L3Device for CableEnd {
        fn set_handler(&self, h: L3Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, p: &Packet) -> Result<()> {
            self.sent.fetch_add(1, Ordering::Relaxed);
            let peer = self.peer.lock().unwrap().upgrade();
            let h = peer.and_then(|p| p.handler.lock().unwrap().clone());
            if let Some(h) = h {
                h(p)?;
            }
            Ok(())
        }
        fn addr(&self) -> IpPrefix {
            IpPrefix::default()
        }
        fn set_addr(&self, _p: IpPrefix) -> Result<()> {
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    fn cable() -> (Arc<CableEnd>, Arc<CableEnd>) {
        let a = Arc::new(CableEnd::default());
        let b = Arc::new(CableEnd::default());
        *a.peer.lock().unwrap() = Arc::downgrade(&b);
        *b.peer.lock().unwrap() = Arc::downgrade(&a);
        (a, b)
    }

    fn udp4(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        let (s, d) = (std::net::Ipv4Addr::from(src), std::net::Ipv4Addr::from(dst));
        let udp = crate::build::build_udp(s.into(), d.into(), 1, 2, b"x");
        crate::build::build_ipv4(s, d, crate::Protocol::UDP, ttl, &udp)
    }

    #[test]
    fn two_hubs_defaulting_to_each_other_do_not_loop_forever() {
        let h1 = Arc::new(L3Hub::new());
        let h2 = Arc::new(L3Hub::new());
        // Two links, each hub defaulting out a different one, so no hub ever
        // sends a packet back out the port it came in on.
        let (e1, e2) = cable();
        let (f1, f2) = cable();
        let e1d: Arc<dyn L3Device> = e1.clone();
        let f2d: Arc<dyn L3Device> = f2.clone();
        let _c1 = h1.connect_arc(e1d.clone());
        let _c2 = h2.connect_arc(e2.clone() as Arc<dyn L3Device>);
        let _c3 = h1.connect_arc(f1.clone() as Arc<dyn L3Device>);
        let _c4 = h2.connect_arc(f2d.clone());
        h1.set_default_route(&e1d);
        h2.set_default_route(&f2d);
        let host = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let _ch = h1.connect_arc(host.clone() as Arc<dyn L3Device>);

        // TTL 255 is the worst case: without a decrement or a depth bound
        // this recurses until the stack overflows.
        let buf = udp4([10, 0, 0, 1], [8, 8, 8, 8], 255);
        host.inject(Packet::from_slice(&buf)).unwrap();

        let hops = e1.sent.load(Ordering::Relaxed) + e2.sent.load(Ordering::Relaxed);
        assert!(hops < 64, "the packet bounced {hops} times");
    }

    #[test]
    fn forwarding_decrements_ttl_and_expiry_answers_time_exceeded() {
        let hub = Arc::new(L3Hub::new());
        let a = sink("10.0.0.1/24");
        let b = sink("10.0.1.1/24");
        let ha = hub.connect(a.clone());
        let _hb = hub.connect(b.clone());
        hub.set_icmp_source("10.0.0.254".parse().unwrap());

        let pkt = udp4([10, 0, 0, 1], [10, 0, 1, 9], 64);
        hub.route(Packet::from_slice(&pkt), ha.id);
        let got = b.inner.lock().unwrap()[0].clone();
        let got = Packet::from_slice(&got);
        assert_eq!(got.ipv4_ttl(), 63);
        assert!(got.verify_ipv4_checksum());

        // TTL 1 must not be forwarded; the sender hears Time Exceeded.
        let expiring = udp4([10, 0, 0, 1], [10, 0, 1, 9], 1);
        hub.route(Packet::from_slice(&expiring), ha.id);
        assert_eq!(count(&b), 1, "an expiring packet is not forwarded");
        let replies = a.inner.lock().unwrap().clone();
        assert_eq!(replies.len(), 1);
        let r = Packet::from_slice(&replies[0]);
        assert_eq!(r.transport_protocol(), crate::Protocol::ICMP);
        assert_eq!(r.src_addr(), Some("10.0.0.254".parse().unwrap()));
        assert_eq!(r.transport_payload()[0], crate::l4::icmpv4::TIME_EXCEEDED);
    }

    #[test]
    fn ipv6_forwarding_decrements_hop_limit() {
        let hub = Arc::new(L3Hub::new());
        let a = sink("2001:db8::1/64");
        let b = sink("2001:db8:1::1/64");
        let ha = hub.connect(a.clone());
        let _hb = hub.connect(b.clone());
        let (s, d): (std::net::Ipv6Addr, std::net::Ipv6Addr) = (
            "2001:db8::1".parse().unwrap(),
            "2001:db8:1::9".parse().unwrap(),
        );
        let udp = crate::build::build_udp(s.into(), d.into(), 1, 2, b"x");
        let pkt = crate::build::build_ipv6(s, d, crate::Protocol::UDP, 1, &udp);
        hub.route(Packet::from_slice(&pkt), ha.id);
        assert_eq!(count(&b), 0, "hop limit 1 expires here");
        // No ICMP source configured: dropped quietly.
        assert_eq!(count(&a), 0);
    }

    #[test]
    fn flooded_packets_keep_their_ttl() {
        let hub = Arc::new(L3Hub::new());
        let a = sink("10.0.0.1/24");
        let b = sink("10.0.1.1/24");
        let ha = hub.connect(a.clone());
        let _hb = hub.connect(b.clone());
        hub.set_icmp_source("10.0.0.254".parse().unwrap());

        // TTL 1 multicast is meant to stay on the link, which the flood is.
        let mcast = udp4([10, 0, 0, 1], [224, 0, 0, 251], 1);
        hub.route(Packet::from_slice(&mcast), ha.id);
        let bcast = udp4([10, 0, 0, 1], [255, 255, 255, 255], 64);
        hub.route(Packet::from_slice(&bcast), ha.id);
        assert_eq!(*b.inner.lock().unwrap(), vec![mcast, bcast]);
        assert_eq!(count(&a), 0, "no Time Exceeded for a flood");

        // Neighbor Discovery needs hop limit 255 on arrival.
        let (s, d): (std::net::Ipv6Addr, std::net::Ipv6Addr) =
            ("fe80::1".parse().unwrap(), "ff02::1".parse().unwrap());
        let udp = crate::build::build_udp(s.into(), d.into(), 1, 2, b"x");
        let nd = crate::build::build_ipv6(s, d, crate::Protocol::UDP, 255, &udp);
        hub.route(Packet::from_slice(&nd), ha.id);
        assert_eq!(b.inner.lock().unwrap()[2], nd);
    }
}

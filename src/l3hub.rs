use crate::{Cleanup, HubCounters, HubStats, L3Device, L3Handler, Packet, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

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
pub struct L3Hub {
    ports: RwLock<Vec<Arc<Port>>>,
    default_route: Mutex<Option<u64>>,
    stats: HubStats,
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

    fn route(&self, pkt: &Packet, source_id: u64) {
        self.stats.record_received();
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

        if let Some(default_id) = *self.default_route.lock().unwrap() {
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
}

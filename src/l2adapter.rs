//! `L2Adapter`: bridges an [`L3Device`] onto an Ethernet network.
//!
//! Equivalent to Go's `L2Adapter`. The adapter:
//! - Picks (or accepts) a MAC address.
//! - Handles ARP for IPv4 (cache + solicitation + reply).
//! - Handles NDP for IPv6 (cache + NS/NA).
//! - Retries an unanswered solicitation, and once resolution fails reports
//!   each packet that was waiting on it to the L3 device as an ICMP
//!   destination unreachable. The timers behind this run on a background
//!   thread; on `wasm32`, call [`L2Adapter::tick`] about once a second.
//! - Optionally runs a DHCP client to obtain the L3 device's address.
//! - When DHCP is bound, the IPv4 gateway is taken from the lease (and
//!   cleared when the lease names no router, or is lost).

use crate::arp::{self, Pending as ArpPending, PendingEvent, Resolved, Table as ArpTable};
use crate::icmp::{self, IcmpError, RateLimiter};
use crate::l4::{icmpv4, icmpv6};
use crate::ndp::{self, Table as NdpTable};
use crate::time::Instant;
use crate::{
    EtherType, Frame, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Protocol, Result,
    build_frame,
};
// Only the DHCP client callback names this type.
#[cfg(feature = "dhcp")]
use crate::IpPrefix;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// How often the background thread runs the neighbour timers. Well within
/// the one second between solicitations.
#[cfg(not(target_family = "wasm"))]
const TIMER_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// Configure an [`L2Adapter`].
#[derive(Default, Debug, Clone)]
#[non_exhaustive]
pub struct L2AdapterConfig {
    /// Override the MAC. Defaults to a random locally-administered unicast.
    pub mac: Option<MacAddr>,
    /// Initial IPv4 gateway, the next hop for off-subnet destinations.
    ///
    /// A static value does not survive DHCP: once the client binds, each
    /// lease replaces it with the lease's router, or clears it if the lease
    /// names none, and a lost lease clears it.
    pub gateway_v4: Option<Ipv4Addr>,
    /// Initial IPv6 gateway, the next hop for off-link destinations: those
    /// outside the L3 device's IPv6 prefix, other than link-local. Without
    /// one they are dropped (RFC 4943). DHCP, being IPv4 only, leaves it
    /// alone.
    pub gateway_v6: Option<Ipv6Addr>,
}

setters! {
    L2AdapterConfig {
        some mac: MacAddr;
        some gateway_v4: Ipv4Addr;
        some gateway_v6: Ipv6Addr;
    }
}

/// Bridges an L3 device onto an L2 network.
///
/// The adapter is an `L2Device` (so plugs into [`L2Hub`](crate::L2Hub)) and
/// owns the wrapped L3 device. Outbound packets from the L3 device are framed
/// in Ethernet and sent on the L2 network; inbound frames are filtered by
/// MAC, terminating ARP / NDP / DHCP and forwarding the rest to the L3 device.
pub struct L2Adapter {
    mac: MacAddr,
    l3: Arc<dyn L3Device>,

    l2_handler: Mutex<Option<L2Handler>>,
    gateway_v4: Mutex<Option<Ipv4Addr>>,
    gateway_v6: Mutex<Option<Ipv6Addr>>,

    arp: ArpTable,
    arp_pending: ArpPending,
    ndp: NdpTable,
    ndp_pending: ArpPending<Ipv6Addr>,

    #[cfg(feature = "dhcp")]
    dhcp: Mutex<Option<Arc<crate::dhcp::Client>>>,
    /// The address the DHCP client is probing before it binds, and whether
    /// anyone has turned out to be using it.
    #[cfg(feature = "dhcp")]
    probe: Mutex<Option<(Ipv4Addr, bool)>>,
    /// The source address and MAC of the last DHCP server message: where a
    /// unicast to that server goes, kept apart from the ARP cache.
    #[cfg(feature = "dhcp")]
    dhcp_server: Mutex<Option<(Ipv4Addr, MacAddr)>>,

    /// ARP and NDP messages from other stations claiming one of our
    /// addresses (RFC 5227 §2.4).
    conflicts: AtomicU64,

    /// Paces the ICMP errors for packets that could not be delivered (RFC
    /// 4443 §2.4(f), RFC 1812 §4.3.2.8).
    icmp_limit: RateLimiter,

    // Self-Arc, for use by closures that need to refer back to us.
    weak_self: Mutex<Weak<L2Adapter>>,
}

impl core::fmt::Debug for L2Adapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("L2Adapter").field("mac", &self.mac).finish()
    }
}

impl L2Adapter {
    /// Build a new adapter wrapping `dev`.
    ///
    /// The L3 device's handler is installed so its outbound packets reach
    /// the L2 network. The returned `Arc<L2Adapter>` is the canonical handle
    /// — clone it freely; methods are `&self`.
    pub fn new<D>(dev: D, cfg: L2AdapterConfig) -> Arc<L2Adapter>
    where
        D: L3Device + 'static,
    {
        Self::new_arc(Arc::new(dev), cfg)
    }

    /// Same as [`new`](Self::new) but for L3 devices already shared.
    pub fn new_arc(dev: Arc<dyn L3Device>, cfg: L2AdapterConfig) -> Arc<L2Adapter> {
        Self::build(dev, cfg, cfg!(not(target_family = "wasm")))
    }

    /// `timer` starts the thread that runs the neighbour timers; tests
    /// leave it out to drive time themselves.
    fn build(dev: Arc<dyn L3Device>, cfg: L2AdapterConfig, timer: bool) -> Arc<L2Adapter> {
        let mac = cfg.mac.unwrap_or_else(MacAddr::random_local_unicast);
        let a = Arc::new(L2Adapter {
            mac,
            l3: dev.clone(),
            l2_handler: Mutex::new(None),
            gateway_v4: Mutex::new(None),
            gateway_v6: Mutex::new(None),
            arp: ArpTable::new(),
            arp_pending: ArpPending::new(),
            ndp: NdpTable::new(),
            ndp_pending: ArpPending::new(),
            #[cfg(feature = "dhcp")]
            dhcp: Mutex::new(None),
            #[cfg(feature = "dhcp")]
            probe: Mutex::new(None),
            #[cfg(feature = "dhcp")]
            dhcp_server: Mutex::new(None),
            conflicts: AtomicU64::new(0),
            // A whole queue's worth at once, so one failed resolution is
            // reported in full.
            icmp_limit: RateLimiter::new(10, arp::PENDING_MAX_PKTS as u32),
            weak_self: Mutex::new(Weak::new()),
        });
        *a.weak_self.lock().unwrap() = Arc::downgrade(&a);
        a.set_gw_v4(cfg.gateway_v4);
        a.set_gw_v6(cfg.gateway_v6);

        // Wire the L3 device's outbound packets back through us.
        let weak = Arc::downgrade(&a);
        let h: L3Handler = Arc::new(move |p: &Packet| {
            if let Some(a) = weak.upgrade() {
                a.handle_outgoing(p);
            }
            Ok(())
        });
        dev.set_handler(h);
        #[cfg(not(target_family = "wasm"))]
        if timer {
            spawn_timer(&a);
        }
        let _ = timer;
        a
    }

    /// Adapter MAC.
    pub fn hw_addr(&self) -> MacAddr {
        self.mac
    }

    /// How many ARP or NDP messages have come from another station claiming
    /// one of our addresses (RFC 5227 §2.4): the sign that someone else is
    /// configured with it. They are not learnt from, so traffic keeps going
    /// out on the wire rather than being handed to the claimant as a
    /// neighbour; resolving the conflict is left to whoever reads this.
    pub fn address_conflicts(&self) -> u64 {
        self.conflicts.load(Ordering::Relaxed)
    }

    /// Set the IPv4 default gateway used for off-subnet ARP. With DHCP
    /// running, the next binding or lost lease replaces it (see
    /// [`L2AdapterConfig::gateway_v4`]).
    pub fn set_gateway_v4(&self, gw: Ipv4Addr) {
        self.set_gw_v4(Some(gw));
    }

    /// Set the IPv6 default gateway used for off-link NDP.
    pub fn set_gateway_v6(&self, gw: Ipv6Addr) {
        self.set_gw_v6(Some(gw));
    }

    /// Every off-link packet goes through the gateway, so it is pinned: a
    /// cache filled by made-up neighbours must not push its entry out, nor
    /// a subnet sweep keep it from being resolved.
    fn set_gw_v4(&self, gw: Option<Ipv4Addr>) {
        let mut g = self.gateway_v4.lock().unwrap();
        *g = gw;
        self.arp.pin(gw);
        self.arp_pending.pin(gw);
    }

    fn set_gw_v6(&self, gw: Option<Ipv6Addr>) {
        let mut g = self.gateway_v6.lock().unwrap();
        *g = gw;
        self.ndp.pin(gw);
        self.ndp_pending.pin(gw);
    }

    // --- DHCP --------------------------------------------------------------

    /// Start the DHCP client (IPv4). Requires the `dhcp` feature.
    #[cfg(feature = "dhcp")]
    pub fn start_dhcp(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let transport = AdapterDhcpTransport { weak };
        let client = Arc::new(crate::dhcp::Client::new(
            transport,
            crate::dhcp::ClientConfig {
                mac: Some(self.mac),
            },
        ));
        // A client already running is stopped, not just forgotten: its
        // lease would otherwise stay configured with nothing renewing it.
        let old = self.dhcp.lock().unwrap().replace(client.clone());
        if let Some(old) = old {
            old.stop();
        }
        client.start();
    }

    /// Stop the DHCP client, giving up its lease (see
    /// [`dhcp::Client::stop`](crate::dhcp::Client::stop)).
    #[cfg(feature = "dhcp")]
    pub fn stop_dhcp(&self) {
        // Taken out first: stopping calls back into the adapter.
        let client = self.dhcp.lock().unwrap().take();
        if let Some(c) = client {
            c.stop();
        }
    }

    /// Run whatever timer has come due: solicit again for an address still
    /// unresolved, report the packets for one that failed, and drive the
    /// DHCP client ([`dhcp::Client::tick`](crate::dhcp::Client::tick)).
    /// Only needed on targets without threads (`wasm32`), where nothing
    /// runs in the background: call it about once a second. Without it an
    /// address is solicited only once, when traffic for it is queued.
    pub fn tick(&self) {
        self.run_timers(Instant::now());
        #[cfg(feature = "dhcp")]
        {
            let client = self.dhcp.lock().unwrap().clone();
            if let Some(c) = client {
                c.tick();
            }
        }
    }

    /// The neighbour timers, as of `now`.
    fn run_timers(&self, now: Instant) {
        for (ip, mac) in self.arp.poll(now) {
            self.send_arp_request_to(ip, mac);
        }
        for (ip, mac) in self.ndp.poll(now) {
            self.send_neighbor_solicitation_to(ip, mac);
        }
        for ev in self.arp_pending.poll(now) {
            match ev {
                PendingEvent::Resolicit(ip) => self.send_arp_request(ip),
                PendingEvent::Failed(_, pkts) => self.report_unreachable(pkts),
            }
        }
        for ev in self.ndp_pending.poll(now) {
            match ev {
                PendingEvent::Resolicit(ip) => self.send_neighbor_solicitation(ip),
                PendingEvent::Failed(_, pkts) => self.report_unreachable(pkts),
            }
        }
    }

    /// Tell the L3 device that each of `pkts` could not be delivered, its
    /// next hop having failed to resolve: ICMP host unreachable (RFC 1122
    /// §2.3.2.2) or ICMPv6 address unreachable (RFC 4861 §7.2.2). Without
    /// it a sender learns of the failure only by timing out.
    fn report_unreachable(&self, pkts: Vec<Vec<u8>>) {
        for buf in pkts {
            let pkt = Packet::from_slice(&buf);
            // The DHCP client's own messages were never the host's, and
            // the client retransmits on its own timers.
            #[cfg(feature = "dhcp")]
            if is_dhcp_to_server(pkt) {
                continue;
            }
            let (from, err) = match (pkt.version(), self.l3.addr().addr()) {
                (4, IpAddr::V4(a)) if !a.is_unspecified() => (
                    IpAddr::V4(a),
                    IcmpError::DestUnreachable(icmpv4::CODE_HOST_UNREACHABLE),
                ),
                // Without an address of ours to send from, there is nobody
                // for the error to come from.
                (4, _) => continue,
                (6, addr) => {
                    let from = match addr {
                        IpAddr::V6(a) if !a.is_unspecified() => a,
                        _ => ndp::link_local_from_mac(self.mac),
                    };
                    (
                        IpAddr::V6(from),
                        IcmpError::DestUnreachable(icmpv6::CODE_ADDR_UNREACHABLE),
                    )
                }
                _ => continue,
            };
            // icmp::error refuses what must not be answered (errors,
            // multicast, later fragments) before a token is spent on it.
            if let Some(reply) = icmp::error(pkt, from, err)
                && self.icmp_limit.allow()
            {
                let _ = self.l3.send(Packet::from_slice(&reply));
            }
        }
    }

    // --- Internals ---------------------------------------------------------

    fn send_l2(&self, f: &Frame) {
        let h = self.l2_handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(f);
        }
    }

    fn handle_incoming(&self, f: &Frame) {
        if !f.is_valid() {
            return;
        }
        let dst = f.dst_mac();
        if !f.is_broadcast() && !f.is_multicast() && dst != Some(self.mac) {
            return;
        }
        // The adapter is a host on the untagged VLAN. The accessors below
        // look through an 802.1Q tag, so without this a frame for VLAN 7
        // would be answered, untagged, on ours -- bridging the two. VID 0 is
        // only a priority tag and belongs to the untagged VLAN (802.1Q
        // §6.9.1).
        if f.has_vlan() && f.vlan_id() != 0 {
            return;
        }
        match f.ether_type() {
            EtherType::ARP => self.handle_arp(f),
            EtherType::IPV4 | EtherType::IPV6 => {
                let payload = f.payload();
                if payload.is_empty() {
                    return;
                }
                let pkt = Packet::from_slice(payload);
                if !pkt.is_valid() {
                    return;
                }
                // Intercept DHCP (IPv4 UDP port 68). Only a whole datagram
                // has a UDP header where one is looked for: in a later
                // fragment those bytes are payload, and a first fragment
                // holds only part of the message. Fragments go to the host.
                #[cfg(feature = "dhcp")]
                if pkt.version() == 4
                    && pkt.ipv4_protocol() == Protocol::UDP
                    && !pkt.ipv4_is_fragment()
                {
                    let udp = pkt.ipv4_payload();
                    if udp.len() >= 8 {
                        let dport = u16::from_be_bytes([udp[2], udp[3]]);
                        if dport == 68 {
                            let dhcp = self.dhcp.lock().unwrap().clone();
                            if let Some(c) = dhcp
                                && c.is_active()
                            {
                                if let (Some(mac), Some(ip)) = (f.src_mac(), pkt.ipv4_src_addr())
                                    && udp[0..2] == 67u16.to_be_bytes()
                                {
                                    *self.dhcp_server.lock().unwrap() = Some((ip, mac));
                                }
                                c.handle_packet(&udp[8..]);
                                return;
                            }
                        }
                    }
                }

                if pkt.version() == 6
                    && pkt.ipv6_next_header() == Protocol::ICMPV6
                    && self.handle_ndp(pkt, f.src_mac())
                {
                    return;
                }

                let _ = self.l3.send(pkt);
            }
            _ => {}
        }
    }

    fn handle_outgoing(&self, pkt: &Packet) {
        self.handle_outgoing_at(pkt, Instant::now());
    }

    fn handle_outgoing_at(&self, pkt: &Packet, now: Instant) {
        if !pkt.is_valid() {
            return;
        }
        // A neighbour to probe once the packet is on its way: its entry is
        // due for Neighbour Unreachability Detection.
        let mut probe = None;
        let (dst_mac, ether_type) = match pkt.version() {
            4 => {
                if pkt.is_broadcast() || self.is_subnet_broadcast(pkt.ipv4_dst_addr().unwrap()) {
                    (MacAddr::broadcast(), EtherType::IPV4)
                } else if pkt.is_multicast() {
                    let d = pkt.ipv4_dst_addr().unwrap().octets();
                    (
                        MacAddr([0x01, 0x00, 0x5e, d[1] & 0x7f, d[2], d[3]]),
                        EtherType::IPV4,
                    )
                } else {
                    let dst = pkt.ipv4_dst_addr().unwrap();
                    let prefix = self.l3.addr();
                    // 169.254/16 is on-link whatever our prefix, and a router
                    // must not forward it: RFC 3927 §2.6.2 has the host ARP
                    // for the destination directly.
                    let target = if prefix.is_valid()
                        && prefix.is_v4()
                        && !prefix.contains(IpAddr::V4(dst))
                        && !dst.is_link_local()
                    {
                        self.gateway_v4.lock().unwrap().unwrap_or(dst)
                    } else {
                        dst
                    };
                    match self.arp.resolve_at(target, now) {
                        Resolved::Hit(m) => (m, EtherType::IPV4),
                        Resolved::Probe(m) => {
                            probe = Some((IpAddr::V4(target), m));
                            (m, EtherType::IPV4)
                        }
                        Resolved::Miss => {
                            let first = self.arp_pending.enqueue_at(target, pkt.as_bytes(), now);
                            if first {
                                self.send_arp_request(target);
                            }
                            return;
                        }
                    }
                }
            }
            6 => {
                if pkt.is_multicast() {
                    let d = pkt.ipv6_dst_addr().unwrap().octets();
                    (
                        MacAddr([0x33, 0x33, d[12], d[13], d[14], d[15]]),
                        EtherType::IPV6,
                    )
                } else {
                    let dst = pkt.ipv6_dst_addr().unwrap();
                    // Link-local addresses are on-link whatever the prefix
                    // (RFC 4861 §5.2); a router would not forward them.
                    // Anything else outside our prefix goes to the router,
                    // and with none there is no route: RFC 4943 withdrew
                    // the old rule that took such a destination for
                    // on-link, since soliciting it only delays the failure
                    // (or finds a host that should not have answered).
                    let target = if self.on_link_v6(dst) {
                        dst
                    } else {
                        match *self.gateway_v6.lock().unwrap() {
                            Some(gw) => gw,
                            None => return,
                        }
                    };
                    match self.ndp.resolve_at(target, now) {
                        Resolved::Hit(m) => (m, EtherType::IPV6),
                        Resolved::Probe(m) => {
                            probe = Some((IpAddr::V6(target), m));
                            (m, EtherType::IPV6)
                        }
                        Resolved::Miss => {
                            if self.ndp_pending.enqueue_at(target, pkt.as_bytes(), now) {
                                self.send_neighbor_solicitation(target);
                            }
                            return;
                        }
                    }
                }
            }
            _ => return,
        };

        let frame = build_frame(dst_mac, self.mac, ether_type, pkt.as_bytes());
        self.send_l2(Frame::from_slice(&frame));
        match probe {
            Some((IpAddr::V4(ip), mac)) => self.send_arp_request_to(ip, mac),
            Some((IpAddr::V6(ip), mac)) => self.send_neighbor_solicitation_to(ip, mac),
            None => {}
        }
    }

    /// The directed broadcast of our own IPv4 subnet, e.g. 10.0.0.255 in
    /// 10.0.0.0/24: nobody answers ARP for it, it goes to every station.
    fn is_subnet_broadcast(&self, dst: Ipv4Addr) -> bool {
        let prefix = self.l3.addr();
        match prefix.addr() {
            // A /31 or /32 has no broadcast address (RFC 3021).
            IpAddr::V4(a) if prefix.is_valid() && prefix.bits() < 31 => {
                let host = u32::MAX >> prefix.bits();
                u32::from(dst) == u32::from(a) | host
            }
            _ => false,
        }
    }

    fn handle_arp(&self, f: &Frame) {
        let p = match arp::parse(f.payload()) {
            Some(p) => p,
            None => return,
        };
        let (op, sender_mac, sender_ip, _, target_ip) = p;

        // RFC 5227 §2.1.1: while probing, the address is taken if anyone
        // sends ARP from it, or probes for it too. Our own probe coming back
        // (a hub floods broadcasts to every port) is neither.
        #[cfg(feature = "dhcp")]
        if sender_mac != self.mac
            && let Some((ip, conflict)) = self.probe.lock().unwrap().as_mut()
            && (sender_ip == *ip || (sender_ip.is_unspecified() && target_ip == *ip))
        {
            *conflict = true;
        }
        let our_addr = match self.l3.addr().addr() {
            IpAddr::V4(a) if !a.is_unspecified() => Some(a),
            _ => None,
        };
        // Someone else sending from our address (RFC 5227 §2.4) is a
        // conflict to report, not a neighbour: caching it would point our
        // own address at another station, and answering a gratuitous ARP
        // would only argue with it. Our own ARP looped back by a hub is
        // neither.
        if our_addr.is_some() && our_addr == Some(sender_ip) {
            if sender_mac != self.mac {
                self.conflicts.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        let for_us = our_addr == Some(target_ip);

        // RFC 826's merge rule: refresh a station already known from any
        // ARP it sends, but add a new one only when it is talking to us (or
        // answering our question), so the cache holds what we use rather
        // than everyone overheard. A 0.0.0.0 sender is probing for an
        // address (RFC 5227) and owns nothing yet.
        // A stranger must also be on our subnet: we would never ARP for an
        // address outside it, so an entry for one could only be junk, and
        // letting anyone mint them would let one host fill the cache.
        if !sender_ip.is_unspecified()
            && ((for_us && self.on_link_v4(sender_ip))
                || self.arp.lookup(sender_ip).is_some()
                || self.arp_pending.contains(sender_ip))
        {
            // Only a reply sent to us answers a request or probe of ours,
            // and so shows the neighbour reachable (as RFC 4861 §7.3.1 has
            // a solicited advertisement do). Requests and broadcast
            // replies are overheard: they keep the MAC current, but leave
            // it to be checked when next used.
            let confirmed = op == arp::OP_REPLY && for_us && f.dst_mac() == Some(self.mac);
            self.arp.update(sender_ip, sender_mac, confirmed, true);
            // Straight to the MAC just learnt rather than back through
            // handle_outgoing: the queue was only waiting for this answer,
            // and a second lookup that missed would queue and solicit again.
            for buf in self.arp_pending.drain(sender_ip) {
                let frame = build_frame(sender_mac, self.mac, EtherType::IPV4, &buf);
                self.send_l2(Frame::from_slice(&frame));
            }
        }

        if let Some(our_addr) = our_addr
            && op == arp::OP_REQUEST
            && for_us
        {
            let payload =
                arp::build_packet(arp::OP_REPLY, self.mac, our_addr, sender_mac, sender_ip);
            let frame = build_frame(sender_mac, self.mac, EtherType::ARP, &payload);
            self.send_l2(Frame::from_slice(&frame));
        }
    }

    /// Whether `ip` is an address we would ARP for directly: on our subnet,
    /// or IPv4 link-local (RFC 3927 §2.6.2).
    fn on_link_v4(&self, ip: Ipv4Addr) -> bool {
        let prefix = self.l3.addr();
        ip.is_link_local() || (prefix.is_valid() && prefix.contains(IpAddr::V4(ip)))
    }

    /// The IPv6 counterpart of [`on_link_v4`](Self::on_link_v4).
    fn on_link_v6(&self, ip: Ipv6Addr) -> bool {
        let prefix = self.l3.addr();
        ip.is_unicast_link_local() || (prefix.is_valid() && prefix.contains(IpAddr::V6(ip)))
    }

    fn send_arp_request(&self, target: Ipv4Addr) {
        self.send_arp_request_to(target, MacAddr::broadcast());
    }

    /// An ARP request for `target` to `dst`: broadcast to resolve it, or
    /// unicast to the MAC we have for it to check it is still there (RFC
    /// 1122 §2.3.2.1).
    fn send_arp_request_to(&self, target: Ipv4Addr, dst: MacAddr) {
        let our_addr = match self.l3.addr().addr() {
            IpAddr::V4(a) => a,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let payload =
            arp::build_packet(arp::OP_REQUEST, self.mac, our_addr, MacAddr::zero(), target);
        let frame = build_frame(dst, self.mac, EtherType::ARP, &payload);
        self.send_l2(Frame::from_slice(&frame));
    }

    /// Terminate Neighbor Solicitations and Advertisements, which are the
    /// adapter's business; returns `false` for any other ICMPv6, which goes
    /// on to the L3 device. `frame_src` is the Ethernet sender.
    fn handle_ndp(&self, pkt: &Packet, frame_src: Option<MacAddr>) -> bool {
        let icmp = pkt.ipv6_payload();
        if icmp.is_empty() || (icmp[0] != ndp::NS_TYPE && icmp[0] != ndp::NA_TYPE) {
            return false;
        }
        // From here the message is consumed either way: one failing the
        // checks of RFC 4861 §7.1 is silently discarded, not passed on.
        let (Some(src), Some(dst)) = (pkt.ipv6_src_addr(), pkt.ipv6_dst_addr()) else {
            return true;
        };
        // A hop limit of 255 proves the sender is on-link: a router would
        // have decremented it.
        if pkt.ipv6_hop_limit() != 255
            || icmp.len() < 24
            || icmp[1] != 0
            || ndp::icmpv6_checksum(src, dst, icmp) != 0
        {
            return true;
        }
        let mut t = [0u8; 16];
        t.copy_from_slice(&icmp[8..24]);
        let target = Ipv6Addr::from(t);
        let opts = &icmp[24..];
        if target.is_multicast() || !ndp::options_valid(opts) {
            return true;
        }

        if icmp[0] == ndp::NS_TYPE {
            let slla = ndp::parse_option(opts, ndp::OPT_SOURCE_LINK_ADDR);
            // Duplicate Address Detection: only to a solicited-node group,
            // and with no address of the sender's to offer.
            if src.is_unspecified()
                && (dst != ndp::solicited_node_multicast(target) || slla.is_some())
            {
                return true;
            }

            // RFC 4861 §7.2.3: an NS whose target is not ours is silently
            // discarded -- before anything is learnt from it. Anyone on the
            // link hears a multicast NS, and caching its source for every
            // one overheard would let any station rewrite, say, the
            // gateway's entry by soliciting some other address.
            if !self.is_our_v6(target) {
                return true;
            }
            // Another station soliciting from one of our addresses is
            // using it too: a conflict, and nobody to learn or answer.
            if self.is_our_v6(src) {
                self.note_conflict(frame_src);
                return true;
            }
            // As for ARP, a neighbour we would never resolve ourselves is
            // not worth a cache entry, and anyone may claim one.
            if !src.is_unspecified()
                && self.on_link_v6(src)
                && let Some(mac) = slla
            {
                // RFC 4861 §7.2.3: not a confirmation, and a new or
                // changed address is STALE, to be probed when used.
                self.learn_neighbor(src, mac, false, true);
            }

            if src.is_unspecified() {
                // DAD: answer to all-nodes (RFC 4861 §7.2.4).
                let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
                let mac = MacAddr([0x33, 0x33, 0, 0, 0, 1]);
                self.send_neighbor_advertisement(all_nodes, mac, target, false);
            } else if let Some(mac) = slla.or_else(|| self.ndp.lookup(src)).or(frame_src) {
                // Without a source link-layer option the sender is still
                // right there: it is the frame's own source.
                self.send_neighbor_advertisement(src, mac, target, true);
            }
            return true;
        }

        let solicited = icmp[4] & 0x40 != 0;
        let override_ = icmp[4] & 0x20 != 0;
        if solicited && dst.is_multicast() {
            return true;
        }
        // Somebody else advertising one of our addresses: a conflict, and
        // never a cache entry for ourselves.
        if self.is_our_v6(target) {
            self.note_conflict(frame_src);
            return true;
        }
        // RFC 4861 §7.2.5: an advertisement for an address nobody here
        // asked about is not cached. One without a target link-layer
        // address can only speak for the one already cached -- as the
        // answer to a unicast probe may (§7.2.4).
        let known = self.ndp.lookup(target);
        if known.is_none() && !self.ndp_pending.contains(target) {
            return true;
        }
        let Some(mac) = ndp::parse_option(opts, ndp::OPT_TARGET_LINK_ADDR).or(known) else {
            return true;
        };
        self.learn_neighbor(target, mac, solicited, override_);
        true
    }

    /// One of our IPv6 addresses: the configured one or the link-local.
    fn is_our_v6(&self, ip: Ipv6Addr) -> bool {
        ip == ndp::link_local_from_mac(self.mac) || self.l3.addr().addr() == IpAddr::V6(ip)
    }

    /// Count a message claiming one of our addresses, unless it is our own,
    /// looped back.
    fn note_conflict(&self, frame_src: Option<MacAddr>) {
        if frame_src != Some(self.mac) {
            self.conflicts.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drop the ARP cache and whatever was queued for resolution, when the
    /// IPv4 configuration they were learnt under goes away. `keep_dhcp`
    /// spares the DHCP client's own messages still waiting for the server
    /// to be resolved: a DHCPRELEASE goes out just before the lease it
    /// gives up is lost, and is still due.
    #[cfg(feature = "dhcp")]
    fn forget_ipv4_neighbours(&self, keep_dhcp: bool) {
        self.arp.clear();
        if keep_dhcp {
            self.arp_pending
                .retain_packets(|p| is_dhcp_to_server(Packet::from_slice(p)));
        } else {
            self.arp_pending.clear();
        }
    }

    /// Cache a neighbour's MAC, as [`arp::Table::update`] takes it, and send
    /// whatever was waiting for it, however it was learnt.
    fn learn_neighbor(&self, ip: Ipv6Addr, mac: MacAddr, solicited: bool, override_: bool) {
        self.ndp.update(ip, mac, solicited, override_);
        // An advertisement that may not override leaves the cached MAC.
        let mac = self.ndp.lookup(ip).unwrap_or(mac);
        // Sent to `mac` directly, not looked up again: what was waiting was
        // waiting for this answer, and a lookup that missed would only queue
        // it and solicit once more.
        for buf in self.ndp_pending.drain(ip) {
            let frame = build_frame(mac, self.mac, EtherType::IPV6, &buf);
            self.send_l2(Frame::from_slice(&frame));
        }
    }

    fn send_neighbor_solicitation(&self, target: Ipv6Addr) {
        let dst = ndp::solicited_node_multicast(target);
        let dst_mac = ndp::solicited_node_mac(target);
        self.send_ns(target, dst, dst_mac);
    }

    /// A unicast NS, checking that `target` is still at `mac` (RFC 4861
    /// §7.3.3 PROBE).
    fn send_neighbor_solicitation_to(&self, target: Ipv6Addr, mac: MacAddr) {
        self.send_ns(target, target, mac);
    }

    fn send_ns(&self, target: Ipv6Addr, dst: Ipv6Addr, dst_mac: MacAddr) {
        let src = ndp::link_local_from_mac(self.mac);
        let mut payload = ndp::build_ns(self.mac, target);
        let ip = ndp::wrap_icmpv6(src, dst, &mut payload);
        let frame = build_frame(dst_mac, self.mac, EtherType::IPV6, &ip);
        self.send_l2(Frame::from_slice(&frame));
    }

    fn send_neighbor_advertisement(
        &self,
        dst_addr: Ipv6Addr,
        dst_mac: MacAddr,
        target: Ipv6Addr,
        solicited: bool,
    ) {
        let src = target;
        let mut payload = ndp::build_na(self.mac, target, solicited);
        let ip = ndp::wrap_icmpv6(src, dst_addr, &mut payload);
        let frame = build_frame(dst_mac, self.mac, EtherType::IPV6, &ip);
        self.send_l2(Frame::from_slice(&frame));
    }
}

impl L2Device for L2Adapter {
    fn set_handler(&self, h: L2Handler) {
        *self.l2_handler.lock().unwrap() = Some(h);
    }
    fn send(&self, f: &Frame) -> Result<()> {
        self.handle_incoming(f);
        Ok(())
    }
    fn hw_addr(&self) -> MacAddr {
        self.mac
    }
    fn close(&self) -> Result<()> {
        #[cfg(feature = "dhcp")]
        self.stop_dhcp();
        Ok(())
    }
}

/// Run the adapter's timers until it is dropped.
#[cfg(not(target_family = "wasm"))]
fn spawn_timer(a: &Arc<L2Adapter>) {
    let weak = Arc::downgrade(a);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(TIMER_INTERVAL);
            let Some(a) = weak.upgrade() else {
                return;
            };
            a.run_timers(Instant::now());
        }
    });
}

// --- DHCP integration ------------------------------------------------------

/// A DHCP client-to-server datagram (UDP 68 to 67), as the adapter's DHCP
/// client sends by unicast.
#[cfg(feature = "dhcp")]
fn is_dhcp_to_server(pkt: &Packet) -> bool {
    if !pkt.is_valid()
        || pkt.version() != 4
        || pkt.ipv4_protocol() != Protocol::UDP
        || pkt.ipv4_is_fragment()
    {
        return false;
    }
    let udp = pkt.ipv4_payload();
    udp.len() >= 8 && udp[0..2] == 68u16.to_be_bytes() && udp[2..4] == 67u16.to_be_bytes()
}

#[cfg(feature = "dhcp")]
struct AdapterDhcpTransport {
    weak: Weak<L2Adapter>,
}

#[cfg(feature = "dhcp")]
impl crate::dhcp::ClientTransport for AdapterDhcpTransport {
    fn mac(&self) -> MacAddr {
        self.weak
            .upgrade()
            .map(|a| a.mac)
            .unwrap_or(MacAddr::zero())
    }
    fn send_broadcast(&self, frame: &Frame) {
        if let Some(a) = self.weak.upgrade() {
            a.send_l2(frame);
        }
    }
    fn send_unicast(&self, dst_ip: Ipv4Addr, frame: &Frame) {
        let Some(a) = self.weak.upgrade() else {
            return;
        };
        // An on-link server is sent to at the MAC its own messages came
        // from. ARP could name another station: a virtual LAN may give the
        // DHCP server the router's address, and then the router answers
        // the ARP but would not hand the message on. Only the message goes
        // there; the ARP cache is not told, so the router keeps the
        // address for everything else.
        let known = *a.dhcp_server.lock().unwrap();
        if let Some((ip, mac)) = known
            && ip == dst_ip
            && a.on_link_v4(ip)
        {
            let mut buf = frame.as_bytes().to_vec();
            buf[0..6].copy_from_slice(&mac.octets());
            a.send_l2(Frame::from_slice(&buf));
            return;
        }
        // Otherwise routed like the host's own traffic: to the server, or
        // to the gateway if the server is off our subnet, ARPing for it (and
        // queueing the message) on a miss. Sent to the broadcast MAC, a
        // datagram for a unicast address would be discarded by a host
        // following RFC 1122 §3.3.6.
        if frame.ether_type() == EtherType::IPV4 {
            a.handle_outgoing(Packet::from_slice(frame.payload()));
        }
    }
    fn can_probe(&self) -> bool {
        true
    }
    fn begin_probe(&self, ip: Ipv4Addr) {
        if let Some(a) = self.weak.upgrade() {
            *a.probe.lock().unwrap() = Some((ip, false));
        }
    }
    fn end_probe(&self) {
        if let Some(a) = self.weak.upgrade() {
            *a.probe.lock().unwrap() = None;
        }
    }
    fn send_probe(&self, ip: Ipv4Addr) {
        let Some(a) = self.weak.upgrade() else {
            return;
        };
        // Only begin_probe starts watching for a conflict. A probe can
        // reach here late: after its check ended, or after a new client
        // (start_dhcp again) began one for another address. Recording it
        // would revive a check nothing is left to end, or wipe what the
        // current one has found.

        // Sender address zero: the probe must not teach anyone's cache an
        // address we do not have yet.
        let payload = arp::build_packet(
            arp::OP_REQUEST,
            a.mac,
            Ipv4Addr::UNSPECIFIED,
            MacAddr::zero(),
            ip,
        );
        let frame = build_frame(MacAddr::broadcast(), a.mac, EtherType::ARP, &payload);
        a.send_l2(Frame::from_slice(&frame));
    }
    fn send_announcement(&self, ip: Ipv4Addr) {
        let Some(a) = self.weak.upgrade() else {
            return;
        };
        let payload = arp::build_packet(arp::OP_REQUEST, a.mac, ip, MacAddr::zero(), ip);
        let frame = build_frame(MacAddr::broadcast(), a.mac, EtherType::ARP, &payload);
        a.send_l2(Frame::from_slice(&frame));
    }
    fn probe_conflict(&self, ip: Ipv4Addr) -> bool {
        self.weak.upgrade().is_some_and(|a| {
            a.probe
                .lock()
                .unwrap()
                .is_some_and(|(p, conflict)| p == ip && conflict)
        })
    }
    fn on_bound(&self, prefix: IpPrefix, gateway: Option<Ipv4Addr>) {
        if let Some(a) = self.weak.upgrade() {
            *a.probe.lock().unwrap() = None;
            // A lease on another network makes every neighbour we know of
            // somebody else's; a renewal of the same one does not.
            if a.l3.addr() != prefix {
                a.forget_ipv4_neighbours(false);
            }
            let _ = a.l3.set_addr(prefix);
            // The lease is the whole configuration: one naming no router
            // means there is none, not that the last lease's still applies.
            a.set_gw_v4(gateway);
        }
    }
    fn on_lease_lost(&self) {
        // The leased address must not be used past the lease (RFC 2131
        // §4.4.5); leave the device unconfigured until the next lease, and
        // drop what came with it -- the next lease may be elsewhere.
        if let Some(a) = self.weak.upgrade() {
            if a.l3.addr().is_v4() {
                let _ =
                    a.l3.set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            }
            a.set_gw_v4(None);
            a.forget_ipv4_neighbours(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "dhcp"))]
    use crate::IpPrefix;
    use crate::PipeL3;
    use std::time::Duration;

    #[test]
    fn arp_reply_on_request_for_our_ip() {
        let pipe = Arc::new(PipeL3::new("10.0.0.5/24".parse().unwrap()));
        let adapter = L2Adapter::new_arc(pipe, L2AdapterConfig::default());

        // Record frames the adapter sends out.
        let out = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let oc = out.clone();
        adapter.set_handler(Arc::new(move |f: &Frame| {
            oc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));

        // Build an ARP request: who-has 10.0.0.5
        let sender_mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let payload = arp::build_packet(
            arp::OP_REQUEST,
            sender_mac,
            Ipv4Addr::new(10, 0, 0, 1),
            MacAddr::zero(),
            Ipv4Addr::new(10, 0, 0, 5),
        );
        let frame = build_frame(adapter.mac, sender_mac, EtherType::ARP, &payload);
        adapter.send(Frame::from_slice(&frame)).unwrap();

        // Adapter should have sent an ARP reply.
        let frames = out.lock().unwrap();
        assert_eq!(frames.len(), 1);
        let f = Frame::from_slice(&frames[0]);
        assert_eq!(f.ether_type(), EtherType::ARP);
        let (op, sm, si, _, _) = arp::parse(f.payload()).unwrap();
        assert_eq!(op, arp::OP_REPLY);
        assert_eq!(sm, adapter.mac);
        assert_eq!(si, Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn outgoing_ipv4_triggers_arp_request() {
        let pipe = Arc::new(PipeL3::new("10.0.0.5/24".parse().unwrap()));
        let adapter = L2Adapter::new_arc(pipe.clone(), L2AdapterConfig::default());

        let out = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let oc = out.clone();
        adapter.set_handler(Arc::new(move |f: &Frame| {
            oc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));

        // Inject an L3 packet 10.0.0.5 -> 10.0.0.6 via the pipe — the pipe's
        // handler is set by L2Adapter::new_arc to handle_outgoing.
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[12..16].copy_from_slice(&[10, 0, 0, 5]);
        p[16..20].copy_from_slice(&[10, 0, 0, 6]);
        pipe.inject(Packet::from_slice(&p)).unwrap();

        // First send: ARP request (no cache hit).
        let frames = out.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(Frame::from_slice(&frames[0]).ether_type(), EtherType::ARP);
    }

    type Out = Arc<Mutex<Vec<Vec<u8>>>>;

    fn rig(addr: &str) -> (Arc<PipeL3>, Arc<L2Adapter>, Out) {
        let pipe = Arc::new(PipeL3::new(addr.parse().unwrap()));
        // No timer thread: the tests say when time passes.
        let adapter = L2Adapter::build(pipe.clone(), L2AdapterConfig::default(), false);
        let out: Out = Arc::default();
        let oc = out.clone();
        adapter.set_handler(Arc::new(move |f: &Frame| {
            oc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));
        (pipe, adapter, out)
    }

    /// An L3 device that keeps what the adapter delivers to it apart from
    /// what it sends, which a `PipeL3` runs through the same handler.
    #[derive(Default)]
    struct Host {
        addr: Mutex<Option<IpPrefix>>,
        handler: Mutex<Option<L3Handler>>,
        got: Mutex<Vec<Vec<u8>>>,
    }

    impl core::fmt::Debug for Host {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("Host")
        }
    }

    impl L3Device for Host {
        fn set_handler(&self, h: L3Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, p: &Packet) -> Result<()> {
            self.got.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }
        fn addr(&self) -> IpPrefix {
            self.addr.lock().unwrap().unwrap()
        }
        fn set_addr(&self, p: IpPrefix) -> Result<()> {
            *self.addr.lock().unwrap() = Some(p);
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    impl Host {
        fn out(&self, p: &[u8]) {
            let h = self.handler.lock().unwrap().clone().unwrap();
            h(Packet::from_slice(p)).unwrap();
        }
        fn take(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.got.lock().unwrap())
        }
    }

    fn host_rig(addr: &str) -> (Arc<Host>, Arc<L2Adapter>, Out) {
        let host = Arc::new(Host::default());
        *host.addr.lock().unwrap() = Some(addr.parse().unwrap());
        let adapter = L2Adapter::build(host.clone(), L2AdapterConfig::default(), false);
        let out: Out = Arc::default();
        let oc = out.clone();
        adapter.set_handler(Arc::new(move |f: &Frame| {
            oc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));
        (host, adapter, out)
    }

    /// The target of each ARP request or NS among `frames`.
    fn solicited(frames: &[Vec<u8>]) -> Vec<IpAddr> {
        frames
            .iter()
            .filter_map(|f| {
                let f = Frame::from_slice(f);
                if f.ether_type() == EtherType::ARP {
                    let (op, _, _, _, ti) = arp::parse(f.payload())?;
                    return (op == arp::OP_REQUEST).then_some(IpAddr::V4(ti));
                }
                let p = Packet::from_slice(f.payload());
                let icmp = p.ipv6_payload();
                (p.version() == 6
                    && p.ipv6_next_header() == Protocol::ICMPV6
                    && icmp.first() == Some(&ndp::NS_TYPE))
                .then(|| IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&icmp[8..24]).unwrap())))
            })
            .collect()
    }

    #[test]
    fn unanswered_solicitations_are_retried_then_reported_unreachable() {
        for (addr, src, dst) in [
            ("10.0.0.5/24", "10.0.0.5", "10.0.0.6"),
            ("2001:db8::5/64", "2001:db8::5", "2001:db8::66"),
        ] {
            let (host, adapter, out) = host_rig(addr);
            let (src, dst): (IpAddr, IpAddr) = (src.parse().unwrap(), dst.parse().unwrap());
            let udp = crate::build::build_udp(src, dst, 1000, 2000, b"hi");
            let pkt = crate::build::build_ip(src, dst, Protocol::UDP, 64, &udp).unwrap();
            let t0 = Instant::now();
            host.out(&pkt);
            host.out(&pkt);
            assert_eq!(solicited(&take(&out)), [dst]);

            // RETRANS_TIMER apart, MAX_MULTICAST_SOLICIT in all.
            let at = |ms| t0 + Duration::from_millis(ms);
            adapter.run_timers(at(500));
            assert!(take(&out).is_empty());
            adapter.run_timers(at(1050));
            assert_eq!(solicited(&take(&out)), [dst], "not solicited again");
            adapter.run_timers(at(2100));
            assert_eq!(solicited(&take(&out)), [dst]);
            assert!(host.take().is_empty());

            // Then each waiting packet is reported to its sender.
            adapter.run_timers(at(3200));
            assert!(take(&out).is_empty(), "solicited a fourth time");
            let errs = host.take();
            assert_eq!(errs.len(), 2, "one error per queued packet");
            let e = Packet::from_slice(&errs[0]);
            assert_eq!(e.dst_addr(), Some(src));
            let icmp = e.transport_payload();
            if src.is_ipv4() {
                assert_eq!(e.ip_protocol(), Protocol::ICMP);
                assert_eq!((icmp[0], icmp[1]), (3, 1), "host unreachable");
            } else {
                assert_eq!(e.ip_protocol(), Protocol::ICMPV6);
                assert_eq!((icmp[0], icmp[1]), (1, 3), "address unreachable");
            }
            assert_eq!(&icmp[8..8 + pkt.len()], &pkt[..], "original quoted");
        }
    }

    /// An ARP reply from `mac`/`ip`, sent to the adapter itself.
    fn arp_reply_to(adapter: &L2Adapter, mac: MacAddr, ip: [u8; 4], target: [u8; 4]) {
        let payload = arp::build_packet(arp::OP_REPLY, mac, ip.into(), adapter.mac, target.into());
        let frame = build_frame(adapter.mac, mac, EtherType::ARP, &payload);
        adapter.send(Frame::from_slice(&frame)).unwrap();
    }

    #[test]
    fn a_neighbour_that_moved_is_found_again_within_seconds() {
        let (_pipe, adapter, out) = rig("10.0.0.5/24");
        let (old, new) = (MacAddr([2, 0, 0, 0, 0, 6]), MacAddr([2, 0, 0, 0, 0, 0x16]));
        let pkt = v4_packet([10, 0, 0, 5], [10, 0, 0, 6]);
        let send = |at: Instant| {
            adapter.handle_outgoing_at(Packet::from_slice(&pkt), at);
            take(&out)
        };
        let t0 = Instant::now();
        let at = |s: u64, ms: u64| t0 + Duration::from_secs(s) + Duration::from_millis(ms);
        let arp_to = |frames: &[Vec<u8>]| -> Vec<Option<MacAddr>> {
            frames
                .iter()
                .map(|f| Frame::from_slice(f))
                .filter(|f| f.ether_type() == EtherType::ARP)
                .map(|f| f.dst_mac())
                .collect()
        };

        assert_eq!(arp_to(&send(t0)), [Some(MacAddr::broadcast())]);
        arp_reply_to(&adapter, old, [10, 0, 0, 6], [10, 0, 0, 5]);
        assert_eq!(take(&out).len(), 1, "queued packet delivered");

        // The neighbour is swapped for another machine that sends nothing.
        // Past REACHABLE_TIME the entry is STALE; once used, it is probed
        // at its old MAC, which never answers.
        let got = send(at(31, 0));
        assert_eq!(Frame::from_slice(&got[0]).dst_mac(), Some(old));
        adapter.run_timers(at(36, 0));
        assert_eq!(arp_to(&take(&out)), [Some(old)], "unicast probe");
        adapter.run_timers(at(37, 0));
        adapter.run_timers(at(38, 0));
        assert_eq!(arp_to(&take(&out)), [Some(old), Some(old)]);
        adapter.run_timers(at(39, 0));
        assert!(take(&out).is_empty());

        // Given up on: the next packet is resolved afresh, and reaches the
        // new MAC -- seconds after the move, not minutes.
        assert_eq!(arp_to(&send(at(39, 100))), [Some(MacAddr::broadcast())]);
        arp_reply_to(&adapter, new, [10, 0, 0, 6], [10, 0, 0, 5]);
        let got = take(&out);
        assert_eq!(Frame::from_slice(&got[0]).dst_mac(), Some(new));
    }

    #[test]
    fn an_ipv6_neighbour_is_probed_by_unicast_and_confirmed() {
        let (_pipe, adapter, out) = rig("2001:db8::5/64");
        let pkt = v6_packet(our_ip(), peer_ip());
        let t0 = Instant::now();
        adapter.handle_outgoing_at(Packet::from_slice(&pkt), t0);
        take(&out);
        let mut na = ndp::build_na(PEER_MAC, peer_ip(), true);
        let f = ndp_frame(&adapter, PEER_MAC, peer_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        take(&out);

        let later = t0 + arp::REACHABLE_TIME + Duration::from_secs(1);
        adapter.handle_outgoing_at(Packet::from_slice(&pkt), later);
        take(&out);
        adapter.run_timers(later + arp::DELAY_FIRST_PROBE_TIME);
        let sent = take(&out);
        assert_eq!(solicited(&sent), [IpAddr::V6(peer_ip())]);
        let f = Frame::from_slice(&sent[0]);
        assert_eq!(f.dst_mac(), Some(PEER_MAC), "probe not unicast");
        assert_eq!(
            Packet::from_slice(f.payload()).ipv6_dst_addr(),
            Some(peer_ip())
        );

        // A solicited NA, even without a link-layer address, confirms it.
        let mut na = ndp::build_na(PEER_MAC, peer_ip(), true)[..24].to_vec();
        let f = ndp_frame(&adapter, PEER_MAC, peer_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        adapter.run_timers(later + Duration::from_secs(10));
        assert!(take(&out).is_empty(), "probed a confirmed neighbour");
        assert_eq!(adapter.ndp.lookup(peer_ip()), Some(PEER_MAC));
    }

    fn take(out: &Out) -> Vec<Vec<u8>> {
        std::mem::take(&mut *out.lock().unwrap())
    }

    fn v6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 59; // no next header
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    /// An NDP message from `src_mac`/`src`, as the adapter would receive it.
    fn ndp_frame(
        adapter: &L2Adapter,
        src_mac: MacAddr,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        icmp: &mut [u8],
    ) -> Vec<u8> {
        let ip = ndp::wrap_icmpv6(src, dst, icmp);
        build_frame(adapter.mac, src_mac, EtherType::IPV6, &ip)
    }

    const PEER_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 0x66]);

    fn peer_ip() -> Ipv6Addr {
        "2001:db8::66".parse().unwrap()
    }

    fn our_ip() -> Ipv6Addr {
        "2001:db8::5".parse().unwrap()
    }

    #[test]
    fn neighbour_queue_is_bounded() {
        let (pipe, adapter, out) = rig("2001:db8::5/64");
        for _ in 0..100 {
            pipe.inject(Packet::from_slice(&v6_packet(our_ip(), peer_ip())))
                .unwrap();
        }
        assert_eq!(take(&out).len(), 1, "one solicitation");

        let mut na = ndp::build_na(PEER_MAC, peer_ip(), true);
        let f = ndp_frame(&adapter, PEER_MAC, peer_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        let flushed = take(&out);
        assert!(!flushed.is_empty());
        assert!(flushed.len() <= arp::PENDING_MAX_PKTS, "{}", flushed.len());
    }

    #[test]
    fn solicitation_from_the_neighbour_flushes_its_queue() {
        let (pipe, adapter, out) = rig("2001:db8::5/64");
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), peer_ip())))
            .unwrap();
        assert_eq!(take(&out).len(), 1, "NS sent");

        // The neighbour happens to resolve us first.
        let mut ns = ndp::build_ns(PEER_MAC, our_ip());
        let f = ndp_frame(
            &adapter,
            PEER_MAC,
            peer_ip(),
            ndp::solicited_node_multicast(our_ip()),
            &mut ns,
        );
        adapter.send(Frame::from_slice(&f)).unwrap();
        let sent = take(&out);
        let data: Vec<_> = sent
            .iter()
            .map(|f| Frame::from_slice(f))
            .filter(|f| Packet::from_slice(f.payload()).ipv6_next_header() == Protocol(59))
            .collect();
        assert_eq!(data.len(), 1, "queued packet delivered");
        assert_eq!(data[0].dst_mac(), Some(PEER_MAC));
    }

    #[test]
    fn advertisement_into_a_full_cache_still_delivers() {
        let (pipe, adapter, out) = rig("2001:db8::5/64");
        for i in 0..ndp::MAX_ENTRIES as u32 {
            let ip = Ipv6Addr::from(0x2001_0db8_u128 << 96 | 0x1_0000 | i as u128);
            adapter
                .ndp
                .set(ip, MacAddr([2, 0, 0, 0, 0, 1]), ndp::DEFAULT_TTL);
        }
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), peer_ip())))
            .unwrap();
        assert_eq!(take(&out).len(), 1, "NS sent");

        let mut na = ndp::build_na(PEER_MAC, peer_ip(), true);
        let f = ndp_frame(&adapter, PEER_MAC, peer_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        let sent = take(&out);
        assert_eq!(sent.len(), 1, "solicited again instead of delivering");
        let f = Frame::from_slice(&sent[0]);
        assert_eq!(f.dst_mac(), Some(PEER_MAC));
        assert_eq!(
            Packet::from_slice(f.payload()).ipv6_next_header(),
            Protocol(59)
        );
        assert_eq!(adapter.ndp.lookup(peer_ip()), Some(PEER_MAC));
    }

    #[test]
    fn arp_flood_does_not_lock_out_real_neighbours() {
        let (pipe, adapter, out) = rig("10.0.0.5/16");
        // Requests for us from made-up senders on our subnet fill the cache.
        for i in 0..arp::MAX_ENTRIES as u32 {
            let ip = (0x0a00_1000 + i).to_be_bytes();
            let mac = MacAddr([2, 0xee, 0, 0, (i >> 8) as u8, i as u8]);
            arp_in(&adapter, arp::OP_REQUEST, mac, ip, [10, 0, 0, 5]);
        }
        take(&out);

        pipe.inject(Packet::from_slice(&v4_packet([10, 0, 0, 5], [10, 0, 0, 6])))
            .unwrap();
        assert_eq!(take(&out).len(), 1, "ARP request");
        let real = MacAddr([2, 0, 0, 0, 0, 6]);
        arp_in(&adapter, arp::OP_REPLY, real, [10, 0, 0, 6], [10, 0, 0, 5]);

        let sent = take(&out);
        assert_eq!(sent.len(), 1, "re-solicited instead of delivering");
        let f = Frame::from_slice(&sent[0]);
        assert_eq!(f.ether_type(), EtherType::IPV4);
        assert_eq!(f.dst_mac(), Some(real));
        assert_eq!(adapter.arp.lookup(Ipv4Addr::new(10, 0, 0, 6)), Some(real));
    }

    #[test]
    fn a_solicitation_flood_does_not_evict_the_router() {
        let (pipe, adapter, out) = rig("2001:db8::5/64");
        let gw: Ipv6Addr = "fe80::1".parse().unwrap();
        let gw_mac = MacAddr([2, 0, 0, 0, 0, 1]);
        adapter.set_gateway_v6(gw);
        let mut ns = ndp::build_ns(gw_mac, our_ip());
        let f = ndp_frame(&adapter, gw_mac, gw, our_ip(), &mut ns);
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(gw), Some(gw_mac));

        // NSes for us from made-up link-local senders, each with a source
        // link-layer address, overflow the cache.
        for i in 0..2 * ndp::MAX_ENTRIES as u32 {
            let src = Ipv6Addr::from(0xfe80_u128 << 112 | 0x10_0000 | i as u128);
            let mac = MacAddr([2, 0xee, 0, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            let mut ns = ndp::build_ns(mac, our_ip());
            let f = ndp_frame(&adapter, mac, src, our_ip(), &mut ns);
            adapter.send(Frame::from_slice(&f)).unwrap();
        }
        take(&out);

        assert_eq!(adapter.ndp.lookup(gw), Some(gw_mac), "router evicted");
        let far: Ipv6Addr = "2001:db9::1".parse().unwrap();
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), far)))
            .unwrap();
        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        assert_eq!(Frame::from_slice(&sent[0]).dst_mac(), Some(gw_mac));
    }

    #[test]
    fn a_subnet_sweep_does_not_keep_the_router_from_being_resolved() {
        let (pipe, adapter, out) = rig("10.0.0.5/16");
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        adapter.set_gateway_v4(gw);
        // Traffic for every address on the subnet, none of which answers.
        let mut big = v4_packet([10, 0, 0, 5], [0; 4]);
        big.resize(1400, 0);
        big[2..4].copy_from_slice(&1400u16.to_be_bytes());
        for i in 0..2 * arp::PENDING_MAX_TARGETS as u32 {
            big[16..20].copy_from_slice(&(0x0a00_1000 + i).to_be_bytes());
            for _ in 0..arp::PENDING_MAX_PKTS {
                pipe.inject(Packet::from_slice(&big)).unwrap();
            }
        }
        take(&out);

        pipe.inject(Packet::from_slice(&v4_packet([10, 0, 0, 5], [8, 8, 8, 8])))
            .unwrap();
        assert_eq!(
            solicited(&take(&out)),
            [IpAddr::V4(gw)],
            "the router was not resolved"
        );
        let gw_mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let payload =
            arp::build_packet(arp::OP_REPLY, gw_mac, gw, adapter.mac, [10, 0, 0, 5].into());
        let f = build_frame(adapter.mac, gw_mac, EtherType::ARP, &payload);
        adapter.send(Frame::from_slice(&f)).unwrap();
        let sent = take(&out);
        assert_eq!(sent.len(), 1, "queued packet not delivered");
        assert_eq!(Frame::from_slice(&sent[0]).dst_mac(), Some(gw_mac));
    }

    #[test]
    fn neighbours_off_our_subnet_are_not_learnt() {
        let (_pipe, adapter, _out) = rig("10.0.0.5/24");
        let a = MacAddr([2, 0, 0, 0, 0, 7]);
        arp_in(
            &adapter,
            arp::OP_REQUEST,
            a,
            [192, 168, 1, 7],
            [10, 0, 0, 5],
        );
        assert_eq!(adapter.arp.lookup(Ipv4Addr::new(192, 168, 1, 7)), None);
        // Link-local is on-link whatever the subnet.
        arp_in(
            &adapter,
            arp::OP_REQUEST,
            a,
            [169, 254, 1, 7],
            [10, 0, 0, 5],
        );
        assert_eq!(adapter.arp.lookup(Ipv4Addr::new(169, 254, 1, 7)), Some(a));

        let (_pipe, adapter, _out) = rig("2001:db8::5/64");
        let off: Ipv6Addr = "2001:db9::66".parse().unwrap();
        let mut ns = ndp::build_ns(PEER_MAC, our_ip());
        let f = ndp_frame(&adapter, PEER_MAC, off, our_ip(), &mut ns);
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(off), None);
    }

    fn v4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[8] = 64;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn link_local_destinations_are_resolved_on_link() {
        let (pipe, adapter, out) = rig("2001:db8::5/64");
        adapter.set_gateway_v6("2001:db8::1".parse().unwrap());
        let peer: Ipv6Addr = "fe80::99".parse().unwrap();
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), peer)))
            .unwrap();
        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        let f = Frame::from_slice(&sent[0]);
        let ns = Packet::from_slice(f.payload()).ipv6_payload();
        assert_eq!(ns[0], ndp::NS_TYPE);
        assert_eq!(ns[8..24], peer.octets(), "solicited the gateway instead");
    }

    #[test]
    fn off_link_destinations_without_a_router_are_not_solicited() {
        let off: Ipv6Addr = "2001:db9::66".parse().unwrap();
        let (pipe, _adapter, out) = rig("2001:db8::5/64");
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), off)))
            .unwrap();
        assert!(take(&out).is_empty(), "solicited an off-link address");

        // With no IPv6 prefix at all, only link-local is on-link.
        let (pipe, adapter, out) = rig("10.0.0.5/24");
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), our_ip())))
            .unwrap();
        assert!(take(&out).is_empty(), "solicited an off-link address");
        let ll: Ipv6Addr = "fe80::66".parse().unwrap();
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), ll)))
            .unwrap();
        assert_eq!(solicited(&take(&out)), [IpAddr::V6(ll)]);

        // A router, once there is one, is where it goes.
        let gw: Ipv6Addr = "fe80::1".parse().unwrap();
        adapter.set_gateway_v6(gw);
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), off)))
            .unwrap();
        assert_eq!(solicited(&take(&out)), [IpAddr::V6(gw)]);
    }

    #[test]
    fn ipv4_link_local_destinations_are_resolved_on_link() {
        let (pipe, adapter, out) = rig("10.0.0.5/24");
        adapter.set_gateway_v4(Ipv4Addr::new(10, 0, 0, 1));
        pipe.inject(Packet::from_slice(&v4_packet(
            [10, 0, 0, 5],
            [169, 254, 3, 4],
        )))
        .unwrap();
        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        let (op, _, _, _, target) = arp::parse(Frame::from_slice(&sent[0]).payload()).unwrap();
        assert_eq!(op, arp::OP_REQUEST);
        assert_eq!(target, Ipv4Addr::new(169, 254, 3, 4), "ARPed the gateway");
    }

    #[test]
    fn subnet_directed_broadcast_goes_to_the_broadcast_mac() {
        let (pipe, _adapter, out) = rig("10.0.0.5/24");
        pipe.inject(Packet::from_slice(&v4_packet(
            [10, 0, 0, 5],
            [10, 0, 0, 255],
        )))
        .unwrap();
        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        let f = Frame::from_slice(&sent[0]);
        assert_eq!(f.ether_type(), EtherType::IPV4, "tried to ARP for it");
        assert_eq!(f.dst_mac(), Some(MacAddr::broadcast()));
    }

    #[test]
    fn ipv4_multicast_maps_to_its_mac() {
        let (pipe, _adapter, out) = rig("10.0.0.5/24");
        pipe.inject(Packet::from_slice(&v4_packet(
            [10, 0, 0, 5],
            [239, 129, 2, 3],
        )))
        .unwrap();
        let sent = take(&out);
        let f = Frame::from_slice(&sent[0]);
        // RFC 1112 §6.4: the low 23 bits into 01:00:5e:00:00:00.
        assert_eq!(f.dst_mac(), Some(MacAddr([0x01, 0x00, 0x5e, 0x01, 2, 3])));
    }

    /// An NS from the peer for our address, as a frame.
    fn ns_for_us(adapter: &L2Adapter, ns: &mut [u8]) -> Vec<u8> {
        ndp_frame(adapter, PEER_MAC, peer_ip(), our_ip(), ns)
    }

    #[test]
    fn ndp_with_a_bad_checksum_or_code_is_ignored() {
        let (_pipe, adapter, out) = rig("2001:db8::5/64");

        let mut ns = ndp::build_ns(PEER_MAC, our_ip());
        let mut f = ns_for_us(&adapter, &mut ns);
        f[14 + 40 + 2] ^= 0xff;
        adapter.send(Frame::from_slice(&f)).unwrap();

        let mut ns = ndp::build_ns(PEER_MAC, our_ip());
        ns[1] = 1; // code
        let f = ns_for_us(&adapter, &mut ns);
        adapter.send(Frame::from_slice(&f)).unwrap();

        assert!(take(&out).is_empty(), "answered an invalid NS");
        assert_eq!(adapter.ndp.lookup(peer_ip()), None, "learnt from it");
    }

    #[test]
    fn advertisement_without_override_keeps_the_cached_address() {
        let (_pipe, adapter, _out) = rig("2001:db8::5/64");
        adapter.ndp.set(peer_ip(), PEER_MAC, ndp::DEFAULT_TTL);

        let other = MacAddr([2, 0, 0, 0, 0, 0x77]);
        let mut na = ndp::build_na(other, peer_ip(), false);
        na[4] &= !0x20; // O clear
        let f = ndp_frame(&adapter, other, peer_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(peer_ip()), Some(PEER_MAC));

        // With the flag, it does replace it.
        let mut na = ndp::build_na(other, peer_ip(), false);
        let f = ndp_frame(&adapter, other, peer_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(peer_ip()), Some(other));
    }

    #[test]
    fn unsolicited_advertisement_for_a_stranger_is_not_cached() {
        let (_pipe, adapter, _out) = rig("2001:db8::5/64");
        let mut na = ndp::build_na(PEER_MAC, peer_ip(), false);
        let f = ndp_frame(&adapter, PEER_MAC, peer_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(peer_ip()), None);
    }

    #[test]
    fn unicast_solicitation_without_source_address_is_answered_to_the_sender() {
        let (_pipe, adapter, out) = rig("2001:db8::5/64");
        let mut ns = ndp::build_ns(PEER_MAC, our_ip())[..24].to_vec();
        let f = ns_for_us(&adapter, &mut ns);
        adapter.send(Frame::from_slice(&f)).unwrap();

        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        let f = Frame::from_slice(&sent[0]);
        assert_eq!(f.dst_mac(), Some(PEER_MAC), "sent to a multicast MAC");
        let na = Packet::from_slice(f.payload());
        assert_eq!(na.ipv6_payload()[0], ndp::NA_TYPE);
        assert_eq!(na.ipv6_dst_addr(), Some(peer_ip()));
    }

    fn arp_in(adapter: &L2Adapter, op: u16, mac: MacAddr, ip: [u8; 4], target: [u8; 4]) {
        let payload = arp::build_packet(op, mac, ip.into(), MacAddr::zero(), target.into());
        let frame = build_frame(MacAddr::broadcast(), mac, EtherType::ARP, &payload);
        adapter.send(Frame::from_slice(&frame)).unwrap();
    }

    #[test]
    fn arp_learns_new_stations_only_from_messages_for_us() {
        let (_pipe, adapter, _out) = rig("10.0.0.5/24");
        let a = MacAddr([2, 0, 0, 0, 0, 7]);

        // Somebody else's conversation.
        arp_in(&adapter, arp::OP_REQUEST, a, [10, 0, 0, 7], [10, 0, 0, 9]);
        assert_eq!(adapter.arp.lookup(Ipv4Addr::new(10, 0, 0, 7)), None);

        // An address probe (RFC 5227) claims nothing yet.
        arp_in(&adapter, arp::OP_REQUEST, a, [0, 0, 0, 0], [10, 0, 0, 5]);
        assert_eq!(adapter.arp.lookup(Ipv4Addr::UNSPECIFIED), None);

        // For us: learnt.
        arp_in(&adapter, arp::OP_REQUEST, a, [10, 0, 0, 7], [10, 0, 0, 5]);
        assert_eq!(adapter.arp.lookup(Ipv4Addr::new(10, 0, 0, 7)), Some(a));

        // Known already: any ARP from it updates it (RFC 826 merge).
        let moved = MacAddr([2, 0, 0, 0, 0, 8]);
        arp_in(
            &adapter,
            arp::OP_REQUEST,
            moved,
            [10, 0, 0, 7],
            [10, 0, 0, 9],
        );
        assert_eq!(adapter.arp.lookup(Ipv4Addr::new(10, 0, 0, 7)), Some(moved));
    }

    #[test]
    fn a_neighbour_claiming_our_address_is_not_cached() {
        let (_pipe, adapter, out) = rig("10.0.0.5/24");
        let evil = MacAddr([2, 0, 0, 0, 0, 0xee]);
        let us = Ipv4Addr::new(10, 0, 0, 5);
        // A gratuitous ARP for our address, then a reply claiming it.
        arp_in(
            &adapter,
            arp::OP_REQUEST,
            evil,
            [10, 0, 0, 5],
            [10, 0, 0, 5],
        );
        arp_in(&adapter, arp::OP_REPLY, evil, [10, 0, 0, 5], [10, 0, 0, 5]);
        assert_eq!(adapter.arp.lookup(us), None, "cached ourselves");
        assert!(take(&out).is_empty(), "answered the conflicting host");
        assert_eq!(adapter.address_conflicts(), 2);

        // Our own announcement, looped back by a hub, is no conflict.
        let mine = adapter.mac;
        arp_in(
            &adapter,
            arp::OP_REQUEST,
            mine,
            [10, 0, 0, 5],
            [10, 0, 0, 5],
        );
        assert_eq!(adapter.address_conflicts(), 2);

        let (_pipe, adapter, _out) = rig("2001:db8::5/64");
        // An NS for our address from our own address, and an NA for it.
        let mut ns = ndp::build_ns(evil, our_ip());
        let f = ndp_frame(&adapter, evil, our_ip(), our_ip(), &mut ns);
        adapter.send(Frame::from_slice(&f)).unwrap();
        let ll = ndp::link_local_from_mac(adapter.mac);
        let mut ns = ndp::build_ns(evil, our_ip());
        let f = ndp_frame(&adapter, evil, ll, our_ip(), &mut ns);
        adapter.send(Frame::from_slice(&f)).unwrap();
        let mut na = ndp::build_na(evil, our_ip(), false);
        let f = ndp_frame(&adapter, evil, our_ip(), our_ip(), &mut na);
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(our_ip()), None, "cached ourselves");
        assert_eq!(adapter.ndp.lookup(ll), None, "cached our link-local");
        assert_eq!(adapter.address_conflicts(), 3);
    }

    /// `frame` with an 802.1Q tag carrying `vid` inserted after the MACs.
    fn tagged(frame: &[u8], vid: u16) -> Vec<u8> {
        let mut t = frame[..12].to_vec();
        t.extend_from_slice(&EtherType::VLAN.as_u16().to_be_bytes());
        t.extend_from_slice(&vid.to_be_bytes());
        t.extend_from_slice(&frame[12..]);
        t
    }

    #[test]
    fn frames_tagged_for_another_vlan_are_not_ours() {
        let (pipe, adapter, out) = rig("10.0.0.5/24");
        let peer = MacAddr([2, 0, 0, 0, 0, 1]);
        let payload = arp::build_packet(
            arp::OP_REQUEST,
            peer,
            Ipv4Addr::new(10, 0, 0, 1),
            MacAddr::zero(),
            Ipv4Addr::new(10, 0, 0, 5),
        );
        let arp = build_frame(MacAddr::broadcast(), peer, EtherType::ARP, &payload);

        adapter.send(Frame::from_slice(&tagged(&arp, 7))).unwrap();
        assert!(take(&out).is_empty(), "answered an ARP on VLAN 7");
        assert_eq!(adapter.arp.lookup(Ipv4Addr::new(10, 0, 0, 1)), None);

        let ip = v4_packet([10, 0, 0, 1], [10, 0, 0, 5]);
        let data = build_frame(adapter.mac, peer, EtherType::IPV4, &ip);
        let got = Arc::new(Mutex::new(0usize));
        let g = got.clone();
        pipe.set_handler(Arc::new(move |_p: &Packet| {
            *g.lock().unwrap() += 1;
            Ok(())
        }));
        adapter.send(Frame::from_slice(&tagged(&data, 7))).unwrap();
        assert_eq!(*got.lock().unwrap(), 0, "bridged VLAN 7 into the host");

        // Priority-tagged (VID 0) is the untagged VLAN (802.1Q §6.9.1).
        adapter
            .send(Frame::from_slice(&tagged(&arp, 0x6000)))
            .unwrap();
        assert_eq!(take(&out).len(), 1, "priority-tagged ARP ignored");
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_probe_detects_an_address_in_use() {
        use crate::dhcp::ClientTransport;
        let (_pipe, adapter, out) = rig("0.0.0.0/0");
        let t = AdapterDhcpTransport {
            weak: Arc::downgrade(&adapter),
        };
        assert!(t.can_probe());
        let ip = Ipv4Addr::new(10, 0, 0, 50);

        t.begin_probe(ip);
        t.send_probe(ip);
        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        let f = Frame::from_slice(&sent[0]);
        assert_eq!(f.dst_mac(), Some(MacAddr::broadcast()));
        let (op, sm, si, _, ti) = arp::parse(f.payload()).unwrap();
        assert_eq!(
            (op, sm, si, ti),
            (arp::OP_REQUEST, adapter.mac, Ipv4Addr::UNSPECIFIED, ip)
        );
        assert!(!t.probe_conflict(ip));

        // Our own probe, looped back, is not a conflict; a stranger's
        // traffic for other addresses is not either.
        adapter.send(f).unwrap();
        let other = MacAddr([2, 0, 0, 0, 0, 9]);
        arp_in(
            &adapter,
            arp::OP_REQUEST,
            other,
            [10, 0, 0, 7],
            [10, 0, 0, 1],
        );
        assert!(!t.probe_conflict(ip));

        // Someone answers for it.
        arp_in(&adapter, arp::OP_REPLY, other, [10, 0, 0, 50], [0, 0, 0, 0]);
        assert!(t.probe_conflict(ip));

        // Another host probing for the same address also counts.
        let ip2 = Ipv4Addr::new(10, 0, 0, 51);
        t.begin_probe(ip2);
        t.send_probe(ip2);
        assert!(!t.probe_conflict(ip2));
        arp_in(
            &adapter,
            arp::OP_REQUEST,
            other,
            [0, 0, 0, 0],
            [10, 0, 0, 51],
        );
        assert!(t.probe_conflict(ip2));

        // Declined, then offered again: a new check starts clean, rather
        // than declining at once on the old conflict.
        t.begin_probe(ip2);
        t.send_probe(ip2);
        assert!(!t.probe_conflict(ip2));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn an_announcement_claims_the_address_for_everyone() {
        use crate::dhcp::ClientTransport;
        let (_pipe, adapter, out) = rig("10.0.0.50/24");
        let t = AdapterDhcpTransport {
            weak: Arc::downgrade(&adapter),
        };
        let ip = Ipv4Addr::new(10, 0, 0, 50);
        t.send_announcement(ip);
        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        let f = Frame::from_slice(&sent[0]);
        assert_eq!(f.dst_mac(), Some(MacAddr::broadcast()));
        let (op, sm, si, tm, ti) = arp::parse(f.payload()).unwrap();
        // RFC 5227 §2.3: an ARP request with our address as both sender
        // and target.
        assert_eq!(
            (op, sm, si, tm, ti),
            (arp::OP_REQUEST, adapter.mac, ip, MacAddr::zero(), ip)
        );
        // Looped back by a hub, it is neither a conflict nor answered.
        adapter.send(f).unwrap();
        assert!(take(&out).is_empty());
        assert_eq!(adapter.address_conflicts(), 0);
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn a_late_probe_leaves_the_check_alone() {
        use crate::dhcp::ClientTransport;
        let (_pipe, adapter, out) = rig("0.0.0.0/0");
        let t = AdapterDhcpTransport {
            weak: Arc::downgrade(&adapter),
        };
        let (old, new) = (Ipv4Addr::new(10, 0, 0, 50), Ipv4Addr::new(10, 0, 0, 51));
        let other = MacAddr([2, 0, 0, 0, 0, 9]);

        // After its check ended, it starts no new one.
        t.begin_probe(old);
        t.end_probe();
        t.send_probe(old);
        assert_eq!(take(&out).len(), 1, "the probe itself still goes out");
        assert!(adapter.probe.lock().unwrap().is_none(), "check revived");

        // Nor does it take over another address's check, or wipe what
        // that one found.
        t.begin_probe(new);
        arp_in(&adapter, arp::OP_REPLY, other, [10, 0, 0, 51], [0, 0, 0, 0]);
        t.send_probe(old);
        assert!(t.probe_conflict(new), "the current check lost its conflict");
        assert!(!t.probe_conflict(old));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn fragments_are_not_taken_for_dhcp() {
        let (pipe, adapter, _out) = rig("10.0.0.5/24");
        adapter.start_dhcp();
        let got = Arc::new(Mutex::new(0usize));
        let g = got.clone();
        pipe.set_handler(Arc::new(move |_p: &Packet| {
            *g.lock().unwrap() += 1;
            Ok(())
        }));
        let (s, d) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
        let udp = crate::build::build_udp(s.into(), d.into(), 67, 68, &[0; 64]);
        let whole = crate::build::build_ipv4(s, d, Protocol::UDP, 64, &udp);
        let peer = MacAddr([2, 0, 0, 0, 0, 1]);

        // A later fragment whose payload happens to read 68 at bytes 2..4.
        let mut later = whole.clone();
        Packet::from_mut(&mut later).set_ipv4_fragment_offset(1480);
        // A first fragment: MF set.
        let mut first = whole.clone();
        Packet::from_mut(&mut first).set_ipv4_more_fragments(true);
        for pkt in [&later, &first] {
            let mut pkt = pkt.clone();
            Packet::from_mut(&mut pkt).recompute_ipv4_checksum();
            let f = build_frame(adapter.mac, peer, EtherType::IPV4, &pkt);
            adapter.send(Frame::from_slice(&f)).unwrap();
        }
        assert_eq!(*got.lock().unwrap(), 2, "fragment swallowed as DHCP");

        // The whole datagram is still the DHCP client's.
        let f = build_frame(adapter.mac, peer, EtherType::IPV4, &whole);
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(*got.lock().unwrap(), 2);
        adapter.stop_dhcp();
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn stopping_dhcp_mid_check_forgets_the_probe() {
        let (_pipe, adapter, out) = rig("0.0.0.0/0");
        adapter.start_dhcp();
        let client = adapter.dhcp.lock().unwrap().clone().unwrap();
        let discover = take(&out);
        let xid = crate::dhcp::wire::Parsed::from_bytes(&discover[0][42..])
            .unwrap()
            .xid;
        let reply = |t| {
            let mut b = crate::dhcp::wire::Builder::new(2, xid, adapter.mac);
            b.yiaddr(Ipv4Addr::new(10, 0, 0, 50))
                .message_type(t)
                .ipv4_option(
                    crate::dhcp::wire::OPT_SUBNET_MASK,
                    [255, 255, 255, 0].into(),
                )
                .u32_option(crate::dhcp::wire::OPT_LEASE_TIME, 3600)
                .ipv4_option(crate::dhcp::wire::OPT_SERVER_ID, [10, 0, 0, 1].into());
            b.finish()
        };
        client.handle_packet(&reply(crate::dhcp::wire::MSG_OFFER));
        client.handle_packet(&reply(crate::dhcp::wire::MSG_ACK));
        assert!(adapter.probe.lock().unwrap().is_some(), "not probing");
        drop(client);

        adapter.stop_dhcp();
        assert!(adapter.probe.lock().unwrap().is_none(), "probe state kept");
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn losing_the_lease_forgets_the_gateway_and_the_neighbours() {
        use crate::dhcp::ClientTransport;
        let (_pipe, adapter, _out) = rig("0.0.0.0/0");
        let t = AdapterDhcpTransport {
            weak: Arc::downgrade(&adapter),
        };
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        t.on_bound("10.0.0.5/24".parse().unwrap(), Some(gw));
        adapter
            .arp
            .set(gw, MacAddr([2, 0, 0, 0, 0, 1]), arp::DEFAULT_TTL);

        t.on_lease_lost();
        assert_eq!(*adapter.gateway_v4.lock().unwrap(), None);
        assert_eq!(
            adapter.arp.lookup(gw),
            None,
            "ARP cache from the old network kept"
        );

        // A lease that names no router has none: the last one's is not
        // carried over onto what may be another network.
        t.on_bound("10.0.0.5/24".parse().unwrap(), Some(gw));
        t.on_bound("192.168.7.5/24".parse().unwrap(), None);
        assert_eq!(*adapter.gateway_v4.lock().unwrap(), None);
    }

    /// A DHCP message from `ip` to `server`, framed as the client frames a
    /// unicast one: to the broadcast MAC, for the transport to resolve.
    #[cfg(feature = "dhcp")]
    fn dhcp_unicast(adapter: &L2Adapter, ip: Ipv4Addr, server: Ipv4Addr) -> Vec<u8> {
        let udp = crate::build::build_udp(ip.into(), server.into(), 68, 67, &[0; 240]);
        let pkt = crate::build::build_ipv4(ip, server, Protocol::UDP, 64, &udp);
        build_frame(MacAddr::broadcast(), adapter.mac, EtherType::IPV4, &pkt)
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_unicasts_are_resolved_like_any_other_traffic() {
        use crate::dhcp::ClientTransport;
        let (_pipe, adapter, out) = rig("0.0.0.0/0");
        let t = AdapterDhcpTransport {
            weak: Arc::downgrade(&adapter),
        };
        let (us, gw) = (Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1));
        let gw_mac = MacAddr([2, 0, 0, 0, 0, 1]);
        t.on_bound("10.0.0.5/24".parse().unwrap(), Some(gw));

        // A renewal to an on-link server: ARP for it, then unicast to it.
        let server = Ipv4Addr::new(10, 0, 0, 2);
        t.send_unicast(
            server,
            Frame::from_slice(&dhcp_unicast(&adapter, us, server)),
        );
        assert_eq!(
            solicited(&take(&out)),
            [IpAddr::V4(server)],
            "not ARPed for"
        );
        let server_mac = MacAddr([2, 0, 0, 0, 0, 2]);
        arp_reply_to(&adapter, server_mac, server.octets(), us.octets());
        let sent = take(&out);
        assert_eq!(sent.len(), 1);
        assert_eq!(Frame::from_slice(&sent[0]).dst_mac(), Some(server_mac));

        // An off-subnet server is reached through the gateway.
        let far = Ipv4Addr::new(192, 168, 9, 1);
        t.send_unicast(far, Frame::from_slice(&dhcp_unicast(&adapter, us, far)));
        assert_eq!(solicited(&take(&out)), [IpAddr::V4(gw)]);
        arp_reply_to(&adapter, gw_mac, gw.octets(), us.octets());
        assert_eq!(Frame::from_slice(&take(&out)[0]).dst_mac(), Some(gw_mac));

        // A RELEASE goes out just before the lease is lost; still waiting
        // for the server's MAC then, it is sent once that arrives.
        adapter.arp.clear();
        t.send_unicast(
            server,
            Frame::from_slice(&dhcp_unicast(&adapter, us, server)),
        );
        t.on_lease_lost();
        assert_eq!(solicited(&take(&out)), [IpAddr::V4(server)]);
        arp_reply_to(&adapter, server_mac, server.octets(), us.octets());
        let sent = take(&out);
        assert_eq!(sent.len(), 1, "RELEASE lost with the lease");
        assert_eq!(Frame::from_slice(&sent[0]).dst_mac(), Some(server_mac));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_unicasts_go_where_the_server_answered_from() {
        use crate::dhcp::ClientTransport;
        let (pipe, adapter, out) = rig("0.0.0.0/0");
        adapter.start_dhcp();
        let t = AdapterDhcpTransport {
            weak: Arc::downgrade(&adapter),
        };
        // The DHCP server shares the router's address, and answers no ARP.
        let (us, server) = (Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1));
        let server_mac = MacAddr([2, 0xdd, 0, 0, 0, 1]);
        let udp = crate::build::build_udp(server.into(), us.into(), 67, 68, &[0; 240]);
        let reply = crate::build::build_ipv4(server, us, Protocol::UDP, 64, &udp);
        let f = build_frame(adapter.mac, server_mac, EtherType::IPV4, &reply);
        adapter.send(Frame::from_slice(&f)).unwrap();
        adapter.stop_dhcp();
        t.on_bound("10.0.0.5/24".parse().unwrap(), Some(server));
        take(&out);

        t.send_unicast(
            server,
            Frame::from_slice(&dhcp_unicast(&adapter, us, server)),
        );
        let sent = take(&out);
        assert_eq!(sent.len(), 1, "not sent at once");
        assert_eq!(Frame::from_slice(&sent[0]).dst_mac(), Some(server_mac));
        // Everything else for that address still goes by ARP: the router's.
        assert_eq!(adapter.arp.lookup(server), None, "ARP cache told");
        pipe.inject(Packet::from_slice(&v4_packet(us.octets(), server.octets())))
            .unwrap();
        assert_eq!(solicited(&take(&out)), [IpAddr::V4(server)]);
    }

    #[test]
    fn overheard_solicitation_for_someone_else_does_not_touch_the_cache() {
        let (_pipe, adapter, out) = rig("2001:db8::5/64");
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let gw_mac = MacAddr([2, 0, 0, 0, 0, 1]);
        adapter.ndp.set(gw, gw_mac, ndp::DEFAULT_TTL);

        // An attacker claims the gateway's address in an NS for a third
        // party's address, multicast so the whole link hears it.
        let evil = MacAddr([2, 0, 0, 0, 0, 0xee]);
        let third: Ipv6Addr = "2001:db8::77".parse().unwrap();
        let mut ns = ndp::build_ns(evil, third);
        let f = ndp_frame(
            &adapter,
            evil,
            gw,
            ndp::solicited_node_multicast(third),
            &mut ns,
        );
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(gw), Some(gw_mac), "cache poisoned");

        // Nor does a stranger get a new entry that way.
        let stranger: Ipv6Addr = "2001:db8::88".parse().unwrap();
        let mut ns = ndp::build_ns(evil, third);
        let f = ndp_frame(
            &adapter,
            evil,
            stranger,
            ndp::solicited_node_multicast(third),
            &mut ns,
        );
        adapter.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(adapter.ndp.lookup(stranger), None);
        assert!(take(&out).is_empty());
    }
}

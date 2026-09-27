//! `L2Adapter`: bridges an [`L3Device`] onto an Ethernet network.
//!
//! Equivalent to Go's `L2Adapter`. The adapter:
//! - Picks (or accepts) a MAC address.
//! - Handles ARP for IPv4 (cache + solicitation + reply).
//! - Handles NDP for IPv6 (cache + NS/NA).
//! - Optionally runs a DHCP client to obtain the L3 device's address.
//! - When DHCP is bound, the gateway is set on the adapter automatically.

use crate::arp::{self, Pending as ArpPending, Table as ArpTable};
use crate::ndp::{self, Table as NdpTable};
use crate::{
    EtherType, Frame, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Protocol, Result,
    build_frame,
};
// Only the DHCP client callback names this type.
#[cfg(feature = "dhcp")]
use crate::IpPrefix;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, Weak};

/// Configure an [`L2Adapter`].
#[derive(Default, Debug, Clone)]
#[non_exhaustive]
pub struct L2AdapterConfig {
    /// Override the MAC. Defaults to a random locally-administered unicast.
    pub mac: Option<MacAddr>,
    /// Initial gateway. Updated automatically once DHCP binds.
    pub gateway_v4: Option<Ipv4Addr>,
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
        let mac = cfg.mac.unwrap_or_else(MacAddr::random_local_unicast);
        let a = Arc::new(L2Adapter {
            mac,
            l3: dev.clone(),
            l2_handler: Mutex::new(None),
            gateway_v4: Mutex::new(cfg.gateway_v4),
            gateway_v6: Mutex::new(cfg.gateway_v6),
            arp: ArpTable::new(),
            arp_pending: ArpPending::new(),
            ndp: NdpTable::new(),
            ndp_pending: ArpPending::new(),
            #[cfg(feature = "dhcp")]
            dhcp: Mutex::new(None),
            weak_self: Mutex::new(Weak::new()),
        });
        *a.weak_self.lock().unwrap() = Arc::downgrade(&a);

        // Wire the L3 device's outbound packets back through us.
        let weak = Arc::downgrade(&a);
        let h: L3Handler = Arc::new(move |p: &Packet| {
            if let Some(a) = weak.upgrade() {
                a.handle_outgoing(p);
            }
            Ok(())
        });
        dev.set_handler(h);
        a
    }

    /// Adapter MAC.
    pub fn hw_addr(&self) -> MacAddr {
        self.mac
    }

    /// Set the IPv4 default gateway used for off-subnet ARP.
    pub fn set_gateway_v4(&self, gw: Ipv4Addr) {
        *self.gateway_v4.lock().unwrap() = Some(gw);
    }

    /// Set the IPv6 default gateway used for off-link NDP.
    pub fn set_gateway_v6(&self, gw: Ipv6Addr) {
        *self.gateway_v6.lock().unwrap() = Some(gw);
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
        *self.dhcp.lock().unwrap() = Some(client.clone());
        client.start();
    }

    /// Stop the DHCP client.
    #[cfg(feature = "dhcp")]
    pub fn stop_dhcp(&self) {
        if let Some(c) = self.dhcp.lock().unwrap().take() {
            c.stop();
        }
    }

    /// Drive the DHCP client's timers: retransmissions, lease renewal and
    /// expiry. Only needed on targets without threads (`wasm32`), where
    /// nothing runs in the background; see
    /// [`dhcp::Client::tick`](crate::dhcp::Client::tick).
    #[cfg(feature = "dhcp")]
    pub fn tick(&self) {
        let client = self.dhcp.lock().unwrap().clone();
        if let Some(c) = client {
            c.tick();
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
                // Intercept DHCP (IPv4 UDP port 68).
                #[cfg(feature = "dhcp")]
                if pkt.version() == 4 && pkt.ipv4_protocol() == Protocol::UDP {
                    let udp = pkt.ipv4_payload();
                    if udp.len() >= 8 {
                        let dport = u16::from_be_bytes([udp[2], udp[3]]);
                        if dport == 68 {
                            let dhcp = self.dhcp.lock().unwrap().clone();
                            if let Some(c) = dhcp
                                && c.is_active()
                            {
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
        if !pkt.is_valid() {
            return;
        }
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
                    let target =
                        if prefix.is_valid() && prefix.is_v4() && !prefix.contains(IpAddr::V4(dst))
                        {
                            self.gateway_v4.lock().unwrap().unwrap_or(dst)
                        } else {
                            dst
                        };
                    match self.arp.lookup(target) {
                        Some(m) => (m, EtherType::IPV4),
                        None => {
                            let first = self.arp_pending.enqueue(target, pkt.as_bytes());
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
                    let prefix = self.l3.addr();
                    // Link-local addresses are on-link whatever the prefix
                    // (RFC 4861 §5.2); a router would not forward them.
                    let target = if prefix.is_valid()
                        && prefix.is_v6()
                        && !prefix.contains(IpAddr::V6(dst))
                        && !dst.is_unicast_link_local()
                    {
                        self.gateway_v6.lock().unwrap().unwrap_or(dst)
                    } else {
                        dst
                    };
                    match self.ndp.lookup(target) {
                        Some(m) => (m, EtherType::IPV6),
                        None => {
                            if self.ndp_pending.enqueue(target, pkt.as_bytes()) {
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
        let our_addr = match self.l3.addr().addr() {
            IpAddr::V4(a) if !a.is_unspecified() => Some(a),
            _ => None,
        };
        let for_us = our_addr == Some(target_ip);

        // RFC 826's merge rule: refresh a station already known from any
        // ARP it sends, but add a new one only when it is talking to us (or
        // answering our question), so the cache holds what we use rather
        // than everyone overheard. A 0.0.0.0 sender is probing for an
        // address (RFC 5227) and owns nothing yet.
        if !sender_ip.is_unspecified()
            && (for_us
                || self.arp.lookup(sender_ip).is_some()
                || self.arp_pending.contains(sender_ip))
        {
            self.arp.set(sender_ip, sender_mac, arp::DEFAULT_TTL);
            for buf in self.arp_pending.drain(sender_ip) {
                self.handle_outgoing(Packet::from_slice(&buf));
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

    fn send_arp_request(&self, target: Ipv4Addr) {
        let our_addr = match self.l3.addr().addr() {
            IpAddr::V4(a) => a,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let payload =
            arp::build_packet(arp::OP_REQUEST, self.mac, our_addr, MacAddr::zero(), target);
        let frame = build_frame(MacAddr::broadcast(), self.mac, EtherType::ARP, &payload);
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
            let dev_addr = match self.l3.addr().addr() {
                IpAddr::V6(a) => Some(a),
                _ => None,
            };
            if target != ndp::link_local_from_mac(self.mac) && dev_addr != Some(target) {
                return true;
            }
            if !src.is_unspecified()
                && let Some(mac) = slla
            {
                self.learn_neighbor(src, mac);
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
        let Some(mac) = ndp::parse_option(opts, ndp::OPT_TARGET_LINK_ADDR) else {
            return true;
        };
        // RFC 4861 §7.2.5: without the Override flag an advertisement may
        // fill in an address being resolved but not replace a known one;
        // and one for an address nobody here asked about is not cached.
        match self.ndp.lookup(target) {
            Some(known) if known != mac && !override_ => {}
            Some(_) => self.learn_neighbor(target, mac),
            None if self.ndp_pending.contains(target) => self.learn_neighbor(target, mac),
            None => {}
        }
        true
    }

    /// Cache a neighbour's MAC and send whatever was waiting for it,
    /// however it was learnt.
    fn learn_neighbor(&self, ip: Ipv6Addr, mac: MacAddr) {
        self.ndp.set(ip, mac, ndp::DEFAULT_TTL);
        // Drained before sending: a packet that misses the cache again is
        // queued anew, which needs the queue's lock.
        for buf in self.ndp_pending.drain(ip) {
            self.handle_outgoing(Packet::from_slice(&buf));
        }
    }

    fn send_neighbor_solicitation(&self, target: Ipv6Addr) {
        let src = ndp::link_local_from_mac(self.mac);
        let dst = ndp::solicited_node_multicast(target);
        let dst_mac = ndp::solicited_node_mac(target);
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

// --- DHCP integration ------------------------------------------------------

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
        // Rewrite the Ethernet destination if we have an ARP entry for dst_ip.
        let bytes = frame.as_bytes();
        let mut buf = bytes.to_vec();
        if let Some(mac) = a.arp.lookup(dst_ip) {
            buf[0..6].copy_from_slice(&mac.octets());
        }
        a.send_l2(Frame::from_slice(&buf));
    }
    fn on_bound(&self, prefix: IpPrefix, gateway: Option<Ipv4Addr>) {
        if let Some(a) = self.weak.upgrade() {
            let _ = a.l3.set_addr(prefix);
            if let Some(gw) = gateway {
                a.set_gateway_v4(gw);
            }
        }
    }
    fn on_lease_lost(&self) {
        // The leased address must not be used past the lease (RFC 2131
        // §4.4.5); leave the device unconfigured until the next lease.
        if let Some(a) = self.weak.upgrade()
            && a.l3.addr().is_v4()
        {
            let _ =
                a.l3.set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PipeL3;

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
        let adapter = L2Adapter::new_arc(pipe.clone(), L2AdapterConfig::default());
        let out: Out = Arc::default();
        let oc = out.clone();
        adapter.set_handler(Arc::new(move |f: &Frame| {
            oc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));
        (pipe, adapter, out)
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
    fn advertisement_that_cannot_be_cached_does_not_deadlock() {
        let (pipe, adapter, out) = rig("2001:db8::5/64");
        // A full neighbour cache: the advertised address will not stick, so
        // the flushed packet misses again and is queued anew.
        for i in 0..ndp::MAX_ENTRIES as u32 {
            let ip = Ipv6Addr::from(0xfd00_u128 << 112 | i as u128);
            adapter.ndp.set(ip, PEER_MAC, ndp::DEFAULT_TTL);
        }
        pipe.inject(Packet::from_slice(&v6_packet(our_ip(), peer_ip())))
            .unwrap();
        take(&out);

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let a = adapter.clone();
        std::thread::spawn(move || {
            let mut na = ndp::build_na(PEER_MAC, peer_ip(), true);
            let f = ndp_frame(&a, PEER_MAC, peer_ip(), our_ip(), &mut na);
            a.send(Frame::from_slice(&f)).unwrap();
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("deadlocked flushing the neighbour queue");
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

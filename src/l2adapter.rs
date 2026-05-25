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
    build_frame, EtherType, Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr,
    Packet, Protocol, Result,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, Weak};

/// Configure an [`L2Adapter`].
#[derive(Default, Debug, Clone)]
pub struct L2AdapterConfig {
    /// Override the MAC. Defaults to a random locally-administered unicast.
    pub mac: Option<MacAddr>,
    /// Initial gateway. Updated automatically once DHCP binds.
    pub gateway_v4: Option<Ipv4Addr>,
    pub gateway_v6: Option<Ipv6Addr>,
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
    ndp_pending: Mutex<HashMap<Ipv6Addr, Vec<Vec<u8>>>>,

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
            ndp_pending: Mutex::new(HashMap::new()),
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
                            if let Some(c) = dhcp {
                                if c.is_active() {
                                    c.handle_packet(&udp[8..]);
                                    return;
                                }
                            }
                        }
                    }
                }

                // Intercept NDP. RFC 4861 §6.1.1: hop limit must be 255.
                if pkt.version() == 6
                    && pkt.ipv6_next_header() == Protocol::ICMPV6
                    && pkt.ipv6_hop_limit() == 255
                    && self.handle_ndp(pkt)
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
                if pkt.is_broadcast() {
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
                    let target = if prefix.is_valid() && prefix.is_v4() && !prefix.contains(IpAddr::V4(dst)) {
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
                    (MacAddr([0x33, 0x33, d[12], d[13], d[14], d[15]]), EtherType::IPV6)
                } else {
                    let dst = pkt.ipv6_dst_addr().unwrap();
                    let prefix = self.l3.addr();
                    let target = if prefix.is_valid() && prefix.is_v6() && !prefix.contains(IpAddr::V6(dst)) {
                        self.gateway_v6.lock().unwrap().unwrap_or(dst)
                    } else {
                        dst
                    };
                    match self.ndp.lookup(target) {
                        Some(m) => (m, EtherType::IPV6),
                        None => {
                            let mut pending = self.ndp_pending.lock().unwrap();
                            let entry = pending.entry(target).or_default();
                            let first = entry.is_empty();
                            entry.push(pkt.as_bytes().to_vec());
                            drop(pending);
                            if first {
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

    fn handle_arp(&self, f: &Frame) {
        let p = match arp::parse(f.payload()) {
            Some(p) => p,
            None => return,
        };
        let (op, sender_mac, sender_ip, _, target_ip) = p;
        self.arp.set(sender_ip, sender_mac, arp::DEFAULT_TTL);

        // Drain pending packets for the sender.
        for buf in self.arp_pending.drain(sender_ip) {
            self.handle_outgoing(Packet::from_slice(&buf));
        }

        let our_addr = match self.l3.addr().addr() {
            IpAddr::V4(a) => a,
            _ => return,
        };
        if op == arp::OP_REQUEST && target_ip == our_addr {
            let payload = arp::build_packet(arp::OP_REPLY, self.mac, our_addr, sender_mac, sender_ip);
            let frame = build_frame(sender_mac, self.mac, EtherType::ARP, &payload);
            self.send_l2(Frame::from_slice(&frame));
        }
    }

    fn send_arp_request(&self, target: Ipv4Addr) {
        let our_addr = match self.l3.addr().addr() {
            IpAddr::V4(a) => a,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let payload = arp::build_packet(arp::OP_REQUEST, self.mac, our_addr, MacAddr::zero(), target);
        let frame = build_frame(MacAddr::broadcast(), self.mac, EtherType::ARP, &payload);
        self.send_l2(Frame::from_slice(&frame));
    }

    fn handle_ndp(&self, pkt: &Packet) -> bool {
        let icmp = pkt.ipv6_payload();
        if icmp.len() < 4 {
            return false;
        }
        let src = match pkt.ipv6_src_addr() {
            Some(a) => a,
            None => return false,
        };
        match icmp[0] {
            ndp::NS_TYPE => {
                if icmp.len() < 24 {
                    return false;
                }
                let mut t = [0u8; 16];
                t.copy_from_slice(&icmp[8..24]);
                let target = Ipv6Addr::from(t);

                // Learn sender unless source is unspecified (DAD).
                if !src.is_unspecified() {
                    if let Some(src_mac) = ndp::parse_option(&icmp[24..], ndp::OPT_SOURCE_LINK_ADDR) {
                        self.ndp.set(src, src_mac, ndp::DEFAULT_TTL);
                    }
                }

                let ll = ndp::link_local_from_mac(self.mac);
                let dev_addr = match self.l3.addr().addr() {
                    IpAddr::V6(a) => Some(a),
                    _ => None,
                };
                if target == ll || dev_addr == Some(target) {
                    if src.is_unspecified() {
                        // DAD: respond to all-nodes multicast.
                        let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
                        self.send_neighbor_advertisement(all_nodes, target, false);
                    } else {
                        self.send_neighbor_advertisement(src, target, true);
                    }
                }
                true
            }
            ndp::NA_TYPE => {
                if icmp.len() < 24 {
                    return false;
                }
                let mut t = [0u8; 16];
                t.copy_from_slice(&icmp[8..24]);
                let target = Ipv6Addr::from(t);
                if let Some(target_mac) = ndp::parse_option(&icmp[24..], ndp::OPT_TARGET_LINK_ADDR) {
                    self.ndp.set(target, target_mac, ndp::DEFAULT_TTL);
                    if let Some(pending) = self.ndp_pending.lock().unwrap().remove(&target) {
                        for buf in pending {
                            self.handle_outgoing(Packet::from_slice(&buf));
                        }
                    }
                }
                true
            }
            ndp::RS_TYPE | ndp::RA_TYPE => false, // pass through to L3
            _ => false,
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

    fn send_neighbor_advertisement(&self, dst_addr: Ipv6Addr, target: Ipv6Addr, solicited: bool) {
        let src = target;
        let dst_mac = if let Some(m) = self.ndp.lookup(dst_addr) {
            m
        } else {
            let d = dst_addr.octets();
            MacAddr([0x33, 0x33, d[12], d[13], d[14], d[15]])
        };
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
        self.weak.upgrade().map(|a| a.mac).unwrap_or(MacAddr::zero())
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
}

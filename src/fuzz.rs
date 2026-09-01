//! Parser entry points collected for fuzzing.
//!
//! Every function here takes untrusted bytes and drives one decoder over them.
//! None of them are part of the crate's API — they exist so that the fuzz
//! targets in `fuzz/` and the randomized test in `tests/robustness.rs` exercise
//! *the same* bodies, rather than drifting into two descriptions of what is
//! worth testing.
//!
//! The contract each body asserts is simply: **do not panic, do not hang, do
//! not read out of bounds.** Returning an error, or nonsense, is fine — these
//! decoders are handed hostile input by definition.
//!
//! Enabled by the `fuzzing` feature, which is not part of `full` and should
//! never be enabled by a dependent.

#![doc(hidden)]
#![allow(clippy::missing_panics_doc)]

use crate::{Frame, Packet};

/// Run every parser that the enabled feature set makes available.
///
/// The randomized test uses this to sweep one input across everything at once.
pub fn all(data: &[u8]) {
    frame_accessors(data);
    packet_accessors(data);
    l4_views(data);
    packet_mutators(data);
    icmp_errors(data);
    fragmentation(data);
    #[cfg(feature = "l2adapter")]
    {
        arp_parse(data);
        ndp_parse(data);
    }
    #[cfg(feature = "dhcp")]
    dhcp_parse(data);
    #[cfg(feature = "vtcp")]
    vtcp_segment(data);
    #[cfg(feature = "vclient")]
    dns_parse(data);
    #[cfg(feature = "nat")]
    {
        defrag(data);
        nat_forward(data);
    }
    #[cfg(feature = "ovpn")]
    ovpn_control(data);
    #[cfg(feature = "wg")]
    wg_process(data);
}

/// Every [`Frame`] accessor, including the VLAN paths.
pub fn frame_accessors(data: &[u8]) {
    let f = Frame::from_slice(data);
    let _ = f.is_valid();
    let _ = f.dst_mac();
    let _ = f.src_mac();
    let _ = f.has_vlan();
    let _ = f.vlan_id();
    let _ = f.vlan_pcp();
    let _ = f.vlan_dei();
    let _ = f.vlan_tci();
    let _ = f.ether_type();
    let _ = f.header_len();
    let _ = f.payload();
    let _ = f.is_broadcast();
    let _ = f.is_multicast();
    let _ = format!("{:?}", f);

    // Tag handling must survive being applied to whatever this is.
    let tagged = crate::build::push_vlan(f, 42, 3);
    let _ = crate::build::pop_vlan(Frame::from_slice(&tagged));
    let _ = crate::build::pop_vlan(f);
}

/// Every [`Packet`] accessor, both address families, extension chain included.
pub fn packet_accessors(data: &[u8]) {
    let p = Packet::from_slice(data);
    let _ = p.is_valid();
    let _ = p.version();
    let _ = p.total_len();

    let _ = p.ipv4_header_len();
    let _ = p.ipv4_dscp();
    let _ = p.ipv4_ecn();
    let _ = p.ipv4_total_len();
    let _ = p.ipv4_id();
    let _ = p.ipv4_flags();
    let _ = p.ipv4_dont_fragment();
    let _ = p.ipv4_more_fragments();
    let _ = p.ipv4_fragment_offset();
    let _ = p.ipv4_is_fragment();
    let _ = p.ipv4_ttl();
    let _ = p.ipv4_protocol();
    let _ = p.ipv4_checksum();
    let _ = p.ipv4_src_addr();
    let _ = p.ipv4_dst_addr();
    let _ = p.ipv4_options();
    let _ = p.ipv4_payload();

    let _ = p.ipv6_traffic_class();
    let _ = p.ipv6_dscp();
    let _ = p.ipv6_ecn();
    let _ = p.ipv6_flow_label();
    let _ = p.ipv6_payload_len();
    let _ = p.ipv6_next_header();
    let _ = p.ipv6_hop_limit();
    let _ = p.ipv6_src_addr();
    let _ = p.ipv6_dst_addr();
    let _ = p.ipv6_payload();
    let _ = p.ipv6_is_fragment();

    // The extension-header walk is the one that has to terminate.
    let (_, off) = p.ipv6_transport();
    assert!(off <= data.len(), "ipv6 walk pointed past the buffer");

    let _ = p.src_addr();
    let _ = p.dst_addr();
    let _ = p.transport_protocol();
    let toff = p.transport_offset();
    assert!(toff <= data.len(), "transport offset past the buffer");
    let _ = p.transport_payload();
    let _ = p.payload();
    let _ = p.is_fragment();
    let _ = p.hop_limit();
    let _ = p.is_broadcast();
    let _ = p.is_multicast();
    let _ = p.five_tuple();
    let _ = p.verify_ipv4_checksum();
    let _ = p.verify_transport_checksum();
    let _ = format!("{:?}", p);
}

/// The typed L4 views, reached both through a packet and directly.
pub fn l4_views(data: &[u8]) {
    use crate::l4::{IcmpMessage, TcpSegment, UdpDatagram};

    let seg = TcpSegment::from_slice(data);
    let _ = seg.is_valid();
    let _ = seg.src_port();
    let _ = seg.dst_port();
    let _ = seg.seq();
    let _ = seg.ack();
    let hl = seg.header_len();
    let _ = seg.flags();
    let _ = seg.window();
    let _ = seg.checksum();
    let _ = seg.urgent_ptr();
    let _ = seg.options();
    let _ = seg.payload();
    let _ = format!("{:?}", seg);
    assert!(hl >= TcpSegment::MIN_HEADER_LEN);
    // The option walk must terminate on any input.
    let mut n = 0;
    for _ in seg.option_iter() {
        n += 1;
        assert!(n < 1024, "TCP option iteration did not terminate");
    }

    let dg = UdpDatagram::from_slice(data);
    let _ = dg.is_valid();
    let _ = dg.src_port();
    let _ = dg.dst_port();
    let _ = dg.length();
    let _ = dg.checksum();
    let _ = dg.payload();
    let _ = format!("{:?}", dg);

    let msg = IcmpMessage::from_slice(data);
    let _ = msg.is_valid();
    let _ = msg.message_type();
    let _ = msg.code();
    let _ = msg.checksum();
    let _ = msg.rest_of_header();
    let _ = msg.payload();
    let _ = msg.echo_id();
    let _ = msg.echo_seq();
    let _ = msg.mtu();
    let _ = msg.is_icmpv4_error();
    let _ = msg.is_icmpv6_error();
    let _ = msg.verify_icmpv4_checksum();

    let p = Packet::from_slice(data);
    let _ = p.tcp();
    let _ = p.udp();
    let _ = p.icmp();
}

/// The in-place mutators, which must not corrupt or overrun a short buffer.
pub fn packet_mutators(data: &[u8]) {
    let mut buf = data.to_vec();
    let p = Packet::from_mut(&mut buf);
    let before = p.len();

    p.set_ipv4_dscp(46);
    p.set_ipv4_ecn(3);
    p.set_ipv4_total_len(1500);
    p.set_ipv4_id(0x1234);
    p.set_ipv4_dont_fragment(true);
    p.set_ipv4_more_fragments(true);
    p.set_ipv4_fragment_offset(1480);
    p.set_ipv4_ttl(7);
    p.set_ipv4_protocol(crate::Protocol::UDP);
    p.set_ipv6_traffic_class(0xAA);
    p.set_ipv6_flow_label(0xBEEF);
    p.set_ipv6_payload_len(99);
    p.set_ipv6_hop_limit(9);
    p.set_hop_limit(5);
    let _ = p.decrement_hop_limit();
    p.recompute_ipv4_checksum();
    let _ = p.recompute_transport_checksum();
    p.recompute_checksums();
    let _ = p.tcp_mut();
    let _ = p.udp_mut();
    let _ = p.icmp_mut();
    let _ = p.transport_payload_mut();

    assert_eq!(p.len(), before, "a mutator changed the buffer length");
}

/// ICMP error generation, which must refuse rather than build a bad reply.
pub fn icmp_errors(data: &[u8]) {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let p = Packet::from_slice(data);
    let v4 = Ipv4Addr::new(192, 0, 2, 1).into();
    let v6: std::net::IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();

    for from in [v4, v6] {
        for reply in [
            crate::icmp::time_exceeded(p, from),
            crate::icmp::port_unreachable(p, from),
            crate::icmp::no_route(p, from),
            crate::icmp::admin_prohibited(p, from),
            crate::icmp::packet_too_big(p, from, 1400),
        ]
        .into_iter()
        .flatten()
        {
            // Anything we emit must itself be a well-formed packet, or we have
            // just put garbage on the wire in response to garbage.
            let r = Packet::from_slice(&reply);
            assert!(r.is_valid(), "generated a malformed ICMP error");
            assert!(r.verify_ipv4_checksum());
            assert!(!crate::icmp::may_reply(r), "an error must not invite one");
        }
    }
    let _ = crate::icmp::may_reply(p);
}

/// Fragmentation, whose output must reassemble to its input.
pub fn fragmentation(data: &[u8]) {
    use crate::fragment::{fragment, Fragmentation};
    let p = Packet::from_slice(data);
    for mtu in [0usize, 28, 68, 576, 1500] {
        match fragment(p, mtu) {
            Fragmentation::Fragments(parts) => {
                let mut total = 0usize;
                for part in &parts {
                    assert!(part.len() <= mtu, "a fragment exceeded the MTU");
                    let f = Packet::from_slice(part);
                    assert!(f.verify_ipv4_checksum(), "fragment checksum is wrong");
                    total += f.ipv4_total_len() as usize - f.ipv4_header_len();
                }
                let want = p.ipv4_total_len() as usize - p.ipv4_header_len();
                assert_eq!(total, want, "fragmentation lost or invented payload");
            }
            Fragmentation::Fits | Fragmentation::DontFragment | Fragmentation::NotFragmentable => {}
        }
    }
}

#[cfg(feature = "l2adapter")]
pub fn arp_parse(data: &[u8]) {
    let _ = crate::arp::parse(data);
}

#[cfg(feature = "l2adapter")]
pub fn ndp_parse(data: &[u8]) {
    for t in [1u8, 2, 3] {
        let _ = crate::ndp::parse_option(data, t);
    }
}

#[cfg(feature = "dhcp")]
pub fn dhcp_parse(data: &[u8]) {
    if let Some(p) = crate::dhcp::wire::Parsed::from_bytes(data) {
        let _ = format!("{:?}", p);
    }
}

#[cfg(feature = "vtcp")]
pub fn vtcp_segment(data: &[u8]) {
    if let Ok(seg) = crate::vtcp::Segment::parse(data) {
        let _ = format!("{:?}", seg);
    }
    let _ = crate::vtcp::parse_options(data);
}

#[cfg(feature = "vclient")]
pub fn dns_parse(data: &[u8]) {
    let _ = crate::vclient::dns::wire::parse_response(data, 0x1234);
    if data.len() >= 2 {
        // Also try with the id the message actually carries, so the parser
        // gets past its first check and into the record loop.
        let id = u16::from_be_bytes([data[0], data[1]]);
        let _ = crate::vclient::dns::wire::parse_response(data, id);
    }
}

#[cfg(feature = "nat")]
pub fn defrag(data: &[u8]) {
    let d = crate::nat::defrag::Defragger::new();
    // Feed it twice: the second pass exercises the "we already have a piece of
    // this datagram" path, where overlapping fragments are resolved.
    let _ = d.process(data);
    let _ = d.process(data);
    d.sweep();
}

/// Drive a NAT with every ALG registered, in both directions.
#[cfg(feature = "nat")]
pub fn nat_forward(data: &[u8]) {
    use crate::nat::{FtpHelper, H323Helper, IrcHelper, Nat, PptpHelper, SipHelper, TftpHelper};
    use crate::L3Device;
    use std::sync::Arc;

    let nat = Nat::new(
        "10.0.0.1/24".parse().unwrap(),
        "192.0.2.1/24".parse().unwrap(),
    );
    nat.enable_defrag();
    nat.add_packet_helper(Arc::new(FtpHelper::new()));
    nat.add_packet_helper(Arc::new(SipHelper::new()));
    nat.add_packet_helper(Arc::new(H323Helper::new()));
    nat.add_packet_helper(Arc::new(IrcHelper::new(&[])));
    nat.add_packet_helper(Arc::new(PptpHelper::new()));
    nat.add_packet_helper(Arc::new(TftpHelper::new()));

    let pkt = Packet::from_slice(data);
    let _ = nat.inside().send(pkt);
    let _ = nat.outside().send(pkt);
    nat.sweep();
}

#[cfg(feature = "ovpn")]
pub fn ovpn_control(data: &[u8]) {
    if let Ok(p) = crate::ovpn::packet_ctrl::ControlPacket::parse(data) {
        let _ = format!("{:?}", p);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = crate::ovpn::Options::parse(s);
    }
}

#[cfg(feature = "wg")]
pub fn wg_process(data: &[u8]) {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::OnceLock;

    // Key generation is expensive, and the handler is stateless with respect
    // to which bytes arrive, so one instance serves every input.
    static HANDLER: OnceLock<std::sync::Arc<crate::wg::Handler>> = OnceLock::new();
    let h = HANDLER.get_or_init(|| {
        crate::wg::Handler::new(crate::wg::Config {
            private_key: [7u8; 32].into(),
            on_unknown_peer: None,
            load_threshold: None,
        })
        .expect("wg handler")
    });
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 51820));
    let _ = h.process_packet(data, &addr);
}

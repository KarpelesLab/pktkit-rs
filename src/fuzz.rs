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
    {
        vtcp_segment(data);
        vtcp_conversation(data);
    }
    #[cfg(feature = "dhcp")]
    dhcp_exchange(data);
    #[cfg(feature = "l2adapter")]
    l2adapter_frames(data);
    #[cfg(feature = "slirp")]
    slirp_reassembly(data);
    #[cfg(feature = "vclient")]
    dns_parse(data);
    #[cfg(feature = "nat")]
    {
        defrag(data);
        nat_forward(data);
        nat64_forward(data);
    }
    #[cfg(feature = "ovpn")]
    ovpn_control(data);
    #[cfg(feature = "wg")]
    wg_process(data);
}

/// Split one input into a sequence of messages, each a 2-byte big-endian
/// length and that many bytes (cut short at the end of the input).
///
/// A single input is one packet to most bodies, which can never reach the
/// bugs that take two: a fragment overlapping an earlier one, a segment
/// arriving in the state an earlier one left behind. Bodies that keep state
/// read their input through this instead.
pub fn messages(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        if data.len() < 2 {
            return None;
        }
        let n = (u16::from_be_bytes([data[0], data[1]]) as usize).min(data.len() - 2);
        let (msg, rest) = data[2..].split_at(n);
        data = rest;
        Some(msg)
    })
    .take(256)
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
    use crate::fragment::{Fragmentation, fragment};
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

/// A TCP conversation between two engines, with the fuzzer as the network
/// between them.
///
/// ISNs are keyed-random, so bytes the fuzzer invents almost never land in
/// the window. Instead the peer is an honest engine, and the fuzzer decides
/// what each side does and what becomes of the peer's segments on the way:
/// delivered, dropped, reordered, duplicated, or corrupted at chosen offsets.
/// Corruptions start from a segment that is valid for the connection, so
/// they reach the state machine rather than its first sequence check.
#[cfg(feature = "vtcp")]
pub fn vtcp_conversation(data: &[u8]) {
    use crate::vtcp::{Conn, ConnConfig, Segment};
    use std::collections::VecDeque;

    let cfg = |local, remote| {
        ConnConfig::default()
            .local_port(local)
            .remote_port(remote)
            .mss(536)
            .send_buf_size(4096)
            .recv_buf_size(4096)
    };
    let mut us = Conn::new(cfg(40000, 80));
    let mut peer = Conn::new(cfg(80, 40000));
    // Segments the peer has sent that the network still holds.
    let mut wire: VecDeque<Vec<u8>> = VecDeque::new();

    let Some(syn) = us.connect().into_iter().next() else {
        return;
    };
    let Ok(syn) = Segment::parse(&syn) else {
        return;
    };
    wire.extend(peer.accept_syn(&syn));

    fn to_peer(peer: &mut Conn, wire: &mut VecDeque<Vec<u8>>, segs: Vec<Vec<u8>>) {
        for s in segs {
            if let Ok(seg) = Segment::parse(&s) {
                wire.extend(peer.handle_segment(&seg));
            }
        }
    }

    let mut buf = [0u8; 1024];
    for msg in messages(data) {
        let Some((&op, arg)) = msg.split_first() else {
            continue;
        };
        match op % 12 {
            0 => {
                let (_, segs) = us.write(arg);
                to_peer(&mut peer, &mut wire, segs);
            }
            1 => wire.extend(peer.write(arg).1),
            2 | 3 => {
                if let Some(s) = wire.pop_front()
                    && let Ok(seg) = Segment::parse(&s)
                {
                    let out = us.handle_segment(&seg);
                    to_peer(&mut peer, &mut wire, out);
                }
            }
            4 => {
                // Corrupt: (offset, value) pairs XORed into the next segment.
                if let Some(mut s) = wire.pop_front() {
                    for pair in arg.as_chunks::<2>().0 {
                        let at = pair[0] as usize % s.len().max(1);
                        if let Some(b) = s.get_mut(at) {
                            *b ^= pair[1];
                        }
                    }
                    if let Ok(seg) = Segment::parse(&s) {
                        let out = us.handle_segment(&seg);
                        to_peer(&mut peer, &mut wire, out);
                    }
                }
            }
            5 => {
                wire.pop_front();
            }
            6 => {
                if let Some(s) = wire.front().cloned() {
                    wire.push_back(s);
                }
            }
            7 => {
                if wire.len() >= 2 {
                    wire.swap(0, 1);
                }
            }
            8 => {
                let _ = us.read(&mut buf);
                let out = us.take_outgoing();
                to_peer(&mut peer, &mut wire, out);
                let _ = peer.read(&mut buf);
                wire.extend(peer.take_outgoing());
            }
            9 => {
                if arg.first().is_some_and(|b| b & 1 == 0) {
                    let out = us.close();
                    to_peer(&mut peer, &mut wire, out);
                } else {
                    wire.extend(peer.close());
                }
            }
            10 => {
                let out = us.tick();
                to_peer(&mut peer, &mut wire, out);
                wire.extend(peer.tick());
            }
            _ => {
                // Wholly attacker-built, as from someone off the path.
                if let Ok(seg) = Segment::parse(arg) {
                    let out = us.handle_segment(&seg);
                    to_peer(&mut peer, &mut wire, out);
                }
            }
        }
        wire.truncate(1024);
    }
}

/// A DHCP server and client each handed a sequence of messages.
#[cfg(feature = "dhcp")]
pub fn dhcp_exchange(data: &[u8]) {
    use crate::dhcp::{Client, ClientConfig, ClientTransport, Server, ServerConfig};
    use crate::{Frame, IpPrefix, MacAddr};
    use std::net::Ipv4Addr;

    struct Quiet;
    impl ClientTransport for Quiet {
        fn mac(&self) -> MacAddr {
            MacAddr([2, 0, 0, 0, 0, 1])
        }
        fn send_broadcast(&self, _: &Frame) {}
        fn send_unicast(&self, _: Ipv4Addr, _: &Frame) {}
        fn on_bound(&self, _: IpPrefix, _: Option<Ipv4Addr>) {}
    }

    let server = Server::new(ServerConfig::new(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 100),
        Ipv4Addr::new(10, 0, 0, 110),
    ));
    // Starting a client spawns its timer thread, so one serves every input,
    // as the wg body does with its handler.
    static CLIENT: std::sync::OnceLock<Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        let c = Client::new(Quiet, ClientConfig::default());
        c.start();
        c
    });
    for msg in messages(data) {
        server.handle_dhcp(msg);
        client.handle_packet(msg);
        client.tick();
    }
}

/// Frames into an L2Adapter: the ARP and NDP handling, the NDP queue, and
/// its cache, fed one frame after another.
#[cfg(feature = "l2adapter")]
pub fn l2adapter_frames(data: &[u8]) {
    use crate::{IpPrefix, L2Adapter, L2AdapterConfig, L2Device, L3Device, MacAddr, PipeL3};
    use std::sync::Arc;

    // An adapter spawns its ARP queue's sweeper thread, so one serves every
    // input, as the wg body does with its handler.
    static ADAPTER: std::sync::OnceLock<(Arc<PipeL3>, Arc<L2Adapter>)> = std::sync::OnceLock::new();
    let (inner, adapter) = ADAPTER.get_or_init(|| {
        let inner = Arc::new(PipeL3::new("10.0.0.2/24".parse::<IpPrefix>().unwrap()));
        let adapter = L2Adapter::new(
            inner.clone(),
            L2AdapterConfig::default()
                .mac(MacAddr([2, 0, 0, 0, 0, 2]))
                .gateway_v4("10.0.0.1".parse().unwrap()),
        );
        (inner, adapter)
    });
    for msg in messages(data) {
        if msg.first().is_some_and(|b| b & 1 == 0) {
            // From the network.
            let _ = adapter.send(Frame::from_slice(&msg[1..]));
        } else if msg.len() > 1 {
            // From the L3 side, to be resolved and framed.
            let _ = inner.send(Packet::from_slice(&msg[1..]));
        }
    }
}

/// slirp's IP reassembler, fed one fragment after another, as slirp's input
/// path would after validating each header.
#[cfg(feature = "slirp")]
pub fn slirp_reassembly(data: &[u8]) {
    let mut r = crate::defrag::Reassembler::default();
    let now = crate::time::Instant::now();
    for msg in messages(data) {
        let p = Packet::from_slice(msg);
        match msg.first().map(|b| b >> 4) {
            Some(4) if msg.len() >= 20 => {
                let ihl = (msg[0] & 0x0F) as usize * 4;
                let total = u16::from_be_bytes([msg[2], msg[3]]) as usize;
                if ihl >= 20 && total >= ihl && total <= msg.len() {
                    let _ = r.push_v4(now, 0, &msg[..total], ihl);
                }
            }
            Some(6) if msg.len() >= 48 => {
                // The fragment header right after the fixed one.
                let _ = r.push_v6(now, 0, msg, 40);
            }
            _ => {
                let _ = p.is_valid();
            }
        }
    }
}

#[cfg(feature = "vclient")]
pub fn dns_parse(data: &[u8]) {
    use crate::vclient::dns::{RecordType, wire};
    if let Some(query) = wire::build_query(0x1234, "example.com", RecordType::A) {
        let _ = wire::parse_response(data, &query);
    }
    // Also as the answer to itself: its ID and question then match, so the
    // parser gets past those checks and into the records and names.
    let _ = wire::parse_response(data, data);
}

#[cfg(feature = "nat")]
pub fn defrag(data: &[u8]) {
    let d = crate::nat::defrag::Defragger::new();
    // The whole input once, then as a sequence of fragments: overlaps and
    // bounds only show up across fragments of one datagram.
    let _ = d.process(data);
    for msg in messages(data) {
        let _ = d.process(msg);
    }
    d.sweep();
}

/// Drive a NAT with every ALG registered, in both directions.
#[cfg(feature = "nat")]
pub fn nat_forward(data: &[u8]) {
    use crate::L3Device;
    use crate::nat::{FtpHelper, H323Helper, IrcHelper, Nat, PptpHelper, SipHelper, TftpHelper};
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
    // Then a conversation: the low bit of each message's first byte picks
    // the side, so mappings made by one packet meet the next.
    for msg in messages(data) {
        if let Some((&side, pkt)) = msg.split_first() {
            let dev = if side & 1 == 0 {
                nat.inside()
            } else {
                nat.outside()
            };
            let _ = dev.send(Packet::from_slice(pkt));
        }
    }
    nat.sweep();
}

/// NAT64, fed a conversation from both sides.
#[cfg(feature = "nat")]
pub fn nat64_forward(data: &[u8]) {
    use crate::L3Device;
    use crate::nat::Nat64;

    let nat = Nat64::new(
        "64:ff9b::/96".parse().unwrap(),
        "192.0.2.1/24".parse().unwrap(),
    );
    for msg in messages(data) {
        if let Some((&side, pkt)) = msg.split_first() {
            let dev = if side & 1 == 0 {
                nat.inside()
            } else {
                nat.outside()
            };
            let _ = dev.send(Packet::from_slice(pkt));
        }
    }
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
            unknown_peer_limit: None,
        })
        .expect("wg handler")
    });
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 51820));
    let _ = h.process_packet(data, &addr);
}

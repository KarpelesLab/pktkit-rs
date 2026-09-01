//! Hot-path microbenchmarks.
//!
//! The crate's central claim is that reading and forwarding a packet costs
//! close to nothing, so it should be possible to check that. There is no
//! benchmark dependency here on purpose: the harness below is a warmup, a
//! timed loop and a division, which is enough to catch a change that makes an
//! accessor an order of magnitude slower.
//!
//! ```sh
//! cargo bench
//! ```
//!
//! Numbers are nanoseconds per operation on one core. They are comparable
//! between runs on the same machine and meaningless between machines; treat a
//! change of a few percent as noise.

use pktkit::build::{build_ipv4, build_ipv6, build_tcp, build_udp};
use pktkit::{
    EtherType, Frame, L2Device, L2Hub, L3Device, L3Hub, MacAddr, Packet, PipeL2, PipeL3, Protocol,
    TcpFlags, build_frame, checksum, incremental_update,
};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

fn main() {
    println!("{:<44} {:>12} {:>14}", "benchmark", "ns/op", "ops/sec");
    println!("{}", "-".repeat(72));

    frame_benches();
    packet_benches();
    checksum_benches();
    build_benches();
    hub_benches();
    misc_benches();
}

/// Time `f`, reporting nanoseconds per iteration.
///
/// A tenth of the iterations run first and are discarded, so the measured loop
/// starts with warm caches and a settled branch predictor.
fn bench<F: FnMut()>(name: &str, iters: u64, mut f: F) {
    let warmup = (iters / 10).max(1);
    for _ in 0..warmup {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let per = elapsed.as_nanos() as f64 / iters as f64;
    let rate = if per > 0.0 { 1e9 / per } else { f64::INFINITY };
    println!("{:<44} {:>12.2} {:>14.0}", name, per, rate);
}

fn v4_udp() -> Vec<u8> {
    let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    let udp = build_udp(a.into(), b.into(), 5000, 53, &[0xAB; 512]);
    build_ipv4(a, b, Protocol::UDP, 64, &udp)
}

fn v4_tcp() -> Vec<u8> {
    let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    let tcp = build_tcp(
        a.into(),
        b.into(),
        1234,
        80,
        1,
        2,
        TcpFlags::PSH | TcpFlags::ACK,
        65535,
        &[0xCD; 512],
    );
    build_ipv4(a, b, Protocol::TCP, 64, &tcp)
}

/// An IPv6 packet behind three extension headers, so the walk has work to do.
fn v6_chained() -> Vec<u8> {
    let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let udp = build_udp(IpAddr::V6(a), IpAddr::V6(b), 5000, 53, &[0xAB; 512]);

    let mut chain = Vec::new();
    // hop-by-hop -> routing -> destination options -> UDP
    chain.extend_from_slice(&[43, 0, 0, 0, 0, 0, 0, 0]);
    chain.extend_from_slice(&[60, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    chain.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    chain.extend_from_slice(&udp);
    build_ipv6(a, b, Protocol(0), 64, &chain)
}

fn frame_benches() {
    let payload = v4_udp();
    let plain = build_frame(
        MacAddr::broadcast(),
        MacAddr::zero(),
        EtherType::IPV4,
        &payload,
    );
    let tagged = pktkit::build::push_vlan(Frame::from_slice(&plain), 100, 3);

    bench("frame/parse_header", 5_000_000, || {
        let f = Frame::from_slice(black_box(&plain));
        black_box((f.dst_mac(), f.src_mac(), f.ether_type()));
    });
    bench("frame/payload", 10_000_000, || {
        black_box(Frame::from_slice(black_box(&plain)).payload());
    });
    bench("frame/payload_vlan_tagged", 10_000_000, || {
        black_box(Frame::from_slice(black_box(&tagged)).payload());
    });
}

fn packet_benches() {
    let v4 = v4_udp();
    let tcp = v4_tcp();
    let v6 = v6_chained();

    bench("packet/v4_addrs_and_proto", 5_000_000, || {
        let p = Packet::from_slice(black_box(&v4));
        black_box((p.src_addr(), p.dst_addr(), p.ip_protocol()));
    });
    bench("packet/v4_five_tuple", 3_000_000, || {
        black_box(Packet::from_slice(black_box(&v4)).five_tuple());
    });
    bench("packet/v6_transport_no_ext", 3_000_000, || {
        let p = Packet::from_slice(black_box(&v4));
        black_box(p.transport_protocol());
    });
    bench("packet/v6_transport_3_ext_headers", 3_000_000, || {
        let p = Packet::from_slice(black_box(&v6));
        black_box(p.transport_protocol());
    });
    bench("packet/tcp_view_and_flags", 3_000_000, || {
        let p = Packet::from_slice(black_box(&tcp));
        black_box(
            p.tcp()
                .map(|s| (s.src_port(), s.flags(), s.payload().len())),
        );
    });
    bench("packet/verify_ipv4_checksum", 3_000_000, || {
        black_box(Packet::from_slice(black_box(&v4)).verify_ipv4_checksum());
    });
    bench("packet/verify_transport_checksum", 500_000, || {
        black_box(Packet::from_slice(black_box(&v4)).verify_transport_checksum());
    });
}

fn checksum_benches() {
    let buf = vec![0xA5u8; 1500];
    let header = &v4_udp()[..20];

    bench("checksum/rfc1071_1500B", 500_000, || {
        black_box(checksum(black_box(&buf)));
    });
    bench("checksum/rfc1071_20B", 5_000_000, || {
        black_box(checksum(black_box(header)));
    });
    // Against the 20-byte IP header a recompute is already about this fast, so
    // the incremental path is a wash there. Where it earns its keep is the
    // transport checksum, which covers the whole payload -- compare this
    // against `packet/verify_transport_checksum` above.
    bench("checksum/incremental_4B_rewrite", 10_000_000, || {
        black_box(incremental_update(
            black_box(0x1234),
            black_box(&[10, 0, 0, 1]),
            black_box(&[192, 168, 0, 1]),
        ));
    });

    let mut owned = v4_udp();
    bench("checksum/full_header_recompute", 3_000_000, || {
        Packet::from_mut(black_box(&mut owned)).recompute_ipv4_checksum();
    });
}

fn build_benches() {
    let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    let payload = [0xEFu8; 512];

    bench("build/udp_512B", 1_000_000, || {
        black_box(build_udp(
            black_box(a).into(),
            b.into(),
            5000,
            53,
            black_box(&payload),
        ));
    });
    bench("build/ipv4_wrap", 2_000_000, || {
        black_box(build_ipv4(
            black_box(a),
            b,
            Protocol::UDP,
            64,
            black_box(&payload),
        ));
    });

    let big = {
        let udp = build_udp(a.into(), b.into(), 1, 2, &[0u8; 4000]);
        build_ipv4(a, b, Protocol::UDP, 64, &udp)
    };
    bench("fragment/4KB_to_1500B_mtu", 200_000, || {
        black_box(pktkit::fragment::fragment(
            Packet::from_slice(black_box(&big)),
            1500,
        ));
    });
    bench("icmp/time_exceeded", 500_000, || {
        black_box(pktkit::icmp::time_exceeded(
            Packet::from_slice(black_box(&big)),
            Ipv4Addr::new(192, 0, 2, 1).into(),
        ));
    });
}

fn hub_benches() {
    // Two ports, one learned MAC: the ordinary forwarding case.
    let hub = Arc::new(L2Hub::new());
    let a_mac: MacAddr = "02:00:00:00:00:01".parse().unwrap();
    let b_mac: MacAddr = "02:00:00:00:00:02".parse().unwrap();
    let a = Arc::new(PipeL2::new(a_mac));
    let b = Arc::new(PipeL2::new(b_mac));
    let _ha = hub.connect_arc(a.clone());
    let _hb = hub.connect_arc(b.clone());
    // Nothing on the far side, so we measure the hub rather than the handler.
    b.set_handler(Arc::new(|_f: &Frame| Ok(())));
    a.set_handler(Arc::new(|_f: &Frame| Ok(())));

    let payload = v4_udp();
    let to_b = build_frame(b_mac, a_mac, EtherType::IPV4, &payload);
    let to_a = build_frame(a_mac, b_mac, EtherType::IPV4, &payload);
    // Teach the hub where both stations live.
    a.inject(Frame::from_slice(&to_b)).unwrap();
    b.inject(Frame::from_slice(&to_a)).unwrap();

    bench("l2hub/forward_known_unicast", 1_000_000, || {
        a.inject(Frame::from_slice(black_box(&to_b))).unwrap();
    });

    let bcast = build_frame(MacAddr::broadcast(), a_mac, EtherType::IPV4, &payload);
    bench("l2hub/flood_broadcast", 1_000_000, || {
        a.inject(Frame::from_slice(black_box(&bcast))).unwrap();
    });

    let l3 = Arc::new(L3Hub::new());
    let x = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
    let y = Arc::new(PipeL3::new("192.0.2.1/24".parse().unwrap()));
    let _hx = l3.connect_arc(x.clone());
    let _hy = l3.connect_arc(y.clone());
    y.set_handler(Arc::new(|_p: &Packet| Ok(())));

    let routed = {
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(192, 0, 2, 9));
        let udp = build_udp(a.into(), b.into(), 1, 2, &[0u8; 512]);
        build_ipv4(a, b, Protocol::UDP, 64, &udp)
    };
    bench("l3hub/route_to_prefix", 1_000_000, || {
        x.inject(Packet::from_slice(black_box(&routed))).unwrap();
    });
}

fn misc_benches() {
    let pool = pktkit::BufferPool::new();
    bench("pool/alloc_free_1500B", 5_000_000, || {
        let buf = pool.alloc(black_box(1500));
        pool.free(buf);
    });

    let v4 = v4_udp();
    bench("packet/full_forward_decision", 1_000_000, || {
        // What a router actually does per packet: read the destination, drop
        // the TTL, fix the checksum.
        let mut buf = black_box(&v4).clone();
        let p = Packet::from_mut(&mut buf);
        black_box(p.dst_addr());
        black_box(p.decrement_hop_limit());
        black_box(p.verify_ipv4_checksum());
    });
}

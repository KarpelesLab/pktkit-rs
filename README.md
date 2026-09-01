# pktkit

[![CI](https://github.com/KarpelesLab/pktkit-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/pktkit-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pktkit.svg)](https://crates.io/crates/pktkit)
[![docs.rs](https://img.shields.io/docsrs/pktkit)](https://docs.rs/pktkit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Zero-copy L2/L3 packet handling toolkit for Rust.

`pktkit` is a feature-gated multi-tool for building virtual network topologies:
devices, hubs, adapters, NAT, and tunnels that move Ethernet frames and IP
packets without copying buffers on the hot path.

It is a Rust port of the Go [pktkit](https://github.com/KarpelesLab/pktkit) library,
re-cast into idiomatic Rust:

- `Frame` and `Packet` are `#[repr(transparent)]` newtypes around `[u8]`. You hold
  them as `&Frame` / `&mut Frame`, exactly like Go's `[]byte` alias, with no
  per-call allocation.
- Forwarding uses synchronous callbacks (`Arc<dyn Fn(&Frame) -> io::Result<()>>`),
  not channels or async — matching the Go API one-for-one and keeping the
  hot path zero-cost.
- Everything beyond the core (`Frame`, `Packet`, `L2Hub`, `L3Hub`, `Pipe`, …)
  lives behind a Cargo feature so a user pulling only the core types pays
  nothing for crypto, OS FFI, or protocol stacks they don't use.

## Features

### Core (always on)

- **Zero-copy types**: `Frame` (L2), `Packet` (L3), and the `l4` views
  `TcpSegment`, `UdpDatagram`, `IcmpMessage` — plus `TcpFlags`, `FiveTuple`,
  `EtherType`, `Protocol`, `MacAddr`, `IpPrefix`
- **Traits**: `L2Device`, `L3Device`, `L2Acceptor`, `L2Connector`, `L3Connector`
- **L2Hub**: MAC-learning switch with VLAN access/trunk ports, per-port
  learning limits, and bounded forwarding for looped topologies
- **L3Hub**: prefix-routing hub with default-route fallback
- **PipeL2 / PipeL3**: in-memory devices for testing
- **connect_l2 / connect_l3**: point-to-point wiring
- **serve**: accept loop, with auto-cleanup on `Done`
- **build**: constructors that fill in lengths and checksums, plus VLAN push/pop
- **icmp**: error generation with the RFC rules on when a reply is forbidden
- **fragment**: IPv4 fragmentation for the send path
- **checksum**: RFC 1071, pseudo-header, and RFC 1624 incremental update
- **DeviceStats / HubStats**: rx/tx/drop counters, for when a packet vanishes

### Opt-in cargo features

| Feature      | What you get                                                                  |
| ------------ | ------------------------------------------------------------------------------ |
| `l2adapter`  | ARP, NDP, gateway routing, `L2Adapter` bridging an L3 device onto an L2 net   |
| `dhcp`       | DHCP client codec + `DHCPServer` (DISCOVER/OFFER/REQUEST/ACK/…)               |
| `qemu`       | QEMU userspace network socket protocol (listener + dialer)                    |
| `pcap`       | Mirror a device's traffic to a `.pcap` file (`TapL2` / `TapL3`)              |
| `impair`     | Delay, jitter, loss, duplication, corruption and rate limits on a link       |
| `tuntap`     | TUN/TAP devices on Linux and macOS                                            |
| `afpacket`   | Bind an L2 device to an existing interface (Linux `AF_PACKET`)               |
| `xdp`        | Linux XDP: load/attach eBPF on a device's RX path, capture chosen IP prefixes |
| `afxdp`      | Linux AF_XDP zero-copy sockets (builds on `xdp`)                             |
| `vtcp`       | Pure-Rust TCP engine (congestion, SACK, timestamps, window scaling, SYN cookies) |
| `slirp`      | Userspace NAT stack routing virtual traffic to real sockets                    |
| `vclient`    | High-level virtual client: `dial`, `listen`, DNS, minimal HTTP                |
| `nat`        | Packet-level IPv4 NAT + NAT64 + ALGs (FTP, SIP, H.323, PPTP, TFTP, IRC)      |
| `wg`         | WireGuard tunnel (Noise IK + transport)                                       |
| `ovpn`       | OpenVPN server (TLS control + AES-CBC/GCM data)                               |
| `full`       | All of the above                                                              |

`full` builds on every platform. `xdp` and `afxdp` are Linux kernel interfaces
with no analogue elsewhere, so those two modules are simply absent off Linux;
`tuntap` and `afpacket` keep their types everywhere and report
`ErrorKind::Unsupported` when opened on a platform that has no such device.

### Dependency policy

`pktkit` depends on:

- the Rust standard library
- `libc` (only when `tuntap`, `afpacket`, `xdp` or `afxdp` is enabled)
- [`purecrypto`](https://crates.io/crates/purecrypto) for every piece of
  cryptography — primitives, X.509 and the TLS 1.2 control channel — only when
  `wg` or `ovpn` is enabled. We do not roll our own crypto.

That is the entire tree. Two direct dependencies, **no transitive ones**, no
vendored C or assembly, and no build scripts.

No async runtime. No framework. No native code beyond `libc`. The default
build pulls in zero dependencies, and so do the `pcap` and `impair` features.
The policy is enforced in CI by `cargo-deny` rather than just stated: `ring`,
`aws-lc-rs`, `openssl-sys` and `rustls` are banned outright, so a second crypto
implementation cannot slip back in behind a default feature.

## Requirements

Rust 1.88 or newer, edition 2024.

## Usage

### Point-to-point L3

Devices are shared as `Arc`s (the `Arc<T>: L3Device` blanket impl makes this
ergonomic), and `connect_l3` cross-wires their handlers:

```rust
use std::net::Ipv4Addr;
use std::sync::Arc;
use pktkit::{PipeL3, IpPrefix, connect_l3};

let a = Arc::new(PipeL3::new(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24)));
let b = Arc::new(PipeL3::new(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 2).into(), 24)));
connect_l3(a, b);
```

### Virtual LAN with DHCP and NAT

```rust,ignore
// requires: --features "l2adapter dhcp slirp"
use std::net::Ipv4Addr;
use std::sync::Arc;
use pktkit::{L2Hub, L2Adapter, L2AdapterConfig, IpPrefix, L3Device};
use pktkit::dhcp::{Server as DhcpServer, ServerConfig as DhcpConfig};
use pktkit::slirp::Stack;

let hub = Arc::new(L2Hub::new());

// DHCP server handing out 192.168.0.10–100.
let mut dcfg = DhcpConfig::new(
    Ipv4Addr::new(192, 168, 0, 1),
    Ipv4Addr::new(192, 168, 0, 10),
    Ipv4Addr::new(192, 168, 0, 100),
);
dcfg.router = Some(Ipv4Addr::new(192, 168, 0, 1));
dcfg.dns = vec![Ipv4Addr::new(1, 1, 1, 1)];
let _dhcp_handle = hub.connect(DhcpServer::new(dcfg));

// NAT gateway: a slirp stack routing to the real network, bridged onto L2.
let stack = Stack::new();
stack.set_addr(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 1).into(), 24)).unwrap();
let gw = L2Adapter::new_arc(stack.clone(), L2AdapterConfig::default());
let _gw_handle = hub.connect_arc(gw);
```

### Virtual client over the tunnel (DNS + TCP + HTTP)

```rust,ignore
// requires: --features "vclient"
use std::net::Ipv4Addr;
use pktkit::IpPrefix;
use pktkit::vclient::{Client, ClientConfig};

let client = Client::new(ClientConfig {
    prefix: Some(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 2).into(), 24)),
    dns: vec![Ipv4Addr::new(1, 1, 1, 1).into()],
});
// Wire `client` into an L3 network (slirp, wg, hub) via its L3Device impl,
// then:
let resp = client.http_get("http://example.com/")?;
println!("{} {}", resp.status, resp.text());
```

### WireGuard server with per-peer isolation

```rust,ignore
// requires: --features "wg slirp"
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use pktkit::{IpPrefix, L3Device};
use pktkit::wg::{Adapter, AdapterConfig};
use pktkit::slirp::Stack;

let stack = Stack::new();
stack.set_addr(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24)).unwrap();

let adapter = Adapter::new(AdapterConfig {
    private_key,                      // your server's WireGuard private key
    multi_handler: None,
    connector: stack,                 // each peer gets isolated NAT via L3Connector
    addr: IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24),
    on_unknown_peer: None,
})?;
adapter.add_peer(client_public_key);

let udp = UdpSocket::bind("0.0.0.0:51820")?;
adapter.serve(udp)?;
```

### QEMU VM networking

```rust,ignore
// requires: --features "qemu"
use std::sync::Arc;
use pktkit::{L2Hub, serve};
use pktkit::qemu;

let listener = qemu::Listener::bind_unix("/tmp/qemu.sock")?;
let hub = Arc::new(L2Hub::new());
serve(&listener, &hub)?;  // accept loop: each VM joins the hub
```

### Reading and building packets

Typed views go all the way to L4, and the builders fill in every length and
checksum, so tests and protocol code never assemble headers by hand:

```rust
use pktkit::build::{build_ipv4, build_udp};
use pktkit::{Packet, Protocol};
use std::net::Ipv4Addr;

let (src, dst) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
let udp = build_udp(src.into(), dst.into(), 5000, 53, b"query");
let buf = build_ipv4(src, dst, Protocol::UDP, 64, &udp);

let pkt = Packet::from_slice(&buf);
assert!(pkt.verify_ipv4_checksum());
assert_eq!(pkt.udp().unwrap().dst_port(), 53);
assert_eq!(pkt.five_tuple().unwrap().dst_port, 53);
```

IPv6 extension headers are walked for you: `ip_protocol()` and `payload()`
report the real upper-layer protocol and where it starts, rather than whatever
the next-header field happens to say. `ipv6_next_header()` still gives you the
literal field when you want it.

### Forwarding a packet correctly

The pieces a forwarder owes its senders — expiry, MTU, and the ICMP that
explains both — are in the box:

```rust,ignore
use pktkit::fragment::{fragment, Fragmentation};
use pktkit::{icmp, Packet};

fn forward(pkt: &mut Packet, mtu: usize, me: std::net::IpAddr) -> Vec<Vec<u8>> {
    if !pkt.decrement_hop_limit() {
        // TTL hit zero. Without this, traceroute sees only timeouts.
        return icmp::time_exceeded(pkt, me).into_iter().collect();
    }
    match fragment(pkt, mtu) {
        Fragmentation::Fits => vec![pkt.to_vec()],
        Fragmentation::Fragments(parts) => parts,
        // Too big and DF set, or IPv6: path MTU discovery runs on this reply.
        _ => icmp::packet_too_big(pkt, me, mtu as u32).into_iter().collect(),
    }
}
```

### Seeing what happened

Devices and hubs keep counters, and any device can be wrapped in a tap that
writes a `.pcap` Wireshark opens:

```rust,ignore
// requires: --features "pcap"
use pktkit::pcap::TapL2;

let tap = TapL2::to_file(device, "/tmp/capture.pcap")?;
// use `tap` in place of `device`; both directions are written as they pass

let s = hub.stats();
println!("received {} forwarded {} flooded {} dropped {}",
         s.received, s.forwarded, s.flooded, s.dropped);
```

### Testing against a bad link

```rust,ignore
// requires: --features "impair"
use pktkit::impair::{ImpairL2, Impairment};
use std::time::Duration;

let link = ImpairL2::new(device, Impairment {
    delay: Duration::from_millis(50),
    jitter: Duration::from_millis(10),
    loss: 0.02,
    rate_bps: 10_000_000,
    seed: 0x5EED,          // same seed, same drops: a flake becomes a test case
    ..Default::default()
});
```

### Capturing specific addresses with XDP

`xdp` attaches an eBPF program that redirects only the traffic belonging to a
set of IP prefixes and returns `XDP_PASS` for everything else, so a capture
device shares a live NIC with the host stack instead of black-holing it.

```rust
use pktkit::afxdp::{Config, Device};
use pktkit::{Frame, IpPrefix, L2Device};
use std::net::Ipv4Addr;
use std::sync::Arc;

// One AF_XDP socket per RX queue, native-mode attach, zero-copy if the
// driver supports it.
let dev = Device::open(Config {
    interface: "eth0".into(),
    ..Default::default()
})?;

dev.set_handler(Arc::new(|frame: &Frame| {
    println!("{} bytes", frame.as_bytes().len());
    Ok(())
}));

// Nothing is diverted until an address is named. Takes effect immediately:
// the prefix goes into a map the running program reads.
dev.capture_add(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 7).into(), 32))?;

println!("zero-copy: {}, queues: {:?}", dev.zerocopy(), dev.queue_ids());
```

Matching is longest-prefix, so a `/24` captures a whole subnet. ARP for a
captured IPv4 address is captured too (otherwise nothing could resolve it), and
adding an IPv6 `/128` also captures its solicited-node multicast address so
neighbour discovery arrives.

**A capture can never widen into the whole interface.** `capture_add` refuses a
`/0` outright, refuses anything shorter than the configured per-family floor
(`min_prefix_v4` / `min_prefix_v6`), and refuses any addition that would leave
the set covering an entire address family — two `/1`s clear the floor
individually but not together. Both checks run before anything reaches the
kernel, so a refused call leaves the set unchanged. Traffic that matches nothing
returns `XDP_PASS` and goes to the host stack as usual.

## Status

Active development; the API is not yet stable. Most features are functionally
complete and tested; a few have documented `// TODO(<feature>)` gaps:

- **ovpn**: tls-crypt/tls-auth, control-packet retransmit timers, and fuller
  PUSH_REPLY negotiation are not yet implemented.
- **xdp / afxdp**: program codegen, map key layout and ring math are
  unit-tested, and `tests/xdp_kernel.rs` covers verifier acceptance and the
  veth datapath — but those are `#[ignore]`d because they need root, so the
  kernel-facing paths stay marked `// TODO(afxdp)` until CI runs them.
  Zero-copy additionally needs a driver that supports it; `Device::zerocopy()`
  reports what was actually negotiated.
- **tuntap**: macOS `utun` is type-checked against the Apple target but not yet
  exercised on a macOS host.
- **slirp**: inbound virtual TCP accept is IPv4-only (IPv6 accept is a TODO).
- **nat**: SIP/H.323/PPTP ALGs rewrite payloads; UPnP's live TCP control
  endpoint awaits wiring through the virtual TCP listener.

## License

MIT — see [LICENSE](LICENSE).

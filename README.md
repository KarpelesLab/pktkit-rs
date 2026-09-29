# pktkit

[![CI](https://github.com/KarpelesLab/pktkit-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/pktkit-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pktkit.svg)](https://crates.io/crates/pktkit)
[![docs.rs](https://img.shields.io/docsrs/pktkit)](https://docs.rs/pktkit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Zero-copy L2/L3 packet handling toolkit for Rust.

`pktkit` is a feature-gated multi-tool for building virtual network topologies:
devices, hubs, adapters, NAT, and tunnels that move Ethernet frames and IP
packets without copying buffers on the hot path.

It began as a port of the Go [pktkit](https://github.com/KarpelesLab/pktkit)
library, which is being discontinued; this crate is where development continues.
Behaviour follows the kernel ABIs, RFCs and wire formats it implements rather
than the Go code, and the design is idiomatic Rust:

- `Frame` and `Packet` are `#[repr(transparent)]` newtypes around `[u8]`. You hold
  them as `&Frame` / `&mut Frame`, exactly like Go's `[]byte` alias, with no
  per-call allocation.
- Forwarding uses synchronous callbacks (`Arc<dyn Fn(&Frame) -> io::Result<()>>`),
  not channels or async, which keeps the hot path zero-cost.
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
- **DeviceStats / HubCounters**: rx/tx/drop counters, for when a packet vanishes

### Opt-in cargo features

| Feature      | What you get                                                                  |
| ------------ | ------------------------------------------------------------------------------ |
| `l2adapter`  | ARP, NDP, gateway routing, `L2Adapter` bridging an L3 device onto an L2 net   |
| `dhcp`       | DHCP client codec + `DHCPServer` (DISCOVER/OFFER/REQUEST/ACK/…)               |
| `qemu`       | QEMU userspace network socket protocol (listener + dialer)                    |
| `pcap`       | Mirror a device's traffic to a `.pcap` file (`TapL2` / `TapL3`)              |
| `impair`     | Delay, jitter, loss, duplication, corruption, rate limits, ECN marking      |
| `tuntap`     | TUN/TAP devices on Linux and macOS                                            |
| `afpacket`   | Bind an L2 device to an existing interface (Linux `AF_PACKET`)               |
| `xdp`        | Linux XDP: load/attach eBPF on a device's RX path, capture chosen IP prefixes |
| `afxdp`      | Linux AF_XDP zero-copy sockets (builds on `xdp`)                             |
| `vtcp`       | Pure-Rust TCP engine: CUBIC/BBRv3, RACK-TLP, SACK, ECN, PLPMTUD, Fast Open ([below](#the-tcp-engine-vtcp)) |
| `slirp`      | Userspace NAT stack routing virtual traffic to real sockets                    |
| `vclient`    | High-level virtual client: `dial`, `listen`, DNS, minimal HTTP                |
| `nat`        | Packet-level IPv4 NAT + NAT64 + ALGs (FTP, SIP, H.323, PPTP, TFTP, IRC)      |
| `wg`         | WireGuard tunnel (Noise IK + transport)                                       |
| `ovpn`       | OpenVPN server (TLS control + AES-CBC/GCM data)                               |
| `full`       | All of the above                                                              |

`full` builds on every platform. `xdp` and `afxdp` are Linux kernel interfaces
with no analogue elsewhere, so those two modules are simply absent off Linux
(and on 32-bit targets, whose syscall ABI they do not speak);
`tuntap` and `afpacket` keep their types everywhere and report
`ErrorKind::Unsupported` when opened on a platform that has no such device.

That includes [fullrust](https://github.com/KarpelesLab/fullrust)'s
`x86_64-unknown-linux-fullrust`, a Linux target with no libc. `xdp` and
`afxdp` work there too, making their syscalls directly; `tuntap` and
`afpacket` are the unsupported stubs.

### The TCP engine (`vtcp`)

A sans-I/O TCP (`vtcp::Conn`: feed it segments, drive its timers, send what
it returns) behind `vclient` and `slirp`, with what a modern Linux TCP does:

- **Handshake and state machine** (RFC 9293): window scaling and timestamps
  (RFC 7323: PAWS, an RTT sample from every ACK), SACK (RFC 2018), SYN
  cookies for listeners past their backlog (RFC 4987), keyed ISNs (RFC 6528),
  challenge ACKs against blind injection (RFC 5961), TIME-WAIT reuse by
  timestamps (RFC 6191), keepalives, zero-window probes, a FIN-WAIT-2
  timeout.
- **Loss recovery**: RACK-TLP (RFC 8985) finds losses by time and probes the
  tail of a flight; PRR (RFC 6937) spreads fast recovery's reduction over the
  round trip; RFC 6675's scoreboard, with NewReno partial ACKs (RFC 6582) and
  Limited Transmit (RFC 3042) against peers without SACK. D-SACK (RFC 2883),
  Eifel (RFC 3522) and F-RTO (RFC 5682) tell a spurious retransmission, and
  its window cut is undone (RFC 3708, RFC 4015).
- **Congestion control**: CUBIC with HyStart++ (RFC 9438, RFC 9406; the
  default), BBRv3 (draft-ietf-ccwg-bbr, over delivery rate estimation),
  NewReno (RFC 5681) and HighSpeed (RFC 3649); congestion window validation
  (RFC 7661) and restart after idle. Pacing, as Linux's: each round trip's
  data spread over it.
- **ECN**: classic (RFC 3168, with RFC 8511's gentler back-off) and accurate
  (RFC 9768, AccECN), negotiated in the handshake.
- **Buffers auto-tuned** as Linux's: the receive window follows what the
  application reads per round trip, the send buffer the congestion window.
  Delayed ACKs (RFC 1122, RFC 5681) with quick-ACK and ping-pong modes.
- **Path MTU**: ICMP Packet Too Big / Fragmentation Needed (RFC 1191, RFC
  8201), checked against what is in flight (RFC 5927); and where ICMP is
  filtered, PLPMTUD (RFC 4821): a black hole found from repeated timeouts,
  and the MTU searched for with probes, as Linux's `tcp_mtu_probing`.
- **TCP Fast Open** (RFC 7413), opt-in: data in the SYN, answered before the
  handshake completes, so a request takes one round trip instead of two.

Each connection is set up by a `vtcp::ConnConfig`; `vclient::ClientConfig::tcp`
and `slirp::Stack::set_tcp` take a `vtcp::Tuning` for the connections they
open:

```rust,ignore
// requires: --features "vclient"
use pktkit::vclient::{Client, ClientConfig};
use pktkit::vtcp::{CongestionKind, Tuning};

let client = Client::new(ClientConfig::default().tcp(
    Tuning::default().congestion(CongestionKind::Bbr).fast_open(true),
));
// With Fast Open, the request rides in the SYN once the server has given a
// cookie (the first connection asks for it).
let conn = client.dial_tcp_with_data("10.0.0.1:80".parse()?, b"GET / HTTP/1.0\r\n\r\n")?;
```

### WebAssembly

`full` also builds for `wasm32-unknown-unknown` (browsers, and hosts that
supply their own imports) and `wasm32-wasip1`. There are no threads or host
sockets there, so the crate works as a sans-I/O stack that the embedder drives:

- **Absent:** `slirp` and `qemu`, which are built on host sockets, and the
  socket-owning `wg::Server` / `wg::Adapter` and `ovpn::Server` /
  `ovpn::Adapter`. `vclient`'s `Resolver` and HTTP client are also absent, and
  so are `vclient`'s blocking `dial_tcp`, `dial_tcp_with_data` and
  `serve_with_done`. The sans-I/O
  cores (`wg::Handler`, `ovpn::Peer`, `nat`, `vtcp`, the codecs) are all
  there.
- **Nothing blocks.** `vclient`'s `TcpConn`, `UdpConn` and `Listener` return
  `ErrorKind::WouldBlock` where they would have waited. Open connections with
  `Client::dial_tcp_nonblocking` and check `TcpConn::poll_connect`.
- **You run the timers.** Work that a background thread does elsewhere is a
  method you call on a timer: `vclient::Client::tick` (TCP retransmits,
  delayed ACKs and keepalives, when `Client::next_timer` says),
  `ImpairL2::poll` / `ImpairL3::poll`
  (each returns when the next message is due), `dhcp::Client::tick` or
  `L2Adapter::tick` (DHCP retransmission, renewal and expiry),
  `wg::Handler::poll_timers` (handshake retries, rekeys and keepalives) and
  `wg::Handler::maintenance`. (`nat::Nat::sweep` is optional: the NAT also
  expires idle mappings as packets pass through it.)

On `wasm32-unknown-unknown` the clock and the entropy come from the page.
Supply these imports when you instantiate the module (each one is only
required if the build uses it):

```js
const imports = {
  pktkit: {
    now_ms: () => performance.now(), // monotonic clock, used by every timer
    unix_ms: () => Date.now(),       // wall clock: pcap timestamps, WireGuard TAI64N, RNG seeding
  },
  purecrypto: {                      // `wg` / `ovpn` only
    random_get: (ptr, len) =>
      crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len)),
  },
};
```

WASI provides a clock and `random_get` natively, so nothing extra is needed
there.

`vtcp` keys its initial sequence numbers, SYN cookies and Fast Open cookies
with std's `RandomState`, which on `wasm32-unknown-unknown` has no entropy
source and can be guessed. Keep Fast Open off there if peers may be hostile:
a forged cookie would have the stack answer SYN data for an address the
sender does not own.

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

Rust 1.89 or newer, edition 2024.

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
// `a` holds the wiring (and `b`): keep it for as long as the link should last.
connect_l3(a.clone(), b);
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
let dcfg = DhcpConfig::new(
    Ipv4Addr::new(192, 168, 0, 1),
    Ipv4Addr::new(192, 168, 0, 10),
    Ipv4Addr::new(192, 168, 0, 100),
)
.router(Ipv4Addr::new(192, 168, 0, 1))
.dns(vec![Ipv4Addr::new(1, 1, 1, 1)]);
let _dhcp_handle = hub.connect(DhcpServer::new(dcfg));

// NAT gateway: a slirp stack routing to the real network, bridged onto L2.
let stack = Stack::new();
stack.set_addr(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 1).into(), 24)).unwrap();
let gw = L2Adapter::new_arc(stack.clone(), L2AdapterConfig::default());
let _gw_handle = hub.connect_arc(gw);
```

### Virtual client (TCP + HTTP over the virtual network)

TCP and UDP connections, and so HTTP, travel the virtual network the client is
wired into. Name resolution does not: `Client::resolve` (which `http_get` uses
for host names) queries the configured DNS servers from the host's own sockets.

```rust,ignore
// requires: --features "vclient"
use std::net::Ipv4Addr;
use pktkit::IpPrefix;
use pktkit::vclient::{Client, ClientConfig};

let client = Client::new(
    ClientConfig::default()
        .prefix(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 2).into(), 24))
        .dns(vec![Ipv4Addr::new(1, 1, 1, 1).into()]),
);
// Wire `client` into an L3 network (slirp, wg, hub) via its L3Device impl,
// then:
let resp = client.http_get("http://example.com/")?;
println!("{} {}", resp.status, resp.text());
```

### WireGuard server with per-peer isolation

```rust,ignore
// requires: --features "wg slirp"
use std::net::{Ipv4Addr, UdpSocket};
use pktkit::{IpPrefix, L3Device};
use pktkit::wg::{Adapter, AdapterConfig, NoisePublicKey, generate_private_key};
use pktkit::slirp::Stack;

// In practice, load both keys from your configuration: each is 32 raw bytes
// (`NoisePrivateKey::from([u8; 32])`, `NoisePublicKey::from([u8; 32])`).
let private_key = generate_private_key()?;
let client_public_key = NoisePublicKey::from([0u8; 32]);

let stack = Stack::new();
stack.set_addr(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24)).unwrap();

let adapter = Adapter::new(AdapterConfig::new(
    private_key,                      // your server's WireGuard private key
    stack,                            // each peer gets isolated NAT via L3Connector
    IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24),
))?;
adapter.add_peer(client_public_key);
// Like the kernel's AllowedIPs: only packets from these sources are taken
// from the peer. Without it any source is accepted, which is fine with one
// isolated stack per peer but not when peers share a routing hub
// (`AdapterConfig::require_allowed_ips` makes it mandatory).
adapter.set_allowed_ips(
    &client_public_key,
    vec![IpPrefix::new(Ipv4Addr::new(10, 0, 0, 2).into(), 32)],
);

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

let link = ImpairL2::new(
    device,
    Impairment::default()
        .delay(Duration::from_millis(50))
        .jitter(Duration::from_millis(10))
        .loss(0.02)
        .rate_bps(10_000_000)
        .seed(0x5EED), // same seed, same drops: a flake becomes a test case
);
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
let dev = Device::open(Config::new("eth0"))?;

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
so is an IPv6 neighbour solicitation whose target is a captured address.

`capture_add` takes the whole address. To share one with the host stack, name
a protocol or a TCP/UDP port on it instead:

```rust
use pktkit::xdp::Rule;
use pktkit::Protocol;

let host = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 32);
// WireGuard on the host's own address. ICMP, SSH, ARP and everything else on
// 10.0.0.1 keep going to the kernel.
dev.capture_add_rule(host, Rule::Port(Protocol::UDP, 51820))?;
// Or a whole protocol.
dev.capture_add_rule(host, Rule::Proto(Protocol::GRE))?;
```

A prefix holds up to `max_rules_per_prefix` rules (default 8) and is captured
when any one of them matches. The port compared is the captured endpoint's —
the destination port when the destination address matched, the source port
when the source did. ARP and neighbour discovery are diverted only for a prefix
with a `Rule::Any`; a narrower rule means the host stack still owns the address
and keeps answering for it. A non-first IPv4 fragment carries no port and
matches only protocol rules; IPv6 extension headers are not walked.

**A capture can never widen into the whole interface.** `capture_add` refuses a
`/0` outright, refuses anything shorter than the configured per-family floor
(`min_prefix_v4` / `min_prefix_v6`), and refuses any addition that would leave
the set covering an entire address family — two `/1`s clear the floor
individually but not together. Both checks run before anything reaches the
kernel, so a refused call leaves the set unchanged. Traffic that matches nothing
returns `XDP_PASS` and goes to the host stack as usual.

That uncaptured traffic is what the program is tuned for: a miss costs the
bounds checks, one key and one lookup, and the transport header is parsed only
after an address hit on a prefix with a narrow rule. `Capture::test_run` runs
the loaded program against a frame you supply and reports the verdict and the
mean nanoseconds per run, so the cost can be measured without traffic.

On the userspace side, three things are worth setting under load:

```rust
// One ring update and at most one wakeup syscall for the whole burst.
let sent = dev.send_batch(&frames)?;

let cfg = Config::new("eth0")
    // Re-check an empty RX ring this many times before blocking in poll().
    .rx_spin(2000)
    // RX thread i, serving the i'th bound queue, runs on rx_cpus[i].
    .rx_cpus(vec![2, 3]);
```

## Status

Active development; the API is not yet stable. Most features are functionally
complete and tested; a few have documented `// TODO(<feature>)` gaps:

- **ovpn**: tls-crypt/tls-auth and fuller PUSH_REPLY negotiation are not yet
  implemented. (Control-packet retransmission, keepalive and renegotiation
  timers run from `Peer::tick`, which `ovpn::Server` drives.)
- **xdp / afxdp**: program codegen, map key layout and ring math are
  unit-tested, and `src/xdp/kernel_tests.rs` (verifier acceptance) and
  `tests/xdp_kernel.rs` (the veth datapath) cover the kernel side — but
  those are `#[ignore]`d because they need root, so the
  kernel-facing paths stay marked `// TODO(afxdp)` until CI runs them.
  Zero-copy additionally needs a driver that supports it; `Device::zerocopy()`
  reports what was actually negotiated.
- **tuntap**: macOS `utun` is type-checked against the Apple target but not yet
  exercised on a macOS host.
- **slirp**: virtual listeners (`Stack::listen`, `Stack::listen6`) drop a SYN
  when their accept queue is full rather than falling back to SYN cookies.
- **nat**: UPnP's SOAP control port is served over the in-tree `vtcp` engine,
  one request per connection; pipelined and chunked requests are not handled.

## License

MIT — see [LICENSE](LICENSE).

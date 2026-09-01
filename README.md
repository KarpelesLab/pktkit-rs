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

- **Zero-copy types**: `Frame`, `Packet`, `EtherType`, `Protocol`, `MacAddr`
- **Traits**: `L2Device`, `L3Device`, `L2Acceptor`, `L2Connector`, `L3Connector`
- **L2Hub**: MAC-learning switch with 5-minute aging
- **L3Hub**: prefix-routing hub with default-route fallback
- **PipeL2 / PipeL3**: in-memory devices for testing
- **connect_l2 / connect_l3**: point-to-point wiring
- **serve**: accept loop, with auto-cleanup on `Done`
- **checksum**: RFC 1071 + pseudo-header

### Opt-in cargo features

| Feature      | What you get                                                                  |
| ------------ | ------------------------------------------------------------------------------ |
| `l2adapter`  | ARP, NDP, gateway routing, `L2Adapter` bridging an L3 device onto an L2 net   |
| `dhcp`       | DHCP client codec + `DHCPServer` (DISCOVER/OFFER/REQUEST/ACK/…)               |
| `qemu`       | QEMU userspace network socket protocol (listener + dialer)                    |
| `tuntap`     | TUN/TAP devices on Linux and macOS                                            |
| `xdp`        | Linux XDP: load/attach eBPF on a device's RX path, capture chosen IP prefixes |
| `afxdp`      | Linux AF_XDP zero-copy sockets (builds on `xdp`)                             |
| `vtcp`       | Pure-Rust TCP engine (congestion, SACK, timestamps, window scaling, SYN cookies) |
| `slirp`      | Userspace NAT stack routing virtual traffic to real sockets                    |
| `vclient`    | High-level virtual client: `dial`, `listen`, DNS, minimal HTTP                |
| `nat`        | Packet-level IPv4 NAT + NAT64 + ALGs (FTP, SIP, H.323, PPTP, TFTP, IRC)      |
| `wg`         | WireGuard tunnel (Noise IK + transport)                                       |
| `ovpn`       | OpenVPN server (TLS control + AES-CBC/GCM data)                               |
| `full`       | All of the above                                                              |

### Dependency policy

`pktkit` depends on:

- the Rust standard library
- `libc` (only when `tuntap`, `xdp` or `afxdp` is enabled)
- RustCrypto primitive crates (`chacha20poly1305`, `aes-gcm`, `curve25519-dalek`,
  `sha2`, `hmac`, `blake2`, `rsa`, …) — only when the relevant tunnel feature is
  enabled. We do not roll our own crypto.
- `rustls` for OpenVPN's control-channel TLS (only when `ovpn` is enabled),
  configured with a **pure-Rust** crypto provider (`rustls-rustcrypto`, backed
  by the same RustCrypto crates) — no `ring`, no `aws-lc-rs`, no vendored
  C/assembly, and no compile-time build script.

Nothing else. No async runtime. No framework. No native code beyond `libc`.
Everything cross-compiles. The default build pulls in zero dependencies.

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

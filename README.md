# pktkit

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
| `afxdp`      | Linux AF_XDP zero-copy sockets                                                |
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
- `libc` (only when `tuntap` or `afxdp` is enabled)
- RustCrypto primitive crates (`chacha20poly1305`, `aes-gcm`, `curve25519-dalek`,
  `sha2`, `hmac`, `blake2`, `rsa`, …) — only when the relevant tunnel feature is
  enabled. We do not roll our own crypto.

Nothing else. No async runtime. No framework. The default build pulls in
zero dependencies.

## Usage

### Point-to-point L3

```rust
use std::net::Ipv4Addr;
use pktkit::{PipeL3, IpPrefix, connect_l3};

let a = PipeL3::new(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24));
let b = PipeL3::new(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 2).into(), 24));
connect_l3(&a, &b);
```

### Virtual LAN with DHCP and NAT (with the right features)

```rust,ignore
# // requires --features "l2adapter,dhcp,slirp,vclient"
use std::net::Ipv4Addr;
use pktkit::{L2Hub, L2Adapter, IpPrefix, dhcp::DhcpServer};
use pktkit::slirp::Stack;
use pktkit::vclient::Client;

let hub = L2Hub::new();

let dhcp = DhcpServer::builder()
    .server_ip(Ipv4Addr::new(192, 168, 0, 1))
    .range(Ipv4Addr::new(192, 168, 0, 10), Ipv4Addr::new(192, 168, 0, 100))
    .router(Ipv4Addr::new(192, 168, 0, 1))
    .dns(Ipv4Addr::new(1, 1, 1, 1))
    .build();
hub.connect(&dhcp);

let stack = Stack::new();
stack.set_addr(IpPrefix::new(Ipv4Addr::new(192, 168, 0, 1).into(), 24));
hub.connect(&L2Adapter::new(&stack, None));

let client = Client::new();
let adapter = L2Adapter::new(&client, None);
hub.connect(&adapter);
adapter.start_dhcp();

let resp = client.http_client().get("https://example.com")?;
```

### WireGuard server with per-peer isolation

```rust,ignore
# // requires --features "wg,slirp"
use std::net::{Ipv4Addr, UdpSocket};
use pktkit::{IpPrefix, wg::Adapter};
use pktkit::slirp::Stack;

let stack = Stack::new();
stack.set_addr(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24));

let adapter = Adapter::builder().connector(&stack).build()?;
adapter.add_peer(client_public_key);

let udp = UdpSocket::bind("0.0.0.0:51820")?;
adapter.serve(udp);
```

### QEMU VM networking

```rust,ignore
# // requires --features "qemu"
use pktkit::{L2Hub, serve};
use pktkit::qemu;

let listener = qemu::Listener::bind_unix("/tmp/qemu.sock")?;
let hub = L2Hub::new();
serve(&listener, &hub)?;
```

## Status

Active development. The API is unstable until 0.1.0.

## License

MIT — see [LICENSE](LICENSE).

# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); this crate follows
semantic versioning once it reaches 1.0.

## [0.1.1](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.0...v0.1.1) - 2026-05-25

### Other

- slirp v6 accept, ovpn retransmit/peer-info, nat UPnP TCP, vclient UDP, wg multi-handler

## [0.1.0] — unreleased

First release: a feature-gated Rust port of the Go
[pktkit](https://github.com/KarpelesLab/pktkit) toolkit.

### Core (always compiled, zero dependencies)

- Zero-copy `Frame` and `Packet` (`#[repr(transparent)]` over `[u8]`).
- `MacAddr`, `EtherType`, `Protocol`, `IpPrefix` value types.
- `L2Device` / `L3Device` traits and `L2Acceptor` / `L2Connector` /
  `L3Connector` connector traits, with a synchronous callback model.
- `L2Hub` (MAC-learning switch with aging) and `L3Hub` (prefix-routing hub).
- `PipeL2` / `PipeL3` in-memory devices, `connect_l2` / `connect_l3`, `serve`.
- `BufferPool`, RFC 1071 `checksum` + pseudo-header checksum.

### Opt-in features

- `l2adapter` — ARP, NDP, gateway routing, DHCP-driven `L2Adapter`.
- `dhcp` — DHCP wire codec, client state machine, and full `Server`.
- `qemu` — QEMU socket netdev protocol (TCP + Unix listener/dialer).
- `tuntap` — TUN/TAP on Linux (`/dev/net/tun`) and TUN on macOS (`utun`).
- `afxdp` — Linux AF_XDP zero-copy sockets (UMEM rings, eBPF redirect).
- `vtcp` — RFC-9293 TCP engine (SACK, window scaling, timestamps, NewReno +
  HighSpeed, SYN cookies).
- `slirp` — userspace NAT stack (`L3Device` + `L3Connector`) with inbound
  virtual TCP accept.
- `vclient` — DNS resolver, TCP dial over `vtcp`, minimal HTTP/1.1 client.
- `nat` — packet-level IPv4 NAT, NAT64, defrag, and FTP/TFTP/IRC/SIP/H.323/
  PPTP ALGs + UPnP IGD.
- `wg` — WireGuard (Noise IKpsk2 handshake, ChaCha20-Poly1305 transport,
  replay window, cookie-reply DoS mitigation, per-peer L3 isolation).
- `ovpn` — OpenVPN server (rustls TLS 1.2 control channel, AES-GCM/CBC data
  channel, PRF key derivation, UDP/TCP servers, L3/L2 adapter).
- `full` — enables all of the above.

### Dependencies

The default build pulls in **zero** third-party crates. `libc` is used only by
`tuntap`/`afxdp`; RustCrypto primitive crates only by `wg`/`ovpn`; and `rustls`
(an explicit, opt-in exception) only by `ovpn`'s control channel — configured
with the pure-Rust `rustls-rustcrypto` provider, so there is no vendored
C/assembly (`ring`/`aws-lc-rs`) and no compile-time build script. The whole
crate cross-compiles.

### Known gaps

Tracked with `// TODO(<feature>)` markers in the source:

- `ovpn`: tls-crypt/tls-auth, control retransmit timers, fuller PUSH_REPLY.
- `afxdp`: datapath needs root + a NIC to exercise (pure logic is unit-tested).
- `tuntap`: macOS `utun` is type-checked, not yet run on a macOS host.
- `slirp`: inbound virtual TCP accept is IPv4-only.
- `nat`: UPnP's live TCP control endpoint awaits the virtual TCP listener wiring.

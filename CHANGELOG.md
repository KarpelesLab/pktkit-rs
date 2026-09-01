# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); this crate follows
semantic versioning once it reaches 1.0.

## [Unreleased]

### Added

- **`xdp` feature**: the in-kernel half of packet capture, split out of
  `afxdp`. eBPF instruction encoding with a label-patching assembler
  (`xdp::insn`), map create/lookup/update/delete with `LPM_TRIE` and `XSKMAP`
  helpers (`xdp::Map`), program loading that surfaces the verifier log
  (`xdp::Program`), and attachment that prefers the native driver hook, falls
  back to rtnetlink and detaches on drop (`xdp::Link`).
- **`xdp::Capture`**: an XDP program that redirects only the IP prefixes in its
  set and passes everything else to the host stack. The set lives in two
  `LPM_TRIE` maps, so `add`/`remove` take effect with no reload and matching is
  longest-prefix. Matches destination, source or either address; captures ARP
  for the v4 set so a captured address stays resolvable; and inserts the
  solicited-node multicast address alongside an IPv6 `/128` so neighbour
  discovery arrives.
- **Working zero-copy**: `Mode::AUTO` attaches native-first, the bind tries
  `XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP` before copy mode, and `XDP_OPTIONS` is
  read back so `Device::zerocopy()` reports what the kernel did rather than what
  was asked for. `Zerocopy::Require` refuses to start on the slow path.
- **One socket, UMEM and poll thread per RX queue.** Queues are discovered via
  `ETHTOOL_GCHANNELS`/`GRXRINGS`. Each sending thread sticks to one queue so it
  cannot reorder its own frames.
- Optional kernel-side busy polling (`SO_PREFER_BUSY_POLL`, `SO_BUSY_POLL`,
  `SO_BUSY_POLL_BUDGET`) and optional huge-page UMEM.
- `tests/xdp_kernel.rs`: `#[ignore]`d tests covering verifier acceptance for
  every program configuration, LPM trie semantics against the real kernel, and
  the veth datapath.

### Fixed

- `bpf_redirect_map` now passes `XDP_PASS` as its miss verdict. With `flags = 0`
  a frame arriving on a queue with no registered socket returned `XDP_ABORTED`
  and was dropped, rather than falling through to the host stack.
- The RX path handed each frame to the handler through a freshly allocated
  `Vec`. `L2Handler` takes `&Frame`, so the borrow cannot outlive the call and
  the UMEM chunk is not recycled until after the batch — the copy was never
  needed.
- TX no longer drains the completion ring on every send, and skips the `sendto`
  wakeup unless the ring asks for one.
- `send` used to silently truncate a frame larger than the UMEM chunk; it now
  returns `InvalidInput`.
- Dropping a `Device` now stops its poll threads. They hold their own `Arc`s, so
  previously they spun until the process exited.

### Changed (breaking)

- `afxdp::bpf` is removed. Use `pktkit::xdp`, which covers everything it did
  plus maps, attach modes and the verifier log.
- `afxdp::Config::queue_id: u32` becomes `queue_ids: Vec<u32>`; empty means
  every RX queue.
- `afxdp::Config::copy: bool` becomes `zerocopy: Zerocopy`.
- `afxdp::Config` gains `mode`, `program`, `busy_poll` and `huge_pages`.
- An `afxdp::Device` now captures **nothing** until `Device::capture_add` names
  an address, where it previously redirected every packet on the interface.
  Attaching to a live NIC no longer takes the host's own traffic with it.

## [0.1.2](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.1...v0.1.2) - 2026-05-25

### Other

- de-flake the outbound-vtcp large-transfer test
- drive outbound TCP NAT with vtcp::Conn (parity with Go)
- server-side Listen (inbound virtual TCP accept)

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

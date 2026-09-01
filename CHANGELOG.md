# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); this crate follows
semantic versioning once it reaches 1.0.

## [Unreleased]

## [0.1.3](https://github.com/KarpelesLab/pktkit-rs/compare/v0.1.2...v0.1.3) - 2026-09-01

### Other

- release-plz authenticates with the org PAT, like every other crate
- VLAN access and trunk ports
- O(1) unicast forwarding, per-port limits, loop bounding
- fix the L2Hub benchmark, which measured nothing
- fix two toolchain-drift lint failures; cover the TLS version range
- move all crypto to purecrypto, dropping rustls
- move all crypto to purecrypto
- edition 2024, MSRV 1.88
- fix the four failing jobs, drop two unused dependencies
- fuzzing, benchmarks, and a dependency audit
- AF_PACKET, cross-platform builds, and the rest of the counters
- observability, capture, and link impairment
- complete the wire type layer through L4
- a capture can never widen into the whole interface
- keep an explicitly captured solicited-node group
- document the xdp feature and the afxdp breaking changes
- kernel-side integration tests behind --ignored
- address-scoped capture, zero-copy, and a per-queue datapath

### Added — L2Hub

- **VLAN port modes.** `PortMode::Access { vlan }` is an edge port belonging to
  one VLAN that never sees a tag; `PortMode::Trunk { allowed, native }` carries
  several, tagged, with the native VLAN untagged. Flooding reaches only ports
  carrying the frame's VLAN, and a learned address is a hit only on the VLAN it
  was learned on. Set with `set_port_mode`; ports start
  `PortMode::transparent()`, which passes every VLAN through with tags
  untouched, so an unconfigured switch behaves exactly as before.
- `VlanSet`, a 4096-bit set of VLAN ids. The bitmap is boxed so "every VLAN" —
  much the commonest setting — costs a discriminant rather than 512 bytes.
- `set_port_mac_limit` to lift the learning cap on uplinks, `loop_drops()` and
  `set_max_forward_depth` for looped topologies, `port_mode` to read a port's
  configuration back.

### Changed (breaking)

- **All cryptography now comes from [`purecrypto`](https://crates.io/crates/purecrypto).**
  `curve25519-dalek`, `chacha20poly1305`, `blake2`, `aes`, `aes-gcm`, `cbc`,
  `sha1`, `sha2`, `hmac`, `zeroize`, `rand_core`, `getrandom`, `rustls`,
  `rustls-rustcrypto`, `rsa` and `rustls-pemfile` are all gone. The crate's
  entire dependency tree is now `libc` and `purecrypto`, with **no transitive
  dependencies at all** — down from around forty packages.
- `ovpn::ServerConfig::tls_config` and `ovpn::AdapterConfig::tls_config` are
  now `Arc<purecrypto::tls::Config>` instead of `Arc<rustls::ServerConfig>`.
  The config must carry an identity *and* an explicit `.rng(...)` entropy
  source: purecrypto's TLS core is sans-I/O, so it takes entropy as an input
  rather than reaching for a global.
- `ovpn::install_crypto_provider` and `ovpn::crypto_provider` are removed.
  They existed only to manage rustls's process-wide provider, which
  purecrypto has no equivalent of.
- **Edition 2024, MSRV 1.88**, which is what purecrypto requires.

### Added

- Known-answer tests for the WireGuard primitives: X25519 against RFC 7748
  §5.2 and §6.1, BLAKE2s-256 against RFC 7693, MixHash against `h || data`,
  the MAC1/cookie keys against `Blake2s256(label || Spub)`, and the
  data-channel nonce layout. Every previous test here was a self-consistency
  round-trip, which passes just as happily against a subtly wrong primitive
  and only fails when talking to a real peer.

### Removed

- The hand-rolled MD5 and HMAC in `ovpn/prf.rs` — about 250 lines of
  hand-written crypto — now that `purecrypto` supplies both. MD5 was only
  hand-written because none of the RustCrypto crates the `ovpn` feature
  pulled in happened to provide it.
- The `unsafe` block-slice transmute in `ovpn/data.rs`: purecrypto's CBC
  takes `&mut [u8]`, so there is nothing to reinterpret.

### Fixed

- All six `cargo-deny` advisories, by removing the dependencies that carried
  them rather than by annotating around them: four in an outdated
  `rustls-webpki` (RUSTSEC-2026-0049/0098/0099/0104), the `rsa` Marvin timing
  sidechannel (RUSTSEC-2023-0071), and unmaintained `paste`
  (RUSTSEC-2024-0436). `rustls-pemfile` (RUSTSEC-2025-0134) went earlier, as
  a declared-but-unused dependency.
- `aead_seal_in_place` no longer allocates. purecrypto's AEAD uses a detached
  tag, so the plaintext is encrypted directly in the caller's buffer instead
  of via a temporary `Vec`.

### Added — packet toolkit

- **L4 wire types** (`l4` module, re-exported at the root): `TcpSegment`,
  `UdpDatagram` and `IcmpMessage` as `#[repr(transparent)]` views, plus
  `TcpFlags` and the `FiveTuple` that identifies a flow. Reachable straight
  from a packet with `Packet::tcp()`, `udp()`, `icmp()` and `five_tuple()`.
- **The rest of both IP headers on `Packet`**: identification, flags, fragment
  offset, DSCP/ECN, options, traffic class, flow label, and setters for all of
  them. `set_hop_limit` / `decrement_hop_limit` update the IPv4 header checksum
  incrementally and report expiry instead of wrapping to 255.
- **Checksums**: `verify_ipv4_checksum`, `recompute_ipv4_checksum`,
  `verify_transport_checksum`, `recompute_transport_checksum`,
  `recompute_checksums`, a standalone `transport_checksum`, and
  `incremental_update` (RFC 1624) for cheap address and port rewrites.
- **`build` module**: `build_ipv4`, `build_ipv6`, `build_ip`, `build_udp`,
  `build_tcp`, `build_icmpv4`, `build_icmpv6` — every length and checksum
  filled in — plus `push_vlan` / `pop_vlan`.
- **`icmp` module**: `time_exceeded`, `packet_too_big`, `port_unreachable`,
  `no_route`, `admin_prohibited` and the general `error`, each returning a
  complete IP packet. `may_reply` implements the RFC 1812 / RFC 4443 rules on
  when a reply is forbidden — never to another error, a later fragment, or
  anything broadcast or multicast — which is what keeps an error storm from
  starting.
- **`fragment` module**: IPv4 egress fragmentation that honours the option copy
  bit, preserves offsets when re-fragmenting a fragment, and reports
  `DontFragment` / `NotFragmentable` so the caller knows to send an ICMP error
  instead.
- **`DeviceStats` and `HubStats`**: rx/tx/drop counters on devices, and
  received/forwarded/flooded/dropped on hubs. Devices opt in through a
  defaulted `L2Device::stats` / `L3Device::stats`, so existing implementors are
  unaffected. Wired into pipes, hubs, TUN/TAP, AF_PACKET, taps and impaired
  links.
- **`pcap` feature**: `PcapWriter` plus `TapL2` / `TapL3`, which wrap any device
  and mirror both directions into a file Wireshark or `tcpdump -r` opens. A
  write failure counts an error rather than taking the link down. No
  dependencies.
- **`impair` feature**: `ImpairL2` / `ImpairL3` apply delay, jitter, loss,
  duplication, corruption and a rate limit in both directions, released from a
  delay queue in deadline order so jitter reorders traffic the way a real link
  does. Seeding the RNG makes a run reproducible. No dependencies.
- **`afpacket` feature**: an L2 device bound to an existing interface via an
  `AF_PACKET` socket, with optional promiscuous mode and an inbound-only
  filter. Needs no eBPF and creates no interface, which makes it the simplest
  way to put a real NIC in a topology.
- **Fuzzing**: `cargo-fuzz` targets in `fuzz/` covering the packet and L4
  accessors, ICMP generation, fragmentation, DHCP, DNS, vTCP, OpenVPN control,
  WireGuard, defrag and the NAT with every ALG registered. `tests/robustness.rs`
  runs the same bodies on stable in ordinary CI, over mutated, random and
  exhaustively-truncated input.
- **Benchmarks**: `benches/hot_path.rs`, harness-free and dependency-free,
  covering accessors, checksums, hub forwarding and the per-packet work a
  forwarder does.
- **CI**: `cargo-deny` (advisories, licences, and a ban on vendored C crypto
  backends), an MSRV check, a Windows build, docs for individual feature
  subsets, a benchmark run, and a rotating-seed robustness sweep.
- Ergonomics: `Deref`, `AsRef<[u8]>`, `PartialEq`, `Eq` and `Hash` on `Frame`
  and `Packet`; `to_vec()` on both; `vlan_pcp`, `vlan_dei` and `vlan_tci` on
  `Frame`.

### Fixed

- **IPv6 extension headers are no longer mistaken for transport protocols.**
  `Packet::ip_protocol()` returned the raw next-header field, so a hop-by-hop,
  routing or fragment header reported itself as the upper-layer protocol, and
  `payload()` started 40 bytes in regardless. Both now walk the chain. The walk
  is bounded, so a crafted chain cannot spin, and it refuses to point at a
  transport header that a later fragment does not carry.
  `ipv6_next_header()` still returns the literal field.
- **`full` builds on every platform.** It pulls in `xdp` and `afxdp`, which
  were not gated on `target_os`, so enabling it anywhere but Linux failed to
  compile. Those modules are now Linux-only, and `tuntap` gained an
  `Unsupported` stub in place of its `compile_error!`.
- Intra-doc links that resolved only under `--all-features` are fixed, so
  `cargo doc` is clean for any feature subset.
- A panic in `set_hop_limit` on a truncated IPv4 header, found by the new
  randomized sweep on its first run.

### Changed

- `L2Hub` learns per (VLAN, MAC) rather than per MAC, so one address appearing
  on two VLANs is no longer read as a station flapping between ports. Flooding
  still reaches every port; ports carry no VLAN membership to filter on.
- `PipeL2::inject` / `PipeL3::inject` count as received rather than
  transmitted. Delivery is unchanged.
- The `namespace` module is now `accept` — it is about accept loops and has
  nothing to do with network namespaces. Private, so no API change.
- `slirp`'s IPv6 extension-header walker delegates to the crate's canonical one
  instead of keeping a second, less careful copy.

### Added — XDP and AF_XDP

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
- **A capture can never widen into the whole interface.** `Capture::add`
  refuses a `/0` in either family, refuses anything shorter than
  `CaptureConfig::min_prefix_v4` / `min_prefix_v6` (both default to 1, i.e.
  reject only the catch-all), and refuses any addition that would leave the set
  covering an entire address family — a per-prefix floor alone does not catch
  two `/1`s. Both checks run before anything is written to a map, so a refused
  call leaves the capture set unchanged. `CaptureConfig::validate` additionally
  rejects a zero or over-wide floor and a `default_action` that is not `PASS` or
  `DROP`.
- `tests/xdp_kernel.rs`: `#[ignore]`d tests covering verifier acceptance for
  every program configuration, LPM trie semantics against the real kernel, the
  veth datapath, and that a refused over-broad prefix leaves the kernel-side
  trie untouched.

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

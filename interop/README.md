# Interoperability tests: vtcp against Linux

Unit tests pit vtcp against itself, which proves it self-consistent and
nothing more. This suite runs it against the Linux kernel's TCP: a real
kernel, booted in QEMU, talking to a `vclient` (or a `slirp` stack) over
pktkit's own QEMU socket transport, through a link pktkit impairs.

```text
guest eth0 ── qemu::Conn ── ImpairL2 ── Narrow ── L2Hub ── Station ── L2Adapter ── vclient / slirp
   (Linux)     (-netdev stream)  delay, loss,  MTU clamp,          pcap per test,
                                 jitter, rate,  ICMP or            a fresh client
                                 ECN marking    black hole         per test
```

No root is needed, and nothing is installed in the guest: it boots directly
(`-kernel`/`-initrd`) into an initramfs with busybox, a handful of modules,
and the agent (`agent/`), a static musl binary that takes orders over a
virtio console and drives the kernel's TCP with plain sockets, reporting
`TCP_INFO` back. Both ends check every byte of every transfer against a
seeded stream (`src/pattern.rs`).

## Running

Needs QEMU (`qemu-system-aarch64` or `qemu-system-x86_64`), `curl`, `tar`
and `gzip`, and the Rust target for the guest:

```sh
rustup target add aarch64-unknown-linux-musl   # or x86_64-unknown-linux-musl
cd interop
cargo run --release                  # the full matrix, guest of the host's arch
cargo run --release -- --quick       # the CI subset
cargo run --release -- ecn fastopen  # tests whose names contain these
cargo run --release -- --list
```

Options: `--arch aarch64|x86_64`, `--accel hvf|kvm|tcg` (the fastest
available by default: HVF on macOS, KVM where `/dev/kvm` is usable, TCG
otherwise or for a foreign arch), `--kernel lts|stable`, `--keep-pcaps`,
`--deadline SECS` (the whole run's limit: 15 minutes for `--quick`, 90
otherwise).

The guest never outlives the harness: it is powered off at the end of the
run, killed on SIGINT, SIGTERM or SIGHUP, when a test overruns (10
minutes) or the run its deadline (exit status 124), and, on a Linux host,
by the kernel if the harness dies of anything else. On macOS a harness
killed with SIGKILL leaves QEMU behind; the next run finds it through
`target/qemu-<arch>.pid` and kills it. The exit status is 0 only if no
test failed; QEMU's own messages are in `qemu.log` beside the report.

The first run downloads Alpine's kernel and busybox into `interop/.cache`
(40 MB for `lts`); later runs reuse them, and refresh the package index
once a day. The agent is cross-built with the linker Rust ships
(`rust-lld`, see `.cargo/config.toml`), so no C toolchain for the guest is
needed. On macOS, if Homebrew's `cargo` shadows rustup's, run with rustup's
first on `PATH`: the nested agent build needs its musl target.

Results go to `interop/target/results/<arch>/`: `report.txt`, the guest's
`console.log`, and a pcap (headers only) of each test that failed, or of
every test with `--keep-pcaps`, captured at the vclient.

### Kernels

- `lts` (default, and CI): Alpine v3.24's `linux-virt`, Linux 6.18.
- `stable`: `linux-stable` from Alpine edge (7.x, 130 MB). Linux takes
  `tcp_ecn = 3` (AccECN) only from 7.0: 6.18 has the code but caps the
  sysctl at 2, so the AccECN tests skip on `lts`.

## What is tested

Each test runs with the guest's defaults (plus Fast Open on, and buffers
sized for the fast link), and a fresh vclient.

- Correctness: 64 MiB each way (16 in `--quick`), vtcp and Linux each as
  client and as server, with half-close (the server sends after the client's
  FIN); resets both ways; refused connections both ways; 200 short
  connections each way; slirp's virtual listener and its NAT to a socket on
  the host, with Linux as the client.
- Negotiation, read from both ends (vtcp's `TcpInfo`, Linux's `TCP_INFO`):
  MSS, window scaling (the shifts cross over, windows past 64 KiB), SACK,
  timestamps, and each switched off in the guest; a guest MTU of 1280; a
  1400-byte hop answering with ICMP (Linux lowers its path MTU; vtcp's IPv4
  segments go without DF, so the hop fragments them instead), and one that
  is a black hole (PLPMTUD, both senders); classic ECN and AccECN both ways,
  with CE marks fed back and acted on; TCP Fast Open both ways (a cookie,
  then data in the SYN, taken); BBR on either side.
- Impaired links, each way with CUBIC and with BBR: 50 ms round trip; 1%
  loss each way; reordering; 50 Mbit/s with CE marking past 10 ms of queue;
  50 Mbit/s with a 100-packet drop-tail queue. These report throughput and
  what held each sender back; they fail only if a transfer does.

## Findings

What running vtcp against Linux turned up, and where Linux itself is the
odd one out:

- AccECN's ACE counter (RFC 9768 §3.2.2.5.2): vtcp took every ACK covering
  more than seven packets to have wrapped the counter as often as it could.
  Linux acknowledges each batch GRO coalesced, often 8 to 45 packets, so an
  unmarked transfer read as marked throughout (643 CE marks read where Linux
  had counted 64). vtcp now assumes the worst for the marks such an ACK would
  carry at the prevailing marking rate, as the RFC's Appendix A.2.1 suggests.
- An abort (a vclient torn down) sent a reset from TIME-WAIT, LAST-ACK and
  CLOSING, where RFC 9293 §3.10.5 sends none.
- `ConnConfig::no_window_scaling` still offered window scaling (shift 0).
- `TcpInfo` gained what the handshake agreed on (`wscale`, `sack`,
  `timestamps`, `syn_data`), keeps `min_rtt` through TIME-WAIT, and reports
  `rcv_wnd` as advertised (at most 64 KiB unscaled).
- vtcp's IPv4 segments go without DF, by design (slirp's and vclient's
  framing): a narrower hop fragments them rather than send Fragmentation
  Needed, so ICMP-driven PMTUD never runs for IPv4. Linux sets DF and
  lowers its path MTU instead. Both get the data through.
- Linux 7.1 counts AccECN's CE marks only in ESTABLISHED
  (`tcp_rcv_established`): data a Linux client receives after its own
  half-close draws no feedback.
- Linux 7.0 changed the tail of `struct tcp_info` (`tcpi_ecn_mode`,
  `tcpi_accecn_opt_seen`, `tcpi_accecn_fail_mode` became bitfields) without
  changing its size; the agent reads it by kernel version.
- With CE marking at a 1-2 ms queue (L4S-style), Linux's CUBIC without `fq`
  sends each window as a burst, draws a mark every round trip and collapses
  (4 Mbit/s of 50) where vtcp, which paces, holds 39. Not a bug either side;
  the test marks at 10 ms, as a classic AQM would.

## CI

The `interop` job in `.github/workflows/ci.yml` runs `--quick` with an
x86_64 guest under KVM on `ubuntu-latest`, caching `interop/.cache` by the
Alpine kernel version, and uploads the results directory when it fails.

# Fuzzing pktkit

The crate decodes untrusted bytes in a lot of places — IP and transport
headers, DHCP, DNS, the OpenVPN control channel, the WireGuard handshake,
fragment reassembly, and six NAT ALGs that scan application payloads. These
targets exist so that hostile input is tested deliberately rather than
incidentally.

## Running

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run all            # everything, one input at a time
cargo +nightly fuzz run nat -- -max_total_time=600
cargo +nightly fuzz list               # what else is here
```

A crash is written to `fuzz/artifacts/<target>/`; replay it with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

## What each body does

The targets are thin: every one calls into `pktkit::fuzz`, which is behind the
`fuzzing` feature and is not part of the crate's API. The bodies live there so
that `tests/robustness.rs` — which runs on stable, in ordinary CI — exercises
exactly the same code. Add a parser there and both halves pick it up.

## Sequences

Some bugs take more than one packet: a fragment that overlaps an earlier one,
a segment arriving in the state the last one left behind. Bodies that keep
state (defragmentation, both NATs, the DHCP server and client, the
L2Adapter, slirp's reassembler, and a TCP conversation between two vtcp
engines) read their input as a sequence of messages, each a 2-byte
big-endian length followed by that many bytes — see `pktkit::fuzz::messages`.
The TCP body puts the fuzzer on the wire between an honest peer and the engine
under test, so its corruptions start from segments valid for the connection.

## The contract

A body may return an error, or nonsense. It may not panic, hang, or read out of
bounds. A few bodies assert more than that where the property is worth pinning
down: a generated ICMP error must itself be a valid packet, and fragmentation
must neither lose nor invent payload bytes.

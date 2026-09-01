//! Randomized robustness sweep over every parser in the crate.
//!
//! This is the cheap, always-on half of fuzzing: it runs on stable Rust in
//! ordinary CI and hammers each decoder with mutated and random input, using
//! the same bodies as the `cargo-fuzz` targets in `fuzz/`. What it cannot do is
//! search — coverage-guided fuzzing finds the deep paths, and this catches the
//! shallow regressions that would otherwise sit until someone runs the fuzzer.
//!
//! The seed is fixed so a failure reproduces. Override it to explore:
//!
//! ```sh
//! PKTKIT_FUZZ_SEED=12345 cargo test --features "full fuzzing" --test robustness
//! ```
#![cfg(feature = "fuzzing")]

use pktkit::fuzz;

/// xorshift64*, so the sweep is reproducible without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

fn seed() -> u64 {
    std::env::var("PKTKIT_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
}

/// Well-formed messages to mutate. Starting from valid input is what gets the
/// mutations past the first length check and into the interesting code.
fn corpus() -> Vec<Vec<u8>> {
    use pktkit::build::{build_icmpv4, build_ipv4, build_ipv6, build_tcp, build_udp};
    use pktkit::{build_frame, EtherType, MacAddr, Protocol, TcpFlags};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let v4a = Ipv4Addr::new(10, 0, 0, 1);
    let v4b = Ipv4Addr::new(10, 0, 0, 2);
    let v6a: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let v6b: Ipv6Addr = "2001:db8::2".parse().unwrap();

    let mut out = Vec::new();

    // IPv4 with each transport.
    let udp = build_udp(v4a.into(), v4b.into(), 5000, 53, b"hello world");
    out.push(build_ipv4(v4a, v4b, Protocol::UDP, 64, &udp));
    let tcp = build_tcp(
        v4a.into(),
        v4b.into(),
        1234,
        21,
        1,
        2,
        TcpFlags::PSH | TcpFlags::ACK,
        65535,
        b"PORT 10,0,0,1,4,1\r\n",
    );
    out.push(build_ipv4(v4a, v4b, Protocol::TCP, 64, &tcp));
    out.push(build_ipv4(
        v4a,
        v4b,
        Protocol::ICMP,
        64,
        &build_icmpv4(8, 0, [0, 1, 0, 1], b"ping"),
    ));

    // A large datagram, so the fragmentation paths get real work.
    let big = build_udp(v4a.into(), v4b.into(), 1, 2, &vec![0xAB; 3000]);
    out.push(build_ipv4(v4a, v4b, Protocol::UDP, 64, &big));

    // IPv6, plain and with an extension chain.
    let udp6 = build_udp(IpAddr::V6(v6a), IpAddr::V6(v6b), 5000, 53, b"hello");
    out.push(build_ipv6(v6a, v6b, Protocol::UDP, 64, &udp6));
    let mut chained = vec![17u8, 0, 0, 0, 0, 0, 0, 0]; // hop-by-hop -> UDP
    chained.extend_from_slice(&udp6);
    out.push(build_ipv6(v6a, v6b, Protocol(0), 64, &chained));
    let mut fragged = vec![17u8, 0, 0, 0, 0, 0, 0, 1]; // fragment header
    fragged.extend_from_slice(&udp6);
    out.push(build_ipv6(v6a, v6b, Protocol(44), 64, &fragged));

    // Ethernet frames, tagged and not.
    let ip = out[0].clone();
    let eth = build_frame(MacAddr::broadcast(), MacAddr::zero(), EtherType::IPV4, &ip);
    out.push(pktkit::build::push_vlan(
        pktkit::Frame::from_slice(&eth),
        100,
        5,
    ));
    out.push(eth);

    // A DHCP DISCOVER and a DNS response, for those decoders.
    out.push(dhcp_discover());
    out.push(dns_response());

    // Degenerate inputs that have historically broken length arithmetic.
    out.push(Vec::new());
    out.push(vec![0x45]);
    out.push(vec![0x60; 39]);
    out.push(vec![0xFF; 64]);

    out
}

fn dhcp_discover() -> Vec<u8> {
    let mut m = vec![0u8; 240];
    m[0] = 1; // BOOTREQUEST
    m[1] = 1; // Ethernet
    m[2] = 6; // hlen
    m[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
    m[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    m[236..240].copy_from_slice(&[99, 130, 83, 99]); // magic cookie
    m.extend_from_slice(&[53, 1, 1]); // DHCP message type = DISCOVER
    m.extend_from_slice(&[55, 3, 1, 3, 6]); // parameter request list
    m.push(255); // end
    m
}

fn dns_response() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // response, no error
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&1u16.to_be_bytes()); // ancount
    m.extend_from_slice(&0u16.to_be_bytes()); // nscount
    m.extend_from_slice(&0u16.to_be_bytes()); // arcount
    m.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    m.extend_from_slice(&[0xC0, 0x0C]); // pointer back to the name
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&300u32.to_be_bytes()); // ttl
    m.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    m.extend_from_slice(&[93, 184, 216, 34]);
    m
}

/// Damage `buf` in one of the ways that tends to break a decoder.
fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    match rng.below(8) {
        // Flip a bit.
        0 => {
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] ^= 1 << rng.below(8);
            }
        }
        // Overwrite a byte with something arbitrary.
        1 => {
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] = rng.byte();
            }
        }
        // Truncate: the single most productive mutation against a parser.
        2 => {
            let n = rng.below(buf.len() + 1);
            buf.truncate(n);
        }
        // Extend with junk.
        3 => {
            let n = rng.below(64);
            for _ in 0..n {
                buf.push(rng.byte());
            }
        }
        // Scribble over a whole run.
        4 => {
            if !buf.is_empty() {
                let start = rng.below(buf.len());
                let end = (start + rng.below(16)).min(buf.len());
                for b in &mut buf[start..end] {
                    *b = rng.byte();
                }
            }
        }
        // Write an absurd length field where one usually lives.
        5 => {
            for at in [2usize, 4, 6, 12] {
                if buf.len() >= at + 2 && rng.below(2) == 0 {
                    buf[at] = 0xFF;
                    buf[at + 1] = 0xFF;
                }
            }
        }
        // Set the version nibble to something unexpected.
        6 => {
            if !buf.is_empty() {
                buf[0] = (rng.byte() & 0xF0) | (buf[0] & 0x0F);
            }
        }
        // Splice in a run of zeros.
        _ => {
            if !buf.is_empty() {
                let start = rng.below(buf.len());
                let end = (start + rng.below(24)).min(buf.len());
                for b in &mut buf[start..end] {
                    *b = 0;
                }
            }
        }
    }
}

#[test]
fn mutated_input_never_panics() {
    let seed = seed();
    let mut rng = Rng(seed);
    let corpus = corpus();

    // Enough to shake out shallow regressions while staying well inside a
    // normal test run's budget.
    for i in 0..4_000 {
        let mut buf = corpus[rng.below(corpus.len())].clone();
        // A handful of mutations at once finds things one at a time does not.
        for _ in 0..1 + rng.below(4) {
            mutate(&mut rng, &mut buf);
        }
        // Print enough on failure to reproduce the exact input.
        let guard = Guard {
            seed,
            iteration: i,
            input: &buf,
        };
        fuzz::all(&buf);
        std::mem::forget(guard);
    }
}

#[test]
fn random_input_never_panics() {
    let mut rng = Rng(seed() ^ 0xA5A5_A5A5);
    for i in 0..4_000 {
        let len = rng.below(200);
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let guard = Guard {
            seed: seed(),
            iteration: i,
            input: &buf,
        };
        fuzz::all(&buf);
        std::mem::forget(guard);
    }
}

#[test]
fn every_prefix_of_a_valid_packet_is_survivable() {
    // Truncation at every possible offset, exhaustively rather than by chance.
    for msg in corpus() {
        for n in 0..=msg.len() {
            let guard = Guard {
                seed: 0,
                iteration: n,
                input: &msg[..n],
            };
            fuzz::all(&msg[..n]);
            std::mem::forget(guard);
        }
    }
}

/// Prints the failing input if a body panics. Deliberately leaked on success
/// (`mem::forget`) so the common path costs nothing.
struct Guard<'a> {
    seed: u64,
    iteration: usize,
    input: &'a [u8],
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        eprintln!(
            "robustness failure: seed={:#x} iteration={} input={:02x?}",
            self.seed, self.iteration, self.input
        );
    }
}

//! Tests of the crate's own eBPF plumbing that need a kernel: whether the
//! verifier accepts every program the capture codegen emits, and whether the
//! trie keys we build match the way the kernel's LPM matcher does.
//!
//! The rest of the kernel-facing tests go through the public API and live in
//! `tests/xdp_kernel.rs`; these need the program builder and the raw maps,
//! which are crate-private. All are `#[ignore]`d because they need `CAP_BPF`
//! (in practice, root). Run them with:
//!
//! ```sh
//! sudo -E cargo test --features xdp --lib xdp::kernel_tests -- --ignored --test-threads=1
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::capture::{CaptureMaps, build_program};
use super::map::{Map, UpdateFlags, lpm_key};
use super::prog::Program;
use super::{Action, CaptureConfig, MAX_RULES_PER_PREFIX, MatchField};
use crate::IpPrefix;

/// True when this process can actually exercise the kernel paths.
///
/// These tests must not quietly no-op: a test that skips looks exactly like
/// a test that passed. So the only tolerated reason to skip is "not running
/// as root"; once we are root, every failure is a real failure.
fn root() -> bool {
    // The effective uid is the second field of the `Uid:` line.
    let euid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|ids| ids.split_whitespace().nth(1).map(str::to_owned))
        });
    if euid.as_deref() == Some("0") {
        return true;
    }
    eprintln!("SKIP: needs root; re-run with sudo -E cargo test ... -- --ignored");
    false
}

fn v4(a: [u8; 4], bits: u8) -> IpPrefix {
    IpPrefix::new(Ipv4Addr::from(a).into(), bits)
}

// --- verifier ---------------------------------------------------------------

/// The one thing no unit test can answer: does the kernel accept what we
/// generate? Every configuration produces a different instruction stream, so
/// every configuration has to be loaded.
#[test]
#[ignore = "needs CAP_BPF"]
fn every_capture_configuration_passes_the_verifier() {
    if !root() {
        return;
    }
    for match_field in [MatchField::Dst, MatchField::Src, MatchField::Either] {
        for arp in [true, false] {
            for default_action in [Action::PASS, Action::DROP] {
                // The rule walk is unrolled per slot, so the widest list is
                // the one most likely to trip an instruction or complexity
                // limit; the narrowest exercises the degenerate loop.
                for max_rules_per_prefix in [1, 8, MAX_RULES_PER_PREFIX] {
                    let cfg = CaptureConfig::default()
                        .match_field(match_field)
                        .arp(arp)
                        .default_action(default_action)
                        .max_rules_per_prefix(max_rules_per_prefix);
                    let maps = CaptureMaps::create(&cfg).expect("create maps");
                    let insns = build_program(&cfg, &maps).expect("codegen");
                    Program::load(&insns, "pktkit_test").unwrap_or_else(|e| {
                        panic!(
                            "verifier rejected {match_field:?} arp={arp} \
                             rules={max_rules_per_prefix}: {e}"
                        )
                    });
                }
            }
        }
    }
}

// --- maps -------------------------------------------------------------------

/// Proves the `bpf_lpm_trie_key` layout against the kernel's own matcher: a
/// prefix entry has to match every address inside it and nothing outside.
#[test]
#[ignore = "needs CAP_BPF"]
fn lpm_trie_matches_by_longest_prefix() {
    if !root() {
        return;
    }
    let map = Map::lpm_trie(4, 4, 64).expect("create trie");
    let one = 1u32.to_ne_bytes();
    let two = 2u32.to_ne_bytes();

    map.update(
        lpm_key(v4([10, 0, 0, 0], 8)).as_bytes(),
        &one,
        UpdateFlags::ANY,
    )
    .unwrap();
    map.update(
        lpm_key(v4([10, 1, 2, 0], 24)).as_bytes(),
        &two,
        UpdateFlags::ANY,
    )
    .unwrap();

    let lookup = |a: [u8; 4]| -> Option<u32> {
        let mut out = [0u8; 4];
        map.lookup(lpm_key(v4(a, 32)).as_bytes(), &mut out)
            .unwrap()
            .then(|| u32::from_ne_bytes(out))
    };

    // Inside the /8 only.
    assert_eq!(lookup([10, 5, 5, 5]), Some(1));
    // Inside both: the longer prefix wins.
    assert_eq!(lookup([10, 1, 2, 9]), Some(2));
    // Outside everything.
    assert_eq!(lookup([192, 0, 2, 1]), None);

    // Removing the /24 falls back to the /8 rather than to nothing.
    assert!(
        map.delete(lpm_key(v4([10, 1, 2, 0], 24)).as_bytes())
            .unwrap()
    );
    assert_eq!(lookup([10, 1, 2, 9]), Some(1));
}

#[test]
#[ignore = "needs CAP_BPF"]
fn ipv6_prefixes_round_trip_through_the_trie() {
    if !root() {
        return;
    }
    let map = Map::lpm_trie(16, 4, 64).expect("create trie");
    let net: Ipv6Addr = "2001:db8:1::".parse().unwrap();
    map.update(
        lpm_key(IpPrefix::new(net.into(), 48)).as_bytes(),
        &1u32.to_ne_bytes(),
        UpdateFlags::ANY,
    )
    .unwrap();

    let hit: Ipv6Addr = "2001:db8:1::dead".parse().unwrap();
    let miss: Ipv6Addr = "2001:db8:2::dead".parse().unwrap();
    let mut out = [0u8; 4];
    assert!(
        map.lookup(lpm_key(IpPrefix::new(hit.into(), 128)).as_bytes(), &mut out)
            .unwrap()
    );
    assert!(
        !map.lookup(
            lpm_key(IpPrefix::new(miss.into(), 128)).as_bytes(),
            &mut out
        )
        .unwrap()
    );
}

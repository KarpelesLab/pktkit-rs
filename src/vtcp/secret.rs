//! Keyed hashing for the values an off-path attacker must not predict:
//! initial sequence numbers (RFC 6528) and SYN cookies (RFC 4987).
//!
//! vtcp has no dependencies, so it has no CSPRNG and no MAC of its own. std
//! does carry a keyed PRF, though: [`RandomState`] is SipHash under a 128-bit
//! key drawn from the OS's entropy source. That is what Linux uses for the
//! same two jobs (`secure_tcp_seq`, `cookie_v4_hash`), and a single
//! process-wide key serves both, as it does there.
//!
//! On `wasm32-unknown-unknown` std has no entropy source and keys
//! `RandomState` from allocation addresses, which an attacker can guess. The
//! wall clock at first use is mixed in there, which is the best the target
//! offers without an import of its own; an embedder facing hostile peers on
//! that target should not rely on ISN or cookie secrecy.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::sync::OnceLock;

use crate::time::Instant;

struct Key {
    state: RandomState,
    salt: u128,
    /// Origin of the RFC 6528 clock.
    epoch: Instant,
}

fn key() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(|| Key {
        state: RandomState::new(),
        salt: if cfg!(all(target_family = "wasm", target_os = "unknown")) {
            crate::time::unix_now().as_nanos()
        } else {
            0
        },
        epoch: Instant::now(),
    })
}

/// SipHash of `v` under the process-wide secret key.
pub(crate) fn keyed_hash<T: Hash>(v: T) -> u64 {
    let k = key();
    k.state.hash_one((k.salt, v))
}

/// An initial sequence number per RFC 6528 §3: `M + F(localip, localport,
/// remoteip, remoteport, secretkey)`, where M ticks every 4 µs. F keeps
/// another connection's ISN from revealing this one's; M keeps a new
/// incarnation of the same 4-tuple from starting inside the old one's
/// sequence space.
pub(crate) fn isn(local: Option<IpAddr>, lport: u16, remote: Option<IpAddr>, rport: u16) -> u32 {
    let m = (key().epoch.elapsed().as_micros() / 4) as u32;
    let f = keyed_hash(("isn", local, lport, remote, rport)) as u32;
    m.wrapping_add(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const A: Option<IpAddr> = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    const B: Option<IpAddr> = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

    #[test]
    fn isn_advances_with_the_clock_for_one_four_tuple() {
        let first = isn(A, 1000, B, 80);
        let second = isn(A, 1000, B, 80);
        // Only M moved: a few 4 µs ticks at most, never backwards.
        assert!(second.wrapping_sub(first) < 1 << 20, "{first} {second}");
    }

    #[test]
    fn isn_differs_across_four_tuples() {
        let base = isn(A, 1000, B, 80);
        for other in [
            isn(A, 1001, B, 80),
            isn(B, 1000, A, 80),
            isn(A, 1000, B, 81),
        ] {
            assert_ne!(base, other);
        }
    }
}

//! Time helpers used by the WireGuard handshake.
//!
//! WireGuard timestamps are TAI64N (12 bytes): an 8-byte unsigned big-endian
//! second count offset by the magic constant `4611686018427387914`, followed
//! by a 4-byte big-endian nanosecond field.

use crate::wg::constants::{INITIATIONS_PER_SECOND, TAI64N_TIMESTAMP_SIZE};

// The TAI64 base offset (2^62 + leap seconds at 1970-01-01). Matches the value
// used by `cr.yp.to/libtai`, which the WireGuard reference also uses.
const TAI64N_BASE: u64 = 4_611_686_018_427_387_914;

/// The granularity of the nanoseconds in our timestamps: the largest power
/// of two no longer than the gap a responder allows between two
/// initiations, as in the reference (2^24 ns, about 16.8 ms).
const TIMESTAMP_GRANULARITY_NS: u32 = {
    let gap = 1_000_000_000 / INITIATIONS_PER_SECOND;
    1 << (31 - gap.leading_zeros())
};

/// Return the current wall time as a TAI64N-encoded 12-byte buffer.
///
/// The nanoseconds are rounded down to [`TIMESTAMP_GRANULARITY_NS`], as the
/// reference does: the timestamp travels encrypted, but whoever can read it
/// (the peer, or anyone once the static keys leak) would otherwise learn
/// the sender's clock to the nanosecond, a fingerprint of the host. The
/// coarser value costs nothing, as a responder refuses a second initiation
/// that soon anyway.
///
/// The current time is read from the system clock. If the
/// system clock is before the Unix epoch (unusual but possible), seconds are
/// clamped to 0 — handshakes from such hosts will fail the monotonicity check
/// at the peer, which is the right behaviour.
pub(crate) fn tai64n_now() -> [u8; TAI64N_TIMESTAMP_SIZE] {
    let dur = crate::time::unix_now();
    encode_tai64n(dur.as_secs(), whiten(dur.subsec_nanos()))
}

#[inline]
fn whiten(nanos: u32) -> u32 {
    nanos & !(TIMESTAMP_GRANULARITY_NS - 1)
}

#[inline]
pub(crate) fn encode_tai64n(unix_secs: u64, nanos: u32) -> [u8; TAI64N_TIMESTAMP_SIZE] {
    let mut out = [0u8; TAI64N_TIMESTAMP_SIZE];
    let tai_secs = unix_secs.wrapping_add(TAI64N_BASE);
    out[0..8].copy_from_slice(&tai_secs.to_be_bytes());
    out[8..12].copy_from_slice(&nanos.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tai64n_offset_applied() {
        // Unix 0 should encode to the base constant.
        let ts = encode_tai64n(0, 0);
        let secs = u64::from_be_bytes(ts[0..8].try_into().unwrap());
        assert_eq!(secs, TAI64N_BASE);

        // Nanos field is independent of seconds.
        let ts = encode_tai64n(0, 123_456_789);
        assert_eq!(
            u32::from_be_bytes(ts[8..12].try_into().unwrap()),
            123_456_789
        );
    }

    #[test]
    fn timestamps_are_whitened_to_2_pow_24_ns() {
        assert_eq!(TIMESTAMP_GRANULARITY_NS, 1 << 24);
        assert_eq!(whiten(0), 0);
        assert_eq!(whiten((1 << 24) - 1), 0);
        assert_eq!(whiten(999_999_999), 59 << 24);
        let ts = tai64n_now();
        let nanos = u32::from_be_bytes(ts[8..12].try_into().unwrap());
        assert_eq!(nanos % (1 << 24), 0, "{nanos} ns leaks the clock");
    }

    #[test]
    fn tai64n_now_monotonic_within_clock_resolution() {
        // Two consecutive reads must produce a non-decreasing timestamp by
        // lexicographic comparison.
        let a = tai64n_now();
        let b = tai64n_now();
        assert!(b >= a, "tai64n_now() went backwards: {:?} -> {:?}", a, b);
    }
}

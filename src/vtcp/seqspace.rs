//! TCP sequence number arithmetic (RFC 793 §3.3).
//!
//! TCP sequence numbers are 32-bit unsigned integers that wrap around.
//! Comparisons use signed 32-bit subtraction so that wrap is transparent
//! as long as the two values are within 2^31 of each other.

/// True iff `a` is strictly before `b` in sequence space.
#[inline]
pub fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// True iff `a` is strictly after `b` in sequence space.
#[inline]
pub fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// True iff `a` is before or equal to `b`.
#[inline]
pub fn seq_before_eq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// True iff `a` is after or equal to `b`.
#[inline]
pub fn seq_after_eq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// True iff `seq` lies in the half-open interval `[lo, hi)`.
#[inline]
pub fn seq_in_range(seq: u32, lo: u32, hi: u32) -> bool {
    seq_after_eq(seq, lo) && seq_before(seq, hi)
}

/// True iff `seq` lies in the closed interval `[lo, hi]`.
#[inline]
pub fn seq_in_range_inclusive(seq: u32, lo: u32, hi: u32) -> bool {
    seq_after_eq(seq, lo) && seq_before_eq(seq, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ordering() {
        assert!(seq_before(1, 2));
        assert!(!seq_before(2, 1));
        assert!(seq_after(2, 1));
        assert!(!seq_after(1, 2));
        assert!(seq_before_eq(1, 1));
        assert!(seq_after_eq(1, 1));
    }

    #[test]
    fn wraparound() {
        // 0xFFFFFFFE is "before" 1 because the gap is just 3 modulo 2^32.
        assert!(seq_before(0xFFFFFFFE, 1));
        assert!(seq_after(1, 0xFFFFFFFE));
        assert!(seq_in_range(0xFFFFFFFF, 0xFFFFFFFE, 2));
        assert!(seq_in_range(0, 0xFFFFFFFE, 2));
        assert!(!seq_in_range(2, 0xFFFFFFFE, 2));
        assert!(seq_in_range_inclusive(2, 0xFFFFFFFE, 2));
    }
}

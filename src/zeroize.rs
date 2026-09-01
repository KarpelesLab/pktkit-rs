//! Wiping secrets out of memory.
//!
//! Key material lives in stack buffers all over the handshake code, and a plain
//! `buf.fill(0)` on a value that is never read again is exactly the kind of
//! store an optimiser is entitled to delete. A volatile write is not, and the
//! fence stops the compiler from moving other accesses across it.
//!
//! This is the one piece of security-relevant code the crate implements itself
//! rather than taking from `purecrypto`: it is a memory-hygiene utility, not a
//! cryptographic primitive, and `purecrypto` keeps its own copy private.

use std::sync::atomic::{Ordering, compiler_fence};

/// Overwrite `buf` with zeros in a way the optimiser may not elide.
#[inline]
pub(crate) fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` comes from a live mutable slice, so it is valid, aligned
        // and writable for one byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes_every_byte() {
        let mut buf = [0xAAu8; 64];
        zeroize(&mut buf);
        assert_eq!(buf, [0u8; 64]);
    }

    #[test]
    fn empty_slice_is_fine() {
        zeroize(&mut []);
    }

    #[test]
    fn wipes_a_subslice_only() {
        let mut buf = [0xFFu8; 8];
        zeroize(&mut buf[2..5]);
        assert_eq!(buf, [0xFF, 0xFF, 0, 0, 0, 0xFF, 0xFF, 0xFF]);
    }
}

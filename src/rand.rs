//! Tiny non-cryptographic RNG, used for DHCP transaction IDs and randomised
//! MAC addresses. Security-sensitive code lives in feature modules and uses
//! audited crates (`rand_core` + `getrandom`).
//!
//! The state is a per-thread xorshift64 seeded from the system clock and a
//! process-global counter, mixed with the thread ID. That is sufficient for
//! "should not collide" use cases like xids and stub MACs; it is not
//! suitable for cryptography.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static GLOBAL: AtomicU64 = AtomicU64::new(0x12345678abcdef01);

thread_local! {
    static STATE: Cell<u64> = const { Cell::new(0) };
}

#[inline]
fn seed_now() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let counter = GLOBAL.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
    let tid = std::thread::current().id();
    let tid_hash = {
        // ThreadId has no public stable identifier; format it.
        let s = format!("{:?}", tid);
        let mut h: u64 = 0xcbf29ce484222325;
        for b in s.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    };
    let mix = nanos ^ counter ^ tid_hash;
    if mix == 0 { 0x9E3779B97F4A7C15 } else { mix }
}

#[inline]
fn next() -> u64 {
    STATE.with(|s| {
        let mut x = s.get();
        if x == 0 {
            x = seed_now();
        }
        // xorshift64*
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x
    })
}

/// Return a `u32` of non-crypto random bits.
pub fn u32() -> u32 {
    next() as u32
}

/// Return a `u64` of non-crypto random bits.
#[allow(dead_code)]
pub fn u64() -> u64 {
    next()
}

/// Fill `buf` with non-crypto random bytes.
pub fn fill(buf: &mut [u8]) {
    let mut i = 0;
    while i + 8 <= buf.len() {
        let v = next().to_le_bytes();
        buf[i..i + 8].copy_from_slice(&v);
        i += 8;
    }
    if i < buf.len() {
        let v = next().to_le_bytes();
        let rem = buf.len() - i;
        buf[i..].copy_from_slice(&v[..rem]);
    }
}

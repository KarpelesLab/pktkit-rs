//! Tiny non-cryptographic RNG, for jitter and randomised MAC addresses.
//! Anything security-sensitive draws from `purecrypto`'s `OsRng` instead, in
//! the features that depend on it, or from [`unpredictable_u64`] in those
//! that do not.
//!
//! The state is a per-thread xorshift64* seeded from the system clock and a
//! process-global counter, mixed with the thread ID. That is sufficient for
//! "should not collide" uses; it is not suitable for anything an attacker
//! must not guess. The seed is guessable, and even the multiplied output
//! gives the state away to anyone who sees a few values.

use std::cell::Cell;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static GLOBAL: AtomicU64 = AtomicU64::new(0x12345678abcdef01);

thread_local! {
    static STATE: Cell<u64> = const { Cell::new(0) };
}

#[inline]
fn seed_now() -> u64 {
    let nanos = crate::time::unix_now().as_nanos() as u64;
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
        // xorshift64* (Vigna, "An experimental exploration of Marsaglia's
        // xorshift generators, scrambled", 2016): Marsaglia's xorshift
        // step, then the multiply that scrambles its output. Without the
        // multiply each output is the state itself, linear in the one
        // before.
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    })
}

/// Return a `u32` of non-crypto random bits: the high half of the output,
/// the better-mixed one for this generator.
/// Unused under some feature sets.
#[allow(dead_code)]
pub fn u32() -> u32 {
    (next() >> 32) as u32
}

/// 64 bits an off-path attacker cannot predict, for values such as
/// transaction IDs and query-name case that stand between a forger and
/// the conversation: SipHash, under a key std draws from the OS's entropy
/// source for [`RandomState`], of a counter.
///
/// This is the construction vtcp uses for its ISNs, for the same reason:
/// the crate has no CSPRNG without `purecrypto`. On
/// `wasm32-unknown-unknown` std has no entropy source and keys
/// `RandomState` from allocation addresses; the wall clock at first use is
/// mixed in there, which is the best the target offers.
#[allow(dead_code)]
pub(crate) fn unpredictable_u64() -> u64 {
    static KEY: OnceLock<(RandomState, u128)> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let (state, salt) = KEY.get_or_init(|| {
        let salt = if cfg!(all(target_family = "wasm", target_os = "unknown")) {
            crate::time::unix_now().as_nanos()
        } else {
            0
        };
        (RandomState::new(), salt)
    });
    state.hash_one((*salt, COUNTER.fetch_add(1, Ordering::Relaxed)))
}

/// [`unpredictable_u64`], cut to 32 bits.
#[allow(dead_code)]
pub(crate) fn unpredictable_u32() -> u32 {
    unpredictable_u64() as u32
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

#[cfg(test)]
mod tests {
    /// The xorshift step alone, as the generator used to output it.
    fn step(mut x: u64) -> u64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }

    #[test]
    fn output_is_not_the_linear_state() {
        // With the state as the output, one u32 gives the low half of the
        // state, and each later u32 is a linear function (over GF(2)) of
        // the 32 unknown bits: a few outputs pin down the state and so
        // every value to come. Solve for those bits as though the output
        // were still the raw state; the prediction must now miss.
        let obs: Vec<u32> = (0..10).map(|_| super::u32()).collect();
        let stepn = |x: u64, n: usize| (0..n).fold(x, |x, _| step(x));
        let a = u64::from(obs[0]);
        let mut rows: Vec<(u32, u32)> = Vec::new();
        for (k, &o) in obs.iter().enumerate().take(9).skip(1) {
            let base = stepn(a, k) as u32;
            let cols: Vec<u32> = (0..32).map(|i| stepn(1u64 << (32 + i), k) as u32).collect();
            for bit in 0..32 {
                let m = (0..32).fold(0u32, |m, i| m | ((cols[i] >> bit) & 1) << i);
                rows.push((m, ((o ^ base) >> bit) & 1));
            }
        }
        let mut pivot = [usize::MAX; 32];
        let mut r = 0;
        for (col, piv) in pivot.iter_mut().enumerate() {
            if let Some(p) = (r..rows.len()).find(|&k| (rows[k].0 >> col) & 1 == 1) {
                rows.swap(r, p);
                for k in 0..rows.len() {
                    if k != r && (rows[k].0 >> col) & 1 == 1 {
                        rows[k].0 ^= rows[r].0;
                        rows[k].1 ^= rows[r].1;
                    }
                }
                *piv = r;
                r += 1;
            }
        }
        let high = (0..32)
            .filter(|&c| pivot[c] != usize::MAX && rows[pivot[c]].1 == 1)
            .fold(0u32, |h, c| h | 1 << c);
        let predicted = stepn(a | u64::from(high) << 32, 9) as u32;
        assert_ne!(predicted, obs[9], "the next output was predicted");
    }

    #[test]
    fn unpredictable_values_do_not_repeat() {
        let v: std::collections::HashSet<u64> =
            (0..1000).map(|_| super::unpredictable_u64()).collect();
        assert_eq!(v.len(), 1000);
    }
}

//! Which outside ports are taken, kept up to date by the tables that take
//! them, so that finding a free one, or learning there is none, does not
//! mean walking the pool.
//!
//! A port is taken while anything holds it, for any protocol: a mapping
//! (through its reverse-table entry), a port forward, or an expectation.
//! Each holder counts itself in on insertion and out on removal, through
//! [`PortMap`] and the NAT's forward and expectation tables.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

const PORTS: usize = 1 << 16;
const WORDS: usize = PORTS / 64;
/// Every other bit, from bit 0: the even ports of a word.
const EVEN: u64 = 0x5555_5555_5555_5555;

/// How many holders each outside port has, with a bitmap of the free ones
/// and a count of those free in the dynamic pool by parity.
///
/// Shared by the tables of one NAT, which only change it under that NAT's
/// lock; the atomics just make it shareable, and are all relaxed.
pub(crate) struct PortUse {
    holders: Box<[AtomicU16]>,
    /// Bit set: the port is free.
    free_bits: Box<[AtomicU64]>,
    /// Free ports in the dynamic pool, `[even, odd]`.
    free: [AtomicU32; 2],
    /// The dynamic pool, inclusive.
    pool: (u16, u16),
}

impl std::fmt::Debug for PortUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortUse")
            .field("pool", &self.pool)
            .field("free", &self.free)
            .finish_non_exhaustive()
    }
}

impl PortUse {
    /// All ports free, with `lo..=hi` the dynamic pool.
    pub(crate) fn new(lo: u16, hi: u16) -> Arc<PortUse> {
        let evens = (u32::from(hi) / 2 + 1) - u32::from(lo).div_ceil(2);
        let total = u32::from(hi - lo) + 1;
        Arc::new(PortUse {
            holders: (0..PORTS).map(|_| AtomicU16::new(0)).collect(),
            free_bits: (0..WORDS).map(|_| AtomicU64::new(u64::MAX)).collect(),
            free: [AtomicU32::new(evens), AtomicU32::new(total - evens)],
            pool: (lo, hi),
        })
    }

    fn in_pool(&self, p: u16) -> bool {
        (self.pool.0..=self.pool.1).contains(&p)
    }

    pub(crate) fn acquire(&self, p: u16) {
        if self.holders[usize::from(p)].fetch_add(1, Ordering::Relaxed) == 0 {
            let w = usize::from(p) / 64;
            self.free_bits[w].fetch_and(!(1 << (p % 64)), Ordering::Relaxed);
            if self.in_pool(p) {
                self.free[usize::from(p & 1)].fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn release(&self, p: u16) {
        if self.holders[usize::from(p)].fetch_sub(1, Ordering::Relaxed) == 1 {
            let w = usize::from(p) / 64;
            self.free_bits[w].fetch_or(1 << (p % 64), Ordering::Relaxed);
            if self.in_pool(p) {
                self.free[usize::from(p & 1)].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    pub(crate) fn is_free(&self, p: u16) -> bool {
        self.holders[usize::from(p)].load(Ordering::Relaxed) == 0
    }

    /// Free ports left in the dynamic pool, of parity `odd` if given.
    pub(crate) fn pool_free(&self, odd: Option<bool>) -> u32 {
        let n = |i: usize| self.free[i].load(Ordering::Relaxed);
        match odd {
            Some(odd) => n(usize::from(odd)),
            None => n(0) + n(1),
        }
    }

    /// The free ports among `word`'s 64 that lie in `lo..=hi`, as bits.
    /// `word` must overlap the range.
    fn free_word(&self, word: usize, (lo, hi): (u16, u16)) -> u64 {
        let base = word * 64;
        let lo = usize::from(lo).saturating_sub(base);
        let hi = (usize::from(hi) - base).min(63);
        self.free_bits[word].load(Ordering::Relaxed) & (u64::MAX << lo) & (u64::MAX >> (63 - hi))
    }

    /// The first port at or after `from` in `lo..=hi` (wrapping to `lo`)
    /// that `pick` finds in a word of free-port bits, or `None`. Takes at
    /// most one pass over the range's words.
    fn search(&self, (lo, hi): (u16, u16), from: u16, pick: impl Fn(u64) -> u64) -> Option<u16> {
        if lo > hi {
            return None;
        }
        let from = from.clamp(lo, hi);
        let found = |range: (u16, u16)| {
            let (first, last) = (usize::from(range.0) / 64, usize::from(range.1) / 64);
            (first..=last).find_map(|w| {
                let bits = pick(self.free_word(w, range));
                (bits != 0).then(|| (w * 64 + bits.trailing_zeros() as usize) as u16)
            })
        };
        // The second pass ends at `from`, not before it: a pair starting
        // just below it needs `from` itself.
        found((from, hi)).or_else(|| (from > lo).then(|| found((lo, from))).flatten())
    }

    /// A free port in `lo..=hi`, searching from `from`, of parity `odd`
    /// if given.
    pub(crate) fn find(&self, range: (u16, u16), from: u16, odd: Option<bool>) -> Option<u16> {
        let mask = match odd {
            None => u64::MAX,
            Some(false) => EVEN,
            Some(true) => EVEN << 1,
        };
        self.search(range, from, |bits| bits & mask)
    }

    /// The outside port for a new mapping of inside source port (or ICMP
    /// identifier) `want`, searching the dynamic pool from `from`; `None`
    /// if nothing fits.
    ///
    /// `want` itself if it is free and in the pool: the host chose it, and
    /// applications that predict their public port from their local one
    /// keep working. Anything else maps into the pool, with the same parity
    /// if one is free (RFC 4787 REQ-4), since peers take RTP on an even
    /// port and RTCP on the odd one above it.
    ///
    /// Ports below the pool are never preserved, nor mapped into the
    /// privileged range as RFC 4787 REQ-3 recommends: a host sending from
    /// 53, 123 or 5060 would take that port on the public address, and the
    /// forward an administrator then adds for it would fail; one host
    /// sending from each of 1-1023 would take them all. Those ports are
    /// left to port forwards.
    pub(crate) fn choose(&self, want: u16, from: u16) -> Option<u16> {
        if self.in_pool(want) && self.is_free(want) {
            return Some(want);
        }
        let odd = Some(want & 1 == 1);
        // The counts answer for a full pool without a search.
        if self.pool_free(odd) > 0 {
            return self.find(self.pool, from, odd);
        }
        if self.pool_free(None) > 0 {
            return self.find(self.pool, from, None);
        }
        None
    }

    /// An even port in `lo..=hi` that is free along with the next one,
    /// searching from `from`. Pairs start at even ports, so never straddle
    /// words.
    pub(crate) fn find_pair(&self, range: (u16, u16), from: u16) -> Option<u16> {
        self.search(range, from, |bits| bits & (bits >> 1) & EVEN)
    }
}

/// A table keyed by outside port whose entries hold their port in a
/// [`PortUse`].
#[derive(Debug)]
pub(crate) struct PortMap<R, K> {
    map: HashMap<R, K>,
    ports: Arc<PortUse>,
}

/// A key naming an outside port.
pub(crate) trait PortKey: Copy + Eq + Hash {
    fn port(&self) -> u16;
}

impl<R: PortKey, K> PortMap<R, K> {
    pub(crate) fn new(ports: Arc<PortUse>) -> Self {
        PortMap {
            map: HashMap::new(),
            ports,
        }
    }

    #[inline]
    pub(crate) fn get(&self, rk: &R) -> Option<&K> {
        self.map.get(rk)
    }

    #[inline]
    pub(crate) fn contains_key(&self, rk: &R) -> bool {
        self.map.contains_key(rk)
    }

    pub(crate) fn insert(&mut self, rk: R, k: K) -> Option<K> {
        let old = self.map.insert(rk, k);
        if old.is_none() {
            self.ports.acquire(rk.port());
        }
        old
    }

    pub(crate) fn remove(&mut self, rk: &R) -> Option<K> {
        let old = self.map.remove(rk);
        if old.is_some() {
            self.ports.release(rk.port());
        }
        old
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&R, &mut K) -> bool) {
        let ports = &self.ports;
        self.map.retain(|rk, k| {
            let kept = keep(rk, k);
            if !kept {
                ports.release(rk.port());
            }
            kept
        });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut K> {
        self.map.values_mut()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&R, &K)> {
        self.map.iter()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &K> {
        self.map.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_follow_holders() {
        let u = PortUse::new(10000, 65535);
        let total = u.pool_free(None);
        assert_eq!(total, 55536);
        assert_eq!(u.pool_free(Some(false)), 27768);
        u.acquire(10000);
        u.acquire(10000);
        u.acquire(80);
        assert_eq!(u.pool_free(None), total - 1);
        assert_eq!(u.pool_free(Some(false)), 27767);
        u.release(10000);
        assert!(!u.is_free(10000));
        u.release(10000);
        assert!(u.is_free(10000));
        assert_eq!(u.pool_free(None), total);
        assert!(!u.is_free(80));
    }

    #[test]
    fn find_respects_range_parity_and_wraps() {
        let u = PortUse::new(10000, 65535);
        assert_eq!(u.find((10000, 65535), 10000, None), Some(10000));
        assert_eq!(u.find((10000, 65535), 10000, Some(true)), Some(10001));
        assert_eq!(u.find((10000, 65535), 65535, None), Some(65535));
        u.acquire(65535);
        assert_eq!(u.find((10000, 65535), 65535, None), Some(10000));
        assert_eq!(u.find((600, 1023), 0, Some(false)), Some(600));
        assert_eq!(u.find((5, 5), 0, None), Some(5));
        u.acquire(5);
        assert_eq!(u.find((5, 5), 5, None), None);
        for p in 10000..=65534 {
            u.acquire(p);
        }
        assert_eq!(u.find((10000, 65535), 30000, None), None);
        u.release(12345);
        assert_eq!(u.find((10000, 65535), 30000, Some(false)), None);
        assert_eq!(u.find((10000, 65535), 30000, Some(true)), Some(12345));
    }

    #[test]
    fn choose_preserves_pool_ports_then_parity() {
        let u = PortUse::new(10000, 65535);
        assert_eq!(u.choose(40001, 10000), Some(40001));
        u.acquire(40001);
        assert_eq!(u.choose(40001, 10000), Some(10001), "odd, from the pool");
        // Below the pool: into it, parity kept, even when free.
        assert_eq!(u.choose(5060, 10000), Some(10000), "even, from the pool");
        assert_eq!(u.choose(123, 10000), Some(10001), "odd, from the pool");
        assert_eq!(u.choose(0, 10000), Some(10000));
        // No port of its parity left: any will do.
        for p in (10001..=65535).step_by(2) {
            u.acquire(p);
        }
        assert_eq!(u.choose(40001, 20000), Some(20000));
        for p in (10000..=65534).step_by(2) {
            u.acquire(p);
        }
        assert_eq!(u.choose(40001, 20000), None);
    }

    #[test]
    fn find_pair_wants_both_free() {
        let u = PortUse::new(10000, 65535);
        assert_eq!(u.find_pair((10000, 65535), 10000), Some(10000));
        u.acquire(10001);
        assert_eq!(u.find_pair((10000, 65535), 10000), Some(10002));
        assert_eq!(u.find_pair((10000, 65535), 65534), Some(65534));
        // Past the last pair it wraps around.
        assert_eq!(u.find_pair((10000, 65535), 65535), Some(10002));
        u.acquire(65535);
        assert_eq!(u.find_pair((10000, 65535), 65534), Some(10002));
        // A pair across a word boundary is still two even-started ports.
        assert_eq!(u.find_pair((10000, 65535), 10047), Some(10048));
    }
}

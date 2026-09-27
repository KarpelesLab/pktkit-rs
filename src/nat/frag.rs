//! Tracking fragmented datagrams for translation one fragment at a time.
//!
//! Only a datagram's first fragment carries the transport header, so only it
//! can be matched to a mapping. The translation found for it is remembered
//! here, keyed by what the fragments share (addresses, IP ID, protocol), and
//! applied to the others. Fragments that overtake their first one are held
//! until it arrives; RFC 6146 §3.4 and RFC 4787 REQ-14 require out-of-order
//! fragments to work, within bounded resources.

use crate::time::Instant;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

/// How long a datagram's fragments may keep arriving. RFC 6146 §3.4 asks for
/// at least 2 seconds (FRAGMENT_MIN).
pub(crate) const FRAG_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on datagrams tracked at once.
const MAX_DATAGRAMS: usize = 256;
/// Cap on bytes held waiting for a first fragment, across all datagrams.
const MAX_HELD_BYTES: usize = 256 * 1024;

#[derive(Debug)]
struct Entry<T> {
    target: Option<T>,
    held: Vec<Vec<u8>>,
    created: Instant,
}

#[derive(Debug)]
pub(crate) struct FragTable<K, T> {
    map: HashMap<K, Entry<T>>,
    held_bytes: usize,
}

impl<K, T> Default for FragTable<K, T> {
    fn default() -> Self {
        FragTable {
            map: HashMap::new(),
            held_bytes: 0,
        }
    }
}

impl<K: Hash + Eq + Copy, T: Copy> FragTable<K, T> {
    /// The first fragment of datagram `key` translated to `target`. Returns
    /// the fragments that were held waiting for it, to be translated now.
    pub(crate) fn resolve(&mut self, key: K, target: T, now: Instant) -> Vec<Vec<u8>> {
        self.expire(now);
        if let Some(e) = self.map.get_mut(&key) {
            e.target = Some(target);
            let held = std::mem::take(&mut e.held);
            self.held_bytes -= held.iter().map(Vec::len).sum::<usize>();
            return held;
        }
        if self.map.len() < MAX_DATAGRAMS {
            self.map.insert(
                key,
                Entry {
                    target: Some(target),
                    held: Vec::new(),
                    created: now,
                },
            );
        }
        Vec::new()
    }

    /// A later fragment of datagram `key`: its translation if the first
    /// fragment has been seen. Otherwise the fragment is held (space
    /// permitting) and `None` returned.
    pub(crate) fn later(&mut self, key: K, frag: &[u8], now: Instant) -> Option<T> {
        self.expire(now);
        if let Some(t) = self.map.get(&key).and_then(|e| e.target) {
            return Some(t);
        }
        if self.held_bytes + frag.len() > MAX_HELD_BYTES
            || (!self.map.contains_key(&key) && self.map.len() >= MAX_DATAGRAMS)
        {
            return None;
        }
        self.map
            .entry(key)
            .or_insert_with(|| Entry {
                target: None,
                held: Vec::new(),
                created: now,
            })
            .held
            .push(frag.to_vec());
        self.held_bytes += frag.len();
        None
    }

    /// Forget datagrams whose fragments have had their time.
    pub(crate) fn expire(&mut self, now: Instant) {
        let held = &mut self.held_bytes;
        self.map.retain(|_, e| {
            let keep = now.saturating_duration_since(e.created) <= FRAG_TIMEOUT;
            if !keep {
                *held -= e.held.iter().map(Vec::len).sum::<usize>();
            }
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_fragments_follow_the_first() {
        let now = Instant::now();
        let mut t = FragTable::<u32, u8>::default();
        assert!(t.resolve(1, 7, now).is_empty());
        assert_eq!(t.later(1, b"x", now), Some(7));
    }

    #[test]
    fn early_fragments_wait_for_the_first() {
        let now = Instant::now();
        let mut t = FragTable::<u32, u8>::default();
        assert_eq!(t.later(1, b"early", now), None);
        assert_eq!(t.resolve(1, 7, now), vec![b"early".to_vec()]);
        assert_eq!(t.held_bytes, 0);
    }

    #[test]
    fn held_fragments_are_bounded_and_expire() {
        let now = Instant::now();
        let mut t = FragTable::<u32, u8>::default();
        let big = vec![0u8; 60_000];
        for i in 0..10 {
            t.later(i, &big, now);
        }
        assert!(t.held_bytes <= MAX_HELD_BYTES);
        t.expire(now + FRAG_TIMEOUT + Duration::from_secs(1));
        assert_eq!(t.held_bytes, 0);
        assert!(t.map.is_empty());
    }
}

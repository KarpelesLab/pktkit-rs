//! Flow tables that know how many entries each namespace holds, so the
//! stack can cap a namespace's share of a table without scanning it on every
//! new flow.

use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;

/// A table key that belongs to a namespace.
pub(crate) trait NsKey: Copy + Eq + Hash {
    fn ns(&self) -> u64;
}

/// A `HashMap` that counts its entries per namespace. Reads go through
/// `Deref`; every change goes through the methods here, which keep the
/// counts in step.
pub(crate) struct NsTable<K, V> {
    map: HashMap<K, V>,
    per_ns: HashMap<u64, usize>,
}

impl<K, V> Default for NsTable<K, V> {
    fn default() -> Self {
        NsTable {
            map: HashMap::new(),
            per_ns: HashMap::new(),
        }
    }
}

impl<K, V> Deref for NsTable<K, V> {
    type Target = HashMap<K, V>;

    fn deref(&self) -> &HashMap<K, V> {
        &self.map
    }
}

impl<K: NsKey, V> NsTable<K, V> {
    /// Entries held by namespace `ns`.
    #[inline]
    pub(crate) fn ns_len(&self, ns: u64) -> usize {
        self.per_ns.get(&ns).copied().unwrap_or(0)
    }

    pub(crate) fn insert(&mut self, k: K, v: V) -> Option<V> {
        let old = self.map.insert(k, v);
        if old.is_none() {
            *self.per_ns.entry(k.ns()).or_default() += 1;
        }
        old
    }

    pub(crate) fn remove(&mut self, k: &K) -> Option<V> {
        let v = self.map.remove(k)?;
        uncount(&mut self.per_ns, k.ns());
        Some(v)
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let per_ns = &mut self.per_ns;
        self.map.retain(|k, v| {
            let kept = keep(k, v);
            if !kept {
                uncount(per_ns, k.ns());
            }
            kept
        });
    }
}

/// Count one entry of `ns` out, forgetting a namespace left with none so
/// that detached namespaces leave nothing behind.
fn uncount(per_ns: &mut HashMap<u64, usize>, ns: u64) {
    if let Some(n) = per_ns.get_mut(&ns) {
        *n -= 1;
        if *n == 0 {
            per_ns.remove(&ns);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    struct K(u64, u32);

    impl NsKey for K {
        fn ns(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn counts_follow_every_change() {
        let mut t = NsTable::default();
        t.insert(K(1, 1), ());
        t.insert(K(1, 2), ());
        t.insert(K(1, 2), ()); // a replacement is not a new entry
        t.insert(K(2, 1), ());
        assert_eq!((t.ns_len(1), t.ns_len(2), t.len()), (2, 1, 3));
        t.remove(&K(1, 1));
        t.remove(&K(1, 9)); // absent
        assert_eq!(t.ns_len(1), 1);
        t.retain(|k, _| k.0 != 1);
        assert_eq!((t.ns_len(1), t.ns_len(2), t.len()), (0, 1, 1));
        assert!(!t.per_ns.contains_key(&1));
    }
}

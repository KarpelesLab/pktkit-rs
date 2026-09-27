//! IPv4 defragmentation. Port of `defrag.go`.
//!
//! Buffers fragments by (src, dst, id, proto), discards on timeout, rejects
//! overlapping fragments (RFC 5722 best practice), reassembles when the full
//! datagram is covered.
//!
//! A forwarder that reassembles must fragment again on the way out: the
//! datagram arrived in pieces because some link on its path could not carry
//! it whole. Like Linux conntrack (`frag_max_size`), reassembly remembers the
//! largest fragment it saw, and [`FragMax::refragment`] cuts the forwarded
//! datagram back down to that.

use crate::fragment::{Fragmentation, MIN_IPV4_MTU, fragment_ipv4};
use crate::time::Instant;
use crate::{Packet, checksum};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

pub(crate) const DEFRAG_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFRAG_MAX_ENTRIES: usize = 256;
/// Cap on fragments buffered for one datagram. A 64 KiB datagram over a
/// 576-byte path is about 120 fragments; more than this is an attack on the
/// buffer, not a datagram.
pub(crate) const DEFRAG_MAX_FRAGS: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    id: u16,
    proto: u8,
}

struct FragData {
    offset: usize,
    data: Vec<u8>,
    /// IP header copied from the first fragment (offset 0). `None` on others.
    hdr: Option<Vec<u8>>,
}

struct FragEntry {
    frags: Vec<FragData>,
    created: Instant,
    /// Total reassembled payload length once last fragment is seen, else `None`.
    total: Option<usize>,
    /// Largest fragment seen, in bytes of IP packet.
    max_size: usize,
    /// Largest fragment seen with Don't Fragment set.
    max_df_size: usize,
}

/// What reassembly learned about the fragments of a datagram: how big they
/// were allowed to be on the way in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FragMax {
    /// The largest fragment, in bytes of IP packet.
    pub(crate) size: usize,
    /// Whether that fragment had Don't Fragment set: the sender is doing
    /// path MTU discovery, and the pieces sent on must keep the bit.
    pub(crate) df: bool,
}

impl FragMax {
    /// Split `pkt`, a reassembled datagram after translation, into fragments
    /// no larger than the ones it arrived in, as Linux's `ip_do_fragment`
    /// does with `frag_max_size`. `None` when it fits as it is.
    pub(crate) fn refragment(&self, pkt: &[u8]) -> Option<Vec<Vec<u8>>> {
        if pkt.len() <= self.size || pkt.len() < 20 {
            return None;
        }
        // Reassembly put DF on the datagram if the fragments had it; it
        // must come off to split, and goes back on every piece.
        let mut whole = pkt.to_vec();
        set_df(&mut whole, false);
        // Every IPv4 link carries 68 bytes (RFC 791), so tinier fragments
        // than that are never needed, however small the ones that came in.
        let mtu = self.size.max(MIN_IPV4_MTU);
        let Fragmentation::Fragments(mut parts) = fragment_ipv4(Packet::from_slice(&whole), mtu)
        else {
            return None;
        };
        if self.df {
            for p in parts.iter_mut() {
                set_df(p, true);
            }
        }
        Some(parts)
    }
}

/// Set or clear an IPv4 header's Don't Fragment bit, keeping its checksum.
fn set_df(pkt: &mut [u8], on: bool) {
    let old = [pkt[6], pkt[7]];
    if on {
        pkt[6] |= 0x40;
    } else {
        pkt[6] &= !0x40;
    }
    let cs = u16::from_be_bytes([pkt[10], pkt[11]]);
    let cs = crate::incremental_update(cs, &old, &[pkt[6], pkt[7]]);
    pkt[10..12].copy_from_slice(&cs.to_be_bytes());
}

/// Reassembler for fragmented IPv4 packets.
pub struct Defragger {
    inner: Mutex<DefragInner>,
}

impl std::fmt::Debug for Defragger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.inner.lock().map(|i| i.entries.len()).unwrap_or(0);
        f.debug_struct("Defragger").field("entries", &n).finish()
    }
}

struct DefragInner {
    entries: HashMap<FragKey, FragEntry>,
}

impl Defragger {
    pub fn new() -> Defragger {
        Defragger {
            inner: Mutex::new(DefragInner {
                entries: HashMap::new(),
            }),
        }
    }

    /// Process one IPv4 datagram.
    ///
    /// - Non-fragmented (`MF=0, offset=0`): returns the input unchanged.
    /// - Fragmented and incomplete: buffers it and returns `None`.
    /// - Last fragment that completes the datagram: returns the reassembled
    ///   packet as a fresh `Vec`.
    pub fn process(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        self.reassemble(pkt).map(|(p, _)| p)
    }

    /// [`process`](Self::process), also returning, for a datagram put
    /// together from fragments, the size they came in.
    pub(crate) fn reassemble(&self, pkt: &[u8]) -> Option<(Vec<u8>, Option<FragMax>)> {
        if pkt.len() < 20 {
            return Some((pkt.to_vec(), None));
        }

        let flags_off = u16::from_be_bytes([pkt[6], pkt[7]]);
        let mf = flags_off & 0x2000 != 0;
        let frag_offset = (flags_off & 0x1FFF) as usize * 8;

        // Not fragmented — pass through.
        if !mf && frag_offset == 0 {
            return Some((pkt.to_vec(), None));
        }

        let ihl = (pkt[0] & 0x0F) as usize * 4;
        // A fragment has to be taken apart, so it must be well formed: the
        // total length bounds the data (anything after it is link padding).
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if ihl < 20 || total_len < ihl || pkt.len() < total_len {
            return None;
        }
        let payload = &pkt[ihl..total_len];
        let end = frag_offset + payload.len();
        // RFC 791: every fragment but the last carries a multiple of 8 bytes,
        // and no fragment may reach past the largest datagram IPv4 can carry.
        if (mf && !payload.len().is_multiple_of(8)) || payload.is_empty() || ihl + end > 65535 {
            return None;
        }

        let mut src = [0u8; 4];
        src.copy_from_slice(&pkt[12..16]);
        let mut dst = [0u8; 4];
        dst.copy_from_slice(&pkt[16..20]);
        let k = FragKey {
            src_ip: src,
            dst_ip: dst,
            id: u16::from_be_bytes([pkt[4], pkt[5]]),
            proto: pkt[9],
        };

        let mut inner = self.inner.lock().expect("Defragger poisoned");

        // Cap the table; over-budget reassemblies are silently dropped.
        if !inner.entries.contains_key(&k) && inner.entries.len() >= DEFRAG_MAX_ENTRIES {
            return None;
        }

        let entry = inner.entries.entry(k).or_insert_with(|| FragEntry {
            frags: Vec::new(),
            created: Instant::now(),
            total: None,
            max_size: 0,
            max_df_size: 0,
        });

        if !mf {
            // Two different last fragments means the datagram is corrupt.
            if entry.total.is_some_and(|t| t != end) {
                inner.entries.remove(&k);
                return None;
            }
            entry.total = Some(end);
        }
        // Data past the end of the datagram is as corrupt as an overlap
        // (RFC 791 gives it nowhere to go), whichever fragment arrived first.
        if let Some(total) = entry.total
            && (end > total || entry.frags.iter().any(|f| f.offset + f.data.len() > total))
        {
            inner.entries.remove(&k);
            return None;
        }

        // Overlaps are rejected on arrival rather than at reassembly, so a
        // fragment sent over and over cannot pile up copies of itself (RFC
        // 5722 has IPv6 drop the whole datagram too).
        let overlaps = entry
            .frags
            .iter()
            .any(|f| frag_offset < f.offset + f.data.len() && f.offset < end);
        if overlaps || entry.frags.len() >= DEFRAG_MAX_FRAGS {
            inner.entries.remove(&k);
            return None;
        }

        entry.max_size = entry.max_size.max(total_len);
        if flags_off & 0x4000 != 0 {
            entry.max_df_size = entry.max_df_size.max(total_len);
        }
        entry.frags.push(FragData {
            offset: frag_offset,
            data: payload.to_vec(),
            hdr: if frag_offset == 0 {
                Some(pkt[..ihl].to_vec())
            } else {
                None
            },
        });

        let total = entry.total?;

        // Coverage check; reject overlaps.
        let mut covered = vec![false; total];
        let mut first_hdr: Option<Vec<u8>> = None;
        for f in entry.frags.iter() {
            let end = (f.offset + f.data.len()).min(total);
            for slot in &mut covered[f.offset..end] {
                if *slot {
                    inner.entries.remove(&k);
                    return None;
                }
                *slot = true;
            }
            if let Some(h) = &f.hdr {
                first_hdr = Some(h.clone());
            }
        }
        if covered.iter().any(|c| !c) {
            return None;
        }

        let hdr = match first_hdr {
            Some(h) => h,
            None => {
                inner.entries.remove(&k);
                return None;
            }
        };

        // Reassemble.
        let mut reassembled = vec![0u8; total];
        for f in entry.frags.iter() {
            let end = (f.offset + f.data.len()).min(total);
            reassembled[f.offset..end].copy_from_slice(&f.data[..end - f.offset]);
        }

        // Linux's rule (ip_frag_reasm): the datagram is as unfragmentable
        // as its largest fragment.
        let max = FragMax {
            size: entry.max_size,
            df: entry.max_df_size == entry.max_size,
        };
        inner.entries.remove(&k);

        let total_len = hdr.len() + reassembled.len();
        if total_len > 65535 {
            return None;
        }
        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(&hdr);
        result.extend_from_slice(&reassembled);

        // Clear MF + offset, fix total length, recompute IP checksum.
        let tl = total_len as u16;
        result[2..4].copy_from_slice(&tl.to_be_bytes());
        result[6..8].copy_from_slice(&[if max.df { 0x40 } else { 0 }, 0]);
        result[10..12].copy_from_slice(&[0, 0]);
        let csum = checksum(&result[..hdr.len()]);
        result[10..12].copy_from_slice(&csum.to_be_bytes());

        Some((result, Some(max)))
    }

    /// Drop entries older than the defrag timeout. Call this periodically;
    /// the NAT's maintenance thread invokes it on its own cadence.
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("Defragger poisoned");
        inner
            .entries
            .retain(|_, e| now.duration_since(e.created) < DEFRAG_TIMEOUT);
    }
}

impl Default for Defragger {
    fn default() -> Self {
        Defragger::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;

    fn build_ipv4(id: u16, mf: bool, offset_bytes: usize, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&id.to_be_bytes());
        let flags_off: u16 = (if mf { 0x2000 } else { 0 }) | ((offset_bytes / 8) as u16 & 0x1FFF);
        p[6..8].copy_from_slice(&flags_off.to_be_bytes());
        p[8] = 64;
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let csum = checksum(&p[..20]);
        p[10..12].copy_from_slice(&csum.to_be_bytes());
        p[20..].copy_from_slice(payload);
        p
    }

    #[test]
    fn passthrough_unfragmented() {
        let d = Defragger::new();
        let p = build_ipv4(0xAB, false, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let out = d.process(&p).unwrap();
        assert_eq!(out, p);
    }

    #[test]
    fn two_fragment_reassembly() {
        let d = Defragger::new();
        // First fragment, MF=1, offset=0, 8 bytes payload.
        let f1 = build_ipv4(0x1234, true, 0, &[1u8; 8]);
        // Second fragment, MF=0, offset=8 bytes.
        let f2 = build_ipv4(0x1234, false, 8, &[2u8; 4]);

        assert!(d.process(&f1).is_none());
        let reassembled = d.process(&f2).unwrap();

        assert_eq!(reassembled.len(), 20 + 12);
        let total_len = u16::from_be_bytes([reassembled[2], reassembled[3]]);
        assert_eq!(total_len as usize, reassembled.len());
        let flags_off = u16::from_be_bytes([reassembled[6], reassembled[7]]);
        assert_eq!(flags_off, 0);
        assert_eq!(&reassembled[20..28], &[1u8; 8]);
        assert_eq!(&reassembled[28..32], &[2u8; 4]);
    }

    #[test]
    fn rejects_overlap() {
        let d = Defragger::new();
        let a = build_ipv4(7, true, 0, &[1u8; 16]);
        // Overlaps bytes 8..16 with a different payload — should be rejected.
        let b = build_ipv4(7, false, 8, &[2u8; 16]);
        assert!(d.process(&a).is_none());
        assert!(d.process(&b).is_none());
    }

    #[test]
    fn fragment_past_the_end_is_dropped_without_panicking() {
        let d = Defragger::new();
        // A middle fragment at offset 800, then a last fragment saying the
        // datagram is 16 bytes long: the first lies past the end.
        let a = build_ipv4(9, true, 800, &[1u8; 8]);
        let b = build_ipv4(9, false, 8, &[2u8; 8]);
        assert!(d.process(&a).is_none());
        assert!(d.process(&b).is_none());

        // The reassembler must still work afterwards.
        let f1 = build_ipv4(10, true, 0, &[1u8; 8]);
        let f2 = build_ipv4(10, false, 8, &[2u8; 4]);
        assert!(d.process(&f1).is_none());
        assert_eq!(d.process(&f2).unwrap().len(), 32);
    }

    #[test]
    fn fragment_past_a_known_end_is_dropped() {
        let d = Defragger::new();
        let last = build_ipv4(11, false, 8, &[2u8; 8]);
        let beyond = build_ipv4(11, true, 64, &[3u8; 8]);
        let first = build_ipv4(11, true, 0, &[1u8; 8]);
        assert!(d.process(&last).is_none());
        assert!(d.process(&beyond).is_none());
        // The datagram is corrupt; it must not be reassembled.
        assert!(d.process(&first).is_none());
    }

    #[test]
    fn conflicting_last_fragments_are_dropped() {
        let d = Defragger::new();
        let first = build_ipv4(12, true, 0, &[1u8; 8]);
        let last_a = build_ipv4(12, false, 8, &[2u8; 8]);
        let last_b = build_ipv4(12, false, 16, &[2u8; 8]);
        assert!(d.process(&first).is_none());
        assert!(d.process(&last_b).is_none());
        assert!(d.process(&last_a).is_none());
    }

    #[test]
    fn link_padding_is_not_reassembled() {
        let d = Defragger::new();
        let f1 = build_ipv4(13, true, 0, &[1u8; 8]);
        let mut f2 = build_ipv4(13, false, 8, &[2u8; 4]);
        // Trailing bytes beyond the IP total length (e.g. Ethernet padding).
        f2.extend_from_slice(&[0xEE; 6]);
        assert!(d.process(&f1).is_none());
        let out = d.process(&f2).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(&out[28..32], &[2u8; 4]);
    }

    fn buffered(d: &Defragger) -> usize {
        d.inner
            .lock()
            .unwrap()
            .entries
            .values()
            .map(|e| e.frags.len())
            .sum()
    }

    #[test]
    fn repeated_fragment_is_not_buffered_again() {
        let d = Defragger::new();
        let f = build_ipv4(20, true, 0, &[1u8; 8]);
        for _ in 0..1000 {
            assert!(d.process(&f).is_none());
        }
        assert!(buffered(&d) <= 1);
    }

    #[test]
    fn fragments_per_datagram_are_bounded() {
        let d = Defragger::new();
        for i in 0..2000 {
            let f = build_ipv4(21, true, i * 8, &[1u8; 8]);
            assert!(d.process(&f).is_none());
        }
        assert!(buffered(&d) <= DEFRAG_MAX_FRAGS);
    }
}

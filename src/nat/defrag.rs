//! IPv4 defragmentation. Port of `defrag.go`.
//!
//! Buffers fragments by (src, dst, id, proto), discards on timeout, rejects
//! overlapping fragments (RFC 5722 best practice), reassembles when the full
//! datagram is covered.

use crate::checksum;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const DEFRAG_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFRAG_MAX_ENTRIES: usize = 256;

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
        if pkt.len() < 20 {
            return Some(pkt.to_vec());
        }

        let flags_off = u16::from_be_bytes([pkt[6], pkt[7]]);
        let mf = flags_off & 0x2000 != 0;
        let frag_offset = (flags_off & 0x1FFF) as usize * 8;

        // Not fragmented — pass through.
        if !mf && frag_offset == 0 {
            return Some(pkt.to_vec());
        }

        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 || pkt.len() < ihl {
            return Some(pkt.to_vec());
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
        });

        let payload = &pkt[ihl..];
        let fd = FragData {
            offset: frag_offset,
            data: payload.to_vec(),
            hdr: if frag_offset == 0 {
                Some(pkt[..ihl].to_vec())
            } else {
                None
            },
        };
        entry.frags.push(fd);

        if !mf {
            entry.total = Some(frag_offset + payload.len());
        }

        let total = match entry.total {
            Some(t) => t,
            None => return None,
        };
        if total > 65535 {
            inner.entries.remove(&k);
            return None;
        }

        // Coverage check; reject overlaps.
        let mut covered = vec![false; total];
        let mut first_hdr: Option<Vec<u8>> = None;
        for f in entry.frags.iter() {
            let end = (f.offset + f.data.len()).min(total);
            for i in f.offset..end {
                if covered[i] {
                    inner.entries.remove(&k);
                    return None;
                }
                covered[i] = true;
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
        result[6..8].copy_from_slice(&[0, 0]);
        result[10..12].copy_from_slice(&[0, 0]);
        let csum = checksum(&result[..hdr.len()]);
        result[10..12].copy_from_slice(&csum.to_be_bytes());

        Some(result)
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
}

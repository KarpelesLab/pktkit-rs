//! Fragment reassembly for the stacks that terminate flows themselves
//! (`slirp` and `vclient`).
//!
//! They need whole datagrams: a fragment carries no transport header past
//! the first one, and the first one alone is truncated. This is a small
//! reassembler (RFC 791 for IPv4, RFC 8200 §4.5 for IPv6) with bounded
//! memory:
//!
//! - at most [`MAX_DATAGRAMS`] datagrams in progress, the oldest evicted
//!   first, each at most 64 KiB in at most [`MAX_PIECES`] fragments;
//! - at most [`MAX_BYTES`] of payload buffers across them, again evicting
//!   the oldest first;
//! - a datagram not completed within [`REASSEMBLY_TIMEOUT`] is discarded;
//! - fragments that overlap what is already held, other than an exact
//!   repeat, discard the whole datagram (RFC 5722; for IPv4 it is the same
//!   defence against overlap-based filter evasion, RFC 1858).
//!
//! The `nat` feature has a reassembler of its own, but neither of them
//! depends on that feature.

use crate::time::Instant;
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

/// Datagrams in progress at once, per stack.
pub(crate) const MAX_DATAGRAMS: usize = 64;

/// Payload buffer bytes (allocated capacity) held across all datagrams in
/// progress. The datagram count alone would allow 64 buffers of up to
/// 64 KiB each; Linux's default budget per network namespace
/// (`ipfrag_high_thresh`) is 4 MiB for far more traffic than these stacks
/// see, and 1 MiB still leaves room for 16 maximum-size datagrams at once.
pub(crate) const MAX_BYTES: usize = 1 << 20;

/// Fragments held for one datagram. Keeping them sorted costs an insertion
/// into a `Vec` per fragment, which is quadratic in their number: without
/// a cap, 8-byte fragments sent in reverse order could make one 64 KiB
/// datagram 8192 pieces and ~33 million element moves. 256 is several
/// times what real paths produce (a 64 KiB datagram over a 1280-byte IPv6
/// minimum MTU is 52 fragments; over a 576-byte IPv4 path, 118), and keeps
/// the worst case to ~32 thousand moves.
pub(crate) const MAX_PIECES: usize = 256;

/// How long a partial datagram is kept waiting for its missing fragments.
pub(crate) const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest payload an IP datagram can carry after reassembly.
const MAX_PAYLOAD: usize = 65535;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
struct Key {
    ns: u64,
    v6: bool,
    src: [u8; 16],
    dst: [u8; 16],
    id: u32,
    /// IPv4 protocol; for IPv6 the next header is taken from the first
    /// fragment instead, as RFC 8200 requires.
    proto: u8,
}

struct Partial {
    started: Instant,
    /// Header for the rebuilt packet, from the first fragment once seen.
    header: Option<Vec<u8>>,
    data: Vec<u8>,
    /// Received fragments as byte ranges `[start, end)`, sorted and
    /// disjoint. Kept as received, not merged, so that a repeat can be told
    /// from an overlap by its bounds.
    pieces: Vec<(usize, usize)>,
    /// Bytes held: the sum of the pieces' lengths.
    received: usize,
    /// Payload length, known once the last fragment has arrived.
    total: Option<usize>,
    /// The piece ending at `total` came with "more fragments" clear (it
    /// did not if an empty last fragment fixed the total after it).
    last_piece_final: bool,
}

/// Where a fragment goes in its datagram.
struct Piece<'a> {
    key: Key,
    offset: usize,
    more: bool,
    data: &'a [u8],
    /// Set for the offset-0 fragment: the header of the rebuilt packet.
    header: Option<Vec<u8>>,
}

#[derive(Default)]
pub(crate) struct Reassembler {
    partial: HashMap<Key, Partial>,
    /// Sum of the `data` capacities in `partial`, checked against
    /// [`MAX_BYTES`].
    bytes: usize,
}

impl Reassembler {
    /// Feed an IPv4 fragment (`pkt` trimmed to its total length, `ihl` its
    /// header length). Returns the reassembled packet once complete.
    pub(crate) fn push_v4(
        &mut self,
        now: Instant,
        ns: u64,
        pkt: &[u8],
        ihl: usize,
    ) -> Option<Vec<u8>> {
        let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
        let offset = (frag & 0x1FFF) as usize * 8;
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src[..4].copy_from_slice(&pkt[12..16]);
        dst[..4].copy_from_slice(&pkt[16..20]);
        let header = (offset == 0).then(|| {
            // Options are dropped: the stack does not act on them.
            let mut h = pkt[..20].to_vec();
            h[0] = 0x45;
            h
        });
        let piece = Piece {
            key: Key {
                ns,
                v6: false,
                src,
                dst,
                id: u16::from_be_bytes([pkt[4], pkt[5]]) as u32,
                proto: pkt[9],
            },
            offset,
            more: frag & 0x2000 != 0,
            data: &pkt[ihl..],
            header,
        };
        let (header, payload) = self.push(now, piece)?;
        let total = 20 + payload.len();
        if total > MAX_PAYLOAD {
            return None;
        }
        let mut out = header;
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[6..8].copy_from_slice(&[0, 0]);
        out[10..12].copy_from_slice(&[0, 0]);
        let cs = crate::checksum::checksum(&out);
        out[10..12].copy_from_slice(&cs.to_be_bytes());
        out.extend_from_slice(&payload);
        Some(out)
    }

    /// Feed an IPv6 packet (trimmed to its payload length) whose fragment
    /// header starts at `frag_off`. Returns the reassembled packet once
    /// complete, rebuilt with a bare fixed header: the headers before the
    /// fragment header are not needed past this point.
    pub(crate) fn push_v6(
        &mut self,
        now: Instant,
        ns: u64,
        pkt: &[u8],
        frag_off: usize,
    ) -> Option<Vec<u8>> {
        if pkt.len() < frag_off + 8 {
            return None;
        }
        let fh = &pkt[frag_off..frag_off + 8];
        let off_flags = u16::from_be_bytes([fh[2], fh[3]]);
        let offset = (off_flags & 0xFFF8) as usize;
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&pkt[8..24]);
        dst.copy_from_slice(&pkt[24..40]);
        let header = (offset == 0).then(|| {
            let mut h = pkt[..40].to_vec();
            h[6] = fh[0]; // next header of the fragmentable part
            h
        });
        let piece = Piece {
            key: Key {
                ns,
                v6: true,
                src,
                dst,
                id: u32::from_be_bytes([fh[4], fh[5], fh[6], fh[7]]),
                proto: 0,
            },
            offset,
            more: off_flags & 1 != 0,
            data: &pkt[frag_off + 8..],
            header,
        };
        let (mut out, payload) = self.push(now, piece)?;
        out[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        Some(out)
    }

    fn push(&mut self, now: Instant, p: Piece<'_>) -> Option<(Vec<u8>, Vec<u8>)> {
        let bytes = &mut self.bytes;
        self.partial.retain(|_, d| {
            let keep = now.duration_since(d.started) < REASSEMBLY_TIMEOUT;
            if !keep {
                *bytes -= d.data.capacity();
            }
            keep
        });

        let end = p.offset + p.data.len();
        // Every fragment but the last carries a multiple of 8 bytes, and
        // nothing may reach past the largest datagram.
        let malformed =
            (p.more && (!p.data.len().is_multiple_of(8) || p.data.is_empty())) || end > MAX_PAYLOAD;
        if malformed {
            self.discard(&p.key);
            return None;
        }

        if !self.partial.contains_key(&p.key) && self.partial.len() >= MAX_DATAGRAMS {
            self.evict_oldest(&p.key);
        }
        let d = self.partial.entry(p.key).or_insert_with(|| Partial {
            started: now,
            header: None,
            data: Vec::new(),
            pieces: Vec::new(),
            received: 0,
            total: None,
            last_piece_final: false,
        });

        let before = d.data.capacity();
        let accepted = d.accept(&p, end);
        self.bytes = self.bytes - before + d.data.capacity();
        let complete = d.total.filter(|&t| d.received == t);
        if !accepted {
            self.discard(&p.key);
            return None;
        }
        if complete.is_none() {
            // Over budget: the oldest datagrams go, then this one if it is
            // still too much on its own.
            while self.bytes > MAX_BYTES && self.evict_oldest(&p.key) {}
            if self.bytes > MAX_BYTES {
                self.discard(&p.key);
            }
            return None;
        }
        let total = complete?;
        let d = self.partial.remove(&p.key)?;
        self.bytes -= d.data.capacity();
        let header = d.header?;
        let mut data = d.data;
        data.truncate(total);
        Some((header, data))
    }

    fn discard(&mut self, key: &Key) {
        if let Some(d) = self.partial.remove(key) {
            self.bytes -= d.data.capacity();
        }
    }

    /// Drop the oldest datagram in progress other than `keep`; `false` if
    /// there is none.
    fn evict_oldest(&mut self, keep: &Key) -> bool {
        let oldest = self
            .partial
            .iter()
            .filter(|(k, _)| *k != keep)
            .min_by_key(|(_, d)| d.started)
            .map(|(k, _)| *k);
        match oldest {
            Some(k) => {
                self.discard(&k);
                true
            }
            None => false,
        }
    }

    #[cfg(test)]
    fn in_progress(&self) -> usize {
        self.partial.len()
    }
}

impl Partial {
    /// Merge a fragment. `false` means the datagram is inconsistent and must
    /// be dropped.
    fn accept(&mut self, p: &Piece<'_>, end: usize) -> bool {
        if !p.more {
            match self.total {
                Some(t) if t != end => return false,
                _ => self.total = Some(end),
            }
        }
        if let Some(t) = self.total
            && (end > t || self.pieces.last().is_some_and(|&(_, e)| e > t))
        {
            return false;
        }
        // An exact repeat (a retransmitted or duplicated fragment, RFC 8200
        // §4.5) is harmless; any other overlap is not. The pieces are sorted
        // and disjoint, so only the one starting before this fragment and
        // the one starting at or after it can overlap it.
        let i = self.pieces.partition_point(|&(s, _)| s < p.offset);
        let neighbours = i
            .checked_sub(1)
            .and_then(|j| self.pieces.get(j))
            .into_iter()
            .chain(self.pieces.get(i));
        for &(s, e) in neighbours {
            if s < end.max(p.offset + 1) && p.offset < e {
                // A repeat must say the same about "more fragments" as the
                // original: final only if the original was. Otherwise a
                // copy of an early fragment with MF clear would cut the
                // datagram short at its end.
                let was_final = self.last_piece_final && self.total == Some(e);
                return s == p.offset
                    && e == end
                    && self.data[s..e] == *p.data
                    && p.more != was_final;
            }
        }
        if p.data.is_empty() {
            // Zero-length last fragment: it only fixes the total.
            return true;
        }
        if self.pieces.len() >= MAX_PIECES {
            return false;
        }
        if self.data.len() < end {
            // Grow geometrically, but never past the largest datagram: the
            // capacity is what counts against MAX_BYTES.
            let want = self.total.unwrap_or(end).max(end);
            if self.data.capacity() < want {
                let cap = (self.data.capacity() * 2).clamp(want, MAX_PAYLOAD.max(want));
                self.data.reserve_exact(cap - self.data.len());
            }
            self.data.resize(end, 0);
        }
        self.data[p.offset..end].copy_from_slice(p.data);
        if let Some(h) = &p.header {
            self.header = Some(h.clone());
        }
        self.pieces.insert(i, (p.offset, end));
        self.last_piece_final |= !p.more;
        self.received += p.data.len();
        true
    }
}

impl Reassembler {
    /// Pass an IP packet through reassembly: a packet that is not a
    /// fragment comes back as it is (trimmed to its IP length), the fragment
    /// completing a datagram brings back the whole datagram, and anything
    /// else (a fragment held for later, a malformed packet) gives `None`.
    pub(crate) fn reassemble<'a>(
        &mut self,
        now: Instant,
        ns: u64,
        pkt: &'a [u8],
    ) -> Option<Cow<'a, [u8]>> {
        match pkt.first()? >> 4 {
            4 => {
                let ihl = (pkt[0] & 0x0F) as usize * 4;
                let total = u16::from_be_bytes([*pkt.get(2)?, *pkt.get(3)?]) as usize;
                if ihl < 20 || total < ihl || total > pkt.len() {
                    return None;
                }
                let pkt = &pkt[..total];
                if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3FFF == 0 {
                    return Some(Cow::Borrowed(pkt));
                }
                self.push_v4(now, ns, pkt, ihl).map(Cow::Owned)
            }
            6 => {
                let len = 40 + u16::from_be_bytes([*pkt.get(4)?, *pkt.get(5)?]) as usize;
                if pkt.len() < len {
                    return None;
                }
                let pkt = &pkt[..len];
                let Some(frag_off) = ipv6_fragment_header(pkt) else {
                    return Some(Cow::Borrowed(pkt));
                };
                let whole = self.push_v6(now, ns, pkt, frag_off)?;
                // Reassembly happens once (RFC 8200 §4.5): a Fragment header
                // left in the rebuilt packet is a nesting trick, not a
                // datagram.
                ipv6_fragment_header(&whole)
                    .is_none()
                    .then_some(Cow::Owned(whole))
            }
            _ => Some(Cow::Borrowed(pkt)),
        }
    }
}

/// Offset of the IPv6 Fragment header in `pkt`, if there is one, found by
/// walking the extension headers that may precede it.
pub(crate) fn ipv6_fragment_header(pkt: &[u8]) -> Option<usize> {
    let mut next = pkt[6];
    let mut off = 40;
    for _ in 0..crate::packet::MAX_EXT_HEADERS {
        match next {
            44 => return Some(off),
            // Hop-by-hop, routing, destination options, mobility, HIP, shim6.
            0 | 43 | 60 | 135 | 139 | 140 => {
                let h = pkt.get(off..off + 2)?;
                next = h[0];
                off += (h[1] as usize + 1) * 8;
            }
            // Authentication header.
            51 => {
                let h = pkt.get(off..off + 2)?;
                next = h[0];
                off += (h[1] as usize + 2) * 4;
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Packet;
    use crate::fragment::{Fragmentation, fragment_ipv4};

    fn v4_datagram(payload_len: usize) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 5]);
        p[16..20].copy_from_slice(&[10, 0, 0, 1]);
        for (i, b) in p[20..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        p
    }

    fn split(p: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        match fragment_ipv4(Packet::from_slice(p), mtu) {
            Fragmentation::Fragments(f) => f,
            other => panic!("expected fragments, got {other:?}"),
        }
    }

    fn push_all(r: &mut Reassembler, frags: &[Vec<u8>]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let mut out = None;
        for f in frags {
            let ihl = (f[0] & 0x0F) as usize * 4;
            out = r.push_v4(now, 0, f, ihl);
        }
        out
    }

    #[test]
    fn v4_in_any_order() {
        let dgram = v4_datagram(3000);
        let mut frags = split(&dgram, 1000);
        assert!(frags.len() >= 4);
        frags.reverse();
        let mut r = Reassembler::default();
        let whole = push_all(&mut r, &frags).expect("reassembled");
        assert_eq!(whole[20..], dgram[20..]);
        assert_eq!(
            u16::from_be_bytes([whole[2], whole[3]]) as usize,
            dgram.len()
        );
        assert_eq!(&whole[6..8], &[0, 0]);
        assert_eq!(r.in_progress(), 0);
    }

    #[test]
    fn v4_duplicate_fragment_is_tolerated() {
        let dgram = v4_datagram(2000);
        let mut frags = split(&dgram, 1000);
        frags.insert(1, frags[0].clone());
        let mut r = Reassembler::default();
        assert_eq!(push_all(&mut r, &frags).unwrap()[20..], dgram[20..]);
    }

    #[test]
    fn v4_duplicate_after_its_neighbour_is_tolerated() {
        let dgram = v4_datagram(3000);
        let frags = split(&dgram, 1000);
        let mut r = Reassembler::default();
        let now = Instant::now();
        // Fragments 0 and 1 are held as one range by the time the repeat
        // of fragment 0 arrives.
        assert!(r.push_v4(now, 0, &frags[0], 20).is_none());
        assert!(r.push_v4(now, 0, &frags[1], 20).is_none());
        assert!(r.push_v4(now, 0, &frags[0], 20).is_none());
        assert!(r.push_v4(now, 0, &frags[1], 20).is_none());
        assert_eq!(r.in_progress(), 1);
        assert_eq!(push_all(&mut r, &frags[2..]).unwrap()[20..], dgram[20..]);

        // A repeat with other bytes is an overlap.
        let mut r = Reassembler::default();
        assert!(r.push_v4(now, 0, &frags[0], 20).is_none());
        assert!(r.push_v4(now, 0, &frags[1], 20).is_none());
        let mut bad = frags[0].clone();
        bad[30] ^= 0xFF;
        assert!(r.push_v4(now, 0, &bad, 20).is_none());
        assert_eq!(r.in_progress(), 0);
    }

    /// Flip "more fragments" on a fragment (the checksum is not checked).
    fn with_more(f: &[u8], more: bool) -> Vec<u8> {
        let mut f = f.to_vec();
        if more {
            f[6] |= 0x20;
        } else {
            f[6] &= !0x20;
        }
        f
    }

    #[test]
    fn v4_repeat_must_agree_on_more_fragments() {
        let dgram = v4_datagram(3000);
        let frags = split(&dgram, 1000);
        let now = Instant::now();

        // A copy of the first fragment claiming to be the last would
        // otherwise complete the datagram at its own end.
        let mut r = Reassembler::default();
        assert!(r.push_v4(now, 0, &frags[0], 20).is_none());
        assert!(
            r.push_v4(now, 0, &with_more(&frags[0], false), 20)
                .is_none()
        );
        assert_eq!(r.in_progress(), 0);

        // Nor may a copy of the last fragment say more follow.
        let last = frags.len() - 1;
        let mut r = Reassembler::default();
        assert!(r.push_v4(now, 0, &frags[last], 20).is_none());
        assert!(
            r.push_v4(now, 0, &with_more(&frags[last], true), 20)
                .is_none()
        );
        assert_eq!(r.in_progress(), 0);

        // A faithful repeat of the last fragment is still fine.
        let mut r = Reassembler::default();
        assert!(r.push_v4(now, 0, &frags[last], 20).is_none());
        assert!(r.push_v4(now, 0, &frags[last], 20).is_none());
        assert_eq!(push_all(&mut r, &frags[..last]).unwrap()[20..], dgram[20..]);
    }

    #[test]
    fn v4_repeat_before_an_empty_last_fragment_is_tolerated() {
        let dgram = v4_datagram(2000);
        let mut frags = split(&dgram, 1000);
        let last = frags.len() - 1;
        let end = frags[last].clone();
        frags[last] = with_more(&end, true);
        // An empty fragment at the end carries the "last" flag instead.
        let off = u16::from_be_bytes([end[6], end[7]]) & 0x1FFF;
        let end_units = off as usize + (end.len() - 20) / 8;
        let mut empty = end[..20].to_vec();
        empty[2..4].copy_from_slice(&20u16.to_be_bytes());
        empty[6..8].copy_from_slice(&(end_units as u16).to_be_bytes());
        let now = Instant::now();
        let mut r = Reassembler::default();
        assert!(r.push_v4(now, 0, &frags[last], 20).is_none());
        assert!(r.push_v4(now, 0, &empty, 20).is_none());
        assert!(r.push_v4(now, 0, &frags[last], 20).is_none());
        assert_eq!(r.in_progress(), 1);
        assert_eq!(push_all(&mut r, &frags[..last]).unwrap()[20..], dgram[20..]);
    }

    #[test]
    fn v4_overlap_drops_the_datagram() {
        let dgram = v4_datagram(2000);
        let frags = split(&dgram, 1000);
        let mut r = Reassembler::default();
        let now = Instant::now();
        assert!(r.push_v4(now, 0, &frags[0], 20).is_none());
        // Same offset, different length: an overlap that is not a repeat.
        let mut bad = frags[0].clone();
        bad.truncate(bad.len() - 8);
        let len = bad.len() as u16;
        bad[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(r.push_v4(now, 0, &bad, 20).is_none());
        assert_eq!(r.in_progress(), 0);
        // The rest cannot complete it any more.
        assert!(push_all(&mut r, &frags[1..]).is_none());
    }

    #[test]
    fn v4_incomplete_datagram_expires() {
        let dgram = v4_datagram(2000);
        let frags = split(&dgram, 1000);
        let mut r = Reassembler::default();
        let t0 = Instant::now();
        assert!(r.push_v4(t0, 0, &frags[0], 20).is_none());
        let later = t0 + REASSEMBLY_TIMEOUT + Duration::from_secs(1);
        // The first fragment is gone, so the rest does not complete it.
        for f in &frags[1..] {
            assert!(r.push_v4(later, 0, f, 20).is_none());
        }
    }

    #[test]
    fn datagrams_in_progress_are_bounded() {
        let mut r = Reassembler::default();
        let now = Instant::now();
        for id in 0..(MAX_DATAGRAMS as u16 * 2) {
            let mut d = v4_datagram(2000);
            d[4..6].copy_from_slice(&id.to_be_bytes());
            let frags = split(&d, 1000);
            r.push_v4(now, 0, &frags[0], 20);
        }
        assert_eq!(r.in_progress(), MAX_DATAGRAMS);
    }

    #[test]
    fn bytes_in_progress_are_bounded() {
        let mut r = Reassembler::default();
        let now = Instant::now();
        // One fragment near the 64 KiB end of each datagram makes each
        // hold a buffer of nearly that size.
        for id in 0..MAX_DATAGRAMS as u16 {
            let mut f = v4_datagram(8);
            f[4..6].copy_from_slice(&id.to_be_bytes());
            f[6..8].copy_from_slice(&(0x2000u16 | 8000).to_be_bytes());
            assert!(r.push_v4(now, 0, &f, 20).is_none());
            let held: usize = r.partial.values().map(|d| d.data.capacity()).sum();
            assert!(held <= MAX_BYTES, "{held} bytes held");
            assert_eq!(held, r.bytes);
        }
        assert!(r.in_progress() < MAX_DATAGRAMS);

        // Completing or discarding datagrams gives their bytes back.
        let mut r = Reassembler::default();
        let dgram = v4_datagram(3000);
        push_all(&mut r, &split(&dgram, 1000)).expect("reassembled");
        assert_eq!(r.bytes, 0);
        let frags = split(&dgram, 1000);
        r.push_v4(now, 0, &frags[0], 20);
        assert!(r.bytes > 0);
        let later = now + REASSEMBLY_TIMEOUT + Duration::from_secs(1);
        r.push_v4(later, 1, &frags[1], 20);
        r.push_v4(later, 1, &frags[1], 20);
        let mut bad = frags[1].clone();
        bad[30] ^= 1;
        r.push_v4(later, 1, &bad, 20);
        assert_eq!((r.in_progress(), r.bytes), (0, 0));
    }

    #[test]
    fn fragments_per_datagram_are_bounded() {
        let mut r = Reassembler::default();
        let now = Instant::now();
        // 8-byte fragments in reverse order: the worst case for keeping
        // the pieces sorted.
        let mut f = v4_datagram(8);
        for unit in (0..MAX_PIECES as u16 + 1).rev() {
            f[6..8].copy_from_slice(&(0x2000 | unit).to_be_bytes());
            assert!(r.push_v4(now, 0, &f, 20).is_none());
        }
        assert_eq!(r.in_progress(), 0, "datagram past MAX_PIECES kept");
    }

    #[test]
    fn v4_fragment_past_64k_is_rejected() {
        let mut r = Reassembler::default();
        let mut f = v4_datagram(16);
        f[6..8].copy_from_slice(&0x1FFFu16.to_be_bytes()); // offset 65528
        assert!(r.push_v4(Instant::now(), 0, &f, 20).is_none());
        assert_eq!(r.in_progress(), 0);
    }

    fn v6_fragment(id: u32, offset: usize, more: bool, next: u8, data: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 48 + data.len()];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        p[6] = 44;
        p[7] = 64;
        p[8..24].copy_from_slice(&"fd00::5".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p[40] = next;
        p[42..44].copy_from_slice(&((offset as u16) | more as u16).to_be_bytes());
        p[44..48].copy_from_slice(&id.to_be_bytes());
        p[48..].copy_from_slice(data);
        p
    }

    #[test]
    fn v6_reassembles_with_next_header_from_first_fragment() {
        let body: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        let f1 = v6_fragment(7, 0, true, 17, &body[..1232]);
        let f2 = v6_fragment(7, 1232, false, 17, &body[1232..]);
        assert_eq!(ipv6_fragment_header(&f1), Some(40));
        let mut r = Reassembler::default();
        let now = Instant::now();
        assert!(r.push_v6(now, 0, &f2, 40).is_none());
        let whole = r.push_v6(now, 0, &f1, 40).expect("reassembled");
        assert_eq!(whole[6], 17);
        assert_eq!(
            u16::from_be_bytes([whole[4], whole[5]]) as usize,
            body.len()
        );
        assert_eq!(whole[40..], body[..]);
    }

    #[test]
    fn v6_atomic_fragment_passes_through() {
        let f = v6_fragment(9, 0, false, 17, b"12345678");
        let whole = Reassembler::default()
            .push_v6(Instant::now(), 0, &f, 40)
            .unwrap();
        assert_eq!(whole.len(), 48);
        assert_eq!(&whole[40..], b"12345678");
    }
}

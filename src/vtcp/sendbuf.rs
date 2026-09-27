//! Sender-side byte buffer with SACK scoreboard.

use super::options::SackBlock;
use super::seqspace::{seq_after, seq_after_eq, seq_before, seq_before_eq};

/// Cap on the SACK scoreboard. Each entry is a range the receiver reported
/// separately, so this bounds how many holes a peer can make us track.
const MAX_SACKED: usize = 128;

/// Tracks application data through the TCP send pipeline:
///
/// ```text
/// [acked] [sent but unacked] [unsent / queued] [free]
///         ^                  ^                 ^
///         una                nxt               tail
/// ```
///
/// `buf[head]` corresponds to sequence `una`. `buf[head..head+nxt-una)` is
/// in flight; the rest is queued for sending.
#[derive(Debug)]
pub struct SendBuf {
    /// Acknowledged bytes before `head` are dropped lazily (see
    /// [`acknowledge`](Self::acknowledge)), keeping the data contiguous for
    /// the slices handed out without shifting it on every ACK.
    buf: Vec<u8>,
    head: usize,
    cap: usize,
    una: u32,
    nxt: u32,
    /// Ranges the receiver has SACKed: sorted, disjoint, non-adjacent, and
    /// all within `una..nxt`.
    sacked: Vec<SackBlock>,
}

impl SendBuf {
    pub fn new(capacity: usize, initial_seq: u32) -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
            cap: capacity,
            una: initial_seq,
            nxt: initial_seq,
            sacked: Vec::new(),
        }
    }

    /// The unacknowledged and unsent data, from SND.UNA on.
    #[inline]
    fn data(&self) -> &[u8] {
        &self.buf[self.head..]
    }

    /// Append data, returning the number of bytes accepted.
    pub fn write(&mut self, p: &[u8]) -> usize {
        let avail = self.available();
        if avail == 0 {
            return 0;
        }
        let n = p.len().min(avail);
        self.buf.extend_from_slice(&p[..n]);
        n
    }

    /// Bytes queued but not yet sent.
    pub fn pending(&self) -> usize {
        let sent = self.nxt.wrapping_sub(self.una) as usize;
        self.data().len().saturating_sub(sent)
    }

    /// Sent-but-unacknowledged bytes.
    pub fn unacked(&self) -> usize {
        self.nxt.wrapping_sub(self.una) as usize
    }

    /// Read at most `n` bytes of unsent data without consuming them.
    pub fn peek_unsent(&self, n: usize) -> &[u8] {
        let offset = self.nxt.wrapping_sub(self.una) as usize;
        let data = self.data();
        let unsent = &data[offset.min(data.len())..];
        if unsent.len() > n {
            &unsent[..n]
        } else {
            unsent
        }
    }

    /// Advance SND.NXT by `n` after the data was put on the wire.
    pub fn advance_sent(&mut self, n: usize) {
        self.nxt = self.nxt.wrapping_add(n as u32);
    }

    /// Cumulative ACK at `ack`; returns the number of bytes newly freed.
    pub fn acknowledge(&mut self, mut ack: u32) -> u32 {
        if !seq_after(ack, self.una) {
            return 0;
        }
        if seq_after(ack, self.nxt) {
            ack = self.nxt;
        }
        let mut n = ack.wrapping_sub(self.una);
        if n as usize > self.data().len() {
            n = self.data().len() as u32;
        }
        self.head += n as usize;
        // Shifting the rest down on every ACK would cost the whole buffer
        // per ACK. Do it only once the dropped bytes outnumber what is
        // left, or reach a quarter of the capacity: each shift then moves
        // at most four bytes per byte acknowledged since the last, and the
        // dead space stays bounded.
        let live = self.buf.len() - self.head;
        if self.head >= live || self.head >= self.cap / 4 {
            self.buf.drain(..self.head);
            self.head = 0;
        }
        self.una = ack;
        self.prune_sack();
        n
    }

    /// Add the receiver's SACK blocks to the scoreboard. Returns true if
    /// they covered anything not SACKed before.
    ///
    /// Blocks accumulate: an ACK carries at most three or four, newest first
    /// (RFC 2018 §4), so ranges reported earlier are not repeated once more
    /// recent ones fill the option.
    pub fn mark_sacked(&mut self, blocks: &[SackBlock]) -> bool {
        let before = self.sacked_between(self.una, self.nxt);
        for b in blocks {
            // Clip to what is actually in flight. D-SACKs (RFC 2883) report
            // data below UNA and so clip to nothing.
            let left = if seq_before(b.left, self.una) {
                self.una
            } else {
                b.left
            };
            let right = if seq_after(b.right, self.nxt) {
                self.nxt
            } else {
                b.right
            };
            if seq_after(right, left) {
                self.add_sacked(left, right);
            }
        }
        // Only MAX_SACKED truncation can lower the total, and that drops
        // the highest range, which a later report may bring back.
        self.sacked_between(self.una, self.nxt) != before
    }

    /// IsLost (RFC 6675 §4): whether `seq` counts as lost, because
    /// `dup_thresh` discontiguous SACKed ranges lie above it, or more than
    /// `(dup_thresh - 1) * mss` SACKed bytes do.
    pub fn is_lost(&self, seq: u32, dup_thresh: u32, mss: u32) -> bool {
        let next = seq.wrapping_add(1);
        let above = |b: &&SackBlock| seq_after(b.right, next);
        let ranges = self.sacked.iter().filter(above).count() as u32;
        let bytes = self.sacked_between(next, self.nxt);
        ranges >= dup_thresh || bytes > (dup_thresh - 1).saturating_mul(mss)
    }

    fn add_sacked(&mut self, mut left: u32, mut right: u32) {
        let mut merged = Vec::with_capacity(self.sacked.len() + 1);
        let mut placed = false;
        for &b in &self.sacked {
            if seq_before(b.right, left) {
                merged.push(b);
            } else if seq_before(right, b.left) {
                if !placed {
                    merged.push(SackBlock { left, right });
                    placed = true;
                }
                merged.push(b);
            } else {
                // Overlapping or touching: absorb it.
                if seq_before(b.left, left) {
                    left = b.left;
                }
                if seq_after(b.right, right) {
                    right = b.right;
                }
            }
        }
        if !placed {
            merged.push(SackBlock { left, right });
        }
        // Forget the highest range first: it is the last one retransmission
        // would reach.
        merged.truncate(MAX_SACKED);
        self.sacked = merged;
    }

    /// Forget every SACK. After a retransmission timeout the receiver may
    /// have discarded what it SACKed, so RFC 2018 §8 has the sender stop
    /// relying on it.
    pub fn clear_sacked(&mut self) {
        self.sacked.clear();
    }

    fn prune_sack(&mut self) {
        let una = self.una;
        self.sacked.retain(|b| seq_after(b.right, una));
        if let Some(first) = self.sacked.first_mut()
            && seq_before(first.left, una)
        {
            first.left = una;
        }
    }

    /// True iff `seq` lies within any SACK block.
    pub fn is_sacked(&self, seq: u32) -> bool {
        self.sacked
            .iter()
            .any(|b| seq_after_eq(seq, b.left) && seq_before(seq, b.right))
    }

    /// The first hole in the in-flight data, for retransmission: its
    /// sequence number and up to `n` bytes of it. The hole ends where the
    /// next SACKed range begins, so data the receiver already holds is not
    /// sent again. `None` when nothing unacknowledged is missing.
    pub fn retransmit_data(&self, n: usize) -> Option<(u32, &[u8])> {
        let unacked = (self.nxt.wrapping_sub(self.una) as usize).min(self.data().len());
        let end = self.una.wrapping_add(unacked as u32);
        // The scoreboard is sorted and never covers UNA itself (that would
        // be a cumulative ACK), but a range may start right at it.
        let mut seq = self.una;
        let mut hole_end = end;
        for b in &self.sacked {
            if seq_before_eq(b.left, seq) {
                if seq_after(b.right, seq) {
                    seq = b.right;
                }
            } else {
                hole_end = b.left;
                break;
            }
        }
        if !seq_before(seq, end) {
            return None;
        }
        if seq_after(hole_end, end) {
            hole_end = end;
        }
        let from = seq.wrapping_sub(self.una) as usize;
        let len = (hole_end.wrapping_sub(seq) as usize).min(n);
        Some((seq, &self.data()[from..from + len]))
    }

    /// The first data at or after `from` and before `limit` that the
    /// receiver has not SACKed: its sequence number and up to `n` bytes,
    /// stopping where the next SACKed range begins.
    pub fn next_unsacked(&self, from: u32, n: usize, limit: u32) -> Option<(u32, &[u8])> {
        let data = self.data();
        let unacked = (self.nxt.wrapping_sub(self.una) as usize).min(data.len());
        let mut end = self.una.wrapping_add(unacked as u32);
        if seq_before(limit, end) {
            end = limit;
        }
        let mut seq = if seq_before(from, self.una) {
            self.una
        } else {
            from
        };
        let mut hole_end = end;
        for b in &self.sacked {
            if seq_before_eq(b.right, seq) {
                continue;
            }
            if seq_before_eq(b.left, seq) {
                seq = b.right;
            } else {
                if seq_before(b.left, hole_end) {
                    hole_end = b.left;
                }
                break;
            }
        }
        if !seq_before(seq, end) {
            return None;
        }
        let off = seq.wrapping_sub(self.una) as usize;
        let len = (hole_end.wrapping_sub(seq) as usize).min(n);
        Some((seq, &data[off..off + len]))
    }

    /// How many bytes in `from..to` the receiver has SACKed.
    pub fn sacked_between(&self, from: u32, to: u32) -> u32 {
        self.sacked
            .iter()
            .map(|b| {
                let l = if seq_after(b.left, from) {
                    b.left
                } else {
                    from
                };
                let r = if seq_before(b.right, to) { b.right } else { to };
                if seq_after(r, l) {
                    r.wrapping_sub(l)
                } else {
                    0
                }
            })
            .sum()
    }

    /// The first hole at or after `from` that counts as lost, and up to `n`
    /// bytes of it.
    ///
    /// RFC 6675 §4 (IsLost): a hole is lost once more than `lost_after`
    /// bytes above it have been SACKed — with `lost_after = (DupThresh - 1) *
    /// SMSS`, the same evidence three duplicate ACKs give for the first hole.
    /// Holes above the highest SACKed byte are never candidates: nothing yet
    /// says that data is missing rather than still in flight.
    pub fn lost_hole_from(&self, from: u32, n: usize, lost_after: u32) -> Option<(u32, &[u8])> {
        let unacked = (self.nxt.wrapping_sub(self.una) as usize).min(self.data().len());
        let end = self.una.wrapping_add(unacked as u32);
        let from = if seq_before(from, self.una) {
            self.una
        } else {
            from
        };
        let mut sacked_above: u32 = self
            .sacked
            .iter()
            .map(|b| b.right.wrapping_sub(b.left))
            .sum();
        let mut hole_start = self.una;
        for b in &self.sacked {
            // The hole is [hole_start, b.left); `b` and everything after it
            // are SACKed above it.
            let start = if seq_before(hole_start, from) {
                from
            } else {
                hole_start
            };
            let hole_end = if seq_after(b.left, end) { end } else { b.left };
            if seq_before(start, hole_end) && sacked_above > lost_after {
                let off = start.wrapping_sub(self.una) as usize;
                let len = (hole_end.wrapping_sub(start) as usize).min(n);
                return Some((start, &self.data()[off..off + len]));
            }
            sacked_above -= b.right.wrapping_sub(b.left);
            hole_start = b.right;
        }
        None
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data().is_empty()
    }

    #[inline]
    pub fn una(&self) -> u32 {
        self.una
    }

    #[inline]
    pub fn nxt(&self) -> u32 {
        self.nxt
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    #[inline]
    pub fn available(&self) -> usize {
        self.cap.saturating_sub(self.data().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_peek() {
        let mut s = SendBuf::new(100, 1000);
        assert_eq!(s.write(b"hello"), 5);
        assert_eq!(s.pending(), 5);
        assert_eq!(s.peek_unsent(10), b"hello");
        s.advance_sent(5);
        assert_eq!(s.pending(), 0);
        assert_eq!(s.unacked(), 5);
    }

    #[test]
    fn capacity_caps_write() {
        let mut s = SendBuf::new(3, 0);
        assert_eq!(s.write(b"hello"), 3);
        assert_eq!(s.write(b"more"), 0);
    }

    #[test]
    fn acknowledge_frees_bytes() {
        let mut s = SendBuf::new(100, 1000);
        s.write(b"hello world");
        s.advance_sent(11);
        let n = s.acknowledge(1005);
        assert_eq!(n, 5);
        assert_eq!(s.una(), 1005);
        assert_eq!(s.unacked(), 6);
    }

    #[test]
    fn acknowledge_clamps_to_nxt() {
        let mut s = SendBuf::new(100, 1000);
        s.write(b"hi");
        s.advance_sent(2);
        let n = s.acknowledge(9999); // bogus ack way past nxt
        assert_eq!(n, 2);
        assert_eq!(s.una(), 1002);
    }

    #[test]
    fn sack_skips_leading_sacked_range_on_retransmit() {
        // UNA=1000, SACK [1000,1003) — the skip loop should jump to 1003
        // and the retransmit should start at the first hole.
        let mut s = SendBuf::new(100, 1000);
        s.write(b"0123456789");
        s.advance_sent(10);
        s.mark_sacked(&[SackBlock {
            left: 1000,
            right: 1003,
        }]);
        assert_eq!(s.retransmit_data(10), Some((1003, &b"3456789"[..])));
    }

    #[test]
    fn sack_with_hole_at_una_retransmits_only_the_hole() {
        // UNA=1000, SACK is past UNA — there's a hole at UNA so retransmit
        // from UNA, stopping where the receiver's data starts.
        let mut s = SendBuf::new(100, 1000);
        s.write(b"0123456789");
        s.advance_sent(10);
        s.mark_sacked(&[SackBlock {
            left: 1003,
            right: 1006,
        }]);
        assert_eq!(s.retransmit_data(10), Some((1000, &b"012"[..])));
        assert_eq!(s.retransmit_data(2), Some((1000, &b"01"[..])));
    }

    #[test]
    fn sack_blocks_accumulate_and_merge() {
        let mut s = SendBuf::new(100, 0);
        s.write(&[7; 50]);
        s.advance_sent(50);
        let b = |left, right| SackBlock { left, right };
        s.mark_sacked(&[b(30, 35)]);
        s.mark_sacked(&[b(10, 15)]);
        assert!(s.is_sacked(30), "an earlier report is not forgotten");
        s.mark_sacked(&[b(15, 20), b(40, 60)]);
        assert_eq!(s.sacked, vec![b(10, 20), b(30, 35), b(40, 50)]);
        // A cumulative ACK into a range trims it.
        s.acknowledge(12);
        assert_eq!(s.sacked[0], b(12, 20));
        assert_eq!(s.retransmit_data(100), Some((20, &[7u8; 10][..])));
        s.clear_sacked();
        assert_eq!(s.retransmit_data(100), Some((12, &[7u8; 38][..])));
    }

    #[test]
    fn lost_holes_need_enough_sacked_above() {
        let mut s = SendBuf::new(100, 0);
        s.write(&[3; 100]);
        s.advance_sent(100);
        let b = |left, right| SackBlock { left, right };
        // Holes 0..10, 20..30, 40..60; SACKed 10..20, 30..40, 60..70.
        s.mark_sacked(&[b(10, 20), b(30, 40), b(60, 70)]);
        // 30 bytes SACKed above the first hole, 20 above the second, 10
        // above the third.
        assert_eq!(s.lost_hole_from(0, 100, 15).map(|h| h.0), Some(0));
        assert_eq!(s.lost_hole_from(5, 100, 15), Some((5, &[3u8; 5][..])));
        assert_eq!(s.lost_hole_from(10, 100, 15), Some((20, &[3u8; 10][..])));
        assert_eq!(
            s.lost_hole_from(30, 100, 15),
            None,
            "only 10 bytes above 40..60"
        );
        assert_eq!(s.lost_hole_from(30, 100, 5), Some((40, &[3u8; 20][..])));
        assert_eq!(s.lost_hole_from(30, 8, 5), Some((40, &[3u8; 8][..])));
        // Past the highest SACK nothing is known to be lost.
        assert_eq!(s.lost_hole_from(70, 100, 0), None);
    }

    /// A megabyte in flight, ACKed a few bytes at a time: each ACK must
    /// cost what it frees, not a shift of everything still in flight.
    #[test]
    fn small_acks_of_a_full_buffer_are_linear() {
        const CAP: usize = 1 << 20;
        let start = std::time::Instant::now();
        let mut s = SendBuf::new(CAP, 7);
        let data: Vec<u8> = (0..CAP).map(|i| i as u8).collect();
        assert_eq!(s.write(&data), CAP);
        s.advance_sent(CAP);
        let (mut acked, mut refilled) = (0, 0);
        while acked < CAP {
            acked = (acked + 3).min(CAP);
            s.acknowledge(7 + acked as u32);
            // Refill as the ACKs free room, like a busy writer.
            if acked < CAP / 2 {
                assert_eq!(s.write(&[acked as u8; 3]), 3);
                refilled += 3;
            }
            if acked % 3072 == 0 {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(3),
                    "quadratic"
                );
            }
        }
        assert_eq!(s.unacked(), 0);
        assert_eq!(s.pending(), refilled);
        assert_eq!(s.peek_unsent(3), &[3, 3, 3][..]);
        assert_eq!(s.available(), CAP - refilled);
    }

    #[test]
    fn is_lost_counts_ranges_or_bytes_above() {
        let mut s = SendBuf::new(100, 0);
        s.write(&[1; 100]);
        s.advance_sent(100);
        let b = |left, right| SackBlock { left, right };
        assert!(s.mark_sacked(&[b(10, 30)]));
        assert!(!s.mark_sacked(&[b(10, 30)]), "nothing new");
        assert!(!s.is_lost(0, 3, 10), "20 bytes, not more than 20");
        assert!(s.mark_sacked(&[b(10, 31)]));
        assert!(s.is_lost(0, 3, 10), "21 bytes");
        assert!(!s.is_lost(15, 3, 10));
        let mut s = SendBuf::new(100, 0);
        s.write(&[1; 100]);
        s.advance_sent(100);
        s.mark_sacked(&[b(10, 11), b(20, 21), b(30, 31)]);
        assert!(s.is_lost(0, 3, 10), "three discontiguous ranges");
        assert!(!s.is_lost(10, 3, 10));
    }

    #[test]
    fn dsack_below_una_is_ignored() {
        let mut s = SendBuf::new(100, 100);
        s.write(&[1; 10]);
        s.advance_sent(10);
        s.mark_sacked(&[SackBlock {
            left: 90,
            right: 95,
        }]);
        assert_eq!(s.retransmit_data(100), Some((100, &[1u8; 10][..])));
    }

    #[test]
    fn nothing_to_retransmit_once_all_is_sacked() {
        let mut s = SendBuf::new(100, 0);
        s.write(&[1; 10]);
        s.advance_sent(10);
        s.mark_sacked(&[SackBlock { left: 0, right: 10 }]);
        assert_eq!(s.retransmit_data(100), None);
    }
}

//! Sender-side byte buffer with SACK scoreboard.

use super::options::SackBlock;
use super::seqspace::{seq_after, seq_after_eq, seq_before};

/// Tracks application data through the TCP send pipeline:
///
/// ```text
/// [acked] [sent but unacked] [unsent / queued] [free]
///         ^                  ^                 ^
///         una                nxt               tail
/// ```
///
/// `buf[0]` corresponds to sequence `una`. `buf[0..nxt-una)` is in flight;
/// `buf[nxt-una..]` is queued for sending.
#[derive(Debug)]
pub struct SendBuf {
    buf: Vec<u8>,
    cap: usize,
    una: u32,
    nxt: u32,
    sacked: Vec<SackBlock>,
}

impl SendBuf {
    pub fn new(capacity: usize, initial_seq: u32) -> Self {
        Self {
            buf: Vec::new(),
            cap: capacity,
            una: initial_seq,
            nxt: initial_seq,
            sacked: Vec::new(),
        }
    }

    /// Append data, returning the number of bytes accepted.
    pub fn write(&mut self, p: &[u8]) -> usize {
        let avail = self.cap.saturating_sub(self.buf.len());
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
        self.buf.len().saturating_sub(sent)
    }

    /// Sent-but-unacknowledged bytes.
    pub fn unacked(&self) -> usize {
        self.nxt.wrapping_sub(self.una) as usize
    }

    /// Read at most `n` bytes of unsent data without consuming them.
    pub fn peek_unsent(&self, n: usize) -> &[u8] {
        let offset = self.nxt.wrapping_sub(self.una) as usize;
        let unsent = &self.buf[offset.min(self.buf.len())..];
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
        if n as usize > self.buf.len() {
            n = self.buf.len() as u32;
        }
        // O(n) shift; fine for the small payloads we handle, matches Go semantics.
        self.buf.drain(..n as usize);
        self.una = ack;
        self.prune_sack();
        n
    }

    /// Record the latest SACK scoreboard from the receiver.
    pub fn mark_sacked(&mut self, blocks: &[SackBlock]) {
        if blocks.is_empty() {
            return;
        }
        self.sacked.clear();
        self.sacked.reserve(blocks.len());
        for b in blocks {
            if seq_after(b.right, self.una) && seq_before(b.left, self.nxt) {
                self.sacked.push(*b);
            }
        }
    }

    fn prune_sack(&mut self) {
        let una = self.una;
        self.sacked.retain(|b| seq_after(b.right, una));
    }

    /// True iff `seq` lies within any SACK block.
    pub fn is_sacked(&self, seq: u32) -> bool {
        self.sacked
            .iter()
            .any(|b| seq_after_eq(seq, b.left) && seq_before(seq, b.right))
    }

    /// Up to `n` bytes for retransmission starting at UNA, skipping any SACK'd
    /// ranges (RFC 6675-ish — we won't retransmit data the receiver has).
    pub fn retransmit_data(&self, n: usize) -> &[u8] {
        let unacked = (self.nxt.wrapping_sub(self.una) as usize).min(self.buf.len());

        if self.sacked.is_empty() {
            let data = &self.buf[..unacked];
            return if data.len() > n { &data[..n] } else { data };
        }

        // Skip over any SACK blocks starting from UNA.
        let mut seq = self.una;
        let mut changed = true;
        while changed {
            changed = false;
            for b in &self.sacked {
                if seq_after_eq(seq, b.left) && seq_before(seq, b.right) {
                    seq = b.right;
                    changed = true;
                }
            }
        }
        if seq_after_eq(seq, self.nxt) {
            return &[];
        }
        let offset = seq.wrapping_sub(self.una) as usize;
        if offset >= unacked {
            return &[];
        }
        let data = &self.buf[offset..unacked];
        if data.len() > n {
            &data[..n]
        } else {
            data
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
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
        self.cap.saturating_sub(self.buf.len())
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
        let data = s.retransmit_data(10);
        assert_eq!(data, b"3456789");
    }

    #[test]
    fn sack_with_hole_at_una_retransmits_from_una() {
        // UNA=1000, SACK is past UNA — there's a hole at UNA so retransmit from UNA.
        let mut s = SendBuf::new(100, 1000);
        s.write(b"0123456789");
        s.advance_sent(10);
        s.mark_sacked(&[SackBlock {
            left: 1003,
            right: 1006,
        }]);
        let data = s.retransmit_data(10);
        assert_eq!(data, b"0123456789");
    }
}

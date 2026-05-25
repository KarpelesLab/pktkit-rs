//! Receiver-side reassembly buffer with SACK reporting.

use super::options::SackBlock;
use super::seqspace::{seq_after, seq_after_eq, seq_before, seq_before_eq};

/// Cap on the number of out-of-order entries — anti-OOM.
const MAX_OOO_ENTRIES: usize = 128;

#[derive(Debug, Clone)]
struct OooEntry {
    seq: u32,
    data: Vec<u8>,
}

/// Reassembles an incoming TCP byte stream, handling in-order and
/// out-of-order segments. Maintains a SACK scoreboard for reporting.
#[derive(Debug)]
pub struct RecvBuf {
    buf: Vec<u8>,
    nxt: u32,
    ooo: Vec<OooEntry>,
    window_size: usize,
}

impl RecvBuf {
    /// `window_size = 0` disables the receive window entirely.
    pub fn new(initial_nxt: u32, window_size: usize) -> Self {
        Self {
            buf: Vec::new(),
            nxt: initial_nxt,
            ooo: Vec::new(),
            window_size,
        }
    }

    /// Bytes available to advertise. Returns `65535` when unbounded.
    pub fn window(&self) -> u32 {
        if self.window_size == 0 {
            return 65535;
        }
        let mut used = self.buf.len();
        for e in &self.ooo {
            used += e.data.len();
        }
        self.window_size.saturating_sub(used) as u32
    }

    /// Insert `data` at sequence `seq`. Returns the number of new
    /// in-order bytes added (now available via `read`).
    pub fn insert(&mut self, mut seq: u32, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        // Work on a window into the slice that we can shrink.
        let mut start = 0usize;
        let mut end = data.len();
        let mut end_seq = seq.wrapping_add(data.len() as u32);

        // Trim already-received prefix.
        if seq_before(seq, self.nxt) {
            let overlap = self.nxt.wrapping_sub(seq) as usize;
            if overlap >= (end - start) {
                return 0;
            }
            start += overlap;
            seq = self.nxt;
        }

        // Trim past the right edge of the window.
        if self.window_size > 0 {
            let right_edge = self.nxt.wrapping_add(self.window_size as u32);
            if seq_after(end_seq, right_edge) {
                let trim = end_seq.wrapping_sub(right_edge) as usize;
                if trim >= (end - start) {
                    return 0;
                }
                end -= trim;
                end_seq = right_edge;
            }
        }

        let slice = &data[start..end];

        if seq == self.nxt {
            self.buf.extend_from_slice(slice);
            self.nxt = end_seq;
            self.merge_ooo();
            return slice.len();
        }

        if self.ooo.len() < MAX_OOO_ENTRIES {
            self.insert_ooo(seq, slice);
        }
        0
    }

    fn insert_ooo(&mut self, mut seq: u32, data: &[u8]) {
        let mut data: Vec<u8> = data.to_vec();
        let mut end_seq = seq.wrapping_add(data.len() as u32);
        let mut merged: Vec<OooEntry> = Vec::with_capacity(self.ooo.len() + 1);
        let mut inserted = false;
        let existing = std::mem::take(&mut self.ooo);
        for e in existing {
            let e_end = e.seq.wrapping_add(e.data.len() as u32);
            if seq_after_eq(e.seq, end_seq) {
                if !inserted {
                    merged.push(OooEntry {
                        seq,
                        data: data.clone(),
                    });
                    inserted = true;
                }
                merged.push(e);
            } else if seq_after_eq(seq, e_end) {
                merged.push(e);
            } else {
                // Overlap — extend our range to cover e.
                if seq_before(e.seq, seq) {
                    let prefix_len = seq.wrapping_sub(e.seq) as usize;
                    let mut prefix = e.data[..prefix_len].to_vec();
                    prefix.extend_from_slice(&data);
                    data = prefix;
                    seq = e.seq;
                }
                if seq_after(e_end, end_seq) {
                    let extra_start = end_seq.wrapping_sub(e.seq) as usize;
                    data.extend_from_slice(&e.data[extra_start..]);
                    end_seq = e_end;
                }
            }
        }
        if !inserted {
            merged.push(OooEntry { seq, data });
        }
        self.ooo = merged;
    }

    fn merge_ooo(&mut self) {
        loop {
            let mut found = false;
            let existing = std::mem::take(&mut self.ooo);
            let mut remaining: Vec<OooEntry> = Vec::with_capacity(existing.len());
            for e in existing {
                let e_end = e.seq.wrapping_add(e.data.len() as u32);
                if seq_before_eq(e.seq, self.nxt) && seq_after(e_end, self.nxt) {
                    let offset = self.nxt.wrapping_sub(e.seq) as usize;
                    self.buf.extend_from_slice(&e.data[offset..]);
                    self.nxt = e_end;
                    found = true;
                } else if seq_after(e.seq, self.nxt) {
                    remaining.push(e);
                }
                // else: entirely before nxt, discard
            }
            self.ooo = remaining;
            if !found {
                break;
            }
        }
    }

    /// Copy contiguous bytes into `p`, returning the count moved.
    pub fn read(&mut self, p: &mut [u8]) -> usize {
        let n = p.len().min(self.buf.len());
        p[..n].copy_from_slice(&self.buf[..n]);
        self.buf.drain(..n);
        n
    }

    #[inline]
    pub fn readable(&self) -> usize {
        self.buf.len()
    }

    /// RCV.NXT — next expected sequence number.
    #[inline]
    pub fn nxt(&self) -> u32 {
        self.nxt
    }

    /// Bump RCV.NXT by `n`. Used to consume the FIN sequence space.
    pub(crate) fn bump_nxt(&mut self, n: u32) {
        self.nxt = self.nxt.wrapping_add(n);
    }

    /// Up to 3 SACK blocks describing out-of-order data.
    pub fn sack_blocks(&self) -> Vec<SackBlock> {
        let n = self.ooo.len().min(3);
        self.ooo[..n]
            .iter()
            .map(|e| SackBlock {
                left: e.seq,
                right: e.seq.wrapping_add(e.data.len() as u32),
            })
            .collect()
    }

    #[inline]
    pub fn has_ooo(&self) -> bool {
        !self.ooo.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_insert_is_readable() {
        let mut r = RecvBuf::new(1000, 0);
        let n = r.insert(1000, b"hello");
        assert_eq!(n, 5);
        assert_eq!(r.nxt(), 1005);
        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn out_of_order_then_gap_filled() {
        let mut r = RecvBuf::new(1000, 0);
        // Hole at 1000..1005, then 1005..1010
        let n = r.insert(1005, b"world");
        assert_eq!(n, 0); // OOO
        assert!(r.has_ooo());
        // Gap fill — returns only the *new* in-order bytes ("hello"); merged
        // OOO is reflected in nxt() advancing and readable() bytes available.
        let n = r.insert(1000, b"hello");
        assert_eq!(n, 5);
        assert_eq!(r.nxt(), 1010);
        assert!(!r.has_ooo());
        let mut buf = [0u8; 16];
        let read = r.read(&mut buf);
        assert_eq!(&buf[..read], b"helloworld");
    }

    #[test]
    fn duplicate_is_dropped() {
        let mut r = RecvBuf::new(1000, 0);
        r.insert(1000, b"hello");
        let n = r.insert(1000, b"hello"); // exact duplicate
        assert_eq!(n, 0);
    }

    #[test]
    fn sack_blocks_reflect_ooo() {
        let mut r = RecvBuf::new(1000, 0);
        r.insert(1010, b"abcde");
        r.insert(1020, b"fghij");
        let blocks = r.sack_blocks();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].left, 1010);
        assert_eq!(blocks[0].right, 1015);
        assert_eq!(blocks[1].left, 1020);
        assert_eq!(blocks[1].right, 1025);
    }
}

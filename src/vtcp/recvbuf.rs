//! Receiver-side reassembly buffer with SACK reporting.

use std::collections::VecDeque;

use super::options::SackBlock;
use super::seqspace::{seq_after, seq_after_eq, seq_before, seq_before_eq};

/// Cap on the number of out-of-order ranges. Adjacent and overlapping
/// segments merge into one range, so this counts holes in the stream, not
/// segments; the bytes they hold are bounded by the window.
const MAX_OOO_ENTRIES: usize = 128;

/// SACK blocks that fit in the 40 option bytes: four alone (34 bytes), three
/// beside a timestamp option (RFC 2018 §3).
const MAX_SACK_BLOCKS: usize = 4;

/// An out-of-order range. A deque, so that a range can grow at either end
/// for the cost of what is added: segments arriving back to front would
/// otherwise copy the whole range each time.
#[derive(Debug, Clone)]
struct OooEntry {
    seq: u32,
    data: VecDeque<u8>,
}

impl OooEntry {
    #[inline]
    fn end(&self) -> u32 {
        self.seq.wrapping_add(self.data.len() as u32)
    }
}

/// Append `src[skip..]` to `dst`.
fn extend_from_deque(dst: &mut VecDeque<u8>, src: &VecDeque<u8>, skip: usize) {
    let (a, b) = src.as_slices();
    if skip < a.len() {
        dst.extend(&a[skip..]);
        dst.extend(b);
    } else {
        dst.extend(&b[skip - a.len()..]);
    }
}

/// Reassembles an incoming TCP byte stream, handling in-order and
/// out-of-order segments. Maintains a SACK scoreboard for reporting.
#[derive(Debug)]
pub struct RecvBuf {
    /// In-order data not yet read. A ring, so reads and arrivals each cost
    /// only the bytes they move.
    buf: VecDeque<u8>,
    nxt: u32,
    ooo: Vec<OooEntry>,
    /// A sequence number inside each of the most recently extended
    /// out-of-order ranges, newest first. RFC 2018 orders SACK blocks by it.
    recent: Vec<u32>,
    window_size: usize,
}

impl RecvBuf {
    /// `window_size = 0` disables the receive window entirely.
    pub fn new(initial_nxt: u32, window_size: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            nxt: initial_nxt,
            ooo: Vec::new(),
            recent: Vec::new(),
            window_size,
        }
    }

    /// Bytes available to advertise. Returns `65535` when unbounded.
    ///
    /// Only unread in-order data counts against it. Out-of-order data sits
    /// inside the window already, and counting it would pull the right edge
    /// back each time a segment arrives ahead of a loss.
    pub fn window(&self) -> u32 {
        if self.window_size == 0 {
            return 65535;
        }
        self.window_size.saturating_sub(self.buf.len()) as u32
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

        // Trim past the right edge of the window, which also bounds the
        // in-order and out-of-order data together to `window_size`. Without a
        // window, in-order data is taken as it comes, but out-of-order data
        // is still held to the 65535 bytes advertised: nothing else bounds
        // the reassembly queue.
        if self.window_size > 0 || seq != self.nxt {
            let right_edge = self.nxt.wrapping_add(self.window());
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
            self.buf.extend(slice);
            self.nxt = end_seq;
            self.merge_ooo();
            return slice.len();
        }

        self.insert_ooo(seq, slice);
        if self.ooo.len() > MAX_OOO_ENTRIES {
            // Too many holes. Give up the range furthest from RCV.NXT, as
            // Linux's tcp_prune_ofo_queue does: it is the last one the
            // stream will need. Dropping it reneges on anything SACKed
            // there, which RFC 2018 allows; the sender keeps it until it is
            // cumulatively acknowledged.
            self.ooo.pop();
        }
        self.note_recent(seq);
        0
    }

    /// The out-of-order range holding `seq`, if any.
    fn range_of(&self, seq: u32) -> Option<&OooEntry> {
        self.ooo
            .iter()
            .find(|e| seq_before_eq(e.seq, seq) && seq_before(seq, e.end()))
    }

    /// Record that the range holding `seq` was just extended, displacing any
    /// older mark for the same range (ranges merge, so two marks can meet).
    fn note_recent(&mut self, seq: u32) {
        let Some(range) = self.range_of(seq) else {
            return; // pruned as soon as it arrived
        };
        let (left, right) = (range.seq, range.end());
        self.recent
            .retain(|&s| !(seq_before_eq(left, s) && seq_before(s, right)));
        self.recent.insert(0, seq);
        self.recent.truncate(MAX_SACK_BLOCKS);
    }

    /// Add `data` at `seq` to the out-of-order ranges, merging it with any
    /// it overlaps or touches. Ranges that merely touch are merged as well
    /// as overlapping ones: kept apart, every segment arriving behind a
    /// single loss would take an entry of its own.
    ///
    /// The largest range involved absorbs the rest, so each byte already
    /// held is moved only when it joins a larger range, and a segment
    /// extending a range costs its own size, not the range's.
    fn insert_ooo(&mut self, seq: u32, data: &[u8]) {
        let end = seq.wrapping_add(data.len() as u32);
        // Ranges i..j touch [seq, end): sorted and disjoint, so they are
        // consecutive, and the gaps between them lie inside [seq, end).
        let i = self.ooo.partition_point(|e| seq_before(e.end(), seq));
        let mut j = i;
        while j < self.ooo.len() && seq_before_eq(self.ooo[j].seq, end) {
            j += 1;
        }
        if i == j {
            self.ooo.insert(
                i,
                OooEntry {
                    seq,
                    data: data.iter().copied().collect(),
                },
            );
            return;
        }
        let k = (i..j).max_by_key(|&k| self.ooo[k].data.len()).unwrap();
        let mut others: Vec<OooEntry> = self.ooo.drain(i..j).collect();
        let mut base = others.remove(k - i);
        let new_part = |from: u32, to: u32| {
            &data[from.wrapping_sub(seq) as usize..to.wrapping_sub(seq) as usize]
        };

        // Everything left of the base range, gathered in order and then
        // pushed onto its front.
        let (left, right): (Vec<OooEntry>, Vec<OooEntry>) = others
            .into_iter()
            .partition(|e| seq_before(e.seq, base.seq));
        let mut front: VecDeque<u8> = VecDeque::new();
        let mut cursor = if seq_before(seq, base.seq) {
            left.first()
                .map_or(seq, |e| if seq_before(seq, e.seq) { seq } else { e.seq })
        } else {
            base.seq
        };
        let front_start = cursor;
        for e in &left {
            if seq_before(cursor, e.seq) {
                front.extend(new_part(cursor, e.seq));
            }
            front.extend(&e.data);
            cursor = e.end();
        }
        if seq_before(cursor, base.seq) {
            front.extend(new_part(cursor, base.seq));
        }
        for &b in front.iter().rev() {
            base.data.push_front(b);
        }
        base.seq = front_start;

        // Everything right of it, appended.
        let mut cursor = base.end();
        for e in &right {
            if seq_before(cursor, e.seq) {
                base.data.extend(new_part(cursor, e.seq));
            }
            base.data.extend(&e.data);
            cursor = e.end();
        }
        if seq_before(cursor, end) {
            base.data.extend(new_part(cursor, end));
        }
        self.ooo.insert(i, base);
    }

    /// Move whatever out-of-order data now continues the stream into it.
    fn merge_ooo(&mut self) {
        // Sorted, so only the leading ranges can join.
        let mut done = 0;
        while let Some(e) = self.ooo.get(done) {
            if seq_after(e.seq, self.nxt) {
                break;
            }
            if seq_after(e.end(), self.nxt) {
                let offset = self.nxt.wrapping_sub(e.seq) as usize;
                extend_from_deque(&mut self.buf, &e.data, offset);
                self.nxt = e.end();
            }
            // else: entirely before nxt, discard
            done += 1;
        }
        self.ooo.drain(..done);
        let nxt = self.nxt;
        self.recent.retain(|&s| seq_after_eq(s, nxt));
    }

    /// Copy contiguous bytes into `p`, returning the count moved.
    pub fn read(&mut self, p: &mut [u8]) -> usize {
        // VecDeque's Read copies from its two halves and frees the front.
        std::io::Read::read(&mut self.buf, p).unwrap_or(0)
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

    /// Up to 3 SACK blocks describing out-of-order data: as many as fit
    /// beside a timestamp option. See [`sack_blocks_up_to`](Self::sack_blocks_up_to).
    pub fn sack_blocks(&self) -> Vec<SackBlock> {
        self.sack_blocks_up_to(3)
    }

    /// Up to `max` (at most 4) SACK blocks describing out-of-order data,
    /// ordered as RFC 2018 §4 requires: the range holding the most recently
    /// received segment first, then the other recently extended ranges,
    /// newest first. Any room left goes to the ranges nearest RCV.NXT, the
    /// holes to fill first.
    pub fn sack_blocks_up_to(&self, max: usize) -> Vec<SackBlock> {
        let max = max.min(MAX_SACK_BLOCKS);
        let block = |e: &OooEntry| SackBlock {
            left: e.seq,
            right: e.end(),
        };
        let mut out: Vec<SackBlock> = Vec::with_capacity(max);
        let recent = self.recent.iter().filter_map(|&s| self.range_of(s));
        for e in recent.chain(self.ooo.iter()) {
            if out.len() == max {
                break;
            }
            let b = block(e);
            if !out.contains(&b) {
                out.push(b);
            }
        }
        out
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
    fn ooo_data_does_not_shrink_window() {
        let mut r = RecvBuf::new(1000, 100);
        r.insert(1050, &[0u8; 30]);
        assert_eq!(r.window(), 100);
        // The right edge stays at 1100: only 20 bytes past the hole fit.
        r.insert(1080, &[0u8; 40]);
        r.insert(1000, &[0u8; 50]);
        assert_eq!(r.nxt(), 1100);
        assert_eq!(r.readable(), 100);
        assert_eq!(r.window(), 0);
    }

    #[test]
    fn contiguous_segments_behind_a_hole_are_all_kept() {
        // One lost segment followed by a full default window of contiguous
        // ones: far more segments than MAX_OOO_ENTRIES, but a single range.
        const MSS: usize = 1460;
        const SEGS: usize = 700;
        let mut r = RecvBuf::new(0, 1 << 20);
        for i in 1..=SEGS {
            r.insert((i * MSS) as u32, &[i as u8; MSS]);
        }
        assert_eq!(r.sack_blocks().len(), 1, "one contiguous range");
        assert_eq!(r.insert(0, &[0; MSS]), MSS);
        assert_eq!(
            r.nxt(),
            ((SEGS + 1) * MSS) as u32,
            "nothing past the hole was dropped"
        );
        assert!(!r.has_ooo());
    }

    #[test]
    fn adjacent_ranges_merge_from_either_side() {
        let mut r = RecvBuf::new(0, 0);
        r.insert(20, b"cccc"); // 20..24
        r.insert(10, b"aaaaa"); // 10..15, separate
        r.insert(15, b"bbbbb"); // 15..20 joins both neighbours
        assert_eq!(r.sack_blocks().len(), 1);
        assert_eq!(
            (r.sack_blocks()[0].left, r.sack_blocks()[0].right),
            (10, 24)
        );
        r.insert(0, b"0123456789");
        let mut buf = [0u8; 32];
        let n = r.read(&mut buf);
        assert_eq!(&buf[..n], b"0123456789aaaaabbbbbcccc");
    }

    #[test]
    fn too_many_holes_drops_the_furthest_range() {
        let mut r = RecvBuf::new(0, 1 << 20);
        // Every other segment: each one is its own hole.
        for i in 0..=MAX_OOO_ENTRIES {
            r.insert((i * 20 + 10) as u32, &[1; 10]);
        }
        assert_eq!(r.ooo.len(), MAX_OOO_ENTRIES);
        assert_eq!(
            r.ooo.last().unwrap().seq,
            ((MAX_OOO_ENTRIES - 1) * 20 + 10) as u32
        );
        // A segment adjacent to an existing range still gets in.
        r.insert(20, &[1; 10]);
        assert_eq!(r.ooo.len(), MAX_OOO_ENTRIES - 1);
    }

    #[test]
    fn unbounded_mode_holds_ooo_to_the_advertised_window() {
        let mut r = RecvBuf::new(0, 0);
        assert_eq!(r.insert(100, &[1; 70_000]), 0);
        let held: usize = r.ooo.iter().map(|e| e.data.len()).sum();
        assert_eq!(held, 65535 - 100);
        // In-order data is still taken whole.
        assert_eq!(r.insert(0, &[1; 100]), 100);
        assert_eq!(r.nxt(), 65535, "the held range joined the stream");
        assert_eq!(r.insert(r.nxt(), &[1; 100_000]), 100_000);
    }

    #[test]
    fn sack_blocks_lead_with_the_newest_range() {
        let mut r = RecvBuf::new(0, 0);
        for seq in [10, 30, 50, 70] {
            r.insert(seq, b"xxxxx");
        }
        let lefts = |r: &RecvBuf| r.sack_blocks().iter().map(|b| b.left).collect::<Vec<_>>();
        assert_eq!(lefts(&r), vec![70, 50, 30]);
        let four: Vec<u32> = r.sack_blocks_up_to(4).iter().map(|b| b.left).collect();
        assert_eq!(four, vec![70, 50, 30, 10]);
        // Extending an older range makes it the newest; the one it pushed out
        // of the recent list is reported only if room remains.
        r.insert(15, b"yyyyy");
        assert_eq!(lefts(&r), vec![10, 70, 50]);
        assert_eq!(r.sack_blocks()[0].right, 20);
        // Once a range joins the stream it is no longer reported.
        r.insert(0, &[0; 10]);
        assert_eq!(r.nxt(), 20);
        assert_eq!(lefts(&r), vec![70, 50, 30]);
    }

    /// Random segments of one stream, overlapping, reordered and
    /// duplicated: the ranges stay sorted, disjoint and apart, hold the
    /// right bytes, and the stream comes out whole.
    #[test]
    fn random_segments_reassemble() {
        let byte = |seq: u32| (seq.wrapping_mul(31) >> 3) as u8;
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rng = |n: u32| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as u32
        };
        for round in 0..60 {
            let base = (u32::MAX - 3000).wrapping_add(round * 17); // wraps mid-stream
            let mut r = RecvBuf::new(base, 4096);
            let mut out = Vec::new();
            for _ in 0..300 {
                let seq = r.nxt().wrapping_add(rng(5000)).wrapping_sub(200);
                let len = 1 + rng(300);
                let seg: Vec<u8> = (0..len).map(|i| byte(seq.wrapping_add(i))).collect();
                r.insert(seq, &seg);
                if rng(4) == 0 {
                    let mut buf = vec![0; rng(2000) as usize];
                    let n = r.read(&mut buf);
                    out.extend_from_slice(&buf[..n]);
                }
                let mut prev_end: Option<u32> = None;
                for e in &r.ooo {
                    assert!(seq_after(e.seq, r.nxt()));
                    assert!(prev_end.is_none_or(|p| seq_after(e.seq, p)), "{round}");
                    for (i, &b) in e.data.iter().enumerate() {
                        assert_eq!(b, byte(e.seq.wrapping_add(i as u32)), "{round}");
                    }
                    prev_end = Some(e.end());
                }
            }
            let mut buf = vec![0; 1 << 16];
            let n = r.read(&mut buf);
            out.extend_from_slice(&buf[..n]);
            let want: Vec<u8> = (0..out.len() as u32)
                .map(|i| byte(base.wrapping_add(i)))
                .collect();
            assert_eq!(out, want, "round {round}");
        }
    }

    /// Fails as soon as `start` is more than `LIMIT` ago. The work below
    /// takes milliseconds when each segment costs its own size; copying a
    /// whole buffer per segment takes minutes, so the bound is loose.
    fn within_budget(start: std::time::Instant) {
        const LIMIT: std::time::Duration = std::time::Duration::from_secs(3);
        assert!(start.elapsed() < LIMIT, "quadratic: over {LIMIT:?}");
    }

    /// 1-byte segments behind a hole, in order and in reverse: each must
    /// cost about its own size, not a copy of the range it joins.
    #[test]
    fn many_tiny_out_of_order_segments_are_linear() {
        const N: u32 = 500_000;
        let start = std::time::Instant::now();
        let mut r = RecvBuf::new(0, 1 << 20);
        for i in 1..=N {
            r.insert(i, &[i as u8]);
            if i % 1024 == 0 {
                within_budget(start);
            }
        }
        // A second range, arriving back to front.
        for i in (N + 2..=2 * N).rev() {
            r.insert(i, &[i as u8]);
            if i % 1024 == 0 {
                within_budget(start);
            }
        }
        assert_eq!(r.sack_blocks().len(), 2);
        assert_eq!(r.insert(N + 1, &[(N + 1) as u8]), 0);
        assert_eq!(r.insert(0, &[0]), 1);
        assert_eq!(r.nxt(), 2 * N + 1);
        let mut out = vec![0; 2 * N as usize + 1];
        let mut got = 0;
        // Tiny reads too: each must not shift what is left.
        while got < out.len() {
            let n = r.read(&mut out[got..(got + 3).min(2 * N as usize + 1)]);
            assert!(n > 0);
            got += n;
            if got % 3072 == 0 {
                within_budget(start);
            }
        }
        assert!(out.iter().enumerate().all(|(i, &b)| b == i as u8));
    }

    #[test]
    fn sack_blocks_reflect_ooo() {
        let mut r = RecvBuf::new(1000, 0);
        r.insert(1010, b"abcde");
        r.insert(1020, b"fghij");
        // Newest first (RFC 2018 §4), not in sequence order.
        let blocks = r.sack_blocks();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].left, 1020);
        assert_eq!(blocks[0].right, 1025);
        assert_eq!(blocks[1].left, 1010);
        assert_eq!(blocks[1].right, 1015);
    }
}

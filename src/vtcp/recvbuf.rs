//! Receiver-side reassembly buffer with SACK reporting.

use std::collections::{BTreeMap, VecDeque};

use super::options::SackBlock;
use super::sendbuf::KEEP_IDLE_CAPACITY;
use super::seqspace::{seq_after, seq_after_eq, seq_before, seq_before_eq};

/// What an out-of-order range costs beyond the bytes it holds: its entry in
/// the map and its buffer's allocation. Charged against the memory bound,
/// so that a peer sending a byte here and a byte there cannot make the
/// ranges cost many times the window they fit in (Linux charges each
/// segment its skb's truesize for the same reason).
const RANGE_OVERHEAD: usize = 128;

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

    /// What it counts against the memory bound.
    #[inline]
    fn cost(&self) -> usize {
        self.data.len() + RANGE_OVERHEAD
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
    /// RCV.NXT as an offset into the stream, which unlike a sequence
    /// number does not wrap: what the out-of-order ranges are ordered by.
    nxt_off: u64,
    /// Out-of-order ranges by stream offset: sorted, disjoint and apart
    /// (touching ranges are merged), so a segment finds its neighbours in
    /// O(log n) however many holes there are.
    ooo: BTreeMap<u64, OooEntry>,
    /// What the ranges cost together (see [`OooEntry::cost`]).
    ooo_mem: usize,
    /// A sequence number inside each of the most recently extended
    /// out-of-order ranges, newest first. RFC 2018 orders SACK blocks by it.
    recent: Vec<u32>,
    window_size: usize,
    /// The right edge of the window as last advertised, which may lie past
    /// `window_size`: a scaled window is rounded up to a whole unit rather
    /// than pull the edge back (RFC 7323 §2.4), and what the peer was told
    /// it may send must still be taken.
    adv_edge: Option<u32>,
    /// The first range of the last segment that was already here: what the
    /// next ACK reports as a D-SACK (RFC 2883).
    dup: Option<SackBlock>,
}

impl RecvBuf {
    /// `window_size = 0` disables the receive window entirely.
    pub fn new(initial_nxt: u32, window_size: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            nxt: initial_nxt,
            nxt_off: 0,
            ooo: BTreeMap::new(),
            ooo_mem: 0,
            recent: Vec::new(),
            window_size,
            adv_edge: None,
            dup: None,
        }
    }

    /// The buffer size: in-order data not yet read, and the window, fit in
    /// it. Zero if unbounded.
    #[inline]
    pub fn limit(&self) -> usize {
        self.window_size
    }

    /// Resize the buffer. Shrinking it does not pull back an edge already
    /// advertised, which stays open (see [`set_adv_edge`](Self::set_adv_edge)).
    pub fn set_limit(&mut self, limit: usize) {
        self.window_size = limit;
    }

    /// Record the right edge of the window just advertised.
    pub fn set_adv_edge(&mut self, edge: u32) {
        if self.adv_edge.is_none_or(|e| seq_after(edge, e)) {
            self.adv_edge = Some(edge);
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

    /// The most the out-of-order ranges may cost before the furthest are
    /// given up. The bytes they hold lie inside the window, so they never
    /// come to more than the buffer (a unit more, when a scaled window was
    /// rounded up); the other half is for the ranges' overhead, which only
    /// many tiny segments scattered over the window run through. Data sent
    /// as the window allows is therefore never dropped once taken, however
    /// many holes a reordering path leaves in it, as Linux prunes its
    /// out-of-order queue only once past the receive buffer.
    fn ooo_budget(&self) -> usize {
        let w = self.window_size.max(65535);
        w + w / 2
    }

    /// The stream offset of `seq`, which lies within a window of RCV.NXT.
    #[inline]
    fn off(&self, seq: u32) -> u64 {
        self.nxt_off
            .wrapping_add(seq.wrapping_sub(self.nxt) as i32 as i64 as u64)
    }

    /// Insert `data` at sequence `seq`. Returns the number of new
    /// in-order bytes added (now available via `read`).
    pub fn insert(&mut self, mut seq: u32, data: &[u8]) -> usize {
        self.dup = None;
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
            let dup_end = if seq_before(end_seq, self.nxt) {
                end_seq
            } else {
                self.nxt
            };
            self.note_dup(seq, dup_end);
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
            let mut right_edge = self.nxt.wrapping_add(self.window());
            if let Some(adv) = self.adv_edge
                && seq_after(adv, right_edge)
            {
                right_edge = adv;
            }
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
            // Out-of-order data this fills in again was here already.
            if let Some((_, e)) = self.ooo.first_key_value()
                && seq_before(e.seq, end_seq)
            {
                let (l, r) = (e.seq, e.end());
                self.note_dup(l, if seq_before(r, end_seq) { r } else { end_seq });
            }
            self.buf.extend(slice);
            self.nxt = end_seq;
            self.nxt_off += slice.len() as u64;
            self.merge_ooo();
            return slice.len();
        }

        self.insert_ooo(seq, slice);
        // Over the memory bound: give up the ranges furthest from RCV.NXT,
        // as Linux's tcp_prune_ofo_queue does: the stream needs them last.
        // Dropping them reneges on what was SACKed there, which RFC 2018
        // allows; the sender keeps it until it is cumulatively acknowledged.
        let budget = self.ooo_budget();
        while self.ooo_mem > budget {
            let Some((_, e)) = self.ooo.pop_last() else {
                break;
            };
            self.ooo_mem -= e.cost();
        }
        self.note_recent(seq);
        0
    }

    /// Record `[left, right)` as received twice, unless a range already
    /// is: RFC 2883 §4 reports the first duplicate a segment brought.
    fn note_dup(&mut self, left: u32, right: u32) {
        if self.dup.is_none() && seq_before(left, right) {
            self.dup = Some(SackBlock { left, right });
        }
    }

    /// The range of the last segment taken in that was here already, for
    /// a D-SACK (RFC 2883), if it had one; forgotten once taken.
    pub fn take_dup(&mut self) -> Option<SackBlock> {
        self.dup.take()
    }

    /// The out-of-order range holding `left..right`, as a SACK block.
    pub fn sack_block_around(&self, left: u32, right: u32) -> Option<SackBlock> {
        let e = self.range_of(left)?;
        seq_before_eq(right, e.end()).then(|| SackBlock {
            left: e.seq,
            right: e.end(),
        })
    }

    /// The out-of-order range holding `seq`, if any.
    fn range_of(&self, seq: u32) -> Option<&OooEntry> {
        if !seq_after(seq, self.nxt) {
            return None;
        }
        // Sorted and disjoint: the last range starting at or before `seq`
        // is the only one that can hold it.
        let (_, e) = self.ooo.range(..=self.off(seq)).next_back()?;
        seq_before(seq, e.end()).then_some(e)
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
        let (lo, hi) = (self.off(seq), self.off(end));
        // The ranges touching [seq, end): the one starting at or before it,
        // if it reaches that far, and any starting inside it or at its end.
        let mut keys: Vec<u64> = Vec::new();
        if let Some((&k, e)) = self.ooo.range(..=lo).next_back()
            && k + e.data.len() as u64 >= lo
        {
            keys.push(k);
        }
        keys.extend(self.ooo.range(lo + 1..=hi).map(|(&k, _)| k));
        if keys.is_empty() {
            let e = OooEntry {
                seq,
                data: data.iter().copied().collect(),
            };
            self.ooo_mem += e.cost();
            self.ooo.insert(lo, e);
            return;
        }
        let mut touching: Vec<OooEntry> = Vec::with_capacity(keys.len());
        for k in keys {
            let e = self.ooo.remove(&k).expect("key just found");
            self.ooo_mem -= e.cost();
            touching.push(e);
        }
        for e in &touching {
            let l = if seq_after(e.seq, seq) { e.seq } else { seq };
            let r = if seq_before(e.end(), end) {
                e.end()
            } else {
                end
            };
            if seq_before(l, r) {
                self.note_dup(l, r);
                break;
            }
        }
        let k = (0..touching.len())
            .max_by_key(|&k| touching[k].data.len())
            .unwrap();
        let mut base = touching.remove(k);
        let new_part = |from: u32, to: u32| {
            &data[from.wrapping_sub(seq) as usize..to.wrapping_sub(seq) as usize]
        };

        // Everything left of the base range, gathered in order and then
        // pushed onto its front.
        let (left, right): (Vec<OooEntry>, Vec<OooEntry>) = touching
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
        self.ooo_mem += base.cost();
        self.ooo.insert(self.off(base.seq), base);
    }

    /// Move whatever out-of-order data now continues the stream into it.
    fn merge_ooo(&mut self) {
        // Sorted, so only the leading ranges can join.
        while let Some(entry) = self.ooo.first_entry() {
            if *entry.key() > self.nxt_off {
                break;
            }
            let e = entry.remove();
            self.ooo_mem -= e.cost();
            if seq_after(e.end(), self.nxt) {
                let offset = self.nxt.wrapping_sub(e.seq) as usize;
                extend_from_deque(&mut self.buf, &e.data, offset);
                self.nxt_off += u64::from(e.end().wrapping_sub(self.nxt));
                self.nxt = e.end();
            }
            // else: entirely before nxt, discard
        }
        let nxt = self.nxt;
        self.recent.retain(|&s| seq_after_eq(s, nxt));
    }

    /// Copy contiguous bytes into `p`, returning the count moved.
    pub fn read(&mut self, p: &mut [u8]) -> usize {
        // VecDeque's Read copies from its two halves and frees the front.
        let n = std::io::Read::read(&mut self.buf, p).unwrap_or(0);
        // Emptied, a large ring goes: an idle connection would otherwise
        // pin its peak (up to the whole window) for as long as it lives.
        // A small one stays for the next segments to reuse.
        if self.buf.is_empty() && self.buf.capacity() > KEEP_IDLE_CAPACITY {
            self.buf = VecDeque::new();
        }
        n
    }

    /// Free what the connection no longer needs once no more data can
    /// arrive (TIME-WAIT, CLOSED): the out-of-order ranges, and the
    /// in-order data too unless it is still to be read (`keep_unread`).
    pub fn release_memory(&mut self, keep_unread: bool) {
        self.ooo = BTreeMap::new();
        self.ooo_mem = 0;
        self.recent = Vec::new();
        if !keep_unread || self.buf.is_empty() {
            self.buf = VecDeque::new();
        }
    }

    /// Bytes allocated for data, in order and out of order.
    #[cfg(test)]
    pub fn allocated(&self) -> usize {
        self.buf.capacity() + self.ooo.values().map(|e| e.data.capacity()).sum::<usize>()
    }

    /// In-order bytes waiting to be read.
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
        self.nxt_off += u64::from(n);
    }

    /// Up to 3 SACK blocks describing out-of-order data: as many as fit
    /// beside a timestamp option. See [`sack_blocks_up_to`](Self::sack_blocks_up_to).
    #[cfg(test)]
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
        for e in recent.chain(self.ooo.values()) {
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

    /// True if out-of-order data is held beyond a hole.
    #[inline]
    pub fn has_ooo(&self) -> bool {
        !self.ooo.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_to_empty_frees_a_large_ring() {
        let mut r = RecvBuf::new(0, 1 << 20);
        assert_eq!(r.insert(0, &vec![1; 1 << 20]), 1 << 20);
        let mut out = vec![0; 1 << 19];
        assert_eq!(r.read(&mut out), 1 << 19);
        assert!(r.buf.capacity() >= 1 << 19, "freed with data unread");
        assert_eq!(r.read(&mut out), 1 << 19);
        assert!(r.buf.capacity() <= KEEP_IDLE_CAPACITY, "idle ring kept");

        // A small one is kept for reuse.
        r.insert(1 << 20, &[2; 1000]);
        let cap = r.buf.capacity();
        assert_eq!(r.read(&mut out), 1000);
        assert_eq!(r.buf.capacity(), cap);
    }

    #[test]
    fn release_memory_keeps_only_unread_data() {
        let mut r = RecvBuf::new(0, 1 << 20);
        r.insert(0, b"unread");
        r.insert(100, &[3; 5000]);
        r.release_memory(true);
        assert!(!r.has_ooo());
        let mut out = [0; 16];
        assert_eq!(r.read(&mut out), 6);
        assert_eq!(&out[..6], b"unread");
        r.insert(6, b"more");
        r.release_memory(false);
        assert_eq!((r.readable(), r.allocated()), (0, 0));
    }

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
        // ones: hundreds of segments, but a single range.
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

    /// A reordering path at a large window leaves thousands of holes:
    /// everything the window let in is kept, SACKed and later delivered,
    /// however many there are.
    #[test]
    fn thousands_of_holes_within_the_window_are_kept() {
        const MSS: usize = 1460;
        const WINDOW: usize = 16 << 20;
        let mut r = RecvBuf::new(u32::MAX - 5000, WINDOW);
        let base = r.nxt();
        let segs = WINDOW / MSS;
        // Every other segment first, back to front for good measure: each
        // is a hole of its own, about 5700 of them.
        for i in (1..segs).step_by(2).rev() {
            let seq = base.wrapping_add((i * MSS) as u32);
            r.insert(seq, &[i as u8; MSS]);
        }
        assert_eq!(r.ooo.len(), segs / 2);
        let first = r.sack_blocks_up_to(4)[0];
        assert_eq!(first.left, base.wrapping_add(MSS as u32), "newest first");
        // Then the rest: all of it comes out in order.
        for i in (0..segs).step_by(2) {
            let seq = base.wrapping_add((i * MSS) as u32);
            r.insert(seq, &[i as u8; MSS]);
        }
        assert!(!r.has_ooo());
        assert_eq!(r.ooo_mem, 0);
        assert_eq!(r.readable(), segs * MSS);
        let mut out = vec![0; segs * MSS];
        assert_eq!(r.read(&mut out), segs * MSS);
        assert!(out.chunks(MSS).enumerate().all(|(i, c)| c[0] == i as u8));
    }

    /// Past the memory bound, which only ranges far smaller than a segment
    /// reach, the ranges furthest out are given up, and the rest stays.
    #[test]
    fn scattered_tiny_segments_are_pruned_from_the_far_end() {
        let window = 1 << 16;
        let mut r = RecvBuf::new(0, window);
        // A byte in every 20: the ranges' overhead far outweighs the data.
        for i in 0..window / 20 {
            r.insert((i * 20 + 10) as u32, &[1]);
            assert!(r.ooo_mem <= r.ooo_budget());
        }
        let kept = r.ooo.len();
        assert!(kept < window / 20, "nothing pruned");
        assert!(kept > 100, "pruned too much: {kept}");
        // The nearest ranges are the ones kept.
        let (_, last) = r.ooo.last_key_value().unwrap();
        assert_eq!(last.seq, ((kept - 1) * 20 + 10) as u32);
        // A segment joining two kept ranges still gets in, and costs less.
        let before = r.ooo_mem;
        r.insert(11, &[1; 19]);
        assert_eq!(r.ooo.len(), kept - 1);
        assert!(r.ooo_mem < before);
    }

    #[test]
    fn unbounded_mode_holds_ooo_to_the_advertised_window() {
        let mut r = RecvBuf::new(0, 0);
        assert_eq!(r.insert(100, &[1; 70_000]), 0);
        let held: usize = r.ooo.values().map(|e| e.data.len()).sum();
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
                for e in r.ooo.values() {
                    assert!(seq_after(e.seq, r.nxt()));
                    assert!(prev_end.is_none_or(|p| seq_after(e.seq, p)), "{round}");
                    for (i, &b) in e.data.iter().enumerate() {
                        assert_eq!(b, byte(e.seq.wrapping_add(i as u32)), "{round}");
                    }
                    prev_end = Some(e.end());
                }
                for (&k, e) in &r.ooo {
                    assert_eq!(k, r.off(e.seq), "{round}: keyed by offset");
                }
                let cost: usize = r.ooo.values().map(OooEntry::cost).sum();
                assert_eq!(cost, r.ooo_mem, "{round}: memory accounted");
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

    /// Whatever part of a segment was here already is reported for a
    /// D-SACK: below RCV.NXT, inside an out-of-order range, or both.
    #[test]
    fn duplicates_are_reported_for_dsack() {
        let b = |left, right| Some(SackBlock { left, right });
        let mut r = RecvBuf::new(1000, 0);
        r.insert(1000, &[1; 100]);
        assert_eq!(r.take_dup(), None);
        r.insert(950, &[1; 100]);
        assert_eq!(r.take_dup(), b(950, 1050), "an old segment");
        assert_eq!(r.take_dup(), None, "taken once");
        r.insert(1050, &[1; 100]);
        assert_eq!(r.take_dup(), b(1050, 1100), "partly old");
        r.insert(1300, &[1; 100]);
        r.insert(1350, &[1; 100]);
        assert_eq!(r.take_dup(), b(1350, 1400), "partly held out of order");
        assert_eq!(r.sack_block_around(1350, 1400), b(1300, 1450));
        r.insert(1310, &[1; 20]);
        assert_eq!(r.take_dup(), b(1310, 1330));
        r.insert(1150, &[1; 200]);
        assert_eq!(r.take_dup(), b(1300, 1350), "filling the hole, and past it");
        assert_eq!(r.nxt(), 1450);
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

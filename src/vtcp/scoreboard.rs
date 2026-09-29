//! The sender's scoreboard (RFC 6675 §3): every segment sent and not yet
//! cumulatively acknowledged, whether the receiver has SACKed it, whether
//! it is deemed lost, and when it was last sent. RACK (RFC 8985 §6) reads
//! losses off it by time: a segment is lost once one sent after it has been
//! delivered and a reordering window has passed since.
//!
//! Sequence numbers wrap; inside, positions are 64-bit offsets into the
//! stream, which do not.

use std::collections::{BTreeSet, VecDeque};
use std::time::Duration;

use crate::time::Instant;

use super::options::SackBlock;
use super::rate::{Rate, RateSample, TxState};
use super::seqspace::{seq_after, seq_before, seq_before_eq};

const SACKED: u8 = 1;
const LOST: u8 = 2;
/// Retransmitted at least once (RFC 8985's `Segment.retransmitted`).
const RETRANS: u8 = 4;
const FIN: u8 = 8;

/// DupThresh (RFC 6675 §2): SACKed segments that show a loss without
/// waiting out the reordering window, while no reordering has been seen.
pub(crate) const DUP_THRESH: u32 = 3;

/// How long the minimum RTT is remembered: Linux's `tcp_min_rtt_wlen`. A
/// windowed minimum lets it grow when the connection moves to a longer
/// path (RFC 8985 §6.2 step 1).
const MIN_RTT_WINDOW: u64 = 300_000_000_000;

/// Reordering windows kept inflated after a D-SACK (RFC 8985 §6.2 step 4).
const REO_WND_PERSIST: u32 = 16;

/// Records a SACK may split the scoreboard into beyond two per MSS in
/// flight: rounding to whole MSS keeps an honest receiver well under that,
/// so only a peer SACKing odd bytes to fragment the scoreboard meets it.
const SPLIT_SLACK: u64 = 64;

/// A segment, as last sent. The pieces of a split segment share `tx`.
#[derive(Debug, Clone, Copy)]
struct Seg {
    start: u64,
    end: u64,
    /// When it was last sent: nanoseconds since the scoreboard's epoch.
    xmit: u64,
    /// The TSval it last carried.
    tsval: u32,
    /// Which transmission that was.
    tx: u64,
    flags: u8,
    /// The delivery state it went out with, for rate samples.
    rate: TxState,
}

impl Seg {
    #[inline]
    fn len(&self) -> u64 {
        self.end - self.start
    }
    #[inline]
    fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// A transmission, queued in the order they happened: the list ordered by
/// transmission time that RFC 8985 §6.2 suggests, so that loss detection
/// looks only at what was sent before RACK.segment rather than at the
/// whole scoreboard. Entries go stale when their segments are delivered,
/// marked lost or sent again, and are dropped when a scan passes them.
#[derive(Debug, Clone, Copy)]
struct TxRec {
    start: u64,
    end: u64,
    xmit: u64,
    tx: u64,
}

/// Kathleen Nichols' windowed minimum, as Linux's `lib/minmax.c`: the best
/// of three samples spread over the window.
#[derive(Debug, Default, Clone, Copy)]
struct WindowedMin {
    s: [(u64, u64); 3],
    set: bool,
}

impl WindowedMin {
    fn update(&mut self, win: u64, t: u64, v: u64) -> u64 {
        let val = (t, v);
        if !self.set || v <= self.s[0].1 || t.saturating_sub(self.s[2].0) > win {
            self.s = [val; 3];
            self.set = true;
            return v;
        }
        if v <= self.s[1].1 {
            self.s[1] = val;
            self.s[2] = val;
        } else if v <= self.s[2].1 {
            self.s[2] = val;
        }
        let dt = t.saturating_sub(self.s[0].0);
        if dt > win {
            self.s = [self.s[1], self.s[2], val];
            if t.saturating_sub(self.s[0].0) > win {
                self.s = [self.s[1], self.s[2], val];
            }
        } else if self.s[1].0 == self.s[0].0 && dt > win / 4 {
            self.s[1] = val;
            self.s[2] = val;
        } else if self.s[2].0 == self.s[1].0 && dt > win / 2 {
            self.s[2] = val;
        }
        self.s[0].1
    }

    fn get(&self) -> Option<u64> {
        self.set.then_some(self.s[0].1)
    }
}

/// RACK's per-connection state (RFC 8985 §5.3).
#[derive(Debug)]
struct Rack {
    /// RACK.segment exists: something has been delivered.
    valid: bool,
    xmit: u64,
    end: u64,
    rtt: u64,
    /// The newest transmission RACK.rtt was taken from in this ACK: step 2
    /// walks the delivered segments oldest first, so the last one counts.
    rtt_from: Option<u64>,
    fack: u64,
    reordering_seen: bool,
    /// Segments delivered out of order, for `TcpInfo`.
    reordered: u64,
    reo_wnd_mult: u32,
    reo_wnd_persist: u32,
    dsack_round: Option<u64>,
    min_rtt: WindowedMin,
}

/// What an ACK told the scoreboard.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Delivery {
    /// Bytes newly delivered, cumulatively or selectively, and not SACKed
    /// before: RFC 6937's DeliveredData.
    pub delivered: u32,
    /// The lowest end among newly delivered segments never retransmitted:
    /// data that reached the receiver in its original transmission.
    pub orig_min_end: Option<u32>,
    /// The highest end among newly delivered segments.
    pub max_end: Option<u32>,
}

impl Delivery {
    fn note(&mut self, bytes: u64, end: u32, original: bool) {
        self.delivered = self.delivered.saturating_add(bytes as u32);
        if original && self.orig_min_end.is_none_or(|e| seq_before(end, e)) {
            self.orig_min_end = Some(end);
        }
        if self.max_end.is_none_or(|e| seq_after(end, e)) {
            self.max_end = Some(end);
        }
    }

    /// Fold in what another part of the same ACK reported.
    pub(crate) fn merge(&mut self, o: Delivery) {
        self.delivered = self.delivered.saturating_add(o.delivered);
        if let Some(e) = o.orig_min_end
            && self.orig_min_end.is_none_or(|m| seq_before(e, m))
        {
            self.orig_min_end = Some(e);
        }
        if let Some(e) = o.max_end
            && self.max_end.is_none_or(|m| seq_after(e, m))
        {
            self.max_end = Some(e);
        }
    }
}

/// A segment to (re)send: its sequence number, its length (1 for a FIN)
/// and whether it is the FIN.
pub(crate) type SegRef = (u32, u32, bool);

/// The scoreboard. Its segments tile the sequence space from SND.UNA to
/// the last byte sent, FIN included; a SYN is never on it.
#[derive(Debug)]
pub(crate) struct Scoreboard {
    segs: VecDeque<Seg>,
    una: u32,
    una_off: u64,
    sacked: u64,
    sacked_segs: u32,
    lost: u64,
    /// Starts of the segments marked lost and not sent since, which are
    /// what retransmission goes through, lowest first.
    lost_set: BTreeSet<u64>,
    /// Keep the transmission queue: only RACK reads it.
    rack_on: bool,
    tq: VecDeque<TxRec>,
    next_tx: u64,
    epoch: Instant,
    rack: Rack,
    /// The previous ACK's SACK blocks. Everything in them is SACKed
    /// already, so a block repeated, or grown by a segment, costs only
    /// what is new in it, not a walk over the whole range again (Linux's
    /// `recv_sack_cache`).
    sack_cache: Vec<(u64, u64)>,
    /// Delivery rate estimation.
    rate: Rate,
    /// The MSS, which SACKs split segments in multiples of.
    mss: u64,
    /// Segments marked lost since last taken, with their size, for a
    /// controller that reacts to each loss (BBR); `None` when none does.
    lost_log: Option<Vec<(TxState, u32)>>,
}

impl Scoreboard {
    /// An empty scoreboard, with SND.UNA at `una`.
    pub fn new(una: u32, now: Instant) -> Self {
        Self {
            segs: VecDeque::new(),
            una,
            una_off: 0,
            sacked: 0,
            sacked_segs: 0,
            lost: 0,
            lost_set: BTreeSet::new(),
            rack_on: false,
            tq: VecDeque::new(),
            next_tx: 0,
            epoch: now,
            rack: Rack {
                valid: false,
                xmit: 0,
                end: 0,
                rtt: 0,
                rtt_from: None,
                fack: 0,
                reordering_seen: false,
                reordered: 0,
                reo_wnd_mult: 1,
                reo_wnd_persist: 0,
                dsack_round: None,
                min_rtt: WindowedMin::default(),
            },
            sack_cache: Vec::new(),
            rate: Rate::default(),
            mss: u64::from(super::options::MIN_MSS),
            lost_log: None,
        }
    }

    /// The MSS segments go out at: a SACK splits a segment only in whole
    /// multiples of it.
    pub fn set_mss(&mut self, mss: u32) {
        self.mss = u64::from(mss.max(1));
    }

    /// Run RACK (it needs SACK, RFC 8985 §4).
    pub fn set_rack(&mut self, on: bool) {
        self.rack_on = on;
        if !on {
            self.tq = VecDeque::new();
        }
    }

    #[inline]
    fn ns(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_nanos() as u64
    }

    #[inline]
    fn off(&self, seq: u32) -> u64 {
        self.una_off + u64::from(seq.wrapping_sub(self.una))
    }

    #[inline]
    fn seq_of(&self, off: u64) -> u32 {
        if off >= self.una_off {
            self.una.wrapping_add((off - self.una_off) as u32)
        } else {
            self.una.wrapping_sub((self.una_off - off) as u32)
        }
    }

    #[inline]
    fn end_off(&self) -> u64 {
        self.segs.back().map_or(self.una_off, |s| s.end)
    }

    /// The sequence number after the last one sent.
    #[inline]
    pub fn end_seq(&self) -> u32 {
        self.seq_of(self.end_off())
    }

    /// Nothing is outstanding.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }

    /// RFC 6675's pipe: bytes sent and still in the network, neither
    /// SACKed nor deemed lost (a lost segment sent again is back in it).
    #[inline]
    pub fn pipe(&self) -> u32 {
        (self.end_off() - self.una_off - self.sacked - self.lost) as u32
    }

    /// RACK.segs_sacked.
    #[inline]
    pub fn sacked_segs(&self) -> u32 {
        self.sacked_segs
    }

    #[inline]
    pub fn lost_bytes(&self) -> u32 {
        self.lost as u32
    }

    /// Bytes SACKed above SND.UNA.
    #[inline]
    pub fn sacked_bytes(&self) -> u32 {
        self.sacked as u32
    }

    /// RACK's windowed minimum RTT.
    pub fn min_rtt(&self) -> Option<Duration> {
        self.rack.min_rtt.get().map(Duration::from_nanos)
    }

    /// Segments found delivered out of order so far.
    #[inline]
    pub fn reordered(&self) -> u64 {
        self.rack.reordered
    }

    /// Carry the count of [`reordered`](Self::reordered) segments over
    /// from a scoreboard this one replaces.
    pub fn inherit_reordered(&mut self, n: u64) {
        self.rack.reordered = n;
    }

    /// Index of the segment holding `off`.
    fn idx(&self, off: u64) -> Option<usize> {
        let i = self.segs.partition_point(|s| s.end <= off);
        (i < self.segs.len() && self.segs[i].start <= off).then_some(i)
    }

    /// Cut segment `i` in two at `at`, strictly inside it.
    fn split(&mut self, i: usize, at: u64) {
        let mut second = self.segs[i];
        debug_assert!(second.start < at && at < second.end);
        second.start = at;
        self.segs[i].end = at;
        if second.has(LOST) {
            self.lost_set.insert(at);
        }
        if second.has(SACKED) {
            self.sacked_segs += 1;
        }
        self.segs.insert(i + 1, second);
    }

    /// Whether segment `i` and the next one can be sent as one: pieces of
    /// one transmission, data, neither SACKed, and both deemed lost or
    /// both not. Segments sent apart stay apart: an MTU probe resent with
    /// what went before it would no longer show which of them was lost.
    fn mergeable(&self, i: usize) -> bool {
        let (Some(a), Some(b)) = (self.segs.get(i), self.segs.get(i + 1)) else {
            return false;
        };
        let (fa, fb) = (
            a.flags & (SACKED | LOST | FIN),
            b.flags & (SACKED | LOST | FIN),
        );
        a.tx == b.tx && fa == fb && fa & (SACKED | FIN) == 0
    }

    /// Join segment `i` and the next, which are [`mergeable`](Self::mergeable),
    /// for a retransmission covering both: what each last went out as is
    /// about to be replaced.
    fn merge_next(&mut self, i: usize) {
        let b = self.segs.remove(i + 1).unwrap();
        if b.has(LOST) {
            self.lost_set.remove(&b.start);
        }
        let a = &mut self.segs[i];
        a.end = b.end;
        a.flags |= b.flags & RETRANS;
    }

    fn push_tx(&mut self, start: u64, end: u64, xmit: u64, tx: u64) {
        if self.rack_on {
            self.tq.push_back(TxRec {
                start,
                end,
                xmit,
                tx,
            });
        }
    }

    /// New data, `[seq, seq+len)`, or the FIN at `seq`, went out at `now`
    /// carrying `tsval` (RFC 8985 §6.1).
    pub fn on_send(&mut self, seq: u32, len: u32, fin: bool, now: Instant, tsval: u32) {
        let len = if fin { 1 } else { len };
        if len == 0 {
            return;
        }
        let start = self.off(seq);
        debug_assert_eq!(start, self.end_off(), "sent out of order");
        let xmit = self.ns(now);
        let tx = self.next_tx;
        self.next_tx += 1;
        let rate = self.rate.on_send(xmit, self.pipe(), len);
        self.segs.push_back(Seg {
            start,
            end: start + u64::from(len),
            xmit,
            tsval,
            tx,
            flags: if fin { FIN } else { 0 },
            rate,
        });
        self.push_tx(start, start + u64::from(len), xmit, tx);
    }

    /// `[seq, seq+len)`, the start of a segment, was sent again at `now`
    /// carrying `tsval`: what is left of the segment past `len` stays as it
    /// was (RFC 8985 §6.1).
    pub fn on_retransmit(&mut self, seq: u32, len: u32, now: Instant, tsval: u32) {
        let start = self.off(seq);
        let Some(mut i) = self.idx(start) else {
            return;
        };
        if self.segs[i].start < start {
            self.split(i, start);
            i += 1;
        }
        let end = start + u64::from(len.max(1));
        // Pieces going out as one segment become one record again, as
        // [`next_lost`](Self::next_lost) put them together.
        while self.segs[i].end < end && self.mergeable(i) {
            self.merge_next(i);
        }
        if end < self.segs[i].end && !self.segs[i].has(FIN) {
            self.split(i, end);
        }
        let xmit = self.ns(now);
        let tx = self.next_tx;
        self.next_tx += 1;
        let s = &mut self.segs[i];
        let (s_start, s_end) = (s.start, s.end);
        if s.has(LOST) {
            s.flags &= !LOST;
            self.lost -= s_end - s_start;
            self.lost_set.remove(&s_start);
        }
        // In flight again, itself included (unless SACKed meanwhile).
        let len = (s_end - s_start) as u32;
        let rate = self
            .rate
            .on_send(xmit, self.pipe().saturating_sub(len), len);
        let s = &mut self.segs[i];
        s.flags |= RETRANS;
        s.xmit = xmit;
        s.tsval = tsval;
        s.tx = tx;
        s.rate = rate;
        self.push_tx(s_start, s_end, xmit, tx);
    }

    /// Start of an ACK's processing.
    pub fn begin_ack(&mut self) {
        self.rack.rtt_from = None;
    }

    /// RACK steps 2 and 3 (RFC 8985 §6.2) for a segment just delivered.
    fn rack_delivered(&mut self, s: &Seg, now: u64, ecr: Option<u32>) {
        let retrans = s.has(RETRANS);
        // Step 3: an original delivered below the forward-most delivery
        // arrived out of order. Segments go by in ascending order within
        // each call, and ACKed ones come before SACKed ones.
        if s.end > self.rack.fack {
            self.rack.fack = s.end;
        } else if s.end < self.rack.fack && !retrans {
            self.rack.reordering_seen = true;
            self.rack.reordered += 1;
        }
        let rtt = now.saturating_sub(s.xmit);
        if retrans {
            // Which transmission arrived is ambiguous: not the last one if
            // the echo is older than it, nor one sent less than a minimum
            // RTT ago.
            if ecr.is_some_and(|e| (e.wrapping_sub(s.tsval) as i32) < 0) {
                return;
            }
            if self.rack.min_rtt.get().is_some_and(|m| rtt < m) {
                return;
            }
        }
        if self.rack.rtt_from.is_none_or(|x| s.xmit >= x) {
            self.rack.rtt = rtt;
            self.rack.rtt_from = Some(s.xmit);
        }
        if !self.rack.valid || sent_after(s.xmit, s.end, self.rack.xmit, self.rack.end) {
            self.rack.valid = true;
            self.rack.xmit = s.xmit;
            self.rack.end = s.end;
        }
    }

    /// Cumulative ACK up to `ack`, at `now`, echoing `ecr` if timestamps
    /// are on.
    pub fn ack(&mut self, ack: u32, now: Instant, ecr: Option<u32>) -> Delivery {
        let mut d = Delivery::default();
        if !seq_after(ack, self.una) {
            return d;
        }
        let ack_off = self.off(ack);
        let now = self.ns(now);
        while let Some(&front) = self.segs.front() {
            if front.end <= ack_off {
                self.segs.pop_front();
                if front.has(LOST) {
                    self.lost -= front.len();
                    self.lost_set.remove(&front.start);
                }
                if front.has(SACKED) {
                    self.sacked -= front.len();
                    self.sacked_segs -= 1;
                } else {
                    let end = self.seq_of(front.end);
                    d.note(front.len(), end, !front.has(RETRANS));
                    self.rate
                        .on_delivered(&front.rate, front.xmit, front.end, front.len(), now);
                    self.rack_delivered(&front, now, ecr);
                }
            } else {
                if front.start < ack_off {
                    // Part of a segment: delivered bytes, but the segment
                    // as RACK sees it is not in until all of it is.
                    let cut = ack_off - front.start;
                    let f = &mut self.segs[0];
                    f.start = ack_off;
                    if f.has(SACKED) {
                        self.sacked -= cut;
                    } else {
                        d.delivered = d.delivered.saturating_add(cut as u32);
                        self.rate.on_partial(cut);
                    }
                    if f.has(LOST) {
                        self.lost -= cut;
                        self.lost_set.remove(&front.start);
                        self.lost_set.insert(ack_off);
                    }
                }
                break;
            }
        }
        // An ACK past what was recorded covers a SYN.
        self.una = ack;
        self.una_off = ack_off;
        d
    }

    /// The SACK blocks of an ACK (a D-SACK block left out), at `now`.
    pub fn sack(&mut self, blocks: &[SackBlock], now: Instant, ecr: Option<u32>) -> Delivery {
        let mut d = Delivery::default();
        let end_seq = self.end_seq();
        let end_off = self.end_off();
        let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(blocks.len());
        for b in blocks {
            // Clip to what is in flight; anything wholly outside is stale
            // or bogus.
            if !seq_after(b.right, self.una) || !seq_before(b.left, end_seq) {
                continue;
            }
            let l = if seq_before(b.left, self.una) {
                self.una_off
            } else {
                self.off(b.left)
            };
            let r = if seq_after(b.right, end_seq) {
                end_off
            } else {
                self.off(b.right)
            };
            if l < r {
                ranges.push((l, r));
            }
        }
        ranges.sort_unstable();
        let now_ns = self.ns(now);
        let cache = std::mem::take(&mut self.sack_cache);
        for &(l, r) in &ranges {
            // What the previous ACK's blocks did not already cover.
            let mut parts = vec![(l, r)];
            for &(cl, cr) in &cache {
                let mut next = Vec::with_capacity(parts.len() + 1);
                for (pl, pr) in parts {
                    if cr <= pl || pr <= cl {
                        next.push((pl, pr));
                        continue;
                    }
                    if pl < cl {
                        next.push((pl, cl));
                    }
                    if cr < pr {
                        next.push((cr, pr));
                    }
                }
                parts = next;
            }
            for (pl, pr) in parts {
                self.mark_sacked((l, r), pl, pr, now_ns, ecr, &mut d);
            }
        }
        self.sack_cache = ranges;
        d
    }

    /// Mark SACKed the segments in `[pl, pr)`, a part of `block` not
    /// reported before, that `block` covers.
    ///
    /// A peer SACKing a byte in every two would otherwise split the
    /// scoreboard into single bytes (CVE-2019-11478): megabytes of records,
    /// every ACK and RACK scan walking them, retransmissions going out a
    /// byte at a time. As Linux's `tcp_match_skb_to_sack`, a block's edge
    /// splits a segment only at a whole number of MSS from its start, a
    /// segment of one MSS or less is SACKed whole or not at all, and past
    /// a cap on records nothing is split. The bytes left out are resent if
    /// need be, which costs an honest receiver nothing: it SACKs what it
    /// received, whole segments.
    fn mark_sacked(
        &mut self,
        block: (u64, u64),
        pl: u64,
        pr: u64,
        now: u64,
        ecr: Option<u32>,
        d: &mut Delivery,
    ) {
        let Some(mut i) = self.idx(pl) else {
            return;
        };
        let (l, r) = block;
        while i < self.segs.len() && self.segs[i].start < pr {
            let s = self.segs[i];
            if s.has(SACKED) {
                i += 1;
                continue;
            }
            let (mut lo, mut hi) = (s.start.max(l), s.end.min(r));
            if lo > s.start || hi < s.end {
                if s.len() <= self.mss || s.has(FIN) {
                    i += 1;
                    continue;
                }
                if lo > s.start {
                    lo = s.start + (lo - s.start).div_ceil(self.mss) * self.mss;
                }
                if hi < s.end {
                    hi = s.start + (hi - s.start) / self.mss * self.mss;
                }
                let cuts = usize::from(lo > s.start) + usize::from(hi < s.end);
                if lo >= hi || !self.may_split(cuts) {
                    i += 1;
                    continue;
                }
                if lo > s.start {
                    self.split(i, lo);
                    i += 1;
                }
                if hi < self.segs[i].end {
                    self.split(i, hi);
                }
            }
            let s = self.segs[i];
            let seg = &mut self.segs[i];
            seg.flags |= SACKED;
            if s.has(LOST) {
                seg.flags &= !LOST;
                self.lost -= s.len();
                self.lost_set.remove(&s.start);
            }
            self.sacked += s.len();
            self.sacked_segs += 1;
            let end = self.seq_of(s.end);
            d.note(s.len(), end, !s.has(RETRANS));
            self.rate.on_delivered(&s.rate, s.xmit, s.end, s.len(), now);
            self.rack_delivered(&s, now, ecr);
            i += 1;
        }
    }

    /// Whether a SACK may add `n` records: at most two per MSS in flight,
    /// and some.
    fn may_split(&self, n: usize) -> bool {
        let cap = 2 * (self.end_off() - self.una_off) / self.mss + SPLIT_SLACK;
        (self.segs.len() + n) as u64 <= cap
    }

    /// Feed an RTT sample to the windowed minimum (RFC 8985 §6.2 step 1).
    pub fn rtt_sample(&mut self, rtt: Duration, now: Instant) {
        let t = self.ns(now);
        self.rack
            .min_rtt
            .update(MIN_RTT_WINDOW, t, rtt.as_nanos() as u64);
    }

    /// The delivery rate sample of the ACK just processed, if it delivered
    /// anything; see [`Rate::sample`].
    pub fn rate_sample(&mut self) -> Option<RateSample> {
        let min_rtt = self.rack.min_rtt.get();
        self.rate.sample(min_rtt)
    }

    /// The connection's delivery state.
    #[inline]
    pub fn rate(&self) -> &Rate {
        &self.rate
    }

    /// ECN feedback on the ACK being processed reports `len` bytes of what
    /// it delivered CE-marked. Before [`rate_sample`](Self::rate_sample).
    #[inline]
    pub fn on_ce(&mut self, len: u64) {
        self.rate.on_ce(len);
    }

    /// The sender has run out of data while the window had room: samples
    /// until what is in flight is delivered are application-limited.
    pub fn mark_app_limited(&mut self) {
        let pipe = self.pipe();
        self.rate.mark_app_limited(pipe);
    }

    /// Keep a log of the segments marked lost, for [`take_losses`](Self::take_losses).
    pub fn set_track_losses(&mut self, on: bool) {
        self.lost_log = on.then(Vec::new);
    }

    /// The segments marked lost since last asked, with their sizes.
    pub fn take_losses(&mut self) -> Vec<(TxState, u32)> {
        match self.lost_log.as_mut() {
            Some(log) => std::mem::take(log),
            None => Vec::new(),
        }
    }

    /// The round trip of the most recently sent segment the ACK in
    /// progress delivered, as RACK took it: what BBR's minimum RTT wants
    /// (draft-ietf-ccwg-bbr §5.5.7.1), where the RTO takes the oldest.
    pub fn ack_rtt(&self) -> Option<Duration> {
        self.rack
            .rtt_from
            .map(|_| Duration::from_nanos(self.rack.rtt))
    }

    /// RACK step 4 (RFC 8985 §6.2): the reordering window for this ACK.
    /// `dsack` if it carried a D-SACK, `recovering` while in fast or
    /// timeout recovery, `exiting` if it ended one.
    pub fn reo_wnd(
        &mut self,
        dsack: bool,
        recovering: bool,
        exiting: bool,
        srtt: Duration,
    ) -> Duration {
        let r = &mut self.rack;
        if r.dsack_round.is_some_and(|round| self.una_off >= round) {
            r.dsack_round = None;
        }
        if r.dsack_round.is_none() && dsack {
            r.dsack_round = Some(self.segs.back().map_or(self.una_off, |s| s.end));
            r.reo_wnd_mult += 1;
            r.reo_wnd_persist = REO_WND_PERSIST;
        } else if exiting {
            r.reo_wnd_persist = r.reo_wnd_persist.saturating_sub(1);
            if r.reo_wnd_persist == 0 {
                r.reo_wnd_mult = 1;
            }
        }
        if !r.reordering_seen && (recovering || self.sacked_segs >= DUP_THRESH) {
            return Duration::ZERO;
        }
        let min_rtt = Duration::from_nanos(r.min_rtt.get().unwrap_or(0));
        (min_rtt * r.reo_wnd_mult / 4).min(srtt)
    }

    /// Whether reordering has been seen (RACK.reordering_seen).
    #[cfg(test)]
    pub fn reordering_seen(&self) -> bool {
        self.rack.reordering_seen
    }

    /// The current reordering-window multiplier.
    #[cfg(test)]
    pub fn reo_wnd_mult(&self) -> u32 {
        self.rack.reo_wnd_mult
    }

    fn mark_lost(&mut self, i: usize) -> bool {
        let s = &mut self.segs[i];
        if s.has(LOST) || s.has(SACKED) {
            return false;
        }
        s.flags |= LOST;
        let (start, len, rate) = (s.start, s.len(), s.rate);
        self.lost += len;
        self.rate.on_lost(len);
        if let Some(log) = self.lost_log.as_mut() {
            log.push((rate, len as u32));
        }
        self.lost_set.insert(start);
        true
    }

    /// RACK step 5 (RFC 8985 §6.2): mark lost what was sent before
    /// RACK.segment and has had `reo_wnd` on top of a round trip to show
    /// up. Returns whether anything was newly marked, and when the rest
    /// sent before RACK.segment is due, for the reordering timer.
    pub fn detect_loss(&mut self, now: Instant, reo_wnd: Duration) -> (bool, Option<Duration>) {
        if !self.rack_on || !self.rack.valid {
            return (false, None);
        }
        let now = self.ns(now);
        let reo = reo_wnd.as_nanos() as u64;
        let (rack_xmit, rack_end, rack_rtt) = (self.rack.xmit, self.rack.end, self.rack.rtt);
        let mut marked = false;
        let mut timeout: u64 = 0;
        // Keep the entries still to be decided at the front, and drop the
        // rest of those scanned: each entry is passed over once as stale.
        let mut w = 0;
        let mut r = 0;
        while r < self.tq.len() {
            let rec = self.tq[r];
            // What follows went out no earlier. Segments sent in one burst
            // share a timestamp, so the tie goes by sequence: the queue is
            // in that order within a burst too, retransmissions first, and
            // the scan stops at the first not sent before RACK.segment, as
            // Linux's does.
            if !sent_after(rack_xmit, rack_end, rec.xmit, rec.end) {
                break;
            }
            r += 1;
            let live = self.live_range(&rec);
            if live.is_empty() {
                continue;
            }
            let due = rec.xmit.saturating_add(rack_rtt).saturating_add(reo);
            if due <= now {
                for i in live {
                    if self.segs[i].tx == rec.tx {
                        marked |= self.mark_lost(i);
                    }
                }
            } else {
                timeout = timeout.max(due - now);
                self.tq.swap(w, r - 1);
                w += 1;
            }
        }
        self.tq.drain(w..r);
        (marked, (timeout > 0).then(|| Duration::from_nanos(timeout)))
    }

    /// The segments of transmission `rec` still in flight as it left them:
    /// not delivered, not deemed lost, not sent again since.
    fn live_range(&self, rec: &TxRec) -> std::ops::Range<usize> {
        if rec.end <= self.una_off {
            return 0..0;
        }
        let first = self.segs.partition_point(|s| s.end <= rec.start);
        let mut last = first;
        let mut any = false;
        while last < self.segs.len() && self.segs[last].start < rec.end {
            let s = &self.segs[last];
            if s.tx == rec.tx && s.flags & (SACKED | LOST) == 0 {
                any = true;
            }
            last += 1;
        }
        if !any {
            return 0..0;
        }
        // Pieces sent again since are the caller's to skip; settled ones
        // mark_lost skips itself.
        let mut out = first;
        while out < last && self.segs[out].tx != rec.tx {
            out += 1;
        }
        out..last
    }

    /// RFC 8985 §6.3 on a retransmission timeout: the first segment is
    /// lost, and so is anything sent longer than a round trip and the
    /// reordering window ago.
    pub fn mark_lost_on_rto(&mut self, now: Instant, reo_wnd: Duration) {
        let now = self.ns(now);
        let wait = self.rack.rtt.saturating_add(reo_wnd.as_nanos() as u64);
        for i in 0..self.segs.len() {
            let s = self.segs[i];
            if i == 0 || s.xmit.saturating_add(wait) <= now {
                self.mark_lost(i);
            }
        }
    }

    /// Everything not SACKed is lost: after a timeout without RACK, or when
    /// the path MTU dropped under what was sent.
    pub fn mark_all_lost(&mut self) {
        for i in 0..self.segs.len() {
            self.mark_lost(i);
        }
    }

    /// Every segment of data longer than `max` bytes is lost: sent before
    /// the MSS came down, it is too large for the path.
    pub fn mark_longer_lost(&mut self, max: u32) {
        for i in 0..self.segs.len() {
            let s = &self.segs[i];
            if !s.has(FIN) && s.len() > u64::from(max) {
                self.mark_lost(i);
            }
        }
    }

    /// The first segment is lost (fast retransmit, or a NewReno partial ACK).
    pub fn mark_head_lost(&mut self) -> bool {
        !self.segs.is_empty() && self.mark_lost(0)
    }

    /// Mark lost what of `[seq, end)` is outstanding, neither SACKed nor
    /// already lost. Returns whether anything was.
    pub fn mark_range_lost(&mut self, seq: u32, end: u32) -> bool {
        let start = if seq_before(seq, self.una) {
            self.una_off
        } else {
            self.off(seq)
        };
        let end = if seq_before(end, self.una) {
            self.una_off
        } else {
            self.off(end)
        };
        let Some(mut i) = self.idx(start) else {
            return false;
        };
        if self.segs[i].start < start {
            self.split(i, start);
            i += 1;
        }
        let mut marked = false;
        while i < self.segs.len() && self.segs[i].start < end {
            if self.segs[i].end > end && !self.segs[i].has(FIN) {
                self.split(i, end);
            }
            marked |= self.mark_lost(i);
            i += 1;
        }
        marked
    }

    /// Whether anything outside `[seq, end)` is deemed lost.
    pub fn lost_outside(&self, seq: u32, end: u32) -> bool {
        let (Some(&first), Some(&last)) = (self.lost_set.first(), self.lost_set.last()) else {
            return false;
        };
        let start = if seq_before(seq, self.una) {
            self.una_off
        } else {
            self.off(seq)
        };
        first < start || last >= self.off(end)
    }

    /// Whether the receiver has SACKed the segment holding `seq`.
    pub fn sacked_at(&self, seq: u32) -> bool {
        if seq_before(seq, self.una) {
            return false;
        }
        self.idx(self.off(seq))
            .is_some_and(|i| self.segs[i].has(SACKED))
    }

    /// Forget every SACK: the receiver has reneged on them.
    pub fn clear_sacks(&mut self) {
        for s in self.segs.iter_mut() {
            s.flags &= !SACKED;
        }
        self.sacked = 0;
        self.sacked_segs = 0;
        self.sack_cache.clear();
    }

    /// The first segment is SACKed: a receiver holding it would have
    /// acknowledged it cumulatively, so it has dropped what it SACKed.
    pub fn head_sacked(&self) -> bool {
        self.segs.front().is_some_and(|s| s.has(SACKED))
    }

    /// Nothing is lost after all: a timeout turned out spurious. What it
    /// marked lost is back in flight as it was sent, and back in RACK's
    /// queue too, which dropped each segment as it marked it: whatever was
    /// really lost, RACK marks again once something sent after it is
    /// delivered, rather than the next timeout.
    pub fn unmark_lost(&mut self) {
        let mut back: Vec<TxRec> = Vec::new();
        for s in self.segs.iter_mut() {
            if !s.has(LOST) {
                continue;
            }
            s.flags &= !LOST;
            if !self.rack_on {
                continue;
            }
            match back.last_mut() {
                Some(r) if r.tx == s.tx && r.end == s.start => r.end = s.end,
                _ => back.push(TxRec {
                    start: s.start,
                    end: s.end,
                    xmit: s.xmit,
                    tx: s.tx,
                }),
            }
        }
        self.lost = 0;
        self.lost_set.clear();
        if !back.is_empty() {
            // In the order of transmission, which the scan relies on to
            // stop at the first record sent after RACK.segment.
            let mut all: Vec<TxRec> = self.tq.drain(..).chain(back).collect();
            all.sort_by_key(|r| (r.xmit, r.end));
            self.tq = all.into();
        }
    }

    /// Whether a retransmission is in flight: resent, and neither delivered
    /// nor deemed lost again since (Linux's `retrans_out`).
    pub fn retrans_in_flight(&self) -> bool {
        self.segs
            .iter()
            .any(|s| s.flags & (RETRANS | SACKED | LOST) == RETRANS)
    }

    fn seg_ref(&self, s: &Seg, max: u32) -> SegRef {
        let fin = s.has(FIN);
        let len = if fin {
            1
        } else {
            (s.len() as u32).min(max.max(1))
        };
        (self.seq_of(s.start), len, fin)
    }

    /// The lowest segment deemed lost and not yet sent again, cut to `max`,
    /// and joined with the lost ones right after it up to `max`: pieces of
    /// what went out as one go out again as one, not one by one.
    pub fn next_lost(&self, max: u32) -> Option<SegRef> {
        let &start = self.lost_set.first()?;
        let i = self.idx(start)?;
        let (seq, len, fin) = self.seg_ref(&self.segs[i], max);
        let max = u64::from(max.max(1));
        let mut end = self.segs[i].end;
        let mut j = i;
        while !fin && end - start < max && self.mergeable(j) && self.segs[j + 1].has(LOST) {
            j += 1;
            end = self.segs[j].end;
        }
        let len = if j == i {
            len
        } else {
            (end - start).min(max) as u32
        };
        Some((seq, len, fin))
    }

    /// The first outstanding segment, cut to `max`.
    pub fn head(&self, max: u32) -> Option<SegRef> {
        self.segs.front().map(|s| self.seg_ref(s, max))
    }

    /// The last segment sent, cut to its last `max` bytes: what a tail
    /// loss probe sends again when there is nothing new (RFC 8985 §7.3).
    pub fn last(&self, max: u32) -> Option<SegRef> {
        let s = self.segs.back()?;
        if s.has(FIN) {
            return Some((self.seq_of(s.start), 1, true));
        }
        let len = (s.len() as u32).min(max.max(1));
        Some((self.seq_of(s.end - u64::from(len)), len, false))
    }

    /// Check the internal bookkeeping.
    #[cfg(test)]
    pub fn check(&self) {
        let (mut sacked, mut lost, mut segs) = (0, 0, 0);
        let mut at = self.una_off;
        let mut lost_starts = BTreeSet::new();
        for s in &self.segs {
            assert_eq!(s.start, at, "segments do not tile");
            assert!(s.end > s.start);
            at = s.end;
            if s.has(SACKED) {
                sacked += s.len();
                segs += 1;
                assert!(!s.has(LOST));
            }
            if s.has(LOST) {
                lost += s.len();
                lost_starts.insert(s.start);
            }
        }
        assert_eq!(sacked, self.sacked);
        assert_eq!(segs, self.sacked_segs);
        assert_eq!(lost, self.lost);
        assert_eq!(lost_starts, self.lost_set);
    }
}

/// RACK_sent_after (RFC 8985 §6.2): whether `(t1, seq1)` was sent after
/// `(t2, seq2)`, sequence breaking a tie of the clock.
#[inline]
fn sent_after(t1: u64, seq1: u64, t2: u64, seq2: u64) -> bool {
    t1 > t2 || (t1 == t2 && seq1 > seq2)
}

/// The D-SACK block of an ACK's SACK blocks, if it has one (RFC 2883 §4):
/// a first block below the cumulative ACK, or inside the second block.
pub(crate) fn dsack_block(blocks: &[SackBlock], ack: u32) -> Option<SackBlock> {
    let first = *blocks.first()?;
    if !seq_after(first.right, first.left) {
        return None;
    }
    if seq_before_eq(first.right, ack) || seq_before(first.left, ack) {
        return Some(first);
    }
    let second = blocks.get(1)?;
    (seq_before_eq(second.left, first.left) && seq_before_eq(first.right, second.right))
        .then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1000;

    fn board(n: u32, t0: Instant) -> Scoreboard {
        let mut b = Scoreboard::new(u32::MAX - 2500, t0);
        b.set_rack(true);
        b.set_mss(MSS);
        for i in 0..n {
            b.on_send(
                (u32::MAX - 2500).wrapping_add(i * MSS),
                MSS,
                false,
                t0 + Duration::from_millis(u64::from(i)),
                i,
            );
        }
        b
    }

    fn seq(i: u32) -> u32 {
        (u32::MAX - 2500).wrapping_add(i * MSS)
    }

    fn blk(from: u32, to: u32) -> SackBlock {
        SackBlock {
            left: seq(from),
            right: seq(to),
        }
    }

    /// Rate samples from SACKs and cumulative ACKs alike, taken from the
    /// newest segment each ACK delivers; a segment SACKed before is not
    /// counted again when cumulatively acknowledged.
    #[test]
    fn deliveries_give_rate_samples() {
        let t0 = Instant::now();
        // Ten segments sent 1 ms apart into an idle path.
        let mut b = board(10, t0);
        let rtt = Duration::from_millis(100);
        b.rtt_sample(rtt, t0 + rtt);
        // Segments 2..4 SACKed 100 ms after segment 3 went out.
        let now = t0 + Duration::from_millis(103);
        b.begin_ack();
        b.sack(&[blk(2, 4)], now, None);
        let rs = b.rate_sample().unwrap();
        assert_eq!(rs.delivered, 2 * u64::from(MSS));
        assert_eq!(rs.prior_delivered, 0);
        assert_eq!(rs.tx_in_flight, 4 * MSS, "segment 3 went out fourth");
        // Over max(send 3 ms, ACK 103 ms).
        assert_eq!(rs.interval, Duration::from_millis(103));
        assert_eq!(rs.delivery_rate, 2 * u64::from(MSS) * 1000 / 103);
        assert!(b.rate_sample().is_none(), "one per ACK");
        // The cumulative ACK of 0..5: 0, 1 and 4 are new; 2 and 3 were in.
        let now = t0 + Duration::from_millis(106);
        b.begin_ack();
        b.ack(seq(5), now, None);
        let rs = b.rate_sample().unwrap();
        assert_eq!(b.rate().delivered(), 5 * u64::from(MSS));
        assert_eq!(rs.delivered, 5 * u64::from(MSS));
        // An ACK of nothing new has no sample; losses show in the next.
        b.begin_ack();
        b.ack(seq(5), now, None);
        assert!(b.rate_sample().is_none());
        b.mark_head_lost();
        assert_eq!(b.rate().lost(), u64::from(MSS));
        b.begin_ack();
        b.sack(&[blk(6, 7)], now + Duration::from_millis(1), None);
        let rs = b.rate_sample().unwrap();
        assert_eq!(rs.lost, u64::from(MSS));
    }

    /// With the log on, each segment marked lost is reported once, with the
    /// state it went out with.
    #[test]
    fn losses_are_logged_for_the_controller() {
        let t0 = Instant::now();
        let mut b = board(4, t0);
        assert!(b.take_losses().is_empty(), "no log unless asked");
        b.set_track_losses(true);
        b.mark_all_lost();
        let lost = b.take_losses();
        assert_eq!(lost.len(), 4);
        assert_eq!(lost[3].0.tx_in_flight, 4 * MSS);
        assert_eq!(lost[3].1, MSS);
        assert!(b.take_losses().is_empty());
    }

    #[test]
    fn sacks_and_acks_keep_the_counts() {
        let t0 = Instant::now();
        let mut b = board(10, t0);
        assert_eq!(b.pipe(), 10 * MSS);
        let now = t0 + Duration::from_millis(50);
        b.begin_ack();
        let d = b.sack(&[blk(2, 4), blk(6, 7)], now, None);
        assert_eq!(d.delivered, 3 * MSS);
        assert_eq!(b.sacked_segs(), 3);
        assert_eq!(b.pipe(), 7 * MSS);
        b.check();
        // A repeated block delivers nothing new; a grown one only its growth.
        let d = b.sack(&[blk(2, 5), blk(6, 7)], now, None);
        assert_eq!(d.delivered, MSS);
        let d = b.ack(seq(3), now, None);
        assert_eq!(d.delivered, 2 * MSS, "segments 0 and 1; 2 was SACKed");
        b.check();
        assert_eq!(b.pipe(), 4 * MSS);
        // A block edge inside a segment of an MSS SACKs none of it.
        let d = b.sack(
            &[SackBlock {
                left: seq(8) + 500,
                right: seq(9),
            }],
            now,
            None,
        );
        assert_eq!(d.delivered, 0);
        b.check();
        let d = b.ack(seq(10), now, None);
        assert_eq!(d.delivered, 4 * MSS);
        assert!(b.is_empty());
        b.check();
    }

    /// Segment 0 lost, 1-2 SACKed: without reordering seen and fewer than
    /// DupThresh SACKed, the loss waits out a quarter of the minimum RTT.
    #[test]
    fn rack_waits_out_the_reordering_window() {
        let t0 = Instant::now();
        let mut b = board(10, t0);
        b.rtt_sample(Duration::from_millis(100), t0);
        let now = t0 + Duration::from_millis(102);
        b.begin_ack();
        b.sack(&[blk(1, 3)], now, None);
        let reo = b.reo_wnd(false, false, false, Duration::from_millis(100));
        assert_eq!(reo, Duration::from_millis(25));
        let (lost, timeout) = b.detect_loss(now, reo);
        assert!(!lost);
        // Segment 0 was sent 2 ms before RACK.segment (segment 2) and is
        // due RACK.rtt (100 ms) + 25 ms after it was sent.
        assert_eq!(timeout, Some(Duration::from_millis(23)));
        let later = now + Duration::from_millis(23);
        let (lost, timeout) = b.detect_loss(later, reo);
        assert!(lost);
        assert_eq!(timeout, None);
        assert_eq!(b.next_lost(MSS), Some((seq(0), MSS, false)));
        b.check();
    }

    /// A third SACKed segment shows the loss at once (step 4's DupThresh).
    #[test]
    fn dupthresh_sacks_mark_at_once() {
        let t0 = Instant::now();
        let mut b = board(10, t0);
        b.rtt_sample(Duration::from_millis(100), t0);
        let now = t0 + Duration::from_millis(103);
        b.begin_ack();
        b.sack(&[blk(1, 4)], now, None);
        let reo = b.reo_wnd(false, false, false, Duration::from_millis(100));
        assert_eq!(reo, Duration::ZERO);
        assert!(b.detect_loss(now, reo).0);
        assert_eq!(b.lost_bytes(), MSS);
        assert_eq!(b.pipe(), 6 * MSS);
    }

    /// Reordering: segment 1 arrives after 2 and 3 were SACKed. It is an
    /// original below the forward ACK, so reordering is seen, and the
    /// window stays at min_rtt/4 however many are SACKed.
    #[test]
    fn late_original_is_reordering() {
        let t0 = Instant::now();
        let mut b = board(10, t0);
        b.rtt_sample(Duration::from_millis(100), t0);
        let now = t0 + Duration::from_millis(103);
        b.begin_ack();
        b.sack(&[blk(2, 4)], now, None);
        b.begin_ack();
        b.sack(&[blk(1, 4)], now, None);
        assert!(b.reordering_seen());
        b.sack(&[blk(1, 6)], now, None);
        let reo = b.reo_wnd(false, false, false, Duration::from_millis(100));
        assert_eq!(reo, Duration::from_millis(25));
        assert!(!b.detect_loss(now, reo).0);
        // D-SACKs grow the window a quarter RTT per round, up to SRTT.
        let reo = b.reo_wnd(true, false, false, Duration::from_millis(100));
        assert_eq!(reo, Duration::from_millis(50));
        assert_eq!(b.reo_wnd_mult(), 2);
        let reo = b.reo_wnd(true, false, false, Duration::from_millis(100));
        assert_eq!(reo, Duration::from_millis(50), "one step per round");
        b.ack(seq(10), now, None);
        let reo = b.reo_wnd(true, false, false, Duration::from_millis(60));
        assert_eq!(reo, Duration::from_millis(60));
    }

    /// A lost retransmission is lost again once something sent after it
    /// is delivered.
    #[test]
    fn lost_retransmission_is_detected() {
        let t0 = Instant::now();
        let mut b = board(5, t0);
        b.rtt_sample(Duration::from_millis(10), t0);
        let now = t0 + Duration::from_millis(20);
        b.begin_ack();
        b.sack(&[blk(1, 5)], now, None);
        let reo = b.reo_wnd(false, false, false, Duration::from_millis(10));
        assert!(b.detect_loss(now, reo).0);
        let (s, l, _) = b.next_lost(MSS).unwrap();
        b.on_retransmit(s, l, now, 100);
        assert_eq!(b.lost_bytes(), 0);
        b.check();
        // New data after the retransmission, delivered: the retransmission
        // is older and overdue.
        b.on_send(seq(5), MSS, false, now + Duration::from_millis(1), 101);
        let later = now + Duration::from_millis(30);
        b.begin_ack();
        b.sack(&[blk(1, 6)], later, None);
        let reo = b.reo_wnd(false, true, false, Duration::from_millis(10));
        assert!(b.detect_loss(later, reo).0);
        assert_eq!(b.next_lost(MSS), Some((seq(0), MSS, false)));
    }

    #[test]
    fn retransmission_splits_to_the_room() {
        let t0 = Instant::now();
        let mut b = board(3, t0);
        b.mark_all_lost();
        assert_eq!(b.next_lost(400), Some((seq(0), 400, false)));
        b.on_retransmit(seq(0), 400, t0, 7);
        b.check();
        assert_eq!(b.next_lost(MSS), Some((seq(0) + 400, 600, false)));
        assert_eq!(b.lost_bytes(), 2 * MSS + 600);
        b.unmark_lost();
        b.check();
        assert_eq!(b.pipe(), 3 * MSS);
    }

    /// A peer SACKing one byte in every two (CVE-2019-11478) splits
    /// nothing: segments of an MSS are SACKed whole or not at all, so the
    /// scoreboard keeps a record per segment and a retransmission is a
    /// whole segment, not a byte.
    #[test]
    fn odd_byte_sacks_do_not_fragment() {
        let t0 = Instant::now();
        let n = 20;
        let mut b = board(n, t0);
        let mut off = 1;
        while off + 8 < n * MSS {
            let blocks: Vec<SackBlock> = (0..4)
                .map(|k| SackBlock {
                    left: seq(0).wrapping_add(off + 2 * k),
                    right: seq(0).wrapping_add(off + 2 * k + 1),
                })
                .collect();
            b.begin_ack();
            b.sack(&blocks, t0 + Duration::from_millis(50), None);
            b.detect_loss(t0 + Duration::from_millis(50), Duration::ZERO);
            off += 8;
        }
        b.check();
        assert_eq!(b.segs.len(), n as usize, "the scoreboard was fragmented");
        assert_eq!(b.sacked_bytes(), 0);
        b.mark_all_lost();
        assert_eq!(b.next_lost(MSS), Some((seq(0), MSS, false)));
    }

    /// A segment longer than an MSS (an MTU probe, or one sent before the
    /// MSS came down) is split at whole MSS from its start: the block's
    /// left edge rounds up, its right edge down.
    #[test]
    fn sack_splits_at_whole_mss() {
        let t0 = Instant::now();
        let mut b = Scoreboard::new(seq(0), t0);
        b.set_rack(true);
        b.set_mss(MSS);
        b.on_send(seq(0), 3 * MSS, false, t0, 0);
        b.on_send(seq(3), MSS, false, t0, 0);
        let d = b.sack(
            &[SackBlock {
                left: seq(0) + 500,
                right: seq(2) + 500,
            }],
            t0,
            None,
        );
        assert_eq!(d.delivered, MSS);
        assert!(!b.sacked_at(seq(0) + 999) && b.sacked_at(seq(1)) && !b.sacked_at(seq(2)));
        b.check();
        // The block grown over the whole segment SACKs the rest of it,
        // though the previous ACK reported part of it already.
        let d = b.sack(
            &[SackBlock {
                left: seq(0),
                right: seq(3),
            }],
            t0,
            None,
        );
        assert_eq!(d.delivered, 2 * MSS);
        assert_eq!(b.sacked_bytes(), 3 * MSS);
        b.check();
    }

    /// Past two records per MSS in flight, and some, nothing is split: a
    /// flight of tiny segments has no room to spare.
    #[test]
    fn sack_splits_are_capped() {
        let t0 = Instant::now();
        let mut b = Scoreboard::new(0, t0);
        b.set_mss(MSS);
        for i in 0..100 {
            b.on_send(i, 1, false, t0, 0);
        }
        b.on_send(100, 3 * MSS, false, t0, 0);
        let d = b.sack(
            &[SackBlock {
                left: 100 + MSS,
                right: 100 + 2 * MSS,
            }],
            t0,
            None,
        );
        assert_eq!(d.delivered, 0);
        assert_eq!(b.segs.len(), 101);
        b.check();
    }

    /// Lost pieces of what went out as one go out again as one, up to the
    /// room, and are one record after; what went out apart stays apart.
    #[test]
    fn lost_pieces_are_resent_together() {
        let t0 = Instant::now();
        let mut b = Scoreboard::new(seq(0), t0);
        b.set_mss(MSS);
        b.on_send(seq(0), 3 * MSS, false, t0, 0);
        b.on_send(seq(3), MSS, false, t0, 1);
        b.mark_range_lost(seq(0), seq(1));
        b.mark_range_lost(seq(1), seq(2));
        b.mark_all_lost();
        assert_eq!(b.segs.len(), 4);
        assert_eq!(b.next_lost(4 * MSS), Some((seq(0), 3 * MSS, false)));
        assert_eq!(b.next_lost(2 * MSS), Some((seq(0), 2 * MSS, false)));
        b.on_retransmit(seq(0), 2 * MSS, t0, 7);
        b.check();
        assert_eq!(b.segs.len(), 3);
        assert_eq!(b.lost_bytes(), 2 * MSS);
        assert_eq!(b.next_lost(4 * MSS), Some((seq(2), MSS, false)));
    }

    /// A timeout found spurious unmarks what it deemed lost, and RACK,
    /// which dropped those segments from its queue when it marked them,
    /// has them back: one really lost is marked again once something sent
    /// after it is delivered.
    #[test]
    fn unmarked_losses_are_rack_s_again() {
        let t0 = Instant::now();
        let mut b = board(4, t0);
        b.rtt_sample(Duration::from_millis(10), t0);
        let now = t0 + Duration::from_millis(20);
        b.begin_ack();
        b.sack(&[blk(1, 2)], now, None);
        assert!(b.detect_loss(now, Duration::ZERO).0);
        assert_eq!(b.next_lost(MSS), Some((seq(0), MSS, false)));
        b.unmark_lost();
        assert_eq!(b.lost_bytes(), 0);
        let later = now + Duration::from_millis(20);
        b.begin_ack();
        b.sack(&[blk(1, 4)], later, None);
        assert!(
            b.detect_loss(later, Duration::ZERO).0,
            "segment 0 forgotten"
        );
        assert_eq!(b.next_lost(MSS), Some((seq(0), MSS, false)));
        b.check();
    }

    #[test]
    fn dsack_blocks_are_recognised() {
        let b = |l, r| SackBlock { left: l, right: r };
        assert_eq!(dsack_block(&[b(10, 20)], 30), Some(b(10, 20)));
        assert_eq!(dsack_block(&[b(40, 50), b(30, 60)], 20), Some(b(40, 50)));
        assert_eq!(dsack_block(&[b(40, 50), b(60, 70)], 20), None);
        assert_eq!(dsack_block(&[], 20), None);
    }

    #[test]
    fn windowed_min_forgets_old_samples() {
        let mut m = WindowedMin::default();
        assert_eq!(m.update(100, 0, 50), 50);
        assert_eq!(m.update(100, 10, 60), 50);
        assert_eq!(m.update(100, 60, 70), 50);
        // The 50 is out of the window; the best since takes over.
        assert_eq!(m.update(100, 120, 80), 70);
        assert_eq!(m.update(100, 400, 90), 90);
    }

    /// Random events against the bookkeeping, sequence numbers wrapping.
    #[test]
    fn random_events_keep_the_books() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut rng = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let t0 = Instant::now();
        for _ in 0..200 {
            let mut b = Scoreboard::new(u32::MAX - 5000, t0);
            b.set_rack(true);
            let mut nxt = u32::MAX - 5000;
            let mut una = nxt;
            let mut t = t0;
            for _ in 0..300 {
                t += Duration::from_micros(rng(3000));
                match rng(8) {
                    0..=2 => {
                        let len = 1 + rng(1500) as u32;
                        b.on_send(nxt, len, false, t, 0);
                        nxt = nxt.wrapping_add(len);
                    }
                    3 => {
                        let span = nxt.wrapping_sub(una);
                        if span > 0 {
                            let ack = una.wrapping_add(rng(u64::from(span) + 1) as u32);
                            b.ack(ack, t, None);
                            una = ack;
                        }
                    }
                    4 => {
                        let span = nxt.wrapping_sub(una).max(1);
                        let l = una.wrapping_add(rng(u64::from(span)) as u32);
                        let r = l.wrapping_add(1 + rng(3000) as u32);
                        b.begin_ack();
                        b.sack(&[SackBlock { left: l, right: r }], t, None);
                    }
                    5 => {
                        b.detect_loss(t, Duration::from_micros(rng(2000)));
                    }
                    6 => {
                        if let Some((s, l, _)) = b.next_lost(1 + rng(2000) as u32) {
                            b.on_retransmit(s, l, t, 0);
                        }
                    }
                    _ => match rng(4) {
                        0 => b.mark_all_lost(),
                        1 => b.unmark_lost(),
                        2 => b.clear_sacks(),
                        _ => {
                            b.mark_head_lost();
                        }
                    },
                }
                b.check();
                assert_eq!(b.end_seq(), nxt);
                assert!(b.pipe() <= nxt.wrapping_sub(una));
            }
        }
    }
}

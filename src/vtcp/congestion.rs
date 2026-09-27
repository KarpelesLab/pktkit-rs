//! Congestion control. NewReno (RFC 5681) and HighSpeed TCP (RFC 3649).

/// Pluggable congestion-control trait.
///
/// The connection treats this as an opaque controller; it only cares about
/// the current send window and a handful of events.
pub trait CongestionController: Send {
    /// New (cumulative) ACK: `bytes_acked` bytes were freshly acknowledged.
    fn on_ack(&mut self, bytes_acked: u32);
    /// New (cumulative) ACK, with `flight_size` the bytes that were
    /// outstanding before it. The connection calls this rather than
    /// [`on_ack`](Self::on_ack): a flight well short of the window means
    /// the sender was limited by the application or the receiver, not by
    /// cwnd, and growing cwnd then would validate nothing (RFC 7661 §4.3,
    /// RFC 5681 §3.1). The default ignores the flight.
    fn on_new_ack(&mut self, bytes_acked: u32, flight_size: u32) {
        let _ = flight_size;
        self.on_ack(bytes_acked);
    }
    /// A duplicate ACK arrived. Returns true on the 3rd dup ACK (caller
    /// should trigger fast retransmit).
    fn on_dup_ack(&mut self) -> bool;
    /// RTO fired; loss inferred via timeout.
    fn on_timeout(&mut self);
    /// RTO fired with `flight_size` bytes outstanding; the connection calls
    /// this rather than [`on_timeout`](Self::on_timeout). `repeated` is set
    /// when the segment had already been retransmitted by the timer, in
    /// which case RFC 5681 §3.1 holds ssthresh where the first timeout put
    /// it. The default ignores both.
    fn on_retransmit_timeout(&mut self, flight_size: u32, repeated: bool) {
        let _ = (flight_size, repeated);
        self.on_timeout();
    }
    /// The SYN or SYN-ACK was lost and resent; the handshake has just
    /// completed. RFC 5681 §3.1 has data start from the loss window (one
    /// segment) with ssthresh untouched. The default does that as a
    /// repeated timeout, which the built-in controllers take the same way.
    fn on_handshake_loss(&mut self) {
        self.on_retransmit_timeout(0, true);
    }
    /// Fast retransmit triggered; enter recovery.
    fn on_fast_retransmit(&mut self, flight_size: u32, snd_nxt: u32);
    /// A partial ACK during fast recovery (RFC 6582 §3.2 step 5):
    /// `bytes_acked` bytes were acknowledged, but not everything outstanding
    /// when recovery began, and the caller is retransmitting the next hole.
    /// The default leaves the window alone.
    fn on_partial_ack(&mut self, bytes_acked: u32) {
        let _ = bytes_acked;
    }
    /// Recovery has completed (cumulative ACK passed `recovery_seq`).
    fn exit_recovery(&mut self);
    /// Current congestion window in bytes.
    fn send_window(&self) -> u32;
    /// True while in fast recovery.
    fn in_recovery(&self) -> bool;
    /// The recovery point: the SND.NXT at entry to recovery.
    fn recovery_seq(&self) -> u32;
}

/// RFC 5681 NewReno: slow start, congestion avoidance, fast retransmit & recovery.
#[derive(Debug)]
pub struct NewReno {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    dup_ack_cnt: u32,
    recovery: bool,
    recovery_seq: u32,
}

impl NewReno {
    /// Initial CWND per RFC 6928 (`min(10*MSS, max(2*MSS, 14600))`).
    pub fn new(mss: u32) -> Self {
        let mut initial = 10 * mss;
        let alt = (2 * mss).max(14600);
        if alt < initial {
            initial = alt;
        }
        Self {
            cwnd: initial,
            ssthresh: u32::MAX,
            mss,
            dup_ack_cnt: 0,
            recovery: false,
            recovery_seq: 0,
        }
    }

    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }
}

impl CongestionController for NewReno {
    fn on_ack(&mut self, bytes_acked: u32) {
        self.on_new_ack(bytes_acked, u32::MAX);
    }

    fn on_new_ack(&mut self, bytes_acked: u32, flight_size: u32) {
        self.dup_ack_cnt = 0;
        if !cwnd_limited(self.cwnd, self.ssthresh, self.mss, flight_size) {
            return;
        }
        if self.cwnd < self.ssthresh {
            let inc = bytes_acked.min(self.mss);
            self.cwnd = self.cwnd.saturating_add(inc);
        } else {
            let mut inc = self.mss.saturating_mul(self.mss) / self.cwnd.max(1);
            if inc == 0 {
                inc = 1;
            }
            self.cwnd = self.cwnd.saturating_add(inc);
        }
    }

    fn on_dup_ack(&mut self) -> bool {
        self.dup_ack_cnt += 1;
        if self.dup_ack_cnt == 3 && !self.recovery {
            return true;
        }
        if self.recovery && self.dup_ack_cnt > 3 {
            self.cwnd = self.cwnd.saturating_add(self.mss);
        }
        false
    }

    fn on_timeout(&mut self) {
        self.on_retransmit_timeout(self.cwnd, false);
    }

    fn on_retransmit_timeout(&mut self, flight_size: u32, repeated: bool) {
        // RFC 5681 eq. (4): half the flight, not of cwnd, which may never
        // have been filled.
        if !repeated {
            self.ssthresh = (flight_size / 2).max(2 * self.mss);
        }
        self.cwnd = self.mss;
        self.recovery = false;
        self.dup_ack_cnt = 0;
        self.recovery_seq = 0;
    }

    fn on_fast_retransmit(&mut self, flight_size: u32, snd_nxt: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh.saturating_add(3 * self.mss);
        self.recovery = true;
        self.recovery_seq = snd_nxt;
    }

    fn on_partial_ack(&mut self, bytes_acked: u32) {
        self.cwnd = deflate(self.cwnd, self.mss, bytes_acked);
    }

    fn exit_recovery(&mut self) {
        self.cwnd = self.ssthresh;
        self.recovery = false;
        self.dup_ack_cnt = 0;
        self.recovery_seq = 0;
    }

    fn send_window(&self) -> u32 {
        self.cwnd
    }
    fn in_recovery(&self) -> bool {
        self.recovery
    }
    fn recovery_seq(&self) -> u32 {
        self.recovery_seq
    }
}

/// Whether an ACK arriving with `flight` bytes outstanding may grow cwnd:
/// only when the window was in use (RFC 7661 §4.3). In slow start, where
/// cwnd doubles each round trip, a flight of over half of it counts, as in
/// Linux's `tcp_is_cwnd_limited`; beyond that, less than a segment of room
/// must have been left.
fn cwnd_limited(cwnd: u32, ssthresh: u32, mss: u32, flight: u32) -> bool {
    if cwnd < ssthresh {
        cwnd < flight.saturating_mul(2)
    } else {
        flight.saturating_add(mss) > cwnd
    }
}

/// Partial window deflation, RFC 6582 §3.2 step 5: take back what the ACK
/// says has left the network, and add one segment for the retransmission if a
/// full one was acknowledged. The duplicate-ACK count is kept, so the
/// inflation that follows carries on.
fn deflate(cwnd: u32, mss: u32, bytes_acked: u32) -> u32 {
    let mut cwnd = cwnd.saturating_sub(bytes_acked);
    if bytes_acked >= mss {
        cwnd = cwnd.saturating_add(mss);
    }
    cwnd.max(mss)
}

// --- HighSpeed TCP (RFC 3649) ----------------------------------------------

const HS_LOW_WINDOW: u32 = 38; // segments
const HS_HIGH_WINDOW: f64 = 83000.0; // segments
const HS_HIGH_DECREASE: f64 = 0.1;

/// HighSpeed TCP — RFC 3649. Identical to NewReno below `Low_Window`, more
/// aggressive increase / less aggressive decrease above it.
#[derive(Debug)]
pub struct HighSpeed {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    dup_ack_cnt: u32,
    recovery: bool,
    recovery_seq: u32,
}

impl HighSpeed {
    pub fn new(mss: u32) -> Self {
        let mut initial = 10 * mss;
        let alt = (2 * mss).max(14600);
        if alt < initial {
            initial = alt;
        }
        Self {
            cwnd: initial,
            ssthresh: u32::MAX,
            mss,
            dup_ack_cnt: 0,
            recovery: false,
            recovery_seq: 0,
        }
    }

    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    fn b(w: u32) -> f64 {
        if w <= HS_LOW_WINDOW {
            return 0.5;
        }
        let log_w = (w as f64).ln();
        let log_low = (HS_LOW_WINDOW as f64).ln();
        let log_high = HS_HIGH_WINDOW.ln();
        // RFC 3649 §5 interpolates between Low_Window and High_Window;
        // past High_Window the extrapolation would fall below High_Decrease
        // and, far enough out, go negative, growing cwnd on a loss.
        let b = (HS_HIGH_DECREASE - 0.5) * (log_w - log_low) / (log_high - log_low) + 0.5;
        b.clamp(HS_HIGH_DECREASE, 0.5)
    }

    /// ssthresh after a loss: RFC 3649's `(1 - b(w)) * w`, with b taken at
    /// the current cwnd, applied to the flight rather than to a cwnd that
    /// may not have been in use (as RFC 5681 does for NewReno).
    fn decreased(&self, flight_size: u32) -> u32 {
        let b = Self::b(self.cwnd / self.mss);
        ((flight_size as f64 * (1.0 - b)) as u32).max(2 * self.mss)
    }

    fn a(w: u32) -> f64 {
        if w <= HS_LOW_WINDOW {
            return 1.0;
        }
        let bw = Self::b(w);
        let p = 0.078 / (w as f64).powf(1.2);
        let wf = w as f64;
        wf * wf * p * 2.0 * bw / (2.0 - bw)
    }
}

impl CongestionController for HighSpeed {
    fn on_ack(&mut self, bytes_acked: u32) {
        self.on_new_ack(bytes_acked, u32::MAX);
    }

    fn on_new_ack(&mut self, bytes_acked: u32, flight_size: u32) {
        self.dup_ack_cnt = 0;
        if !cwnd_limited(self.cwnd, self.ssthresh, self.mss, flight_size) {
            return;
        }
        if self.cwnd < self.ssthresh {
            let inc = bytes_acked.min(self.mss);
            self.cwnd = self.cwnd.saturating_add(inc);
        } else {
            let w_segs = self.cwnd / self.mss;
            let a = Self::a(w_segs);
            let inc = (a * self.mss as f64 * self.mss as f64 / self.cwnd as f64) as u32;
            let inc = inc.max(1);
            self.cwnd = self.cwnd.saturating_add(inc);
        }
    }

    fn on_dup_ack(&mut self) -> bool {
        self.dup_ack_cnt += 1;
        if self.dup_ack_cnt == 3 && !self.recovery {
            return true;
        }
        if self.recovery && self.dup_ack_cnt > 3 {
            self.cwnd = self.cwnd.saturating_add(self.mss);
        }
        false
    }

    fn on_timeout(&mut self) {
        self.on_retransmit_timeout(self.cwnd, false);
    }

    fn on_retransmit_timeout(&mut self, flight_size: u32, repeated: bool) {
        if !repeated {
            self.ssthresh = self.decreased(flight_size);
        }
        self.cwnd = self.mss;
        self.recovery = false;
        self.dup_ack_cnt = 0;
        self.recovery_seq = 0;
    }

    fn on_fast_retransmit(&mut self, flight_size: u32, snd_nxt: u32) {
        self.ssthresh = self.decreased(flight_size);
        self.cwnd = self.ssthresh.saturating_add(3 * self.mss);
        self.recovery = true;
        self.recovery_seq = snd_nxt;
    }

    fn on_partial_ack(&mut self, bytes_acked: u32) {
        self.cwnd = deflate(self.cwnd, self.mss, bytes_acked);
    }

    fn exit_recovery(&mut self) {
        self.cwnd = self.ssthresh;
        self.recovery = false;
        self.dup_ack_cnt = 0;
        self.recovery_seq = 0;
    }

    fn send_window(&self) -> u32 {
        self.cwnd
    }
    fn in_recovery(&self) -> bool {
        self.recovery
    }
    fn recovery_seq(&self) -> u32 {
        self.recovery_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_grows_per_ack() {
        let mut nr = NewReno::new(1460);
        let initial = nr.send_window();
        nr.on_ack(1460);
        assert!(nr.send_window() > initial);
    }

    #[test]
    fn timeout_collapses_cwnd_to_one_mss() {
        let mut nr = NewReno::new(1460);
        nr.on_timeout();
        assert_eq!(nr.send_window(), 1460);
    }

    #[test]
    fn third_dup_ack_triggers_fast_retransmit() {
        let mut nr = NewReno::new(1460);
        assert!(!nr.on_dup_ack());
        assert!(!nr.on_dup_ack());
        assert!(nr.on_dup_ack());
    }

    #[test]
    fn fast_retransmit_then_exit() {
        let mut nr = NewReno::new(1460);
        nr.on_fast_retransmit(20_000, 50_000);
        assert!(nr.in_recovery());
        assert_eq!(nr.recovery_seq(), 50_000);
        nr.exit_recovery();
        assert!(!nr.in_recovery());
        assert_eq!(nr.send_window(), nr.ssthresh());
    }

    #[test]
    fn highspeed_decrease_is_clamped_past_high_window() {
        assert_eq!(HighSpeed::b(83_000), HS_HIGH_DECREASE);
        assert_eq!(HighSpeed::b(1_000_000), HS_HIGH_DECREASE);
        let mss = 1000;
        let mut hs = HighSpeed::new(mss);
        hs.cwnd = 4_000_000_000;
        hs.on_fast_retransmit(hs.cwnd, 0);
        assert_eq!(hs.ssthresh(), 3_600_000_000);
    }

    // RFC 5681 eq. (4): ssthresh is half the flight, not half of cwnd.
    #[test]
    fn loss_halves_the_flight_not_cwnd() {
        let mss = 1000;
        let mut nr = NewReno::new(mss);
        nr.cwnd = 100 * mss;
        nr.on_retransmit_timeout(20 * mss, false);
        assert_eq!(nr.ssthresh(), 10 * mss);
        // A second timeout of the same segment keeps it.
        nr.on_retransmit_timeout(20 * mss, true);
        assert_eq!(nr.ssthresh(), 10 * mss);

        let mut hs = HighSpeed::new(mss);
        hs.cwnd = 30 * mss;
        hs.on_fast_retransmit(20 * mss, 0);
        assert_eq!(hs.ssthresh(), 10 * mss);
        let mut hs = HighSpeed::new(mss);
        hs.cwnd = 30 * mss;
        hs.on_retransmit_timeout(20 * mss, false);
        assert_eq!(hs.ssthresh(), 10 * mss);
    }

    // An application-limited flow does not grow cwnd (RFC 7661).
    #[test]
    fn cwnd_grows_only_when_in_use() {
        let mss = 1000;
        let controllers: [Box<dyn CongestionController>; 2] =
            [Box::new(NewReno::new(mss)), Box::new(HighSpeed::new(mss))];
        for mut cc in controllers {
            let initial = cc.send_window();
            for _ in 0..100 {
                cc.on_new_ack(mss, 2 * mss);
            }
            assert_eq!(cc.send_window(), initial);
            cc.on_new_ack(mss, initial);
            assert_eq!(cc.send_window(), initial + mss);
        }
    }

    #[test]
    fn highspeed_matches_newreno_below_low_window() {
        let mss = 1460;
        let mut nr = NewReno::new(mss);
        let mut hs = HighSpeed::new(mss);
        for _ in 0..5 {
            nr.on_ack(mss);
            hs.on_ack(mss);
        }
        assert_eq!(nr.send_window(), hs.send_window());
    }
}

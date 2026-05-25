//! Congestion control. NewReno (RFC 5681) and HighSpeed TCP (RFC 3649).

/// Pluggable congestion-control trait.
///
/// The connection treats this as an opaque controller; it only cares about
/// the current send window and a handful of events.
pub trait CongestionController: Send {
    /// New (cumulative) ACK: `bytes_acked` bytes were freshly acknowledged.
    fn on_ack(&mut self, bytes_acked: u32);
    /// A duplicate ACK arrived. Returns true on the 3rd dup ACK (caller
    /// should trigger fast retransmit).
    fn on_dup_ack(&mut self) -> bool;
    /// RTO fired; loss inferred via timeout.
    fn on_timeout(&mut self);
    /// Fast retransmit triggered; enter recovery.
    fn on_fast_retransmit(&mut self, flight_size: u32, snd_nxt: u32);
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
        self.dup_ack_cnt = 0;
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
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
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
        (HS_HIGH_DECREASE - 0.5) * (log_w - log_low) / (log_high - log_low) + 0.5
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
        self.dup_ack_cnt = 0;
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
        let w_segs = self.cwnd / self.mss;
        let b = Self::b(w_segs);
        let mut ss = (self.cwnd as f64 * (1.0 - b)) as u32;
        if ss < 2 * self.mss {
            ss = 2 * self.mss;
        }
        self.ssthresh = ss;
        self.cwnd = self.mss;
        self.recovery = false;
        self.dup_ack_cnt = 0;
        self.recovery_seq = 0;
    }

    fn on_fast_retransmit(&mut self, _flight_size: u32, snd_nxt: u32) {
        let w_segs = self.cwnd / self.mss;
        let b = Self::b(w_segs);
        let mut ss = (self.cwnd as f64 * (1.0 - b)) as u32;
        if ss < 2 * self.mss {
            ss = 2 * self.mss;
        }
        self.ssthresh = ss;
        self.cwnd = self.ssthresh.saturating_add(3 * self.mss);
        self.recovery = true;
        self.recovery_seq = snd_nxt;
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

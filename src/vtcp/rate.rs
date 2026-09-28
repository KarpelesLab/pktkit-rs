//! Delivery rate estimation (draft-cheng-iccrg-delivery-rate-estimation,
//! as folded into draft-ietf-ccwg-bbr §4.1).
//!
//! Each transmission takes a snapshot of how much the connection had
//! delivered by then, and when; when it is delivered (cumulatively or
//! selectively acknowledged), the data delivered since that snapshot over
//! the time since gives a delivery rate sample. The interval is the longer
//! of the send and the ACK intervals, so that neither a burst of sends nor
//! a burst of compressed ACKs reads as a rate the path never carried.
//!
//! Samples taken while the application, not the network, kept the sender
//! short of its window are marked application-limited: they show what the
//! application offered, not what the path can take. A controller that
//! models the path (BBR) keeps them out of its bandwidth estimate unless
//! they exceed it.
//!
//! Times are nanoseconds since the scoreboard's epoch, amounts are bytes.

use std::time::Duration;

/// What a transmission carries away of the connection's delivery state
/// (the draft's per-packet `P` state).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct TxState {
    /// C.delivered when it was sent.
    pub delivered: u64,
    /// C.delivered_time when it was sent.
    pub delivered_time: u64,
    /// C.first_send_time when it was sent.
    pub first_sent: u64,
    /// C.lost when it was sent.
    pub lost: u64,
    /// Bytes in flight just after it was sent, itself included.
    pub tx_in_flight: u32,
    /// Sent while the connection was application-limited.
    pub app_limited: bool,
}

/// A delivery rate sample: what one ACK tells about the path (the draft's
/// `RS`). Taken from the most recently sent of the segments it delivered.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RateSample {
    /// Bytes per second; zero when the interval was too short to trust (a
    /// sample is still returned then, for its other fields).
    pub delivery_rate: u64,
    /// Bytes delivered over the interval.
    pub delivered: u64,
    /// The interval: the longer of the send and ACK intervals.
    pub interval: Duration,
    /// C.delivered when the segment the sample is taken from was sent:
    /// what packet-timed round trips are counted by.
    pub prior_delivered: u64,
    /// The sample reflects the application's pace, not the path's.
    pub is_app_limited: bool,
    /// Bytes in flight when that segment was sent.
    pub tx_in_flight: u32,
    /// Bytes marked lost between its transmission and now.
    pub lost: u64,
}

/// What the newest segment delivered by the ACK being processed said.
#[derive(Debug, Clone, Copy)]
struct Newest {
    xmit: u64,
    end: u64,
    tx: TxState,
    send_elapsed: u64,
    ack_elapsed: u64,
}

/// The connection's delivery state (the draft's `C` state).
#[derive(Debug, Default)]
pub(crate) struct Rate {
    /// Bytes delivered over the connection's life, SACKed or cumulatively
    /// acknowledged, spurious retransmissions included.
    delivered: u64,
    /// When `delivered` last grew.
    delivered_time: u64,
    /// The send time of the segment most recently delivered, or, after an
    /// idle spell, of the first one sent since.
    first_sent: u64,
    /// While application-limited, `delivered` at which the bubble ends;
    /// zero otherwise.
    app_limited: u64,
    /// Bytes marked lost over the connection's life.
    lost: u64,
    /// The sample the ACK in progress is building.
    newest: Option<Newest>,
}

impl Rate {
    /// Bytes delivered so far (C.delivered).
    #[inline]
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Bytes marked lost so far (C.lost).
    #[inline]
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Whether the connection is application-limited now.
    #[inline]
    pub fn is_app_limited(&self) -> bool {
        self.app_limited != 0
    }

    /// A segment of `len` bytes goes out at `now` with `in_flight` bytes
    /// in flight before it: its snapshot (OnPacketSent). With nothing in
    /// flight, the interval starts now: any ACK from here on shows what the
    /// network delivered since.
    pub fn on_send(&mut self, now: u64, in_flight: u32, len: u32) -> TxState {
        if in_flight == 0 {
            self.first_sent = now;
            self.delivered_time = now;
        }
        TxState {
            delivered: self.delivered,
            delivered_time: self.delivered_time,
            first_sent: self.first_sent,
            lost: self.lost,
            tx_in_flight: in_flight.saturating_add(len),
            app_limited: self.app_limited != 0,
        }
    }

    /// `len` bytes of a segment were marked lost.
    #[inline]
    pub fn on_lost(&mut self, len: u64) {
        self.lost += len;
    }

    /// `len` bytes of a segment were acknowledged without the segment being
    /// delivered whole (a cumulative ACK ending inside it).
    #[inline]
    pub fn on_partial(&mut self, len: u64) {
        self.delivered += len;
    }

    /// A segment `[.., end)` of `len` bytes, last sent at `xmit` with
    /// snapshot `tx`, was delivered at `now` (UpdateRateSample).
    pub fn on_delivered(&mut self, tx: &TxState, xmit: u64, end: u64, len: u64, now: u64) {
        self.delivered += len;
        self.delivered_time = now;
        let newest = match self.newest {
            None => true,
            Some(n) => xmit > n.xmit || (xmit == n.xmit && end > n.end),
        };
        if newest {
            self.newest = Some(Newest {
                xmit,
                end,
                tx: *tx,
                send_elapsed: xmit.saturating_sub(tx.first_sent),
                ack_elapsed: now.saturating_sub(tx.delivered_time),
            });
            self.first_sent = xmit;
        }
    }

    /// The sample of the ACK just processed, if it delivered anything
    /// (GenerateRateSample). `min_rtt` in nanoseconds: a shorter interval
    /// than a round trip cannot be a rate the path sustained, and gives a
    /// sample without a rate.
    pub fn sample(&mut self, min_rtt: Option<u64>) -> Option<RateSample> {
        if self.app_limited != 0 && self.delivered > self.app_limited {
            self.app_limited = 0;
        }
        let n = self.newest.take()?;
        let interval = n.send_elapsed.max(n.ack_elapsed);
        let delivered = self.delivered - n.tx.delivered;
        let mut rs = RateSample {
            delivery_rate: 0,
            delivered,
            interval: Duration::from_nanos(interval),
            prior_delivered: n.tx.delivered,
            is_app_limited: n.tx.app_limited,
            tx_in_flight: n.tx.tx_in_flight,
            lost: self.lost - n.tx.lost,
        };
        if interval > 0 && min_rtt.is_none_or(|m| interval >= m) {
            let rate = u128::from(delivered) * 1_000_000_000 / u128::from(interval);
            rs.delivery_rate = rate.min(u128::from(u64::MAX)) as u64;
        }
        Some(rs)
    }

    /// The sender has nothing to send that the window would let out: what
    /// goes out from here until what is in flight now is delivered shows the
    /// application's pace (MarkConnectionAppLimited).
    pub fn mark_app_limited(&mut self, in_flight: u32) {
        self.app_limited = (self.delivered + u64::from(in_flight)).max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    /// Ten segments of 1000 bytes sent 1 ms apart into an idle path, each
    /// delivered 50 ms later: the last sample spans the whole exchange.
    #[test]
    fn steady_flow_samples_its_rate() {
        let mut r = Rate::default();
        let mut sent = Vec::new();
        for i in 0..10u64 {
            let in_flight = (i * 1000) as u32;
            sent.push((i * MS, r.on_send(i * MS, in_flight, 1000)));
        }
        let mut last = None;
        for (i, (xmit, tx)) in sent.iter().enumerate() {
            let now = xmit + 50 * MS;
            r.on_delivered(tx, *xmit, (i as u64 + 1) * 1000, 1000, now);
            last = r.sample(Some(40 * MS));
        }
        let rs = last.unwrap();
        // The last segment was sent with nothing delivered, 9 ms after the
        // first went out: delivered 10 kB over max(9 ms, 59 ms).
        assert_eq!(rs.delivered, 10_000);
        assert_eq!(rs.interval, Duration::from_millis(59));
        assert_eq!(rs.delivery_rate, 10_000 * 1000 / 59);
        assert_eq!(rs.tx_in_flight, 10_000);
        assert!(!rs.is_app_limited);
    }

    /// Once the flow is ACK-clocked, a segment sent on an ACK measures the
    /// data delivered over one round trip.
    #[test]
    fn ack_clocked_sample_covers_a_round_trip() {
        let mut r = Rate::default();
        let a = r.on_send(0, 0, 1000);
        r.on_delivered(&a, 0, 1000, 1000, 100 * MS);
        r.sample(None);
        // Sent on that ACK, with 3000 more bytes then delivered by the time
        // it arrives 100 ms later.
        let b = r.on_send(100 * MS, 0, 1000);
        let c = r.on_send(100 * MS, 1000, 1000);
        r.on_delivered(&b, 100 * MS, 2000, 1000, 200 * MS);
        r.on_delivered(&c, 100 * MS, 3000, 1000, 200 * MS);
        let rs = r.sample(Some(100 * MS)).unwrap();
        assert_eq!(rs.prior_delivered, 1000);
        assert_eq!(rs.delivered, 2000);
        assert_eq!(rs.interval, Duration::from_millis(100));
        assert_eq!(rs.delivery_rate, 20_000);
        assert_eq!(rs.tx_in_flight, 2000, "the newest of the two");
    }

    /// An interval shorter than the minimum RTT gives no rate, but the
    /// sample's other fields stand.
    #[test]
    fn short_interval_has_no_rate() {
        let mut r = Rate::default();
        let a = r.on_send(0, 0, 1000);
        r.on_delivered(&a, 0, 1000, 1000, 5 * MS);
        let rs = r.sample(Some(10 * MS)).unwrap();
        assert_eq!(rs.delivery_rate, 0);
        assert_eq!(rs.delivered, 1000);
        assert!(r.sample(None).is_none(), "nothing more delivered");
    }

    /// Segments sent while application-limited give app-limited samples
    /// until what was in flight when the bubble began has been delivered.
    #[test]
    fn app_limited_bubble_ends_once_delivered() {
        let mut r = Rate::default();
        let a = r.on_send(0, 0, 1000);
        r.mark_app_limited(1000);
        assert!(r.is_app_limited());
        let b = r.on_send(MS, 1000, 1000);
        assert!(!a.app_limited && b.app_limited);
        r.on_delivered(&a, 0, 1000, 1000, 50 * MS);
        let rs = r.sample(None).unwrap();
        assert!(!rs.is_app_limited);
        assert!(r.is_app_limited(), "the bubble is not yet delivered");
        let c = r.on_send(50 * MS, 1000, 1000);
        r.on_delivered(&b, MS, 2000, 1000, 51 * MS);
        let rs = r.sample(None).unwrap();
        assert!(rs.is_app_limited);
        assert!(!r.is_app_limited(), "past the bubble");
        r.on_delivered(&c, 50 * MS, 3000, 1000, 100 * MS);
        assert!(r.sample(None).unwrap().is_app_limited, "sent inside it");
        let d = r.on_send(100 * MS, 0, 1000);
        assert!(!d.app_limited);
    }

    /// Losses between a segment's transmission and its delivery are
    /// reported with its sample.
    #[test]
    fn losses_since_transmission_are_counted() {
        let mut r = Rate::default();
        let a = r.on_send(0, 0, 1000);
        let _b = r.on_send(0, 1000, 1000);
        let c = r.on_send(0, 2000, 1000);
        r.on_lost(1000);
        r.on_delivered(&a, 0, 1000, 1000, 10 * MS);
        r.on_delivered(&c, 0, 3000, 1000, 10 * MS);
        let rs = r.sample(None).unwrap();
        assert_eq!((rs.lost, rs.tx_in_flight), (1000, 3000));
        assert_eq!(r.lost(), 1000);
        assert_eq!(r.delivered(), 2000);
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

/// A snapshot of a device's counters, taken at one instant.
///
/// Returned by [`DeviceStats::snapshot`]. Because the underlying counters are
/// updated without a lock, the fields of one snapshot may not be perfectly
/// consistent with each other under concurrent traffic — near enough for
/// monitoring, not a transactional view.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Packets or frames handed to the device's handler.
    pub rx_packets: u64,
    /// Bytes received, counted at the same layer as the device operates.
    pub rx_bytes: u64,
    /// Packets or frames transmitted successfully.
    pub tx_packets: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Inbound messages the device discarded — too short, unroutable, no
    /// handler installed, or a full queue.
    pub rx_dropped: u64,
    /// Outbound messages discarded before they reached the wire.
    pub tx_dropped: u64,
    /// I/O errors encountered while reading or writing.
    pub errors: u64,
}

/// Traffic counters for a device.
///
/// Devices expose these through [`L2Device::stats`](crate::L2Device::stats) and
/// [`L3Device::stats`](crate::L3Device::stats), which default to `None` — an
/// implementation opts in by holding a `DeviceStats` and returning it.
///
/// When a packet vanishes inside a topology, these are what tell you where.
/// Counters saturate rather than wrap, so a long-running process cannot show a
/// count going backwards.
///
/// ```
/// # use pktkit::{DeviceStats, L2Device, PipeL2, MacAddr, Frame, EtherType, build_frame};
/// let pipe = PipeL2::new(MacAddr::zero());
/// let buf = build_frame(MacAddr::broadcast(), MacAddr::zero(), EtherType::IPV4, &[0; 46]);
/// pipe.send(Frame::from_slice(&buf)).unwrap();
///
/// let s = pipe.stats().unwrap().snapshot();
/// assert_eq!(s.tx_packets, 1);
/// assert_eq!(s.tx_bytes, buf.len() as u64);
/// // Nothing was listening, so the frame was dropped rather than delivered.
/// assert_eq!(s.tx_dropped, 1);
/// ```
#[derive(Debug, Default)]
pub struct DeviceStats {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_dropped: AtomicU64,
    tx_dropped: AtomicU64,
    errors: AtomicU64,
}

impl DeviceStats {
    /// Create a zeroed counter set.
    pub fn new() -> DeviceStats {
        DeviceStats::default()
    }

    /// Record a received message of `bytes` bytes.
    #[inline]
    pub fn record_rx(&self, bytes: usize) {
        bump(&self.rx_packets, 1);
        bump(&self.rx_bytes, bytes as u64);
    }

    /// Record a transmitted message of `bytes` bytes.
    #[inline]
    pub fn record_tx(&self, bytes: usize) {
        bump(&self.tx_packets, 1);
        bump(&self.tx_bytes, bytes as u64);
    }

    /// Record an inbound message that was discarded.
    #[inline]
    pub fn record_rx_drop(&self) {
        bump(&self.rx_dropped, 1);
    }

    /// Record an outbound message that was discarded.
    #[inline]
    pub fn record_tx_drop(&self) {
        bump(&self.tx_dropped, 1);
    }

    /// Record an I/O error.
    #[inline]
    pub fn record_error(&self) {
        bump(&self.errors, 1);
    }

    /// Read every counter.
    pub fn snapshot(&self) -> Stats {
        Stats {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }

    /// Reset every counter to zero.
    pub fn reset(&self) {
        for c in [
            &self.rx_packets,
            &self.rx_bytes,
            &self.tx_packets,
            &self.tx_bytes,
            &self.rx_dropped,
            &self.tx_dropped,
            &self.errors,
        ] {
            c.store(0, Ordering::Relaxed);
        }
    }
}

/// A snapshot of a hub's counters. See [`HubStats`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HubCounters {
    /// Messages that arrived at the hub from a connected port.
    pub received: u64,
    /// Copies delivered to a specific port because the hub knew where the
    /// destination lived.
    pub forwarded: u64,
    /// Messages flooded to every port but the source — broadcast, multicast,
    /// or a destination the hub has not learned. Counted once per message, not
    /// once per copy.
    pub flooded: u64,
    /// Messages the hub had nowhere to send, or refused as malformed. A
    /// climbing count here is where "my packet disappeared" usually ends.
    pub dropped: u64,
}

/// Traffic counters for a hub.
///
/// A hub sees every message twice over — once arriving, once or many times
/// leaving — so its counters answer a different question than a device's:
/// not "how much traffic", but "did the hub know where to send it".
#[derive(Debug, Default)]
pub struct HubStats {
    received: AtomicU64,
    forwarded: AtomicU64,
    flooded: AtomicU64,
    dropped: AtomicU64,
}

impl HubStats {
    pub fn new() -> HubStats {
        HubStats::default()
    }

    #[inline]
    pub fn record_received(&self) {
        bump(&self.received, 1);
    }

    /// Record `n` copies delivered to known ports.
    #[inline]
    pub fn record_forwarded(&self, n: u64) {
        bump(&self.forwarded, n);
    }

    #[inline]
    pub fn record_flooded(&self) {
        bump(&self.flooded, 1);
    }

    #[inline]
    pub fn record_dropped(&self) {
        bump(&self.dropped, 1);
    }

    pub fn snapshot(&self) -> HubCounters {
        HubCounters {
            received: self.received.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            flooded: self.flooded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        for c in [
            &self.received,
            &self.forwarded,
            &self.flooded,
            &self.dropped,
        ] {
            c.store(0, Ordering::Relaxed);
        }
    }
}

/// Add to a counter, saturating instead of wrapping.
#[inline]
fn bump(counter: &AtomicU64, by: u64) {
    // Relaxed is right here: counters are read for reporting, never to
    // establish ordering with the data plane.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(by))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let s = DeviceStats::new();
        s.record_rx(100);
        s.record_rx(50);
        s.record_tx(10);
        s.record_rx_drop();
        s.record_tx_drop();
        s.record_error();

        let snap = s.snapshot();
        assert_eq!(snap.rx_packets, 2);
        assert_eq!(snap.rx_bytes, 150);
        assert_eq!(snap.tx_packets, 1);
        assert_eq!(snap.tx_bytes, 10);
        assert_eq!(snap.rx_dropped, 1);
        assert_eq!(snap.tx_dropped, 1);
        assert_eq!(snap.errors, 1);
    }

    #[test]
    fn reset_zeroes_everything() {
        let s = DeviceStats::new();
        s.record_rx(1);
        s.record_tx(1);
        s.reset();
        assert_eq!(s.snapshot(), Stats::default());
    }

    #[test]
    fn counters_saturate() {
        let s = DeviceStats::new();
        s.rx_bytes.store(u64::MAX - 1, Ordering::Relaxed);
        s.record_rx(1000);
        assert_eq!(s.snapshot().rx_bytes, u64::MAX, "must not wrap to zero");
    }

    #[test]
    fn shared_across_threads() {
        use std::sync::Arc;
        let s = Arc::new(DeviceStats::new());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = s.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    s.record_rx(10);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let snap = s.snapshot();
        assert_eq!(snap.rx_packets, 4000);
        assert_eq!(snap.rx_bytes, 40000);
    }
}

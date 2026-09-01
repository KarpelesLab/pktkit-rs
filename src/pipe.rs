use crate::{
    DeviceStats, Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Result,
};
use std::sync::Mutex;

/// A simple in-memory [`L2Device`] useful for tests and for wiring subpackages.
///
/// Frames passed to [`send`](L2Device::send) are forwarded to the installed
/// handler. [`inject`](PipeL2::inject) is the same operation, named to read
/// well in test code where the direction is "incoming from the wire".
pub struct PipeL2 {
    handler: Mutex<Option<L2Handler>>,
    mac: MacAddr,
    stats: DeviceStats,
}

impl PipeL2 {
    /// Create a new pipe with the given MAC address.
    pub fn new(mac: MacAddr) -> PipeL2 {
        PipeL2 {
            handler: Mutex::new(None),
            mac,
            stats: DeviceStats::new(),
        }
    }

    /// Push a frame through the handler as if it had been received from the
    /// network. Delivery is identical to [`send`](L2Device::send); the two
    /// differ only in which counters they move, so a test can tell the
    /// directions apart.
    pub fn inject(&self, f: &Frame) -> Result<()> {
        self.stats.record_rx(f.len());
        match self.take_handler() {
            Some(h) => h(f),
            None => {
                self.stats.record_rx_drop();
                Ok(())
            }
        }
    }

    /// Clone the handler out from under the lock. Invoking it while holding
    /// the lock would deadlock if it called back into this pipe.
    fn take_handler(&self) -> Option<L2Handler> {
        self.handler
            .lock()
            .expect("PipeL2 handler poisoned")
            .clone()
    }
}

impl core::fmt::Debug for PipeL2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeL2").field("mac", &self.mac).finish()
    }
}

impl L2Device for PipeL2 {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.lock().expect("PipeL2 handler poisoned") = Some(h);
    }

    fn send(&self, f: &Frame) -> Result<()> {
        self.stats.record_tx(f.len());
        // Clone the Arc out, drop the lock, then invoke. This lets the handler
        // call back into another pipe without re-entering the same mutex.
        match self.take_handler() {
            Some(h) => h(f),
            None => {
                self.stats.record_tx_drop();
                Ok(())
            }
        }
    }

    fn hw_addr(&self) -> MacAddr {
        self.mac
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.stats)
    }
}

/// A simple in-memory [`L3Device`] useful for tests.
pub struct PipeL3 {
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
    stats: DeviceStats,
}

impl PipeL3 {
    /// Create a new pipe with the given IP prefix.
    pub fn new(addr: IpPrefix) -> PipeL3 {
        PipeL3 {
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            stats: DeviceStats::new(),
        }
    }

    /// Push a packet through the handler as if it had been received from the
    /// network.
    pub fn inject(&self, p: &Packet) -> Result<()> {
        self.stats.record_rx(p.len());
        match self.take_handler() {
            Some(h) => h(p),
            None => {
                self.stats.record_rx_drop();
                Ok(())
            }
        }
    }

    fn take_handler(&self) -> Option<L3Handler> {
        self.handler
            .lock()
            .expect("PipeL3 handler poisoned")
            .clone()
    }
}

impl core::fmt::Debug for PipeL3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeL3")
            .field("addr", &self.addr())
            .finish()
    }
}

impl L3Device for PipeL3 {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().expect("PipeL3 handler poisoned") = Some(h);
    }

    fn send(&self, p: &Packet) -> Result<()> {
        self.stats.record_tx(p.len());
        match self.take_handler() {
            Some(h) => h(p),
            None => {
                self.stats.record_tx_drop();
                Ok(())
            }
        }
    }

    fn addr(&self) -> IpPrefix {
        *self.addr.lock().expect("PipeL3 addr poisoned")
    }

    fn set_addr(&self, prefix: IpPrefix) -> Result<()> {
        *self.addr.lock().expect("PipeL3 addr poisoned") = prefix;
        Ok(())
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_frame, EtherType};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn pipe_l2_invokes_handler() {
        let p = PipeL2::new(MacAddr::zero());
        let n = Arc::new(AtomicUsize::new(0));
        let nn = n.clone();
        p.set_handler(Arc::new(move |_f: &Frame| {
            nn.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));

        let buf = build_frame(MacAddr::zero(), MacAddr::zero(), EtherType::IPV4, &[]);
        let f = Frame::from_slice(&buf);
        p.send(f).unwrap();
        p.inject(f).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pipe_l2_no_handler_is_silent() {
        let p = PipeL2::new(MacAddr::zero());
        let buf = build_frame(MacAddr::zero(), MacAddr::zero(), EtherType::IPV4, &[]);
        let f = Frame::from_slice(&buf);
        p.send(f).unwrap();
    }

    #[test]
    fn pipe_counts_both_directions() {
        let p = PipeL2::new(MacAddr::zero());
        let buf = build_frame(MacAddr::zero(), MacAddr::zero(), EtherType::IPV4, &[0; 10]);
        let f = Frame::from_slice(&buf);

        // No handler yet: both directions count as dropped.
        p.send(f).unwrap();
        p.inject(f).unwrap();
        let s = p.stats().unwrap().snapshot();
        assert_eq!((s.tx_packets, s.tx_dropped), (1, 1));
        assert_eq!((s.rx_packets, s.rx_dropped), (1, 1));
        assert_eq!(s.rx_bytes, buf.len() as u64);

        p.set_handler(Arc::new(|_f: &Frame| Ok(())));
        p.inject(f).unwrap();
        let s = p.stats().unwrap().snapshot();
        assert_eq!(s.rx_packets, 2);
        assert_eq!(s.rx_dropped, 1, "the delivered frame was not dropped");
    }

    #[test]
    fn pipe_l3_set_addr() {
        let pfx: IpPrefix = "10.0.0.1/24".parse().unwrap();
        let p = PipeL3::new(pfx);
        assert_eq!(p.addr(), pfx);
        let new: IpPrefix = "10.0.0.2/24".parse().unwrap();
        p.set_addr(new).unwrap();
        assert_eq!(p.addr(), new);
    }
}

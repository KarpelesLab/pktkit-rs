use crate::{Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Result};
use std::sync::Mutex;

/// A simple in-memory [`L2Device`] useful for tests and for wiring subpackages.
///
/// Frames passed to [`send`](L2Device::send) are forwarded to the installed
/// handler. [`inject`](PipeL2::inject) is the same operation, named to read
/// well in test code where the direction is "incoming from the wire".
pub struct PipeL2 {
    handler: Mutex<Option<L2Handler>>,
    mac: MacAddr,
}

impl PipeL2 {
    /// Create a new pipe with the given MAC address.
    pub fn new(mac: MacAddr) -> PipeL2 {
        PipeL2 {
            handler: Mutex::new(None),
            mac,
        }
    }

    /// Push a frame through the handler as if it had been received from the
    /// network. Equivalent to [`send`](L2Device::send) — provided to make
    /// test direction explicit.
    pub fn inject(&self, f: &Frame) -> Result<()> {
        self.send(f)
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
        // Clone the Arc out, drop the lock, then invoke. This lets the handler
        // call back into another pipe without re-entering the same mutex.
        let h = self.handler.lock().expect("PipeL2 handler poisoned").clone();
        match h {
            Some(h) => h(f),
            None => Ok(()),
        }
    }

    fn hw_addr(&self) -> MacAddr {
        self.mac
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// A simple in-memory [`L3Device`] useful for tests.
pub struct PipeL3 {
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
}

impl PipeL3 {
    /// Create a new pipe with the given IP prefix.
    pub fn new(addr: IpPrefix) -> PipeL3 {
        PipeL3 {
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
        }
    }

    /// Push a packet through the handler as if it had been received from the
    /// network.
    pub fn inject(&self, p: &Packet) -> Result<()> {
        self.send(p)
    }
}

impl core::fmt::Debug for PipeL3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeL3").field("addr", &self.addr()).finish()
    }
}

impl L3Device for PipeL3 {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().expect("PipeL3 handler poisoned") = Some(h);
    }

    fn send(&self, p: &Packet) -> Result<()> {
        let h = self.handler.lock().expect("PipeL3 handler poisoned").clone();
        match h {
            Some(h) => h(p),
            None => Ok(()),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_frame, EtherType};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    fn pipe_l3_set_addr() {
        let pfx: IpPrefix = "10.0.0.1/24".parse().unwrap();
        let p = PipeL3::new(pfx);
        assert_eq!(p.addr(), pfx);
        let new: IpPrefix = "10.0.0.2/24".parse().unwrap();
        p.set_addr(new).unwrap();
        assert_eq!(p.addr(), new);
    }
}

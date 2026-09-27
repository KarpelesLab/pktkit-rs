use crate::l2hub::DepthGuard;
use crate::{Frame, L2Device, L3Device, Packet};
use std::sync::Arc;

/// Wire two [`L2Device`]s point-to-point: frames produced by one are delivered
/// to the other.
///
/// `a` owns the wiring. Its handler holds `b`, while `b`'s handler holds only
/// a weak reference back to `a`, so the pair is not a reference cycle: once
/// the last `Arc` to `a` is dropped, `a` goes, and `b` with it unless it is
/// shared elsewhere. Keep `a` for as long as the two should stay connected.
///
/// Delivery is a synchronous call from one device into the other, so a loop
/// in the topology is recursion. It is cut off, and the frame dropped, 16
/// hops deep on the thread, or as deep as the deepest
/// [`L2Hub::set_max_forward_depth`](crate::L2Hub::set_max_forward_depth)
/// allows. Two devices that hand what they are sent straight back to their
/// handler, such as two [`PipeL2`](crate::PipeL2)s, are such a loop.
///
/// ```
/// # #[cfg(feature = "l2adapter")] {
/// use pktkit::{L2Adapter, L2AdapterConfig, PipeL3, connect_l2};
///
/// // Two hosts on one cable: what either adapter sends reaches the other.
/// let host = |ip: &str| PipeL3::new(ip.parse().unwrap());
/// let a = L2Adapter::new(host("10.0.0.1/24"), L2AdapterConfig::default());
/// let b = L2Adapter::new(host("10.0.0.2/24"), L2AdapterConfig::default());
/// connect_l2(a.clone(), b);
/// # }
/// ```
pub fn connect_l2<A, B>(a: Arc<A>, b: B)
where
    A: L2Device + ?Sized + 'static,
    B: L2Device + 'static,
{
    let weak_a = Arc::downgrade(&a);
    b.set_handler(Arc::new(move |f: &Frame| {
        let Some(_depth) = DepthGuard::enter_shared() else {
            return Ok(());
        };
        match weak_a.upgrade() {
            Some(a) => a.send(f),
            None => Ok(()),
        }
    }));
    a.set_handler(Arc::new(move |f: &Frame| {
        let Some(_depth) = DepthGuard::enter_shared() else {
            return Ok(());
        };
        b.send(f)
    }));
}

/// Wire two [`L3Device`]s point-to-point.
///
/// As with [`connect_l2`], `a` owns the wiring and keeps `b` alive, `b`
/// refers back to `a` only weakly, and a loop between them is cut off.
pub fn connect_l3<A, B>(a: Arc<A>, b: B)
where
    A: L3Device + ?Sized + 'static,
    B: L3Device + 'static,
{
    let weak_a = Arc::downgrade(&a);
    b.set_handler(Arc::new(move |p: &Packet| {
        let Some(_depth) = DepthGuard::enter_shared() else {
            return Ok(());
        };
        match weak_a.upgrade() {
            Some(a) => a.send(p),
            None => Ok(()),
        }
    }));
    a.set_handler(Arc::new(move |p: &Packet| {
        let Some(_depth) = DepthGuard::enter_shared() else {
            return Ok(());
        };
        b.send(p)
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EtherType, Frame, IpPrefix, L2Handler, L3Handler, MacAddr, Packet, PipeL2, PipeL3, Result,
        build_frame,
    };
    use std::sync::{Arc, Mutex};

    // A minimal terminal L2Device that records every frame sent to it. Its
    // Send does not invoke a handler, so it doesn't loop when wired to a Pipe.
    #[derive(Default, Clone)]
    struct L2Recorder {
        inner: Arc<Mutex<Vec<Vec<u8>>>>,
        mac: MacAddr,
    }
    impl L2Device for L2Recorder {
        fn set_handler(&self, _h: L2Handler) {}
        fn send(&self, f: &Frame) -> Result<()> {
            self.inner.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            self.mac
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Default, Clone)]
    struct L3Recorder {
        inner: Arc<Mutex<Vec<Vec<u8>>>>,
        prefix: Arc<Mutex<IpPrefix>>,
    }
    impl L3Device for L3Recorder {
        fn set_handler(&self, _h: L3Handler) {}
        fn send(&self, p: &Packet) -> Result<()> {
            self.inner.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }
        fn addr(&self) -> IpPrefix {
            *self.prefix.lock().unwrap()
        }
        fn set_addr(&self, p: IpPrefix) -> Result<()> {
            *self.prefix.lock().unwrap() = p;
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pipe_to_recorder_l2() {
        let m1: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let m2: MacAddr = "02:00:00:00:00:02".parse().unwrap();
        let pipe = Arc::new(PipeL2::new(m1));
        let rec = L2Recorder {
            mac: m2,
            ..Default::default()
        };
        connect_l2(pipe.clone(), rec.clone());

        for i in 0..5u8 {
            let buf = build_frame(m2, m1, EtherType::IPV4, &[i]);
            pipe.inject(Frame::from_slice(&buf)).unwrap();
        }
        assert_eq!(rec.inner.lock().unwrap().len(), 5);
    }

    #[test]
    fn pipe_to_recorder_l3() {
        let pfx: IpPrefix = "10.0.0.1/24".parse().unwrap();
        let pipe = Arc::new(PipeL3::new(pfx));
        let rec = L3Recorder::default();
        rec.set_addr("10.0.0.2/24".parse().unwrap()).unwrap();
        connect_l3(pipe.clone(), rec.clone());

        // Build a minimal IPv4 packet
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        pipe.inject(Packet::from_slice(&p)).unwrap();
        assert_eq!(rec.inner.lock().unwrap().len(), 1);
    }

    #[test]
    fn two_pipes_wired_together_do_not_overflow_the_stack() {
        let a = Arc::new(PipeL2::new(MacAddr::zero()));
        let b = Arc::new(PipeL2::new(MacAddr::zero()));
        connect_l2(a.clone(), b.clone());
        let buf = build_frame(MacAddr::broadcast(), MacAddr::zero(), EtherType::IPV4, &[1]);
        // Run on a small stack: unbounded, the bouncing frame recurses until
        // it overflows.
        let a2 = a.clone();
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || a2.inject(Frame::from_slice(&buf)).unwrap())
            .unwrap()
            .join()
            .expect("recursed without bound");
        let tx = a.stats().unwrap().snapshot().tx_packets;
        assert!(tx < 64, "bounced {tx} times");

        let p = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let q = Arc::new(PipeL3::new("10.0.0.2/24".parse().unwrap()));
        connect_l3(p.clone(), q.clone());
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&20u16.to_be_bytes());
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || p.inject(Packet::from_slice(&pkt)).unwrap())
            .unwrap()
            .join()
            .expect("recursed without bound");
    }

    /// A chain an L2Hub was allowed to run deeper than 16 is not cut off
    /// where it crosses a point-to-point link, which used to hold to 16.
    #[test]
    fn a_link_honours_a_raised_hub_depth() {
        crate::L2Hub::new().set_max_forward_depth(24);
        let m1: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let pipe = Arc::new(PipeL2::new(m1));
        let rec = L2Recorder::default();
        connect_l2(pipe.clone(), rec.clone());
        let p3 = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let rec3 = L3Recorder::default();
        connect_l3(p3.clone(), rec3.clone());

        // As if 20 hubs deep already.
        let _deep: Vec<_> = (0..20)
            .map(|_| DepthGuard::enter(u32::MAX).unwrap())
            .collect();
        let buf = build_frame(m1, m1, EtherType::IPV4, &[1]);
        pipe.inject(Frame::from_slice(&buf)).unwrap();
        assert_eq!(rec.inner.lock().unwrap().len(), 1);
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p3.inject(Packet::from_slice(&p)).unwrap();
        assert_eq!(rec3.inner.lock().unwrap().len(), 1);
    }

    #[test]
    fn wiring_is_not_a_reference_cycle() {
        let a = Arc::new(PipeL2::new(MacAddr::zero()));
        let b = Arc::new(PipeL2::new(MacAddr::zero()));
        let (wa, wb) = (Arc::downgrade(&a), Arc::downgrade(&b));
        connect_l2(a, b);
        assert!(wa.upgrade().is_none(), "a leaked");
        assert!(wb.upgrade().is_none(), "b leaked");

        // While `a` is kept, it keeps `b`.
        let a = Arc::new(PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let b = Arc::new(PipeL3::new("10.0.0.2/24".parse().unwrap()));
        let wb = Arc::downgrade(&b);
        connect_l3(a.clone(), b);
        assert!(wb.upgrade().is_some());
        drop(a);
        assert!(wb.upgrade().is_none(), "b leaked");
    }
}

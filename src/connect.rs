use crate::{Frame, L2Device, L3Device, Packet};
use std::sync::Arc;

/// Wire two [`L2Device`]s point-to-point: frames produced by one are delivered
/// to the other.
///
/// Both devices must outlive the wiring; pass `Arc`s if their lifetimes are
/// distinct from the surrounding scope.
///
/// ```
/// # use std::sync::Arc;
/// # use pktkit::{PipeL2, MacAddr, connect_l2, L2Device, build_frame, EtherType, Frame};
/// let a = Arc::new(PipeL2::new(MacAddr::zero()));
/// let b = Arc::new(PipeL2::new(MacAddr::zero()));
/// connect_l2(a.clone(), b.clone());
///
/// // Frames sent into `a` reach `b` and vice-versa.
/// ```
pub fn connect_l2<A, B>(a: A, b: B)
where
    A: L2Device + Clone + 'static,
    B: L2Device + Clone + 'static,
{
    let b_for_a = b.clone();
    a.set_handler(Arc::new(move |f: &Frame| b_for_a.send(f)));
    let a_for_b = a;
    b.set_handler(Arc::new(move |f: &Frame| a_for_b.send(f)));
}

/// Wire two [`L3Device`]s point-to-point.
pub fn connect_l3<A, B>(a: A, b: B)
where
    A: L3Device + Clone + 'static,
    B: L3Device + Clone + 'static,
{
    let b_for_a = b.clone();
    a.set_handler(Arc::new(move |p: &Packet| b_for_a.send(p)));
    let a_for_b = a;
    b.set_handler(Arc::new(move |p: &Packet| a_for_b.send(p)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_frame, EtherType, Frame, IpPrefix, L2Handler, L3Handler, MacAddr, Packet, PipeL2, PipeL3, Result};
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
}

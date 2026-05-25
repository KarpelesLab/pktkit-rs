use crate::{Frame, L2Device, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const MAC_AGING: Duration = Duration::from_secs(5 * 60);
const MAC_TABLE_MAX_SIZE: usize = 8192;

static PORT_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline]
fn next_port_id() -> u64 {
    PORT_ID_COUNTER.fetch_add(1, Ordering::Relaxed) + 1
}

struct Port {
    dev: Arc<dyn L2Device>,
    id: u64,
}

#[derive(Copy, Clone)]
struct MacEntry {
    port_id: u64,
    expires: Instant,
}

/// A learning Ethernet switch.
///
/// `L2Hub` forwards Ethernet frames between connected devices: it learns
/// source MAC addresses, sends unicast frames only to the port associated with
/// the destination MAC, and floods unknown unicast / broadcast / multicast to
/// every port except the source.
///
/// The MAC table ages entries out after five minutes and is capped to 8192
/// entries to bound memory.
///
/// ```
/// # use std::sync::Arc;
/// # use pktkit::{L2Hub, PipeL2, MacAddr};
/// let hub = Arc::new(L2Hub::new());
/// let a = Arc::new(PipeL2::new("02:00:00:00:00:01".parse().unwrap()));
/// let _h = hub.connect(a.clone());
/// ```
pub struct L2Hub {
    // RwLock<Vec<Arc<Port>>> is read-heavy on the forwarding path; writers
    // (connect / disconnect) are rare.
    ports: RwLock<Vec<Arc<Port>>>,
    mac_table: Mutex<HashMap<[u8; 6], MacEntry>>,
}

impl Default for L2Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for L2Hub {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.ports.read().map(|p| p.len()).unwrap_or(0);
        f.debug_struct("L2Hub").field("ports", &n).finish()
    }
}

impl L2Hub {
    /// Create an empty learning switch.
    pub fn new() -> L2Hub {
        L2Hub {
            ports: RwLock::new(Vec::new()),
            mac_table: Mutex::new(HashMap::new()),
        }
    }

    /// Attach a device to the switch. The device's handler is installed to
    /// route received frames through the switch's learning logic. Returns a
    /// handle whose [`L2HubHandle::close`] disconnects the device.
    pub fn connect<D>(self: &Arc<Self>, dev: D) -> L2HubHandle
    where
        D: L2Device + 'static,
    {
        let id = next_port_id();
        let dev_arc: Arc<dyn L2Device> = Arc::new(dev);
        let port = Arc::new(Port {
            dev: dev_arc.clone(),
            id,
        });

        self.ports.write().unwrap().push(port);

        let hub = Arc::downgrade(self);
        dev_arc.set_handler(Arc::new(move |f: &Frame| {
            if let Some(hub) = hub.upgrade() {
                hub.forward(f, id);
            }
            Ok(())
        }));

        L2HubHandle {
            hub: Arc::downgrade(self),
            id,
            closed: Mutex::new(false),
        }
    }

    /// Same as [`connect`](Self::connect) but for devices already wrapped in `Arc`.
    pub fn connect_arc(self: &Arc<Self>, dev: Arc<dyn L2Device>) -> L2HubHandle {
        let id = next_port_id();
        let port = Arc::new(Port {
            dev: dev.clone(),
            id,
        });
        self.ports.write().unwrap().push(port);

        let hub = Arc::downgrade(self);
        dev.set_handler(Arc::new(move |f: &Frame| {
            if let Some(hub) = hub.upgrade() {
                hub.forward(f, id);
            }
            Ok(())
        }));

        L2HubHandle {
            hub: Arc::downgrade(self),
            id,
            closed: Mutex::new(false),
        }
    }

    fn forward(&self, f: &Frame, source_id: u64) {
        let bytes = f.as_bytes();
        if bytes.len() < 14 {
            return;
        }

        // Learn source MAC → port mapping.
        let mut src = [0u8; 6];
        src.copy_from_slice(&bytes[6..12]);
        {
            let mut table = self.mac_table.lock().unwrap();
            match table.get(&src) {
                Some(entry) if entry.port_id == source_id => {}
                Some(_) => {
                    // Same MAC moved ports; overwrite.
                    table.insert(
                        src,
                        MacEntry {
                            port_id: source_id,
                            expires: Instant::now() + MAC_AGING,
                        },
                    );
                }
                None => {
                    if table.len() < MAC_TABLE_MAX_SIZE {
                        table.insert(
                            src,
                            MacEntry {
                                port_id: source_id,
                                expires: Instant::now() + MAC_AGING,
                            },
                        );
                    }
                }
            }
        }

        // Snapshot the port list (cheap: clones Arcs).
        let ports: Vec<Arc<Port>> = self.ports.read().unwrap().clone();

        // Broadcast / multicast → flood to all ports except source.
        if bytes[0] & 1 != 0 {
            for p in &ports {
                if p.id != source_id {
                    let _ = p.dev.send(f);
                }
            }
            return;
        }

        // Unicast: look up the destination MAC.
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&bytes[0..6]);
        let target = {
            let mut table = self.mac_table.lock().unwrap();
            match table.get(&dst).copied() {
                Some(entry) if entry.expires > Instant::now() => Some(entry.port_id),
                Some(_) => {
                    table.remove(&dst);
                    None
                }
                None => None,
            }
        };

        if let Some(pid) = target {
            for p in &ports {
                if p.id == pid && p.id != source_id {
                    let _ = p.dev.send(f);
                    return;
                }
            }
            // Port vanished — fall through to flood.
        }

        // Unknown unicast → flood.
        for p in &ports {
            if p.id != source_id {
                let _ = p.dev.send(f);
            }
        }
    }

    fn disconnect(&self, id: u64) {
        self.ports.write().unwrap().retain(|p| p.id != id);
        // Drop any MAC table entries pointing at this port.
        self.mac_table.lock().unwrap().retain(|_, e| e.port_id != id);
    }
}

/// Implements [`L2Connector`](crate::L2Connector). Devices attached this way
/// always join the shared hub; the returned cleanup detaches them.
impl crate::L2Connector for Arc<L2Hub> {
    fn connect_l2(&self, dev: Arc<dyn L2Device>) -> Result<crate::Cleanup> {
        let handle = self.connect_arc(dev);
        let mut taken = Some(handle);
        Ok(Box::new(move || {
            if let Some(h) = taken.take() {
                h.close();
            }
            Ok(())
        }))
    }
}

/// Returned by [`L2Hub::connect`]; dropping or calling [`close`](Self::close)
/// detaches the device.
pub struct L2HubHandle {
    hub: std::sync::Weak<L2Hub>,
    id: u64,
    closed: Mutex<bool>,
}

impl core::fmt::Debug for L2HubHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("L2HubHandle").field("id", &self.id).finish()
    }
}

impl L2HubHandle {
    /// Detach the device from the hub. Idempotent.
    pub fn close(&self) {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            return;
        }
        if let Some(hub) = self.hub.upgrade() {
            hub.disconnect(self.id);
        }
        *closed = true;
    }
}

impl Drop for L2HubHandle {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_frame, EtherType, L2Handler, MacAddr};
    use std::sync::Mutex;

    #[derive(Default, Clone)]
    struct Sink {
        inner: Arc<Mutex<Vec<Vec<u8>>>>,
        mac: MacAddr,
    }
    impl L2Device for Sink {
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

    #[test]
    fn broadcast_floods_to_all_except_source() {
        let hub = Arc::new(L2Hub::new());
        let a_mac: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let b = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let c = Sink {
            mac: "02:00:00:00:00:03".parse().unwrap(),
            ..Default::default()
        };

        let a = Arc::new(crate::PipeL2::new(a_mac));
        let _ha = hub.connect_arc(a.clone() as Arc<dyn L2Device>);
        let _hb = hub.connect(b.clone());
        let _hc = hub.connect(c.clone());

        let buf = build_frame(MacAddr::broadcast(), a_mac, EtherType::IPV4, &[1, 2, 3]);
        a.inject(Frame::from_slice(&buf)).unwrap();

        assert_eq!(b.inner.lock().unwrap().len(), 1);
        assert_eq!(c.inner.lock().unwrap().len(), 1);
    }

    // A spy is a Sink-like device that we can also "inject" frames into — the
    // injection calls whatever handler the hub installed on this port, while
    // `send` just records (without firing the handler). This mirrors the Go
    // `l2Spy` pattern and avoids the mutual recursion you'd get from wiring
    // two PipeL2s into a hub.
    #[derive(Default, Clone)]
    struct Spy {
        inner: Arc<Mutex<Vec<Vec<u8>>>>,
        handler: Arc<Mutex<Option<L2Handler>>>,
        mac: MacAddr,
    }
    impl L2Device for Spy {
        fn set_handler(&self, h: L2Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
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
    impl Spy {
        fn inject(&self, f: &Frame) {
            let h = self.handler.lock().unwrap().clone();
            if let Some(h) = h {
                let _ = h(f);
            }
        }
        fn count(&self) -> usize {
            self.inner.lock().unwrap().len()
        }
    }

    #[test]
    fn learned_unicast_goes_to_one_port() {
        let hub = Arc::new(L2Hub::new());
        let a_mac: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let b_mac: MacAddr = "02:00:00:00:00:02".parse().unwrap();
        let c_mac: MacAddr = "02:00:00:00:00:03".parse().unwrap();

        let a = Spy { mac: a_mac, ..Default::default() };
        let b = Spy { mac: b_mac, ..Default::default() };
        let c = Spy { mac: c_mac, ..Default::default() };

        let _ha = hub.connect(a.clone());
        let _hb = hub.connect(b.clone());
        let _hc = hub.connect(c.clone());

        // Teach the hub where b is by having b inject a frame.
        let bf = build_frame(MacAddr::broadcast(), b_mac, EtherType::IPV4, &[0]);
        b.inject(Frame::from_slice(&bf));
        assert_eq!(c.count(), 1);
        assert_eq!(a.count(), 1);

        // a → b directly — only b's port should receive.
        let ab = build_frame(b_mac, a_mac, EtherType::IPV4, &[1]);
        a.inject(Frame::from_slice(&ab));
        assert_eq!(b.count(), 1);
        assert_eq!(c.count(), 1); // unchanged
    }

    #[test]
    fn disconnect_removes_port() {
        let hub = Arc::new(L2Hub::new());
        let a = Arc::new(crate::PipeL2::new("02:00:00:00:00:01".parse().unwrap()));
        let b = Sink {
            mac: "02:00:00:00:00:02".parse().unwrap(),
            ..Default::default()
        };
        let _ha = hub.connect_arc(a.clone() as Arc<dyn L2Device>);
        let hb = hub.connect(b.clone());
        hb.close();

        // Broadcast from a should now have no recipients.
        let bf = build_frame(MacAddr::broadcast(), MacAddr::zero(), EtherType::IPV4, &[]);
        a.inject(Frame::from_slice(&bf)).unwrap();
        assert_eq!(b.inner.lock().unwrap().len(), 0);
    }
}

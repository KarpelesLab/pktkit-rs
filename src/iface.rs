use crate::{Frame, IpPrefix, MacAddr, Packet, Result};
use std::sync::Arc;

/// A frame handler: invoked synchronously by an [`L2Device`] when a frame is
/// received. The `&Frame` borrow is valid only for the duration of the call;
/// callers that need to retain the bytes must copy them.
pub type L2Handler = Arc<dyn Fn(&Frame) -> Result<()> + Send + Sync + 'static>;

/// A packet handler: invoked synchronously by an [`L3Device`] when a packet is
/// received. The `&Packet` borrow is valid only for the duration of the call.
pub type L3Handler = Arc<dyn Fn(&Packet) -> Result<()> + Send + Sync + 'static>;

/// A generic handler over any borrowed message type.
///
/// Most users will want [`L2Handler`] or [`L3Handler`] instead.
pub type Handler<T> = Arc<dyn Fn(&T) -> Result<()> + Send + Sync + 'static>;

/// A Layer 2 (Ethernet) network device.
///
/// Implementors must call the handler set by [`set_handler`](Self::set_handler)
/// whenever a frame is received. [`send`](Self::send) may be invoked from any
/// thread; implementations are responsible for any internal synchronization.
///
/// The `&Frame` passed to either method is only valid for the duration of the
/// call — clone the bytes if you need to keep them.
pub trait L2Device: Send + Sync {
    /// Install or replace the handler invoked on every received frame.
    fn set_handler(&self, h: L2Handler);

    /// Transmit a frame on the device.
    fn send(&self, frame: &Frame) -> Result<()>;

    /// The device's hardware address.
    fn hw_addr(&self) -> MacAddr;

    /// Release any resources held by the device.
    fn close(&self) -> Result<()>;
}

/// A Layer 3 (IP) network device.
///
/// `Addr` returns the device's current IP prefix; `set_addr` updates it,
/// typically from a DHCP client or other source of dynamic configuration.
pub trait L3Device: Send + Sync {
    fn set_handler(&self, h: L3Handler);
    fn send(&self, packet: &Packet) -> Result<()>;

    fn addr(&self) -> IpPrefix;
    fn set_addr(&self, prefix: IpPrefix) -> Result<()>;

    fn close(&self) -> Result<()>;
}

// Blanket impls so callers can store devices as `Arc<dyn L2Device>` or
// `Box<dyn L2Device>` without rewriting the trait surface.

impl<T: L2Device + ?Sized> L2Device for Arc<T> {
    #[inline]
    fn set_handler(&self, h: L2Handler) {
        (**self).set_handler(h)
    }
    #[inline]
    fn send(&self, f: &Frame) -> Result<()> {
        (**self).send(f)
    }
    #[inline]
    fn hw_addr(&self) -> MacAddr {
        (**self).hw_addr()
    }
    #[inline]
    fn close(&self) -> Result<()> {
        (**self).close()
    }
}

impl<T: L3Device + ?Sized> L3Device for Arc<T> {
    #[inline]
    fn set_handler(&self, h: L3Handler) {
        (**self).set_handler(h)
    }
    #[inline]
    fn send(&self, p: &Packet) -> Result<()> {
        (**self).send(p)
    }
    #[inline]
    fn addr(&self) -> IpPrefix {
        (**self).addr()
    }
    #[inline]
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        (**self).set_addr(p)
    }
    #[inline]
    fn close(&self) -> Result<()> {
        (**self).close()
    }
}

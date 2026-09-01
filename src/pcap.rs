//! Writing captured traffic to a `.pcap` file.
//!
//! When a packet goes missing inside a virtual topology, counters tell you
//! *that* it did; a capture tells you *what happened*. [`TapL2`] and [`TapL3`]
//! wrap any device and mirror everything crossing it into a pcap file that
//! Wireshark or `tcpdump -r` opens directly.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use pktkit::{L2Device, MacAddr, PipeL2};
//! # use pktkit::pcap::TapL2;
//! # fn main() -> std::io::Result<()> {
//! let dev: Arc<dyn L2Device> = Arc::new(PipeL2::new(MacAddr::zero()));
//! let tap = TapL2::to_file(dev, "/tmp/capture.pcap")?;
//!
//! // Use `tap` wherever the device would have gone; both directions are
//! // written as they pass through.
//! # let _ = tap.hw_addr();
//! # Ok(())
//! # }
//! ```
//!
//! The classic pcap format is used (microsecond timestamps, little-endian), so
//! the files are readable by everything. Records are written as they arrive; a
//! [`PcapWriter`] wrapping a [`BufWriter`](std::io::BufWriter) will hold data
//! until it is flushed or dropped.

use crate::{DeviceStats, Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr};
use crate::{Packet, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Link type 1: Ethernet frames, what [`TapL2`] writes.
pub const LINKTYPE_ETHERNET: u32 = 1;

/// Link type 101: raw IP packets with no link header, what [`TapL3`] writes.
pub const LINKTYPE_RAW: u32 = 101;

/// Default capture length. Records longer than this are truncated in the file,
/// with the original length recorded alongside.
pub const DEFAULT_SNAPLEN: u32 = 262_144;

/// Writes packet records in classic pcap format.
///
/// One writer holds one link type for its whole life, because the file header
/// declares it once — do not mix Ethernet frames and raw IP packets in a single
/// file.
pub struct PcapWriter<W: Write> {
    inner: W,
    snaplen: u32,
}

impl<W: Write> core::fmt::Debug for PcapWriter<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PcapWriter")
            .field("snaplen", &self.snaplen)
            .finish_non_exhaustive()
    }
}

impl<W: Write> PcapWriter<W> {
    /// Start a capture, writing the file header immediately.
    pub fn new(inner: W, linktype: u32) -> Result<PcapWriter<W>> {
        Self::with_snaplen(inner, linktype, DEFAULT_SNAPLEN)
    }

    /// Start a capture with an explicit snap length.
    pub fn with_snaplen(mut inner: W, linktype: u32, snaplen: u32) -> Result<PcapWriter<W>> {
        let mut hdr = Vec::with_capacity(24);
        // 0xa1b2c3d4 in the file's byte order tells the reader which end we
        // wrote; little-endian is what every mainstream capture tool emits.
        hdr.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        hdr.extend_from_slice(&2u16.to_le_bytes()); // version major
        hdr.extend_from_slice(&4u16.to_le_bytes()); // version minor
        hdr.extend_from_slice(&0i32.to_le_bytes()); // GMT offset
        hdr.extend_from_slice(&0u32.to_le_bytes()); // timestamp accuracy
        hdr.extend_from_slice(&snaplen.to_le_bytes());
        hdr.extend_from_slice(&linktype.to_le_bytes());
        inner.write_all(&hdr)?;
        Ok(PcapWriter { inner, snaplen })
    }

    /// Append a record timestamped now.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.write_at(data, SystemTime::now())
    }

    /// Append a record with an explicit timestamp.
    ///
    /// Data longer than the snap length is truncated in the file; the record
    /// still reports the original length, which is how a reader knows.
    pub fn write_at(&mut self, data: &[u8], ts: SystemTime) -> Result<()> {
        let since = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
        let incl = data.len().min(self.snaplen as usize);
        let mut hdr = [0u8; 16];
        hdr[0..4].copy_from_slice(&(since.as_secs() as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&since.subsec_micros().to_le_bytes());
        hdr[8..12].copy_from_slice(&(incl as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes());
        self.inner.write_all(&hdr)?;
        self.inner.write_all(&data[..incl])
    }

    /// Flush buffered records to the underlying writer.
    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    /// Recover the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// A boxed sink a tap writes into.
type Sink = PcapWriter<Box<dyn Write + Send>>;

/// Open `path` for a capture of `linktype`, buffered.
fn file_sink(path: &Path, linktype: u32) -> Result<Sink> {
    let file = BufWriter::new(File::create(path)?);
    PcapWriter::new(Box::new(file) as Box<dyn Write + Send>, linktype)
}

/// The parts of a tap the mirroring closure needs. Held behind an `Arc` so the
/// handler installed on the wrapped device can hold its own reference without
/// a cycle back through the tap.
struct Shared {
    sink: Mutex<Sink>,
    stats: DeviceStats,
}

impl Shared {
    /// Write a record, counting an I/O failure rather than propagating it.
    ///
    /// A capture is an observer: a full disk should not take the network down
    /// with it. Failures surface as the tap's `errors` counter.
    fn mirror(&self, data: &[u8]) {
        // A poisoned capture lock means some other thread panicked mid-write.
        // The file may have a torn record, but dropping the rest of the
        // capture as well would be worse.
        let mut w = match self.sink.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        if w.write(data).is_err() {
            self.stats.record_error();
        }
    }

    fn flush(&self) -> Result<()> {
        let mut w = match self.sink.lock() {
            Ok(w) => w,
            Err(p) => p.into_inner(),
        };
        w.flush()
    }
}

/// An [`L2Device`] that mirrors every frame crossing it into a pcap file.
///
/// Wrap a device in a tap and use the tap in its place; frames are written in
/// both directions, then passed on unchanged.
pub struct TapL2 {
    inner: Arc<dyn L2Device>,
    shared: Arc<Shared>,
}

impl core::fmt::Debug for TapL2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TapL2")
            .field("inner", &self.inner.hw_addr())
            .finish_non_exhaustive()
    }
}

impl TapL2 {
    /// Mirror `inner` into an arbitrary writer.
    pub fn new<W: Write + Send + 'static>(inner: Arc<dyn L2Device>, out: W) -> Result<Arc<TapL2>> {
        let sink = PcapWriter::new(Box::new(out) as Box<dyn Write + Send>, LINKTYPE_ETHERNET)?;
        Ok(Self::from_sink(inner, sink))
    }

    /// Mirror `inner` into a new pcap file, truncating any existing one.
    pub fn to_file<P: AsRef<Path>>(inner: Arc<dyn L2Device>, path: P) -> Result<Arc<TapL2>> {
        let sink = file_sink(path.as_ref(), LINKTYPE_ETHERNET)?;
        Ok(Self::from_sink(inner, sink))
    }

    fn from_sink(inner: Arc<dyn L2Device>, sink: Sink) -> Arc<TapL2> {
        Arc::new(TapL2 {
            inner,
            shared: Arc::new(Shared {
                sink: Mutex::new(sink),
                stats: DeviceStats::new(),
            }),
        })
    }

    /// Flush the capture to disk. Do this before reading the file back; a
    /// buffered writer otherwise holds the tail of the capture in memory.
    pub fn flush(&self) -> Result<()> {
        self.shared.flush()
    }
}

impl L2Device for TapL2 {
    fn set_handler(&self, h: L2Handler) {
        // Received frames are mirrored on their way to the real handler.
        let shared = self.shared.clone();
        self.inner.set_handler(Arc::new(move |f: &Frame| {
            shared.stats.record_rx(f.len());
            shared.mirror(f.as_bytes());
            h(f)
        }));
    }

    fn send(&self, frame: &Frame) -> Result<()> {
        self.shared.stats.record_tx(frame.len());
        self.shared.mirror(frame.as_bytes());
        self.inner.send(frame)
    }

    fn hw_addr(&self) -> MacAddr {
        self.inner.hw_addr()
    }

    fn close(&self) -> Result<()> {
        let _ = self.flush();
        self.inner.close()
    }

    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.shared.stats)
    }
}

/// An [`L3Device`] that mirrors every packet crossing it into a pcap file,
/// written with the raw-IP link type.
pub struct TapL3 {
    inner: Arc<dyn L3Device>,
    shared: Arc<Shared>,
}

impl core::fmt::Debug for TapL3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TapL3")
            .field("addr", &self.inner.addr())
            .finish_non_exhaustive()
    }
}

impl TapL3 {
    /// Mirror `inner` into an arbitrary writer.
    pub fn new<W: Write + Send + 'static>(inner: Arc<dyn L3Device>, out: W) -> Result<Arc<TapL3>> {
        let sink = PcapWriter::new(Box::new(out) as Box<dyn Write + Send>, LINKTYPE_RAW)?;
        Ok(Self::from_sink(inner, sink))
    }

    /// Mirror `inner` into a new pcap file.
    pub fn to_file<P: AsRef<Path>>(inner: Arc<dyn L3Device>, path: P) -> Result<Arc<TapL3>> {
        let sink = file_sink(path.as_ref(), LINKTYPE_RAW)?;
        Ok(Self::from_sink(inner, sink))
    }

    fn from_sink(inner: Arc<dyn L3Device>, sink: Sink) -> Arc<TapL3> {
        Arc::new(TapL3 {
            inner,
            shared: Arc::new(Shared {
                sink: Mutex::new(sink),
                stats: DeviceStats::new(),
            }),
        })
    }

    /// Flush the capture to disk.
    pub fn flush(&self) -> Result<()> {
        self.shared.flush()
    }
}

impl L3Device for TapL3 {
    fn set_handler(&self, h: L3Handler) {
        let shared = self.shared.clone();
        self.inner.set_handler(Arc::new(move |p: &Packet| {
            shared.stats.record_rx(p.len());
            shared.mirror(p.as_bytes());
            h(p)
        }));
    }

    fn send(&self, packet: &Packet) -> Result<()> {
        self.shared.stats.record_tx(packet.len());
        self.shared.mirror(packet.as_bytes());
        self.inner.send(packet)
    }

    fn addr(&self) -> IpPrefix {
        self.inner.addr()
    }

    fn set_addr(&self, prefix: IpPrefix) -> Result<()> {
        self.inner.set_addr(prefix)
    }

    fn close(&self) -> Result<()> {
        let _ = self.flush();
        self.inner.close()
    }

    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.shared.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_frame, EtherType};
    use std::time::Duration;

    /// A `Write` whose bytes stay inspectable after the writer takes ownership.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl SharedBuf {
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    #[test]
    fn file_header_is_classic_pcap() {
        let buf = SharedBuf::default();
        let w = PcapWriter::new(buf.clone(), LINKTYPE_ETHERNET).unwrap();
        drop(w);

        let b = buf.bytes();
        assert_eq!(b.len(), 24);
        assert_eq!(&b[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "little-endian magic");
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 2);
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), 4);
        assert_eq!(le32(&b, 16), DEFAULT_SNAPLEN);
        assert_eq!(le32(&b, 20), LINKTYPE_ETHERNET);
    }

    #[test]
    fn record_carries_timestamp_and_lengths() {
        let buf = SharedBuf::default();
        let mut w = PcapWriter::new(buf.clone(), LINKTYPE_RAW).unwrap();
        let ts = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000);
        w.write_at(&[1, 2, 3, 4, 5], ts).unwrap();

        let b = buf.bytes();
        assert_eq!(b.len(), 24 + 16 + 5);
        assert_eq!(le32(&b, 24), 1_700_000_000);
        assert_eq!(le32(&b, 28), 123_456);
        assert_eq!(le32(&b, 32), 5, "captured length");
        assert_eq!(le32(&b, 36), 5, "original length");
        assert_eq!(&b[40..45], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn oversize_record_is_truncated_but_reports_full_length() {
        let buf = SharedBuf::default();
        let mut w = PcapWriter::with_snaplen(buf.clone(), LINKTYPE_RAW, 4).unwrap();
        w.write(&[9u8; 100]).unwrap();

        let b = buf.bytes();
        assert_eq!(le32(&b, 32), 4, "only the snap length is stored");
        assert_eq!(le32(&b, 36), 100, "the reader still learns the real size");
        assert_eq!(b.len(), 24 + 16 + 4);
    }

    /// A device that records what it is asked to send and delivers inbound
    /// frames only when told to. `PipeL2` would not do: it feeds whatever is
    /// sent straight back into its own handler, so every frame would be
    /// captured twice.
    #[derive(Default)]
    struct Wire {
        sent: Mutex<Vec<Vec<u8>>>,
        handler: Mutex<Option<L2Handler>>,
    }

    impl Wire {
        fn deliver(&self, f: &Frame) {
            let h = self.handler.lock().unwrap().clone();
            if let Some(h) = h {
                h(f).unwrap();
            }
        }
    }

    impl L2Device for Wire {
        fn set_handler(&self, h: L2Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, f: &Frame) -> Result<()> {
            self.sent.lock().unwrap().push(f.to_vec());
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            MacAddr::zero()
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tap_mirrors_both_directions_and_passes_frames_through() {
        let buf = SharedBuf::default();
        let wire = Arc::new(Wire::default());
        let pipe: Arc<dyn L2Device> = wire.clone();
        let tap = TapL2::new(pipe.clone(), buf.clone()).unwrap();

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tap.set_handler(Arc::new(move |f: &Frame| {
            seen2.lock().unwrap().push(f.to_vec());
            Ok(())
        }));

        let out = build_frame(
            MacAddr::broadcast(),
            MacAddr::zero(),
            EtherType::IPV4,
            &[1; 20],
        );
        tap.send(Frame::from_slice(&out)).unwrap();

        // An inbound frame arrives through the wrapped device.
        let inb = build_frame(
            MacAddr::zero(),
            MacAddr::broadcast(),
            EtherType::ARP,
            &[2; 20],
        );
        wire.deliver(Frame::from_slice(&inb));

        tap.flush().unwrap();
        let b = buf.bytes();

        // Two records, in order, with the payloads intact.
        let first = 24 + 16;
        assert_eq!(le32(&b, 24 + 8) as usize, out.len());
        assert_eq!(&b[first..first + out.len()], &out[..]);
        let second = first + out.len() + 16;
        assert_eq!(&b[second..second + inb.len()], &inb[..]);

        // The handler still saw the inbound frame, and the wrapped device
        // still saw the outbound one: a tap observes, it does not intercept.
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(seen.lock().unwrap()[0], inb);
        assert_eq!(
            wire.sent.lock().unwrap().as_slice(),
            std::slice::from_ref(&out)
        );

        let s = tap.stats().unwrap().snapshot();
        assert_eq!(s.tx_packets, 1);
        assert_eq!(s.rx_packets, 1);
        assert_eq!(s.errors, 0);
    }

    #[test]
    fn tap_l3_writes_raw_ip_records() {
        let buf = SharedBuf::default();
        let dev: Arc<dyn L3Device> = Arc::new(crate::PipeL3::new("10.0.0.1/24".parse().unwrap()));
        let tap = TapL3::new(dev, buf.clone()).unwrap();

        let pkt = crate::build::build_ipv4(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            crate::Protocol::UDP,
            64,
            &[0; 8],
        );
        tap.send(Packet::from_slice(&pkt)).unwrap();
        tap.flush().unwrap();

        let b = buf.bytes();
        assert_eq!(le32(&b, 20), LINKTYPE_RAW, "no link header in the file");
        assert_eq!(&b[40..40 + pkt.len()], &pkt[..]);
        assert_eq!(tap.addr(), "10.0.0.1/24".parse().unwrap());
    }

    #[test]
    fn write_failure_counts_an_error_instead_of_breaking_the_link() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }

        let pipe: Arc<dyn L2Device> = Arc::new(Wire::default());
        // The file header write fails immediately, so construction reports it.
        assert!(TapL2::new(pipe.clone(), Broken).is_err());

        // A sink that accepts the header and then fails keeps traffic flowing.
        struct FailAfterHeader(usize);
        impl Write for FailAfterHeader {
            fn write(&mut self, buf: &[u8]) -> Result<usize> {
                self.0 += 1;
                if self.0 > 1 {
                    return Err(std::io::Error::other("disk full"));
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }

        let tap = TapL2::new(pipe, FailAfterHeader(0)).unwrap();
        let f = build_frame(MacAddr::zero(), MacAddr::zero(), EtherType::IPV4, &[0; 20]);
        tap.send(Frame::from_slice(&f)).unwrap();
        assert_eq!(tap.stats().unwrap().snapshot().errors, 1);
    }
}

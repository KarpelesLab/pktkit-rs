//! The test link: the guest's NIC, impaired, on an `L2Hub` with a vclient
//! behind an `L2Adapter`.
//!
//! ```text
//! guest eth0 ── qemu::Conn ── ImpairL2 ── Narrow ── L2Hub ── Station ── L2Adapter ── vclient
//! ```
//!
//! `Narrow` is a hop with a smaller MTU than the ends. As a router would,
//! it fragments IPv4 packets longer than its MTU that allow it, and drops
//! those with DF set, answering each with ICMP Fragmentation Needed; or,
//! as a black hole, drops them all without a word. `Station` captures
//! what the vclient sees to a pcap per test, and swaps in a fresh vclient
//! for each test, with that test's TCP settings.

use crate::image::HOST_IP;
use pktkit::impair::{ImpairL2, Impairment};
use pktkit::pcap::{LINKTYPE_ETHERNET, PcapWriter};
use pktkit::vclient::{Client, ClientConfig};
use pktkit::{
    EtherType, Frame, IpPrefix, L2Adapter, L2AdapterConfig, L2Device, L2Handler, L2Hub,
    L2HubHandle, L3Device, MacAddr, Packet, Result, build_frame,
};
use std::fs::File;
use std::io::BufWriter;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The vclient's MAC: the same for every test, so the guest's ARP entry
/// for it stays right when the vclient behind it is swapped.
pub const STATION_MAC: MacAddr = MacAddr::new([0x02, 0x70, 0x6b, 0x74, 0x00, 0x01]);
/// Where `Narrow`'s ICMP messages come from.
const ROUTER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 254);

#[derive(Debug, Clone, Copy)]
pub struct Clamp {
    pub mtu: usize,
    /// Answer with ICMP; `false` makes the hop a black hole.
    pub icmp: bool,
}

/// A narrower hop between the guest and the hub.
pub struct Narrow {
    inner: Arc<dyn L2Device>,
    hub: Arc<Mutex<Option<L2Handler>>>,
    clamp: Arc<Mutex<Option<Clamp>>>,
    pub dropped: Arc<AtomicU64>,
    pub icmp_sent: Arc<AtomicU64>,
    pub fragmented: Arc<AtomicU64>,
}

impl std::fmt::Debug for Narrow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Narrow").finish_non_exhaustive()
    }
}

/// What the narrow hop does with a frame.
enum Verdict {
    Pass,
    /// Too big, and DF is set: dropped, with the ICMP Fragmentation Needed
    /// to send back, if the hop sends any.
    Drop(Option<Vec<u8>>),
    /// Too big, and DF is clear: the fragments to forward instead, as a
    /// router does (RFC 791). A black hole drops these too.
    Fragments(Vec<Vec<u8>>),
}

fn judge(frame: &Frame, clamp: Option<Clamp>) -> Verdict {
    let Some(c) = clamp else {
        return Verdict::Pass;
    };
    if frame.ether_type() != EtherType::IPV4 {
        return Verdict::Pass;
    }
    let pkt = Packet::from_slice(frame.payload());
    if pkt.len() < 20 || usize::from(pkt.ipv4_total_len()) <= c.mtu {
        return Verdict::Pass;
    }
    if !c.icmp {
        return Verdict::Drop(None);
    }
    let (Some(src), Some(dst)) = (frame.src_mac(), frame.dst_mac()) else {
        return Verdict::Drop(None);
    };
    if !pkt.ipv4_dont_fragment() {
        return match pktkit::fragment::fragment_ipv4(pkt, c.mtu) {
            pktkit::fragment::Fragmentation::Fragments(f) => Verdict::Fragments(
                f.iter()
                    .map(|p| build_frame(dst, src, EtherType::IPV4, p))
                    .collect(),
            ),
            _ => Verdict::Drop(None),
        };
    }
    let icmp = pktkit::icmp::packet_too_big(pkt, IpAddr::V4(ROUTER_IP), c.mtu as u32);
    Verdict::Drop(icmp.map(|icmp| build_frame(src, dst, EtherType::IPV4, &icmp)))
}

impl Narrow {
    pub fn new(inner: Arc<dyn L2Device>) -> Arc<Narrow> {
        Arc::new(Narrow {
            inner,
            hub: Arc::default(),
            clamp: Arc::default(),
            dropped: Arc::default(),
            icmp_sent: Arc::default(),
            fragmented: Arc::default(),
        })
    }

    pub fn set_clamp(&self, c: Option<Clamp>) {
        *self.clamp.lock().unwrap() = c;
    }
}

impl L2Device for Narrow {
    fn set_handler(&self, h: L2Handler) {
        *self.hub.lock().unwrap() = Some(h.clone());
        let (clamp, inner) = (self.clamp.clone(), self.inner.clone());
        let (dropped, icmp_sent) = (self.dropped.clone(), self.icmp_sent.clone());
        let fragmented = self.fragmented.clone();
        let inner_weak = Arc::downgrade(&inner);
        // From the guest towards the hub.
        inner.set_handler(Arc::new(move |f: &Frame| {
            let c = *clamp.lock().unwrap();
            match judge(f, c) {
                Verdict::Pass => h(f),
                Verdict::Fragments(fs) => {
                    fragmented.fetch_add(1, Ordering::Relaxed);
                    for f in fs {
                        let _ = h(Frame::from_slice(&f));
                    }
                    Ok(())
                }
                Verdict::Drop(icmp) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    if let (Some(icmp), Some(inner)) = (icmp, inner_weak.upgrade()) {
                        icmp_sent.fetch_add(1, Ordering::Relaxed);
                        let _ = inner.send(Frame::from_slice(&icmp));
                    }
                    Ok(())
                }
            }
        }));
    }

    fn send(&self, f: &Frame) -> Result<()> {
        let c = *self.clamp.lock().unwrap();
        match judge(f, c) {
            Verdict::Pass => self.inner.send(f),
            Verdict::Fragments(fs) => {
                self.fragmented.fetch_add(1, Ordering::Relaxed);
                for f in fs {
                    let _ = self.inner.send(Frame::from_slice(&f));
                }
                Ok(())
            }
            Verdict::Drop(icmp) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                let hub = self.hub.lock().unwrap().clone();
                if let (Some(icmp), Some(hub)) = (icmp, hub) {
                    self.icmp_sent.fetch_add(1, Ordering::Relaxed);
                    let _ = hub(Frame::from_slice(&icmp));
                }
                Ok(())
            }
        }
    }

    fn hw_addr(&self) -> MacAddr {
        self.inner.hw_addr()
    }

    fn close(&self) -> Result<()> {
        self.inner.close()
    }
}

fn host_prefix() -> IpPrefix {
    format!("{HOST_IP}/24").parse().unwrap()
}

type Pcap = Mutex<Option<PcapWriter<BufWriter<File>>>>;

fn mirror(pcap: &Pcap, f: &Frame) {
    if let Some(w) = pcap.lock().unwrap().as_mut() {
        let _ = w.write(f.as_bytes());
    }
}

/// What the station has plugged in: the adapter, and the L3 device behind
/// it.
type Attached = (Arc<L2Adapter>, Arc<dyn L3Device>);

/// The vclient's port on the hub.
pub struct Station {
    hub: Arc<Mutex<Option<L2Handler>>>,
    adapter: Mutex<Option<Attached>>,
    pcap: Arc<Pcap>,
}

impl std::fmt::Debug for Station {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Station").finish_non_exhaustive()
    }
}

impl Station {
    fn new() -> Arc<Station> {
        Arc::new(Station {
            hub: Arc::default(),
            adapter: Mutex::new(None),
            pcap: Arc::default(),
        })
    }

    /// Replace the vclient with a fresh one built from `cfg` (its address
    /// is filled in).
    pub fn swap(&self, cfg: ClientConfig) -> Arc<Client> {
        let client = Client::new(cfg.prefix(host_prefix()));
        self.swap_l3(client.clone());
        client
    }

    /// Replace the vclient with a slirp stack, at the same address.
    pub fn swap_slirp(&self, tcp: pktkit::vtcp::Tuning) -> Arc<pktkit::slirp::Stack> {
        let stack = pktkit::slirp::Stack::new();
        let _ = stack.set_addr(host_prefix());
        stack.set_tcp(tcp);
        self.swap_l3(stack.clone());
        stack
    }

    fn swap_l3(&self, dev: Arc<dyn L3Device>) {
        let adapter = L2Adapter::new_arc(dev.clone(), L2AdapterConfig::default().mac(STATION_MAC));
        let (hub, pcap) = (self.hub.clone(), self.pcap.clone());
        adapter.set_handler(Arc::new(move |f: &Frame| {
            mirror(&pcap, f);
            let h = hub.lock().unwrap().clone();
            match h {
                Some(h) => h(f),
                None => Ok(()),
            }
        }));
        let old = self.adapter.lock().unwrap().replace((adapter, dev));
        if let Some((a, c)) = old {
            let _ = c.close();
            let _ = L2Device::close(&*a);
        }
    }

    /// Capture to `path` from now on (headers only), or stop capturing.
    pub fn capture(&self, path: Option<&Path>) -> std::io::Result<()> {
        let w = match path {
            Some(p) => Some(PcapWriter::with_snaplen(
                BufWriter::new(File::create(p)?),
                LINKTYPE_ETHERNET,
                160,
            )?),
            None => None,
        };
        if let Some(mut old) = std::mem::replace(&mut *self.pcap.lock().unwrap(), w) {
            let _ = old.flush();
        }
        Ok(())
    }
}

impl L2Device for Station {
    fn set_handler(&self, h: L2Handler) {
        *self.hub.lock().unwrap() = Some(h);
    }

    fn send(&self, f: &Frame) -> Result<()> {
        mirror(&self.pcap, f);
        let a = self
            .adapter
            .lock()
            .unwrap()
            .as_ref()
            .map(|(a, _)| a.clone());
        match a {
            Some(a) => a.send(f),
            None => Ok(()),
        }
    }

    fn hw_addr(&self) -> MacAddr {
        STATION_MAC
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct Net {
    pub hub: Arc<L2Hub>,
    pub impair: Arc<ImpairL2>,
    pub narrow: Arc<Narrow>,
    pub station: Arc<Station>,
    _ports: Vec<L2HubHandle>,
}

impl Net {
    pub fn new(nic: Arc<dyn L2Device>) -> Net {
        let hub = Arc::new(L2Hub::new());
        let impair = ImpairL2::new(nic, Impairment::default());
        let narrow = Narrow::new(impair.clone());
        let station = Station::new();
        let ports = vec![
            hub.connect_arc(narrow.clone()),
            hub.connect_arc(station.clone()),
        ];
        Net {
            hub,
            impair,
            narrow,
            station,
            _ports: ports,
        }
    }
}

//! Connected UDP over the virtual network.
//!
//! A [`UdpConn`] is a connected UDP socket: it sends datagrams to a fixed
//! remote and receives datagrams from that remote, all framed as IP packets
//! pushed through the owning [`Client`](super::Client)'s L3 handler. Inbound
//! UDP packets the client receives are demultiplexed to the matching
//! `UdpConn` by 4-tuple. This is the building block the (tunnel-routed) DNS
//! path uses and mirrors the Go `vclient` `udpConn`.

use super::next_ipv4_id;
use super::tcp::pick_port;
use crate::time::Instant;
use crate::{Packet, Protocol, checksum};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// 4-tuple key for a connected UDP socket, from the client's point of view.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct UdpKey {
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

pub(crate) struct UdpState {
    key: UdpKey,
    local_ip: IpAddr,
    rx: Mutex<RxQueue>,
    signal: Condvar,
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    /// Set when the owning client closes.
    closed: AtomicBool,
}

/// Bytes of payload a socket holds for its reader before further datagrams
/// are dropped, as a kernel socket's receive buffer bounds it.
const RX_BUF_BYTES: usize = 256 * 1024;

/// Datagrams waiting to be read, and their total payload size.
#[derive(Default)]
struct RxQueue {
    q: VecDeque<Vec<u8>>,
    bytes: usize,
}

impl RxQueue {
    fn pop_front(&mut self) -> Option<Vec<u8>> {
        let d = self.q.pop_front()?;
        self.bytes -= d.len();
        Some(d)
    }
}

fn client_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "client is closed")
}

impl UdpState {
    /// Queue a datagram for the reader. When the reader has fallen behind
    /// and the buffer is full, the datagram is dropped, as UDP allows: an
    /// unread socket must not grow without bound.
    fn deliver(&self, payload: &[u8]) {
        let mut rx = self.rx.lock().unwrap();
        // One datagram always fits, whatever its size, as with a kernel
        // socket's receive buffer.
        if !rx.q.is_empty() && rx.bytes + payload.len() > RX_BUF_BYTES {
            return;
        }
        rx.bytes += payload.len();
        rx.q.push_back(payload.to_vec());
        drop(rx);
        self.signal.notify_all();
    }
}

/// A connected UDP socket over the virtual network.
pub struct UdpConn {
    state: Arc<UdpState>,
    read_timeout: Mutex<Option<Duration>>,
    nonblocking: AtomicBool,
    stack: Arc<UdpStack>,
}

impl core::fmt::Debug for UdpConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("vclient::UdpConn")
            .field("key", &self.state.key)
            .finish()
    }
}

impl UdpConn {
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.local_ip, self.state.key.local_port)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.key.remote, self.state.key.remote_port)
    }

    pub fn set_read_timeout(&self, t: Option<Duration>) {
        *self.read_timeout.lock().unwrap() = t;
    }

    /// Switch between blocking and non-blocking [`recv`](Self::recv). On
    /// `wasm32` it never waits, whatever this is set to.
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    /// Send a datagram to the connected remote.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if self.state.closed.load(Ordering::Acquire) {
            return Err(client_closed());
        }
        // The IPv4 total length and the UDP / IPv6 payload lengths are 16
        // bits: past these, they would wrap and describe another datagram.
        let max = if self.state.key.remote.is_ipv4() {
            65535 - 20 - 8
        } else {
            65535 - 8
        };
        if buf.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram too large",
            ));
        }
        let pkt = wrap_udp(
            self.state.local_ip,
            self.state.key.local_port,
            self.state.key.remote,
            self.state.key.remote_port,
            buf,
        );
        (self.state.sink)(&pkt);
        Ok(buf.len())
    }

    /// Receive the next datagram from the connected remote, blocking until one
    /// arrives or the read timeout elapses. In non-blocking mode, returns
    /// [`WouldBlock`](io::ErrorKind::WouldBlock) when none is queued.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self
            .read_timeout
            .lock()
            .unwrap()
            .map(|t| Instant::now() + t);
        let mut rx = self.state.rx.lock().unwrap();
        loop {
            if let Some(dgram) = rx.pop_front() {
                let n = dgram.len().min(buf.len());
                buf[..n].copy_from_slice(&dgram[..n]);
                return Ok(n);
            }
            if self.state.closed.load(Ordering::Acquire) {
                return Err(client_closed());
            }
            // Without threads nothing could deliver a datagram while we wait.
            if cfg!(target_family = "wasm") || self.nonblocking.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no datagram queued",
                ));
            }
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "recv timeout"));
                    }
                    let (g, _) = self.state.signal.wait_timeout(rx, d - now).unwrap();
                    rx = g;
                }
                None => rx = self.state.signal.wait(rx).unwrap(),
            }
        }
    }
}

impl Drop for UdpConn {
    fn drop(&mut self) {
        let mut conns = self.stack.conns.lock().unwrap();
        // Only our own entry, never a later socket's on the same 4-tuple.
        if conns
            .get(&self.state.key)
            .is_some_and(|s| Arc::ptr_eq(s, &self.state))
        {
            conns.remove(&self.state.key);
        }
    }
}

/// Per-client UDP connection registry.
pub(crate) struct UdpStack {
    conns: Mutex<HashMap<UdpKey, Arc<UdpState>>>,
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    next_port: Mutex<u16>,
    closed: AtomicBool,
}

impl UdpStack {
    pub fn new(sink: Arc<dyn Fn(&[u8]) + Send + Sync>) -> Arc<UdpStack> {
        Arc::new(UdpStack {
            conns: Mutex::new(HashMap::new()),
            sink,
            next_port: Mutex::new(super::tcp::EPHEMERAL_FIRST),
            closed: AtomicBool::new(false),
        })
    }

    /// Open a connected UDP socket to `remote` from `local_ip`.
    pub fn dial(self: &Arc<Self>, local_ip: IpAddr, remote: SocketAddr) -> io::Result<UdpConn> {
        // Picked and registered under the one lock (see the TCP dial).
        let mut conns = self.conns.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            return Err(client_closed());
        }
        let local_port = pick_port(&mut self.next_port.lock().unwrap(), |p| {
            conns.contains_key(&UdpKey {
                local_port: p,
                remote: remote.ip(),
                remote_port: remote.port(),
            })
        })?;
        let key = UdpKey {
            local_port,
            remote: remote.ip(),
            remote_port: remote.port(),
        };
        let state = Arc::new(UdpState {
            key,
            local_ip,
            rx: Mutex::new(RxQueue::default()),
            signal: Condvar::new(),
            sink: self.sink.clone(),
            closed: AtomicBool::new(false),
        });
        conns.insert(key, state.clone());
        Ok(UdpConn {
            state,
            read_timeout: Mutex::new(None),
            nonblocking: AtomicBool::new(false),
            stack: self.clone(),
        })
    }

    /// Close every socket and wake its readers; no new ones can be opened.
    pub fn shutdown(&self) {
        let mut conns = self.conns.lock().unwrap();
        self.closed.store(true, Ordering::Release);
        for (_, s) in conns.drain() {
            // Under the rx lock, so a reader between its checks and its wait
            // cannot miss the wakeup.
            let _rx = s.rx.lock().unwrap();
            s.closed.store(true, Ordering::Release);
            s.signal.notify_all();
        }
    }

    /// Demultiplex an inbound UDP packet to the matching connection. Returns
    /// `true` if it was consumed.
    pub fn handle_inbound(&self, pkt: &Packet) -> bool {
        if pkt.ip_protocol() != Protocol::UDP {
            return false;
        }
        let (src, dst) = match (pkt.src_addr(), pkt.dst_addr()) {
            (Some(s), Some(d)) => (s, d),
            _ => return false,
        };
        let udp = pkt.payload();
        if udp.len() < 8 {
            return false;
        }
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if len < 8 || udp.len() < len {
            return false;
        }
        // A damaged datagram is dropped (RFC 768). Over IPv4 a zero
        // checksum means the sender computed none; over IPv6 the checksum
        // is mandatory and a zero one is invalid (RFC 8200 §8.1).
        let sum = u16::from_be_bytes([udp[6], udp[7]]);
        let valid = if sum == 0 {
            src.is_ipv4()
        } else {
            checksum::raw_transport_sum(Protocol::UDP, src, dst, &udp[..len]) == 0xFFFF
        };
        if !valid {
            return false;
        }
        let payload = &udp[8..len];
        // Inbound: packet src=remote, dst=us. Key by remote = src.
        let key = UdpKey {
            local_port: dst_port,
            remote: src,
            remote_port: src_port,
        };
        let state = match self.conns.lock().unwrap().get(&key) {
            Some(s) => s.clone(),
            None => return false,
        };
        state.deliver(payload);
        true
    }
}

// --- IP/UDP framing ---------------------------------------------------------

fn wrap_udp(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => wrap_udp_v4(s, src_port, d, dst_port, payload),
        (IpAddr::V6(s), IpAddr::V6(d)) => wrap_udp_v6(s, src_port, d, dst_port, payload),
        _ => Vec::new(),
    }
}

fn udp_header(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);
    udp
}

fn udp_checksum(src: IpAddr, dst: IpAddr, udp: &[u8]) -> u16 {
    let pseudo = checksum::pseudo_header_checksum(Protocol::UDP, src, dst, udp.len() as u16);
    let body = !checksum::checksum(udp);
    let cs = !checksum::combine_checksums(pseudo, body);
    // RFC 768: a 0 checksum is transmitted as 0xFFFF.
    if cs == 0 { 0xFFFF } else { cs }
}

fn wrap_udp_v4(src: Ipv4Addr, sp: u16, dst: Ipv4Addr, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = udp_header(sp, dp, payload);
    let cs = udp_checksum(IpAddr::V4(src), IpAddr::V4(dst), &udp);
    udp[6..8].copy_from_slice(&cs.to_be_bytes());

    let total = 20 + udp.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&next_ipv4_id().to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::UDP.as_u8();
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ipcs = checksum::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ipcs.to_be_bytes());
    ip[20..].copy_from_slice(&udp);
    ip
}

fn wrap_udp_v6(src: Ipv6Addr, sp: u16, dst: Ipv6Addr, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = udp_header(sp, dp, payload);
    let cs = udp_checksum(IpAddr::V6(src), IpAddr::V6(dst), &udp);
    udp[6..8].copy_from_slice(&cs.to_be_bytes());

    let total = 40 + udp.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(udp.len() as u16).to_be_bytes());
    ip[6] = Protocol::UDP.as_u8();
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip[40..].copy_from_slice(&udp);
    ip
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_v4_checksum_validates_at_receiver() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = wrap_udp_v4(
            Ipv4Addr::new(10, 0, 0, 2),
            1234,
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            b"hi",
        );
        // IP header checksum folds to zero.
        assert_eq!(checksum::checksum(&pkt[..20]), 0);
        let udp = &pkt[20..];
        // pseudo + full UDP folds to 0xFFFF (i.e. complement is 0).
        let pseudo = checksum::pseudo_header_checksum(Protocol::UDP, src, dst, udp.len() as u16);
        let body = !checksum::checksum(udp);
        assert_eq!(checksum::combine_checksums(pseudo, body), 0xFFFF);
    }

    #[test]
    fn dial_then_inbound_demux_delivers() {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cc = captured.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> =
            Arc::new(move |b: &[u8]| cc.lock().unwrap().push(b.to_vec()));
        let stack = UdpStack::new(sink);

        let conn = stack
            .dial(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SocketAddr::from(([10, 0, 0, 1], 53)),
            )
            .unwrap();
        conn.send(b"query").unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);

        // Craft an inbound reply 10.0.0.1:53 -> 10.0.0.2:<local>.
        let reply = wrap_udp_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            Ipv4Addr::new(10, 0, 0, 2),
            conn.local_addr().port(),
            b"answer",
        );
        assert!(stack.handle_inbound(Packet::from_slice(&reply)));

        conn.set_read_timeout(Some(Duration::from_secs(1)));
        let mut buf = [0u8; 16];
        let n = conn.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"answer");
    }

    #[test]
    fn datagrams_with_a_bad_checksum_are_dropped() {
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(|_b: &[u8]| {});
        let stack = UdpStack::new(sink);
        let (us4, peer4) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        let (us6, peer6): (Ipv6Addr, Ipv6Addr) =
            ("fd00::2".parse().unwrap(), "fd00::1".parse().unwrap());
        let v4 = stack
            .dial(IpAddr::V4(us4), SocketAddr::from((peer4, 53)))
            .unwrap();
        let v6 = stack
            .dial(IpAddr::V6(us6), SocketAddr::from((peer6, 53)))
            .unwrap();
        let reply4 = wrap_udp_v4(peer4, 53, us4, v4.local_addr().port(), b"answer");
        let reply6 = wrap_udp_v6(peer6, 53, us6, v6.local_addr().port(), b"answer");

        for (reply, at) in [(&reply4, 20), (&reply6, 40)] {
            let mut bad = reply.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(!stack.handle_inbound(Packet::from_slice(&bad)));
            // No checksum at all: none needed over IPv4, invalid over IPv6.
            let mut none = reply.clone();
            none[at + 6..at + 8].copy_from_slice(&[0, 0]);
            assert_eq!(stack.handle_inbound(Packet::from_slice(&none)), at == 20);
            assert!(stack.handle_inbound(Packet::from_slice(reply)));
        }
        assert_eq!(v4.state.rx.lock().unwrap().q.len(), 2);
        assert_eq!(v6.state.rx.lock().unwrap().q.len(), 1);
    }

    #[test]
    fn oversized_datagrams_are_refused_and_ids_vary() {
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let s = sent.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> =
            Arc::new(move |b: &[u8]| s.lock().unwrap().push(b.to_vec()));
        let stack = UdpStack::new(sink);
        let v4 = stack
            .dial(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SocketAddr::from(([10, 0, 0, 1], 53)),
            )
            .unwrap();
        let err = v4.send(&vec![0u8; 65508]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(sent.lock().unwrap().is_empty());
        v4.send(&vec![0u8; 65507]).unwrap();
        v4.send(b"x").unwrap();
        {
            let sent = sent.lock().unwrap();
            assert_eq!(u16::from_be_bytes([sent[0][2], sent[0][3]]), 65535);
            assert_eq!(sent[0].len(), 65535);
            // Fragmentable datagrams, so each needs its own ID (RFC 6864).
            assert_ne!(sent[0][4..6], sent[1][4..6]);
        }

        let v6 = stack
            .dial(
                IpAddr::V6("fd00::2".parse().unwrap()),
                SocketAddr::from(("fd00::1".parse::<Ipv6Addr>().unwrap(), 53)),
            )
            .unwrap();
        assert!(v6.send(&vec![0u8; 65528]).is_err());
        v6.send(&vec![0u8; 65527]).unwrap();
    }

    #[test]
    fn port_wrap_skips_sockets_still_open() {
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(|_b: &[u8]| {});
        let stack = UdpStack::new(sink);
        let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let remote = SocketAddr::from(([10, 0, 0, 1], 53));
        let first = stack.dial(local, remote).unwrap();
        // Wrap the allocator round to the port `first` still holds.
        *stack.next_port.lock().unwrap() = first.local_addr().port();
        let second = stack.dial(local, remote).unwrap();
        assert_ne!(second.local_addr().port(), first.local_addr().port());

        drop(first);
        // `second` still receives.
        let reply = wrap_udp_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            Ipv4Addr::new(10, 0, 0, 2),
            second.local_addr().port(),
            b"answer",
        );
        assert!(stack.handle_inbound(Packet::from_slice(&reply)));
    }

    #[test]
    fn fragmented_reply_is_reassembled() {
        use crate::L3Device;
        use crate::fragment::{Fragmentation, fragment_ipv4};

        let client = super::super::Client::new(super::super::ClientConfig::default().prefix(
            crate::IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24),
        ));
        let conn = client
            .dial_udp(SocketAddr::from(([10, 0, 0, 1], 53)))
            .unwrap();
        conn.set_nonblocking(true);
        let port = conn.local_addr().port();
        // Where the second fragment's data starts, the payload looks like a
        // UDP header for this socket: read as one, it would be delivered.
        let mut payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let at = 1480 - 8;
        payload[at..at + 2].copy_from_slice(&53u16.to_be_bytes());
        payload[at + 2..at + 4].copy_from_slice(&port.to_be_bytes());
        payload[at + 4..at + 6].copy_from_slice(&16u16.to_be_bytes());
        payload[at + 6..at + 8].copy_from_slice(&[0, 0]);
        let mut reply = wrap_udp_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            Ipv4Addr::new(10, 0, 0, 2),
            port,
            &payload,
        );
        reply[4..6].copy_from_slice(&0x77u16.to_be_bytes());
        let Fragmentation::Fragments(frags) = fragment_ipv4(Packet::from_slice(&reply), 1500)
        else {
            panic!("expected fragments");
        };

        let mut buf = vec![0u8; 8192];
        client.send(Packet::from_slice(&frags[1])).unwrap();
        assert!(conn.recv(&mut buf).is_err(), "a fragment read as UDP");
        for f in frags.iter().rev() {
            client.send(Packet::from_slice(f)).unwrap();
        }
        let n = conn.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &payload[..]);
    }

    #[test]
    fn receive_queue_is_bounded() {
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(|_b: &[u8]| {});
        let stack = UdpStack::new(sink);
        let conn = stack
            .dial(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SocketAddr::from(([10, 0, 0, 1], 53)),
            )
            .unwrap();
        let payload = vec![0u8; 1000];
        let reply = wrap_udp_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            Ipv4Addr::new(10, 0, 0, 2),
            conn.local_addr().port(),
            &payload,
        );
        for _ in 0..1000 {
            stack.handle_inbound(Packet::from_slice(&reply));
        }
        let rx = conn.state.rx.lock().unwrap();
        assert!(rx.bytes <= RX_BUF_BYTES);
        assert_eq!(rx.q.len(), RX_BUF_BYTES / 1000);
    }
}

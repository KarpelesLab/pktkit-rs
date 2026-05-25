//! Connected UDP over the virtual network.
//!
//! A [`UdpConn`] is a connected UDP socket: it sends datagrams to a fixed
//! remote and receives datagrams from that remote, all framed as IP packets
//! pushed through the owning [`Client`](super::Client)'s L3 handler. Inbound
//! UDP packets the client receives are demultiplexed to the matching
//! `UdpConn` by 4-tuple. This is the building block the (tunnel-routed) DNS
//! path uses and mirrors the Go `vclient` `udpConn`.

use crate::{checksum, Packet, Protocol};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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
    rx: Mutex<VecDeque<Vec<u8>>>,
    signal: Condvar,
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
}

impl UdpState {
    fn deliver(&self, payload: &[u8]) {
        self.rx.lock().unwrap().push_back(payload.to_vec());
        self.signal.notify_all();
    }
}

/// A connected UDP socket over the virtual network.
pub struct UdpConn {
    state: Arc<UdpState>,
    read_timeout: Mutex<Option<Duration>>,
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

    /// Send a datagram to the connected remote.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
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
    /// arrives or the read timeout elapses.
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
        self.stack.conns.lock().unwrap().remove(&self.state.key);
    }
}

/// Per-client UDP connection registry.
pub(crate) struct UdpStack {
    conns: Mutex<HashMap<UdpKey, Arc<UdpState>>>,
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    next_port: Mutex<u16>,
}

impl UdpStack {
    pub fn new(sink: Arc<dyn Fn(&[u8]) + Send + Sync>) -> Arc<UdpStack> {
        Arc::new(UdpStack {
            conns: Mutex::new(HashMap::new()),
            sink,
            next_port: Mutex::new(49152),
        })
    }

    fn alloc_port(&self) -> u16 {
        let mut p = self.next_port.lock().unwrap();
        let port = *p;
        *p = if *p == 65535 { 49152 } else { *p + 1 };
        port
    }

    /// Open a connected UDP socket to `remote` from `local_ip`.
    pub fn dial(self: &Arc<Self>, local_ip: IpAddr, remote: SocketAddr) -> UdpConn {
        let local_port = self.alloc_port();
        let key = UdpKey {
            local_port,
            remote: remote.ip(),
            remote_port: remote.port(),
        };
        let state = Arc::new(UdpState {
            key,
            local_ip,
            rx: Mutex::new(VecDeque::new()),
            signal: Condvar::new(),
            sink: self.sink.clone(),
        });
        self.conns.lock().unwrap().insert(key, state.clone());
        UdpConn {
            state,
            read_timeout: Mutex::new(None),
            stack: self.clone(),
        }
    }

    /// Demultiplex an inbound UDP packet to the matching connection. Returns
    /// `true` if it was consumed.
    pub fn handle_inbound(&self, pkt: &Packet) -> bool {
        if pkt.ip_protocol() != Protocol::UDP {
            return false;
        }
        let src = match pkt.src_addr() {
            Some(s) => s,
            None => return false,
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
    if cs == 0 {
        0xFFFF
    } else {
        cs
    }
}

fn wrap_udp_v4(src: Ipv4Addr, sp: u16, dst: Ipv4Addr, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = udp_header(sp, dp, payload);
    let cs = udp_checksum(IpAddr::V4(src), IpAddr::V4(dst), &udp);
    udp[6..8].copy_from_slice(&cs.to_be_bytes());

    let total = 20 + udp.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
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

        let conn = stack.dial(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            SocketAddr::from(([10, 0, 0, 1], 53)),
        );
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
}

//! Peer address key.
//!
//! A [`PeerKey`] uniquely identifies a peer by its transport (UDP/TCP), IP, and
//! port. It is the map key used by the server to demultiplex incoming packets
//! to per-peer state. Ported from the Go `addr.go` (`Addr [19]byte`): 16 bytes
//! of IPv6-mapped address, 1 protocol byte, 2 port bytes.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Transport protocol of a peer connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn byte(self) -> u8 {
        match self {
            Transport::Udp => 0x01,
            Transport::Tcp => 0x02,
        }
    }
}

/// A 19-byte peer identity: `[ipv6-mapped:16][proto:1][port:2]`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerKey([u8; 19]);

impl PeerKey {
    /// Build a key from a socket address and transport.
    pub fn new(addr: SocketAddr, transport: Transport) -> PeerKey {
        let mut k = [0u8; 19];
        let v6 = match addr.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        k[0..16].copy_from_slice(&v6.octets());
        k[16] = transport.byte();
        let port = addr.port();
        k[17] = (port >> 8) as u8;
        k[18] = (port & 0xff) as u8;
        PeerKey(k)
    }

    /// The IP address embedded in the key.
    pub fn ip(&self) -> IpAddr {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.0[0..16]);
        let v6 = Ipv6Addr::from(octets);
        // Unmap IPv4-mapped addresses for friendlier display.
        match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }
    }

    /// The port embedded in the key.
    pub fn port(&self) -> u16 {
        ((self.0[17] as u16) << 8) | self.0[18] as u16
    }

    /// The transport, if recognized.
    pub fn transport(&self) -> Option<Transport> {
        match self.0[16] {
            0x01 => Some(Transport::Udp),
            0x02 => Some(Transport::Tcp),
            _ => None,
        }
    }

    /// The socket address (IP + port) of the peer.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip(), self.port())
    }
}

impl fmt::Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.transport() {
            Some(Transport::Udp) => write!(f, "udp/{}", self.socket_addr()),
            Some(Transport::Tcp) => write!(f, "tcp/{}", self.socket_addr()),
            None => write!(f, "{}", self.socket_addr()),
        }
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn tcp_proto_and_port() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let k = PeerKey::new(a, Transport::Tcp);
        assert_eq!(k.0[16], 0x02);
        assert_eq!(k.0[17], 0x01);
        assert_eq!(k.0[18], 0xBB);
        assert_eq!(k.port(), 443);
        assert_eq!(k.transport(), Some(Transport::Tcp));
    }

    #[test]
    fn udp_proto() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1194);
        let k = PeerKey::new(a, Transport::Udp);
        assert_eq!(k.0[16], 0x01);
        assert_eq!(k.transport(), Some(Transport::Udp));
    }

    #[test]
    fn display_prefixes() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(PeerKey::new(a, Transport::Tcp).to_string().starts_with("tcp/"));
        assert!(PeerKey::new(a, Transport::Udp).to_string().starts_with("udp/"));
    }

    #[test]
    fn roundtrip_v4() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let k = PeerKey::new(a, Transport::Udp);
        assert_eq!(k.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(k.port(), 12345);
    }

    #[test]
    fn v6() {
        let a = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let k = PeerKey::new(a, Transport::Tcp);
        assert_eq!(k.transport(), Some(Transport::Tcp));
        assert_eq!(k.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }
}

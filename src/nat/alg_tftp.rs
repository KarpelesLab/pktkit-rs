//! TFTP Application Layer Gateway (RFC 1350).
//!
//! TFTP uses port 69 only for the initial request; the server answers from a
//! fresh port (its transfer ID), to the port the request came from (RFC 1350
//! §4). Through this NAT that is the client's mapped outside port, which
//! delivers traffic from any remote (endpoint-independent filtering), and
//! the client's first acknowledgement to the new port makes the server
//! tracked on the mapping. So the transfer needs nothing from an ALG, and
//! this helper passes packets through untouched. It is kept so that code
//! registering it keeps working.
//!
//! It used to register an expectation for the client's own mapped port. That
//! never matched (a live mapping takes the port before expectations are
//! looked at) and only held the port for a minute after the mapping was gone.

use crate::nat::helper::{Helper, PROTO_UDP, PacketHelper};

/// TFTP ALG. TFTP needs nothing from an ALG behind this NAT, so it passes
/// packets through untouched; it is kept so code registering it keeps
/// working. Register via
/// [`Nat::add_packet_helper`](crate::nat::Nat::add_packet_helper).
#[derive(Debug, Default)]
pub struct TftpHelper;

impl TftpHelper {
    /// A new TFTP helper.
    pub fn new() -> TftpHelper {
        TftpHelper
    }
}

impl Helper for TftpHelper {
    fn name(&self) -> &str {
        "tftp"
    }
}

impl PacketHelper for TftpHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_UDP && dst_port == 69
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::Nat;
    use crate::{IpPrefix, L3Device, Packet};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    fn udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let c = crate::checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    #[test]
    fn transfer_from_a_fresh_server_port_needs_no_expectation() {
        let pfx = |s: &str| s.parse::<IpPrefix>().unwrap();
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(TftpHelper::new()));
        let outside = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let c = outside.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let inside = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let c = inside.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(198, 51, 100, 9);
        let rrq = udp(client, 3000, server, 69, b"\x00\x01file\x00octet\x00");
        nat.inside().send(Packet::from_slice(&rrq)).unwrap();
        assert!(nat.take_expectation(PROTO_UDP, client, 3000).is_none());

        let mapped = {
            let o = outside.lock().unwrap();
            assert_eq!(o[0][28..], rrq[28..], "request passes unchanged");
            u16::from_be_bytes([o[0][20], o[0][21]])
        };
        let data = udp(
            server,
            41000,
            Ipv4Addr::new(203, 0, 113, 1),
            mapped,
            b"\x00\x03\x00\x01x",
        );
        nat.outside().send(Packet::from_slice(&data)).unwrap();
        let got = inside.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0][16..20], &client.octets());
        assert_eq!(u16::from_be_bytes([got[0][22], got[0][23]]), 3000);
    }
}

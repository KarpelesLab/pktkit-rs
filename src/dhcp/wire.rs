//! DHCP/BOOTP wire format: option codes, message types, parser, builder.
//!
//! All BOOTP/DHCP packets share the same 236-byte header followed by a four-
//! byte magic cookie (`63 82 53 63`) and a TLV option list terminated by
//! [`OPT_END`].

use crate::MacAddr;
use std::net::Ipv4Addr;

// --- Message types (option 53) ---------------------------------------------

pub const MSG_DISCOVER: u8 = 1;
pub const MSG_OFFER: u8 = 2;
pub const MSG_REQUEST: u8 = 3;
pub const MSG_DECLINE: u8 = 4;
pub const MSG_ACK: u8 = 5;
pub const MSG_NAK: u8 = 6;
pub const MSG_RELEASE: u8 = 7;
pub const MSG_INFORM: u8 = 8;

// --- Option codes ----------------------------------------------------------

pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST: u8 = 55;
pub const OPT_END: u8 = 255;

/// BOOTP minimum size (header + cookie + a few bytes of options).
pub const MIN_PACKET_LEN: usize = 240;

/// Magic cookie, written at offset 236.
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Fields parsed out of a received DHCP message.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub op: u8,
    pub xid: u32,
    pub yiaddr: Ipv4Addr,
    pub chaddr: MacAddr,
    pub msg_type: u8,
    pub subnet_mask: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: u32,
    pub requested_ip: Option<Ipv4Addr>,
}

impl Default for Parsed {
    fn default() -> Parsed {
        Parsed {
            op: 0,
            xid: 0,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: MacAddr::zero(),
            msg_type: 0,
            subnet_mask: None,
            server_id: None,
            router: None,
            dns: Vec::new(),
            lease_time: 0,
            requested_ip: None,
        }
    }
}

impl Parsed {
    /// Parse a UDP DHCP payload (everything after the UDP header).
    ///
    /// Returns `None` if the buffer is too short or has the wrong magic cookie.
    pub fn from_bytes(b: &[u8]) -> Option<Parsed> {
        if b.len() < MIN_PACKET_LEN + 4 {
            return None;
        }
        if b[236..240] != MAGIC_COOKIE {
            return None;
        }
        let mut p = Parsed {
            op: b[0],
            xid: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            yiaddr: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
            chaddr: {
                let mut o = [0u8; 6];
                o.copy_from_slice(&b[28..34]);
                MacAddr(o)
            },
            ..Default::default()
        };
        let mut opts = &b[240..];
        while !opts.is_empty() {
            let code = opts[0];
            if code == OPT_END {
                break;
            }
            if code == OPT_PAD {
                opts = &opts[1..];
                continue;
            }
            if opts.len() < 2 {
                break;
            }
            let len = opts[1] as usize;
            if opts.len() < 2 + len {
                break;
            }
            let data = &opts[2..2 + len];
            match code {
                OPT_MESSAGE_TYPE if len >= 1 => p.msg_type = data[0],
                OPT_SUBNET_MASK if len == 4 => {
                    p.subnet_mask = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                }
                OPT_SERVER_ID if len == 4 => {
                    p.server_id = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                }
                OPT_ROUTER if len >= 4 => {
                    p.router = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                }
                OPT_DNS if len % 4 == 0 => {
                    for chunk in data.chunks(4) {
                        p.dns.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                    }
                }
                OPT_LEASE_TIME if len == 4 => {
                    p.lease_time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                }
                OPT_REQUESTED_IP if len == 4 => {
                    p.requested_ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                }
                _ => {}
            }
            opts = &opts[2 + len..];
        }
        Some(p)
    }
}

/// In-place builder for an outgoing DHCP message. Writes into a caller-owned
/// `Vec<u8>` and tracks the option offset so callers can append options one
/// by one without recomputing positions.
#[derive(Debug)]
pub struct Builder {
    buf: Vec<u8>,
    off: usize,
}

impl Builder {
    /// Start a new DHCP message. `op` is 1 for BOOTREQUEST, 2 for BOOTREPLY.
    pub fn new(op: u8, xid: u32, chaddr: MacAddr) -> Builder {
        let mut buf = vec![0u8; 240];
        buf[0] = op;
        buf[1] = 1; // htype Ethernet
        buf[2] = 6; // hlen
        buf[4..8].copy_from_slice(&xid.to_be_bytes());
        buf[28..34].copy_from_slice(&chaddr.octets());
        buf[236..240].copy_from_slice(&MAGIC_COOKIE);
        Builder { buf, off: 240 }
    }

    /// Set the `yiaddr` ("your address") field — the IP the server is
    /// granting to the client.
    pub fn yiaddr(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.buf[16..20].copy_from_slice(&ip.octets());
        self
    }

    /// Set the `siaddr` ("server IP") field.
    pub fn siaddr(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.buf[20..24].copy_from_slice(&ip.octets());
        self
    }

    /// Set the `ciaddr` ("client IP") field — used for RENEW.
    pub fn ciaddr(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.buf[12..16].copy_from_slice(&ip.octets());
        self
    }

    /// Append an option with `len` bytes of `data`.
    pub fn option(&mut self, code: u8, data: &[u8]) -> &mut Self {
        self.buf.push(code);
        self.buf.push(data.len() as u8);
        self.buf.extend_from_slice(data);
        self.off += 2 + data.len();
        self
    }

    /// Append the message-type option.
    pub fn message_type(&mut self, t: u8) -> &mut Self {
        self.option(OPT_MESSAGE_TYPE, &[t])
    }

    /// Append a 4-byte IPv4 option (subnet mask, router, server ID, etc.).
    pub fn ipv4_option(&mut self, code: u8, ip: Ipv4Addr) -> &mut Self {
        let o = ip.octets();
        self.option(code, &o)
    }

    /// Append a list of IPv4 addresses (e.g. DNS servers).
    pub fn ipv4_list_option(&mut self, code: u8, ips: &[Ipv4Addr]) -> &mut Self {
        let mut data = Vec::with_capacity(ips.len() * 4);
        for ip in ips {
            data.extend_from_slice(&ip.octets());
        }
        self.option(code, &data)
    }

    /// Append a 4-byte big-endian u32 option (lease time).
    pub fn u32_option(&mut self, code: u8, v: u32) -> &mut Self {
        self.option(code, &v.to_be_bytes())
    }

    /// Terminate options with [`OPT_END`] and return the final byte buffer.
    /// Pads to BOOTP minimum (300 bytes) if needed.
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.push(OPT_END);
        if self.buf.len() < 300 {
            self.buf.resize(300, 0);
        }
        self.buf
    }
}

/// Return the prefix length encoded in a 4-byte IPv4 subnet mask.
pub fn mask_bits(mask: Ipv4Addr) -> u8 {
    let m = u32::from(mask);
    m.leading_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let mut b = Builder::new(2, 0xCAFEBABE, mac);
        b.yiaddr(Ipv4Addr::new(10, 0, 0, 5))
            .siaddr(Ipv4Addr::new(10, 0, 0, 1))
            .message_type(MSG_OFFER)
            .ipv4_option(OPT_SUBNET_MASK, Ipv4Addr::new(255, 255, 255, 0))
            .ipv4_option(OPT_ROUTER, Ipv4Addr::new(10, 0, 0, 1))
            .ipv4_list_option(
                OPT_DNS,
                &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
            )
            .u32_option(OPT_LEASE_TIME, 3600)
            .ipv4_option(OPT_SERVER_ID, Ipv4Addr::new(10, 0, 0, 1));
        let pkt = b.finish();

        let p = Parsed::from_bytes(&pkt).unwrap();
        assert_eq!(p.op, 2);
        assert_eq!(p.xid, 0xCAFEBABE);
        assert_eq!(p.chaddr, mac);
        assert_eq!(p.yiaddr, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(p.msg_type, MSG_OFFER);
        assert_eq!(p.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(p.router, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(p.dns, vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]);
        assert_eq!(p.lease_time, 3600);
        assert_eq!(p.server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn mask_bits_calc() {
        assert_eq!(mask_bits(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_bits(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_bits(Ipv4Addr::new(0, 0, 0, 0)), 0);
        assert_eq!(mask_bits(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn parse_rejects_short() {
        assert!(Parsed::from_bytes(&[0u8; 100]).is_none());
    }

    #[test]
    fn parse_rejects_bad_cookie() {
        let mut b = vec![0u8; 300];
        b[236..240].copy_from_slice(&[1, 2, 3, 4]);
        b[240] = OPT_END;
        assert!(Parsed::from_bytes(&b).is_none());
    }
}

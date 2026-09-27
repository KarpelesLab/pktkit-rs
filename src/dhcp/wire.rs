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

/// The BROADCAST bit of `flags` (RFC 2131 §2).
pub const FLAG_BROADCAST: u16 = 0x8000;

// --- Option codes ----------------------------------------------------------

pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_RENEWAL_TIME: u8 = 58;
pub const OPT_REBINDING_TIME: u8 = 59;
pub const OPT_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST: u8 = 55;
pub const OPT_OVERLOAD: u8 = 52;
pub const OPT_CLIENT_ID: u8 = 61;
pub const OPT_END: u8 = 255;

/// BOOTP minimum size (header + cookie + a few bytes of options).
pub const MIN_PACKET_LEN: usize = 240;

/// Magic cookie, written at offset 236.
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Fields parsed out of a received DHCP message.
///
/// Only the parser builds it, so fields may be added as more options are
/// understood.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Parsed {
    pub op: u8,
    pub xid: u32,
    /// `flags`; the top bit is BROADCAST (RFC 2131 §2), set by a client
    /// that cannot receive unicast before it has an address.
    pub flags: u16,
    /// Client's current address, set only when it is renewing or rebinding a
    /// lease it holds (RFC 2131 §4.3.2).
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    /// Relay agent address: non-zero when a BOOTP relay forwarded the
    /// message from another subnet.
    pub giaddr: Ipv4Addr,
    /// The first six bytes of `chaddr`: the client's MAC on Ethernet.
    pub chaddr: MacAddr,
    /// Hardware address type (`htype`, 1 for Ethernet) and length (`hlen`).
    pub htype: u8,
    pub hlen: u8,
    /// The whole 16-byte `chaddr` field, of which the first `hlen` bytes
    /// are the hardware address.
    pub chaddr_field: [u8; 16],
    pub msg_type: u8,
    pub subnet_mask: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// IP address lease time (option 51), in seconds; `u32::MAX` is
    /// infinite. `None` when absent, which RFC 2131 Table 3 does not allow
    /// in an OFFER or in an ACK to a REQUEST.
    pub lease_time: Option<u32>,
    /// Renewal (T1) and rebinding (T2) times, options 58 and 59.
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
    pub requested_ip: Option<Ipv4Addr>,
    /// Client identifier (option 61): type byte and identifier (RFC 2132
    /// §9.14). A server keys the client's lease on it when present (RFC
    /// 2131 §4.2).
    pub client_id: Option<Vec<u8>>,
}

impl Default for Parsed {
    fn default() -> Parsed {
        Parsed {
            op: 0,
            xid: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: MacAddr::zero(),
            htype: 0,
            hlen: 0,
            chaddr_field: [0; 16],
            msg_type: 0,
            subnet_mask: None,
            server_id: None,
            router: None,
            dns: Vec::new(),
            lease_time: None,
            renewal_time: None,
            rebinding_time: None,
            requested_ip: None,
            client_id: None,
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
            flags: u16::from_be_bytes([b[10], b[11]]),
            ciaddr: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
            yiaddr: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
            giaddr: Ipv4Addr::new(b[24], b[25], b[26], b[27]),
            chaddr: {
                let mut o = [0u8; 6];
                o.copy_from_slice(&b[28..34]);
                MacAddr(o)
            },
            htype: b[1],
            hlen: b[2],
            chaddr_field: b[28..44].try_into().unwrap(),
            ..Default::default()
        };
        // RFC 3396: an option may come as several instances, which are one
        // option once concatenated; and option 52 may move options into the
        // file and sname fields, read after the options field in that order.
        let mut opts: Vec<(u8, Vec<u8>)> = Vec::new();
        collect_options(&b[240..], &mut opts);
        let overload = opts
            .iter()
            .find(|(c, _)| *c == OPT_OVERLOAD)
            .and_then(|(_, d)| d.first().copied())
            .unwrap_or(0);
        if overload & 1 != 0 {
            collect_options(&b[108..236], &mut opts);
        }
        if overload & 2 != 0 {
            collect_options(&b[44..108], &mut opts);
        }
        for (code, data) in &opts {
            let (code, data, len) = (*code, &data[..], data.len());
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
                OPT_DNS if len.is_multiple_of(4) => {
                    for chunk in data.chunks(4) {
                        p.dns
                            .push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                    }
                }
                OPT_LEASE_TIME if len == 4 => {
                    p.lease_time = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                }
                OPT_RENEWAL_TIME if len == 4 => {
                    p.renewal_time = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                }
                OPT_REBINDING_TIME if len == 4 => {
                    p.rebinding_time =
                        Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                }
                OPT_REQUESTED_IP if len == 4 => {
                    p.requested_ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                }
                OPT_CLIENT_ID if len >= 2 => p.client_id = Some(data.to_vec()),
                _ => {}
            }
        }
        Some(p)
    }
}

/// Walk one option area into `out`, joining the instances of each option
/// (RFC 3396 §7). Stops at END, or at an option that runs off the area.
fn collect_options(mut area: &[u8], out: &mut Vec<(u8, Vec<u8>)>) {
    while let Some(&code) = area.first() {
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            area = &area[1..];
            continue;
        }
        let Some(&len) = area.get(1) else {
            break;
        };
        let Some(data) = area.get(2..2 + len as usize) else {
            break;
        };
        match out.iter_mut().find(|(c, _)| *c == code) {
            Some((_, d)) => d.extend_from_slice(data),
            None => out.push((code, data.to_vec())),
        }
        area = &area[2 + len as usize..];
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

    /// Set the hardware type, length and whole `chaddr` field, for a reply
    /// that must echo a client's that is not a plain Ethernet MAC.
    pub fn hardware(&mut self, htype: u8, hlen: u8, chaddr: &[u8; 16]) -> &mut Self {
        self.buf[1] = htype;
        self.buf[2] = hlen;
        self.buf[28..44].copy_from_slice(chaddr);
        self
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

    /// Set the `flags` field (the top bit is BROADCAST).
    pub fn flags(&mut self, flags: u16) -> &mut Self {
        self.buf[10..12].copy_from_slice(&flags.to_be_bytes());
        self
    }

    /// Set the `giaddr` (relay agent) field.
    pub fn giaddr(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.buf[24..28].copy_from_slice(&ip.octets());
        self
    }

    /// Set the `ciaddr` ("client IP") field — used for RENEW.
    pub fn ciaddr(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.buf[12..16].copy_from_slice(&ip.octets());
        self
    }

    /// Append an option carrying `data`.
    ///
    /// Data longer than the 255 bytes one length octet can describe goes
    /// out as consecutive instances of the option, which the receiver joins
    /// back together (RFC 3396); a single one would state a wrapped length
    /// and garble every option after it.
    pub fn option(&mut self, code: u8, data: &[u8]) -> &mut Self {
        let mut chunks = data.chunks(255).peekable();
        if chunks.peek().is_none() {
            self.buf.extend_from_slice(&[code, 0]);
            self.off += 2;
        }
        for chunk in chunks {
            self.buf.push(code);
            self.buf.push(chunk.len() as u8);
            self.buf.extend_from_slice(chunk);
            self.off += 2 + chunk.len();
        }
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
            .ciaddr(Ipv4Addr::new(10, 0, 0, 7))
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
        assert_eq!(p.ciaddr, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(p.msg_type, MSG_OFFER);
        assert_eq!(p.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(p.router, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            p.dns,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
        assert_eq!(p.lease_time, Some(3600));
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
    fn an_option_longer_than_255_bytes_is_split_and_rejoined() {
        // 64 DNS servers are 256 bytes: one past what a length octet holds.
        let dns: Vec<Ipv4Addr> = (0..64).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let mut b = Builder::new(2, 1, MacAddr::zero());
        b.message_type(MSG_ACK).ipv4_list_option(OPT_DNS, &dns);
        let pkt = b.finish();
        // RFC 3396: consecutive instances, each at most 255 bytes.
        assert_eq!(pkt[243], OPT_DNS);
        assert_eq!(pkt[244], 255);
        assert_eq!(Parsed::from_bytes(&pkt).unwrap().dns, dns);
    }

    #[test]
    fn options_overloaded_into_file_and_sname_are_parsed() {
        let mut b = Builder::new(2, 1, MacAddr::zero());
        b.message_type(MSG_OFFER).option(OPT_OVERLOAD, &[3]);
        let mut pkt = b.finish();
        // RFC 2131 §4.1 / RFC 3396: options field, then file, then sname.
        pkt[108..116].copy_from_slice(&[OPT_SERVER_ID, 4, 10, 0, 0, 1, OPT_END, 0]);
        pkt[44..51].copy_from_slice(&[OPT_LEASE_TIME, 4, 0, 0, 0x0e, 0x10, OPT_END]);
        let p = Parsed::from_bytes(&pkt).unwrap();
        assert_eq!(p.server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(p.lease_time, Some(3600));

        // Without the overload option, those fields are a name and a path.
        let mut b = Builder::new(2, 1, MacAddr::zero());
        b.message_type(MSG_OFFER);
        let mut pkt = b.finish();
        pkt[108..116].copy_from_slice(&[OPT_SERVER_ID, 4, 10, 0, 0, 1, OPT_END, 0]);
        assert_eq!(Parsed::from_bytes(&pkt).unwrap().server_id, None);
    }

    #[test]
    fn parse_rejects_bad_cookie() {
        let mut b = vec![0u8; 300];
        b[236..240].copy_from_slice(&[1, 2, 3, 4]);
        b[240] = OPT_END;
        assert!(Parsed::from_bytes(&b).is_none());
    }
}

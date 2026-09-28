//! TCP option codec (RFCs 793, 2018, 7323).

/// TCP option kinds, the values of [`TcpOption::kind`].
#[allow(non_upper_case_globals)]
pub mod kind {
    /// End of option list.
    pub const End: u8 = 0;
    /// No-operation (padding).
    pub const Nop: u8 = 1;
    /// Maximum segment size (RFC 9293).
    pub const Mss: u8 = 2;
    /// Window scale (RFC 7323).
    pub const WScale: u8 = 3;
    /// SACK permitted (RFC 2018).
    pub const SackPerm: u8 = 4;
    /// SACK blocks (RFC 2018).
    pub const Sack: u8 = 5;
    /// Timestamps (RFC 7323).
    pub const Timestamp: u8 = 8;
}

/// A parsed TCP option (kind + raw payload, excluding the kind and length
/// bytes for kinds that carry a length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOption {
    /// The option kind; see [`kind`].
    pub kind: u8,
    /// The option's payload, without its kind and length bytes.
    pub data: Vec<u8>,
}

/// A SACK block: `[left, right)` in sequence space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    pub left: u32,
    pub right: u32,
}

/// Parse the options portion of a TCP header. Stops at end-of-options or a
/// malformed entry; never panics.
pub fn parse_options(raw: &[u8]) -> Vec<TcpOption> {
    // Room for what a segment usually carries (timestamps and SACK, or a
    // SYN's four), without growing.
    let mut opts = Vec::with_capacity(4);
    let mut i = 0;
    while i < raw.len() {
        let k = raw[i];
        if k == kind::End {
            break;
        }
        if k == kind::Nop {
            opts.push(TcpOption {
                kind: kind::Nop,
                data: Vec::new(),
            });
            i += 1;
            continue;
        }
        if i + 1 >= raw.len() {
            break;
        }
        let l = raw[i + 1] as usize;
        if l < 2 || i + l > raw.len() {
            break;
        }
        let data = if l > 2 {
            raw[i + 2..i + l].to_vec()
        } else {
            Vec::new()
        };
        opts.push(TcpOption { kind: k, data });
        i += l;
    }
    opts
}

/// Serialize options into wire format, padding to a 4-byte boundary with
/// end-of-options bytes. What the engine sends is written in place
/// ([`write_options`]); only the tests still build options on their own.
#[cfg(test)]
pub fn build_options(opts: &[TcpOption]) -> Vec<u8> {
    let mut buf = vec![0; options_len(opts)];
    write_options(opts, &mut buf);
    buf
}

/// The length [`build_options`] gives `opts`, padding included, without
/// building them.
pub(crate) fn options_len(opts: &[TcpOption]) -> usize {
    let raw: usize = opts
        .iter()
        .map(|o| {
            if o.kind == kind::Nop {
                1
            } else {
                2 + o.data.len()
            }
        })
        .sum();
    raw.next_multiple_of(4)
}

/// Serialize `opts` into `buf`, which is [`options_len`] long, padding
/// with end-of-options bytes.
pub(crate) fn write_options(opts: &[TcpOption], buf: &mut [u8]) {
    let mut i = 0;
    for o in opts {
        buf[i] = o.kind;
        i += 1;
        if o.kind == kind::Nop {
            continue;
        }
        buf[i] = (2 + o.data.len()) as u8;
        buf[i + 1..i + 1 + o.data.len()].copy_from_slice(&o.data);
        i += 1 + o.data.len();
    }
    buf[i..].fill(kind::End);
}

/// A Maximum Segment Size option.
pub fn mss_option(mss: u16) -> TcpOption {
    TcpOption {
        kind: kind::Mss,
        data: mss.to_be_bytes().to_vec(),
    }
}

/// A Window Scale option with shift count `shift`.
pub fn wscale_option(shift: u8) -> TcpOption {
    TcpOption {
        kind: kind::WScale,
        data: vec![shift],
    }
}

/// A SACK-Permitted option.
pub fn sack_perm_option() -> TcpOption {
    TcpOption {
        kind: kind::SackPerm,
        data: Vec::new(),
    }
}

/// A SACK option reporting `blocks`.
pub fn sack_option(blocks: &[SackBlock]) -> TcpOption {
    let mut data = Vec::with_capacity(8 * blocks.len());
    for b in blocks {
        data.extend_from_slice(&b.left.to_be_bytes());
        data.extend_from_slice(&b.right.to_be_bytes());
    }
    TcpOption {
        kind: kind::Sack,
        data,
    }
}

/// A Timestamps option (TSval, TSecr).
pub fn timestamp_option(ts_val: u32, ts_ecr: u32) -> TcpOption {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&ts_val.to_be_bytes());
    data.extend_from_slice(&ts_ecr.to_be_bytes());
    TcpOption {
        kind: kind::Timestamp,
        data,
    }
}

/// Extract the MSS value from a list of options, or 0 if absent.
pub fn get_mss(opts: &[TcpOption]) -> u16 {
    for o in opts {
        if o.kind == kind::Mss && o.data.len() == 2 {
            return u16::from_be_bytes([o.data[0], o.data[1]]);
        }
    }
    0
}

/// The smallest MSS vtcp sends with, whatever the peer advertises: Linux's
/// `TCP_MIN_MSS`. An MSS of a few bytes is legal on the wire but no real
/// path needs it, and it would let a peer make us spend a 40-byte header on
/// every byte of data.
pub const MIN_MSS: u16 = 88;

/// The MSS to send with, given a SYN's options: the advertised value, or
/// when there is none, 536 for IPv4 (RFC 9293 §3.7.1, RFC 1122 §4.2.2.6) and
/// 1220 for IPv6 (its 1280-byte minimum MTU less 60 bytes of headers, RFC
/// 8200 §5). Never below [`MIN_MSS`].
pub(crate) fn peer_mss(opts: &[TcpOption], ipv6: bool) -> u16 {
    match get_mss(opts) {
        0 if ipv6 => 1220,
        0 => 536,
        m => m.max(MIN_MSS),
    }
}

/// Extract the window scale shift, returning `None` if absent.
pub fn get_wscale(opts: &[TcpOption]) -> std::option::Option<u8> {
    for o in opts {
        if o.kind == kind::WScale && o.data.len() == 1 {
            return Some(o.data[0]);
        }
    }
    None
}

/// Extract (TSval, TSecr) from the options, if a Timestamp option is present.
pub fn get_timestamp(opts: &[TcpOption]) -> std::option::Option<(u32, u32)> {
    for o in opts {
        if o.kind == kind::Timestamp && o.data.len() == 8 {
            let a = u32::from_be_bytes([o.data[0], o.data[1], o.data[2], o.data[3]]);
            let b = u32::from_be_bytes([o.data[4], o.data[5], o.data[6], o.data[7]]);
            return Some((a, b));
        }
    }
    None
}

/// Extract SACK blocks (returns empty vec if none).
pub fn get_sack_blocks(opts: &[TcpOption]) -> Vec<SackBlock> {
    for o in opts {
        if o.kind == kind::Sack && o.data.len() >= 8 && o.data.len() % 8 == 0 {
            let n = o.data.len() / 8;
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let base = i * 8;
                let l = u32::from_be_bytes([
                    o.data[base],
                    o.data[base + 1],
                    o.data[base + 2],
                    o.data[base + 3],
                ]);
                let r = u32::from_be_bytes([
                    o.data[base + 4],
                    o.data[base + 5],
                    o.data[base + 6],
                    o.data[base + 7],
                ]);
                out.push(SackBlock { left: l, right: r });
            }
            return out;
        }
    }
    Vec::new()
}

/// True iff the SACK-Permitted option is present.
pub fn has_sack_perm(opts: &[TcpOption]) -> bool {
    opts.iter().any(|o| o.kind == kind::SackPerm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_roundtrip() {
        let o = mss_option(1460);
        let raw = build_options(&[o]);
        // MSS option = kind(1) + len(1) + value(2) = 4 bytes, already aligned.
        assert_eq!(raw.len(), 4);
        let parsed = parse_options(&raw);
        assert_eq!(get_mss(&parsed), 1460);
    }

    #[test]
    fn multiple_options_with_padding() {
        // MSS + WScale + SackPerm = 4 + 3 + 2 = 9 bytes → padded to 12
        let opts = vec![mss_option(1460), wscale_option(7), sack_perm_option()];
        let raw = build_options(&opts);
        assert_eq!(raw.len(), 12);
        let parsed = parse_options(&raw);
        assert_eq!(get_mss(&parsed), 1460);
        assert_eq!(get_wscale(&parsed), Some(7));
        assert!(has_sack_perm(&parsed));
    }

    #[test]
    fn timestamp_roundtrip() {
        let raw = build_options(&[timestamp_option(0xdeadbeef, 0x12345678)]);
        let parsed = parse_options(&raw);
        assert_eq!(get_timestamp(&parsed), Some((0xdeadbeef, 0x12345678)));
    }

    #[test]
    fn sack_roundtrip() {
        let blocks = vec![
            SackBlock {
                left: 100,
                right: 200,
            },
            SackBlock {
                left: 300,
                right: 400,
            },
        ];
        let raw = build_options(&[sack_option(&blocks)]);
        let parsed = parse_options(&raw);
        assert_eq!(get_sack_blocks(&parsed), blocks);
    }

    /// The length is what building gives, padding and NOPs included, and
    /// what is built parses back.
    #[test]
    fn options_len_matches_the_built_options() {
        let nop = TcpOption {
            kind: kind::Nop,
            data: Vec::new(),
        };
        let block = SackBlock { left: 1, right: 2 };
        for opts in [
            vec![],
            vec![nop.clone()],
            vec![nop.clone(), nop.clone(), timestamp_option(1, 2)],
            vec![timestamp_option(1, 2), sack_option(&[block; 3])],
            vec![mss_option(1460), sack_perm_option(), wscale_option(7)],
        ] {
            let raw = build_options(&opts);
            assert_eq!(raw.len(), options_len(&opts));
            assert_eq!(raw.len() % 4, 0);
            let parsed = parse_options(&raw);
            assert_eq!(parsed, opts);
        }
    }

    #[test]
    fn truncated_options_are_safe() {
        // kind=MSS, len=10, but only 2 bytes follow → must not panic
        let raw = [kind::Mss, 10, 0x05, 0xb4];
        let parsed = parse_options(&raw);
        assert!(parsed.is_empty());
    }
}

//! TCP option codec (RFCs 793, 2018, 7323).

/// TCP option kinds.
#[allow(non_upper_case_globals)]
pub mod kind {
    pub const End: u8 = 0;
    pub const Nop: u8 = 1;
    pub const Mss: u8 = 2;
    pub const WScale: u8 = 3;
    pub const SackPerm: u8 = 4;
    pub const Sack: u8 = 5;
    pub const Timestamp: u8 = 8;
}

/// A parsed TCP option (kind + raw payload, excluding the kind and length
/// bytes for kinds that carry a length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOption {
    pub kind: u8,
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
    let mut opts = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let k = raw[i];
        if k == kind::End {
            break;
        }
        if k == kind::Nop {
            opts.push(TcpOption { kind: kind::Nop, data: Vec::new() });
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
/// end-of-options bytes.
pub fn build_options(opts: &[TcpOption]) -> Vec<u8> {
    let mut buf = Vec::new();
    for o in opts {
        if o.kind == kind::Nop {
            buf.push(kind::Nop);
            continue;
        }
        buf.push(o.kind);
        buf.push((2 + o.data.len()) as u8);
        buf.extend_from_slice(&o.data);
    }
    while buf.len() % 4 != 0 {
        buf.push(kind::End);
    }
    buf
}

pub fn mss_option(mss: u16) -> TcpOption {
    TcpOption { kind: kind::Mss, data: mss.to_be_bytes().to_vec() }
}

pub fn wscale_option(shift: u8) -> TcpOption {
    TcpOption { kind: kind::WScale, data: vec![shift] }
}

pub fn sack_perm_option() -> TcpOption {
    TcpOption { kind: kind::SackPerm, data: Vec::new() }
}

pub fn sack_option(blocks: &[SackBlock]) -> TcpOption {
    let mut data = Vec::with_capacity(8 * blocks.len());
    for b in blocks {
        data.extend_from_slice(&b.left.to_be_bytes());
        data.extend_from_slice(&b.right.to_be_bytes());
    }
    TcpOption { kind: kind::Sack, data }
}

pub fn timestamp_option(ts_val: u32, ts_ecr: u32) -> TcpOption {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&ts_val.to_be_bytes());
    data.extend_from_slice(&ts_ecr.to_be_bytes());
    TcpOption { kind: kind::Timestamp, data }
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
                    o.data[base], o.data[base + 1], o.data[base + 2], o.data[base + 3],
                ]);
                let r = u32::from_be_bytes([
                    o.data[base + 4], o.data[base + 5], o.data[base + 6], o.data[base + 7],
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
            SackBlock { left: 100, right: 200 },
            SackBlock { left: 300, right: 400 },
        ];
        let raw = build_options(&[sack_option(&blocks)]);
        let parsed = parse_options(&raw);
        assert_eq!(get_sack_blocks(&parsed), blocks);
    }

    #[test]
    fn truncated_options_are_safe() {
        // kind=MSS, len=10, but only 2 bytes follow → must not panic
        let raw = [kind::Mss, 10, 0x05, 0xb4];
        let parsed = parse_options(&raw);
        assert!(parsed.is_empty());
    }
}

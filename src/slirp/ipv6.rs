//! IPv6-side dispatch.

/// Skip IPv6 extension headers starting at `offset`. Returns the final
/// transport protocol number and the offset where that protocol begins.
/// Mirrors `slirp/ipv6.go::skipExtensionHeaders`.
pub(crate) fn skip_extension_headers(
    packet: &[u8],
    mut next_header: u8,
    mut offset: usize,
) -> (u8, usize) {
    loop {
        match next_header {
            // Hop-by-Hop, Routing, Destination Options.
            0 | 43 | 60 => {
                if offset + 2 > packet.len() {
                    return (next_header, offset);
                }
                let nh = packet[offset];
                let hdr_len = ((packet[offset + 1] as usize) + 1) * 8;
                next_header = nh;
                offset += hdr_len;
            }
            // Fragment — fixed 8 bytes.
            44 => {
                if offset + 8 > packet.len() {
                    return (next_header, offset);
                }
                let nh = packet[offset];
                next_header = nh;
                offset += 8;
            }
            _ => return (next_header, offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_extension_returns_input() {
        let pkt = [0u8; 40];
        let (proto, off) = skip_extension_headers(&pkt, 6, 40);
        assert_eq!(proto, 6);
        assert_eq!(off, 40);
    }

    #[test]
    fn skip_hop_by_hop() {
        // 0 = hop-by-hop, length byte = 0 → 8 bytes.
        let mut pkt = vec![0u8; 60];
        pkt[40] = 17; // next header after hbh = UDP
        pkt[41] = 0; // (0+1)*8 = 8 bytes
        let (proto, off) = skip_extension_headers(&pkt, 0, 40);
        assert_eq!(proto, 17);
        assert_eq!(off, 48);
    }

    #[test]
    fn skip_fragment_header() {
        let mut pkt = vec![0u8; 60];
        pkt[40] = 6; // next = TCP
        let (proto, off) = skip_extension_headers(&pkt, 44, 40);
        assert_eq!(proto, 6);
        assert_eq!(off, 48);
    }
}

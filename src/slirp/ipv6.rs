//! IPv6-side dispatch.

/// Skip IPv6 extension headers starting at `offset`. Returns the final
/// transport protocol number and the offset where that protocol begins.
///
/// This is a thin wrapper over the crate's canonical walker, which also backs
/// [`Packet::transport_protocol`](crate::Packet::transport_protocol). It knows
/// about more header types than a hand-rolled loop here would, bounds the walk
/// so a crafted chain cannot spin, and refuses to point at a transport header
/// that a later fragment does not actually carry.
#[inline]
pub(crate) fn skip_extension_headers(packet: &[u8], next_header: u8, offset: usize) -> (u8, usize) {
    crate::packet::skip_ipv6_ext(packet, next_header, offset)
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

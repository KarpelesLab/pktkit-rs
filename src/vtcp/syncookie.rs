//! SYN-cookie generator/validator for stateless TCP handshake completion.
//!
//! When a listener's accept queue is full, SYN cookies allow handshakes to
//! finish without allocating any per-connection state until the final ACK.
//! The tradeoff is that SYN-cookie-established connections do not negotiate
//! window scaling, SACK, or timestamps (the 32-bit ISS isn't wide enough).
//! This matches the Linux behavior.
//!
//! The cookie's MAC is the keyed SipHash vtcp also derives its ISNs from,
//! as in Linux, over the full 4-tuple (RFC 4987 §3.6: without the addresses,
//! a cookie earned from one source validates an ACK spoofed from any other),
//! the peer's ISN, the MSS index and a time counter. The counter is what expires
//! a cookie, so the key itself never has to rotate.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use super::options::{mss_option, peer_mss};
use super::secret;
use super::segment::{Segment, flags};

const COOKIE_COUNTER_PERIOD_SECS: u64 = 64;

/// MSS table — values indexed by 3 bits in the cookie. A cookie encodes the
/// largest entry not above the MSS actually agreed, so the table starts at
/// the smallest MSS vtcp sends with and includes the no-option defaults
/// (536 for IPv4, 1220 for IPv6).
const MSS_TABLE: [u16; 8] = [88, 536, 1220, 1360, 1440, 1460, 4312, 8960];

/// SYN-cookie engine. One per listener.
pub struct SynCookies {
    /// Keeps one listener's cookies from validating at another.
    salt: u64,
}

impl std::fmt::Debug for SynCookies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynCookies").finish_non_exhaustive()
    }
}

impl Default for SynCookies {
    fn default() -> Self {
        Self::new()
    }
}

impl SynCookies {
    /// A cookie engine with a salt of its own, so its cookies are not valid at
    /// another.
    pub fn new() -> Self {
        static INSTANCE: AtomicU64 = AtomicU64::new(0);
        let n = INSTANCE.fetch_add(1, Ordering::Relaxed);
        Self {
            salt: secret::keyed_hash(("syncookie-instance", n)),
        }
    }

    /// Build a SYN-ACK whose ISS is a SYN cookie. No per-connection state
    /// is allocated. The caller is responsible for sending the segment.
    ///
    /// `local_ip` and `remote_ip` are the SYN's destination and source
    /// addresses; `mss` is the MSS we advertise. The cookie records the MSS
    /// to send with: the smaller of ours and the SYN's (or the default for
    /// the address family, if the SYN has none).
    pub fn generate_syn_ack(
        &self,
        syn: &Segment,
        local_ip: IpAddr,
        remote_ip: IpAddr,
        mss: u16,
    ) -> Segment {
        let counter = now_counter();
        let send_mss = peer_mss(&syn.options, remote_ip.is_ipv6()).min(mss);
        let mss_idx = closest_mss_index(send_mss);
        let cookie = self.cookie(
            (local_ip, syn.dst_port),
            (remote_ip, syn.src_port),
            syn.seq,
            counter,
            mss_idx,
        );
        Segment {
            src_port: syn.dst_port,
            dst_port: syn.src_port,
            seq: cookie,
            ack: syn.seq.wrapping_add(1),
            flags: flags::SYN | flags::ACK,
            window: 65535,
            options: vec![mss_option(mss)],
            ..Default::default()
        }
    }

    /// Check whether a final ACK, received at `local_ip` from `remote_ip`,
    /// completes a SYN-cookie handshake. Returns `Some((mss, remote_isn))`
    /// if valid, `mss` being the one to send with.
    pub fn validate_ack(
        &self,
        seg: &Segment,
        local_ip: IpAddr,
        remote_ip: IpAddr,
    ) -> Option<(u16, u32)> {
        if !seg.has_flag(flags::ACK) {
            return None;
        }
        let cookie = seg.ack.wrapping_sub(1);
        let mss_idx = ((cookie >> 5) & 0x07) as u8;
        let remote_isn = seg.seq.wrapping_sub(1);
        let now = now_counter();
        // This period's cookies and the last one's: a cookie lives 64-128 s.
        for counter in [now, now.wrapping_sub(1)] {
            if counter as u32 & 0x1F != cookie & 0x1F {
                continue;
            }
            let expect = self.cookie(
                (local_ip, seg.dst_port),
                (remote_ip, seg.src_port),
                remote_isn,
                counter,
                mss_idx,
            );
            if expect == cookie {
                return Some((MSS_TABLE[mss_idx as usize], remote_isn));
            }
        }
        None
    }

    /// Cookie layout (32 bits):
    ///   31..8 : truncated MAC (24 bits)
    ///   7..5  : MSS table index (3 bits)
    ///   4..0  : low bits of the counter (5 bits)
    ///
    /// The MAC covers the full counter and the MSS index too, so neither
    /// can be altered in the clear bits.
    fn cookie(
        &self,
        local: (IpAddr, u16),
        remote: (IpAddr, u16),
        remote_isn: u32,
        counter: u64,
        mss_idx: u8,
    ) -> u32 {
        let mac = secret::keyed_hash((
            "syncookie",
            self.salt,
            local,
            remote,
            remote_isn,
            counter,
            mss_idx,
        ));
        ((mac as u32) << 8) | (((mss_idx & 0x07) as u32) << 5) | (counter as u32 & 0x1F)
    }
}

fn now_counter() -> u64 {
    secret::elapsed().as_secs() / COOKIE_COUNTER_PERIOD_SECS
}

fn closest_mss_index(mss: u16) -> u8 {
    // Round down, so the connection never sends more than was agreed; only
    // an MSS below the whole table rounds up, to the floor vtcp enforces.
    MSS_TABLE.iter().rposition(|&v| v <= mss).unwrap_or(0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    const SPOOF: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    fn syn(mss: Option<u16>) -> Segment {
        Segment {
            src_port: 12345,
            dst_port: 80,
            seq: 1_000_000,
            flags: flags::SYN,
            window: 65535,
            options: mss.map(mss_option).into_iter().collect(),
            ..Default::default()
        }
    }

    fn final_ack(syn: &Segment, synack: &Segment) -> Segment {
        Segment {
            src_port: syn.src_port,
            dst_port: syn.dst_port,
            seq: syn.seq.wrapping_add(1),
            ack: synack.seq.wrapping_add(1),
            flags: flags::ACK,
            window: 65535,
            ..Default::default()
        }
    }

    /// Complete a cookie handshake and return the MSS the cookie carried.
    fn roundtrip(sc: &SynCookies, syn: &Segment, ours: u16) -> Option<u16> {
        let synack = sc.generate_syn_ack(syn, LOCAL, PEER, ours);
        sc.validate_ack(&final_ack(syn, &synack), LOCAL, PEER)
            .map(|(mss, _)| mss)
    }

    #[test]
    fn cookie_roundtrip() {
        let sc = SynCookies::new();
        let syn = syn(Some(1460));
        let synack = sc.generate_syn_ack(&syn, LOCAL, PEER, 1460);
        assert_eq!(synack.src_port, 80);
        assert_eq!(synack.dst_port, 12345);
        assert_eq!(synack.ack, syn.seq + 1);
        assert_eq!(synack.flags, flags::SYN | flags::ACK);
        let (mss, isn) = sc
            .validate_ack(&final_ack(&syn, &synack), LOCAL, PEER)
            .expect("valid cookie");
        assert_eq!(isn, syn.seq);
        assert_eq!(mss, 1460);
    }

    // RFC 4987 §3.6: a cookie is bound to the addresses it was issued to.
    #[test]
    fn cookie_rejects_other_addresses() {
        let sc = SynCookies::new();
        let syn = syn(Some(1460));
        let ack = final_ack(&syn, &sc.generate_syn_ack(&syn, LOCAL, PEER, 1460));
        assert!(sc.validate_ack(&ack, LOCAL, SPOOF).is_none());
        assert!(sc.validate_ack(&ack, SPOOF, PEER).is_none());
    }

    #[test]
    fn cookie_rejects_other_listener() {
        let syn = syn(Some(1460));
        let ack = final_ack(
            &syn,
            &SynCookies::new().generate_syn_ack(&syn, LOCAL, PEER, 1460),
        );
        assert!(SynCookies::new().validate_ack(&ack, LOCAL, PEER).is_none());
    }

    // The peer's MSS limits what we send, not ours alone.
    #[test]
    fn cookie_carries_the_smaller_mss() {
        let sc = SynCookies::new();
        assert_eq!(roundtrip(&sc, &syn(Some(536)), 1460), Some(536));
        assert_eq!(roundtrip(&sc, &syn(Some(1460)), 1360), Some(1360));
        // No option: RFC 9293's default, not our MSS.
        assert_eq!(roundtrip(&sc, &syn(None), 1460), Some(536));
        // Below 536 rounds down, never up past what the peer takes.
        assert_eq!(roundtrip(&sc, &syn(Some(300)), 1460), Some(88));
    }

    #[test]
    fn cookie_rejects_random_ack() {
        let sc = SynCookies::new();
        let ack = Segment {
            src_port: 12345,
            dst_port: 80,
            seq: 5000,
            ack: 99999,
            flags: flags::ACK,
            ..Default::default()
        };
        assert!(sc.validate_ack(&ack, LOCAL, PEER).is_none());
    }

    #[test]
    fn cookie_rejects_tampered_ack() {
        let sc = SynCookies::new();
        let syn = syn(Some(536));
        let synack = sc.generate_syn_ack(&syn, LOCAL, PEER, 1460);
        for flip in [0x0001_0000, 1 << 5, 1 << 7] {
            let mut ack = final_ack(&syn, &synack);
            ack.ack ^= flip;
            assert!(sc.validate_ack(&ack, LOCAL, PEER).is_none(), "{flip:#x}");
        }
    }
}

//! Explicit Congestion Notification: classic ECN (RFC 3168) and More
//! Accurate ECN feedback (AccECN, RFC 9768).
//!
//! With ECN, a queue that is building marks packets Congestion
//! Experienced (CE) in their IP header instead of dropping them, and the
//! receiver feeds the marks back in the TCP header. The sender cuts its
//! window as for a loss, but nothing has to be sent again and nothing
//! waits on a timer: the signal comes a round trip after the queue began
//! to build, not once it overflowed.
//!
//! Both ends must agree to it in the handshake. Classic ECN's SYN sets ECE
//! and CWR, its SYN-ACK ECE; the receiver then sets ECE on every ACK from
//! the first CE mark until a segment with CWR shows the sender has
//! reduced, so at most one signal gets through per round trip. AccECN's
//! SYN sets AE as well, and its SYN-ACK says which IP-ECN codepoint the
//! SYN arrived with; the receiver then counts CE-marked packets, and every
//! ACK carries the count's three low bits in AE, CWR and ECE (the ACE
//! field), so the sender learns how many packets were marked, not just
//! that one was: what an L4S sender, or BBR's ECN response, needs. The
//! AccECN option, which counts bytes by codepoint, is optional (RFC 9768
//! §3.2.3) and not implemented.
//!
//! Which codepoint each segment goes out with is for the IP layer to set:
//! [`Ecn::mark`] tells it (see `Conn::ecn_marks`), and the codepoint each
//! segment arrived with comes back through `Conn::handle_segment_ecn`.

use super::options::get_sack_blocks;
use super::segment::{Segment, flags};

/// Whether a connection uses ECN (RFC 3168), and asks for it.
///
/// ECN is used only when both ends agree to it in the handshake: whichever
/// asks for it in its SYN, the other has to accept. The default accepts it
/// but does not ask, as Linux does by default (`net.ipv4.tcp_ecn = 2`):
/// a peer that asks knows its path, while asking blindly meets the odd
/// middlebox that drops ECN SYNs, and costs a retransmitted SYN there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum EcnMode {
    /// No ECN: none is asked for, and a peer's request is declined.
    Off,
    /// Accept classic ECN (RFC 3168) from a peer that asks for it, AccECN
    /// included, but do not ask.
    #[default]
    Passive,
    /// Ask for classic ECN, and accept it.
    Classic,
    /// Ask for AccECN (RFC 9768), taking classic ECN from a peer that
    /// only offers that; and accept either, as asked. Linux's
    /// `tcp_ecn = 3`.
    Accurate,
}

/// An IP-ECN codepoint (RFC 3168 §5): the two low bits of the IPv4 TOS
/// or IPv6 Traffic Class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct IpEcn(pub u8);

impl IpEcn {
    pub const NOT_ECT: IpEcn = IpEcn(0);
    pub const ECT1: IpEcn = IpEcn(1);
    pub const ECT0: IpEcn = IpEcn(2);
    pub const CE: IpEcn = IpEcn(3);

    /// The codepoint of the two low bits of `bits`.
    #[inline]
    #[cfg_attr(not(feature = "fuzzing"), allow(dead_code))]
    pub fn from_bits(bits: u8) -> IpEcn {
        IpEcn(bits & 3)
    }
}

/// The feedback the handshake settled on (RFC 9768 Table 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Feedback {
    #[default]
    Off,
    Classic,
    Accurate,
}

/// The ACE field of `seg`: AE, CWR and ECE as a 3-bit number.
#[inline]
pub(crate) fn ace(seg: &Segment) -> u32 {
    (u32::from(seg.ae) << 2)
        | (u32::from(seg.has_flag(flags::CWR)) << 1)
        | u32::from(seg.has_flag(flags::ECE))
}

fn set_ace(seg: &mut Segment, ace: u32) {
    seg.ae = ace & 4 != 0;
    seg.flags &= !(flags::CWR | flags::ECE);
    if ace & 2 != 0 {
        seg.flags |= flags::CWR;
    }
    if ace & 1 != 0 {
        seg.flags |= flags::ECE;
    }
}

/// What AccECN's SYN-ACK flags (Table 2), and the ACE field of the ACK
/// of the SYN-ACK (Table 3), report of a codepoint.
fn handshake_code(ip: IpEcn) -> u32 {
    match ip {
        IpEcn::NOT_ECT => 0b010,
        IpEcn::ECT1 => 0b011,
        IpEcn::ECT0 => 0b100,
        _ => 0b110,
    }
}

/// The codepoint a handshake code reports, if it is one.
fn handshake_codepoint(code: u32) -> Option<IpEcn> {
    match code {
        0b010 => Some(IpEcn::NOT_ECT),
        0b011 => Some(IpEcn::ECT1),
        0b100 => Some(IpEcn::ECT0),
        0b110 => Some(IpEcn::CE),
        _ => None,
    }
}

/// AccECN's counters start at 5 (RFC 9768 §3.2.1), so that an ACE field a
/// middlebox zeroed does not read as a count.
const CEP_INIT: u32 = 5;

/// The codepoint our SYNs and SYN-ACKs go out with. RFC 3168 has them
/// Not-ECT; RFC 8311 lets that be experimented with, but Linux keeps it.
const HANDSHAKE_ECT: IpEcn = IpEcn::NOT_ECT;

/// A connection's ECN state.
#[derive(Debug, Default)]
pub(crate) struct Ecn {
    /// The feedback the handshake settled on.
    pub fb: Feedback,
    /// Our segments may be sent ECN-capable. Not after the handshake
    /// found the path mangling the IP-ECN field (RFC 9768 §3.2.2.3), or
    /// zeroing the ACE field (§3.2.2.1).
    pub ect: bool,
    /// The peer's feedback is acted on: not once the ACE field on the
    /// ACK of our SYN-ACK was zeroed, which shows a middlebox clearing it
    /// (RFC 9768 Table 4, note 1).
    pub respond: bool,
    /// Classic receiver: a CE mark came in, and ECE goes on every ACK
    /// until a segment with CWR shows the sender has reduced.
    demand_cwr: bool,
    /// Classic sender: CWR goes on the next new data segment.
    queue_cwr: bool,
    /// AccECN: CE-marked packets received (r.cep) and sent (s.cep, as the
    /// peer's ACE fields tell it).
    r_cep: u32,
    s_cep: u32,
    /// AccECN receiver: CE marks since our last ACK, and whether the last
    /// packet was marked, for the ACKs RFC 9768 §3.2.2.5.1 asks for.
    ce_unacked: u32,
    last_ce: bool,
    /// Client: the codepoint the SYN-ACK came with, and the ACK number
    /// that acknowledges the SYN-ACK alone. A pure ACK of it reports the
    /// codepoint in its ACE field (Table 3) rather than the count.
    synack: Option<(IpEcn, u32)>,
    /// Server: the codepoint the SYN came with, which the SYN-ACK reports.
    syn_ip: IpEcn,
    /// SYNs sent so far.
    syns: u32,
    /// Something received calls for an ACK at once.
    ack_now: bool,
}

impl Ecn {
    /// The ECN flags our SYN carries: `(flags, ae)`. The request goes on
    /// the first SYN only for classic ECN, as on Linux: a middlebox that
    /// drops ECN SYNs (RFC 3168 §6.1.1.1) then costs one retransmission.
    /// AccECN keeps it for the first retransmission too, as RFC 9768
    /// §3.1.4 suggests.
    pub fn syn_flags(&mut self, mode: EcnMode) -> (u8, bool) {
        let n = self.syns;
        self.syns += 1;
        match mode {
            EcnMode::Classic if n == 0 => (flags::ECE | flags::CWR, false),
            EcnMode::Accurate if n <= 1 => (flags::ECE | flags::CWR, true),
            _ => (0, false),
        }
    }

    /// Take the peer's SYN, which arrived with `ip`: settle the feedback,
    /// as a server set to `mode` (RFC 3168 §6.1.1, RFC 9768 §3.1).
    pub fn on_syn(&mut self, mode: EcnMode, syn: &Segment, ip: IpEcn) {
        let (ece, cwr) = (syn.has_flag(flags::ECE), syn.has_flag(flags::CWR));
        let code = ace(syn);
        self.fb = match mode {
            EcnMode::Off => Feedback::Off,
            // §3.1.3: any combination other than none and classic's is
            // taken as AccECN's, for forward compatibility.
            EcnMode::Accurate if code != 0 && code != 0b011 => Feedback::Accurate,
            _ if ece && cwr => Feedback::Classic,
            _ => Feedback::Off,
        };
        self.syn_ip = ip;
        self.settle();
    }

    /// Server: the peer's SYN again. One no longer asking for ECN is the
    /// client falling back from a path that dropped its first (RFC 9768
    /// §3.1.5): AccECN stays the feedback, but nothing is sent ECT.
    pub fn on_syn_again(&mut self, syn: &Segment) {
        if self.fb == Feedback::Accurate && ace(syn) == 0 {
            self.ect = false;
        }
    }

    /// The ECN flags of our SYN-ACK: `(flags, ae)`.
    pub fn synack_flags(&self) -> (u8, bool) {
        match self.fb {
            Feedback::Off => (0, false),
            Feedback::Classic => (flags::ECE, false),
            Feedback::Accurate => {
                let mut s = Segment::default();
                set_ace(&mut s, handshake_code(self.syn_ip));
                (s.flags, s.ae)
            }
        }
    }

    /// Take the peer's SYN-ACK, which arrived with `ip` and acknowledged
    /// our SYN; `irs1` is the ACK number that acknowledges it. Settle the
    /// feedback, as a client set to `mode`.
    pub fn on_synack(&mut self, mode: EcnMode, seg: &Segment, ip: IpEcn, irs1: u32) {
        let code = ace(seg);
        self.fb = match mode {
            // Table 2: (0,0,0) no ECN, (0,0,1) classic, (1,1,1) a broken
            // server echoing our flags; anything else AccECN.
            EcnMode::Accurate => match code {
                0b000 | 0b111 => Feedback::Off,
                0b001 => Feedback::Classic,
                _ => Feedback::Accurate,
            },
            // RFC 3168 §6.1.1: ECE without CWR (AE is a reserved bit to a
            // classic client).
            EcnMode::Classic if seg.has_flag(flags::ECE) && !seg.has_flag(flags::CWR) => {
                Feedback::Classic
            }
            _ => Feedback::Off,
        };
        self.settle();
        if self.fb == Feedback::Accurate {
            // The SYN-ACK reports what our SYN arrived as: anything but what
            // it left with is a path mangling the field, which later marks
            // could not be trusted through (§3.2.2.3). Its reserved code
            // (1,0,1) says nothing.
            if handshake_codepoint(code).is_some_and(|c| c != HANDSHAKE_ECT) {
                self.ect = false;
            }
            self.synack = Some((ip, irs1));
            // A CE mark on the SYN-ACK counts, as Linux counts it.
            if ip == IpEcn::CE {
                self.r_cep += 1;
            }
        }
    }

    fn settle(&mut self) {
        self.ect = self.fb != Feedback::Off;
        self.respond = self.ect;
        self.r_cep = CEP_INIT;
        self.s_cep = CEP_INIT;
    }

    /// Server, in SYN-RECEIVED: the ACK completing the handshake. A pure
    /// one reports the codepoint our SYN-ACK arrived with in its ACE field
    /// (RFC 9768 §3.2.2.1, Table 4); one with data carries the count.
    pub fn on_handshake_ack(&mut self, seg: &Segment) {
        if self.fb != Feedback::Accurate
            || !seg.payload.is_empty()
            || !get_sack_blocks(&seg.options).is_empty()
        {
            return;
        }
        let code = ace(seg);
        if code == 0 {
            // Zeroed on the way: nothing it says can be trusted.
            self.ect = false;
            self.respond = false;
            return;
        }
        let Some(c) = handshake_codepoint(code) else {
            return;
        };
        if c != HANDSHAKE_ECT {
            self.ect = false;
        }
        // The client counted a CE mark on the SYN-ACK (see `on_synack`).
        if c == IpEcn::CE {
            self.s_cep += 1;
        }
    }

    /// Receiver: `seg`, which arrived with `ip`, passed the sequence check.
    pub fn on_receive(&mut self, seg: &Segment, ip: IpEcn) {
        let data = !seg.payload.is_empty();
        let ce = ip == IpEcn::CE;
        self.ack_now = false;
        match self.fb {
            Feedback::Off => {}
            Feedback::Classic => {
                // The sender has reduced (Linux's tcp_ecn_accept_cwr),
                // before this segment's own mark, if any, asks again.
                if seg.has_flag(flags::CWR) {
                    self.demand_cwr = false;
                    self.ack_now |= data;
                }
                if ce {
                    // An ACK at once: the sender may have a small window,
                    // and every delayed ACK would hold its reduction up.
                    self.ack_now |= !self.demand_cwr;
                    self.demand_cwr = true;
                }
            }
            Feedback::Accurate => {
                if ce {
                    self.r_cep = self.r_cep.wrapping_add(1);
                    self.ce_unacked += 1;
                }
                // §3.2.2.5.1: an ACK when marking starts, and after two CE
                // marks on data (three on ACKs alone) since the last, so
                // the three-bit counter cannot wrap unseen.
                let n = if data { 2 } else { 3 };
                self.ack_now |= (ce && data && !self.last_ce) || self.ce_unacked >= n;
                self.last_ce = ce;
            }
        }
    }

    /// Whether what was received calls for an ACK at once. Taken once.
    #[inline]
    pub fn take_ack_now(&mut self) -> bool {
        std::mem::take(&mut self.ack_now)
    }

    /// Sender: CWR goes on the next new data segment (classic ECN), to
    /// show the peer the window has been reduced.
    #[inline]
    pub fn queue_cwr(&mut self) {
        self.queue_cwr = self.fb == Feedback::Classic;
    }

    /// Put the ECN flags on `seg`, about to go out, and return the
    /// codepoint it goes with. `new_data` if it carries data never sent
    /// before.
    pub fn mark(&mut self, seg: &mut Segment, new_data: bool) -> IpEcn {
        if seg.has_flag(flags::SYN) || seg.has_flag(flags::RST) || !seg.has_flag(flags::ACK) {
            return IpEcn::NOT_ECT;
        }
        let ect = if self.ect {
            IpEcn::ECT0
        } else {
            IpEcn::NOT_ECT
        };
        match self.fb {
            Feedback::Off => IpEcn::NOT_ECT,
            Feedback::Classic => {
                if self.demand_cwr {
                    seg.flags |= flags::ECE;
                }
                if new_data && self.queue_cwr {
                    seg.flags |= flags::CWR;
                    self.queue_cwr = false;
                }
                // RFC 3168 §6.1.4-6: not on pure ACKs (whose marks nobody
                // would answer), retransmissions or window probes. Linux
                // keeps to that for classic ECN, RFC 8311 notwithstanding.
                if new_data { ect } else { IpEcn::NOT_ECT }
            }
            Feedback::Accurate => {
                let handshake = self.synack.filter(|&(_, irs1)| {
                    seg.ack == irs1
                        && seg.payload.is_empty()
                        && !seg.has_flag(flags::FIN)
                        && get_sack_blocks(&seg.options).is_empty()
                });
                let code = match handshake {
                    Some((ip, _)) => handshake_code(ip),
                    None => self.r_cep & 7,
                };
                set_ace(seg, code);
                self.ce_unacked = 0;
                // With feedback that counts every mark, pure ACKs and
                // retransmissions can be ECN-capable too (RFC 8311 §4.3,
                // draft-ietf-tcpm-generalized-ecn), as on Linux.
                ect
            }
        }
    }

    /// Sender: the peer's feedback on an ACK that made progress (advanced
    /// SND.UNA or SACKed new data) when `progress`, delivering
    /// `delivered` bytes in segments of `mss`. Returns the bytes to count
    /// as CE-marked, if the ACK signals congestion.
    pub fn on_ack(
        &mut self,
        seg: &Segment,
        progress: bool,
        delivered: u32,
        mss: u32,
    ) -> Option<u32> {
        match self.fb {
            Feedback::Off => None,
            // Every ACK from the first mark until our CWR gets through
            // says so; the connection answers once per round trip. What it
            // delivered counts as marked, as Linux counts it for BBR.
            Feedback::Classic => {
                (self.respond && seg.has_flag(flags::ECE)).then_some(delivered.max(1))
            }
            Feedback::Accurate => {
                // Only an ACK that made progress: an older one, reordered,
                // carries an older count (Linux's tcp_accecn_process).
                if !progress {
                    return None;
                }
                let mut delta = ace(seg).wrapping_sub(self.s_cep) & 7;
                // RFC 9768 §3.2.2.5.2: the counter may have wrapped over an
                // ACK of more than seven packets. Assume it did as often as
                // it could have, as Linux does without the AccECN option:
                // a congestion signal missed is worse than one overstated.
                let pkts = delivered.div_ceil(mss.max(1));
                if pkts > 7 {
                    delta = pkts - ((pkts - delta) & 7);
                }
                self.s_cep = self.s_cep.wrapping_add(delta);
                (self.respond && delta > 0).then(|| delta.saturating_mul(mss).min(delivered).max(1))
            }
        }
    }

    /// Whether ECN feedback is in use and acted on.
    #[inline]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn active(&self) -> bool {
        self.fb != Feedback::Off && self.respond
    }

    /// r.cep: CE-marked packets received, for tests.
    #[cfg(test)]
    pub fn received_ce(&self) -> u32 {
        self.r_cep.wrapping_sub(CEP_INIT)
    }

    /// s.cep: CE marks the peer reported, for tests.
    #[cfg(test)]
    pub fn sent_ce(&self) -> u32 {
        self.s_cep.wrapping_sub(CEP_INIT)
    }

    /// Whether ECE goes on our ACKs (classic).
    #[cfg(test)]
    pub fn echoing(&self) -> bool {
        self.demand_cwr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn(code: u32) -> Segment {
        let mut s = Segment {
            flags: flags::SYN,
            ..Default::default()
        };
        set_ace(&mut s, code);
        s
    }

    fn synack(code: u32) -> Segment {
        let mut s = syn(code);
        s.flags |= flags::ACK;
        s
    }

    /// RFC 9768 Table 2, from the server's side: what each mode answers
    /// each request with.
    #[test]
    fn server_negotiation() {
        use EcnMode::*;
        let cases = [
            (Off, 0b111, Feedback::Off),
            (Passive, 0b000, Feedback::Off),
            (Passive, 0b011, Feedback::Classic),
            // An RFC 3168 server sees ECE and CWR, and answers classic.
            (Passive, 0b111, Feedback::Classic),
            (Classic, 0b111, Feedback::Classic),
            (Classic, 0b001, Feedback::Off),
            (Accurate, 0b111, Feedback::Accurate),
            (Accurate, 0b011, Feedback::Classic),
            (Accurate, 0b000, Feedback::Off),
            // §3.1.3: other combinations are AccECN's.
            (Accurate, 0b101, Feedback::Accurate),
            (Accurate, 0b001, Feedback::Accurate),
        ];
        for (mode, code, want) in cases {
            let mut e = Ecn::default();
            e.on_syn(mode, &syn(code), IpEcn::NOT_ECT);
            assert_eq!(e.fb, want, "{mode:?} {code:03b}");
        }
    }

    /// A client's retransmitted SYN dropping the request leaves an AccECN
    /// server sending Not-ECT; one still asking changes nothing.
    #[test]
    fn a_fallback_syn_stops_ect() {
        let mut e = Ecn::default();
        e.on_syn(EcnMode::Accurate, &syn(0b111), IpEcn::NOT_ECT);
        e.on_syn_again(&syn(0b111));
        assert!(e.ect);
        e.on_syn_again(&syn(0));
        assert_eq!((e.fb, e.ect), (Feedback::Accurate, false));
    }

    /// The AccECN SYN-ACK reports the SYN's codepoint.
    #[test]
    fn synack_reports_the_syn_codepoint() {
        for (ip, code) in [
            (IpEcn::NOT_ECT, 0b010),
            (IpEcn::ECT1, 0b011),
            (IpEcn::ECT0, 0b100),
            (IpEcn::CE, 0b110),
        ] {
            let mut e = Ecn::default();
            e.on_syn(EcnMode::Accurate, &syn(0b111), ip);
            let (f, ae) = e.synack_flags();
            let s = Segment {
                flags: f,
                ae,
                ..Default::default()
            };
            assert_eq!(ace(&s), code);
        }
        let mut e = Ecn::default();
        e.on_syn(EcnMode::Passive, &syn(0b011), IpEcn::NOT_ECT);
        assert_eq!(e.synack_flags(), (flags::ECE, false));
    }

    /// RFC 9768 Table 2, from the client's side.
    #[test]
    fn client_negotiation() {
        use EcnMode::*;
        let cases = [
            (Accurate, 0b010, Feedback::Accurate, true),
            // The path turned our Not-ECT SYN into ECT(0): mangled.
            (Accurate, 0b100, Feedback::Accurate, false),
            (Accurate, 0b101, Feedback::Accurate, true),
            (Accurate, 0b001, Feedback::Classic, true),
            (Accurate, 0b000, Feedback::Off, false),
            (Accurate, 0b111, Feedback::Off, false),
            (Classic, 0b001, Feedback::Classic, true),
            (Classic, 0b011, Feedback::Off, false),
            (Classic, 0b101, Feedback::Classic, true),
            (Passive, 0b001, Feedback::Off, false),
        ];
        for (mode, code, want, ect) in cases {
            let mut e = Ecn::default();
            e.on_synack(mode, &synack(code), IpEcn::NOT_ECT, 1);
            assert_eq!((e.fb, e.ect), (want, ect), "{mode:?} {code:03b}");
        }
    }

    /// The request goes on the first SYN, and for AccECN the first
    /// retransmission too, but no further.
    #[test]
    fn syn_retransmissions_drop_the_request() {
        let mut e = Ecn::default();
        assert_eq!(
            e.syn_flags(EcnMode::Classic),
            (flags::ECE | flags::CWR, false)
        );
        assert_eq!(e.syn_flags(EcnMode::Classic), (0, false));
        let mut e = Ecn::default();
        for _ in 0..2 {
            assert_eq!(
                e.syn_flags(EcnMode::Accurate),
                (flags::ECE | flags::CWR, true)
            );
        }
        assert_eq!(e.syn_flags(EcnMode::Accurate), (0, false));
        assert_eq!(Ecn::default().syn_flags(EcnMode::Passive), (0, false));
    }

    fn accurate_pair() -> (Ecn, Ecn) {
        let mut server = Ecn::default();
        server.on_syn(EcnMode::Accurate, &syn(0b111), IpEcn::NOT_ECT);
        let mut client = Ecn::default();
        client.on_synack(EcnMode::Accurate, &synack(0b010), IpEcn::NOT_ECT, 1);
        (client, server)
    }

    fn ack(n: u32) -> Segment {
        Segment {
            flags: flags::ACK,
            ack: n,
            ..Default::default()
        }
    }

    /// The pure ACK of the SYN-ACK reports its codepoint (Table 3); the
    /// server reads it as such (Table 4), and zeroes as a middlebox's.
    #[test]
    fn handshake_ack_encoding() {
        let (mut client, mut server) = accurate_pair();
        let mut a = ack(1);
        assert_eq!(client.mark(&mut a, false), IpEcn::ECT0);
        assert_eq!(ace(&a), 0b010);
        server.on_handshake_ack(&a);
        assert!(server.ect && server.respond);
        // Later ACKs carry the count, 5.
        let mut b = ack(100);
        client.mark(&mut b, false);
        assert_eq!(ace(&b), CEP_INIT);

        let (_, mut server) = accurate_pair();
        server.on_handshake_ack(&ack(1));
        assert!(!server.ect && !server.respond, "zeroed ACE not caught");

        // A CE-marked SYN-ACK: counted by the client, and reported.
        let mut client = Ecn::default();
        client.on_synack(EcnMode::Accurate, &synack(0b010), IpEcn::CE, 1);
        let mut a = ack(1);
        client.mark(&mut a, false);
        assert_eq!(ace(&a), 0b110);
        let (_, mut server) = accurate_pair();
        server.on_handshake_ack(&a);
        let mut b = ack(100);
        client.mark(&mut b, false);
        // The count went up by one, which the server expects.
        assert_eq!(server.on_ack(&b, true, 1000, 1000), None);
    }

    /// Classic: ECE from the first CE mark until CWR; CWR on the next new
    /// data only; ECT on new data only.
    #[test]
    fn classic_echo_until_cwr() {
        let mut rx = Ecn::default();
        rx.on_syn(EcnMode::Passive, &syn(0b011), IpEcn::NOT_ECT);
        let data = Segment {
            flags: flags::ACK,
            payload: vec![0; 100],
            ..Default::default()
        };
        rx.on_receive(&data, IpEcn::CE);
        assert!(rx.take_ack_now());
        for _ in 0..3 {
            let mut a = ack(0);
            assert_eq!(rx.mark(&mut a, false), IpEcn::NOT_ECT);
            assert!(a.has_flag(flags::ECE));
            rx.on_receive(&data, IpEcn::ECT0);
        }
        let mut cwr = data.clone();
        cwr.flags |= flags::CWR;
        rx.on_receive(&cwr, IpEcn::ECT0);
        let mut a = ack(0);
        rx.mark(&mut a, false);
        assert!(!a.has_flag(flags::ECE));

        let mut tx = Ecn::default();
        tx.on_synack(EcnMode::Classic, &synack(0b001), IpEcn::NOT_ECT, 1);
        tx.queue_cwr();
        let mut old = data.clone();
        assert_eq!(tx.mark(&mut old, false), IpEcn::NOT_ECT);
        assert!(!old.has_flag(flags::CWR));
        let mut new = data.clone();
        assert_eq!(tx.mark(&mut new, true), IpEcn::ECT0);
        assert!(new.has_flag(flags::CWR));
        let mut next = data.clone();
        tx.mark(&mut next, true);
        assert!(!next.has_flag(flags::CWR));
    }

    /// The ACE counter: increments come through, across its wrap.
    #[test]
    fn ace_counter_wraps() {
        let (mut client, mut server) = accurate_pair();
        let data = Segment {
            flags: flags::ACK,
            payload: vec![0; 1000],
            ..Default::default()
        };
        let mut total = 0;
        for round in 0..20u32 {
            let marks = round % 4 + (round % 3);
            for _ in 0..marks {
                client.on_receive(&data, IpEcn::CE);
            }
            client.on_receive(&data, IpEcn::ECT0);
            let mut a = ack(2 + round);
            client.mark(&mut a, false);
            // Few enough packets per ACK that the count cannot be
            // ambiguous: reported exactly.
            let got = server.on_ack(&a, true, (marks + 1) * 1000, 1000);
            assert_eq!(got.map_or(0, |b| b / 1000), marks, "round {round}");
            total += marks;
        }
        assert_eq!(client.received_ce(), total);
        assert_eq!(server.sent_ce(), total);
        assert!(total > 8, "never wrapped");
    }

    /// Over an ACK of more than seven packets the counter may have wrapped
    /// unseen; it is taken to have, as often as it could.
    #[test]
    fn ace_assumes_the_worst_over_a_stretch_ack() {
        let (_, mut server) = accurate_pair();
        let mut a = ack(2);
        set_ace(&mut a, (CEP_INIT + 1) & 7);
        // 10 packets: 1 or 9 marked; 9 it is.
        assert_eq!(server.on_ack(&a, true, 10_000, 1000), Some(9000));
        // Not on an ACK without progress: it may be an old one.
        let mut b = ack(2);
        set_ace(&mut b, (CEP_INIT + 12) & 7);
        assert_eq!(server.on_ack(&b, false, 0, 1000), None);
    }

    /// AccECN asks for an ACK when marking starts, and after two marks.
    #[test]
    fn accurate_change_and_increment_triggered_acks() {
        let (mut client, _) = accurate_pair();
        let data = Segment {
            flags: flags::ACK,
            payload: vec![0; 100],
            ..Default::default()
        };
        client.on_receive(&data, IpEcn::ECT0);
        assert!(!client.take_ack_now());
        client.on_receive(&data, IpEcn::CE);
        assert!(client.take_ack_now(), "change not ACKed");
        client.mark(&mut ack(3), false);
        client.on_receive(&data, IpEcn::CE);
        assert!(!client.take_ack_now());
        client.on_receive(&data, IpEcn::CE);
        assert!(client.take_ack_now(), "increment not ACKed");
    }
}

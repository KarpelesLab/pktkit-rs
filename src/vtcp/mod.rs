//! Virtual TCP engine.
//!
//! A synchronous TCP state machine operating on raw TCP segments, in pure
//! Rust (it began as a port of the Go `vtcp` subpackage). It is IP-agnostic
//! and Ethernet-agnostic — callers feed inbound segments via
//! [`Conn::handle_segment`] and transmit whatever the connection returns.
//! [`Conn::tick`] drives the RTO, RACK's reordering timer, the tail loss
//! probe, pacing, persist, keepalive, FIN-WAIT-2 and TIME-WAIT timers;
//! there is no background thread. Call it
//! when [`Conn::next_deadline`] comes due: a timer fires only as precisely
//! as it is driven.
//!
//! Supported RFCs:
//! - RFC 9293 (TCP, rolled-up): state machine and segment processing.
//! - RFC 6298: RTO smoothing + Karn's algorithm, with Linux's constants
//!   (200 ms floor under the variance term, 1 s initial RTO).
//! - RFC 5681: congestion control (slow start, congestion avoidance, fast
//!   retransmit/recovery) and RFC 6928's initial window; cwnd grows by
//!   bytes acknowledged (RFC 3465, L = 2). Against a peer without SACK,
//!   losses are found by three duplicate ACKs, with RFC 3042 Limited
//!   Transmit and RFC 6582's NewReno partial-ACK handling.
//! - RFC 1122 §4.2.3.2, RFC 5681 §4.2: delayed ACKs (40 ms, at least every
//!   second full-sized segment, at once for anything out of order), with
//!   Linux's quick-ACK and ping-pong modes.
//! - RFC 9438: CUBIC, the default controller (as on Linux): after a loss
//!   the window regrows along a cubic curve of the time since, cut by
//!   β = 0.7, with fast convergence, the Reno-friendly region, and its
//!   state put back when the loss turns out spurious. Its first slow start
//!   runs RFC 9406 HyStart++, which leaves slow start when the round trip
//!   rises rather than when the bottleneck's queue overflows. NewReno and
//!   RFC 3649 HighSpeed TCP are the others, and BBR below.
//! - draft-ietf-ccwg-bbr ("BBRv3"), opt in: a model of the path's
//!   bottleneck bandwidth and round trip, from delivery rate samples
//!   (draft-cheng-iccrg-delivery-rate-estimation), sets the pacing rate
//!   and cwnd, rather than a queue overflowing. It keeps queues short, and
//!   its rate through random loss under 2%.
//! - Pacing, as Linux's: each round trip's data goes out spread over it, a
//!   millisecond's worth at a time, not in bursts as ACKs let it go.
//! - RFC 7661: congestion window validation. No cwnd growth while the
//!   sender is application-limited; a window left unused (pipeACK under
//!   half of it) is kept for five minutes, a loss meanwhile answered from
//!   what was in use. After an idle spell of more than an RTO the window
//!   decays towards the initial window first (RFC 5681 §4.1), as Linux's
//!   does by default.
//! - RFC 7323: window scaling, timestamps (PAWS, and an RTT sample from
//!   every ACK, weighed as its Appendix G suggests).
//! - RFC 2018: SACK, with RFC 6675's scoreboard and pipe. Out-of-order
//!   data is kept however many holes it leaves; only ranges costing more
//!   memory than the receive buffer allows are given up.
//! - RFC 8985: RACK-TLP. With SACK, losses are found by time rather than
//!   by counting duplicates: a segment is lost once one sent after it has
//!   been delivered and a reordering window (a quarter of the minimum RTT)
//!   has passed, which repairs losses in small flights and lost
//!   retransmissions alike, and rides out reordering. A tail loss probe
//!   two round trips after the last ACK draws the feedback that shows a
//!   loss at the end of a flight, which otherwise only the RTO would.
//! - RFC 6937: Proportional Rate Reduction (PRR-SSRB). During fast
//!   recovery the window comes down to ssthresh in step with what the
//!   ACKs report delivered, a segment for about every other ACK, rather
//!   than inflating with every duplicate ACK or going quiet and bursting.
//! - RFC 2883: D-SACK, reporting data received twice.
//! - RFC 3168: ECN. Where both ends agree to it (see [`EcnMode`]; by
//!   default a peer's request is accepted, none made), a queue marking
//!   packets Congestion Experienced has the window cut, once per round
//!   trip, with nothing to resend: by RFC 8511's gentler β in congestion
//!   avoidance (0.85 for CUBIC), as marks come while the queue is still
//!   short. RFC 9768's AccECN has the receiver count the marks rather than
//!   flag them, which BBR's response goes by.
//! - Undoing a needless loss response: D-SACKs for everything an episode
//!   retransmitted (RFC 3708), the Eifel detection's timestamp echo (RFC
//!   3522) and F-RTO after a timeout (RFC 5682) tell a spurious
//!   retransmission, and RFC 4015's response puts cwnd and ssthresh back.
//!   D-SACKs also widen RACK's reordering window.
//! - RFC 1191, RFC 8201: path MTU discovery, from ICMP Fragmentation
//!   Needed and Packet Too Big messages ([`Conn::on_icmp_too_big`]), each
//!   checked against what is in flight (RFC 5927 §4.1).
//! - RFC 4821: Packetization Layer PMTUD, where ICMP does not get through
//!   (see [`MtuProbing`]). Once the first segment keeps timing out, a black
//!   hole is suspected and the MSS drops to a base of 1024 bytes; probes,
//!   ordinary data segments larger than the MSS, then search up for what
//!   the path carries, as Linux's `tcp_mtu_probing` does. A probe lost to
//!   its size costs no window.
//! - RFC 7413: TCP Fast Open, opt in ([`ConnConfig::fast_open`]): a server
//!   gives cookies, and takes the data of a SYN that brings one back before
//!   the handshake completes. `vclient` is the client side.
//! - RFC 5961: challenge ACKs against blind RST, SYN and data injection,
//!   rate-limited.
//! - RFC 6191: a new SYN may reuse a 4-tuple in TIME-WAIT when its
//!   timestamps show it is newer.
//! - RFC 6528: initial sequence numbers from a keyed hash and a clock.
//! - RFC 4987: SYN cookies for stateless half-open completion (used by
//!   `vclient`'s listener).
//! - RFC 2525 §2.17: releasing a connection with unread data resets it.
//!
//! # Layering: blocking I/O and accept live above this engine
//!
//! `Conn` is intentionally a pure, non-blocking, socket-less state machine —
//! it owns no I/O, so "blocking read/write" and "an accept queue" do not
//! belong here; they belong to whatever drives the engine over a real
//! transport. The crate provides exactly those drivers:
//!
//! - Blocking, `std::io::Read`/`Write` connection handles: `vclient::TcpConn`
//!   (client side) and `slirp::TcpStream` (server side) wrap a `Conn` with a
//!   `Condvar` and a tick thread (enable the `vclient` / `slirp` features).
//! - Accept queues: `slirp::Listener` and `vclient::Listener` build them on
//!   top of [`Conn::accept_syn`].
//!
//! Synchronous mutual recursion is avoided by the return-segments API: methods
//! hand back outgoing bytes (`take_outgoing`) rather than calling a sink, so the
//! caller drains them explicitly and the borrow checker keeps re-entrancy out.

// The drivers' tick threads.
#[cfg(all(
    any(feature = "vclient", feature = "slirp"),
    not(target_family = "wasm")
))]
pub(crate) mod alarm;
pub(crate) mod autotune;
pub(crate) mod bbr;
pub(crate) mod congestion;
pub(crate) mod conn;
pub(crate) mod cubic;
pub(crate) mod cwv;
pub(crate) mod ecn;
pub(crate) mod fastopen;
pub(crate) mod options;
pub(crate) mod plpmtud;
pub(crate) mod rate;
pub(crate) mod recvbuf;
pub(crate) mod rto;
pub(crate) mod scoreboard;
pub(crate) mod secret;
pub(crate) mod segment;
pub(crate) mod sendbuf;
pub(crate) mod seqspace;
pub(crate) mod tuning;
// The listeners that answer SYNs statelessly past their backlog.
#[cfg(any(feature = "vclient", feature = "slirp", test))]
pub(crate) mod syncookie;

pub use conn::{CongestionKind, Conn, ConnConfig, State};
pub use ecn::EcnMode;
pub use options::{TcpOption, kind};
pub use plpmtud::MtuProbing;
pub use segment::{Segment, flags};
pub use tuning::Tuning;

// nat's UPnP tests read the window scale off a SYN-ACK.
#[cfg(all(test, feature = "nat"))]
pub(crate) use options::get_wscale;

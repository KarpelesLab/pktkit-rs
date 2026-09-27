//! Virtual TCP engine.
//!
//! A synchronous TCP state machine operating on raw TCP segments, in pure
//! Rust (it began as a port of the Go `vtcp` subpackage). It is IP-agnostic
//! and Ethernet-agnostic — callers feed inbound segments via
//! [`Conn::handle_segment`] and transmit whatever the connection returns. A
//! periodic [`Conn::tick`] drives the RTO, Early Retransmit, persist,
//! keepalive, FIN-WAIT-2 and TIME-WAIT timers; there is no background
//! thread.
//!
//! Supported RFCs:
//! - RFC 9293 (TCP, rolled-up): state machine and segment processing.
//! - RFC 6298: RTO smoothing + Karn's algorithm.
//! - RFC 5681: congestion control (slow start, congestion avoidance, fast
//!   retransmit/recovery), with RFC 6582's NewReno partial-ACK handling,
//!   RFC 3042 Limited Transmit and RFC 6928's initial window.
//! - RFC 3649: HighSpeed TCP (default controller); NewReno is the other.
//! - RFC 7661 §4.3: no cwnd growth while the sender is application-limited.
//! - RFC 7323: window scaling, timestamps (PAWS).
//! - RFC 2018: SACK, and RFC 6675 SACK-based loss recovery.
//! - RFC 5827: Early Retransmit, for a flight too small to draw three
//!   duplicate ACKs.
//! - RFC 5961: challenge ACKs against blind RST, SYN and data injection,
//!   rate-limited.
//! - RFC 6191: a new SYN may reuse a 4-tuple in TIME-WAIT when its
//!   timestamps show it is newer.
//! - RFC 6528: initial sequence numbers from a keyed hash and a clock.
//! - RFC 4987: SYN cookies ([`SynCookies`]) for stateless half-open
//!   completion.
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
//! - Accept queues: `slirp::Listener` builds one on top of
//!   [`Conn::accept_syn`], and [`syncookie::SynCookies`] is available for the
//!   stateless-completion variant.
//!
//! Synchronous mutual recursion is avoided by the return-segments API: methods
//! hand back outgoing bytes (`take_outgoing`) rather than calling a sink, so the
//! caller drains them explicitly and the borrow checker keeps re-entrancy out.

pub mod congestion;
pub mod conn;
pub mod options;
pub mod recvbuf;
pub mod rto;
pub(crate) mod secret;
pub mod segment;
pub mod sendbuf;
pub mod seqspace;
pub mod syncookie;

pub use congestion::{CongestionController, HighSpeed, NewReno};
pub use conn::{CongestionKind, Conn, ConnConfig, State};
pub use options::{
    SackBlock, TcpOption, build_options, get_mss, get_sack_blocks, get_timestamp, get_wscale,
    has_sack_perm, kind, mss_option, parse_options, sack_option, sack_perm_option,
    timestamp_option, wscale_option,
};
pub use recvbuf::RecvBuf;
pub use rto::{DEFAULT_RTO, MAX_RTO, MIN_RTO, RtoState};
pub use segment::{Segment, flags};
pub use sendbuf::SendBuf;
pub use seqspace::{
    seq_after, seq_after_eq, seq_before, seq_before_eq, seq_in_range, seq_in_range_inclusive,
};
pub use syncookie::SynCookies;

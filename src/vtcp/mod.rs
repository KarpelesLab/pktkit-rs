//! Virtual TCP engine.
//!
//! Pure-Rust port of the Go `vtcp` subpackage: a synchronous TCP state machine
//! operating on raw TCP segments. It is IP-agnostic and Ethernet-agnostic —
//! callers feed inbound segments via [`Conn::handle_segment`] and transmit
//! whatever the connection returns. A periodic [`Conn::tick`] drives RTO,
//! persist, keepalive, and TIME-WAIT timers; there is no background thread.
//!
//! Supported RFCs:
//! - RFC 9293 (TCP, rolled-up): state machine, basic segment processing.
//! - RFC 6298: RTO smoothing + Karn's algorithm.
//! - RFC 5681: NewReno congestion control (slow start, congestion avoidance,
//!   fast retransmit/recovery).
//! - RFC 3649: HighSpeed TCP (default controller).
//! - RFC 7323: window scaling, timestamps (PAWS).
//! - RFC 2018: SACK.
//! - SYN-cookie engine for stateless half-open completion.
//!
//! What was intentionally not ported in this initial cut:
//! - `// TODO(vtcp)`: blocking [`Conn::read`]/[`Conn::write`] with deadlines —
//!   the port is non-blocking; callers compose their own waiting strategy.
//! - `// TODO(vtcp)`: Listener / accept-queue type (the Go upstream exposes
//!   one; here we expose [`Conn::accept_syn`] and [`syncookie::SynCookies`]
//!   so callers can build the listener that suits their loop).
//! - `// TODO(vtcp)`: re-entrancy "trampoline" for synchronous mutual recursion
//!   — Rust's borrow checker forces callers to drain `take_outgoing()`
//!   themselves, sidestepping the issue.

pub mod conn;
pub mod congestion;
pub mod options;
pub mod recvbuf;
pub mod rto;
pub mod segment;
pub mod sendbuf;
pub mod seqspace;
pub mod syncookie;

pub use conn::{Conn, ConnConfig, CongestionKind, State};
pub use congestion::{CongestionController, HighSpeed, NewReno};
pub use options::{
    build_options, get_mss, get_sack_blocks, get_timestamp, get_wscale, has_sack_perm, kind,
    mss_option, parse_options, sack_option, sack_perm_option, timestamp_option, wscale_option,
    SackBlock, TcpOption,
};
pub use recvbuf::RecvBuf;
pub use rto::{RtoState, DEFAULT_RTO, MAX_RTO, MIN_RTO};
pub use segment::{flags, Segment};
pub use sendbuf::SendBuf;
pub use seqspace::{
    seq_after, seq_after_eq, seq_before, seq_before_eq, seq_in_range, seq_in_range_inclusive,
};
pub use syncookie::SynCookies;

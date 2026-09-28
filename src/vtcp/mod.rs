//! Virtual TCP engine.
//!
//! A synchronous TCP state machine operating on raw TCP segments, in pure
//! Rust (it began as a port of the Go `vtcp` subpackage). It is IP-agnostic
//! and Ethernet-agnostic — callers feed inbound segments via
//! [`Conn::handle_segment`] and transmit whatever the connection returns.
//! [`Conn::tick`] drives the RTO, Early Retransmit, persist, keepalive,
//! FIN-WAIT-2 and TIME-WAIT timers; there is no background thread. Call it
//! when [`Conn::next_deadline`] comes due: a timer fires only as precisely
//! as it is driven.
//!
//! Supported RFCs:
//! - RFC 9293 (TCP, rolled-up): state machine and segment processing.
//! - RFC 6298: RTO smoothing + Karn's algorithm, with Linux's constants
//!   (200 ms floor under the variance term, 1 s initial RTO).
//! - RFC 5681: congestion control (slow start, congestion avoidance, fast
//!   retransmit/recovery), with RFC 6582's NewReno partial-ACK handling,
//!   RFC 3042 Limited Transmit and RFC 6928's initial window.
//! - RFC 3649: HighSpeed TCP (default controller); NewReno is the other.
//! - RFC 7661 §4.3: no cwnd growth while the sender is application-limited.
//! - RFC 7323: window scaling, timestamps (PAWS, and an RTT sample from
//!   every ACK, weighed as its Appendix G suggests).
//! - RFC 2018: SACK, and RFC 6675 SACK-based loss recovery.
//! - RFC 5827: Early Retransmit, for a flight too small to draw three
//!   duplicate ACKs.
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
pub(crate) mod congestion;
pub(crate) mod conn;
pub(crate) mod options;
pub(crate) mod recvbuf;
pub(crate) mod rto;
pub(crate) mod secret;
pub(crate) mod segment;
pub(crate) mod sendbuf;
pub(crate) mod seqspace;
// The listeners that answer SYNs statelessly past their backlog.
#[cfg(any(feature = "vclient", feature = "slirp", test))]
pub(crate) mod syncookie;

pub use conn::{CongestionKind, Conn, ConnConfig, State};
pub use options::{TcpOption, kind};
pub use segment::{Segment, flags};

// nat's UPnP tests read the window scale off a SYN-ACK.
#[cfg(all(test, feature = "nat"))]
pub(crate) use options::get_wscale;

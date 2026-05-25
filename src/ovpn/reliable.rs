//! Reliable control-channel transport.
//!
//! OpenVPN runs its TLS control channel over an in-protocol reliable layer
//! (because the underlying transport may be lossy UDP). This module implements
//! that layer: it assigns outgoing packet IDs, buffers unacknowledged outgoing
//! packets for retransmit, reorders incoming packets into the TLS byte stream,
//! and tracks the ACKs that must be echoed back to the peer.
//!
//! Ported from the reliability bits of the Go `peer.go` (`ctrlIn`, `ctrlOut`,
//! `ctrlAck`, the in/out counters) and `peerconn.go` (chunking the TLS stream
//! into `P_CONTROL_V1` packets). This is the substrate the rustls
//! `ServerConnection` reads from and writes to — there is no TCP socket below
//! the TLS, only this layer.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use super::consts::{CONTROL_CHANNEL_MTU, TLS_RELIABLE_N_REC_BUFFERS};
use super::packet_ctrl::ControlPacket;
use super::Opcode;

/// Initial retransmit timeout for an unacked control packet. OpenVPN's
/// reliable layer starts at ~1s and backs off exponentially.
pub const RETRANSMIT_INITIAL: Duration = Duration::from_secs(1);
/// Cap on the backed-off retransmit interval (OpenVPN clamps around here).
pub const RETRANSMIT_MAX_INTERVAL: Duration = Duration::from_secs(8);
/// Maximum number of retransmit attempts before the packet is abandoned and
/// the caller is told to tear the connection down.
pub const RETRANSMIT_MAX_ATTEMPTS: u32 = 8;

/// Outcome of feeding one control packet into the reliable layer.
#[derive(Debug, Default)]
pub struct RecvOutcome {
    /// In-order TLS-stream bytes newly available (concatenated payloads of
    /// `P_CONTROL_V1` packets delivered in order).
    pub tls_bytes: Vec<u8>,
    /// True if a `P_CONTROL_HARD_RESET_CLIENT_V2` was received and the server
    /// should respond with its own hard reset.
    pub got_client_reset: bool,
}

/// An outgoing control packet awaiting acknowledgement, with the retransmit
/// bookkeeping the [`Reliable::tick`] timer loop drives.
#[derive(Debug, Clone)]
struct Unacked {
    pkt: ControlPacket,
    /// When the packet was most recently (re)transmitted.
    last_sent: Instant,
    /// Number of times the packet has been transmitted (1 = original send).
    attempts: u32,
}

/// Outcome of a retransmission tick: datagrams to resend and whether the
/// connection has exhausted its retries and should be closed.
#[derive(Debug, Default)]
pub struct TickOutcome {
    /// Re-serialized control datagrams to put back on the wire.
    pub resend: Vec<Vec<u8>>,
    /// True if some packet blew past [`RETRANSMIT_MAX_ATTEMPTS`]; the caller
    /// should tear the connection down.
    pub timed_out: bool,
}

/// Reliable transport state for one peer.
#[derive(Debug)]
pub struct Reliable {
    pub local_id: [u8; 8],
    pub peer_id: [u8; 8],

    // Outgoing.
    out_counter: u32,
    unacked: HashMap<u32, Unacked>,

    // Incoming reorder buffer.
    in_counter: u32, // id of the next in-order packet we expect
    in_buf: HashMap<u32, ControlPacket>,

    // ACKs we owe the peer for packets we've received.
    pending_ack: Vec<u32>,
}

/// Retransmit interval for a packet that has been sent `attempts` times,
/// doubling each time from [`RETRANSMIT_INITIAL`] and clamped at
/// [`RETRANSMIT_MAX_INTERVAL`]. `attempts` is 1 after the first send.
fn backoff(attempts: u32) -> Duration {
    // attempts==1 -> base, ==2 -> 2x, ==3 -> 4x, ... saturating at the cap.
    let shift = attempts.saturating_sub(1).min(16);
    let scaled = RETRANSMIT_INITIAL
        .checked_mul(1u32 << shift)
        .unwrap_or(RETRANSMIT_MAX_INTERVAL);
    scaled.min(RETRANSMIT_MAX_INTERVAL)
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

impl Reliable {
    pub fn new(local_id: [u8; 8]) -> Reliable {
        Reliable {
            local_id,
            peer_id: [0u8; 8],
            out_counter: 0,
            unacked: HashMap::new(),
            in_counter: 0,
            in_buf: HashMap::new(),
            pending_ack: Vec::new(),
        }
    }

    /// Process an inbound control packet (full datagram including opcode byte).
    pub fn recv(&mut self, data: &[u8]) -> io::Result<RecvOutcome> {
        let pkt = ControlPacket::parse(data)?;

        // Apply ACKs the peer reported.
        for pid in &pkt.acked_pids {
            self.unacked.remove(pid);
        }

        let mut outcome = RecvOutcome::default();

        // ACK packets carry no pid and need no further processing.
        if pkt.opcode == Opcode::ACK_V1 {
            return Ok(outcome);
        }

        let pid = pkt
            .pid
            .ok_or_else(|| invalid("control packet missing packet id"))?;

        // We owe an ACK for this received packet.
        self.pending_ack.push(pid);

        // A hard reset (client- or server-side) establishes the peer session
        // id and occupies a slot in the ordered control stream. The server acts
        // on a *client* reset; either side advances its in-order counter past
        // the reset so the first real CONTROL_V1 (pid 1) is delivered.
        if pkt.opcode == Opcode::CONTROL_HARD_RESET_CLIENT_V2
            || pkt.opcode == Opcode::CONTROL_HARD_RESET_SERVER_V2
        {
            self.peer_id = pkt.session_id;
            if pkt.opcode == Opcode::CONTROL_HARD_RESET_CLIENT_V2 {
                outcome.got_client_reset = true;
            }
            if pid == self.in_counter {
                self.in_counter += 1;
            }
            return Ok(outcome);
        }

        if pkt.opcode != Opcode::CONTROL_V1 {
            // Soft resets are not driven by the happy path; ack but ignore.
            return Ok(outcome);
        }

        // Reorder buffer (mirrors handleControlPacket in peer.go).
        if pid < self.in_counter {
            return Ok(outcome); // already processed
        }
        if pid > self.in_counter + TLS_RELIABLE_N_REC_BUFFERS as u32 {
            return Err(invalid("rejecting packet because pid looks invalid"));
        }
        self.in_buf.entry(pid).or_insert(pkt);

        loop {
            match self.in_buf.remove(&self.in_counter) {
                Some(p) => {
                    self.in_counter += 1;
                    outcome.tls_bytes.extend_from_slice(&p.payload);
                }
                None => {
                    if self.in_buf.len() > TLS_RELIABLE_N_REC_BUFFERS {
                        return Err(invalid("received too many packets, dropping connection"));
                    }
                    break;
                }
            }
        }

        Ok(outcome)
    }

    /// Take the list of ACKs we currently owe, clearing the pending set. The
    /// caller attaches these to the next outgoing packet (or a dedicated ACK).
    pub fn take_pending_acks(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.pending_ack)
    }

    /// True if there are ACKs awaiting transmission.
    pub fn has_pending_acks(&self) -> bool {
        !self.pending_ack.is_empty()
    }

    /// Build an outgoing `P_CONTROL_V1` packet carrying `payload` (which must
    /// already be sized within [`CONTROL_CHANNEL_MTU`]). Assigns the next pid,
    /// records it as unacknowledged, and attaches pending ACKs.
    pub fn build_control(&mut self, payload: &[u8]) -> ControlPacket {
        let mut pkt = ControlPacket::new(Opcode::CONTROL_V1, 0, self.local_id, self.peer_id);
        pkt.payload = payload.to_vec();
        let pid = self.out_counter;
        pkt.set_pid(pid);
        self.out_counter += 1;
        self.track_unacked(pid, pkt.clone());
        pkt
    }

    /// Record an outgoing reliable packet as unacknowledged, stamping its send
    /// time so [`tick`](Self::tick) can drive retransmission.
    fn track_unacked(&mut self, pid: u32, pkt: ControlPacket) {
        self.unacked.insert(
            pid,
            Unacked {
                pkt,
                last_sent: Instant::now(),
                attempts: 1,
            },
        );
    }

    /// Chunk a TLS-record byte stream into one or more outgoing control
    /// packets, each within the control-channel MTU. Each returned packet has
    /// its pid assigned and is tracked for retransmit.
    pub fn chunk_tls_stream(&mut self, data: &[u8]) -> Vec<ControlPacket> {
        let mut packets = Vec::new();
        let mut off = 0;
        while off < data.len() {
            let end = (off + CONTROL_CHANNEL_MTU).min(data.len());
            packets.push(self.build_control(&data[off..end]));
            off = end;
        }
        packets
    }

    /// Build a server hard-reset packet in response to a client hard reset.
    pub fn build_hard_reset(&mut self) -> ControlPacket {
        self.build_reset(Opcode::CONTROL_HARD_RESET_SERVER_V2)
    }

    /// Build a client hard-reset packet (used by client-side drivers/tests).
    #[allow(dead_code)]
    pub fn build_client_hard_reset(&mut self) -> ControlPacket {
        self.build_reset(Opcode::CONTROL_HARD_RESET_CLIENT_V2)
    }

    fn build_reset(&mut self, opcode: Opcode) -> ControlPacket {
        let mut pkt = ControlPacket::new(opcode, 0, self.local_id, self.peer_id);
        let pid = self.out_counter;
        pkt.set_pid(pid);
        self.out_counter += 1;
        self.track_unacked(pid, pkt.clone());
        pkt
    }

    /// Build a standalone ACK packet (no pid of its own). The ACK pids are
    /// supplied at serialization time via [`ControlPacket::to_bytes`].
    pub fn build_ack(&self) -> ControlPacket {
        ControlPacket::new(Opcode::ACK_V1, 0, self.local_id, self.peer_id)
    }

    /// Packets still awaiting acknowledgement (for retransmission). Returns
    /// clones so the caller can re-serialize without holding a borrow.
    #[allow(dead_code)]
    pub fn unacked_packets(&self) -> Vec<ControlPacket> {
        self.unacked.values().map(|u| u.pkt.clone()).collect()
    }

    /// Number of unacknowledged outgoing packets.
    #[allow(dead_code)]
    pub fn unacked_count(&self) -> usize {
        self.unacked.len()
    }

    /// Drive retransmission timers. For every unacknowledged outgoing packet
    /// whose retransmit deadline (`last_sent + backoff(attempts)`) has passed
    /// at `now`, re-serialize it, bump its attempt count, double its backoff,
    /// and reset its send time. Packets that exceed
    /// [`RETRANSMIT_MAX_ATTEMPTS`] are dropped and flagged via
    /// [`TickOutcome::timed_out`] so the caller can close the connection.
    ///
    /// This is the caller-driven equivalent of OpenVPN's per-packet
    /// retransmit timer: there is no background thread, so the server (or the
    /// [`Adapter`](super::Adapter)) must call this periodically — roughly every
    /// [`RETRANSMIT_INITIAL`] — to make progress against packet loss.
    ///
    /// Pending ACKs are *not* re-attached here; a retransmit carries whatever
    /// ACKs the packet was originally built with (none, in practice — ACKs ride
    /// on freshly-built packets), which matches OpenVPN's behaviour of treating
    /// the reliable packet body as immutable once queued.
    pub fn tick(&mut self, now: Instant) -> TickOutcome {
        let mut outcome = TickOutcome::default();

        // Collect due pids first to avoid borrowing `self.unacked` mutably
        // while iterating (the values are cheap u32s).
        let mut due: Vec<u32> = Vec::new();
        for (&pid, u) in self.unacked.iter() {
            if now.duration_since(u.last_sent) >= backoff(u.attempts) {
                due.push(pid);
            }
        }
        // Deterministic order makes the resend stream predictable / testable.
        due.sort_unstable();

        for pid in due {
            let u = self.unacked.get_mut(&pid).expect("pid just collected");
            if u.attempts >= RETRANSMIT_MAX_ATTEMPTS {
                outcome.timed_out = true;
                self.unacked.remove(&pid);
                continue;
            }
            u.attempts += 1;
            u.last_sent = now;
            // Re-send the packet exactly as first framed (no ACKs piggybacked).
            outcome.resend.push(u.pkt.to_bytes(&[]));
        }

        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> [u8; 8] {
        [1, 2, 3, 4, 5, 6, 7, 8]
    }

    // Build a client P_CONTROL_V1 datagram with the given pid and payload.
    fn client_control(pid: u32, peer_local: [u8; 8], payload: &[u8]) -> Vec<u8> {
        let mut pkt = ControlPacket::new(Opcode::CONTROL_V1, 0, peer_local, [0u8; 8]);
        pkt.set_pid(pid);
        pkt.payload = payload.to_vec();
        pkt.to_bytes(&[])
    }

    #[test]
    fn hard_reset_sets_peer_id() {
        let mut r = Reliable::new(local());
        let client_sid = [9u8, 9, 9, 9, 9, 9, 9, 9];
        let mut reset =
            ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, client_sid, [0; 8]);
        reset.set_pid(0);
        let out = r.recv(&reset.to_bytes(&[])).unwrap();
        assert!(out.got_client_reset);
        assert_eq!(r.peer_id, client_sid);
        // We owe an ACK for pid 0.
        assert_eq!(r.take_pending_acks(), vec![0]);
    }

    #[test]
    fn in_order_stream_reassembly() {
        let mut r = Reliable::new(local());
        let client_sid = [9u8; 8];
        // Establish session.
        let mut reset =
            ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, client_sid, [0; 8]);
        reset.set_pid(0);
        r.recv(&reset.to_bytes(&[])).unwrap();

        // Deliver pid 2 first (out of order), then pid 1.
        let out2 = r.recv(&client_control(2, client_sid, b"world")).unwrap();
        assert!(out2.tls_bytes.is_empty(), "pid 2 should buffer");
        let out1 = r.recv(&client_control(1, client_sid, b"hello")).unwrap();
        assert_eq!(out1.tls_bytes, b"helloworld");
    }

    #[test]
    fn duplicate_old_packet_ignored() {
        let mut r = Reliable::new(local());
        let sid = [9u8; 8];
        let mut reset = ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, sid, [0; 8]);
        reset.set_pid(0);
        r.recv(&reset.to_bytes(&[])).unwrap();
        let out = r.recv(&client_control(1, sid, b"a")).unwrap();
        assert_eq!(out.tls_bytes, b"a");
        // Replaying pid 1 yields nothing (already past in_counter).
        let dup = r.recv(&client_control(1, sid, b"a")).unwrap();
        assert!(dup.tls_bytes.is_empty());
    }

    #[test]
    fn outgoing_acks_remove_unacked() {
        let mut r = Reliable::new(local());
        let _p0 = r.build_control(b"x");
        let _p1 = r.build_control(b"y");
        assert_eq!(r.unacked_count(), 2);

        // Peer acks pid 0.
        let sid = [9u8; 8];
        let mut ack = ControlPacket::new(Opcode::ACK_V1, 0, sid, r.local_id);
        let data = ack_bytes(&mut ack, &[0]);
        r.recv(&data).unwrap();
        assert_eq!(r.unacked_count(), 1);
    }

    fn ack_bytes(pkt: &mut ControlPacket, acks: &[u32]) -> Vec<u8> {
        pkt.to_bytes(acks)
    }

    #[test]
    fn chunking_respects_mtu() {
        let mut r = Reliable::new(local());
        let big = vec![0u8; CONTROL_CHANNEL_MTU * 2 + 10];
        let chunks = r.chunk_tls_stream(&big);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].payload.len(), CONTROL_CHANNEL_MTU);
        assert_eq!(chunks[1].payload.len(), CONTROL_CHANNEL_MTU);
        assert_eq!(chunks[2].payload.len(), 10);
        // pids assigned sequentially.
        assert_eq!(chunks[0].pid, Some(0));
        assert_eq!(chunks[2].pid, Some(2));
    }

    #[test]
    fn far_future_pid_rejected() {
        let mut r = Reliable::new(local());
        let sid = [9u8; 8];
        let mut reset = ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, sid, [0; 8]);
        reset.set_pid(0);
        r.recv(&reset.to_bytes(&[])).unwrap();
        // pid way beyond the receive window.
        assert!(r.recv(&client_control(1000, sid, b"z")).is_err());
    }

    // --- retransmission timers ----------------------------------------------

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(1), RETRANSMIT_INITIAL);
        assert_eq!(backoff(2), RETRANSMIT_INITIAL * 2);
        assert_eq!(backoff(3), RETRANSMIT_INITIAL * 4);
        // Eventually clamps at the cap and never exceeds it.
        assert_eq!(backoff(100), RETRANSMIT_MAX_INTERVAL);
        assert!(backoff(50) <= RETRANSMIT_MAX_INTERVAL);
    }

    #[test]
    fn unacked_past_deadline_is_resent() {
        let mut r = Reliable::new(local());
        let p = r.build_control(b"hello");
        let start = Instant::now();

        // Before the deadline: nothing to resend.
        let early = r.tick(start + RETRANSMIT_INITIAL - Duration::from_millis(1));
        assert!(early.resend.is_empty());
        assert!(!early.timed_out);

        // Past the deadline: the original packet comes back out verbatim.
        let late = r.tick(start + RETRANSMIT_INITIAL + Duration::from_millis(1));
        assert_eq!(late.resend.len(), 1);
        assert_eq!(late.resend[0], p.to_bytes(&[]));
        assert!(!late.timed_out);
    }

    #[test]
    fn acked_packet_is_not_resent() {
        let mut r = Reliable::new(local());
        let _p = r.build_control(b"hello");
        let start = Instant::now();
        assert_eq!(r.unacked_count(), 1);

        // Peer acks pid 0.
        let sid = [9u8; 8];
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, sid, r.local_id);
        r.recv(&ack.to_bytes(&[0])).unwrap();
        assert_eq!(r.unacked_count(), 0);

        // Well past the deadline, nothing is resent.
        let out = r.tick(start + RETRANSMIT_INITIAL * 4);
        assert!(out.resend.is_empty());
    }

    #[test]
    fn backoff_increases_between_retransmits() {
        let mut r = Reliable::new(local());
        let _p = r.build_control(b"x");
        let start = Instant::now();

        // First retransmit fires after the base interval.
        let t1 = start + RETRANSMIT_INITIAL;
        assert_eq!(r.tick(t1).resend.len(), 1);

        // A second tick only one base-interval later must NOT fire: the next
        // deadline is now 2x the base from t1.
        let t2 = t1 + RETRANSMIT_INITIAL;
        assert!(r.tick(t2).resend.is_empty(), "backoff should have doubled");

        // Waiting the doubled interval does fire the second retransmit.
        let t3 = t1 + RETRANSMIT_INITIAL * 2;
        assert_eq!(r.tick(t3).resend.len(), 1);
    }

    #[test]
    fn retries_cap_and_signal_timeout() {
        let mut r = Reliable::new(local());
        let _p = r.build_control(b"x");
        let mut t = Instant::now();
        let mut timed_out = false;
        // Advance well past each (growing) deadline until the packet is dropped.
        for _ in 0..(RETRANSMIT_MAX_ATTEMPTS + 4) {
            t += RETRANSMIT_MAX_INTERVAL * 2;
            let out = r.tick(t);
            if out.timed_out {
                timed_out = true;
                break;
            }
        }
        assert!(timed_out, "packet should eventually time out");
        // Once timed out the packet is gone; further ticks are quiet.
        assert_eq!(r.unacked_count(), 0);
        let after = r.tick(t + RETRANSMIT_MAX_INTERVAL * 2);
        assert!(after.resend.is_empty());
        assert!(!after.timed_out);
    }
}

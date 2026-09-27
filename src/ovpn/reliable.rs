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
//! into `P_CONTROL_V1` packets). This is the substrate purecrypto's
//! `tls::Connection` reads from and writes to — there is no TCP socket below
//! the TLS, only this layer.

use crate::time::Instant;
use std::collections::HashMap;
use std::io;
use std::time::Duration;

use super::Opcode;
use super::consts::{
    CONTROL_CHANNEL_MTU, CONTROL_SEND_ACK_MAX, TLS_RELIABLE_N_REC_BUFFERS,
    TLS_RELIABLE_N_SEND_BUFFERS,
};
use super::packet_ctrl::ControlPacket;

/// Initial retransmit timeout for an unacked control packet. OpenVPN's
/// reliable layer starts at ~1s and backs off exponentially.
pub const RETRANSMIT_INITIAL: Duration = Duration::from_secs(1);
/// Cap on the backed-off retransmit interval (OpenVPN clamps around here).
///
/// There is no cap on the number of attempts: like OpenVPN's reliable_send,
/// a packet is retried for as long as its key lives. What gives up on an
/// unresponsive client is the handshake window, for a key still
/// negotiating, and ping-restart for an established one.
pub const RETRANSMIT_MAX_INTERVAL: Duration = Duration::from_secs(8);

/// Outcome of feeding one control packet into the reliable layer.
#[derive(Debug, Default)]
pub struct RecvOutcome {
    /// In-order TLS-stream bytes newly available (concatenated payloads of
    /// `P_CONTROL_V1` packets delivered in order).
    pub tls_bytes: Vec<u8>,
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

/// Outcome of a retransmission tick: datagrams to resend.
#[derive(Debug, Default)]
pub struct TickOutcome {
    /// Re-serialized control datagrams to put back on the wire.
    pub resend: Vec<Vec<u8>>,
}

/// Reliable transport state for one peer.
#[derive(Debug)]
pub struct Reliable {
    pub local_id: [u8; 8],
    pub peer_id: [u8; 8],
    /// Key id stamped on every packet built here: each key has its own
    /// reliable stream.
    pub key_id: u8,

    // Outgoing.
    out_counter: u32,
    unacked: HashMap<u32, Unacked>,
    /// TLS output not yet put in a packet, held back while the send window
    /// is full (OpenVPN leaves it in the TLS engine's BIO the same way).
    held: Vec<u8>,

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
            key_id: 0,
            out_counter: 0,
            unacked: HashMap::new(),
            held: Vec::new(),
            in_counter: 0,
            in_buf: HashMap::new(),
            pending_ack: Vec::new(),
        }
    }

    /// Process an inbound control packet (full datagram including opcode
    /// byte). The server routes packets to a session first and uses
    /// [`recv_packet`](Self::recv_packet); the test client uses this.
    #[cfg(test)]
    pub fn recv(&mut self, data: &[u8]) -> io::Result<RecvOutcome> {
        self.recv_packet(ControlPacket::parse(data)?)
    }

    /// Process an inbound control packet already routed to this transport.
    /// `Err` means the packet was dropped: its payload was not taken, nor is
    /// it ACKed. The ACKs it carried for this session still count, as in
    /// OpenVPN, which reads them before looking at the packet's own id.
    pub fn recv_packet(&mut self, pkt: ControlPacket) -> io::Result<RecvOutcome> {
        // An ACK names the session it acknowledges (reliable_ack_read): one
        // for another session must not release our unacknowledged packets.
        if !pkt.acked_pids.is_empty() && pkt.remote_id != self.local_id {
            return Err(invalid("ACK for another session"));
        }
        // ssl.c tls_pre_decrypt purges acknowledged packets first: an ACK
        // riding on a packet that is itself refused below (out of the
        // window, say) is still news, and dropping it would only cause
        // needless retransmissions.
        for pid in &pkt.acked_pids {
            self.unacked.remove(pid);
        }

        let mut outcome = RecvOutcome::default();
        let is_reset = pkt.opcode == Opcode::CONTROL_HARD_RESET_CLIENT_V2
            || pkt.opcode == Opcode::CONTROL_HARD_RESET_SERVER_V2;
        let pid = match pkt.pid {
            // ACK packets carry no pid and need no further processing.
            _ if pkt.opcode == Opcode::ACK_V1 => None,
            Some(pid) => Some(pid),
            None => return Err(invalid("control packet missing packet id")),
        };
        // A hard reset is always packet 0 of its session; OpenVPN ignores one
        // claiming another id (a stale replay, in practice).
        if is_reset && pid != Some(0) {
            return Err(invalid("hard reset with a non-zero packet id"));
        }
        // A packet that would not fit the receive window is neither stored
        // nor ACKed.
        if let Some(pid) = pid
            && pid >= self.in_counter + TLS_RELIABLE_N_REC_BUFFERS as u32
        {
            return Err(invalid("rejecting packet because pid looks invalid"));
        }

        let Some(pid) = pid else {
            return Ok(outcome);
        };

        // We owe an ACK for this received packet, even for a duplicate: our
        // earlier ACK may have been lost. Once is enough, though.
        if !self.pending_ack.contains(&pid) {
            self.pending_ack.push(pid);
        }

        // The client learns the server's session id from its hard reset; a
        // server's is fixed when the session is opened.
        if pkt.opcode == Opcode::CONTROL_HARD_RESET_SERVER_V2 && self.peer_id == [0; 8] {
            self.peer_id = pkt.session_id;
        }

        // Reorder buffer. Resets occupy a slot in the ordered stream but carry
        // no TLS bytes.
        if pid < self.in_counter {
            return Ok(outcome); // already processed
        }
        self.in_buf.entry(pid).or_insert(pkt);
        while let Some(p) = self.in_buf.remove(&self.in_counter) {
            self.in_counter += 1;
            if p.opcode == Opcode::CONTROL_V1 {
                outcome.tls_bytes.extend_from_slice(&p.payload);
            }
        }

        Ok(outcome)
    }

    /// Take up to [`CONTROL_SEND_ACK_MAX`] of the ACKs we owe, oldest first,
    /// for the caller to attach to the next outgoing packet (or a dedicated
    /// ACK). One packet carries no more (reliable_ack_write), which keeps it
    /// within [`TLS_MTU`](super::consts::TLS_MTU); the rest wait for the
    /// next.
    pub fn take_pending_acks(&mut self) -> Vec<u32> {
        let n = self.pending_ack.len().min(CONTROL_SEND_ACK_MAX);
        self.pending_ack.drain(..n).collect()
    }

    /// True if there are ACKs awaiting transmission.
    pub fn has_pending_acks(&self) -> bool {
        !self.pending_ack.is_empty()
    }

    /// Build an outgoing `P_CONTROL_V1` packet carrying `payload` (which must
    /// already be sized within [`CONTROL_CHANNEL_MTU`]). Assigns the next pid,
    /// records it as unacknowledged, and attaches pending ACKs.
    pub fn build_control(&mut self, payload: &[u8]) -> ControlPacket {
        let mut pkt =
            ControlPacket::new(Opcode::CONTROL_V1, self.key_id, self.local_id, self.peer_id);
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
    /// packets, each within the control-channel MTU, with no regard for the
    /// send window. Only the test client uses this; the server goes through
    /// [`queue_tls`](Self::queue_tls) and [`flush_tls`](Self::flush_tls).
    #[cfg(test)]
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

    /// Append TLS output to what is waiting to be sent.
    pub fn queue_tls(&mut self, data: &[u8]) {
        self.held.extend_from_slice(data);
    }

    /// Bytes of TLS output waiting for room in the send window.
    pub fn held_len(&self) -> usize {
        self.held.len()
    }

    /// Whether the send window has room for another packet
    /// (reliable_can_send, reliable_get_buf_output_sequenced): its id must
    /// stay within TLS_RELIABLE_N_SEND_BUFFERS of the oldest one still
    /// unacknowledged. Without the bound, a peer that never ACKs has us
    /// keep, and retransmit, everything we ever sent it.
    fn can_send(&self) -> bool {
        let window = TLS_RELIABLE_N_SEND_BUFFERS as u32;
        match self.unacked.keys().min() {
            Some(&oldest) => self.out_counter < oldest.saturating_add(window),
            None => true,
        }
    }

    /// Put as much of the held-back TLS output into control packets as the
    /// send window allows. Each returned packet has its pid assigned and is
    /// tracked for retransmit; the rest waits for ACKs to open the window.
    pub fn flush_tls(&mut self) -> Vec<ControlPacket> {
        let mut packets = Vec::new();
        while !self.held.is_empty() && self.can_send() {
            let n = self.held.len().min(CONTROL_CHANNEL_MTU);
            let chunk: Vec<u8> = self.held.drain(..n).collect();
            packets.push(self.build_control(&chunk));
        }
        packets
    }

    /// Build a server hard-reset packet in response to a client hard reset.
    pub fn build_hard_reset(&mut self) -> ControlPacket {
        self.build_reset(Opcode::CONTROL_HARD_RESET_SERVER_V2)
    }

    /// Count the hard resets as exchanged without this transport having
    /// seen either: the peer's reset (packet 0) as received, and ours as
    /// sent and acknowledged. For a session opened after the server answered
    /// the client's reset statelessly (ssl.c session_skip_to_pre_start).
    pub fn skip_reset(&mut self) {
        self.out_counter = self.out_counter.max(1);
        self.in_counter = self.in_counter.max(1);
    }

    /// Build the P_CONTROL_SOFT_RESET_V1 that opens a renegotiated key's
    /// stream.
    pub fn build_soft_reset(&mut self) -> ControlPacket {
        self.build_reset(Opcode::CONTROL_SOFT_RESET_V1)
    }

    /// Build a client hard-reset packet (used by client-side drivers/tests).
    #[allow(dead_code)]
    pub fn build_client_hard_reset(&mut self) -> ControlPacket {
        self.build_reset(Opcode::CONTROL_HARD_RESET_CLIENT_V2)
    }

    fn build_reset(&mut self, opcode: Opcode) -> ControlPacket {
        let mut pkt = ControlPacket::new(opcode, self.key_id, self.local_id, self.peer_id);
        let pid = self.out_counter;
        pkt.set_pid(pid);
        self.out_counter += 1;
        self.track_unacked(pid, pkt.clone());
        pkt
    }

    /// Whether the peer has acknowledged our reset, this stream's packet 0.
    pub fn reset_acked(&self) -> bool {
        self.out_counter > 0 && !self.unacked.contains_key(&0)
    }

    /// Build a standalone ACK packet (no pid of its own). The ACK pids are
    /// supplied at serialization time via [`ControlPacket::to_bytes`].
    pub fn build_ack(&self) -> ControlPacket {
        ControlPacket::new(Opcode::ACK_V1, self.key_id, self.local_id, self.peer_id)
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
    /// and reset its send time.
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
            u.attempts = u.attempts.saturating_add(1);
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
    fn server_hard_reset_sets_peer_id_on_the_client() {
        let mut r = Reliable::new(local());
        let server_sid = [9u8, 9, 9, 9, 9, 9, 9, 9];
        let mut reset =
            ControlPacket::new(Opcode::CONTROL_HARD_RESET_SERVER_V2, 0, server_sid, [0; 8]);
        reset.set_pid(0);
        r.recv(&reset.to_bytes(&[])).unwrap();
        assert_eq!(r.peer_id, server_sid);
        // We owe an ACK for pid 0.
        assert_eq!(r.take_pending_acks(), vec![0]);
    }

    #[test]
    fn hard_reset_with_nonzero_pid_is_dropped() {
        let mut r = Reliable::new(local());
        let mut reset = ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, [9; 8], [0; 8]);
        reset.set_pid(3);
        assert!(r.recv(&reset.to_bytes(&[])).is_err());
        assert!(!r.has_pending_acks());
    }

    #[test]
    fn ack_naming_another_session_is_dropped() {
        let mut r = Reliable::new(local());
        let _p0 = r.build_control(b"x");
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, [9; 8], [7; 8]);
        assert!(r.recv(&ack.to_bytes(&[0])).is_err());
        assert_eq!(r.unacked_count(), 1);
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

    /// One packet carries at most CONTROL_SEND_ACK_MAX ACKs, so it stays
    /// within the tls-mtu; the rest wait for the next, and a packet
    /// received twice is owed one ACK.
    #[test]
    fn acks_per_packet_are_capped() {
        let mut r = Reliable::new(local());
        let sid = [9u8; 8];
        let mut reset = ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, sid, [0; 8]);
        reset.set_pid(0);
        r.recv(&reset.to_bytes(&[])).unwrap();
        for pid in 1..6 {
            r.recv(&client_control(pid, sid, b"x")).unwrap();
        }
        r.recv(&client_control(5, sid, b"x")).unwrap();
        assert_eq!(r.take_pending_acks(), vec![0, 1, 2, 3]);
        assert_eq!(r.take_pending_acks(), vec![4, 5]);
        assert!(!r.has_pending_acks());
    }

    /// At most TLS_RELIABLE_N_SEND_BUFFERS packets are in flight; the rest
    /// of the TLS output waits until ACKs open the window, oldest first.
    #[test]
    fn send_window_holds_back_output_until_acked() {
        let mut r = Reliable::new(local());
        r.queue_tls(&vec![7u8; CONTROL_CHANNEL_MTU * 6]);
        let first = r.flush_tls();
        assert_eq!(first.len(), TLS_RELIABLE_N_SEND_BUFFERS);
        assert_eq!(r.unacked_count(), TLS_RELIABLE_N_SEND_BUFFERS);
        assert_eq!(r.held_len(), CONTROL_CHANNEL_MTU * 2);
        assert!(r.flush_tls().is_empty(), "window is full");

        // An ACK for a later packet does not move the window past the
        // oldest one still outstanding.
        let ack = ControlPacket::new(Opcode::ACK_V1, 0, [9; 8], r.local_id);
        r.recv(&ack.to_bytes(&[3])).unwrap();
        assert!(r.flush_tls().is_empty());
        r.recv(&ack.to_bytes(&[0])).unwrap();
        let next = r.flush_tls();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].pid, Some(4));
        r.recv(&ack.to_bytes(&[1, 2])).unwrap();
        let last = r.flush_tls();
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].pid, Some(5));
        assert_eq!(r.held_len(), 0);
    }

    /// ACKs are read before the packet's own id is checked (ssl.c
    /// tls_pre_decrypt: reliable_send_purge, then
    /// reliable_wont_break_sequentiality): ones riding on a packet we cannot
    /// take yet still release what they acknowledge.
    #[test]
    fn acks_on_an_out_of_window_packet_are_applied() {
        let mut r = Reliable::new(local());
        let _p0 = r.build_control(b"x");
        let mut far = ControlPacket::new(Opcode::CONTROL_V1, 0, [9; 8], r.local_id);
        far.set_pid(1000);
        assert!(r.recv(&far.to_bytes(&[0])).is_err());
        assert_eq!(r.unacked_count(), 0);
        assert!(!r.has_pending_acks(), "the packet itself is not ACKed");
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

        // Past the deadline: the original packet comes back out verbatim.
        let late = r.tick(start + RETRANSMIT_INITIAL + Duration::from_millis(1));
        assert_eq!(late.resend.len(), 1);
        assert_eq!(late.resend[0], p.to_bytes(&[]));
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

    /// Retransmission never gives up (reliable.c has no retry limit); it
    /// settles at the capped interval.
    #[test]
    fn retransmits_forever_at_the_capped_interval() {
        let mut r = Reliable::new(local());
        let _p = r.build_control(b"x");
        let mut t = Instant::now();
        for _ in 0..100 {
            t += RETRANSMIT_MAX_INTERVAL;
            assert_eq!(r.tick(t).resend.len(), 1);
        }
        assert_eq!(r.unacked_count(), 1);
    }
}

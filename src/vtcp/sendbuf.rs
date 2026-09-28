//! Sender-side byte buffer. What the receiver SACKed, and what is lost,
//! is the [scoreboard](super::scoreboard)'s.

use super::seqspace::seq_after;

/// Capacity an empty buffer may keep. Above it, draining to empty frees the
/// storage: an idle connection would otherwise pin its peak (up to the
/// whole send buffer) for as long as it lives. Below it, a connection
/// that empties its buffer on every ACK keeps reusing the same allocation.
pub(crate) const KEEP_IDLE_CAPACITY: usize = 64 * 1024;

/// Tracks application data through the TCP send pipeline:
///
/// ```text
/// [acked] [sent but unacked] [unsent / queued] [free]
///         ^                  ^                 ^
///         una                nxt               tail
/// ```
///
/// `buf[head]` corresponds to sequence `una`. `buf[head..head+nxt-una)` is
/// in flight; the rest is queued for sending.
#[derive(Debug)]
pub struct SendBuf {
    /// Acknowledged bytes before `head` are dropped lazily (see
    /// [`acknowledge`](Self::acknowledge)), keeping the data contiguous for
    /// the slices handed out without shifting it on every ACK.
    buf: Vec<u8>,
    head: usize,
    cap: usize,
    una: u32,
    nxt: u32,
}

impl SendBuf {
    /// An empty buffer holding up to `capacity` bytes, whose first byte will
    /// have sequence number `initial_seq`.
    pub fn new(capacity: usize, initial_seq: u32) -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
            cap: capacity,
            una: initial_seq,
            nxt: initial_seq,
        }
    }

    /// The unacknowledged and unsent data, from SND.UNA on.
    #[inline]
    fn data(&self) -> &[u8] {
        &self.buf[self.head..]
    }

    /// Append data, returning the number of bytes accepted.
    pub fn write(&mut self, p: &[u8]) -> usize {
        let avail = self.available();
        if avail == 0 {
            return 0;
        }
        let n = p.len().min(avail);
        self.buf.extend_from_slice(&p[..n]);
        n
    }

    /// Bytes queued but not yet sent.
    pub fn pending(&self) -> usize {
        let sent = self.nxt.wrapping_sub(self.una) as usize;
        self.data().len().saturating_sub(sent)
    }

    /// Sent-but-unacknowledged bytes.
    pub fn unacked(&self) -> usize {
        self.nxt.wrapping_sub(self.una) as usize
    }

    /// Read at most `n` bytes of unsent data without consuming them.
    pub fn peek_unsent(&self, n: usize) -> &[u8] {
        let offset = self.nxt.wrapping_sub(self.una) as usize;
        let data = self.data();
        let unsent = &data[offset.min(data.len())..];
        if unsent.len() > n {
            &unsent[..n]
        } else {
            unsent
        }
    }

    /// Advance SND.NXT by `n` after the data was put on the wire.
    pub fn advance_sent(&mut self, n: usize) {
        self.nxt = self.nxt.wrapping_add(n as u32);
    }

    /// Cumulative ACK at `ack`; returns the number of bytes newly freed.
    pub fn acknowledge(&mut self, mut ack: u32) -> u32 {
        if !seq_after(ack, self.una) {
            return 0;
        }
        if seq_after(ack, self.nxt) {
            ack = self.nxt;
        }
        let mut n = ack.wrapping_sub(self.una);
        if n as usize > self.data().len() {
            n = self.data().len() as u32;
        }
        self.head += n as usize;
        // Shifting the rest down on every ACK would cost the whole buffer
        // per ACK. Do it only once the dropped bytes outnumber what is
        // left, or reach a quarter of the capacity: each shift then moves
        // at most four bytes per byte acknowledged since the last, and the
        // dead space stays bounded.
        let live = self.buf.len() - self.head;
        if live == 0 && self.buf.capacity() > KEEP_IDLE_CAPACITY {
            self.buf = Vec::new();
            self.head = 0;
        } else if self.head >= live || self.head >= self.cap / 4 {
            self.buf.drain(..self.head);
            self.head = 0;
        }
        self.una = ack;
        n
    }

    /// Up to `n` bytes of data from `seq` on, which must lie between
    /// SND.UNA and SND.NXT: for a retransmission. Stops at the FIN, which
    /// is not data.
    pub fn data_at(&self, seq: u32, n: usize) -> &[u8] {
        let data = self.data();
        let off = (seq.wrapping_sub(self.una) as usize).min(data.len());
        let sent = (self.nxt.wrapping_sub(self.una) as usize).min(data.len());
        &data[off..sent.max(off).min(off + n)]
    }

    /// Free the storage for good, once the connection will send nothing
    /// more (TIME-WAIT, CLOSED). Data still held is discarded; the sequence
    /// numbers stay as they are.
    pub fn release_memory(&mut self) {
        self.buf = Vec::new();
        self.head = 0;
    }

    /// Bytes allocated for data.
    #[cfg(test)]
    pub fn allocated(&self) -> usize {
        self.buf.capacity()
    }

    /// True if no data is buffered, unacknowledged or not yet sent.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.data().is_empty()
    }

    /// SND.UNA: the oldest unacknowledged sequence number.
    #[inline]
    pub fn una(&self) -> u32 {
        self.una
    }

    /// SND.NXT: the next sequence number to send.
    #[inline]
    pub fn nxt(&self) -> u32 {
        self.nxt
    }

    /// Room left for more data, in bytes.
    #[inline]
    pub fn available(&self) -> usize {
        self.cap.saturating_sub(self.data().len())
    }

    /// The most data the buffer holds, in bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Resize the buffer. Data already in it past a smaller capacity stays,
    /// and only keeps more from being written.
    pub fn set_capacity(&mut self, cap: usize) {
        self.cap = cap;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_peek() {
        let mut s = SendBuf::new(100, 1000);
        assert_eq!(s.write(b"hello"), 5);
        assert_eq!(s.pending(), 5);
        assert_eq!(s.peek_unsent(10), b"hello");
        s.advance_sent(5);
        assert_eq!(s.pending(), 0);
        assert_eq!(s.unacked(), 5);
    }

    #[test]
    fn capacity_caps_write() {
        let mut s = SendBuf::new(3, 0);
        assert_eq!(s.write(b"hello"), 3);
        assert_eq!(s.write(b"more"), 0);
    }

    #[test]
    fn acknowledge_frees_bytes() {
        let mut s = SendBuf::new(100, 1000);
        s.write(b"hello world");
        s.advance_sent(11);
        let n = s.acknowledge(1005);
        assert_eq!(n, 5);
        assert_eq!(s.una(), 1005);
        assert_eq!(s.unacked(), 6);
    }

    #[test]
    fn data_at_stops_at_what_was_sent() {
        let mut s = SendBuf::new(100, u32::MAX - 2);
        s.write(b"0123456789");
        s.advance_sent(6);
        assert_eq!(s.data_at(u32::MAX - 2, 4), b"0123");
        assert_eq!(s.data_at(1, 10), b"45");
        s.acknowledge(0);
        assert_eq!(s.data_at(0, 3), b"345");
    }

    #[test]
    fn acknowledge_clamps_to_nxt() {
        let mut s = SendBuf::new(100, 1000);
        s.write(b"hi");
        s.advance_sent(2);
        let n = s.acknowledge(9999); // bogus ack way past nxt
        assert_eq!(n, 2);
        assert_eq!(s.una(), 1002);
    }

    /// A megabyte in flight, ACKed a few bytes at a time: each ACK must
    /// cost what it frees, not a shift of everything still in flight.
    #[test]
    fn small_acks_of_a_full_buffer_are_linear() {
        const CAP: usize = 1 << 20;
        let start = std::time::Instant::now();
        let mut s = SendBuf::new(CAP, 7);
        let data: Vec<u8> = (0..CAP).map(|i| i as u8).collect();
        assert_eq!(s.write(&data), CAP);
        s.advance_sent(CAP);
        let (mut acked, mut refilled) = (0, 0);
        while acked < CAP {
            acked = (acked + 3).min(CAP);
            s.acknowledge(7 + acked as u32);
            // Refill as the ACKs free room, like a busy writer.
            if acked < CAP / 2 {
                assert_eq!(s.write(&[acked as u8; 3]), 3);
                refilled += 3;
            }
            if acked % 3072 == 0 {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(3),
                    "quadratic"
                );
            }
        }
        assert_eq!(s.unacked(), 0);
        assert_eq!(s.pending(), refilled);
        assert_eq!(s.peek_unsent(3), &[3, 3, 3][..]);
        assert_eq!(s.available(), CAP - refilled);
    }

    #[test]
    fn draining_to_empty_frees_a_large_buffer() {
        let mut s = SendBuf::new(1 << 20, 0);
        assert_eq!(s.write(&vec![1; 1 << 20]), 1 << 20);
        s.advance_sent(1 << 20);
        s.acknowledge(1 << 19);
        assert!(s.buf.capacity() >= 1 << 19, "freed with data in flight");
        s.acknowledge(1 << 20);
        assert!(s.is_empty());
        assert!(s.buf.capacity() <= KEEP_IDLE_CAPACITY, "idle buffer kept");

        // A small one is kept for reuse.
        s.write(&[2; 1000]);
        s.advance_sent(1000);
        let cap = s.buf.capacity();
        s.acknowledge((1 << 20) + 1000);
        assert_eq!(s.buf.capacity(), cap);
        assert_eq!(s.write(b"x"), 1);
        assert_eq!(s.peek_unsent(10), b"x");
    }
}

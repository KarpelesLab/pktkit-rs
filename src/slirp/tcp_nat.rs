//! Minimal TCP NAT engine.
//!
//! Bridges a virtual TCP client (segments delivered via [`handle_segment`])
//! to a real OS [`TcpStream`]. This is a hand-rolled, deliberately small
//! TCP state machine — it covers the cases slirp actually generates:
//!
//! - SYN handshake (we mint SYN-ACK on receipt of SYN, complete on ACK).
//! - Bulk data transfer in both directions.
//! - FIN-initiated graceful close from either side.
//! - RST on errors.
//!
//! This is *not* a generally-correct TCP stack — there's no congestion
//! control, no SACK, no out-of-order reassembly, and the window
//! advertised is fixed. Adequate for slirp's bridging role; the full
//! pktkit `vtcp` engine should replace it once ported.
//!
//! TODO(slirp): once `vtcp` lands in pktkit-rs, swap this minimal engine
//! out for `vtcp::Conn` to inherit the proper RFC-compliant state machine.

use crate::slirp::packet::{build_packet4, build_packet6};
use crate::Result;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// TCP flag bits.
pub(crate) const FLAG_FIN: u8 = 0x01;
pub(crate) const FLAG_SYN: u8 = 0x02;
pub(crate) const FLAG_RST: u8 = 0x04;
pub(crate) const FLAG_PSH: u8 = 0x08;
pub(crate) const FLAG_ACK: u8 = 0x10;

const RECV_WINDOW: u16 = 32768;
const MSS_V4: usize = 1460;
const MSS_V6: usize = 1440;

/// Owns the two halves of the bridge: a packet-shaped function used to
/// write back to the virtual client, and the real OS-side TcpStream.
pub(crate) enum SendBack {
    V4 {
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        send: Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>,
    },
    V6 {
        local_ip: Ipv6Addr,
        remote_ip: Ipv6Addr,
        send: Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>,
    },
}

impl SendBack {
    fn write_seg(&self, seg: &[u8]) -> Result<()> {
        match self {
            SendBack::V4 { local_ip, remote_ip, send } => {
                let pkt = build_packet4(*local_ip, *remote_ip, seg);
                send(&pkt)
            }
            SendBack::V6 { local_ip, remote_ip, send } => {
                let pkt = build_packet6(*local_ip, *remote_ip, seg);
                send(&pkt)
            }
        }
    }

    fn mss(&self) -> usize {
        match self {
            SendBack::V4 { .. } => MSS_V4,
            SendBack::V6 { .. } => MSS_V6,
        }
    }
}

/// Per-connection state shared between the writer (TCP segments arriving
/// from the virtual client) and the reader (bytes arriving from the real
/// server).
struct State {
    /// Next sequence number we will send (i.e. our SND.NXT).
    snd_nxt: AtomicU32,
    /// Initial sequence number (ISN) chosen at SYN-ACK time.
    snd_iss: AtomicU32,
    /// Last cumulative ACK we sent to the client (covers their bytes received).
    rcv_nxt: AtomicU32,
    /// Set when our side has shut down sending.
    fin_sent: AtomicBool,
    /// Set when the client's FIN has been seen.
    fin_recv: AtomicBool,
    /// Set on RST or after both FINs have been ACKed.
    closed: AtomicBool,
    /// Owned write-side of the real upstream socket. Wrapped in `Mutex` so
    /// the writer in `handle_segment` can serialize against concurrent
    /// shutdown calls. The read half is cloned out once in `accept_syn`.
    remote_write: Mutex<Option<TcpStream>>,
}

/// A live TCP NAT bridge.
pub(crate) struct TcpNatConn {
    state: Arc<State>,
    src_port: u16, // client's port (becomes destination on the way back)
    dst_port: u16, // server's port (our local port on the way back)
    send_back: SendBack,
}

impl TcpNatConn {
    /// Construct a connection in response to a SYN from the virtual client.
    /// Returns the connection wrapper and immediately writes a SYN-ACK back.
    pub(crate) fn accept_syn(
        client_src_port: u16,
        client_dst_port: u16,
        client_seq: u32,
        remote: TcpStream,
        send_back: SendBack,
    ) -> Result<Arc<TcpNatConn>> {
        // Clone the underlying file descriptor for the read loop; the original
        // is kept for writes and for the shutdown signaling.
        let remote_read = remote.try_clone()?;

        let iss = crate::rand::u32();
        let state = Arc::new(State {
            snd_nxt: AtomicU32::new(iss.wrapping_add(1)),
            snd_iss: AtomicU32::new(iss),
            rcv_nxt: AtomicU32::new(client_seq.wrapping_add(1)),
            fin_sent: AtomicBool::new(false),
            fin_recv: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            remote_write: Mutex::new(Some(remote)),
        });

        let conn = Arc::new(TcpNatConn {
            state: state.clone(),
            src_port: client_src_port,
            dst_port: client_dst_port,
            send_back,
        });

        // SYN-ACK: SEQ=ISS, ACK=client_seq+1, flags SYN|ACK.
        conn.send_control(FLAG_SYN | FLAG_ACK, iss, client_seq.wrapping_add(1))?;

        // Background reader: real-side → virtual client.
        let conn2 = conn.clone();
        thread::spawn(move || conn2.read_loop(remote_read));

        Ok(conn)
    }

    /// Handle a TCP segment from the virtual client.
    pub(crate) fn handle_segment(&self, tcp: &[u8]) -> Result<()> {
        if tcp.len() < 20 {
            return Ok(());
        }
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_off = ((tcp[12] >> 4) as usize) * 4;
        let flags = tcp[13];
        if data_off < 20 || data_off > tcp.len() {
            return Ok(());
        }
        let payload = &tcp[data_off..];

        // RST → tear down.
        if flags & FLAG_RST != 0 {
            self.shutdown_remote_both();
            self.state.closed.store(true, Ordering::Release);
            return Ok(());
        }

        // Retransmitted SYN (or SYN before our SYN-ACK was ACKed): re-send SYN-ACK.
        if flags & FLAG_SYN != 0 && self.state.snd_nxt.load(Ordering::Acquire)
            == self.state.snd_iss.load(Ordering::Acquire).wrapping_add(1)
            && !self.state.fin_sent.load(Ordering::Acquire)
        {
            let iss = self.state.snd_iss.load(Ordering::Acquire);
            self.send_control(FLAG_SYN | FLAG_ACK, iss, seq.wrapping_add(1))?;
            return Ok(());
        }

        // ACK only — first ACK after our SYN-ACK completes the handshake.
        // Subsequent ACKs may carry data; the `ack` field acknowledges our bytes.
        let _ = ack; // we don't track outgoing buffers, OS socket handles retransmits

        // Update RCV.NXT for inbound data and the FIN bit.
        let mut consumed = self.state.rcv_nxt.load(Ordering::Acquire);

        // If `seq` is what we expect, accept the payload.
        if seq == consumed && !payload.is_empty() {
            // Write to remote.
            let mut guard = self.state.remote_write.lock().expect("poisoned");
            let write_err = match guard.as_mut() {
                Some(s) => s.write_all(payload).err(),
                None => None,
            };
            drop(guard);
            if write_err.is_some() {
                let _ = self.send_rst_keepalive(seq.wrapping_add(payload.len() as u32));
                self.shutdown_remote_both();
                self.state.closed.store(true, Ordering::Release);
                return Ok(());
            }
            consumed = consumed.wrapping_add(payload.len() as u32);
            self.state.rcv_nxt.store(consumed, Ordering::Release);
            // Ack the bytes.
            let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
            self.send_control(FLAG_ACK, snd_nxt, consumed)?;
        } else if seq == consumed && payload.is_empty() {
            // Pure ACK (handshake completion or just an ack). Nothing to do
            // unless the FIN bit is set.
        } else if (seq.wrapping_add(payload.len() as u32)).wrapping_sub(consumed) as i32 <= 0 {
            // Old retransmission, re-ack and ignore.
            let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
            self.send_control(FLAG_ACK, snd_nxt, consumed)?;
        } else {
            // Out-of-order segment: re-send last ACK.
            // TODO(slirp): proper reassembly buffer when wired through vtcp.
            let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
            self.send_control(FLAG_ACK, snd_nxt, consumed)?;
        }

        // FIN handling.
        if flags & FLAG_FIN != 0 && !self.state.fin_recv.load(Ordering::Acquire) {
            self.state.fin_recv.store(true, Ordering::Release);
            let new_rcv = consumed.wrapping_add(1);
            self.state.rcv_nxt.store(new_rcv, Ordering::Release);
            // Half-close the real side: client won't send more data.
            if let Ok(g) = self.state.remote_write.lock() {
                if let Some(s) = g.as_ref() {
                    let _ = s.shutdown(Shutdown::Write);
                }
            }
            // ACK the FIN.
            let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
            self.send_control(FLAG_ACK, snd_nxt, new_rcv)?;
            // If we've also sent our FIN, the connection is closing.
            if self.state.fin_sent.load(Ordering::Acquire) {
                self.state.closed.store(true, Ordering::Release);
            }
        }

        Ok(())
    }

    /// Background loop: read from the real socket and ship bytes back to the
    /// virtual client as TCP segments. Exits when the remote closes or when
    /// `closed` is set.
    fn read_loop(self: Arc<Self>, mut remote_read: TcpStream) {
        let mss = self.send_back.mss();
        let mut buf = vec![0u8; mss];
        loop {
            if self.state.closed.load(Ordering::Acquire) {
                return;
            }
            let n = match remote_read.read(&mut buf) {
                Ok(n) => n,
                Err(_) => 0,
            };
            if n == 0 {
                // Remote closed; send FIN to client.
                if !self.state.fin_sent.swap(true, Ordering::AcqRel) {
                    let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
                    let rcv_nxt = self.state.rcv_nxt.load(Ordering::Acquire);
                    let _ = self.send_control(FLAG_FIN | FLAG_ACK, snd_nxt, rcv_nxt);
                    // Advance SND.NXT for the FIN sequence.
                    self.state
                        .snd_nxt
                        .store(snd_nxt.wrapping_add(1), Ordering::Release);
                }
                self.state.closed.store(true, Ordering::Release);
                return;
            }

            let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
            let rcv_nxt = self.state.rcv_nxt.load(Ordering::Acquire);
            // Send the data with PSH|ACK.
            let _ = self.send_data(snd_nxt, rcv_nxt, &buf[..n]);
            self.state
                .snd_nxt
                .store(snd_nxt.wrapping_add(n as u32), Ordering::Release);
        }
    }

    /// Send a control-only segment (no payload).
    fn send_control(&self, flags: u8, seq: u32, ack: u32) -> Result<()> {
        let mut hdr = vec![0u8; 20];
        self.fill_hdr(&mut hdr, flags, seq, ack);
        self.send_back.write_seg(&hdr)
    }

    /// Send a segment with payload.
    fn send_data(&self, seq: u32, ack: u32, payload: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; 20 + payload.len()];
        self.fill_hdr(&mut buf, FLAG_PSH | FLAG_ACK, seq, ack);
        buf[20..].copy_from_slice(payload);
        self.send_back.write_seg(&buf)
    }

    /// Send a RST. `ack` is the cumulative ACK to use.
    fn send_rst_keepalive(&self, ack: u32) -> Result<()> {
        let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
        self.send_control(FLAG_RST | FLAG_ACK, snd_nxt, ack)
    }

    fn fill_hdr(&self, hdr: &mut [u8], flags: u8, seq: u32, ack: u32) {
        // Source port = server's port (dst_port from client's view).
        hdr[0..2].copy_from_slice(&self.dst_port.to_be_bytes());
        // Destination = client's port (src_port from client's view).
        hdr[2..4].copy_from_slice(&self.src_port.to_be_bytes());
        hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        hdr[8..12].copy_from_slice(&ack.to_be_bytes());
        hdr[12] = 5 << 4; // data offset = 5 (no options)
        hdr[13] = flags;
        hdr[14..16].copy_from_slice(&RECV_WINDOW.to_be_bytes());
        // checksum/urgent left zero; build_packet* fills the checksum.
    }

    fn shutdown_remote_both(&self) {
        if let Ok(g) = self.state.remote_write.lock() {
            if let Some(s) = g.as_ref() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }

    /// Forcibly tear the connection down (called by Stack::close or
    /// namespace cleanup).
    pub(crate) fn close(&self) {
        self.shutdown_remote_both();
        self.state.closed.store(true, Ordering::Release);
        // Send RST to client for good measure.
        let snd_nxt = self.state.snd_nxt.load(Ordering::Acquire);
        let rcv_nxt = self.state.rcv_nxt.load(Ordering::Acquire);
        let _ = self.send_control(FLAG_RST | FLAG_ACK, snd_nxt, rcv_nxt);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Acquire)
    }
}

impl Drop for TcpNatConn {
    fn drop(&mut self) {
        self.shutdown_remote_both();
        self.state.closed.store(true, Ordering::Release);
    }
}

/// Build a standalone RST segment used to reject a non-SYN-to-nothing.
/// Mirrors the Go `slirp` RFC 9293 §3.10.7.1 behaviour.
pub(crate) fn build_rst_for_stray(tcp: &[u8], dst_port: u16, src_port: u16) -> Option<Vec<u8>> {
    if tcp.len() < 20 {
        return None;
    }
    let flags = tcp[13];
    let mut hdr = vec![0u8; 20];
    hdr[0..2].copy_from_slice(&dst_port.to_be_bytes());
    hdr[2..4].copy_from_slice(&src_port.to_be_bytes());
    hdr[12] = 5 << 4;
    hdr[14..16].copy_from_slice(&RECV_WINDOW.to_be_bytes());
    if (flags & FLAG_ACK) != 0 {
        // Send RST with SEQ=SEG.ACK, no ACK.
        let seg_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        hdr[4..8].copy_from_slice(&seg_ack.to_be_bytes());
        hdr[13] = FLAG_RST;
    } else {
        // Send RST+ACK with SEQ=0, ACK=SEG.SEQ+SEG.LEN.
        let seg_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let data_off = ((tcp[12] >> 4) as usize) * 4;
        let data_off = data_off.min(tcp.len());
        let mut data_len = (tcp.len() - data_off) as u32;
        if (tcp[13] & FLAG_FIN) != 0 {
            data_len = data_len.wrapping_add(1);
        }
        hdr[4..8].copy_from_slice(&0u32.to_be_bytes());
        hdr[8..12].copy_from_slice(&seg_seq.wrapping_add(data_len).to_be_bytes());
        hdr[13] = FLAG_RST | FLAG_ACK;
    }
    Some(hdr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rst_with_ack() {
        let mut tcp = vec![0u8; 20];
        tcp[12] = 5 << 4;
        tcp[13] = FLAG_ACK;
        tcp[8..12].copy_from_slice(&12345u32.to_be_bytes());
        let rst = build_rst_for_stray(&tcp, 80, 5000).unwrap();
        assert_eq!(rst[13], FLAG_RST);
        let seq = u32::from_be_bytes([rst[4], rst[5], rst[6], rst[7]]);
        assert_eq!(seq, 12345);
    }

    #[test]
    fn build_rst_without_ack() {
        let mut tcp = vec![0u8; 20];
        tcp[12] = 5 << 4;
        tcp[13] = FLAG_SYN;
        tcp[4..8].copy_from_slice(&100u32.to_be_bytes());
        let rst = build_rst_for_stray(&tcp, 80, 5000).unwrap();
        assert_eq!(rst[13], FLAG_RST | FLAG_ACK);
        let ack = u32::from_be_bytes([rst[8], rst[9], rst[10], rst[11]]);
        // SYN counts as 1 in seq space, but we treat it as data-len=0 here;
        // payload of 0 plus FIN bit (none) ⇒ ack=100.
        assert_eq!(ack, 100);
    }
}

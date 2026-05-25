//! IPv4 UDP NAT.
//!
//! Each (srcIP, srcPort, dstIP, dstPort) tuple gets a real OS-level UDP
//! socket dialed to the destination. A background reader thread reads
//! responses and injects them back to the virtual client as IPv4+UDP
//! packets.

use crate::slirp::packet::build_udp_packet4;
use crate::Result;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A function that delivers a constructed IPv4 packet to the virtual client.
pub(crate) type SendFn = Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// How long the reader thread blocks in a single `recv` before re-checking the
/// stop flag. `std::net::UdpSocket` exposes no `shutdown(2)`, so we wake the
/// reader cooperatively rather than by closing the fd out from under it.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) struct UdpConn {
    c_src_ip: Ipv4Addr,
    c_src_port: u16,
    r_ip: Ipv4Addr,
    r_port: u16,
    socket: Arc<UdpSocket>,
    closed: Arc<AtomicBool>,
    pub(crate) last_act: Mutex<Instant>,
}

impl UdpConn {
    /// Open an outbound socket and spawn the read loop.
    pub(crate) fn new(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        send: SendFn,
    ) -> Result<Arc<UdpConn>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect((dst_ip, dst_port))?;
        // A bounded read timeout lets the reader thread observe `closed`
        // promptly without relying on closing the fd (std has no UDP shutdown).
        socket.set_read_timeout(Some(READ_TIMEOUT))?;
        let socket = Arc::new(socket);
        let closed = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(UdpConn {
            c_src_ip: src_ip,
            c_src_port: src_port,
            r_ip: dst_ip,
            r_port: dst_port,
            socket: socket.clone(),
            closed: closed.clone(),
            last_act: Mutex::new(Instant::now()),
        });

        let weak = Arc::downgrade(&conn);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                if closed.load(Ordering::Relaxed) {
                    return;
                }
                let n = match socket.recv(&mut buf) {
                    Ok(n) if n > 0 => n,
                    Ok(_) => continue,
                    // Timeout: loop back and re-check the stop flag.
                    Err(e)
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => return,
                };
                let conn = match weak.upgrade() {
                    Some(c) => c,
                    None => return,
                };
                let pkt = build_udp_packet4(
                    conn.r_ip,
                    conn.r_port,
                    conn.c_src_ip,
                    conn.c_src_port,
                    &buf[..n],
                );
                let _ = send(&pkt);
                {
                    if let Ok(mut t) = conn.last_act.lock() {
                        *t = Instant::now();
                    }
                }
                drop(conn);
            }
        });

        Ok(conn)
    }

    /// Handle an outbound UDP datagram coming from the virtual client.
    /// `ip` is the full IPv4 packet; `ihl` is the IPv4 header length.
    pub(crate) fn handle_outbound(&self, ip: &[u8], ihl: usize) {
        if ip.len() < ihl + 8 {
            return;
        }
        let udp = &ip[ihl..];
        if udp.len() < 8 {
            return;
        }
        let payload = &udp[8..];
        if !payload.is_empty() {
            let _ = self.socket.send(payload);
        }
        if let Ok(mut t) = self.last_act.lock() {
            *t = Instant::now();
        }
    }

    pub(crate) fn close(&self) {
        // `std::net::UdpSocket` offers no `shutdown(2)` and slirp stays
        // libc-free, so we cannot unblock the reader by tearing down the fd.
        // Instead the reader uses a bounded read timeout (READ_TIMEOUT) and
        // polls this flag, so it exits cleanly within one timeout window.
        self.closed.store(true, Ordering::Relaxed);
    }
}

impl Drop for UdpConn {
    fn drop(&mut self) {
        self.close();
    }
}

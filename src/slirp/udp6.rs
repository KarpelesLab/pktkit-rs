//! IPv6 UDP NAT, mirroring [`udp`](super::udp) for IPv6.

use crate::Result;
use crate::slirp::packet::{build_udp_packet6, fit_link};
use crate::slirp::udp::is_transient;
use crate::time::Instant;
use std::net::{Ipv6Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) type SendFn = Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// How long the reader thread blocks in a single `recv` before re-checking the
/// stop flag. `std::net::UdpSocket` exposes no `shutdown(2)`, so we wake the
/// reader cooperatively rather than by closing the fd out from under it.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) struct UdpConn6 {
    c_src_ip: Ipv6Addr,
    c_src_port: u16,
    r_ip: Ipv6Addr,
    r_port: u16,
    socket: Arc<UdpSocket>,
    closed: Arc<AtomicBool>,
    pub(crate) last_act: Mutex<Instant>,
}

impl UdpConn6 {
    pub(crate) fn new(
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
        send: SendFn,
    ) -> Result<Arc<UdpConn6>> {
        let socket = UdpSocket::bind("[::]:0")?;
        socket.connect((dst_ip, dst_port))?;
        // A bounded read timeout lets the reader thread observe `closed`
        // promptly without relying on closing the fd (std has no UDP shutdown).
        socket.set_read_timeout(Some(READ_TIMEOUT))?;
        let socket = Arc::new(socket);
        let closed = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(UdpConn6 {
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
            // Room for the largest datagram, so none is silently cut short.
            let mut buf = vec![0u8; 65535];
            loop {
                if closed.load(Ordering::Relaxed) {
                    return;
                }
                let n = match socket.recv(&mut buf) {
                    // Zero-length datagrams are valid and relayed too.
                    Ok(n) => n,
                    // Timeout: loop back and re-check the stop flag.
                    Err(e) if is_transient(&e) => continue,
                    Err(_) => {
                        // Mark the flow dead so the next datagram from the
                        // client opens a fresh one instead of feeding a flow
                        // that can no longer answer.
                        closed.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                let conn = match weak.upgrade() {
                    Some(c) => c,
                    None => return,
                };
                let pkt = build_udp_packet6(
                    conn.r_ip,
                    conn.r_port,
                    conn.c_src_ip,
                    conn.c_src_port,
                    &buf[..n],
                );
                for p in fit_link(pkt) {
                    let _ = send(&p);
                }
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

    pub(crate) fn handle_outbound(&self, packet: &[u8], transport_off: usize) {
        if packet.len() < transport_off + 8 {
            return;
        }
        let udp = &packet[transport_off..];
        if udp.len() < 8 {
            return;
        }
        // The UDP length, not the IP payload, bounds the datagram: anything
        // past it is link padding. An empty payload is a valid datagram.
        let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if len < 8 || len > udp.len() {
            return;
        }
        let _ = self.socket.send(&udp[8..len]);
        if let Ok(mut t) = self.last_act.lock() {
            *t = Instant::now();
        }
    }

    /// True once the flow has been closed or its reader has died.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub(crate) fn close(&self) {
        // `std::net::UdpSocket` offers no `shutdown(2)` and slirp stays
        // libc-free, so we cannot unblock the reader by tearing down the fd.
        // Instead the reader uses a bounded read timeout (READ_TIMEOUT) and
        // polls this flag, so it exits cleanly within one timeout window.
        self.closed.store(true, Ordering::Relaxed);
    }
}

impl Drop for UdpConn6 {
    fn drop(&mut self) {
        self.close();
    }
}

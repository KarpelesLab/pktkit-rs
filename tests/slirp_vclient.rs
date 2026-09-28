//! End-to-end: a `vclient::Client` inside the virtual network, wired to a
//! `slirp::Stack` with `connect_l3`, talks through it to listeners of the
//! stack and to real sockets on the host.
#![cfg(all(feature = "slirp", feature = "vclient"))]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pktkit::vclient::{Client, ClientConfig};
use pktkit::{IpPrefix, L3Device, L3Handler, Packet, connect_l3};

const STACK_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// `connect_l3` takes its second device by value.
#[derive(Debug)]
struct Shared(Arc<Client>);

impl L3Device for Shared {
    fn set_handler(&self, h: L3Handler) {
        self.0.set_handler(h)
    }
    fn send(&self, p: &Packet) -> pktkit::Result<()> {
        self.0.send(p)
    }
    fn addr(&self) -> IpPrefix {
        self.0.addr()
    }
    fn set_addr(&self, p: IpPrefix) -> pktkit::Result<()> {
        self.0.set_addr(p)
    }
    fn close(&self) -> pktkit::Result<()> {
        self.0.close()
    }
}

fn topology() -> (Arc<pktkit::slirp::Stack>, Arc<Client>) {
    let stack = pktkit::slirp::Stack::new();
    stack
        .set_addr(IpPrefix::new(IpAddr::V4(STACK_IP), 24))
        .unwrap();
    let client =
        Client::new(ClientConfig::default().prefix(IpPrefix::new(IpAddr::V4(CLIENT_IP), 24)));
    connect_l3(stack.clone(), Shared(client.clone()));
    (stack, client)
}

/// A burst of clients completing their handshakes faster than the
/// application accepts overflows the accept queue: the connections past it
/// wait to be accepted, as on Linux, rather than being reset.
#[test]
fn a_burst_of_dials_to_a_slow_acceptor_is_not_reset() {
    const DIALS: usize = 400;
    let (stack, client) = topology();
    let listener = stack.listen("tcp", &format!("{STACK_IP}:8080")).unwrap();
    std::thread::spawn(move || {
        while let Ok(s) = listener.accept() {
            std::thread::sleep(Duration::from_millis(2));
            std::thread::spawn(move || {
                let mut b = [0u8; 16];
                let n = s.read(&mut b).unwrap_or(0);
                let _ = s.write(&b[..n]);
            });
        }
    });
    let dials: Vec<_> = (0..DIALS)
        .map(|i| {
            let client = client.clone();
            std::thread::spawn(move || -> Result<(), String> {
                let dest = SocketAddr::from((STACK_IP, 8080));
                let c = client
                    .dial_tcp_timeout(dest, Duration::from_secs(30))
                    .map_err(|e| format!("dial {i}: {e}"))?;
                c.set_read_timeout(Some(Duration::from_secs(30)));
                c.write(b"ping").map_err(|e| format!("write {i}: {e}"))?;
                let mut b = [0u8; 16];
                match c.read(&mut b) {
                    Ok(4) if &b[..4] == b"ping" => Ok(()),
                    r => Err(format!("read {i}: {r:?}")),
                }
            })
        })
        .collect();
    let errors: Vec<String> = dials
        .into_iter()
        .filter_map(|d| d.join().unwrap().err())
        .collect();
    assert!(
        errors.is_empty(),
        "{} of {DIALS} failed: {:?}",
        errors.len(),
        &errors[..errors.len().min(5)]
    );
}

/// A host server that aborts mid-stream reaches the guest as a reset: a
/// clean end of stream would pass the truncated transfer off as whole.
#[test]
fn a_server_reset_reaches_the_guest_as_a_reset() {
    let (_stack, client) = topology();
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut s, _) = server.accept().unwrap();
        let _ = s.write_all(&vec![7u8; 200_000]);
        // Closing a socket with received data left unread resets the
        // connection (RFC 2525 §2.17): an abort std alone can make.
        let mut b = [0u8; 1];
        let _ = s.peek(&mut b);
        drop(s);
    });
    let mut c = client
        .dial_tcp(SocketAddr::from(([127, 0, 0, 1], port)))
        .unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10)));
    c.write_all(b"unread").unwrap();
    let mut got = Vec::new();
    let r = c.read_to_end(&mut got);
    assert!(
        r.is_err(),
        "an aborted transfer read as a clean end of stream after {} bytes",
        got.len()
    );
}

/// A dial through a stack that has been shut down fails at once, rather
/// than after the whole connect timeout.
#[test]
fn a_dial_through_a_shut_down_stack_fails_fast() {
    let (stack, client) = topology();
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dest = server.local_addr().unwrap();
    stack.shutdown().unwrap();
    let started = std::time::Instant::now();
    let r = client.dial_tcp_timeout(dest, Duration::from_secs(10));
    assert!(r.is_err(), "dialed through a shut-down stack");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?} to fail",
        started.elapsed()
    );
    let listener = stack.listen("tcp", &format!("{STACK_IP}:8080"));
    assert!(listener.is_err());
    let r = client.dial_tcp_timeout(SocketAddr::from((STACK_IP, 8080)), Duration::from_secs(10));
    assert!(r.is_err());
    assert!(started.elapsed() < Duration::from_secs(4));
}

/// A datagram to a closed host port fails the guest socket's `recv` with
/// `ConnectionRefused` as soon as the stack's port unreachable comes back,
/// rather than after the whole read timeout; the socket stays usable.
#[test]
fn udp_to_a_closed_host_port_is_refused() {
    let (_stack, client) = topology();
    // A port that was just free: nothing listens on it.
    let dest = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let c = client.dial_udp(dest).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10)));
    let started = std::time::Instant::now();
    c.send(b"anyone?").unwrap();
    let err = c.recv(&mut [0; 16]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    // Reported once; the socket still sends.
    c.set_read_timeout(Some(Duration::from_millis(50)));
    let again = c.recv(&mut [0; 16]).unwrap_err();
    assert_eq!(again.kind(), std::io::ErrorKind::WouldBlock);
    c.send(b"still here").unwrap();
}

/// A host server that writes a message in two small pieces, with
/// TCP_NODELAY set, has both sent on to the guest as they come: the bridge
/// must not re-impose Nagle, which would hold the second piece until the
/// guest had acknowledged the first, a round trip later.
///
/// Timed where the pieces leave the stack rather than end to end: a busy CI
/// runner adds its own delays to a whole exchange, but not to the gap
/// between two segments sent milliseconds apart.
#[cfg(feature = "impair")]
#[test]
fn the_bridge_adds_no_nagle_delay_to_small_writes() {
    use pktkit::impair::{ImpairL3, Impairment};
    // A round trip on this link is 300 ms: a second piece held for the
    // first one's ACK would leave at least that long after it.
    const ONE_WAY: Duration = Duration::from_millis(150);
    let stack = pktkit::slirp::Stack::new();
    stack
        .set_addr(IpPrefix::new(IpAddr::V4(STACK_IP), 24))
        .unwrap();
    let client =
        Client::new(ClientConfig::default().prefix(IpPrefix::new(IpAddr::V4(CLIENT_IP), 24)));
    let link = ImpairL3::new(
        client.clone() as Arc<dyn L3Device>,
        Impairment::default().delay(ONE_WAY),
    );
    let sent: Sent = Arc::default();
    connect_l3(stack.clone(), Delayed(link, sent.clone()));

    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dest = server.local_addr().unwrap();
    let host = std::thread::spawn(move || {
        let (mut s, _) = server.accept().unwrap();
        s.set_nodelay(true).unwrap();
        // Once the guest has spoken the bridge is up, and each piece goes
        // out as it is written; before, both would wait in the socket for
        // the handshake to finish and leave together.
        let mut go = [0u8; 1];
        s.read_exact(&mut go).unwrap();
        s.write_all(&[1; 10]).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        s.write_all(&[2; 10]).unwrap();
        let mut b = [0u8; 1];
        s.read_exact(&mut b).unwrap();
    });
    let mut c = client.dial_tcp(dest).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10)));
    c.write_all(b"g").unwrap();
    let mut msg = [0u8; 20];
    c.read_exact(&mut msg).unwrap();
    c.write_all(b"k").unwrap();
    host.join().unwrap();

    // When the stack sent each byte of the message on (first copy only).
    let sent = sent.lock().unwrap();
    let mut at = Vec::new();
    for &(t, len) in sent.iter() {
        if at.len() < 20 {
            at.extend(std::iter::repeat_n(t, len.min(20 - at.len())));
        }
    }
    assert_eq!(at.len(), 20, "the message never left the stack");
    let gap = at[19] - at[0];
    assert!(
        gap < ONE_WAY,
        "the second piece left {gap:?} after the first: it waited on an ACK"
    );
}

/// When the stack sent a TCP segment toward the guest, and its payload size.
#[cfg(feature = "impair")]
type Sent = Arc<Mutex<Vec<(std::time::Instant, usize)>>>;

/// `connect_l3` takes its second device by value. Notes the TCP payloads
/// the stack sends through it.
#[cfg(feature = "impair")]
#[derive(Debug)]
struct Delayed(Arc<pktkit::impair::ImpairL3>, Sent);

#[cfg(feature = "impair")]
impl L3Device for Delayed {
    fn set_handler(&self, h: L3Handler) {
        self.0.set_handler(h)
    }
    fn send(&self, p: &Packet) -> pktkit::Result<()> {
        let b = p.as_bytes();
        if b.len() >= 40 && b[0] >> 4 == 4 && b[9] == 6 {
            let ihl = usize::from(b[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([b[2], b[3]]));
            let doff = b.get(ihl + 12).map_or(0, |d| usize::from(d >> 4) * 4);
            let len = total.saturating_sub(ihl + doff);
            if len > 0 {
                self.1
                    .lock()
                    .unwrap()
                    .push((std::time::Instant::now(), len));
            }
        }
        self.0.send(p)
    }
    fn addr(&self) -> IpPrefix {
        self.0.addr()
    }
    fn set_addr(&self, p: IpPrefix) -> pktkit::Result<()> {
        self.0.set_addr(p)
    }
    fn close(&self) -> pktkit::Result<()> {
        self.0.close()
    }
}

/// The guest's end of a narrower link: packets from the stack larger than
/// `mtu` are dropped at the hop and answered with a Packet Too Big, as an
/// IPv6 router must (RFC 8201), and never fragmented.
struct NarrowHop {
    client: Arc<Client>,
    to_stack: Mutex<Option<L3Handler>>,
    mtu: usize,
    too_big: Arc<AtomicUsize>,
}

impl std::fmt::Debug for NarrowHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NarrowHop").field("mtu", &self.mtu).finish()
    }
}

impl L3Device for NarrowHop {
    fn set_handler(&self, h: L3Handler) {
        *self.to_stack.lock().unwrap() = Some(h.clone());
        self.client.set_handler(h);
    }
    fn send(&self, p: &Packet) -> pktkit::Result<()> {
        if p.len() <= self.mtu {
            return self.client.send(p);
        }
        self.too_big.fetch_add(1, Ordering::Relaxed);
        let hop: IpAddr = "fd00::fe".parse().unwrap();
        let ptb = pktkit::icmp::packet_too_big(p, hop, self.mtu as u32).unwrap();
        let h = self.to_stack.lock().unwrap().clone();
        if let Some(h) = h {
            h(Packet::from_slice(&ptb))?;
        }
        Ok(())
    }
    fn addr(&self) -> IpPrefix {
        self.client.addr()
    }
    fn set_addr(&self, p: IpPrefix) -> pktkit::Result<()> {
        self.client.set_addr(p)
    }
    fn close(&self) -> pktkit::Result<()> {
        self.client.close()
    }
}

/// An IPv6 stack and client with a 1400-byte hop between them; the count
/// is of the Packet Too Big messages the hop has sent.
fn narrow_v6() -> (Arc<pktkit::slirp::Stack>, Arc<Client>, Arc<AtomicUsize>) {
    let stack = pktkit::slirp::Stack::new();
    stack
        .set_addr(IpPrefix::new("fd00::1".parse().unwrap(), 64))
        .unwrap();
    let client =
        Client::new(ClientConfig::default().prefix(IpPrefix::new("fd00::2".parse().unwrap(), 64)));
    let too_big = Arc::new(AtomicUsize::new(0));
    let hop = NarrowHop {
        client: client.clone(),
        to_stack: Mutex::default(),
        mtu: 1400,
        too_big: too_big.clone(),
    };
    connect_l3(stack.clone(), hop);
    (stack, client, too_big)
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// A download from the host through the stack to a guest behind a
/// narrower IPv6 hop completes: the stack takes the hop's Packet Too Big
/// and cuts the bridge's segments to fit, rather than resend, for good,
/// segments the hop can never forward.
#[test]
fn a_v6_download_through_a_narrower_hop_completes() {
    let (_stack, client, too_big) = narrow_v6();
    let Ok(server) = std::net::TcpListener::bind("[::1]:0") else {
        return; // no IPv6 loopback on this host
    };
    let dest = server.local_addr().unwrap();
    let data = pattern(1 << 20);
    let sent = data.clone();
    std::thread::spawn(move || {
        let (mut s, _) = server.accept().unwrap();
        s.write_all(&sent).unwrap();
    });
    let mut c = client.dial_tcp(dest).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20)));
    let mut got = vec![0u8; data.len()];
    c.read_exact(&mut got).expect("download stalled");
    assert!(got == data, "download corrupted");
    assert!(too_big.load(Ordering::Relaxed) > 0);
}

/// The same for a connection a guest opens to one of the stack's own
/// listeners, which the application then writes to.
#[test]
fn a_v6_listener_write_through_a_narrower_hop_completes() {
    let (stack, client, too_big) = narrow_v6();
    let listener = stack.listen6("[fd00::1]:8080").unwrap();
    let data = pattern(1 << 20);
    let sent = data.clone();
    std::thread::spawn(move || {
        let mut s = listener.accept().unwrap();
        s.write_all(&sent).unwrap();
        // Held until the guest has it all: dropping the stream closes it.
        std::thread::sleep(Duration::from_secs(30));
    });
    let mut c = client.dial_tcp("[fd00::1]:8080".parse().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20)));
    let mut got = vec![0u8; data.len()];
    c.read_exact(&mut got).expect("transfer stalled");
    assert!(got == data, "transfer corrupted");
    assert!(too_big.load(Ordering::Relaxed) > 0);
}

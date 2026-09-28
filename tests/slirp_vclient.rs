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

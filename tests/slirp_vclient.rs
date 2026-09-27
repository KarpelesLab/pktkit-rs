//! End-to-end: a `vclient::Client` inside the virtual network, wired to a
//! `slirp::Stack` with `connect_l3`, talks through it to listeners of the
//! stack and to real sockets on the host.
#![cfg(all(feature = "slirp", feature = "vclient"))]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
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

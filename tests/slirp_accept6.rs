//! End-to-end (IPv6): a host inside the virtual network connects to a port the
//! application opened via `slirp::Stack::listen6`. We play the role of the
//! virtual client with our own `vtcp::Conn`, inject its segments into the stack
//! as IPv6 packets, and route the stack's emitted packets back into the client.
//! `Listener6::accept()` should yield a `slirp::TcpStream`, after which we
//! exchange data in both directions. This mirrors `tests/slirp_accept.rs`.
#![cfg(feature = "slirp")]

use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pktkit::vtcp::segment::Segment;
use pktkit::vtcp::{Conn, ConnConfig, State};
use pktkit::{IpPrefix, L3Device, Packet, Protocol};

const CLIENT_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5); // peer in net
const SERVER_IP: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1); // stack addr
const SERVER_PORT: u16 = 8080;
const CLIENT_PORT: u16 = 51000;

/// Wrap a marshaled TCP segment from `src` to `dst` in a minimal IPv6 packet.
/// The stack reads the addresses/payload-length and parses the TCP segment; it
/// does not require the TCP checksum to be valid here.
fn wrap(src: Ipv6Addr, dst: Ipv6Addr, seg: &[u8]) -> Vec<u8> {
    let total = 40 + seg.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(seg.len() as u16).to_be_bytes());
    ip[6] = Protocol::TCP.as_u8(); // next header
    ip[7] = 64; // hop limit
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip[40..].copy_from_slice(seg);
    ip
}

#[test]
fn inbound_accept_handshake_and_bidirectional_data_v6() {
    let stack = pktkit::slirp::Stack::new();
    stack
        .set_addr(IpPrefix::new(IpAddr::V6(SERVER_IP), 64))
        .unwrap();

    // Register the virtual IPv6 listener.
    let listener = stack
        .listen6(&format!("[{SERVER_IP}]:{SERVER_PORT}"))
        .unwrap();

    // The virtual client (the host connecting *to* our listener).
    let client = Arc::new(Mutex::new(Conn::new(ConnConfig {
        local_port: CLIENT_PORT,
        remote_port: SERVER_PORT,
        mss: 1440,
        ..Default::default()
    })));

    // The stack pushes packets it wants to send out via its L3 handler. Those
    // packets are destined for the client: parse the TCP segment and feed it
    // into the client conn. Any reply the client produces is wrapped and
    // injected back into the stack.
    let stack_for_handler = stack.clone();
    let client_for_handler = client.clone();
    stack.set_handler(Arc::new(move |pkt: &Packet| {
        let bytes = pkt.as_bytes();
        // IPv6 + TCP only in this test.
        if bytes.len() < 60 || (bytes[0] >> 4) != 6 || bytes[6] != Protocol::TCP.as_u8() {
            return Ok(());
        }
        let seg = match Segment::parse(&bytes[40..]) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        let replies = {
            let mut c = client_for_handler.lock().unwrap();
            c.handle_segment(&seg)
        };
        for r in replies {
            let ip = wrap(CLIENT_IP, SERVER_IP, &r);
            let _ = stack_for_handler.send(Packet::from_slice(&ip));
        }
        Ok(())
    }));

    // Kick off the client's active open: SYN → stack.
    {
        let segs = client.lock().unwrap().connect();
        for s in segs {
            let ip = wrap(CLIENT_IP, SERVER_IP, &s);
            stack.send(Packet::from_slice(&ip)).unwrap();
        }
    }
    // The SYN-ACK was delivered to the client synchronously inside `send`, the
    // client's ACK was injected back, and the server-side conn should reach
    // ESTABLISHED. Confirm the client also reached ESTABLISHED.
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if client.lock().unwrap().state() == State::Established {
                break;
            }
            assert!(Instant::now() < deadline, "client never established");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // accept() blocks until the stack's waiter thread observes ESTABLISHED.
    let server_conn = {
        let l = listener.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(l.accept());
        });
        rx.recv_timeout(Duration::from_secs(3))
            .expect("accept timed out")
            .expect("accept failed")
    };

    assert_eq!(server_conn.local_addr().port(), SERVER_PORT);
    assert_eq!(server_conn.peer_addr().port(), CLIENT_PORT);
    assert_eq!(server_conn.peer_addr().ip(), IpAddr::V6(CLIENT_IP));

    // Server → client: write data, which the handler feeds into the client.
    server_conn.write(b"hello from server").unwrap();

    // Read it on the client side. The data segment reached the client conn via
    // the handler when the server wrote; poll until it surfaces.
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = [0u8; 64];
        let got = loop {
            let n = client.lock().unwrap().read(&mut buf);
            if n > 0 {
                break buf[..n].to_vec();
            }
            assert!(
                Instant::now() < deadline,
                "client never received server data"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(&got, b"hello from server");
        // Ack the data back to the server.
        let acks = {
            // A read alone doesn't emit an ACK; tick to flush the delayed ACK.
            let mut c = client.lock().unwrap();
            c.tick()
        };
        for a in acks {
            let ip = wrap(CLIENT_IP, SERVER_IP, &a);
            stack.send(Packet::from_slice(&ip)).unwrap();
        }
    }

    // Client → server: write data into the client conn, inject segments.
    {
        let (n, segs) = client.lock().unwrap().write(b"hi from client");
        assert_eq!(n, b"hi from client".len());
        for s in segs {
            let ip = wrap(CLIENT_IP, SERVER_IP, &s);
            stack.send(Packet::from_slice(&ip)).unwrap();
        }
    }

    // Read it on the server side.
    server_conn.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 64];
    let n = server_conn.read(&mut buf).expect("server read");
    assert!(n > 0, "expected client data on server side");
    assert_eq!(&buf[..n], b"hi from client");

    let _ = server_conn.close();
    let _ = listener.close();
    let _ = stack.shutdown();
}

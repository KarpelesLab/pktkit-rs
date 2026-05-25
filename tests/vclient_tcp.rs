//! End-to-end: a `vclient::Client` dials a server-side `vtcp::Conn`, the two
//! exchange data. Packets are routed between them in-process — the client's
//! L3 handler hands outbound packets to the server engine, and the server's
//! segments are wrapped back into IP and pushed into the client.
#![cfg(feature = "vclient")]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pktkit::vtcp::segment::Segment;
use pktkit::vtcp::{Conn, ConnConfig};
use pktkit::{IpPrefix, L3Device, Packet, Protocol};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_PORT: u16 = 80;

/// Wrap a marshaled TCP segment from `src` to `dst` in a minimal IPv4 packet.
fn wrap(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> Vec<u8> {
    let total = 20 + seg.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::TCP.as_u8();
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cs = pktkit::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    ip[20..].copy_from_slice(seg);
    ip
}

#[test]
fn dial_handshake_and_bidirectional_data() {
    // Server-side vtcp connection in LISTEN-ish posture (Closed → accept_syn).
    let server = Arc::new(Mutex::new(Conn::new(ConnConfig {
        local_port: SERVER_PORT,
        remote_port: 0, // learned from the SYN
        ..Default::default()
    })));

    // The client: when it emits a packet, feed it to the server engine. The
    // server's response segments are wrapped and pushed back into the client.
    let client = pktkit::vclient::Client::new(pktkit::vclient::ClientConfig {
        prefix: Some(IpPrefix::new(IpAddr::V4(CLIENT_IP), 24)),
        dns: vec![],
    });

    // Stash a weak ref so the handler can push packets back into the client.
    let client_for_handler = client.clone();
    let server_for_handler = server.clone();

    client.set_handler(Arc::new(move |pkt: &Packet| {
        // Outbound packet from client → server. Extract the TCP segment.
        let seg = Segment::parse(pkt.payload()).expect("valid segment");
        let mut srv = server_for_handler.lock().unwrap();
        // Set the server's remote port from the first SYN we see.
        let resp = if srv.state() == pktkit::vtcp::State::Closed
            && seg.has_flag(pktkit::vtcp::segment::flags::SYN)
            && !seg.has_flag(pktkit::vtcp::segment::flags::ACK)
        {
            // Re-create the server conn now that we know the client's port.
            *srv = Conn::new(ConnConfig {
                local_port: SERVER_PORT,
                remote_port: seg.src_port,
                ..Default::default()
            });
            srv.accept_syn(&seg)
        } else {
            srv.handle_segment(&seg)
        };
        drop(srv);
        // Wrap each server segment in IP and deliver to the client.
        for s in resp {
            let ip = wrap(SERVER_IP, CLIENT_IP, &s);
            let _ = client_for_handler.send(Packet::from_slice(&ip));
        }
        Ok(())
    }));

    // Dial.
    let conn = client
        .dial_tcp_timeout(
            SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT),
            Duration::from_secs(2),
        )
        .expect("dial should succeed");

    assert_eq!(conn.peer_addr(), SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT));

    // Client → server.
    let mut conn = conn;
    conn.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();

    // Give the server the data and have it reply.
    // The write already drove the segment to the server via the handler; the
    // server buffered it. Now push a server response.
    {
        let mut srv = server.lock().unwrap();
        let (_n, segs) = srv.write(b"HTTP/1.0 200 OK\r\n\r\nhi");
        drop(srv);
        for s in segs {
            let ip = wrap(SERVER_IP, CLIENT_IP, &s);
            let _ = client.send(Packet::from_slice(&ip));
        }
    }

    // Read the server's response.
    conn.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert!(n > 0, "expected server data");
    let got = String::from_utf8_lossy(&buf[..n]);
    assert!(got.contains("200 OK"), "got: {got:?}");
}

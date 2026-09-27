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
    // The remote port is learned from the SYN.
    let server = Arc::new(Mutex::new(Conn::new(
        ConnConfig::default().local_port(SERVER_PORT),
    )));

    // The client: when it emits a packet, feed it to the server engine. The
    // server's response segments are wrapped and pushed back into the client.
    let client = pktkit::vclient::Client::new(
        pktkit::vclient::ClientConfig::default().prefix(IpPrefix::new(IpAddr::V4(CLIENT_IP), 24)),
    );

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
            *srv = Conn::new(
                ConnConfig::default()
                    .local_port(SERVER_PORT)
                    .remote_port(seg.src_port),
            );
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

    assert_eq!(
        conn.peer_addr(),
        SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT)
    );

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

const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const PEER_PORT: u16 = 50000;
const LISTEN_PORT: u16 = 8080;

#[test]
fn listen_accept_and_bidirectional_data() {
    // The vclient `Client` is the *server*: it listens. A remote `vtcp::Conn`
    // acts as the connecting client ("peer").
    let client = pktkit::vclient::Client::new(
        pktkit::vclient::ClientConfig::default().prefix(IpPrefix::new(IpAddr::V4(CLIENT_IP), 24)),
    );

    let peer = Arc::new(Mutex::new(Conn::new(
        ConnConfig::default()
            .local_port(PEER_PORT)
            .remote_port(LISTEN_PORT)
            .local_addr(SocketAddr::new(IpAddr::V4(PEER_IP), PEER_PORT))
            .remote_addr(SocketAddr::new(IpAddr::V4(CLIENT_IP), LISTEN_PORT))
            .mss(1460),
    )));

    // Client's outbound packets (server side) are delivered to the peer, and
    // the peer's responses wrapped back into the client.
    let client_for_handler = client.clone();
    let peer_for_handler = peer.clone();
    client.set_handler(Arc::new(move |pkt: &Packet| {
        let seg = Segment::parse(pkt.payload()).expect("valid segment");
        let resp = peer_for_handler.lock().unwrap().handle_segment(&seg);
        for s in resp {
            let ip = wrap(PEER_IP, CLIENT_IP, &s);
            let _ = client_for_handler.send(Packet::from_slice(&ip));
        }
        Ok(())
    }));

    let listener = client.listen_tcp(LISTEN_PORT).unwrap();
    assert_eq!(
        listener.local_addr(),
        SocketAddr::new(IpAddr::V4(CLIENT_IP), LISTEN_PORT)
    );

    // Drive the handshake: peer SYN → client accepts → SYN-ACK → peer ACK.
    // This whole exchange runs synchronously through the handler.
    let syns = peer.lock().unwrap().connect();
    for s in syns {
        let ip = wrap(PEER_IP, CLIENT_IP, &s);
        client.send(Packet::from_slice(&ip)).unwrap();
    }

    // The handshake completed inline, which queued the connection on the
    // listener.
    let mut accepted = listener.accept().expect("accept");
    assert_eq!(
        accepted.peer_addr(),
        SocketAddr::new(IpAddr::V4(PEER_IP), PEER_PORT)
    );

    // Peer → server.
    {
        let (_n, segs) = peer.lock().unwrap().write(b"ping from peer");
        for s in segs {
            let ip = wrap(PEER_IP, CLIENT_IP, &s);
            client.send(Packet::from_slice(&ip)).unwrap();
        }
    }
    accepted.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 64];
    let n = accepted.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping from peer");

    // Server → peer (writing auto-delivers to the peer via the handler).
    accepted.write_all(b"pong from server").unwrap();
    let mut got = Vec::new();
    for _ in 0..50 {
        let mut b = [0u8; 64];
        let r = peer.lock().unwrap().read(&mut b);
        if r > 0 {
            got.extend_from_slice(&b[..r]);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&got, b"pong from server");
}

fn client(last_octet: u8) -> Arc<pktkit::vclient::Client> {
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet));
    pktkit::vclient::Client::new(
        pktkit::vclient::ClientConfig::default().prefix(IpPrefix::new(ip, 24)),
    )
}

/// The shape wasm uses: nothing waits, nothing runs in the background. Two
/// clients wired back to back complete the handshake synchronously, the
/// listener hands over the connection as soon as it is established, and
/// every call answers `WouldBlock` rather than waiting.
#[test]
fn nonblocking_dial_accept_and_data() {
    use std::io::ErrorKind::WouldBlock;

    let (a, b) = (client(1), client(2));
    let listener = b.listen_tcp(LISTEN_PORT).unwrap();
    listener.set_nonblocking(true);
    assert_eq!(listener.accept().unwrap_err().kind(), WouldBlock);

    pktkit::connect_l3(a.clone(), b.clone());
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), LISTEN_PORT);
    let conn = a.dial_tcp_nonblocking(dst).unwrap();
    assert!(
        conn.poll_connect().unwrap(),
        "handshake runs inline over a direct wire"
    );

    let accepted = listener.accept().expect("established connection is queued");
    accepted.set_nonblocking(true);
    let mut buf = [0u8; 64];
    assert_eq!(accepted.read(&mut buf).unwrap_err().kind(), WouldBlock);

    assert_eq!(conn.write(b"hello").unwrap(), 5);
    assert_eq!(accepted.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");

    accepted.write(b"bye").unwrap();
    accepted.close().unwrap();
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"bye");
    assert_eq!(conn.read(&mut buf).unwrap(), 0, "FIN reads as EOF");
    a.tick();
    b.tick();
}

#[test]
fn nonblocking_dial_reports_progress() {
    use std::io::ErrorKind::WouldBlock;

    // No wire: the SYN goes nowhere, so the handshake stays in progress.
    let a = client(1);
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), LISTEN_PORT);
    let conn = a.dial_tcp_nonblocking(dst).unwrap();
    assert!(!conn.poll_connect().unwrap());
    assert_eq!(conn.write(b"early").unwrap_err().kind(), WouldBlock);
    let mut buf = [0u8; 8];
    assert_eq!(conn.read(&mut buf).unwrap_err().kind(), WouldBlock);
}

/// A connection whose handshake completes after its listener has closed
/// cannot be accepted by anyone: it must be reset, not left established.
#[test]
fn handshake_completing_after_listener_closed_is_reset() {
    let client = client(2);
    let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let s = sent.clone();
    client.set_handler(Arc::new(move |pkt: &Packet| {
        s.lock().unwrap().push(pkt.payload().to_vec());
        Ok(())
    }));
    let listener = client.listen_tcp(LISTEN_PORT).unwrap();
    let mut peer = Conn::new(
        ConnConfig::default()
            .local_port(PEER_PORT)
            .remote_port(LISTEN_PORT),
    );
    let deliver = |segs: Vec<Vec<u8>>| {
        for s in segs {
            client
                .send(Packet::from_slice(&wrap(PEER_IP, CLIENT_IP, &s)))
                .unwrap();
        }
    };
    deliver(peer.connect());
    let synack = sent.lock().unwrap().remove(0);

    listener.close();
    deliver(peer.handle_segment(&Segment::parse(&synack).unwrap()));
    assert_eq!(peer.state(), pktkit::vtcp::State::Established);
    let rst =
        sent.lock().unwrap().iter().any(|s| {
            Segment::parse(s).is_ok_and(|s| s.has_flag(pktkit::vtcp::segment::flags::RST))
        });
    assert!(rst, "the orphaned connection was not reset");
}

#[test]
fn dropping_a_closed_listener_leaves_its_successor_alone() {
    let client = client(2);
    let old = client.listen_tcp(LISTEN_PORT).unwrap();
    old.close();
    let _new = client.listen_tcp(LISTEN_PORT).unwrap();
    drop(old);
    assert_eq!(
        client.listen_tcp(LISTEN_PORT).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse,
        "the newer listener was unregistered"
    );
}

/// Closing the client tears down everything it has open and wakes whoever
/// is waiting on it; nothing new can be opened afterwards.
#[test]
fn close_wakes_waiters_and_refuses_new_work() {
    use std::sync::mpsc;

    let client = client(2);
    let _server = raw_server(&client, |_| Vec::new());
    let conn = client
        .dial_tcp_timeout(
            SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT),
            Duration::from_secs(2),
        )
        .unwrap();
    let listener = Arc::new(client.listen_tcp(LISTEN_PORT).unwrap());
    let udp = Arc::new(
        client
            .dial_udp(SocketAddr::new(IpAddr::V4(SERVER_IP), 53))
            .unwrap(),
    );

    let (tx, rx) = mpsc::channel();
    let t = tx.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8];
        let _ = t.send(("read", conn.read(&mut buf).map(|_| ())));
    });
    let (t, l) = (tx.clone(), listener.clone());
    std::thread::spawn(move || {
        let _ = t.send(("accept", l.accept().map(|_| ())));
    });
    let (t, u) = (tx, udp.clone());
    std::thread::spawn(move || {
        let mut buf = [0u8; 8];
        let _ = t.send(("recv", u.recv(&mut buf).map(|_| ())));
    });
    std::thread::sleep(Duration::from_millis(100));

    client.close().unwrap();
    for _ in 0..3 {
        let (what, res) = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("a waiter was not woken by close");
        assert!(res.is_err(), "{what} succeeded on a closed client");
    }
    let dst = SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT);
    assert!(
        client
            .dial_tcp_timeout(dst, Duration::from_millis(100))
            .is_err()
    );
    assert!(client.dial_tcp_nonblocking(dst).is_err());
    assert!(client.listen_tcp(LISTEN_PORT + 1).is_err());
    assert!(client.dial_udp(dst).is_err());
    assert!(udp.send(b"x").is_err());
}

/// A reset is not an end of stream: data that arrived is still read, and
/// then the reset is reported.
#[test]
fn reset_reads_as_an_error_not_eof() {
    let client = client(2);
    let _server = raw_server(&client, |c| {
        let mut out = c.write(b"partial").1;
        out.extend(c.abort());
        out
    });
    let conn = client
        .dial_tcp_timeout(
            SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT),
            Duration::from_secs(2),
        )
        .unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"partial");
    assert_eq!(
        conn.read(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::ConnectionReset
    );
}

/// Route `client`'s packets to a raw `vtcp::Conn` server on
/// `SERVER_IP:SERVER_PORT`, created on the first SYN. Once the handshake
/// completes, `on_established` runs on the server and its segments are sent.
fn raw_server(
    client: &Arc<pktkit::vclient::Client>,
    on_established: impl Fn(&mut Conn) -> Vec<Vec<u8>> + Send + Sync + 'static,
) -> Arc<Mutex<Option<Conn>>> {
    let server: Arc<Mutex<Option<Conn>>> = Arc::new(Mutex::new(None));
    let srv_for_handler = server.clone();
    let weak = Arc::downgrade(client);
    client.set_handler(Arc::new(move |pkt: &Packet| {
        let Ok(seg) = Segment::parse(pkt.payload()) else {
            return Ok(());
        };
        let out = {
            let mut srv = srv_for_handler.lock().unwrap();
            match srv.as_mut() {
                None => {
                    let mut c = Conn::new(
                        ConnConfig::default()
                            .local_port(SERVER_PORT)
                            .remote_port(seg.src_port),
                    );
                    let out = c.accept_syn(&seg);
                    *srv = Some(c);
                    out
                }
                Some(c) => {
                    let was = c.state();
                    let mut out = c.handle_segment(&seg);
                    if was != pktkit::vtcp::State::Established
                        && c.state() == pktkit::vtcp::State::Established
                    {
                        out.extend(on_established(c));
                    }
                    out
                }
            }
        };
        if let Some(client) = weak.upgrade() {
            for s in out {
                let _ = client.send(Packet::from_slice(&wrap(SERVER_IP, CLIENT_IP, &s)));
            }
        }
        Ok(())
    }));
    server
}

/// A server that answers the handshake, sends a little and closes at once:
/// by the time the dialer looks, the connection is already in CLOSE-WAIT.
#[test]
fn dial_succeeds_when_the_server_closes_straight_away() {
    let client = client(2);
    let _server = raw_server(&client, |c| {
        let mut out = c.write(b"bye").1;
        out.extend(c.close());
        out
    });
    let mut conn = client
        .dial_tcp_timeout(
            SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT),
            Duration::from_secs(2),
        )
        .expect("a handshake that completed is a successful dial");
    let mut got = Vec::new();
    std::io::Read::read_to_end(&mut conn, &mut got).unwrap();
    assert_eq!(got, b"bye");
}

/// The listening side closes first and so holds TIME-WAIT, which now lasts
/// long enough (60 s) that a client reusing its port will meet it. A SYN
/// numbered beyond the old connection takes the 4-tuple over, as in Linux
/// (RFC 6191), instead of being refused for a minute.
#[test]
fn a_new_syn_takes_over_a_4_tuple_in_time_wait() {
    let client = pktkit::vclient::Client::new(
        pktkit::vclient::ClientConfig::default().prefix(IpPrefix::new(IpAddr::V4(CLIENT_IP), 24)),
    );
    let new_peer = || {
        Conn::new(
            ConnConfig::default()
                .local_port(PEER_PORT)
                .remote_port(LISTEN_PORT)
                .local_addr(SocketAddr::new(IpAddr::V4(PEER_IP), PEER_PORT))
                .remote_addr(SocketAddr::new(IpAddr::V4(CLIENT_IP), LISTEN_PORT)),
        )
    };
    let peer = Arc::new(Mutex::new(new_peer()));
    let (c, p) = (client.clone(), peer.clone());
    client.set_handler(Arc::new(move |pkt: &Packet| {
        let seg = Segment::parse(pkt.payload()).expect("valid segment");
        let resp = p.lock().unwrap().handle_segment(&seg);
        for s in resp {
            let _ = c.send(Packet::from_slice(&wrap(PEER_IP, CLIENT_IP, &s)));
        }
        Ok(())
    }));
    let listener = client.listen_tcp(LISTEN_PORT).unwrap();
    listener.set_nonblocking(true);
    let send = |segs: Vec<Vec<u8>>| {
        for s in segs {
            client
                .send(Packet::from_slice(&wrap(PEER_IP, CLIENT_IP, &s)))
                .unwrap();
        }
    };

    // Each lock is dropped before sending: the handler takes it again as
    // the reply loops back through the synchronous link.
    let syn = peer.lock().unwrap().connect();
    send(syn);
    let first = listener.accept().expect("first connection");
    first.close().unwrap(); // the listening side's FIN goes first
    let fin = peer.lock().unwrap().close();
    send(fin);
    drop(first);

    // RFC 6528 ISNs advance with a 4 µs clock; let it move past the old
    // connection's sequence space, as any real reuse would.
    std::thread::sleep(Duration::from_millis(2));
    *peer.lock().unwrap() = new_peer();
    let syn = peer.lock().unwrap().connect();
    send(syn);
    let second = listener.accept().expect("the new SYN was refused");
    assert_eq!(
        second.peer_addr(),
        SocketAddr::new(IpAddr::V4(PEER_IP), PEER_PORT)
    );
}

/// After our own close a write can never go out: it fails at once with
/// `BrokenPipe`, as on a socket shut down for writing, rather than waiting
/// for a window no state past FIN-WAIT-1 will use.
#[test]
fn write_after_close_is_a_broken_pipe() {
    let client = client(2);
    let _server = raw_server(&client, |_| Vec::new());
    let conn = client
        .dial_tcp_timeout(
            SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT),
            Duration::from_secs(2),
        )
        .unwrap();
    conn.close().unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(2)));
    let start = std::time::Instant::now();
    let err = conn.write(b"late").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    assert!(start.elapsed() < Duration::from_secs(1));
}

/// Dropping a connection whose incoming data was never read resets it
/// rather than closing it gracefully: a FIN would tell the sender its bytes
/// were consumed (RFC 2525 §2.17), which is how Linux closes such a socket.
#[test]
fn dropping_a_connection_with_unread_data_resets_it() {
    use std::io::ErrorKind::ConnectionReset;

    let (a, b) = (client(1), client(2));
    let listener = b.listen_tcp(LISTEN_PORT).unwrap();
    listener.set_nonblocking(true);
    pktkit::connect_l3(a.clone(), b.clone());
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), LISTEN_PORT);
    let conn = a.dial_tcp_nonblocking(dst).unwrap();
    let accepted = listener.accept().unwrap();

    conn.write(b"never read").unwrap();
    drop(accepted);

    let mut buf = [0u8; 16];
    match conn.read(&mut buf) {
        Err(e) => assert_eq!(e.kind(), ConnectionReset),
        Ok(n) => panic!("read {n} bytes, expected a reset"),
    }
}

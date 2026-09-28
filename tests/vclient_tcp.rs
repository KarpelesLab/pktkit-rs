//! End-to-end: a `vclient::Client` dials a server-side `vtcp::Conn`, the two
//! exchange data. Packets are routed between them in-process — the client's
//! L3 handler hands outbound packets to the server engine, and the server's
//! segments are wrapped back into IP and pushed into the client.
#![cfg(feature = "vclient")]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pktkit::vtcp::Segment;
use pktkit::vtcp::{Conn, ConnConfig};
use pktkit::{IpPrefix, L3Device, Packet, Protocol};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_PORT: u16 = 80;

/// Wrap a marshaled TCP segment from `src` to `dst` in a minimal IPv4 packet,
/// with the TCP checksum the client verifies.
fn wrap(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> Vec<u8> {
    let mut seg = seg.to_vec();
    seg[16..18].fill(0);
    let tcp_cs = pktkit::transport_checksum(Protocol::TCP, src.into(), dst.into(), &seg);
    seg[16..18].copy_from_slice(&tcp_cs.to_be_bytes());
    let seg = &seg[..];
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
            && seg.has_flag(pktkit::vtcp::flags::SYN)
            && !seg.has_flag(pktkit::vtcp::flags::ACK)
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
    let rst = sent
        .lock()
        .unwrap()
        .iter()
        .any(|s| Segment::parse(s).is_ok_and(|s| s.has_flag(pktkit::vtcp::flags::RST)));
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
    conn.set_write_timeout(Some(Duration::from_secs(30)));
    let start = std::time::Instant::now();
    let err = conn.write(b"late").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    // Far below the timeout: failing at once, not after waiting it out.
    assert!(start.elapsed() < Duration::from_secs(10));
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

/// With `set_nodelay`, as on a `std::net::TcpStream`, a short write goes
/// out at once even while the one before it is unacknowledged.
#[test]
fn nodelay_sends_short_writes_without_waiting_for_an_ack() {
    let client = client(2);
    let _server = raw_server(&client, |_| Vec::new());
    let conn = client
        .dial_tcp_timeout(
            SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT),
            Duration::from_secs(2),
        )
        .unwrap();
    // From here on the server hears nothing, so no ACK comes back.
    let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let s = sent.clone();
    client.set_handler(Arc::new(move |pkt: &Packet| {
        if let Ok(seg) = Segment::parse(pkt.payload())
            && !seg.payload.is_empty()
        {
            s.lock().unwrap().push(seg.payload);
        }
        Ok(())
    }));
    assert!(!conn.nodelay().unwrap());
    conn.write(b"0123456789").unwrap();
    conn.write(b"abcdefghij").unwrap();
    assert_eq!(sent.lock().unwrap().len(), 1, "Nagle holds the second back");
    // Turning Nagle off sends what it held, and then every write at once.
    conn.set_nodelay(true).unwrap();
    assert!(conn.nodelay().unwrap());
    conn.write(b"klmnopqrst").unwrap();
    assert_eq!(
        *sent.lock().unwrap(),
        [&b"0123456789"[..], b"abcdefghij", b"klmnopqrst"]
    );
}

/// A listener whose application is slow to accept must not reset the
/// handshakes that complete while its accept queue is full: as Linux does
/// (`tcp_abort_on_overflow` = 0), it lets them wait, and each connection is
/// accepted once there is room.
#[test]
fn a_full_accept_queue_does_not_reset_connections() {
    use std::io::Read;

    const DIALS: usize = 400;
    let (a, b) = (client(2), client(3));
    let hub = Arc::new(pktkit::L3Hub::new());
    let _ha = hub.connect_arc(a.clone());
    let _hb = hub.connect_arc(b.clone());
    let listener = b.listen_tcp(LISTEN_PORT).unwrap();
    std::thread::spawn(move || {
        while let Ok(mut s) = listener.accept() {
            std::thread::sleep(Duration::from_millis(2));
            std::thread::spawn(move || {
                let mut v = Vec::new();
                s.set_read_timeout(Some(Duration::from_secs(60)));
                if s.read_to_end(&mut v).is_ok() {
                    let _ = s.write_all(&v);
                }
            });
        }
    });
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), LISTEN_PORT);
    let dials: Vec<_> = (0..DIALS)
        .map(|i| {
            let a = a.clone();
            std::thread::spawn(move || -> std::io::Result<()> {
                let mut c = a.dial_tcp_timeout(dst, Duration::from_secs(60))?;
                c.set_read_timeout(Some(Duration::from_secs(60)));
                let msg = vec![i as u8; 2000];
                c.write_all(&msg)?;
                c.close()?;
                let mut v = Vec::new();
                c.read_to_end(&mut v)?;
                assert!(v == msg, "connection {i} echoed the wrong data");
                Ok(())
            })
        })
        .collect();
    let errors: Vec<_> = dials
        .into_iter()
        .filter_map(|h| h.join().unwrap().err())
        .map(|e| e.kind())
        .collect();
    assert!(
        errors.is_empty(),
        "{} connections failed: {errors:?}",
        errors.len()
    );
}

/// Records the TCP data segments (SEQ, length) a client sends.
struct Sniff {
    dev: Arc<pktkit::vclient::Client>,
    log: Arc<Mutex<Vec<(u32, usize)>>>,
}

impl std::fmt::Debug for Sniff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sniff")
    }
}

impl L3Device for Sniff {
    fn set_handler(&self, h: pktkit::L3Handler) {
        let log = self.log.clone();
        self.dev.set_handler(Arc::new(move |p: &Packet| {
            if let Ok(seg) = Segment::parse(p.payload())
                && !seg.payload.is_empty()
            {
                log.lock().unwrap().push((seg.seq, seg.payload.len()));
            }
            h(p)
        }));
    }
    fn send(&self, p: &Packet) -> pktkit::Result<()> {
        self.dev.send(p)
    }
    fn addr(&self) -> IpPrefix {
        self.dev.addr()
    }
    fn set_addr(&self, p: IpPrefix) -> pktkit::Result<()> {
        self.dev.set_addr(p)
    }
    fn close(&self) -> pktkit::Result<()> {
        self.dev.close()
    }
}

/// Over a synchronous link every send runs the peer, and the peer's ACK
/// comes back on the same stack, into the sender, before the rest of the
/// sender's burst has gone out. The segments that ACK releases must still
/// go out after that burst, not ahead of it: out of order, every burst
/// looks like loss, and throughput collapses to a few Mbit/s of RTOs.
#[test]
fn bulk_transfer_over_a_synchronous_hub_stays_in_order() {
    use std::io::Read;

    const SIZE: usize = 8 << 20;
    let (a, b) = (client(2), client(3));
    let hub = Arc::new(pktkit::L3Hub::new());
    let log: Arc<Mutex<Vec<(u32, usize)>>> = Arc::default();
    let _ha = hub.connect(Sniff {
        dev: a.clone(),
        log: Arc::default(),
    });
    let _hb = hub.connect(Sniff {
        dev: b.clone(),
        log: log.clone(),
    });
    let listener = b.listen_tcp(LISTEN_PORT).unwrap();
    let data: Vec<u8> = (0..SIZE).map(|i| (i * 7 + i / 4096) as u8).collect();
    let sent = data.clone();
    let server = std::thread::spawn(move || {
        let mut s = listener.accept().unwrap();
        s.write_all(&sent).unwrap();
        s
    });
    let start = std::time::Instant::now();
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), LISTEN_PORT);
    let mut conn = a.dial_tcp(dst).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(60)));
    let mut got = vec![0u8; SIZE];
    conn.read_exact(&mut got).unwrap();
    let took = start.elapsed();
    let _server = server.join().unwrap();
    assert!(got == data, "the stream arrived corrupted");

    // Nothing was lost, so every data segment starts where the last ended.
    let log = log.lock().unwrap();
    let out_of_order = log
        .windows(2)
        .filter(|w| w[1].0 != w[0].0.wrapping_add(w[0].1 as u32))
        .count();
    assert_eq!(out_of_order, 0, "segments left out of order");
    let limit = if cfg!(debug_assertions) { 20 } else { 2 };
    assert!(
        took < Duration::from_secs(limit),
        "8 MiB took {took:?} over a lossless link"
    );
}

/// Wire `a` and `b` back to back through a router whose link carries at
/// most `mtu` bytes: anything larger is dropped and answered with an ICMP
/// Packet Too Big (or Fragmentation Needed) from `router`. Returns the
/// count of those sent, and the largest packet that got through.
fn narrow_link(
    a: &Arc<pktkit::vclient::Client>,
    b: &Arc<pktkit::vclient::Client>,
    router: IpAddr,
    mtu: usize,
) -> (
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (too_big, largest) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    for (from, to) in [(a, b), (b, a)] {
        let (from_w, to_w) = (Arc::downgrade(from), Arc::downgrade(to));
        let (too_big, largest) = (too_big.clone(), largest.clone());
        from.set_handler(Arc::new(move |p: &Packet| {
            if p.len() <= mtu {
                largest.fetch_max(p.len(), Ordering::Relaxed);
                if let Some(to) = to_w.upgrade() {
                    let _ = to.send(p);
                }
            } else if let (Some(ptb), Some(from)) = (
                pktkit::icmp::packet_too_big(p, router, mtu as u32),
                from_w.upgrade(),
            ) {
                too_big.fetch_add(1, Ordering::Relaxed);
                let _ = from.send(Packet::from_slice(&ptb));
            }
            Ok(())
        }));
    }
    (too_big, largest)
}

/// Path MTU discovery (RFC 8201): across a 1400-byte link that drops what
/// is larger and says so, both directions of an IPv6 bulk transfer shrink
/// their segments to fit and complete, where they used to stall on
/// full-size segments that could never get through.
#[test]
fn ipv6_bulk_transfer_discovers_the_path_mtu() {
    use std::io::Read;
    use std::sync::atomic::Ordering;

    const SIZE: usize = 2 << 20;
    let v6 = |ip: &str| {
        pktkit::vclient::Client::new(
            pktkit::vclient::ClientConfig::default().prefix(IpPrefix::new(ip.parse().unwrap(), 64)),
        )
    };
    let (a, b) = (v6("fd00::2"), v6("fd00::3"));
    let (too_big, largest) = narrow_link(&a, &b, "fd00::fe".parse().unwrap(), 1400);
    let listener = b.listen_tcp(LISTEN_PORT).unwrap();
    let data: Vec<u8> = (0..SIZE).map(|i| (i * 13 + i / 1000) as u8).collect();
    let sent = data.clone();
    let server = std::thread::spawn(move || {
        let mut s = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30)));
        s.write_all(&sent).unwrap();
        let mut back = vec![0; SIZE];
        s.read_exact(&mut back).unwrap();
        back
    });
    let dst = SocketAddr::new("fd00::3".parse().unwrap(), LISTEN_PORT);
    let mut conn = a.dial_tcp(dst).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)));
    conn.set_write_timeout(Some(Duration::from_secs(30)));
    let mut got = vec![0u8; SIZE];
    conn.read_exact(&mut got).expect("download stalled");
    assert!(got == data, "download corrupted");
    conn.write_all(&data).expect("upload stalled");
    assert!(server.join().unwrap() == data, "upload corrupted");
    assert!(too_big.load(Ordering::Relaxed) > 0, "nothing was too big");
    assert_eq!(largest.load(Ordering::Relaxed), 1400);
}

/// A client configured for a narrower link never sends past it, and
/// tells the peer, through its MSS, not to either.
#[test]
fn a_configured_mtu_bounds_both_directions() {
    use std::io::Read;
    use std::sync::atomic::Ordering;

    let a = pktkit::vclient::Client::new(
        pktkit::vclient::ClientConfig::default()
            .prefix(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24))
            .mtu(1280),
    );
    let b = client(3);
    let (too_big, largest) = narrow_link(&a, &b, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)), 1280);
    let listener = b.listen_tcp(LISTEN_PORT).unwrap();
    let server = std::thread::spawn(move || {
        let mut s = listener.accept().unwrap();
        s.write_all(&[5; 100_000]).unwrap();
        // Read to the end: unread data would have the drop reset.
        let mut v = Vec::new();
        s.read_to_end(&mut v).unwrap();
        assert_eq!(v.len(), 100_000);
    });
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), LISTEN_PORT);
    let mut conn = a.dial_tcp(dst).unwrap();
    conn.write_all(&[6; 100_000]).unwrap();
    conn.close().unwrap();
    let mut got = vec![0; 100_000];
    conn.read_exact(&mut got).unwrap();
    server.join().unwrap();
    assert_eq!(too_big.load(Ordering::Relaxed), 0);
    assert_eq!(largest.load(Ordering::Relaxed), 1280);
}

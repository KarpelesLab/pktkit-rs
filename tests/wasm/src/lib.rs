//! Smoke test for pktkit on wasm, run by `run.mjs`.
//!
//! Compiling for wasm proves little: std stubs out threads, clocks and sockets
//! with functions that panic or fail at run time. This module does real work
//! there instead: a WireGuard handshake (entropy + wall clock), a pcap record
//! (wall clock), and a TCP transfer between two `vclient`s across a lossy,
//! delayed link, whose retransmissions only happen because the host calls
//! `step` on a timer.
//!
//! Each export returns 1 on success, 0 for "call again", negative on failure.

use pktkit::impair::{ImpairL3, Impairment};
use pktkit::time::Instant;
use pktkit::vclient::{Client, ClientConfig, Listener, TcpConn};
use pktkit::{IpPrefix, L3Device, connect_l3};
use std::io::ErrorKind::WouldBlock;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn log(ptr: *const u8, len: usize);
}

fn say(s: &str) {
    // SAFETY: the host reads `len` bytes at `ptr` and keeps no reference.
    unsafe { log(s.as_ptr(), s.len()) }
}

macro_rules! check {
    ($code:expr, $cond:expr, $($msg:tt)*) => {
        if !$cond {
            say(&format!($($msg)*));
            return $code;
        }
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn wg_handshake() -> i32 {
    use pktkit::wg::{Config, Handler, PacketType};
    let a = Handler::new(Config::default()).unwrap();
    let b = Handler::new(Config::default()).unwrap();
    a.add_peer(b.public_key());
    b.add_peer(a.public_key());
    let addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    let init = a.initiate_handshake(&b.public_key()).unwrap();
    let resp = b.process_packet(&init, &addr).unwrap();
    let keepalive = a.process_packet(&resp.response, &addr).unwrap();
    b.process_packet(&keepalive.response, &addr).unwrap();
    let sealed = a.encrypt(b"hello from wasm", &b.public_key()).unwrap();
    let opened = b.process_packet(&sealed, &addr).unwrap();
    check!(-1, opened.ty == PacketType::TransportData, "wg: got {:?}", opened.ty);
    check!(-2, opened.data == b"hello from wasm", "wg: payload mismatch");
    b.maintenance();
    say("wg: handshake and transport ok");
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn pcap_timestamp() -> i32 {
    let mut buf = Vec::new();
    let mut w = pktkit::pcap::PcapWriter::new(&mut buf, 1).unwrap();
    w.write(&[0u8; 60]).unwrap();
    drop(w);
    // Global header is 24 bytes; the record's seconds field comes first.
    let secs = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    check!(-1, secs > 1_700_000_000, "pcap: timestamp {secs} is not now");
    say(&format!("pcap: record stamped {secs}"));
    1
}

const TOTAL: usize = 200_000;
const PORT: u16 = 80;

fn pattern(i: usize) -> u8 {
    (i * 31 % 251) as u8
}

struct Transfer {
    a: Arc<Client>,
    b: Arc<Client>,
    link: Arc<ImpairL3>,
    listener: Listener,
    client: TcpConn,
    server: Option<TcpConn>,
    sent: usize,
    received: usize,
    replied: bool,
    reply: Vec<u8>,
    started: Instant,
}

static TRANSFER: Mutex<Option<Transfer>> = Mutex::new(None);

#[unsafe(no_mangle)]
pub extern "C" fn tcp_start() -> i32 {
    let prefix = |host| IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, host)), 24);
    let a = Client::new(ClientConfig::default().prefix(prefix(1)));
    let b = Client::new(ClientConfig::default().prefix(prefix(2)));
    let listener = b.listen_tcp(PORT).unwrap();
    let link = ImpairL3::new(
        b.clone() as Arc<dyn L3Device>,
        Impairment::default()
            .delay(Duration::from_millis(15))
            .jitter(Duration::from_millis(5))
            .loss(0.03)
            .seed(7),
    );
    connect_l3(a.clone(), link.clone());
    let to = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), PORT);
    let client = a.dial_tcp_nonblocking(to).unwrap();
    *TRANSFER.lock().unwrap() = Some(Transfer {
        a,
        b,
        link,
        listener,
        client,
        server: None,
        sent: 0,
        received: 0,
        replied: false,
        reply: Vec::new(),
        started: Instant::now(),
    });
    1
}

/// One turn of the host's event loop: run the timers, then move whatever
/// data can move without waiting.
#[unsafe(no_mangle)]
pub extern "C" fn tcp_step() -> i32 {
    let mut guard = TRANSFER.lock().unwrap();
    let t = guard.as_mut().unwrap();
    t.link.poll();
    t.a.tick();
    t.b.tick();

    if t.server.is_none() {
        match t.listener.accept() {
            Ok(c) => t.server = Some(c),
            Err(e) if e.kind() == WouldBlock => {}
            Err(e) => return fail(-1, "accept", e),
        }
    }
    match t.client.poll_connect() {
        Ok(true) => {}
        Ok(false) => return 0,
        Err(e) => return fail(-2, "connect", e),
    }

    while t.sent < TOTAL {
        let chunk: Vec<u8> = (t.sent..TOTAL.min(t.sent + 4096)).map(pattern).collect();
        match t.client.write(&chunk) {
            Ok(n) => t.sent += n,
            Err(e) if e.kind() == WouldBlock => break,
            Err(e) => return fail(-3, "client write", e),
        }
    }

    if let Some(server) = &t.server {
        let mut buf = [0u8; 8192];
        loop {
            match server.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let ok = buf[..n]
                        .iter()
                        .enumerate()
                        .all(|(k, &b)| b == pattern(t.received + k));
                    check!(-4, ok, "tcp: corrupted stream near byte {}", t.received);
                    t.received += n;
                }
                Err(e) if e.kind() == WouldBlock => break,
                Err(e) => return fail(-5, "server read", e),
            }
        }
        if t.received == TOTAL && !t.replied && server.write(b"thanks").is_ok() {
            t.replied = true;
            server.close().unwrap();
        }
    }

    let mut buf = [0u8; 64];
    loop {
        match t.client.read(&mut buf) {
            Ok(0) if t.replied => {
                check!(-6, t.reply == b"thanks", "tcp: reply {:?}", t.reply);
                let drops = t.link.stats().map(|s| s.snapshot());
                let drops = drops.map_or(0, |s| s.tx_dropped + s.rx_dropped);
                say(&format!(
                    "tcp: {TOTAL} bytes and reply in {:?}, recovering from {drops} drops",
                    t.started.elapsed()
                ));
                check!(-7, drops > 0, "tcp: the link dropped nothing, so no retransmit ran");
                return 1;
            }
            Ok(0) => break,
            Ok(n) => t.reply.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == WouldBlock => break,
            Err(e) => return fail(-8, "client read", e),
        }
    }
    0
}

fn fail(code: i32, what: &str, e: std::io::Error) -> i32 {
    say(&format!("{what}: {e}"));
    code
}

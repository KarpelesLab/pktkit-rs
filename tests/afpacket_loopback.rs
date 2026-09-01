//! AF_PACKET tests that need a real interface and `CAP_NET_RAW`.
//!
//! Ignored by default because binding an `AF_PACKET` socket is privileged.
//! Run them with:
//!
//! ```sh
//! sudo -E cargo test --features afpacket --test afpacket_loopback -- --ignored
//! ```
//!
//! Everything is done over `lo`, so no external network is touched and no
//! other host sees the traffic.
#![cfg(all(feature = "afpacket", target_os = "linux"))]

use pktkit::afpacket::{Config, Socket};
use pktkit::{build_frame, EtherType, Frame, L2Device, MacAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A frame carrying a distinctive ethertype and payload, so it is easy to pick
/// out of whatever else the loopback interface is carrying.
const TEST_ETHERTYPE: u16 = 0x88B5; // IEEE 802.1 local experimental
const MAGIC: &[u8] = b"pktkit-afpacket-loopback";

fn open_lo(inbound_only: bool) -> Socket_ {
    match Socket::open(Config {
        interface: "lo".into(),
        inbound_only,
        ..Default::default()
    }) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            panic!("needs CAP_NET_RAW: run under sudo")
        }
        Err(e) => panic!("opening lo: {e}"),
    }
}

type Socket_ = Arc<Socket>;

fn wait_for<F: Fn() -> bool>(timeout: Duration, cond: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    cond()
}

#[test]
#[ignore = "needs CAP_NET_RAW"]
fn sent_frame_comes_back_on_loopback() {
    let sock = open_lo(false);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    sock.set_handler(Arc::new(move |f: &Frame| {
        if f.ether_type() == EtherType::new(TEST_ETHERTYPE) && f.payload().starts_with(MAGIC) {
            seen2.lock().unwrap().push(f.to_vec());
        }
        Ok(())
    }));

    let mut payload = MAGIC.to_vec();
    payload.resize(46, 0); // pad to the Ethernet minimum
    let out = build_frame(
        MacAddr::zero(),
        MacAddr::zero(),
        EtherType::new(TEST_ETHERTYPE),
        &payload,
    );
    sock.send(Frame::from_slice(&out)).unwrap();

    assert!(
        wait_for(Duration::from_secs(5), || !seen.lock().unwrap().is_empty()),
        "the frame we sent on lo never came back"
    );
    assert_eq!(seen.lock().unwrap()[0], out);

    let stats = sock.stats().unwrap().snapshot();
    assert_eq!(stats.tx_packets, 1);
    assert!(stats.rx_packets >= 1);

    sock.close().unwrap();
}

#[test]
#[ignore = "needs CAP_NET_RAW"]
fn inbound_only_hides_our_own_transmissions() {
    // On loopback every frame we send is also received, but it is marked
    // PACKET_OUTGOING; `inbound_only` should filter exactly those.
    let sock = open_lo(true);

    let count = Arc::new(AtomicUsize::new(0));
    let count2 = count.clone();
    sock.set_handler(Arc::new(move |f: &Frame| {
        if f.ether_type() == EtherType::new(TEST_ETHERTYPE) {
            count2.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }));

    let mut payload = MAGIC.to_vec();
    payload.resize(46, 0);
    let out = build_frame(
        MacAddr::zero(),
        MacAddr::zero(),
        EtherType::new(TEST_ETHERTYPE),
        &payload,
    );
    for _ in 0..5 {
        sock.send(Frame::from_slice(&out)).unwrap();
    }

    // The loopback copy is delivered as PACKET_HOST too, so we expect to see
    // each frame exactly once rather than twice.
    assert!(wait_for(Duration::from_secs(2), || count
        .load(Ordering::SeqCst)
        >= 5));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        count.load(Ordering::SeqCst),
        5,
        "outgoing copies should have been filtered out"
    );

    sock.close().unwrap();
}

#[test]
#[ignore = "needs CAP_NET_RAW"]
fn close_stops_the_reader_and_rejects_sends() {
    let sock = open_lo(false);
    sock.close().unwrap();
    assert!(sock.close().is_ok(), "close is idempotent");

    let f = build_frame(MacAddr::zero(), MacAddr::zero(), EtherType::IPV4, &[0; 46]);
    let err = sock.send(Frame::from_slice(&f)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);
}

#[test]
#[ignore = "needs CAP_NET_RAW"]
fn reports_the_interface_mtu() {
    let sock = open_lo(false);
    assert_eq!(sock.interface(), "lo");
    assert!(sock.mtu() >= 1500, "lo MTU looked like {}", sock.mtu());
    sock.close().unwrap();
}

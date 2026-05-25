//! Exercises the WireGuard cookie-reply DoS-mitigation path end to end:
//! under load the responder answers an initiation with a cookie reply; the
//! initiator consumes it and its retry (now carrying a valid MAC2) is accepted.
#![cfg(feature = "wg")]

use std::net::SocketAddr;

use pktkit::wg::{Config, Handler, PacketType};

#[test]
fn under_load_cookie_reply_then_accepted_retry() {
    // Responder with load_threshold = 0 → always "under load", so MAC2 is
    // mandatory and the first (MAC2-less) initiation must be answered with a
    // cookie reply.
    let responder = Handler::new(Config {
        load_threshold: Some(0),
        ..Default::default()
    })
    .unwrap();
    let initiator = Handler::new(Config::default()).unwrap();

    responder.add_peer(initiator.public_key());
    initiator.add_peer(responder.public_key());

    let peer_addr: SocketAddr = "203.0.113.7:51820".parse().unwrap();

    // First initiation — no cookie yet, so MAC2 is zero.
    let init1 = initiator.initiate_handshake(&responder.public_key()).unwrap();
    let res1 = responder.process_packet(&init1, &peer_addr).unwrap();
    assert_eq!(res1.ty, PacketType::CookieReply, "expected a cookie reply under load");
    assert!(!res1.response.is_empty());

    // Initiator consumes the cookie reply.
    let res2 = initiator
        .process_packet(&res1.response, &peer_addr)
        .unwrap();
    assert_eq!(res2.ty, PacketType::CookieReceived);
    assert_eq!(res2.peer_key, responder.public_key());

    // Retry — this initiation now carries a valid MAC2 bound to peer_addr.
    let init2 = initiator.initiate_handshake(&responder.public_key()).unwrap();
    let res3 = responder.process_packet(&init2, &peer_addr).unwrap();
    assert_eq!(
        res3.ty,
        PacketType::HandshakeResponse,
        "retry with valid MAC2 should be accepted"
    );
    assert_eq!(res3.peer_key, initiator.public_key());
}

#[test]
fn cookie_mac2_is_source_bound() {
    // A cookie minted for one source address must not authorize an initiation
    // arriving from a different address.
    let responder = Handler::new(Config {
        load_threshold: Some(0),
        ..Default::default()
    })
    .unwrap();
    let initiator = Handler::new(Config::default()).unwrap();
    responder.add_peer(initiator.public_key());
    initiator.add_peer(responder.public_key());

    let addr_a: SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let addr_b: SocketAddr = "203.0.113.8:51820".parse().unwrap();

    let init1 = initiator.initiate_handshake(&responder.public_key()).unwrap();
    let reply = responder.process_packet(&init1, &addr_a).unwrap();
    assert_eq!(reply.ty, PacketType::CookieReply);
    initiator.process_packet(&reply.response, &addr_a).unwrap();

    // Retry, but delivered from a different source address → MAC2 mismatch →
    // the responder issues another cookie reply rather than accepting.
    let init2 = initiator.initiate_handshake(&responder.public_key()).unwrap();
    let res = responder.process_packet(&init2, &addr_b).unwrap();
    assert_eq!(res.ty, PacketType::CookieReply);
}

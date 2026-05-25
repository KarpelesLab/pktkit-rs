//! End-to-end DHCP over an L2 hub: a DHCP server and an `L2Adapter`-wrapped
//! L3 device share a hub; the adapter's DHCP client obtains a lease and the
//! wrapped device's address is configured. Exercises `l2adapter` + `dhcp` +
//! the core `L2Hub` together, entirely in-process (no privileges needed).
#![cfg(all(feature = "l2adapter", feature = "dhcp"))]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use pktkit::dhcp::{Server as DhcpServer, ServerConfig as DhcpConfig};
use pktkit::{IpPrefix, L2Adapter, L2AdapterConfig, L2Device, L2Hub, L3Device, PipeL3};

#[test]
fn adapter_obtains_lease_from_server_over_hub() {
    let hub = Arc::new(L2Hub::new());

    // DHCP server: pool 192.168.50.10–20, router/DNS set.
    let mut dcfg = DhcpConfig::new(
        Ipv4Addr::new(192, 168, 50, 1),
        Ipv4Addr::new(192, 168, 50, 10),
        Ipv4Addr::new(192, 168, 50, 20),
    );
    dcfg.router = Some(Ipv4Addr::new(192, 168, 50, 1));
    dcfg.dns = vec![Ipv4Addr::new(1, 1, 1, 1)];
    let _server_handle = hub.connect(DhcpServer::new(dcfg));

    // Client: an unconfigured L3 pipe wrapped in an L2Adapter, joined to the hub.
    let pipe = Arc::new(PipeL3::new(IpPrefix::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    )));
    let adapter = L2Adapter::new_arc(pipe.clone(), L2AdapterConfig::default());
    let _adapter_handle = hub.connect_arc(adapter.clone() as Arc<dyn L2Device>);

    // Kick off DHCP. The whole DISCOVER/OFFER/REQUEST/ACK exchange runs
    // synchronously through the hub's flooding, so by the time start_dhcp
    // returns the lease is (almost certainly) bound. Allow a brief grace
    // period in case the timer thread is involved.
    adapter.start_dhcp();
    for _ in 0..50 {
        if pipe.addr().is_valid() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let leased = pipe.addr();
    assert!(leased.is_valid(), "client should have a bound address");
    assert_eq!(leased.bits(), 24, "default /24 subnet from the server");
    match leased.addr() {
        IpAddr::V4(ip) => {
            let raw = u32::from(ip);
            assert!(
                raw >= u32::from(Ipv4Addr::new(192, 168, 50, 10))
                    && raw <= u32::from(Ipv4Addr::new(192, 168, 50, 20)),
                "leased IP {ip} should be inside the pool"
            );
        }
        _ => panic!("expected an IPv4 lease"),
    }
}

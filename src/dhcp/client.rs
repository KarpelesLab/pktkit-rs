//! Minimal RFC 2131 DHCP client.
//!
//! The client is transport-agnostic: callers implement [`ClientTransport`] to
//! hand the resulting Ethernet frames to whatever wire (`L2Device`, raw
//! socket, …) is appropriate, and to learn when a lease is bound.
//!
//! Construction does no I/O. Call [`Client::start`] to begin discovery and
//! [`Client::handle_packet`] for each UDP-port-68 payload received on the
//! same network. Renewal is driven by an internal timer thread.

use super::wire;
use crate::{checksum, EtherType, Frame, IpPrefix, MacAddr, Protocol};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// User-controllable knobs.
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// Override the client MAC. Defaults to whatever [`ClientTransport::mac`]
    /// returns at start time.
    pub mac: Option<MacAddr>,
}

/// What the client needs from its surroundings: a way to send Ethernet
/// frames, the MAC to put in the chaddr / source fields, and a callback for
/// when a lease is bound.
pub trait ClientTransport: Send + Sync + 'static {
    /// MAC to use as the client identifier and Ethernet source.
    fn mac(&self) -> MacAddr;

    /// Send a broadcast Ethernet frame (DISCOVER, REQUEST in INIT).
    fn send_broadcast(&self, frame: &Frame);

    /// Send a unicast Ethernet frame to `dst_ip`. The transport is expected
    /// to resolve `dst_ip` to a MAC (e.g. via ARP) — the wire layer here
    /// builds an Ethernet broadcast as a fallback when no resolver is in
    /// reach.
    fn send_unicast(&self, dst_ip: Ipv4Addr, frame: &Frame);

    /// Called whenever the client transitions into BOUND or refreshes its
    /// lease. `gateway` is the IPv4 router from the OFFER/ACK, if any.
    fn on_bound(&self, prefix: IpPrefix, gateway: Option<Ipv4Addr>);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum State {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
}

struct Inner {
    state: State,
    xid: u32,
    offered_ip: Option<Ipv4Addr>,
    server_ip: Option<Ipv4Addr>,
    lease: Duration,
    stop: bool,
}

/// DHCP client state machine.
pub struct Client {
    transport: Arc<dyn ClientTransport>,
    mac: MacAddr,
    inner: Arc<Mutex<Inner>>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.inner.lock().map(|i| i.state).unwrap_or(State::Init);
        f.debug_struct("dhcp::Client")
            .field("mac", &self.mac)
            .field("state", &s)
            .finish()
    }
}

impl Client {
    /// Build a new client. No I/O happens until [`start`](Self::start) is called.
    pub fn new<T>(transport: T, config: ClientConfig) -> Client
    where
        T: ClientTransport,
    {
        let transport: Arc<dyn ClientTransport> = Arc::new(transport);
        let mac = config.mac.unwrap_or_else(|| transport.mac());
        Client {
            transport,
            mac,
            inner: Arc::new(Mutex::new(Inner {
                state: State::Init,
                xid: 0,
                offered_ip: None,
                server_ip: None,
                lease: Duration::ZERO,
                stop: false,
            })),
        }
    }

    /// True if the client is past INIT (actively discovering, bound, or renewing).
    pub fn is_active(&self) -> bool {
        self.inner.lock().unwrap().state != State::Init
    }

    /// Begin DHCP discovery.
    pub fn start(&self) {
        {
            let mut i = self.inner.lock().unwrap();
            i.xid = crate::rand::u32();
            i.state = State::Selecting;
            i.stop = false;
        }
        self.send_discover();
    }

    /// Cancel any pending operations.
    pub fn stop(&self) {
        let mut i = self.inner.lock().unwrap();
        i.stop = true;
        i.state = State::Init;
    }

    /// Process an inbound DHCP UDP payload (full BOOTP message).
    pub fn handle_packet(&self, udp_payload: &[u8]) {
        let p = match wire::Parsed::from_bytes(udp_payload) {
            Some(p) => p,
            None => return,
        };
        if p.op != 2 {
            return; // not a BOOTREPLY
        }

        // Pull out everything we need under the lock, then drop it.
        let (action, send_renew_after): (Action, Option<Duration>) = {
            let mut i = self.inner.lock().unwrap();
            if i.xid != p.xid {
                return;
            }
            match i.state {
                State::Selecting if p.msg_type == wire::MSG_OFFER => {
                    i.offered_ip = Some(p.yiaddr);
                    i.server_ip = p.server_id;
                    i.state = State::Requesting;
                    (Action::SendRequest, None)
                }
                State::Requesting | State::Renewing if p.msg_type == wire::MSG_ACK => {
                    let bits = p.subnet_mask.map(wire::mask_bits).unwrap_or(24);
                    let prefix = IpPrefix::new(IpAddr::V4(p.yiaddr), bits);
                    self.transport.on_bound(prefix, p.router);
                    i.state = State::Bound;
                    let after = if p.lease_time > 0 {
                        i.lease = Duration::from_secs(p.lease_time as u64);
                        Some(i.lease / 2)
                    } else {
                        None
                    };
                    (Action::None, after)
                }
                State::Requesting | State::Renewing if p.msg_type == wire::MSG_NAK => {
                    i.state = State::Selecting;
                    i.xid = crate::rand::u32();
                    (Action::SendDiscover, None)
                }
                _ => (Action::None, None),
            }
        };

        match action {
            Action::SendDiscover => self.send_discover(),
            Action::SendRequest => self.send_request(),
            Action::None => {}
        }

        if let Some(after) = send_renew_after {
            self.spawn_renew_timer(after);
        }
    }

    fn send_discover(&self) {
        let xid = self.inner.lock().unwrap().xid;
        let mut b = wire::Builder::new(1, xid, self.mac);
        b.message_type(wire::MSG_DISCOVER).option(
            wire::OPT_PARAM_REQUEST,
            &[wire::OPT_SUBNET_MASK, wire::OPT_ROUTER, wire::OPT_DNS],
        );
        let dhcp = b.finish();
        let frame = wrap_for_broadcast(self.mac, &dhcp);
        self.transport.send_broadcast(Frame::from_slice(&frame));
    }

    fn send_request(&self) {
        let (xid, requested, server) = {
            let i = self.inner.lock().unwrap();
            (i.xid, i.offered_ip, i.server_ip)
        };
        let mut b = wire::Builder::new(1, xid, self.mac);
        b.message_type(wire::MSG_REQUEST);
        if let Some(ip) = requested {
            b.ipv4_option(wire::OPT_REQUESTED_IP, ip);
        }
        if let Some(ip) = server {
            b.ipv4_option(wire::OPT_SERVER_ID, ip);
        }
        b.option(
            wire::OPT_PARAM_REQUEST,
            &[wire::OPT_SUBNET_MASK, wire::OPT_ROUTER, wire::OPT_DNS],
        );
        let dhcp = b.finish();
        let frame = wrap_for_broadcast(self.mac, &dhcp);
        self.transport.send_broadcast(Frame::from_slice(&frame));
    }

    fn spawn_renew_timer(&self, after: Duration) {
        let weak_inner = Arc::downgrade(&self.inner);
        let transport = self.transport.clone();
        let mac = self.mac;
        std::thread::spawn(move || {
            std::thread::sleep(after);
            let Some(inner) = weak_inner.upgrade() else {
                return;
            };
            let (client_ip, server_ip) = {
                let mut i = inner.lock().unwrap();
                if i.stop || i.state != State::Bound {
                    return;
                }
                i.state = State::Renewing;
                match (i.offered_ip, i.server_ip) {
                    (Some(c), Some(s)) => (c, s),
                    _ => return,
                }
            };
            // Build & send renew. We can't reuse Client::send_renew because
            // we've borrowed weak_inner; inline the same logic here.
            let xid = inner.lock().unwrap().xid;
            let mut b = wire::Builder::new(1, xid, mac);
            b.message_type(wire::MSG_REQUEST).ciaddr(client_ip).option(
                wire::OPT_PARAM_REQUEST,
                &[wire::OPT_SUBNET_MASK, wire::OPT_ROUTER, wire::OPT_DNS],
            );
            let dhcp = b.finish();
            let frame = wrap_unicast(mac, client_ip, server_ip, &dhcp);
            transport.send_unicast(server_ip, Frame::from_slice(&frame));
        });
    }
}

enum Action {
    None,
    SendDiscover,
    SendRequest,
}

// --- frame wrappers --------------------------------------------------------

/// Wrap a DHCP payload in UDP(68→67) + IPv4(0.0.0.0→255.255.255.255) + Ethernet(broadcast).
fn wrap_for_broadcast(src_mac: MacAddr, dhcp: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + dhcp.len());
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&67u16.to_be_bytes());
    let udp_len = 8 + dhcp.len();
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum = 0
    udp.extend_from_slice(dhcp);

    let ip_len = 20 + udp_len;
    let mut ip = vec![0u8; ip_len];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::UDP.as_u8();
    ip[16..20].copy_from_slice(&[0xff; 4]);
    let cs = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    ip[20..].copy_from_slice(&udp);

    crate::build_frame(MacAddr::broadcast(), src_mac, EtherType::IPV4, &ip)
}

fn wrap_unicast(src_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, dhcp: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + dhcp.len());
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&67u16.to_be_bytes());
    let udp_len = 8 + dhcp.len();
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(dhcp);

    let ip_len = 20 + udp_len;
    let mut ip = vec![0u8; ip_len];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::UDP.as_u8();
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    let cs = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    ip[20..].copy_from_slice(&udp);

    // We don't know the destination MAC here — the transport will resolve
    // dst_ip to a MAC and rewrite the Ethernet destination if needed.
    crate::build_frame(MacAddr::broadcast(), src_mac, EtherType::IPV4, &ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<Vec<u8>>>,
        bound: Mutex<Option<(IpPrefix, Option<Ipv4Addr>)>>,
        mac: MacAddr,
    }
    impl ClientTransport for Recorder {
        fn mac(&self) -> MacAddr {
            self.mac
        }
        fn send_broadcast(&self, f: &Frame) {
            self.sent.lock().unwrap().push(f.as_bytes().to_vec());
        }
        fn send_unicast(&self, _ip: Ipv4Addr, f: &Frame) {
            self.sent.lock().unwrap().push(f.as_bytes().to_vec());
        }
        fn on_bound(&self, p: IpPrefix, g: Option<Ipv4Addr>) {
            *self.bound.lock().unwrap() = Some((p, g));
        }
    }

    fn make_offer(xid: u32, client_mac: MacAddr) -> Vec<u8> {
        let mut b = wire::Builder::new(2, xid, client_mac);
        b.yiaddr(Ipv4Addr::new(192, 168, 1, 100))
            .siaddr(Ipv4Addr::new(192, 168, 1, 1))
            .message_type(wire::MSG_OFFER)
            .ipv4_option(wire::OPT_SUBNET_MASK, Ipv4Addr::new(255, 255, 255, 0))
            .ipv4_option(wire::OPT_ROUTER, Ipv4Addr::new(192, 168, 1, 1))
            .u32_option(wire::OPT_LEASE_TIME, 3600)
            .ipv4_option(wire::OPT_SERVER_ID, Ipv4Addr::new(192, 168, 1, 1));
        b.finish()
    }

    fn make_ack(xid: u32, client_mac: MacAddr) -> Vec<u8> {
        let mut b = wire::Builder::new(2, xid, client_mac);
        b.yiaddr(Ipv4Addr::new(192, 168, 1, 100))
            .siaddr(Ipv4Addr::new(192, 168, 1, 1))
            .message_type(wire::MSG_ACK)
            .ipv4_option(wire::OPT_SUBNET_MASK, Ipv4Addr::new(255, 255, 255, 0))
            .ipv4_option(wire::OPT_ROUTER, Ipv4Addr::new(192, 168, 1, 1))
            .u32_option(wire::OPT_LEASE_TIME, 3600)
            .ipv4_option(wire::OPT_SERVER_ID, Ipv4Addr::new(192, 168, 1, 1));
        b.finish()
    }

    #[test]
    fn full_handshake() {
        let r = Arc::new(Recorder {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        });
        let c = Client::new(ArcTransport(r.clone()), ClientConfig::default());
        c.start();
        assert!(c.is_active());
        // Sent DISCOVER
        assert_eq!(r.sent.lock().unwrap().len(), 1);

        // Server sends OFFER
        let xid = c.inner.lock().unwrap().xid;
        let offer = make_offer(xid, r.mac);
        c.handle_packet(&offer);

        // Client should have sent REQUEST
        assert_eq!(r.sent.lock().unwrap().len(), 2);

        // Server sends ACK
        let ack = make_ack(xid, r.mac);
        c.handle_packet(&ack);

        let bound = r.bound.lock().unwrap().expect("should have bound");
        assert_eq!(bound.0.bits(), 24);
        assert_eq!(bound.1, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // Helper: wrap an Arc<Recorder> as a ClientTransport.
    struct ArcTransport(Arc<Recorder>);
    impl ClientTransport for ArcTransport {
        fn mac(&self) -> MacAddr {
            self.0.mac()
        }
        fn send_broadcast(&self, f: &Frame) {
            self.0.send_broadcast(f)
        }
        fn send_unicast(&self, ip: Ipv4Addr, f: &Frame) {
            self.0.send_unicast(ip, f)
        }
        fn on_bound(&self, p: IpPrefix, g: Option<Ipv4Addr>) {
            self.0.on_bound(p, g)
        }
    }
}

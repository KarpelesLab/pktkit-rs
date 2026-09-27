//! RFC 2131 DHCP client.
//!
//! The client is transport-agnostic: callers implement [`ClientTransport`] to
//! hand the resulting Ethernet frames to whatever wire (`L2Device`, raw
//! socket, …) is appropriate, and to learn when a lease is bound or lost.
//!
//! Construction does no I/O. Call [`Client::start`] to begin discovery and
//! [`Client::handle_packet`] for each UDP-port-68 payload received on the
//! same network. Everything timed — retransmitting an unanswered DISCOVER or
//! REQUEST, renewing at T1, rebinding at T2, giving the address up when the
//! lease expires — happens in [`Client::tick`]. Where threads exist, `start`
//! runs a background thread that calls it; on `wasm32` call it yourself,
//! about once a second.

use super::wire;
use crate::time::Instant;
use crate::{EtherType, Frame, IpPrefix, MacAddr, Protocol, checksum};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// User-controllable knobs.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Override the client MAC. Defaults to whatever [`ClientTransport::mac`]
    /// returns at start time.
    pub mac: Option<MacAddr>,
}

setters! {
    ClientConfig {
        some mac: MacAddr;
    }
}

/// What the client needs from its surroundings: a way to send Ethernet
/// frames, the MAC to put in the chaddr / source fields, and callbacks for
/// when a lease is bound or lost.
///
/// The callbacks run with no client lock held, so they may call back into
/// the [`Client`].
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

    /// Called when the bound lease is gone: it expired without being
    /// renewed, or the server refused to extend it (DHCPNAK). The address
    /// from [`on_bound`](Self::on_bound) must no longer be used (RFC 2131
    /// §4.4.5). The client goes back to discovery by itself.
    fn on_lease_lost(&self) {}
}

/// First retransmission delay and its ceiling (RFC 2131 §4.1: 4 s, doubled
/// each time, up to 64 s, each randomised by ±1 s).
const FIRST_RETRANSMIT: Duration = Duration::from_secs(4);
const MAX_RETRANSMIT: Duration = Duration::from_secs(64);
/// REQUESTs sent for one offer before starting over with a DISCOVER. RFC
/// 2131 §3.1 leaves the count to the client; five spans about a minute.
const MAX_REQUESTS: u32 = 5;
/// Floor on the retransmission interval while RENEWING or REBINDING
/// (RFC 2131 §4.4.5).
const MIN_RENEW_RETRANSMIT: Duration = Duration::from_secs(60);
/// How often the background thread looks for due timers. Well under the
/// ±1 s jitter the retransmission delays already carry.
#[cfg(not(target_family = "wasm"))]
const TIMER_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum State {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

/// When a bound lease must be renewed (T1), rebound (T2) and when it is
/// gone.
#[derive(Copy, Clone, Debug)]
struct LeaseTimers {
    t1: Instant,
    t2: Instant,
    expiry: Instant,
}

struct Inner {
    state: State,
    xid: u32,
    offered_ip: Option<Ipv4Addr>,
    server_ip: Option<Ipv4Addr>,
    /// `None` for an infinite lease, or before one is bound.
    lease: Option<LeaseTimers>,
    /// When to retransmit the outstanding DISCOVER or REQUEST.
    next_tx: Option<Instant>,
    /// Retransmissions of the outstanding message so far.
    tries: u32,
    /// Bumped by every start and stop, so the timer thread of an earlier run
    /// knows to exit.
    run: u64,
}

impl Inner {
    /// Start over from INIT: a fresh transaction, DISCOVER due now.
    fn restart(&mut self, now: Instant) -> Out {
        self.state = State::Selecting;
        self.xid = crate::rand::u32();
        self.offered_ip = None;
        self.server_ip = None;
        self.lease = None;
        self.tries = 0;
        self.next_tx = Some(now + backoff(0));
        Out::Discover(self.xid)
    }
}

/// Something to send, worked out under the lock and sent after it is
/// released.
enum Out {
    Discover(u32),
    /// Broadcast REQUEST for an offered address (SELECTING).
    Select {
        xid: u32,
        ip: Ipv4Addr,
        server: Option<Ipv4Addr>,
    },
    /// Unicast REQUEST to the leasing server (RENEWING).
    Renew {
        xid: u32,
        ip: Ipv4Addr,
        server: Ipv4Addr,
    },
    /// Broadcast REQUEST to any server (REBINDING).
    Rebind {
        xid: u32,
        ip: Ipv4Addr,
    },
}

/// What to tell the transport, also after the lock is released.
enum Event {
    Bound(IpPrefix, Option<Ipv4Addr>),
    Lost,
}

struct Shared {
    transport: Arc<dyn ClientTransport>,
    mac: MacAddr,
    inner: Mutex<Inner>,
}

/// DHCP client state machine.
pub struct Client {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self
            .shared
            .inner
            .lock()
            .map(|i| i.state)
            .unwrap_or(State::Init);
        f.debug_struct("dhcp::Client")
            .field("mac", &self.shared.mac)
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
            shared: Arc::new(Shared {
                transport,
                mac,
                inner: Mutex::new(Inner {
                    state: State::Init,
                    xid: 0,
                    offered_ip: None,
                    server_ip: None,
                    lease: None,
                    next_tx: None,
                    tries: 0,
                    run: 0,
                }),
            }),
        }
    }

    /// True if the client is past INIT (actively discovering, bound, or renewing).
    pub fn is_active(&self) -> bool {
        self.shared.inner.lock().unwrap().state != State::Init
    }

    /// Begin DHCP discovery, and where threads exist, the thread that runs
    /// [`tick`](Self::tick).
    pub fn start(&self) {
        self.begin(cfg!(not(target_family = "wasm")));
    }

    fn begin(&self, timer_thread: bool) {
        let (out, run) = {
            let mut i = self.shared.inner.lock().unwrap();
            i.run += 1;
            (i.restart(Instant::now()), i.run)
        };
        #[cfg(not(target_family = "wasm"))]
        if timer_thread {
            spawn_timer(&self.shared, run);
        }
        let _ = (timer_thread, run);
        self.shared.send(out);
    }

    /// Cancel any pending operations.
    pub fn stop(&self) {
        let mut i = self.shared.inner.lock().unwrap();
        i.run += 1;
        i.state = State::Init;
        i.lease = None;
        i.next_tx = None;
    }

    /// Process an inbound DHCP UDP payload (full BOOTP message).
    pub fn handle_packet(&self, udp_payload: &[u8]) {
        let p = match wire::Parsed::from_bytes(udp_payload) {
            Some(p) => p,
            None => return,
        };
        if p.op != 2 || p.chaddr != self.shared.mac {
            return; // not a BOOTREPLY for us
        }

        let now = Instant::now();
        let (event, out) = {
            let mut i = self.shared.inner.lock().unwrap();
            if i.xid != p.xid {
                return;
            }
            match (i.state, p.msg_type) {
                (State::Selecting, wire::MSG_OFFER) => {
                    i.offered_ip = Some(p.yiaddr);
                    i.server_ip = p.server_id;
                    i.state = State::Requesting;
                    i.tries = 0;
                    i.next_tx = Some(now + backoff(0));
                    let out = Out::Select {
                        xid: i.xid,
                        ip: p.yiaddr,
                        server: p.server_id,
                    };
                    (None, Some(out))
                }
                (State::Requesting | State::Renewing | State::Rebinding, wire::MSG_ACK) => {
                    let bits = p.subnet_mask.map(wire::mask_bits).unwrap_or(24);
                    let prefix = IpPrefix::new(IpAddr::V4(p.yiaddr), bits);
                    i.state = State::Bound;
                    i.offered_ip = Some(p.yiaddr);
                    if p.server_id.is_some() {
                        i.server_ip = p.server_id;
                    }
                    i.next_tx = None;
                    i.lease = lease_timers(now, p.lease_time);
                    (Some(Event::Bound(prefix, p.router)), None)
                }
                (State::Requesting, wire::MSG_NAK) => (None, Some(i.restart(now))),
                (State::Renewing | State::Rebinding, wire::MSG_NAK) => {
                    (Some(Event::Lost), Some(i.restart(now)))
                }
                _ => (None, None),
            }
        };
        self.shared.notify(event);
        if let Some(out) = out {
            self.shared.send(out);
        }
    }

    /// Run whatever timer has come due: retransmit an unanswered DISCOVER
    /// or REQUEST, renew the lease at T1, rebind it at T2, or give it up
    /// once expired. A background thread does this where threads exist; on
    /// `wasm32` the caller drives it, about once a second.
    pub fn tick(&self) {
        self.shared.tick(Instant::now());
    }
}

impl Shared {
    fn tick(&self, now: Instant) {
        let (event, out) = {
            let mut i = self.inner.lock().unwrap();
            step(&mut i, now)
        };
        self.notify(event);
        if let Some(out) = out {
            self.send(out);
        }
    }

    fn notify(&self, event: Option<Event>) {
        match event {
            Some(Event::Bound(prefix, gw)) => self.transport.on_bound(prefix, gw),
            Some(Event::Lost) => self.transport.on_lease_lost(),
            None => {}
        }
    }

    fn send(&self, out: Out) {
        let params = [wire::OPT_SUBNET_MASK, wire::OPT_ROUTER, wire::OPT_DNS];
        let mac = self.mac;
        match out {
            Out::Discover(xid) => {
                let mut b = wire::Builder::new(1, xid, mac);
                b.message_type(wire::MSG_DISCOVER)
                    .option(wire::OPT_PARAM_REQUEST, &params);
                let frame = wrap_for_broadcast(mac, &b.finish());
                self.transport.send_broadcast(Frame::from_slice(&frame));
            }
            Out::Select { xid, ip, server } => {
                let mut b = wire::Builder::new(1, xid, mac);
                b.message_type(wire::MSG_REQUEST)
                    .ipv4_option(wire::OPT_REQUESTED_IP, ip);
                if let Some(s) = server {
                    b.ipv4_option(wire::OPT_SERVER_ID, s);
                }
                b.option(wire::OPT_PARAM_REQUEST, &params);
                let frame = wrap_for_broadcast(mac, &b.finish());
                self.transport.send_broadcast(Frame::from_slice(&frame));
            }
            // RFC 2131 §4.3.2: RENEWING and REBINDING put the address in
            // ciaddr and carry neither server identifier nor requested
            // address.
            Out::Renew { xid, ip, server } => {
                let mut b = wire::Builder::new(1, xid, mac);
                b.message_type(wire::MSG_REQUEST)
                    .ciaddr(ip)
                    .option(wire::OPT_PARAM_REQUEST, &params);
                let frame = wrap_unicast(mac, ip, server, &b.finish());
                self.transport
                    .send_unicast(server, Frame::from_slice(&frame));
            }
            Out::Rebind { xid, ip } => {
                let mut b = wire::Builder::new(1, xid, mac);
                b.message_type(wire::MSG_REQUEST)
                    .ciaddr(ip)
                    .option(wire::OPT_PARAM_REQUEST, &params);
                let frame = wrap_unicast(mac, ip, Ipv4Addr::BROADCAST, &b.finish());
                self.transport.send_broadcast(Frame::from_slice(&frame));
            }
        }
    }
}

/// The state machine's timed transitions.
fn step(i: &mut Inner, now: Instant) -> (Option<Event>, Option<Out>) {
    let due = |at: Option<Instant>| at.is_some_and(|at| at <= now);
    match i.state {
        State::Init => (None, None),
        State::Selecting => {
            if !due(i.next_tx) {
                return (None, None);
            }
            i.tries += 1;
            i.next_tx = Some(now + backoff(i.tries));
            (None, Some(Out::Discover(i.xid)))
        }
        State::Requesting => {
            if !due(i.next_tx) {
                return (None, None);
            }
            if i.tries + 1 >= MAX_REQUESTS {
                return (None, Some(i.restart(now)));
            }
            i.tries += 1;
            i.next_tx = Some(now + backoff(i.tries));
            let Some(ip) = i.offered_ip else {
                return (None, Some(i.restart(now)));
            };
            let out = Out::Select {
                xid: i.xid,
                ip,
                server: i.server_ip,
            };
            (None, Some(out))
        }
        State::Bound | State::Renewing | State::Rebinding => {
            let Some(lease) = i.lease else {
                return (None, None); // infinite
            };
            let Some(ip) = i.offered_ip else {
                return (None, None);
            };
            if lease.expiry <= now {
                return (Some(Event::Lost), Some(i.restart(now)));
            }
            // Once T2 passes, or without a server to unicast to, any server
            // may extend the lease.
            if lease.t2 <= now || (lease.t1 <= now && i.server_ip.is_none()) {
                if i.state != State::Rebinding {
                    i.state = State::Rebinding;
                    i.next_tx = Some(now);
                }
                if !due(i.next_tx) {
                    return (None, None);
                }
                i.next_tx = Some(now + renew_wait(lease.expiry, now));
                return (None, Some(Out::Rebind { xid: i.xid, ip }));
            }
            if lease.t1 <= now {
                if i.state == State::Bound {
                    i.state = State::Renewing;
                    i.xid = crate::rand::u32();
                    i.next_tx = Some(now);
                }
                if !due(i.next_tx) {
                    return (None, None);
                }
                i.next_tx = Some(now + renew_wait(lease.t2, now));
                let server = i.server_ip.unwrap_or(Ipv4Addr::BROADCAST);
                return (
                    None,
                    Some(Out::Renew {
                        xid: i.xid,
                        ip,
                        server,
                    }),
                );
            }
            (None, None)
        }
    }
}

/// Timers for a lease of `secs` seconds granted at `now`: T1 at half the
/// lease and T2 at seven eighths (RFC 2131 §4.4.5). A lease of 0xffffffff
/// is infinite (§3.3), and one without a lease time is treated the same,
/// since there is nothing to renew against.
fn lease_timers(now: Instant, secs: u32) -> Option<LeaseTimers> {
    if secs == 0 || secs == u32::MAX {
        return None;
    }
    let lease = Duration::from_secs(secs as u64);
    Some(LeaseTimers {
        t1: now + lease / 2,
        t2: now + lease * 7 / 8,
        expiry: now + lease,
    })
}

/// Delay before the next DISCOVER or REQUEST after `tries` retransmissions
/// (RFC 2131 §4.1).
fn backoff(tries: u32) -> Duration {
    let base = FIRST_RETRANSMIT
        .checked_mul(1 << tries.min(4))
        .unwrap_or(MAX_RETRANSMIT)
        .min(MAX_RETRANSMIT);
    let jitter = Duration::from_millis((crate::rand::u32() % 2001) as u64);
    base - Duration::from_secs(1) + jitter
}

/// Delay before retransmitting a RENEWING or REBINDING request: half the
/// time left until `deadline`, but at least a minute (RFC 2131 §4.4.5).
fn renew_wait(deadline: Instant, now: Instant) -> Duration {
    (deadline.saturating_duration_since(now) / 2).max(MIN_RENEW_RETRANSMIT)
}

#[cfg(not(target_family = "wasm"))]
fn spawn_timer(shared: &Arc<Shared>, run: u64) {
    let weak = Arc::downgrade(shared);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(TIMER_INTERVAL);
            let Some(shared) = weak.upgrade() else {
                return;
            };
            if shared.inner.lock().unwrap().run != run {
                return;
            }
            shared.tick(Instant::now());
        }
    });
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
        /// (sent by unicast, frame)
        sent: Mutex<Vec<(bool, Vec<u8>)>>,
        bound: Mutex<Option<(IpPrefix, Option<Ipv4Addr>)>>,
        lost: Mutex<u32>,
        mac: MacAddr,
    }
    impl ClientTransport for Recorder {
        fn mac(&self) -> MacAddr {
            self.mac
        }
        fn send_broadcast(&self, f: &Frame) {
            self.sent
                .lock()
                .unwrap()
                .push((false, f.as_bytes().to_vec()));
        }
        fn send_unicast(&self, _ip: Ipv4Addr, f: &Frame) {
            self.sent
                .lock()
                .unwrap()
                .push((true, f.as_bytes().to_vec()));
        }
        fn on_bound(&self, p: IpPrefix, g: Option<Ipv4Addr>) {
            *self.bound.lock().unwrap() = Some((p, g));
        }
        fn on_lease_lost(&self) {
            *self.lost.lock().unwrap() += 1;
            *self.bound.lock().unwrap() = None;
        }
    }

    fn reply(msg_type: u8, xid: u32, client_mac: MacAddr) -> Vec<u8> {
        let mut b = wire::Builder::new(2, xid, client_mac);
        b.yiaddr(Ipv4Addr::new(192, 168, 1, 100))
            .siaddr(Ipv4Addr::new(192, 168, 1, 1))
            .message_type(msg_type)
            .ipv4_option(wire::OPT_SUBNET_MASK, Ipv4Addr::new(255, 255, 255, 0))
            .ipv4_option(wire::OPT_ROUTER, Ipv4Addr::new(192, 168, 1, 1))
            .u32_option(wire::OPT_LEASE_TIME, 3600)
            .ipv4_option(wire::OPT_SERVER_ID, Ipv4Addr::new(192, 168, 1, 1));
        b.finish()
    }

    fn make_offer(xid: u32, client_mac: MacAddr) -> Vec<u8> {
        reply(wire::MSG_OFFER, xid, client_mac)
    }

    fn make_ack(xid: u32, client_mac: MacAddr) -> Vec<u8> {
        reply(wire::MSG_ACK, xid, client_mac)
    }

    fn setup() -> (Arc<Recorder>, Client) {
        let r = Arc::new(Recorder {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            ..Default::default()
        });
        let c = Client::new(ArcTransport(r.clone()), ClientConfig::default());
        (r, c)
    }

    fn xid(c: &Client) -> u32 {
        c.shared.inner.lock().unwrap().xid
    }

    fn state(c: &Client) -> State {
        c.shared.inner.lock().unwrap().state
    }

    /// Every message sent so far, as (unicast, ciaddr, parsed), and forget
    /// them.
    fn sent(r: &Recorder) -> Vec<(bool, Ipv4Addr, wire::Parsed)> {
        r.sent
            .lock()
            .unwrap()
            .drain(..)
            .map(|(uni, f)| {
                let p = wire::Parsed::from_bytes(&f[42..]).unwrap();
                (uni, p.ciaddr, p)
            })
            .collect()
    }

    /// Run the timer as if `after` had passed.
    fn tick_after(c: &Client, after: Duration) {
        c.shared.tick(Instant::now() + after);
    }

    /// Start (without the timer thread, so the test drives time) and bind.
    fn bound() -> (Arc<Recorder>, Client) {
        let (r, c) = setup();
        c.begin(false);
        c.handle_packet(&make_offer(xid(&c), r.mac));
        c.handle_packet(&make_ack(xid(&c), r.mac));
        assert_eq!(state(&c), State::Bound);
        sent(&r);
        (r, c)
    }

    #[test]
    fn full_handshake() {
        let (r, c) = setup();
        c.start();
        assert!(c.is_active());
        // Sent DISCOVER
        assert_eq!(r.sent.lock().unwrap().len(), 1);

        // Server sends OFFER
        let xid = xid(&c);
        c.handle_packet(&make_offer(xid, r.mac));

        // Client should have sent REQUEST
        assert_eq!(r.sent.lock().unwrap().len(), 2);

        // Server sends ACK
        c.handle_packet(&make_ack(xid, r.mac));

        let bound = r.bound.lock().unwrap().expect("should have bound");
        assert_eq!(bound.0.bits(), 24);
        assert_eq!(bound.1, Some(Ipv4Addr::new(192, 168, 1, 1)));
        c.stop();
    }

    #[test]
    fn discover_is_retransmitted_with_backoff() {
        let (r, c) = setup();
        c.begin(false);
        assert_eq!(sent(&r).len(), 1);

        tick_after(&c, Duration::from_secs(2));
        assert!(sent(&r).is_empty(), "the first retry waits 4 s ± 1 s");

        tick_after(&c, Duration::from_secs(5));
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2.msg_type, wire::MSG_DISCOVER);

        // The next wait is doubled: 8 s ± 1 s from the retransmission.
        tick_after(&c, Duration::from_secs(5 + 6));
        assert!(sent(&r).is_empty());
        tick_after(&c, Duration::from_secs(5 + 9));
        assert_eq!(sent(&r).len(), 1);
    }

    #[test]
    fn unanswered_request_is_retransmitted_then_discovery_restarts() {
        let (r, c) = setup();
        c.begin(false);
        c.handle_packet(&make_offer(xid(&c), r.mac));
        assert_eq!(sent(&r).len(), 2);

        let mut t = Duration::ZERO;
        for _ in 1..MAX_REQUESTS {
            t += MAX_RETRANSMIT + Duration::from_secs(1);
            tick_after(&c, t);
            let got = sent(&r);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].2.msg_type, wire::MSG_REQUEST);
            assert_eq!(got[0].2.requested_ip, Some(Ipv4Addr::new(192, 168, 1, 100)));
        }
        t += MAX_RETRANSMIT + Duration::from_secs(1);
        tick_after(&c, t);
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2.msg_type, wire::MSG_DISCOVER);
        assert_eq!(state(&c), State::Selecting);
    }

    #[test]
    fn lease_is_renewed_then_rebound_then_given_up() {
        let (r, c) = bound();
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        tick_after(&c, Duration::from_secs(1799));
        assert!(sent(&r).is_empty(), "T1 is half of the one-hour lease");

        // T1: unicast to the server, the address in ciaddr.
        tick_after(&c, Duration::from_secs(1800));
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert!(got[0].0, "renewal is unicast");
        assert_eq!(got[0].1, ip);
        assert_eq!(got[0].2.msg_type, wire::MSG_REQUEST);
        assert_eq!(got[0].2.requested_ip, None);
        assert_eq!(state(&c), State::Renewing);

        // No answer: again after half the time left to T2 (3150 s).
        tick_after(&c, Duration::from_secs(1800 + 600));
        assert!(sent(&r).is_empty());
        tick_after(&c, Duration::from_secs(1800 + 675));
        assert_eq!(sent(&r).len(), 1, "renewal retried");

        // T2: broadcast to any server.
        tick_after(&c, Duration::from_secs(3150));
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert!(!got[0].0, "rebinding is broadcast");
        assert_eq!(got[0].1, ip);
        assert_eq!(state(&c), State::Rebinding);
        tick_after(&c, Duration::from_secs(3150 + 225));
        assert_eq!(sent(&r).len(), 1, "rebinding retried");

        // Expiry: the address goes, and discovery starts over.
        assert_eq!(*r.lost.lock().unwrap(), 0);
        tick_after(&c, Duration::from_secs(3600));
        assert_eq!(*r.lost.lock().unwrap(), 1);
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2.msg_type, wire::MSG_DISCOVER);
        assert_eq!(state(&c), State::Selecting);
    }

    #[test]
    fn ack_while_rebinding_extends_the_lease() {
        let (r, c) = bound();
        tick_after(&c, Duration::from_secs(3150));
        assert_eq!(state(&c), State::Rebinding);
        c.handle_packet(&make_ack(xid(&c), r.mac));
        assert_eq!(state(&c), State::Bound);
        sent(&r);
        tick_after(&c, Duration::from_secs(1700));
        assert!(sent(&r).is_empty(), "a fresh lease, T1 half an hour out");
    }

    #[test]
    fn nak_while_renewing_gives_the_address_up() {
        let (r, c) = bound();
        tick_after(&c, Duration::from_secs(1800));
        sent(&r);
        c.handle_packet(&reply(wire::MSG_NAK, xid(&c), r.mac));
        assert_eq!(*r.lost.lock().unwrap(), 1);
        assert_eq!(state(&c), State::Selecting);
        assert_eq!(sent(&r)[0].2.msg_type, wire::MSG_DISCOVER);
    }

    #[test]
    fn transport_may_call_back_into_the_client() {
        // A transport that asks the client for its state when bound.
        struct Reentrant(Arc<Mutex<Option<std::sync::Weak<Client>>>>, MacAddr);
        impl ClientTransport for Reentrant {
            fn mac(&self) -> MacAddr {
                self.1
            }
            fn send_broadcast(&self, _: &Frame) {}
            fn send_unicast(&self, _: Ipv4Addr, _: &Frame) {}
            fn on_bound(&self, _: IpPrefix, _: Option<Ipv4Addr>) {
                let c = self.0.lock().unwrap().as_ref().unwrap().upgrade().unwrap();
                assert!(c.is_active());
            }
        }
        let slot = Arc::new(Mutex::new(None));
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let c = Arc::new(Client::new(
            Reentrant(slot.clone(), mac),
            ClientConfig::default(),
        ));
        *slot.lock().unwrap() = Some(Arc::downgrade(&c));

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            c.begin(false);
            c.handle_packet(&make_offer(xid(&c), mac));
            c.handle_packet(&make_ack(xid(&c), mac));
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("on_bound deadlocked calling back into the client");
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
        fn on_lease_lost(&self) {
            self.0.on_lease_lost()
        }
    }
}

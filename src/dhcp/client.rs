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
//!
//! A transport that can send ARP (the `L2Adapter`'s
//! does) lets the client check a newly granted address before using it: a
//! few seconds of ARP probes after the DHCPACK, and a DHCPDECLINE if anyone
//! turns out to hold it (RFC 2131 §2.2, RFC 5227).

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
    /// renewed, the server refused to extend it (DHCPNAK), or the client
    /// was stopped, released or restarted while holding it. The address
    /// from [`on_bound`](Self::on_bound) must no longer be used (RFC 2131
    /// §4.4.5). After an expiry or a NAK the client goes back to discovery
    /// by itself.
    fn on_lease_lost(&self) {}

    /// Whether this transport can check an address for conflicts before
    /// the client binds it (RFC 2131 §2.2, §4.4.1), with
    /// [`send_probe`](Self::send_probe) and
    /// [`probe_conflict`](Self::probe_conflict). Asked once, when the
    /// [`Client`] is built. The default, `false`, binds without checking.
    fn can_probe(&self) -> bool {
        false
    }

    /// A new check of `ip` starts: forget any conflict seen before, for this
    /// address or another. Called before the first
    /// [`send_probe`](Self::send_probe) of each check, so an address
    /// declined once and offered again later is judged afresh.
    fn begin_probe(&self, ip: Ipv4Addr) {
        let _ = ip;
    }

    /// The check under way ended without binding the address: it was
    /// declined, or the client stopped or started over. Whatever was noted about the address being
    /// probed can be forgotten.
    fn end_probe(&self) {}

    /// Send one ARP probe for `ip`: an ARP request from our MAC with sender
    /// address 0.0.0.0 and target `ip` (RFC 5227 §2.1.1). The client sends a
    /// few, a second apart, between the DHCPACK and binding.
    fn send_probe(&self, ip: Ipv4Addr) {
        let _ = ip;
    }

    /// True if, since [`begin_probe`](Self::begin_probe) for `ip`,
    /// another station has shown it is using `ip`: any ARP whose sender
    /// address is `ip`, or another host's probe for it (RFC 5227 §2.1.1).
    /// The client then sends a DHCPDECLINE and starts over.
    fn probe_conflict(&self, ip: Ipv4Addr) -> bool {
        let _ = ip;
        false
    }
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
/// RFC 5227 §1.1: probes sent before claiming an address, the gap between
/// them, and how long to listen after the last. The RFC draws the gap from
/// one to two seconds; a fixed second keeps the whole check near four.
const PROBE_NUM: u32 = 3;
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const ANNOUNCE_WAIT: Duration = Duration::from_secs(2);
/// RFC 2131 §3.1.5: after declining an address, wait at least ten seconds
/// before starting over, so a conflict does not turn into a storm.
const DECLINE_WAIT: Duration = Duration::from_secs(10);
/// How often the background thread looks for due timers. Well under the
/// ±1 s jitter the retransmission delays already carry.
#[cfg(not(target_family = "wasm"))]
const TIMER_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum State {
    Init,
    Selecting,
    Requesting,
    /// ACKed, but checking with ARP that nobody else uses the address.
    Probing,
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
    /// Retransmissions of the outstanding message so far; while PROBING,
    /// probes sent.
    tries: u32,
    /// While PROBING: what to bind once the address proves free.
    pending: Option<(IpPrefix, Option<Ipv4Addr>, Option<LeaseTimers>)>,
    /// Numbers each address check, so an answer about one is never taken
    /// for another.
    probe_check: u64,
    /// Whether the transport has started check `probe_check`
    /// ([`ClientTransport::begin_probe`]). Until then it may still hold a
    /// conflict from an earlier check, which must not be believed.
    probe_live: bool,
    /// When the first REQUEST of the current transaction went out. The
    /// lease runs from then, not from the ACK (RFC 2131 §4.4.1): the server
    /// started its clock when it got the request, and the client must not
    /// think its lease lasts longer than the server does.
    requested_at: Option<Instant>,
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
        self.pending = None;
        self.tries = 0;
        self.next_tx = Some(now + backoff(0));
        Out::Discover(self.xid)
    }

    /// Bind what a DHCPACK granted.
    fn bind(
        &mut self,
        prefix: IpPrefix,
        router: Option<Ipv4Addr>,
        lease: Option<LeaseTimers>,
    ) -> Event {
        self.state = State::Bound;
        self.next_tx = None;
        self.pending = None;
        self.lease = lease;
        Event::Bound(prefix, router)
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
    /// ARP probe for an address about to be bound. `check` is set on the
    /// first probe of a check, which starts it.
    Probe {
        ip: Ipv4Addr,
        check: Option<u64>,
    },
    /// Give the lease back (RFC 2131 §4.4.6).
    Release {
        xid: u32,
        ip: Ipv4Addr,
        server: Ipv4Addr,
    },
    /// The ACKed address is in use by someone else (RFC 2131 §4.4.1).
    Decline {
        xid: u32,
        ip: Ipv4Addr,
        server: Option<Ipv4Addr>,
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
    /// [`ClientTransport::can_probe`], asked once.
    can_probe: bool,
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
        let can_probe = transport.can_probe();
        Client {
            shared: Arc::new(Shared {
                transport,
                mac,
                can_probe,
                inner: Mutex::new(Inner {
                    state: State::Init,
                    xid: 0,
                    offered_ip: None,
                    server_ip: None,
                    lease: None,
                    next_tx: None,
                    tries: 0,
                    pending: None,
                    probe_check: 0,
                    probe_live: false,
                    requested_at: None,
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
        let (out, run, left) = {
            let mut i = self.shared.inner.lock().unwrap();
            let left = Left::of(i.state);
            i.run += 1;
            (i.restart(Instant::now()), i.run, left)
        };
        // Starting over drops any lease held: the transport has to stop
        // using its address, or it would keep it past the lease.
        self.shared.left(left);
        #[cfg(not(target_family = "wasm"))]
        if timer_thread {
            spawn_timer(&self.shared, run);
        }
        let _ = (timer_thread, run);
        self.shared.send(out);
    }

    /// Cancel any pending operations. A lease held is given up:
    /// [`on_lease_lost`](ClientTransport::on_lease_lost) is called, since
    /// nothing would renew it any more and the address must not outlive it.
    ///
    /// The server is not told; it keeps the address for this client until
    /// the lease runs out, so a restart is likely to get it back. RFC 2131
    /// §4.4.6 leaves a DHCPRELEASE to the client's discretion: use
    /// [`release`](Self::release) to send one.
    pub fn stop(&self) {
        self.halt(false);
    }

    /// Hand the lease back to the server with a DHCPRELEASE (RFC 2131
    /// §4.4.6), then stop as [`stop`](Self::stop) does. Without a bound
    /// lease, or a server identifier to address it to, nothing is sent.
    pub fn release(&self) {
        self.halt(true);
    }

    fn halt(&self, release: bool) {
        let (left, out) = {
            let mut i = self.shared.inner.lock().unwrap();
            let left = Left::of(i.state);
            let out = match (release && left.lease, i.offered_ip, i.server_ip) {
                (true, Some(ip), Some(server)) => Some(Out::Release {
                    xid: crate::rand::u32(),
                    ip,
                    server,
                }),
                _ => None,
            };
            i.run += 1;
            i.state = State::Init;
            i.lease = None;
            i.pending = None;
            i.next_tx = None;
            (left, out)
        };
        // The RELEASE goes out first, from the address it gives up: once
        // the transport hears the lease is lost it may unconfigure it.
        if let Some(out) = out {
            self.shared.send(out);
        }
        self.shared.left(left);
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
                // RFC 2131 Table 3: an OFFER and an ACK carry the address
                // in yiaddr and a lease time. One without either grants
                // nothing usable, and binding it would configure 0.0.0.0 or
                // loop on a lease that has already run out.
                (State::Selecting, wire::MSG_OFFER) if !grants_a_lease(&p) => (None, None),
                (_, wire::MSG_ACK) if !grants_a_lease(&p) => (None, None),
                (State::Selecting, wire::MSG_OFFER) => {
                    i.requested_at = Some(now);
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
                    let fresh = i.state == State::Requesting;
                    i.offered_ip = Some(p.yiaddr);
                    if p.server_id.is_some() {
                        i.server_ip = p.server_id;
                    }
                    let lease = lease_timers(
                        i.requested_at.unwrap_or(now),
                        p.lease_time.unwrap_or(0),
                        p.renewal_time,
                        p.rebinding_time,
                    );
                    // A newly granted address is checked before use (RFC
                    // 2131 §4.4.1); one being renewed is ours already.
                    if fresh && self.shared.can_probe {
                        i.state = State::Probing;
                        i.pending = Some((prefix, p.router, lease));
                        i.tries = 1;
                        i.next_tx = Some(now + PROBE_INTERVAL);
                        i.probe_check += 1;
                        i.probe_live = false;
                        (
                            None,
                            Some(Out::Probe {
                                ip: p.yiaddr,
                                check: Some(i.probe_check),
                            }),
                        )
                    } else {
                        (Some(i.bind(prefix, p.router, lease)), None)
                    }
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

/// What a client leaving a state (to stop, or to start over) has to wind up.
#[derive(Copy, Clone)]
struct Left {
    /// A lease was held, and is now lost.
    lease: bool,
    /// An address check was under way.
    probe: bool,
}

impl Left {
    fn of(state: State) -> Left {
        Left {
            lease: matches!(state, State::Bound | State::Renewing | State::Rebinding),
            probe: state == State::Probing,
        }
    }
}

impl Shared {
    /// Tell the transport what leaving a state gave up. No lock held.
    fn left(&self, left: Left) {
        if left.probe {
            self.transport.end_probe();
        }
        if left.lease {
            self.transport.on_lease_lost();
        }
    }

    fn tick(&self, now: Instant) {
        // Asked with no lock held, like every other transport call -- so
        // only once the check has begun, and only believed if it is still
        // the same check afterwards. Between the ACK and begin_probe the
        // transport may still report a conflict from a check before.
        let probing = {
            let i = self.inner.lock().unwrap();
            match (i.state, i.offered_ip) {
                (State::Probing, Some(ip)) if i.probe_live => Some((ip, i.probe_check)),
                _ => None,
            }
        };
        let conflict = probing.filter(|&(ip, _)| self.transport.probe_conflict(ip));
        let (event, out) = {
            let mut i = self.inner.lock().unwrap();
            let conflict = conflict
                .is_some_and(|(_, check)| i.state == State::Probing && i.probe_check == check);
            step(&mut i, now, conflict)
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
            Out::Probe { ip, check } => {
                if let Some(check) = check {
                    self.transport.begin_probe(ip);
                    let mut i = self.inner.lock().unwrap();
                    if i.state == State::Probing && i.probe_check == check {
                        i.probe_live = true;
                    }
                }
                self.transport.send_probe(ip)
            }
            // RFC 2131 Table 5: a RELEASE carries the address in ciaddr and
            // the server identifier, and is unicast to that server.
            Out::Release { xid, ip, server } => {
                let mut b = wire::Builder::new(1, xid, mac);
                b.message_type(wire::MSG_RELEASE)
                    .ciaddr(ip)
                    .ipv4_option(wire::OPT_SERVER_ID, server);
                let frame = wrap_unicast(mac, ip, server, &b.finish());
                self.transport
                    .send_unicast(server, Frame::from_slice(&frame));
            }
            // RFC 2131 Table 5: the declined address and the server go in
            // options; ciaddr stays zero, since the client has no address.
            Out::Decline { xid, ip, server } => {
                self.transport.end_probe();
                let mut b = wire::Builder::new(1, xid, mac);
                b.message_type(wire::MSG_DECLINE)
                    .ipv4_option(wire::OPT_REQUESTED_IP, ip);
                if let Some(s) = server {
                    b.ipv4_option(wire::OPT_SERVER_ID, s);
                }
                let frame = wrap_for_broadcast(mac, &b.finish());
                self.transport.send_broadcast(Frame::from_slice(&frame));
            }
        }
    }
}

/// The state machine's timed transitions. `conflict` is the transport's
/// answer, while PROBING, to whether someone else has the address.
fn step(i: &mut Inner, now: Instant, conflict: bool) -> (Option<Event>, Option<Out>) {
    let due = |at: Option<Instant>| at.is_some_and(|at| at <= now);
    match i.state {
        State::Init => (None, None),
        State::Probing => {
            let Some(ip) = i.offered_ip else {
                return (None, Some(i.restart(now)));
            };
            if conflict {
                let (xid, server) = (i.xid, i.server_ip);
                let _ = i.restart(now);
                i.next_tx = Some(now + DECLINE_WAIT);
                return (None, Some(Out::Decline { xid, ip, server }));
            }
            if !due(i.next_tx) {
                return (None, None);
            }
            if i.tries < PROBE_NUM {
                i.tries += 1;
                let wait = if i.tries == PROBE_NUM {
                    ANNOUNCE_WAIT
                } else {
                    PROBE_INTERVAL
                };
                i.next_tx = Some(now + wait);
                return (None, Some(Out::Probe { ip, check: None }));
            }
            let Some((prefix, router, lease)) = i.pending else {
                return (None, Some(i.restart(now)));
            };
            (Some(i.bind(prefix, router, lease)), None)
        }
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
                    // Straight from BOUND (no server to renew with) this is a
                    // new transaction; from RENEWING it carries on the same
                    // one, so a late answer to a renewal still counts.
                    if i.state == State::Bound {
                        i.xid = crate::rand::u32();
                        i.requested_at = Some(now);
                    }
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
                    i.requested_at = Some(now);
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

/// Whether an OFFER or ACK grants something the client can use: a unicast
/// address and a lease time (RFC 2131 Table 3 makes both MUSTs). A lease
/// time of zero is no lease at all.
fn grants_a_lease(p: &wire::Parsed) -> bool {
    let a = p.yiaddr;
    let unicast = !(a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_loopback()
        || a.octets()[0] == 0
        || a.octets()[0] >= 240);
    unicast && p.lease_time.is_some_and(|l| l != 0)
}

/// Timers for a lease of `secs` seconds that started at `start`.
///
/// T1 and T2 come from options 58 and 59 when the server sent sensible ones
/// (T1 < T2 < lease), and otherwise default to half and seven eighths of
/// the lease (RFC 2131 §4.4.5). Each is fuzzed by up to a second either
/// way, as §4.4.5 asks, so that clients leased together do not all renew
/// in the same instant. A lease of 0xffffffff is infinite (§3.3), as is one
/// too long for the clock to represent.
fn lease_timers(
    start: Instant,
    secs: u32,
    t1: Option<u32>,
    t2: Option<u32>,
) -> Option<LeaseTimers> {
    if secs == u32::MAX {
        return None;
    }
    let lease = Duration::from_secs(secs as u64);
    let t2 = t2
        .map(|s| Duration::from_secs(s as u64))
        .filter(|&t| t < lease)
        .unwrap_or(lease * 7 / 8);
    let t1 = t1
        .map(|s| Duration::from_secs(s as u64))
        .filter(|&t| t < t2)
        .unwrap_or((lease / 2).min(t2));
    let fuzz = |d: Duration| {
        let up = Duration::from_millis((crate::rand::u32() % 2001) as u64);
        (d + up).saturating_sub(Duration::from_secs(1))
    };
    let expiry = start.checked_add(lease)?;
    let t2 = start.checked_add(fuzz(t2))?.min(expiry);
    let t1 = start.checked_add(fuzz(t1))?.min(t2);
    Some(LeaseTimers { t1, t2, expiry })
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
        /// Probing support, the probes sent, and whether one was answered.
        probing: bool,
        probes: Mutex<Vec<Ipv4Addr>>,
        conflict: Mutex<bool>,
        /// Checks started with `begin_probe`, and ended with `end_probe`.
        checks: Mutex<u32>,
        ended: Mutex<u32>,
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

    /// A reply built by hand, for the malformed cases.
    fn custom(
        msg_type: u8,
        xid: u32,
        mac: MacAddr,
        yiaddr: Ipv4Addr,
        lease: Option<u32>,
        extra: &[(u8, u32)],
    ) -> Vec<u8> {
        let mut b = wire::Builder::new(2, xid, mac);
        b.yiaddr(yiaddr)
            .message_type(msg_type)
            .ipv4_option(wire::OPT_SERVER_ID, Ipv4Addr::new(192, 168, 1, 1));
        if let Some(l) = lease {
            b.u32_option(wire::OPT_LEASE_TIME, l);
        }
        for (code, v) in extra {
            b.u32_option(*code, *v);
        }
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

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);

    #[test]
    fn offers_and_acks_without_a_usable_address_or_lease_are_ignored() {
        let (r, c) = setup();
        c.begin(false);
        let x = xid(&c);
        for bad in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST] {
            c.handle_packet(&custom(wire::MSG_OFFER, x, r.mac, bad, Some(3600), &[]));
            assert_eq!(state(&c), State::Selecting, "took an offer of {bad}");
        }
        // RFC 2131 Table 3: an OFFER MUST carry a lease time.
        c.handle_packet(&custom(wire::MSG_OFFER, x, r.mac, IP, None, &[]));
        assert_eq!(state(&c), State::Selecting);

        c.handle_packet(&make_offer(x, r.mac));
        assert_eq!(state(&c), State::Requesting);
        c.handle_packet(&custom(
            wire::MSG_ACK,
            x,
            r.mac,
            Ipv4Addr::UNSPECIFIED,
            Some(3600),
            &[],
        ));
        c.handle_packet(&custom(wire::MSG_ACK, x, r.mac, IP, None, &[]));
        c.handle_packet(&custom(wire::MSG_ACK, x, r.mac, IP, Some(0), &[]));
        assert!(r.bound.lock().unwrap().is_none(), "bound a bad ACK");
        assert_eq!(state(&c), State::Requesting);
    }

    #[test]
    fn lease_is_timed_from_the_request_and_honours_t1_t2() {
        let (r, c) = setup();
        c.begin(false);
        c.handle_packet(&make_offer(xid(&c), r.mac));
        // The REQUEST went out 100 s before the ACK arrives.
        {
            let mut i = c.shared.inner.lock().unwrap();
            i.requested_at = i
                .requested_at
                .and_then(|t| t.checked_sub(Duration::from_secs(100)));
        }
        let ack = custom(
            wire::MSG_ACK,
            xid(&c),
            r.mac,
            IP,
            Some(3600),
            &[
                (wire::OPT_RENEWAL_TIME, 1000),
                (wire::OPT_REBINDING_TIME, 2000),
            ],
        );
        let now = Instant::now();
        c.handle_packet(&ack);
        let l = c.shared.inner.lock().unwrap().lease.unwrap();
        let near = |t: Instant, secs: u64| {
            let want = now + Duration::from_secs(secs) - Duration::from_secs(100);
            let d = if t > want { t - want } else { want - t };
            d <= Duration::from_secs(2)
        };
        assert!(near(l.expiry, 3600), "expiry not counted from the request");
        assert!(near(l.t1, 1000), "T1 option ignored");
        assert!(near(l.t2, 2000), "T2 option ignored");

        // Options that make no sense fall back to the defaults.
        let t = lease_timers(now, 3600, Some(3000), Some(2000));
        let t = t.unwrap();
        assert!(t.t1 <= t.t2 && t.t2 <= t.expiry);
        assert!(t.t1 < now + Duration::from_secs(1802));
    }

    #[test]
    fn rebinding_without_a_server_identifier_starts_a_new_transaction() {
        let (r, c) = bound();
        c.shared.inner.lock().unwrap().server_ip = None;
        let old = xid(&c);
        tick_after(&c, Duration::from_secs(1802));
        assert_eq!(state(&c), State::Rebinding);
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert_ne!(got[0].2.xid, old, "rebinding reused the old xid");
    }

    #[test]
    fn lease_is_renewed_then_rebound_then_given_up() {
        let (r, c) = bound();
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        tick_after(&c, Duration::from_secs(1798));
        assert!(
            sent(&r).is_empty(),
            "T1 is half of the one-hour lease, give or take a second"
        );

        // T1: unicast to the server, the address in ciaddr.
        tick_after(&c, Duration::from_secs(1801));
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert!(got[0].0, "renewal is unicast");
        assert_eq!(got[0].1, ip);
        assert_eq!(got[0].2.msg_type, wire::MSG_REQUEST);
        assert_eq!(got[0].2.requested_ip, None);
        assert_eq!(state(&c), State::Renewing);

        // No answer: again after half the time left to T2 (3150 s ± 1 s).
        tick_after(&c, Duration::from_secs(2400));
        assert!(sent(&r).is_empty());
        tick_after(&c, Duration::from_secs(2477));
        assert_eq!(sent(&r).len(), 1, "renewal retried");

        // T2: broadcast to any server.
        tick_after(&c, Duration::from_secs(3151));
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        assert!(!got[0].0, "rebinding is broadcast");
        assert_eq!(got[0].1, ip);
        assert_eq!(state(&c), State::Rebinding);
        tick_after(&c, Duration::from_secs(3377));
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
        tick_after(&c, Duration::from_secs(3151));
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
        tick_after(&c, Duration::from_secs(1801));
        sent(&r);
        c.handle_packet(&reply(wire::MSG_NAK, xid(&c), r.mac));
        assert_eq!(*r.lost.lock().unwrap(), 1);
        assert_eq!(state(&c), State::Selecting);
        assert_eq!(sent(&r)[0].2.msg_type, wire::MSG_DISCOVER);
    }

    #[test]
    fn stopping_or_restarting_gives_the_lease_up() {
        let (r, c) = bound();
        c.stop();
        assert_eq!(*r.lost.lock().unwrap(), 1, "address kept past stop");
        assert!(r.bound.lock().unwrap().is_none());
        assert!(sent(&r).is_empty(), "stop() is not a release");
        c.stop();
        assert_eq!(*r.lost.lock().unwrap(), 1, "lost twice");

        let (r, c) = bound();
        tick_after(&c, Duration::from_secs(1801));
        assert_eq!(state(&c), State::Renewing);
        c.begin(false);
        assert_eq!(*r.lost.lock().unwrap(), 1, "address kept past restart");

        // Stopping mid-check ends the check.
        let (r, c) = probing();
        c.stop();
        assert_eq!(*r.ended.lock().unwrap(), 1);
        assert_eq!(*r.lost.lock().unwrap(), 0, "nothing was bound");
    }

    #[test]
    fn release_hands_the_lease_back_to_its_server() {
        let (r, c) = bound();
        c.release();
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        let (unicast, ciaddr, p) = &got[0];
        assert!(unicast);
        assert_eq!(p.msg_type, wire::MSG_RELEASE);
        assert_eq!(*ciaddr, IP);
        assert_eq!(p.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(*r.lost.lock().unwrap(), 1);
        assert_eq!(state(&c), State::Init);

        // Nothing to release when nothing is bound.
        c.release();
        assert!(sent(&r).is_empty());
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
        fn can_probe(&self) -> bool {
            self.0.probing
        }
        fn begin_probe(&self, _ip: Ipv4Addr) {
            *self.0.checks.lock().unwrap() += 1;
        }
        fn end_probe(&self) {
            *self.0.ended.lock().unwrap() += 1;
        }
        fn send_probe(&self, ip: Ipv4Addr) {
            self.0.probes.lock().unwrap().push(ip);
        }
        fn probe_conflict(&self, _ip: Ipv4Addr) -> bool {
            *self.0.conflict.lock().unwrap()
        }
    }

    fn probing() -> (Arc<Recorder>, Client) {
        let r = Arc::new(Recorder {
            mac: "02:00:00:00:00:01".parse().unwrap(),
            probing: true,
            ..Default::default()
        });
        let c = Client::new(ArcTransport(r.clone()), ClientConfig::default());
        c.begin(false);
        c.handle_packet(&make_offer(xid(&c), r.mac));
        c.handle_packet(&make_ack(xid(&c), r.mac));
        sent(&r);
        (r, c)
    }

    #[test]
    fn the_address_is_probed_before_it_is_bound() {
        let (r, c) = probing();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        assert!(r.bound.lock().unwrap().is_none(), "bound before probing");
        assert_eq!(*r.probes.lock().unwrap(), vec![ip]);

        tick_after(&c, Duration::from_millis(1100));
        tick_after(&c, Duration::from_millis(2200));
        assert_eq!(r.probes.lock().unwrap().len(), 3, "RFC 5227 PROBE_NUM");
        assert_eq!(*r.checks.lock().unwrap(), 1, "one check, three probes");
        assert!(r.bound.lock().unwrap().is_none());

        // ANNOUNCE_WAIT after the last probe with no answer: it is ours.
        tick_after(&c, Duration::from_millis(4300));
        assert_eq!(r.bound.lock().unwrap().unwrap().0.addr(), IpAddr::V4(ip));
        assert_eq!(state(&c), State::Bound);
        assert!(sent(&r).is_empty());
    }

    #[test]
    fn a_conflict_left_from_an_earlier_check_is_not_believed() {
        // The transport still reports the last check's conflict until
        // begin_probe clears it, and a tick lands just before that.
        struct Stale {
            client: Mutex<std::sync::Weak<Client>>,
            conflict: Mutex<bool>,
            declined: Mutex<bool>,
        }
        struct T(Arc<Stale>);
        impl ClientTransport for T {
            fn mac(&self) -> MacAddr {
                MacAddr([2, 0, 0, 0, 0, 1])
            }
            fn send_broadcast(&self, f: &Frame) {
                let p = wire::Parsed::from_bytes(&f.as_bytes()[42..]).unwrap();
                if p.msg_type == wire::MSG_DECLINE {
                    *self.0.declined.lock().unwrap() = true;
                }
            }
            fn send_unicast(&self, _: Ipv4Addr, _: &Frame) {}
            fn on_bound(&self, _: IpPrefix, _: Option<Ipv4Addr>) {}
            fn can_probe(&self) -> bool {
                true
            }
            fn begin_probe(&self, _: Ipv4Addr) {
                if let Some(c) = self.0.client.lock().unwrap().upgrade() {
                    c.tick();
                }
                *self.0.conflict.lock().unwrap() = false;
            }
            fn probe_conflict(&self, _: Ipv4Addr) -> bool {
                *self.0.conflict.lock().unwrap()
            }
        }
        let st = Arc::new(Stale {
            client: Mutex::new(std::sync::Weak::new()),
            conflict: Mutex::new(true),
            declined: Mutex::new(false),
        });
        let c = Arc::new(Client::new(T(st.clone()), ClientConfig::default()));
        *st.client.lock().unwrap() = Arc::downgrade(&c);
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        c.begin(false);
        c.handle_packet(&make_offer(xid(&c), mac));
        c.handle_packet(&make_ack(xid(&c), mac));
        assert!(
            !*st.declined.lock().unwrap(),
            "declined on a stale conflict"
        );
        assert_eq!(state(&c), State::Probing);

        // A conflict seen once the check is under way still counts.
        *st.conflict.lock().unwrap() = true;
        c.tick();
        assert!(*st.declined.lock().unwrap());
    }

    #[test]
    fn a_conflict_is_declined_and_discovery_restarts_after_a_pause() {
        let (r, c) = probing();
        *r.conflict.lock().unwrap() = true;
        tick_after(&c, Duration::from_millis(500));

        assert!(
            r.bound.lock().unwrap().is_none(),
            "bound a conflicting address"
        );
        let got = sent(&r);
        assert_eq!(got.len(), 1);
        let d = &got[0].2;
        assert_eq!(d.msg_type, wire::MSG_DECLINE);
        assert_eq!(d.requested_ip, Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(d.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(d.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(state(&c), State::Selecting);

        // RFC 2131 §3.1.5: at least ten seconds before trying again.
        *r.conflict.lock().unwrap() = false;
        tick_after(&c, Duration::from_secs(9));
        assert!(sent(&r).is_empty());
        tick_after(&c, Duration::from_secs(11));
        assert_eq!(sent(&r)[0].2.msg_type, wire::MSG_DISCOVER);
    }
}

//! DHCP server. Hands out leases on an Ethernet network.

use super::wire;
use crate::time::Instant;
use crate::{
    EtherType, Frame, L2Device, L2Handler, MacAddr, Protocol, Result, build_frame, checksum,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

const MAX_LEASES: usize = 1024;
const OFFER_HOLD: Duration = Duration::from_secs(60);
const DEFAULT_LEASE: Duration = Duration::from_secs(3600);
/// The lease granted to a client asking for an address we have no record
/// of giving it. As short as an offer's hold, since such a request is as
/// cheap to forge as a DISCOVER; a real client renews at half of it and
/// then gets the full lease, a forger has to keep asking.
const PROVISIONAL_LEASE: Duration = OFFER_HOLD;
/// How long a provisional lease must have been held before a renewal makes
/// it whole: the half of it at which a real client renews (RFC 2131 T1).
/// Anything sooner is a client asking again, not renewing, and stays
/// provisional.
const PROVISIONAL_MIN_AGE: Duration = Duration::from_secs(PROVISIONAL_LEASE.as_secs() / 2);

/// Configure a [`Server`].
#[derive(Clone)]
#[non_exhaustive]
pub struct ServerConfig {
    /// The server's own address: the source of its replies and the server
    /// identifier (option 54) clients answer to.
    pub server_ip: Ipv4Addr,
    /// Subnet mask handed to clients (option 1). Default `/24`.
    pub subnet_mask: Ipv4Addr,
    /// First address of the dynamic pool, inclusive.
    pub range_start: Ipv4Addr,
    /// Last address of the dynamic pool, inclusive.
    pub range_end: Ipv4Addr,
    /// Default gateway handed to clients (option 3), if any.
    pub router: Option<Ipv4Addr>,
    /// DNS servers handed to clients (option 6).
    pub dns: Vec<Ipv4Addr>,
    /// Lease length granted. Default one hour.
    pub lease_time: Duration,
    /// The server's MAC, the source of the frames it sends.
    pub mac: MacAddr,
    /// Reserved IPs handed out to specific clients, never recycled to anyone
    /// else.
    pub static_leases: HashMap<MacAddr, Ipv4Addr>,
}

setters! {
    ServerConfig {
        set server_ip: Ipv4Addr;
        set subnet_mask: Ipv4Addr;
        set range_start: Ipv4Addr;
        set range_end: Ipv4Addr;
        some router: Ipv4Addr;
        set dns: Vec<Ipv4Addr>;
        set lease_time: Duration;
        set mac: MacAddr;
        set static_leases: HashMap<MacAddr, Ipv4Addr>;
    }
}

impl core::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("server_ip", &self.server_ip)
            .field("subnet_mask", &self.subnet_mask)
            .field("range_start", &self.range_start)
            .field("range_end", &self.range_end)
            .field("router", &self.router)
            .field("dns", &self.dns)
            .field("lease_time", &self.lease_time)
            .field("mac", &self.mac)
            .field("static_leases", &self.static_leases.len())
            .finish()
    }
}

impl ServerConfig {
    /// New config with defaults: 1-hour lease, /24 subnet, MAC `02:DD:CC:00:00:01`.
    pub fn new(server_ip: Ipv4Addr, range_start: Ipv4Addr, range_end: Ipv4Addr) -> ServerConfig {
        ServerConfig {
            server_ip,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            range_start,
            range_end,
            router: None,
            dns: Vec::new(),
            lease_time: DEFAULT_LEASE,
            mac: MacAddr([0x02, 0xDD, 0xCC, 0x00, 0x00, 0x01]),
            static_leases: HashMap::new(),
        }
    }
}

/// A client's MAC (for an Ethernet client) and the address reserved for
/// it in [`ServerConfig::static_leases`], if any.
#[derive(Clone, Copy)]
struct Reservation {
    mac: Option<MacAddr>,
    ip: Option<Ipv4Addr>,
}

enum Answer {
    /// The address, and the lease time to grant, in seconds.
    Ack(Ipv4Addr, u32),
    Nak,
    Silent,
}

/// Whom a lease is for. RFC 2131 §4.2: the client identifier (option 61)
/// when the client sends one, which "MUST" then be the key, and otherwise
/// the hardware address, taken with its type and length since `chaddr` is
/// 16 bytes of which only `hlen` are the address.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum ClientKey {
    Id(Vec<u8>),
    Hw(u8, Vec<u8>),
}

impl ClientKey {
    /// `None` for a message whose `hlen` overruns `chaddr`.
    fn of(p: &wire::Parsed) -> Option<ClientKey> {
        if let Some(id) = &p.client_id {
            return Some(ClientKey::Id(id.clone()));
        }
        let hw = p.chaddr_field.get(..p.hlen as usize)?;
        Some(ClientKey::Hw(p.htype, hw.to_vec()))
    }
}

#[derive(Copy, Clone)]
struct Lease {
    ip: Ipv4Addr,
    expiry: Instant,
    bound: bool,
    /// For a lease granted on the client's word alone (see
    /// [`PROVISIONAL_LEASE`]), when it was first granted. `None` for a
    /// full lease, or an offer.
    provisional: Option<Instant>,
}

/// The lease table, indexed by address too, so that whether an address is
/// taken is a lookup rather than a walk over every lease on each packet.
#[derive(Default)]
struct Leases {
    by_key: HashMap<ClientKey, Lease>,
    /// How many leases hold each address. More than one only for a machine
    /// seen under two keys (with and without a client identifier), each
    /// given the address reserved for its MAC.
    by_ip: HashMap<Ipv4Addr, u32>,
}

/// Reads go straight to the table; writes go through [`Leases`]'s own
/// methods, which keep the index in step.
impl core::ops::Deref for Leases {
    type Target = HashMap<ClientKey, Lease>;
    fn deref(&self) -> &Self::Target {
        &self.by_key
    }
}

impl Leases {
    fn insert(&mut self, key: ClientKey, lease: Lease) {
        if let Some(old) = self.by_key.insert(key, lease) {
            self.unindex(old.ip);
        }
        *self.by_ip.entry(lease.ip).or_default() += 1;
    }

    fn remove(&mut self, key: &ClientKey) -> Option<Lease> {
        let old = self.by_key.remove(key)?;
        self.unindex(old.ip);
        Some(old)
    }

    fn unindex(&mut self, ip: Ipv4Addr) {
        if let Some(n) = self.by_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                self.by_ip.remove(&ip);
            }
        }
    }

    /// Drop the leases and offers run out by `now`.
    fn expire(&mut self, now: Instant) {
        let by_ip = &mut self.by_ip;
        self.by_key.retain(|_, l| {
            let live = l.expiry > now;
            if !live && let Some(n) = by_ip.get_mut(&l.ip) {
                *n -= 1;
                if *n == 0 {
                    by_ip.remove(&l.ip);
                }
            }
            live
        });
    }

    /// Whether a lease other than `key`'s holds `ip`.
    fn held_by_other(&self, ip: Ipv4Addr, key: &ClientKey) -> bool {
        let n = self.by_ip.get(&ip).copied().unwrap_or(0);
        let own = self.by_key.get(key).is_some_and(|l| l.ip == ip);
        n > u32::from(own)
    }
}

/// A DHCP server, implementing [`L2Device`] so it plugs into an
/// [`L2Hub`](crate::L2Hub) like any other device.
pub struct Server {
    cfg: ServerConfig,
    handler: Mutex<Option<L2Handler>>,
    leases: Mutex<Leases>,
    declined: Mutex<HashMap<Ipv4Addr, Instant>>,
    /// [`ServerConfig::static_leases`] by address: the MACs each is
    /// reserved for.
    reserved: HashMap<Ipv4Addr, Vec<MacAddr>>,
    /// How many clients the server can hold leases for: the pool's size,
    /// up to [`MAX_LEASES`].
    capacity: usize,
}

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("dhcp::Server")
            .field("mac", &self.cfg.mac)
            .field("server_ip", &self.cfg.server_ip)
            .finish()
    }
}

impl Server {
    /// Build a new server.
    pub fn new(cfg: ServerConfig) -> Server {
        let mut reserved = HashMap::<_, Vec<_>>::new();
        for (mac, ip) in &cfg.static_leases {
            reserved.entry(*ip).or_default().push(*mac);
        }
        Server {
            capacity: pool_size(&cfg).min(MAX_LEASES),
            reserved,
            cfg,
            handler: Mutex::new(None),
            leases: Mutex::new(Leases::default()),
            declined: Mutex::new(HashMap::new()),
        }
    }

    /// Decode a UDP/DHCP payload and react. Public so callers that already
    /// stripped the IP and UDP headers can drive the server directly.
    ///
    /// Without the Ethernet frame the server does not know a relay agent's
    /// MAC, so replies to a relay go to the broadcast MAC (still addressed
    /// to the relay's IP). Frames given to [`send`](L2Device::send) do not
    /// have that problem.
    pub fn handle_dhcp(&self, msg: &[u8]) {
        self.handle(msg, None);
    }

    /// `from` is the Ethernet source of the request: for a relayed one, the
    /// relay agent (or the router toward it), which is where the answer goes.
    fn handle(&self, msg: &[u8], from: Option<MacAddr>) {
        let p = match wire::Parsed::from_bytes(msg) {
            Some(p) => p,
            None => return,
        };
        if p.op != 1 {
            return; // not a BOOTREQUEST
        }
        // A hardware address longer than chaddr's 16 bytes is malformed.
        let Some(key) = ClientKey::of(&p) else {
            return;
        };
        // RFC 2131 §4.3.1: a relayed request is for the subnet the relay
        // sits on. This server has one pool; for a relay on any other
        // subnet it has nothing that would work there, so it stays out.
        if !p.giaddr.is_unspecified() && !self.on_our_subnet(p.giaddr) {
            return;
        }
        match p.msg_type {
            wire::MSG_DISCOVER => {
                if let Some(ip) = self.allocate(&key, self.reservation(&p)) {
                    let lease = (ip, self.lease_secs());
                    self.send_reply(&p, from, wire::MSG_OFFER, Some(lease));
                }
            }
            wire::MSG_REQUEST => match self.request(&p, &key) {
                Answer::Ack(ip, secs) => self.send_reply(&p, from, wire::MSG_ACK, Some((ip, secs))),
                Answer::Nak => self.send_nak(&p, from),
                Answer::Silent => {}
            },
            wire::MSG_RELEASE => self.release(&p, &key),
            wire::MSG_DECLINE => self.decline(&p, &key),
            wire::MSG_INFORM => {
                self.send_reply(&p, from, wire::MSG_ACK, None);
            }
            _ => {}
        }
    }

    /// A client gives its lease back (RFC 2131 §4.4.6).
    ///
    /// Like a DECLINE this is unauthenticated, and chaddr is whatever the
    /// sender wrote, so it is believed only as a real client would send it:
    /// naming us as the server and carrying in ciaddr the address it holds
    /// (Table 5). Otherwise anyone could free a client's address for
    /// someone else to be given while the client still uses it.
    fn release(&self, p: &wire::Parsed, key: &ClientKey) {
        if p.server_id != Some(self.cfg.server_ip) {
            return;
        }
        let mut leases = self.leases.lock().unwrap();
        if leases.get(key).is_some_and(|l| l.ip == p.ciaddr) {
            leases.remove(key);
        }
    }

    /// The address reserved for the client that sent `p`, if any.
    /// Reservations are by MAC, so only an Ethernet client can have one.
    fn reservation(&self, p: &wire::Parsed) -> Reservation {
        let mac = (p.htype == 1 && p.hlen == 6).then_some(p.chaddr);
        Reservation {
            mac,
            ip: mac.and_then(|m| self.cfg.static_leases.get(&m).copied()),
        }
    }

    /// A client found the address we gave it already in use (RFC 2131
    /// §4.3.3), so we stop handing it out for a while.
    ///
    /// A DECLINE is unauthenticated broadcast, so it is believed only as far
    /// as it could be true: it must name us as the server (Table 5 makes the
    /// server identifier and requested address MUSTs), and the address must
    /// be the one this very client was offered or leased. Anything else
    /// would let one station fence off the whole pool, or grow the declined
    /// table without bound.
    fn decline(&self, p: &wire::Parsed, key: &ClientKey) {
        if p.server_id != Some(self.cfg.server_ip) {
            return;
        }
        let Some(ip) = p.requested_ip else {
            return;
        };
        let now = Instant::now();
        let mut leases = self.live_leases(now);
        let ours =
            leases.get(key).is_some_and(|l| l.ip == ip) || self.reservation(p).ip == Some(ip);
        if !ours {
            return;
        }
        leases.remove(key);
        let mut declined = self.declined.lock().unwrap();
        // Only addresses we gave out get here, so this bounds only what a
        // pathological configuration (a pool larger than the table) allows.
        if declined.len() >= MAX_LEASES && !declined.contains_key(&ip) {
            return;
        }
        declined.insert(ip, self.lease_end(now));
    }

    /// The table as of `now`: leases and offers that have run out are
    /// dropped, so they neither keep their address from anyone else nor
    /// count toward [`MAX_LEASES`].
    fn live_leases(&self, now: Instant) -> std::sync::MutexGuard<'_, Leases> {
        let mut leases = self.leases.lock().unwrap();
        leases.expire(now);
        self.declined.lock().unwrap().retain(|_, exp| *exp > now);
        leases
    }

    /// Whether client `key` (with reservation `res`) cannot have `ip`
    /// because another client holds or has it reserved.
    fn held_by_others(
        &self,
        leases: &Leases,
        (key, res): (&ClientKey, Reservation),
        ip: Ipv4Addr,
    ) -> bool {
        leases.held_by_other(ip, key)
            || self
                .reserved
                .get(&ip)
                .is_some_and(|macs| macs.iter().any(|m| Some(*m) != res.mac))
    }

    /// Pick an address to OFFER. The offer only reserves it for
    /// [`OFFER_HOLD`]: a DISCOVER is unauthenticated and cheap to forge, and
    /// holding the address for a whole lease would let a flood of made-up
    /// client addresses drain the pool.
    fn allocate(&self, key: &ClientKey, res: Reservation) -> Option<Ipv4Addr> {
        let now = Instant::now();
        if let Some(ip) = res.ip {
            // A reservation off our subnet could never be ACKed (see
            // `commit`); offering it would only start the same loop.
            return self.on_our_subnet(ip).then_some(ip);
        }
        let mut leases = self.live_leases(now);

        if let Some(l) = leases.get(key).copied() {
            if !self.held_by_others(&leases, (key, res), l.ip) {
                if !l.bound {
                    let expiry = now + OFFER_HOLD;
                    leases.insert(key.clone(), Lease { expiry, ..l });
                }
                return Some(l.ip);
            }
            leases.remove(key);
        }

        if leases.len() >= MAX_LEASES {
            return None;
        }

        let declined = self.declined.lock().unwrap();
        let start = u32::from(self.cfg.range_start);
        let end = u32::from(self.cfg.range_end);
        let ip = (start..=end).map(Ipv4Addr::from).find(|ip| {
            self.in_pool(*ip)
                && !self.held_by_others(&leases, (key, res), *ip)
                && !declined.contains_key(ip)
        })?;
        leases.insert(
            key.clone(),
            Lease {
                ip,
                expiry: now + OFFER_HOLD,
                bound: false,
                provisional: None,
            },
        );
        Some(ip)
    }

    /// Answer a DHCPREQUEST, telling apart the client states of RFC 2131
    /// §4.3.2 by which of server identifier, requested address and ciaddr
    /// it carries.
    fn request(&self, p: &wire::Parsed, key: &ClientKey) -> Answer {
        let now = Instant::now();
        let mut leases = self.live_leases(now);
        let mut renewing = false;
        let ip = match (p.server_id, p.requested_ip) {
            // SELECTING, but the client took another server's offer: ours is
            // free again.
            (Some(sid), _) if sid != self.cfg.server_ip => {
                if leases.get(key).is_some_and(|l| !l.bound) {
                    leases.remove(key);
                }
                return Answer::Silent;
            }
            // SELECTING our offer, which must be for the address it names.
            (Some(_), Some(ip)) => {
                if leases.get(key).is_some_and(|l| !l.bound && l.ip != ip) {
                    leases.remove(key);
                    return Answer::Nak;
                }
                ip
            }
            // INIT-REBOOT: the client asks to keep an address it remembers.
            (None, Some(ip)) => ip,
            // RENEWING or REBINDING: the address is in ciaddr.
            (None, None) if !p.ciaddr.is_unspecified() => {
                renewing = true;
                p.ciaddr
            }
            _ => return Answer::Silent,
        };
        self.commit(&mut leases, (key, self.reservation(p)), ip, renewing, now)
    }

    /// Bind `ip` to client `key` (with reservation `res`) if the server
    /// agrees that is the client's address. `renewing` is set for a client
    /// RENEWING or REBINDING, which is already using `ip`.
    fn commit(
        &self,
        leases: &mut Leases,
        (key, res): (&ClientKey, Reservation),
        ip: Ipv4Addr,
        renewing: bool,
        now: Instant,
    ) -> Answer {
        let lease = Lease {
            ip,
            expiry: self.lease_end(now),
            bound: true,
            provisional: None,
        };
        if !self.on_our_subnet(ip) {
            return Answer::Nak; // the client moved here from another network
        }
        if let Some(static_ip) = res.ip {
            if ip != static_ip {
                return Answer::Nak;
            }
            leases.insert(key.clone(), lease);
            return Answer::Ack(ip, self.lease_secs());
        }

        let held = self.held_by_others(leases, (key, res), ip);
        match leases.get(key).copied() {
            // A provisional lease is made whole only by what a real client
            // does and a forger cannot hurry: a renewal (ciaddr set, from
            // the address itself) once half of it has passed. The same
            // REQUEST again, or a renewal straight away, costs nothing to
            // send, and would otherwise turn a minute's lease into a full
            // one on the spot. Until then it stays provisional, counted
            // from when it was first granted.
            Some(l) if l.ip == ip && !held && l.provisional.is_some() => {
                let since = l.provisional.unwrap_or(now);
                if renewing && now.saturating_duration_since(since) >= PROVISIONAL_MIN_AGE {
                    leases.insert(key.clone(), lease);
                    return Answer::Ack(ip, self.lease_secs());
                }
                let provisional = self.cfg.lease_time.min(PROVISIONAL_LEASE);
                leases.insert(
                    key.clone(),
                    Lease {
                        expiry: now + provisional,
                        ..l
                    },
                );
                return Answer::Ack(ip, provisional.as_secs() as u32);
            }
            Some(l) if l.ip == ip && !held => {
                leases.insert(key.clone(), lease);
                return Answer::Ack(ip, self.lease_secs());
            }
            Some(l) if l.bound => return Answer::Nak,
            // An outstanding offer the client chose not to take: forget it,
            // and treat the request like one from a client we have no record
            // of.
            Some(_) => {
                leases.remove(key);
            }
            None => {}
        }

        // No record, as after a server restart. RFC 2131 §4.3.2 wants
        // silence here so servers sharing a segment do not fight; an
        // address from our own pool is ours to judge, though, and granting
        // it when it is free lets clients keep their address across a
        // restart -- provisionally, as below.
        if !self.in_pool(ip) {
            return Answer::Silent;
        }
        if held {
            return Answer::Nak;
        }
        {
            let mut declined = self.declined.lock().unwrap();
            if declined.contains_key(&ip) {
                // Having forgotten the lease, we may well have offered the
                // address to someone else, whose ARP check found this very
                // client on it and declined it. A client renewing is using
                // the address, so the decline was about it: refusing it now
                // would take the address from its rightful holder. Anyone
                // else is kept off an address found in use.
                if !renewing {
                    return Answer::Nak;
                }
                declined.remove(&ip);
            }
        }
        // Nothing but its word says the client ever had the address, and
        // a stream of such requests from made-up clients would take the
        // pool a lease at a time, skipping the offer's short hold. So the
        // lease is only as long as that hold, and past three quarters full
        // we keep to the RFC's silence: the client falls back to DISCOVER,
        // and the offer path.
        if leases.len() * 4 >= self.capacity * 3 {
            return Answer::Silent;
        }
        let provisional = self.cfg.lease_time.min(PROVISIONAL_LEASE);
        leases.insert(
            key.clone(),
            Lease {
                expiry: now + provisional,
                provisional: Some(now),
                ..lease
            },
        );
        Answer::Ack(ip, provisional.as_secs() as u32)
    }

    /// The lease time as option 51 carries it. Anything from 0xffffffff
    /// seconds up is infinite (RFC 2131 §3.3), not a value to wrap.
    fn lease_secs(&self) -> u32 {
        u32::try_from(self.cfg.lease_time.as_secs()).unwrap_or(u32::MAX)
    }

    /// When a lease granted `now` runs out. A lease time too long for the
    /// clock (`Duration::MAX` spells "forever" naturally enough) ends as far
    /// out as the clock reaches, instead of panicking on a request from the
    /// network.
    fn lease_end(&self, now: Instant) -> Instant {
        let mut d = self.cfg.lease_time;
        loop {
            if let Some(t) = now.checked_add(d) {
                return t;
            }
            d /= 2;
        }
    }

    /// Whether `ip` is one of the addresses this server hands out: in the
    /// configured range, on the server's subnet, and not one the subnet
    /// already uses for something else, however the range was drawn.
    ///
    /// An address off the subnet is refused by [`commit`](Self::commit)
    /// whatever the pool says; offering one would have the client request
    /// it, be NAKed, and discover again, forever.
    fn in_pool(&self, ip: Ipv4Addr) -> bool {
        let raw = u32::from(ip);
        if raw < u32::from(self.cfg.range_start) || raw > u32::from(self.cfg.range_end) {
            return false;
        }
        if !self.on_our_subnet(ip) {
            return false;
        }
        if ip == self.cfg.server_ip || Some(ip) == self.cfg.router {
            return false;
        }
        // A /31 or /32 has no network or broadcast address (RFC 3021).
        let mask = u32::from(self.cfg.subnet_mask);
        if mask.leading_ones() < 31 {
            let net = u32::from(self.cfg.server_ip) & mask;
            if raw == net || raw == net | !mask {
                return false;
            }
        }
        true
    }

    /// DHCPNAK carries no address or configuration, only who refused
    /// (RFC 2131 Table 3), and is broadcast since the client may have no
    /// usable address.
    fn send_nak(&self, p: &wire::Parsed, from: Option<MacAddr>) {
        let mut b = wire::Builder::new(2, p.xid, p.chaddr);
        b.hardware(p.htype, p.hlen, &p.chaddr_field);
        // Through a relay, the BROADCAST bit tells it to broadcast the NAK
        // on the client's subnet (RFC 2131 §4.1).
        let mut flags = p.flags;
        if !p.giaddr.is_unspecified() {
            flags |= wire::FLAG_BROADCAST;
        }
        b.flags(flags)
            .giaddr(p.giaddr)
            .message_type(wire::MSG_NAK)
            .ipv4_option(wire::OPT_SERVER_ID, self.cfg.server_ip);
        let (mac, ip, port) = self.destination(p, from, None, true);
        self.send_message(mac, ip, port, &b.finish());
    }

    fn send_reply(
        &self,
        p: &wire::Parsed,
        from: Option<MacAddr>,
        msg_type: u8,
        lease: Option<(Ipv4Addr, u32)>,
    ) {
        let yiaddr = lease.map(|(ip, _)| ip);
        let mut b = wire::Builder::new(2, p.xid, p.chaddr);
        // Table 3: htype, hlen, chaddr, flags and giaddr are the client's,
        // echoed back.
        b.hardware(p.htype, p.hlen, &p.chaddr_field)
            .flags(p.flags)
            .giaddr(p.giaddr);
        if let Some(ip) = yiaddr {
            b.yiaddr(ip);
        }
        b.siaddr(self.cfg.server_ip).message_type(msg_type);
        b.ipv4_option(wire::OPT_SUBNET_MASK, self.cfg.subnet_mask);
        if let Some(r) = self.cfg.router {
            b.ipv4_option(wire::OPT_ROUTER, r);
        }
        if !self.cfg.dns.is_empty() {
            b.ipv4_list_option(wire::OPT_DNS, &self.cfg.dns);
        }
        // RFC 2131 Table 3: every OFFER and ACK names its server, an ACK to
        // an INFORM (which grants no address, so carries no lease time)
        // included; clients use it to tell servers' answers apart.
        if let Some((_, secs)) = lease {
            b.u32_option(wire::OPT_LEASE_TIME, secs);
        }
        b.ipv4_option(wire::OPT_SERVER_ID, self.cfg.server_ip);
        let (mac, ip, port) = self.destination(p, from, yiaddr, false);
        self.send_message(mac, ip, port, &b.finish());
    }

    /// Where a reply to `p` goes, as RFC 2131 §4.1 lays out: (Ethernet
    /// destination, IP destination, UDP port).
    fn destination(
        &self,
        p: &wire::Parsed,
        from: Option<MacAddr>,
        yiaddr: Option<Ipv4Addr>,
        nak: bool,
    ) -> (MacAddr, Ipv4Addr, u16) {
        let everyone = (MacAddr::broadcast(), Ipv4Addr::BROADCAST, 68);
        if !p.giaddr.is_unspecified() {
            // Back to the relay, on the server port.
            return (from.unwrap_or(MacAddr::broadcast()), p.giaddr, 67);
        }
        if nak {
            return everyone;
        }
        if !p.ciaddr.is_unspecified() {
            // The client has an address and answers ARP for it.
            return (p.chaddr, p.ciaddr, 68);
        }
        if p.flags & wire::FLAG_BROADCAST != 0 {
            return everyone;
        }
        match yiaddr {
            // Unicast to the new address, at the client's own MAC, since it
            // cannot answer ARP for an address it does not have yet.
            Some(ip) => (p.chaddr, ip, 68),
            None => everyone,
        }
    }

    /// Whether `ip` is on the subnet this server hands addresses out on.
    fn on_our_subnet(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::from(self.cfg.subnet_mask);
        u32::from(ip) & mask == u32::from(self.cfg.server_ip) & mask
    }

    fn send_message(&self, dst_mac: MacAddr, dst_ip: Ipv4Addr, dst_port: u16, dhcp: &[u8]) {
        let udp_len = 8 + dhcp.len();
        let mut udp = Vec::with_capacity(udp_len);
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum = 0
        udp.extend_from_slice(dhcp);

        let ip_len = 20 + udp_len;
        let mut ip = vec![0u8; ip_len];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = Protocol::UDP.as_u8();
        ip[12..16].copy_from_slice(&self.cfg.server_ip.octets());
        ip[16..20].copy_from_slice(&dst_ip.octets());
        let cs = checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&cs.to_be_bytes());
        ip[20..].copy_from_slice(&udp);

        let frame = build_frame(dst_mac, self.cfg.mac, EtherType::IPV4, &ip);
        let h = self.handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(Frame::from_slice(&frame));
        }
    }
}

/// How many addresses [`Server::in_pool`] accepts: the configured range
/// within the server's subnet, less the addresses the subnet uses for
/// something else.
fn pool_size(cfg: &ServerConfig) -> usize {
    let mask = u32::from(cfg.subnet_mask);
    let net = u32::from(cfg.server_ip) & mask;
    let last = net | !mask;
    let lo = u32::from(cfg.range_start).max(net);
    let hi = u32::from(cfg.range_end).min(last);
    if lo > hi {
        return 0;
    }
    let mut taken = vec![u32::from(cfg.server_ip)];
    taken.extend(cfg.router.map(u32::from));
    if mask.leading_ones() < 31 {
        taken.extend([net, last]);
    }
    taken.sort_unstable();
    taken.dedup();
    let taken = taken.iter().filter(|&&a| (lo..=hi).contains(&a)).count() as u64;
    usize::try_from(u64::from(hi - lo) + 1 - taken).unwrap_or(usize::MAX)
}

impl L2Device for Server {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, f: &Frame) -> Result<()> {
        if !f.is_valid() || f.ether_type() != EtherType::IPV4 {
            return Ok(());
        }
        let payload = f.payload();
        if payload.len() < 28 {
            return Ok(());
        }
        if payload[9] != Protocol::UDP.as_u8() {
            return Ok(());
        }
        let ihl = (payload[0] & 0x0F) as usize * 4;
        if ihl < 20 || payload.len() < ihl + 8 {
            return Ok(());
        }
        let udp = &payload[ihl..];
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        if dst_port != 67 {
            return Ok(());
        }
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if udp_len < 8 || udp.len() < udp_len {
            return Ok(());
        }
        let dhcp = &udp[8..udp_len];
        self.handle(dhcp, f.src_mac());
        Ok(())
    }
    fn hw_addr(&self) -> MacAddr {
        self.cfg.mac
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lease key of an Ethernet client that sends no client identifier.
    fn hw(mac: MacAddr) -> ClientKey {
        ClientKey::Hw(1, mac.octets().to_vec())
    }
    use crate::dhcp::wire;
    use std::sync::Arc;

    fn build_discover(xid: u32, mac: MacAddr) -> Vec<u8> {
        let mut b = wire::Builder::new(1, xid, mac);
        b.message_type(wire::MSG_DISCOVER);
        b.finish()
    }

    #[test]
    fn allocate_returns_an_ip_in_range() {
        let s = Server::new(ServerConfig::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
        ));
        let mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let recorded = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let r2 = recorded.clone();
        s.set_handler(Arc::new(move |f: &Frame| {
            r2.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));

        s.handle_dhcp(&build_discover(0xDEADBEEF, mac));
        let frames = recorded.lock().unwrap();
        assert_eq!(frames.len(), 1);
        // Parse out the reply.
        let f = Frame::from_slice(&frames[0]);
        let ip = f.payload();
        let udp = &ip[20..];
        let dhcp = &udp[8..];
        let p = wire::Parsed::from_bytes(dhcp).unwrap();
        assert_eq!(p.msg_type, wire::MSG_OFFER);
        assert!(u32::from(p.yiaddr) >= u32::from(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(u32::from(p.yiaddr) <= u32::from(Ipv4Addr::new(192, 168, 1, 20)));
    }

    #[test]
    fn static_lease_wins() {
        let mut cfg = ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        );
        let mac = MacAddr([0x02, 0, 0, 0, 0, 0x42]);
        cfg.static_leases.insert(mac, Ipv4Addr::new(10, 0, 0, 99));
        let s = Server::new(cfg);
        let r = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let rc = r.clone();
        s.set_handler(Arc::new(move |f: &Frame| {
            rc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));
        s.handle_dhcp(&build_discover(1, mac));
        let frames = r.lock().unwrap();
        let f = Frame::from_slice(&frames[0]);
        let dhcp = &f.payload()[20..][8..];
        let p = wire::Parsed::from_bytes(dhcp).unwrap();
        assert_eq!(p.yiaddr, Ipv4Addr::new(10, 0, 0, 99));
    }

    #[test]
    fn release_frees_the_ip() {
        let s = Server::new(ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 10),
        ));
        let mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let r = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let rc = r.clone();
        s.set_handler(Arc::new(move |f: &Frame| {
            rc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));

        s.handle_dhcp(&build_discover(1, mac));
        let ip = Ipv4Addr::new(10, 0, 0, 10);
        s.handle_dhcp(&request(1, mac, ip, Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(r.lock().unwrap().len(), 2);

        s.handle_dhcp(&release(mac, ip, Some(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(s.leases.lock().unwrap().len(), 0);
    }

    fn release(mac: MacAddr, ciaddr: Ipv4Addr, server: Option<Ipv4Addr>) -> Vec<u8> {
        let mut b = wire::Builder::new(1, 2, mac);
        b.message_type(wire::MSG_RELEASE).ciaddr(ciaddr);
        if let Some(s) = server {
            b.ipv4_option(wire::OPT_SERVER_ID, s);
        }
        b.finish()
    }

    #[test]
    fn a_release_must_name_us_and_the_leased_address() {
        let (s, r) = recording(one_address_pool());
        let a = MacAddr([2, 0, 0, 0, 0, 0xa]);
        let ip = bound_lease(&s, &r, a);
        let us = Some(Ipv4Addr::new(10, 0, 0, 1));

        // Forged by MAC alone, for another server, or for another address.
        s.handle_dhcp(&release(a, Ipv4Addr::UNSPECIFIED, None));
        s.handle_dhcp(&release(a, Ipv4Addr::UNSPECIFIED, us));
        s.handle_dhcp(&release(a, ip, None));
        s.handle_dhcp(&release(a, ip, Some(Ipv4Addr::new(10, 0, 0, 2))));
        s.handle_dhcp(&release(a, Ipv4Addr::new(10, 0, 0, 11), us));
        assert_eq!(
            s.leases.lock().unwrap().get(&hw(a)).map(|l| l.ip),
            Some(ip),
            "a forged RELEASE freed the lease"
        );

        s.handle_dhcp(&release(a, ip, us));
        assert!(!s.leases.lock().unwrap().contains_key(&hw(a)));
    }

    type Sent = Arc<Mutex<Vec<Vec<u8>>>>;

    fn recording(cfg: ServerConfig) -> (Server, Sent) {
        let s = Server::new(cfg);
        let r: Sent = Arc::default();
        let rc = r.clone();
        s.set_handler(Arc::new(move |f: &Frame| {
            rc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));
        (s, r)
    }

    /// Parse every reply sent so far, and forget them.
    fn replies(r: &Sent) -> Vec<wire::Parsed> {
        r.lock()
            .unwrap()
            .drain(..)
            .map(|f| wire::Parsed::from_bytes(&Frame::from_slice(&f).payload()[28..]).unwrap())
            .collect()
    }

    fn request(xid: u32, mac: MacAddr, ip: Ipv4Addr, server: Ipv4Addr) -> Vec<u8> {
        let mut b = wire::Builder::new(1, xid, mac);
        b.message_type(wire::MSG_REQUEST)
            .ipv4_option(wire::OPT_REQUESTED_IP, ip)
            .ipv4_option(wire::OPT_SERVER_ID, server);
        b.finish()
    }

    fn one_address_pool() -> ServerConfig {
        ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 10),
        )
    }

    #[test]
    fn expired_lease_is_not_handed_back_once_someone_else_holds_it() {
        let (s, r) = recording(one_address_pool());
        let a = MacAddr([2, 0, 0, 0, 0, 0xa]);
        let b = MacAddr([2, 0, 0, 0, 0, 0xb]);
        let server = Ipv4Addr::new(10, 0, 0, 1);
        let ip = Ipv4Addr::new(10, 0, 0, 10);

        s.handle_dhcp(&build_discover(1, a));
        s.handle_dhcp(&request(1, a, ip, server));
        assert_eq!(replies(&r).last().unwrap().msg_type, wire::MSG_ACK);

        // A's lease runs out and B takes the address.
        s.leases
            .lock()
            .unwrap()
            .by_key
            .get_mut(&hw(a))
            .unwrap()
            .expiry = Instant::now();
        s.handle_dhcp(&build_discover(2, b));
        s.handle_dhcp(&request(2, b, ip, server));
        let got = replies(&r);
        assert_eq!(got.last().unwrap().msg_type, wire::MSG_ACK);
        assert_eq!(got.last().unwrap().yiaddr, ip);

        // A comes back: the only address is B's now, so there is nothing to
        // offer.
        s.handle_dhcp(&build_discover(3, a));
        assert!(
            replies(&r).iter().all(|p| p.msg_type != wire::MSG_OFFER),
            "offered B's address to A"
        );
    }

    #[test]
    fn an_offer_holds_its_address_only_briefly() {
        let (s, r) = recording(one_address_pool());
        s.handle_dhcp(&build_discover(1, MacAddr([2, 0, 0, 0, 0, 1])));
        assert_eq!(replies(&r).len(), 1);
        let held = s.leases.lock().unwrap()[&hw(MacAddr([2, 0, 0, 0, 0, 1]))].expiry;
        assert!(
            held <= Instant::now() + OFFER_HOLD,
            "a DISCOVER must not reserve the address for a whole lease"
        );
    }

    #[test]
    fn expired_leases_do_not_count_toward_the_table_limit() {
        let (s, r) = recording(one_address_pool());
        {
            let mut leases = s.leases.lock().unwrap();
            let gone = Instant::now();
            for i in 0..MAX_LEASES {
                let n = i as u32;
                leases.insert(
                    hw(MacAddr([2, 1, 0, (n >> 16) as u8, (n >> 8) as u8, n as u8])),
                    Lease {
                        ip: Ipv4Addr::new(10, 0, 0, 10),
                        expiry: gone,
                        bound: true,
                        provisional: None,
                    },
                );
            }
        }
        s.handle_dhcp(&build_discover(1, MacAddr([2, 0, 0, 0, 0, 1])));
        let got = replies(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_type, wire::MSG_OFFER);
    }

    fn bound_lease(s: &Server, r: &Sent, mac: MacAddr) -> Ipv4Addr {
        s.handle_dhcp(&build_discover(1, mac));
        let ip = replies(r)[0].yiaddr;
        s.handle_dhcp(&request(1, mac, ip, Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(replies(r)[0].msg_type, wire::MSG_ACK);
        ip
    }

    #[test]
    fn request_for_another_server_is_ignored_and_releases_our_offer() {
        let (s, r) = recording(one_address_pool());
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        s.handle_dhcp(&build_discover(1, mac));
        let offered = replies(&r)[0].yiaddr;

        s.handle_dhcp(&request(1, mac, offered, Ipv4Addr::new(10, 0, 0, 2)));
        assert!(replies(&r).is_empty(), "the client chose another server");
        assert!(s.leases.lock().unwrap().is_empty(), "offer withdrawn");
    }

    #[test]
    fn selecting_a_different_address_than_offered_is_naked() {
        let cfg = ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        );
        let (s, r) = recording(cfg);
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        s.handle_dhcp(&build_discover(1, mac));
        let offered = replies(&r)[0].yiaddr;
        let other = Ipv4Addr::from(u32::from(offered) + 1);
        s.handle_dhcp(&request(1, mac, other, Ipv4Addr::new(10, 0, 0, 1)));
        let got = replies(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_type, wire::MSG_NAK);
        assert_eq!(got[0].server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(got[0].yiaddr, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn init_reboot_is_naked_when_the_address_is_wrong() {
        let (s, r) = recording(one_address_pool());
        let a = MacAddr([2, 0, 0, 0, 0, 0xa]);
        let b = MacAddr([2, 0, 0, 0, 0, 0xb]);
        let ip = bound_lease(&s, &r, a);

        let init_reboot = |mac: MacAddr, ip: Ipv4Addr| {
            let mut m = wire::Builder::new(1, 9, mac);
            m.message_type(wire::MSG_REQUEST)
                .ipv4_option(wire::OPT_REQUESTED_IP, ip);
            m.finish()
        };

        // B reboots believing it owns A's address.
        s.handle_dhcp(&init_reboot(b, ip));
        assert_eq!(replies(&r)[0].msg_type, wire::MSG_NAK);

        // A client moved over from another network.
        s.handle_dhcp(&init_reboot(b, Ipv4Addr::new(192, 168, 7, 7)));
        assert_eq!(replies(&r)[0].msg_type, wire::MSG_NAK);

        // A reboots and asks for what it has.
        s.handle_dhcp(&init_reboot(a, ip));
        let got = replies(&r);
        assert_eq!(got[0].msg_type, wire::MSG_ACK);
        assert_eq!(got[0].yiaddr, ip);
    }

    #[test]
    fn renewal_by_ciaddr_is_acked() {
        let (s, r) = recording(one_address_pool());
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let ip = bound_lease(&s, &r, mac);
        s.leases
            .lock()
            .unwrap()
            .by_key
            .get_mut(&hw(mac))
            .unwrap()
            .expiry = Instant::now() + Duration::from_secs(5);

        let mut m = wire::Builder::new(1, 7, mac);
        m.message_type(wire::MSG_REQUEST).ciaddr(ip);
        s.handle_dhcp(&m.finish());
        let got = replies(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_type, wire::MSG_ACK);
        assert_eq!(got[0].yiaddr, ip);
        assert!(
            s.leases.lock().unwrap()[&hw(mac)].expiry > Instant::now() + Duration::from_secs(60),
            "renewal extends the lease"
        );

        // Renewing an address the server never gave this client.
        let mut m = wire::Builder::new(1, 8, MacAddr([2, 0, 0, 0, 0, 2]));
        m.message_type(wire::MSG_REQUEST).ciaddr(ip);
        s.handle_dhcp(&m.finish());
        assert_eq!(replies(&r)[0].msg_type, wire::MSG_NAK);
    }

    #[test]
    fn requests_from_unknown_clients_cannot_drain_the_pool() {
        let cfg = ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 209),
        );
        let (s, r) = recording(cfg);
        assert_eq!(s.capacity, 200);
        // INIT-REBOOT from made-up clients, each for an address of its own.
        let mut acked = 0;
        for i in 0..200u32 {
            let mac = MacAddr([2, 0xee, 0, 0, (i >> 8) as u8, i as u8]);
            let mut m = wire::Builder::new(1, i, mac);
            m.message_type(wire::MSG_REQUEST)
                .ipv4_option(wire::OPT_REQUESTED_IP, Ipv4Addr::from(0x0a00_000a + i));
            s.handle_dhcp(&m.finish());
            for p in replies(&r) {
                assert_eq!(p.msg_type, wire::MSG_ACK);
                assert!(p.lease_time.unwrap() <= 60, "{:?}", p.lease_time);
                acked += 1;
            }
        }
        assert_eq!(acked, 150, "past three quarters full, silence");
        // A real client still gets an address.
        s.handle_dhcp(&build_discover(1, MacAddr([2, 0, 0, 0, 0, 1])));
        assert_eq!(replies(&r)[0].msg_type, wire::MSG_OFFER, "pool drained");
    }

    /// Age every provisional lease by `by`, as if granted that long ago.
    fn age_provisional(s: &Server, by: Duration) {
        let mut leases = s.leases.lock().unwrap();
        let aged: Vec<_> = leases
            .iter()
            .filter_map(|(k, l)| {
                let since = l.provisional?.checked_sub(by)?;
                Some((
                    k.clone(),
                    Lease {
                        provisional: Some(since),
                        ..*l
                    },
                ))
            })
            .collect();
        for (k, l) in aged {
            leases.insert(k, l);
        }
    }

    #[test]
    fn a_provisional_lease_is_made_whole_on_renewal() {
        let (s, r) = recording(one_address_pool());
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let ip = Ipv4Addr::new(10, 0, 0, 10);
        let mut m = wire::Builder::new(1, 1, mac);
        m.message_type(wire::MSG_REQUEST)
            .ipv4_option(wire::OPT_REQUESTED_IP, ip);
        s.handle_dhcp(&m.finish());
        let got = replies(&r);
        assert_eq!(got[0].msg_type, wire::MSG_ACK);
        assert_eq!(got[0].lease_time, Some(PROVISIONAL_LEASE.as_secs() as u32));

        // Renewing at T1, as a real client does.
        age_provisional(&s, PROVISIONAL_MIN_AGE);
        let mut m = wire::Builder::new(1, 2, mac);
        m.message_type(wire::MSG_REQUEST).ciaddr(ip);
        s.handle_dhcp(&m.finish());
        let got = replies(&r);
        assert_eq!(got[0].msg_type, wire::MSG_ACK);
        assert_eq!(got[0].lease_time, Some(DEFAULT_LEASE.as_secs() as u32));
    }

    /// Asking again costs a forger nothing, so it must not buy the full
    /// lease: neither the same INIT-REBOOT REQUEST repeated, nor a renewal
    /// sent before half the provisional lease has passed.
    #[test]
    fn a_provisional_lease_is_not_made_whole_by_asking_again() {
        let (s, r) = recording(one_address_pool());
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let ip = Ipv4Addr::new(10, 0, 0, 10);
        let provisional = Some(PROVISIONAL_LEASE.as_secs() as u32);
        for xid in 1..=3 {
            let mut m = wire::Builder::new(1, xid, mac);
            m.message_type(wire::MSG_REQUEST)
                .ipv4_option(wire::OPT_REQUESTED_IP, ip);
            s.handle_dhcp(&m.finish());
            let got = replies(&r);
            assert_eq!(got[0].msg_type, wire::MSG_ACK);
            assert_eq!(got[0].lease_time, provisional, "REQUEST #{xid}");
        }
        // Old enough, but still not a renewal.
        age_provisional(&s, PROVISIONAL_MIN_AGE);
        let mut m = wire::Builder::new(1, 4, mac);
        m.message_type(wire::MSG_REQUEST)
            .ipv4_option(wire::OPT_REQUESTED_IP, ip);
        s.handle_dhcp(&m.finish());
        assert_eq!(replies(&r)[0].lease_time, provisional);

        // A renewal straight away, on a fresh provisional lease.
        let (s, r) = recording(one_address_pool());
        let mut m = wire::Builder::new(1, 1, mac);
        m.message_type(wire::MSG_REQUEST)
            .ipv4_option(wire::OPT_REQUESTED_IP, ip);
        s.handle_dhcp(&m.finish());
        replies(&r);
        let mut m = wire::Builder::new(1, 2, mac);
        m.message_type(wire::MSG_REQUEST).ciaddr(ip);
        s.handle_dhcp(&m.finish());
        let got = replies(&r);
        assert_eq!(got[0].msg_type, wire::MSG_ACK);
        assert_eq!(got[0].lease_time, provisional, "renewed too soon");
    }

    #[test]
    fn pool_size_counts_what_in_pool_accepts() {
        for (start, end, router) in [
            ([10, 0, 0, 0], [10, 0, 0, 255], Some([10, 0, 0, 254])),
            ([10, 0, 0, 10], [10, 0, 0, 20], None),
            ([9, 0, 0, 0], [11, 0, 0, 0], Some([10, 0, 0, 1])),
            ([10, 0, 1, 0], [10, 0, 2, 0], None),
        ] {
            let mut cfg = ServerConfig::new(Ipv4Addr::new(10, 0, 0, 1), start.into(), end.into());
            cfg.router = router.map(Ipv4Addr::from);
            let s = Server::new(cfg);
            let n = (0x0a00_0000..=0x0a00_00ffu32)
                .filter(|&a| s.in_pool(a.into()))
                .count();
            assert_eq!(pool_size(&s.cfg), n, "{start:?}-{end:?}");
        }
    }

    #[test]
    fn the_address_index_follows_the_table() {
        let check = |s: &Server| {
            let l = s.leases.lock().unwrap();
            let mut counts = HashMap::new();
            for lease in l.by_key.values() {
                *counts.entry(lease.ip).or_insert(0u32) += 1;
            }
            assert_eq!(counts, l.by_ip);
        };
        let (s, r) = recording(two_address_pool());
        let server = Ipv4Addr::new(10, 0, 0, 1);
        let (a, b) = (MacAddr([2, 0, 0, 0, 0, 0xa]), MacAddr([2, 0, 0, 0, 0, 0xb]));
        let ip = bound_lease(&s, &r, a);
        s.handle_dhcp(&build_discover(2, b));
        check(&s);
        s.handle_dhcp(&release(a, ip, Some(server)));
        check(&s);
        let ip = bound_lease(&s, &r, b);
        s.handle_dhcp(&decline(b, Some(ip), Some(server)));
        check(&s);
        bound_lease(&s, &r, a);
        s.leases
            .lock()
            .unwrap()
            .by_key
            .get_mut(&hw(a))
            .unwrap()
            .expiry = Instant::now();
        s.handle_dhcp(&build_discover(3, b));
        check(&s);
        assert_eq!(s.leases.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_renewal_after_a_restart_keeps_an_address_declined_for_it() {
        // The server restarted and forgot A's lease. It offered A's address
        // to B, whose ARP probe found A there, so B declined it.
        let (s, r) = recording(one_address_pool());
        let a = MacAddr([2, 0, 0, 0, 0, 0xa]);
        let b = MacAddr([2, 0, 0, 0, 0, 0xb]);
        let ip = bound_lease(&s, &r, b);
        s.handle_dhcp(&decline(b, Some(ip), Some(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(s.declined.lock().unwrap().contains_key(&ip));

        let renew = |mac: MacAddr| {
            let mut m = wire::Builder::new(1, 7, mac);
            m.message_type(wire::MSG_REQUEST).ciaddr(ip);
            m.finish()
        };
        // A, which rightly holds it, renews.
        s.handle_dhcp(&renew(a));
        let got = replies(&r);
        assert_eq!(got[0].msg_type, wire::MSG_ACK, "NAKed the address's holder");
        assert_eq!(got[0].yiaddr, ip);
        assert!(!s.declined.lock().unwrap().contains_key(&ip));
        assert_eq!(s.leases.lock().unwrap()[&hw(a)].ip, ip);

        // A renewal never takes an address someone else holds, though.
        s.handle_dhcp(&renew(b));
        assert_eq!(replies(&r)[0].msg_type, wire::MSG_NAK);

        // Nor does an INIT-REBOOT get a declined address: the client asking
        // is not known to be on it.
        let (s, r) = recording(one_address_pool());
        let ip = bound_lease(&s, &r, b);
        s.handle_dhcp(&decline(b, Some(ip), Some(Ipv4Addr::new(10, 0, 0, 1))));
        let mut m = wire::Builder::new(1, 9, a);
        m.message_type(wire::MSG_REQUEST)
            .ipv4_option(wire::OPT_REQUESTED_IP, ip);
        s.handle_dhcp(&m.finish());
        assert_eq!(replies(&r)[0].msg_type, wire::MSG_NAK);
    }

    #[test]
    fn pool_skips_the_server_router_network_and_broadcast_addresses() {
        // A pool drawn carelessly over the whole subnet.
        let cfg = ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let (s, r) = recording(cfg);
        s.handle_dhcp(&build_discover(1, MacAddr([2, 0, 0, 0, 0, 1])));
        assert_eq!(replies(&r)[0].yiaddr, Ipv4Addr::new(10, 0, 0, 2));

        let cfg = ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 254),
            Ipv4Addr::new(10, 0, 0, 255),
        )
        .router(Ipv4Addr::new(10, 0, 0, 254));
        let (s, r) = recording(cfg);
        s.handle_dhcp(&build_discover(1, MacAddr([2, 0, 0, 0, 0, 1])));
        assert!(replies(&r).is_empty(), "nothing usable in the pool");

        // Nor can a client claim one of them.
        let init_reboot = |ip: Ipv4Addr| {
            let mut m = wire::Builder::new(1, 9, MacAddr([2, 0, 0, 0, 0, 2]));
            m.message_type(wire::MSG_REQUEST)
                .ipv4_option(wire::OPT_REQUESTED_IP, ip);
            m.finish()
        };
        s.handle_dhcp(&init_reboot(Ipv4Addr::new(10, 0, 0, 255)));
        s.handle_dhcp(&init_reboot(Ipv4Addr::new(10, 0, 0, 254)));
        assert!(replies(&r).iter().all(|p| p.msg_type != wire::MSG_ACK));
    }

    #[test]
    fn nothing_off_our_subnet_is_offered() {
        // A range running past the end of the /24.
        let cfg = ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 254),
            Ipv4Addr::new(10, 0, 1, 5),
        );
        let (s, r) = recording(cfg);
        let a = MacAddr([2, 0, 0, 0, 0, 0xa]);
        assert_eq!(bound_lease(&s, &r, a), Ipv4Addr::new(10, 0, 0, 254));
        // .255 is the broadcast, and 10.0.1.x is another network: the
        // client would be NAKed on its REQUEST and start over, forever.
        s.handle_dhcp(&build_discover(2, MacAddr([2, 0, 0, 0, 0, 0xb])));
        assert!(replies(&r).is_empty(), "offered an address off the subnet");

        // Nor is a reservation off the subnet offered.
        let mac = MacAddr([2, 0, 0, 0, 0, 0xc]);
        let mut cfg = one_address_pool();
        cfg.static_leases.insert(mac, Ipv4Addr::new(192, 168, 9, 9));
        let (s, r) = recording(cfg);
        s.handle_dhcp(&build_discover(3, mac));
        assert!(replies(&r).is_empty());
    }

    fn decline(mac: MacAddr, ip: Option<Ipv4Addr>, server: Option<Ipv4Addr>) -> Vec<u8> {
        let mut b = wire::Builder::new(1, 5, mac);
        b.message_type(wire::MSG_DECLINE);
        if let Some(ip) = ip {
            b.ipv4_option(wire::OPT_REQUESTED_IP, ip);
        }
        if let Some(s) = server {
            b.ipv4_option(wire::OPT_SERVER_ID, s);
        }
        b.finish()
    }

    #[test]
    fn decline_is_accepted_only_for_what_we_gave_that_client() {
        let cfg = ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        );
        let (s, r) = recording(cfg);
        let us = Some(Ipv4Addr::new(10, 0, 0, 1));
        let a = MacAddr([2, 0, 0, 0, 0, 0xa]);
        let b = MacAddr([2, 0, 0, 0, 0, 0xb]);
        let ip = bound_lease(&s, &r, a);

        // Not addressed to us, or naming no server at all.
        s.handle_dhcp(&decline(a, Some(ip), Some(Ipv4Addr::new(10, 0, 0, 2))));
        s.handle_dhcp(&decline(a, Some(ip), None));
        // A stranger declining A's address, or addresses nobody was given.
        s.handle_dhcp(&decline(b, Some(ip), us));
        s.handle_dhcp(&decline(a, Some(Ipv4Addr::new(10, 0, 0, 15)), us));
        s.handle_dhcp(&decline(a, Some(Ipv4Addr::new(8, 8, 8, 8)), us));
        assert!(
            s.declined.lock().unwrap().is_empty(),
            "accepted a bad DECLINE"
        );
        assert_eq!(s.leases.lock().unwrap()[&hw(a)].ip, ip, "lease lost");

        // The real thing: A found the address in use.
        s.handle_dhcp(&decline(a, Some(ip), us));
        assert!(s.declined.lock().unwrap().contains_key(&ip));
        assert!(!s.leases.lock().unwrap().contains_key(&hw(a)));
    }

    #[test]
    fn forged_declines_cannot_grow_the_table_without_bound() {
        let (s, _r) = recording(one_address_pool());
        let us = Some(Ipv4Addr::new(10, 0, 0, 1));
        for i in 0..5000u32 {
            let mac = MacAddr([2, 9, 0, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            s.handle_dhcp(&decline(mac, Some(Ipv4Addr::from(0x0a00_0000 + i)), us));
        }
        assert!(s.declined.lock().unwrap().len() <= MAX_LEASES);
    }

    /// Where each reply sent so far went: (Ethernet dst, IP dst, UDP dst
    /// port, message); and forget them.
    fn addressed(r: &Sent) -> Vec<(MacAddr, Ipv4Addr, u16, wire::Parsed)> {
        r.lock()
            .unwrap()
            .drain(..)
            .map(|f| {
                let f = Frame::from_slice(&f);
                let ip = crate::Packet::from_slice(f.payload());
                let udp = ip.ipv4_payload();
                (
                    f.dst_mac().unwrap(),
                    ip.ipv4_dst_addr().unwrap(),
                    u16::from_be_bytes([udp[2], udp[3]]),
                    wire::Parsed::from_bytes(&udp[8..]).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn replies_are_addressed_per_rfc_2131_section_4_1() {
        let (s, r) = recording(ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 20),
        ));
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);

        // No flag: unicast to the offered address at chaddr.
        s.handle_dhcp(&build_discover(1, mac));
        let (emac, ip, port, p) = addressed(&r).remove(0);
        assert_eq!((emac, ip, port), (mac, p.yiaddr, 68));

        // Broadcast flag: the client cannot take unicast yet.
        let mut b = wire::Builder::new(1, 2, mac);
        b.flags(0x8000).message_type(wire::MSG_DISCOVER);
        s.handle_dhcp(&b.finish());
        let (emac, ip, _, p) = addressed(&r).remove(0);
        assert_eq!((emac, ip), (MacAddr::broadcast(), Ipv4Addr::BROADCAST));
        assert_eq!(p.flags & 0x8000, 0x8000, "flags echoed");

        // A renewal is answered at its ciaddr.
        let leased = p.yiaddr;
        s.handle_dhcp(&request(3, mac, leased, Ipv4Addr::new(10, 0, 0, 1)));
        addressed(&r);
        let mut b = wire::Builder::new(1, 4, mac);
        b.message_type(wire::MSG_REQUEST).ciaddr(leased);
        s.handle_dhcp(&b.finish());
        let (emac, ip, _, p) = addressed(&r).remove(0);
        assert_eq!(p.msg_type, wire::MSG_ACK);
        assert_eq!((emac, ip), (mac, leased));

        // A NAK with no relay is always broadcast.
        let mut b = wire::Builder::new(1, 5, mac);
        b.message_type(wire::MSG_REQUEST)
            .ipv4_option(wire::OPT_REQUESTED_IP, Ipv4Addr::new(192, 168, 9, 9));
        s.handle_dhcp(&b.finish());
        let (emac, ip, _, p) = addressed(&r).remove(0);
        assert_eq!(p.msg_type, wire::MSG_NAK);
        assert_eq!((emac, ip), (MacAddr::broadcast(), Ipv4Addr::BROADCAST));
    }

    #[test]
    fn relayed_requests_are_answered_to_the_relay_and_only_for_our_subnet() {
        let (s, r) = recording(one_address_pool());
        let relay_mac = MacAddr([2, 0, 0, 0, 0, 0xee]);
        let client = MacAddr([2, 0, 0, 0, 0, 1]);
        let relayed = |giaddr: Ipv4Addr| {
            let mut b = wire::Builder::new(1, 1, client);
            b.giaddr(giaddr).message_type(wire::MSG_DISCOVER);
            let dhcp = b.finish();
            let udp = crate::build::build_udp(
                std::net::IpAddr::V4(giaddr),
                std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                67,
                67,
                &dhcp,
            );
            let ip = crate::build::build_ipv4(
                giaddr,
                Ipv4Addr::new(10, 0, 0, 1),
                Protocol::UDP,
                64,
                &udp,
            );
            build_frame(s.cfg.mac, relay_mac, EtherType::IPV4, &ip)
        };

        // A relay on a subnet this server has no pool for.
        s.send(Frame::from_slice(&relayed(Ipv4Addr::new(192, 168, 5, 1))))
            .unwrap();
        assert!(
            addressed(&r).is_empty(),
            "offered 10.0.0.x to 192.168.5.0/24"
        );

        // A relay on ours: the answer goes back through it, to port 67.
        s.send(Frame::from_slice(&relayed(Ipv4Addr::new(10, 0, 0, 254))))
            .unwrap();
        let (emac, ip, port, p) = addressed(&r).remove(0);
        assert_eq!(p.msg_type, wire::MSG_OFFER);
        assert_eq!(
            (emac, ip, port),
            (relay_mac, Ipv4Addr::new(10, 0, 0, 254), 67)
        );
        assert_eq!(p.giaddr, Ipv4Addr::new(10, 0, 0, 254));
    }

    #[test]
    fn a_lease_time_beyond_32_bits_is_infinite_not_a_panic() {
        for lease in [Duration::MAX, Duration::from_secs(1 << 33)] {
            let (s, r) = recording(one_address_pool().lease_time(lease));
            let mac = MacAddr([2, 0, 0, 0, 0, 1]);
            s.handle_dhcp(&build_discover(1, mac));
            let offer = replies(&r).remove(0);
            assert_eq!(offer.lease_time, Some(u32::MAX), "wrapped, not saturated");
            s.handle_dhcp(&request(1, mac, offer.yiaddr, Ipv4Addr::new(10, 0, 0, 1)));
            assert_eq!(replies(&r)[0].msg_type, wire::MSG_ACK);
            s.handle_dhcp(&decline(
                mac,
                Some(offer.yiaddr),
                Some(Ipv4Addr::new(10, 0, 0, 1)),
            ));
            assert!(s.declined.lock().unwrap().contains_key(&offer.yiaddr));
        }
    }

    #[test]
    fn an_inform_ack_names_the_server_and_grants_nothing() {
        let (s, r) = recording(one_address_pool());
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let mut b = wire::Builder::new(1, 7, mac);
        b.ciaddr(Ipv4Addr::new(10, 0, 0, 50))
            .message_type(wire::MSG_INFORM);
        s.handle_dhcp(&b.finish());
        let got = replies(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_type, wire::MSG_ACK);
        assert_eq!(got[0].server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(got[0].lease_time, None);
        assert!(got[0].yiaddr.is_unspecified());
    }

    fn two_address_pool() -> ServerConfig {
        ServerConfig::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(10, 0, 0, 11),
        )
    }

    /// DISCOVER then REQUEST from `mac` with client identifier `id`;
    /// returns the address ACKed.
    fn lease_with_id(s: &Server, r: &Sent, mac: MacAddr, id: &[u8]) -> Ipv4Addr {
        let mut b = wire::Builder::new(1, 1, mac);
        b.message_type(wire::MSG_DISCOVER)
            .option(wire::OPT_CLIENT_ID, id);
        s.handle_dhcp(&b.finish());
        let ip = replies(r)[0].yiaddr;
        let mut b = wire::Builder::new(1, 2, mac);
        b.message_type(wire::MSG_REQUEST)
            .ipv4_option(wire::OPT_REQUESTED_IP, ip)
            .ipv4_option(wire::OPT_SERVER_ID, Ipv4Addr::new(10, 0, 0, 1))
            .option(wire::OPT_CLIENT_ID, id);
        s.handle_dhcp(&b.finish());
        let ack = &replies(r)[0];
        assert_eq!(ack.msg_type, wire::MSG_ACK);
        ack.yiaddr
    }

    #[test]
    fn leases_are_keyed_by_client_identifier_when_given() {
        let (s, r) = recording(two_address_pool());
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        // Two clients behind one hardware address (virtual machines on a
        // shared NIC, or one host's two interfaces), told apart by id.
        let a = lease_with_id(&s, &r, mac, b"\x00vm-a");
        let b = lease_with_id(&s, &r, mac, b"\x00vm-b");
        assert_ne!(a, b, "two clients were given one address");

        // The same client keeps its address when its hardware changes.
        let again = lease_with_id(&s, &r, MacAddr([2, 0, 0, 0, 0, 9]), b"\x00vm-a");
        assert_eq!(again, a);
    }

    #[test]
    fn an_overlong_hardware_address_is_ignored() {
        let (s, r) = recording(one_address_pool());
        let mut msg = build_discover(1, MacAddr([2, 0, 0, 0, 0, 1]));
        msg[2] = 17; // hlen past the 16-byte chaddr field
        s.handle_dhcp(&msg);
        assert!(replies(&r).is_empty());
        assert!(s.leases.lock().unwrap().is_empty());
    }
}

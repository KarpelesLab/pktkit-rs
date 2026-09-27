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

/// Configure a [`Server`].
#[derive(Clone)]
#[non_exhaustive]
pub struct ServerConfig {
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: Duration,
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

enum Answer {
    Ack(Ipv4Addr),
    Nak,
    Silent,
}

#[derive(Copy, Clone)]
struct Lease {
    ip: Ipv4Addr,
    expiry: Instant,
    bound: bool,
}

/// A DHCP server, implementing [`L2Device`] so it plugs into an
/// [`L2Hub`](crate::L2Hub) like any other device.
pub struct Server {
    cfg: ServerConfig,
    handler: Mutex<Option<L2Handler>>,
    leases: Mutex<HashMap<MacAddr, Lease>>,
    declined: Mutex<HashMap<Ipv4Addr, Instant>>,
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
        Server {
            cfg,
            handler: Mutex::new(None),
            leases: Mutex::new(HashMap::new()),
            declined: Mutex::new(HashMap::new()),
        }
    }

    /// Decode a UDP/DHCP payload and react. Public so callers that already
    /// stripped the IP and UDP headers can drive the server directly.
    pub fn handle_dhcp(&self, msg: &[u8]) {
        let p = match wire::Parsed::from_bytes(msg) {
            Some(p) => p,
            None => return,
        };
        if p.op != 1 {
            return; // not a BOOTREQUEST
        }
        match p.msg_type {
            wire::MSG_DISCOVER => {
                if let Some(ip) = self.allocate(p.chaddr) {
                    self.send_reply(wire::MSG_OFFER, p.xid, p.chaddr, Some(ip));
                }
            }
            wire::MSG_REQUEST => match self.request(&p) {
                Answer::Ack(ip) => self.send_reply(wire::MSG_ACK, p.xid, p.chaddr, Some(ip)),
                Answer::Nak => self.send_nak(p.xid, p.chaddr),
                Answer::Silent => {}
            },
            wire::MSG_RELEASE => {
                self.leases.lock().unwrap().remove(&p.chaddr);
            }
            wire::MSG_DECLINE => self.decline(&p),
            wire::MSG_INFORM => {
                self.send_reply(wire::MSG_ACK, p.xid, p.chaddr, None);
            }
            _ => {}
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
    fn decline(&self, p: &wire::Parsed) {
        if p.server_id != Some(self.cfg.server_ip) {
            return;
        }
        let Some(ip) = p.requested_ip else {
            return;
        };
        let now = Instant::now();
        let mut leases = self.live_leases(now);
        let ours = leases.get(&p.chaddr).is_some_and(|l| l.ip == ip)
            || self.cfg.static_leases.get(&p.chaddr) == Some(&ip);
        if !ours {
            return;
        }
        leases.remove(&p.chaddr);
        let mut declined = self.declined.lock().unwrap();
        // Only addresses we gave out get here, so this bounds only what a
        // pathological configuration (a pool larger than the table) allows.
        if declined.len() >= MAX_LEASES && !declined.contains_key(&ip) {
            return;
        }
        declined.insert(ip, now + self.cfg.lease_time);
    }

    /// The table as of `now`: leases and offers that have run out are
    /// dropped, so they neither keep their address from anyone else nor
    /// count toward [`MAX_LEASES`].
    fn live_leases(&self, now: Instant) -> std::sync::MutexGuard<'_, HashMap<MacAddr, Lease>> {
        let mut leases = self.leases.lock().unwrap();
        leases.retain(|_, l| l.expiry > now);
        self.declined.lock().unwrap().retain(|_, exp| *exp > now);
        leases
    }

    /// Addresses that `mac` cannot have because another client holds them.
    fn held_by_others(
        &self,
        leases: &HashMap<MacAddr, Lease>,
        mac: MacAddr,
    ) -> std::collections::HashSet<Ipv4Addr> {
        let mut held = std::collections::HashSet::new();
        for (m, l) in leases {
            if *m != mac {
                held.insert(l.ip);
            }
        }
        for (m, ip) in &self.cfg.static_leases {
            if *m != mac {
                held.insert(*ip);
            }
        }
        held
    }

    /// Pick an address to OFFER. The offer only reserves it for
    /// [`OFFER_HOLD`]: a DISCOVER is unauthenticated and cheap to forge, and
    /// holding the address for a whole lease would let a flood of made-up
    /// client addresses drain the pool.
    fn allocate(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        let now = Instant::now();
        if let Some(ip) = self.cfg.static_leases.get(&mac).copied() {
            return Some(ip);
        }
        let mut leases = self.live_leases(now);
        let held = self.held_by_others(&leases, mac);

        if let Some(l) = leases.get_mut(&mac) {
            if !held.contains(&l.ip) {
                if !l.bound {
                    l.expiry = now + OFFER_HOLD;
                }
                return Some(l.ip);
            }
            leases.remove(&mac);
        }

        if leases.len() >= MAX_LEASES {
            return None;
        }

        let declined = self.declined.lock().unwrap();
        let start = u32::from(self.cfg.range_start);
        let end = u32::from(self.cfg.range_end);
        let ip = (start..=end)
            .map(Ipv4Addr::from)
            .find(|ip| self.in_pool(*ip) && !held.contains(ip) && !declined.contains_key(ip))?;
        leases.insert(
            mac,
            Lease {
                ip,
                expiry: now + OFFER_HOLD,
                bound: false,
            },
        );
        Some(ip)
    }

    /// Answer a DHCPREQUEST, telling apart the client states of RFC 2131
    /// §4.3.2 by which of server identifier, requested address and ciaddr
    /// it carries.
    fn request(&self, p: &wire::Parsed) -> Answer {
        let now = Instant::now();
        let mac = p.chaddr;
        let mut leases = self.live_leases(now);
        let ip = match (p.server_id, p.requested_ip) {
            // SELECTING, but the client took another server's offer: ours is
            // free again.
            (Some(sid), _) if sid != self.cfg.server_ip => {
                if leases.get(&mac).is_some_and(|l| !l.bound) {
                    leases.remove(&mac);
                }
                return Answer::Silent;
            }
            // SELECTING our offer, which must be for the address it names.
            (Some(_), Some(ip)) => {
                if leases.get(&mac).is_some_and(|l| !l.bound && l.ip != ip) {
                    leases.remove(&mac);
                    return Answer::Nak;
                }
                ip
            }
            // INIT-REBOOT: the client asks to keep an address it remembers.
            (None, Some(ip)) => ip,
            // RENEWING or REBINDING: the address is in ciaddr.
            (None, None) if !p.ciaddr.is_unspecified() => p.ciaddr,
            _ => return Answer::Silent,
        };
        self.commit(&mut leases, mac, ip, now)
    }

    /// Bind `ip` to `mac` if the server agrees that is the client's address.
    fn commit(
        &self,
        leases: &mut HashMap<MacAddr, Lease>,
        mac: MacAddr,
        ip: Ipv4Addr,
        now: Instant,
    ) -> Answer {
        let lease = Lease {
            ip,
            expiry: now + self.cfg.lease_time,
            bound: true,
        };
        let mask = u32::from(self.cfg.subnet_mask);
        if u32::from(ip) & mask != u32::from(self.cfg.server_ip) & mask {
            return Answer::Nak; // the client moved here from another network
        }
        if let Some(static_ip) = self.cfg.static_leases.get(&mac).copied() {
            if ip != static_ip {
                return Answer::Nak;
            }
            leases.insert(mac, lease);
            return Answer::Ack(ip);
        }

        let held = self.held_by_others(leases, mac);
        match leases.get(&mac) {
            Some(l) if l.ip == ip && !held.contains(&ip) => {
                leases.insert(mac, lease);
                return Answer::Ack(ip);
            }
            Some(l) if l.bound => return Answer::Nak,
            // An outstanding offer the client chose not to take: forget it,
            // and treat the request like one from a client we have no record
            // of.
            Some(_) => {
                leases.remove(&mac);
            }
            None => {}
        }

        // No record, as after a server restart. RFC 2131 wants silence here
        // so servers sharing a segment do not fight; an address from our
        // own pool is ours to judge, though, and granting it when it is free
        // lets clients keep their address across a restart.
        if !self.in_pool(ip) {
            return Answer::Silent;
        }
        if held.contains(&ip) || self.declined.lock().unwrap().contains_key(&ip) {
            return Answer::Nak;
        }
        if leases.len() >= MAX_LEASES {
            return Answer::Silent;
        }
        leases.insert(mac, lease);
        Answer::Ack(ip)
    }

    /// Whether `ip` is one of the addresses this server hands out: in the
    /// configured range, and not one the subnet already uses for something
    /// else, however the range was drawn.
    fn in_pool(&self, ip: Ipv4Addr) -> bool {
        let raw = u32::from(ip);
        if raw < u32::from(self.cfg.range_start) || raw > u32::from(self.cfg.range_end) {
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
    fn send_nak(&self, xid: u32, chaddr: MacAddr) {
        let mut b = wire::Builder::new(2, xid, chaddr);
        b.message_type(wire::MSG_NAK)
            .ipv4_option(wire::OPT_SERVER_ID, self.cfg.server_ip);
        self.send_message(chaddr, &b.finish());
    }

    fn send_reply(&self, msg_type: u8, xid: u32, chaddr: MacAddr, yiaddr: Option<Ipv4Addr>) {
        let mut b = wire::Builder::new(2, xid, chaddr);
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
        if yiaddr.is_some() {
            b.u32_option(wire::OPT_LEASE_TIME, self.cfg.lease_time.as_secs() as u32);
            b.ipv4_option(wire::OPT_SERVER_ID, self.cfg.server_ip);
        }
        self.send_message(chaddr, &b.finish());
    }

    fn send_message(&self, chaddr: MacAddr, dhcp: &[u8]) {
        // UDP 67→68
        let udp_len = 8 + dhcp.len();
        let mut udp = Vec::with_capacity(udp_len);
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&68u16.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum = 0
        udp.extend_from_slice(dhcp);

        // IPv4 server_ip → 255.255.255.255
        let ip_len = 20 + udp_len;
        let mut ip = vec![0u8; ip_len];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = Protocol::UDP.as_u8();
        ip[12..16].copy_from_slice(&self.cfg.server_ip.octets());
        ip[16..20].copy_from_slice(&[0xff; 4]);
        let cs = checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&cs.to_be_bytes());
        ip[20..].copy_from_slice(&udp);

        let frame = build_frame(chaddr, self.cfg.mac, EtherType::IPV4, &ip);
        let h = self.handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(Frame::from_slice(&frame));
        }
    }
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
        self.handle_dhcp(dhcp);
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
        assert_eq!(r.lock().unwrap().len(), 1);

        // Release.
        let mut b = wire::Builder::new(1, 2, mac);
        b.message_type(wire::MSG_RELEASE);
        s.handle_dhcp(&b.finish());

        // Lease table should be empty.
        assert_eq!(s.leases.lock().unwrap().len(), 0);
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
        s.leases.lock().unwrap().get_mut(&a).unwrap().expiry = Instant::now();
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
        let held = s.leases.lock().unwrap()[&MacAddr([2, 0, 0, 0, 0, 1])].expiry;
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
                    MacAddr([2, 1, 0, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
                    Lease {
                        ip: Ipv4Addr::new(10, 0, 0, 10),
                        expiry: gone,
                        bound: true,
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
        s.leases.lock().unwrap().get_mut(&mac).unwrap().expiry =
            Instant::now() + Duration::from_secs(5);

        let mut m = wire::Builder::new(1, 7, mac);
        m.message_type(wire::MSG_REQUEST).ciaddr(ip);
        s.handle_dhcp(&m.finish());
        let got = replies(&r);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_type, wire::MSG_ACK);
        assert_eq!(got[0].yiaddr, ip);
        assert!(
            s.leases.lock().unwrap()[&mac].expiry > Instant::now() + Duration::from_secs(60),
            "renewal extends the lease"
        );

        // Renewing an address the server never gave this client.
        let mut m = wire::Builder::new(1, 8, MacAddr([2, 0, 0, 0, 0, 2]));
        m.message_type(wire::MSG_REQUEST).ciaddr(ip);
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
        assert_eq!(s.leases.lock().unwrap()[&a].ip, ip, "lease lost");

        // The real thing: A found the address in use.
        s.handle_dhcp(&decline(a, Some(ip), us));
        assert!(s.declined.lock().unwrap().contains_key(&ip));
        assert!(!s.leases.lock().unwrap().contains_key(&a));
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
}

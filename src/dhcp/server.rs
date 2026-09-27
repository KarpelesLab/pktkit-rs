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
            wire::MSG_REQUEST => {
                if let Some(ip) = self.confirm(p.chaddr, p.requested_ip) {
                    self.send_reply(wire::MSG_ACK, p.xid, p.chaddr, Some(ip));
                }
                // No NAK on confirmation failure — Go upstream is silent in
                // that case too. Adding NAK would simplify renewal across
                // server restarts; left as future work.
            }
            wire::MSG_RELEASE => {
                self.leases.lock().unwrap().remove(&p.chaddr);
            }
            wire::MSG_DECLINE => {
                let mut leases = self.leases.lock().unwrap();
                leases.remove(&p.chaddr);
                if let Some(ip) = p.requested_ip {
                    self.declined
                        .lock()
                        .unwrap()
                        .insert(ip, Instant::now() + self.cfg.lease_time);
                }
            }
            wire::MSG_INFORM => {
                self.send_reply(wire::MSG_ACK, p.xid, p.chaddr, None);
            }
            _ => {}
        }
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
            .find(|ip| !held.contains(ip) && !declined.contains_key(ip))?;
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

    fn confirm(&self, mac: MacAddr, requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let now = Instant::now();
        let mut leases = self.live_leases(now);

        if let Some(static_ip) = self.cfg.static_leases.get(&mac).copied() {
            if let Some(req) = requested
                && req != static_ip
            {
                return None;
            }
            leases.insert(
                mac,
                Lease {
                    ip: static_ip,
                    expiry: now + self.cfg.lease_time,
                    bound: true,
                },
            );
            return Some(static_ip);
        }

        let held = self.held_by_others(&leases, mac);
        if let Some(l) = leases.get_mut(&mac) {
            if requested.is_some_and(|req| req != l.ip) || held.contains(&l.ip) {
                return None;
            }
            l.expiry = now + self.cfg.lease_time;
            l.bound = true;
            return Some(l.ip);
        }

        // No existing lease — try to grant the requested IP if it's in range.
        let req = requested?;
        if req == self.cfg.server_ip {
            return None;
        }
        let raw = u32::from(req);
        if raw < u32::from(self.cfg.range_start) || raw > u32::from(self.cfg.range_end) {
            return None;
        }
        if held.contains(&req) || self.declined.lock().unwrap().contains_key(&req) {
            return None;
        }
        if leases.len() >= MAX_LEASES {
            return None;
        }
        leases.insert(
            mac,
            Lease {
                ip: req,
                expiry: now + self.cfg.lease_time,
                bound: true,
            },
        );
        Some(req)
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
        let dhcp = b.finish();

        // UDP 67→68
        let udp_len = 8 + dhcp.len();
        let mut udp = Vec::with_capacity(udp_len);
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&68u16.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum = 0
        udp.extend_from_slice(&dhcp);

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
        if payload.len() < ihl + 8 {
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
}

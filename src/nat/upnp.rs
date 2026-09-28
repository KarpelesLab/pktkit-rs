//! UPnP IGD (Internet Gateway Device) helper.
//!
//! Implements the inside-facing control surface a UPnP client uses to open
//! port forwards on the NAT:
//!
//! - **SSDP discovery** (`M-SEARCH` over UDP multicast to
//!   `239.255.255.250:1900`) is handled entirely at the L3 packet level: the
//!   responder builds a raw IPv4+UDP reply and injects it back onto the inside
//!   via [`Nat::send_inside_in`]. No OS sockets, std-only.
//! - **SOAP control** (`AddPortMapping`, `DeletePortMapping`,
//!   `GetExternalIPAddress`, and the port-mapping query actions) is implemented
//!   as a pure request handler (`UPnPHelper::soap`) that parses a SOAP
//!   body and returns the response/fault body plus any NAT mutation. It is
//!   driven by the unit tests directly.
//!
//! **SOAP over live TCP** is terminated by the crate's virtual TCP engine
//! ([`vtcp::Conn`]). When an inside client opens a TCP connection to the NAT's
//! inside IP on the control port, [`UPnPHelper::handle_local`] mints a
//! server-side `vtcp::Conn` (passive open via `accept_syn`), drives the
//! handshake, accumulates the HTTP/1.1 request bytes off the established
//! stream, and parses the request line + headers + Content-Length body. A GET
//! of the SSDP `LOCATION` (`/rootDesc.xml`) returns the device description
//! (`UPnPHelper::root_desc`), a GET of the service description it names
//! returns that, and a POST to its control URL is a SOAP action handled as
//! `UPnPHelper::soap` does; anything else draws a 404 or 405. The
//! HTTP/1.1 response is written back over the connection, which then closes.
//! This is a minimal embedded HTTP/1.1 server over a single vtcp connection:
//! one request/response, then close. Outgoing segments are wrapped in IPv4 (with correct IP + TCP
//! checksums) and injected onto the inside via [`Nat::send_inside_in`].

use crate::nat::helper::{Helper, LocalHelper, PROTO_TCP, PROTO_UDP, PortForward};
use crate::nat::nat::Nat;
use crate::time::Instant;
use crate::vtcp::segment::Segment;
use crate::vtcp::{Conn, ConnConfig};
use crate::{Packet, Protocol, checksum, combine_checksums, pseudo_header_checksum};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

const SSDP_PORT: u16 = 1900;
const SSDP_MCAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// Cap on the buffered HTTP request size, to bound memory for a misbehaving or
/// hostile client. A UPnP SOAP control request is a few hundred bytes.
const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Cap on the description kept for a mapping. It is only a label, and the
/// forward holds it for the whole lease: a client could otherwise park a
/// request's worth of text in each of its mappings. miniupnpd keeps 64 bytes
/// too.
const MAX_DESCRIPTION_BYTES: usize = 64;

/// Cap on concurrent control connections. Each holds a TCP engine and a
/// request buffer, and a SYN is all it takes to create one.
const MAX_CTRL_CONNS: usize = 64;

/// Cap on concurrent control connections from one client, so that one host
/// opening connections and leaving them idle cannot take the whole table
/// and lock every other host out of UPnP. A control point makes one
/// request at a time.
const MAX_CTRL_CONNS_PER_CLIENT: usize = 8;

/// A control connection with no traffic for this long is dropped: a SOAP
/// exchange takes milliseconds.
const CTRL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default [`UPnPConfig::max_mappings`].
const DEFAULT_MAX_MAPPINGS: usize = 1024;
/// Default [`UPnPConfig::max_per_client`].
const DEFAULT_MAX_PER_CLIENT: usize = 128;
/// Default [`UPnPConfig::max_per_namespace`].
const DEFAULT_MAX_PER_NAMESPACE: usize = 256;
/// Default [`UPnPConfig::lease_duration`]: 7 days, the longest lease
/// WANIPConnection:2 allows.
const DEFAULT_MAX_LEASE: Duration = Duration::from_secs(604_800);

/// Where the control port serves the device description (the SSDP
/// `LOCATION`), the WANIPConnection service description, and its control
/// URL.
const ROOT_DESC_PATH: &str = "/rootDesc.xml";
const SCPD_PATH: &str = "/WANIPConnection.xml";
const CONTROL_PATH: &str = "/ctl/WANIPConnection";

/// Configuration knobs for the UPnP IGD helper.
///
/// Any inside host may ask for mappings, so the defaults bound what one can
/// take. Forwards hold outside ports, most of them in the range the NAT
/// hands out to its own sessions, and a host that took them all would leave
/// none for anyone else's traffic. By default there are at most 1024
/// mappings in all (under 2% of that range) and 128 per host, on
/// unprivileged ports only (1024-65535, as in miniupnpd's sample
/// configuration), each for at most 7 days. A tenant namespace, which may
/// send from any address and so claim to be any number of hosts, has at
/// most 256 in all.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UPnPConfig {
    /// TCP port for the SOAP control server (default 5000).
    pub control_port: u16,
    /// Allowed outside port ranges `(low, high)` inclusive. Empty = allow
    /// all. Default: 1024-65535.
    pub allowed_ports: Vec<(u16, u16)>,
    /// Maximum mappings made through UPnP, in all (0 = unlimited). Static
    /// forwards do not count. Default: 1024.
    pub max_mappings: usize,
    /// Maximum mappings made through UPnP per inside host (0 = unlimited).
    /// Default: 128.
    pub max_per_client: usize,
    /// Maximum mappings made through UPnP for the hosts of one inside
    /// namespace attached through
    /// [`connect_l3`](crate::L3Connector::connect_l3), together (0 =
    /// unlimited). The NAT's own inside interface (namespace 0) is bound by
    /// the other caps only. Default: 256.
    pub max_per_namespace: usize,
    /// Longest lease granted; a longer request is cut to it, and a request
    /// for 0 (permanent, in IGD:1) gets it. `None` grants permanent
    /// mappings. Default: 7 days, the longest lease WANIPConnection:2
    /// allows.
    pub lease_duration: Option<Duration>,
}

setters! {
    UPnPConfig {
        set control_port: u16;
        set allowed_ports: Vec<(u16, u16)>;
        set max_mappings: usize;
        set max_per_client: usize;
        set max_per_namespace: usize;
        some lease_duration: Duration;
    }
}

impl Default for UPnPConfig {
    fn default() -> Self {
        UPnPConfig {
            control_port: 5000,
            allowed_ports: vec![(1024, 65535)],
            max_mappings: DEFAULT_MAX_MAPPINGS,
            max_per_client: DEFAULT_MAX_PER_CLIENT,
            max_per_namespace: DEFAULT_MAX_PER_NAMESPACE,
            lease_duration: Some(DEFAULT_MAX_LEASE),
        }
    }
}

/// Outcome of a SOAP action: an HTTP-ish status code and an XML body. A code of
/// 200 is a success response; anything else is a SOAP fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SoapResult {
    pub(crate) status: u16,
    pub(crate) body: String,
}

/// Identifies a control-port TCP connection by the inside client's 4-tuple
/// (and namespace, since namespaces may reuse addresses).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct CtrlKey {
    ns: u64,
    client_ip: Ipv4Addr,
    client_port: u16,
}

/// Per-connection state for a terminated control-port TCP connection: the
/// server-side [`vtcp::Conn`] plus the in-flight HTTP request buffer.
#[derive(Debug)]
struct CtrlConn {
    conn: Conn,
    client_ip: Ipv4Addr,
    /// Accumulated request bytes read off the established stream.
    req: Vec<u8>,
    /// How far `req` has been parsed.
    framing: Framing,
    /// Set once we have parsed a complete request and written the response, so
    /// further inbound bytes on this connection are ignored (single
    /// request/response per connection — the common UPnP control flow).
    responded: bool,
    /// When the client last sent anything.
    last: Instant,
}

/// A forward UPnP made: for whom, and which one ([`PortForward::id`]). A
/// forward added later on the same port is someone else's, even if it
/// points at the same host: an administrator's static forward must not
/// become deletable by the host a lapsed UPnP mapping belonged to.
#[derive(Clone, Copy, Debug)]
struct Owned {
    ns: u64,
    ip: Ipv4Addr,
    id: u64,
}

/// The forwards UPnP made, by `(proto, outside port)` and by client, so that
/// neither a request nor the caps need a scan of every forward. A record
/// counts only while its very forward is in place; one whose forward lapsed
/// or was removed or replaced behind UPnP's back is dropped when found.
#[derive(Debug, Default)]
struct OwnedTable {
    by_port: HashMap<(u8, u16), Owned>,
    by_client: HashMap<(u64, Ipv4Addr), HashSet<(u8, u16)>>,
}

impl OwnedTable {
    fn live(nat: &Nat, (proto, port): (u8, u16), rec: &Owned) -> bool {
        nat.port_forward(proto, port)
            .is_some_and(|pf| pf.id == rec.id)
    }

    fn insert(&mut self, key: (u8, u16), rec: Owned) {
        self.remove(key);
        self.by_client
            .entry((rec.ns, rec.ip))
            .or_default()
            .insert(key);
        self.by_port.insert(key, rec);
    }

    fn remove(&mut self, key: (u8, u16)) {
        let Some(rec) = self.by_port.remove(&key) else {
            return;
        };
        let client = (rec.ns, rec.ip);
        if let Some(keys) = self.by_client.get_mut(&client) {
            keys.remove(&key);
            if keys.is_empty() {
                self.by_client.remove(&client);
            }
        }
    }

    /// Who owns the forward on `(proto, port)`: `None` if there is none,
    /// `Some(None)` for one UPnP did not create, `Some(Some(owner))` for one
    /// it did.
    fn owner(&mut self, nat: &Nat, proto: u8, port: u16) -> Option<Option<(u64, Ipv4Addr)>> {
        let key = (proto, port);
        let rec = self.by_port.get(&key).copied();
        let Some(pf) = nat.port_forward(proto, port) else {
            self.remove(key);
            return None;
        };
        match rec {
            Some(rec) if rec.id == pf.id => Some(Some((rec.ns, rec.ip))),
            Some(_) => {
                self.remove(key);
                Some(None)
            }
            None => Some(None),
        }
    }

    /// How many live mappings `client` has.
    fn count_for(&mut self, nat: &Nat, client: (u64, Ipv4Addr)) -> usize {
        let Some(keys) = self.by_client.get(&client) else {
            return 0;
        };
        let stale: Vec<(u8, u16)> = keys
            .iter()
            .filter(|k| !Self::live(nat, **k, &self.by_port[*k]))
            .copied()
            .collect();
        for k in stale {
            self.remove(k);
        }
        self.by_client.get(&client).map_or(0, HashSet::len)
    }

    /// How many live mappings the hosts of namespace `ns` have together.
    fn count_in_ns(&mut self, nat: &Nat, ns: u64) -> usize {
        let clients: Vec<(u64, Ipv4Addr)> = self
            .by_client
            .keys()
            .filter(|c| c.0 == ns)
            .copied()
            .collect();
        clients.into_iter().map(|c| self.count_for(nat, c)).sum()
    }

    /// How many live mappings there are, counted exactly only once the
    /// records reach `cap`: below it, stale ones cannot push a request over.
    fn count_up_to(&mut self, nat: &Nat, cap: usize) -> usize {
        if self.by_port.len() >= cap {
            let stale: Vec<(u8, u16)> = self
                .by_port
                .iter()
                .filter(|(k, rec)| !Self::live(nat, **k, rec))
                .map(|(k, _)| *k)
                .collect();
            for k in stale {
                self.remove(k);
            }
        }
        self.by_port.len()
    }
}

/// UPnP IGD helper. Register via
/// [`Nat::add_local_helper`](crate::nat::Nat::add_local_helper).
#[derive(Debug)]
pub struct UPnPHelper {
    cfg: UPnPConfig,
    /// Live control-port TCP connections, keyed by inside-client 4-tuple.
    ctrl: Mutex<HashMap<CtrlKey, CtrlConn>>,
    /// Forwards this helper created, by `(proto, outside port)`, with the
    /// namespace and address of the client that asked. A control point may
    /// only delete its own mappings, and statically configured forwards are
    /// not UPnP's to touch at all.
    owned: Mutex<OwnedTable>,
}

impl UPnPHelper {
    /// A UPnP IGD service configured by `cfg`. It does nothing until
    /// registered with [`Nat::add_local_helper`].
    pub fn new(cfg: UPnPConfig) -> UPnPHelper {
        let mut cfg = cfg;
        if cfg.control_port == 0 {
            cfg.control_port = 5000;
        }
        UPnPHelper {
            cfg,
            ctrl: Mutex::new(HashMap::new()),
            owned: Mutex::new(OwnedTable::default()),
        }
    }

    #[cfg(test)]
    pub(crate) fn config(&self) -> &UPnPConfig {
        &self.cfg
    }

    // ---- SSDP ----------------------------------------------------------

    /// Handle a UDP packet, returning true if it was an SSDP M-SEARCH that we
    /// answered.
    fn handle_udp(&self, nat: &Nat, ns: u64, pkt: &[u8], ihl: usize) -> bool {
        if pkt.len() < ihl + 8 {
            return false;
        }
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        if dst_port != SSDP_PORT {
            return false;
        }
        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        if dst_ip != SSDP_MCAST {
            return false;
        }
        let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
        if udp_len < 8 || ihl + udp_len > pkt.len() {
            return false;
        }
        let payload = &pkt[ihl + 8..ihl + udp_len];
        if !is_ssdp_msearch(payload) {
            return false;
        }
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        self.send_ssdp_response(nat, ns, src_ip, src_port);
        true
    }

    /// Build and inject an SSDP 200 OK reply onto the inside network.
    fn send_ssdp_response(&self, nat: &Nat, ns: u64, dst_ip: Ipv4Addr, dst_port: u16) {
        let inside_ip = match nat.inside_addr() {
            Some(a) => a,
            None => return,
        };
        let location = format!(
            "http://{}:{}{}",
            inside_ip, self.cfg.control_port, ROOT_DESC_PATH
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age=1800\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
USN: uuid:pktkit-nat-1::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
LOCATION: {}\r\n\
SERVER: pktkit/1.0 UPnP/1.1\r\n\
EXT:\r\n\r\n",
            location
        );
        let pkt = build_udp_packet(inside_ip, SSDP_PORT, dst_ip, dst_port, resp.as_bytes());
        nat.send_inside_in(ns, Packet::from_slice(&pkt));
    }

    // ---- TCP control termination ---------------------------------------

    /// Terminate inbound TCP traffic destined for the inside IP on the control
    /// port with a server-side [`vtcp::Conn`], run a one-shot HTTP/1.1 server
    /// over it, and call [`Self::handle_soap`]. Returns `true` if the packet was
    /// addressed to the control port and consumed.
    fn handle_tcp(&self, nat: &Nat, ns: u64, pkt: &[u8], ihl: usize) -> bool {
        if pkt.len() < ihl + 20 {
            return false;
        }
        let inside_ip = match nat.inside_addr() {
            Some(a) => a,
            None => return false,
        };
        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        // Only intercept TCP to our own inside IP on the configured control
        // port; everything else flows through normal NAT processing.
        if dst_ip != inside_ip || dst_port != self.cfg.control_port {
            return false;
        }

        let seg = match Segment::parse(&pkt[ihl..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let client_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let client_port = seg.src_port;
        let key = CtrlKey {
            ns,
            client_ip,
            client_port,
        };

        // Segments the engine wants to send back to the client (server->client).
        let mut outgoing: Vec<Vec<u8>> = Vec::new();
        let mut remove = false;
        {
            let mut table = self.ctrl.lock().unwrap();
            let now = Instant::now();
            table.retain(|_, c| now.duration_since(c.last) < CTRL_IDLE_TIMEOUT);
            // Mint a fresh server-side Conn on the opening SYN.
            let mut fresh = false;
            if seg.has_flag(crate::vtcp::flags::SYN)
                && !seg.has_flag(crate::vtcp::flags::ACK)
                && !table.contains_key(&key)
                && table.len() < MAX_CTRL_CONNS
                && table
                    .keys()
                    .filter(|k| k.ns == ns && k.client_ip == client_ip)
                    .count()
                    < MAX_CTRL_CONNS_PER_CLIENT
            {
                let cfg = ConnConfig {
                    local_addr: Some(SocketAddr::new(
                        IpAddr::V4(inside_ip),
                        self.cfg.control_port,
                    )),
                    remote_addr: Some(SocketAddr::new(IpAddr::V4(client_ip), client_port)),
                    local_port: self.cfg.control_port,
                    remote_port: client_port,
                    // A request past MAX_REQUEST_BYTES is refused anyway,
                    // and a response is a few KiB: the engine's 1 MiB
                    // defaults would only let each of the connections any
                    // SYN opens hold that much out-of-order data. Nor is
                    // there a transfer worth growing them for.
                    recv_buf_size: MAX_REQUEST_BYTES,
                    send_buf_size: MAX_REQUEST_BYTES,
                    recv_buf_max: MAX_REQUEST_BYTES,
                    send_buf_max: MAX_REQUEST_BYTES,
                    ..Default::default()
                };
                table.insert(
                    key,
                    CtrlConn {
                        conn: Conn::new(cfg),
                        client_ip,
                        req: Vec::new(),
                        framing: Framing::default(),
                        responded: false,
                        last: now,
                    },
                );
                fresh = true;
            }

            let Some(cc) = table.get_mut(&key) else {
                // No state for this tuple (e.g. a stray ACK/data after we tore
                // the connection down). Consume it so it does not leak into the
                // NAT mapping path for our own control endpoint.
                return true;
            };
            cc.last = now;

            // Drive the state machine: the opening SYN goes through the passive
            // open (`accept_syn`); every later segment goes through the normal
            // dispatcher.
            if fresh {
                outgoing.extend(cc.conn.accept_syn(&seg));
            } else {
                outgoing.extend(cc.conn.handle_segment(&seg));
            }

            // Once established, pull any decrypted bytes off the stream and try
            // to satisfy a complete HTTP request.
            if cc.conn.is_established() && !cc.responded {
                let mut buf = [0u8; 2048];
                loop {
                    let n = cc.conn.read(&mut buf);
                    if n == 0 {
                        break;
                    }
                    if cc.req.len() + n > MAX_REQUEST_BYTES {
                        // Oversized request: abort the connection.
                        outgoing.extend(cc.conn.abort());
                        remove = true;
                        break;
                    }
                    cc.req.extend_from_slice(&buf[..n]);
                }

                match cc.framing.poll(&cc.req) {
                    _ if remove => {}
                    Ok(Some(req)) => {
                        let resp = self.serve(nat, ns, &req, cc.client_ip, inside_ip);
                        let (_, segs) = cc.conn.write(&resp);
                        outgoing.extend(segs);
                        // Single request/response per connection: half-close.
                        outgoing.extend(cc.conn.close());
                        cc.responded = true;
                    }
                    Ok(None) => {}
                    Err(()) => {
                        // A framing we cannot trust: there is no telling where
                        // the body ends, so answering would be a guess.
                        outgoing.extend(cc.conn.abort());
                        remove = true;
                    }
                }
                // TODO(nat): pipelined / multi-request HTTP over a single
                // control connection is not handled — we serve exactly one
                // request then close, which matches the common UPnP control
                // flow (one AddPortMapping/DeletePortMapping/etc).
            }

            // Reap fully-closed connections so the table does not grow.
            if cc.conn.is_closed() {
                remove = true;
            } else if let Some(at) = cc.conn.next_deadline() {
                // The engine armed a timer: a retransmission of the reply,
                // a delayed ACK. The NAT runs it when due.
                nat.wake_helpers_at(at);
            }
        }

        if remove {
            self.ctrl.lock().unwrap().remove(&key);
        }

        // Wrap each emitted segment in IPv4 (server->client) and inject inside.
        for seg in outgoing {
            let ip = wrap_tcp_v4(inside_ip, client_ip, &seg);
            nat.send_inside_in(ns, Packet::from_slice(&ip));
        }
        true
    }

    /// Run the control connections' due timers at `now`, sending what they
    /// produce, and return when the next one is due. Idle connections are
    /// reaped here too, so a NAT that only ticks still lets them go.
    fn tick_ctrl(&self, nat: &Nat, now: Instant) -> Option<Instant> {
        let inside_ip = nat.inside_addr()?;
        let mut outgoing: Vec<(u64, Ipv4Addr, Vec<u8>)> = Vec::new();
        let mut next: Option<Instant> = None;
        {
            let mut table = self.ctrl.lock().unwrap();
            table.retain(|k, c| {
                if now.saturating_duration_since(c.last) >= CTRL_IDLE_TIMEOUT {
                    return false;
                }
                if c.conn.next_deadline().is_some_and(|d| d <= now) {
                    for seg in c.conn.tick() {
                        outgoing.push((k.ns, c.client_ip, seg));
                    }
                }
                if c.conn.is_closed() {
                    return false;
                }
                // Past the idle timeout the connection goes, timers or not.
                let reap = c.last + CTRL_IDLE_TIMEOUT;
                let due = c.conn.next_deadline().map_or(reap, |d| d.min(reap));
                next = Some(next.map_or(due, |n| n.min(due)));
                true
            });
        }
        for (ns, client_ip, seg) in outgoing {
            let ip = wrap_tcp_v4(inside_ip, client_ip, &seg);
            nat.send_inside_in(ns, Packet::from_slice(&ip));
        }
        next
    }

    /// Answer one HTTP request on the control port. A control point fetches
    /// the device description at the SSDP `LOCATION`, then (some do) the
    /// service description it names, and POSTs SOAP to the control URL;
    /// each has its own path, and only the last is a SOAP action.
    fn serve(
        &self,
        nat: &Nat,
        ns: u64,
        req: &HttpRequest,
        client_ip: Ipv4Addr,
        inside_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let method = req.method.as_str();
        let get = method == "GET" || method == "HEAD";
        let doc = |body: String| build_http_response(200, "OK", "", &body, method == "HEAD");
        match request_path(&req.target) {
            ROOT_DESC_PATH if get => doc(self.root_desc(inside_ip)),
            SCPD_PATH if get => doc(wanip_scpd()),
            CONTROL_PATH if method == "POST" => {
                let res = self.soap(nat, ns, &req.soap_action, &req.body, Some(client_ip));
                // UPnP faults travel with HTTP 500 (UDA 1.0 §3.2.2).
                let (code, reason) = if res.status == 200 {
                    (200, "OK")
                } else {
                    (500, "Internal Server Error")
                };
                build_http_response(code, reason, "", &res.body, false)
            }
            ROOT_DESC_PATH | SCPD_PATH => {
                build_http_response(405, "Method Not Allowed", "Allow: GET, HEAD\r\n", "", false)
            }
            CONTROL_PATH => {
                build_http_response(405, "Method Not Allowed", "Allow: POST\r\n", "", false)
            }
            _ => build_http_response(404, "Not Found", "", "", false),
        }
    }

    // ---- SOAP ----------------------------------------------------------

    /// The device description document a client fetches from `LOCATION`.
    pub(crate) fn root_desc(&self, inside_ip: Ipv4Addr) -> String {
        let control_url = format!(
            "http://{}:{}{}",
            inside_ip, self.cfg.control_port, CONTROL_PATH
        );
        format!(
            "<?xml version=\"1.0\"?>\n\
<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
<specVersion><major>1</major><minor>0</minor></specVersion>\
<device>\
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
<friendlyName>pktkit NAT</friendlyName>\
<manufacturer>pktkit</manufacturer>\
<modelName>pktkit-nat</modelName>\
<UDN>uuid:pktkit-nat-1</UDN>\
<deviceList><device>\
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\
<UDN>uuid:pktkit-nat-wan-1</UDN>\
<deviceList><device>\
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
<UDN>uuid:pktkit-nat-wanconn-1</UDN>\
<serviceList><service>\
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
<serviceId>urn:upnp-org:serviceId:WANIPConnection</serviceId>\
<controlURL>{}</controlURL>\
<SCPDURL>{}</SCPDURL>\
</service></serviceList>\
</device></deviceList>\
</device></deviceList>\
</device></root>",
            control_url, SCPD_PATH
        )
    }

    /// Dispatch a SOAP control action. `soap_action` is the value of the
    /// `SOAPAction` HTTP header (quotes and the leading service URN are
    /// tolerated). `body` is the raw XML request body. `client_ip` is the
    /// requesting host (the inside client), used to enforce that a client only
    /// forwards to itself.
    #[cfg(test)]
    pub(crate) fn handle_soap(
        &self,
        nat: &Nat,
        soap_action: &str,
        body: &[u8],
        client_ip: Option<Ipv4Addr>,
    ) -> SoapResult {
        self.soap(nat, 0, soap_action, body, client_ip)
    }

    /// Dispatch a SOAP control action for a client in inside namespace `ns`,
    /// where the forwards it creates must point. `soap_action` is the value
    /// of the `SOAPAction` HTTP header (quotes and the leading service URN
    /// are tolerated), `body` the raw XML request body, and `client_ip` the
    /// requesting inside host, which may only forward to itself.
    fn soap(
        &self,
        nat: &Nat,
        ns: u64,
        soap_action: &str,
        body: &[u8],
        client_ip: Option<Ipv4Addr>,
    ) -> SoapResult {
        let action = normalize_action(soap_action);
        match action.as_str() {
            "GetExternalIPAddress" => self.action_get_external_ip(nat),
            "AddPortMapping" => self.action_add_port_mapping(nat, ns, body, client_ip),
            "DeletePortMapping" => self.action_delete_port_mapping(nat, ns, body, client_ip),
            "GetGenericPortMappingEntry" => self.action_get_generic(nat, ns, body),
            "GetSpecificPortMappingEntry" => self.action_get_specific(nat, ns, body),
            _ => soap_fault(401, "Invalid Action"),
        }
    }

    fn action_get_external_ip(&self, nat: &Nat) -> SoapResult {
        let ext = nat
            .outside_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        soap_response(&format!(
            "<u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
<NewExternalIPAddress>{}</NewExternalIPAddress>\
</u:GetExternalIPAddressResponse>",
            ext
        ))
    }

    fn action_add_port_mapping(
        &self,
        nat: &Nat,
        ns: u64,
        body: &[u8],
        client_ip: Option<Ipv4Addr>,
    ) -> SoapResult {
        let xml = String::from_utf8_lossy(body);
        let proto_str = xml_field(&xml, "NewProtocol").unwrap_or_default();
        let proto = match parse_protocol(&proto_str) {
            Some(p) => p,
            None => return soap_fault(402, "Invalid protocol"),
        };
        let ext_port: u16 = xml_field(&xml, "NewExternalPort")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if ext_port == 0 {
            return soap_fault(716, "External port wildcard not supported");
        }
        let int_port: u16 = xml_field(&xml, "NewInternalPort")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if int_port == 0 {
            return soap_fault(402, "Invalid internal port");
        }
        let inside_ip: Ipv4Addr =
            match xml_field(&xml, "NewInternalClient").and_then(|s| s.trim().parse().ok()) {
                Some(a) => a,
                None => return soap_fault(402, "Invalid internal client IP"),
            };
        // A client may only forward to itself.
        if let Some(cip) = client_ip
            && cip != inside_ip
        {
            return soap_fault(718, "Internal client must be the requesting host");
        }
        if !self.is_port_allowed(ext_port) {
            return soap_fault(718, "External port not in allowed range");
        }
        let mut owned = self.owned.lock().unwrap();
        let existing = owned.owner(nat, proto, ext_port);
        if existing.is_some_and(|o| o != Some((ns, inside_ip))) {
            return soap_fault(718, "ConflictInMappingEntry");
        }
        // Clients renew a lease by adding the same mapping again before it
        // runs out; one already counted must not be refused by the caps it
        // counts towards.
        let renewal = existing.is_some();
        if !renewal
            && self.cfg.max_mappings > 0
            && owned.count_up_to(nat, self.cfg.max_mappings) >= self.cfg.max_mappings
        {
            return soap_fault(728, "Too many port mappings");
        }
        if !renewal
            && self.cfg.max_per_client > 0
            && owned.count_for(nat, (ns, inside_ip)) >= self.cfg.max_per_client
        {
            return soap_fault(728, "Too many port mappings for this client");
        }
        if !renewal
            && ns != 0
            && self.cfg.max_per_namespace > 0
            && owned.count_in_ns(nat, ns) >= self.cfg.max_per_namespace
        {
            return soap_fault(728, "Too many port mappings for this client");
        }

        let lease_secs: u32 = xml_field(&xml, "NewLeaseDuration")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let expires = compute_expiry(lease_secs, self.cfg.lease_duration);

        let desc = truncate_utf8(
            xml_field(&xml, "NewPortMappingDescription").unwrap_or_default(),
            MAX_DESCRIPTION_BYTES,
        );
        let mut pf = PortForward::new(proto, ext_port, inside_ip, int_port)
            .description(desc)
            .namespace(ns);
        pf.expires = expires;
        let id = match nat.add_port_forward_id(pf) {
            Ok(id) => id,
            Err(_) => return soap_fault(718, "ConflictInMappingEntry"),
        };
        owned.insert(
            (proto, ext_port),
            Owned {
                ns,
                ip: inside_ip,
                id,
            },
        );
        drop(owned);
        soap_response(
            "<u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:AddPortMappingResponse>",
        )
    }

    fn action_delete_port_mapping(
        &self,
        nat: &Nat,
        ns: u64,
        body: &[u8],
        client_ip: Option<Ipv4Addr>,
    ) -> SoapResult {
        let xml = String::from_utf8_lossy(body);
        let proto = match parse_protocol(&xml_field(&xml, "NewProtocol").unwrap_or_default()) {
            Some(p) => p,
            None => return soap_fault(402, "Invalid protocol"),
        };
        let ext_port: u16 = xml_field(&xml, "NewExternalPort")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let mut owned = self.owned.lock().unwrap();
        let allowed = match owned.owner(nat, proto, ext_port) {
            None => return soap_fault(714, "NoSuchEntryInArray"),
            // Without a requesting host (a direct API call) any mapping UPnP
            // made may go, but never a static one.
            Some(Some(owner)) => client_ip.is_none_or(|ip| owner == (ns, ip)),
            Some(None) => false,
        };
        if !allowed {
            return soap_fault(606, "Action not authorized");
        }
        nat.remove_port_forward(proto, ext_port);
        owned.remove((proto, ext_port));
        drop(owned);
        soap_response(
            "<u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:DeletePortMappingResponse>",
        )
    }

    /// Mappings are listed only to clients of the namespace they lead
    /// into: another tenant's would tell a client what that tenant runs,
    /// and on which ports.
    fn action_get_generic(&self, nat: &Nat, ns: u64, body: &[u8]) -> SoapResult {
        let xml = String::from_utf8_lossy(body);
        let idx: Option<usize> =
            xml_field(&xml, "NewPortMappingIndex").and_then(|s| s.trim().parse().ok());
        // Only the entry asked for is copied out: a client walks the table
        // one index at a time, and each request copying all of it would
        // make the walk quadratic in the table's size.
        match idx.and_then(|i| nat.port_forward_at(ns, i)) {
            Some(pf) => soap_response(&port_mapping_entry_xml(
                &pf,
                "GetGenericPortMappingEntryResponse",
            )),
            None => soap_fault(713, "SpecifiedArrayIndexInvalid"),
        }
    }

    fn action_get_specific(&self, nat: &Nat, ns: u64, body: &[u8]) -> SoapResult {
        let xml = String::from_utf8_lossy(body);
        let proto = match parse_protocol(&xml_field(&xml, "NewProtocol").unwrap_or_default()) {
            Some(p) => p,
            None => return soap_fault(402, "Invalid protocol"),
        };
        let ext_port: u16 = xml_field(&xml, "NewExternalPort")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        match nat
            .port_forward(proto, ext_port)
            .filter(|pf| pf.namespace == ns)
        {
            Some(pf) => soap_response(&port_mapping_entry_xml(
                &pf,
                "GetSpecificPortMappingEntryResponse",
            )),
            None => soap_fault(714, "NoSuchEntryInArray"),
        }
    }

    fn is_port_allowed(&self, port: u16) -> bool {
        if self.cfg.allowed_ports.is_empty() {
            return true;
        }
        self.cfg
            .allowed_ports
            .iter()
            .any(|&(lo, hi)| port >= lo && port <= hi)
    }
}

impl Helper for UPnPHelper {
    fn name(&self) -> &str {
        "upnp"
    }
}

impl LocalHelper for UPnPHelper {
    fn handle_local(&self, nat: &Nat, pkt: &Packet) -> bool {
        self.handle_local_in(nat, 0, pkt)
    }

    fn handle_local_in(&self, nat: &Nat, ns: u64, pkt: &Packet) -> bool {
        let bytes = pkt.as_bytes();
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return false;
        }
        let ihl = (bytes[0] & 0x0F) as usize * 4;
        // The NAT hands over validated datagrams, but this is a public entry
        // point: an IHL under 5 would have the transport header read from
        // inside the IP header.
        if ihl < 20 || bytes.len() < ihl {
            return false;
        }
        match bytes[9] {
            PROTO_UDP => self.handle_udp(nat, ns, bytes, ihl),
            PROTO_TCP => self.handle_tcp(nat, ns, bytes, ihl),
            _ => false,
        }
    }

    fn tick(&self, nat: &Nat, now: Instant) -> Option<Instant> {
        self.tick_ctrl(nat, now)
    }
}

// ===== free helpers =====

/// True if `payload` is an SSDP M-SEARCH targeting an IGD / WANIPConnection /
/// rootdevice / ssdp:all.
fn is_ssdp_msearch(payload: &[u8]) -> bool {
    if !payload.starts_with(b"M-SEARCH") {
        return false;
    }
    let upper = payload.to_ascii_uppercase();
    contains(&upper, b"SSDP:ALL")
        || contains(
            payload,
            b"urn:schemas-upnp-org:device:InternetGatewayDevice",
        )
        || contains(payload, b"urn:schemas-upnp-org:service:WANIPConnection")
        || contains(payload, b"upnp:rootdevice")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Build a raw IPv4+UDP packet (checksum on IP only; UDP checksum left zero,
/// which is valid for IPv4).
fn build_udp_packet(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_UDP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ic = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ic.to_be_bytes());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    // pkt[26..28] UDP checksum left zero.
    pkt
}

/// Wrap a marshaled TCP segment (`src`->`dst`) in a minimal IPv4 header with a
/// correct IP header checksum and TCP checksum. Mirrors the framing used by
/// `vclient::tcp` / `slirp::tcp_stream`.
fn wrap_tcp_v4(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> Vec<u8> {
    let total = 20 + seg.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::TCP.as_u8();
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cs = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    ip[20..].copy_from_slice(seg);
    // Patch the TCP checksum (pseudo-header + segment) into bytes 16..18.
    let pseudo = pseudo_header_checksum(
        Protocol::TCP,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        seg.len() as u16,
    );
    let body = !checksum(seg);
    let tcp_cs = !combine_checksums(pseudo, body);
    ip[20 + 16..20 + 18].copy_from_slice(&tcp_cs.to_be_bytes());
    ip
}

/// A parsed HTTP/1.1 request: enough of one for the UPnP SOAP control flow.
struct HttpRequest {
    method: String,
    /// The request target as sent (origin or absolute form).
    target: String,
    /// Value of the `SOAPAction` header (raw; `normalize_action` strips it).
    soap_action: String,
    /// The request body (Content-Length bytes).
    body: Vec<u8>,
}

/// A request's line and headers, parsed.
#[derive(Debug)]
struct HttpHead {
    method: String,
    target: String,
    soap_action: String,
    content_length: usize,
}

/// How far a connection's buffered request has been parsed, so that each
/// segment costs only its own bytes: the end of the header block is looked
/// for from where the last look stopped, and once found the headers are
/// parsed once and the body waited on by length. Rescanning the whole
/// buffer per segment would let a client sending 64 KiB a few bytes at a
/// time cost the NAT quadratic work.
#[derive(Debug, Default)]
struct Framing {
    /// Bytes already searched for the end of the header block.
    scanned: usize,
    /// The headers, and where the body starts, once they are in.
    head: Option<(HttpHead, usize)>,
}

impl Framing {
    /// The request in `buf`, which only ever grows between calls, once it
    /// is complete; see [`parse_http_request`].
    fn poll(&mut self, buf: &[u8]) -> Result<Option<HttpRequest>, ()> {
        if self.head.is_none() {
            // The terminator may straddle what was searched and what came.
            let from = self.scanned.saturating_sub(3);
            let Some(at) = find_subslice(&buf[from..], b"\r\n\r\n") else {
                self.scanned = buf.len();
                return Ok(None);
            };
            let hdr_end = from + at;
            self.head = Some((parse_http_head(&buf[..hdr_end])?, hdr_end + 4));
        }
        let Some((head, body_start)) = &self.head else {
            return Ok(None);
        };
        let body_end = body_start + head.content_length;
        if buf.len() < body_end {
            return Ok(None); // body not fully buffered yet
        }
        let body = buf[*body_start..body_end].to_vec();
        let (head, _) = self.head.take().expect("checked above");
        Ok(Some(HttpRequest {
            method: head.method,
            target: head.target,
            soap_action: head.soap_action,
            body,
        }))
    }
}

/// Parse a buffered HTTP/1.1 request. Returns `Ok(None)` if the request is not
/// yet complete (headers not terminated, or body shorter than
/// `Content-Length`), and `Err` if its framing is invalid (RFC 9112 §6.3) or
/// announces a body larger than we are willing to buffer.
///
/// This is a deliberately small, std-only parser for the single
/// request/response UPnP control exchange: it reads the request line + headers,
/// honours `Content-Length`, and pulls out the `SOAPAction` header. Anything
/// beyond that (chunked transfer-encoding, pipelining, trailers) is left as
/// `// TODO(nat)`.
#[cfg(test)]
fn parse_http_request(buf: &[u8]) -> Result<Option<HttpRequest>, ()> {
    Framing::default().poll(buf)
}

/// Parse a request's line and headers, `head` being the header block
/// without its terminating blank line. `Err` as for
/// [`parse_http_request`].
fn parse_http_head(head: &[u8]) -> Result<HttpHead, ()> {
    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.split("\r\n");
    // Request line: METHOD SP target SP version.
    let mut request_line = lines.next().unwrap_or("").split(' ');
    let method = request_line.next().unwrap_or("").to_string();
    let target = request_line.next().unwrap_or("").to_string();

    let mut content_length: Option<usize> = None;
    let mut soap_action = String::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                // Bounded before any arithmetic: the value is attacker-chosen.
                let len = value
                    .parse::<usize>()
                    .ok()
                    .filter(|&n| n <= MAX_REQUEST_BYTES)
                    .ok_or(())?;
                if content_length.is_some_and(|prev| prev != len) {
                    return Err(());
                }
                content_length = Some(len);
            } else if name.eq_ignore_ascii_case("soapaction") {
                soap_action = value.to_string();
            }
            // TODO(nat): chunked Transfer-Encoding is not handled.
        }
    }
    Ok(HttpHead {
        method,
        target,
        soap_action,
        content_length: content_length.unwrap_or(0),
    })
}

/// The path of a request target, in origin form (`/x?q`) or absolute form
/// (`http://host:port/x?q`, RFC 9112 §3.2.2), without its query.
fn request_path(target: &str) -> &str {
    let path = match target.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("/", |i| &rest[i..]),
        None => target,
    };
    path.split('?').next().unwrap_or(path)
}

/// Build an HTTP/1.1 response. `extra` holds further header lines, each
/// ending in CRLF. A response to HEAD announces the body but leaves it out.
fn build_http_response(code: u16, reason: &str, extra: &str, body: &str, head: bool) -> Vec<u8> {
    let content_type = if body.is_empty() {
        ""
    } else {
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
    };
    let mut out = format!(
        "HTTP/1.1 {} {}\r\n\
{}{}Content-Length: {}\r\n\
Connection: close\r\n\
Server: pktkit/1.0 UPnP/1.1\r\n\r\n",
        code,
        reason,
        content_type,
        extra,
        body.len(),
    )
    .into_bytes();
    if !head {
        out.extend_from_slice(body.as_bytes());
    }
    out
}

/// The service description (SCPD) of WANIPConnection:1, trimmed to the
/// actions this helper implements.
fn wanip_scpd() -> String {
    const ACTIONS: &[(&str, &[(&str, bool, &str)])] = &[
        (
            "GetExternalIPAddress",
            &[("NewExternalIPAddress", false, "ExternalIPAddress")],
        ),
        (
            "AddPortMapping",
            &[
                ("NewRemoteHost", true, "RemoteHost"),
                ("NewExternalPort", true, "ExternalPort"),
                ("NewProtocol", true, "PortMappingProtocol"),
                ("NewInternalPort", true, "InternalPort"),
                ("NewInternalClient", true, "InternalClient"),
                ("NewEnabled", true, "PortMappingEnabled"),
                ("NewPortMappingDescription", true, "PortMappingDescription"),
                ("NewLeaseDuration", true, "PortMappingLeaseDuration"),
            ],
        ),
        (
            "DeletePortMapping",
            &[
                ("NewRemoteHost", true, "RemoteHost"),
                ("NewExternalPort", true, "ExternalPort"),
                ("NewProtocol", true, "PortMappingProtocol"),
            ],
        ),
        (
            "GetGenericPortMappingEntry",
            &[
                ("NewPortMappingIndex", true, "PortMappingNumberOfEntries"),
                ("NewRemoteHost", false, "RemoteHost"),
                ("NewExternalPort", false, "ExternalPort"),
                ("NewProtocol", false, "PortMappingProtocol"),
                ("NewInternalPort", false, "InternalPort"),
                ("NewInternalClient", false, "InternalClient"),
                ("NewEnabled", false, "PortMappingEnabled"),
                ("NewPortMappingDescription", false, "PortMappingDescription"),
                ("NewLeaseDuration", false, "PortMappingLeaseDuration"),
            ],
        ),
        (
            "GetSpecificPortMappingEntry",
            &[
                ("NewRemoteHost", true, "RemoteHost"),
                ("NewExternalPort", true, "ExternalPort"),
                ("NewProtocol", true, "PortMappingProtocol"),
                ("NewInternalPort", false, "InternalPort"),
                ("NewInternalClient", false, "InternalClient"),
                ("NewEnabled", false, "PortMappingEnabled"),
                ("NewPortMappingDescription", false, "PortMappingDescription"),
                ("NewLeaseDuration", false, "PortMappingLeaseDuration"),
            ],
        ),
    ];
    const VARIABLES: &[(&str, &str)] = &[
        ("ExternalIPAddress", "string"),
        ("RemoteHost", "string"),
        ("ExternalPort", "ui2"),
        ("InternalPort", "ui2"),
        ("PortMappingProtocol", "string"),
        ("InternalClient", "string"),
        ("PortMappingEnabled", "boolean"),
        ("PortMappingDescription", "string"),
        ("PortMappingLeaseDuration", "ui4"),
        ("PortMappingNumberOfEntries", "ui2"),
    ];
    let mut out = String::from(
        "<?xml version=\"1.0\"?>\n\
<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">\
<specVersion><major>1</major><minor>0</minor></specVersion><actionList>",
    );
    for (name, args) in ACTIONS {
        out.push_str(&format!("<action><name>{name}</name><argumentList>"));
        for (arg, input, var) in *args {
            let dir = if *input { "in" } else { "out" };
            out.push_str(&format!(
                "<argument><name>{arg}</name><direction>{dir}</direction>\
<relatedStateVariable>{var}</relatedStateVariable></argument>"
            ));
        }
        out.push_str("</argumentList></action>");
    }
    out.push_str("</actionList><serviceStateTable>");
    for (name, ty) in VARIABLES {
        out.push_str(&format!(
            "<stateVariable sendEvents=\"no\"><name>{name}</name><dataType>{ty}</dataType>"
        ));
        if *name == "PortMappingProtocol" {
            out.push_str(
                "<allowedValueList><allowedValue>TCP</allowedValue>\
<allowedValue>UDP</allowedValue></allowedValueList>",
            );
        }
        out.push_str("</stateVariable>");
    }
    out.push_str("</serviceStateTable></scpd>");
    out
}

/// Find the first occurrence of `needle` in `haystack`, returning its offset.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Strip surrounding quotes and the leading `urn...#` from a SOAPAction header.
fn normalize_action(soap_action: &str) -> String {
    let trimmed = soap_action.trim().trim_matches('"');
    match trimmed.rsplit_once('#') {
        Some((_, a)) => a.to_string(),
        None => trimmed.to_string(),
    }
}

/// Extract the text content of the first `<name>...</name>` element. Tolerates
/// namespace prefixes (matches on the local element name).
fn xml_field(xml: &str, name: &str) -> Option<String> {
    // Find "<...name>" honouring an optional namespace prefix and the bare tag.
    let bytes = xml.as_bytes();
    let mut search = 0;
    while let Some(rel) = xml[search..].find('<') {
        let lt = search + rel;
        // Read the tag name.
        let after = lt + 1;
        let tag_end = xml[after..]
            .find(|c: char| c == '>' || c.is_whitespace())
            .map(|p| after + p)?;
        let raw_tag = &xml[after..tag_end];
        let local = raw_tag.rsplit(':').next().unwrap_or(raw_tag);
        if !raw_tag.starts_with('/') && local == name {
            // Find end of this opening tag.
            let gt = xml[lt..].find('>').map(|p| lt + p)?;
            let content_start = gt + 1;
            // Find matching close tag (by local name).
            let close = format!("</{}>", raw_tag);
            if let Some(crel) = xml[content_start..].find(&close) {
                return Some(xml[content_start..content_start + crel].to_string());
            }
            // Try a namespaced/bare close that ends with ":name>" or "name>".
            let needle = format!("{}>", name);
            if let Some(crel) = find_close(&xml[content_start..], &needle) {
                return Some(xml[content_start..content_start + crel].to_string());
            }
            return None;
        }
        let _ = bytes;
        search = tag_end;
    }
    None
}

/// Find the byte offset of a closing tag whose local name+">" matches `needle`,
/// i.e. `</...needle`.
fn find_close(s: &str, needle: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = s[from..].find("</") {
        let pos = from + rel;
        let rest = &s[pos + 2..];
        let tag_end = rest.find('>')? + 1;
        let tag = &rest[..tag_end];
        let local = tag.rsplit(':').next().unwrap_or(tag);
        if local == needle {
            return Some(pos);
        }
        from = pos + 2;
    }
    None
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn truncate_utf8(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

fn parse_protocol(s: &str) -> Option<u8> {
    match s.trim().to_ascii_uppercase().as_str() {
        "TCP" => Some(PROTO_TCP),
        "UDP" => Some(PROTO_UDP),
        _ => None,
    }
}

fn compute_expiry(lease_secs: u32, max: Option<Duration>) -> Option<Instant> {
    if lease_secs > 0 {
        let mut dur = Duration::from_secs(lease_secs as u64);
        if let Some(m) = max
            && dur > m
        {
            dur = m;
        }
        Some(Instant::now() + dur)
    } else {
        max.map(|m| Instant::now() + m)
    }
}

fn port_mapping_entry_xml(pf: &PortForward, response_name: &str) -> String {
    let proto_str = if pf.proto == PROTO_UDP { "UDP" } else { "TCP" };
    let lease = pf
        .expires
        .map(|e| e.saturating_duration_since(Instant::now()).as_secs() as u32)
        .unwrap_or(0);
    format!(
        "<u:{name} xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{ext}</NewExternalPort>\
<NewProtocol>{proto}</NewProtocol>\
<NewInternalPort>{int}</NewInternalPort>\
<NewInternalClient>{ip}</NewInternalClient>\
<NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>{desc}</NewPortMappingDescription>\
<NewLeaseDuration>{lease}</NewLeaseDuration>\
</u:{name}>",
        name = response_name,
        ext = pf.outside_port,
        proto = proto_str,
        int = pf.inside_port,
        ip = pf.inside_ip,
        desc = xml_escape(&pf.description),
        lease = lease,
    )
}

fn soap_response(body: &str) -> SoapResult {
    SoapResult {
        status: 200,
        body: format!(
            "<?xml version=\"1.0\"?>\n\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body>{}</s:Body></s:Envelope>",
            body
        ),
    }
}

fn soap_fault(code: u16, desc: &str) -> SoapResult {
    SoapResult {
        status: 500,
        body: format!(
            "<?xml version=\"1.0\"?>\n\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><s:Fault><faultcode>s:Client</faultcode>\
<faultstring>UPnPError</faultstring>\
<detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
<errorCode>{}</errorCode>\
<errorDescription>{}</errorDescription>\
</UPnPError></detail></s:Fault></s:Body></s:Envelope>",
            code,
            xml_escape(desc)
        ),
    }
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::nat::Nat;
    use crate::{IpPrefix, L3Device};
    use std::sync::{Arc, Mutex as StdMutex};

    fn pfx(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn add_body(ext: u16, int: u16, client: &str, proto: &str, lease: u32) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{}</NewExternalPort>\
<NewProtocol>{}</NewProtocol>\
<NewInternalPort>{}</NewInternalPort>\
<NewInternalClient>{}</NewInternalClient>\
<NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>test map</NewPortMappingDescription>\
<NewLeaseDuration>{}</NewLeaseDuration>\
</u:AddPortMapping></s:Body></s:Envelope>",
            ext, proto, int, client, lease
        )
        .into_bytes()
    }

    #[test]
    fn upnp_add_port_mapping_creates_forward() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let client = Ipv4Addr::new(10, 0, 0, 42);

        let res = h.handle_soap(
            &nat,
            "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"",
            &add_body(8080, 80, "10.0.0.42", "TCP", 3600),
            Some(client),
        );
        assert_eq!(res.status, 200, "body: {}", res.body);
        assert!(res.body.contains("AddPortMappingResponse"));

        let fwds = nat.list_port_forwards();
        assert_eq!(fwds.len(), 1);
        assert_eq!(fwds[0].outside_port, 8080);
        assert_eq!(fwds[0].inside_port, 80);
        assert_eq!(fwds[0].inside_ip, client);
        assert_eq!(fwds[0].proto, PROTO_TCP);
        assert!(fwds[0].expires.is_some());
    }

    #[test]
    fn upnp_add_then_delete_removes_forward() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let client = Ipv4Addr::new(10, 0, 0, 42);

        let res = h.handle_soap(
            &nat,
            "AddPortMapping",
            &add_body(9000, 9000, "10.0.0.42", "UDP", 0),
            Some(client),
        );
        assert_eq!(res.status, 200);
        assert_eq!(nat.list_port_forwards().len(), 1);

        let del = "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
<NewExternalPort>9000</NewExternalPort><NewProtocol>UDP</NewProtocol>\
</u:DeletePortMapping></s:Body></s:Envelope>";
        let res = h.handle_soap(&nat, "DeletePortMapping", del.as_bytes(), Some(client));
        assert_eq!(res.status, 200, "body: {}", res.body);
        assert_eq!(nat.list_port_forwards().len(), 0);
    }

    #[test]
    fn huge_content_length_is_rejected() {
        let req = b"POST /ctl HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\nabc";
        assert!(parse_http_request(req).is_err());
        let req = b"POST /ctl HTTP/1.1\r\nContent-Length: 100000\r\n\r\nabc";
        assert!(parse_http_request(req).is_err());
        let req = b"POST /ctl HTTP/1.1\r\nContent-Length: nope\r\n\r\nabc";
        assert!(parse_http_request(req).is_err());
        let req = b"POST /ctl HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd";
        assert!(parse_http_request(req).is_err());
    }

    #[test]
    fn content_length_bounds_the_body() {
        let req = b"POST /ctl HTTP/1.1\r\nSOAPAction: \"x#Y\"\r\nContent-Length: 3\r\n\r\nab";
        assert!(matches!(parse_http_request(req), Ok(None)));
        let req = b"POST /ctl HTTP/1.1\r\nSOAPAction: \"x#Y\"\r\nContent-Length: 3\r\n\r\nabcd";
        let r = parse_http_request(req).unwrap().unwrap();
        assert_eq!(r.body, b"abc");
        assert_eq!(r.soap_action, "\"x#Y\"");
    }

    #[test]
    fn upnp_get_external_ip_returns_outside_addr() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.7/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let res = h.handle_soap(&nat, "GetExternalIPAddress", b"", None);
        assert_eq!(res.status, 200);
        assert!(res.body.contains("203.0.113.7"), "body: {}", res.body);
    }

    #[test]
    fn upnp_client_cannot_forward_to_other_host() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        // Requesting host is .42 but the body asks to forward to .99.
        let res = h.handle_soap(
            &nat,
            "AddPortMapping",
            &add_body(8080, 80, "10.0.0.99", "TCP", 0),
            Some(Ipv4Addr::new(10, 0, 0, 42)),
        );
        assert_eq!(res.status, 500);
        assert!(res.body.contains("718"), "body: {}", res.body);
        assert_eq!(nat.list_port_forwards().len(), 0);
    }

    #[test]
    fn upnp_disallowed_port_rejected() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let cfg = UPnPConfig {
            allowed_ports: vec![(1024, 2048)],
            ..Default::default()
        };
        let h = UPnPHelper::new(cfg);
        let res = h.handle_soap(
            &nat,
            "AddPortMapping",
            &add_body(8080, 80, "10.0.0.42", "TCP", 0),
            Some(Ipv4Addr::new(10, 0, 0, 42)),
        );
        assert_eq!(res.status, 500);
        assert_eq!(nat.list_port_forwards().len(), 0);
    }

    #[test]
    fn ssdp_msearch_gets_response() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());

        let injected = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let i = injected.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            i.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        // Build an M-SEARCH from inside client to 239.255.255.250:1900 and
        // hand it to the helper directly (see
        // `inside_msearch_is_answered_through_the_nat` for the NAT path).
        let payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        let pkt = build_udp_packet(
            Ipv4Addr::new(10, 0, 0, 50),
            40000,
            SSDP_MCAST,
            SSDP_PORT,
            payload,
        );
        let consumed = h.handle_local(&nat, crate::Packet::from_slice(&pkt));
        assert!(consumed, "M-SEARCH should be consumed");

        let injected = injected.lock().unwrap();
        assert_eq!(injected.len(), 1, "expected one SSDP reply");
        let reply = &injected[0];
        // From inside IP:1900 to the requester.
        assert_eq!(&reply[12..16], &[10, 0, 0, 1]);
        assert_eq!(&reply[16..20], &[10, 0, 0, 50]);
        let ihl = (reply[0] & 0x0F) as usize * 4;
        let body = &reply[ihl + 8..];
        let s = String::from_utf8_lossy(body);
        assert!(s.starts_with("HTTP/1.1 200 OK"), "body: {}", s);
        assert!(s.contains("rootDesc.xml"), "body: {}", s);
    }

    /// Drive a client `vtcp::Conn` through the NAT's UPnP control path: open a
    /// TCP connection to the control port, POST an `AddPortMapping` SOAP
    /// request, and assert that a port forward is created and a 200 HTTP
    /// response with the SOAP envelope comes back.
    #[test]
    fn upnp_control_tcp_add_port_mapping_round_trip() {
        use crate::vtcp::{Conn, ConnConfig};

        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let inside_ip = Ipv4Addr::new(10, 0, 0, 1);
        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let control_port = h.config().control_port;
        let client_port = 51000u16;

        // The helper injects server->client packets onto the inside via
        // `send_inside`; capture them in a queue we pump back into the client.
        let to_client = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let tc = to_client.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            tc.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        // The virtual client (the inside host dialing the control port).
        let mut client = Conn::new(ConnConfig {
            local_addr: Some(SocketAddr::new(IpAddr::V4(client_ip), client_port)),
            remote_addr: Some(SocketAddr::new(IpAddr::V4(inside_ip), control_port)),
            local_port: client_port,
            remote_port: control_port,
            ..Default::default()
        });

        // Pump: feed every queued client segment into the helper, then feed
        // every server->client packet the helper produced back into the client,
        // until both stop emitting. Collected client-side payload accumulates in
        // `recv_payload`.
        let mut pending: Vec<Vec<u8>> = client.connect();
        let mut recv_payload: Vec<u8> = Vec::new();
        let mut http_sent = false;

        for _round in 0..64 {
            // Deliver client->server segments to the helper.
            for seg in pending.drain(..) {
                let ip = wrap_tcp_v4(client_ip, inside_ip, &seg);
                let consumed = h.handle_local(&nat, crate::Packet::from_slice(&ip));
                assert!(consumed, "control-port TCP should be consumed");
            }

            // Pull server->client packets and feed them into the client conn.
            let server_pkts: Vec<Vec<u8>> = std::mem::take(&mut *to_client.lock().unwrap());
            let mut produced: Vec<Vec<u8>> = Vec::new();
            for pkt in server_pkts {
                let ihl = (pkt[0] & 0x0F) as usize * 4;
                let seg = Segment::parse(&pkt[ihl..]).expect("server segment parses");
                produced.extend(client.handle_segment(&seg));
            }

            // Drain any HTTP response bytes the client received.
            let mut buf = [0u8; 2048];
            loop {
                let n = client.read(&mut buf);
                if n == 0 {
                    break;
                }
                recv_payload.extend_from_slice(&buf[..n]);
            }

            // Once established, send the SOAP POST exactly once.
            if client.is_established() && !http_sent {
                let body = add_body(8080, 80, "10.0.0.42", "TCP", 3600);
                let req = format!(
                    "POST /ctl/WANIPConnection HTTP/1.1\r\n\
Host: {inside}:{port}\r\n\
Content-Type: text/xml; charset=\"utf-8\"\r\n\
SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\
Content-Length: {len}\r\n\r\n",
                    inside = inside_ip,
                    port = control_port,
                    len = body.len(),
                );
                let mut wire = req.into_bytes();
                wire.extend_from_slice(&body);
                let (n, segs) = client.write(&wire);
                assert_eq!(
                    n,
                    wire.len(),
                    "client send buffer should accept the request"
                );
                produced.extend(segs);
                http_sent = true;
            }

            pending = produced;
            if pending.is_empty()
                && http_sent
                && find_subslice(&recv_payload, b"\r\n\r\n").is_some()
            {
                break;
            }
        }

        // The port forward must have been created by `handle_soap`.
        let fwds = nat.list_port_forwards();
        assert_eq!(fwds.len(), 1, "expected one port forward");
        assert_eq!(fwds[0].outside_port, 8080);
        assert_eq!(fwds[0].inside_port, 80);
        assert_eq!(fwds[0].inside_ip, client_ip);
        assert_eq!(fwds[0].proto, PROTO_TCP);

        // The client must have received a 200 HTTP response with the SOAP body.
        let resp = String::from_utf8_lossy(&recv_payload);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "response: {}", resp);
        assert!(
            resp.contains("AddPortMappingResponse"),
            "response: {}",
            resp
        );
        assert!(resp.contains("s:Envelope"), "response: {}", resp);
    }

    #[test]
    fn control_connection_table_is_bounded_and_reaped() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let inside_ip = Ipv4Addr::new(10, 0, 0, 1);
        // From many hosts, so that the per-client cap is not what binds.
        let syn = |port: u16| {
            let client_ip = Ipv4Addr::new(10, 0, 0, 2 + (port % 200) as u8);
            let mut c = crate::vtcp::Conn::new(crate::vtcp::ConnConfig {
                local_addr: Some(SocketAddr::new(IpAddr::V4(client_ip), port)),
                remote_addr: Some(SocketAddr::new(IpAddr::V4(inside_ip), 5000)),
                local_port: port,
                remote_port: 5000,
                ..Default::default()
            });
            wrap_tcp_v4(client_ip, inside_ip, &c.connect()[0])
        };
        // Half-open handshakes that never complete.
        for port in 0..(MAX_CTRL_CONNS as u16 + 50) {
            h.handle_local(&nat, crate::Packet::from_slice(&syn(40000 + port)));
        }
        assert_eq!(h.ctrl.lock().unwrap().len(), MAX_CTRL_CONNS);

        let long_ago = Instant::now() - CTRL_IDLE_TIMEOUT - Duration::from_secs(1);
        h.ctrl
            .lock()
            .unwrap()
            .values_mut()
            .for_each(|c| c.last = long_ago);
        h.handle_local(&nat, crate::Packet::from_slice(&syn(60000)));
        assert_eq!(h.ctrl.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_request_arriving_in_pieces_is_parsed_once() {
        let req = b"POST /ctl HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        // Byte by byte, so that the terminator straddles every boundary.
        let mut f = Framing::default();
        for n in 1..req.len() {
            assert!(f.poll(&req[..n]).unwrap().is_none(), "{n}");
        }
        let r = f.poll(req).unwrap().unwrap();
        assert_eq!(
            (r.method.as_str(), r.body.as_slice()),
            ("POST", &b"hello"[..])
        );
    }

    /// Open a control connection from `client` and return the client's end
    /// of it once established, with the server's SYN-ACK.
    fn establish(
        h: &UPnPHelper,
        nat: &Nat,
        to_client: &StdMutex<Vec<Vec<u8>>>,
        (client, port): (Ipv4Addr, u16),
    ) -> (crate::vtcp::Conn, Segment) {
        use crate::vtcp::{Conn, ConnConfig};
        let inside_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut conn = Conn::new(ConnConfig {
            local_addr: Some(SocketAddr::new(IpAddr::V4(client), port)),
            remote_addr: Some(SocketAddr::new(IpAddr::V4(inside_ip), 5000)),
            local_port: port,
            remote_port: 5000,
            ..Default::default()
        });
        let mut pending = conn.connect();
        let mut synack = None;
        for _ in 0..8 {
            for seg in pending.drain(..) {
                let ip = wrap_tcp_v4(client, inside_ip, &seg);
                h.handle_local(nat, crate::Packet::from_slice(&ip));
            }
            for pkt in std::mem::take(&mut *to_client.lock().unwrap()) {
                let seg = Segment::parse(&pkt[20..]).unwrap();
                if seg.has_flag(crate::vtcp::flags::SYN) {
                    synack = Some(seg.clone());
                }
                pending.extend(conn.handle_segment(&seg));
            }
            if conn.is_established() && pending.is_empty() {
                break;
            }
        }
        assert!(conn.is_established());
        (conn, synack.unwrap())
    }

    /// The reply to a request is lost on its way to the client. Nothing
    /// else comes from the client, which has had its request acknowledged
    /// and just waits; the NAT's timer resends the reply.
    #[test]
    fn a_lost_reply_is_retransmitted() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = Arc::new(UPnPHelper::new(UPnPConfig::default()));
        nat.add_local_helper(h.clone());
        let to_client = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let tc = to_client.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            tc.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let (client, inside_ip) = (Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 1));
        let (mut conn, _) = establish(&h, &nat, &to_client, (client, 30001));
        let (_, segs) = conn.write(format!("GET {ROOT_DESC_PATH} HTTP/1.1\r\n\r\n").as_bytes());
        for seg in segs {
            let ip = wrap_tcp_v4(client, inside_ip, &seg);
            h.handle_local(&nat, crate::Packet::from_slice(&ip));
        }
        let lost = std::mem::take(&mut *to_client.lock().unwrap());
        assert!(!lost.is_empty(), "a reply went out, and was lost");
        assert!(nat.next_deadline().is_some(), "its retransmission is timed");

        let mut reply = Vec::new();
        let start = Instant::now();
        while !reply.windows(4).any(|w| w == b"\r\n\r\n") {
            assert!(start.elapsed() < Duration::from_secs(30), "never resent");
            let due = nat.next_deadline().expect("a timer while unacknowledged");
            std::thread::sleep(due.saturating_duration_since(Instant::now()));
            nat.tick();
            for pkt in std::mem::take(&mut *to_client.lock().unwrap()) {
                let seg = Segment::parse(&pkt[20..]).unwrap();
                for ack in conn.handle_segment(&seg) {
                    let ip = wrap_tcp_v4(client, inside_ip, &ack);
                    h.handle_local(&nat, crate::Packet::from_slice(&ip));
                }
            }
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf);
            reply.extend_from_slice(&buf[..n]);
        }
        assert!(reply.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[test]
    fn control_connections_hold_little_and_parse_as_they_go() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let to_client = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let tc = to_client.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            tc.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let (client, inside_ip) = (Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 1));
        let (mut conn, synack) = establish(&h, &nat, &to_client, (client, 30000));
        // The window offered is about what a request may be, not the 1 MiB
        // the engine defaults to.
        let scale = crate::vtcp::get_wscale(&synack.options).unwrap_or(0);
        assert!(
            65535usize << scale <= 2 * MAX_REQUEST_BYTES,
            "scale {scale}"
        );

        // Just short of the request cap, a few bytes a segment, with no end
        // to the header block. Each segment used to rescan all that came
        // before. The bound is loose enough for a slow debug build on a
        // loaded machine; segments this small make the rescans take it
        // well past it.
        let (_, segs) = conn.write(b"G");
        let first = Segment::parse(&segs[0]).unwrap();
        let mut seq = first.seq;
        let chunk = 4;
        let start = std::time::Instant::now();
        for _ in 0..(MAX_REQUEST_BYTES - 100) / chunk {
            let mut s = first.clone();
            s.seq = seq;
            s.payload = vec![b'a'; chunk];
            seq = seq.wrapping_add(chunk as u32);
            let ip = wrap_tcp_v4(client, inside_ip, &s.marshal());
            h.handle_local(&nat, crate::Packet::from_slice(&ip));
        }
        let took = start.elapsed();
        assert!(took < Duration::from_secs(2), "{took:?}");
        let ctrl = h.ctrl.lock().unwrap();
        let cc = ctrl.values().next().unwrap();
        assert!(cc.req.len() > MAX_REQUEST_BYTES - 200);
        assert!(!cc.responded);
    }

    fn del_body(ext: u16, proto: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>{}</NewProtocol>\
</u:DeletePortMapping></s:Body></s:Envelope>",
            ext, proto
        )
        .into_bytes()
    }

    #[test]
    fn upnp_cannot_delete_a_static_forward() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let server = Ipv4Addr::new(10, 0, 0, 42);
        nat.add_port_forward(PortForward::new(PROTO_TCP, 443, server, 443))
            .unwrap();
        for client in [Some(server), Some(Ipv4Addr::new(10, 0, 0, 66)), None] {
            let res = h.handle_soap(&nat, "DeletePortMapping", &del_body(443, "TCP"), client);
            assert_eq!(res.status, 500, "body: {}", res.body);
            assert!(res.body.contains("606"), "body: {}", res.body);
        }
        assert_eq!(nat.list_port_forwards().len(), 1);

        // Nor take one over by re-adding it with a lease.
        let res = h.handle_soap(
            &nat,
            "AddPortMapping",
            &add_body(443, 443, "10.0.0.42", "TCP", 60),
            Some(server),
        );
        assert_eq!(res.status, 500, "body: {}", res.body);
        assert!(nat.list_port_forwards()[0].expires.is_none());
    }

    #[test]
    fn upnp_clients_only_delete_their_own_mappings() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let owner = Ipv4Addr::new(10, 0, 0, 42);
        let res = h.handle_soap(
            &nat,
            "AddPortMapping",
            &add_body(9000, 9000, "10.0.0.42", "UDP", 0),
            Some(owner),
        );
        assert_eq!(res.status, 200);

        let other = Some(Ipv4Addr::new(10, 0, 0, 66));
        let res = h.handle_soap(&nat, "DeletePortMapping", &del_body(9000, "UDP"), other);
        assert!(res.body.contains("606"), "body: {}", res.body);
        assert_eq!(nat.list_port_forwards().len(), 1);

        let res = h.handle_soap(
            &nat,
            "DeletePortMapping",
            &del_body(9000, "UDP"),
            Some(owner),
        );
        assert_eq!(res.status, 200, "body: {}", res.body);
        assert!(nat.list_port_forwards().is_empty());
    }

    fn msearch(src: Ipv4Addr) -> Vec<u8> {
        let payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n\r\n";
        build_udp_packet(src, 40000, SSDP_MCAST, SSDP_PORT, payload)
    }

    fn wired() -> (
        Arc<Nat>,
        Arc<StdMutex<Vec<Vec<u8>>>>,
        Arc<StdMutex<Vec<Vec<u8>>>>,
    ) {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_local_helper(Arc::new(UPnPHelper::new(UPnPConfig::default())));
        let inside = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let outside = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let i = inside.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            i.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let o = outside.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            o.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        (nat, inside, outside)
    }

    #[test]
    fn inside_msearch_is_answered_through_the_nat() {
        let (nat, inside, outside) = wired();
        let client = Ipv4Addr::new(10, 0, 0, 50);
        nat.inside()
            .send(crate::Packet::from_slice(&msearch(client)))
            .unwrap();
        let got = inside.lock().unwrap();
        assert_eq!(got.len(), 1, "expected an SSDP reply");
        assert_eq!(&got[0][16..20], &client.octets());
        assert!(
            outside.lock().unwrap().is_empty(),
            "multicast leaked outside"
        );
    }

    #[test]
    fn outside_msearch_is_ignored() {
        let (nat, inside, _outside) = wired();
        // Spoofed to make the NAT fire a reply at an inside host.
        nat.outside()
            .send(crate::Packet::from_slice(&msearch(Ipv4Addr::new(
                10, 0, 0, 50,
            ))))
            .unwrap();
        assert!(inside.lock().unwrap().is_empty());
    }

    #[test]
    fn a_lease_renewal_is_not_refused_by_the_caps() {
        let client = Ipv4Addr::new(10, 0, 0, 42);
        for cfg in [
            UPnPConfig::default().max_per_client(1),
            UPnPConfig::default().max_mappings(1),
        ] {
            let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
            let h = UPnPHelper::new(cfg);
            let add = |ext, lease| {
                h.handle_soap(
                    &nat,
                    "AddPortMapping",
                    &add_body(ext, 80, "10.0.0.42", "TCP", lease),
                    Some(client),
                )
            };
            assert_eq!(add(8080, 60).status, 200);
            let r = add(8080, 3600);
            assert_eq!(r.status, 200, "renewal refused: {}", r.body);
            let lease = nat.list_port_forwards()[0].expires.unwrap();
            assert!(lease > Instant::now() + Duration::from_secs(60));
            // A second mapping is still over the cap.
            assert!(add(8081, 60).body.contains("728"));
        }
    }

    #[test]
    fn a_static_forward_added_over_a_upnp_one_is_not_upnps() {
        let owner = Ipv4Addr::new(10, 0, 0, 42);
        // Re-added over the live UPnP mapping, or after it was removed.
        for remove_first in [false, true] {
            let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
            let h = UPnPHelper::new(UPnPConfig::default());
            let res = h.handle_soap(
                &nat,
                "AddPortMapping",
                &add_body(9000, 9000, "10.0.0.42", "UDP", 3600),
                Some(owner),
            );
            assert_eq!(res.status, 200);
            if remove_first {
                nat.remove_port_forward(PROTO_UDP, 9000);
            }
            nat.add_port_forward(PortForward::new(PROTO_UDP, 9000, owner, 9000))
                .unwrap();

            let res = h.handle_soap(
                &nat,
                "DeletePortMapping",
                &del_body(9000, "UDP"),
                Some(owner),
            );
            assert!(res.body.contains("606"), "body: {}", res.body);
            assert_eq!(nat.list_port_forwards().len(), 1);
            assert!(nat.list_port_forwards()[0].expires.is_none());
        }
    }

    #[test]
    fn a_renewed_upnp_mapping_stays_its_clients() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let owner = Some(Ipv4Addr::new(10, 0, 0, 42));
        for _ in 0..2 {
            let body = add_body(9000, 9000, "10.0.0.42", "UDP", 3600);
            assert_eq!(
                h.handle_soap(&nat, "AddPortMapping", &body, owner).status,
                200
            );
        }
        let res = h.handle_soap(&nat, "DeletePortMapping", &del_body(9000, "UDP"), owner);
        assert_eq!(res.status, 200, "body: {}", res.body);
        assert!(nat.list_port_forwards().is_empty());
    }

    #[test]
    fn defaults_bound_what_one_client_can_take() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let add = |ext: u16, client: &str, lease| {
            h.handle_soap(
                &nat,
                "AddPortMapping",
                &add_body(ext, ext, client, "UDP", lease),
                Some(client.parse().unwrap()),
            )
        };

        // A "permanent" request gets the longest lease instead.
        assert_eq!(add(20000, "10.0.0.42", 0).status, 200);
        let pf = nat.list_port_forwards().pop().unwrap();
        let left = pf.expires.expect("lease must be finite");
        assert!(left <= Instant::now() + Duration::from_secs(7 * 86400));
        assert!(left > Instant::now() + Duration::from_secs(6 * 86400));

        // Privileged ports stay out of reach.
        assert_eq!(add(80, "10.0.0.42", 60).status, 500);

        // One host gets its share of the pool, and no more.
        let mut ok = 1;
        for ext in 20001..20300 {
            if add(ext, "10.0.0.42", 60).status == 200 {
                ok += 1;
            }
        }
        assert_eq!(ok, 128);
        assert_eq!(add(30000, "10.0.0.43", 60).status, 200);
    }

    #[test]
    fn mappings_keep_short_descriptions_and_list_cheaply() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let long = "é".repeat(30_000);
        let mut n = 0;
        for i in 0..1024u16 {
            let client = format!("10.0.0.{}", 2 + i / 128);
            let body = String::from_utf8(add_body(20000 + i, 1000 + i, &client, "TCP", 0))
                .unwrap()
                .replace("test map", &long);
            let r = h.handle_soap(
                &nat,
                "AddPortMapping",
                body.as_bytes(),
                Some(client.parse().unwrap()),
            );
            n += usize::from(r.status == 200);
        }
        assert_eq!(n, 1024);
        let fwds = nat.list_port_forwards();
        assert!(fwds.iter().all(|pf| pf.description.len() <= 64));
        assert_eq!(fwds[0].description, "é".repeat(32));

        // Walking the table by index copies one entry per request. Each
        // used to copy them all, descriptions included. The bound is loose
        // enough for a slow debug build on a loaded machine; walking the
        // table four times, copying it all would take it well past it.
        let start = std::time::Instant::now();
        let mut ports = HashSet::new();
        for i in (0..1024).cycle().take(4 * 1024) {
            let q = format!("<NewPortMappingIndex>{i}</NewPortMappingIndex>");
            let r = h.handle_soap(&nat, "GetGenericPortMappingEntry", q.as_bytes(), None);
            assert_eq!(r.status, 200);
            ports.insert(xml_field(&r.body, "NewExternalPort").unwrap());
        }
        let took = start.elapsed();
        assert!(took < Duration::from_secs(2), "{took:?}");
        assert_eq!(ports.len(), 1024, "each index names another entry");
        let q = b"<NewPortMappingIndex>1024</NewPortMappingIndex>";
        let r = h.handle_soap(&nat, "GetGenericPortMappingEntry", q, None);
        assert_eq!(r.status, 500);
        let q = b"<NewPortMappingIndex>-1</NewPortMappingIndex>";
        let r = h.handle_soap(&nat, "GetGenericPortMappingEntry", q, None);
        assert_eq!(r.status, 500);
    }

    #[test]
    fn caps_count_only_live_mappings() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default().max_per_client(2).max_mappings(3));
        let add = |ext: u16, client: &str| {
            h.handle_soap(
                &nat,
                "AddPortMapping",
                &add_body(ext, ext, client, "TCP", 60),
                Some(client.parse().unwrap()),
            )
            .status
        };
        assert_eq!(add(20000, "10.0.0.42"), 200);
        assert_eq!(add(20001, "10.0.0.42"), 200);
        assert_eq!(add(20002, "10.0.0.42"), 500);
        // Removed behind UPnP's back: no longer counts.
        nat.remove_port_forward(PROTO_TCP, 20000);
        assert_eq!(add(20002, "10.0.0.42"), 200);
        assert_eq!(add(20003, "10.0.0.43"), 200);
        assert_eq!(add(20004, "10.0.0.44"), 500);
        nat.remove_port_forward(PROTO_TCP, 20003);
        assert_eq!(add(20004, "10.0.0.44"), 200);
    }

    #[test]
    fn one_client_cannot_take_every_control_connection() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let inside_ip = Ipv4Addr::new(10, 0, 0, 1);
        let syn = |client_ip: Ipv4Addr, port: u16| {
            let mut c = crate::vtcp::Conn::new(crate::vtcp::ConnConfig {
                local_addr: Some(SocketAddr::new(IpAddr::V4(client_ip), port)),
                remote_addr: Some(SocketAddr::new(IpAddr::V4(inside_ip), 5000)),
                local_port: port,
                remote_port: 5000,
                ..Default::default()
            });
            wrap_tcp_v4(client_ip, inside_ip, &c.connect()[0])
        };
        let greedy = Ipv4Addr::new(10, 0, 0, 66);
        for port in 0..MAX_CTRL_CONNS as u16 {
            h.handle_local(&nat, crate::Packet::from_slice(&syn(greedy, 40000 + port)));
        }
        let held = h.ctrl.lock().unwrap().len();
        assert!(held < MAX_CTRL_CONNS, "one client holds all {held}");

        let polite = Ipv4Addr::new(10, 0, 0, 42);
        h.handle_local(&nat, crate::Packet::from_slice(&syn(polite, 50000)));
        assert!(h.ctrl.lock().unwrap().keys().any(|k| k.client_ip == polite));
    }

    /// One HTTP exchange over a fresh TCP connection from `client` to
    /// `server:port` through the NAT's inside interface, as a UPnP control
    /// point makes it. Returns the response bytes.
    fn http_through_nat(
        nat: &Nat,
        inside: &StdMutex<Vec<Vec<u8>>>,
        (client, cport): (Ipv4Addr, u16),
        (server, port): (Ipv4Addr, u16),
        request: &[u8],
    ) -> Vec<u8> {
        use crate::vtcp::{Conn, ConnConfig};
        let mut conn = Conn::new(ConnConfig {
            local_addr: Some(SocketAddr::new(IpAddr::V4(client), cport)),
            remote_addr: Some(SocketAddr::new(IpAddr::V4(server), port)),
            local_port: cport,
            remote_port: port,
            ..Default::default()
        });
        let mut pending = conn.connect();
        let mut sent = false;
        let mut got = Vec::new();
        for _ in 0..64 {
            for seg in pending.drain(..) {
                let ip = wrap_tcp_v4(client, server, &seg);
                nat.inside().send(crate::Packet::from_slice(&ip)).unwrap();
            }
            for pkt in std::mem::take(&mut *inside.lock().unwrap()) {
                let ihl = (pkt[0] & 0x0F) as usize * 4;
                let seg = Segment::parse(&pkt[ihl..]).unwrap();
                pending.extend(conn.handle_segment(&seg));
            }
            let mut buf = [0u8; 4096];
            loop {
                let n = conn.read(&mut buf);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            if conn.is_established() && !sent {
                let (n, segs) = conn.write(request);
                assert_eq!(n, request.len());
                pending.extend(segs);
                sent = true;
            }
            if sent && pending.is_empty() && inside.lock().unwrap().is_empty() {
                break;
            }
        }
        got
    }

    fn header<'a>(msg: &'a str, name: &str) -> Option<&'a str> {
        msg.split("\r\n").find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    fn body(resp: &[u8]) -> String {
        let at = find_subslice(resp, b"\r\n\r\n").unwrap() + 4;
        String::from_utf8_lossy(&resp[at..]).into_owned()
    }

    /// Split `http://host:port/path` into its parts.
    fn split_url(url: &str) -> (Ipv4Addr, u16, String) {
        let rest = url.strip_prefix("http://").unwrap();
        let (auth, path) = rest.split_at(rest.find('/').unwrap());
        let (host, port) = auth.split_once(':').unwrap();
        (
            host.parse().unwrap(),
            port.parse().unwrap(),
            path.to_string(),
        )
    }

    /// What a client such as miniupnpc does: discover the gateway over SSDP,
    /// fetch the description at its LOCATION, find the WANIPConnection
    /// control URL there, and POST AddPortMapping to it.
    #[test]
    fn a_standard_client_walks_discovery_to_control() {
        let (nat, inside, _outside) = wired();
        let client = Ipv4Addr::new(10, 0, 0, 50);

        nat.inside()
            .send(crate::Packet::from_slice(&msearch(client)))
            .unwrap();
        let reply = inside.lock().unwrap().pop().expect("SSDP reply");
        let reply = String::from_utf8_lossy(&reply[28..]).into_owned();
        let (host, port, path) = split_url(header(&reply, "LOCATION").unwrap());

        let get = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
        let resp = http_through_nat(&nat, &inside, (client, 40001), (host, port), get.as_bytes());
        assert!(
            resp.starts_with(b"HTTP/1.1 200 "),
            "{}",
            String::from_utf8_lossy(&resp)
        );
        let desc = body(&resp);
        let service = desc
            .split("<service>")
            .find(|s| s.contains("urn:schemas-upnp-org:service:WANIPConnection:1"))
            .expect("WANIPConnection service");
        let control = xml_field(service, "controlURL").unwrap();
        let scpd = xml_field(service, "SCPDURL").unwrap();

        let get = format!("GET {scpd} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
        let resp = http_through_nat(&nat, &inside, (client, 40002), (host, port), get.as_bytes());
        assert!(resp.starts_with(b"HTTP/1.1 200 "));
        assert!(body(&resp).contains("<name>AddPortMapping</name>"));

        let (chost, cport, cpath) = split_url(&control);
        let soap = add_body(8080, 80, "10.0.0.50", "TCP", 3600);
        let mut post = format!(
            "POST {cpath} HTTP/1.1\r\nHost: {chost}:{cport}\r\n\
Content-Type: text/xml; charset=\"utf-8\"\r\n\
SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\
Content-Length: {}\r\n\r\n",
            soap.len()
        )
        .into_bytes();
        post.extend_from_slice(&soap);
        let resp = http_through_nat(&nat, &inside, (client, 40003), (chost, cport), &post);
        assert!(
            resp.starts_with(b"HTTP/1.1 200 "),
            "{}",
            String::from_utf8_lossy(&resp)
        );
        assert!(body(&resp).contains("AddPortMappingResponse"));
        let fwds = nat.list_port_forwards();
        assert_eq!(fwds.len(), 1);
        assert_eq!((fwds[0].outside_port, fwds[0].inside_ip), (8080, client));
    }

    #[test]
    fn only_a_post_to_the_control_url_is_soap() {
        let (nat, inside, _outside) = wired();
        let client = Ipv4Addr::new(10, 0, 0, 50);
        let server = (Ipv4Addr::new(10, 0, 0, 1), 5000);
        let soap = add_body(8080, 80, "10.0.0.50", "TCP", 3600);
        let request = |line: &str| {
            let mut r = format!(
                "{line} HTTP/1.1\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\
Content-Length: {}\r\n\r\n",
                soap.len()
            )
            .into_bytes();
            r.extend_from_slice(&soap);
            r
        };
        for (i, (line, status)) in [
            ("POST /rootDesc.xml", "405"),
            ("GET /ctl/WANIPConnection", "405"),
            ("POST /elsewhere", "404"),
            ("GET /", "404"),
        ]
        .into_iter()
        .enumerate()
        {
            let resp = http_through_nat(
                &nat,
                &inside,
                (client, 41000 + i as u16),
                server,
                &request(line),
            );
            let resp = String::from_utf8_lossy(&resp);
            assert!(
                resp.starts_with(&format!("HTTP/1.1 {status} ")),
                "{line}: {resp}"
            );
        }
        assert!(nat.list_port_forwards().is_empty());

        // The absolute form of the control URL is the control URL.
        let resp = http_through_nat(
            &nat,
            &inside,
            (client, 42000),
            server,
            &request("POST http://10.0.0.1:5000/ctl/WANIPConnection"),
        );
        assert!(resp.starts_with(b"HTTP/1.1 200 "));
        assert_eq!(nat.list_port_forwards().len(), 1);
    }

    #[test]
    fn a_tenant_cannot_take_every_upnp_mapping() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let mut ok = 0;
        for host in 2..=10u8 {
            let ip = format!("10.0.0.{host}");
            for i in 0..128u16 {
                let ext = 20000 + u16::from(host) * 200 + i;
                let body = add_body(ext, ext, &ip, "UDP", 3600);
                if h.soap(&nat, 1, "AddPortMapping", &body, Some(ip.parse().unwrap()))
                    .status
                    == 200
                {
                    ok += 1;
                }
            }
        }
        assert_eq!(ok, 256);
        let body = add_body(30001, 23, "10.0.0.50", "TCP", 3600);
        let r = h.soap(
            &nat,
            2,
            "AddPortMapping",
            &body,
            Some("10.0.0.50".parse().unwrap()),
        );
        assert_eq!(r.status, 200, "another tenant is still served");
    }

    #[test]
    fn tenants_see_only_their_own_mappings() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = UPnPHelper::new(UPnPConfig::default());
        let victim = Some("10.0.0.50".parse().unwrap());
        let body = add_body(30000, 22, "10.0.0.50", "TCP", 3600);
        assert_eq!(h.soap(&nat, 2, "AddPortMapping", &body, victim).status, 200);
        let generic = |ns, i: usize| {
            let body = format!("<NewPortMappingIndex>{i}</NewPortMappingIndex>");
            h.soap(
                &nat,
                ns,
                "GetGenericPortMappingEntry",
                body.as_bytes(),
                None,
            )
            .status
        };
        let specific = |ns| {
            let body = b"<NewExternalPort>30000</NewExternalPort><NewProtocol>TCP</NewProtocol>";
            h.soap(&nat, ns, "GetSpecificPortMappingEntry", body, None)
                .status
        };
        assert_eq!((generic(2, 0), specific(2)), (200, 200));
        assert_ne!(generic(1, 0), 200);
        assert_ne!(specific(1), 200);
        assert_ne!(generic(0, 0), 200);
    }

    #[test]
    fn spoofed_sources_get_no_upnp_service() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_local_helper(Arc::new(UPnPHelper::new(UPnPConfig::default())));
        let injected = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let i = injected.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            i.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        for src in [Ipv4Addr::new(192, 168, 9, 9), Ipv4Addr::new(10, 0, 0, 1)] {
            let pkt = build_udp_packet(src, 40000, SSDP_MCAST, SSDP_PORT, payload);
            nat.inside().send(crate::Packet::from_slice(&pkt)).unwrap();
        }
        assert!(injected.lock().unwrap().is_empty());
        let pkt = build_udp_packet(
            Ipv4Addr::new(10, 0, 0, 50),
            40000,
            SSDP_MCAST,
            SSDP_PORT,
            payload,
        );
        nat.inside().send(crate::Packet::from_slice(&pkt)).unwrap();
        assert_eq!(injected.lock().unwrap().len(), 1);
    }
}

//! UPnP IGD (Internet Gateway Device) helper.
//!
//! Implements the inside-facing control surface a UPnP client uses to open
//! port forwards on the NAT:
//!
//! - **SSDP discovery** (`M-SEARCH` over UDP multicast to
//!   `239.255.255.250:1900`) is handled entirely at the L3 packet level: the
//!   responder builds a raw IPv4+UDP reply and injects it back onto the inside
//!   via [`Nat::send_inside`]. No OS sockets, std-only.
//! - **SOAP control** (`AddPortMapping`, `DeletePortMapping`,
//!   `GetExternalIPAddress`, and the port-mapping query actions) is implemented
//!   as a pure request handler ([`UPnPHelper::handle_soap`]) that parses a SOAP
//!   body and returns the response/fault body plus any NAT mutation. It is
//!   driven by the unit tests directly.
//!
//! TODO(nat): wire the SOAP handler to live TCP control traffic. The Go
//! upstream terminates a TCP connection on the control port using a virtual TCP
//! stack (`vclient`) and runs `net/http` over it. The crate's `vclient` is
//! still a scaffold (no inbound `Listen`), and the NAT core does not terminate
//! TCP, so `handle_local`'s TCP branch currently only recognises traffic to the
//! control port without driving a full HTTP/1.1 + TCP handshake. Once a virtual
//! TCP server is available, decode the HTTP request there and call
//! [`UPnPHelper::handle_soap`].

use crate::nat::helper::{Helper, LocalHelper, PortForward, PROTO_TCP, PROTO_UDP};
use crate::nat::nat::Nat;
use crate::{checksum, Packet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const SSDP_PORT: u16 = 1900;
const SSDP_MCAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// Configuration knobs for the UPnP IGD helper.
#[derive(Debug, Clone)]
pub struct UPnPConfig {
    /// TCP port for the SOAP control server (default 5000).
    pub control_port: u16,
    /// Allowed outside port ranges `(low, high)` inclusive. Empty = allow all.
    pub allowed_ports: Vec<(u16, u16)>,
    /// Maximum total port forwards (0 = unlimited).
    pub max_mappings: usize,
    /// Maximum port forwards per inside IP (0 = unlimited).
    pub max_per_client: usize,
    /// Maximum lease duration (`None` = permanent allowed).
    pub lease_duration: Option<Duration>,
}

impl Default for UPnPConfig {
    fn default() -> Self {
        UPnPConfig {
            control_port: 5000,
            allowed_ports: Vec::new(),
            max_mappings: 0,
            max_per_client: 0,
            lease_duration: None,
        }
    }
}

/// Outcome of a SOAP action: an HTTP-ish status code and an XML body. A code of
/// 200 is a success response; anything else is a SOAP fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapResult {
    pub status: u16,
    pub body: String,
}

/// UPnP IGD helper. Register via
/// [`Nat::add_local_helper`](crate::nat::Nat::add_local_helper).
#[derive(Debug)]
pub struct UPnPHelper {
    cfg: UPnPConfig,
}

impl UPnPHelper {
    pub fn new(cfg: UPnPConfig) -> UPnPHelper {
        let mut cfg = cfg;
        if cfg.control_port == 0 {
            cfg.control_port = 5000;
        }
        UPnPHelper { cfg }
    }

    pub fn config(&self) -> &UPnPConfig {
        &self.cfg
    }

    // ---- SSDP ----------------------------------------------------------

    /// Handle a UDP packet, returning true if it was an SSDP M-SEARCH that we
    /// answered.
    fn handle_udp(&self, nat: &Nat, pkt: &[u8], ihl: usize) -> bool {
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
        self.send_ssdp_response(nat, src_ip, src_port);
        true
    }

    /// Build and inject an SSDP 200 OK reply onto the inside network.
    fn send_ssdp_response(&self, nat: &Nat, dst_ip: Ipv4Addr, dst_port: u16) {
        let inside_ip = match nat.inside_addr() {
            Some(a) => a,
            None => return,
        };
        let location = format!(
            "http://{}:{}/rootDesc.xml",
            inside_ip, self.cfg.control_port
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
        nat.send_inside(Packet::from_slice(&pkt));
    }

    // ---- SOAP ----------------------------------------------------------

    /// The device description document a client fetches from `LOCATION`.
    pub fn root_desc(&self, inside_ip: Ipv4Addr) -> String {
        let control_url = format!(
            "http://{}:{}/ctl/WANIPConnection",
            inside_ip, self.cfg.control_port
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
<SCPDURL>/WANIPConnection.xml</SCPDURL>\
</service></serviceList>\
</device></deviceList>\
</device></deviceList>\
</device></root>",
            control_url
        )
    }

    /// Dispatch a SOAP control action. `soap_action` is the value of the
    /// `SOAPAction` HTTP header (quotes and the leading service URN are
    /// tolerated). `body` is the raw XML request body. `client_ip` is the
    /// requesting host (the inside client), used to enforce that a client only
    /// forwards to itself.
    pub fn handle_soap(
        &self,
        nat: &Nat,
        soap_action: &str,
        body: &[u8],
        client_ip: Option<Ipv4Addr>,
    ) -> SoapResult {
        let action = normalize_action(soap_action);
        match action.as_str() {
            "GetExternalIPAddress" => self.action_get_external_ip(nat),
            "AddPortMapping" => self.action_add_port_mapping(nat, body, client_ip),
            "DeletePortMapping" => self.action_delete_port_mapping(nat, body),
            "GetGenericPortMappingEntry" => self.action_get_generic(nat, body),
            "GetSpecificPortMappingEntry" => self.action_get_specific(nat, body),
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
        if let Some(cip) = client_ip {
            if cip != inside_ip {
                return soap_fault(718, "Internal client must be the requesting host");
            }
        }
        if !self.is_port_allowed(ext_port) {
            return soap_fault(718, "External port not in allowed range");
        }
        if self.cfg.max_mappings > 0 && nat.list_port_forwards().len() >= self.cfg.max_mappings {
            return soap_fault(728, "Too many port mappings");
        }
        if self.cfg.max_per_client > 0 {
            let count = nat
                .list_port_forwards()
                .iter()
                .filter(|pf| pf.inside_ip == inside_ip)
                .count();
            if count >= self.cfg.max_per_client {
                return soap_fault(728, "Too many port mappings for this client");
            }
        }

        let lease_secs: u32 = xml_field(&xml, "NewLeaseDuration")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let expires = compute_expiry(lease_secs, self.cfg.lease_duration);

        let desc = xml_field(&xml, "NewPortMappingDescription").unwrap_or_default();
        let pf = PortForward {
            proto,
            outside_port: ext_port,
            inside_ip,
            inside_port: int_port,
            description: desc,
            expires,
        };
        if nat.add_port_forward(pf).is_err() {
            return soap_fault(718, "Port already mapped to another host");
        }
        soap_response(
            "<u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:AddPortMappingResponse>",
        )
    }

    fn action_delete_port_mapping(&self, nat: &Nat, body: &[u8]) -> SoapResult {
        let xml = String::from_utf8_lossy(body);
        let proto = match parse_protocol(&xml_field(&xml, "NewProtocol").unwrap_or_default()) {
            Some(p) => p,
            None => return soap_fault(402, "Invalid protocol"),
        };
        let ext_port: u16 = xml_field(&xml, "NewExternalPort")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let existed = nat
            .list_port_forwards()
            .iter()
            .any(|pf| pf.proto == proto && pf.outside_port == ext_port);
        if !existed {
            return soap_fault(714, "No such port mapping");
        }
        nat.remove_port_forward(proto, ext_port);
        soap_response(
            "<u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:DeletePortMappingResponse>",
        )
    }

    fn action_get_generic(&self, nat: &Nat, body: &[u8]) -> SoapResult {
        let xml = String::from_utf8_lossy(body);
        let idx: i64 = xml_field(&xml, "NewPortMappingIndex")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(-1);
        let forwards = nat.list_port_forwards();
        if idx < 0 || idx as usize >= forwards.len() {
            return soap_fault(713, "SpecifiedArrayIndexInvalid");
        }
        soap_response(&port_mapping_entry_xml(
            &forwards[idx as usize],
            "GetGenericPortMappingEntryResponse",
        ))
    }

    fn action_get_specific(&self, nat: &Nat, body: &[u8]) -> SoapResult {
        let xml = String::from_utf8_lossy(body);
        let proto = match parse_protocol(&xml_field(&xml, "NewProtocol").unwrap_or_default()) {
            Some(p) => p,
            None => return soap_fault(402, "Invalid protocol"),
        };
        let ext_port: u16 = xml_field(&xml, "NewExternalPort")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        for pf in nat.list_port_forwards() {
            if pf.proto == proto && pf.outside_port == ext_port {
                return soap_response(&port_mapping_entry_xml(
                    &pf,
                    "GetSpecificPortMappingEntryResponse",
                ));
            }
        }
        soap_fault(714, "NoSuchEntryInArray")
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
        let bytes = pkt.as_bytes();
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return false;
        }
        let ihl = (bytes[0] & 0x0F) as usize * 4;
        match bytes[9] {
            PROTO_UDP => self.handle_udp(nat, bytes, ihl),
            PROTO_TCP => {
                // TODO(nat): terminate TCP to the control port and run the SOAP
                // handler over it. Needs a virtual TCP server (vclient.Listen),
                // which is not yet available. We do not consume the packet so
                // normal NAT processing continues.
                false
            }
            _ => false,
        }
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
        if let Some(m) = max {
            if dur > m {
                dur = m;
            }
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

        // Build an M-SEARCH from inside client to 239.255.255.250:1900.
        // (The NAT's outbound dispatch only routes packets addressed to the
        // inside IP into handle_local — matching the Go upstream — so we invoke
        // the helper directly to exercise the SSDP responder.)
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
}

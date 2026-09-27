//! Userspace NAT/routing stack.
//!
//! [`Stack`] implements [`L3Device`] (virtual IP packets are accepted by
//! `send`) and [`L3Connector`] (peer devices can be attached with their own
//! per-namespace connection-tracking table).
//!
//! Outbound flow:
//!
//! - IPv4 ICMP echo to our address → reply.
//! - IPv4 TCP SYN → dial real `TcpStream`, terminate the virtual side with a
//!   server-side `vtcp::Conn` (`tcp_out::TcpOutConn`), and bridge bytes.
//! - IPv4 TCP non-SYN to nothing → send RST per RFC 9293.
//! - IPv4 UDP → dial real `UdpSocket`, ship payload through, return responses.
//! - Symmetric handling for IPv6.
//!
//! Inbound to a virtual listener (ports claimed via [`Stack::listen`]) is also
//! served by the `vtcp` engine: an inbound SYN passive-opens a server-side
//! `vtcp::Conn` and surfaces a [`TcpStream`](super::TcpStream) on ESTABLISHED.

use crate::accept::{Cleanup, L3Connector};
use crate::iface::{L3Device, L3Handler};
use crate::packet::Packet;
use crate::slirp::defrag::{Reassembler, ipv6_fragment_header};
use crate::slirp::icmpv4::build_icmpv4_echo_reply;
use crate::slirp::icmpv6::build_icmpv6_echo_reply;
use crate::slirp::ipv6::skip_extension_headers;
use crate::slirp::listener::{Listener, ListenerKey, resolve_v4};
use crate::slirp::listener6::{Listener6, ListenerKey6, resolve_v6};
use crate::slirp::tcp_out::{TcpOutConn, build_rst_for_stray};
use crate::slirp::tcp_stream::{ConnState, Endpoints, tick_conn};
use crate::slirp::udp::{SendFn as UdpSendFn, UdpConn};
use crate::slirp::udp6::{SendFn as UdpSendFn6, UdpConn6};
use crate::vtcp::segment::{Segment, flags as tcp_flags};
use crate::vtcp::{Conn, ConnConfig};
use crate::{IpPrefix, Result, connect_l3};

use crate::time::Instant;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread;
use std::time::Duration;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
struct Key {
    ns: u64,
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
struct Key6 {
    ns: u64,
    src_ip: [u8; 16],
    src_port: u16,
    dst_ip: [u8; 16],
    dst_port: u16,
}

/// Cap on simultaneous virtual-side TCP connections; mirrors the Go
/// constant of the same name.
const MAX_VIRT_TCP_CONNS: usize = 10_000;

/// Cap on outbound TCP bridges per address family. Each holds a real socket
/// and two pump threads, and any guest can open them, so this bounds the
/// threads a guest can make the host create (with [`MAX_UDP_FLOWS`], about
/// 12k in all).
const MAX_OUTBOUND_TCP: usize = 2048;

/// Cap on outbound TCP dials in flight at once. A dial to a destination that
/// drops SYNs holds a thread for up to the connect timeout; SYNs past the cap
/// are dropped, and the client's retransmissions try again later.
const MAX_PENDING_DIALS: usize = 256;

/// Cap on UDP flows per address family. Each one holds a real socket and a
/// reader thread, and any new 4-tuple from the virtual network opens one.
/// Small under test so the cap itself can be exercised.
const MAX_UDP_FLOWS: usize = if cfg!(test) { 8 } else { 2048 };

/// Time a UDP flow may sit idle before its socket is reaped.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// State shared between Stack and its background maintenance thread.
struct Inner {
    addr: RwLock<IpPrefix>,
    handler: Mutex<Option<L3Handler>>,
    // Per-protocol connection tables. Outbound TCP terminates the virtual side
    // with a server-side vtcp::Conn and bridges to a real socket (`TcpOutConn`).
    tcp: Mutex<HashMap<Key, Arc<TcpOutConn>>>,
    tcp6: Mutex<HashMap<Key6, Arc<TcpOutConn>>>,
    udp: Mutex<HashMap<Key, Arc<UdpConn>>>,
    udp6: Mutex<HashMap<Key6, Arc<UdpConn6>>>,
    // Inbound virtual TCP connections accepted by a Listener (vtcp-backed).
    virt_tcp: Mutex<HashMap<Key, Arc<ConnState>>>,
    virt_tcp6: Mutex<HashMap<Key6, Arc<ConnState>>>,
    // Held weakly: the application owns its listeners, and dropping the last
    // handle closes one and frees its address.
    listeners: Mutex<HashMap<ListenerKey, Weak<Listener>>>,
    listeners6: Mutex<HashMap<ListenerKey6, Weak<Listener6>>>,
    // Per-namespace sides (each device attached via ConnectL3).
    ns_sides: Mutex<HashMap<u64, Arc<NsSide>>>,
    ns_counter: AtomicU64,
    /// Outbound dials still waiting on the real destination; each holds a
    /// thread, so they are capped separately from established flows.
    pending_dials: Arc<AtomicUsize>,
    /// Fragments from the virtual network awaiting the rest of their datagram.
    defrag: Mutex<Reassembler>,
    closed: AtomicBool,
}

/// A namespace-isolated [`L3Device`] handed out by [`Stack::connect_l3`].
///
/// Packets sent to the device are dispatched through the parent [`Stack`]
/// with the namespace tag set, so multiple devices may use overlapping
/// virtual addresses without colliding in the connection table.
pub struct NsSide {
    stack: Arc<Inner>,
    ns: u64,
    handler: Mutex<Option<L3Handler>>,
    addr: RwLock<IpPrefix>,
}

impl core::fmt::Debug for NsSide {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NsSide")
            .field("ns", &self.ns)
            .field("addr", &*self.addr.read().unwrap())
            .finish()
    }
}

impl L3Device for NsSide {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().expect("poisoned") = Some(h);
    }

    fn send(&self, p: &Packet) -> Result<()> {
        Stack::handle_packet(&self.stack, self.ns, p.as_bytes())
    }

    fn addr(&self) -> IpPrefix {
        *self.addr.read().expect("poisoned")
    }

    fn set_addr(&self, prefix: IpPrefix) -> Result<()> {
        *self.addr.write().expect("poisoned") = prefix;
        Ok(())
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// The userspace NAT/routing stack.
///
/// Construct one with [`Stack::new`], optionally [`Stack::set_addr`] its
/// IP prefix, then wire it up either via `connect_l3` (single peer) or via
/// [`L3Connector::connect_l3`] (multi-tenant, each peer in its own
/// namespace).
pub struct Stack {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for Stack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stack")
            .field("addr", &self.addr())
            .field("closed", &self.inner.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl Stack {
    /// Construct a fresh stack and start its maintenance thread.
    pub fn new() -> Arc<Stack> {
        let inner = Arc::new(Inner {
            addr: RwLock::new(IpPrefix::default()),
            handler: Mutex::new(None),
            tcp: Mutex::new(HashMap::new()),
            tcp6: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            udp6: Mutex::new(HashMap::new()),
            virt_tcp: Mutex::new(HashMap::new()),
            virt_tcp6: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            listeners6: Mutex::new(HashMap::new()),
            ns_sides: Mutex::new(HashMap::new()),
            ns_counter: AtomicU64::new(0),
            pending_dials: Arc::new(AtomicUsize::new(0)),
            defrag: Mutex::new(Reassembler::default()),
            closed: AtomicBool::new(false),
        });

        // Maintenance thread: GC idle UDP flows and closed TCP connections.
        let weak = Arc::downgrade(&inner);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(30));
                let inner = match weak.upgrade() {
                    Some(i) => i,
                    None => return,
                };
                if inner.closed.load(Ordering::Acquire) {
                    return;
                }
                let now = Instant::now();
                // TCP: drop closed entries.
                if let Ok(mut t) = inner.tcp.lock() {
                    t.retain(|_, c| !c.is_closed());
                }
                if let Ok(mut t) = inner.tcp6.lock() {
                    t.retain(|_, c| !c.is_closed());
                }
                // UDP: drop entries idle for more than UDP_IDLE.
                if let Ok(mut u) = inner.udp.lock() {
                    u.retain(|_, conn| {
                        let last = conn.last_act.lock().map(|t| *t).unwrap_or(now);
                        !conn.is_closed() && now.duration_since(last) < UDP_IDLE
                    });
                }
                if let Ok(mut u) = inner.udp6.lock() {
                    u.retain(|_, conn| {
                        let last = conn.last_act.lock().map(|t| *t).unwrap_or(now);
                        !conn.is_closed() && now.duration_since(last) < UDP_IDLE
                    });
                }
                drop(inner);
            }
        });

        // Tick thread: drive vtcp timers (RTO / keepalive / TIME-WAIT) for
        // every vtcp-backed connection — both inbound accepts (`virt_tcp*`) and
        // outbound NAT bridges (`tcp*`) — every 100ms, and reap any that have
        // reached CLOSED.
        let weak_tick = Arc::downgrade(&inner);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(100));
                let inner = match weak_tick.upgrade() {
                    Some(i) => i,
                    None => return,
                };
                if inner.closed.load(Ordering::Acquire) {
                    return;
                }
                let conns: Vec<(Key, Arc<ConnState>)> = inner
                    .virt_tcp
                    .lock()
                    .expect("poisoned")
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                let mut dead = Vec::new();
                for (k, cs) in conns {
                    if tick_conn(&cs) {
                        dead.push(k);
                    }
                }
                if !dead.is_empty() {
                    let mut t = inner.virt_tcp.lock().expect("poisoned");
                    for k in dead {
                        t.remove(&k);
                    }
                }
                let conns6: Vec<(Key6, Arc<ConnState>)> = inner
                    .virt_tcp6
                    .lock()
                    .expect("poisoned")
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                let mut dead6 = Vec::new();
                for (k, cs) in conns6 {
                    if tick_conn(&cs) {
                        dead6.push(k);
                    }
                }
                if !dead6.is_empty() {
                    let mut t = inner.virt_tcp6.lock().expect("poisoned");
                    for k in dead6 {
                        t.remove(&k);
                    }
                }

                // Outbound NAT bridges: tick the virtual-side engine; reap when the
                // bridge has fully torn down.
                let out: Vec<(Key, Arc<TcpOutConn>)> = inner
                    .tcp
                    .lock()
                    .expect("poisoned")
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                let mut dead_out = Vec::new();
                for (k, c) in out {
                    tick_conn(c.state());
                    if c.is_closed() {
                        dead_out.push(k);
                    }
                }
                if !dead_out.is_empty() {
                    let mut t = inner.tcp.lock().expect("poisoned");
                    for k in dead_out {
                        t.remove(&k);
                    }
                }
                let out6: Vec<(Key6, Arc<TcpOutConn>)> = inner
                    .tcp6
                    .lock()
                    .expect("poisoned")
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                let mut dead_out6 = Vec::new();
                for (k, c) in out6 {
                    tick_conn(c.state());
                    if c.is_closed() {
                        dead_out6.push(k);
                    }
                }
                if !dead_out6.is_empty() {
                    let mut t = inner.tcp6.lock().expect("poisoned");
                    for k in dead_out6 {
                        t.remove(&k);
                    }
                }
                drop(inner);
            }
        });

        Arc::new(Stack { inner })
    }

    /// Open a virtual listener on the stack. Inbound SYNs destined for the
    /// registered (IP, port) are passive-opened against the in-tree vtcp
    /// engine; [`Listener::accept`] yields a [`TcpStream`](super::TcpStream)
    /// once the handshake completes.
    pub fn listen(&self, network: &str, address: &str) -> Result<Arc<Listener>> {
        match network {
            "tcp" | "tcp4" => {
                let addr = resolve_v4(address)?;
                let listener = Arc::new(Listener::new(addr));
                let key = ListenerKey {
                    ip: addr.ip().octets(),
                    port: addr.port(),
                };
                let mut m = self.inner.listeners.lock().expect("poisoned");
                if m.get(&key).is_some_and(|l| l.strong_count() > 0) {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "address already in use",
                    ));
                }
                let me = Arc::downgrade(&listener);
                m.insert(key, me.clone());
                let stack = Arc::downgrade(&self.inner);
                listener.set_unregister(Box::new(move || {
                    if let Some(inner) = stack.upgrade() {
                        let mut m = inner.listeners.lock().expect("poisoned");
                        // Only this listener's entry: a newer one may own the
                        // address by now.
                        if m.get(&key).is_some_and(|l| l.ptr_eq(&me)) {
                            m.remove(&key);
                        }
                    }
                }));
                Ok(listener)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only tcp/tcp4 supported in slirp::Stack::listen",
            )),
        }
    }

    /// Open a virtual IPv6 listener on the stack.
    pub fn listen6(&self, address: &str) -> Result<Arc<Listener6>> {
        let addr = resolve_v6(address)?;
        let listener = Arc::new(Listener6::new(addr));
        let key = ListenerKey6 {
            ip: addr.ip().octets(),
            port: addr.port(),
        };
        let mut m = self.inner.listeners6.lock().expect("poisoned");
        if m.get(&key).is_some_and(|l| l.strong_count() > 0) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "address already in use",
            ));
        }
        let me = Arc::downgrade(&listener);
        m.insert(key, me.clone());
        let stack = Arc::downgrade(&self.inner);
        listener.set_unregister(Box::new(move || {
            if let Some(inner) = stack.upgrade() {
                let mut m = inner.listeners6.lock().expect("poisoned");
                // Only this listener's entry (see `listen`).
                if m.get(&key).is_some_and(|l| l.ptr_eq(&me)) {
                    m.remove(&key);
                }
            }
        }));
        Ok(listener)
    }

    /// Shut the stack down: close every in-flight connection and stop
    /// the maintenance thread.
    pub fn shutdown(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        Self::close_flows(&self.inner, |_| true);
        // Namespace sides point back at the stack; dropping them here breaks
        // that cycle for peers whose cleanup never runs.
        self.inner.ns_sides.lock().expect("poisoned").clear();
        Ok(())
    }

    /// Route a packet originating from the namespace `ns` to the right handler.
    /// `ns == 0` means the legacy single-peer path.
    fn dispatch(inner: &Arc<Inner>, ns: u64, pkt: &[u8]) -> Result<()> {
        if ns == 0 {
            let h = inner.handler.lock().expect("poisoned").clone();
            if let Some(h) = h {
                return h(Packet::from_slice(pkt));
            }
            return Ok(());
        }
        let side = inner.ns_sides.lock().expect("poisoned").get(&ns).cloned();
        if let Some(side) = side {
            let h = side.handler.lock().expect("poisoned").clone();
            if let Some(h) = h {
                return h(Packet::from_slice(pkt));
            }
        }
        Ok(())
    }

    /// The packet sink handed to a flow, injecting into namespace `ns`.
    ///
    /// It holds the stack weakly: the flows live in the stack's own tables,
    /// so a strong reference would make a cycle that keeps the stack, its
    /// sockets and its threads alive after the last handle is dropped.
    fn sink(inner: &Arc<Inner>, ns: u64) -> Arc<dyn Fn(&[u8]) + Send + Sync> {
        let weak = Arc::downgrade(inner);
        Arc::new(move |p: &[u8]| {
            if let Some(inner) = weak.upgrade() {
                let _ = Self::dispatch(&inner, ns, p);
            }
        })
    }

    /// Process an inbound IP packet from the virtual client. Public-facing
    /// entry point is `<Stack as L3Device>::send`.
    fn handle_packet(inner: &Arc<Inner>, ns: u64, pkt: &[u8]) -> Result<()> {
        if inner.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stack is shut down",
            ));
        }
        if pkt.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }
        match pkt[0] >> 4 {
            4 => Self::handle_ipv4(inner, ns, pkt),
            6 => Self::handle_ipv6(inner, ns, pkt),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported IP version",
            )),
        }
    }

    fn handle_ipv4(inner: &Arc<Inner>, ns: u64, pkt: &[u8]) -> Result<()> {
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < 20 || pkt.len() < ihl {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ihl"));
        }
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total_len < ihl || total_len > pkt.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IPv4 total length",
            ));
        }
        let pkt = &pkt[..total_len];
        // A fragment is not a datagram: past the first one there is no
        // transport header at all, and the first alone is truncated.
        if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3FFF != 0 {
            let whole =
                inner
                    .defrag
                    .lock()
                    .expect("poisoned")
                    .push_v4(Instant::now(), ns, pkt, ihl);
            return match whole {
                Some(p) => Self::handle_ipv4(inner, ns, &p),
                None => Ok(()),
            };
        }
        let proto = pkt[9];
        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&pkt[12..16]);
        dst_ip.copy_from_slice(&pkt[16..20]);
        let src = Ipv4Addr::from(src_ip);
        let dst = Ipv4Addr::from(dst_ip);

        match proto {
            1 => {
                // ICMP.
                let our = inner.addr.read().expect("poisoned").addr();
                if let Some(reply) = build_icmpv4_echo_reply(pkt, src, dst, ihl, Some(our)) {
                    return Self::dispatch(inner, ns, &reply);
                }
                Ok(())
            }
            6 => Self::handle_ipv4_tcp(inner, ns, pkt, src, dst, ihl),
            17 => Self::handle_ipv4_udp(inner, ns, pkt, src_ip, dst_ip, ihl, src, dst),
            _ => Ok(()),
        }
    }

    fn handle_ipv4_tcp(
        inner: &Arc<Inner>,
        ns: u64,
        pkt: &[u8],
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ihl: usize,
    ) -> Result<()> {
        if pkt.len() < ihl + 20 {
            return Ok(());
        }
        let tcp = &pkt[ihl..];
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let flags = tcp[13];

        let key = Key {
            ns,
            src_ip: src.octets(),
            src_port,
            dst_ip: dst.octets(),
            dst_port,
        };

        // 1) Existing inbound virtual TCP connection (vtcp-backed)?
        let virt = inner.virt_tcp.lock().expect("poisoned").get(&key).cloned();
        if let Some(state) = virt {
            if let Ok(seg) = Segment::parse(tcp) {
                state.deliver(&seg);
            }
            if !state.complete_accept() {
                inner.virt_tcp.lock().expect("poisoned").remove(&key);
            }
            return Ok(());
        }

        // 2) SYN destined for a registered virtual listener? Passive-open a
        //    server-side vtcp::Conn and drive the handshake.
        if (flags & tcp_flags::SYN) != 0 {
            let listener = Self::find_listener(inner, dst, dst_port);
            if let Some(listener) = listener {
                return Self::accept_syn_v4(inner, ns, tcp, src, dst, src_port, dst_port, listener);
            }
        }

        // 3) Existing outbound NAT connection?
        let existing = inner.tcp.lock().expect("poisoned").get(&key).cloned();
        if let Some(c) = existing {
            return c.handle_segment(tcp);
        }

        // Non-SYN to unknown connection — RST per RFC 9293.
        if (flags & tcp_flags::SYN) == 0 {
            if let Some(rst) = build_rst_for_stray(tcp, dst_port, src_port) {
                let pkt = crate::slirp::packet::build_packet4(dst, src, &rst);
                return Self::dispatch(inner, ns, &pkt);
            }
            return Ok(());
        }

        // SYN → dial the real destination and bridge it to a server-side
        // vtcp::Conn terminating the virtual side.
        if inner.tcp.lock().expect("poisoned").len() >= MAX_OUTBOUND_TCP
            || inner.pending_dials.load(Ordering::Acquire) >= MAX_PENDING_DIALS
        {
            return Ok(()); // silently drop; client will retransmit
        }
        let seg = match Segment::parse(tcp) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        let sink = Self::sink(inner, ns);
        let endpoints = Endpoints::V4 {
            local_ip: dst,
            local_port: dst_port,
            remote_ip: src,
            remote_port: src_port,
        };
        let conn = TcpOutConn::pending(endpoints, &seg, sink);
        // Register before the dial can answer, so the client's ACK of the
        // SYN-ACK resolves to this connection rather than drawing a RST.
        inner
            .tcp
            .lock()
            .expect("poisoned")
            .insert(key, conn.clone());
        Self::start_dial(
            inner,
            &conn,
            SocketAddr::V4(SocketAddrV4::new(dst, dst_port)),
        );
        Ok(())
    }

    /// Dial the real destination of an outbound bridge in the background,
    /// counting it against [`MAX_PENDING_DIALS`] until it finishes.
    fn start_dial(inner: &Arc<Inner>, conn: &Arc<TcpOutConn>, dest: SocketAddr) {
        let pending = inner.pending_dials.clone();
        pending.fetch_add(1, Ordering::AcqRel);
        conn.start_dial(dest, move || {
            pending.fetch_sub(1, Ordering::AcqRel);
        });
    }

    /// Look up a registered IPv4 listener for `(dst, dst_port)`, falling back
    /// to a wildcard (0.0.0.0) listener on the same port.
    fn find_listener(inner: &Arc<Inner>, dst: Ipv4Addr, dst_port: u16) -> Option<Arc<Listener>> {
        let m = inner.listeners.lock().expect("poisoned");
        let exact = ListenerKey {
            ip: dst.octets(),
            port: dst_port,
        };
        let wildcard = ListenerKey {
            ip: [0, 0, 0, 0],
            port: dst_port,
        };
        [exact, wildcard]
            .iter()
            .filter_map(|k| m.get(k)?.upgrade())
            .find(|l| !l.closed.load(Ordering::Acquire))
    }

    /// Passive-open a server-side `vtcp::Conn` for an inbound SYN to a virtual
    /// listener. Drives the SYN-ACK out, registers the connection, and spawns a
    /// short-lived thread that enqueues the [`TcpStream`](super::TcpStream)
    /// onto the listener once the handshake reaches ESTABLISHED.
    #[allow(clippy::too_many_arguments)]
    fn accept_syn_v4(
        inner: &Arc<Inner>,
        ns: u64,
        tcp: &[u8],
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        listener: Arc<Listener>,
    ) -> Result<()> {
        let key = Key {
            ns,
            src_ip: src.octets(),
            src_port,
            dst_ip: dst.octets(),
            dst_port,
        };
        if inner.virt_tcp.lock().expect("poisoned").len() >= MAX_VIRT_TCP_CONNS {
            return Ok(()); // silently drop; client will retransmit
        }
        // TODO(slirp): when the accept queue is near-full, fall back to a
        // stateless SYN-cookie (vtcp::SynCookies) SYN-ACK instead of dropping.
        if listener.queue_full() {
            return Ok(());
        }
        let seg = match Segment::parse(tcp) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        // Sink: wrap engine segments (built by ConnState) and inject them.
        let sink = Self::sink(inner, ns);

        let cfg = ConnConfig {
            local_addr: Some(SocketAddr::new(std::net::IpAddr::V4(dst), dst_port)),
            remote_addr: Some(SocketAddr::new(std::net::IpAddr::V4(src), src_port)),
            local_port: dst_port,
            remote_port: src_port,
            mss: 1460,
            keepalive: true,
            ..Default::default()
        };
        let mut conn = Conn::new(cfg);
        let synack = conn.accept_syn(&seg);

        let state = ConnState::new(
            Endpoints::V4 {
                local_ip: dst,
                local_port: dst_port,
                remote_ip: src,
                remote_port: src_port,
            },
            conn,
            sink,
        );
        let listener = Arc::downgrade(&listener);
        state.set_pending_accept(Box::new(move |s| {
            listener.upgrade().is_some_and(|l| l.enqueue(s))
        }));
        inner
            .virt_tcp
            .lock()
            .expect("poisoned")
            .insert(key, state.clone());
        // Emit the SYN-ACK. The connection joins the listener's queue when an
        // inbound segment completes the handshake (see `complete_accept`).
        state.wrap_and_send(synack);
        Ok(())
    }

    fn handle_ipv4_udp(
        inner: &Arc<Inner>,
        ns: u64,
        pkt: &[u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        ihl: usize,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Result<()> {
        if pkt.len() < ihl + 8 {
            return Ok(());
        }
        let udp = &pkt[ihl..];
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let key = Key {
            ns,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        // Look up or create.
        let conn = {
            let mut t = inner.udp.lock().expect("poisoned");
            if let Some(c) = t.get(&key).filter(|c| !c.is_closed()) {
                c.clone()
            } else if t.len() >= MAX_UDP_FLOWS && !t.contains_key(&key) {
                return Ok(()); // table full: drop, as a full conntrack table would
            } else {
                let weak = Arc::downgrade(inner);
                let send_fn: UdpSendFn = Arc::new(move |p: &[u8]| match weak.upgrade() {
                    Some(inner) => Self::dispatch(&inner, ns, p),
                    None => Ok(()),
                });
                let conn = UdpConn::new(src, src_port, dst, dst_port, send_fn)?;
                t.insert(key, conn.clone());
                conn
            }
        };
        conn.handle_outbound(pkt, ihl);
        Ok(())
    }

    fn handle_ipv6(inner: &Arc<Inner>, ns: u64, pkt: &[u8]) -> Result<()> {
        if pkt.len() < 40 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPv6 packet too short",
            ));
        }
        let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        if pkt.len() < 40 + payload_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPv6 packet shorter than payload length",
            ));
        }
        let pkt = &pkt[..40 + payload_len];
        // See the IPv4 path: fragments are reassembled before anything reads
        // a transport header.
        if let Some(frag_off) = ipv6_fragment_header(pkt) {
            let whole =
                inner
                    .defrag
                    .lock()
                    .expect("poisoned")
                    .push_v6(Instant::now(), ns, pkt, frag_off);
            return match whole {
                Some(p) => Self::handle_ipv6(inner, ns, &p),
                None => Ok(()),
            };
        }
        let next_header = pkt[6];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&pkt[8..24]);
        dst.copy_from_slice(&pkt[24..40]);
        let (proto, transport_off) = skip_extension_headers(pkt, next_header, 40);
        let src_addr = Ipv6Addr::from(src);
        let dst_addr = Ipv6Addr::from(dst);

        match proto {
            6 => {
                if pkt.len() < transport_off + 20 {
                    return Ok(());
                }
                Self::handle_ipv6_tcp(inner, ns, pkt, src_addr, dst_addr, transport_off)
            }
            17 => {
                if pkt.len() < transport_off + 8 {
                    return Ok(());
                }
                Self::handle_ipv6_udp(inner, ns, pkt, src, dst, src_addr, dst_addr, transport_off)
            }
            58 => {
                // ICMPv6.
                let our = inner.addr.read().expect("poisoned").addr();
                if let Some(reply) =
                    build_icmpv6_echo_reply(pkt, src_addr, dst_addr, transport_off, Some(our))
                {
                    return Self::dispatch(inner, ns, &reply);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn handle_ipv6_tcp(
        inner: &Arc<Inner>,
        ns: u64,
        pkt: &[u8],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        transport_off: usize,
    ) -> Result<()> {
        let tcp = &pkt[transport_off..];
        if tcp.len() < 20 {
            return Ok(());
        }
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let flags = tcp[13];

        let key = Key6 {
            ns,
            src_ip: src.octets(),
            src_port,
            dst_ip: dst.octets(),
            dst_port,
        };

        // 1) Existing inbound virtual TCP connection (vtcp-backed)?
        let virt = inner.virt_tcp6.lock().expect("poisoned").get(&key).cloned();
        if let Some(state) = virt {
            if let Ok(seg) = Segment::parse(tcp) {
                state.deliver(&seg);
            }
            if !state.complete_accept() {
                inner.virt_tcp6.lock().expect("poisoned").remove(&key);
            }
            return Ok(());
        }

        // 2) SYN destined for a registered virtual listener? Passive-open a
        //    server-side vtcp::Conn and drive the handshake.
        if (flags & tcp_flags::SYN) != 0 {
            let listener = Self::find_listener6(inner, dst, dst_port);
            if let Some(listener) = listener {
                return Self::accept_syn_v6(inner, ns, tcp, src, dst, src_port, dst_port, listener);
            }
        }

        let existing = inner.tcp6.lock().expect("poisoned").get(&key).cloned();
        if let Some(c) = existing {
            return c.handle_segment(tcp);
        }

        if (flags & tcp_flags::SYN) == 0 {
            if let Some(rst) = build_rst_for_stray(tcp, dst_port, src_port) {
                let pkt = crate::slirp::packet::build_packet6(dst, src, &rst);
                return Self::dispatch(inner, ns, &pkt);
            }
            return Ok(());
        }

        if inner.tcp6.lock().expect("poisoned").len() >= MAX_OUTBOUND_TCP
            || inner.pending_dials.load(Ordering::Acquire) >= MAX_PENDING_DIALS
        {
            return Ok(()); // silently drop; client will retransmit
        }
        let seg = match Segment::parse(tcp) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        let sink = Self::sink(inner, ns);
        let endpoints = Endpoints::V6 {
            local_ip: dst,
            local_port: dst_port,
            remote_ip: src,
            remote_port: src_port,
        };
        let conn = TcpOutConn::pending(endpoints, &seg, sink);
        // Register before the dial can answer (see the v4 path).
        inner
            .tcp6
            .lock()
            .expect("poisoned")
            .insert(key, conn.clone());
        Self::start_dial(
            inner,
            &conn,
            SocketAddr::V6(SocketAddrV6::new(dst, dst_port, 0, 0)),
        );
        Ok(())
    }

    /// Look up a registered IPv6 listener for `(dst, dst_port)`, falling back
    /// to a wildcard (`::`) listener on the same port.
    fn find_listener6(inner: &Arc<Inner>, dst: Ipv6Addr, dst_port: u16) -> Option<Arc<Listener6>> {
        let m = inner.listeners6.lock().expect("poisoned");
        let exact = ListenerKey6 {
            ip: dst.octets(),
            port: dst_port,
        };
        let wildcard = ListenerKey6 {
            ip: Ipv6Addr::UNSPECIFIED.octets(),
            port: dst_port,
        };
        [exact, wildcard]
            .iter()
            .filter_map(|k| m.get(k)?.upgrade())
            .find(|l| !l.closed.load(Ordering::Acquire))
    }

    /// IPv6 analogue of [`accept_syn_v4`](Self::accept_syn_v4): passive-open a
    /// server-side `vtcp::Conn` for an inbound SYN to a virtual `Listener6`,
    /// emit the SYN-ACK, register the connection in `virt_tcp6`, and spawn a
    /// waiter that enqueues the [`TcpStream`](super::TcpStream) once ESTABLISHED.
    #[allow(clippy::too_many_arguments)]
    fn accept_syn_v6(
        inner: &Arc<Inner>,
        ns: u64,
        tcp: &[u8],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        listener: Arc<Listener6>,
    ) -> Result<()> {
        let key = Key6 {
            ns,
            src_ip: src.octets(),
            src_port,
            dst_ip: dst.octets(),
            dst_port,
        };
        if inner.virt_tcp6.lock().expect("poisoned").len() >= MAX_VIRT_TCP_CONNS {
            return Ok(()); // silently drop; client will retransmit
        }
        // TODO(slirp): when the accept queue is near-full, fall back to a
        // stateless SYN-cookie (vtcp::SynCookies) SYN-ACK instead of dropping.
        if listener.queue_full() {
            return Ok(());
        }
        let seg = match Segment::parse(tcp) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        // Sink: wrap engine segments (built by ConnState) and inject them.
        let sink = Self::sink(inner, ns);

        let cfg = ConnConfig {
            local_addr: Some(SocketAddr::new(std::net::IpAddr::V6(dst), dst_port)),
            remote_addr: Some(SocketAddr::new(std::net::IpAddr::V6(src), src_port)),
            local_port: dst_port,
            remote_port: src_port,
            mss: 1440,
            keepalive: true,
            ..Default::default()
        };
        let mut conn = Conn::new(cfg);
        let synack = conn.accept_syn(&seg);

        let state = ConnState::new(
            Endpoints::V6 {
                local_ip: dst,
                local_port: dst_port,
                remote_ip: src,
                remote_port: src_port,
            },
            conn,
            sink,
        );
        let listener = Arc::downgrade(&listener);
        state.set_pending_accept(Box::new(move |s| {
            listener.upgrade().is_some_and(|l| l.enqueue(s))
        }));
        inner
            .virt_tcp6
            .lock()
            .expect("poisoned")
            .insert(key, state.clone());
        // Emit the SYN-ACK. The connection joins the listener's queue when an
        // inbound segment completes the handshake (see `complete_accept`).
        state.wrap_and_send(synack);
        Ok(())
    }

    fn handle_ipv6_udp(
        inner: &Arc<Inner>,
        ns: u64,
        pkt: &[u8],
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        transport_off: usize,
    ) -> Result<()> {
        let udp = &pkt[transport_off..];
        if udp.len() < 8 {
            return Ok(());
        }
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let key = Key6 {
            ns,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        let conn = {
            let mut t = inner.udp6.lock().expect("poisoned");
            if let Some(c) = t.get(&key).filter(|c| !c.is_closed()) {
                c.clone()
            } else if t.len() >= MAX_UDP_FLOWS && !t.contains_key(&key) {
                return Ok(()); // table full: drop, as a full conntrack table would
            } else {
                let weak = Arc::downgrade(inner);
                let send_fn: UdpSendFn6 = Arc::new(move |p: &[u8]| match weak.upgrade() {
                    Some(inner) => Self::dispatch(&inner, ns, p),
                    None => Ok(()),
                });
                let conn = UdpConn6::new(src, src_port, dst, dst_port, send_fn)?;
                t.insert(key, conn.clone());
                conn
            }
        };
        conn.handle_outbound(pkt, transport_off);
        Ok(())
    }

    fn cleanup_namespace(inner: &Arc<Inner>, ns: u64) {
        Self::close_flows(inner, |k| k == ns);
    }

    /// Remove every flow whose namespace matches `which` and tear it down.
    ///
    /// The flows are taken out of their tables first and closed afterwards:
    /// closing sends RSTs through the handler, and a handler that answers
    /// synchronously re-enters `send`, which needs those same table locks.
    fn close_flows(inner: &Arc<Inner>, which: impl Fn(u64) -> bool) {
        fn take<K: Copy + Eq + std::hash::Hash, V>(
            m: &Mutex<HashMap<K, V>>,
            ns: impl Fn(&K) -> u64,
            which: &impl Fn(u64) -> bool,
        ) -> Vec<V> {
            let Ok(mut t) = m.lock() else {
                return Vec::new();
            };
            let keys: Vec<K> = t.keys().filter(|k| which(ns(k))).copied().collect();
            keys.iter().filter_map(|k| t.remove(k)).collect()
        }
        let virt: Vec<Arc<ConnState>> = take(&inner.virt_tcp, |k| k.ns, &which)
            .into_iter()
            .chain(take(&inner.virt_tcp6, |k| k.ns, &which))
            .collect();
        for state in virt {
            let segs = state.conn.lock().expect("poisoned").abort();
            state.wrap_and_send(segs);
            state.signal.notify_all();
        }
        for c in take(&inner.tcp, |k| k.ns, &which).into_iter().chain(take(
            &inner.tcp6,
            |k| k.ns,
            &which,
        )) {
            c.close();
        }
        for c in take(&inner.udp, |k| k.ns, &which) {
            c.close();
        }
        for c in take(&inner.udp6, |k| k.ns, &which) {
            c.close();
        }
    }
}

impl Drop for Stack {
    /// The last handle going away shuts the stack down: its flows are closed
    /// and its background threads wind down.
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl L3Device for Stack {
    fn set_handler(&self, h: L3Handler) {
        *self.inner.handler.lock().expect("poisoned") = Some(h);
    }

    fn send(&self, packet: &Packet) -> Result<()> {
        Self::handle_packet(&self.inner, 0, packet.as_bytes())
    }

    fn addr(&self) -> IpPrefix {
        *self.inner.addr.read().expect("poisoned")
    }

    fn set_addr(&self, prefix: IpPrefix) -> Result<()> {
        *self.inner.addr.write().expect("poisoned") = prefix;
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.shutdown()
    }
}

impl L3Connector for Stack {
    fn connect_l3(&self, dev: Arc<dyn L3Device>) -> Result<Cleanup> {
        let ns = self.inner.ns_counter.fetch_add(1, Ordering::AcqRel) + 1;
        let side = Arc::new(NsSide {
            stack: self.inner.clone(),
            ns,
            handler: Mutex::new(None),
            addr: RwLock::new(*self.inner.addr.read().expect("poisoned")),
        });
        connect_l3(side.clone() as Arc<dyn L3Device>, dev);
        self.inner
            .ns_sides
            .lock()
            .expect("poisoned")
            .insert(ns, side);

        let weak = Arc::downgrade(&self.inner);
        Ok(Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                inner.ns_sides.lock().expect("poisoned").remove(&ns);
                Stack::cleanup_namespace(&inner, ns);
            }
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protocol;
    use crate::slirp::checksum::{ipv4_header_checksum, udp_v4_checksum};
    use crate::vtcp::State as VtcpState;
    use crate::vtcp::segment::flags as tcp_flags;
    use std::net::{IpAddr, UdpSocket};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn make_v4_icmp_echo(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let ihl = 20;
        let icmp = 8 + 4; // type|code|csum|id|seq
        let mut p = vec![0u8; ihl + icmp];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((ihl + icmp) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 1;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let cs = ipv4_header_checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&cs.to_be_bytes());
        p[ihl] = 8;
        p[ihl + 1] = 0;
        // checksum=0; let stack recompute
        let cs = super::super::checksum::internet_checksum(&p[ihl..]);
        p[ihl + 2..ihl + 4].copy_from_slice(&cs.to_be_bytes());
        p
    }

    #[test]
    fn icmp_echo_reply_routed_to_handler() {
        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let c = captured.clone();
        s.set_handler(Arc::new(move |p: &Packet| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let echo = make_v4_icmp_echo(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1));
        L3Device::send(&*s, Packet::from_slice(&echo)).unwrap();

        let got = captured.lock().unwrap();
        assert_eq!(got.len(), 1);
        // Reply has src=our addr, dst=client.
        assert_eq!(&got[0][12..16], &[10, 0, 0, 1]);
        assert_eq!(&got[0][16..20], &[10, 0, 0, 5]);
        // Type byte = 0 (echo reply).
        assert_eq!(got[0][20], 0);
    }

    #[test]
    fn ignores_ping_for_other_address() {
        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        s.set_handler(Arc::new(move |_p: &Packet| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        // Destined for 10.0.0.9, not us.
        let echo = make_v4_icmp_echo(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9));
        L3Device::send(&*s, Packet::from_slice(&echo)).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn icmpv6_echo_answered_only_for_our_address() {
        let ours: Ipv6Addr = "fd00::1".parse().unwrap();
        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V6(ours), 64)).unwrap();
        let captured = capture(&s);
        let echo = |dst: Ipv6Addr| {
            let src: Ipv6Addr = "fd00::5".parse().unwrap();
            let mut p = vec![0u8; 48];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&8u16.to_be_bytes());
            p[6] = 58;
            p[7] = 64;
            p[8..24].copy_from_slice(&src.octets());
            p[24..40].copy_from_slice(&dst.octets());
            p[40] = 128; // echo request
            p
        };
        for dst in ["fd00::9", "ff02::1"] {
            L3Device::send(&*s, Packet::from_slice(&echo(dst.parse().unwrap()))).unwrap();
        }
        assert!(
            captured.lock().unwrap().is_empty(),
            "answered for another address"
        );
        L3Device::send(&*s, Packet::from_slice(&echo(ours))).unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    fn build_udp_v4_packet(
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let ihl = 20;
        let uh = 8;
        let total = ihl + uh + body.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let cs = ipv4_header_checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&cs.to_be_bytes());
        p[ihl..ihl + 2].copy_from_slice(&src_port.to_be_bytes());
        p[ihl + 2..ihl + 4].copy_from_slice(&dst_port.to_be_bytes());
        p[ihl + 4..ihl + 6].copy_from_slice(&((uh + body.len()) as u16).to_be_bytes());
        p[ihl + 8..ihl + 8 + body.len()].copy_from_slice(body);
        let cs = udp_v4_checksum(src, dst, &p[ihl..ihl + 8], body);
        p[ihl + 6..ihl + 8].copy_from_slice(&cs.to_be_bytes());
        p
    }

    #[test]
    fn udp_nat_round_trip_loopback() {
        // Spin up a real UDP echo server on loopback.
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sport = server.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let server_arc = Arc::new(server);
        let server2 = server_arc.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while !stop2.load(Ordering::Acquire) {
                if let Ok((n, src)) = server2.recv_from(&mut buf) {
                    let _ = server2.send_to(&buf[..n], src);
                }
            }
        });

        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let c = captured.clone();
        s.set_handler(Arc::new(move |p: &Packet| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let dgram = build_udp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            45678,
            Ipv4Addr::new(127, 0, 0, 1),
            sport,
            b"hello",
        );
        L3Device::send(&*s, Packet::from_slice(&dgram)).unwrap();

        // Poll for the echoed response.
        let deadline = crate::time::Instant::now() + Duration::from_secs(2);
        loop {
            if !captured.lock().unwrap().is_empty() {
                break;
            }
            if crate::time::Instant::now() > deadline {
                panic!("no response received");
            }
            thread::sleep(Duration::from_millis(10));
        }

        let got = captured.lock().unwrap();
        let pkt = &got[0];
        assert_eq!(pkt[9], 17); // UDP
        let udp = &pkt[20..];
        // dst port should be our virtual client's source port.
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        assert_eq!(dport, 45678);
        // payload echoed back
        assert_eq!(&udp[8..], b"hello");

        stop.store(true, Ordering::Release);
    }

    #[test]
    fn non_syn_to_nothing_yields_rst() {
        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let c = captured.clone();
        s.set_handler(Arc::new(move |p: &Packet| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        // ACK to a port nothing's listening on, no SYN.
        let ihl = 20;
        let mut p = vec![0u8; ihl + 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((ihl + 20) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 5]);
        p[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let cs = ipv4_header_checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&cs.to_be_bytes());
        p[ihl..ihl + 2].copy_from_slice(&12345u16.to_be_bytes());
        p[ihl + 2..ihl + 4].copy_from_slice(&80u16.to_be_bytes());
        p[ihl + 12] = 5 << 4;
        p[ihl + 13] = tcp_flags::ACK;
        p[ihl + 8..ihl + 12].copy_from_slice(&1234u32.to_be_bytes()); // ACK
        L3Device::send(&*s, Packet::from_slice(&p)).unwrap();

        let got = captured.lock().unwrap();
        assert_eq!(got.len(), 1);
        // Resulting packet is IPv4 TCP RST.
        assert_eq!(got[0][9], Protocol::TCP.as_u8());
        let rst_tcp = &got[0][20..];
        assert!(rst_tcp[13] & tcp_flags::RST != 0);
    }

    #[test]
    fn listen_registers_and_close_succeeds() {
        let s = Stack::new();
        let l = s.listen("tcp", "127.0.0.1:8088").unwrap();
        assert_eq!(l.addr().port(), 8088);
        // duplicate listen → AddrInUse
        assert!(s.listen("tcp", "127.0.0.1:8088").is_err());
        l.close().unwrap();
    }

    #[test]
    fn closing_or_dropping_a_listener_frees_its_address() {
        let s = Stack::new();
        let l = s.listen("tcp", "10.0.0.1:8089").unwrap();
        l.close().unwrap();
        let l2 = s
            .listen("tcp", "10.0.0.1:8089")
            .expect("closed listener freed the port");
        // The first listener's handle going away must not unregister the
        // second one.
        drop(l);
        assert!(s.listen("tcp", "10.0.0.1:8089").is_err());
        drop(l2);
        s.listen("tcp", "10.0.0.1:8089")
            .expect("dropped listener freed the port");

        let l6 = s.listen6("[fd00::1]:8089").unwrap();
        l6.close().unwrap();
        s.listen6("[fd00::1]:8089")
            .expect("closed listener6 freed the port");
    }

    #[test]
    fn namespace_isolation_keys_per_peer() {
        // Two peers attached via connect_l3 should occupy different ns ids.
        let s = Stack::new();
        let pipe1 = Arc::new(crate::PipeL3::new(IpPrefix::default()));
        let pipe2 = Arc::new(crate::PipeL3::new(IpPrefix::default()));
        let c1 = L3Connector::connect_l3(&*s, pipe1.clone()).unwrap();
        let c2 = L3Connector::connect_l3(&*s, pipe2.clone()).unwrap();
        let inner = s.inner.clone();
        assert_eq!(inner.ns_sides.lock().unwrap().len(), 2);
        c1().unwrap();
        c2().unwrap();
        assert_eq!(inner.ns_sides.lock().unwrap().len(), 0);
    }

    /// Assemble an IPv4+TCP packet from the supplied fields. Computes both
    /// IP and TCP checksums (TCP via the pseudo-header).
    fn build_tcp_v4_packet(
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let ihl = 20usize;
        let tcph = 20usize;
        let total = ihl + tcph + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let hcs = ipv4_header_checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&hcs.to_be_bytes());
        p[ihl..ihl + 2].copy_from_slice(&src_port.to_be_bytes());
        p[ihl + 2..ihl + 4].copy_from_slice(&dst_port.to_be_bytes());
        p[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
        p[ihl + 8..ihl + 12].copy_from_slice(&ack.to_be_bytes());
        p[ihl + 12] = 5 << 4;
        p[ihl + 13] = flags;
        p[ihl + 14..ihl + 16].copy_from_slice(&32768u16.to_be_bytes());
        if !payload.is_empty() {
            p[ihl + tcph..ihl + tcph + payload.len()].copy_from_slice(payload);
        }
        // Zero the checksum, then compute pseudo-header+TCP+payload sum.
        let cs = crate::slirp::checksum::tcp_v4_checksum(src, dst, &p[ihl..]);
        p[ihl + 16..ihl + 18].copy_from_slice(&cs.to_be_bytes());
        p
    }

    #[test]
    fn tcp_nat_round_trip_loopback() {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener};

        // Real TCP echo-ish server on loopback: reads one chunk, replies "pong".
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                if n > 0 {
                    let _ = s.write_all(b"pong");
                    let _ = s.shutdown(Shutdown::Write);
                }
            }
        });

        let stack = Stack::new();
        stack
            .set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();

        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let r = received.clone();
        stack.set_handler(Arc::new(move |p: &Packet| {
            r.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(127, 0, 0, 1);
        let cport = 50000u16;

        // 1) Client → SYN
        let syn = build_tcp_v4_packet(client, cport, server, port, 1000, 0, tcp_flags::SYN, &[]);
        L3Device::send(&*stack, Packet::from_slice(&syn)).unwrap();

        // Wait for the SYN-ACK to land.
        let server_iss: u32;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            {
                let g = received.lock().unwrap();
                if !g.is_empty() {
                    let pkt = &g[0];
                    let tcp = &pkt[20..];
                    assert!(
                        tcp[13] & tcp_flags::SYN != 0 && tcp[13] & tcp_flags::ACK != 0,
                        "expected SYN+ACK, got flags {:02x}",
                        tcp[13]
                    );
                    server_iss = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
                    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
                    assert_eq!(ack, 1001);
                    break;
                }
            }
            if Instant::now() > deadline {
                panic!("did not receive SYN-ACK");
            }
            thread::sleep(Duration::from_millis(10));
        }

        // 2) Client → ACK (handshake completes)
        let ack = build_tcp_v4_packet(
            client,
            cport,
            server,
            port,
            1001,
            server_iss.wrapping_add(1),
            tcp_flags::ACK,
            &[],
        );
        L3Device::send(&*stack, Packet::from_slice(&ack)).unwrap();

        // 3) Client → PSH+ACK with "ping"
        let data = build_tcp_v4_packet(
            client,
            cport,
            server,
            port,
            1001,
            server_iss.wrapping_add(1),
            tcp_flags::ACK,
            b"ping",
        );
        L3Device::send(&*stack, Packet::from_slice(&data)).unwrap();

        // Wait for the server's response "pong" to come back to us.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got_pong = false;
        loop {
            {
                let g = received.lock().unwrap();
                for pkt in g.iter() {
                    if pkt.len() < 40 {
                        continue;
                    }
                    let tcp = &pkt[20..];
                    let data_off = ((tcp[12] >> 4) as usize) * 4;
                    if data_off < tcp.len() {
                        let payload = &tcp[data_off..];
                        if payload == b"pong" {
                            got_pong = true;
                            break;
                        }
                    }
                }
            }
            if got_pong || Instant::now() > deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(got_pong, "did not see pong payload come back");
    }

    /// Handler that records every packet the stack emits.
    fn capture(stack: &Stack) -> Arc<Mutex<Vec<Vec<u8>>>> {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let c = captured.clone();
        stack.set_handler(Arc::new(move |p: &Packet| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        captured
    }

    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn syn_to_blackholed_destination_does_not_stall_packet_path() {
        let stack = Stack::new();
        stack
            .set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();
        let _captured = capture(&stack);
        // TEST-NET-1 (RFC 5737): nothing answers, so a connect hangs until the
        // OS gives up (or fails at once where there is no route at all).
        let syn = build_tcp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            40000,
            Ipv4Addr::new(192, 0, 2, 1),
            80,
            1000,
            0,
            tcp_flags::SYN,
            &[],
        );
        let start = Instant::now();
        L3Device::send(&*stack, Packet::from_slice(&syn)).unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "send blocked for {:?} dialing the destination",
            start.elapsed()
        );
        let _ = stack.shutdown();
    }

    #[test]
    fn syn_to_refused_port_draws_rst() {
        // A port that was just free: nothing listens on it.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let stack = Stack::new();
        stack
            .set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();
        let captured = capture(&stack);
        let syn = build_tcp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            40001,
            Ipv4Addr::new(127, 0, 0, 1),
            port,
            7000,
            0,
            tcp_flags::SYN,
            &[],
        );
        L3Device::send(&*stack, Packet::from_slice(&syn)).unwrap();
        wait_for("RST", || !captured.lock().unwrap().is_empty());
        let got = captured.lock().unwrap();
        let seg = Segment::parse(&got[0][20..]).unwrap();
        assert_eq!(seg.flags, tcp_flags::RST | tcp_flags::ACK);
        assert_eq!(seg.ack, 7001);
        assert_eq!(seg.src_port, port);
        assert_eq!(seg.dst_port, 40001);
    }

    /// Wire a `vtcp::Conn` as the virtual client of `stack`: segments the
    /// stack emits for it are fed in, and its replies injected back.
    fn wire_vtcp_client(
        stack: &Arc<Stack>,
        client: Ipv4Addr,
        server: Ipv4Addr,
        cport: u16,
        sport: u16,
    ) -> Arc<Mutex<Conn>> {
        let conn = Arc::new(Mutex::new(Conn::new(ConnConfig {
            local_port: cport,
            remote_port: sport,
            mss: 1460,
            ..Default::default()
        })));
        let stack_for_handler = Arc::downgrade(stack);
        let conn_for_handler = conn.clone();
        stack.set_handler(Arc::new(move |p: &Packet| {
            let bytes = p.as_bytes();
            if bytes.len() < 40 || bytes[9] != 6 {
                return Ok(());
            }
            let Ok(seg) = Segment::parse(&bytes[20..]) else {
                return Ok(());
            };
            // Never hold the client lock while injecting: the stack may emit
            // (and so re-enter this handler) from inside `send`.
            let replies = conn_for_handler.lock().unwrap().handle_segment(&seg);
            if let Some(stack) = stack_for_handler.upgrade() {
                for r in replies {
                    let ip = crate::slirp::packet::build_packet4(client, server, &r);
                    let _ = stack.send(Packet::from_slice(&ip));
                }
            }
            Ok(())
        }));
        conn
    }

    fn inject_segs(stack: &Stack, client: Ipv4Addr, server: Ipv4Addr, segs: Vec<Vec<u8>>) {
        for s in segs {
            let ip = crate::slirp::packet::build_packet4(client, server, &s);
            let _ = stack.send(Packet::from_slice(&ip));
        }
    }

    #[test]
    fn shutdown_unblocks_bridge_stuck_writing_to_remote() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        // A real server that accepts and then never reads, so the bridge's
        // writes to it eventually block.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (held_tx, held_rx) = mpsc::channel();
        thread::spawn(move || {
            if let Ok((s, _)) = listener.accept() {
                let _ = held_tx.send(s);
            }
        });

        let stack = Stack::new();
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(127, 0, 0, 1);
        let vc = wire_vtcp_client(&stack, client, server, 50002, port);
        let syn = vc.lock().unwrap().connect();
        inject_segs(&stack, client, server, syn);
        wait_for("ESTABLISHED", || {
            vc.lock().unwrap().state() == VtcpState::Established
        });
        let _held = held_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        // Push until nothing more fits anywhere: the real socket's buffers,
        // then the bridge's vtcp receive buffer, then ours.
        let chunk = vec![0x5au8; 64 * 1024];
        let mut last_progress = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(60);
        while last_progress.elapsed() < Duration::from_millis(500) {
            assert!(Instant::now() < deadline, "the remote never pushed back");
            let (n, segs) = vc.lock().unwrap().write(&chunk);
            inject_segs(&stack, client, server, segs);
            if n > 0 {
                last_progress = Instant::now();
            } else {
                let segs = vc.lock().unwrap().tick();
                inject_segs(&stack, client, server, segs);
                thread::sleep(Duration::from_millis(5));
            }
        }

        let (done_tx, done_rx) = mpsc::channel();
        let s2 = stack.clone();
        thread::spawn(move || {
            let _ = s2.shutdown();
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "shutdown deadlocked against the blocked writer"
        );
    }

    #[test]
    fn udp_flow_survives_port_unreachable() {
        // A port nothing listens on yet.
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let stack = Stack::new();
        let captured = capture(&stack);
        let dgram = build_udp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            41500,
            Ipv4Addr::new(127, 0, 0, 1),
            port,
            b"early",
        );
        // The kernel answers with port unreachable, which the flow's socket
        // reports as ECONNREFUSED on its next recv.
        L3Device::send(&*stack, Packet::from_slice(&dgram)).unwrap();
        thread::sleep(Duration::from_millis(200));

        // The server comes up on that port; the same flow must now work.
        let server = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        L3Device::send(&*stack, Packet::from_slice(&dgram)).unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        server.send_to(&buf[..n], from).unwrap();
        wait_for("the reply", || !captured.lock().unwrap().is_empty());
        assert_eq!(&captured.lock().unwrap()[0][28..], b"early");
    }

    #[test]
    fn fragmented_udp_is_reassembled_before_forwarding() {
        use crate::fragment::{Fragmentation, fragment_ipv4};

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sport = server.local_addr().unwrap().port();
        let stack = Stack::new();
        let _captured = capture(&stack);
        let body: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let mut dgram = build_udp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            41600,
            Ipv4Addr::new(127, 0, 0, 1),
            sport,
            &body,
        );
        dgram[4..6].copy_from_slice(&0x4242u16.to_be_bytes());
        let Fragmentation::Fragments(frags) = fragment_ipv4(Packet::from_slice(&dgram), 1500)
        else {
            panic!("expected fragments");
        };

        // A later fragment alone must not be read as a UDP header.
        L3Device::send(&*stack, Packet::from_slice(&frags[2])).unwrap();
        assert!(stack.inner.udp.lock().unwrap().is_empty());

        for f in &frags[..2] {
            L3Device::send(&*stack, Packet::from_slice(f)).unwrap();
        }
        let mut buf = vec![0u8; 4096];
        let (n, _) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &body[..]);
    }

    #[test]
    fn large_udp_reply_arrives_whole_in_fragments() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sport = server.local_addr().unwrap().port();
        let stack = Stack::new();
        let captured = capture(&stack);
        let dgram = build_udp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            41700,
            Ipv4Addr::new(127, 0, 0, 1),
            sport,
            b"q",
        );
        L3Device::send(&*stack, Packet::from_slice(&dgram)).unwrap();
        let mut buf = [0u8; 16];
        let (_, from) = server.recv_from(&mut buf).unwrap();
        let reply: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
        server.send_to(&reply, from).unwrap();

        let mut r = crate::slirp::defrag::Reassembler::default();
        let mut whole = None;
        wait_for("the whole reply", || {
            for p in captured.lock().unwrap().drain(..) {
                assert!(p.len() <= crate::slirp::packet::LINK_MTU);
                whole = whole
                    .take()
                    .or_else(|| r.push_v4(Instant::now(), 0, &p, 20));
            }
            whole.is_some()
        });
        let whole = whole.unwrap();
        assert_eq!(&whole[28..], &reply[..]);
    }

    #[test]
    fn zero_length_udp_datagrams_are_relayed_both_ways() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sport = server.local_addr().unwrap().port();
        let stack = Stack::new();
        let captured = capture(&stack);
        let mut dgram = build_udp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            41800,
            Ipv4Addr::new(127, 0, 0, 1),
            sport,
            &[],
        );
        // Link padding past the UDP length is not part of the datagram.
        dgram.extend_from_slice(&[0xEE; 6]);
        let total = dgram.len() as u16;
        dgram[2..4].copy_from_slice(&total.to_be_bytes());
        L3Device::send(&*stack, Packet::from_slice(&dgram)).unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(n, 0);
        server.send_to(&[], from).unwrap();
        wait_for("the empty reply", || !captured.lock().unwrap().is_empty());
        let got = captured.lock().unwrap();
        assert_eq!(got[0].len(), 28);
        assert_eq!(u16::from_be_bytes([got[0][24], got[0][25]]), 8);
    }

    #[test]
    fn udp_flows_are_capped() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sport = server.local_addr().unwrap().port();
        let stack = Stack::new();
        let _captured = capture(&stack);
        for i in 0..(MAX_UDP_FLOWS as u16 + 5) {
            let dgram = build_udp_v4_packet(
                Ipv4Addr::new(10, 0, 0, 5),
                41000 + i,
                Ipv4Addr::new(127, 0, 0, 1),
                sport,
                b"x",
            );
            L3Device::send(&*stack, Packet::from_slice(&dgram)).unwrap();
        }
        assert_eq!(stack.inner.udp.lock().unwrap().len(), MAX_UDP_FLOWS);
    }

    #[test]
    fn handshake_to_closed_listener_is_reset() {
        let stack = Stack::new();
        let captured = capture(&stack);
        let listener = stack.listen("tcp", "10.0.0.1:8080").unwrap();
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(10, 0, 0, 1);
        let syn = build_tcp_v4_packet(client, 40020, server, 8080, 500, 0, tcp_flags::SYN, &[]);
        L3Device::send(&*stack, Packet::from_slice(&syn)).unwrap();
        let synack = Segment::parse(&captured.lock().unwrap()[0][20..]).unwrap();
        assert_eq!(synack.flags, tcp_flags::SYN | tcp_flags::ACK);

        // The listener goes away while the handshake is in flight.
        listener.close().unwrap();
        let ack = build_tcp_v4_packet(
            client,
            40020,
            server,
            8080,
            501,
            synack.seq.wrapping_add(1),
            tcp_flags::ACK,
            &[],
        );
        L3Device::send(&*stack, Packet::from_slice(&ack)).unwrap();
        wait_for("RST", || {
            captured
                .lock()
                .unwrap()
                .iter()
                .any(|p| Segment::parse(&p[20..]).is_ok_and(|s| s.flags & tcp_flags::RST != 0))
        });
        wait_for("the connection to be dropped", || {
            stack.inner.virt_tcp.lock().unwrap().is_empty()
        });
    }

    #[test]
    fn dropping_the_stack_releases_it() {
        use std::net::TcpListener;

        let udp_server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = tcp_server.local_addr().unwrap().port();
        thread::spawn(move || {
            let _held = tcp_server.accept();
            thread::sleep(Duration::from_secs(30));
        });

        let stack = Stack::new();
        let captured = capture(&stack);
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let lo = Ipv4Addr::new(127, 0, 0, 1);
        let dgram = build_udp_v4_packet(
            client,
            40010,
            lo,
            udp_server.local_addr().unwrap().port(),
            b"x",
        );
        L3Device::send(&*stack, Packet::from_slice(&dgram)).unwrap();
        let syn = build_tcp_v4_packet(client, 40011, lo, tcp_port, 1, 0, tcp_flags::SYN, &[]);
        L3Device::send(&*stack, Packet::from_slice(&syn)).unwrap();
        wait_for("SYN-ACK", || !captured.lock().unwrap().is_empty());

        let weak = Arc::downgrade(&stack.inner);
        drop(stack);
        wait_for("the stack to be freed", || weak.upgrade().is_none());
    }

    /// Drive a real `vtcp::Conn` as the virtual client through the outbound NAT
    /// bridge and transfer a payload far larger than one MSS / one window in
    /// both directions. This exercises the vtcp engine's segmentation, ACK
    /// clocking, windowing, and reassembly on the virtual side — none of which
    /// the old hand-rolled engine had.
    #[test]
    fn tcp_out_large_transfer_via_vtcp_client() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // Real TCP echo server on loopback: echoes everything until EOF.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let stack = Stack::new();
        stack
            .set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();

        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(127, 0, 0, 1);
        let cport = 50001u16;

        // The virtual client is a full vtcp::Conn. The stack's handler feeds
        // packets it emits into the client; the client's replies are injected
        // back into the stack.
        let vclient = Arc::new(Mutex::new(Conn::new(ConnConfig {
            local_port: cport,
            remote_port: port,
            mss: 1460,
            ..Default::default()
        })));

        let stack_for_handler = stack.clone();
        let client_for_handler = vclient.clone();
        stack.set_handler(Arc::new(move |p: &Packet| {
            let bytes = p.as_bytes();
            if bytes.len() < 40 || bytes[9] != 6 {
                return Ok(());
            }
            let seg = match Segment::parse(&bytes[20..]) {
                Ok(s) => s,
                Err(_) => return Ok(()),
            };
            let replies = {
                let mut c = client_for_handler.lock().unwrap();
                c.handle_segment(&seg)
            };
            for r in replies {
                let ip = crate::slirp::packet::build_packet4(client, server, &r);
                let _ = stack_for_handler.send(Packet::from_slice(&ip));
            }
            Ok(())
        }));

        let inject = |segs: Vec<Vec<u8>>| {
            for s in segs {
                let ip = crate::slirp::packet::build_packet4(client, server, &s);
                stack.send(Packet::from_slice(&ip)).unwrap();
            }
        };

        // Active open: client SYN → stack dials loopback, bridges with a
        // server-side vtcp::Conn, replies SYN-ACK (handled in the handler).
        // NB: never hold the vclient lock across `inject` — the handler re-locks
        // it when the bridge emits segments, which would self-deadlock.
        let syn = vclient.lock().unwrap().connect();
        inject(syn);

        // Wait for the client to reach ESTABLISHED.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if vclient.lock().unwrap().state() == VtcpState::Established {
                break;
            }
            assert!(Instant::now() < deadline, "client never established");
            // A tick may be needed to flush the client's handshake ACK.
            let segs = vclient.lock().unwrap().tick();
            inject(segs);
            thread::sleep(Duration::from_millis(10));
        }

        // Send a payload many MSS-segments long (well past the initial
        // congestion window) so the transfer spans ~11 segments and several
        // windows — enough to exercise vtcp segmentation, ACK clocking, and the
        // reassembly path the old hand-rolled engine lacked. Kept modest (16 KB)
        // so the manually-pumped, lock-stepped transfer stays well inside the
        // deadlines even on slow / loaded CI runners.
        let payload: Vec<u8> = (0..16_000u32).map(|i| (i % 251) as u8).collect();

        // Writer thread: push the whole payload into the client conn, ticking
        // to keep segments flowing as the window opens.
        let writer_client = vclient.clone();
        let stack_for_writer = stack.clone();
        let payload_for_writer = payload.clone();
        let writer = thread::spawn(move || {
            let mut off = 0usize;
            let total = payload_for_writer.len();
            let deadline = Instant::now() + Duration::from_secs(30);
            while off < total {
                let (n, segs) = {
                    let mut c = writer_client.lock().unwrap();
                    c.write(&payload_for_writer[off..])
                };
                for s in segs {
                    let ip = crate::slirp::packet::build_packet4(client, server, &s);
                    let _ = stack_for_writer.send(Packet::from_slice(&ip));
                }
                off += n;
                if n == 0 {
                    // Window full: tick to drive retransmit / probe, let ACKs flow.
                    let segs = writer_client.lock().unwrap().tick();
                    for s in segs {
                        let ip = crate::slirp::packet::build_packet4(client, server, &s);
                        let _ = stack_for_writer.send(Packet::from_slice(&ip));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                assert!(Instant::now() < deadline, "writer stalled");
            }
            // Close the client → triggers FIN to the bridge → real socket EOF.
            let segs = writer_client.lock().unwrap().close();
            for s in segs {
                let ip = crate::slirp::packet::build_packet4(client, server, &s);
                let _ = stack_for_writer.send(Packet::from_slice(&ip));
            }
        });

        // Reader: drain the echoed payload from the client conn, ticking to
        // emit ACKs (which clock the bridge's send window open). A bare read
        // does not ACK in vtcp; the periodic tick flushes the delayed ACK.
        let mut received = Vec::with_capacity(payload.len());
        let mut buf = [0u8; 16 * 1024];
        let deadline = Instant::now() + Duration::from_secs(30);
        while received.len() < payload.len() {
            let (n, segs) = {
                let mut c = vclient.lock().unwrap();
                let n = c.read(&mut buf);
                let segs = c.tick();
                (n, segs)
            };
            inject(segs);
            if n > 0 {
                received.extend_from_slice(&buf[..n]);
            } else {
                thread::sleep(Duration::from_millis(2));
            }
            assert!(
                Instant::now() < deadline,
                "only received {} of {} bytes",
                received.len(),
                payload.len()
            );
        }

        writer.join().unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload, "echoed payload mismatch");

        let _ = stack.shutdown();
    }
}

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
//! - Host destinations can be restricted with [`Stack::set_dest_filter`].
//!
//! Inbound to a virtual listener (ports claimed via [`Stack::listen`]) is also
//! served by the `vtcp` engine: an inbound SYN passive-opens a server-side
//! `vtcp::Conn` and surfaces a [`TcpStream`](super::TcpStream) on ESTABLISHED.

use crate::accept::{Cleanup, L3Connector};
use crate::defrag::{Reassembler, ipv6_fragment_header};
use crate::iface::{L3Device, L3Handler};
use crate::packet::Packet;
use crate::slirp::checksum::{tcp_ok, udp_ok};
use crate::slirp::icmpv4::build_icmpv4_echo_reply;
use crate::slirp::icmpv6::build_icmpv6_echo_reply;
use crate::slirp::ipv6::skip_extension_headers;
use crate::slirp::listener::{Listener, ListenerKey, resolve_v4};
use crate::slirp::listener6::{Listener6, ListenerKey6, resolve_v6};
use crate::slirp::packet::fit_link;
use crate::slirp::tcp_out::{TcpOutConn, build_refused_rst, build_rst_for_stray};
use crate::slirp::tcp_stream::{ConnState, Endpoints, tick_conn};
use crate::slirp::udp::{SendFn as UdpSendFn, UdpConn};
use crate::slirp::udp6::{SendFn as UdpSendFn6, UdpConn6};
use crate::vtcp::segment::{Segment, flags as tcp_flags};
use crate::vtcp::{Conn, ConnConfig};
use crate::{IpPrefix, Protocol, Result, connect_l3};

use crate::time::Instant;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
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
const MAX_OUTBOUND_TCP: usize = if cfg!(test) { 8 } else { 2048 };

/// Cap on outbound TCP bridges in TIME-WAIT, per address family. They hold
/// no thread and are not counted against [`MAX_OUTBOUND_TCP`], so a server
/// that closes first cannot use them up; past this cap the oldest are
/// dropped early, as Linux does past `tcp_max_tw_buckets`.
const MAX_TIME_WAIT: usize = if cfg!(test) { 4 } else { 8192 };

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

/// The error for an operation on a stack that has been shut down.
fn shut_down() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "stack is shut down")
}

/// Decides whether a guest may reach a host destination; see
/// [`Stack::set_dest_filter`]. It gets the destination and the transport
/// ([`Protocol::TCP`] or [`Protocol::UDP`]), and returns `true` to allow.
pub type DestFilter = Arc<dyn Fn(SocketAddr, Protocol) -> bool + Send + Sync>;

/// State shared between Stack and its background maintenance thread.
struct Inner {
    addr: RwLock<IpPrefix>,
    handler: Mutex<Option<L3Handler>>,
    // Per-protocol connection tables. Outbound TCP terminates the virtual side
    // with a server-side vtcp::Conn and bridges to a real socket (`TcpOutConn`).
    tcp: Mutex<HashMap<Key, Arc<TcpOutConn>>>,
    tcp6: Mutex<HashMap<Key6, Arc<TcpOutConn>>>,
    /// How many of the `tcp` / `tcp6` entries are in TIME-WAIT, as of the
    /// last tick: those do not count against [`MAX_OUTBOUND_TCP`].
    tcp_time_wait: AtomicUsize,
    tcp6_time_wait: AtomicUsize,
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
    /// Which host destinations the guests may reach; `None` allows all.
    filter: RwLock<Option<DestFilter>>,
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
            tcp_time_wait: AtomicUsize::new(0),
            tcp6_time_wait: AtomicUsize::new(0),
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
            filter: RwLock::new(None),
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
                reap_closed(&inner.tcp);
                reap_closed(&inner.tcp6);
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
                tick_outbound(&inner.tcp, &inner.tcp_time_wait);
                tick_outbound(&inner.tcp6, &inner.tcp6_time_wait);
                drop(inner);
            }
        });

        Arc::new(Stack { inner })
    }

    /// Open a virtual listener on the stack. Inbound SYNs destined for the
    /// registered (IP, port) are passive-opened against the in-tree vtcp
    /// engine; [`Listener::accept`] yields a [`TcpStream`](super::TcpStream)
    /// once the handshake completes.
    ///
    /// `network` must be `"tcp"` or `"tcp4"` (else `Unsupported`), and
    /// `address` is `"ip:port"`, or `":port"` for every address; for IPv6
    /// use [`listen6`](Self::listen6).
    ///
    /// A listener holds at most 128 connections in the middle of their
    /// handshake, as a listen backlog does, and at most 10 completed ones
    /// waiting for `accept`. A SYN that finds the handshakes at their cap, or
    /// the accept queue full or one short of it, is dropped for the peer to
    /// retransmit.
    ///
    /// Fails with `AddrInUse` if a live listener already has the address,
    /// and with `NotConnected` once the stack has been
    /// [`shutdown`](Self::shutdown).
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
                // Checked under the table lock that `shutdown` sets it under:
                // a listener registered after shutdown has collected the
                // table would never be closed, and its `accept` would wait
                // on a stack that will never feed it.
                if self.inner.closed.load(Ordering::Acquire) {
                    return Err(shut_down());
                }
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

    /// Open a virtual IPv6 TCP listener on the stack, the IPv6 counterpart
    /// of [`listen`](Self::listen); `address` is `"[ip]:port"`, or
    /// `"[]:port"` for every address.
    ///
    /// A listener holds at most 128 connections in the middle of their
    /// handshake, as a listen backlog does, and at most 10 completed ones
    /// waiting for `accept`. A SYN that finds the handshakes at their cap, or
    /// the accept queue full or one short of it, is dropped for the peer to
    /// retransmit.
    ///
    /// Fails with `AddrInUse` if a live listener already has the address,
    /// and with `NotConnected` once the stack has been
    /// [`shutdown`](Self::shutdown).
    pub fn listen6(&self, address: &str) -> Result<Arc<Listener6>> {
        let addr = resolve_v6(address)?;
        let listener = Arc::new(Listener6::new(addr));
        let key = ListenerKey6 {
            ip: addr.ip().octets(),
            port: addr.port(),
        };
        let mut m = self.inner.listeners6.lock().expect("poisoned");
        // See `listen`.
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(shut_down());
        }
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

    /// Restrict which host destinations the guests may reach.
    ///
    /// By default the stack relays to any address the host can reach,
    /// which includes the host's own loopback, link-local neighbours and
    /// cloud metadata endpoints (169.254.169.254). A filter decides instead.
    /// It is asked before each new TCP connection is dialed, and a refused
    /// one is reset as a closed port would be; and before each UDP datagram
    /// is sent, a refused one being dropped. Connections already open are
    /// not revisited. Virtual listeners ([`listen`](Self::listen)) are not
    /// host destinations and are never filtered.
    ///
    /// The filter sees the address that will actually be dialed, in
    /// canonical form: an IPv4-mapped IPv6 destination such as
    /// `::ffff:169.254.169.254` reaches it as `169.254.169.254`, so checks
    /// like [`Ipv4Addr::is_loopback`] or [`Ipv4Addr::is_link_local`] catch
    /// it. Unspecified destinations (`0.0.0.0`, `::`), which the host would
    /// treat as its own loopback, are refused before the filter runs, as are
    /// TCP connections to a multicast address or to the limited broadcast
    /// address `255.255.255.255`. A subnet's directed broadcast (such as
    /// `192.168.1.255`) is an ordinary address to the stack, which cannot
    /// know the host's subnets: a filter that should refuse one must do so
    /// itself.
    ///
    /// The filter runs on the packet path, so it should be quick, and must
    /// not call back into the stack. `None` allows everything again.
    pub fn set_dest_filter(&self, filter: Option<DestFilter>) {
        *self.inner.filter.write().expect("poisoned") = filter;
    }

    /// The host address to dial for a guest's `dest` over `proto`, or `None`
    /// if the guests may not reach it.
    ///
    /// The address is canonicalised first: an IPv4-mapped IPv6 destination
    /// (`::ffff:127.0.0.1`) is dialed by a dual-stack socket as the IPv4
    /// address it wraps, so the filter must judge, and the dial must use,
    /// that IPv4 address, or a filter refusing loopback is walked around in
    /// IPv6 clothing. An unspecified destination (`0.0.0.0`, `::`) is never
    /// relayed: the host's stack treats a connect or send to it as one to
    /// its own loopback, which is not somewhere a guest asked to go. Nor is
    /// a TCP connection to a multicast address or to `255.255.255.255`,
    /// which no peer can answer.
    fn dial_target(inner: &Inner, dest: SocketAddr, proto: Protocol) -> Option<SocketAddr> {
        let ip = dest.ip().to_canonical();
        if ip.is_unspecified() {
            return None;
        }
        if proto == Protocol::TCP && (ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST)) {
            return None;
        }
        let dest = SocketAddr::new(ip, dest.port());
        // Cloned out, so the filter never runs under the lock.
        let filter = inner.filter.read().expect("poisoned").clone();
        filter.is_none_or(|f| f(dest, proto)).then_some(dest)
    }

    /// Shut the stack down: close every listener and in-flight connection,
    /// and stop the maintenance thread.
    pub fn shutdown(&self) -> Result<()> {
        // A listener outlives the stack in the application's hands, and
        // nothing will ever feed its queue again: close it, or a thread
        // parked in `accept` waits forever. `closed` is set with both tables
        // locked, so a concurrent `listen` either registered before and is
        // collected here, or sees the flag and fails. Collected first, as
        // closing unregisters through these same table locks.
        let (listeners, listeners6) = {
            let m = self.inner.listeners.lock().expect("poisoned");
            let m6 = self.inner.listeners6.lock().expect("poisoned");
            self.inner.closed.store(true, Ordering::Release);
            let l: Vec<Arc<Listener>> = m.values().filter_map(Weak::upgrade).collect();
            let l6: Vec<Arc<Listener6>> = m6.values().filter_map(Weak::upgrade).collect();
            (l, l6)
        };
        for l in listeners {
            let _ = l.close();
        }
        for l in listeners6 {
            let _ = l.close();
        }
        Self::close_flows(&self.inner, |_| true);
        // Namespace sides point back at the stack; dropping them here breaks
        // that cycle for peers whose cleanup never runs.
        self.inner.ns_sides.lock().expect("poisoned").clear();
        Ok(())
    }

    /// Route a packet originating from the namespace `ns` to the right handler.
    /// `ns == 0` means the legacy single-peer path.
    fn dispatch(inner: &Arc<Inner>, ns: u64, pkt: &[u8]) -> Result<()> {
        let h = if ns == 0 {
            inner.handler.lock().expect("poisoned").clone()
        } else {
            let side = inner.ns_sides.lock().expect("poisoned").get(&ns).cloned();
            side.and_then(|s| s.handler.lock().expect("poisoned").clone())
        };
        match h {
            Some(h) => call_handler(&h, pkt),
            None => Ok(()),
        }
    }

    /// Dispatch a packet the stack built, fragmented to fit the link: an
    /// echo reply is as large as the (possibly reassembled) request.
    fn dispatch_fitted(inner: &Arc<Inner>, ns: u64, pkt: Vec<u8>) -> Result<()> {
        for p in fit_link(pkt) {
            Self::dispatch(inner, ns, &p)?;
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
            return Err(shut_down());
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
                    return Self::dispatch_fitted(inner, ns, reply);
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
        if !tcp_ok(src.into(), dst.into(), tcp) {
            return Ok(()); // corrupt: dropped, as RFC 9293 §3.1 asks
        }
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

        // 1) Existing inbound virtual TCP connection (vtcp-backed)? One in
        //    TIME-WAIT gives way to a new connection's SYN on its 4-tuple.
        let mut virt = inner.virt_tcp.lock().expect("poisoned").get(&key).cloned();
        if virt.as_ref().is_some_and(|st| takes_new_syn(&st.conn, tcp)) {
            inner.virt_tcp.lock().expect("poisoned").remove(&key);
            virt = None;
        }
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
        if opens_connection(flags) {
            let listener = Self::find_listener(inner, dst, dst_port);
            if let Some(listener) = listener {
                return Self::accept_syn_v4(inner, ns, tcp, src, dst, src_port, dst_port, listener);
            }
        }

        // 3) Existing outbound NAT connection? A new SYN may take over one in
        //    TIME-WAIT, as above.
        let mut existing = inner.tcp.lock().expect("poisoned").get(&key).cloned();
        if existing
            .as_ref()
            .is_some_and(|c| takes_new_syn(&c.state().conn, tcp))
        {
            inner.tcp.lock().expect("poisoned").remove(&key);
            existing = None;
        }
        if let Some(c) = existing {
            return c.handle_segment(tcp);
        }

        // Anything but a bare SYN to an unknown connection takes the
        // CLOSED-state path of RFC 9293 §3.10.7.1.
        if !opens_connection(flags) {
            if let Some(rst) = build_rst_for_stray(tcp, dst_port, src_port) {
                let pkt = crate::slirp::packet::build_packet4(dst, src, &rst);
                return Self::dispatch(inner, ns, &pkt);
            }
            return Ok(());
        }

        // A destination the filter refuses is refused as a closed port would
        // be, before anything reaches the host.
        let Some(dial) = Self::dial_target(
            inner,
            SocketAddr::V4(SocketAddrV4::new(dst, dst_port)),
            Protocol::TCP,
        ) else {
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let rst = build_refused_rst(src_port, dst_port, seq);
            let pkt = crate::slirp::packet::build_packet4(dst, src, &rst);
            return Self::dispatch(inner, ns, &pkt);
        };

        // SYN → dial the real destination and bridge it to a server-side
        // vtcp::Conn terminating the virtual side.
        if !outbound_slot_free(&inner.tcp, &inner.tcp_time_wait)
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
        Self::start_dial(inner, &conn, dial);
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
        // A full backlog drops the SYN, as Linux does: the peer retransmits,
        // and by then a slot may have freed up.
        let Some(slot) = listener.half_open_slot() else {
            return Ok(());
        };
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
            // Whatever becomes of the handshake, it is no longer half open.
            drop(slot);
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
        if !udp_datagram_ok(src.into(), dst.into(), udp) {
            return Ok(());
        }
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let key = Key {
            ns,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        if Self::dial_target(
            inner,
            SocketAddr::V4(SocketAddrV4::new(dst, dst_port)),
            Protocol::UDP,
        )
        .is_none()
        {
            return Ok(()); // refused by the filter: dropped
        }
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
        if ipv6_fragment_header(pkt).is_some() {
            let whole = inner
                .defrag
                .lock()
                .expect("poisoned")
                .reassemble(Instant::now(), ns, pkt);
            // Straight to the datagram path, never back through this one:
            // reassembly happens once, and a rebuilt packet that still
            // carries a Fragment header has already been dropped. Unwrapping
            // it again would recurse, and copy up to 64 KiB, once per
            // 8-byte header.
            return match whole {
                Some(p) => Self::handle_ipv6_datagram(inner, ns, &p),
                None => Ok(()),
            };
        }
        Self::handle_ipv6_datagram(inner, ns, pkt)
    }

    /// Dispatch a whole (unfragmented or reassembled) IPv6 packet.
    fn handle_ipv6_datagram(inner: &Arc<Inner>, ns: u64, pkt: &[u8]) -> Result<()> {
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
                    return Self::dispatch_fitted(inner, ns, reply);
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
        if !tcp_ok(src.into(), dst.into(), tcp) {
            return Ok(()); // corrupt: dropped, as RFC 9293 §3.1 asks
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

        // 1) Existing inbound virtual TCP connection (vtcp-backed)? One in
        //    TIME-WAIT gives way to a new connection's SYN on its 4-tuple.
        let mut virt = inner.virt_tcp6.lock().expect("poisoned").get(&key).cloned();
        if virt.as_ref().is_some_and(|st| takes_new_syn(&st.conn, tcp)) {
            inner.virt_tcp6.lock().expect("poisoned").remove(&key);
            virt = None;
        }
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
        if opens_connection(flags) {
            let listener = Self::find_listener6(inner, dst, dst_port);
            if let Some(listener) = listener {
                return Self::accept_syn_v6(inner, ns, tcp, src, dst, src_port, dst_port, listener);
            }
        }

        let mut existing = inner.tcp6.lock().expect("poisoned").get(&key).cloned();
        if existing
            .as_ref()
            .is_some_and(|c| takes_new_syn(&c.state().conn, tcp))
        {
            inner.tcp6.lock().expect("poisoned").remove(&key);
            existing = None;
        }
        if let Some(c) = existing {
            return c.handle_segment(tcp);
        }

        if !opens_connection(flags) {
            if let Some(rst) = build_rst_for_stray(tcp, dst_port, src_port) {
                let pkt = crate::slirp::packet::build_packet6(dst, src, &rst);
                return Self::dispatch(inner, ns, &pkt);
            }
            return Ok(());
        }

        // Refused as in the IPv4 path.
        let dest = SocketAddr::V6(SocketAddrV6::new(dst, dst_port, 0, 0));
        let Some(dial) = Self::dial_target(inner, dest, Protocol::TCP) else {
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let rst = build_refused_rst(src_port, dst_port, seq);
            let pkt = crate::slirp::packet::build_packet6(dst, src, &rst);
            return Self::dispatch(inner, ns, &pkt);
        };

        if !outbound_slot_free(&inner.tcp6, &inner.tcp6_time_wait)
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
        Self::start_dial(inner, &conn, dial);
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
        // A full backlog drops the SYN, as Linux does: the peer retransmits,
        // and by then a slot may have freed up.
        let Some(slot) = listener.half_open_slot() else {
            return Ok(());
        };
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
            // Whatever becomes of the handshake, it is no longer half open.
            drop(slot);
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
        if !udp_datagram_ok(src.into(), dst.into(), udp) {
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
        let dest = SocketAddr::V6(SocketAddrV6::new(dst, dst_port, 0, 0));
        let Some(dial) = Self::dial_target(inner, dest, Protocol::UDP) else {
            return Ok(()); // refused by the filter: dropped
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
                let conn = UdpConn6::new(src, src_port, dst, dst_port, dial, send_fn)?;
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
                // Flows first: the RSTs that closing them sends reach the
                // peer through its side, which must still be there.
                Stack::cleanup_namespace(&inner, ns);
                inner.ns_sides.lock().expect("poisoned").remove(&ns);
            }
            Ok(())
        }))
    }
}

/// Hand `pkt` to a user handler, containing a panic in it.
///
/// Most packets reach the handler from the stack's own threads: the tick
/// thread that drives the timers of every connection of every namespace, the
/// UDP readers, the dials and the byte pumps. Nothing joins or watches them,
/// so a panic unwinding out of one would end it for good, silently: one bad
/// packet would stop every retransmission and keepalive of the stack, or
/// leave a flow in the table that nobody reads. The panic costs that packet
/// only, and reads as an error to a caller that looks.
fn call_handler(h: &L3Handler, pkt: &[u8]) -> Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(Packet::from_slice(pkt))))
        .unwrap_or_else(|_| Err(io::Error::other("packet handler panicked")))
}

/// Whether a new outbound bridge may be opened in `table`. Bridges in
/// TIME-WAIT hold no thread and are bounded on their own, by
/// [`MAX_TIME_WAIT`]; the hard stop covers the entries that entered
/// TIME-WAIT, or left it, since the tick last counted them.
fn outbound_slot_free<K>(
    table: &Mutex<HashMap<K, Arc<TcpOutConn>>>,
    time_wait: &AtomicUsize,
) -> bool {
    let len = table.lock().expect("poisoned").len();
    len < MAX_OUTBOUND_TCP + MAX_TIME_WAIT
        && len.saturating_sub(time_wait.load(Ordering::Acquire)) < MAX_OUTBOUND_TCP
}

/// Drive the timers of every outbound bridge in `table`, reap those that
/// have torn down, and keep those in TIME-WAIT within [`MAX_TIME_WAIT`] by
/// dropping the oldest early.
fn tick_outbound<K: Copy + Eq + std::hash::Hash>(
    table: &Mutex<HashMap<K, Arc<TcpOutConn>>>,
    time_wait: &AtomicUsize,
) {
    let out: Vec<(K, Arc<TcpOutConn>)> = table
        .lock()
        .expect("poisoned")
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let now = Instant::now();
    let mut dead = Vec::new();
    let mut waiting = Vec::new();
    for (k, c) in out {
        tick_conn(c.state());
        if c.is_closed() {
            dead.push((k, c));
        } else if let Some(since) = c.time_wait_since(now) {
            waiting.push((since, k, c));
        }
    }
    if waiting.len() > MAX_TIME_WAIT {
        waiting.sort_by_key(|w| w.0);
        let excess = waiting.len() - MAX_TIME_WAIT;
        dead.extend(waiting.drain(..excess).map(|(_, k, c)| (k, c)));
    }
    time_wait.store(waiting.len(), Ordering::Release);
    if dead.is_empty() {
        return;
    }
    let gone: Vec<Arc<TcpOutConn>> = {
        let mut t = table.lock().expect("poisoned");
        dead.into_iter()
            // A new connection may have taken the 4-tuple over meanwhile.
            .filter_map(|(k, c)| {
                t.get(&k)
                    .is_some_and(|x| Arc::ptr_eq(x, &c))
                    .then(|| t.remove(&k))
                    .flatten()
            })
            .collect()
    };
    // Closing shuts the real socket, which is what ends a pump still
    // blocked reading it; outside the table lock, as close() may emit and
    // so re-enter `send`.
    for c in gone {
        c.close();
    }
}

/// Remove the bridges in `table` that have torn down, and close them.
///
/// Closing, not merely dropping: a bridge whose engine reached CLOSED may
/// still have a pump blocked on the real socket (reading from a server that
/// never ends, or writing to one that never reads), and that pump holds the
/// bridge alive. Only shutting the socket down frees it; dropping the table's
/// handle would leave the pump, its thread and the descriptor stuck.
fn reap_closed<K: Copy + Eq + std::hash::Hash>(table: &Mutex<HashMap<K, Arc<TcpOutConn>>>) {
    let gone: Vec<Arc<TcpOutConn>> = {
        let Ok(mut t) = table.lock() else {
            return;
        };
        let keys: Vec<K> = t
            .iter()
            .filter(|(_, c)| c.is_closed())
            .map(|(k, _)| *k)
            .collect();
        keys.iter().filter_map(|k| t.remove(k)).collect()
    };
    // Outside the table lock, as close() may emit and so re-enter `send`.
    for c in gone {
        c.close();
    }
}

/// Whether the UDP datagram at the start of `udp` (an IP payload) is sound:
/// its length fits, and its checksum holds (see [`udp_ok`]). Checked before
/// a flow is looked up, so a corrupt datagram neither reaches the host nor
/// opens a socket there.
fn udp_datagram_ok(src: std::net::IpAddr, dst: std::net::IpAddr, udp: &[u8]) -> bool {
    // The UDP length, not the IP payload, bounds the datagram: anything
    // past it is link padding, and outside the checksum.
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    (8..=udp.len()).contains(&len) && udp_ok(src, dst, &udp[..len])
}

/// Whether a segment with these flags, to a 4-tuple with no connection,
/// opens one. Only a bare SYN does: a SYN that also carries ACK answers a
/// handshake we never started, and one with RST or FIN is not an opener
/// either (RFC 9293 §3.10.7.1–2). Treating those as SYNs would let a stray
/// or forged segment dial a real host or mint a SYN-RECEIVED connection.
fn opens_connection(flags: u8) -> bool {
    use tcp_flags::{ACK, FIN, RST, SYN};
    flags & (SYN | ACK | RST | FIN) == SYN
}

/// Whether `tcp` is a new connection's SYN that may take over `conn`'s
/// 4-tuple, the old connection being in TIME-WAIT (see
/// [`Conn::accepts_new_syn`](crate::vtcp::Conn::accepts_new_syn)).
fn takes_new_syn(conn: &Mutex<crate::vtcp::Conn>, tcp: &[u8]) -> bool {
    Segment::parse(tcp).is_ok_and(|seg| conn.lock().expect("poisoned").accepts_new_syn(&seg))
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
        let cs = crate::slirp::checksum::tcp_v4_checksum(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 1),
            &p[ihl..],
        );
        p[ihl + 16..ihl + 18].copy_from_slice(&cs.to_be_bytes());
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

    /// A peer device that records what the stack sends it.
    #[derive(Default)]
    struct Recorder {
        handler: Mutex<Option<L3Handler>>,
        got: Mutex<Vec<Vec<u8>>>,
    }

    impl core::fmt::Debug for Recorder {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("Recorder")
        }
    }

    impl L3Device for Recorder {
        fn set_handler(&self, h: L3Handler) {
            *self.handler.lock().unwrap() = Some(h);
        }
        fn send(&self, p: &Packet) -> Result<()> {
            self.got.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }
        fn addr(&self) -> IpPrefix {
            IpPrefix::default()
        }
        fn set_addr(&self, _: IpPrefix) -> Result<()> {
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn detaching_a_peer_resets_its_connections() {
        let s = Stack::new();
        let _listener = s.listen("tcp", "10.0.0.1:80").unwrap();
        let peer = Arc::new(Recorder::default());
        let cleanup = L3Connector::connect_l3(&*s, peer.clone()).unwrap();
        let syn = Segment {
            src_port: 40000,
            dst_port: 80,
            seq: 1000,
            flags: tcp_flags::SYN,
            window: 65535,
            ..Default::default()
        };
        let pkt = crate::slirp::packet::build_packet4(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 1),
            &syn.marshal(),
        );
        let inject = peer.handler.lock().unwrap().clone().unwrap();
        inject(Packet::from_slice(&pkt)).unwrap();
        assert_eq!(peer.got.lock().unwrap().len(), 1, "SYN-ACK");

        cleanup().unwrap();
        let got = peer.got.lock().unwrap();
        let last = Segment::parse(&got.last().unwrap()[20..]).unwrap();
        assert!(last.has_flag(tcp_flags::RST), "no RST reached the peer");
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

    /// A SYN retransmitted just as the dial completes belongs to the
    /// handshake under way: it must never meet the engine before the
    /// handshake has started, which answers it with a RST.
    #[test]
    fn syn_retransmitted_as_the_dial_completes_is_not_reset() {
        use std::net::TcpListener;
        use std::sync::atomic::AtomicBool;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut held = Vec::new();
            for s in listener.incoming() {
                held.push(s);
            }
        });
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(127, 0, 0, 1);
        for round in 0..50u16 {
            let stack = Stack::new();
            let resets = Arc::new(AtomicUsize::new(0));
            let r = resets.clone();
            stack.set_handler(Arc::new(move |p: &Packet| {
                if Segment::parse(&p.as_bytes()[20..]).is_ok_and(|s| s.has_flag(tcp_flags::RST)) {
                    r.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            }));
            let mut vc = Conn::new(ConnConfig {
                local_port: 40000 + round,
                remote_port: port,
                mss: 1460,
                ..Default::default()
            });
            let syn = crate::slirp::packet::build_packet4(client, server, &vc.connect()[0]);
            let done = Arc::new(AtomicBool::new(false));
            let spammer = {
                let (stack, syn, done) = (stack.clone(), syn.clone(), done.clone());
                thread::spawn(move || {
                    while !done.load(Ordering::SeqCst) {
                        let _ = stack.send(Packet::from_slice(&syn));
                    }
                })
            };
            wait_for("the SYN-ACK", || {
                let bridge = stack.inner.tcp.lock().unwrap().values().next().cloned();
                bridge.is_some_and(|b| b.state().conn.lock().unwrap().state() != VtcpState::Closed)
            });
            done.store(true, Ordering::SeqCst);
            spammer.join().unwrap();
            assert_eq!(resets.load(Ordering::SeqCst), 0, "round {round}");
        }
    }

    #[test]
    fn client_reset_tears_the_whole_bridge_down() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        // A server that neither sends nor closes: only the bridge closing
        // its socket can end the remote→client pump's read.
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
        let vc = wire_vtcp_client(&stack, client, server, 50003, port);
        let syn = vc.lock().unwrap().connect();
        inject_segs(&stack, client, server, syn);
        wait_for("ESTABLISHED", || {
            vc.lock().unwrap().state() == VtcpState::Established
        });
        let mut held = held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let bridge = stack.inner.tcp.lock().unwrap().values().next().cloned();
        let bridge = bridge.expect("bridge registered");

        let rst = vc.lock().unwrap().abort();
        inject_segs(&stack, client, server, rst);

        // The pumps let go of the bridge, and the real socket is closed
        // outright rather than half-closed.
        wait_for("the pump threads to exit", || {
            Arc::strong_count(&bridge) == 1
        });
        assert!(stack.inner.tcp.lock().unwrap().is_empty());
        held.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(std::io::Read::read(&mut held, &mut buf).unwrap(), 0);
    }

    #[test]
    fn time_wait_bridges_do_not_hold_live_connection_slots() {
        use std::net::TcpListener;

        // A server that closes first, which leaves each bridge in TIME-WAIT.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for s in listener.incoming() {
                drop(s);
            }
        });

        let stack = Stack::new();
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(127, 0, 0, 1);
        type Clients = Arc<Mutex<HashMap<u16, Arc<Mutex<Conn>>>>>;
        let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
        let weak = Arc::downgrade(&stack);
        let routes = clients.clone();
        stack.set_handler(Arc::new(move |p: &Packet| {
            let bytes = p.as_bytes();
            let Ok(seg) = Segment::parse(&bytes[20..]) else {
                return Ok(());
            };
            let conn = routes.lock().unwrap().get(&seg.dst_port).cloned();
            let Some(conn) = conn else { return Ok(()) };
            let replies = conn.lock().unwrap().handle_segment(&seg);
            if let Some(stack) = weak.upgrade() {
                inject_segs(&stack, client, server, replies);
            }
            Ok(())
        }));

        let open = |cport: u16| {
            let conn = Arc::new(Mutex::new(Conn::new(ConnConfig {
                local_port: cport,
                remote_port: port,
                mss: 1460,
                ..Default::default()
            })));
            clients.lock().unwrap().insert(cport, conn.clone());
            let syn = conn.lock().unwrap().connect();
            inject_segs(&stack, client, server, syn);
            conn
        };
        let bridges_in_time_wait = || {
            let t = stack.inner.tcp.lock().unwrap();
            t.values()
                .filter(|c| c.state().conn.lock().unwrap().state() == VtcpState::TimeWait)
                .count()
        };

        // More connections than there are live slots, each closed by the
        // server and then by the client.
        for i in 0..(MAX_OUTBOUND_TCP + MAX_TIME_WAIT) as u16 {
            let conn = open(51000 + i);
            wait_for(&format!("the server's FIN on connection {i}"), || {
                // A SYN dropped before the stack counted the last TIME-WAIT
                // entry is retransmitted.
                let segs = conn.lock().unwrap().tick();
                inject_segs(&stack, client, server, segs);
                conn.lock().unwrap().fin_received()
            });
            let fin = conn.lock().unwrap().close();
            inject_segs(&stack, client, server, fin);
            // The client closes once the bridge ACKs its FIN, which puts the
            // bridge in TIME-WAIT.
            wait_for("TIME-WAIT", || conn.lock().unwrap().is_closed());
        }

        // Another connection still gets through, and the TIME-WAIT entries
        // themselves stay bounded.
        let conn = open(52000);
        wait_for("ESTABLISHED", || {
            let segs = conn.lock().unwrap().tick();
            inject_segs(&stack, client, server, segs);
            conn.lock().unwrap().is_established()
        });
        wait_for("TIME-WAIT to be bounded", || {
            bridges_in_time_wait() <= MAX_TIME_WAIT
        });
        // A parked bridge has closed its real socket: host descriptors are
        // bounded by live connections, not by TIME-WAIT.
        wait_for("TIME-WAIT bridges to release their sockets", || {
            let t = stack.inner.tcp.lock().unwrap();
            t.values()
                .filter(|c| c.state().conn.lock().unwrap().state() == VtcpState::TimeWait)
                .all(|c| c.remote.lock().unwrap().is_none())
        });
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

        let mut r = crate::defrag::Reassembler::default();
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

    /// An IPv6 echo request to `fd00::1` whose Fragmentable Part starts with
    /// `inner` (extension headers, `next` naming what follows them), padded
    /// so it needs fragmenting; returned as the fragments the guest sends.
    fn v6_echo_behind(first_next: u8, inner: &[u8], pad: usize) -> Vec<Vec<u8>> {
        let mut body = inner.to_vec();
        body.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);
        body.resize(body.len() + pad, 0x5A);
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
        p[6] = first_next;
        p[7] = 64;
        p[8..24].copy_from_slice(&"fd00::5".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&body);
        crate::slirp::packet::fit_link(p)
    }

    #[test]
    fn large_echo_replies_fit_the_link() {
        use crate::fragment::{Fragmentation, fragment_ipv4};
        use crate::slirp::packet::LINK_MTU;

        // Reassemble what the stack sent, checking every piece fits.
        let collect = |captured: &Arc<Mutex<Vec<Vec<u8>>>>| {
            let mut r = Reassembler::default();
            let mut whole = None;
            for p in captured.lock().unwrap().drain(..) {
                assert!(p.len() <= LINK_MTU, "{}-byte packet sent", p.len());
                if let Some(w) = r.reassemble(Instant::now(), 0, &p) {
                    whole = Some(w.into_owned());
                }
            }
            whole.expect("a whole reply")
        };

        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
            .unwrap();
        let captured = capture(&s);
        let mut echo = make_v4_icmp_echo(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1));
        echo.resize(4000, 0x33);
        echo[2..4].copy_from_slice(&4000u16.to_be_bytes());
        echo[4..6].copy_from_slice(&0x99u16.to_be_bytes());
        echo[22..24].copy_from_slice(&[0, 0]);
        let cs = super::super::checksum::internet_checksum(&echo[20..]);
        echo[22..24].copy_from_slice(&cs.to_be_bytes());
        echo[10..12].copy_from_slice(&[0, 0]);
        let cs = ipv4_header_checksum(&echo[..20]);
        echo[10..12].copy_from_slice(&cs.to_be_bytes());
        let Fragmentation::Fragments(frags) = fragment_ipv4(Packet::from_slice(&echo), 1500) else {
            panic!("expected fragments");
        };
        for f in &frags {
            L3Device::send(&*s, Packet::from_slice(f)).unwrap();
        }
        let reply = collect(&captured);
        assert_eq!(reply[20], 0, "echo reply");
        assert_eq!(reply[28..], echo[28..]);

        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V6("fd00::1".parse().unwrap()), 64))
            .unwrap();
        let captured = capture(&s);
        for f in v6_echo_behind(58, &[], 3000) {
            L3Device::send(&*s, Packet::from_slice(&f)).unwrap();
        }
        let reply = collect(&captured);
        assert_eq!(reply[40], 129, "echo reply");
        assert_eq!(reply.len(), 40 + 8 + 3000);
    }

    #[test]
    fn fragment_header_after_a_fragment_header_is_dropped() {
        let s = Stack::new();
        s.set_addr(IpPrefix::new(IpAddr::V6("fd00::1".parse().unwrap()), 64))
            .unwrap();
        let captured = capture(&s);
        // Reassembled, this is a packet that is itself an atomic fragment:
        // reassembly happens once (RFC 8200 §4.5), so it must not be
        // unwrapped again.
        let atomic = [58, 0, 0, 0, 0, 0, 0, 9];
        for f in v6_echo_behind(44, &atomic, 3000) {
            L3Device::send(&*s, Packet::from_slice(&f)).unwrap();
        }
        assert!(captured.lock().unwrap().is_empty(), "nested fragment used");

        // A long chain of them must neither recurse nor copy per level.
        let chain: Vec<u8> = (0..8000)
            .flat_map(|i| {
                let next = if i == 7999 { 58 } else { 44 };
                [next, 0, 0, 0, 0, 0, 0, 9]
            })
            .collect();
        for f in v6_echo_behind(44, &chain, 0) {
            L3Device::send(&*s, Packet::from_slice(&f)).unwrap();
        }
        assert!(captured.lock().unwrap().is_empty());

        // The same echo fragmented once is answered.
        for f in v6_echo_behind(58, &[], 3000) {
            L3Device::send(&*s, Packet::from_slice(&f)).unwrap();
        }
        assert!(!captured.lock().unwrap().is_empty());
    }

    #[test]
    fn listen_after_shutdown_fails() {
        let s = Stack::new();
        s.shutdown().unwrap();
        let err = s.listen("tcp", "10.0.0.1:80").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        let err = s.listen6("[fd00::1]:80").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn shutdown_wakes_threads_blocked_in_accept() {
        use std::sync::mpsc;
        let s = Stack::new();
        let l = s.listen("tcp", "10.0.0.1:80").unwrap();
        let l6 = s.listen6("[fd00::1]:80").unwrap();
        let (tx, rx) = mpsc::channel();
        let tx6 = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(l.accept().is_err());
        });
        thread::spawn(move || {
            let _ = tx6.send(l6.accept().is_err());
        });
        // Let both threads park in accept before the stack goes away.
        thread::sleep(Duration::from_millis(50));
        drop(s);
        for _ in 0..2 {
            let failed = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("accept still blocked after the stack shut down");
            assert!(failed);
        }
    }

    #[test]
    fn segments_and_datagrams_with_bad_checksums_are_dropped() {
        let s = Stack::new();
        let _l = s.listen("tcp", "10.0.0.1:80").unwrap();
        let _l6 = s.listen6("[fd00::1]:80").unwrap();
        let captured = capture(&s);
        let (client, us) = (Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1));
        let (c6, us6): (Ipv6Addr, Ipv6Addr) =
            ("fd00::5".parse().unwrap(), "fd00::1".parse().unwrap());
        let inject = |p: &[u8]| L3Device::send(&*s, Packet::from_slice(p)).unwrap();
        let send = |p: &mut Vec<u8>, at: usize| {
            p[at] ^= 0x01;
            inject(p);
        };

        let mut syn = build_tcp_v4_packet(client, 40000, us, 80, 1, 0, tcp_flags::SYN, &[]);
        send(&mut syn, 37); // checksum's low byte
        let syn6 = Segment {
            src_port: 40000,
            dst_port: 80,
            seq: 1,
            flags: tcp_flags::SYN,
            ..Default::default()
        };
        let mut syn6 = crate::slirp::packet::build_packet6(c6, us6, &syn6.marshal());
        send(&mut syn6, 45); // sequence number
        assert!(s.inner.virt_tcp.lock().unwrap().is_empty());
        assert!(s.inner.virt_tcp6.lock().unwrap().is_empty());
        assert!(
            captured.lock().unwrap().is_empty(),
            "answered a corrupt SYN"
        );

        let lo = Ipv4Addr::LOCALHOST;
        let mut dgram = build_udp_v4_packet(client, 40000, lo, 9, b"hello");
        send(&mut dgram, 30); // payload
        let mut dgram6 =
            crate::slirp::packet::build_udp_packet6(c6, 40000, Ipv6Addr::LOCALHOST, 9, b"hello");
        send(&mut dgram6, 50);
        // Over IPv6 a zero checksum is invalid too.
        let mut dgram6 =
            crate::slirp::packet::build_udp_packet6(c6, 40001, Ipv6Addr::LOCALHOST, 9, b"hello");
        dgram6[46..48].copy_from_slice(&[0, 0]);
        inject(&dgram6);
        assert!(s.inner.udp.lock().unwrap().is_empty(), "v4 flow opened");
        assert!(s.inner.udp6.lock().unwrap().is_empty(), "v6 flow opened");

        // Over IPv4 it means "no checksum", and the datagram goes through.
        let mut dgram = build_udp_v4_packet(client, 40001, lo, 9, b"hello");
        dgram[26..28].copy_from_slice(&[0, 0]);
        inject(&dgram);
        assert_eq!(s.inner.udp.lock().unwrap().len(), 1);
    }

    #[test]
    fn half_open_connections_per_listener_are_capped() {
        use crate::slirp::listener::HALF_OPEN_CAP;
        let s = Stack::new();
        let _l = s.listen("tcp", "10.0.0.1:80").unwrap();
        let _l6 = s.listen6("[fd00::1]:80").unwrap();
        let _captured = capture(&s);
        let (client, us) = (Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1));
        let (c6, us6): (Ipv6Addr, Ipv6Addr) =
            ("fd00::5".parse().unwrap(), "fd00::1".parse().unwrap());
        let seg = |port: u16, flags: u8| Segment {
            src_port: port,
            dst_port: 80,
            seq: 1000,
            flags,
            ..Default::default()
        };
        let inject = |p: Vec<u8>| L3Device::send(&*s, Packet::from_slice(&p)).unwrap();
        for port in 0..(HALF_OPEN_CAP as u16 + 50) {
            let syn = seg(10000 + port, tcp_flags::SYN).marshal();
            inject(crate::slirp::packet::build_packet4(client, us, &syn));
            inject(crate::slirp::packet::build_packet6(c6, us6, &syn));
        }
        assert_eq!(s.inner.virt_tcp.lock().unwrap().len(), HALF_OPEN_CAP);
        assert_eq!(s.inner.virt_tcp6.lock().unwrap().len(), HALF_OPEN_CAP);

        // A handshake that ends gives its slot back.
        let mut rst = seg(10000, tcp_flags::RST);
        rst.seq = 1001;
        inject(crate::slirp::packet::build_packet4(
            client,
            us,
            &rst.marshal(),
        ));
        wait_for("the reset connection to be reaped", || {
            s.inner.virt_tcp.lock().unwrap().len() < HALF_OPEN_CAP
        });
        let syn = seg(20000, tcp_flags::SYN).marshal();
        inject(crate::slirp::packet::build_packet4(client, us, &syn));
        assert_eq!(s.inner.virt_tcp.lock().unwrap().len(), HALF_OPEN_CAP);
    }

    #[test]
    fn dest_filter_refuses_tcp_with_a_reset_and_drops_udp() {
        let real_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        real_udp
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let uport = real_udp.local_addr().unwrap().port();
        let s = Stack::new();
        let captured = capture(&s);
        let asked: Arc<Mutex<Vec<(SocketAddr, Protocol)>>> = Arc::default();
        let a = asked.clone();
        s.set_dest_filter(Some(Arc::new(move |dest: SocketAddr, proto| {
            a.lock().unwrap().push((dest, proto));
            !dest.ip().is_loopback()
        })));
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let lo = Ipv4Addr::LOCALHOST;

        let syn = build_tcp_v4_packet(client, 40000, lo, 22, 7000, 0, tcp_flags::SYN, &[]);
        L3Device::send(&*s, Packet::from_slice(&syn)).unwrap();
        assert!(s.inner.tcp.lock().unwrap().is_empty(), "dialed the host");
        let got = captured.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        let rst = Segment::parse(&got[0][20..]).unwrap();
        assert_eq!(rst.flags, tcp_flags::RST | tcp_flags::ACK);
        assert_eq!(rst.ack, 7001);

        let dgram = build_udp_v4_packet(client, 40000, lo, uport, b"hello");
        L3Device::send(&*s, Packet::from_slice(&dgram)).unwrap();
        assert!(s.inner.udp.lock().unwrap().is_empty(), "opened a UDP flow");
        assert!(real_udp.recv_from(&mut [0u8; 16]).is_err(), "datagram sent");

        let lo_addr = |port| SocketAddr::V4(SocketAddrV4::new(lo, port));
        assert_eq!(
            *asked.lock().unwrap(),
            [
                (lo_addr(22), Protocol::TCP),
                (lo_addr(uport), Protocol::UDP)
            ]
        );

        // Allowed again, the same datagram goes through.
        s.set_dest_filter(None);
        L3Device::send(&*s, Packet::from_slice(&dgram)).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = real_udp.recv_from(&mut buf).expect("datagram relayed");
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn dest_filter_sees_mapped_addresses_in_canonical_form() {
        let real_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        real_udp
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let uport = real_udp.local_addr().unwrap().port();
        let s = Stack::new();
        let captured = capture(&s);
        let asked: Arc<Mutex<Vec<(SocketAddr, Protocol)>>> = Arc::default();
        let a = asked.clone();
        let refuse = Arc::new(AtomicBool::new(true));
        let r = refuse.clone();
        s.set_dest_filter(Some(Arc::new(move |dest: SocketAddr, proto| {
            a.lock().unwrap().push((dest, proto));
            !(r.load(Ordering::SeqCst) && dest.ip().is_loopback())
        })));
        let client: Ipv6Addr = "fd00::5".parse().unwrap();
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let syn = Segment {
            src_port: 40000,
            dst_port: 22,
            seq: 7000,
            flags: tcp_flags::SYN,
            ..Default::default()
        };
        let p = crate::slirp::packet::build_packet6(client, mapped, &syn.marshal());
        L3Device::send(&*s, Packet::from_slice(&p)).unwrap();
        assert!(s.inner.tcp6.lock().unwrap().is_empty(), "dialed the host");
        let got = captured.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        let rst = Segment::parse(&got[0][40..]).unwrap();
        assert_eq!(rst.flags, tcp_flags::RST | tcp_flags::ACK);

        let dgram = crate::slirp::packet::build_udp_packet6(client, 40000, mapped, uport, b"hi");
        L3Device::send(&*s, Packet::from_slice(&dgram)).unwrap();
        assert!(s.inner.udp6.lock().unwrap().is_empty(), "opened a flow");
        assert!(real_udp.recv_from(&mut [0u8; 16]).is_err(), "datagram sent");

        let lo = |port| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        assert_eq!(
            *asked.lock().unwrap(),
            [(lo(22), Protocol::TCP), (lo(uport), Protocol::UDP)]
        );

        // Allowed, the mapped destination is reached over IPv4, and the
        // answer comes back from the address the guest used.
        refuse.store(false, Ordering::SeqCst);
        captured.lock().unwrap().clear();
        L3Device::send(&*s, Packet::from_slice(&dgram)).unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = real_udp.recv_from(&mut buf).expect("datagram relayed");
        assert_eq!(&buf[..n], b"hi");
        real_udp.send_to(b"yo", from).unwrap();
        wait_for("the reply", || !captured.lock().unwrap().is_empty());
        let reply = captured.lock().unwrap()[0].clone();
        assert_eq!(reply[0] >> 4, 6);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&reply[8..24]).unwrap()),
            mapped
        );
        assert_eq!(&reply[48..], b"yo");
    }

    #[test]
    fn unspecified_and_group_destinations_are_never_dialed() {
        let s = Stack::new();
        let captured = capture(&s);
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let client6: Ipv6Addr = "fd00::5".parse().unwrap();
        let syn = |port| {
            Segment {
                src_port: 40000,
                dst_port: port,
                seq: 7000,
                flags: tcp_flags::SYN,
                ..Default::default()
            }
            .marshal()
        };
        // No filter at all: these are refused regardless.
        for dst in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            let p = crate::slirp::packet::build_packet4(client, dst, &syn(22));
            L3Device::send(&*s, Packet::from_slice(&p)).unwrap();
        }
        for dst in [
            Ipv6Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
            "ff02::1".parse().unwrap(),
        ] {
            let p = crate::slirp::packet::build_packet6(client6, dst, &syn(22));
            L3Device::send(&*s, Packet::from_slice(&p)).unwrap();
        }
        assert!(s.inner.tcp.lock().unwrap().is_empty(), "dialed over v4");
        assert!(s.inner.tcp6.lock().unwrap().is_empty(), "dialed over v6");
        let got = captured.lock().unwrap().clone();
        assert_eq!(got.len(), 6);
        for p in &got {
            let off = if p[0] >> 4 == 4 { 20 } else { 40 };
            let rst = Segment::parse(&p[off..]).unwrap();
            assert_eq!(rst.flags, tcp_flags::RST | tcp_flags::ACK);
        }

        let d4 = build_udp_v4_packet(client, 40000, Ipv4Addr::UNSPECIFIED, 53, b"x");
        L3Device::send(&*s, Packet::from_slice(&d4)).unwrap();
        let d6 = crate::slirp::packet::build_udp_packet6(
            client6,
            40000,
            Ipv6Addr::UNSPECIFIED,
            53,
            b"x",
        );
        L3Device::send(&*s, Packet::from_slice(&d6)).unwrap();
        assert!(s.inner.udp.lock().unwrap().is_empty(), "opened a v4 flow");
        assert!(s.inner.udp6.lock().unwrap().is_empty(), "opened a v6 flow");
    }

    #[test]
    fn only_a_bare_syn_opens_a_connection() {
        let real = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let rport = real.local_addr().unwrap().port();
        let s = Stack::new();
        let _l = s.listen("tcp", "10.0.0.1:80").unwrap();
        let _l6 = s.listen6("[fd00::1]:80").unwrap();
        let captured = capture(&s);
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let (c6, us6): (Ipv6Addr, Ipv6Addr) =
            ("fd00::5".parse().unwrap(), "fd00::1".parse().unwrap());
        let seg = |port: u16, flags: u8| Segment {
            src_port: 40000,
            dst_port: port,
            seq: 1000,
            ack: 5000,
            flags,
            ..Default::default()
        };
        for flags in [
            tcp_flags::SYN | tcp_flags::ACK,
            tcp_flags::SYN | tcp_flags::FIN,
        ] {
            for (dst, port) in [
                (Ipv4Addr::new(10, 0, 0, 1), 80),
                (Ipv4Addr::LOCALHOST, rport),
            ] {
                let p =
                    crate::slirp::packet::build_packet4(client, dst, &seg(port, flags).marshal());
                L3Device::send(&*s, Packet::from_slice(&p)).unwrap();
            }
            let p = crate::slirp::packet::build_packet6(c6, us6, &seg(80, flags).marshal());
            L3Device::send(&*s, Packet::from_slice(&p)).unwrap();
        }
        assert!(s.inner.tcp.lock().unwrap().is_empty(), "dialed the host");
        assert!(
            s.inner.virt_tcp.lock().unwrap().is_empty(),
            "minted a v4 conn"
        );
        assert!(
            s.inner.virt_tcp6.lock().unwrap().is_empty(),
            "minted a v6 conn"
        );
        // Each is refused as a stray segment: with SEQ=SEG.ACK when it
        // carries an ACK, else acknowledging its SYN and FIN.
        let got = captured.lock().unwrap();
        assert_eq!(got.len(), 6);
        for (i, p) in got.iter().enumerate() {
            let off = if p[0] >> 4 == 4 { 20 } else { 40 };
            let rst = Segment::parse(&p[off..]).unwrap();
            if i < 3 {
                assert_eq!((rst.flags, rst.seq), (tcp_flags::RST, 5000));
            } else {
                assert_eq!(rst.flags, tcp_flags::RST | tcp_flags::ACK);
                assert_eq!(rst.ack, 1002);
            }
        }
    }

    /// A handler that panics once, on one of the stack's own threads, must
    /// cost that packet only: the tick thread serves every connection of
    /// every namespace, and must keep retransmitting after it.
    #[test]
    fn handler_panic_does_not_kill_the_tick_thread() {
        let stack = Stack::new();
        let from_bg = Arc::new(AtomicUsize::new(0));
        let panicked = Arc::new(AtomicBool::new(false));
        let (fb, pk) = (from_bg.clone(), panicked.clone());
        stack.set_handler(Arc::new(move |_p: &Packet| {
            // The test's own thread is named; the stack's are not.
            if thread::current().name().is_none() {
                if !pk.swap(true, Ordering::SeqCst) {
                    panic!("handler bug, once");
                }
                fb.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }));
        let _l = stack.listen("tcp", "10.0.0.1:8080").unwrap();
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(10, 0, 0, 1);
        // Unanswered SYN-ACKs, which only the tick thread retransmits.
        let syn = build_tcp_v4_packet(client, 40030, server, 8080, 500, 0, tcp_flags::SYN, &[]);
        L3Device::send(&*stack, Packet::from_slice(&syn)).unwrap();
        wait_for("the panic", || panicked.load(Ordering::SeqCst));
        let syn = build_tcp_v4_packet(client, 40031, server, 8080, 900, 0, tcp_flags::SYN, &[]);
        L3Device::send(&*stack, Packet::from_slice(&syn)).unwrap();
        wait_for("a retransmission after the panic", || {
            from_bg.load(Ordering::SeqCst) > 0
        });
    }

    /// Likewise for a UDP flow's reader thread: a panic in the handler must
    /// not leave the flow in the table with nobody reading its replies.
    #[test]
    fn handler_panic_does_not_blackhole_a_udp_flow() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sport = server.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut b = [0u8; 1500];
            while let Ok((n, a)) = server.recv_from(&mut b) {
                let _ = server.send_to(&b[..n], a);
            }
        });
        let stack = Stack::new();
        let got = Arc::new(AtomicUsize::new(0));
        let panicked = Arc::new(AtomicBool::new(false));
        let (g, pk) = (got.clone(), panicked.clone());
        stack.set_handler(Arc::new(move |_p: &Packet| {
            if !pk.swap(true, Ordering::SeqCst) {
                panic!("handler bug, once");
            }
            g.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        let pkt = build_udp_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            5555,
            Ipv4Addr::new(127, 0, 0, 1),
            sport,
            b"a",
        );
        L3Device::send(&*stack, Packet::from_slice(&pkt)).unwrap();
        wait_for("the panic", || panicked.load(Ordering::SeqCst));
        wait_for("a reply after the panic", || {
            L3Device::send(&*stack, Packet::from_slice(&pkt)).unwrap();
            thread::sleep(Duration::from_millis(50));
            got.load(Ordering::SeqCst) > 0
        });
    }

    /// A bridge reaching TIME-WAIT while its client→remote pump is blocked
    /// writing to a server that stopped reading must not leave that pump,
    /// and the socket it holds, stuck for good: whatever reaps the bridge
    /// has to be able to shut the socket down.
    #[test]
    fn time_wait_does_not_strand_a_blocked_pump() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        // A server that ends its side at once and never reads.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (held_tx, held_rx) = mpsc::channel();
        thread::spawn(move || {
            if let Ok((s, _)) = listener.accept() {
                s.shutdown(std::net::Shutdown::Write).unwrap();
                let _ = held_tx.send(s);
            }
        });
        let stack = Stack::new();
        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(127, 0, 0, 1);
        let vc = Arc::new(Mutex::new(Conn::new(ConnConfig {
            local_port: 50077,
            remote_port: port,
            mss: 1460,
            ..Default::default()
        })));
        // The window the bridge last advertised.
        let win = Arc::new(AtomicUsize::new(0));
        let (w2, c2, weak) = (win.clone(), vc.clone(), Arc::downgrade(&stack));
        stack.set_handler(Arc::new(move |p: &Packet| {
            let Ok(seg) = Segment::parse(&p.as_bytes()[20..]) else {
                return Ok(());
            };
            if seg.flags & tcp_flags::SYN == 0 {
                w2.store(seg.window as usize, Ordering::SeqCst);
            }
            let replies = c2.lock().unwrap().handle_segment(&seg);
            if let Some(s) = weak.upgrade() {
                inject_segs(&s, client, server, replies);
            }
            Ok(())
        }));
        let syn = vc.lock().unwrap().connect();
        inject_segs(&stack, client, server, syn);
        wait_for("the server's FIN", || vc.lock().unwrap().fin_received());
        let _held = held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let bridge = stack
            .inner
            .tcp
            .lock()
            .unwrap()
            .values()
            .next()
            .cloned()
            .unwrap();

        // Push until the bridge's window has half closed: the server's
        // socket buffers are full by then, and the pump blocked writing,
        // while there is still room for the rest and our FIN.
        let w0 = win.load(Ordering::SeqCst);
        let chunk = vec![0x5au8; 16 * 1024];
        let deadline = Instant::now() + Duration::from_secs(60);
        while win.load(Ordering::SeqCst) >= w0 / 2 {
            assert!(Instant::now() < deadline, "the remote never pushed back");
            let (_, segs) = vc.lock().unwrap().write(&chunk);
            inject_segs(&stack, client, server, segs);
            thread::sleep(Duration::from_millis(5));
            let segs = vc.lock().unwrap().tick();
            inject_segs(&stack, client, server, segs);
        }
        // Our FIN puts the bridge, which closed first, in TIME-WAIT.
        let fin = vc.lock().unwrap().close();
        inject_segs(&stack, client, server, fin);
        wait_for("the bridge in TIME-WAIT", || {
            let segs = vc.lock().unwrap().tick();
            inject_segs(&stack, client, server, segs);
            bridge.state().conn.lock().unwrap().state() == VtcpState::TimeWait
                && bridge.time_wait_since(Instant::now()).is_some()
        });
        stack.shutdown().unwrap();
        wait_for("the pumps to let go of the bridge", || {
            Arc::strong_count(&bridge) == 1
        });
    }

    /// The maintenance sweep reaps a torn-down bridge by closing it, which
    /// shuts its real socket down: a pump blocked on that socket holds the
    /// bridge alive, and nothing else would ever free it.
    #[test]
    fn reaping_a_closed_bridge_shuts_its_socket_down() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let ours = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut theirs, _) = listener.accept().unwrap();
        let syn = Segment::parse(
            &Conn::new(ConnConfig::default().local_port(5000).remote_port(80)).connect()[0],
        )
        .unwrap();
        let bridge = TcpOutConn::pending(
            Endpoints::V4 {
                local_ip: Ipv4Addr::new(1, 1, 1, 1),
                local_port: 80,
                remote_ip: Ipv4Addr::new(10, 0, 0, 5),
                remote_port: 5000,
            },
            &syn,
            Arc::new(|_: &[u8]| {}),
        );
        *bridge.remote.lock().unwrap() = Some(Arc::new(ours));
        let mut conn = bridge.state().conn.lock().unwrap();
        let _ = conn.accept_syn(&syn);
        let _ = conn.abort();
        drop(conn);
        assert!(bridge.is_closed());
        // Standing in for a pump blocked on the socket.
        let _pump = bridge.clone();
        let table = Mutex::new(HashMap::from([(1u32, bridge)]));
        reap_closed(&table);
        assert!(table.lock().unwrap().is_empty());
        theirs
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut b = [0u8; 1];
        assert_eq!(
            theirs.read(&mut b).map_err(|e| e.kind()),
            Ok(0),
            "the server never saw the bridge's socket shut down"
        );
    }
}

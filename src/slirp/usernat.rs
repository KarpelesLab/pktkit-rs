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

use crate::iface::{L3Device, L3Handler};
use crate::namespace::{Cleanup, L3Connector};
use crate::packet::Packet;
use crate::slirp::icmpv4::build_icmpv4_echo_reply;
use crate::slirp::icmpv6::build_icmpv6_echo_reply;
use crate::slirp::ipv6::skip_extension_headers;
use crate::slirp::listener::{resolve_v4, Listener, ListenerKey};
use crate::slirp::listener6::{resolve_v6, Listener6, ListenerKey6};
use crate::slirp::tcp_out::{build_refused_rst, build_rst_for_stray, TcpOutConn};
use crate::slirp::tcp_stream::{is_closed as conn_is_closed, tick_conn, ConnState, Endpoints};
use crate::slirp::udp::{SendFn as UdpSendFn, UdpConn};
use crate::slirp::udp6::{SendFn as UdpSendFn6, UdpConn6};
use crate::vtcp::segment::{flags as tcp_flags, Segment};
use crate::vtcp::{Conn, ConnConfig, State as VtcpState};
use crate::{connect_l3, IpPrefix, Result};

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

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
    listeners: Mutex<HashMap<ListenerKey, Arc<Listener>>>,
    listeners6: Mutex<HashMap<ListenerKey6, Arc<Listener6>>>,
    // Per-namespace sides (each device attached via ConnectL3).
    ns_sides: Mutex<HashMap<u64, Arc<NsSide>>>,
    ns_counter: AtomicU64,
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
            closed: AtomicBool::new(false),
        });

        // Maintenance thread: GC idle UDP flows and closed TCP connections.
        let weak = Arc::downgrade(&inner);
        thread::spawn(move || loop {
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
                    now.duration_since(last) < UDP_IDLE
                });
            }
            if let Ok(mut u) = inner.udp6.lock() {
                u.retain(|_, conn| {
                    let last = conn.last_act.lock().map(|t| *t).unwrap_or(now);
                    now.duration_since(last) < UDP_IDLE
                });
            }
            drop(inner);
        });

        // Tick thread: drive vtcp timers (RTO / keepalive / TIME-WAIT) for
        // every vtcp-backed connection — both inbound accepts (`virt_tcp*`) and
        // outbound NAT bridges (`tcp*`) — every 100ms, and reap any that have
        // reached CLOSED.
        let weak_tick = Arc::downgrade(&inner);
        thread::spawn(move || loop {
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
                if m.contains_key(&key) {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "address already in use",
                    ));
                }
                m.insert(key, listener.clone());
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
        if m.contains_key(&key) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "address already in use",
            ));
        }
        m.insert(key, listener.clone());
        Ok(listener)
    }

    /// Shut the stack down: close every in-flight connection and stop
    /// the maintenance thread.
    pub fn shutdown(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        if let Ok(mut t) = self.inner.tcp.lock() {
            for (_, c) in t.drain() {
                c.close();
            }
        }
        if let Ok(mut t) = self.inner.tcp6.lock() {
            for (_, c) in t.drain() {
                c.close();
            }
        }
        if let Ok(mut u) = self.inner.udp.lock() {
            for (_, c) in u.drain() {
                c.close();
            }
        }
        if let Ok(mut u) = self.inner.udp6.lock() {
            for (_, c) in u.drain() {
                c.close();
            }
        }
        if let Ok(mut t) = self.inner.virt_tcp.lock() {
            for (_, state) in t.drain() {
                let segs = state.conn.lock().expect("poisoned").abort();
                state.wrap_and_send(segs);
                state.signal.notify_all();
            }
        }
        if let Ok(mut t) = self.inner.virt_tcp6.lock() {
            for (_, state) in t.drain() {
                let segs = state.conn.lock().expect("poisoned").abort();
                state.wrap_and_send(segs);
                state.signal.notify_all();
            }
        }
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

    /// Process an inbound IP packet from the virtual client. Public-facing
    /// entry point is `<Stack as L3Device>::send`.
    fn handle_packet(inner: &Arc<Inner>, ns: u64, pkt: &[u8]) -> Result<()> {
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
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
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
        if inner.tcp.lock().expect("poisoned").len() >= MAX_VIRT_TCP_CONNS {
            return Ok(()); // silently drop; client will retransmit
        }
        let seg = match Segment::parse(tcp) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        let remote = match TcpStream::connect(SocketAddrV4::new(dst, dst_port)) {
            Ok(s) => s,
            Err(_) => {
                // Refused/unreachable: RST+ACK so the client doesn't hang.
                let rst = build_refused_rst(src_port, dst_port, seq);
                let pkt = crate::slirp::packet::build_packet4(dst, src, &rst);
                return Self::dispatch(inner, ns, &pkt);
            }
        };

        let inner_for_send = inner.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |p: &[u8]| {
            let _ = Self::dispatch(&inner_for_send, ns, p);
        });
        let endpoints = Endpoints::V4 {
            local_ip: dst,
            local_port: dst_port,
            remote_ip: src,
            remote_port: src_port,
        };
        let conn = TcpOutConn::accept_syn(endpoints, &seg, remote, sink)?;
        // Register before emitting the SYN-ACK so the client's ACK resolves to
        // this connection rather than triggering a spurious RST.
        inner
            .tcp
            .lock()
            .expect("poisoned")
            .insert(key, conn.clone());
        conn.send_synack();
        Ok(())
    }

    /// Look up a registered IPv4 listener for `(dst, dst_port)`, falling back
    /// to a wildcard (0.0.0.0) listener on the same port.
    fn find_listener(inner: &Arc<Inner>, dst: Ipv4Addr, dst_port: u16) -> Option<Arc<Listener>> {
        let m = inner.listeners.lock().expect("poisoned");
        if let Some(l) = m.get(&ListenerKey {
            ip: dst.octets(),
            port: dst_port,
        }) {
            return Some(l.clone());
        }
        m.get(&ListenerKey {
            ip: [0, 0, 0, 0],
            port: dst_port,
        })
        .cloned()
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
        let inner_for_send = inner.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |p: &[u8]| {
            let _ = Self::dispatch(&inner_for_send, ns, p);
        });

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

        let state = Arc::new(ConnState {
            endpoints: Endpoints::V4 {
                local_ip: dst,
                local_port: dst_port,
                remote_ip: src,
                remote_port: src_port,
            },
            conn: Mutex::new(conn),
            signal: Condvar::new(),
            sink,
        });
        inner
            .virt_tcp
            .lock()
            .expect("poisoned")
            .insert(key, state.clone());
        // Emit the SYN-ACK.
        state.wrap_and_send(synack);

        // Wait (off the dispatch path) for ESTABLISHED, then enqueue.
        Self::spawn_accept_waiter(inner.clone(), key, state, listener);
        Ok(())
    }

    /// Background helper: block until the handshake completes (or the conn
    /// dies), then hand the connection to the listener's accept queue.
    fn spawn_accept_waiter(
        inner: Arc<Inner>,
        key: Key,
        state: Arc<ConnState>,
        listener: Arc<Listener>,
    ) {
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let st = state.conn.lock().expect("poisoned").state();
                match st {
                    VtcpState::Established
                    | VtcpState::FinWait1
                    | VtcpState::FinWait2
                    | VtcpState::CloseWait
                    | VtcpState::Closing
                    | VtcpState::LastAck
                    | VtcpState::TimeWait => {
                        if !listener.enqueue(state.clone()) {
                            // Listener closed or queue full: abort and drop.
                            let segs = state.conn.lock().expect("poisoned").abort();
                            state.wrap_and_send(segs);
                            inner.virt_tcp.lock().expect("poisoned").remove(&key);
                        }
                        return;
                    }
                    VtcpState::Closed => {
                        inner.virt_tcp.lock().expect("poisoned").remove(&key);
                        return;
                    }
                    _ => {}
                }
                if conn_is_closed(&state) || Instant::now() >= deadline {
                    inner.virt_tcp.lock().expect("poisoned").remove(&key);
                    return;
                }
                // Wait for an inbound segment / tick to advance the handshake.
                let guard = state.conn.lock().expect("poisoned");
                let _ = state
                    .signal
                    .wait_timeout(guard, Duration::from_millis(50))
                    .expect("poisoned");
            }
        });
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
            if let Some(c) = t.get(&key) {
                c.clone()
            } else {
                let inner_for_send = inner.clone();
                let send_fn: UdpSendFn =
                    Arc::new(move |p: &[u8]| Self::dispatch(&inner_for_send, ns, p));
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
                if let Some(reply) = build_icmpv6_echo_reply(pkt, src_addr, dst_addr, transport_off)
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
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
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

        if inner.tcp6.lock().expect("poisoned").len() >= MAX_VIRT_TCP_CONNS {
            return Ok(()); // silently drop; client will retransmit
        }
        let seg = match Segment::parse(tcp) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        let remote = match TcpStream::connect(SocketAddrV6::new(dst, dst_port, 0, 0)) {
            Ok(s) => s,
            Err(_) => {
                let rst = build_refused_rst(src_port, dst_port, seq);
                let pkt = crate::slirp::packet::build_packet6(dst, src, &rst);
                return Self::dispatch(inner, ns, &pkt);
            }
        };

        let inner_for_send = inner.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |p: &[u8]| {
            let _ = Self::dispatch(&inner_for_send, ns, p);
        });
        let endpoints = Endpoints::V6 {
            local_ip: dst,
            local_port: dst_port,
            remote_ip: src,
            remote_port: src_port,
        };
        let conn = TcpOutConn::accept_syn(endpoints, &seg, remote, sink)?;
        // Register before emitting the SYN-ACK (see the v4 path).
        inner
            .tcp6
            .lock()
            .expect("poisoned")
            .insert(key, conn.clone());
        conn.send_synack();
        Ok(())
    }

    /// Look up a registered IPv6 listener for `(dst, dst_port)`, falling back
    /// to a wildcard (`::`) listener on the same port.
    fn find_listener6(inner: &Arc<Inner>, dst: Ipv6Addr, dst_port: u16) -> Option<Arc<Listener6>> {
        let m = inner.listeners6.lock().expect("poisoned");
        if let Some(l) = m.get(&ListenerKey6 {
            ip: dst.octets(),
            port: dst_port,
        }) {
            return Some(l.clone());
        }
        m.get(&ListenerKey6 {
            ip: Ipv6Addr::UNSPECIFIED.octets(),
            port: dst_port,
        })
        .cloned()
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
        let inner_for_send = inner.clone();
        let sink: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |p: &[u8]| {
            let _ = Self::dispatch(&inner_for_send, ns, p);
        });

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

        let state = Arc::new(ConnState {
            endpoints: Endpoints::V6 {
                local_ip: dst,
                local_port: dst_port,
                remote_ip: src,
                remote_port: src_port,
            },
            conn: Mutex::new(conn),
            signal: Condvar::new(),
            sink,
        });
        inner
            .virt_tcp6
            .lock()
            .expect("poisoned")
            .insert(key, state.clone());
        // Emit the SYN-ACK.
        state.wrap_and_send(synack);

        // Wait (off the dispatch path) for ESTABLISHED, then enqueue.
        Self::spawn_accept_waiter6(inner.clone(), key, state, listener);
        Ok(())
    }

    /// IPv6 analogue of [`spawn_accept_waiter`](Self::spawn_accept_waiter).
    fn spawn_accept_waiter6(
        inner: Arc<Inner>,
        key: Key6,
        state: Arc<ConnState>,
        listener: Arc<Listener6>,
    ) {
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let st = state.conn.lock().expect("poisoned").state();
                match st {
                    VtcpState::Established
                    | VtcpState::FinWait1
                    | VtcpState::FinWait2
                    | VtcpState::CloseWait
                    | VtcpState::Closing
                    | VtcpState::LastAck
                    | VtcpState::TimeWait => {
                        if !listener.enqueue(state.clone()) {
                            // Listener closed or queue full: abort and drop.
                            let segs = state.conn.lock().expect("poisoned").abort();
                            state.wrap_and_send(segs);
                            inner.virt_tcp6.lock().expect("poisoned").remove(&key);
                        }
                        return;
                    }
                    VtcpState::Closed => {
                        inner.virt_tcp6.lock().expect("poisoned").remove(&key);
                        return;
                    }
                    _ => {}
                }
                if conn_is_closed(&state) || Instant::now() >= deadline {
                    inner.virt_tcp6.lock().expect("poisoned").remove(&key);
                    return;
                }
                // Wait for an inbound segment / tick to advance the handshake.
                let guard = state.conn.lock().expect("poisoned");
                let _ = state
                    .signal
                    .wait_timeout(guard, Duration::from_millis(50))
                    .expect("poisoned");
            }
        });
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
            if let Some(c) = t.get(&key) {
                c.clone()
            } else {
                let inner_for_send = inner.clone();
                let send_fn: UdpSendFn6 =
                    Arc::new(move |p: &[u8]| Self::dispatch(&inner_for_send, ns, p));
                let conn = UdpConn6::new(src, src_port, dst, dst_port, send_fn)?;
                t.insert(key, conn.clone());
                conn
            }
        };
        conn.handle_outbound(pkt, transport_off);
        Ok(())
    }

    fn cleanup_namespace(inner: &Arc<Inner>, ns: u64) {
        // Drop all per-namespace flows.
        if let Ok(mut t) = inner.virt_tcp.lock() {
            t.retain(|k, state| {
                if k.ns == ns {
                    let segs = state.conn.lock().expect("poisoned").abort();
                    state.wrap_and_send(segs);
                    state.signal.notify_all();
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut t) = inner.virt_tcp6.lock() {
            t.retain(|k, state| {
                if k.ns == ns {
                    let segs = state.conn.lock().expect("poisoned").abort();
                    state.wrap_and_send(segs);
                    state.signal.notify_all();
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut t) = inner.tcp.lock() {
            t.retain(|k, c| {
                if k.ns == ns {
                    c.close();
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut t) = inner.tcp6.lock() {
            t.retain(|k, c| {
                if k.ns == ns {
                    c.close();
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut u) = inner.udp.lock() {
            u.retain(|k, c| {
                if k.ns == ns {
                    c.close();
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut u) = inner.udp6.lock() {
            u.retain(|k, c| {
                if k.ns == ns {
                    c.close();
                    false
                } else {
                    true
                }
            });
        }
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

        let inner = self.inner.clone();
        Ok(Box::new(move || {
            inner.ns_sides.lock().expect("poisoned").remove(&ns);
            Stack::cleanup_namespace(&inner, ns);
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slirp::checksum::{ipv4_header_checksum, udp_v4_checksum};
    use crate::vtcp::segment::flags as tcp_flags;
    use crate::Protocol;
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
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if !captured.lock().unwrap().is_empty() {
                break;
            }
            if std::time::Instant::now() > deadline {
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

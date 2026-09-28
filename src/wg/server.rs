//! UDP server loop that owns the read thread, dispatches packets into the
//! handler(s), and writes back protocol responses.
//!
//! Ported from `wg/server.go`. Concurrency is much simpler than the Go
//! version: one reader thread per call to [`Server::serve`] (the kernel
//! distributes packets across multiple `UdpSocket`s automatically; if the
//! caller wants `Concurrency > 1`, they can call `serve` from multiple threads
//! sharing the same `UdpSocket`).

use crate::time::Instant;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::Result;
use crate::wg::NoisePublicKey;
use crate::wg::TimerAction;
use crate::wg::handler::{Handler, PacketResult, PacketType, PeerRemovedFn};
use crate::wg::multihandler::MultiHandler;

/// Callback fired when decrypted transport data arrives.
pub type OnPacketFn = Arc<dyn Fn(&[u8], NoisePublicKey, &Arc<Handler>) + Send + Sync + 'static>;

/// Callback fired when a handshake completes.
pub type OnPeerConnectedFn = Arc<dyn Fn(NoisePublicKey, &Arc<Handler>) + Send + Sync + 'static>;

/// Server configuration.
#[derive(Clone)]
#[non_exhaustive]
pub struct ServerConfig {
    /// The single identity to serve. Exactly one of `handler` and
    /// `multi_handler` must be set.
    pub handler: Option<Arc<Handler>>,
    /// Several identities sharing the socket, instead of `handler`.
    pub multi_handler: Option<Arc<MultiHandler>>,
    /// Called with each decrypted transport packet. Default: drop it.
    pub on_packet: OnPacketFn,
    /// Called when a handshake with a peer completes.
    pub on_peer_connected: Option<OnPeerConnectedFn>,
    /// How often the handler's
    /// [`maintenance`](Handler::maintenance) runs. Default: 10 seconds.
    pub maintenance_interval: Option<Duration>,
    /// Size of the receive buffer, the largest datagram read whole.
    /// Default (and when 0): 65535.
    pub read_buffer_size: usize,
}

setters! {
    ServerConfig {
        some handler: Arc<Handler>;
        some multi_handler: Arc<MultiHandler>;
        set on_packet: OnPacketFn;
        some on_peer_connected: OnPeerConnectedFn;
        some maintenance_interval: Duration;
        set read_buffer_size: usize;
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("has_handler", &self.handler.is_some())
            .field("has_multi", &self.multi_handler.is_some())
            .field("read_buffer_size", &self.read_buffer_size)
            .field("maintenance_interval", &self.maintenance_interval)
            .finish()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            handler: None,
            multi_handler: None,
            on_packet: Arc::new(|_d, _k, _h| {}),
            on_peer_connected: None,
            maintenance_interval: None,
            read_buffer_size: 65535,
        }
    }
}

/// A WireGuard UDP server.
pub struct Server {
    handler: Option<Arc<Handler>>,
    multi_handler: Option<Arc<MultiHandler>>,
    on_packet: OnPacketFn,
    on_peer_connected: Option<OnPeerConnectedFn>,
    maintenance_interval: Duration,
    read_buffer_size: usize,

    conn: Mutex<Option<Arc<UdpSocket>>>,
    done: Arc<AtomicBool>,
    threads: Mutex<Vec<JoinHandle<()>>>,

    peer_addrs: RwLock<std::collections::HashMap<NoisePublicKey, SocketAddr>>,
    peer_handlers: RwLock<std::collections::HashMap<NoisePublicKey, Arc<Handler>>>,
    /// Plaintext waiting for a session with its peer: sent while there was
    /// none (or it had expired), and flushed once a handshake completes.
    staged: Mutex<Staged>,
    /// Installed on the handler(s), which hold it weakly: it lives as long
    /// as the server.
    removal_hook: Arc<PeerRemovedFn>,
}

/// Plaintext held per peer until a handshake gives it a keypair, with the
/// total size tracked so no number of peers can make it grow unbounded.
#[derive(Default)]
struct Staged {
    queues: std::collections::HashMap<NoisePublicKey, std::collections::VecDeque<Vec<u8>>>,
    bytes: usize,
}

impl Staged {
    /// Queue `data` for `peer`, dropping the peer's oldest past
    /// [`MAX_STAGED_PACKETS`], or `data` itself if every peer's together
    /// would pass [`MAX_STAGED_BYTES`].
    fn push(&mut self, peer: &NoisePublicKey, data: &[u8]) {
        let q = self.queues.entry(*peer).or_default();
        if q.len() >= MAX_STAGED_PACKETS
            && let Some(old) = q.pop_front()
        {
            self.bytes -= old.len();
        }
        if self.bytes + data.len() <= MAX_STAGED_BYTES {
            self.bytes += data.len();
            q.push_back(data.to_vec());
        }
        if q.is_empty() {
            self.queues.remove(peer);
        }
    }

    fn take(&mut self, peer: &NoisePublicKey) -> Option<std::collections::VecDeque<Vec<u8>>> {
        let q = self.queues.remove(peer)?;
        self.bytes -= q.iter().map(Vec::len).sum::<usize>();
        Some(q)
    }

    /// Return what [`take`](Self::take) took and could not send, ahead of
    /// anything queued since, within the same limits as [`push`](Self::push).
    fn put_back(&mut self, peer: &NoisePublicKey, older: std::collections::VecDeque<Vec<u8>>) {
        let q = self.queues.entry(*peer).or_default();
        for data in older.into_iter().rev() {
            if q.len() >= MAX_STAGED_PACKETS || self.bytes + data.len() > MAX_STAGED_BYTES {
                break;
            }
            self.bytes += data.len();
            q.push_front(data);
        }
        if q.is_empty() {
            self.queues.remove(peer);
        }
    }

    fn peers(&self) -> Vec<NoisePublicKey> {
        self.queues.keys().copied().collect()
    }
}

/// Packets held per peer while a handshake is under way, as in the
/// reference implementation. Past this, the oldest are dropped.
const MAX_STAGED_PACKETS: usize = 128;
/// Bytes held across all peers: a bound on memory whatever the number of
/// peers with a handshake pending.
const MAX_STAGED_BYTES: usize = 4 << 20;
/// How often the maintenance thread runs the protocol timers.
const TIMER_TICK: Duration = Duration::from_millis(100);

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("maintenance_interval", &self.maintenance_interval)
            .finish()
    }
}

impl Server {
    /// Build a server; it does nothing until [`serve`](Self::serve) is
    /// given a socket. Fails with `InvalidInput` unless exactly one of the
    /// config's `handler` and `multi_handler` is set.
    pub fn new(cfg: ServerConfig) -> Result<Arc<Self>> {
        match (cfg.handler.is_some(), cfg.multi_handler.is_some()) {
            (false, false) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "either handler or multi_handler must be set",
                ));
            }
            (true, true) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "handler and multi_handler are mutually exclusive",
                ));
            }
            _ => {}
        }
        let interval = cfg.maintenance_interval.unwrap_or(Duration::from_secs(10));
        // A UDP datagram can be up to 65535 bytes; a smaller buffer would
        // silently truncate a peer's large packet, which then fails to
        // decrypt.
        let rb = if cfg.read_buffer_size == 0 {
            65535
        } else {
            cfg.read_buffer_size
        };

        let server = Arc::new_cyclic(|me: &std::sync::Weak<Server>| {
            let me = me.clone();
            let removal_hook: Arc<PeerRemovedFn> = Arc::new(move |h, gone| {
                if let Some(s) = me.upgrade() {
                    s.peers_removed(h, gone);
                }
            });
            Server {
                handler: cfg.handler,
                multi_handler: cfg.multi_handler,
                on_packet: cfg.on_packet,
                on_peer_connected: cfg.on_peer_connected,
                maintenance_interval: interval,
                read_buffer_size: rb,
                conn: Mutex::new(None),
                done: Arc::new(AtomicBool::new(false)),
                threads: Mutex::new(Vec::new()),
                peer_addrs: RwLock::new(std::collections::HashMap::new()),
                peer_handlers: RwLock::new(std::collections::HashMap::new()),
                staged: Mutex::new(Staged::default()),
                removal_hook,
            }
        });
        if let Some(mh) = server.multi_handler.as_ref() {
            mh.watch_removals(&server.removal_hook);
        } else if let Some(h) = server.handler.as_ref() {
            h.watch_removals(&server.removal_hook);
        }
        Ok(server)
    }

    /// Start the read loop + maintenance thread. Blocks until [`Server::close`]
    /// is called (or the socket errors permanently).
    pub fn serve(self: &Arc<Self>, conn: Arc<UdpSocket>) -> Result<()> {
        // Single short read timeout so close() unblocks promptly.
        conn.set_read_timeout(Some(Duration::from_millis(500)))?;

        *self.conn.lock().expect("conn lock") = Some(conn.clone());

        // Spawn the maintenance thread. It lives as long as this call:
        // however the read loop ends, `_stop` tells it to go, rather than
        // leaving it to send keepalives for a server that no longer reads.
        // It holds the server weakly, so it never keeps one alive.
        let weak = Arc::downgrade(self);
        let interval = self.maintenance_interval;
        let done = self.done.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let _stop = StopOnDrop(stop.clone());
        let maint = thread::Builder::new()
            .name("wg-maint".into())
            .spawn(move || {
                let mut last = Instant::now();
                while !done.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
                    thread::sleep(TIMER_TICK);
                    let Some(me) = weak.upgrade() else { break };
                    me.run_timers();
                    if last.elapsed() >= interval {
                        if let Some(mh) = me.multi_handler.as_ref() {
                            mh.maintenance();
                        } else if let Some(h) = me.handler.as_ref() {
                            h.maintenance();
                        }
                        last = Instant::now();
                    }
                }
            })?;
        self.threads.lock().expect("threads lock").push(maint);

        // Reader: run inline (blocking) so caller's `serve` is the read loop.
        self.read_loop(conn);
        Ok(())
    }

    fn read_loop(&self, conn: Arc<UdpSocket>) {
        let mut buf = vec![0u8; self.read_buffer_size];
        while !self.done.load(Ordering::SeqCst) {
            match conn.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    // Copy out so the buffer can be reused on the next iteration.
                    let data = buf[..n].to_vec();
                    self.process_incoming(&data, addr, &conn);
                }
                Err(e) => match e.kind() {
                    // An ICMP unreachable from one peer surfaces here (as
                    // ConnectionReset on Windows, ConnectionRefused on some
                    // Unixes). It says nothing about the socket, and ending
                    // the loop would cut off every other peer.
                    io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused => continue,
                    _ => break,
                },
            }
        }
    }

    /// Handle `data` as if it had just arrived from `addr`: reply, record
    /// the peer's address and fire the callbacks. For a handshake held back
    /// while its peer was being authorized.
    pub(crate) fn handle_packet(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .expect("conn lock")
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "server not serving"))?;
        self.process_incoming(data, addr, &conn);
        Ok(())
    }

    fn process_incoming(&self, data: &[u8], addr: SocketAddr, conn: &UdpSocket) {
        // Processing may call on_unknown_peer, caller code, which must not
        // take the read loop down with it; no lock is held while it runs.
        let processed = catch_callback(|| {
            if let Some(mh) = self.multi_handler.as_ref() {
                mh.process_packet(data, &addr)
                    .map(|mr| (mr.result, mr.handler))
            } else {
                let h = self.handler.as_ref().unwrap().clone();
                h.process_packet(data, &addr).map(|r| (r, h))
            }
        });
        let Some(Ok((result, handler))) = processed else {
            return;
        };

        // Roaming (whitepaper §6): only a packet that authenticated as the
        // peer may move its endpoint. A cookie reply names a peer but proves
        // nothing: anyone who saw our initiation can forge one, and taking
        // its source would hand them the peer's traffic.
        let authenticated = !result.peer_key.is_zero()
            && matches!(
                result.ty,
                PacketType::HandshakeResponse | PacketType::TransportData | PacketType::Keepalive
            );
        if authenticated {
            self.peer_addrs
                .write()
                .expect("addr lock")
                .insert(result.peer_key, addr);
            if self.multi_handler.is_some() {
                self.peer_handlers
                    .write()
                    .expect("handler lock")
                    .insert(result.peer_key, handler.clone());
            }
        }

        let peer = result.peer_key;
        self.dispatch(result, &handler, addr, conn);
        if authenticated {
            self.flush_staged(&peer, &handler, addr, conn);
        }
    }

    /// Send what the protocol timers ask for: handshake retries and rekeys,
    /// keepalives. Without this nothing ever rekeyed, so a tunnel died when
    /// its keypair reached REJECT_AFTER_TIME.
    fn run_timers(&self) {
        self.prune_staged();
        let actions: Vec<(Arc<Handler>, TimerAction)> =
            if let Some(mh) = self.multi_handler.as_ref() {
                mh.poll_timers()
            } else if let Some(h) = self.handler.as_ref() {
                h.poll_timers()
                    .into_iter()
                    .map(|a| (h.clone(), a))
                    .collect()
            } else {
                Vec::new()
            };
        if actions.is_empty() {
            return;
        }
        let Some(conn) = self.conn.lock().expect("conn lock").clone() else {
            return;
        };
        for (_, action) in actions {
            match action {
                TimerAction::SendHandshake { peer, packet }
                | TimerAction::SendKeepalive { peer, packet } => {
                    if let Some(addr) = self.peer_addr(&peer) {
                        let _ = conn.send_to(&packet, addr);
                    }
                }
                TimerAction::HandshakeFailed { peer } => {
                    self.staged.lock().expect("staged lock").take(&peer);
                }
            }
        }
    }

    /// Drop what is staged for peers no handler would start a handshake
    /// with any more (removed, or past their expiry): the timers only poll
    /// authorized peers, so nothing would ever report them failed.
    fn prune_staged(&self) {
        let peers = self.staged.lock().expect("staged lock").peers();
        for peer in peers {
            if !self.authorized_anywhere(&peer) {
                self.staged.lock().expect("staged lock").take(&peer);
            }
        }
    }

    fn authorized_anywhere(&self, peer: &NoisePublicKey) -> bool {
        match self.multi_handler.as_ref() {
            Some(mh) => mh.handlers().iter().any(|h| h.is_authorized_peer(peer)),
            None => self
                .handler
                .as_ref()
                .is_some_and(|h| h.is_authorized_peer(peer)),
        }
    }

    /// Forget everything held for `peer`: its staged packets and endpoint.
    /// For a peer that has just been removed.
    pub(crate) fn forget_peer(&self, peer: &NoisePublicKey) {
        self.staged.lock().expect("staged lock").take(peer);
        self.peer_addrs.write().expect("addr lock").remove(peer);
        self.peer_handlers
            .write()
            .expect("handler lock")
            .remove(peer);
    }

    /// `from` dropped the peers in `gone` from its table. Those no handler
    /// knows any more are forgotten; one another member still has is only
    /// no longer routed to `from`.
    fn peers_removed(&self, from: &Handler, gone: &[NoisePublicKey]) {
        for peer in gone {
            if !self.known_anywhere(peer) {
                // One authorized again meanwhile loses at worst its
                // endpoint, which its next authenticated packet records.
                self.forget_peer(peer);
                continue;
            }
            let mut handlers = self.peer_handlers.write().expect("handler lock");
            if handlers.get(peer).is_some_and(|h| std::ptr::eq(&**h, from)) {
                handlers.remove(peer);
            }
        }
    }

    /// Whether any handler has `peer` in its table, expired or not.
    fn known_anywhere(&self, peer: &NoisePublicKey) -> bool {
        match self.multi_handler.as_ref() {
            Some(mh) => mh.handlers().iter().any(|h| h.has_peer(peer)),
            None => self.handler.as_ref().is_some_and(|h| h.has_peer(peer)),
        }
    }

    /// Send what was staged for `peer` once it has a session.
    fn flush_staged(
        &self,
        peer: &NoisePublicKey,
        handler: &Arc<Handler>,
        addr: SocketAddr,
        conn: &UdpSocket,
    ) {
        if !handler.has_session(peer) {
            return;
        }
        let Some(mut queue) = self.staged.lock().expect("staged lock").take(peer) else {
            return;
        };
        while let Some(data) = queue.pop_front() {
            match handler.encrypt(&data, peer) {
                Ok(ct) => {
                    let _ = conn.send_to(&ct, addr);
                }
                Err(_) => {
                    // The keypair became unusable under us (it expired or
                    // ran out of messages); encrypt has asked for a
                    // handshake. Keep the rest for that one, ahead of
                    // anything staged meanwhile.
                    queue.push_front(data);
                    self.staged
                        .lock()
                        .expect("staged lock")
                        .put_back(peer, queue);
                    return;
                }
            }
        }
    }

    fn stage(&self, peer: &NoisePublicKey, data: &[u8]) {
        self.staged.lock().expect("staged lock").push(peer, data);
    }

    fn dispatch(
        &self,
        result: PacketResult,
        handler: &Arc<Handler>,
        addr: SocketAddr,
        conn: &UdpSocket,
    ) {
        match result.ty {
            PacketType::HandshakeResponse | PacketType::CookieReply => {
                let _ = conn.send_to(&result.response, addr);
                if result.ty == PacketType::HandshakeResponse
                    && let Some(cb) = self.on_peer_connected.as_ref()
                {
                    catch_callback(|| cb(result.peer_key, handler));
                }
            }
            PacketType::TransportData => {
                catch_callback(|| (self.on_packet)(&result.data, result.peer_key, handler));
            }
            PacketType::Keepalive | PacketType::CookieReceived => {
                // Nothing else to do; address already noted above.
            }
        }
    }

    /// Encrypt and send to a known peer (last-known address).
    pub fn send(&self, data: &[u8], peer_key: &NoisePublicKey) -> Result<()> {
        let h = if let Some(mh) = self.multi_handler.as_ref() {
            self.peer_handlers
                .read()
                .expect("handler lock")
                .get(peer_key)
                .cloned()
                .or_else(|| mh.handlers().first().cloned())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no handler for peer"))?
        } else {
            self.handler.as_ref().unwrap().clone()
        };
        self.send_with(data, peer_key, &h)
    }

    /// Send using a specific handler (multi-mode).
    pub fn send_to(
        &self,
        data: &[u8],
        peer_key: &NoisePublicKey,
        handler: &Arc<Handler>,
    ) -> Result<()> {
        self.send_with(data, peer_key, handler)
    }

    fn send_with(
        &self,
        data: &[u8],
        peer_key: &NoisePublicKey,
        handler: &Arc<Handler>,
    ) -> Result<()> {
        let addr = self
            .peer_addrs
            .read()
            .expect("addr lock")
            .get(peer_key)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address known for peer"))?;
        let conn = self
            .conn
            .lock()
            .expect("conn lock")
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "server not serving"))?;
        match handler.encrypt(data, peer_key) {
            Ok(ct) => {
                conn.send_to(&ct, addr)?;
                Ok(())
            }
            // No usable keypair: the handler has asked for a handshake. Hold
            // the packet for when it completes instead of losing it, and
            // start the handshake now rather than on the next timer tick.
            Err(e) if matches!(e.kind(), io::ErrorKind::NotConnected | io::ErrorKind::Other) => {
                // Unless no handshake can be started: then nothing would
                // ever send the packet, or report that it failed.
                if !handler.is_authorized_peer(peer_key) {
                    self.staged.lock().expect("staged lock").take(peer_key);
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "peer not authorized",
                    ));
                }
                self.stage(peer_key, data);
                self.run_timers();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Where the server sends to `peer_key`: the source of the peer's last
    /// authenticated packet (a handshake response or transport data, so a
    /// roaming peer is followed), or the address [`connect`](Self::connect)
    /// was given. `None` before either.
    pub fn peer_addr(&self, peer_key: &NoisePublicKey) -> Option<SocketAddr> {
        self.peer_addrs
            .read()
            .expect("addr lock")
            .get(peer_key)
            .copied()
    }

    /// Initiate a handshake (single-handler mode).
    pub fn connect(&self, peer_key: &NoisePublicKey, addr: SocketAddr) -> Result<()> {
        let h = self
            .handler
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "use connect_with in multi mode",
                )
            })?
            .clone();
        self.connect_with(peer_key, addr, &h)
    }

    /// Initiate a handshake (multi-handler mode).
    pub fn connect_with(
        &self,
        peer_key: &NoisePublicKey,
        addr: SocketAddr,
        handler: &Arc<Handler>,
    ) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .expect("conn lock")
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "server not serving"))?;

        let init = handler.initiate_handshake(peer_key)?;
        self.peer_addrs
            .write()
            .expect("addr lock")
            .insert(*peer_key, addr);
        if self.multi_handler.is_some() {
            self.peer_handlers
                .write()
                .expect("handler lock")
                .insert(*peer_key, handler.clone());
        }
        conn.send_to(&init, addr)?;
        Ok(())
    }

    /// Stop the read loop and maintenance thread.
    pub fn close(&self) -> Result<()> {
        self.done.store(true, Ordering::SeqCst);
        // The reader thread (caller's serve()) will exit on the next timeout.
        let handles: Vec<_> = self
            .threads
            .lock()
            .expect("threads lock")
            .drain(..)
            .collect();
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }
}

/// Run caller code for the read loop: a panic in it costs the packet
/// being handled, not the loop (and with it every peer).
fn catch_callback<T>(f: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
}

/// Sets its flag when dropped, however the scope holding it is left.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::NoisePrivateKey;
    use crate::wg::handler::Config;

    fn server(on_packet: OnPacketFn) -> (Arc<Server>, Arc<Handler>, SocketAddr) {
        let h = Handler::new(Config::default()).unwrap();
        let s = Server::new(
            ServerConfig::default()
                .handler(h.clone())
                .on_packet(on_packet),
        )
        .unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let addr = sock.local_addr().unwrap();
        let s2 = s.clone();
        thread::spawn(move || s2.serve(sock));
        // Let serve() install the socket.
        while s.conn.lock().unwrap().is_none() {
            thread::sleep(Duration::from_millis(1));
        }
        (s, h, addr)
    }

    /// A server for `h` with a socket installed but no threads, so tests
    /// can feed `process_incoming` directly.
    fn idle_server(h: &Arc<Handler>) -> (Arc<Server>, Arc<UdpSocket>) {
        let s = Server::new(ServerConfig::default().handler(h.clone())).unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        *s.conn.lock().unwrap() = Some(sock.clone());
        (s, sock)
    }

    /// A cookie reply is not authenticated by anything the peer alone
    /// holds: its key derives from the peer's public key, and its AD is
    /// the MAC1 of our initiation, sent in clear. Anyone who saw the
    /// initiation can forge one, so it must not move the peer's endpoint
    /// (whitepaper §5.4.7, §6).
    #[test]
    fn a_cookie_reply_does_not_move_the_endpoint() {
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        let (s, sock) = idle_server(&a);
        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        s.connect(&b.public_key(), peer_addr).unwrap();
        let mut init = [0u8; 256];
        let (n, _) = peer_sock.recv_from(&mut init).unwrap();
        let init = &init[..n];

        // What an on-path observer can build from b's public key alone.
        let sender = u32::from_le_bytes(init[4..8].try_into().unwrap());
        let forged = b
            .cookie_generate_reply(&[1, 2, 3, 4, 0, 1], sender, &init[116..132])
            .unwrap();
        let attacker: SocketAddr = "127.0.0.1:9".parse().unwrap();
        s.process_incoming(&forged, attacker, &sock);
        assert_eq!(s.peer_addr(&b.public_key()), Some(peer_addr));
    }

    /// Receive from `sock` until a packet of WireGuard type `ty` arrives.
    fn recv_type(sock: &UdpSocket, ty: u8) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        loop {
            let (n, _) = sock.recv_from(&mut buf).expect("nothing arrived");
            if buf[0] == ty {
                return buf[..n].to_vec();
            }
        }
    }

    /// Packets staged while the current keypair had expired (it lingers
    /// until the next cleanup) wait for a usable one, rather than being
    /// flushed into it and dropped when encryption fails.
    #[test]
    fn staged_packets_wait_out_an_expired_keypair() {
        use crate::wg::handler::Keypair;
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());
        let (s, sock) = idle_server(&a);
        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        let a_addr = sock.local_addr().unwrap();

        // A session, whose current keypair then ages past REJECT_AFTER_TIME.
        s.connect(&b.public_key(), peer_addr).unwrap();
        let init = recv_type(&peer_sock, 1);
        let resp = b.process_packet(&init, &a_addr).unwrap();
        s.process_incoming(&resp.response, peer_addr, &sock);
        {
            let mut sess = a.sessions.write().unwrap();
            let slot = &mut sess.get_mut(&b.public_key()).unwrap().keypair_current;
            let kp = slot.take().unwrap();
            *slot = Some(Arc::new(Keypair {
                send_key: kp.send_key,
                receive_key: kp.receive_key,
                send_counter: Default::default(),
                created: Instant::now() - crate::wg::constants::REJECT_AFTER_TIME * 2,
                local_index: kp.local_index,
                remote_index: kp.remote_index,
                peer_key: kp.peer_key,
                is_initiator: kp.is_initiator,
                replay_filter: crate::wg::replay::SlidingWindow::new(),
            }));
        }
        s.send(b"staged", &b.public_key()).unwrap();

        // The peer initiates. Our response leaves the new keypair
        // unconfirmed, and the expired one is still current.
        let init = b.initiate_handshake(&a.public_key()).unwrap();
        s.process_incoming(&init, peer_addr, &sock);
        let resp = recv_type(&peer_sock, 2);
        let ka = b.process_packet(&resp, &a_addr).unwrap();
        // Its keepalive confirms the new keypair; now the packet goes out.
        s.process_incoming(&ka.response, peer_addr, &sock);
        let pkt = recv_type(&peer_sock, 4);
        assert_eq!(b.process_packet(&pkt, &a_addr).unwrap().data, b"staged");
    }

    fn staged_for(s: &Server, peer: &NoisePublicKey) -> usize {
        s.staged
            .lock()
            .unwrap()
            .queues
            .get(peer)
            .map_or(0, |q| q.len())
    }

    /// Packets are staged only for a peer a handshake can be started with,
    /// and go once it no longer can be: otherwise nothing ever reports the
    /// handshake failed, and they stay forever.
    #[test]
    fn staged_packets_do_not_outlive_the_peer() {
        let a = Handler::new(Config::default()).unwrap();
        let (s, _sock) = idle_server(&a);
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let known = |k: NoisePublicKey| {
            s.peer_addrs.write().unwrap().insert(k, addr);
        };

        // Removed while its packets wait.
        let b = crate::wg::generate_private_key().unwrap();
        let b = crate::wg::crypto::x25519_public(&b);
        a.add_peer(b);
        known(b);
        s.send(b"x", &b).unwrap();
        assert_eq!(staged_for(&s, &b), 1);
        a.remove_peer(&b);
        s.run_timers();
        assert_eq!(staged_for(&s, &b), 0, "removed peer");

        // Never authorized, or expired: nothing to stage for.
        let c = NoisePublicKey([7; 32]);
        known(c);
        assert!(s.send(b"x", &c).is_err());
        assert_eq!(staged_for(&s, &c), 0, "unauthorized peer");
        let d = crate::wg::crypto::x25519_public(&crate::wg::generate_private_key().unwrap());
        a.add_peer(d);
        a.set_peer_expiry(&d, Instant::now() - Duration::from_secs(1));
        known(d);
        assert!(s.send(b"x", &d).is_err());
        assert_eq!(staged_for(&s, &d), 0, "expired peer");
    }

    /// However many peers have packets waiting, the total held is bounded.
    #[test]
    fn staged_memory_is_bounded() {
        let a = Handler::new(Config::default()).unwrap();
        let (s, _sock) = idle_server(&a);
        let big = vec![0u8; 60_000];
        for i in 0..1000u32 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            s.stage(&NoisePublicKey(k), &big);
        }
        let total: usize = s
            .staged
            .lock()
            .unwrap()
            .queues
            .values()
            .flat_map(|q| q.iter())
            .map(|p| p.len())
            .sum();
        assert!(total <= MAX_STAGED_BYTES, "{total} bytes staged");
    }

    /// Data sent before the handshake completes is held and delivered once
    /// it does, not lost.
    #[test]
    fn data_sent_during_the_handshake_arrives() {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let tx = Mutex::new(tx);
        let (b, hb, b_addr) = server(Arc::new(move |d: &[u8], _, _| {
            let _ = tx.lock().unwrap().send(d.to_vec());
        }));
        let (a, ha, _) = server(Arc::new(|_, _, _| {}));
        ha.add_peer(hb.public_key());
        hb.add_peer(ha.public_key());

        a.connect(&hb.public_key(), b_addr).unwrap();
        a.send(b"first", &hb.public_key()).unwrap();
        a.send(b"second", &hb.public_key()).unwrap();
        let got: Vec<Vec<u8>> = (0..2)
            .map(|_| rx.recv_timeout(Duration::from_secs(5)).expect("lost"))
            .collect();
        assert_eq!(got, vec![b"first".to_vec(), b"second".to_vec()]);
        a.close().unwrap();
        b.close().unwrap();
    }

    /// Complete a handshake between `client` and the server at `saddr`
    /// over `sock`.
    fn handshake(client: &Handler, sock: &UdpSocket, saddr: SocketAddr, spub: NoisePublicKey) {
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock.send_to(&client.initiate_handshake(&spub).unwrap(), saddr)
            .unwrap();
        let resp = recv_type(sock, 2);
        client.process_packet(&resp, &saddr).unwrap();
    }

    /// A panicking on_packet costs the packet it was handed, not the read
    /// loop: before, the loop died with it, and every peer went unheard.
    #[test]
    fn a_panicking_callback_does_not_stop_the_read_loop() {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let tx = Mutex::new(tx);
        let (s, h, saddr) = server(Arc::new(move |d: &[u8], _, _| {
            if d == b"boom" {
                panic!("caller bug");
            }
            let _ = tx.lock().unwrap().send(d.to_vec());
        }));
        let c = Handler::new(Config::default()).unwrap();
        c.add_peer(h.public_key());
        h.add_peer(c.public_key());
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        handshake(&c, &sock, saddr, h.public_key());
        for d in [&b"boom"[..], b"after"] {
            sock.send_to(&c.encrypt(d, &h.public_key()).unwrap(), saddr)
                .unwrap();
        }
        let got = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("read loop died");
        assert_eq!(got, b"after");
        s.close().unwrap();
    }

    /// Likewise a panicking on_unknown_peer, which runs inside processing.
    #[test]
    fn a_panicking_unknown_peer_callback_does_not_stop_the_read_loop() {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let tx = Mutex::new(tx);
        let (s, h, saddr) = server(Arc::new(move |d: &[u8], _, _| {
            let _ = tx.lock().unwrap().send(d.to_vec());
        }));
        h.set_on_unknown_peer(Arc::new(|_, _, _| panic!("caller bug")));
        let stranger = Handler::new(Config::default()).unwrap();
        stranger.add_peer(h.public_key());
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(
            &stranger.initiate_handshake(&h.public_key()).unwrap(),
            saddr,
        )
        .unwrap();

        let c = Handler::new(Config::default()).unwrap();
        c.add_peer(h.public_key());
        h.add_peer(c.public_key());
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        handshake(&c, &sock, saddr, h.public_key());
        sock.send_to(&c.encrypt(b"hi", &h.public_key()).unwrap(), saddr)
            .unwrap();
        let got = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("read loop died");
        assert_eq!(got, b"hi");
        s.close().unwrap();
    }

    /// However serve ends, its maintenance thread ends with it, rather than
    /// sending keepalives and handshakes for a server nobody reads for.
    #[test]
    fn the_maintenance_thread_stops_when_serve_does() {
        let h = Handler::new(Config::default()).unwrap();
        let s = Server::new(ServerConfig::default().handler(h.clone())).unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let saddr = sock.local_addr().unwrap();
        // Something in the read loop panics: here a poisoned lock.
        let s2 = s.clone();
        let _ = thread::spawn(move || {
            let _g = s2.peer_addrs.write().unwrap();
            panic!("poison");
        })
        .join();
        let s2 = s.clone();
        let serve = thread::spawn(move || s2.serve(sock));

        let c = Handler::new(Config::default()).unwrap();
        c.add_peer(h.public_key());
        h.add_peer(c.public_key());
        let csock = UdpSocket::bind("127.0.0.1:0").unwrap();
        csock
            .send_to(&c.initiate_handshake(&h.public_key()).unwrap(), saddr)
            .unwrap();
        assert!(serve.join().is_err(), "serve should have panicked");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !s.threads.lock().unwrap()[0].is_finished() {
            assert!(
                Instant::now() < deadline,
                "maintenance thread still running"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The maintenance thread does not keep its server alive.
    #[test]
    fn the_maintenance_thread_holds_the_server_weakly() {
        let h = Handler::new(Config::default()).unwrap();
        let s = Server::new(ServerConfig::default().handler(h)).unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let s2 = s.clone();
        let serve = thread::spawn(move || s2.serve(sock));
        while s.threads.lock().unwrap().is_empty() {
            thread::sleep(Duration::from_millis(1));
        }
        // Ours and the one serve runs on; not a third for the thread.
        assert_eq!(Arc::strong_count(&s), 2);
        s.close().unwrap();
        serve.join().unwrap().unwrap();
    }

    /// A peer the handler drops by itself, or that is removed from it
    /// directly, takes its endpoint with it. Before, the server kept one for
    /// every key ever accepted, however long gone.
    #[test]
    fn a_peer_the_handler_drops_loses_its_endpoint() {
        use crate::wg::handler::EXPIRED_PEER_GRACE;
        let h = Handler::new(Config::default().unknown_peer_limit(2)).unwrap();
        let (s, _sock) = idle_server(&h);
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let key = |i: u8| crate::wg::crypto::x25519_public(&NoisePrivateKey([i; 32]));
        let known = |k: NoisePublicKey| {
            s.peer_addrs.write().unwrap().insert(k, addr);
        };
        let long_expired = Instant::now() - EXPIRED_PEER_GRACE - Duration::from_secs(1);

        // Removed directly.
        h.add_peer(key(1));
        known(key(1));
        h.remove_peer(&key(1));
        assert_eq!(s.peer_addr(&key(1)), None, "removed");

        // Taken as unknown, expired, then pruned by maintenance.
        h.add_unknown_peer(key(2)).unwrap();
        known(key(2));
        h.set_peer_expiry(&key(2), long_expired);
        h.maintenance();
        assert_eq!(s.peer_addr(&key(2)), None, "pruned");

        // Evicted for a newcomer, one after the other: the endpoints never
        // outnumber the table.
        for i in 10..20 {
            h.add_unknown_peer(key(i)).unwrap();
            known(key(i));
            h.set_peer_expiry(&key(i), Instant::now() - Duration::from_secs(1));
            assert!(s.peer_addrs.read().unwrap().len() <= 2);
        }
        assert_eq!(h.peers().len(), 2);
        assert_eq!(s.peer_addrs.read().unwrap().len(), 2);
    }
}

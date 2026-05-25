//! UDP server loop that owns the read thread, dispatches packets into the
//! handler(s), and writes back protocol responses.
//!
//! Ported from `wg/server.go`. Concurrency is much simpler than the Go
//! version: one reader thread per call to [`Server::serve`] (the kernel
//! distributes packets across multiple `UdpSocket`s automatically; if the
//! caller wants `Concurrency > 1`, they can call `serve` from multiple threads
//! sharing the same `UdpSocket`).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::wg::handler::{Handler, PacketResult, PacketType};
use crate::wg::multihandler::MultiHandler;
use crate::wg::NoisePublicKey;
use crate::Result;

/// Callback fired when decrypted transport data arrives.
pub type OnPacketFn = Arc<dyn Fn(&[u8], NoisePublicKey, &Arc<Handler>) + Send + Sync + 'static>;

/// Callback fired when a handshake completes.
pub type OnPeerConnectedFn = Arc<dyn Fn(NoisePublicKey, &Arc<Handler>) + Send + Sync + 'static>;

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    pub handler: Option<Arc<Handler>>,
    pub multi_handler: Option<Arc<MultiHandler>>,
    pub on_packet: OnPacketFn,
    pub on_peer_connected: Option<OnPeerConnectedFn>,
    pub maintenance_interval: Option<Duration>,
    pub read_buffer_size: usize,
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
            read_buffer_size: 2048,
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
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("maintenance_interval", &self.maintenance_interval)
            .finish()
    }
}

impl Server {
    pub fn new(cfg: ServerConfig) -> Result<Arc<Self>> {
        match (cfg.handler.is_some(), cfg.multi_handler.is_some()) {
            (false, false) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "either handler or multi_handler must be set",
                ))
            }
            (true, true) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "handler and multi_handler are mutually exclusive",
                ))
            }
            _ => {}
        }
        let interval = cfg.maintenance_interval.unwrap_or(Duration::from_secs(10));
        let rb = if cfg.read_buffer_size == 0 {
            2048
        } else {
            cfg.read_buffer_size
        };

        Ok(Arc::new(Server {
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
        }))
    }

    /// Start the read loop + maintenance thread. Blocks until [`Server::close`]
    /// is called (or the socket errors permanently).
    pub fn serve(self: &Arc<Self>, conn: Arc<UdpSocket>) -> Result<()> {
        // Single short read timeout so close() unblocks promptly.
        conn.set_read_timeout(Some(Duration::from_millis(500)))?;

        *self.conn.lock().expect("conn lock") = Some(conn.clone());

        // Spawn the maintenance thread.
        let me = self.clone();
        let interval = self.maintenance_interval;
        let done = self.done.clone();
        let maint = thread::Builder::new()
            .name("wg-maint".into())
            .spawn(move || {
                let mut last = Instant::now();
                while !done.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(200));
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
        let me = self.clone();
        me.read_loop(conn);
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
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => continue,
                    _ => break,
                },
            }
        }
    }

    fn process_incoming(&self, data: &[u8], addr: SocketAddr, conn: &UdpSocket) {
        let (result, handler) = if let Some(mh) = self.multi_handler.as_ref() {
            match mh.process_packet(data, &addr) {
                Ok(mr) => (mr.result, mr.handler),
                Err(_) => return,
            }
        } else {
            let h = self.handler.as_ref().unwrap().clone();
            match h.process_packet(data, &addr) {
                Ok(r) => (r, h),
                Err(_) => return,
            }
        };

        // Update peer address (skip zero key — cookie replies etc).
        if !result.peer_key.is_zero() {
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

        self.dispatch(result, &handler, addr, conn);
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
                if result.ty == PacketType::HandshakeResponse {
                    if let Some(cb) = self.on_peer_connected.as_ref() {
                        cb(result.peer_key, handler);
                    }
                }
            }
            PacketType::TransportData => {
                (self.on_packet)(&result.data, result.peer_key, handler);
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
        let ct = handler.encrypt(data, peer_key)?;
        conn.send_to(&ct, addr)?;
        Ok(())
    }

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

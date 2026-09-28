//! Multiplex several [`Handler`]s on a single UDP port.
//!
//! For an incoming packet we route based on the message type:
//! - **type 1 (initiation)**: try every handler's MAC1.
//! - **type 2 (response)** / **type 3 (cookie reply)**: extract the receiver
//!   index and find the handler that has a pending handshake for it.
//! - **type 4 (transport)**: extract the receiver index and find the handler
//!   that owns a keypair for it.
//!
//! Routing by index needs each index to name one handler, so while a
//! handler is a member it draws its local indexes to be free in every
//! member, not only in its own tables. A handler belongs to one
//! `MultiHandler` at a time for this purpose: adding it to another moves it.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::Result;
use crate::wg::NoisePublicKey;
use crate::wg::constants::{
    MESSAGE_COOKIE_REPLY_TYPE, MESSAGE_INITIATION_TYPE, MESSAGE_RESPONSE_TYPE,
    MESSAGE_TRANSPORT_TYPE,
};
use crate::wg::handler::{Handler, PacketResult, PeerRemovedFn};
use crate::wg::handshake::check_mac1;

/// A processed-packet result tagged with the handler that produced it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MultiPacketResult {
    /// What the handler made of the packet.
    pub result: PacketResult,
    /// The member identity the packet was for.
    pub handler: Arc<Handler>,
}

/// Multiplexer over a set of handlers identified by their public keys.
/// Members can be added and removed while it runs
/// ([`add_handler`](Self::add_handler), [`remove_handler`](Self::remove_handler)),
/// no two with the same key.
#[derive(Debug)]
pub struct MultiHandler {
    handlers: RwLock<Vec<Arc<Handler>>>,
    /// Handed to members, which look each other up through it when drawing
    /// an index.
    me: Weak<MultiHandler>,
    /// Removal hooks to install on members, those added later included.
    removal_hooks: Mutex<Vec<Weak<PeerRemovedFn>>>,
}

impl MultiHandler {
    /// Build a `MultiHandler` from the given handlers. At least one is required,
    /// and duplicate public keys are rejected.
    pub fn new(handlers: Vec<Arc<Handler>>) -> Result<Arc<Self>> {
        if handlers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one handler required",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for h in &handlers {
            if !seen.insert(h.public_key()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate public key",
                ));
            }
        }
        Ok(Arc::new_cyclic(|me: &Weak<MultiHandler>| {
            for h in &handlers {
                h.set_group(me.clone());
            }
            MultiHandler {
                handlers: RwLock::new(handlers),
                me: me.clone(),
                removal_hooks: Mutex::default(),
            }
        }))
    }

    /// A snapshot of the members. Everything that calls into a handler
    /// iterates over one rather than holding the lock: a handler may run
    /// the unknown-peer callback, which may come back here (say, through
    /// [`Adapter::accept_unknown_peer`](crate::wg::Adapter::accept_unknown_peer)),
    /// and a second read lock taken while a writer waits deadlocks.
    pub fn handlers(&self) -> Vec<Arc<Handler>> {
        self.handlers.read().expect("multihandler lock").clone()
    }

    /// The member with public key `pubkey`, if there is one.
    pub fn handler(&self, pubkey: &NoisePublicKey) -> Option<Arc<Handler>> {
        self.handlers
            .read()
            .expect("multihandler lock")
            .iter()
            .find(|h| h.public_key() == *pubkey)
            .cloned()
    }

    /// Add a member. Fails with `AlreadyExists` if one with the same public
    /// key is a member already. A handler that belonged to another
    /// `MultiHandler` moves to this one (see the module docs).
    pub fn add_handler(&self, h: Arc<Handler>) -> Result<()> {
        let mut g = self.handlers.write().expect("multihandler lock");
        let pk = h.public_key();
        if g.iter().any(|x| x.public_key() == pk) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "handler with this public key already exists",
            ));
        }
        h.set_group(self.me.clone());
        // A server over this multiplexer has to hear of its peers going
        // whichever member drops them, not only the members it started with.
        {
            let mut hooks = self.removal_hooks.lock().expect("hooks lock");
            hooks.retain(|w| w.strong_count() > 0);
            for hook in hooks.iter().filter_map(Weak::upgrade) {
                h.watch_removals(&hook);
            }
        }
        g.push(h);
        Ok(())
    }

    /// [`Handler::watch_removals`] on every member, present and future.
    #[cfg_attr(target_family = "wasm", allow(dead_code))]
    pub(crate) fn watch_removals(&self, hook: &Arc<PeerRemovedFn>) {
        // Under the members lock, so a handler being added gets the hook
        // either from this loop or from add_handler.
        let g = self.handlers.read().expect("multihandler lock");
        self.removal_hooks
            .lock()
            .expect("hooks lock")
            .push(Arc::downgrade(hook));
        for h in g.iter() {
            h.watch_removals(hook);
        }
    }

    /// Remove the member with public key `pubkey` and return it, or `None`
    /// if there is none.
    pub fn remove_handler(&self, pubkey: &NoisePublicKey) -> Option<Arc<Handler>> {
        let mut g = self.handlers.write().expect("multihandler lock");
        let idx = g.iter().position(|h| h.public_key() == *pubkey)?;
        let h = g.remove(idx);
        h.leave_group(&self.me);
        Some(h)
    }

    /// Route + process one incoming packet.
    pub fn process_packet(
        &self,
        data: &[u8],
        remote_addr: &SocketAddr,
    ) -> Result<MultiPacketResult> {
        if data.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }
        let msg_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match msg_type {
            MESSAGE_INITIATION_TYPE => self.route_handshake(data, remote_addr),
            MESSAGE_RESPONSE_TYPE | MESSAGE_COOKIE_REPLY_TYPE => {
                self.route_by_receiver_index(data, remote_addr)
            }
            MESSAGE_TRANSPORT_TYPE => self.route_transport(data, remote_addr),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported message type: {}", other),
            )),
        }
    }

    fn route_handshake(&self, data: &[u8], remote_addr: &SocketAddr) -> Result<MultiPacketResult> {
        let found = self
            .handlers()
            .into_iter()
            .find(|h| check_mac1(h.public_key().as_bytes(), data));
        if let Some(h) = found {
            let res = h.process_packet(data, remote_addr)?;
            return Ok(MultiPacketResult {
                result: res,
                handler: h,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no handler matched MAC1 for initiation",
        ))
    }

    fn route_transport(&self, data: &[u8], remote_addr: &SocketAddr) -> Result<MultiPacketResult> {
        if data.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transport packet too short",
            ));
        }
        let receiver_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let found = self
            .handlers()
            .into_iter()
            .find(|h| h.has_keypair_index(receiver_idx));
        if let Some(h) = found {
            let res = h.process_packet(data, remote_addr)?;
            return Ok(MultiPacketResult {
                result: res,
                handler: h,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no handler owns receiver index {}", receiver_idx),
        ))
    }

    fn route_by_receiver_index(
        &self,
        data: &[u8],
        remote_addr: &SocketAddr,
    ) -> Result<MultiPacketResult> {
        if data.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too short for receiver index",
            ));
        }
        let msg_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let receiver_idx = if msg_type == MESSAGE_RESPONSE_TYPE {
            if data.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response packet too short",
                ));
            }
            u32::from_le_bytes([data[8], data[9], data[10], data[11]])
        } else {
            u32::from_le_bytes([data[4], data[5], data[6], data[7]])
        };

        let found = self
            .handlers()
            .into_iter()
            .find(|h| h.has_handshake_index(receiver_idx));
        if let Some(h) = found {
            let res = h.process_packet(data, remote_addr)?;
            return Ok(MultiPacketResult {
                result: res,
                handler: h,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no handler has pending handshake for {}", receiver_idx),
        ))
    }

    /// Run [`Handler::poll_timers`] on every member, pairing each action
    /// with the identity it belongs to.
    pub fn poll_timers(&self) -> Vec<(Arc<Handler>, crate::wg::TimerAction)> {
        self.handlers()
            .into_iter()
            .flat_map(|h| h.poll_timers().into_iter().map(move |a| (h.clone(), a)))
            .collect()
    }

    /// Run [`Handler::maintenance`] on every member.
    pub fn maintenance(&self) {
        for h in self.handlers() {
            h.maintenance();
        }
    }

    /// Close every member; returns the first error encountered.
    pub fn close(&self) -> Result<()> {
        let mut first: Option<io::Error> = None;
        for h in self.handlers() {
            if let Err(e) = h.close()
                && first.is_none()
            {
                first = Some(e);
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::handler::Config;

    #[test]
    fn duplicate_keys_rejected() {
        let h = Handler::new(Config::default()).unwrap();
        let err = MultiHandler::new(vec![h.clone(), h.clone()]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn handler_lookup() {
        let h1 = Handler::new(Config::default()).unwrap();
        let h2 = Handler::new(Config::default()).unwrap();
        let mh = MultiHandler::new(vec![h1.clone(), h2.clone()]).unwrap();
        assert!(mh.handler(&h1.public_key()).is_some());
        assert!(mh.handler(&h2.public_key()).is_some());
        let missing = NoisePublicKey([0xAB; 32]);
        assert!(mh.handler(&missing).is_none());
    }

    /// The unknown-peer callback runs while an initiation is being routed,
    /// and what it is documented to do (accept the peer, which looks the
    /// handlers up again) takes the handler list's lock. With a writer
    /// queued in between, as add_handler on another thread, a read lock
    /// held across the callback deadlocks.
    #[test]
    fn unknown_peer_callback_may_use_the_multihandler() {
        use std::sync::{Mutex, Weak, mpsc};
        use std::time::Duration;
        let slot: Arc<Mutex<Option<Weak<MultiHandler>>>> = Arc::new(Mutex::new(None));
        let s = slot.clone();
        let on_unknown: crate::wg::UnknownPeerFn = Arc::new(move |_, _, _| {
            let mh = s.lock().unwrap().as_ref().and_then(Weak::upgrade);
            let Some(mh) = mh else { return };
            let writer = mh.clone();
            std::thread::spawn(move || {
                let extra = Handler::new(Config::default()).unwrap();
                writer.add_handler(extra).unwrap();
            });
            // Give the writer time to queue on the lock.
            std::thread::sleep(Duration::from_millis(100));
            let _ = mh.handlers();
        });
        let server = Handler::new(Config::default().on_unknown_peer(on_unknown)).unwrap();
        let mh = MultiHandler::new(vec![server.clone()]).unwrap();
        *slot.lock().unwrap() = Some(Arc::downgrade(&mh));

        let client = Handler::new(Config::default()).unwrap();
        client.add_peer(server.public_key());
        let init = client.initiate_handshake(&server.public_key()).unwrap();
        let (tx, rx) = mpsc::channel();
        let routed = mh.clone();
        std::thread::spawn(move || {
            let addr = "127.0.0.1:1".parse().unwrap();
            let _ = routed.process_packet(&init, &addr);
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(10))
            .expect("deadlocked in the unknown-peer callback");
    }
}

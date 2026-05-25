//! Multiplex several [`Handler`]s on a single UDP port.
//!
//! For an incoming packet we route based on the message type:
//! - **type 1 (initiation)**: try every handler's MAC1.
//! - **type 2 (response)** / **type 3 (cookie reply)**: extract the receiver
//!   index and find the handler that has a pending handshake for it.
//! - **type 4 (transport)**: extract the receiver index and find the handler
//!   that owns a keypair for it.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use crate::wg::constants::{
    MESSAGE_COOKIE_REPLY_TYPE, MESSAGE_INITIATION_TYPE, MESSAGE_RESPONSE_TYPE,
    MESSAGE_TRANSPORT_TYPE,
};
use crate::wg::handler::{Handler, PacketResult};
use crate::wg::handshake::check_mac1;
use crate::wg::NoisePublicKey;
use crate::Result;

/// A processed-packet result tagged with the handler that produced it.
#[derive(Clone, Debug)]
pub struct MultiPacketResult {
    pub result: PacketResult,
    pub handler: Arc<Handler>,
}

/// Multiplexer over a fixed set of handlers identified by their public keys.
#[derive(Debug)]
pub struct MultiHandler {
    handlers: RwLock<Vec<Arc<Handler>>>,
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
        Ok(Arc::new(MultiHandler {
            handlers: RwLock::new(handlers),
        }))
    }

    pub fn handlers(&self) -> Vec<Arc<Handler>> {
        self.handlers.read().expect("multihandler lock").clone()
    }

    pub fn handler(&self, pubkey: &NoisePublicKey) -> Option<Arc<Handler>> {
        self.handlers
            .read()
            .expect("multihandler lock")
            .iter()
            .find(|h| h.public_key() == *pubkey)
            .cloned()
    }

    pub fn add_handler(&self, h: Arc<Handler>) -> Result<()> {
        let mut g = self.handlers.write().expect("multihandler lock");
        let pk = h.public_key();
        if g.iter().any(|x| x.public_key() == pk) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "handler with this public key already exists",
            ));
        }
        g.push(h);
        Ok(())
    }

    pub fn remove_handler(&self, pubkey: &NoisePublicKey) -> Option<Arc<Handler>> {
        let mut g = self.handlers.write().expect("multihandler lock");
        let idx = g.iter().position(|h| h.public_key() == *pubkey)?;
        Some(g.remove(idx))
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
        let g = self.handlers.read().expect("multihandler lock");
        for h in g.iter() {
            if check_mac1(h.public_key().as_bytes(), data) {
                let res = h.process_packet(data, remote_addr)?;
                return Ok(MultiPacketResult {
                    result: res,
                    handler: h.clone(),
                });
            }
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
        let g = self.handlers.read().expect("multihandler lock");
        for h in g.iter() {
            if h.has_keypair_index(receiver_idx) {
                let res = h.process_packet(data, remote_addr)?;
                return Ok(MultiPacketResult {
                    result: res,
                    handler: h.clone(),
                });
            }
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

        let g = self.handlers.read().expect("multihandler lock");
        for h in g.iter() {
            if h.has_handshake_index(receiver_idx) {
                let res = h.process_packet(data, remote_addr)?;
                return Ok(MultiPacketResult {
                    result: res,
                    handler: h.clone(),
                });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no handler has pending handshake for {}", receiver_idx),
        ))
    }

    /// Run [`Handler::maintenance`] on every member.
    pub fn maintenance(&self) {
        let g = self.handlers.read().expect("multihandler lock");
        for h in g.iter() {
            h.maintenance();
        }
    }

    /// Close every member; returns the first error encountered.
    pub fn close(&self) -> Result<()> {
        let g = self.handlers.read().expect("multihandler lock");
        let mut first: Option<io::Error> = None;
        for h in g.iter() {
            if let Err(e) = h.close() {
                if first.is_none() {
                    first = Some(e);
                }
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
}

//! Data-channel transport: encryption / decryption of type-4 packets.
//!
//! These functions are split out of `handler.rs` so the AEAD machinery and the
//! wire layout sit in one place. They are called by `Handler::process_packet`
//! and `Handler::encrypt`.

use std::io;
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::wg::constants::{
    CHACHAPOLY_OVERHEAD, MESSAGE_TRANSPORT_HEADER_SIZE, MESSAGE_TRANSPORT_TYPE,
    REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
};
use crate::wg::crypto::{aead_open, aead_seal_in_place};
use crate::wg::handler::{Handler, PacketResult, PacketType};
use crate::Result;

/// Total wire size of an encrypted WireGuard packet for the given plaintext
/// length: 16-byte header + plaintext + 16-byte tag.
#[inline]
pub fn encrypted_size(plaintext_len: usize) -> usize {
    MESSAGE_TRANSPORT_HEADER_SIZE + plaintext_len + CHACHAPOLY_OVERHEAD
}

/// Decrypt an incoming type-4 transport packet. Returns a [`PacketResult`]
/// classified as either `TransportData` or `Keepalive`.
pub(crate) fn process_data_packet(h: &Handler, data: &[u8]) -> Result<PacketResult> {
    if data.len() < MESSAGE_TRANSPORT_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("data packet too short: {}", data.len()),
        ));
    }

    let msg_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if msg_type != MESSAGE_TRANSPORT_TYPE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid message type: {}", msg_type),
        ));
    }

    let receiver_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let counter = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    // Find keypair by local-index.
    let kp = h
        .lookup_keypair(receiver_idx)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no keypair for receiver index"))?;

    // Reject expired keypairs (forward secrecy).
    if Instant::now().duration_since(kp.created) > REJECT_AFTER_TIME {
        return Err(io::Error::other("keypair expired"));
    }

    // Replay window check.
    if kp.replay_filter.check_replay(counter) {
        return Err(io::Error::other(format!(
            "replay detected: counter={}",
            counter
        )));
    }

    let ciphertext = &data[MESSAGE_TRANSPORT_HEADER_SIZE..];
    let plaintext = aead_open(&kp.receive_key, counter, ciphertext, &[])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt failed"))?;

    let peer_key = kp.peer_key;

    // Update session last-received timestamp.
    h.touch_session_received(&peer_key);

    let result_type = if plaintext.is_empty() {
        PacketType::Keepalive
    } else {
        PacketType::TransportData
    };

    Ok(PacketResult {
        ty: result_type,
        response: Vec::new(),
        data: plaintext,
        peer_key,
    })
}

/// Encrypt `data` for `peer_key` into a freshly allocated `Vec<u8>`. Returns
/// the full wire packet. Passing an empty `data` produces a keepalive.
///
/// If the keypair is approaching its lifetime limits, returns
/// `io::ErrorKind::WouldBlock` alongside a still-valid packet by signalling
/// via `rekey_needed` in [`encrypt_into`]; this convenience wrapper folds the
/// rekey signal into a `WouldBlock` error after the packet is built, matching
/// the Go `ErrRekeyRequired` semantics.
pub(crate) fn encrypt_data_packet(
    h: &Handler,
    data: &[u8],
    peer_key: &crate::wg::NoisePublicKey,
) -> std::result::Result<Vec<u8>, EncryptError> {
    let needed = encrypted_size(data.len());
    let mut out = vec![0u8; needed];
    let (n, rekey) = encrypt_into(h, &mut out, data, peer_key)?;
    out.truncate(n);
    if rekey {
        Err(EncryptError::RekeyRequired(out))
    } else {
        Ok(out)
    }
}

/// In-place encrypt to `dst`. Returns `(bytes_written, rekey_required)`.
///
/// `rekey_required` is `true` when the keypair has exceeded `REKEY_AFTER_*`
/// thresholds — the caller should send the packet anyway and then initiate a
/// new handshake.
pub(crate) fn encrypt_into(
    h: &Handler,
    dst: &mut [u8],
    data: &[u8],
    peer_key: &crate::wg::NoisePublicKey,
) -> std::result::Result<(usize, bool), EncryptError> {
    let needed = encrypted_size(data.len());
    if dst.len() < needed {
        return Err(EncryptError::DstTooSmall {
            needed,
            got: dst.len(),
        });
    }

    let (kp_view, kp_age) = h
        .with_current_keypair(peer_key)
        .ok_or(EncryptError::NoSession)?;
    if kp_age > REJECT_AFTER_TIME {
        return Err(EncryptError::KeypairExpired);
    }

    // Increment per-keypair counter (starts at 0).
    let counter = kp_view.send_counter.fetch_add(1, Ordering::SeqCst);
    if counter >= REJECT_AFTER_MESSAGES {
        return Err(EncryptError::MessageLimitExceeded);
    }

    // Header: type | remote-index | counter.
    dst[0..4].copy_from_slice(&MESSAGE_TRANSPORT_TYPE.to_le_bytes());
    dst[4..8].copy_from_slice(&kp_view.remote_index.to_le_bytes());
    dst[8..16].copy_from_slice(&counter.to_le_bytes());

    aead_seal_in_place(
        kp_view.send_key,
        counter,
        data,
        &[],
        &mut dst[MESSAGE_TRANSPORT_HEADER_SIZE..needed],
    );

    let rekey = counter >= REKEY_AFTER_MESSAGES || kp_age >= REKEY_AFTER_TIME;
    Ok((needed, rekey))
}

/// Errors returned by the transport-encrypt path.
#[derive(Debug)]
pub enum EncryptError {
    NoSession,
    KeypairExpired,
    MessageLimitExceeded,
    DstTooSmall {
        needed: usize,
        got: usize,
    },
    /// Encryption succeeded but the keypair is past its rekey threshold; the
    /// inner buffer is a valid wire packet that the caller may still send.
    RekeyRequired(Vec<u8>),
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::NoSession => write!(f, "no session for peer"),
            EncryptError::KeypairExpired => write!(f, "keypair expired: initiate new handshake"),
            EncryptError::MessageLimitExceeded => {
                write!(f, "keypair message limit exceeded: initiate new handshake")
            }
            EncryptError::DstTooSmall { needed, got } => {
                write!(f, "dst too small: need {}, got {}", needed, got)
            }
            EncryptError::RekeyRequired(_) => write!(f, "rekey required"),
        }
    }
}

impl std::error::Error for EncryptError {}

impl From<EncryptError> for io::Error {
    fn from(e: EncryptError) -> io::Error {
        match &e {
            EncryptError::DstTooSmall { .. } => io::Error::new(io::ErrorKind::InvalidInput, e),
            EncryptError::NoSession => io::Error::new(io::ErrorKind::NotConnected, e),
            EncryptError::KeypairExpired | EncryptError::MessageLimitExceeded => {
                io::Error::other(e)
            }
            EncryptError::RekeyRequired(_) => io::Error::new(io::ErrorKind::WouldBlock, e),
        }
    }
}

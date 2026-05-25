//! WireGuard cookie machinery (RFC: "Cookie Reply Message", §5.4.7).
//!
//! Two halves:
//! - [`CookieChecker`] lives on the responder. It validates MAC1 (always) and
//!   MAC2 (when under load), and mints cookie-reply messages keyed on a
//!   rotating secret + the requester's source address.
//! - [`CookieGenerator`] lives on the initiator, one per peer. It writes MAC1
//!   into every outgoing handshake and, once a cookie reply has been received
//!   and decrypted, also writes MAC2 so subsequent initiations survive the
//!   responder's under-load filter.

use crate::wg::constants::{
    NoisePublicKey, BLAKE2S_128_SIZE, COOKIE_REFRESH_TIME, MESSAGE_COOKIE_REPLY_SIZE,
    MESSAGE_COOKIE_REPLY_TYPE,
};
use crate::wg::crypto::{
    blake2s_mac_128, calculate_cookie_key, calculate_mac1_key, ct_eq, fill_random, xaead_open,
    xaead_seal,
};
use crate::Result;
use std::time::Instant;

/// Responder-side cookie validator + reply generator.
pub(crate) struct CookieChecker {
    mac1_key: [u8; 32],
    secret: [u8; 32],
    secret_set: Instant,
    encryption_key: [u8; 32],
}

impl CookieChecker {
    /// Build a checker keyed on the *local* (responder) public key.
    pub fn new(local_pub: &NoisePublicKey) -> CookieChecker {
        let mut secret = [0u8; 32];
        let _ = fill_random(&mut secret);
        CookieChecker {
            mac1_key: calculate_mac1_key(local_pub),
            secret,
            secret_set: Instant::now(),
            encryption_key: calculate_cookie_key(local_pub),
        }
    }

    /// Rotate the secret if it has aged past `COOKIE_REFRESH_TIME`.
    fn maybe_refresh(&mut self) {
        if self.secret_set.elapsed() > COOKIE_REFRESH_TIME {
            let _ = fill_random(&mut self.secret);
            self.secret_set = Instant::now();
        }
    }

    /// Verify the MAC1 field (last-but-one 16 bytes) of a handshake message.
    pub fn check_mac1(&self, msg: &[u8]) -> bool {
        if msg.len() < BLAKE2S_128_SIZE * 2 {
            return false;
        }
        let smac2 = msg.len() - BLAKE2S_128_SIZE;
        let smac1 = smac2 - BLAKE2S_128_SIZE;
        let computed = blake2s_mac_128(&self.mac1_key, &msg[..smac1]);
        ct_eq(&computed, &msg[smac1..smac2])
    }

    /// Verify the MAC2 field (last 16 bytes), derived from the rotating secret
    /// and the requester's source-address bytes. Fresh secret required.
    pub fn check_mac2(&self, msg: &[u8], src: &[u8]) -> bool {
        if self.secret_set.elapsed() > COOKIE_REFRESH_TIME {
            return false;
        }
        if msg.len() < BLAKE2S_128_SIZE {
            return false;
        }
        let cookie = blake2s_mac_128(&self.secret, src);
        let smac2 = msg.len() - BLAKE2S_128_SIZE;
        let computed = blake2s_mac_128(&cookie, &msg[..smac2]);
        ct_eq(&computed, &msg[smac2..])
    }

    /// Build a 64-byte cookie-reply message for `receiver_idx`, encrypting the
    /// address-bound cookie under the per-key cookie key with `init_mac1` as
    /// associated data.
    pub fn generate_reply(
        &mut self,
        src: &[u8],
        receiver_idx: u32,
        init_mac1: &[u8],
    ) -> Result<Vec<u8>> {
        self.maybe_refresh();
        let mut msg = vec![0u8; MESSAGE_COOKIE_REPLY_SIZE];
        msg[0..4].copy_from_slice(&MESSAGE_COOKIE_REPLY_TYPE.to_le_bytes());
        msg[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
        fill_random(&mut msg[8..32])?; // 24-byte nonce

        let cookie = blake2s_mac_128(&self.secret, src);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&msg[8..32]);
        let enc = xaead_seal(&self.encryption_key, &nonce, &cookie, init_mac1);
        msg[32..].copy_from_slice(&enc);
        Ok(msg)
    }
}

/// Initiator-side, per-peer MAC writer + cookie store.
pub(crate) struct CookieGenerator {
    mac1_key: [u8; 32],
    encryption_key: [u8; 32],
    cookie: [u8; BLAKE2S_128_SIZE],
    cookie_set: Option<Instant>,
    last_mac1: [u8; BLAKE2S_128_SIZE],
    has_last_mac1: bool,
}

impl CookieGenerator {
    /// Build a generator keyed on the *remote* (responder) public key.
    pub fn new(remote_pub: &NoisePublicKey) -> CookieGenerator {
        CookieGenerator {
            mac1_key: calculate_mac1_key(remote_pub),
            encryption_key: calculate_cookie_key(remote_pub),
            cookie: [0u8; BLAKE2S_128_SIZE],
            cookie_set: None,
            last_mac1: [0u8; BLAKE2S_128_SIZE],
            has_last_mac1: false,
        }
    }

    /// Compute and write MAC1 (and MAC2 if a fresh cookie is held) into the
    /// trailing 32 bytes of `msg`.
    pub fn add_macs(&mut self, msg: &mut [u8]) {
        let size = msg.len();
        if size < BLAKE2S_128_SIZE * 2 {
            return;
        }
        let smac2 = size - BLAKE2S_128_SIZE;
        let smac1 = smac2 - BLAKE2S_128_SIZE;

        let mac1 = blake2s_mac_128(&self.mac1_key, &msg[..smac1]);
        msg[smac1..smac2].copy_from_slice(&mac1);
        self.last_mac1.copy_from_slice(&mac1);
        self.has_last_mac1 = true;

        let fresh = self
            .cookie_set
            .map(|t| t.elapsed() <= COOKIE_REFRESH_TIME)
            .unwrap_or(false);
        if !fresh {
            // Leave MAC2 zeroed.
            for b in &mut msg[smac2..] {
                *b = 0;
            }
            return;
        }
        let mac2 = blake2s_mac_128(&self.cookie, &msg[..smac2]);
        msg[smac2..].copy_from_slice(&mac2);
    }

    /// Decrypt and store a received cookie. `nonce` is the 24 bytes from the
    /// reply; `ct` is the 32-byte encrypted cookie. The AAD is our last MAC1.
    pub fn consume_reply(&mut self, nonce: &[u8; 24], ct: &[u8]) -> Result<()> {
        if !self.has_last_mac1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cookie reply with no prior initiation",
            ));
        }
        let pt = xaead_open(&self.encryption_key, nonce, ct, &self.last_mac1)?;
        if pt.len() != BLAKE2S_128_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decrypted cookie wrong size",
            ));
        }
        self.cookie.copy_from_slice(&pt);
        self.cookie_set = Some(Instant::now());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::crypto::generate_private_key;
    use crate::wg::crypto::x25519_public;

    fn keypair() -> NoisePublicKey {
        let priv_k = generate_private_key().unwrap();
        x25519_public(&priv_k)
    }

    #[test]
    fn mac1_matches_between_checker_and_generator() {
        // The responder's checker uses mac1_key(responder_pub); the initiator's
        // generator targeting that responder uses the same key — so the MAC1 a
        // generator writes must validate at the checker.
        let responder = keypair();
        let checker = CookieChecker::new(&responder);
        let mut gen = CookieGenerator::new(&responder);

        // A fake 148-byte initiation: only the MAC fields matter here.
        let mut pkt = vec![7u8; 148];
        gen.add_macs(&mut pkt);
        assert!(checker.check_mac1(&pkt));

        // Corrupting the body breaks MAC1.
        pkt[0] ^= 0xFF;
        assert!(!checker.check_mac1(&pkt));
    }

    #[test]
    fn cookie_reply_roundtrip_enables_mac2() {
        let responder = keypair();
        let mut checker = CookieChecker::new(&responder);
        let mut gen = CookieGenerator::new(&responder);

        let src = [10u8, 0, 0, 9];

        // Initiator builds a first initiation (MAC1 only).
        let mut pkt = vec![3u8; 148];
        gen.add_macs(&mut pkt);
        let init_mac1 = pkt[116..132].to_vec();

        // Responder mints a cookie reply for it.
        let reply = checker.generate_reply(&src, 0x1234, &init_mac1).unwrap();
        assert_eq!(reply.len(), MESSAGE_COOKIE_REPLY_SIZE);
        assert_eq!(u32::from_le_bytes(reply[0..4].try_into().unwrap()), MESSAGE_COOKIE_REPLY_TYPE);

        // Initiator consumes the reply, then a fresh initiation carries a MAC2
        // that validates at the checker.
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&reply[8..32]);
        gen.consume_reply(&nonce, &reply[32..]).unwrap();

        let mut pkt2 = vec![5u8; 148];
        gen.add_macs(&mut pkt2);
        assert!(checker.check_mac1(&pkt2));
        assert!(checker.check_mac2(&pkt2, &src));
        // A different source address must NOT validate the MAC2.
        assert!(!checker.check_mac2(&pkt2, &[10, 0, 0, 10]));
    }

    #[test]
    fn consume_reply_without_initiation_fails() {
        let responder = keypair();
        let mut gen = CookieGenerator::new(&responder);
        let nonce = [0u8; 24];
        assert!(gen.consume_reply(&nonce, &[0u8; 32]).is_err());
    }
}

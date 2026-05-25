//! Per-direction data-channel keys derived from the PRF key expansion.
//!
//! After the TLS handshake, OpenVPN key-method 2 produces 256 bytes of key
//! material (via [`prf10`](super::prf::prf10) expansion). That block is split
//! into four 64-byte regions — cipher/HMAC for each direction. The server side
//! uses the layout below; a client reverses the encrypt/decrypt halves.
//! Ported from the Go `peer-keys.go`.

/// Data-channel keys for one peer, split per direction.
///
/// Each field is 64 bytes; the relevant prefix is used depending on the
/// cipher/HMAC sizes negotiated (e.g. 32 bytes for AES-256, the HMAC tail for
/// the GCM implicit IV).
pub struct PeerKeys {
    pub cipher_encrypt: [u8; 64],
    pub hmac_encrypt: [u8; 64],
    pub cipher_decrypt: [u8; 64],
    pub hmac_decrypt: [u8; 64],
}

impl std::fmt::Debug for PeerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("PeerKeys").finish_non_exhaustive()
    }
}

impl PeerKeys {
    /// Split the 256-byte PRF expansion into per-direction keys (server layout).
    ///
    /// Panics if `main` is not exactly 256 bytes, matching the Go upstream's
    /// invariant — callers always pass the fixed-size expansion buffer.
    pub fn from_expansion(main: &[u8]) -> PeerKeys {
        assert_eq!(main.len(), 256, "invalid length for peer keys master");
        let mut k = PeerKeys {
            cipher_encrypt: [0; 64],
            hmac_encrypt: [0; 64],
            cipher_decrypt: [0; 64],
            hmac_decrypt: [0; 64],
        };
        // Server-side order (a client reverses decrypt/encrypt).
        k.cipher_decrypt.copy_from_slice(&main[0..64]);
        k.hmac_decrypt.copy_from_slice(&main[64..128]);
        k.cipher_encrypt.copy_from_slice(&main[128..192]);
        k.hmac_encrypt.copy_from_slice(&main[192..256]);
        k
    }
}

impl Drop for PeerKeys {
    fn drop(&mut self) {
        // Best-effort wipe of key material. `write_volatile` prevents the
        // compiler from eliding the stores. (The `zeroize` crate is only a
        // dependency of the `wg` feature, so we do this by hand here.)
        for buf in [
            &mut self.cipher_encrypt,
            &mut self.hmac_encrypt,
            &mut self.cipher_decrypt,
            &mut self.hmac_decrypt,
        ] {
            for b in buf.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_expansion_layout() {
        let material: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let keys = PeerKeys::from_expansion(&material);
        for i in 0..64 {
            assert_eq!(keys.cipher_decrypt[i], i as u8);
            assert_eq!(keys.hmac_decrypt[i], (64 + i) as u8);
            assert_eq!(keys.cipher_encrypt[i], (128 + i) as u8);
            assert_eq!(keys.hmac_encrypt[i], (192 + i) as u8);
        }
    }

    #[test]
    #[should_panic]
    fn from_expansion_bad_len_panics() {
        PeerKeys::from_expansion(&[0u8; 128]);
    }
}

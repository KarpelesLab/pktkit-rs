//! WireGuard wire-protocol constants and key types.
//!
//! Ported from `wg/constants.go`. The Noise IKpsk2 transcript labels and
//! message sizes are baked into the spec; nothing here is configurable.

use core::fmt;
use std::time::Duration;

// === Noise / WireGuard protocol labels =====================================

pub(crate) const WG_LABEL_MAC1: &[u8] = b"mac1----";
pub(crate) const WG_LABEL_COOKIE: &[u8] = b"cookie--";

pub(crate) const NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub(crate) const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

// === Sizes (bytes) =========================================================

/// TAI64N timestamp size: 8 bytes seconds + 4 bytes nanoseconds.
pub(crate) const TAI64N_TIMESTAMP_SIZE: usize = 12;

/// Blake2s-128 (truncated MAC) size.
pub(crate) const BLAKE2S_128_SIZE: usize = 16;

/// Blake2s-256 output size.
pub(crate) const BLAKE2S_256_SIZE: usize = 32;

/// ChaCha20-Poly1305 authentication tag size.
pub(crate) const CHACHAPOLY_OVERHEAD: usize = 16;

/// ChaCha20-Poly1305 96-bit nonce size.
#[allow(dead_code)]
pub(crate) const CHACHAPOLY_NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 192-bit nonce size.
#[allow(dead_code)]
pub(crate) const XCHACHAPOLY_NONCE_SIZE: usize = 24;

/// ChaCha20-Poly1305 key size.
pub(crate) const CHACHAPOLY_KEY_SIZE: usize = 32;

// === WireGuard message types ===============================================

pub(crate) const MESSAGE_INITIATION_TYPE: u32 = 1;
pub(crate) const MESSAGE_RESPONSE_TYPE: u32 = 2;
pub(crate) const MESSAGE_COOKIE_REPLY_TYPE: u32 = 3;
pub(crate) const MESSAGE_TRANSPORT_TYPE: u32 = 4;

// === Wire sizes ============================================================

pub(crate) const MESSAGE_INITIATION_SIZE: usize = 148;
pub(crate) const MESSAGE_RESPONSE_SIZE: usize = 92;
pub(crate) const MESSAGE_COOKIE_REPLY_SIZE: usize = 64;
pub(crate) const MESSAGE_TRANSPORT_HEADER_SIZE: usize = 16;

// === Timers (WireGuard spec §6 / §5.1) =====================================

/// Maximum lifetime of a cookie secret.
pub const COOKIE_REFRESH_TIME: Duration = Duration::from_secs(120);

/// How long sessions and pending handshakes stick around before maintenance
/// removes them.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Initiate a rekey once a keypair has encrypted this many messages.
pub const REKEY_AFTER_MESSAGES: u64 = 1u64 << 60;

/// Hard limit; a keypair beyond this counter must be retired.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1u64 << 13);

/// Initiate a rekey when the keypair is older than this.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

// === DoS mitigation thresholds =============================================

pub(crate) const DEFAULT_LOAD_THRESHOLD: usize = 20;

/// Size of the per-keypair replay window.
pub const WINDOW_SIZE: usize = 8192;

/// Maximum number of in-flight handshakes per handler before new entries are
/// rejected.
pub(crate) const MAX_HANDSHAKES: usize = 10000;

/// Maximum number of established sessions per handler.
pub(crate) const MAX_SESSIONS: usize = 10000;

// === Key sizes =============================================================

pub const NOISE_PUBLIC_KEY_SIZE: usize = 32;
pub const NOISE_PRIVATE_KEY_SIZE: usize = 32;
pub const NOISE_PRESHARED_KEY_SIZE: usize = 32;

// === Key newtypes ==========================================================

/// A Curve25519 public key. Equality and hashing operate on the raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoisePublicKey(pub [u8; NOISE_PUBLIC_KEY_SIZE]);

impl NoisePublicKey {
    #[inline]
    pub const fn zero() -> Self {
        Self([0u8; NOISE_PUBLIC_KEY_SIZE])
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; NOISE_PUBLIC_KEY_SIZE] {
        &self.0
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; NOISE_PUBLIC_KEY_SIZE]
    }
}

impl From<[u8; NOISE_PUBLIC_KEY_SIZE]> for NoisePublicKey {
    fn from(b: [u8; NOISE_PUBLIC_KEY_SIZE]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for NoisePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Stable, compact debug: first 4 bytes hex, no key leakage beyond that.
        let b = &self.0;
        write!(
            f,
            "NoisePublicKey({:02x}{:02x}{:02x}{:02x}...)",
            b[0], b[1], b[2], b[3]
        )
    }
}

/// A Curve25519 private key. Bytes are zeroed on drop.
#[derive(Clone, Default)]
pub struct NoisePrivateKey(pub [u8; NOISE_PRIVATE_KEY_SIZE]);

impl NoisePrivateKey {
    #[inline]
    pub const fn zero() -> Self {
        Self([0u8; NOISE_PRIVATE_KEY_SIZE])
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; NOISE_PRIVATE_KEY_SIZE] {
        &self.0
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; NOISE_PRIVATE_KEY_SIZE]
    }
}

impl From<[u8; NOISE_PRIVATE_KEY_SIZE]> for NoisePrivateKey {
    fn from(b: [u8; NOISE_PRIVATE_KEY_SIZE]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for NoisePrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoisePrivateKey(<redacted>)")
    }
}

impl Drop for NoisePrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// A preshared key (optional second factor mixed into the Noise transcript).
#[derive(Clone)]
pub struct NoisePresharedKey(pub [u8; NOISE_PRESHARED_KEY_SIZE]);

impl NoisePresharedKey {
    #[inline]
    pub const fn zero() -> Self {
        Self([0u8; NOISE_PRESHARED_KEY_SIZE])
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; NOISE_PRESHARED_KEY_SIZE] {
        &self.0
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; NOISE_PRESHARED_KEY_SIZE]
    }
}

impl From<[u8; NOISE_PRESHARED_KEY_SIZE]> for NoisePresharedKey {
    fn from(b: [u8; NOISE_PRESHARED_KEY_SIZE]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for NoisePresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoisePresharedKey(<redacted>)")
    }
}

impl Drop for NoisePresharedKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Internal handshake state-machine marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum HandshakeState {
    Zeroed,
    InitiationCreated,
    ResponseCreated,
}

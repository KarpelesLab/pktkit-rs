//! Parse and render the OpenVPN options string,
//! e.g. `V4,dev-type tun,link-mtu 1570,tun-mtu 1500,proto UDPv4,cipher AES-128-CBC,…`.

use super::consts::{CipherBlockMethod, CipherCryptoAlg};
use core::fmt;

/// Hash algorithm for the OpenVPN HMAC auth.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum AuthHash {
    #[default]
    None,
    Sha1,
    Sha224,
    Sha256,
}

impl AuthHash {
    fn from_str(s: &str) -> Result<AuthHash, String> {
        match s {
            "[null-digest]" => Ok(AuthHash::None),
            "SHA1" => Ok(AuthHash::Sha1),
            "SHA224" => Ok(AuthHash::Sha224),
            "SHA256" => Ok(AuthHash::Sha256),
            other => Err(format!("unrecognized crypto hash {other:?}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AuthHash::None => "[null-digest]",
            AuthHash::Sha1 => "SHA1",
            AuthHash::Sha224 => "SHA224",
            AuthHash::Sha256 => "SHA256",
        }
    }
}

/// Parsed and renderable OpenVPN options string.
///
/// The default constructor mirrors the upstream's `NewOptions()`:
/// AES-128-CBC + SHA256, tun, UDPv4, LZO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub version: u32,
    pub is_server: bool,
    pub dev_type: String, // "tun" or "tap"
    pub link_mtu: u64,
    pub tun_mtu: u64,
    pub proto: String,
    pub compression: String,
    pub cipher_crypto: CipherCryptoAlg,
    pub cipher_size: u32,
    pub cipher_block: CipherBlockMethod,
    pub auth: AuthHash,
    pub key_size: u64,
    pub key_method: u64,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            version: 4,
            is_server: true,
            dev_type: "tun".to_string(),
            link_mtu: 1500,
            tun_mtu: 1500 - 70,
            proto: "UDPv4".to_string(),
            compression: "lzo".to_string(),
            cipher_crypto: CipherCryptoAlg::Aes,
            cipher_size: 128,
            cipher_block: CipherBlockMethod::Cbc,
            auth: AuthHash::Sha256,
            key_size: 128,
            key_method: 2,
        }
    }
}

impl Options {
    /// Parse an `V4,…` options string (the format OpenVPN exchanges during
    /// negotiation). Returns the error as a String to keep the dependency
    /// footprint minimal.
    pub fn parse(s: &str) -> Result<Options, String> {
        let mut o = Options::default();
        let mut parts = s.split(',');
        let first = parts.next().ok_or("empty options")?;
        if first != "V4" {
            return Err("expected V4 options string".into());
        }
        for part in parts {
            let (k, v) = match part.find(' ') {
                Some(i) => (&part[..i], &part[i + 1..]),
                None => (part, ""),
            };
            match k {
                "dev-type" => match v {
                    "tun" | "tap" => o.dev_type = v.into(),
                    _ => return Err(format!("invalid dev-type {v:?}")),
                },
                "link-mtu" => {
                    o.link_mtu = v.parse().map_err(|e| format!("link-mtu: {e}"))?
                }
                "tun-mtu" => o.tun_mtu = v.parse().map_err(|e| format!("tun-mtu: {e}"))?,
                "proto" => o.proto = v.into(),
                "cipher" => o.parse_cipher(v)?,
                "auth" => o.auth = AuthHash::from_str(v)?,
                "keysize" => o.key_size = v.parse().map_err(|e| format!("keysize: {e}"))?,
                "key-method" => {
                    o.key_method = v.parse().map_err(|e| format!("key-method: {e}"))?
                }
                _ => {} // ignore unknown options for forward-compat
            }
        }
        Ok(o)
    }

    fn parse_cipher(&mut self, c: &str) -> Result<(), String> {
        if c == "[null-cipher]" {
            self.cipher_crypto = CipherCryptoAlg::None;
            return Ok(());
        }
        let parts: Vec<&str> = c.split('-').collect();
        if parts.len() != 3 {
            return Err("invalid cipher format, expected ALG-SIZE-MODE".into());
        }
        if parts[0] != "AES" {
            return Err("only AES is supported".into());
        }
        self.cipher_crypto = CipherCryptoAlg::Aes;
        self.cipher_size = match parts[1] {
            "128" => 128,
            "256" => 256,
            other => return Err(format!("invalid cipher block size {other:?}")),
        };
        self.cipher_block = match parts[2] {
            "CBC" => CipherBlockMethod::Cbc,
            "GCM" => CipherBlockMethod::Gcm,
            other => return Err(format!("invalid cipher block mode {other:?}")),
        };
        Ok(())
    }
}

impl fmt::Display for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "V{},dev-type {},link-mtu {},tun-mtu {},proto {}",
            self.version, self.dev_type, self.link_mtu, self.tun_mtu, self.proto
        )?;
        if self.compression != "none" {
            f.write_str(",comp-lzo")?;
        }
        if self.cipher_crypto == CipherCryptoAlg::None {
            f.write_str(",cipher [null-cipher]")?;
        } else {
            write!(
                f,
                ",cipher {}-{}-{}",
                self.cipher_crypto, self.cipher_size, self.cipher_block
            )?;
        }
        write!(f, ",auth {}", self.auth.as_str())?;
        write!(f, ",keysize {}", self.key_size)?;
        write!(f, ",key-method {}", self.key_method)?;
        if self.is_server {
            f.write_str(",tls-server")?;
        } else {
            f.write_str(",tls-client")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roundtrip() {
        let o = Options::default();
        let s = o.to_string();
        assert!(s.starts_with("V4,dev-type tun,"));
        assert!(s.contains(",cipher AES-128-CBC,"));
        assert!(s.contains(",auth SHA256,"));
        assert!(s.ends_with(",tls-server"));
    }

    #[test]
    fn parse_basic() {
        let s = "V4,dev-type tun,link-mtu 1570,tun-mtu 1500,proto UDPv4,comp-lzo,\
                 cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-client";
        let o = Options::parse(s).unwrap();
        assert_eq!(o.dev_type, "tun");
        assert_eq!(o.link_mtu, 1570);
        assert_eq!(o.cipher_size, 256);
        assert_eq!(o.cipher_block, CipherBlockMethod::Gcm);
    }

    #[test]
    fn rejects_non_v4_header() {
        assert!(Options::parse("V3,…").is_err());
    }

    #[test]
    fn rejects_malformed_cipher() {
        assert!(Options::parse("V4,cipher AES-128").is_err());
        assert!(Options::parse("V4,cipher DES-128-CBC").is_err());
    }
}

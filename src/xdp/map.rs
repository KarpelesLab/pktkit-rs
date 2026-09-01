//! eBPF maps: creation and element access from userspace.
//!
//! Only the map types this crate needs are wrapped — [`MapType::XSKMAP`] to
//! hand AF_XDP sockets to a redirecting program, and [`MapType::LPM_TRIE`] to
//! hold the set of IP prefixes the capture program matches against. Both are
//! read from the datapath by the in-kernel program and written from here.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::sys::{self, MapCreateAttr, MapElemAttr, bpf_cmd, ctx_err};
use crate::{IpPrefix, Result};

/// `bpf_map_type`. Open newtype: the kernel adds types faster than we care to
/// track, and only the ones named here are exercised.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapType(pub u32);

impl MapType {
    pub const HASH: MapType = MapType(1);
    pub const ARRAY: MapType = MapType(2);
    pub const LPM_TRIE: MapType = MapType(11);
    pub const XSKMAP: MapType = MapType(17);
}

/// `BPF_F_NO_PREALLOC`. Mandatory for `LPM_TRIE`, which allocates nodes as
/// they are inserted.
pub const BPF_F_NO_PREALLOC: u32 = 1 << 0;

/// Update semantics for [`Map::update`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateFlags(pub u64);

impl UpdateFlags {
    /// Create or replace.
    pub const ANY: UpdateFlags = UpdateFlags(0);
    /// Create only; fails with `EEXIST` if present.
    pub const NOEXIST: UpdateFlags = UpdateFlags(1);
    /// Replace only; fails with `ENOENT` if absent.
    pub const EXIST: UpdateFlags = UpdateFlags(2);
}

/// An eBPF map. Closes its file descriptor on drop; the kernel frees the map
/// once no program or fd references it any more.
#[derive(Debug)]
pub struct Map {
    fd: OwnedFd,
    kind: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

impl Map {
    /// Create a map. `flags` carries `BPF_F_*` bits; see [`BPF_F_NO_PREALLOC`].
    pub fn create(
        kind: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        flags: u32,
    ) -> Result<Map> {
        let mut attr = MapCreateAttr {
            map_type: kind.0,
            key_size,
            value_size,
            max_entries,
            map_flags: flags,
        };
        // SAFETY: attr matches BPF_MAP_CREATE and holds no pointers.
        let fd = unsafe { bpf_cmd(sys::BPF_MAP_CREATE, &mut attr) }
            .map_err(|e| ctx_err("map create", e))?;
        Ok(Map {
            // SAFETY: bpf() returned a fresh, owned fd on success.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            kind,
            key_size,
            value_size,
            max_entries,
        })
    }

    /// An XSKMAP with one slot per NIC queue: queue index -> AF_XDP socket.
    pub fn xskmap(max_entries: u32) -> Result<Map> {
        Map::create(MapType::XSKMAP, 4, 4, max_entries, 0)
    }

    /// A longest-prefix-match trie keyed by `addr_len`-byte addresses.
    ///
    /// The key the kernel expects is `struct bpf_lpm_trie_key { u32 prefixlen;
    /// u8 data[addr_len]; }` — build one with [`lpm_key`].
    pub fn lpm_trie(addr_len: u32, value_size: u32, max_entries: u32) -> Result<Map> {
        Map::create(
            MapType::LPM_TRIE,
            4 + addr_len,
            value_size,
            max_entries,
            BPF_F_NO_PREALLOC,
        )
    }

    #[inline]
    pub fn kind(&self) -> MapType {
        self.kind
    }

    #[inline]
    pub fn key_size(&self) -> u32 {
        self.key_size
    }

    #[inline]
    pub fn value_size(&self) -> u32 {
        self.value_size
    }

    #[inline]
    pub fn max_entries(&self) -> u32 {
        self.max_entries
    }

    fn check_key(&self, key: &[u8]) -> Result<()> {
        if key.len() != self.key_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xdp: map key is {} bytes, expected {}",
                    key.len(),
                    self.key_size
                ),
            ));
        }
        Ok(())
    }

    /// Insert or replace `key -> value`.
    pub fn update(&self, key: &[u8], value: &[u8], flags: UpdateFlags) -> Result<()> {
        self.check_key(key)?;
        if value.len() != self.value_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xdp: map value is {} bytes, expected {}",
                    value.len(),
                    self.value_size
                ),
            ));
        }
        let mut attr = MapElemAttr {
            map_fd: self.fd.as_raw_fd() as u32,
            _pad: 0,
            key: key.as_ptr() as u64,
            value: value.as_ptr() as u64,
            flags: flags.0,
        };
        // SAFETY: key/value point at caller slices of exactly the sizes the
        // map was created with, and outlive the call.
        unsafe { bpf_cmd(sys::BPF_MAP_UPDATE_ELEM, &mut attr) }
            .map_err(|e| ctx_err("map update", e))?;
        Ok(())
    }

    /// Read `key` into `out`. Returns `false` if the key is absent.
    pub fn lookup(&self, key: &[u8], out: &mut [u8]) -> Result<bool> {
        self.check_key(key)?;
        if out.len() != self.value_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xdp: lookup buffer is {} bytes, expected {}",
                    out.len(),
                    self.value_size
                ),
            ));
        }
        let mut attr = MapElemAttr {
            map_fd: self.fd.as_raw_fd() as u32,
            _pad: 0,
            key: key.as_ptr() as u64,
            value: out.as_mut_ptr() as u64,
            flags: 0,
        };
        // SAFETY: as for `update`; `out` is writable for value_size bytes.
        match unsafe { bpf_cmd(sys::BPF_MAP_LOOKUP_ELEM, &mut attr) } {
            Ok(_) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(e) => Err(ctx_err("map lookup", e)),
        }
    }

    /// Remove `key`. Returns `false` if it was not present.
    pub fn delete(&self, key: &[u8]) -> Result<bool> {
        self.check_key(key)?;
        let mut attr = MapElemAttr {
            map_fd: self.fd.as_raw_fd() as u32,
            _pad: 0,
            key: key.as_ptr() as u64,
            value: 0,
            flags: 0,
        };
        // SAFETY: as for `update`; delete reads only the key.
        match unsafe { bpf_cmd(sys::BPF_MAP_DELETE_ELEM, &mut attr) } {
            Ok(_) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(e) => Err(ctx_err("map delete", e)),
        }
    }

    /// Bind an AF_XDP socket to a queue index in an XSKMAP.
    pub fn set_socket(&self, queue_id: u32, socket_fd: RawFd) -> Result<()> {
        self.update(
            &queue_id.to_ne_bytes(),
            &(socket_fd as u32).to_ne_bytes(),
            UpdateFlags::ANY,
        )
    }

    /// Give up ownership of the map's file descriptor. The map lives as long
    /// as the fd, or any program referencing it, does.
    #[inline]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
}

impl AsRawFd for Map {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Bind an AF_XDP socket to a queue index in an XSKMAP identified only by its
/// file descriptor.
///
/// For the case where the program and its map belong to somebody else and all
/// we were handed is the fd.
pub fn set_socket_raw(map_fd: RawFd, queue_id: u32, socket_fd: RawFd) -> Result<()> {
    let key = queue_id.to_ne_bytes();
    let value = (socket_fd as u32).to_ne_bytes();
    let mut attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad: 0,
        key: key.as_ptr() as u64,
        value: value.as_ptr() as u64,
        flags: UpdateFlags::ANY.0,
    };
    // SAFETY: key and value are 4-byte locals matching an XSKMAP's geometry,
    // and both outlive the call.
    unsafe { bpf_cmd(sys::BPF_MAP_UPDATE_ELEM, &mut attr) }
        .map_err(|e| ctx_err("xskmap update", e))?;
    Ok(())
}

/// The largest `bpf_lpm_trie_key` we build: 4-byte prefix length plus a
/// 16-byte IPv6 address.
const LPM_KEY_MAX: usize = 4 + 16;

/// A `struct bpf_lpm_trie_key` laid out for the kernel.
///
/// `prefixlen` is a native-endian `u32`; the address bytes that follow stay in
/// network order, because the trie walks them most-significant byte first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpmKey {
    buf: [u8; LPM_KEY_MAX],
    len: usize,
}

impl LpmKey {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Length in bytes of the address portion (4 for v4, 16 for v6).
    #[inline]
    pub fn addr_len(&self) -> usize {
        self.len - 4
    }
}

/// Build the trie key for `prefix`.
///
/// Host bits are masked off first: the trie only compares `prefixlen` bits, so
/// leaving them set would let `10.0.0.1/24` and `10.0.0.2/24` occupy two nodes
/// that match identically.
pub fn lpm_key(prefix: IpPrefix) -> LpmKey {
    let prefix = prefix.masked();
    let mut buf = [0u8; LPM_KEY_MAX];
    buf[..4].copy_from_slice(&(prefix.bits() as u32).to_ne_bytes());
    let len = match prefix.addr() {
        IpAddr::V4(a) => {
            buf[4..8].copy_from_slice(&a.octets());
            8
        }
        IpAddr::V6(a) => {
            buf[4..20].copy_from_slice(&a.octets());
            20
        }
    };
    LpmKey { buf, len }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn v4_key_layout() {
        let k = lpm_key(IpPrefix::new(Ipv4Addr::new(192, 0, 2, 5).into(), 32));
        assert_eq!(k.as_bytes().len(), 8);
        assert_eq!(&k.as_bytes()[..4], &32u32.to_ne_bytes());
        // Address stays in network order.
        assert_eq!(&k.as_bytes()[4..], &[192, 0, 2, 5]);
    }

    #[test]
    fn v6_key_layout() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let k = lpm_key(IpPrefix::new(addr.into(), 128));
        assert_eq!(k.as_bytes().len(), 20);
        assert_eq!(&k.as_bytes()[..4], &128u32.to_ne_bytes());
        assert_eq!(&k.as_bytes()[4..], &addr.octets());
        assert_eq!(k.addr_len(), 16);
    }

    #[test]
    fn host_bits_are_masked() {
        // 10.1.2.3/24 and 10.1.2.9/24 must produce the same trie node.
        let a = lpm_key(IpPrefix::new(Ipv4Addr::new(10, 1, 2, 3).into(), 24));
        let b = lpm_key(IpPrefix::new(Ipv4Addr::new(10, 1, 2, 9).into(), 24));
        assert_eq!(a, b);
        assert_eq!(&a.as_bytes()[4..], &[10, 1, 2, 0]);
    }

    #[test]
    fn key_size_matches_lpm_trie_map_geometry() {
        // What lpm_key produces must equal 4 + addr_len, the key_size
        // Map::lpm_trie registers with the kernel.
        let v4 = lpm_key(IpPrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0));
        let v6 = lpm_key(IpPrefix::new(Ipv6Addr::UNSPECIFIED.into(), 0));
        assert_eq!(v4.as_bytes().len(), 4 + 4);
        assert_eq!(v6.as_bytes().len(), 4 + 16);
    }
}

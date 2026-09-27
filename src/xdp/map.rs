//! eBPF maps: creation and element access from userspace.
//!
//! Only the map types this crate needs are wrapped — [`MapType::XSKMAP`] to
//! hand AF_XDP sockets to a redirecting program, and [`MapType::LPM_TRIE`] to
//! hold the set of IP prefixes the capture program matches against. Both are
//! read from the datapath by the in-kernel program and written from here.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::sys::{self, MapCreateAttr, MapElemAttr, MapInfo, ObjInfoAttr, bpf_cmd, ctx_err};
use crate::{IpPrefix, Result};

/// `bpf_map_type`. Open newtype: the kernel adds types faster than we care to
/// track, and only the ones named here are exercised.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapType(pub u32);

impl MapType {
    pub const HASH: MapType = MapType(1);
    pub const ARRAY: MapType = MapType(2);
    pub const PERCPU_HASH: MapType = MapType(5);
    pub const PERCPU_ARRAY: MapType = MapType(6);
    pub const LRU_PERCPU_HASH: MapType = MapType(10);
    pub const LPM_TRIE: MapType = MapType(11);
    pub const XSKMAP: MapType = MapType(17);
    pub const PERCPU_CGROUP_STORAGE: MapType = MapType(21);

    /// True for the types whose elements hold one value per possible CPU.
    ///
    /// Userspace reads and writes such an element as
    /// `round_up(value_size, 8) * num_possible_cpus()` bytes, not
    /// `value_size`, which [`Map::lookup`] and [`Map::update`] do not support.
    pub fn is_per_cpu(self) -> bool {
        matches!(
            self,
            MapType::PERCPU_HASH
                | MapType::PERCPU_ARRAY
                | MapType::LRU_PERCPU_HASH
                | MapType::PERCPU_CGROUP_STORAGE
        )
    }
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

    /// Refuse element access whose size the kernel would not take from
    /// `value_size`: a per-CPU map copies a value per possible CPU, which
    /// would overrun a `value_size` buffer in both directions.
    fn check_value_access(&self) -> Result<()> {
        if self.kind.is_per_cpu() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "xdp: map type {} holds a value per CPU; element access is not supported",
                    self.kind.0
                ),
            ));
        }
        Ok(())
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
    ///
    /// Fails with [`io::ErrorKind::Unsupported`] on a per-CPU map; see
    /// [`MapType::is_per_cpu`].
    pub fn update(&self, key: &[u8], value: &[u8], flags: UpdateFlags) -> Result<()> {
        self.check_value_access()?;
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
    ///
    /// Fails with [`io::ErrorKind::Unsupported`] on a per-CPU map; see
    /// [`MapType::is_per_cpu`].
    pub fn lookup(&self, key: &[u8], out: &mut [u8]) -> Result<bool> {
        self.check_value_access()?;
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
            Err(e) if e.raw_os_error() == Some(crate::syscall::ENOENT) => Ok(false),
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
            Err(e) if e.raw_os_error() == Some(crate::syscall::ENOENT) => Ok(false),
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
/// we were handed is the fd. The map is checked to be an XSKMAP first: any
/// other geometry would have the kernel read past the 4-byte key or value.
pub fn set_socket_raw(map_fd: RawFd, queue_id: u32, socket_fd: RawFd) -> Result<()> {
    let info = map_info(map_fd)?;
    if info.map_type != MapType::XSKMAP.0 || info.key_size != 4 || info.value_size != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "xdp: fd {map_fd} is not an XSKMAP (type {}, key {} bytes, value {} bytes)",
                info.map_type, info.key_size, info.value_size
            ),
        ));
    }
    if queue_id >= info.max_entries {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "xdp: queue {queue_id} is past the {} slots of the XSKMAP at fd {map_fd}",
                info.max_entries
            ),
        ));
    }
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

/// What the kernel says about the map behind `fd`.
fn map_info(fd: RawFd) -> Result<MapInfo> {
    let mut info = MapInfo::default();
    let mut attr = ObjInfoAttr {
        bpf_fd: fd as u32,
        info_len: std::mem::size_of::<MapInfo>() as u32,
        info: &mut info as *mut MapInfo as u64,
    };
    // SAFETY: `info` is writable for `info_len` bytes, which caps what the
    // kernel copies out, and outlives the call.
    unsafe { bpf_cmd(sys::BPF_OBJ_GET_INFO_BY_FD, &mut attr) }
        .map_err(|e| ctx_err("map info", e))?;
    Ok(info)
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
    fn per_cpu_maps_refuse_element_access_before_the_kernel_sees_it() {
        // A per-CPU lookup has the kernel write a value per possible CPU,
        // far past a `value_size` buffer. Any fd will do: the call must be
        // refused before one is issued.
        let fd =
            crate::syscall::socket(crate::syscall::AF_INET, crate::syscall::SOCK_DGRAM, 0).unwrap();
        for kind in [
            MapType::PERCPU_HASH,
            MapType::PERCPU_ARRAY,
            MapType::LRU_PERCPU_HASH,
            MapType::PERCPU_CGROUP_STORAGE,
        ] {
            let map = Map {
                fd: fd.try_clone().unwrap(),
                kind,
                key_size: 4,
                value_size: 4,
                max_entries: 1,
            };
            let mut out = [0u8; 4];
            let e = map.lookup(&[0; 4], &mut out).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{e}");
            let e = map.update(&[0; 4], &[0; 4], UpdateFlags::ANY).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{e}");
        }
        assert!(!MapType::XSKMAP.is_per_cpu());
        assert!(!MapType::LPM_TRIE.is_per_cpu());
    }

    #[test]
    fn a_non_map_fd_is_not_taken_for_an_xskmap() {
        let s =
            crate::syscall::socket(crate::syscall::AF_INET, crate::syscall::SOCK_DGRAM, 0).unwrap();
        assert!(set_socket_raw(s.as_raw_fd(), 0, 0).is_err());
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

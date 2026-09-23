//! The Linux syscalls behind XDP and AF_XDP, as `io::Result`s.
//!
//! Two targets speak the Linux kernel ABI: `target_os = "linux"`, where libc
//! sits between us and the kernel, and `target_os = "fullrust"`, which has no
//! libc at all and is not in the `unix` family. Everything here funnels into a
//! single `syscall(nr, args)` — libc's `syscall(3)` on the first, the
//! `syscall` instruction on the second — so both run the same wrappers and
//! differ only in the trap and the numbers.
//!
//! On Linux the constants still come from libc, which knows the handful of
//! architectures where they differ; fullrust is x86-64 only, so its values are
//! the x86-64 ones from the kernel headers.

// Most of this is AF_XDP's; `xdp` alone needs only sockets and `bpf(2)`.
#![cfg_attr(not(feature = "afxdp"), allow(dead_code, unused_imports))]

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::Result;

#[cfg(all(target_os = "fullrust", not(target_arch = "x86_64")))]
compile_error!("pktkit's XDP support on fullrust only knows the x86-64 syscall ABI");

#[cfg(target_os = "linux")]
mod nr {
    #[cfg(test)]
    pub use libc::SYS_sched_getaffinity as SCHED_GETAFFINITY;
    pub use libc::{
        SYS_bind as BIND, SYS_bpf as BPF, SYS_getsockopt as GETSOCKOPT, SYS_ioctl as IOCTL,
        SYS_mmap as MMAP, SYS_munmap as MUNMAP, SYS_ppoll as PPOLL, SYS_recvfrom as RECVFROM,
        SYS_sched_setaffinity as SCHED_SETAFFINITY, SYS_sendto as SENDTO,
        SYS_setsockopt as SETSOCKOPT, SYS_socket as SOCKET,
    };
}

// arch/x86/entry/syscalls/syscall_64.tbl
#[cfg(target_os = "fullrust")]
mod nr {
    pub const IOCTL: i64 = 16;
    pub const MMAP: i64 = 9;
    pub const MUNMAP: i64 = 11;
    pub const SOCKET: i64 = 41;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const BIND: i64 = 49;
    pub const SETSOCKOPT: i64 = 54;
    pub const GETSOCKOPT: i64 = 55;
    pub const SCHED_SETAFFINITY: i64 = 203;
    #[cfg(test)]
    pub const SCHED_GETAFFINITY: i64 = 204;
    pub const PPOLL: i64 = 271;
    pub const BPF: i64 = 321;
}

#[cfg(target_os = "linux")]
pub(crate) use libc::{
    AF_INET, AF_NETLINK, AF_UNSPEC, AF_XDP, ENODEV, ENOENT, MAP_ANONYMOUS, MAP_HUGETLB,
    MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MSG_DONTWAIT, POLLIN, PROT_READ, PROT_WRITE, SOCK_DGRAM,
    SOCK_RAW, SOL_SOCKET,
};

#[cfg(target_os = "fullrust")]
mod consts {
    pub(crate) const AF_UNSPEC: i32 = 0;
    pub(crate) const AF_INET: i32 = 2;
    pub(crate) const AF_NETLINK: i32 = 16;
    pub(crate) const AF_XDP: i32 = 44;
    pub(crate) const SOCK_DGRAM: i32 = 2;
    pub(crate) const SOCK_RAW: i32 = 3;
    pub(crate) const SOL_SOCKET: i32 = 1;
    pub(crate) const MSG_DONTWAIT: i32 = 0x40;
    pub(crate) const POLLIN: i16 = 0x1;
    pub(crate) const PROT_READ: i32 = 0x1;
    pub(crate) const PROT_WRITE: i32 = 0x2;
    pub(crate) const MAP_SHARED: i32 = 0x01;
    pub(crate) const MAP_PRIVATE: i32 = 0x02;
    pub(crate) const MAP_ANONYMOUS: i32 = 0x20;
    pub(crate) const MAP_POPULATE: i32 = 0x8000;
    pub(crate) const MAP_HUGETLB: i32 = 0x40000;
    pub(crate) const ENOENT: i32 = 2;
    pub(crate) const ENODEV: i32 = 19;
}
#[cfg(target_os = "fullrust")]
pub(crate) use consts::*;

// Socket ioctls are numbered the same on every architecture.
pub(crate) const SIOCGIFHWADDR: u64 = 0x8927;
pub(crate) const SIOCGIFINDEX: u64 = 0x8933;
pub(crate) const SIOCETHTOOL: u64 = 0x8946;

/// Issue a syscall, returning its result or the errno it failed with.
///
/// # Safety
/// `args` must be what syscall `nr` expects; any pointers among them must be
/// valid for the reads and writes that syscall makes.
#[cfg(target_os = "linux")]
unsafe fn syscall(nr: libc::c_long, args: [usize; 6]) -> Result<usize> {
    // Passing all six is harmless: the kernel ignores the registers a syscall
    // does not use.
    // SAFETY: the caller vouches for the arguments.
    let r = unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(r as usize)
}

/// As above, for a target with no libc: no `errno` either, so the error comes
/// back in-band as `-errno`, the way the kernel returns it.
///
/// # Safety
/// As above.
#[cfg(target_os = "fullrust")]
unsafe fn syscall(nr: i64, args: [usize; 6]) -> Result<usize> {
    let r: isize;
    // SAFETY: the caller vouches for the arguments. `syscall` clobbers rcx and
    // r11 and touches nothing else outside the argument registers.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") nr as isize => r,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    // Every errno is below 4096, and no successful result lands in that range.
    if (-4095..0).contains(&r) {
        return Err(io::Error::from_raw_os_error(-r as i32));
    }
    Ok(r as usize)
}

pub(crate) fn socket(domain: i32, ty: i32, proto: i32) -> Result<OwnedFd> {
    // SAFETY: no pointers.
    let fd = unsafe {
        syscall(
            nr::SOCKET,
            [domain as usize, ty as usize, proto as usize, 0, 0, 0],
        )?
    };
    // SAFETY: a fresh fd nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// `bind(2)` with `addr`, a `sockaddr_*` struct, passed at its own size.
pub(crate) fn bind<T>(fd: RawFd, addr: &T) -> Result<()> {
    // SAFETY: `addr` is readable for size_of::<T>() bytes.
    unsafe {
        syscall(
            nr::BIND,
            [
                fd as usize,
                addr as *const T as usize,
                size_of::<T>(),
                0,
                0,
                0,
            ],
        )?;
    }
    Ok(())
}

/// `setsockopt(2)` with `val` passed at its own size.
pub(crate) fn setsockopt<T>(fd: RawFd, level: i32, opt: i32, val: &T) -> Result<()> {
    // SAFETY: `val` is readable for size_of::<T>() bytes.
    unsafe {
        syscall(
            nr::SETSOCKOPT,
            [
                fd as usize,
                level as usize,
                opt as usize,
                val as *const T as usize,
                size_of::<T>(),
                0,
            ],
        )?;
    }
    Ok(())
}

/// `getsockopt(2)` into `val`. The kernel may fill in less than all of it.
///
/// # Safety
/// Every bit pattern must be a valid `T`, since the kernel writes raw bytes.
pub(crate) unsafe fn getsockopt<T>(fd: RawFd, level: i32, opt: i32, val: &mut T) -> Result<()> {
    let mut len = size_of::<T>() as u32;
    // SAFETY: `val` is writable for `len` bytes and `len` is a live socklen_t;
    // the caller guarantees any bytes the kernel writes make a valid `T`.
    unsafe {
        syscall(
            nr::GETSOCKOPT,
            [
                fd as usize,
                level as usize,
                opt as usize,
                val as *mut T as usize,
                &mut len as *mut u32 as usize,
                0,
            ],
        )?;
    }
    Ok(())
}

/// `sendto(2)`. `addr` is the raw `sockaddr` bytes, or `None` for a connected
/// (or, for AF_XDP, address-less) socket.
pub(crate) fn sendto(fd: RawFd, buf: &[u8], flags: i32, addr: Option<&[u8]>) -> Result<usize> {
    let (ap, al) = addr.map_or((0, 0), |a| (a.as_ptr() as usize, a.len()));
    // SAFETY: `buf` and `addr` are readable for their lengths.
    unsafe {
        syscall(
            nr::SENDTO,
            [
                fd as usize,
                buf.as_ptr() as usize,
                buf.len(),
                flags as usize,
                ap,
                al,
            ],
        )
    }
}

/// `recv(2)`, which on every 64-bit Linux ABI is `recvfrom` without an address.
pub(crate) fn recv(fd: RawFd, buf: &mut [u8], flags: i32) -> Result<usize> {
    // SAFETY: `buf` is writable for its length; null address pointers are
    // what `recv` itself passes.
    unsafe {
        syscall(
            nr::RECVFROM,
            [
                fd as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                flags as usize,
                0,
                0,
            ],
        )
    }
}

/// Wait up to `timeout_ms` (negative: forever) for `events` on one fd.
/// Returns whether any arrived.
///
/// Built on `ppoll`, since plain `poll` does not exist on every architecture.
pub(crate) fn poll(fd: RawFd, events: i16, timeout_ms: i32) -> Result<bool> {
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    #[repr(C)]
    struct Timespec {
        sec: i64,
        nsec: i64,
    }
    let mut pfd = PollFd {
        fd,
        events,
        revents: 0,
    };
    let ts = Timespec {
        sec: i64::from(timeout_ms / 1000),
        nsec: i64::from(timeout_ms % 1000) * 1_000_000,
    };
    let tsp = if timeout_ms < 0 {
        0
    } else {
        &ts as *const Timespec as usize
    };
    // SAFETY: one live pollfd the kernel writes only `revents` of; the timeout
    // is either null or a live timespec; a null sigmask leaves it unchanged.
    let n = unsafe {
        syscall(
            nr::PPOLL,
            [&mut pfd as *mut PollFd as usize, 1, tsp, 0, 0, 0],
        )?
    };
    Ok(n > 0)
}

/// `ioctl(2)` with a pointer argument.
///
/// # Safety
/// `arg` must be the struct request `req` expects, valid for everything the
/// kernel reads and writes through it.
pub(crate) unsafe fn ioctl<T>(fd: RawFd, req: u64, arg: *mut T) -> Result<usize> {
    // SAFETY: the caller vouches for `arg`.
    unsafe {
        syscall(
            nr::IOCTL,
            [fd as usize, req as usize, arg as usize, 0, 0, 0],
        )
    }
}

/// `mmap(2)`, returning the mapping's address.
///
/// # Safety
/// The usual `mmap` caveats: a `MAP_FIXED` or shared mapping can alias memory
/// Rust believes it owns.
pub(crate) unsafe fn mmap(
    len: usize,
    prot: i32,
    flags: i32,
    fd: RawFd,
    off: i64,
) -> Result<*mut u8> {
    // SAFETY: the caller vouches for the flags; a null hint lets the kernel
    // choose where the mapping goes.
    let p = unsafe {
        syscall(
            nr::MMAP,
            [
                0,
                len,
                prot as usize,
                flags as usize,
                fd as usize,
                off as usize,
            ],
        )?
    };
    Ok(p as *mut u8)
}

/// `munmap(2)`.
///
/// # Safety
/// Nothing may use `[ptr, ptr + len)` afterwards.
pub(crate) unsafe fn munmap(ptr: *mut u8, len: usize) -> Result<()> {
    // SAFETY: the caller gives up the range.
    unsafe { syscall(nr::MUNMAP, [ptr as usize, len, 0, 0, 0, 0])? };
    Ok(())
}

/// `bpf(2)`.
///
/// # Safety
/// `attr` must point at a valid, initialized struct of at least `size` bytes
/// matching `cmd`, and any pointers inside it must be valid for the call.
pub(crate) unsafe fn bpf(cmd: i32, attr: *mut u8, size: usize) -> Result<i32> {
    // SAFETY: the caller vouches for `attr`.
    let r = unsafe { syscall(nr::BPF, [cmd as usize, attr as usize, size, 0, 0, 0])? };
    Ok(r as i32)
}

/// A CPU mask, laid out as glibc's `cpu_set_t`: 1024 bits.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct CpuSet([u64; CPU_SETSIZE / 64]);

/// CPUs a [`CpuSet`] can name.
pub(crate) const CPU_SETSIZE: usize = 1024;

impl CpuSet {
    pub(crate) fn new() -> CpuSet {
        CpuSet([0; CPU_SETSIZE / 64])
    }

    /// Add `cpu`, which must be below [`CPU_SETSIZE`].
    pub(crate) fn set(&mut self, cpu: usize) {
        self.0[cpu / 64] |= 1 << (cpu % 64);
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, cpu: usize) -> bool {
        cpu < CPU_SETSIZE && self.0[cpu / 64] & (1 << (cpu % 64)) != 0
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..CPU_SETSIZE).filter(|&c| self.contains(c))
    }
}

/// Restrict the calling thread to `set`.
pub(crate) fn sched_setaffinity(set: &CpuSet) -> Result<()> {
    // SAFETY: `set` is readable for its size; tid 0 is the calling thread.
    unsafe {
        syscall(
            nr::SCHED_SETAFFINITY,
            [
                0,
                size_of::<CpuSet>(),
                set as *const CpuSet as usize,
                0,
                0,
                0,
            ],
        )?;
    }
    Ok(())
}

/// The calling thread's CPU mask.
#[cfg(test)]
pub(crate) fn sched_getaffinity() -> Result<CpuSet> {
    let mut set = CpuSet::new();
    // SAFETY: `set` is writable for its size. The raw syscall writes only as
    // many bytes as the kernel's own mask; the rest stay zero.
    unsafe {
        syscall(
            nr::SCHED_GETAFFINITY,
            [
                0,
                size_of::<CpuSet>(),
                &mut set as *mut CpuSet as usize,
                0,
                0,
                0,
            ],
        )?;
    }
    Ok(set)
}

/// The size of a page, which is what `mmap` offsets and UMEM chunks are
/// measured against.
#[cfg(target_os = "linux")]
pub(crate) fn page_size() -> usize {
    // SAFETY: sysconf with a valid name; -1 on failure, handled below.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 { 4096 } else { n as usize }
}

/// x86-64, the only fullrust architecture, has one page size.
#[cfg(target_os = "fullrust")]
pub(crate) fn page_size() -> usize {
    4096
}

/// `struct ifreq`: a 16-byte name followed by a 24-byte union.
#[repr(C)]
pub(crate) struct IfReq {
    pub(crate) name: [u8; 16],
    pub(crate) data: [u8; 24],
}

impl IfReq {
    pub(crate) fn new(name: &str) -> Result<IfReq> {
        let b = name.as_bytes();
        if b.len() >= 16 || b.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {name:?} is not a valid ifname"),
            ));
        }
        let mut req = IfReq {
            name: [0; 16],
            data: [0; 24],
        };
        req.name[..b.len()].copy_from_slice(b);
        Ok(req)
    }

    /// Point the union at `p`, for requests like `SIOCETHTOOL` that take a
    /// pointer to their real argument.
    pub(crate) fn set_data_ptr<T>(&mut self, p: *mut T) {
        self.data[..8].copy_from_slice(&(p as usize as u64).to_ne_bytes());
    }
}

/// Resolve an interface name to its index, as libc's `if_nametoindex` does:
/// `SIOCGIFINDEX` on a throwaway socket.
pub(crate) fn if_nametoindex(name: &str) -> Result<u32> {
    let not_found = || {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name:?} not found"),
        )
    };
    // No interface can have a name that does not fit an ifreq, so like libc,
    // report that as not found rather than as a bad argument.
    let mut req = IfReq::new(name).map_err(|_| not_found())?;
    let sock = socket(AF_INET, SOCK_DGRAM, 0)?;
    // SAFETY: SIOCGIFINDEX reads the name and writes an int into the union,
    // both inside `req`.
    match unsafe {
        ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&sock),
            SIOCGIFINDEX,
            &mut req,
        )
    } {
        Ok(_) => Ok(u32::from_ne_bytes([
            req.data[0],
            req.data[1],
            req.data[2],
            req.data[3],
        ])),
        Err(e) if e.raw_os_error() == Some(ENODEV) => Err(not_found()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn ifreq_layout_matches_the_kernel_struct() {
        assert_eq!(size_of::<IfReq>(), 40);
        let req = IfReq::new("eth0").unwrap();
        assert_eq!(&req.name[..5], b"eth0\0");
        assert!(IfReq::new("an-interface-name-that-is-far-too-long").is_err());
        assert!(IfReq::new("nul\0inside").is_err());
    }

    #[test]
    fn cpu_set_matches_cpu_set_t() {
        assert_eq!(size_of::<CpuSet>(), CPU_SETSIZE / 8);
        let mut s = CpuSet::new();
        s.set(0);
        s.set(65);
        s.set(CPU_SETSIZE - 1);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![0, 65, CPU_SETSIZE - 1]);
        assert!(!s.contains(CPU_SETSIZE));
    }

    #[test]
    fn loopback_resolves() {
        assert_eq!(if_nametoindex("lo").unwrap(), 1);
    }

    #[test]
    fn missing_interfaces_are_not_found() {
        for name in ["pktkit-nope", "pktkit-no-such-if", "nul\0inside"] {
            let e = if_nametoindex(name).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::NotFound, "{name:?}: {e}");
        }
    }

    #[test]
    fn errors_come_back_as_errno() {
        // Not a socket family anyone has.
        let e = socket(4095, SOCK_DGRAM, 0).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(97)); // EAFNOSUPPORT
    }

    #[test]
    fn datagrams_round_trip_through_poll_and_recv() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = peer.local_addr().unwrap().port();
        let fd = peer.as_raw_fd();
        // Nothing queued: times out.
        assert!(!poll(fd, POLLIN, 0).unwrap());

        // struct sockaddr_in: family, port (big-endian), address, padding.
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        sa[2..4].copy_from_slice(&port.to_be_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let s = socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        assert_eq!(sendto(s.as_raw_fd(), b"hi", 0, Some(&sa)).unwrap(), 2);

        assert!(poll(fd, POLLIN, 1000).unwrap());
        let mut buf = [0u8; 8];
        assert_eq!(recv(fd, &mut buf, MSG_DONTWAIT).unwrap(), 2);
        assert_eq!(&buf[..2], b"hi");
    }

    #[test]
    fn anonymous_mapping_round_trip() {
        let len = page_size();
        // SAFETY: a fresh private anonymous mapping aliases nothing.
        let p = unsafe {
            mmap(
                len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        }
        .unwrap();
        // SAFETY: inside the mapping we just made, unmapped exactly once.
        unsafe {
            *p.add(len - 1) = 7;
            assert_eq!(*p.add(len - 1), 7);
            munmap(p, len).unwrap();
        }
    }
}

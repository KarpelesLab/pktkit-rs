//! Small Linux syscall helpers shared by the OS-touching device features.
//!
//! Only compiled on Linux, and only when a feature that needs it is enabled.

use crate::{MacAddr, Result};
use std::io;
use std::os::fd::AsRawFd;

/// A raw socket fd closed on drop. Used for the throwaway sockets that exist
/// only to carry an `ioctl`.
pub(crate) struct OwnedSock(pub(crate) i32);

impl AsRawFd for OwnedSock {
    fn as_raw_fd(&self) -> i32 {
        self.0
    }
}

impl Drop for OwnedSock {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Open a datagram socket for issuing interface ioctls on.
fn ioctl_socket() -> Result<OwnedSock> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedSock(sock))
}

/// `name` as the kernel's NUL-terminated `char[IFNAMSIZ]`.
///
/// A name that does not fit, or has a NUL inside, is refused rather than cut
/// short: the kernel would act on the shortened name, which can be a
/// different interface that happens to exist.
pub(crate) fn ifname(name: &str) -> Result<[u8; 16]> {
    let b = name.as_bytes();
    if b.len() > 15 || b.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name {name:?} is not a valid ifname (at most 15 bytes, no NUL)"),
        ));
    }
    let mut out = [0u8; 16];
    out[..b.len()].copy_from_slice(b);
    Ok(out)
}

/// Build the 40-byte `struct ifreq` prefix: an interface name, NUL-padded.
///
/// The struct is laid out by hand rather than through a libc binding because
/// the union in its tail differs between requests; every caller here only
/// needs the name in and some bytes out.
fn ifreq(name: &str) -> Result<[u8; 40]> {
    let mut ifr = [0u8; 40];
    ifr[..16].copy_from_slice(&ifname(name)?);
    Ok(ifr)
}

/// Read an interface's hardware address via `SIOCGIFHWADDR`.
pub(crate) fn if_hw_addr(name: &str) -> Result<MacAddr> {
    let sock = ioctl_socket()?;
    let mut ifr = ifreq(name)?;
    let r = unsafe { libc::ioctl(sock.0, libc::SIOCGIFHWADDR, &mut ifr) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // Past the 16-byte name comes `struct sockaddr`: 2 bytes of family, then
    // the address itself.
    let mut o = [0u8; 6];
    o.copy_from_slice(&ifr[18..24]);
    Ok(MacAddr(o))
}

/// Resolve an interface name to its kernel index.
#[cfg(feature = "afpacket")]
pub(crate) fn if_index(name: &str) -> Result<u32> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has a NUL"))?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such interface: {}", name),
        ));
    }
    Ok(idx)
}

/// Read an interface's MTU via `SIOCGIFMTU`.
#[cfg(feature = "afpacket")]
pub(crate) fn if_mtu(name: &str) -> Result<usize> {
    let sock = ioctl_socket()?;
    let mut ifr = ifreq(name)?;
    let r = unsafe { libc::ioctl(sock.0, libc::SIOCGIFMTU, &mut ifr) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let mtu = i32::from_ne_bytes([ifr[16], ifr[17], ifr[18], ifr[19]]);
    if mtu <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bogus MTU"));
    }
    Ok(mtu as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_fits_or_is_refused() {
        assert_eq!(&ifname("eth0").unwrap()[..5], b"eth0\0");
        let longest = "a".repeat(15);
        assert_eq!(
            &ifname(&longest).unwrap()[..16],
            format!("{longest}\0").as_bytes()
        );
        // Cut to 15 bytes this would name some other interface.
        let e = ifname("pktkit-tap-very-long").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(ifname("tap0\0x").is_err());
    }
}

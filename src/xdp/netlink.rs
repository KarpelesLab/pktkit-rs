//! `RTM_SETLINK` / `IFLA_XDP` — the pre-`bpf_link` way to attach an XDP
//! program, still the only way to detach one that outlived its process.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::Result;

const NETLINK_ROUTE: i32 = 0;
const RTM_SETLINK: u16 = 19;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLA_F_NESTED: u16 = 0x8000;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;

/// One netlink attribute: `[len:u16][type:u16][data...]`, padded to 4 bytes.
/// `len` counts the header but not the padding.
fn nl_attr(typ: u16, data: &[u8]) -> Vec<u8> {
    let l = 4 + data.len();
    let padded = (l + 3) & !3;
    let mut buf = vec![0u8; padded];
    buf[0..2].copy_from_slice(&(l as u16).to_ne_bytes());
    buf[2..4].copy_from_slice(&typ.to_ne_bytes());
    buf[4..4 + data.len()].copy_from_slice(data);
    buf
}

/// Assemble the `RTM_SETLINK` message that sets (or clears) the XDP program on
/// `ifindex`. Split out so the encoding is unit-testable without a socket.
fn build_setlink_xdp(ifindex: u32, prog_fd: i32, flags: u32, seq: u32) -> Vec<u8> {
    let fd_attr = nl_attr(IFLA_XDP_FD, &prog_fd.to_ne_bytes());
    let flags_attr = nl_attr(IFLA_XDP_FLAGS, &flags.to_ne_bytes());
    let mut nested_data = fd_attr;
    nested_data.extend_from_slice(&flags_attr);
    let nested = nl_attr(IFLA_XDP | NLA_F_NESTED, &nested_data);

    // struct ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4).
    let mut ifinfo = [0u8; 16];
    ifinfo[0] = libc::AF_UNSPEC as u8;
    ifinfo[4..8].copy_from_slice(&ifindex.to_ne_bytes());

    let mut payload = Vec::with_capacity(16 + nested.len());
    payload.extend_from_slice(&ifinfo);
    payload.extend_from_slice(&nested);

    // struct nlmsghdr: len(4) type(2) flags(2) seq(4) pid(4).
    let msg_len = 16 + payload.len();
    let mut msg = vec![0u8; msg_len];
    msg[0..4].copy_from_slice(&(msg_len as u32).to_ne_bytes());
    msg[4..6].copy_from_slice(&RTM_SETLINK.to_ne_bytes());
    msg[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg[8..12].copy_from_slice(&seq.to_ne_bytes());
    // pid (12..16) left zero: the kernel fills it in.
    msg[16..].copy_from_slice(&payload);
    msg
}

/// Set the XDP program on `ifindex`. `prog_fd < 0` detaches.
//
// TODO(xdp): needs a real interface + CAP_NET_ADMIN to verify. The message
// encoding is unit-tested; the socket round-trip is not.
pub fn set_xdp(ifindex: u32, prog_fd: i32, flags: u32) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd; OwnedFd closes it on drop.
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };
    let raw = sock.as_raw_fd();

    let msg = build_setlink_xdp(ifindex, prog_fd, flags, 1);

    // struct sockaddr_nl { family:u16, pad:u16, pid:u32, groups:u32 }.
    let mut sa = [0u8; 12];
    sa[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());

    let sent = unsafe {
        libc::sendto(
            raw,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            sa.as_ptr() as *const libc::sockaddr,
            sa.len() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    // The ACK is an nlmsgerr whose `error` is 0 on success.
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::recv(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize >= 20 {
        let err_code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if err_code != 0 {
            return Err(io::Error::from_raw_os_error(-err_code));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setlink_message_layout() {
        let msg = build_setlink_xdp(7, 42, 1 << 2, 1);

        // Header: total length, type, flags, seq.
        assert_eq!(
            u32::from_ne_bytes(msg[0..4].try_into().unwrap()),
            msg.len() as u32
        );
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_SETLINK
        );
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_ACK
        );

        // ifinfomsg.ifi_index sits 4 bytes into the payload.
        assert_eq!(u32::from_ne_bytes(msg[20..24].try_into().unwrap()), 7);

        // Then the nested IFLA_XDP attribute.
        assert_eq!(
            u16::from_ne_bytes(msg[34..36].try_into().unwrap()),
            IFLA_XDP | NLA_F_NESTED
        );
        // ... holding IFLA_XDP_FD = 42 ...
        assert_eq!(
            u16::from_ne_bytes(msg[38..40].try_into().unwrap()),
            IFLA_XDP_FD
        );
        assert_eq!(i32::from_ne_bytes(msg[40..44].try_into().unwrap()), 42);
        // ... and IFLA_XDP_FLAGS = XDP_FLAGS_DRV_MODE.
        assert_eq!(
            u16::from_ne_bytes(msg[46..48].try_into().unwrap()),
            IFLA_XDP_FLAGS
        );
        assert_eq!(u32::from_ne_bytes(msg[48..52].try_into().unwrap()), 1 << 2);
    }

    #[test]
    fn detach_encodes_negative_fd() {
        let msg = build_setlink_xdp(3, -1, 0, 1);
        assert_eq!(i32::from_ne_bytes(msg[40..44].try_into().unwrap()), -1);
    }

    #[test]
    fn attributes_are_padded_to_four_bytes() {
        // A 5-byte payload occupies 12 bytes: 4 header + 5 data + 3 padding.
        let a = nl_attr(1, &[1, 2, 3, 4, 5]);
        assert_eq!(a.len(), 12);
        // The length field still reports the unpadded length.
        assert_eq!(u16::from_ne_bytes(a[0..2].try_into().unwrap()), 9);
    }
}

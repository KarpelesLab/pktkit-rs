//! `RTM_SETLINK` / `IFLA_XDP` — the pre-`bpf_link` way to attach an XDP
//! program, still the only way to detach one that outlived its process.

use std::io;
use std::os::fd::AsRawFd;

use crate::{Result, syscall};

const NETLINK_ROUTE: i32 = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLA_F_NESTED: u16 = 0x8000;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;
const IFLA_XDP_PROG_ID: u16 = 4;
const IFLA_XDP_DRV_PROG_ID: u16 = 5;
const IFLA_XDP_SKB_PROG_ID: u16 = 6;
const IFLA_XDP_HW_PROG_ID: u16 = 7;
const IFLA_XDP_EXPECTED_FD: u16 = 8;
/// The attribute type proper, without the nested/byte-order flag bits.
const NLA_TYPE_MASK: u16 = 0x3fff;

/// `XDP_FLAGS_REPLACE` (5.7): act only if the program attached is the one
/// named by `IFLA_XDP_EXPECTED_FD`, else fail with `EEXIST`.
pub const XDP_FLAGS_REPLACE: u32 = 1 << 4;

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

/// A link-level request: `struct nlmsghdr` and `struct ifinfomsg` for
/// `ifindex`, followed by `attrs`.
fn build_link_msg(typ: u16, flags: u16, ifindex: u32, attrs: &[u8], seq: u32) -> Vec<u8> {
    // struct ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4).
    let mut ifinfo = [0u8; 16];
    ifinfo[0] = syscall::AF_UNSPEC as u8;
    ifinfo[4..8].copy_from_slice(&ifindex.to_ne_bytes());

    // struct nlmsghdr: len(4) type(2) flags(2) seq(4) pid(4).
    let msg_len = 16 + ifinfo.len() + attrs.len();
    let mut msg = vec![0u8; 16];
    msg[0..4].copy_from_slice(&(msg_len as u32).to_ne_bytes());
    msg[4..6].copy_from_slice(&typ.to_ne_bytes());
    msg[6..8].copy_from_slice(&flags.to_ne_bytes());
    msg[8..12].copy_from_slice(&seq.to_ne_bytes());
    // pid (12..16) left zero: the kernel fills it in.
    msg.extend_from_slice(&ifinfo);
    msg.extend_from_slice(attrs);
    msg
}

/// Assemble the `RTM_SETLINK` message that sets (or clears) the XDP program on
/// `ifindex`, with `expected_fd` for [`XDP_FLAGS_REPLACE`]. Split out so the
/// encoding is unit-testable without a socket.
fn build_setlink_xdp(
    ifindex: u32,
    prog_fd: i32,
    flags: u32,
    expected_fd: Option<i32>,
    seq: u32,
) -> Vec<u8> {
    let mut nested_data = nl_attr(IFLA_XDP_FD, &prog_fd.to_ne_bytes());
    nested_data.extend_from_slice(&nl_attr(IFLA_XDP_FLAGS, &flags.to_ne_bytes()));
    if let Some(fd) = expected_fd {
        nested_data.extend_from_slice(&nl_attr(IFLA_XDP_EXPECTED_FD, &fd.to_ne_bytes()));
    }
    let nested = nl_attr(IFLA_XDP | NLA_F_NESTED, &nested_data);
    build_link_msg(
        RTM_SETLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        ifindex,
        &nested,
        seq,
    )
}

/// Send `msg` on a fresh rtnetlink socket and return the first reply.
//
// TODO(xdp): needs a real interface + CAP_NET_ADMIN to verify. The message
// encoding and parsing are unit-tested; the socket round-trip is not.
fn request(msg: &[u8]) -> Result<Vec<u8>> {
    let sock = syscall::socket(syscall::AF_NETLINK, syscall::SOCK_RAW, NETLINK_ROUTE)?;
    let raw = sock.as_raw_fd();

    // struct sockaddr_nl { family:u16, pad:u16, pid:u32, groups:u32 }.
    let mut sa = [0u8; 12];
    sa[0..2].copy_from_slice(&(syscall::AF_NETLINK as u16).to_ne_bytes());
    syscall::sendto(raw, msg, 0, Some(&sa))?;

    // A link dump can carry per-VF data; leave it room.
    let mut buf = vec![0u8; 64 * 1024];
    let n = syscall::recv(raw, &mut buf, 0)?;
    buf.truncate(n);
    Ok(buf)
}

/// The `error` of an `NLMSG_ERROR` reply, 0 being an ACK.
fn reply_errno(reply: &[u8]) -> Option<i32> {
    if reply.len() >= 20 && u16::from_ne_bytes([reply[4], reply[5]]) == NLMSG_ERROR {
        Some(i32::from_ne_bytes([
            reply[16], reply[17], reply[18], reply[19],
        ]))
    } else {
        None
    }
}

/// Set the XDP program on `ifindex`. `prog_fd < 0` detaches.
pub fn set_xdp(ifindex: u32, prog_fd: i32, flags: u32) -> Result<()> {
    set_xdp_inner(ifindex, prog_fd, flags, None)
}

/// As [`set_xdp`], but only if the program attached now is `expected_fd`'s;
/// `EEXIST` if it is another. Kernel 5.7 and later: an older one refuses the
/// flag with `EINVAL`.
pub fn set_xdp_expected(ifindex: u32, prog_fd: i32, flags: u32, expected_fd: i32) -> Result<()> {
    set_xdp_inner(
        ifindex,
        prog_fd,
        flags | XDP_FLAGS_REPLACE,
        Some(expected_fd),
    )
}

fn set_xdp_inner(ifindex: u32, prog_fd: i32, flags: u32, expected_fd: Option<i32>) -> Result<()> {
    let reply = request(&build_setlink_xdp(ifindex, prog_fd, flags, expected_fd, 1))?;
    match reply_errno(&reply) {
        Some(e) if e != 0 => Err(io::Error::from_raw_os_error(-e)),
        _ => Ok(()),
    }
}

/// The id of the XDP program attached to `ifindex` in `mode` (an
/// `XDP_FLAGS_*_MODE` value), 0 if there is none.
pub fn attached_prog_id(ifindex: u32, mode: u32) -> Result<u32> {
    let reply = request(&build_link_msg(RTM_GETLINK, NLM_F_REQUEST, ifindex, &[], 1))?;
    if let Some(e) = reply_errno(&reply) {
        return Err(io::Error::from_raw_os_error(-e));
    }
    parse_xdp_prog_id(&reply, mode).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "xdp: unexpected RTM_GETLINK reply",
        )
    })
}

/// Walk the attributes in `buf`, `(type, payload)` each, flag bits masked.
fn nl_attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if buf.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let typ = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            return None;
        }
        let data = &buf[4..len];
        buf = &buf[((len + 3) & !3).min(buf.len())..];
        Some((typ, data))
    })
}

/// The XDP program id an `RTM_NEWLINK` reply reports for `mode`.
///
/// Since 4.19 the kernel reports each mode's program in its own attribute;
/// 4.18 has only `IFLA_XDP_PROG_ID`, which a newer kernel leaves out when
/// programs are attached in more than one mode. `None` if `reply` is not a
/// link message at all.
fn parse_xdp_prog_id(reply: &[u8], mode: u32) -> Option<u32> {
    if reply.len() < 32 || u16::from_ne_bytes([reply[4], reply[5]]) != RTM_NEWLINK {
        return None;
    }
    let end = (u32::from_ne_bytes(reply[0..4].try_into().ok()?) as usize).min(reply.len());
    let per_mode = match mode {
        m if m & (1 << 1) != 0 => IFLA_XDP_SKB_PROG_ID,
        m if m & (1 << 2) != 0 => IFLA_XDP_DRV_PROG_ID,
        m if m & (1 << 3) != 0 => IFLA_XDP_HW_PROG_ID,
        _ => IFLA_XDP_PROG_ID,
    };
    let u32_of = |d: &[u8]| {
        d.get(..4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
    };
    let Some((_, xdp)) = nl_attrs(reply.get(32..end)?).find(|(t, _)| *t == IFLA_XDP) else {
        return Some(0);
    };
    let (mut only, mut exact, mut per_mode_seen) = (None, None, false);
    for (t, d) in nl_attrs(xdp) {
        match t {
            IFLA_XDP_PROG_ID => only = u32_of(d),
            IFLA_XDP_DRV_PROG_ID | IFLA_XDP_SKB_PROG_ID | IFLA_XDP_HW_PROG_ID => {
                per_mode_seen = true;
                if t == per_mode {
                    exact = u32_of(d);
                }
            }
            _ => {}
        }
    }
    // A kernel that reports modes separately has said what is in ours, even
    // if that is nothing.
    let id = if per_mode_seen && per_mode != IFLA_XDP_PROG_ID {
        exact
    } else {
        only
    };
    Some(id.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setlink_message_layout() {
        let msg = build_setlink_xdp(7, 42, 1 << 2, None, 1);

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
        let msg = build_setlink_xdp(3, -1, 0, None, 1);
        assert_eq!(i32::from_ne_bytes(msg[40..44].try_into().unwrap()), -1);
    }

    #[test]
    fn replace_carries_the_expected_fd() {
        let msg = build_setlink_xdp(3, -1, XDP_FLAGS_REPLACE | 4, Some(9), 1);
        // The nested IFLA_XDP grows by one 8-byte attribute.
        assert_eq!(u16::from_ne_bytes(msg[32..34].try_into().unwrap()), 4 + 24);
        assert_eq!(u32::from_ne_bytes(msg[48..52].try_into().unwrap()), 0x14);
        assert_eq!(
            u16::from_ne_bytes(msg[54..56].try_into().unwrap()),
            IFLA_XDP_EXPECTED_FD
        );
        assert_eq!(i32::from_ne_bytes(msg[56..60].try_into().unwrap()), 9);
        assert_eq!(
            u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize,
            msg.len()
        );
    }

    /// An `RTM_NEWLINK` reply with an `IFLA_MTU` and then `IFLA_XDP` holding
    /// `xdp`'s attributes.
    fn newlink(xdp: &[(u16, u32)]) -> Vec<u8> {
        let mut attrs = nl_attr(4, &1500u32.to_ne_bytes());
        let mut nested = nl_attr(2, &[1]); // IFLA_XDP_ATTACHED, padded
        for (t, v) in xdp {
            nested.extend_from_slice(&nl_attr(*t, &v.to_ne_bytes()));
        }
        attrs.extend_from_slice(&nl_attr(IFLA_XDP | NLA_F_NESTED, &nested));
        build_link_msg(RTM_NEWLINK, 0, 2, &attrs, 1)
    }

    #[test]
    fn prog_id_prefers_the_per_mode_attribute() {
        let r = newlink(&[(IFLA_XDP_SKB_PROG_ID, 7), (IFLA_XDP_PROG_ID, 7)]);
        assert_eq!(parse_xdp_prog_id(&r, 1 << 1), Some(7));
        // Nothing attached in driver mode, although generic has one.
        assert_eq!(parse_xdp_prog_id(&r, 1 << 2), Some(0));
        let multi = newlink(&[(IFLA_XDP_SKB_PROG_ID, 7), (IFLA_XDP_DRV_PROG_ID, 9)]);
        assert_eq!(parse_xdp_prog_id(&multi, 1 << 1), Some(7));
        assert_eq!(parse_xdp_prog_id(&multi, 1 << 2), Some(9));
    }

    #[test]
    fn prog_id_falls_back_to_the_4_18_attribute() {
        let r = newlink(&[(IFLA_XDP_PROG_ID, 5)]);
        assert_eq!(parse_xdp_prog_id(&r, 1 << 2), Some(5));
    }

    #[test]
    fn prog_id_zero_without_xdp_and_none_for_other_replies() {
        let bare = build_link_msg(RTM_NEWLINK, 0, 2, &nl_attr(4, &[0; 4]), 1);
        assert_eq!(parse_xdp_prog_id(&bare, 1 << 2), Some(0));
        let err = build_link_msg(NLMSG_ERROR, 0, 2, &[], 1);
        assert_eq!(parse_xdp_prog_id(&err, 1 << 2), None);
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

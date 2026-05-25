//! Minimal in-kernel eBPF support for AF_XDP: build and load a tiny
//! `XDP_REDIRECT` program plus its `BPF_MAP_TYPE_XSKMAP`, then attach the
//! program to an interface.
//!
//! This is a hand port of `bpf.go`. We talk to `bpf(2)` directly via
//! `syscall(SYS_bpf, cmd, &attr, sizeof attr)` rather than depending on
//! libbpf — the program is four instructions, so encoding it by hand is
//! simpler than pulling in an ELF loader.
//!
//! The program reads `ctx->rx_queue_index` and calls `bpf_redirect_map` into
//! the XSKMAP, so any queue whose socket we registered gets its frames
//! delivered to userspace; everything else falls through to the stack
//! (redirect returns an error -> `XDP_PASS` semantics for unmatched queues
//! is provided by passing flags=0, which makes the helper return the default
//! action for a miss).

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

use crate::Result;

// --- bpf(2) command numbers (from <linux/bpf.h>; not in the libc crate) ---

const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_PROG_LOAD: i32 = 5;
const BPF_LINK_CREATE: i32 = 28;

// Map / program / attach types.
const BPF_MAP_TYPE_XSKMAP: u32 = 17;
const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_XDP: u32 = 37; // attach type bpf_attach_type::BPF_XDP

// eBPF helper function IDs.
const BPF_FUNC_REDIRECT_MAP: i32 = 51;

// --- eBPF instruction encoding ---------------------------------------------
//
// Instruction classes / sizes / modes / sources / ops. The low-level class
// constants (BPF_LD, BPF_LDX, BPF_JMP, BPF_W, BPF_IMM, BPF_MEM, BPF_K,
// BPF_X) are in the libc crate; the rest are not, so we define them.

const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;

const BPF_W: u8 = 0x00; // 32-bit
const BPF_DW: u8 = 0x18; // 64-bit

const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

const BPF_K: u8 = 0x00; // immediate operand

const BPF_MOV: u8 = 0xb0;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;

// Registers.
const BPF_REG_1: u8 = 1;
const BPF_REG_2: u8 = 2;
const BPF_REG_3: u8 = 3;

// `BPF_PSEUDO_MAP_FD`: src_reg marker for the LD_IMM64 that loads a map fd.
const BPF_PSEUDO_MAP_FD: u8 = 1;

// `xdp_md` layout: rx_queue_index is the 5th u32 field, at byte offset 16.
const XDP_MD_RX_QUEUE_INDEX_OFF: i16 = 16;

/// One eBPF instruction (8 bytes on the wire).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    /// dst_reg in the low nibble, src_reg in the high nibble.
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

#[inline]
fn reg(dst: u8, src: u8) -> u8 {
    (src << 4) | (dst & 0x0f)
}

impl Insn {
    fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Insn {
        Insn {
            code: BPF_LDX | size | BPF_MEM,
            regs: reg(dst, src),
            off,
            imm: 0,
        }
    }

    fn mov64_imm(dst: u8, imm: i32) -> Insn {
        Insn {
            code: BPF_ALU64 | BPF_K | BPF_MOV,
            regs: reg(dst, 0),
            off: 0,
            imm,
        }
    }

    fn call(func: i32) -> Insn {
        Insn {
            code: BPF_JMP | BPF_K | BPF_CALL,
            regs: 0,
            off: 0,
            imm: func,
        }
    }

    fn exit() -> Insn {
        Insn {
            code: BPF_JMP | BPF_EXIT,
            regs: 0,
            off: 0,
            imm: 0,
        }
    }

    /// Serialize one instruction to its 8 wire bytes (little-endian, the eBPF
    /// in-kernel byte order on all supported arches).
    fn to_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.code;
        b[1] = self.regs;
        b[2..4].copy_from_slice(&self.off.to_le_bytes());
        b[4..8].copy_from_slice(&self.imm.to_le_bytes());
        b
    }
}

/// `BPF_LD | BPF_DW | BPF_IMM` with `BPF_PSEUDO_MAP_FD` — the two-slot
/// pseudo-instruction that loads a map file descriptor into `dst`. The second
/// slot carries the upper 32 bits of the 64-bit immediate, which is zero here.
fn ld_map_fd(dst: u8, fd: i32) -> [Insn; 2] {
    [
        Insn {
            code: BPF_LD | BPF_DW | BPF_IMM,
            regs: reg(dst, BPF_PSEUDO_MAP_FD),
            off: 0,
            imm: fd,
        },
        Insn::default(),
    ]
}

/// Build the redirect program instruction stream.
///
/// ```text
/// r2 = *(u32*)(r1 + 16)   ; r2 = ctx->rx_queue_index
/// r1 = map_fd             ; LD_IMM64 pseudo (2 slots)
/// r3 = 0                  ; flags
/// call bpf_redirect_map   ; r0 = bpf_redirect_map(map, key, flags)
/// exit                    ; return r0
/// ```
pub fn redirect_program(map_fd: i32) -> Vec<Insn> {
    let mut insns = Vec::with_capacity(6);
    insns.push(Insn::ldx_mem(
        BPF_W,
        BPF_REG_2,
        BPF_REG_1,
        XDP_MD_RX_QUEUE_INDEX_OFF,
    ));
    insns.extend_from_slice(&ld_map_fd(BPF_REG_1, map_fd));
    insns.push(Insn::mov64_imm(BPF_REG_3, 0));
    insns.push(Insn::call(BPF_FUNC_REDIRECT_MAP));
    insns.push(Insn::exit());
    insns
}

/// Flatten instructions to the contiguous byte buffer `bpf(2)` expects.
pub fn encode_program(insns: &[Insn]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(insns.len() * 8);
    for insn in insns {
        buf.extend_from_slice(&insn.to_bytes());
    }
    buf
}

// --- bpf(2) syscall wrappers -----------------------------------------------

/// Hand-roll the `bpf(2)` syscall. `attr` points at the command-specific
/// `bpf_attr` union variant; `size` is its byte length.
///
/// # Safety
/// `attr` must point at a valid, initialized struct of at least `size` bytes
/// matching `cmd`, and any pointers inside it must be valid for the call.
unsafe fn bpf(cmd: i32, attr: *mut libc::c_void, size: usize) -> Result<i32> {
    let r = libc::syscall(libc::SYS_bpf, cmd as libc::c_long, attr, size as libc::c_long);
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r as i32)
}

/// `bpf_attr` for `BPF_MAP_CREATE` (prefix of the union variant we use).
#[repr(C)]
#[derive(Default)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

/// Create a `BPF_MAP_TYPE_XSKMAP` with `max_entries` slots (one per NIC
/// queue). Key and value are both 4 bytes: queue index -> socket fd.
pub fn create_xskmap(max_entries: u32) -> Result<OwnedFd> {
    let mut attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_XSKMAP,
        key_size: 4,
        value_size: 4,
        max_entries,
        map_flags: 0,
    };
    let fd = unsafe {
        bpf(
            BPF_MAP_CREATE,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<MapCreateAttr>(),
        )?
    };
    // SAFETY: bpf() returned a fresh, owned fd on success.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `bpf_attr` for `BPF_MAP_UPDATE_ELEM`. `key`/`value` are userspace pointers
/// the kernel dereferences.
#[repr(C)]
struct MapUpdateAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Insert `key -> value` into a BPF map. Used to bind a queue index to a
/// socket fd in the XSKMAP.
pub fn map_update_elem(map_fd: i32, key: u32, value: u32) -> Result<()> {
    let k = key;
    let v = value;
    let mut attr = MapUpdateAttr {
        map_fd: map_fd as u32,
        _pad: 0,
        key: &k as *const u32 as u64,
        value: &v as *const u32 as u64,
        flags: 0,
    };
    unsafe {
        bpf(
            BPF_MAP_UPDATE_ELEM,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<MapUpdateAttr>(),
        )?;
    }
    Ok(())
}

/// Insert a socket fd into the XSKMAP at the given queue index.
#[inline]
pub fn update_xskmap(map_fd: i32, queue_id: u32, socket_fd: i32) -> Result<()> {
    map_update_elem(map_fd, queue_id, socket_fd as u32)
}

/// `bpf_attr` for `BPF_PROG_LOAD` (prefix sufficient for our use).
#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// Create an XSKMAP and load the redirect program against it. Returns
/// `(prog_fd, map_fd)`; the caller owns both.
pub fn load_xdp_program(max_queues: u32) -> Result<(OwnedFd, OwnedFd)> {
    let map = create_xskmap(max_queues)?;
    let map_fd = std::os::fd::AsRawFd::as_raw_fd(&map);

    let insns = redirect_program(map_fd);
    let insn_bytes = encode_program(&insns);

    // GPL is required to call GPL-only helpers like bpf_redirect_map.
    let license = b"GPL\0";
    let mut log_buf = vec![0u8; 65536];

    let mut prog_name = [0u8; 16];
    let name = b"pktkit_xdp";
    prog_name[..name.len()].copy_from_slice(name);

    let mut attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: insns.len() as u32,
        insns: insn_bytes.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name,
        prog_ifindex: 0,
        expected_attach_type: 0,
    };

    let prog = unsafe {
        bpf(
            BPF_PROG_LOAD,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<ProgLoadAttr>(),
        )
    };
    match prog {
        Ok(fd) => {
            // SAFETY: fresh owned fd on success.
            let prog_fd = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok((prog_fd, map))
        }
        Err(e) => {
            // Surface the verifier log to make load failures debuggable.
            let end = log_buf.iter().position(|&c| c == 0).unwrap_or(log_buf.len());
            let log = String::from_utf8_lossy(&log_buf[..end]);
            if log.is_empty() {
                Err(e)
            } else {
                Err(io::Error::new(
                    e.kind(),
                    format!("load XDP program: {e}\nverifier: {log}"),
                ))
            }
        }
    }
}

/// `bpf_attr` for `BPF_LINK_CREATE` against an XDP target.
#[repr(C)]
#[derive(Default)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
}

/// Attach an XDP program to `ifindex`. Tries the modern `BPF_LINK_CREATE`
/// first; on failure falls back to the netlink `IFLA_XDP` path.
///
/// `flags` carries the XDP mode bits (e.g. `XDP_FLAGS_SKB_MODE`) used by the
/// netlink fallback.
//
// TODO(afxdp): needs hardware to verify — neither path can be exercised in a
// sandbox without a real NIC and CAP_NET_ADMIN.
pub fn attach_xdp(ifindex: u32, prog_fd: i32, flags: u32) -> Result<()> {
    let mut attr = LinkCreateAttr {
        prog_fd: prog_fd as u32,
        target_ifindex: ifindex,
        attach_type: BPF_XDP,
        flags: 0,
    };
    let r = unsafe {
        bpf(
            BPF_LINK_CREATE,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<LinkCreateAttr>(),
        )
    };
    if r.is_ok() {
        return Ok(());
    }
    attach_xdp_netlink(ifindex, prog_fd, flags)
}

/// Detach any XDP program from `ifindex` (set prog fd to -1 via netlink).
pub fn detach_xdp(ifindex: u32) -> Result<()> {
    attach_xdp_netlink(ifindex, -1, 0)
}

// --- netlink fallback for XDP attach/detach --------------------------------

// rtnetlink / IFLA_XDP constants not exposed by the libc crate.
const NETLINK_ROUTE: i32 = 0;
const RTM_SETLINK: u16 = 19;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLA_F_NESTED: u16 = 0x8000;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;

/// Build one netlink attribute: `[len:u16][type:u16][data...]`, padded to a
/// 4-byte boundary. `len` counts the header but not the padding.
fn nl_attr(typ: u16, data: &[u8]) -> Vec<u8> {
    let l = 4 + data.len();
    let padded = (l + 3) & !3;
    let mut buf = vec![0u8; padded];
    buf[0..2].copy_from_slice(&(l as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&typ.to_le_bytes());
    buf[4..4 + data.len()].copy_from_slice(data);
    buf
}

/// Assemble the `RTM_SETLINK` message body that sets (or clears) the XDP prog
/// fd on `ifindex`. Split out so the encoding can be unit-tested without a
/// netlink socket.
fn build_setlink_xdp(ifindex: u32, prog_fd: i32, flags: u32, seq: u32) -> Vec<u8> {
    // Nested IFLA_XDP { IFLA_XDP_FD, IFLA_XDP_FLAGS }.
    let fd_attr = nl_attr(IFLA_XDP_FD, &prog_fd.to_le_bytes());
    let flags_attr = nl_attr(IFLA_XDP_FLAGS, &flags.to_le_bytes());
    let mut nested_data = fd_attr;
    nested_data.extend_from_slice(&flags_attr);
    let nested = nl_attr(IFLA_XDP | NLA_F_NESTED, &nested_data);

    // struct ifinfomsg is 16 bytes: family(1) pad(1) type(2) index(4)
    // flags(4) change(4). We only set family=AF_UNSPEC and ifi_index.
    let mut ifinfo = [0u8; 16];
    ifinfo[0] = libc::AF_UNSPEC as u8;
    ifinfo[4..8].copy_from_slice(&ifindex.to_le_bytes());

    let mut payload = Vec::with_capacity(16 + nested.len());
    payload.extend_from_slice(&ifinfo);
    payload.extend_from_slice(&nested);

    // struct nlmsghdr is 16 bytes: len(4) type(2) flags(2) seq(4) pid(4).
    let msg_len = 16 + payload.len();
    let mut msg = vec![0u8; msg_len];
    msg[0..4].copy_from_slice(&(msg_len as u32).to_le_bytes());
    msg[4..6].copy_from_slice(&RTM_SETLINK.to_le_bytes());
    msg[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_le_bytes());
    msg[8..12].copy_from_slice(&seq.to_le_bytes());
    // pid (12..16) left 0: kernel assigns.
    msg[16..].copy_from_slice(&payload);
    msg
}

/// Attach/detach an XDP program via `RTM_SETLINK` over an `AF_NETLINK` route
/// socket. `prog_fd < 0` detaches.
//
// TODO(afxdp): needs hardware to verify — requires CAP_NET_ADMIN and a real
// interface. The message encoding is unit-tested; the socket round-trip is
// not.
fn attach_xdp_netlink(ifindex: u32, prog_fd: i32, flags: u32) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sock is a fresh fd; OwnedFd closes it on drop.
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };
    let raw = std::os::fd::AsRawFd::as_raw_fd(&sock);

    let msg = build_setlink_xdp(ifindex, prog_fd, flags, 1);

    // struct sockaddr_nl { family:u16, pad:u16, pid:u32, groups:u32 } = 12B.
    let mut sa = [0u8; 12];
    sa[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_le_bytes());

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

    // Read the ACK: an nlmsgerr whose error field is 0 on success.
    let mut buf = [0u8; 4096];
    let n = unsafe {
        libc::recv(
            raw,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize >= 20 {
        // nlmsgerr.error is a signed i32 right after the 16-byte nlmsghdr.
        let err_code = i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
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
    fn reg_packs_dst_and_src() {
        assert_eq!(reg(1, 0), 0x01);
        assert_eq!(reg(2, 1), 0x12);
        assert_eq!(reg(0x0f, 0x0f), 0xff);
        // dst is masked to the low nibble.
        assert_eq!(reg(0x1f, 1), 0x1f);
    }

    #[test]
    fn ldx_mem_encoding() {
        // r2 = *(u32*)(r1 + 16)
        let i = Insn::ldx_mem(BPF_W, BPF_REG_2, BPF_REG_1, 16);
        // class LDX(0x01) | size W(0x00) | mode MEM(0x60) = 0x61
        assert_eq!(i.code, 0x61);
        assert_eq!(i.regs, 0x12); // dst=2, src=1
        assert_eq!(i.off, 16);
        assert_eq!(i.imm, 0);
        assert_eq!(i.to_bytes(), [0x61, 0x12, 16, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn mov64_imm_encoding() {
        let i = Insn::mov64_imm(BPF_REG_3, 0);
        // ALU64(0x07) | K(0x00) | MOV(0xb0) = 0xb7
        assert_eq!(i.code, 0xb7);
        assert_eq!(i.regs, 0x03);
        assert_eq!(i.to_bytes(), [0xb7, 0x03, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn call_and_exit_encoding() {
        let c = Insn::call(BPF_FUNC_REDIRECT_MAP);
        // JMP(0x05) | K(0x00) | CALL(0x80) = 0x85
        assert_eq!(c.code, 0x85);
        assert_eq!(c.imm, 51);
        assert_eq!(c.to_bytes(), [0x85, 0, 0, 0, 51, 0, 0, 0]);

        let e = Insn::exit();
        // JMP(0x05) | EXIT(0x90) = 0x95
        assert_eq!(e.code, 0x95);
        assert_eq!(e.to_bytes(), [0x95, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn ld_map_fd_is_two_slots() {
        let slots = ld_map_fd(BPF_REG_1, 7);
        // LD(0x00) | DW(0x18) | IMM(0x00) = 0x18
        assert_eq!(slots[0].code, 0x18);
        // dst=r1, src=BPF_PSEUDO_MAP_FD(1)
        assert_eq!(slots[0].regs, 0x11);
        assert_eq!(slots[0].imm, 7);
        // second slot is all zero (upper 32 bits of the 64-bit immediate).
        assert_eq!(slots[1], Insn::default());
    }

    #[test]
    fn redirect_program_shape() {
        let insns = redirect_program(7);
        // ldx + (ld_map_fd x2) + mov + call + exit = 6 instructions.
        assert_eq!(insns.len(), 6);
        assert_eq!(insns[0].code, 0x61); // LDX_MEM W
        assert_eq!(insns[1].code, 0x18); // LD_IMM64 part 1
        assert_eq!(insns[1].imm, 7); // map fd
        assert_eq!(insns[2], Insn::default()); // LD_IMM64 part 2
        assert_eq!(insns[3].code, 0xb7); // MOV64 imm (flags=0)
        assert_eq!(insns[3].regs, 0x03); // r3
        assert_eq!(insns[4].code, 0x85); // CALL
        assert_eq!(insns[4].imm, 51); // bpf_redirect_map
        assert_eq!(insns[5].code, 0x95); // EXIT
    }

    #[test]
    fn encode_program_byte_for_byte() {
        let insns = redirect_program(0x42);
        let bytes = encode_program(&insns);
        assert_eq!(bytes.len(), 6 * 8);
        let expected: [u8; 48] = [
            // r2 = *(u32*)(r1 + 16)
            0x61, 0x12, 16, 0, 0, 0, 0, 0,
            // r1 = map_fd (LD_IMM64, pseudo map fd, imm=0x42)
            0x18, 0x11, 0, 0, 0x42, 0, 0, 0,
            // LD_IMM64 second slot
            0x00, 0x00, 0, 0, 0, 0, 0, 0,
            // r3 = 0
            0xb7, 0x03, 0, 0, 0, 0, 0, 0,
            // call bpf_redirect_map (51)
            0x85, 0x00, 0, 0, 51, 0, 0, 0,
            // exit
            0x95, 0x00, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(&bytes[..], &expected[..]);
    }

    #[test]
    fn nl_attr_padding_and_header() {
        // 4-byte data -> total 8, already aligned.
        let a = nl_attr(IFLA_XDP_FD, &7i32.to_le_bytes());
        assert_eq!(a.len(), 8);
        assert_eq!(u16::from_le_bytes([a[0], a[1]]), 8); // nla_len includes header
        assert_eq!(u16::from_le_bytes([a[2], a[3]]), IFLA_XDP_FD);
        assert_eq!(i32::from_le_bytes([a[4], a[5], a[6], a[7]]), 7);

        // 1-byte data -> total 5, padded up to 8; nla_len stays 5.
        let b = nl_attr(99, &[0xAB]);
        assert_eq!(b.len(), 8);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 5);
        assert_eq!(b[4], 0xAB);
        assert_eq!(&b[5..8], &[0, 0, 0]); // padding zeroed
    }

    #[test]
    fn setlink_message_layout() {
        let ifindex = 5u32;
        let prog_fd = 9i32;
        let flags = 2u32; // e.g. XDP_FLAGS_SKB_MODE
        let msg = build_setlink_xdp(ifindex, prog_fd, flags, 1);

        // nlmsghdr
        let len = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
        assert_eq!(len as usize, msg.len());
        assert_eq!(u16::from_le_bytes([msg[4], msg[5]]), RTM_SETLINK);
        assert_eq!(
            u16::from_le_bytes([msg[6], msg[7]]),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 1);

        // ifinfomsg starts at byte 16.
        assert_eq!(msg[16], libc::AF_UNSPEC as u8);
        assert_eq!(
            u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]),
            ifindex
        );

        // Nested IFLA_XDP attribute starts at byte 32 (16 hdr + 16 ifinfomsg).
        let nla_type = u16::from_le_bytes([msg[34], msg[35]]);
        assert_eq!(nla_type, IFLA_XDP | NLA_F_NESTED);

        // First nested attr: IFLA_XDP_FD carrying prog_fd at byte 36..44.
        assert_eq!(u16::from_le_bytes([msg[36], msg[37]]), 8); // nla_len
        assert_eq!(u16::from_le_bytes([msg[38], msg[39]]), IFLA_XDP_FD);
        assert_eq!(
            i32::from_le_bytes([msg[40], msg[41], msg[42], msg[43]]),
            prog_fd
        );

        // Second nested attr: IFLA_XDP_FLAGS at byte 44..52.
        assert_eq!(u16::from_le_bytes([msg[46], msg[47]]), IFLA_XDP_FLAGS);
        assert_eq!(
            u32::from_le_bytes([msg[48], msg[49], msg[50], msg[51]]),
            flags
        );
    }

    #[test]
    fn detach_encodes_negative_fd() {
        // Detach is RTM_SETLINK with prog_fd = -1.
        let msg = build_setlink_xdp(3, -1, 0, 1);
        // IFLA_XDP_FD payload sits at the same offset as the attach case.
        assert_eq!(
            i32::from_le_bytes([msg[40], msg[41], msg[42], msg[43]]),
            -1
        );
    }
}

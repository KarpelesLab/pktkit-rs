//! Raw `bpf(2)` plumbing.
//!
//! We call `syscall(SYS_bpf, cmd, &attr, sizeof attr)` directly rather than
//! depend on libbpf: the programs in this module are hand-encoded, so an ELF
//! loader would be the only thing libbpf brought to the table.
//!
//! `bpf_attr` is a union in `<linux/bpf.h>`. The kernel reads only as many
//! bytes as the command needs and requires any tail beyond the struct it knows
//! about to be zero, so declaring one `#[repr(C)]` prefix struct per command is
//! both sufficient and forward-compatible.

use std::io;

use crate::Result;

// --- bpf(2) command numbers ------------------------------------------------

pub const BPF_MAP_CREATE: i32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_MAP_UPDATE_ELEM: i32 = 2;
pub const BPF_MAP_DELETE_ELEM: i32 = 3;
pub const BPF_PROG_LOAD: i32 = 5;
pub const BPF_LINK_CREATE: i32 = 28;

// --- program / attach types ------------------------------------------------

pub const BPF_PROG_TYPE_XDP: u32 = 6;
/// `bpf_attach_type::BPF_XDP`.
pub const BPF_ATTACH_TYPE_XDP: u32 = 37;

/// `bpf_attr` for `BPF_MAP_CREATE`.
#[repr(C)]
#[derive(Default)]
pub struct MapCreateAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

/// `bpf_attr` for the element commands. `key`/`value` are userspace pointers
/// the kernel dereferences.
#[repr(C)]
#[derive(Default)]
pub struct MapElemAttr {
    pub map_fd: u32,
    pub _pad: u32,
    pub key: u64,
    /// `value` for update, `next_key` for iteration; unused by delete.
    pub value: u64,
    pub flags: u64,
}

/// `bpf_attr` for `BPF_PROG_LOAD`.
#[repr(C)]
#[derive(Default)]
pub struct ProgLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; 16],
    pub prog_ifindex: u32,
    pub expected_attach_type: u32,
}

/// `bpf_attr` for `BPF_LINK_CREATE` against an XDP target.
#[repr(C)]
#[derive(Default)]
pub struct LinkCreateAttr {
    pub prog_fd: u32,
    pub target_ifindex: u32,
    pub attach_type: u32,
    pub flags: u32,
}

/// Invoke `bpf(2)`.
///
/// # Safety
/// `attr` must point at a valid, initialized struct of at least `size` bytes
/// matching `cmd`, and any pointers inside it must be valid for the call.
pub unsafe fn bpf(cmd: i32, attr: *mut libc::c_void, size: usize) -> Result<i32> {
    // SAFETY: the caller guarantees `attr` points at a valid `size`-byte
    // struct matching `cmd`.
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            attr,
            size as libc::c_long,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r as i32)
}

/// `bpf(2)` with a `#[repr(C)]` attr struct, sized automatically.
///
/// # Safety
/// `attr` must be the struct `cmd` expects, with valid pointers inside it.
pub unsafe fn bpf_cmd<T>(cmd: i32, attr: &mut T) -> Result<i32> {
    // SAFETY: `attr` is a live `&mut T`, so the pointer and size are valid;
    // the caller guarantees `T` is the struct `cmd` expects.
    unsafe {
        bpf(
            cmd,
            attr as *mut T as *mut libc::c_void,
            std::mem::size_of::<T>(),
        )
    }
}

/// Wrap an errno with context, since a bare `EINVAL` from `bpf(2)` is close to
/// useless when debugging.
pub fn ctx_err(what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("xdp: {what}: {e}"))
}

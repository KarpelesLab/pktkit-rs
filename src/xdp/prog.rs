//! Loading XDP programs and attaching them to an interface.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::insn::{Insn, encode};
use super::netlink;
use super::sys::{
    self, GetFdByIdAttr, LinkCreateAttr, ObjInfoAttr, ProgInfo, ProgLoadAttr, ProgTestRunAttr,
    bpf_cmd, ctx_err,
};
use crate::Result;

/// The verdict an XDP program returns for a packet.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action(pub u32);

impl Action {
    /// Drop and flag an error (shows up in `xdp:xdp_exception` tracepoints).
    pub const ABORTED: Action = Action(0);
    /// Drop silently.
    pub const DROP: Action = Action(1);
    /// Hand the packet to the normal kernel stack.
    pub const PASS: Action = Action(2);
    /// Bounce the packet back out the interface it arrived on.
    pub const TX: Action = Action(3);
    /// Send the packet wherever the preceding `bpf_redirect*` call pointed.
    pub const REDIRECT: Action = Action(4);
}

/// Where in the receive path the program runs.
///
/// This is the single biggest performance knob: [`Mode::DRIVER`] runs the
/// program inside the NIC driver's NAPI poll, before an `sk_buff` exists, and
/// is a precondition for AF_XDP zero-copy. [`Mode::GENERIC`] runs after the
/// skb has been allocated, works on any interface, and cannot do zero-copy.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode(pub u32);

impl Mode {
    /// Try [`Mode::DRIVER`], fall back to [`Mode::GENERIC`].
    pub const AUTO: Mode = Mode(0);
    /// `XDP_FLAGS_SKB_MODE`.
    pub const GENERIC: Mode = Mode(1 << 1);
    /// `XDP_FLAGS_DRV_MODE`.
    pub const DRIVER: Mode = Mode(1 << 2);
    /// `XDP_FLAGS_HW_MODE` (SmartNIC offload).
    ///
    /// [`Program::attach`] refuses it: the kernel only attaches a program in
    /// this mode if it was loaded for that one device (`prog_ifindex`), which
    /// [`Program::load`] does not do.
    pub const HARDWARE: Mode = Mode(1 << 3);

    /// True if a socket bound behind a program in this mode can negotiate
    /// `XDP_ZEROCOPY`. Generic XDP always copies, and an offloaded program
    /// cannot redirect to a socket at all (XSKMAPs are not offloadable).
    #[inline]
    pub fn supports_zerocopy(self) -> bool {
        self == Mode::DRIVER
    }

    /// The concrete modes to try, in order, for this setting.
    fn candidates(self) -> &'static [Mode] {
        match self {
            Mode::AUTO => &[Mode::DRIVER, Mode::GENERIC],
            Mode::DRIVER => &[Mode::DRIVER],
            Mode::GENERIC => &[Mode::GENERIC],
            Mode::HARDWARE => &[Mode::HARDWARE],
            _ => &[Mode::GENERIC],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mode::GENERIC => "generic",
            Mode::DRIVER => "driver",
            Mode::HARDWARE => "hardware",
            _ => "auto",
        }
    }
}

/// `XDP_FLAGS_UPDATE_IF_NOEXIST`: refuse rather than replace an XDP program
/// somebody else attached.
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;

/// A loaded XDP program.
#[derive(Debug)]
pub struct Program {
    fd: OwnedFd,
}

impl Program {
    /// Load `insns` into the kernel as an XDP program named `name`.
    ///
    /// `name` is truncated to the kernel's 15-character limit; it shows up in
    /// `bpftool prog list`.
    pub fn load(insns: &[Insn], name: &str) -> Result<Program> {
        let bytes = encode(insns);

        let mut prog_name = [0u8; 16];
        let n = name.len().min(15);
        prog_name[..n].copy_from_slice(&name.as_bytes()[..n]);

        // A first attempt without a verifier log is the common case and avoids
        // the kernel formatting one; on failure we retry with a log so the
        // error is actually diagnosable.
        let load = |log: Option<&mut Vec<u8>>| -> Result<i32> {
            let (log_buf, log_size, log_level) = match log {
                Some(b) => (b.as_mut_ptr() as u64, b.len() as u32, 1),
                None => (0, 0, 0),
            };
            let mut attr = ProgLoadAttr {
                prog_type: sys::BPF_PROG_TYPE_XDP,
                insn_cnt: insns.len() as u32,
                insns: bytes.as_ptr() as u64,
                // GPL is required to call GPL-only helpers such as
                // bpf_redirect_map.
                license: c"GPL".as_ptr() as u64,
                log_level,
                log_size,
                log_buf,
                kern_version: 0,
                prog_flags: 0,
                prog_name,
                prog_ifindex: 0,
                expected_attach_type: 0,
            };
            // SAFETY: attr matches BPF_PROG_LOAD; the instruction, license and
            // log pointers all outlive the call.
            unsafe { bpf_cmd(sys::BPF_PROG_LOAD, &mut attr) }
        };

        match load(None) {
            Ok(fd) => Ok(Program {
                // SAFETY: fresh owned fd on success.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            }),
            Err(first) => {
                let mut log = vec![0u8; 65536];
                match load(Some(&mut log)) {
                    Ok(fd) => Ok(Program {
                        // SAFETY: fresh owned fd on success.
                        fd: unsafe { OwnedFd::from_raw_fd(fd) },
                    }),
                    Err(e) => {
                        let end = log.iter().position(|&c| c == 0).unwrap_or(log.len());
                        let text = String::from_utf8_lossy(&log[..end]);
                        let text = text.trim();
                        if text.is_empty() {
                            Err(ctx_err("prog load", first))
                        } else {
                            Err(io::Error::new(
                                e.kind(),
                                format!("xdp: prog load: {e}\nverifier log:\n{text}"),
                            ))
                        }
                    }
                }
            }
        }
    }

    /// Attach to `ifindex`, returning a [`Link`] that detaches on drop.
    ///
    /// With [`Mode::AUTO`] the driver hook is tried first and generic XDP is
    /// the fallback, so the returned link reports which one took effect.
    /// Attaching never replaces a program somebody else installed; that is an
    /// `EBUSY`, and [`detach`] is the deliberate way out.
    pub fn attach(&self, ifindex: u32, mode: Mode) -> Result<Link> {
        check_attach_mode(mode)?;
        let mut last: Option<io::Error> = None;
        for &m in mode.candidates() {
            match self.attach_exact(ifindex, m) {
                Ok(link) => return Ok(link),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "xdp: no attach mode to try")
        }))
    }

    fn attach_exact(&self, ifindex: u32, mode: Mode) -> Result<Link> {
        // BPF_LINK_CREATE is the modern path: the attachment is owned by an fd,
        // so it cannot leak if we crash, and it refuses to displace an existing
        // program without us asking.
        let mut attr = LinkCreateAttr {
            prog_fd: self.fd.as_raw_fd() as u32,
            target_ifindex: ifindex,
            attach_type: sys::BPF_ATTACH_TYPE_XDP,
            // UPDATE_IF_NOEXIST/REPLACE are rejected on the link path; link
            // attachment is already non-displacing.
            flags: mode.0,
        };
        // SAFETY: attr matches BPF_LINK_CREATE and holds no pointers.
        let link = unsafe { bpf_cmd(sys::BPF_LINK_CREATE, &mut attr) };
        if let Ok(fd) = link {
            return Ok(Link {
                // SAFETY: fresh owned fd on success.
                kind: LinkKind::Bpf {
                    _link: unsafe { OwnedFd::from_raw_fd(fd) },
                },
                ifindex,
                mode,
            });
        }

        // Pre-5.7 kernels have no XDP bpf_link; fall back to rtnetlink.
        netlink::set_xdp(
            ifindex,
            self.fd.as_raw_fd(),
            mode.0 | XDP_FLAGS_UPDATE_IF_NOEXIST,
        )
        .map_err(|e| ctx_err(&format!("attach {} mode", mode.name()), e))?;
        Ok(Link {
            kind: LinkKind::Netlink {
                prog_id: prog_id(self.fd.as_raw_fd()).ok(),
            },
            ifindex,
            mode,
        })
    }
}

/// Refuse a mode no program from [`Program::load`] can attach in.
///
/// An offloaded attachment needs a program the kernel translated for the
/// NIC at load time, and `dev_xdp_attach` refuses anything else with a bare
/// `EINVAL`. Offload could not run the capture program anyway: it has no
/// `bpf_redirect_map` into an XSKMAP and no LPM tries.
fn check_attach_mode(mode: Mode) -> Result<()> {
    if mode == Mode::HARDWARE {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "xdp: hardware (offload) mode needs a program loaded for that device; \
             use Mode::DRIVER or Mode::GENERIC",
        ));
    }
    Ok(())
}

/// What [`Program::test_run`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestRun {
    /// The verdict the program returned for the frame.
    pub action: Action,
    /// Mean wall time of one run, in nanoseconds, as the kernel measured it.
    pub duration_ns: u32,
}

impl Program {
    /// Run the program in the kernel against `frame`, `repeat` times, without
    /// any traffic having to arrive (`BPF_PROG_TEST_RUN`).
    ///
    /// This is the JITed program and the real maps, so it answers both "what
    /// would the kernel do with this frame" and, with a large `repeat`, "what
    /// does the program cost per packet". The frame is seen as arriving on RX
    /// queue 0. A redirect is only reported, never carried out.
    pub fn test_run(&self, frame: &[u8], repeat: u32) -> Result<TestRun> {
        let mut attr = ProgTestRunAttr {
            prog_fd: self.fd.as_raw_fd() as u32,
            data_size_in: frame.len() as u32,
            data_in: frame.as_ptr() as u64,
            repeat: repeat.max(1),
            ..Default::default()
        };
        // SAFETY: attr matches BPF_PROG_TEST_RUN; `frame` outlives the call
        // and no output buffer is supplied.
        unsafe { bpf_cmd(sys::BPF_PROG_TEST_RUN, &mut attr) }
            .map_err(|e| ctx_err("prog test run", e))?;
        Ok(TestRun {
            action: Action(attr.retval),
            duration_ns: attr.duration,
        })
    }

    /// Give up ownership of the program's file descriptor.
    ///
    /// The program stays loaded for as long as the fd is open (or something
    /// else, such as an attachment, references it).
    #[inline]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
}

impl AsRawFd for Program {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[derive(Debug)]
enum LinkKind {
    /// Held by an fd: the kernel detaches when it closes, so the fd is never
    /// read — only kept.
    Bpf { _link: OwnedFd },
    /// Attached through `RTM_SETLINK`; must be cleared explicitly, and only
    /// while the program there is still ours: `prog_id`, if it could be read.
    Netlink { prog_id: Option<u32> },
}

/// A live attachment of a [`Program`] to an interface. Detaches on drop.
#[derive(Debug)]
pub struct Link {
    kind: LinkKind,
    ifindex: u32,
    mode: Mode,
}

impl Link {
    /// The mode the program actually attached in — the thing to check before
    /// expecting zero-copy.
    #[inline]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    #[inline]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        // The bpf_link case detaches itself when the fd closes.
        if let LinkKind::Netlink { prog_id } = self.kind {
            detach_own(self.ifindex, self.mode, prog_id);
        }
    }
}

/// Detach the netlink attachment in `mode` on `ifindex`, but only if the
/// program there is still `prog_id`: somebody may have replaced ours since
/// (`xdp-loader`, `ip link set xdp`, a restarted copy of this process), and a
/// plain detach would take theirs off.
fn detach_own(ifindex: u32, mode: Mode, prog_id: Option<u32>) {
    let Some(id) = prog_id else {
        // Nothing to compare against; the old, unconditional detach.
        let _ = netlink::set_xdp(ifindex, -1, mode.0);
        return;
    };
    // The kernel does the comparison itself (5.7+) given a fd for our
    // program. The `Program` may be closed by now, so the fd is fetched
    // again by id; if that id no longer exists, it cannot be attached.
    match prog_fd_by_id(id) {
        Err(e) if e.raw_os_error() == Some(crate::syscall::ENOENT) => return,
        Ok(fd) => match netlink::set_xdp_expected(ifindex, -1, mode.0, fd.as_raw_fd()) {
            // EINVAL: a kernel without XDP_FLAGS_REPLACE. Anything else,
            // EEXIST above all, means it is not ours to remove.
            Err(e) if e.raw_os_error() == Some(crate::syscall::EINVAL) => {}
            _ => return,
        },
        Err(_) => {}
    }
    // Compare by hand. Not atomic, but the window is one netlink round trip.
    if netlink::attached_prog_id(ifindex, mode.0).map_or(true, |cur| cur == id) {
        let _ = netlink::set_xdp(ifindex, -1, mode.0);
    }
}

/// The kernel's id for the program behind `fd`.
fn prog_id(fd: RawFd) -> Result<u32> {
    let mut info = ProgInfo::default();
    let mut attr = ObjInfoAttr {
        bpf_fd: fd as u32,
        info_len: std::mem::size_of::<ProgInfo>() as u32,
        info: &mut info as *mut ProgInfo as u64,
    };
    // SAFETY: `info` is writable for `info_len` bytes, which caps what the
    // kernel copies out, and outlives the call.
    unsafe { bpf_cmd(sys::BPF_OBJ_GET_INFO_BY_FD, &mut attr) }?;
    Ok(info.id)
}

/// A new fd for the program with id `id`.
fn prog_fd_by_id(id: u32) -> Result<OwnedFd> {
    let mut attr = GetFdByIdAttr {
        id,
        ..Default::default()
    };
    // SAFETY: attr matches BPF_PROG_GET_FD_BY_ID and holds no pointers.
    let fd = unsafe { bpf_cmd(sys::BPF_PROG_GET_FD_BY_ID, &mut attr) }?;
    // SAFETY: fresh owned fd on success.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Force-detach whatever XDP program is on `ifindex`.
///
/// The escape hatch for a program left behind by a process that died before
/// its [`Link`] dropped. Has no effect on a `bpf_link` attachment, which the
/// kernel already cleaned up.
pub fn detach(ifindex: u32) -> Result<()> {
    netlink::set_xdp(ifindex, -1, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_tries_driver_before_generic() {
        assert_eq!(Mode::AUTO.candidates(), &[Mode::DRIVER, Mode::GENERIC]);
    }

    #[test]
    fn hardware_mode_is_refused_up_front() {
        let e = check_attach_mode(Mode::HARDWARE).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        for m in [Mode::AUTO, Mode::DRIVER, Mode::GENERIC] {
            assert!(check_attach_mode(m).is_ok());
        }
    }

    #[test]
    fn explicit_mode_does_not_fall_back() {
        assert_eq!(Mode::DRIVER.candidates(), &[Mode::DRIVER]);
        assert_eq!(Mode::GENERIC.candidates(), &[Mode::GENERIC]);
    }

    #[test]
    fn only_native_modes_can_zerocopy() {
        assert!(Mode::DRIVER.supports_zerocopy());
        assert!(!Mode::HARDWARE.supports_zerocopy());
        assert!(!Mode::GENERIC.supports_zerocopy());
        // AUTO is not a resolved mode; it must not promise zero-copy.
        assert!(!Mode::AUTO.supports_zerocopy());
    }

    #[test]
    fn mode_flag_values_match_uapi() {
        assert_eq!(Mode::GENERIC.0, 2); // XDP_FLAGS_SKB_MODE
        assert_eq!(Mode::DRIVER.0, 4); // XDP_FLAGS_DRV_MODE
        assert_eq!(Mode::HARDWARE.0, 8); // XDP_FLAGS_HW_MODE
    }

    #[test]
    fn action_values_match_uapi() {
        assert_eq!(Action::ABORTED.0, 0);
        assert_eq!(Action::DROP.0, 1);
        assert_eq!(Action::PASS.0, 2);
        assert_eq!(Action::TX.0, 3);
        assert_eq!(Action::REDIRECT.0, 4);
    }
}

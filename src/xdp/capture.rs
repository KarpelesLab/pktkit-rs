//! An XDP program that redirects only the traffic belonging to a set of IP
//! prefixes, and passes everything else to the kernel.
//!
//! The set lives in two `LPM_TRIE` maps (one per address family) rather than
//! being baked into the instruction stream, so [`Capture::add`] and
//! [`Capture::remove`] take effect immediately without reloading or
//! reattaching anything. Lookup cost is independent of how many prefixes are
//! in the set.
//!
//! # What gets captured
//!
//! For each frame the program checks, in order:
//!
//! - **IPv4** (`0x0800`): the destination address, the source address, or
//!   both, per [`MatchField`].
//! - **IPv6** (`0x86DD`): likewise, against the v6 trie.
//! - **ARP** (`0x0806`), when [`CaptureConfig::arp`] is set: the target
//!   protocol address, so an `ARP who-has <captured ip>` reaches userspace.
//!   Without this a captured address is unreachable — nobody can resolve it.
//!
//! IPv6 neighbor discovery needs the equivalent treatment, but a neighbor
//! solicitation is addressed to a *solicited-node multicast* address rather
//! than to the target, so no amount of destination matching finds it. Instead
//! [`Capture::add`] inserts that multicast address into the trie alongside a
//! `/128` (see [`CaptureConfig::neighbor_discovery`]) — same effect, and it
//! costs nothing in the datapath.
//!
//! Anything that matches nothing returns [`CaptureConfig::default_action`],
//! normally [`Action::PASS`]. A capture device therefore coexists with the
//! host stack on the same NIC instead of black-holing it.
//!
//! # Never the whole interface
//!
//! Sharing the NIC only holds if the capture set stays a strict subset of the
//! traffic on it, so [`Capture::add`] enforces that on two levels:
//!
//! - **Per prefix.** A `/0` matches every packet and is refused unconditionally.
//!   [`CaptureConfig::min_prefix_v4`] and [`CaptureConfig::min_prefix_v6`] raise
//!   the floor further for callers who want to allow no more than, say, a
//!   subnet at a time.
//! - **Per set.** A floor alone is not enough — two `/1`s clear it individually
//!   and cover all of IPv4 between them. Any addition that would leave the set
//!   spanning an entire address family is refused as well.
//!
//! Both checks run before anything reaches the kernel, so a refused call leaves
//! the capture set exactly as it was.
//!
//! The guarantee is a property of [`Capture`]. Assembling [`CaptureMaps`] and
//! [`build_program`] by hand, or supplying your own program through
//! `afxdp::ProgramSource::External`, opts out of it — those are the deliberate
//! low-level paths, and policing them is the caller's job.

use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::sync::Mutex;

use super::insn::{
    Asm, BPF_FUNC_MAP_LOOKUP_ELEM, BPF_FUNC_REDIRECT_MAP, Insn, Jmp, R0, R1, R2, R3, R6, R7, R8,
    R10, Size, host_be16, ld_map_fd,
};
use super::map::{Map, UpdateFlags, lpm_key};
use super::prog::{Action, Link, Mode, Program};
use crate::{EtherType, IpPrefix, Result};

// --- packet offsets --------------------------------------------------------

const ETH_HLEN: i32 = 14;
const ETH_TYPE: i16 = 12;

const IPV4_SRC: i16 = ETH_HLEN as i16 + 12;
const IPV4_DST: i16 = ETH_HLEN as i16 + 16;
/// Ethernet header plus a minimum-length IPv4 header.
const IPV4_MIN: i32 = ETH_HLEN + 20;

const IPV6_SRC: i16 = ETH_HLEN as i16 + 8;
const IPV6_DST: i16 = ETH_HLEN as i16 + 24;
/// Ethernet header plus the fixed IPv6 header.
const IPV6_MIN: i32 = ETH_HLEN + 40;

/// `arp.ptype` — the protocol the ARP message resolves, which we require to be
/// IPv4 before reading the addresses at IPv4 offsets.
const ARP_PTYPE: i16 = ETH_HLEN as i16 + 2;
/// `arp.spa`, sender protocol address.
const ARP_SPA: i16 = ETH_HLEN as i16 + 14;
/// `arp.tpa`, target protocol address.
const ARP_TPA: i16 = ETH_HLEN as i16 + 24;
/// Ethernet header plus an ARP message for IPv4-over-Ethernet.
const ARP_MIN: i32 = ETH_HLEN + 28;

/// `xdp_md.rx_queue_index` — the 5th `u32` of the context.
const XDP_MD_RX_QUEUE_INDEX: i16 = 16;

// --- stack slots -----------------------------------------------------------
//
// Every `bpf_lpm_trie_key` we pass to the helper is staged on the stack.
// Offsets are 4-byte aligned because the verifier enforces alignment strictly
// for stack access (unlike packet access, which it relaxes on architectures
// with cheap unaligned loads). Both keys for a family are staged before the
// first lookup so that no packet read happens after a helper call.

/// `{ u32 prefixlen; u8 addr[4]; }`
const V4_DST_KEY: i16 = -8;
const V4_SRC_KEY: i16 = -16;
/// `{ u32 prefixlen; u8 addr[16]; }`
const V6_DST_KEY: i16 = -40;
const V6_SRC_KEY: i16 = -64;

// The verifier enforces alignment strictly for PTR_TO_STACK, the keys must not
// overlap, and the whole lot has to fit the 512-byte BPF stack. Cheaper to
// prove here than to debug as an EACCES from the verifier.
const _: () = {
    assert!(V4_DST_KEY % 4 == 0 && V4_SRC_KEY % 4 == 0);
    assert!(V6_DST_KEY % 4 == 0 && V6_SRC_KEY % 4 == 0);
    assert!(V4_SRC_KEY + 8 <= V4_DST_KEY, "v4 keys overlap");
    assert!(
        V6_DST_KEY + 20 <= V4_SRC_KEY,
        "v6 dst key overlaps a v4 key"
    );
    assert!(V6_SRC_KEY + 20 <= V6_DST_KEY, "v6 keys overlap");
    assert!(V6_SRC_KEY > -512, "keys exceed the BPF stack");
};

/// Which address in the packet is matched against the capture set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchField {
    /// Traffic addressed *to* a captured prefix. The usual choice: the
    /// captured addresses are ones this process answers for.
    #[default]
    Dst,
    /// Traffic originating *from* a captured prefix.
    Src,
    /// Either endpoint. Two trie lookups on a miss instead of one.
    Either,
}

impl MatchField {
    #[inline]
    fn wants_dst(self) -> bool {
        matches!(self, MatchField::Dst | MatchField::Either)
    }

    #[inline]
    fn wants_src(self) -> bool {
        matches!(self, MatchField::Src | MatchField::Either)
    }
}

/// How the capture program is built.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Which address to match. See [`MatchField`].
    pub match_field: MatchField,
    /// Also capture ARP whose protocol address is in the v4 set. Required for
    /// a captured IPv4 address to be reachable at all.
    pub arp: bool,
    /// When adding a `/128`, also capture its solicited-node multicast address
    /// so IPv6 neighbor discovery reaches userspace.
    pub neighbor_discovery: bool,
    /// Verdict for traffic that matches nothing.
    ///
    /// [`Action::PASS`] (the default) leaves it to the host stack, which is
    /// what lets a capture device share a live NIC. [`Action::DROP`] takes the
    /// interface away from the host entirely — only meaningful on a NIC
    /// dedicated to this process.
    pub default_action: Action,
    /// Shortest IPv4 prefix [`Capture::add`] will accept, 1-32.
    ///
    /// The floor exists so a capture can never widen into the whole interface.
    /// `/0` matches every packet and is refused at any setting; raise this to
    /// hold callers to something tighter (e.g. 24 to allow no more than a
    /// subnet at a time).
    pub min_prefix_v4: u8,
    /// Shortest IPv6 prefix [`Capture::add`] will accept, 1-128.
    pub min_prefix_v6: u8,
    /// Capacity of each address-family trie.
    pub max_prefixes: u32,
    /// XSKMAP slots, i.e. the highest NIC queue index that can be bound.
    pub max_queues: u32,
}

impl Default for CaptureConfig {
    fn default() -> CaptureConfig {
        CaptureConfig {
            match_field: MatchField::Dst,
            arp: true,
            neighbor_discovery: true,
            // Never steal traffic we were not asked for: anything unmatched
            // belongs to the host stack.
            default_action: Action::PASS,
            // Reject only the outright catch-all by default; anything narrower
            // is a judgement call that belongs to the caller.
            min_prefix_v4: 1,
            min_prefix_v6: 1,
            max_prefixes: 1024,
            max_queues: 64,
        }
    }
}

impl CaptureConfig {
    /// Reject a configuration that could not uphold the sharing invariant.
    pub fn validate(&self) -> Result<()> {
        if self.min_prefix_v4 == 0 || self.min_prefix_v6 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xdp: min_prefix_v4/min_prefix_v6 must be at least 1; a /0                  matches every packet on the interface",
            ));
        }
        if self.min_prefix_v4 > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("xdp: min_prefix_v4 is /{}, max is /32", self.min_prefix_v4),
            ));
        }
        if self.min_prefix_v6 > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("xdp: min_prefix_v6 is /{}, max is /128", self.min_prefix_v6),
            ));
        }
        if self.default_action != Action::PASS && self.default_action != Action::DROP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xdp: default_action must be PASS or DROP, got {:?}",
                    self.default_action
                ),
            ));
        }
        if self.max_prefixes == 0 || self.max_queues == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xdp: max_prefixes and max_queues must be non-zero",
            ));
        }
        Ok(())
    }

    /// Reject a prefix broader than this configuration allows.
    pub fn check_prefix(&self, prefix: IpPrefix) -> Result<()> {
        let (min, family) = if prefix.is_v4() {
            (self.min_prefix_v4.max(1), "IPv4")
        } else {
            (self.min_prefix_v6.max(1), "IPv6")
        };
        if prefix.bits() >= min {
            return Ok(());
        }
        let why = if prefix.bits() == 0 {
            " — a /0 matches every packet on the interface".to_string()
        } else {
            format!(" — the {family} floor is /{min}")
        };
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("xdp: refusing to capture {prefix}{why}"),
        ))
    }
}

/// Addresses covered by the `v4`/`v6` half of `prefixes`, saturating.
///
/// Overlapping prefixes are counted twice, which can only overstate coverage —
/// the check built on this errs towards refusing.
fn coverage(prefixes: &[IpPrefix], v4: bool) -> u128 {
    let width: u32 = if v4 { 32 } else { 128 };
    prefixes
        .iter()
        .filter(|p| p.is_v4() == v4)
        .fold(0u128, |acc, p| {
            let host_bits = width - u32::from(p.bits()).min(width);
            // `add` refuses a /0, so host_bits <= 127 and the shift is defined.
            let n = 1u128.checked_shl(host_bits).unwrap_or(u128::MAX);
            acc.saturating_add(n)
        })
}

/// Every address in a family, as `coverage` counts them.
///
/// For IPv6 this saturates one short of 2^128, so the check triggers a single
/// address early — in the safe direction.
fn family_total(v4: bool) -> u128 {
    if v4 { 1u128 << 32 } else { u128::MAX }
}

/// Refuse a prefix that would let the set span an entire address family.
///
/// The per-prefix floor alone does not close this: two `/1`s cover all of IPv4
/// between them. This is what makes "never captures a whole interface" a
/// property of the set rather than of each addition.
fn check_coverage(held: &[IpPrefix], new: IpPrefix) -> Result<()> {
    let v4 = new.is_v4();
    let mut combined = held.to_vec();
    combined.push(new);
    if coverage(&combined, v4) >= family_total(v4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "xdp: refusing to capture {new}: it would leave the capture set                  covering every {} address on the interface",
                if v4 { "IPv4" } else { "IPv6" }
            ),
        ));
    }
    Ok(())
}

/// The maps a capture program reads.
#[derive(Debug)]
pub struct CaptureMaps {
    /// Queue index -> AF_XDP socket.
    pub xskmap: Map,
    /// IPv4 prefixes to capture.
    pub v4: Map,
    /// IPv6 prefixes to capture.
    pub v6: Map,
}

impl CaptureMaps {
    /// Create the three maps a capture program needs.
    pub fn create(cfg: &CaptureConfig) -> Result<CaptureMaps> {
        Ok(CaptureMaps {
            xskmap: Map::xskmap(cfg.max_queues)?,
            v4: Map::lpm_trie(4, 4, cfg.max_prefixes)?,
            v6: Map::lpm_trie(16, 4, cfg.max_prefixes)?,
        })
    }
}

/// Stage a `bpf_lpm_trie_key` for a 4-byte address at `slot`, reading the
/// address from `pkt_off` in the packet.
fn stage_v4(asm: &mut Asm, slot: i16, pkt_off: i16) {
    asm.emit(Insn::mov64_imm(R1, 32));
    asm.emit(Insn::stx(Size::W, R10, slot, R1));
    asm.emit(Insn::ldx(Size::W, R1, R7, pkt_off));
    asm.emit(Insn::stx(Size::W, R10, slot + 4, R1));
}

/// As [`stage_v4`], for a 16-byte address. Copied a word at a time: the
/// address sits at an odd offset behind the 14-byte Ethernet header, so a
/// wider load would buy nothing and would need 8-byte stack alignment.
fn stage_v6(asm: &mut Asm, slot: i16, pkt_off: i16) {
    asm.emit(Insn::mov64_imm(R1, 128));
    asm.emit(Insn::stx(Size::W, R10, slot, R1));
    for w in 0..4i16 {
        asm.emit(Insn::ldx(Size::W, R1, R7, pkt_off + w * 4));
        asm.emit(Insn::stx(Size::W, R10, slot + 4 + w * 4, R1));
    }
}

/// `if (bpf_map_lookup_elem(map, stack + slot)) goto hit`.
fn lookup(asm: &mut Asm, map_fd: i32, slot: i16, hit: super::insn::Label) {
    asm.emit_all(&ld_map_fd(R1, map_fd));
    asm.emit(Insn::mov64_reg(R2, R10));
    asm.emit(Insn::add64_imm(R2, slot as i32));
    asm.emit(Insn::call(BPF_FUNC_MAP_LOOKUP_ELEM));
    asm.jump(Insn::jmp_imm(Jmp::JNE, R0, 0, 0), hit);
}

/// `if (data + n > data_end) goto miss` — the bounds check the verifier
/// requires before every packet read.
fn need_bytes(asm: &mut Asm, n: i32, miss: super::insn::Label) {
    asm.emit(Insn::mov64_reg(R1, R7));
    asm.emit(Insn::add64_imm(R1, n));
    asm.jump(Insn::jmp_reg(Jmp::JGT, R1, R8, 0), miss);
}

/// Build the capture program against `maps`.
///
/// The map file descriptors are embedded in the instruction stream, so `maps`
/// must stay open until the program is loaded (and the program keeps the maps
/// alive from then on).
pub fn build_program(cfg: &CaptureConfig, maps: &CaptureMaps) -> Result<Vec<Insn>> {
    build_program_with_fds(
        cfg,
        maps.xskmap.as_raw_fd(),
        maps.v4.as_raw_fd(),
        maps.v6.as_raw_fd(),
    )
}

/// Codegen proper, parameterised on the map file descriptors so it can be
/// exercised without `CAP_BPF`.
fn build_program_with_fds(
    cfg: &CaptureConfig,
    xskmap_fd: i32,
    v4_fd: i32,
    v6_fd: i32,
) -> Result<Vec<Insn>> {
    let mut asm = Asm::new();
    let l_v4 = asm.label();
    let l_v6 = asm.label();
    let l_arp = asm.label();
    let l_redirect = asm.label();
    let l_default = asm.label();

    // r6 = ctx; r7 = ctx->data; r8 = ctx->data_end.
    //
    // These are `u32` fields that the verifier rewrites into pointer loads,
    // which is why they are read with a 32-bit access. r6-r9 are callee-saved,
    // so they survive the helper calls below.
    asm.emit(Insn::mov64_reg(R6, R1));
    asm.emit(Insn::ldx(Size::W, R7, R6, 0));
    asm.emit(Insn::ldx(Size::W, R8, R6, 4));

    need_bytes(&mut asm, ETH_HLEN, l_default);
    asm.emit(Insn::ldx(Size::H, R2, R7, ETH_TYPE));
    asm.jump(
        Insn::jmp_imm(Jmp::JEQ, R2, host_be16(EtherType::IPV4.0), 0),
        l_v4,
    );
    asm.jump(
        Insn::jmp_imm(Jmp::JEQ, R2, host_be16(EtherType::IPV6.0), 0),
        l_v6,
    );
    if cfg.arp {
        asm.jump(
            Insn::jmp_imm(Jmp::JEQ, R2, host_be16(EtherType::ARP.0), 0),
            l_arp,
        );
    }
    asm.jump(Insn::ja(0), l_default);

    // --- IPv4 ---
    asm.place(l_v4);
    need_bytes(&mut asm, IPV4_MIN, l_default);
    if cfg.match_field.wants_dst() {
        stage_v4(&mut asm, V4_DST_KEY, IPV4_DST);
    }
    if cfg.match_field.wants_src() {
        stage_v4(&mut asm, V4_SRC_KEY, IPV4_SRC);
    }
    if cfg.match_field.wants_dst() {
        lookup(&mut asm, v4_fd, V4_DST_KEY, l_redirect);
    }
    if cfg.match_field.wants_src() {
        lookup(&mut asm, v4_fd, V4_SRC_KEY, l_redirect);
    }
    asm.jump(Insn::ja(0), l_default);

    // --- IPv6 ---
    asm.place(l_v6);
    need_bytes(&mut asm, IPV6_MIN, l_default);
    if cfg.match_field.wants_dst() {
        stage_v6(&mut asm, V6_DST_KEY, IPV6_DST);
    }
    if cfg.match_field.wants_src() {
        stage_v6(&mut asm, V6_SRC_KEY, IPV6_SRC);
    }
    if cfg.match_field.wants_dst() {
        lookup(&mut asm, v6_fd, V6_DST_KEY, l_redirect);
    }
    if cfg.match_field.wants_src() {
        lookup(&mut asm, v6_fd, V6_SRC_KEY, l_redirect);
    }
    asm.jump(Insn::ja(0), l_default);

    // --- ARP ---
    if cfg.arp {
        asm.place(l_arp);
        need_bytes(&mut asm, ARP_MIN, l_default);
        // Only IPv4-over-Ethernet ARP has addresses where we expect them.
        asm.emit(Insn::ldx(Size::H, R2, R7, ARP_PTYPE));
        asm.jump(
            Insn::jmp_imm(Jmp::JNE, R2, host_be16(EtherType::IPV4.0), 0),
            l_default,
        );
        // `tpa` answers "who has <captured ip>"; `spa` catches the replies of a
        // captured sender. Which one is live follows MatchField.
        if cfg.match_field.wants_dst() {
            stage_v4(&mut asm, V4_DST_KEY, ARP_TPA);
        }
        if cfg.match_field.wants_src() {
            stage_v4(&mut asm, V4_SRC_KEY, ARP_SPA);
        }
        if cfg.match_field.wants_dst() {
            lookup(&mut asm, v4_fd, V4_DST_KEY, l_redirect);
        }
        if cfg.match_field.wants_src() {
            lookup(&mut asm, v4_fd, V4_SRC_KEY, l_redirect);
        }
        asm.jump(Insn::ja(0), l_default);
    }

    // --- redirect into the XSKMAP ---
    asm.place(l_redirect);
    asm.emit_all(&ld_map_fd(R1, xskmap_fd));
    asm.emit(Insn::ldx(Size::W, R2, R6, XDP_MD_RX_QUEUE_INDEX));
    // The low bits of `flags` are the verdict the helper returns when the map
    // has no socket for this queue. XDP_PASS keeps traffic flowing to the host
    // stack on queues we did not bind, instead of the XDP_ABORTED that flags=0
    // would produce.
    asm.emit(Insn::mov64_imm(R3, Action::PASS.0 as i32));
    asm.emit(Insn::call(BPF_FUNC_REDIRECT_MAP));
    asm.emit(Insn::exit());

    asm.place(l_default);
    asm.emit(Insn::mov64_imm(R0, cfg.default_action.0 as i32));
    asm.emit(Insn::exit());

    asm.build()
}

/// A loaded, attached capture program together with the maps that drive it.
///
/// Dropping this detaches the program and frees the maps.
#[derive(Debug)]
pub struct Capture {
    maps: CaptureMaps,
    _prog: Program,
    link: Link,
    cfg: CaptureConfig,
    /// Prefixes the caller added, kept so a removal can tell whether a derived
    /// entry (a solicited-node multicast address) is still needed.
    prefixes: Mutex<Vec<IpPrefix>>,
}

impl Capture {
    /// Build, load and attach a capture program on `ifindex`.
    ///
    /// The capture set starts empty, so nothing is diverted from the host
    /// stack until [`Capture::add`] is called.
    pub fn attach(ifindex: u32, cfg: CaptureConfig, mode: Mode) -> Result<Capture> {
        cfg.validate()?;
        let maps = CaptureMaps::create(&cfg)?;
        let insns = build_program(&cfg, &maps)?;
        let prog = Program::load(&insns, "pktkit_cap")?;
        let link = prog.attach(ifindex, mode)?;
        Ok(Capture {
            maps,
            _prog: prog,
            link,
            cfg,
            prefixes: Mutex::new(Vec::new()),
        })
    }

    /// The mode the program attached in.
    #[inline]
    pub fn mode(&self) -> Mode {
        self.link.mode()
    }

    /// The XSKMAP an AF_XDP socket registers itself in.
    #[inline]
    pub fn xskmap(&self) -> &Map {
        &self.maps.xskmap
    }

    /// Start capturing `prefix`. Idempotent.
    ///
    /// Refuses anything broader than [`CaptureConfig::min_prefix_v4`] /
    /// [`CaptureConfig::min_prefix_v6`], and refuses any prefix that would
    /// leave the set covering a whole address family. Nothing reaches the
    /// kernel until both checks pass, so a rejected call changes nothing.
    pub fn add(&self, prefix: IpPrefix) -> Result<()> {
        let prefix = prefix.masked();
        self.cfg.check_prefix(prefix)?;

        let mut held = self.prefixes.lock().unwrap();
        if held.contains(&prefix) {
            return Ok(());
        }
        check_coverage(&held, prefix)?;

        self.insert(prefix)?;
        if let Some(sn) = self.solicited_node(prefix) {
            // Derived entries are always /128, so they cannot move coverage.
            self.insert(sn)?;
        }
        held.push(prefix);
        Ok(())
    }

    /// Stop capturing `prefix`. Returns `false` if it was not in the set.
    pub fn remove(&self, prefix: IpPrefix) -> Result<bool> {
        let prefix = prefix.masked();
        let mut held = self.prefixes.lock().unwrap();
        let had = match held.iter().position(|p| *p == prefix) {
            Some(i) => {
                held.remove(i);
                true
            }
            None => false,
        };

        if let Some(sn) = self.solicited_node(prefix) {
            // Two addresses can share a solicited-node group (it is derived
            // from the low 24 bits), so only drop it once nothing needs it —
            // including a caller who added that group address in its own right.
            let still_needed = held
                .iter()
                .any(|p| *p == sn || self.solicited_node(*p) == Some(sn));
            if !still_needed {
                self.map_for(sn).delete(lpm_key(sn).as_bytes())?;
            }
        }
        drop(held);

        let removed = self.map_for(prefix).delete(lpm_key(prefix).as_bytes())?;
        Ok(had || removed)
    }

    /// True if `addr` is matched by the capture set.
    pub fn contains(&self, addr: IpAddr) -> Result<bool> {
        let full = IpPrefix::new(addr, if addr.is_ipv4() { 32 } else { 128 });
        let mut out = [0u8; 4];
        self.map_for(full)
            .lookup(lpm_key(full).as_bytes(), &mut out)
    }

    /// The prefixes added through [`Capture::add`], excluding derived entries.
    pub fn prefixes(&self) -> Vec<IpPrefix> {
        self.prefixes.lock().unwrap().clone()
    }

    fn insert(&self, prefix: IpPrefix) -> Result<()> {
        self.map_for(prefix).update(
            lpm_key(prefix).as_bytes(),
            &1u32.to_ne_bytes(),
            UpdateFlags::ANY,
        )
    }

    #[inline]
    fn map_for(&self, prefix: IpPrefix) -> &Map {
        if prefix.is_v4() {
            &self.maps.v4
        } else {
            &self.maps.v6
        }
    }

    /// The solicited-node multicast address a `/128` must also listen on for
    /// neighbor discovery to work. `None` for anything else.
    fn solicited_node(&self, prefix: IpPrefix) -> Option<IpPrefix> {
        if !self.cfg.neighbor_discovery || prefix.bits() != 128 {
            return None;
        }
        match prefix.addr() {
            IpAddr::V6(a) => Some(IpPrefix::new(solicited_node_multicast(a).into(), 128)),
            IpAddr::V4(_) => None,
        }
    }
}

/// `ff02::1:ffXX:XXXX` for `addr`, per RFC 4291 §2.7.1.
pub fn solicited_node_multicast(addr: Ipv6Addr) -> Ipv6Addr {
    let o = addr.octets();
    let mut sn = [0u8; 16];
    sn[0] = 0xff;
    sn[1] = 0x02;
    sn[11] = 0x01;
    sn[12] = 0xff;
    sn[13..16].copy_from_slice(&o[13..16]);
    Ipv6Addr::from(sn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::insn::{BPF_ADD, BPF_ALU64, BPF_JMP, BPF_K, BPF_STX};
    use std::net::Ipv4Addr;

    fn v4(a: [u8; 4], bits: u8) -> IpPrefix {
        IpPrefix::new(Ipv4Addr::from(a).into(), bits)
    }

    /// Codegen tests use placeholder fds: creating real maps needs CAP_BPF,
    /// which is exactly what these tests avoid.
    fn program(cfg: &CaptureConfig) -> Vec<Insn> {
        build_program_with_fds(cfg, 10, 11, 12).unwrap()
    }

    fn jumps(p: &[Insn]) -> Vec<usize> {
        p.iter()
            .enumerate()
            .filter(|(_, i)| i.code & 0x07 == BPF_JMP)
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        for cfg in [
            CaptureConfig::default(),
            CaptureConfig {
                match_field: MatchField::Either,
                ..Default::default()
            },
            CaptureConfig {
                arp: false,
                match_field: MatchField::Src,
                ..Default::default()
            },
        ] {
            let p = program(&cfg);
            for n in jumps(&p) {
                let i = p[n];
                // call and exit carry no branch offset.
                if i.code == (BPF_JMP | 0x80) || i.code == (BPF_JMP | 0x90) {
                    continue;
                }
                let target = n as isize + 1 + i.off as isize;
                assert!(
                    target >= 0 && target < p.len() as isize,
                    "jump at {n} targets {target}, program is {} insns",
                    p.len()
                );
            }
        }
    }

    #[test]
    fn program_ends_with_the_default_verdict() {
        let cfg = CaptureConfig::default();
        let p = program(&cfg);
        let n = p.len();
        assert_eq!(p[n - 1], Insn::exit());
        assert_eq!(p[n - 2], Insn::mov64_imm(R0, Action::PASS.0 as i32));
    }

    #[test]
    fn drop_default_is_honoured() {
        let cfg = CaptureConfig {
            default_action: Action::DROP,
            ..Default::default()
        };
        let p = program(&cfg);
        assert_eq!(p[p.len() - 2], Insn::mov64_imm(R0, Action::DROP.0 as i32));
    }

    #[test]
    fn redirect_falls_back_to_pass_on_an_unbound_queue() {
        let p = program(&CaptureConfig::default());
        let call = p
            .iter()
            .position(|i| *i == Insn::call(BPF_FUNC_REDIRECT_MAP))
            .expect("redirect call present");
        // flags (r3) is the verdict returned when the XSKMAP has no socket for
        // this queue; XDP_ABORTED (0) would black-hole unbound queues.
        assert_eq!(p[call - 1], Insn::mov64_imm(R3, Action::PASS.0 as i32));
    }

    #[test]
    fn dst_only_does_one_lookup_per_family() {
        let p = program(&CaptureConfig {
            match_field: MatchField::Dst,
            arp: false,
            ..Default::default()
        });
        let n = p
            .iter()
            .filter(|i| **i == Insn::call(BPF_FUNC_MAP_LOOKUP_ELEM))
            .count();
        assert_eq!(n, 2, "one v4 + one v6 lookup");
    }

    #[test]
    fn either_doubles_the_lookups() {
        let p = program(&CaptureConfig {
            match_field: MatchField::Either,
            arp: false,
            ..Default::default()
        });
        let n = p
            .iter()
            .filter(|i| **i == Insn::call(BPF_FUNC_MAP_LOOKUP_ELEM))
            .count();
        assert_eq!(n, 4);
    }

    #[test]
    fn arp_adds_a_third_family_branch() {
        let with = program(&CaptureConfig::default());
        let without = program(&CaptureConfig {
            arp: false,
            ..Default::default()
        });
        assert!(with.len() > without.len());
        let n = with
            .iter()
            .filter(|i| **i == Insn::call(BPF_FUNC_MAP_LOOKUP_ELEM))
            .count();
        assert_eq!(n, 3, "v4 + v6 + arp");
    }

    #[test]
    fn packet_reads_never_follow_a_helper_call() {
        // Packet pointers survive a call, but their verified range is easier to
        // reason about — and to keep the verifier happy across kernels — if
        // every read happens before the first lookup in its branch. This test
        // pins that property.
        let p = program(&CaptureConfig {
            match_field: MatchField::Either,
            ..Default::default()
        });
        let mut seen_call = false;
        for i in &p {
            if *i == Insn::call(BPF_FUNC_MAP_LOOKUP_ELEM) {
                seen_call = true;
            }
            // A load off r7 (packet data) after a lookup call, other than in a
            // fresh branch, is what we are ruling out. Branch boundaries reset
            // the flag.
            if i.code & 0x07 == 0x01 && (i.regs >> 4) == R7 {
                assert!(!seen_call, "packet read after a helper call");
            }
            // A jump target begins a new branch: reads there are re-bounded.
            if i.code & 0x07 == BPF_JMP && i.code != (BPF_JMP | 0x80) && i.off != 0 {
                seen_call = false;
            }
        }
    }

    #[test]
    fn every_staged_key_is_written_before_it_is_read() {
        // Each lookup passes `r10 + slot`; the slot must have been fully
        // initialised (prefixlen + address) or the verifier rejects the key.
        let p = program(&CaptureConfig {
            match_field: MatchField::Either,
            ..Default::default()
        });
        let add64_imm = BPF_ALU64 | BPF_K | BPF_ADD;
        let mut written: Vec<i16> = Vec::new();
        for i in &p {
            if i.code & 0x07 == BPF_STX && (i.regs & 0x0f) == R10 {
                written.push(i.off);
            }
            // `r2 = r10; r2 += slot` is what sets up each lookup's key pointer.
            if i.code == add64_imm && (i.regs & 0x0f) == R2 && i.imm < 0 {
                let slot = i.imm as i16;
                assert!(written.contains(&slot), "lookup key at {slot} never staged");
            }
        }
    }

    // --- the interface-sharing invariant ---

    #[test]
    fn a_default_route_is_never_capturable() {
        let cfg = CaptureConfig::default();
        for p in [
            IpPrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpPrefix::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        ] {
            let e = cfg.check_prefix(p).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            assert!(
                e.to_string().contains("every packet"),
                "error should say why: {e}"
            );
        }
    }

    #[test]
    fn a_zero_floor_cannot_be_configured() {
        // Otherwise `min_prefix = 0` would re-admit the catch-all.
        for cfg in [
            CaptureConfig {
                min_prefix_v4: 0,
                ..Default::default()
            },
            CaptureConfig {
                min_prefix_v6: 0,
                ..Default::default()
            },
        ] {
            assert!(cfg.validate().is_err());
        }
        // And even if one were smuggled in, check_prefix floors it at 1.
        let smuggled = CaptureConfig {
            min_prefix_v4: 0,
            ..Default::default()
        };
        assert!(
            smuggled
                .check_prefix(IpPrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0))
                .is_err()
        );
    }

    #[test]
    fn ordinary_prefixes_are_accepted() {
        let cfg = CaptureConfig::default();
        cfg.check_prefix(v4([10, 0, 0, 7], 32)).unwrap();
        cfg.check_prefix(v4([10, 0, 0, 0], 24)).unwrap();
        cfg.check_prefix(v4([10, 0, 0, 0], 8)).unwrap();
        cfg.check_prefix(v4([0, 0, 0, 0], 1)).unwrap();
    }

    #[test]
    fn a_tighter_floor_is_enforced_per_family() {
        let cfg = CaptureConfig {
            min_prefix_v4: 24,
            min_prefix_v6: 64,
            ..Default::default()
        };
        cfg.validate().unwrap();
        cfg.check_prefix(v4([10, 0, 0, 0], 24)).unwrap();
        assert!(cfg.check_prefix(v4([10, 0, 0, 0], 16)).is_err());
        // The v4 floor must not leak into the v6 decision.
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        cfg.check_prefix(IpPrefix::new(net.into(), 64)).unwrap();
        assert!(cfg.check_prefix(IpPrefix::new(net.into(), 48)).is_err());
    }

    #[test]
    fn a_floor_wider_than_the_family_is_rejected() {
        assert!(
            CaptureConfig {
                min_prefix_v4: 33,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CaptureConfig {
                min_prefix_v6: 129,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn two_halves_cannot_add_up_to_the_whole_interface() {
        // Each /1 clears the per-prefix floor; together they are a /0.
        let low = v4([0, 0, 0, 0], 1);
        let high = v4([128, 0, 0, 0], 1);
        check_coverage(&[], low).unwrap();
        let e = check_coverage(&[low], high).unwrap_err();
        assert!(e.to_string().contains("every IPv4 address"), "{e}");
    }

    #[test]
    fn four_quarters_cannot_either() {
        let quarters: Vec<IpPrefix> = [0u8, 64, 128, 192]
            .iter()
            .map(|&a| v4([a, 0, 0, 0], 2))
            .collect();
        for i in 0..3 {
            check_coverage(&quarters[..i], quarters[i]).unwrap();
        }
        assert!(check_coverage(&quarters[..3], quarters[3]).is_err());
    }

    #[test]
    fn ipv6_halves_are_caught_without_overflowing() {
        let low = IpPrefix::new("::".parse::<Ipv6Addr>().unwrap().into(), 1);
        let high = IpPrefix::new("8000::".parse::<Ipv6Addr>().unwrap().into(), 1);
        check_coverage(&[], low).unwrap();
        assert!(check_coverage(&[low], high).is_err());
    }

    #[test]
    fn coverage_is_counted_per_family() {
        // A full IPv6 set must not block an IPv4 addition, or vice versa.
        let v6_low = IpPrefix::new("::".parse::<Ipv6Addr>().unwrap().into(), 1);
        let v6_high = IpPrefix::new("8000::".parse::<Ipv6Addr>().unwrap().into(), 1);
        check_coverage(&[v6_low, v6_high], v4([10, 0, 0, 1], 32)).unwrap();
    }

    #[test]
    fn realistic_sets_stay_far_from_the_limit() {
        // A thousand hosts plus a couple of subnets must not trip the guard.
        let mut held: Vec<IpPrefix> = (0..1000)
            .map(|i| v4([10, (i / 256) as u8, (i % 256) as u8, 1], 32))
            .collect();
        held.push(v4([192, 168, 0, 0], 16));
        held.push(v4([172, 16, 0, 0], 12));
        check_coverage(&held, v4([10, 0, 0, 0], 8)).unwrap();
    }

    #[test]
    fn coverage_totals_are_exact_at_the_boundary() {
        assert_eq!(coverage(&[v4([10, 0, 0, 1], 32)], true), 1);
        assert_eq!(coverage(&[v4([10, 0, 0, 0], 24)], true), 256);
        assert_eq!(coverage(&[v4([0, 0, 0, 0], 1)], true), 1 << 31);
        assert_eq!(family_total(true), 1u128 << 32);
        // Only /0 could reach the v6 total on its own, and that is refused
        // before coverage is ever consulted.
        assert_eq!(coverage(&[], false), 0);
    }

    #[test]
    fn default_action_must_be_a_terminal_verdict() {
        for a in [Action::PASS, Action::DROP] {
            CaptureConfig {
                default_action: a,
                ..Default::default()
            }
            .validate()
            .unwrap();
        }
        // REDIRECT with no preceding redirect call, or ABORTED, are not
        // sensible fall-throughs.
        for a in [Action::REDIRECT, Action::TX, Action::ABORTED] {
            assert!(
                CaptureConfig {
                    default_action: a,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn the_default_configuration_validates() {
        CaptureConfig::default().validate().unwrap();
    }

    #[test]
    fn solicited_node_follows_rfc4291() {
        let a: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
        let sn = solicited_node_multicast(a);
        assert_eq!(sn, "ff02::1:ffad:beef".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn solicited_node_only_depends_on_the_low_24_bits() {
        let a: Ipv6Addr = "2001:db8::1:2:3".parse().unwrap();
        let b: Ipv6Addr = "fe80::ffff:1:2:3".parse().unwrap();
        assert_eq!(solicited_node_multicast(a), solicited_node_multicast(b));
    }

    #[test]
    fn ethertype_constants_are_compared_in_wire_order() {
        let p = program(&CaptureConfig::default());
        // The ethertype load is followed by the family comparisons.
        let load = p
            .iter()
            .position(|i| *i == Insn::ldx(Size::H, R2, R7, ETH_TYPE))
            .unwrap();
        assert_eq!(p[load + 1].imm, host_be16(0x0800));
        assert_eq!(p[load + 2].imm, host_be16(0x86DD));
        assert_eq!(p[load + 3].imm, host_be16(0x0806));
    }

    #[test]
    fn v4_prefix_round_trips_through_a_key() {
        let p = IpPrefix::new(Ipv4Addr::new(198, 51, 100, 7).into(), 32);
        assert_eq!(lpm_key(p).as_bytes()[4..], [198, 51, 100, 7]);
    }
}

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
//! An address hit is not yet a capture: each prefix carries a short list of
//! [`Rule`]s, and the packet has to satisfy one of them. [`Rule::Any`] takes
//! the whole address; [`Rule::Proto`] one IP protocol on it; [`Rule::Port`]
//! one TCP or UDP port. The port compared is the one at the captured endpoint
//! — the destination port when the destination address matched, the source
//! port when the source address did — so `Port(UDP, 53)` on a captured address
//! means "the DNS service *at* that address", whichever way the packet is
//! travelling.
//!
//! ARP and neighbor discovery follow the rules too. Only a prefix with an
//! [`Rule::Any`] entry has its ARP captured, and only a `/128` with one gets a
//! solicited-node multicast entry: a narrower rule means the address is shared
//! with the host stack, which then has to keep answering for it.
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
//! # Where the transport header is not
//!
//! A port rule can only be judged on a packet that carries a transport header
//! at a place the program can find:
//!
//! - An IPv4 packet with a fragment offset other than zero has no transport
//!   header. It does not match a port rule, and goes wherever the address's
//!   other rules (or the default action) send it. The first fragment carries
//!   the ports and matches normally.
//! - IPv6 extension headers are not walked. A [`Rule::Proto`] is compared
//!   against the Next Header field of the fixed header, and a [`Rule::Port`]
//!   requires TCP or UDP to follow the fixed header directly. A packet with,
//!   say, a Fragment header in between matches neither.
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
//! The rules on a prefix do not relax either check: a port rule on every
//! address is still a program that inspects every packet on the interface.
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
    Asm, BPF_FUNC_MAP_LOOKUP_ELEM, BPF_FUNC_REDIRECT_MAP, Insn, Jmp, Label, R0, R1, R2, R3, R4, R5,
    R6, R7, R8, R10, Size, host_be16, ld_map_fd,
};
use super::map::{Map, UpdateFlags, lpm_key};
use super::prog::{Action, Link, Mode, Program, TestRun};
use crate::{EtherType, IpPrefix, Protocol, Result};

// --- packet offsets --------------------------------------------------------

const ETH_HLEN: i32 = 14;
const ETH_TYPE: i16 = 12;

/// `ip.frag_off` — the flags and fragment offset word.
const IPV4_FRAG: i16 = ETH_HLEN as i16 + 6;
const IPV4_PROTO: i16 = ETH_HLEN as i16 + 9;
const IPV4_SRC: i16 = ETH_HLEN as i16 + 12;
const IPV4_DST: i16 = ETH_HLEN as i16 + 16;
/// Ethernet header plus a minimum-length IPv4 header.
const IPV4_MIN: i32 = ETH_HLEN + 20;
/// The 13-bit fragment offset within `ip.frag_off`, in wire order.
const IPV4_FRAG_OFF_MASK: u16 = 0x1fff;

const IPV6_NEXT: i16 = ETH_HLEN as i16 + 6;
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

/// Where a TCP or UDP header keeps its two ports.
const L4_SPORT: i16 = 0;
const L4_DPORT: i16 = 2;

/// The packet's protocol and the port at the captured endpoint, as the rule
/// walk compares them. Registers rather than stack slots: they are filled in
/// after the lookup and nothing is called before the walk is over.
const RULE_PROTO: u8 = R3;
const RULE_PORT: u8 = R4;

/// Loaded as the port when the packet has no readable transport header. A
/// rule's port is 16 bits, so nothing can ever equal it.
const NO_PORT: i32 = 0x1_0000;

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

// --- rules -----------------------------------------------------------------

/// What, beyond the address, a packet has to carry to be captured.
///
/// Every prefix in the set holds a list of these; a packet is captured if its
/// address matches the prefix *and* any one rule accepts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Every protocol: the whole address belongs to the capture. This is what
    /// [`Capture::add`] installs, and the only rule under which ARP and
    /// neighbor discovery for the address are captured too.
    Any,
    /// One IP protocol, e.g. `Protocol::ICMP` or `Protocol::GRE`, on any port.
    Proto(Protocol),
    /// One TCP or UDP port at the captured endpoint. Any other protocol is
    /// refused: the program reads ports at the offsets those two share.
    Port(Protocol, u16),
}

/// Byte tags in the map value. `KIND_END` marks the end of a prefix's list,
/// which is why the list is kept packed.
const KIND_END: u8 = 0;
const KIND_ANY: u8 = 1;
const KIND_PROTO: u8 = 2;
const KIND_PORT: u8 = 3;

/// `{ u8 kind; u8 proto; u8 port[2] (wire order); }`
const RULE_SIZE: usize = 4;

/// Hard cap on [`CaptureConfig::max_rules_per_prefix`]. The rule check is
/// unrolled once per slot at up to four lookup sites, and 64 keeps even the
/// widest configuration comfortably inside the old 4096-instruction limit.
pub const MAX_RULES_PER_PREFIX: u8 = 64;

impl Rule {
    /// Reject a rule the program could not evaluate.
    pub fn validate(&self) -> Result<()> {
        match self {
            Rule::Port(proto, _) if *proto != Protocol::TCP && *proto != Protocol::UDP => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "xdp: a port rule needs TCP or UDP, got protocol {}",
                        proto.as_u8()
                    ),
                ))
            }
            _ => Ok(()),
        }
    }

    fn encode(self) -> [u8; RULE_SIZE] {
        match self {
            Rule::Any => [KIND_ANY, 0, 0, 0],
            Rule::Proto(p) => [KIND_PROTO, p.as_u8(), 0, 0],
            Rule::Port(p, port) => {
                // Wire order, so the program compares it against the packet's
                // port with the same `ldx H` and no byte swap on either side.
                let b = port.to_be_bytes();
                [KIND_PORT, p.as_u8(), b[0], b[1]]
            }
        }
    }

    fn decode(b: &[u8; RULE_SIZE]) -> Option<Rule> {
        match b[0] {
            KIND_ANY => Some(Rule::Any),
            KIND_PROTO => Some(Rule::Proto(Protocol(b[1]))),
            KIND_PORT => Some(Rule::Port(Protocol(b[1]), u16::from_be_bytes([b[2], b[3]]))),
            _ => None,
        }
    }
}

/// The trie value for a prefix: its rules, packed, padded with `KIND_END`.
///
/// A [`Rule::Any`] goes first whatever order the caller added things in: it
/// decides the packet by itself, and in the first slot the program finds it
/// before parsing a transport header it would not need.
fn encode_rules(rules: &[Rule], max_rules: u8) -> Vec<u8> {
    let mut v = vec![KIND_END; value_size(max_rules) as usize];
    let any = rules.iter().filter(|r| **r == Rule::Any);
    let rest = rules.iter().filter(|r| **r != Rule::Any);
    for (slot, rule) in any.chain(rest).take(max_rules as usize).enumerate() {
        v[slot * RULE_SIZE..(slot + 1) * RULE_SIZE].copy_from_slice(&rule.encode());
    }
    v
}

fn decode_rules(value: &[u8]) -> Vec<Rule> {
    value
        .as_chunks::<RULE_SIZE>()
        .0
        .iter()
        .map_while(Rule::decode)
        .collect()
}

#[inline]
fn value_size(max_rules: u8) -> u32 {
    u32::from(max_rules) * RULE_SIZE as u32
}

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
#[non_exhaustive]
pub struct CaptureConfig {
    /// Which address to match. See [`MatchField`].
    pub match_field: MatchField,
    /// Also capture ARP whose protocol address is in the v4 set with a
    /// [`Rule::Any`]. Required for a captured IPv4 address to be reachable at
    /// all.
    pub arp: bool,
    /// When adding a `/128` with a [`Rule::Any`], also capture its
    /// solicited-node multicast address so IPv6 neighbor discovery reaches
    /// userspace.
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
    /// How many [`Rule`]s one prefix can hold, 1 to
    /// [`MAX_RULES_PER_PREFIX`]. Sets the trie value size and how far the
    /// in-program rule check is unrolled, so it cannot change after attach.
    pub max_rules_per_prefix: u8,
    /// XSKMAP slots, i.e. the highest NIC queue index that can be bound.
    pub max_queues: u32,
}

setters! {
    CaptureConfig {
        set match_field: MatchField;
        set arp: bool;
        set neighbor_discovery: bool;
        set default_action: Action;
        set min_prefix_v4: u8;
        set min_prefix_v6: u8;
        set max_prefixes: u32;
        set max_rules_per_prefix: u8;
        set max_queues: u32;
    }
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
            max_rules_per_prefix: 8,
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
                "xdp: min_prefix_v4/min_prefix_v6 must be at least 1; a /0 \
                 matches every packet on the interface",
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
        if self.max_rules_per_prefix == 0 || self.max_rules_per_prefix > MAX_RULES_PER_PREFIX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xdp: max_rules_per_prefix is {}, must be 1-{MAX_RULES_PER_PREFIX}",
                    self.max_rules_per_prefix
                ),
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
                "xdp: refusing to capture {new}: it would leave the capture set \
                 covering every {} address on the interface",
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
    /// IPv4 prefixes to capture. The value is the prefix's packed rule list.
    pub v4: Map,
    /// IPv6 prefixes to capture, likewise.
    pub v6: Map,
}

impl CaptureMaps {
    /// Create the three maps a capture program needs.
    pub fn create(cfg: &CaptureConfig) -> Result<CaptureMaps> {
        let value = value_size(cfg.max_rules_per_prefix);
        Ok(CaptureMaps {
            xskmap: Map::xskmap(cfg.max_queues)?,
            v4: Map::lpm_trie(4, value, cfg.max_prefixes)?,
            v6: Map::lpm_trie(16, value, cfg.max_prefixes)?,
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

/// Which packet the transport fields are read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Load [`RULE_PROTO`] and [`RULE_PORT`] from the packet, the port being the
/// one at `port_off` in the transport header.
///
/// This runs after a lookup has hit, never before: most packets on the
/// interface miss, and they should not pay for a transport parse nobody will
/// look at. `r7`/`r8` are callee-saved and `bpf_map_lookup_elem` does not move
/// packet data, so they are still good packet pointers here. `r0` — the rule
/// list — is left alone; `r1`, `r2` and `r5` are scratch.
fn load_l4(asm: &mut Asm, family: Family, port_off: i16) {
    let l_done = asm.label();
    asm.emit(Insn::mov64_imm(RULE_PORT, NO_PORT));
    match family {
        // The transport header sits at `ihl * 4`, a variable offset the
        // verifier accepts because `ihl` is masked to four bits before it is
        // added to the packet pointer. A non-first fragment carries no
        // transport header, and neither does a packet whose `ihl` is short of
        // the fixed header, so both keep `NO_PORT`.
        Family::V4 => {
            asm.emit(Insn::ldx(Size::B, RULE_PROTO, R7, IPV4_PROTO));
            asm.emit(Insn::ldx(Size::H, R1, R7, IPV4_FRAG));
            asm.jump(
                Insn::jmp_imm(Jmp::JSET, R1, host_be16(IPV4_FRAG_OFF_MASK), 0),
                l_done,
            );
            asm.emit(Insn::ldx(Size::B, R2, R7, ETH_HLEN as i16));
            asm.emit(Insn::and64_imm(R2, 0x0f));
            asm.emit(Insn::lsh64_imm(R2, 2));
            asm.jump(Insn::jmp_imm(Jmp::JLT, R2, IPV4_MIN - ETH_HLEN, 0), l_done);
            asm.emit(Insn::mov64_reg(R1, R7));
            asm.emit(Insn::add64_imm(R1, ETH_HLEN));
            asm.emit(Insn::add64_reg(R1, R2));
        }
        // Extension headers are not walked (see the module docs), so the
        // ports are wherever a directly-following TCP/UDP header puts them.
        Family::V6 => {
            asm.emit(Insn::ldx(Size::B, RULE_PROTO, R7, IPV6_NEXT));
            asm.emit(Insn::mov64_reg(R1, R7));
            asm.emit(Insn::add64_imm(R1, IPV6_MIN));
        }
    }
    // r1 = transport header; both ports have to be in bounds to read either.
    asm.emit(Insn::mov64_reg(R5, R1));
    asm.emit(Insn::add64_imm(R5, 4));
    asm.jump(Insn::jmp_reg(Jmp::JGT, R5, R8, 0), l_done);
    asm.emit(Insn::ldx(Size::H, RULE_PORT, R1, port_off));
    asm.place(l_done);
}

/// `if (!bpf_map_lookup_elem(map, stack + slot)) goto miss`, leaving the
/// value pointer in `r0`.
fn lookup(asm: &mut Asm, map_fd: i32, slot: i16, miss: Label) {
    asm.emit_all(&ld_map_fd(R1, map_fd));
    asm.emit(Insn::mov64_reg(R2, R10));
    asm.emit(Insn::add64_imm(R2, slot as i32));
    asm.emit(Insn::call(BPF_FUNC_MAP_LOOKUP_ELEM));
    asm.jump(Insn::jmp_imm(Jmp::JEQ, R0, 0, 0), miss);
}

/// Walk the rule list `r0` points at: `goto hit` on the first rule the packet
/// satisfies, `goto miss` once none does.
///
/// `l4` names the packet family and the port the packet is judged on —
/// [`L4_DPORT`] after a destination-address hit, [`L4_SPORT`] after a source
/// one. `None` is the ARP branch, where only a [`Rule::Any`] can match: there
/// is no transport header to judge anything else on, and a narrower rule
/// leaves ARP to the host.
///
/// The transport fields are loaded only once the first slot has turned out to
/// be neither the end of the list nor a [`Rule::Any`], which [`encode_rules`]
/// always puts first. A whole-address capture is therefore decided on one byte
/// of the value.
fn match_rules(asm: &mut Asm, max_rules: u8, l4: Option<(Family, i16)>, hit: Label, miss: Label) {
    for i in 0..max_rules as i16 {
        let next = asm.label();
        let off = i * RULE_SIZE as i16;
        asm.emit(Insn::ldx(Size::B, R1, R0, off));
        asm.jump(Insn::jmp_imm(Jmp::JEQ, R1, KIND_END as i32, 0), miss);
        asm.jump(Insn::jmp_imm(Jmp::JEQ, R1, KIND_ANY as i32, 0), hit);
        if let Some((family, port_off)) = l4 {
            if i == 0 {
                load_l4(asm, family, port_off);
                // The parse used r1.
                asm.emit(Insn::ldx(Size::B, R1, R0, off));
            }
            asm.emit(Insn::ldx(Size::B, R2, R0, off + 1));
            asm.jump(Insn::jmp_reg(Jmp::JNE, R2, RULE_PROTO, 0), next);
            asm.jump(Insn::jmp_imm(Jmp::JEQ, R1, KIND_PROTO as i32, 0), hit);
            asm.emit(Insn::ldx(Size::H, R2, R0, off + 2));
            asm.jump(Insn::jmp_reg(Jmp::JEQ, R2, RULE_PORT, 0), hit);
        }
        asm.place(next);
    }
    asm.jump(Insn::ja(0), miss);
}

/// One trie lookup followed by its rule check: falls through on a miss.
fn lookup_and_match(
    asm: &mut Asm,
    cfg: &CaptureConfig,
    map_fd: i32,
    slot: i16,
    l4: Option<(Family, i16)>,
    hit: Label,
) {
    let miss = asm.label();
    lookup(asm, map_fd, slot, miss);
    match_rules(asm, cfg.max_rules_per_prefix, l4, hit, miss);
    asm.place(miss);
}

/// `if (data + n > data_end) goto miss` — the bounds check the verifier
/// requires before every packet read.
fn need_bytes(asm: &mut Asm, n: i32, miss: Label) {
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

    // Both keys are staged before the first lookup. The transport header is
    // not: it is parsed after an address hit, inside the rule walk.

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
        let l4 = Some((Family::V4, L4_DPORT));
        lookup_and_match(&mut asm, cfg, v4_fd, V4_DST_KEY, l4, l_redirect);
    }
    if cfg.match_field.wants_src() {
        let l4 = Some((Family::V4, L4_SPORT));
        lookup_and_match(&mut asm, cfg, v4_fd, V4_SRC_KEY, l4, l_redirect);
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
        let l4 = Some((Family::V6, L4_DPORT));
        lookup_and_match(&mut asm, cfg, v6_fd, V6_DST_KEY, l4, l_redirect);
    }
    if cfg.match_field.wants_src() {
        let l4 = Some((Family::V6, L4_SPORT));
        lookup_and_match(&mut asm, cfg, v6_fd, V6_SRC_KEY, l4, l_redirect);
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
            lookup_and_match(&mut asm, cfg, v4_fd, V4_DST_KEY, None, l_redirect);
        }
        if cfg.match_field.wants_src() {
            lookup_and_match(&mut asm, cfg, v4_fd, V4_SRC_KEY, None, l_redirect);
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

/// One prefix in the set and the rules the caller gave it.
#[derive(Debug, Clone)]
struct Entry {
    prefix: IpPrefix,
    rules: Vec<Rule>,
}

/// A loaded, attached capture program together with the maps that drive it.
///
/// Dropping this detaches the program and frees the maps.
#[derive(Debug)]
pub struct Capture {
    maps: CaptureMaps,
    prog: Program,
    link: Link,
    cfg: CaptureConfig,
    /// What the caller added, kept so a removal can tell whether a derived
    /// entry (a solicited-node multicast address) is still needed, and so a
    /// rule can be added to a prefix without reading the trie back.
    entries: Mutex<Vec<Entry>>,
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
            prog,
            link,
            cfg,
            entries: Mutex::new(Vec::new()),
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

    /// Run the attached program against `frame` in the kernel, `repeat` times:
    /// the verdict it gives with the capture set as it stands, and its mean
    /// cost per packet. See [`Program::test_run`].
    pub fn test_run(&self, frame: &[u8], repeat: u32) -> Result<TestRun> {
        self.prog.test_run(frame, repeat)
    }

    /// Start capturing everything for `prefix`: [`Capture::add_rule`] with
    /// [`Rule::Any`]. Idempotent.
    ///
    /// Refuses anything broader than [`CaptureConfig::min_prefix_v4`] /
    /// [`CaptureConfig::min_prefix_v6`], and refuses any prefix that would
    /// leave the set covering a whole address family. Nothing reaches the
    /// kernel until both checks pass, so a rejected call changes nothing.
    pub fn add(&self, prefix: IpPrefix) -> Result<()> {
        self.add_rule(prefix, Rule::Any)
    }

    /// Start capturing the traffic `rule` selects for `prefix`. Idempotent
    /// per rule; a prefix accumulates rules up to
    /// [`CaptureConfig::max_rules_per_prefix`].
    ///
    /// The prefix checks of [`Capture::add`] apply whatever the rule.
    pub fn add_rule(&self, prefix: IpPrefix, rule: Rule) -> Result<()> {
        let prefix = prefix.masked();
        self.cfg.check_prefix(prefix)?;
        rule.validate()?;

        let mut held = self.entries.lock().unwrap();
        match held.iter().position(|e| e.prefix == prefix) {
            Some(i) => {
                if held[i].rules.contains(&rule) {
                    return Ok(());
                }
                if held[i].rules.len() >= usize::from(self.cfg.max_rules_per_prefix) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "xdp: {prefix} already holds {} rules, the configured maximum",
                            held[i].rules.len()
                        ),
                    ));
                }
                let mut rules = held[i].rules.clone();
                rules.push(rule);
                self.write(prefix, &rules)?;
                held[i].rules = rules;
            }
            None => {
                let prefixes: Vec<IpPrefix> = held.iter().map(|e| e.prefix).collect();
                check_coverage(&prefixes, prefix)?;
                self.write(prefix, &[rule])?;
                held.push(Entry {
                    prefix,
                    rules: vec![rule],
                });
            }
        }
        if rule == Rule::Any
            && let Some(sn) = self.solicited_node(prefix)
        {
            self.sync_solicited_node(&held, sn)?;
        }
        Ok(())
    }

    /// Stop capturing `prefix` under every rule. Returns `false` if it was not
    /// in the set.
    pub fn remove(&self, prefix: IpPrefix) -> Result<bool> {
        let prefix = prefix.masked();
        let mut held = self.entries.lock().unwrap();
        let had = match held.iter().position(|e| e.prefix == prefix) {
            Some(i) => {
                held.remove(i);
                true
            }
            None => false,
        };
        let removed = self.map_for(prefix).delete(lpm_key(prefix).as_bytes())?;
        self.after_removal(&held, prefix)?;
        Ok(had || removed)
    }

    /// Stop capturing what `rule` selects for `prefix`, leaving its other
    /// rules in place. Returns `false` if the prefix did not hold that rule.
    pub fn remove_rule(&self, prefix: IpPrefix, rule: Rule) -> Result<bool> {
        let prefix = prefix.masked();
        let mut held = self.entries.lock().unwrap();
        let Some(i) = held.iter().position(|e| e.prefix == prefix) else {
            return Ok(false);
        };
        let Some(r) = held[i].rules.iter().position(|r| *r == rule) else {
            return Ok(false);
        };
        let mut rules = held[i].rules.clone();
        rules.remove(r);
        if rules.is_empty() {
            self.map_for(prefix).delete(lpm_key(prefix).as_bytes())?;
            held.remove(i);
        } else {
            self.write(prefix, &rules)?;
            held[i].rules = rules;
        }
        if rule == Rule::Any {
            self.after_removal(&held, prefix)?;
        }
        Ok(true)
    }

    /// True if `addr` is matched by the capture set under any rule.
    pub fn contains(&self, addr: IpAddr) -> Result<bool> {
        Ok(!self.rules_for(addr)?.is_empty())
    }

    /// The rules the kernel-side set applies to `addr`: those of the longest
    /// prefix containing it, or none if nothing does. They come back in the
    /// order the program walks them, which has any [`Rule::Any`] first.
    pub fn rules_for(&self, addr: IpAddr) -> Result<Vec<Rule>> {
        let full = IpPrefix::new(addr, if addr.is_ipv4() { 32 } else { 128 });
        let mut out = vec![0u8; value_size(self.cfg.max_rules_per_prefix) as usize];
        if self
            .map_for(full)
            .lookup(lpm_key(full).as_bytes(), &mut out)?
        {
            Ok(decode_rules(&out))
        } else {
            Ok(Vec::new())
        }
    }

    /// The prefixes added through [`Capture::add`] / [`Capture::add_rule`],
    /// excluding derived entries.
    pub fn prefixes(&self) -> Vec<IpPrefix> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.prefix)
            .collect()
    }

    /// The rules added for `prefix`, in insertion order; empty if it is not
    /// in the set.
    pub fn rules(&self, prefix: IpPrefix) -> Vec<Rule> {
        let prefix = prefix.masked();
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.prefix == prefix)
            .map(|e| e.rules.clone())
            .unwrap_or_default()
    }

    fn write(&self, prefix: IpPrefix, rules: &[Rule]) -> Result<()> {
        self.map_for(prefix).update(
            lpm_key(prefix).as_bytes(),
            &encode_rules(rules, self.cfg.max_rules_per_prefix),
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

    /// Bring the derived entries `prefix` could have touched back in line: the
    /// group it derives, and — if `prefix` is itself a solicited-node group
    /// the caller had claimed — the group another `/128` may still need.
    fn after_removal(&self, held: &[Entry], prefix: IpPrefix) -> Result<()> {
        if let Some(sn) = self.solicited_node(prefix) {
            self.sync_solicited_node(held, sn)?;
        }
        if is_solicited_node_group(prefix) {
            self.sync_solicited_node(held, prefix)?;
        }
        Ok(())
    }

    /// Insert or delete the derived entry for the solicited-node group `sn`
    /// according to whether any `/128` with a [`Rule::Any`] still derives it.
    ///
    /// A caller who added the group address in its own right owns it: its
    /// rules stand, and it is neither overwritten nor deleted here.
    fn sync_solicited_node(&self, held: &[Entry], sn: IpPrefix) -> Result<()> {
        if held.iter().any(|e| e.prefix == sn) {
            return Ok(());
        }
        // Two addresses can share a group (it is derived from the low 24
        // bits), so it stays as long as any of them needs it.
        let needed = held
            .iter()
            .any(|e| e.rules.contains(&Rule::Any) && self.solicited_node(e.prefix) == Some(sn));
        if needed {
            // Derived entries are always /128, so they cannot move coverage.
            self.write(sn, &[Rule::Any])
        } else {
            self.map_for(sn).delete(lpm_key(sn).as_bytes()).map(|_| ())
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

/// True if `prefix` is a single address inside `ff02::1:ff00:0/104`.
fn is_solicited_node_group(prefix: IpPrefix) -> bool {
    match prefix.addr() {
        IpAddr::V6(a) if prefix.bits() == 128 => {
            let o = a.octets();
            o[..13] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff]
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::insn::{BPF_ADD, BPF_ALU64, BPF_JMP, BPF_K, BPF_STX};
    use std::net::Ipv4Addr;

    const UDP: Protocol = Protocol::UDP;
    const TCP: Protocol = Protocol::TCP;

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
            CaptureConfig {
                max_rules_per_prefix: 1,
                ..Default::default()
            },
            CaptureConfig {
                max_rules_per_prefix: MAX_RULES_PER_PREFIX,
                match_field: MatchField::Either,
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

    // --- rules ---

    #[test]
    fn a_port_rule_needs_tcp_or_udp() {
        Rule::Port(TCP, 443).validate().unwrap();
        Rule::Port(UDP, 53).validate().unwrap();
        Rule::Proto(Protocol::ICMP).validate().unwrap();
        Rule::Any.validate().unwrap();
        for p in [Protocol::ICMP, Protocol::GRE, Protocol(132)] {
            let e = Rule::Port(p, 80).validate().unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn rules_round_trip_through_the_value() {
        let rules = [Rule::Any, Rule::Proto(Protocol::GRE), Rule::Port(TCP, 443)];
        let v = encode_rules(&rules, 8);
        assert_eq!(v.len(), 32);
        assert_eq!(decode_rules(&v), rules);
        // The list is packed and END-terminated: the fourth slot stops the walk.
        assert_eq!(v[12], KIND_END);
    }

    #[test]
    fn a_port_is_stored_in_wire_order() {
        // So `ldx H` sees the same bits from the value as from the packet.
        assert_eq!(
            Rule::Port(UDP, 0x1234).encode(),
            [KIND_PORT, 17, 0x12, 0x34]
        );
    }

    #[test]
    fn an_empty_list_decodes_to_nothing() {
        assert!(decode_rules(&encode_rules(&[], 4)).is_empty());
    }

    #[test]
    fn value_size_follows_the_rule_cap() {
        assert_eq!(value_size(1), 4);
        assert_eq!(value_size(8), 32);
        assert_eq!(value_size(MAX_RULES_PER_PREFIX), 256);
    }

    #[test]
    fn the_rule_cap_is_bounded() {
        for n in [0, MAX_RULES_PER_PREFIX + 1] {
            assert!(
                CaptureConfig {
                    max_rules_per_prefix: n,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        CaptureConfig {
            max_rules_per_prefix: MAX_RULES_PER_PREFIX,
            ..Default::default()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn solicited_node_groups_are_recognised() {
        let sn: Ipv6Addr = "ff02::1:ffad:beef".parse().unwrap();
        assert!(is_solicited_node_group(IpPrefix::new(sn.into(), 128)));
        assert!(!is_solicited_node_group(IpPrefix::new(sn.into(), 104)));
        let other: Ipv6Addr = "ff02::16".parse().unwrap();
        assert!(!is_solicited_node_group(IpPrefix::new(other.into(), 128)));
        assert!(!is_solicited_node_group(v4([224, 0, 0, 1], 32)));
    }

    #[test]
    fn rule_reads_stay_inside_the_value() {
        // Every load off r0 (the map value) must be within value_size, or the
        // verifier rejects the program.
        for n in [1u8, 3, 8, MAX_RULES_PER_PREFIX] {
            let cfg = CaptureConfig {
                max_rules_per_prefix: n,
                match_field: MatchField::Either,
                ..Default::default()
            };
            let size = value_size(n) as i16;
            for i in program(&cfg) {
                if i.code & 0x07 == 0x01 && (i.regs >> 4) == R0 {
                    let width = match Size(i.code & 0x18) {
                        Size::B => 1,
                        Size::H => 2,
                        Size::W => 4,
                        _ => 8,
                    };
                    assert!(
                        i.off >= 0 && i.off + width <= size,
                        "read at {} past {size}",
                        i.off
                    );
                }
            }
        }
    }

    #[test]
    fn the_arp_branch_never_compares_a_protocol() {
        // ARP has no transport header: its rule walk may only look at kinds.
        let p = program(&CaptureConfig {
            match_field: MatchField::Dst,
            ..Default::default()
        });
        let arp = p
            .iter()
            .position(|i| *i == Insn::ldx(Size::H, R2, R7, ARP_PTYPE))
            .expect("arp branch present");
        let redirect = p
            .iter()
            .position(|i| *i == Insn::call(BPF_FUNC_REDIRECT_MAP))
            .unwrap();
        for i in &p[arp..redirect] {
            assert_ne!(*i, Insn::mov64_imm(RULE_PORT, NO_PORT));
            assert_ne!(*i, Insn::ldx(Size::B, R2, R0, 1));
        }
    }

    #[test]
    fn the_transport_header_is_not_parsed_before_a_lookup() {
        // A miss is the common case on a shared NIC and must stay cheap: no
        // branch may start its transport parse ahead of its first lookup.
        let p = program(&CaptureConfig::default());
        let first_call = p
            .iter()
            .position(|i| *i == Insn::call(BPF_FUNC_MAP_LOOKUP_ELEM))
            .unwrap();
        let head = &p[..first_call];
        assert!(!head.contains(&Insn::mov64_imm(RULE_PORT, NO_PORT)));
        assert!(!head.contains(&Insn::ldx(Size::B, RULE_PROTO, R7, IPV4_PROTO)));
        // And it is there afterwards, once per lookup site.
        let parses = p
            .iter()
            .filter(|i| **i == Insn::mov64_imm(RULE_PORT, NO_PORT))
            .count();
        assert_eq!(parses, 2, "one v4 site and one v6 site under Dst");
    }

    #[test]
    fn any_is_encoded_first() {
        let rules = [Rule::Port(TCP, 443), Rule::Any, Rule::Proto(Protocol::GRE)];
        assert_eq!(
            decode_rules(&encode_rules(&rules, 8)),
            [Rule::Any, Rule::Port(TCP, 443), Rule::Proto(Protocol::GRE)]
        );
    }

    // --- executing the program ---
    //
    // The verifier can only be consulted as root (see tests/xdp_kernel.rs).
    // What can be checked here is that the instruction stream *means* what the
    // codegen intends: a small interpreter runs it against synthetic frames and
    // simulated maps, and the verdicts have to come out right.

    mod vm {
        use super::*;

        const PKT: u64 = 0x1000_0000;
        const STACK_TOP: u64 = 0x2000_0200;
        const VALUE: u64 = 0x3000_0000;
        const CTX: u64 = 0x4000_0000;
        const MAP: u64 = 0x5000_0000;

        pub const XSK_FD: i32 = 10;
        pub const V4_FD: i32 = 11;
        pub const V6_FD: i32 = 12;

        pub struct Trie {
            pub addr_len: usize,
            /// `(prefixlen, address, value)`
            pub entries: Vec<(u32, Vec<u8>, Vec<u8>)>,
        }

        impl Trie {
            fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
                assert_eq!(key.len(), 4 + self.addr_len, "key does not fit this trie");
                let bits = u32::from_ne_bytes(key[..4].try_into().unwrap());
                let addr = &key[4..];
                self.entries
                    .iter()
                    .filter(|(plen, paddr, _)| *plen <= bits && prefix_eq(paddr, addr, *plen))
                    .max_by_key(|(plen, _, _)| *plen)
                    .map(|(_, _, v)| v.as_slice())
            }
        }

        fn prefix_eq(a: &[u8], b: &[u8], bits: u32) -> bool {
            let full = (bits / 8) as usize;
            if a[..full] != b[..full] {
                return false;
            }
            let rem = bits % 8;
            rem == 0 || {
                let mask = 0xffu8 << (8 - rem);
                a[full] & mask == b[full] & mask
            }
        }

        pub struct Vm<'a> {
            pub v4: Trie,
            pub v6: Trie,
            pub xsk_queues: Vec<u32>,
            pub rx_queue: u32,
            /// Instructions the last [`Vm::run`] executed.
            pub steps: usize,
            pkt: &'a [u8],
            stack: [u8; 512],
            value: Vec<u8>,
            ctx: [u8; 20],
            regs: [u64; 11],
        }

        impl<'a> Vm<'a> {
            pub fn new(pkt: &'a [u8], v4: Trie, v6: Trie) -> Vm<'a> {
                Vm {
                    v4,
                    v6,
                    xsk_queues: vec![0],
                    rx_queue: 0,
                    steps: 0,
                    pkt,
                    stack: [0; 512],
                    value: Vec::new(),
                    ctx: [0; 20],
                    regs: [0; 11],
                }
            }

            fn mem(&mut self, addr: u64, len: usize) -> &mut [u8] {
                // Packet memory is read-only to the program and is served by
                // `load`; a write there is a codegen bug.
                let (base, buf): (u64, &mut [u8]) = if (STACK_TOP - 512..STACK_TOP).contains(&addr)
                {
                    (STACK_TOP - 512, &mut self.stack[..])
                } else if (VALUE..VALUE + self.value.len() as u64).contains(&addr) {
                    (VALUE, &mut self.value[..])
                } else if (CTX..CTX + 20).contains(&addr) {
                    (CTX, &mut self.ctx[..])
                } else {
                    panic!("access to unmapped address {addr:#x}")
                };
                let off = (addr - base) as usize;
                assert!(off + len <= buf.len(), "access past the end of a region");
                &mut buf[off..off + len]
            }

            fn load(&mut self, addr: u64, len: usize) -> u64 {
                let mut b = [0u8; 8];
                if (PKT..PKT + self.pkt.len() as u64).contains(&addr) {
                    let off = (addr - PKT) as usize;
                    assert!(
                        off + len <= self.pkt.len(),
                        "packet read at {off}+{len} past data_end — the verifier would reject this"
                    );
                    b[..len].copy_from_slice(&self.pkt[off..off + len]);
                } else {
                    b[..len].copy_from_slice(self.mem(addr, len));
                }
                u64::from_ne_bytes(b)
            }

            fn store(&mut self, addr: u64, len: usize, v: u64) {
                let b = v.to_ne_bytes();
                self.mem(addr, len).copy_from_slice(&b[..len]);
            }

            fn call(&mut self, func: i32) {
                match func {
                    BPF_FUNC_MAP_LOOKUP_ELEM => {
                        let fd = (self.regs[1] - MAP) as i32;
                        let addr_len = match fd {
                            V4_FD => 4,
                            V6_FD => 16,
                            _ => panic!("lookup on non-trie fd {fd}"),
                        };
                        let key = self.load_bytes(self.regs[2], 4 + addr_len);
                        let trie = if fd == V4_FD { &self.v4 } else { &self.v6 };
                        match trie.lookup(&key).map(<[u8]>::to_vec) {
                            Some(v) => {
                                self.value = v;
                                self.regs[0] = VALUE;
                            }
                            None => self.regs[0] = 0,
                        }
                    }
                    BPF_FUNC_REDIRECT_MAP => {
                        assert_eq!(self.regs[1], MAP + XSK_FD as u64);
                        let q = self.regs[2] as u32;
                        self.regs[0] = if self.xsk_queues.contains(&q) {
                            Action::REDIRECT.0 as u64
                        } else {
                            self.regs[3] & 0xf
                        };
                    }
                    _ => panic!("unknown helper {func}"),
                }
                // r1-r5 are clobbered by a call.
                for r in 1..=5 {
                    self.regs[r] = 0xdead_beef_dead_beef;
                }
            }

            fn load_bytes(&mut self, addr: u64, len: usize) -> Vec<u8> {
                (0..len)
                    .map(|i| self.load(addr + i as u64, 1) as u8)
                    .collect()
            }

            /// Run `prog` to `exit` and return the verdict in r0.
            pub fn run(&mut self, prog: &[Insn]) -> u32 {
                let end = PKT + self.pkt.len() as u64;
                self.ctx[..4].copy_from_slice(&(PKT as u32).to_ne_bytes());
                self.ctx[4..8].copy_from_slice(&(end as u32).to_ne_bytes());
                self.ctx[16..20].copy_from_slice(&self.rx_queue.to_ne_bytes());
                self.regs[1] = CTX;
                self.regs[10] = STACK_TOP;

                let mut pc = 0usize;
                self.steps = 0;
                loop {
                    self.steps += 1;
                    assert!(self.steps < 10_000, "program does not terminate");
                    let i = prog[pc];
                    let dst = (i.regs & 0x0f) as usize;
                    let src = (i.regs >> 4) as usize;
                    let class = i.code & 0x07;
                    pc += 1;
                    match class {
                        0x00 => {
                            // ld_map_fd, two slots.
                            assert_eq!(i.code, 0x18);
                            self.regs[dst] = MAP + i.imm as u64;
                            pc += 1;
                        }
                        0x01 => {
                            let len = width(i.code);
                            let addr = self.regs[src].wrapping_add(i.off as i64 as u64);
                            self.regs[dst] = self.load(addr, len);
                        }
                        0x02 | 0x03 => {
                            let len = width(i.code);
                            let addr = self.regs[dst].wrapping_add(i.off as i64 as u64);
                            let v = if class == 0x02 {
                                i.imm as u64
                            } else {
                                self.regs[src]
                            };
                            self.store(addr, len, v);
                        }
                        0x07 => {
                            let operand = if i.code & 0x08 != 0 {
                                self.regs[src]
                            } else {
                                i.imm as i64 as u64
                            };
                            match i.code & 0xf0 {
                                0xb0 => self.regs[dst] = operand,
                                0x00 => self.regs[dst] = self.regs[dst].wrapping_add(operand),
                                0x50 => self.regs[dst] &= operand,
                                0x60 => self.regs[dst] <<= operand,
                                op => panic!("unsupported alu op {op:#x}"),
                            }
                        }
                        0x05 => {
                            let op = i.code & 0xf0;
                            if op == 0x80 {
                                self.call(i.imm);
                                continue;
                            }
                            if op == 0x90 {
                                return self.regs[0] as u32;
                            }
                            let a = self.regs[dst];
                            let b = if i.code & 0x08 != 0 {
                                self.regs[src]
                            } else {
                                i.imm as i64 as u64
                            };
                            let taken = match op {
                                0x00 => true,
                                0x10 => a == b,
                                0x20 => a > b,
                                0x30 => a >= b,
                                0x40 => a & b != 0,
                                0x50 => a != b,
                                0xa0 => a < b,
                                op => panic!("unsupported jump op {op:#x}"),
                            };
                            if taken {
                                pc = (pc as isize + i.off as isize) as usize;
                            }
                        }
                        c => panic!("unsupported class {c:#x}"),
                    }
                }
            }
        }

        fn width(code: u8) -> usize {
            match Size(code & 0x18) {
                Size::B => 1,
                Size::H => 2,
                Size::W => 4,
                _ => 8,
            }
        }
    }

    use vm::{Trie, Vm};

    /// A trie populated from `(prefix, rules)` pairs exactly the way `Capture`
    /// would populate the kernel's.
    fn tries(cfg: &CaptureConfig, set: &[(IpPrefix, &[Rule])]) -> (Trie, Trie) {
        let mut v4 = Trie {
            addr_len: 4,
            entries: Vec::new(),
        };
        let mut v6 = Trie {
            addr_len: 16,
            entries: Vec::new(),
        };
        for (prefix, rules) in set {
            let key = lpm_key(*prefix);
            let entry = (
                u32::from(prefix.bits()),
                key.as_bytes()[4..].to_vec(),
                encode_rules(rules, cfg.max_rules_per_prefix),
            );
            if prefix.is_v4() {
                v4.entries.push(entry);
            } else {
                v6.entries.push(entry);
            }
        }
        (v4, v6)
    }

    fn verdict(cfg: &CaptureConfig, set: &[(IpPrefix, &[Rule])], pkt: &[u8]) -> u32 {
        let prog = build_program_with_fds(cfg, vm::XSK_FD, vm::V4_FD, vm::V6_FD).unwrap();
        let (v4, v6) = tries(cfg, set);
        Vm::new(pkt, v4, v6).run(&prog)
    }

    /// Instructions executed for `pkt`, the measure of what a packet costs
    /// before the JIT: helper calls count as one.
    fn steps(cfg: &CaptureConfig, set: &[(IpPrefix, &[Rule])], pkt: &[u8]) -> usize {
        let prog = build_program_with_fds(cfg, vm::XSK_FD, vm::V4_FD, vm::V6_FD).unwrap();
        let (v4, v6) = tries(cfg, set);
        let mut vm = Vm::new(pkt, v4, v6);
        vm.run(&prog);
        vm.steps
    }

    const REDIRECT: u32 = Action::REDIRECT.0;
    const PASS: u32 = Action::PASS.0;

    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// An IPv4 header with `ihl` words (options zero-filled) and the given
    /// flags/fragment-offset word, followed by `l4`.
    fn ipv4_with(
        proto: Protocol,
        src: [u8; 4],
        dst: [u8; 4],
        ihl: u8,
        frag: u16,
        l4: &[u8],
    ) -> Vec<u8> {
        let mut h = vec![0u8; usize::from(ihl) * 4];
        h[0] = 0x40 | ihl;
        let total = (h.len() + l4.len()) as u16;
        h[2..4].copy_from_slice(&total.to_be_bytes());
        h[6..8].copy_from_slice(&frag.to_be_bytes());
        h[8] = 64;
        h[9] = proto.as_u8();
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        h.extend_from_slice(l4);
        eth(EtherType::IPV4.0, &h)
    }

    fn ipv4(proto: Protocol, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        ipv4_with(proto, src, dst, 5, 0, l4)
    }

    fn ipv6(next: Protocol, src: &str, dst: &str, l4: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[0] = 0x60;
        h[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        h[6] = next.as_u8();
        h[7] = 64;
        h[8..24].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        h[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        h.extend_from_slice(l4);
        eth(EtherType::IPV6.0, &h)
    }

    /// The first four bytes of a TCP or UDP header, plus a little payload.
    fn ports(sport: u16, dport: u16) -> Vec<u8> {
        let mut l4 = Vec::new();
        l4.extend_from_slice(&sport.to_be_bytes());
        l4.extend_from_slice(&dport.to_be_bytes());
        l4.extend_from_slice(&[0u8; 16]);
        l4
    }

    fn arp(spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut a = vec![0u8; 28];
        a[..2].copy_from_slice(&1u16.to_be_bytes());
        a[2..4].copy_from_slice(&EtherType::IPV4.0.to_be_bytes());
        a[4] = 6;
        a[5] = 4;
        a[6..8].copy_from_slice(&1u16.to_be_bytes());
        a[14..18].copy_from_slice(&spa);
        a[24..28].copy_from_slice(&tpa);
        eth(EtherType::ARP.0, &a)
    }

    const HOST: [u8; 4] = [10, 0, 0, 7];
    const PEER: [u8; 4] = [10, 0, 0, 9];

    #[test]
    fn any_rule_takes_every_protocol_on_the_address() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Any])];
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(1, 2))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(1, 2))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(Protocol::ICMP, PEER, HOST, &[8, 0, 0, 0])),
            REDIRECT
        );
        // Another address on the same wire is left alone.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, HOST, PEER, &ports(1, 2))),
            PASS
        );
    }

    #[test]
    fn proto_rule_takes_one_protocol_only() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Proto(UDP)])];
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(1000, 53))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(1000, 53))),
            PASS
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(Protocol::ICMP, PEER, HOST, &[8, 0, 0, 0])),
            PASS
        );
    }

    #[test]
    fn port_rule_takes_one_port_of_one_protocol() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Port(UDP, 51820)])];
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(4000, 51820))),
            REDIRECT
        );
        // Right port, wrong protocol.
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(4000, 51820))),
            PASS
        );
        // Right protocol, wrong port.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(4000, 53))),
            PASS
        );
        // The rule is about the captured endpoint's port, not the peer's.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(51820, 4000))),
            PASS
        );
    }

    #[test]
    fn port_is_found_behind_ipv4_options() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Port(TCP, 443)])];
        for ihl in [5u8, 6, 8, 15] {
            let f = ipv4_with(TCP, PEER, HOST, ihl, 0, &ports(4000, 443));
            assert_eq!(verdict(&cfg, set, &f), REDIRECT, "ihl={ihl}");
            let f = ipv4_with(TCP, PEER, HOST, ihl, 0, &ports(4000, 80));
            assert_eq!(verdict(&cfg, set, &f), PASS, "ihl={ihl}");
        }
    }

    #[test]
    fn a_bogus_ihl_cannot_match_a_port() {
        // ihl < 5 would put the "transport header" inside the IP header.
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Port(TCP, 0x0a00)])];
        // With ihl=4 the bytes at 14+16 would be the destination address —
        // 10.0.0.7 — whose first two bytes spell port 0x0a00.
        let mut f = ipv4_with(TCP, PEER, HOST, 5, 0, &ports(1, 2));
        f[14] = 0x44;
        assert_eq!(verdict(&cfg, set, &f), PASS);
    }

    #[test]
    fn only_the_first_fragment_carries_a_port() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Port(UDP, 53)])];
        // First fragment: MF set, offset 0. Ports are there.
        let f = ipv4_with(UDP, PEER, HOST, 5, 0x2000, &ports(4000, 53));
        assert_eq!(verdict(&cfg, set, &f), REDIRECT);
        // Later fragments: whatever the bytes at the transport offset are,
        // they are payload, not a port.
        let f = ipv4_with(UDP, PEER, HOST, 5, 0x2000 | 185, &ports(4000, 53));
        assert_eq!(verdict(&cfg, set, &f), PASS);
        let f = ipv4_with(UDP, PEER, HOST, 5, 185, &ports(4000, 53));
        assert_eq!(verdict(&cfg, set, &f), PASS);
        // A protocol rule on the same address still takes them.
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Proto(UDP)])];
        assert_eq!(verdict(&cfg, set, &f), REDIRECT);
    }

    #[test]
    fn a_truncated_transport_header_cannot_match_a_port() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] =
            &[(v4(HOST, 32), &[Rule::Port(UDP, 53), Rule::Proto(TCP)])];
        // IP header complete, transport header missing entirely.
        assert_eq!(verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &[])), PASS);
        // Or short by a byte.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &[0x00, 0x35, 0x00])),
            PASS
        );
        // The protocol rule does not need the transport header.
        assert_eq!(verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &[])), REDIRECT);
    }

    #[test]
    fn the_rule_list_is_walked_in_full() {
        let cfg = CaptureConfig::default();
        let rules: &[Rule] = &[
            Rule::Proto(Protocol::ICMP),
            Rule::Port(TCP, 443),
            Rule::Port(UDP, 53),
            Rule::Port(TCP, 22),
        ];
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), rules)];
        assert_eq!(
            verdict(&cfg, set, &ipv4(Protocol::ICMP, PEER, HOST, &[8, 0, 0, 0])),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(1, 443))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(1, 53))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(1, 22))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(1, 80))),
            PASS
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(1, 443))),
            PASS
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(Protocol::GRE, PEER, HOST, &[0; 4])),
            PASS
        );
    }

    #[test]
    fn a_full_rule_list_has_no_terminator_and_still_stops() {
        let cfg = CaptureConfig {
            max_rules_per_prefix: 2,
            ..Default::default()
        };
        let rules: &[Rule] = &[Rule::Port(TCP, 1), Rule::Port(TCP, 2)];
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), rules)];
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(9, 2))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(9, 3))),
            PASS
        );
    }

    #[test]
    fn any_anywhere_in_the_list_wins() {
        let cfg = CaptureConfig::default();
        let rules: &[Rule] = &[Rule::Port(TCP, 1), Rule::Any];
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), rules)];
        assert_eq!(
            verdict(&cfg, set, &ipv4(Protocol::GRE, PEER, HOST, &[0; 4])),
            REDIRECT
        );
    }

    #[test]
    fn any_is_honoured_wherever_it_sits_in_the_value() {
        // `encode_rules` puts Any first, but the maps are public: a value
        // written by someone else must still mean what it says.
        let cfg = CaptureConfig::default();
        let mut value = encode_rules(&[Rule::Port(TCP, 1)], cfg.max_rules_per_prefix);
        value[RULE_SIZE..2 * RULE_SIZE].copy_from_slice(&Rule::Any.encode());
        let (mut v4t, v6t) = tries(&cfg, &[]);
        v4t.entries.push((32, HOST.to_vec(), value));
        let prog = build_program_with_fds(&cfg, vm::XSK_FD, vm::V4_FD, vm::V6_FD).unwrap();
        let f = ipv4(Protocol::GRE, PEER, HOST, &[0; 4]);
        assert_eq!(Vm::new(&f, v4t, v6t).run(&prog), REDIRECT);
    }

    #[test]
    fn a_miss_is_the_cheapest_path_through_the_program() {
        let cfg = CaptureConfig::default();
        let any: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Any])];
        let port: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Port(UDP, 53)])];
        let hit = ipv4(UDP, PEER, HOST, &ports(1, 53));
        let miss = ipv4(UDP, HOST, PEER, &ports(1, 53));

        // Host traffic that is none of our business: bounds checks, one key,
        // one lookup, the default verdict. The exact count is pinned so that
        // anything added to this path has to be added on purpose.
        assert_eq!(steps(&cfg, port, &miss), 23);
        assert_eq!(steps(&cfg, any, &miss), steps(&cfg, port, &miss));
        // A whole-address capture is decided without a transport parse...
        assert!(steps(&cfg, any, &hit) < steps(&cfg, port, &hit));
        // ...and only a narrow rule pays for one.
        assert!(steps(&cfg, port, &hit) > steps(&cfg, port, &miss));
    }

    #[test]
    fn src_match_judges_the_source_port() {
        let cfg = CaptureConfig {
            match_field: MatchField::Src,
            ..Default::default()
        };
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Port(UDP, 51820)])];
        // Replies from the captured service.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, HOST, PEER, &ports(51820, 4000))),
            REDIRECT
        );
        // The captured host talking *to* someone's 51820 is not its service.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, HOST, PEER, &ports(4000, 51820))),
            PASS
        );
        // And traffic addressed to it is not matched at all under Src.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(4000, 51820))),
            PASS
        );
    }

    #[test]
    fn either_falls_through_to_the_source_lookup_after_a_port_mismatch() {
        let cfg = CaptureConfig {
            match_field: MatchField::Either,
            ..Default::default()
        };
        let set: &[(IpPrefix, &[Rule])] = &[
            (v4(HOST, 32), &[Rule::Port(UDP, 51820)]),
            (v4(PEER, 32), &[Rule::Port(UDP, 4000)]),
        ];
        // dst=HOST hits but port 53 != 51820; src=PEER:4000 then matches.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(4000, 53))),
            REDIRECT
        );
        // Neither endpoint's port is its captured one.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(5000, 53))),
            PASS
        );
        // Both directions of the captured flow.
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, PEER, HOST, &ports(9, 51820))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(UDP, HOST, PEER, &ports(51820, 9))),
            REDIRECT
        );
    }

    #[test]
    fn a_subnet_rule_applies_to_every_address_in_it() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v4([10, 0, 0, 0], 24), &[Rule::Port(TCP, 80)])];
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, [10, 0, 0, 200], &ports(1, 80))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, [10, 0, 1, 200], &ports(1, 80))),
            PASS
        );
        // A longer prefix inside carries its own rules, not the subnet's.
        let set: &[(IpPrefix, &[Rule])] = &[
            (v4([10, 0, 0, 0], 24), &[Rule::Port(TCP, 80)]),
            (v4(HOST, 32), &[Rule::Port(TCP, 22)]),
        ];
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(1, 22))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv4(TCP, PEER, HOST, &ports(1, 80))),
            PASS
        );
    }

    #[test]
    fn arp_is_captured_only_under_any() {
        let cfg = CaptureConfig::default();
        let who_has = arp(PEER, HOST);
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Any])];
        assert_eq!(verdict(&cfg, set, &who_has), REDIRECT);
        // A shared address: the host stack keeps answering ARP for it.
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Port(UDP, 51820)])];
        assert_eq!(verdict(&cfg, set, &who_has), PASS);
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Proto(UDP)])];
        assert_eq!(verdict(&cfg, set, &who_has), PASS);
        // Any later in the list still counts.
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Proto(UDP), Rule::Any])];
        assert_eq!(verdict(&cfg, set, &who_has), REDIRECT);
        // ARP for someone else is never ours.
        assert_eq!(verdict(&cfg, set, &arp(HOST, PEER)), PASS);
    }

    #[test]
    fn arp_follows_the_sender_under_src() {
        let cfg = CaptureConfig {
            match_field: MatchField::Src,
            ..Default::default()
        };
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Any])];
        assert_eq!(verdict(&cfg, set, &arp(HOST, PEER)), REDIRECT);
        assert_eq!(verdict(&cfg, set, &arp(PEER, HOST)), PASS);
    }

    #[test]
    fn arp_is_off_when_disabled() {
        let cfg = CaptureConfig {
            arp: false,
            ..Default::default()
        };
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Any])];
        assert_eq!(verdict(&cfg, set, &arp(PEER, HOST)), PASS);
    }

    const HOST6: &str = "2001:db8::7";
    const PEER6: &str = "2001:db8::9";

    fn v6(addr: &str, bits: u8) -> IpPrefix {
        IpPrefix::new(addr.parse::<Ipv6Addr>().unwrap().into(), bits)
    }

    #[test]
    fn ipv6_rules_behave_like_ipv4_ones() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v6(HOST6, 128), &[Rule::Port(UDP, 51820)])];
        assert_eq!(
            verdict(&cfg, set, &ipv6(UDP, PEER6, HOST6, &ports(4000, 51820))),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv6(UDP, PEER6, HOST6, &ports(4000, 53))),
            PASS
        );
        assert_eq!(
            verdict(&cfg, set, &ipv6(TCP, PEER6, HOST6, &ports(4000, 51820))),
            PASS
        );
        assert_eq!(
            verdict(&cfg, set, &ipv6(UDP, HOST6, PEER6, &ports(51820, 4000))),
            PASS
        );

        let set: &[(IpPrefix, &[Rule])] =
            &[(v6("2001:db8::", 64), &[Rule::Proto(Protocol::ICMPV6)])];
        assert_eq!(
            verdict(
                &cfg,
                set,
                &ipv6(Protocol::ICMPV6, PEER6, HOST6, &[128, 0, 0, 0])
            ),
            REDIRECT
        );
        assert_eq!(
            verdict(&cfg, set, &ipv6(UDP, PEER6, HOST6, &ports(1, 2))),
            PASS
        );

        let set: &[(IpPrefix, &[Rule])] = &[(v6(HOST6, 128), &[Rule::Any])];
        assert_eq!(
            verdict(&cfg, set, &ipv6(Protocol::GRE, PEER6, HOST6, &[0; 4])),
            REDIRECT
        );
    }

    #[test]
    fn ipv6_extension_headers_are_not_walked() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] = &[(v6(HOST6, 128), &[Rule::Port(UDP, 53)])];
        // A Fragment header (44) between the fixed header and UDP. Its first
        // bytes are `next=17, reserved`; a naive read would see garbage ports.
        let mut ext = vec![UDP.as_u8(), 0, 0, 53, 0, 0, 0, 1];
        ext.extend_from_slice(&ports(4000, 53));
        assert_eq!(
            verdict(&cfg, set, &ipv6(Protocol(44), PEER6, HOST6, &ext)),
            PASS
        );
        // Even one whose payload happens to spell the port where UDP's would be.
        let mut ext = vec![UDP.as_u8(), 0];
        ext.extend_from_slice(&53u16.to_be_bytes());
        ext.extend_from_slice(&[0; 20]);
        assert_eq!(
            verdict(&cfg, set, &ipv6(Protocol(44), PEER6, HOST6, &ext)),
            PASS
        );
        // A protocol rule for the extension header itself does match, since
        // that is what the Next Header field says.
        let set: &[(IpPrefix, &[Rule])] = &[(v6(HOST6, 128), &[Rule::Proto(Protocol(44))])];
        assert_eq!(
            verdict(&cfg, set, &ipv6(Protocol(44), PEER6, HOST6, &ext)),
            REDIRECT
        );
    }

    #[test]
    fn frames_too_short_for_their_header_take_the_default() {
        let cfg = CaptureConfig::default();
        let set: &[(IpPrefix, &[Rule])] =
            &[(v4(HOST, 32), &[Rule::Any]), (v6(HOST6, 128), &[Rule::Any])];
        let f = ipv4(UDP, PEER, HOST, &ports(1, 2));
        assert_eq!(verdict(&cfg, set, &f[..30]), PASS);
        let f = ipv6(UDP, PEER6, HOST6, &ports(1, 2));
        assert_eq!(verdict(&cfg, set, &f[..50]), PASS);
        assert_eq!(verdict(&cfg, set, &f[..10]), PASS);
        let f = arp(PEER, HOST);
        assert_eq!(verdict(&cfg, set, &f[..40]), PASS);
        // Exactly the fixed headers is enough for an address match.
        let f = ipv4(UDP, PEER, HOST, &[]);
        assert_eq!(verdict(&cfg, set, &f), REDIRECT);
        let f = ipv6(UDP, PEER6, HOST6, &[]);
        assert_eq!(verdict(&cfg, set, &f), REDIRECT);
    }

    #[test]
    fn unmatched_traffic_takes_the_configured_default() {
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Any])];
        let f = ipv4(UDP, HOST, PEER, &ports(1, 2));
        let drop = CaptureConfig {
            default_action: Action::DROP,
            ..Default::default()
        };
        assert_eq!(verdict(&drop, set, &f), Action::DROP.0);
        assert_eq!(
            verdict(&drop, set, &ipv4(UDP, PEER, HOST, &ports(1, 2))),
            REDIRECT
        );
        assert_eq!(verdict(&CaptureConfig::default(), set, &f), PASS);
        // Something that is neither IP nor ARP.
        assert_eq!(verdict(&drop, set, &eth(0x88cc, &[0; 40])), Action::DROP.0);
    }

    #[test]
    fn a_queue_with_no_socket_passes_to_the_host() {
        let cfg = CaptureConfig::default();
        let prog = build_program_with_fds(&cfg, vm::XSK_FD, vm::V4_FD, vm::V6_FD).unwrap();
        let set: &[(IpPrefix, &[Rule])] = &[(v4(HOST, 32), &[Rule::Any])];
        let (v4t, v6t) = tries(&cfg, set);
        let f = ipv4(UDP, PEER, HOST, &ports(1, 2));
        let mut vm = Vm::new(&f, v4t, v6t);
        vm.xsk_queues = vec![0, 1];
        vm.rx_queue = 3;
        assert_eq!(vm.run(&prog), PASS);
        vm.rx_queue = 1;
        assert_eq!(vm.run(&prog), REDIRECT);
    }
}

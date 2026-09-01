//! eBPF instruction encoding and a tiny label-patching assembler.
//!
//! Programs here are written by hand — a few dozen instructions — so there is
//! no ELF loader and no libbpf dependency. What this module provides is the
//! 8-byte instruction encoding from `<linux/bpf.h>` plus [`Asm`], which
//! resolves forward jumps to labels so the branch-heavy capture program in
//! [`capture`](super::capture) stays readable.

use std::io;

use crate::Result;

// --- instruction classes ---------------------------------------------------

pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_ALU64: u8 = 0x07;

// --- operand sizes ---------------------------------------------------------

/// Width of a memory access, encoded in bits 3-4 of `code`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size(pub u8);

impl Size {
    pub const W: Size = Size(0x00); // 32-bit
    pub const H: Size = Size(0x08); // 16-bit
    pub const B: Size = Size(0x10); // 8-bit
    pub const DW: Size = Size(0x18); // 64-bit
}

// --- modes / operand sources ----------------------------------------------

pub const BPF_IMM: u8 = 0x00;
pub const BPF_MEM: u8 = 0x60;

pub const BPF_K: u8 = 0x00; // immediate operand
pub const BPF_X: u8 = 0x08; // register operand

// --- ALU / jump operations -------------------------------------------------

pub const BPF_ADD: u8 = 0x00;
pub const BPF_MOV: u8 = 0xb0;

/// Jump condition, encoded in the high nibble of `code`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jmp(pub u8);

impl Jmp {
    pub const JA: Jmp = Jmp(0x00);
    pub const JEQ: Jmp = Jmp(0x10);
    pub const JGT: Jmp = Jmp(0x20);
    pub const JGE: Jmp = Jmp(0x30);
    pub const JNE: Jmp = Jmp(0x50);
}

pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;

// --- registers -------------------------------------------------------------

pub const R0: u8 = 0;
pub const R1: u8 = 1;
pub const R2: u8 = 2;
pub const R3: u8 = 3;
pub const R4: u8 = 4;
pub const R5: u8 = 5;
pub const R6: u8 = 6;
pub const R7: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;
/// Frame pointer. Read-only; stack slots are addressed as `R10 + negative`.
pub const R10: u8 = 10;

/// `src_reg` marker on an `LD_IMM64` whose immediate is a map file descriptor.
const BPF_PSEUDO_MAP_FD: u8 = 1;

// --- helper function IDs ---------------------------------------------------

pub const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_FUNC_REDIRECT_MAP: i32 = 51;

/// One eBPF instruction (8 bytes on the wire).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    /// `dst_reg` in the low nibble, `src_reg` in the high nibble.
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

#[inline]
fn reg(dst: u8, src: u8) -> u8 {
    (src << 4) | (dst & 0x0f)
}

impl Insn {
    /// `dst = src`
    pub fn mov64_reg(dst: u8, src: u8) -> Insn {
        Insn {
            code: BPF_ALU64 | BPF_X | BPF_MOV,
            regs: reg(dst, src),
            off: 0,
            imm: 0,
        }
    }

    /// `dst = imm`
    pub fn mov64_imm(dst: u8, imm: i32) -> Insn {
        Insn {
            code: BPF_ALU64 | BPF_K | BPF_MOV,
            regs: reg(dst, 0),
            off: 0,
            imm,
        }
    }

    /// `dst += imm`
    pub fn add64_imm(dst: u8, imm: i32) -> Insn {
        Insn {
            code: BPF_ALU64 | BPF_K | BPF_ADD,
            regs: reg(dst, 0),
            off: 0,
            imm,
        }
    }

    /// `dst = *(size *)(src + off)`
    pub fn ldx(size: Size, dst: u8, src: u8, off: i16) -> Insn {
        Insn {
            code: BPF_LDX | size.0 | BPF_MEM,
            regs: reg(dst, src),
            off,
            imm: 0,
        }
    }

    /// `*(size *)(dst + off) = src`
    pub fn stx(size: Size, dst: u8, off: i16, src: u8) -> Insn {
        Insn {
            code: BPF_STX | size.0 | BPF_MEM,
            regs: reg(dst, src),
            off,
            imm: 0,
        }
    }

    /// `*(size *)(dst + off) = imm`
    pub fn st_imm(size: Size, dst: u8, off: i16, imm: i32) -> Insn {
        Insn {
            code: BPF_ST | size.0 | BPF_MEM,
            regs: reg(dst, 0),
            off,
            imm,
        }
    }

    /// `if dst <op> imm goto off`
    pub fn jmp_imm(op: Jmp, dst: u8, imm: i32, off: i16) -> Insn {
        Insn {
            code: BPF_JMP | BPF_K | op.0,
            regs: reg(dst, 0),
            off,
            imm,
        }
    }

    /// `if dst <op> src goto off`
    pub fn jmp_reg(op: Jmp, dst: u8, src: u8, off: i16) -> Insn {
        Insn {
            code: BPF_JMP | BPF_X | op.0,
            regs: reg(dst, src),
            off,
            imm: 0,
        }
    }

    /// `goto off`
    pub fn ja(off: i16) -> Insn {
        Insn {
            code: BPF_JMP | Jmp::JA.0,
            regs: 0,
            off,
            imm: 0,
        }
    }

    pub fn call(func: i32) -> Insn {
        Insn {
            code: BPF_JMP | BPF_K | BPF_CALL,
            regs: 0,
            off: 0,
            imm: func,
        }
    }

    pub fn exit() -> Insn {
        Insn {
            code: BPF_JMP | BPF_EXIT,
            regs: 0,
            off: 0,
            imm: 0,
        }
    }

    /// Serialize to the 8 wire bytes. eBPF is little-endian on every arch the
    /// kernel supports for this ABI.
    pub fn to_bytes(self) -> [u8; 8] {
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
/// slot carries the upper 32 bits of the 64-bit immediate, which is zero here;
/// the verifier rewrites the pair into the map's kernel address at load time.
pub fn ld_map_fd(dst: u8, fd: i32) -> [Insn; 2] {
    [
        Insn {
            code: BPF_LD | Size::DW.0 | BPF_IMM,
            regs: reg(dst, BPF_PSEUDO_MAP_FD),
            off: 0,
            imm: fd,
        },
        Insn::default(),
    ]
}

/// Flatten instructions to the contiguous byte buffer `bpf(2)` expects.
pub fn encode(insns: &[Insn]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(insns.len() * 8);
    for insn in insns {
        buf.extend_from_slice(&insn.to_bytes());
    }
    buf
}

/// Read a 16-bit wire constant the way a `BPF_LDX | BPF_H` from packet memory
/// will see it.
///
/// Register loads use host byte order, so a big-endian field like an EtherType
/// arrives byte-swapped on a little-endian host. Comparing against this keeps
/// the swap in the (host-side) code generator instead of costing a `bswap` in
/// the datapath.
#[inline]
pub fn host_be16(v: u16) -> i32 {
    u16::from_ne_bytes(v.to_be_bytes()) as i32
}

/// A jump destination, resolved by [`Asm::build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label(usize);

/// Instruction buffer with forward-jump patching.
///
/// Jumps are emitted with a placeholder offset and fixed up once every label
/// has been placed, so a program can branch to a block it has not emitted yet.
#[derive(Debug, Default)]
pub struct Asm {
    insns: Vec<Insn>,
    /// `(instruction index, label)` for every jump awaiting patching.
    fixups: Vec<(usize, Label)>,
    /// Instruction index each label resolves to; `None` until placed.
    marks: Vec<Option<usize>>,
}

impl Asm {
    pub fn new() -> Asm {
        Asm::default()
    }

    /// Reserve a label. It must be placed with [`Asm::place`] before
    /// [`Asm::build`].
    pub fn label(&mut self) -> Label {
        self.marks.push(None);
        Label(self.marks.len() - 1)
    }

    /// Bind `l` to the next instruction emitted.
    pub fn place(&mut self, l: Label) {
        self.marks[l.0] = Some(self.insns.len());
    }

    pub fn emit(&mut self, i: Insn) {
        self.insns.push(i);
    }

    pub fn emit_all(&mut self, insns: &[Insn]) {
        self.insns.extend_from_slice(insns);
    }

    /// Emit a jump whose `off` is filled in once `l` is placed.
    pub fn jump(&mut self, mut i: Insn, l: Label) {
        i.off = 0;
        self.fixups.push((self.insns.len(), l));
        self.insns.push(i);
    }

    /// Resolve every fixup and return the finished program.
    pub fn build(mut self) -> Result<Vec<Insn>> {
        for (at, label) in &self.fixups {
            let target = self.marks[label.0].ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("xdp: label {} referenced but never placed", label.0),
                )
            })?;
            // A jump offset is relative to the instruction *after* the jump.
            let delta = target as isize - (*at as isize + 1);
            let off = i16::try_from(delta).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("xdp: jump offset {delta} out of range"),
                )
            })?;
            self.insns[*at].off = off;
        }
        Ok(self.insns)
    }

    /// Number of instructions emitted so far.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insn_wire_encoding() {
        // r2 = *(u32 *)(r1 + 16)
        let i = Insn::ldx(Size::W, R2, R1, 16);
        assert_eq!(i.to_bytes(), [0x61, 0x12, 0x10, 0x00, 0, 0, 0, 0]);

        // exit
        assert_eq!(Insn::exit().to_bytes(), [0x95, 0, 0, 0, 0, 0, 0, 0]);

        // r0 = 2
        assert_eq!(
            Insn::mov64_imm(R0, 2).to_bytes(),
            [0xb7, 0x00, 0, 0, 2, 0, 0, 0]
        );
    }

    #[test]
    fn stx_puts_src_in_high_nibble() {
        // *(u32 *)(r10 - 4) = r1
        let i = Insn::stx(Size::W, R10, -4, R1);
        assert_eq!(i.code, 0x63);
        assert_eq!(i.regs, 0x1a); // src=1, dst=10
        assert_eq!(i.off, -4);
    }

    #[test]
    fn ld_map_fd_is_two_slots() {
        let pair = ld_map_fd(R1, 7);
        assert_eq!(pair[0].code, 0x18);
        assert_eq!(pair[0].regs, 0x11); // src=BPF_PSEUDO_MAP_FD, dst=r1
        assert_eq!(pair[0].imm, 7);
        assert_eq!(pair[1], Insn::default());
    }

    #[test]
    fn host_be16_matches_a_packet_load() {
        // Whatever the host endianness, comparing a register loaded from these
        // two wire bytes against host_be16 must succeed.
        let wire = 0x86DDu16.to_be_bytes();
        let as_loaded = u16::from_ne_bytes(wire) as i32;
        assert_eq!(host_be16(0x86DD), as_loaded);
    }

    #[test]
    fn asm_patches_forward_jumps() {
        let mut a = Asm::new();
        let end = a.label();
        a.jump(Insn::jmp_imm(Jmp::JEQ, R1, 0, 0), end); // 0
        a.emit(Insn::mov64_imm(R0, 1)); // 1
        a.place(end);
        a.emit(Insn::exit()); // 2

        let p = a.build().unwrap();
        // From index 0, skipping one instruction lands on index 2.
        assert_eq!(p[0].off, 1);
    }

    #[test]
    fn asm_patches_backward_jumps() {
        let mut a = Asm::new();
        let top = a.label();
        a.place(top);
        a.emit(Insn::mov64_imm(R0, 0)); // 0
        a.jump(Insn::ja(0), top); // 1
        let p = a.build().unwrap();
        assert_eq!(p[1].off, -2);
    }

    #[test]
    fn asm_rejects_unplaced_label() {
        let mut a = Asm::new();
        let l = a.label();
        a.jump(Insn::ja(0), l);
        assert!(a.build().is_err());
    }
}

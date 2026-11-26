// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RV64 gate templates: emission for the rewriter and decoding for
//! [`recovery`](super::recovery). See the [module docs](super) for the forms.

use super::GateTls;
use crate::{Error, Result};
use alloc::{format, vec::Vec};
use core::mem::offset_of;

/// Register number of `gp` (x3).
pub const GP: u32 = 3;
const T0: u32 = 5;
/// Bit position of an instruction's `rd` field.
pub const RD: u32 = 7;
/// Bit position of an instruction's `rs1` field.
pub const RS1: u32 = 15;
/// Bit position of an instruction's `rs2` field.
pub const RS2: u32 = 20;
/// Registers a gate may borrow, in order of preference: t0, t1, t2 and t3.
const SCRATCH: [u32; 4] = [5, 6, 7, 28];

/// The longest gate: an `auipc gp` gate, or a gp read-modify-write.
pub const MAX_GATE_WORDS: usize = 6;

const fn tls_offset(offset: usize) -> u32 {
    assert!(offset < 2048);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "checked signed 12-bit offset"
    )]
    {
        offset as u32
    }
}
const GUEST_GP: u32 = tls_offset(offset_of!(GateTls, guest_gp));
const SPILL: u32 = tls_offset(offset_of!(GateTls, spill));
const ENTRY: u32 = tls_offset(offset_of!(GateTls, syscall_entry));

/// Returns the 5-bit register field of `insn` at bit `shift`.
pub const fn reg(insn: u32, shift: u32) -> u32 {
    (insn >> shift) & 31
}

const fn ld(rd: u32, offset: u32) -> u32 {
    offset << 20 | GP << RS1 | 3 << 12 | rd << RD | 0x03
}

const fn sd(rs: u32, offset: u32) -> u32 {
    (offset >> 5) << 25 | rs << RS2 | GP << RS1 | 3 << 12 | (offset & 31) << RD | 0x23
}

/// `jalr t0, 0(t0)`: t0 links to the reload, preserving guest ra.
const JALR_T0: u32 = T0 << RS1 | T0 << RD | 0x67;

/// Whether `word` is a load or store addressed off physical gp, i.e. one of a
/// gate's own [`GateTls`] accesses. Relocated guest instructions never are.
pub(super) const fn accesses_gate_tls(word: u32) -> bool {
    matches!(word & 0x7f, 0x03 | 0x23) && reg(word, RS1) == GP
}

/// Whether `word` is a gate's first instruction, `sd r, SPILL(gp)`.
pub(super) const fn is_spill(word: u32) -> bool {
    word == sd(reg(word, RS2), SPILL)
}

fn unsupported(pc: u64, reason: &str) -> Error {
    Error::UnsupportedExecutable(format!("RV64 at {pc:#x}: {reason}"))
}

fn checked_add(base: u64, addend: u64, context: &str) -> Result<u64> {
    base.checked_add(addend)
        .ok_or_else(|| Error::AddressOverflow(format!("{context} address overflow")))
}

/// Signed even byte displacement for a JAL or C.J.
fn displacement(pc: u64, target: u64, bits: u32) -> Result<u32> {
    let delta = i128::from(target) - i128::from(pc);
    let limit = 1 << (bits - 1);
    if delta & 1 != 0 || !(-limit..limit).contains(&delta) {
        return Err(unsupported(pc, "trampoline branch out of range"));
    }
    Ok(i32::try_from(delta).unwrap().cast_unsigned())
}

fn jal(pc: u64, target: u64) -> Result<u32> {
    let d = displacement(pc, target, 21)?;
    Ok(((d >> 20) & 1) << 31 | (d & 0x7fe) << 20 | (d & 0x800) << 9 | d & 0xff000 | 0x6f)
}

fn compressed_jump(pc: u64, target: u64) -> Result<u16> {
    let d = displacement(pc, target, 12)?;
    let bits = ((d >> 11) & 1) << 12
        | ((d >> 4) & 1) << 11
        | ((d >> 8) & 3) << 9
        | ((d >> 10) & 1) << 8
        | ((d >> 6) & 1) << 7
        | ((d >> 7) & 1) << 6
        | ((d >> 1) & 7) << 3
        | ((d >> 5) & 1) << 2;
    Ok(0xa001 | u16::try_from(bits).unwrap())
}

/// Sign-extends the low `bits` bits of `value`.
const fn sign_extend(value: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (value << shift).cast_signed() >> shift
}

/// The displacement of a `jal x0`, or `None` for any other instruction.
pub(super) const fn jal_x0_offset(word: u32) -> Option<i32> {
    if word & 0xfff != 0x6f {
        return None;
    }
    let imm = ((word >> 31) & 1) << 20
        | ((word >> 21) & 0x3ff) << 1
        | ((word >> 20) & 1) << 11
        | word & 0xff000;
    Some(sign_extend(imm, 21))
}

/// The displacement of a `c.j`, or `None` for any other instruction.
pub(super) const fn compressed_jump_offset(half: u16) -> Option<i32> {
    let h = half as u32;
    if h & 0xe003 != 0xa001 {
        return None;
    }
    let imm = ((h >> 12) & 1) << 11
        | ((h >> 11) & 1) << 4
        | ((h >> 9) & 3) << 8
        | ((h >> 8) & 1) << 10
        | ((h >> 7) & 1) << 6
        | ((h >> 6) & 1) << 7
        | ((h >> 3) & 7) << 1
        | ((h >> 2) & 1) << 5;
    Some(sign_extend(imm, 12))
}

/// What a rewritten site does, and so which gate [`emit`] appends.
#[derive(Clone, Copy, Debug)]
pub enum GateKind {
    /// `ecall`: enter the runtime through [`GateTls::syscall_entry`].
    Ecall,
    /// `auipc gp, upper`, with `upper` the instruction's `imm << 12` bits.
    AuipcGp(u32),
    /// Execute `word` after substituting a scratch register for its integer
    /// gp operands. `fields` lists the bit positions ([`RD`], [`RS1`],
    /// [`RS2`]) of all of `word`'s integer register operands; at least one
    /// must be gp.
    ///
    /// `word` must fall through to the next instruction. When `word` writes
    /// gp, [recovery](super::recovery) may restart the original instruction
    /// after the relocated `word` has run but before the gate stores its
    /// result, so writing the scratch register must then be its only effect,
    /// as for a load or an integer computation. Any other `word` is followed
    /// directly by the reload, which completes the gate. The rewriter
    /// relocates only loads, stores, integer computations and `lui`, and
    /// rejects control transfers through gp.
    Gp { word: u32, fields: &'static [u32] },
}

/// Appends the gate for the instruction `site` at `pc` to `gates`, which will
/// be loaded at `base`, and overwrites `site` (two or four bytes) with a jump
/// to it.
///
/// # Errors
/// Fails if the gate would not be 4-byte aligned, or a [`GateKind::Ecall`]
/// site is not four bytes, both of which recovery requires, the site's jump
/// to the gate or the gate's return jump is out of range, a relocated `auipc`
/// is out of range, or an address overflows. The first two fail before
/// appending anything.
///
/// # Panics
/// Panics if `site` is not two or four bytes long or, for [`GateKind::Gp`], if
/// `fields` names more than three registers.
pub fn emit(
    site: &mut [u8],
    pc: u64,
    kind: GateKind,
    base: u64,
    gates: &mut Vec<u8>,
) -> Result<()> {
    assert!(matches!(site.len(), 2 | 4));
    let start = checked_add(base, gates.len() as u64, "RV64 gate")?;
    if !start.is_multiple_of(4) {
        return Err(Error::TrampolinePatchFailure(format!(
            "RV64 gate at {start:#x} is not 4-byte aligned"
        )));
    }
    if matches!(kind, GateKind::Ecall) && site.len() != 4 {
        return Err(Error::TrampolinePatchFailure(format!(
            "RV64 ecall site at {pc:#x} is not 4 bytes long"
        )));
    }
    let mut emit = |word: u32| gates.extend_from_slice(&word.to_le_bytes());
    match kind {
        GateKind::Ecall => {
            emit(sd(T0, SPILL));
            emit(ld(T0, ENTRY));
            emit(JALR_T0);
            emit(ld(T0, SPILL));
        }
        GateKind::AuipcGp(upper) => {
            emit(sd(T0, SPILL));
            let delta = i128::from(pc) + i128::from(upper.cast_signed()) - (i128::from(start) + 4);
            let hi = i32::try_from((delta + 0x800) >> 12)
                .ok()
                .filter(|n| (-0x80000..0x80000).contains(n))
                .ok_or_else(|| unsupported(pc, "relocated auipc out of range"))?;
            let lo = u32::try_from(delta & 0xfff).unwrap();
            emit(hi.cast_unsigned() << 12 | T0 << RD | 0x17);
            emit(lo << 20 | T0 << RS1 | T0 << RD | 0x13);
            emit(sd(T0, GUEST_GP));
            emit(ld(T0, SPILL));
        }
        GateKind::Gp { mut word, fields } => {
            // Never borrow a real source or destination; e.g., sd t0,8(gp)
            // must still store the guest t0. At most three registers are used.
            let tmp = SCRATCH
                .into_iter()
                .find(|&r| fields.iter().all(|&f| reg(word, f) != r))
                .unwrap();
            emit(sd(tmp, SPILL));
            let mut writes_gp = false;
            if fields.iter().any(|&f| f != RD && reg(word, f) == GP) {
                emit(ld(tmp, GUEST_GP));
            }
            for &f in fields {
                if reg(word, f) == GP {
                    writes_gp |= f == RD;
                    word = (word & !(31 << f)) | tmp << f;
                }
            }
            emit(word);
            if writes_gp {
                emit(sd(tmp, GUEST_GP));
            }
            emit(ld(tmp, SPILL));
        }
    }
    let next = checked_add(pc, site.len() as u64, "RV64 resume PC")?;
    let at = checked_add(base, gates.len() as u64, "RV64 return jump")?;
    gates.extend_from_slice(&jal(at, next)?.to_le_bytes());
    if site.len() == 2 {
        site.copy_from_slice(&compressed_jump(pc, start)?.to_le_bytes());
    } else {
        site.copy_from_slice(&jal(pc, start)?.to_le_bytes());
    }
    Ok(())
}

/// The gate forms of the [module docs](super).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Form {
    Ecall,
    AuipcGp,
    Gp,
}

/// A gate recognized by [`decode`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Template {
    pub(super) form: Form,
    /// The borrowed register.
    pub(super) scratch: u32,
    /// Word index of the reload `ld scratch, SPILL(gp)`. The return `jal`
    /// follows it and ends the gate.
    pub(super) reload: usize,
}

/// Recognizes the gate that `words` starts with, if `words` holds all of it.
/// Accepts everything [`emit`] produces. It checks only the gate's structure,
/// not that a relocated instruction is one the rewriter admits or that the
/// gate's `GUEST_GP` load and store match that instruction's operands.
pub(super) fn decode(words: &[u32]) -> Option<Template> {
    let &first = words.first()?;
    let scratch = reg(first, RS2);
    if !is_spill(first) || !SCRATCH.contains(&scratch) {
        return None;
    }
    let is_t0 = scratch == T0;
    let form = match words.get(1..)? {
        [w, JALR_T0, ..] if is_t0 && *w == ld(T0, ENTRY) => (Form::Ecall, 3),
        [auipc, addi, store, ..]
            if is_t0
                && auipc & 0xfff == T0 << RD | 0x17
                && addi & 0xf_ffff == T0 << RS1 | T0 << RD | 0x13
                && *store == sd(T0, GUEST_GP) =>
        {
            (Form::AuipcGp, 4)
        }
        body => {
            let loads = body.first() == Some(&ld(scratch, GUEST_GP));
            let relocated = *body.get(usize::from(loads))?;
            if accesses_gate_tls(relocated) {
                return None;
            }
            let stores = body.get(usize::from(loads) + 1) == Some(&sd(scratch, GUEST_GP));
            if !loads && !stores {
                return None;
            }
            (Form::Gp, 2 + usize::from(loads) + usize::from(stores))
        }
    };
    let (form, reload) = form;
    if *words.get(reload)? != ld(scratch, SPILL) || jal_x0_offset(*words.get(reload + 1)?).is_none()
    {
        return None;
    }
    Some(Template {
        form,
        scratch,
        reload,
    })
}

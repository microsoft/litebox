// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded structural recognition, not instruction admission. Publication must
//! first use the offline decoder. Like direct-gate recovery, this recognizes
//! transport bytes, not the authenticity of guest-controlled executable memory.
//! No decoder, allocator, registry, or lock is reachable from these functions.

use super::super::{X18BranchKind, X18IndirectBranchKind};
use super::{
    AUX_MARKER, GATE_ALIGNMENT, GateMetadata, Host, ISLAND_HEADER_BYTES, ISLAND_SLOT_BYTES,
    ISLAND_SLOTS, Insn, IslandSlot, IslandStage, Item, LDST_UIMM12_IMM_MASK, LDST_UIMM12_IMM_SHIFT,
    MAX_ISLAND_GATE_BYTES, NOP, X16, X30, b_target, brk, decode_island_metadata, get,
    island_slot_words, program, x18,
};

/// A stack-backed, structurally checked gate. Callers must also close the loop
/// through the island, table, original site and (if present) auxiliary exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IslandSignalGate {
    pub metadata: GateMetadata,
    pub size: usize,
    pub stage: IslandStage,
    pub scratches: Option<(u8, u8)>,
    pub entry_depth: u16,
    pub exit_depth: u16,
    pub k: Option<u64>,
    pub callback_literal: Option<u64>,
    /// Embedded original, used only by the narrow target checks below.
    pub original: Option<u32>,
    /// The transformed guest instruction, as opposed to transport scaffolding.
    pub guest_instruction: bool,
    /// A guest-stack store (SP-relative), whose still-live inputs survive a
    /// partial store fault. Recovery must not read the destination of this store.
    pub stack_store: bool,
    /// At this boundary live x30 names the auxiliary rather than primary exit.
    pub live_auxiliary: bool,
}

impl IslandSignalGate {
    /// Resolve only the fixed ADR/ADRP/conditional immediate encodings. This is
    /// deliberately not a general instruction decoder.
    pub fn target(self, site: u64) -> Option<u64> {
        let raw = self.original?;
        match self.metadata {
            GateMetadata::X18Adr { .. } => {
                let imm = (((raw >> 5) & 0x7ffff) << 2) | ((raw >> 29) & 3);
                let delta = i64::from((imm << 11).cast_signed() >> 11);
                if raw >> 31 != 0 {
                    (site & !4095).checked_add_signed(delta * 4096)
                } else {
                    site.checked_add_signed(delta)
                }
            }
            GateMetadata::X18CompareBranch { .. } => {
                let delta = if raw & 0x7e00_0000 == 0x3400_0000 {
                    (((raw >> 5) & 0x7ffff) << 13).cast_signed() >> 11
                } else {
                    (((raw >> 5) & 0x3fff) << 18).cast_signed() >> 16
                };
                site.checked_add_signed(i64::from(delta))
            }
            _ => None,
        }
    }
}

fn scratch_valid(r: u8) -> bool {
    (7..=17).contains(&r) && r != X16
}

fn structural_spec(slot: &[u8], metadata: GateMetadata, host: Host) -> Option<x18::Spec> {
    let original = get(slot, slot.len().checked_sub(8)?)?;
    let mut spec = x18::Spec {
        original,
        metadata,
        value: 17,
        anchor: 15,
        transformed: 0,
        entry: 16,
        exit: 16,
        target: None,
        branch: None,
    };
    match metadata {
        GateMetadata::X18Branch { kind } => {
            let expected = match kind {
                X18IndirectBranchKind::Br => 0xd61f_0240,
                X18IndirectBranchKind::Blr => 0xd63f_0240,
                X18IndirectBranchKind::Ret => 0xd65f_0240,
            };
            if original != expected {
                return None;
            }
        }
        GateMetadata::X18Adr { scratch: X30 } => {
            if original & 0x1f00_001f != 0x1000_0012 {
                return None;
            }
        }
        GateMetadata::X18 { scratch }
        | GateMetadata::X18StackWriteback { scratch }
        | GateMetadata::X18CompareBranch { scratch } => {
            spec.value = scratch;
            spec.anchor = ((get(slot, 4)? >> 10) & 31) as u8;
            if !scratch_valid(scratch) || !scratch_valid(spec.anchor) || scratch == spec.anchor {
                return None;
            }
            if matches!(metadata, GateMetadata::X18CompareBranch { .. }) {
                if original & 31 != 18 {
                    return None;
                }
                spec.branch = Some(match original & 0x7f00_0000 {
                    0x3400_0000 if original >> 31 == 0 => X18BranchKind::CbzW,
                    0x3400_0000 => X18BranchKind::CbzX,
                    0x3500_0000 if original >> 31 == 0 => X18BranchKind::CbnzW,
                    0x3500_0000 => X18BranchKind::CbnzX,
                    0x3600_0000 => X18BranchKind::Tbz(
                        ((original >> 19) & 31) as u8 | ((original >> 26) & 32) as u8,
                    ),
                    0x3700_0000 => X18BranchKind::Tbnz(
                        ((original >> 19) & 31) as u8 | ((original >> 26) & 32) as u8,
                    ),
                    _ => return None,
                });
            } else {
                let pair = super::super::decode_x18_stack_writeback(original);
                if pair.is_some() != matches!(metadata, GateMetadata::X18StackWriteback { .. }) {
                    return None;
                }
                if let Some(pair) = pair {
                    if pair.rt != 18 && pair.rt2 != 18 {
                        return None;
                    }
                    spec.entry = (16
                        + if pair.delta < 0 {
                            pair.delta.unsigned_abs()
                        } else {
                            0
                        })
                    .next_multiple_of(16);
                    spec.exit =
                        u16::try_from(i32::from(spec.entry) + i32::from(pair.delta)).ok()?;
                }
                // Locate the transformed word through the shared template,
                // rather than duplicating Linux/macOS instruction offsets.
                let scaffold = program(metadata, host, Some(spec))?;
                let execute = scaffold
                    .items
                    .iter()
                    .position(|(item, _)| matches!(item, Item::Raw(_)))?;
                spec.transformed = get(slot, execute * 4)?;
                if let Some(pair) = pair {
                    if [pair.rt, pair.rt2].contains(&scratch)
                        || [pair.rt, pair.rt2].contains(&spec.anchor)
                    {
                        return None;
                    }
                    let mut expected = original;
                    for shift in [0, 10] {
                        if (original >> shift) & 31 == 18 {
                            expected = (expected & !(31 << shift)) | (u32::from(scratch) << shift);
                        }
                    }
                    if spec.transformed != expected {
                        return None;
                    }
                }
                // The offline decoder admits the operation and chooses unused
                // scratches. On signal-side only register-field substitution
                // may differ; neither opcode nor immediate bits may change.
                let mut changed = 0;
                for shift in [0, 5, 10, 16] {
                    let mask = 31 << shift;
                    if (original ^ spec.transformed) & mask != 0 {
                        if (original >> shift) & 31 != 18
                            || (spec.transformed >> shift) & 31 != u32::from(scratch)
                        {
                            return None;
                        }
                        changed |= mask;
                    }
                }
                if changed == 0 || (original ^ spec.transformed) & !changed != 0 {
                    return None;
                }
                // Within the branch/system class, offline admission supports
                // SYS and MRS (except TPIDR_EL0) with x18 as Rt. Only Rt may
                // change: the other apparent register fields are system bits.
                // This recognizes admitted code, not EL0 access permission.
                if original & 0x1c00_0000 == 0x1400_0000 {
                    let ordinary_system = original & 0xfff8_001f == 0xd508_0012
                        || original & 0xfff0_001f == 0xd530_0012;
                    if !ordinary_system
                        || original == 0xd53b_d052 // MRS x18, TPIDR_EL0 is unsupported.
                        || spec.transformed != ((original & !31) | u32::from(scratch))
                    {
                        return None;
                    }
                }
                // PC-relative operations use distinct templates.
                if original & 0x1f00_0000 == 0x1000_0000 {
                    return None;
                }
            }
        }
        _ => return None,
    }
    Some(spec)
}

/// Recognize exactly one copied slot using the emitter's fixed-size template.
/// `gate` is the slot address. `offset` must name an
/// executable boundary, never a literal, padding word, or footer.
pub fn classify_island_signal_gate(
    slot: &[u8],
    gate: u64,
    offset: usize,
    host: crate::TargetHost,
) -> Option<IslandSignalGate> {
    if slot.len() > MAX_ISLAND_GATE_BYTES
        || !slot.len().is_multiple_of(GATE_ALIGNMENT)
        || !gate.is_multiple_of(GATE_ALIGNMENT as u64)
        || !offset.is_multiple_of(4)
    {
        return None;
    }
    let metadata = decode_island_metadata(get(slot, slot.len().checked_sub(4)?)?)?;
    let host = Host::from(host);
    let is_x18 = !matches!(
        metadata,
        GateMetadata::Svc | GateMetadata::MrsTpidr { .. } | GateMetadata::MsrTpidr { .. }
    );
    let spec = if is_x18 {
        Some(structural_spec(slot, metadata, host)?)
    } else {
        None
    };
    let program = program(metadata, host, spec)?;
    if program.slot_size != slot.len() {
        return None;
    }
    let (current, stage) = *program.items.get(offset / 4)?;
    let mut tls_offset = None;
    let mut callback_literal = None;
    for (i, (item, _)) in program.items.iter().enumerate() {
        let at = i * 4;
        let actual = get(slot, at)?;
        let expected = match *item {
            Item::Fixed(insn) => insn.encode()?,
            Item::Raw(raw) => raw,
            Item::Tls(insn) | Item::X18Tls(insn) => {
                let field = ((actual & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT) * 8;
                let x18 = matches!(item, Item::X18Tls(_));
                if !(if x18 {
                    super::super::valid_emitted_x18_offset(field)
                } else {
                    super::super::valid_emitted_tpidr_offset(field)
                }) {
                    return None;
                }
                let base = field.checked_sub(if x18 { 8 } else { 0 })?;
                if tls_offset.is_some_and(|old| old != base) {
                    return None;
                }
                tls_offset = Some(base);
                (insn.encode()? & !LDST_UIMM12_IMM_MASK) | (actual & LDST_UIMM12_IMM_MASK)
            }
            Item::LoadCallback => {
                callback_literal = Some(super::super::decode_ldr_literal_target(
                    actual,
                    gate.checked_add(at as u64)?,
                )?);
                actual
            }
            Item::LoadK => Insn::LdrLiteral {
                rt: X16,
                off: i64::try_from(program.k_literal?.checked_sub(at)?).ok()?,
            }
            .encode()?,
        };
        if actual != expected {
            return None;
        }
    }
    let code_end = program.items.len() * 4;
    let footer = slot.len().checked_sub(if spec.is_some() { 8 } else { 4 })?;
    let mut k = None;
    for at in (code_end..footer).step_by(4) {
        if let Some(literal) = program.k_literal {
            if at == literal {
                k = Some(u64::from_le_bytes(slot.get(at..at + 8)?.try_into().ok()?));
            }
            if (literal..literal + 8).contains(&at) {
                continue;
            }
            if at < literal {
                if get(slot, at)? != brk() {
                    return None;
                }
                continue;
            }
        }
        if get(slot, at)? != NOP {
            return None;
        }
    }
    Some(IslandSignalGate {
        metadata,
        size: slot.len(),
        stage,
        scratches: spec
            .filter(|_| {
                matches!(
                    metadata,
                    GateMetadata::X18 { .. }
                        | GateMetadata::X18StackWriteback { .. }
                        | GateMetadata::X18CompareBranch { .. }
                )
            })
            .map(|s| (s.value, s.anchor)),
        entry_depth: spec.map_or(16, |s| s.entry),
        exit_depth: spec.map_or(16, |s| s.exit),
        k,
        callback_literal,
        original: spec.map(|s| s.original),
        guest_instruction: matches!(current, Item::Raw(_)),
        stack_store: matches!(
            current,
            Item::Fixed(
                Insn::StrUimm { rn: 31, .. }
                    | Insn::Stp { rn: 31, .. }
                    | Insn::StpPre { rn: 31, .. }
            )
        ),
        live_auxiliary: stage.taken
            && !matches!(
                current,
                Item::Fixed(Insn::AddImm {
                    rd: X30,
                    rn: X30,
                    imm12: 24
                })
            ),
    })
}

/// Recognize a copied 24-byte slot, without recursive auxiliary traversal.
/// An auxiliary must be accompanied by its already checked immediate primary.
pub fn classify_island_signal_slot(
    bytes: &[u8],
    island: u64,
    index: usize,
    primary: Option<IslandSlot>,
) -> Option<IslandSlot> {
    if index >= ISLAND_SLOTS || bytes.len() != ISLAND_SLOT_BYTES {
        return None;
    }
    let pc = island.checked_add((ISLAND_HEADER_BYTES + index * ISLAND_SLOT_BYTES) as u64)?;
    let resume = b_target(get(bytes, 20)?, pc.checked_add(20)?)?;
    let auxiliary = get(bytes, 0)? == AUX_MARKER;
    let exit_depth = ((get(bytes, 16)? >> 10) & 4095) as u16;
    let (site, entry_depth) = if auxiliary {
        let p = primary?;
        if p.auxiliary || p.index.checked_add(1)? != index {
            return None;
        }
        (p.site, p.entry_depth)
    } else {
        (
            resume.checked_sub(4)?,
            ((get(bytes, 0)? >> 10) & 4095) as u16,
        )
    };
    if entry_depth < 16 || !entry_depth.is_multiple_of(16) {
        return None;
    }
    let expected = island_slot_words(island, index, resume, entry_depth, exit_depth, auxiliary)?;
    for (i, word) in expected.into_iter().enumerate() {
        if get(bytes, i * 4)? != word {
            return None;
        }
    }
    Some(IslandSlot {
        index,
        site,
        resume,
        auxiliary,
        entry_depth,
        exit_depth,
    })
}

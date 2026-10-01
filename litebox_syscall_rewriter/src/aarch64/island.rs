// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 trampoline islands: a one-page, per-site *island* near the code
//! plus a position-independent *gate chunk* that may be mapped anywhere.
//!
//! ```text
//! site_k:  B in_k
//! island:  +0   LDR x16, delta ; ADD x16, x16, x30 ; BR x16 ; BRK
//!          +16  delta = chunk_table - out_0
//!          +32  slot k (24 B): SUB SP,SP,#entry_depth ; STP x16,x30,[SP] ; BL dispatch
//!                      out_k: LDP x16,x30,[SP] ; ADD SP,SP,#exit_depth ; B resume
//! chunk:   +0   callback literal, NOP, NOP
//!          +16  table[k] (24 B): B gate_k, five inert padding words
//!          +CHUNK_GATES_OFFSET gates, each ending in a version-2 metadata word
//! ```
//!
//! Gate contract: on entry `[SP] = {guest x16, guest x30}` (the *island
//! frame*), `x30 = out_k`, `x16` is scratch. On exit every other register holds
//! its final value, the island frame holds final x16/x30, and the gate executes
//! `RET` with `x30 = out_k`. No gate instruction encodes the chunk's distance to
//! the island or the guest, so a chunk is copied verbatim to any address; only
//! the island's `delta` literal and the chunk's callback literal are written
//! after placement, plus the usual TLS-offset finalization.
//!
//! All guests are Linux guests. Ordinary gates need writable stack below SP;
//! SP-writeback pair gates place the island frame below the lowest operand,
//! up to 528 bytes below original SP, plus 32 bytes of gate scratch frame.
//! Entry depth and exit depth differ by the guest SP writeback displacement.
//! Mach-O guests and direct APIs are unchanged; ELF AOT uses these same images.
//! Linux-guest signal
//! recovery recognizes this contract without retaining a mapping registry.
//!
//! Islands pair 1:1 with chunks, which keeps one `delta` per island valid for
//! the island's whole lifetime.

use alloc::format;
use alloc::vec::Vec;

use super::{
    Asm, EncodedGateMetadata, GATE_ALIGNMENT, GATE_METADATA_BYTES, GATE_METADATA_VERSION_MASK,
    GATE_METADATA_VERSION_SHIFT, GUEST_TPIDR_OFFSET_ALIGN, GUEST_TPIDR_OFFSET_PLACEHOLDER,
    GateMetadata, Host, INSN_BYTES, INSN_BYTES_U64, Insn, LDST_UIMM12_IMM_MASK,
    LDST_UIMM12_IMM_SHIFT, NOP, PatchKind, PatchSite, RewriteConfig, SP, X16, XZR,
    find_patch_sites_with_code_ranges, trap_site, validate_guest_offset,
};
use crate::{Error, Result, TextSectionInfo, checked_add_u64};

/// Populated bytes of one island. Islands are mapped as one host page; only the
/// first `ISLAND_BYTES` are used so capacity does not depend on the host.
pub const ISLAND_BYTES: usize = 4096;
/// Island header: shared dispatcher and the `delta` literal.
pub const ISLAND_HEADER_BYTES: usize = 32;
/// Byte offset of the `delta` literal within the island.
pub const ISLAND_DELTA_OFFSET: usize = 16;
/// Bytes per island slot.
pub const ISLAND_SLOT_BYTES: usize = 24;
/// Slots per island.
pub const ISLAND_SLOTS: usize = (ISLAND_BYTES - ISLAND_HEADER_BYTES) / ISLAND_SLOT_BYTES;
/// Offset of `out_k` within a slot.
pub const ISLAND_OUT_OFFSET: usize = 12;

/// Offset of the callback literal in a chunk.
pub const CHUNK_CALLBACK_OFFSET: usize = 0;
/// Offset of the jump table in a chunk.
pub const CHUNK_TABLE_OFFSET: usize = 16;
/// Offset of the first gate in a chunk.
pub const CHUNK_GATES_OFFSET: usize =
    (CHUNK_TABLE_OFFSET + ISLAND_SLOTS * ISLAND_SLOT_BYTES).next_multiple_of(GATE_ALIGNMENT);
const _: () = assert!(CHUNK_GATES_OFFSET.is_multiple_of(GATE_ALIGNMENT));
const _: () = assert!(CHUNK_GATES_OFFSET >= CHUNK_TABLE_OFFSET + ISLAND_SLOTS * ISLAND_SLOT_BYTES);

/// Largest island gate slot.
pub const MAX_ISLAND_GATE_BYTES: usize = 96;
/// Upper bound on a chunk's populated size.
pub const CHUNK_CAPACITY_BYTES: usize = CHUNK_GATES_OFFSET + ISLAND_SLOTS * MAX_ISLAND_GATE_BYTES;

/// Island frame payload size (entry depth may be greater).
pub const ISLAND_FRAME_BYTES: u16 = 16;
/// SVC callback frame below the island frame: `{retaddr, stub}`.
pub const ISLAND_SVC_FRAME_BYTES: u16 = 16;
/// Offset of the return address in the SVC callback frame.
pub const ISLAND_SVC_FRAME_OFF_RETADDR: u16 = 0;
/// Offset of the outbound stub (`out_k`) in the SVC callback frame.
pub const ISLAND_SVC_FRAME_OFF_STUB: u16 = 8;
/// Offset of guest x16 from SP at callback entry.
pub const ISLAND_SVC_FRAME_OFF_X16: u16 = ISLAND_SVC_FRAME_BYTES;
/// Offset of guest x30 from SP at callback entry.
pub const ISLAND_SVC_FRAME_OFF_X30: u16 = ISLAND_SVC_FRAME_BYTES + 8;

/// Metadata version tagging island-contract gates.
const ISLAND_METADATA_VERSION: u32 = 2;
const ISLAND_BRK_IMM: u16 = 0x15A;
const X30: u8 = 30;

// ============================================================
// Raw encodings not covered by `Insn`
// ============================================================

/// `BL <offset>`.
fn bl(offset: i64) -> Option<u32> {
    Insn::B(offset).encode().map(|b| b | 0x8000_0000)
}

/// `ADD x16, x16, x30` (island and table use the same stride).
const DISPATCH_ADD: u32 = 0x8B00_0000 | (30 << 16) | (16 << 5) | 16;

#[cfg(test)]
fn word(insn: Insn) -> u32 {
    insn.encode().expect("statically valid island instruction")
}

const fn brk() -> u32 {
    0xd420_0000 | ((ISLAND_BRK_IMM as u32) << 5)
}

fn put(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + INSN_BYTES].copy_from_slice(&value.to_le_bytes());
}

fn get(buf: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buf.get(offset..offset.checked_add(INSN_BYTES)?)?
            .try_into()
            .ok()?,
    ))
}

fn b_target(insn: u32, pc: u64) -> Option<u64> {
    super::decode_branch_target(insn, pc)
}

// ============================================================
// Island header and slots
// ============================================================

/// The fixed island header words (`delta` excluded).
fn island_header_words() -> [u32; 4] {
    [
        0x5800_0090, // LDR x16, +16
        DISPATCH_ADD,
        0xd61f_0200, // BR x16
        brk(),
    ]
}

/// `delta` for an island at `island_vaddr` whose chunk is at `chunk_vaddr`.
pub fn island_delta(island_vaddr: u64, chunk_vaddr: u64) -> u64 {
    let out0 = island_vaddr.wrapping_add((ISLAND_HEADER_BYTES + ISLAND_OUT_OFFSET) as u64);
    chunk_vaddr
        .wrapping_add(CHUNK_TABLE_OFFSET as u64)
        .wrapping_sub(out0)
}

/// Address of `out_k` for slot `k` of the island at `island_vaddr`.
pub fn island_out(island_vaddr: u64, slot: usize) -> u64 {
    island_vaddr + (ISLAND_HEADER_BYTES + slot * ISLAND_SLOT_BYTES + ISLAND_OUT_OFFSET) as u64
}

const AUX_MARKER: u32 = 0xd420_2b60; // BRK #0x15b, never an inbound entry.

fn island_slot_words(
    island_vaddr: u64,
    slot: usize,
    resume: u64,
    entry: u16,
    exit: u16,
    auxiliary: bool,
) -> Option<[u32; 6]> {
    let slot_vaddr =
        island_vaddr.checked_add((ISLAND_HEADER_BYTES + slot * ISLAND_SLOT_BYTES) as u64)?;
    let dispatch_call = slot_vaddr.checked_add(8)?;
    let resume_branch = slot_vaddr.checked_add(20)?;
    Some([
        if auxiliary {
            AUX_MARKER
        } else {
            Insn::SubSp(entry).encode()?
        },
        if auxiliary {
            brk()
        } else {
            Insn::Stp {
                rt: X16,
                rt2: X30,
                rn: SP,
                imm_bytes: 0,
            }
            .encode()?
        },
        if auxiliary {
            brk()
        } else {
            bl(branch_distance(island_vaddr, dispatch_call)?)?
        },
        Insn::Ldp {
            rt: X16,
            rt2: X30,
            rn: SP,
            imm_bytes: 0,
        }
        .encode()?,
        Insn::AddSp(exit).encode()?,
        Insn::B(branch_distance(resume, resume_branch)?).encode()?,
    ])
}

fn branch_distance(target: u64, pc: u64) -> Option<i64> {
    i64::try_from(i128::from(target) - i128::from(pc)).ok()
}

/// A validated island slot: its original site and index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IslandSlot {
    /// Slot index within the island.
    pub index: usize,
    /// Address of the rewritten guest instruction.
    pub site: u64,
    /// Actual continuation (not necessarily `site + 4` for auxiliary exits).
    pub resume: u64,
    /// Auxiliary taken exit belonging to the preceding primary slot.
    pub auxiliary: bool,
    /// Distance from original guest SP to the island frame.
    pub entry_depth: u16,
    /// Distance from the island frame to final guest SP.
    pub exit_depth: u16,
}

/// Validate slot `index` of an island image placed at `island_vaddr` and return
/// the site it serves. Checks the slot template only; callers that need the
/// closed loop must also check that the site branches to `in_k`.
pub fn decode_island_slot(island: &[u8], island_vaddr: u64, index: usize) -> Option<IslandSlot> {
    if index >= ISLAND_SLOTS {
        return None;
    }
    let offset = ISLAND_HEADER_BYTES + index * ISLAND_SLOT_BYTES;
    let b_pc = island_vaddr.checked_add((offset + 20) as u64)?;
    let resume = b_target(get(island, offset + 20)?, b_pc)?;
    let auxiliary = get(island, offset)? == AUX_MARKER;
    let exit_depth = ((get(island, offset + 16)? >> 10) & 4095) as u16;
    let (site, entry_depth) = if auxiliary {
        let primary = decode_island_slot(island, island_vaddr, index.checked_sub(1)?)?;
        if primary.auxiliary {
            return None;
        }
        (primary.site, primary.entry_depth)
    } else {
        (
            resume.checked_sub(4)?,
            ((get(island, offset)? >> 10) & 4095) as u16,
        )
    };
    if entry_depth < 16 || !entry_depth.is_multiple_of(16) {
        return None;
    }
    let expected = island_slot_words(
        island_vaddr,
        index,
        resume,
        entry_depth,
        exit_depth,
        auxiliary,
    )?;
    (0..6)
        .all(|i| get(island, offset + i * INSN_BYTES) == Some(expected[i]))
        .then_some(IslandSlot {
            index,
            site,
            resume,
            auxiliary,
            entry_depth,
            exit_depth,
        })
}

/// Validate an island header, returning its `delta`.
pub fn decode_island_header(island: &[u8]) -> Option<u64> {
    let words = island_header_words();
    if !(0..4).all(|i| get(island, i * INSN_BYTES) == Some(words[i])) {
        return None;
    }
    let delta = u64::from_le_bytes(
        island
            .get(ISLAND_DELTA_OFFSET..ISLAND_DELTA_OFFSET + 8)?
            .try_into()
            .ok()?,
    );
    (get(island, 24) == Some(brk()) && get(island, 28) == Some(brk())).then_some(delta)
}

// ============================================================
// Gate programs
// ============================================================

/// Whether an interrupted gate is logically before or after the guest
/// instruction it replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IslandPhase {
    /// The guest instruction has not taken effect; resume at the site.
    Before,
    /// The guest instruction has taken effect; resume at its continuation.
    After,
}

/// Recovery information for one executable gate instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IslandStage {
    /// Logical position relative to the guest instruction. After means memory
    /// side effects must never be replayed, even when the TLS commit is pending.
    pub phase: IslandPhase,
    /// Bytes between `frame_base` and the island frame.
    pub frame_offset: u16,
    /// Register identifying the frame, or SP. The anchor survives the guest op.
    pub frame_base: u8,
    /// Guest x16/x30 are live rather than in the island frame.
    pub guest_pair_live: bool,
    /// Saved value/anchor registers at island-frame offsets -32/-24.
    pub scratches_saved: bool,
    /// Saved out_k offset relative to the island frame, or None when live in x30.
    pub out_saved: Option<i16>,
    /// Post-instruction logical x18 value still awaiting its TLS commit.
    pub pending_x18: Option<u8>,
    /// This boundary follows the taken conditional exit.
    pub taken: bool,
}

#[derive(Clone, Copy)]
enum Item {
    /// A fixed instruction.
    Fixed(Insn),
    /// A thread-pointer load/store whose unsigned offset is finalized later.
    Tls(Insn),
    /// Linux direct logical-x18 TLS field (TP offset + 8).
    X18Tls(Insn),
    /// Validated substituted guest instruction.
    Raw(u32),
    /// `LDR x16, <callback literal at chunk + 0>`.
    LoadCallback,
    /// `LDR x16, <K literal>`.
    LoadK,
}

// The same bounded template builder serves emission and signal recognition.
// Overflow makes construction fail, never allocating or panicking in a handler.
struct ProgramItems {
    data: [(Item, IslandStage); MAX_ISLAND_GATE_BYTES / INSN_BYTES],
    len: usize,
    overflow: bool,
}

impl ProgramItems {
    fn new() -> Self {
        Self {
            data: [(Item::Fixed(Insn::Ret(X30)), before(0)); MAX_ISLAND_GATE_BYTES / INSN_BYTES],
            len: 0,
            overflow: false,
        }
    }

    fn push(&mut self, item: (Item, IslandStage)) {
        if let Some(at) = self.data.get_mut(self.len) {
            *at = item;
            self.len += 1;
        } else {
            self.overflow = true;
        }
    }
}

impl core::ops::Deref for ProgramItems {
    type Target = [(Item, IslandStage)];
    fn deref(&self) -> &Self::Target {
        self.data.get(..self.len).unwrap_or_default()
    }
}

impl<'a> IntoIterator for &'a ProgramItems {
    type Item = &'a (Item, IslandStage);
    type IntoIter = core::slice::Iter<'a, (Item, IslandStage)>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

struct Program {
    items: ProgramItems,
    /// Slot offset of the per-site `K = site + 4 - out_k` literal, if any.
    k_literal: Option<usize>,
    slot_size: usize,
    original: Option<u32>,
}

const fn before(frame_offset: u16) -> IslandStage {
    IslandStage {
        phase: IslandPhase::Before,
        frame_offset,
        frame_base: SP,
        guest_pair_live: false,
        scratches_saved: false,
        out_saved: None,
        pending_x18: None,
        taken: false,
    }
}

const fn after(frame_offset: u16) -> IslandStage {
    IslandStage {
        phase: IslandPhase::After,
        ..before(frame_offset)
    }
}

/// Emit the host's guest-TLS base computation into x16 (all Before).
fn tls_base(items: &mut ProgramItems, host: Host, stage: IslandStage) {
    items.push((Item::Fixed(host.anchor_read(X16)), stage));
    if host == Host::MacOs {
        items.push((Item::Fixed(super::anchor_mask(X16)), stage));
        items.push((
            Item::Tls(Insn::LdrUimm {
                rt: X16,
                rn: X16,
                imm_bytes: GUEST_TPIDR_OFFSET_PLACEHOLDER,
            }),
            stage,
        ));
    }
}

fn tls_access(insn: Insn, host: Host) -> Item {
    if host == Host::MacOs {
        Item::Fixed(insn)
    } else {
        Item::Tls(insn)
    }
}

fn program(metadata: GateMetadata, host: Host, spec: Option<x18::Spec>) -> Option<Program> {
    if host == Host::Windows {
        return None;
    }
    if let Some(spec) = spec {
        return x18::program(spec, host);
    }
    let access = host.guest_tpidr_access_offset();
    let mut items = ProgramItems::new();
    let mut k_literal = None;
    match metadata {
        GateMetadata::Svc => {
            items.push((Item::Fixed(Insn::SubSp(ISLAND_SVC_FRAME_BYTES)), before(0)));
            let frame = ISLAND_SVC_FRAME_BYTES;
            items.push((
                Item::Fixed(Insn::StrUimm {
                    rt: X30,
                    rn: SP,
                    imm_bytes: ISLAND_SVC_FRAME_OFF_STUB,
                }),
                before(frame),
            ));
            let saved = IslandStage {
                out_saved: Some(-8),
                ..before(frame)
            };
            items.push((Item::LoadK, saved));
            items.push((Item::Fixed(add_reg(X16, X16, X30)), saved));
            items.push((
                Item::Fixed(Insn::StrUimm {
                    rt: X16,
                    rn: SP,
                    imm_bytes: ISLAND_SVC_FRAME_OFF_RETADDR,
                }),
                saved,
            ));
            items.push((Item::LoadCallback, saved));
            items.push((Item::Fixed(Insn::Br(X16)), saved));
            k_literal = Some(8 * INSN_BYTES);
        }
        GateMetadata::MrsTpidr { destination } if destination != XZR => {
            tls_base(&mut items, host, before(0));
            if destination == X16 || destination == X30 {
                items.push((
                    tls_access(
                        Insn::LdrUimm {
                            rt: X16,
                            rn: X16,
                            imm_bytes: access,
                        },
                        host,
                    ),
                    before(0),
                ));
                items.push((
                    Item::Fixed(Insn::StrUimm {
                        rt: X16,
                        rn: SP,
                        imm_bytes: if destination == X16 { 0 } else { 8 },
                    }),
                    before(0),
                ));
            } else {
                items.push((
                    tls_access(
                        Insn::LdrUimm {
                            rt: destination,
                            rn: X16,
                            imm_bytes: access,
                        },
                        host,
                    ),
                    before(0),
                ));
            }
            items.push((Item::Fixed(Insn::Ret(X30)), after(0)));
        }
        GateMetadata::MsrTpidr { source } => {
            if source == X16 || source == X30 {
                let frame = ISLAND_FRAME_BYTES;
                let saved = IslandStage {
                    out_saved: Some(-16),
                    ..before(frame)
                };
                items.push((
                    Item::Fixed(Insn::StpPre {
                        rt: X30,
                        rt2: XZR,
                        rn: SP,
                        imm_bytes: -(frame.cast_signed()),
                    }),
                    before(0),
                ));
                items.push((
                    Item::Fixed(Insn::LdrUimm {
                        rt: X30,
                        rn: SP,
                        imm_bytes: frame + if source == X16 { 0 } else { 8 },
                    }),
                    saved,
                ));
                tls_base(&mut items, host, saved);
                items.push((
                    tls_access(
                        Insn::StrUimm {
                            rt: X30,
                            rn: X16,
                            imm_bytes: access,
                        },
                        host,
                    ),
                    saved,
                ));
                items.push((
                    Item::Fixed(Insn::LdpPost {
                        rt: X30,
                        rt2: XZR,
                        rn: SP,
                        imm_bytes: frame.cast_signed(),
                    }),
                    IslandStage {
                        phase: IslandPhase::After,
                        ..saved
                    },
                ));
            } else {
                tls_base(&mut items, host, before(0));
                items.push((
                    tls_access(
                        Insn::StrUimm {
                            rt: source,
                            rn: X16,
                            imm_bytes: access,
                        },
                        host,
                    ),
                    before(0),
                ));
            }
            items.push((Item::Fixed(Insn::Ret(X30)), after(0)));
        }
        _ => return None,
    }
    let code_bytes = items.len() * INSN_BYTES;
    let literal_end = k_literal.map_or(code_bytes, |offset| offset + 8);
    let slot_size = (literal_end + GATE_METADATA_BYTES).next_multiple_of(GATE_ALIGNMENT);
    if items.overflow || slot_size > MAX_ISLAND_GATE_BYTES {
        return None;
    }
    Some(Program {
        items,
        k_literal,
        slot_size,
        original: None,
    })
}

/// `ADD Xd, Xn, Xm`.
fn add_reg(rd: u8, rn: u8, rm: u8) -> Insn {
    Insn::AddReg { rd, rn, rm }
}

fn encode_metadata(metadata: GateMetadata) -> Option<u32> {
    let v1 = EncodedGateMetadata::encode(metadata)?.0;
    Some(
        (v1 & !GATE_METADATA_VERSION_MASK)
            | (ISLAND_METADATA_VERSION << GATE_METADATA_VERSION_SHIFT),
    )
}

/// Decode an island (version-2) gate metadata word.
pub fn decode_island_metadata(word: u32) -> Option<GateMetadata> {
    if (word & GATE_METADATA_VERSION_MASK) >> GATE_METADATA_VERSION_SHIFT != ISLAND_METADATA_VERSION
    {
        return None;
    }
    let v1 = (word & !GATE_METADATA_VERSION_MASK) | (1 << GATE_METADATA_VERSION_SHIFT);
    let metadata = EncodedGateMetadata(v1).decode()?;
    Some(metadata)
}

/// Recovery stage of the instruction at `offset` within a previously validated
/// gate. This is a bounded slice lookup: no allocation or instruction decoding.
/// Keep the descriptor alive while its executable mapping is live.
pub fn island_gate_stage(gate: &IslandGate, offset: usize) -> Option<IslandStage> {
    if !offset.is_multiple_of(INSN_BYTES) {
        return None;
    }
    gate.stages.get(offset / INSN_BYTES).copied()
}

/// Emit one gate slot at chunk offset `gate_offset`. `k` is the per-site
/// literal (ignored by gates without one); TLS fields hold `tls_offset`.
fn emit_gate(
    metadata: GateMetadata,
    host: Host,
    gate_offset: usize,
    k: u64,
    tls_offset: u16,
    spec: Option<x18::Spec>,
) -> Result<Vec<u8>> {
    let program = program(metadata, host, spec)
        .ok_or_else(|| Error::TrampolinePatchFailure("unsupported island gate kind".into()))?;
    let mut asm = Asm::new(gate_offset as u64);
    for (item, _) in &program.items {
        match *item {
            Item::Fixed(insn) => asm.emit(insn),
            Item::Tls(insn) => asm.emit(with_uimm(insn, tls_offset)),
            Item::X18Tls(insn) => asm.emit(with_uimm(
                insn,
                if tls_offset == GUEST_TPIDR_OFFSET_PLACEHOLDER {
                    super::GUEST_X18_OFFSET_PLACEHOLDER
                } else {
                    tls_offset
                        .checked_add(8)
                        .ok_or_else(|| Error::AddressOverflow("x18 TLS offset".into()))?
                },
            )),
            Item::Raw(raw) => asm.push_word(raw),
            Item::LoadCallback => asm.ldr_literal(X16, CHUNK_CALLBACK_OFFSET as u64)?,
            Item::LoadK => asm.ldr_literal(
                X16,
                (gate_offset + program.k_literal.expect("K-loading gate has a literal")) as u64,
            )?,
        }
    }
    let mut code = asm.finish();
    if let Some(offset) = program.k_literal {
        while code.len() < offset {
            code.extend_from_slice(&brk().to_le_bytes());
        }
        code.extend_from_slice(&k.to_le_bytes());
    }
    let footer = GATE_METADATA_BYTES + if program.original.is_some() { 4 } else { 0 };
    while code.len() + footer < program.slot_size {
        code.extend_from_slice(&NOP.to_le_bytes());
    }
    if let Some(original) = program.original {
        code.extend_from_slice(&original.to_le_bytes());
    }
    let meta = encode_metadata(metadata)
        .ok_or_else(|| Error::TrampolinePatchFailure("invalid island gate metadata".into()))?;
    code.extend_from_slice(&meta.to_le_bytes());
    debug_assert_eq!(code.len(), program.slot_size);
    Ok(code)
}

fn with_uimm(insn: Insn, imm_bytes: u16) -> Insn {
    match insn {
        Insn::LdrUimm { rt, rn, .. } => Insn::LdrUimm { rt, rn, imm_bytes },
        Insn::StrUimm { rt, rn, .. } => Insn::StrUimm { rt, rn, imm_bytes },
        other => other,
    }
}

/// A gate slot validated against its template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IslandGate {
    /// Chunk offset of the slot.
    pub offset: usize,
    /// Slot size.
    pub size: usize,
    /// Decoded semantic metadata.
    pub metadata: GateMetadata,
    /// `K = target - out_k`: SVC continuation or ADR/ADRP target.
    pub k: Option<u64>,
    /// Original guest instruction for x18 gates; validated before publication.
    pub original: Option<u32>,
    /// Saved value/anchor pair for execute and conditional gates. ADR and
    /// indirect-trap gates do not borrow this pair.
    pub scratches: Option<(u8, u8)>,
    /// Original/final guest SP relative to the island frame.
    pub entry_depth: u16,
    /// Final guest SP relative to the island frame.
    pub exit_depth: u16,
    /// Auxiliary taken slot, not a new original site.
    pub auxiliary: bool,
    stages: Vec<IslandStage>,
}

/// Patch locations paired with their addend over the finalized TP/root offset.
type TlsFields = Vec<(usize, u16)>;

/// Validate the gate slot at chunk offset `offset`, trying every slot size.
/// Finalization additionally validates TLS field values transactionally.
fn decode_gate(chunk: &[u8], offset: usize, host: Host) -> Option<(IslandGate, TlsFields)> {
    let mut found = None;
    for size in (GATE_ALIGNMENT..=MAX_ISLAND_GATE_BYTES).step_by(GATE_ALIGNMENT) {
        let Some(slot) = chunk.get(offset..offset.checked_add(size)?) else {
            continue;
        };
        let Some(metadata) = get(slot, size - GATE_METADATA_BYTES).and_then(decode_island_metadata)
        else {
            continue;
        };
        let is_x18 = matches!(
            metadata,
            GateMetadata::X18 { .. }
                | GateMetadata::X18StackWriteback { .. }
                | GateMetadata::X18CompareBranch { .. }
                | GateMetadata::X18Adr { .. }
                | GateMetadata::X18Branch { .. }
        );
        let spec = if is_x18 {
            let Some(spec) =
                get(slot, size - 8).and_then(|raw| x18::Spec::decode(raw, 0x1_0000_0000))
            else {
                continue;
            };
            if spec.metadata != metadata {
                continue;
            }
            Some(spec)
        } else {
            None
        };
        let Some(program) = program(metadata, host, spec) else {
            continue;
        };
        if program.slot_size != size {
            continue;
        }
        let k = program
            .k_literal
            .map(|at| u64::from_le_bytes(slot[at..at + 8].try_into().expect("eight-byte literal")));
        let Ok(expected) = emit_gate(
            metadata,
            host,
            offset,
            k.unwrap_or(0),
            GUEST_TPIDR_OFFSET_PLACEHOLDER,
            spec,
        ) else {
            continue;
        };
        let mut tls = Vec::new();
        let matches = (0..size / INSN_BYTES).all(|i| {
            let at = i * INSN_BYTES;
            let (Some(actual), Some(wanted)) = (get(slot, at), get(&expected, at)) else {
                return false;
            };
            match program.items.get(i) {
                Some((Item::Tls(_), _)) => {
                    tls.push((offset + at, 0));
                    super::valid_emitted_tpidr_offset(
                        ((actual & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT) * 8,
                    ) && actual & !LDST_UIMM12_IMM_MASK == wanted & !LDST_UIMM12_IMM_MASK
                }
                Some((Item::X18Tls(_), _)) => {
                    tls.push((offset + at, 8));
                    super::valid_emitted_x18_offset(
                        ((actual & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT) * 8,
                    ) && actual & !LDST_UIMM12_IMM_MASK == wanted & !LDST_UIMM12_IMM_MASK
                }
                _ => actual == wanted,
            }
        });
        if !matches {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some((
            IslandGate {
                offset,
                size,
                metadata,
                k,
                original: spec.map(|s| s.original),
                scratches: spec
                    .filter(|s| {
                        matches!(
                            s.metadata,
                            GateMetadata::X18 { .. }
                                | GateMetadata::X18StackWriteback { .. }
                                | GateMetadata::X18CompareBranch { .. }
                        )
                    })
                    .map(|s| (s.value, s.anchor)),
                entry_depth: spec.map_or(16, |s| s.entry),
                exit_depth: spec.map_or(16, |s| s.exit),
                auxiliary: false,
                stages: program.items.iter().map(|(_, stage)| *stage).collect(),
            },
            tls,
        ));
    }
    found
}

/// Validate the gate slot starting at chunk offset `offset`.
///
/// This constructs the stage cache, allocates, and decodes the embedded guest
/// instruction. It is not signal-safe. Only [`island_gate_stage`] on an already
/// validated, live descriptor is allocation- and decoder-free.
pub fn decode_island_gate(
    chunk: &[u8],
    offset: usize,
    host: crate::TargetHost,
) -> Option<IslandGate> {
    decode_gate(chunk, offset, host.into()).map(|(gate, _)| gate)
}

// ============================================================
// Island + chunk images
// ============================================================

/// One island and its paired gate chunk, as byte images.
///
/// The island image is address-dependent (its slots branch to guest sites);
/// the chunk image is position independent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IslandPair {
    island_vaddr: u64,
    island: Vec<u8>,
    chunk: Vec<u8>,
    slots_used: usize,
}

impl IslandPair {
    /// An empty island at `island_vaddr` (4 KiB-aligned) and an empty chunk.
    pub fn new(island_vaddr: u64) -> Result<Self> {
        if island_vaddr.checked_add(ISLAND_BYTES as u64).is_none()
            || !island_vaddr.is_multiple_of(ISLAND_BYTES as u64)
        {
            return Err(Error::AddressOverflow(format!(
                "island address {island_vaddr:#x} is not {ISLAND_BYTES}-byte aligned"
            )));
        }
        let mut island = alloc::vec![0; ISLAND_BYTES];
        for offset in (0..ISLAND_BYTES).step_by(INSN_BYTES) {
            put(&mut island, offset, brk());
        }
        for (i, value) in island_header_words().into_iter().enumerate() {
            put(&mut island, i * INSN_BYTES, value);
        }
        island[ISLAND_DELTA_OFFSET..ISLAND_DELTA_OFFSET + 8].fill(0);
        let mut chunk = alloc::vec![0; CHUNK_GATES_OFFSET];
        put(&mut chunk, 8, NOP);
        put(&mut chunk, 12, NOP);
        for offset in (CHUNK_TABLE_OFFSET..CHUNK_GATES_OFFSET).step_by(INSN_BYTES) {
            put(&mut chunk, offset, brk());
        }
        Ok(Self {
            island_vaddr,
            island,
            chunk,
            slots_used: 0,
        })
    }

    /// Reconstruct a pair from existing images (for example, from an AOT
    /// payload), validating every used slot and gate.
    pub fn from_images(
        island_vaddr: u64,
        island: Vec<u8>,
        chunk: Vec<u8>,
        host: crate::TargetHost,
    ) -> Result<Self> {
        let malformed = |what: &str| Error::TrampolinePatchFailure(format!("island: {what}"));
        let mut pair = Self::new(island_vaddr)?;
        if island.len() != ISLAND_BYTES || chunk.len() < CHUNK_GATES_OFFSET {
            return Err(malformed("bad image size"));
        }
        decode_island_header(&island).ok_or_else(|| malformed("bad header"))?;
        let gates = walk_chunk(&chunk, host.into())?;
        let used = gates.len();
        for (index, gate) in gates.iter().enumerate() {
            let slot = decode_island_slot(&island, island_vaddr, index)
                .ok_or_else(|| malformed("bad slot"))?;
            if slot.auxiliary != gate.auxiliary
                || slot.entry_depth != gate.entry_depth
                || slot.exit_depth != gate.exit_depth
            {
                return Err(malformed("slot/gate contract mismatch"));
            }
            let spec = gate
                .original
                .and_then(|raw| x18::Spec::decode(raw, slot.site));
            if gate.original.is_some() && spec.is_none() {
                return Err(malformed("overflowing guest target"));
            }
            let target = spec.and_then(|s| s.target);
            if slot.auxiliary && target != Some(slot.resume) {
                return Err(malformed("bad taken target"));
            }
            if let Some(k) = gate.k {
                let expected = target
                    .unwrap_or(slot.site + 4)
                    .wrapping_sub(island_out(island_vaddr, index));
                if k != expected {
                    return Err(malformed("bad relative literal"));
                }
            }
        }
        for at in (ISLAND_HEADER_BYTES + used * ISLAND_SLOT_BYTES..ISLAND_BYTES).step_by(4) {
            if get(&island, at) != Some(brk()) {
                return Err(malformed("nonempty unused slot"));
            }
        }
        pair.island = island;
        pair.chunk = chunk;
        pair.slots_used = used;
        Ok(pair)
    }

    /// Exact common base-address interval for all inbound and return branches,
    /// including auxiliary taken exits. Alignment is checked at placement time.
    pub fn placement_range(&self) -> Result<core::ops::RangeInclusive<u64>> {
        let reach = 1i128 << 27;
        let mut low = 0;
        let mut high = i128::from(u64::MAX - ISLAND_BYTES as u64);
        for index in 0..self.slots_used {
            let slot = decode_island_slot(&self.island, self.island_vaddr, index)
                .ok_or_else(|| Error::TrampolinePatchFailure("invalid relocation slot".into()))?;
            let offset = (ISLAND_HEADER_BYTES + index * ISLAND_SLOT_BYTES) as i128;
            if !slot.auxiliary {
                low = low.max(i128::from(slot.site) - reach - offset);
                high = high.min(i128::from(slot.site) + reach - 4 - offset);
            }
            low = low.max(i128::from(slot.resume) - reach + 4 - offset - 20);
            high = high.min(i128::from(slot.resume) + reach - offset - 20);
        }
        if low > high {
            return Err(Error::TrampolinePatchFailure(
                "no common island reach".into(),
            ));
        }
        let bound = |value| {
            u64::try_from(value)
                .map_err(|_| Error::AddressOverflow("island placement bound".into()))
        };
        Ok(bound(low)?..=bound(high)?)
    }

    /// Move an unpublished, validated pair without regenerating any operation.
    /// Only slot return branches and existing out-relative K literals change;
    /// delta is reset for the publisher to bind to the independently placed chunk.
    /// Guest site/continuation/ADR targets stay fixed, in either direction.
    pub fn relocated(&self, address: u64, host: crate::TargetHost) -> Result<Self> {
        if !self.placement_range()?.contains(&address) {
            return Err(Error::TrampolinePatchFailure(
                "island relocation out of reach".into(),
            ));
        }
        let mut island = self.island.clone();
        let mut chunk = self.chunk.clone();
        for (index, gate) in walk_chunk(&chunk, host.into())?.iter().enumerate() {
            let slot = decode_island_slot(&self.island, self.island_vaddr, index)
                .ok_or_else(|| Error::TrampolinePatchFailure("invalid relocation slot".into()))?;
            let at = ISLAND_HEADER_BYTES + index * ISLAND_SLOT_BYTES + 20;
            let branch = branch_distance(slot.resume, address + at as u64)
                .and_then(|distance| Insn::B(distance).encode())
                .ok_or_else(|| Error::TrampolinePatchFailure("relocation return".into()))?;
            put(&mut island, at, branch);
            if let Some(k) = gate.k {
                let spec = gate
                    .original
                    .and_then(|raw| x18::Spec::decode(raw, slot.site));
                let at = gate.offset
                    + program(gate.metadata, host.into(), spec)
                        .and_then(|p| p.k_literal)
                        .ok_or_else(|| {
                            Error::TrampolinePatchFailure("relocation literal".into())
                        })?;
                chunk[at..at + 8].copy_from_slice(
                    &k.wrapping_add(self.island_vaddr)
                        .wrapping_sub(address)
                        .to_le_bytes(),
                );
            }
        }
        island[ISLAND_DELTA_OFFSET..ISLAND_DELTA_OFFSET + 8].fill(0);
        Self::from_images(address, island, chunk, host)
    }

    /// Redirect only recognized primary source branches in a staged mapping.
    /// Both the original serialized placement and this pair's placement are
    /// accepted (for replay). Changed instructions are left to the caller's
    /// current-byte scanner, never overwritten using serialized metadata. No
    /// bytes change on error; auxiliary exits never acquire a primary identity.
    pub fn redirect_inbound_branches(
        &self,
        code: &mut [u8],
        address: u64,
        serialized_address: u64,
    ) -> Result<()> {
        let mut patches = Vec::new();
        for index in 0..self.slots_used {
            let slot = decode_island_slot(&self.island, self.island_vaddr, index)
                .ok_or_else(|| Error::TrampolinePatchFailure("invalid redirection slot".into()))?;
            if slot.auxiliary {
                continue;
            }
            let Some(at) = slot
                .site
                .checked_sub(address)
                .and_then(|v| usize::try_from(v).ok())
                .filter(|at| *at < code.len())
            else {
                continue;
            };
            let original = serialized_address
                .checked_add((ISLAND_HEADER_BYTES + index * ISLAND_SLOT_BYTES) as u64)
                .and_then(|target| branch_distance(target, slot.site))
                .and_then(|distance| Insn::B(distance).encode());
            let redirected = self
                .inbound(slot.site, index)
                .ok_or_else(|| Error::TrampolinePatchFailure("relocation entry".into()))?;
            let current = get(code, at);
            if current.is_none() {
                return Err(Error::TrampolinePatchFailure(
                    "truncated serialized source".into(),
                ));
            }
            if current == original || current == Some(redirected) {
                patches.push((at, redirected));
            }
        }
        for (at, branch) in patches {
            put(code, at, branch);
        }
        Ok(())
    }

    /// Island address.
    pub fn island_vaddr(&self) -> u64 {
        self.island_vaddr
    }

    /// Island image (`ISLAND_BYTES`).
    pub fn island(&self) -> &[u8] {
        &self.island
    }

    /// Chunk image (populated bytes).
    pub fn chunk(&self) -> &[u8] {
        &self.chunk
    }

    /// Number of slots in use.
    pub fn slots_used(&self) -> usize {
        self.slots_used
    }

    /// Number of free slots.
    pub fn slots_free(&self) -> usize {
        ISLAND_SLOTS - self.slots_used
    }

    /// Record where the chunk is mapped by writing the island's `delta`.
    pub fn set_chunk_vaddr(&mut self, chunk_vaddr: u64) -> Result<()> {
        if !chunk_vaddr.is_multiple_of(GATE_ALIGNMENT as u64)
            || chunk_vaddr
                .checked_add(CHUNK_CAPACITY_BYTES as u64)
                .is_none()
        {
            return Err(Error::AddressOverflow("island chunk mapping".into()));
        }
        let delta = island_delta(self.island_vaddr, chunk_vaddr);
        self.island[ISLAND_DELTA_OFFSET..ISLAND_DELTA_OFFSET + 8]
            .copy_from_slice(&delta.to_le_bytes());
        Ok(())
    }

    /// Write the chunk's callback literal.
    pub fn set_callback(&mut self, callback: u64) {
        self.chunk[CHUNK_CALLBACK_OFFSET..CHUNK_CALLBACK_OFFSET + 8]
            .copy_from_slice(&callback.to_le_bytes());
    }

    /// Whether a branch at `site` can reach this island's next slot.
    fn reaches(&self, site: u64, spec: Option<x18::Spec>) -> bool {
        let slots = spec.map_or(1, x18::Spec::slots);
        self.slots_free() >= slots
            && self.inbound(site, self.slots_used).is_some()
            && (slots == 1
                || island_slot_words(
                    self.island_vaddr,
                    self.slots_used + 1,
                    spec.and_then(|s| s.target).expect("conditional target"),
                    16,
                    16,
                    true,
                )
                .is_some())
    }

    fn slot_vaddr(&self, slot: usize) -> u64 {
        self.island_vaddr + (ISLAND_HEADER_BYTES + slot * ISLAND_SLOT_BYTES) as u64
    }

    fn inbound(&self, site: u64, slot: usize) -> Option<u32> {
        if slot >= ISLAND_SLOTS {
            return None;
        }
        let inbound = Insn::B(branch_distance(self.slot_vaddr(slot), site)?).encode()?;
        let back = branch_distance(site.checked_add(4)?, self.slot_vaddr(slot) + 20)?;
        Insn::B(back).encode().map(|_| inbound)
    }

    /// Append slot + gate for `site`. Returns the inbound branch word.
    fn push(
        &mut self,
        site: u64,
        metadata: GateMetadata,
        host: Host,
        spec: Option<x18::Spec>,
    ) -> Result<Option<u32>> {
        if !self.reaches(site, spec) {
            return Ok(None);
        }
        let slot = self.slots_used;
        let Some(inbound) = self.inbound(site, slot) else {
            return Ok(None);
        };
        let gate_offset = self.chunk.len();
        let out = island_out(self.island_vaddr, slot);
        let resume = checked_add_u64(site, INSN_BYTES_U64, "island return")?;
        let target = spec
            .filter(|s| s.branch.is_none())
            .and_then(|s| s.target)
            .unwrap_or(resume);
        let k = target.wrapping_sub(out);
        let gate = emit_gate(
            metadata,
            host,
            gate_offset,
            k,
            GUEST_TPIDR_OFFSET_PLACEHOLDER,
            spec,
        )?;
        let entry = spec.map_or(16, |s| s.entry);
        let exit = spec.map_or(16, |s| s.exit);
        let words = island_slot_words(self.island_vaddr, slot, resume, entry, exit, false)
            .ok_or_else(|| Error::AddressOverflow("island slot branch".into()))?;
        for (i, value) in words.into_iter().enumerate() {
            put(
                &mut self.island,
                ISLAND_HEADER_BYTES + slot * ISLAND_SLOT_BYTES + i * INSN_BYTES,
                value,
            );
        }
        let table = CHUNK_TABLE_OFFSET + slot * ISLAND_SLOT_BYTES;
        let entry = Insn::B(i64::try_from(gate_offset - table).expect("chunk-local offset"))
            .encode()
            .expect("chunk-local branch");
        put(&mut self.chunk, table, entry);
        self.chunk.extend_from_slice(&gate);
        self.slots_used += 1;
        if let Some(spec) = spec.filter(|s| s.branch.is_some()) {
            let aux = self.slots_used;
            let words = island_slot_words(
                self.island_vaddr,
                aux,
                spec.target.expect("branch target"),
                spec.entry,
                spec.exit,
                true,
            )
            .expect("reach prevalidated");
            for (i, value) in words.into_iter().enumerate() {
                put(
                    &mut self.island,
                    ISLAND_HEADER_BYTES + aux * ISLAND_SLOT_BYTES + i * 4,
                    value,
                );
            }
            put(
                &mut self.chunk,
                CHUNK_TABLE_OFFSET + aux * ISLAND_SLOT_BYTES,
                AUX_MARKER,
            );
            self.slots_used += 1;
        }
        Ok(Some(inbound))
    }
}

/// Validate a chunk image, returning its gates in slot order and the offsets
/// of their TLS fields.
fn walk_chunk_with_tls(chunk: &[u8], host: Host) -> Result<(Vec<IslandGate>, TlsFields)> {
    let malformed = |what: &str| Error::TrampolinePatchFailure(format!("island chunk: {what}"));
    if chunk.len() < CHUNK_GATES_OFFSET
        || chunk.len() > CHUNK_CAPACITY_BYTES
        || !chunk.len().is_multiple_of(GATE_ALIGNMENT)
    {
        return Err(malformed("bad length"));
    }
    if get(chunk, 8) != Some(NOP) || get(chunk, 12) != Some(NOP) {
        return Err(malformed("bad header"));
    }
    let mut gates: Vec<IslandGate> = Vec::new();
    let mut tls = Vec::new();
    let mut cursor = CHUNK_GATES_OFFSET;
    for slot in 0..ISLAND_SLOTS {
        let table = CHUNK_TABLE_OFFSET + slot * ISLAND_SLOT_BYTES;
        let entry = get(chunk, table).ok_or_else(|| malformed("table"))?;
        if (4..ISLAND_SLOT_BYTES)
            .step_by(4)
            .any(|at| get(chunk, table + at) != Some(brk()))
        {
            return Err(malformed("bad table padding"));
        }
        let needs_aux = gates.last().is_some_and(|g| {
            !g.auxiliary && matches!(g.metadata, GateMetadata::X18CompareBranch { .. })
        });
        if needs_aux {
            if entry != AUX_MARKER {
                return Err(malformed("missing taken exit"));
            }
            let mut aux = gates.last().expect("primary").clone();
            aux.auxiliary = true;
            aux.stages.clear();
            gates.push(aux);
            continue;
        }
        if entry == AUX_MARKER {
            return Err(malformed("orphan taken exit"));
        }
        if entry == brk() {
            // Slots are allocated in order: the rest of the table is unused.
            if (slot..ISLAND_SLOTS).any(|s| {
                (0..ISLAND_SLOT_BYTES).step_by(4).any(|at| {
                    get(chunk, CHUNK_TABLE_OFFSET + s * ISLAND_SLOT_BYTES + at) != Some(brk())
                })
            }) {
                return Err(malformed("sparse table"));
            }
            break;
        }
        if b_target(entry, table as u64) != Some(cursor as u64) {
            return Err(malformed("table entry does not name the next gate"));
        }
        let (gate, fields) =
            decode_gate(chunk, cursor, host).ok_or_else(|| malformed("bad gate"))?;
        cursor += gate.size;
        gates.push(gate);
        tls.extend(fields);
    }
    if gates.last().is_some_and(|g| {
        !g.auxiliary && matches!(g.metadata, GateMetadata::X18CompareBranch { .. })
    }) {
        return Err(malformed("missing final taken exit"));
    }
    if (CHUNK_TABLE_OFFSET + ISLAND_SLOTS * ISLAND_SLOT_BYTES..CHUNK_GATES_OFFSET)
        .step_by(4)
        .any(|at| get(chunk, at) != Some(brk()))
    {
        return Err(malformed("bad table alignment padding"));
    }
    if cursor != chunk.len() {
        return Err(malformed("trailing bytes"));
    }
    Ok((gates, tls))
}

/// Serialized chunks contain placeholders only, never another process's TLS
/// offsets. This check is separate from idempotent runtime finalization.
pub(super) fn validate_serialized_chunk(
    chunk: &[u8],
    host: crate::TargetHost,
    x18: bool,
) -> Result<()> {
    let (gates, fields) = walk_chunk_with_tls(chunk, host.into())?;
    if (!x18 && gates.iter().any(|gate| gate.original.is_some()))
        || fields.iter().any(|&(at, addend)| {
            let expected = if addend == 0 {
                GUEST_TPIDR_OFFSET_PLACEHOLDER
            } else {
                super::GUEST_X18_OFFSET_PLACEHOLDER
            };
            get(chunk, at).map(|word| ((word & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT) * 8)
                != Some(u32::from(expected))
        })
    {
        return Err(Error::TrampolinePatchFailure(
            "serialized island TLS/options".into(),
        ));
    }
    Ok(())
}

fn walk_chunk(chunk: &[u8], host: Host) -> Result<Vec<IslandGate>> {
    walk_chunk_with_tls(chunk, host).map(|(gates, _)| gates)
}

/// Validate a chunk image and return its gates in slot order.
/// Like [`decode_island_gate`], this allocates and decodes guest instructions;
/// construct these descriptors outside signal handling.
pub fn decode_island_chunk(chunk: &[u8], host: crate::TargetHost) -> Result<Vec<IslandGate>> {
    walk_chunk(chunk, host.into())
}

/// Finalize every TLS field of a chunk with the guest thread-pointer offset.
/// Validates the whole chunk before mutating it.
///
/// # Errors
///
/// Rejects invalid offsets, malformed chunks, and TLS fields holding neither
/// the placeholder nor `tls_offset`.
///
/// # Panics
///
/// Never: every field offset comes from the validated walk.
pub fn finalize_island_chunk(
    chunk: &mut [u8],
    tls_offset: u16,
    host: crate::TargetHost,
) -> Result<()> {
    validate_guest_offset(tls_offset, false)?;
    let (_, fields) = walk_chunk_with_tls(chunk, host.into())?;
    for &(at, addend) in &fields {
        let offset = tls_offset
            .checked_add(addend)
            .ok_or_else(|| Error::AddressOverflow("x18 TLS offset".into()))?;
        validate_guest_offset(offset, addend != 0)?;
        let placeholder = u32::from(
            if addend == 0 {
                GUEST_TPIDR_OFFSET_PLACEHOLDER
            } else {
                super::GUEST_X18_OFFSET_PLACEHOLDER
            } / GUEST_TPIDR_OFFSET_ALIGN,
        );
        let wanted = u32::from(offset / GUEST_TPIDR_OFFSET_ALIGN);
        let imm =
            (get(chunk, at).expect("validated") & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT;
        if imm != placeholder && imm != wanted {
            return Err(Error::TrampolinePatchFailure(format!(
                "island chunk TLS field at {at} has unexpected offset"
            )));
        }
    }
    for &(at, addend) in &fields {
        let wanted = u32::from((tls_offset + addend) / GUEST_TPIDR_OFFSET_ALIGN);
        let insn = get(chunk, at).expect("validated");
        put(
            chunk,
            at,
            (insn & !LDST_UIMM12_IMM_MASK) | (wanted << LDST_UIMM12_IMM_SHIFT),
        );
    }
    Ok(())
}

// ============================================================
// Rewriting
// ============================================================

/// Outcome of rewriting code through islands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IslandRewrite {
    /// Sites redirected through an island.
    pub patched_sites: usize,
    /// Sites replaced with a trap: unsupported, or no island in reach/capacity.
    pub trapped_sites: Vec<u64>,
    /// Supported trapped sites for which another reachable pair may help.
    pub unplaced_sites: Vec<UnplacedIslandSite>,
}

/// An admitted site that needs a fresh pair, with all direct branch edges in reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnplacedIslandSite {
    /// Guest instruction address.
    pub site: u64,
    /// Allowed base addresses for an empty pair (primary slot zero). The caller
    /// must additionally align the base and reserve the whole island image.
    pub placement_range: core::ops::RangeInclusive<u64>,
    /// Required slots, including any auxiliary taken exit.
    pub slots: usize,
}

/// Intersect the signed imm26 edges at their actual slot PCs, not at the base.
/// ADR/ADRP targets are data computed by the gate, not direct branch exits.
fn site_placement_range(
    site: u64,
    spec: Option<x18::Spec>,
) -> Result<core::ops::RangeInclusive<u64>> {
    checked_add_u64(site, INSN_BYTES_U64, "island return")?;
    let s = i128::from(site);
    let reach = 1i128 << 27;
    let mut low = (s - reach - ISLAND_HEADER_BYTES as i128).max(0);
    let mut high = (s + reach - (ISLAND_HEADER_BYTES + 16) as i128)
        .min(i128::from(u64::MAX - ISLAND_BYTES as u64));
    if let Some(spec) = spec.filter(|s| s.slots() == 2) {
        let target = i128::from(spec.target.expect("conditional target"));
        let branch = (ISLAND_HEADER_BYTES + ISLAND_SLOT_BYTES + 20) as i128;
        low = low.max(target - (reach - 4) - branch);
        high = high.min(target + reach - branch);
    }
    if low > high {
        return Err(Error::TrampolinePatchFailure(
            "no common island reach".into(),
        ));
    }
    let bound =
        |value| u64::try_from(value).map_err(|_| Error::AddressOverflow("island reach".into()));
    Ok(bound(low)?..=bound(high)?)
}

fn island_metadata(kind: PatchKind) -> Option<GateMetadata> {
    match kind {
        PatchKind::Svc => Some(GateMetadata::Svc),
        PatchKind::MrsTpidr(destination) => Some(GateMetadata::MrsTpidr { destination }),
        PatchKind::MsrTpidr(source) => Some(GateMetadata::MsrTpidr { source }),
        _ => None,
    }
}

fn admit_site(buf: &[u8], site: &PatchSite) -> Option<(GateMetadata, Option<x18::Spec>)> {
    let spec = if island_metadata(site.kind).is_none() {
        get(buf, site.file_offset).and_then(|raw| x18::Spec::decode(raw, site.vaddr))
    } else {
        None
    };
    spec.map(|s| s.metadata)
        .or_else(|| island_metadata(site.kind))
        .map(|metadata| (metadata, spec))
}

/// Rewrite sites in `buf` through `pairs`. Each site goes to the reachable
/// island with free capacity whose slot is nearest. On error, neither `buf` nor
/// `pairs` is modified.
pub(crate) fn rewrite_sections(
    buf: &mut [u8],
    executable: &[TextSectionInfo],
    code: &[TextSectionInfo],
    pairs: &mut [IslandPair],
    config: RewriteConfig,
) -> Result<IslandRewrite> {
    let sites: Vec<PatchSite> = find_patch_sites_with_code_ranges(executable, code, buf, config)?;
    let mut staged_pairs = pairs.to_vec();
    let mut staged = Vec::new();
    let mut outcome = IslandRewrite::default();
    for site in &sites {
        let admitted = admit_site(buf, site);
        let metadata = admitted.map(|(metadata, _)| metadata);
        let spec = admitted.and_then(|(_, spec)| spec);
        let chosen = metadata.and_then(|_| {
            staged_pairs
                .iter()
                .enumerate()
                .filter(|(_, pair)| pair.reaches(site.vaddr, spec))
                .min_by_key(|(_, pair)| pair.slot_vaddr(pair.slots_used).abs_diff(site.vaddr))
                .map(|(index, _)| index)
        });
        let inbound = match (metadata, chosen) {
            (Some(metadata), Some(index)) => {
                staged_pairs[index].push(site.vaddr, metadata, config.host, spec)?
            }
            _ => None,
        };
        if inbound.is_some() {
            outcome.patched_sites += 1;
        } else {
            outcome.trapped_sites.push(site.vaddr);
            if metadata.is_some() {
                outcome.unplaced_sites.push(UnplacedIslandSite {
                    site: site.vaddr,
                    placement_range: site_placement_range(site.vaddr, spec)?,
                    slots: spec.map_or(1, x18::Spec::slots),
                });
            }
        }
        staged.push((site.file_offset, inbound));
    }
    for (offset, word) in staged {
        if let Some(word) = word {
            put(buf, offset, word);
        } else {
            trap_site(buf, offset);
        }
    }
    pairs.clone_from_slice(&staged_pairs);
    Ok(outcome)
}

/// AOT-only planner: scan/admit once, then allocate at most one fresh pair per
/// site. The allocator sees the exact slot-zero inbound/return intersection,
/// including the auxiliary conditional exit; it never retries an instruction.
pub(crate) fn rewrite_allocating_sections(
    buf: &mut [u8],
    executable: &[TextSectionInfo],
    code: &[TextSectionInfo],
    config: RewriteConfig,
    mut allocate: impl FnMut(u64, core::ops::RangeInclusive<u64>, &[IslandPair]) -> Option<u64>,
) -> Result<Vec<IslandPair>> {
    let sites = find_patch_sites_with_code_ranges(executable, code, buf, config)?;
    let admitted = sites
        .iter()
        .map(|site| {
            let (metadata, spec) = admit_site(buf, site).ok_or_else(|| {
                Error::UnpatchableSyscalls(alloc::format!(
                    "unsupported island site {:#x}",
                    site.vaddr
                ))
            })?;
            Ok((site, metadata, spec))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut pairs: Vec<IslandPair> = Vec::new();
    let mut patches = Vec::new();
    for (site, metadata, spec) in admitted {
        let chosen = pairs
            .iter()
            .enumerate()
            .filter(|(_, pair)| pair.reaches(site.vaddr, spec))
            .min_by_key(|(_, pair)| pair.slot_vaddr(pair.slots_used).abs_diff(site.vaddr))
            .map(|(index, _)| index);
        let index = if let Some(index) = chosen {
            index
        } else {
            let range = site_placement_range(site.vaddr, spec)?;
            let address = allocate(site.vaddr, range, &pairs).ok_or_else(|| {
                Error::UnpatchableSyscalls(alloc::format!(
                    "no safe ELF island placement for {:#x}; changing LOAD layout is required",
                    site.vaddr
                ))
            })?;
            pairs.push(IslandPair::new(address)?);
            pairs.len() - 1
        };
        let word = pairs[index]
            .push(site.vaddr, metadata, config.host, spec)?
            .ok_or_else(|| Error::TrampolinePatchFailure("planned island out of reach".into()))?;
        patches.push((site.file_offset, word));
    }
    for (offset, word) in patches {
        put(buf, offset, word);
    }
    Ok(pairs)
}

/// Upper bound on island slots needed to rewrite `sections` of `buf`.
pub(crate) fn count_sites(
    buf: &[u8],
    executable: &[TextSectionInfo],
    code: &[TextSectionInfo],
    config: RewriteConfig,
) -> Result<usize> {
    find_patch_sites_with_code_ranges(executable, code, buf, config)?
        .iter()
        .try_fold(0usize, |count, site| {
            let slots =
                admit_site(buf, site).map_or(0, |(_, spec)| spec.map_or(1, x18::Spec::slots));
            count
                .checked_add(slots)
                .ok_or_else(|| Error::AddressOverflow("island slot count".into()))
        })
}

pub mod signal;
mod x18;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod x18_tests;

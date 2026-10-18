// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Single-source AArch64 gate templates.
//!
//! [`build`] describes every gate kind exactly once, as a sequence of
//! instructions. Each instruction carries a `Role`, which says how slot
//! validation compares that word, and a recovery [`Stage`], which says how a
//! signal handler canonicalizes a context interrupted *before* that
//! instruction executes. Everything else derives from this one description:
//!
//! * emission builds a slot from the patch site's parameters;
//! * validation extracts the free parameters from a candidate slot, rebuilds
//!   it, and compares the two word by word ([`validate`]);
//! * TLS-offset finalization patches the words tagged `Role::Tls`;
//! * signal recovery reads the [`Stage`] of the interrupted instruction.
//!
//! Host differences are confined to the anchor macro (`GateAsm::tls_base`),
//! so no host-specific offset tables exist. The builder neither allocates nor
//! panics, because validation also runs inside signal handlers.

use super::{
    ADD_IMM_SHAPE_MASK, ADRP_SHAPE_MASK, Boundary, Frame, FrameBase, GATE_METADATA_BYTES,
    GUEST_TPIDR_OFFSET_ALIGN, GUEST_TPIDR_OFFSET_PLACEHOLDER, GUEST_X18_OFFSET_PLACEHOLDER,
    GateLayout, GateMetadata, GuestSp, IMM26_BITS, IMM26_MASK, IN_GUEST_OFFSET_FROM_GUEST_TP,
    INSN_BYTES, Insn, LDST_UIMM12_IMM_MASK, LDST_UIMM12_IMM_SHIFT, MAX_GATE_SLOT_BYTES,
    MSR_FRAME_BYTES, MSR_FRAME_OFF_VALUE, NOP, OPCODE_TOP6_MASK, Opcode, PAGE_OFFSET_MASK,
    REG_MASK, RT2_SHIFT, Resume, SP, SVC_FRAME_OFF_RETADDR, SVC_FRAME_OFF_STUB, SVC_FRAME_OFF_X16,
    Stage, TargetHost, Value, X16, X17, X18_BRANCH_BRK_IMM, X18_FRAME_BYTES, X18BranchKind,
    X18PcRelative, X18StackWritebackLayout, anchor_mask, classify_x18_stack_writeback,
    decode_ldr_literal_target, pcrel_bytes, valid_emitted_tpidr_offset, valid_emitted_x18_offset,
};

/// Most words any gate slot holds, including padding and metadata.
pub(crate) const MAX_SLOT_WORDS: usize = MAX_GATE_SLOT_BYTES / INSN_BYTES;

impl Boundary {
    const fn new(frame: Frame, sp: GuestSp, value: Value, resume: Resume) -> Self {
        Self {
            frame,
            sp,
            value,
            resume,
            runtime_fault: false,
            check_capture: false,
        }
    }

    const fn fault(mut self) -> Self {
        self.runtime_fault = true;
        self
    }

    const fn capture(mut self) -> Self {
        self.check_capture = true;
        self
    }

    /// This boundary as the stage of an executable word. Stages are optional
    /// because padding and provenance words have none.
    #[allow(clippy::unnecessary_wraps, reason = "matches the per-word stage type")]
    const fn stage(self) -> Option<Stage> {
        Some(Stage::Recover(self))
    }
}

// ============================================================
// Template representation
// ============================================================

/// Runtime-patched guest TLS field in an unsigned-offset `LDR`/`STR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsField {
    /// Guest thread-pointer slot, or the indirect-TLS block pointer.
    Tp,
    /// Direct-TLS guest x18 slot.
    X18,
}

impl TlsField {
    pub(crate) const fn placeholder(self) -> u16 {
        match self {
            Self::Tp => GUEST_TPIDR_OFFSET_PLACEHOLDER,
            Self::X18 => GUEST_X18_OFFSET_PLACEHOLDER,
        }
    }

    fn accepts(self, offset: u32) -> bool {
        match self {
            Self::Tp => valid_emitted_tpidr_offset(offset),
            Self::X18 => valid_emitted_x18_offset(offset),
        }
    }
}

/// How validation compares one slot word against its rebuilt template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// Must match exactly.
    Fixed,
    /// Matches except for a runtime-patched TLS offset, which must be the
    /// placeholder or a valid patched offset.
    Tls(TlsField),
    /// Copied (possibly relocated) guest instruction; supplies its own value.
    Guest,
    /// Scratch-pair spill; `Rt2` names the anchor scratch.
    Spill,
    /// Branch back to the instruction after the original site.
    Return,
    /// Branch to the original compare/test-branch taken target.
    Taken,
    /// Gate-local compare/test branch on the value scratch.
    Test,
    /// `ADRP`/`ADD` of the SVC return address: exact once placed, structural
    /// before placement.
    ReturnPage,
    ReturnOffset,
    /// `ADRP`/`ADD` of an `ADR X18` target: structural only.
    AdrPage,
    AdrOffset,
    /// `LDR` literal of the trampoline's callback slot.
    Callback,
}

/// Parameters of one gate instance. Kinds use only the fields they need.
#[derive(Clone, Copy, Debug)]
pub struct GateInstance {
    pub metadata: GateMetadata,
    /// x18 gates: the scratch holding the host anchor.
    pub anchor: u8,
    /// x18 gates: the guest instruction with x18 substituted.
    pub guest: u32,
    /// Ordinary x18 gate: relocate a PC-relative guest instruction.
    pub pc_relative: Option<X18PcRelative>,
    /// Compare/test-branch gate: the branch form.
    pub test: X18BranchKind,
    /// SP-writeback gate: the decoded pair layout.
    pub stack: X18StackWritebackLayout,
    /// Address of the instruction after the original site.
    pub return_addr: u64,
    /// Compare/test-branch gate: the taken target.
    pub taken: u64,
    /// `ADR X18` gate: the materialized address.
    pub adr_target: u64,
}

impl GateInstance {
    /// An instance with every kind-specific field at a harmless default.
    pub const fn new(metadata: GateMetadata, return_addr: u64) -> Self {
        Self {
            metadata,
            anchor: 0,
            guest: NOP,
            pc_relative: None,
            test: X18BranchKind::CbzX,
            stack: X18StackWritebackLayout {
                rt: 0,
                rt2: 0,
                delta: 0,
                element_bytes: 8,
                frame_bytes: X18_FRAME_BYTES,
            },
            return_addr,
            taken: return_addr,
            adr_target: return_addr,
        }
    }

    /// Value scratch register of an x18 gate.
    fn scratch(&self) -> u8 {
        match self.metadata {
            GateMetadata::X18 { scratch }
            | GateMetadata::X18StackWriteback { scratch }
            | GateMetadata::X18CompareBranch { scratch }
            | GateMetadata::X18Adr { scratch } => scratch,
            _ => 0,
        }
    }
}

/// Why a gate could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A PC-relative reference is out of range; the site must be trapped.
    Unreachable,
    /// An address computation overflowed (`"{context} address overflow"`).
    Overflow(&'static str),
    /// The callback literal is out of `LDR`-literal range.
    Literal(i64),
    /// A computed operand cannot be encoded.
    Unencodable(&'static str),
    /// The gate kind is not available for the selected host.
    Unsupported(&'static str),
    /// The body does not fit before the slot's metadata word.
    TooLarge(usize),
    /// The metadata cannot be encoded.
    Metadata,
}

/// One built slot: body, NOP padding and metadata, with per-word roles and
/// recovery stages. A fixed-size value so that signal handlers can build it.
#[derive(Clone, Copy)]
pub struct BuiltSlot {
    words: [u32; MAX_SLOT_WORDS],
    roles: [Role; MAX_SLOT_WORDS],
    stages: [Option<Stage>; MAX_SLOT_WORDS],
    len: usize,
}

impl BuiltSlot {
    pub const fn empty() -> Self {
        Self {
            words: [0; MAX_SLOT_WORDS],
            roles: [Role::Fixed; MAX_SLOT_WORDS],
            stages: [None; MAX_SLOT_WORDS],
            len: 0,
        }
    }

    pub fn words(&self) -> &[u32] {
        &self.words[..self.len]
    }

    fn roles(&self) -> &[Role] {
        &self.roles[..self.len]
    }

    /// Recovery stage of the instruction at byte offset `offset`, or `None`
    /// when that word is not part of the executable body.
    pub fn stage_at(&self, offset: usize) -> Option<Stage> {
        if !offset.is_multiple_of(INSN_BYTES) {
            return None;
        }
        self.stages[..self.len]
            .get(offset / INSN_BYTES)
            .copied()
            .flatten()
    }

    /// Byte offset of the first word with `role`.
    pub(crate) fn offset_of(&self, role: Role) -> Option<usize> {
        self.roles()
            .iter()
            .position(|candidate| *candidate == role)
            .map(|index| index * INSN_BYTES)
    }

    /// Byte offsets and fields of every runtime-patched TLS word.
    pub(crate) fn tls_words(&self) -> impl Iterator<Item = (usize, TlsField)> + '_ {
        self.roles()
            .iter()
            .enumerate()
            .filter_map(|(index, role)| match role {
                Role::Tls(field) => Some((index * INSN_BYTES, *field)),
                _ => None,
            })
    }

    pub fn append_to(&self, out: &mut alloc::vec::Vec<u8>) {
        for word in self.words() {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }
}

/// A position-tracking, role- and stage-tagging assembler for one slot. It
/// writes into a caller-owned buffer so that no slot is copied between frames
/// on signal stacks.
struct GateAsm<'a> {
    vaddr: u64,
    host: TargetHost,
    slot: &'a mut BuiltSlot,
}

impl<'a> GateAsm<'a> {
    fn new(vaddr: u64, host: TargetHost, slot: &'a mut BuiltSlot) -> Self {
        slot.len = 0;
        Self { vaddr, host, slot }
    }

    fn here(&self) -> Result<u64, BuildError> {
        self.vaddr
            .checked_add((self.slot.len * INSN_BYTES) as u64)
            .ok_or(BuildError::Overflow("trampoline gate next-instruction"))
    }

    fn push(&mut self, stage: Option<Stage>, role: Role, word: u32) -> Result<(), BuildError> {
        let index = self.slot.len;
        if index == MAX_SLOT_WORDS {
            return Err(BuildError::TooLarge(index * INSN_BYTES));
        }
        self.slot.words[index] = word;
        self.slot.roles[index] = role;
        self.slot.stages[index] = stage;
        self.slot.len += 1;
        Ok(())
    }

    fn emit(&mut self, stage: Option<Stage>, role: Role, insn: Insn) -> Result<(), BuildError> {
        let word = insn
            .encode()
            .ok_or(BuildError::Unencodable("AArch64 gate instruction"))?;
        self.push(stage, role, word)
    }

    fn op(&mut self, stage: Option<Stage>, insn: Insn) -> Result<(), BuildError> {
        self.emit(stage, Role::Fixed, insn)
    }

    fn delta_to(&self, target: u64) -> Result<i64, BuildError> {
        Ok(target
            .cast_signed()
            .saturating_sub(self.here()?.cast_signed()))
    }

    /// `B <target>`.
    fn branch(&mut self, stage: Option<Stage>, role: Role, target: u64) -> Result<(), BuildError> {
        let word = Insn::B(self.delta_to(target)?)
            .encode()
            .ok_or(BuildError::Unreachable)?;
        self.push(stage, role, word)
    }

    /// `ADR Xd, <target>`.
    fn adr(&mut self, stage: Option<Stage>, rd: u8, target: u64) -> Result<(), BuildError> {
        let word = Insn::Adr {
            rd,
            byte_off: self.delta_to(target)?,
        }
        .encode()
        .ok_or(BuildError::Unreachable)?;
        self.push(stage, Role::Fixed, word)
    }

    /// `ADRP Xd, <target>`.
    fn adrp(
        &mut self,
        stage: Option<Stage>,
        role: Role,
        rd: u8,
        target: u64,
    ) -> Result<(), BuildError> {
        let here = self.here()?;
        let page_off = (target & !PAGE_OFFSET_MASK)
            .cast_signed()
            .saturating_sub((here & !PAGE_OFFSET_MASK).cast_signed())
            >> 12;
        let word = Insn::Adrp { rd, page_off }
            .encode()
            .ok_or(BuildError::Unreachable)?;
        self.push(stage, role, word)
    }

    /// `ADRP Xd, <target>; ADD Xd, Xd, #<page offset>`.
    fn address(
        &mut self,
        stages: [Option<Stage>; 2],
        roles: [Role; 2],
        rd: u8,
        target: u64,
    ) -> Result<(), BuildError> {
        self.adrp(stages[0], roles[0], rd, target)?;
        let imm12 = u16::try_from(target & PAGE_OFFSET_MASK).expect("masked to 12 bits");
        self.emit(stages[1], roles[1], Insn::AddImm { rd, rn: rd, imm12 })
    }

    /// `LDR Xt, <literal>`.
    fn ldr_literal(&mut self, stage: Option<Stage>, rt: u8, target: u64) -> Result<(), BuildError> {
        let off = self.delta_to(target)?;
        let word = Insn::LdrLiteral { rt, off }
            .encode()
            .ok_or(BuildError::Literal(off))?;
        self.push(stage, Role::Callback, word)
    }

    /// Loads the guest TLS base into `rd`. The anchor read itself is tagged
    /// `stage`; the extra words of an indirect-TLS (macOS) lookup are tagged
    /// `next`, the stage of the instruction that follows the macro.
    fn tls_base(
        &mut self,
        stage: Option<Stage>,
        next: Option<Stage>,
        rd: u8,
    ) -> Result<(), BuildError> {
        self.op(stage, self.host.anchor_read(rd))?;
        if self.host == TargetHost::MacOs {
            self.op(next, anchor_mask(rd))?;
            self.tls(next, TlsField::Tp, Opcode::LdrUimm, rd, rd)?;
        }
        Ok(())
    }

    /// A load or store of the runtime-patched TLS field.
    fn tls(
        &mut self,
        stage: Option<Stage>,
        field: TlsField,
        opcode: Opcode,
        rt: u8,
        rn: u8,
    ) -> Result<(), BuildError> {
        let word = opcode.bits()
            | (u32::from(field.placeholder() / GUEST_TPIDR_OFFSET_ALIGN) << LDST_UIMM12_IMM_SHIFT)
            | (u32::from(rn) << super::RN_SHIFT)
            | u32::from(rt);
        self.push(stage, Role::Tls(field), word)
    }

    /// Accesses the guest thread pointer relative to a loaded TLS base.
    fn tp_access(
        &mut self,
        stage: Option<Stage>,
        opcode: Opcode,
        rt: u8,
        rn: u8,
    ) -> Result<(), BuildError> {
        if self.host == TargetHost::MacOs {
            self.op(stage, ldst(opcode, rt, rn, 0))
        } else {
            self.tls(stage, TlsField::Tp, opcode, rt, rn)
        }
    }

    /// Accesses guest x18 relative to a loaded TLS base.
    fn x18_access(
        &mut self,
        stage: Option<Stage>,
        opcode: Opcode,
        rt: u8,
        rn: u8,
    ) -> Result<(), BuildError> {
        if self.host == TargetHost::MacOs {
            self.op(stage, ldst(opcode, rt, rn, GUEST_TPIDR_OFFSET_ALIGN))
        } else {
            self.tls(stage, TlsField::X18, opcode, rt, rn)
        }
    }

    /// Pads with NOPs and closes the slot with its metadata word.
    fn finish(mut self, metadata: GateMetadata, slot_size: usize) -> Result<(), BuildError> {
        let body = self.slot.len * INSN_BYTES;
        let metadata_offset = slot_size - GATE_METADATA_BYTES;
        if body > metadata_offset {
            return Err(BuildError::TooLarge(body));
        }
        while self.slot.len * INSN_BYTES < metadata_offset {
            self.push(None, Role::Fixed, NOP)?;
        }
        let encoded = super::EncodedGateMetadata::encode(metadata).ok_or(BuildError::Metadata)?;
        self.push(None, Role::Fixed, encoded.0)
    }
}

fn ldst(opcode: Opcode, rt: u8, rn: u8, imm_bytes: u16) -> Insn {
    if matches!(opcode, Opcode::StrUimm) {
        Insn::StrUimm { rt, rn, imm_bytes }
    } else {
        Insn::LdrUimm { rt, rn, imm_bytes }
    }
}

// ============================================================
// The gate templates
// ============================================================

use Frame::{Live, Restore};
use FrameBase::{Anchor, BelowSp, Sp};
use GuestSp::{FrameEnd, FrameEndPlusDelta, Signal};
use Resume::{LogicalX18, Next, Site, Taken};
use Value::{Scratch, Slot};

/// Inputs every gate template receives.
struct Gate<'a> {
    instance: &'a GateInstance,
    layout: GateLayout,
    slot_vaddr: u64,
    trampoline_base: u64,
}

/// Builds the slot for `instance` at `slot_vaddr` in a trampoline mapped at
/// `trampoline_base`. This is the only definition of each gate's code.
pub fn build(
    instance: &GateInstance,
    layout: GateLayout,
    slot_vaddr: u64,
    trampoline_base: u64,
) -> Result<BuiltSlot, BuildError> {
    let mut slot = BuiltSlot::empty();
    build_into(instance, layout, slot_vaddr, trampoline_base, &mut slot)?;
    Ok(slot)
}

/// [`build`] into a caller-owned buffer.
fn build_into(
    instance: &GateInstance,
    layout: GateLayout,
    slot_vaddr: u64,
    trampoline_base: u64,
    out: &mut BuiltSlot,
) -> Result<(), BuildError> {
    let template = match instance.metadata {
        GateMetadata::Svc => build_svc,
        GateMetadata::MrsTpidr { .. } => build_mrs,
        GateMetadata::HostAwareMrsTpidr { .. } => build_host_aware_mrs,
        GateMetadata::MsrTpidr { .. } => build_msr,
        GateMetadata::X18 { .. } => build_x18,
        GateMetadata::X18StackWriteback { .. } => build_x18_stack_writeback,
        GateMetadata::X18CompareBranch { .. } => build_x18_compare_branch,
        GateMetadata::X18Adr { .. } => build_x18_adr,
        GateMetadata::X18Branch { .. } => build_x18_branch,
    };
    // Each template is a separate, non-inlined function so that its frame
    // holds only its own temporaries: this also runs on signal stacks.
    let mut asm = GateAsm::new(slot_vaddr, layout.host, out);
    template(
        &mut asm,
        &Gate {
            instance,
            layout,
            slot_vaddr,
            trampoline_base,
        },
    )?;
    asm.finish(
        instance.metadata,
        instance.metadata.slot_size_for_host(layout.host),
    )
}

/// `SVC`: spill X16, record the return address and this site's outbound stub
/// on a guest-stack frame, and dispatch through the trampoline's callback. The
/// outbound stub that follows restores X16 and SP and returns to the site.
#[inline(never)]
fn build_svc(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let layout = gate.layout;
    let slot_vaddr = gate.slot_vaddr;
    let trampoline_base = gate.trampoline_base;
    let frame = layout.svc_frame_bytes;
    let entry = Boundary::new(none, Signal, Value::None, Site).stage();
    let spilled = Boundary::new(Live(Sp), FrameEnd, Value::None, Site);
    let saved = Boundary::new(Restore(Sp), FrameEnd, Value::None, Site);
    let stub = slot_vaddr
        .checked_add(super::SVC_GATE_BYTES as u64)
        .ok_or(BuildError::Overflow("SVC outbound stub"))?;
    let callback = trampoline_base
        .checked_add(super::HEADER_CALLBACK_OFFSET as u64)
        .ok_or(BuildError::Overflow("callback slot"))?;
    // Darwin spills below the red zone; neither SUB nor ADD changes NZCV.
    asm.op(entry, Insn::SubSp(frame))?;
    asm.op(spilled.stage(), str_sp(X16, SVC_FRAME_OFF_X16))?;
    asm.address(
        [spilled.stage(), saved.stage()],
        [Role::ReturnPage, Role::ReturnOffset],
        X16,
        ret,
    )?;
    asm.op(saved.stage(), str_sp(X16, SVC_FRAME_OFF_RETADDR))?;
    asm.adr(saved.stage(), X16, stub)?;
    asm.op(saved.stage(), str_sp(X16, SVC_FRAME_OFF_STUB))?;
    // The literal reaches back to the header, which caps one object at
    // about 16K SVC slots.
    asm.ldr_literal(saved.fault().stage(), X16, callback)?;
    asm.op(saved.stage(), Insn::Br(X16))?;
    debug_assert_eq!(asm.here(), Ok(stub));
    // Outbound stub: restore guest X16 and SP, then return to site+4.
    let outbound = Some(Stage::SvcOutbound);
    asm.op(outbound, ldr_sp(X16, SVC_FRAME_OFF_X16))?;
    asm.op(outbound, Insn::AddSp(frame))?;
    asm.branch(outbound, Role::Return, ret)?;
    Ok(())
}

/// `MRS Xd, TPIDR_EL0`: load the guest thread pointer, using `Xd` as the only
/// scratch. Once the first instruction runs the old `Xd` is gone, so recovery
/// completes the logical MRS rather than rewinding it.
#[inline(never)]
fn build_mrs(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let GateMetadata::MrsTpidr { destination: rd } = instance.metadata else {
        return Err(BuildError::Metadata);
    };
    let entry = Boundary::new(none, Signal, Value::None, Site).stage();
    let load = Boundary::new(none, Signal, Slot, Next).fault().stage();
    asm.tls_base(entry, load, rd)?;
    asm.tp_access(load, Opcode::LdrUimm, rd, rd)?;
    asm.branch(
        Boundary::new(none, Signal, Value::None, Next).stage(),
        Role::Return,
        ret,
    )?;
    Ok(())
}

/// Darwin shared-cache `MRS Xd, TPIDRRO_EL0`: guest state while LiteBox runs
/// guest code, the physical register otherwise.
#[inline(never)]
fn build_host_aware_mrs(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let GateMetadata::HostAwareMrsTpidr { destination: rd } = instance.metadata else {
        return Err(BuildError::Metadata);
    };
    if asm.host != TargetHost::MacOs {
        return Err(BuildError::Unsupported(
            "host-aware TPIDRRO gates require macOS",
        ));
    }
    let entry = Boundary::new(none, Signal, Value::None, Site).stage();
    let lookup = Boundary::new(none, Signal, Slot, Next).fault().stage();
    let done = Boundary::new(none, Signal, Value::None, Next).stage();
    // First lookup: is this a LiteBox thread executing guest code? The
    // destination is the only scratch: an architectural MRS overwrites
    // it anyway. The pthread key slot is null on threads LiteBox never
    // registered, and that null branch is the only guard.
    asm.op(entry, Insn::MrsTpidrroEl0(rd))?;
    asm.op(lookup, anchor_mask(rd))?;
    asm.tls(lookup, TlsField::Tp, Opcode::LdrUimm, rd, rd)?;
    asm.op(lookup, Insn::CbzX { rt: rd, offset: 32 })?;
    asm.op(
        lookup,
        Insn::LdrUimm {
            rt: rd,
            rn: rd,
            imm_bytes: IN_GUEST_OFFSET_FROM_GUEST_TP,
        },
    )?;
    asm.op(lookup, Insn::CbzX { rt: rd, offset: 24 })?;
    // Guest path: repeat the lookup, since the block pointer was
    // consumed by the mode load.
    asm.op(lookup, Insn::MrsTpidrroEl0(rd))?;
    asm.op(lookup, anchor_mask(rd))?;
    asm.tls(lookup, TlsField::Tp, Opcode::LdrUimm, rd, rd)?;
    asm.op(
        lookup,
        Insn::LdrUimm {
            rt: rd,
            rn: rd,
            imm_bytes: 0,
        },
    )?;
    asm.op(done, Insn::B(8))?;
    // TargetHost path: reproduce the original instruction, including the CPU
    // tag. TargetHost signals are forwarded without gate canonicalization,
    // so reaching here from a guest-mode signal is a runtime bug.
    asm.op(Some(Stage::Invalid), Insn::MrsTpidrroEl0(rd))?;
    asm.branch(done, Role::Return, ret)?;
    Ok(())
}

/// `MSR TPIDR_EL0, Xn`: store the guest thread pointer through an X16/X17
/// frame. NZCV and X30 reach the guest unchanged.
#[inline(never)]
fn build_msr(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let GateMetadata::MsrTpidr { source } = instance.metadata else {
        return Err(BuildError::Metadata);
    };
    let entry = Boundary::new(none, Signal, Value::None, Site).stage();
    let spilled = Boundary::new(Live(Sp), FrameEnd, Value::None, Site);
    let saved = Boundary::new(Restore(Sp), FrameEnd, Value::None, Site).capture();
    asm.op(entry, Insn::SubSp(MSR_FRAME_BYTES))?;
    asm.op(spilled.stage(), stp(X16, X17, 0))?;
    // Capture the source while all guest registers are pristine, so it
    // needs no special-casing when it is X16, X17 or XZR.
    asm.op(spilled.stage(), str_sp(source, MSR_FRAME_OFF_VALUE))?;
    asm.tls_base(spilled.capture().stage(), saved.stage(), X16)?;
    asm.op(saved.stage(), ldr_sp(X17, MSR_FRAME_OFF_VALUE))?;
    asm.tp_access(saved.fault().stage(), Opcode::StrUimm, X17, X16)?;
    asm.op(
        Boundary {
            resume: Next,
            ..saved
        }
        .stage(),
        Insn::Ldp {
            rt: X16,
            rt2: X17,
            rn: SP,
            imm_bytes: 0,
        },
    )?;
    asm.op(
        Boundary::new(Live(Sp), FrameEnd, Value::None, Next).stage(),
        Insn::AddSp(MSR_FRAME_BYTES),
    )?;
    // Two branches to the same return address; only the first runs.
    // The pair pins the slot's position without a stored site address.
    asm.branch(
        Boundary::new(none, Signal, Value::None, Next).stage(),
        Role::Return,
        ret,
    )?;
    asm.branch(None, Role::Return, ret)?;
    Ok(())
}

/// An ordinary x18 use: run the guest instruction with x18 renamed to a scratch,
/// at the original SP, with the scratches saved on a 16-byte frame.
#[inline(never)]
fn build_x18(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let GateMetadata::X18 { scratch } = instance.metadata else {
        return Err(BuildError::Metadata);
    };
    let anchor = instance.anchor;
    let at = |frame, value, resume| Boundary::new(frame, FrameEnd, value, resume);
    asm.emit(
        Boundary::new(none, Signal, Slot, Site).stage(),
        Role::Spill,
        Insn::StpPre {
            rt: scratch,
            rt2: anchor,
            rn: SP,
            imm_bytes: -(X18_FRAME_BYTES.cast_signed()),
        },
    )?;
    let loading = at(Restore(Sp), Slot, Site);
    asm.tls_base(
        at(Live(Sp), Slot, Site).stage(),
        loading.fault().stage(),
        anchor,
    )?;
    asm.x18_access(loading.fault().stage(), Opcode::LdrUimm, scratch, anchor)?;
    asm.op(
        loading.stage(),
        Insn::AddImm {
            rd: anchor,
            rn: SP,
            imm12: 0,
        },
    )?;
    asm.op(loading.stage(), Insn::AddSp(X18_FRAME_BYTES))?;
    // The guest instruction runs at the original SP; the anchor scratch
    // carries the frame address meanwhile.
    let guest_pc = asm.here()?;
    let guest = match instance.pc_relative {
        None => instance.guest,
        Some(X18PcRelative::Adr(target)) => Insn::Adr {
            rd: scratch,
            byte_off: target.cast_signed().saturating_sub(guest_pc.cast_signed()),
        }
        .encode()
        .ok_or(BuildError::Unreachable)?,
        Some(X18PcRelative::Adrp(target)) => Insn::Adrp {
            rd: scratch,
            page_off: (target & !PAGE_OFFSET_MASK)
                .cast_signed()
                .saturating_sub((guest_pc & !PAGE_OFFSET_MASK).cast_signed())
                >> 12,
        }
        .encode()
        .ok_or(BuildError::Unreachable)?,
    };
    asm.push(at(Restore(BelowSp), Slot, Site).stage(), Role::Guest, guest)?;
    asm.op(
        at(Restore(BelowSp), Scratch, Next).stage(),
        Insn::AddImm {
            rd: SP,
            rn: anchor,
            imm12: 0,
        },
    )?;
    let storing = at(Restore(Sp), Scratch, Next);
    asm.tls_base(storing.stage(), storing.fault().stage(), anchor)?;
    asm.x18_access(storing.fault().stage(), Opcode::StrUimm, scratch, anchor)?;
    asm.op(
        at(Restore(Sp), Slot, Next).stage(),
        Insn::LdpPost {
            rt: scratch,
            rt2: anchor,
            rn: SP,
            imm_bytes: X18_FRAME_BYTES.cast_signed(),
        },
    )?;
    asm.branch(
        Boundary::new(none, Signal, Slot, Next).stage(),
        Role::Return,
        ret,
    )?;
    Ok(())
}

/// An x18 pair with SP writeback: like [`build_x18`], but the frame sits below
/// the pair's own stack access and SP keeps the pair's writeback.
#[inline(never)]
fn build_x18_stack_writeback(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let GateMetadata::X18StackWriteback { scratch } = instance.metadata else {
        return Err(BuildError::Metadata);
    };
    let anchor = instance.anchor;
    let pair = instance.stack;
    // Every boundary but the pair itself is runtime-attributed: a fault
    // in the spill is not the guest instruction's.
    let at = |frame, sp, value, resume| Boundary::new(frame, sp, value, resume).fault();
    let loading = at(Restore(Sp), FrameEnd, Slot, Site);
    asm.op(
        at(none, Signal, Slot, Site).stage(),
        Insn::SubSp(pair.frame_bytes),
    )?;
    asm.emit(
        at(Live(Sp), FrameEnd, Slot, Site).stage(),
        Role::Spill,
        stp(scratch, anchor, 0),
    )?;
    asm.tls_base(loading.stage(), loading.stage(), anchor)?;
    asm.x18_access(loading.stage(), Opcode::LdrUimm, scratch, anchor)?;
    asm.op(
        loading.stage(),
        Insn::AddImm {
            rd: anchor,
            rn: SP,
            imm12: 0,
        },
    )?;
    asm.op(loading.stage(), Insn::AddSp(pair.frame_bytes))?;
    asm.push(
        Boundary::new(Restore(Anchor), Signal, Scratch, Site).stage(),
        Role::Guest,
        instance.guest,
    )?;
    asm.op(
        at(Restore(Anchor), Signal, Scratch, Next).stage(),
        Insn::AddImm {
            rd: SP,
            rn: anchor,
            imm12: 0,
        },
    )?;
    let storing = at(Restore(Sp), FrameEndPlusDelta, Scratch, Next);
    asm.tls_base(storing.stage(), storing.stage(), anchor)?;
    asm.x18_access(storing.stage(), Opcode::StrUimm, scratch, anchor)?;
    asm.op(
        storing.stage(),
        Insn::Ldp {
            rt: scratch,
            rt2: anchor,
            rn: SP,
            imm_bytes: 0,
        },
    )?;
    let final_adjustment = u16::try_from(i32::from(pair.frame_bytes) + i32::from(pair.delta))
        .map_err(|_| BuildError::Unencodable("x18 SP-writeback adjustment"))?;
    asm.op(
        at(Live(Sp), FrameEndPlusDelta, Slot, Next).stage(),
        Insn::AddSp(final_adjustment),
    )?;
    asm.branch(at(none, Signal, Slot, Next).stage(), Role::Return, ret)?;
    Ok(())
}

/// A compare/test branch on x18, with separate fallthrough and taken exits.
#[inline(never)]
fn build_x18_compare_branch(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let GateMetadata::X18CompareBranch { scratch } = instance.metadata else {
        return Err(BuildError::Metadata);
    };
    let anchor = instance.anchor;
    let at = |frame, resume| Boundary::new(frame, FrameEnd, Slot, resume);
    asm.op(
        Boundary::new(none, Signal, Slot, Site).stage(),
        Insn::SubSp(X18_FRAME_BYTES),
    )?;
    asm.emit(
        at(Live(Sp), Site).stage(),
        Role::Spill,
        stp(scratch, anchor, 0),
    )?;
    let loading = at(Restore(Sp), Site);
    asm.tls_base(loading.stage(), loading.fault().stage(), anchor)?;
    asm.x18_access(loading.fault().stage(), Opcode::LdrUimm, scratch, anchor)?;
    asm.emit(
        loading.stage(),
        Role::Test,
        test_insn(instance.test, scratch),
    )?;
    for (role, resume, target) in [
        (Role::Return, Next, ret),
        (Role::Taken, Taken, instance.taken),
    ] {
        asm.op(
            at(Restore(Sp), resume).stage(),
            Insn::Ldp {
                rt: scratch,
                rt2: anchor,
                rn: SP,
                imm_bytes: 0,
            },
        )?;
        asm.op(at(Live(Sp), resume).stage(), Insn::AddSp(X18_FRAME_BYTES))?;
        asm.branch(
            Boundary::new(none, Signal, Slot, resume).stage(),
            role,
            target,
        )?;
    }
    Ok(())
}

/// `ADR X18`: store the materialized absolute address to guest x18.
#[inline(never)]
fn build_x18_adr(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    let GateMetadata::X18Adr { scratch } = instance.metadata else {
        return Err(BuildError::Metadata);
    };
    let anchor = instance.anchor;
    let at = |frame, value, resume| Boundary::new(frame, FrameEnd, value, resume);
    asm.emit(
        Boundary::new(none, Signal, Slot, Site).stage(),
        Role::Spill,
        Insn::StpPre {
            rt: scratch,
            rt2: anchor,
            rn: SP,
            imm_bytes: -(X18_FRAME_BYTES.cast_signed()),
        },
    )?;
    let computing = at(Restore(Sp), Slot, Site).stage();
    asm.tls_base(at(Live(Sp), Slot, Site).stage(), computing, anchor)?;
    asm.address(
        [computing, computing],
        [Role::AdrPage, Role::AdrOffset],
        scratch,
        instance.adr_target,
    )?;
    asm.x18_access(
        at(Restore(Sp), Scratch, Next).fault().stage(),
        Opcode::StrUimm,
        scratch,
        anchor,
    )?;
    asm.op(
        at(Restore(Sp), Slot, Next).stage(),
        Insn::LdpPost {
            rt: scratch,
            rt2: anchor,
            rn: SP,
            imm_bytes: X18_FRAME_BYTES.cast_signed(),
        },
    )?;
    asm.branch(
        Boundary::new(none, Signal, Slot, Next).stage(),
        Role::Return,
        ret,
    )?;
    Ok(())
}

/// An indirect branch through x18: no physical scratch can be consumed
/// transparently, so the exception handler emulates it at a breakpoint. The
/// trailing branch only records provenance and never executes.
#[inline(never)]
fn build_x18_branch(asm: &mut GateAsm, gate: &Gate<'_>) -> Result<(), BuildError> {
    let instance = gate.instance;
    let ret = instance.return_addr;
    let none = Frame::None;
    // No physical scratch can be consumed transparently, so the
    // exception handler emulates the branch. The trailing branch only
    // records provenance and never executes.
    asm.op(
        Boundary::new(none, Signal, Slot, LogicalX18).stage(),
        Insn::Brk(X18_BRANCH_BRK_IMM),
    )?;
    asm.branch(None, Role::Return, ret)?;
    asm.op(None, Insn::Nop)?;
    Ok(())
}

const fn str_sp(rt: u8, imm_bytes: u16) -> Insn {
    Insn::StrUimm {
        rt,
        rn: SP,
        imm_bytes,
    }
}

const fn ldr_sp(rt: u8, imm_bytes: u16) -> Insn {
    Insn::LdrUimm {
        rt,
        rn: SP,
        imm_bytes,
    }
}

const fn stp(rt: u8, rt2: u8, imm_bytes: i16) -> Insn {
    Insn::Stp {
        rt,
        rt2,
        rn: SP,
        imm_bytes,
    }
}

/// The gate-local compare/test branch over the fallthrough exit.
fn test_insn(kind: X18BranchKind, rt: u8) -> Insn {
    const OVER_FALLTHROUGH: i64 = 16;
    match kind {
        X18BranchKind::CbzW => Insn::CbzW {
            rt,
            offset: OVER_FALLTHROUGH,
        },
        X18BranchKind::CbzX => Insn::CbzX {
            rt,
            offset: OVER_FALLTHROUGH,
        },
        X18BranchKind::CbnzW => Insn::CbnzW {
            rt,
            offset: OVER_FALLTHROUGH,
        },
        X18BranchKind::CbnzX => Insn::CbnzX {
            rt,
            offset: OVER_FALLTHROUGH,
        },
        X18BranchKind::Tbz(bit) => Insn::TestBranch {
            rt,
            bit,
            offset: OVER_FALLTHROUGH,
            nonzero: false,
        },
        X18BranchKind::Tbnz(bit) => Insn::TestBranch {
            rt,
            bit,
            offset: OVER_FALLTHROUGH,
            nonzero: true,
        },
    }
}

/// Inverse of [`test_insn`].
fn decode_test(word: u32, rt: u8) -> Option<X18BranchKind> {
    let kinds = [
        X18BranchKind::CbzW,
        X18BranchKind::CbzX,
        X18BranchKind::CbnzW,
        X18BranchKind::CbnzX,
    ];
    kinds
        .into_iter()
        .chain((0..64).flat_map(|bit| [X18BranchKind::Tbz(bit), X18BranchKind::Tbnz(bit)]))
        .find(|kind| test_insn(*kind, rt).encode() == Some(word))
}

// ============================================================
// Validation
// ============================================================

/// Where a slot being validated lives, which decides how exactly its branch and
/// literal targets can be checked.
#[derive(Clone, Copy, Debug)]
pub enum SlotAddressing {
    /// The trampoline has been placed at its final address, so every target
    /// resolves to an absolute address and can be compared exactly.
    Placed {
        /// Address the trampoline starts at.
        trampoline_base: u64,
        /// Address the slot itself starts at.
        slot_vaddr: u64,
    },
    /// The trampoline is still a position-independent blob, so targets can only
    /// be checked structurally.
    Unplaced {
        /// Byte offset of the slot within the blob.
        slot_offset: u64,
    },
}

impl SlotAddressing {
    /// The slot address and trampoline base to rebuild the slot at. An
    /// unplaced blob is rebuilt as if mapped at address zero.
    fn origin(self) -> (u64, u64) {
        match self {
            Self::Placed {
                trampoline_base,
                slot_vaddr,
            } => (slot_vaddr, trampoline_base),
            Self::Unplaced { slot_offset } => (slot_offset, 0),
        }
    }
}

/// Validates `slot` as a gate described by `metadata`: extracts the free
/// parameters, rebuilds the slot from them, and compares every word.
///
/// On success, returns the slot's parameters and leaves the rebuilt slot in
/// `out`. Allocation-free and panic-free, for use from signal handlers.
pub fn validate(
    slot: &[u8],
    addressing: SlotAddressing,
    metadata: GateMetadata,
    layout: GateLayout,
    out: &mut BuiltSlot,
) -> Option<GateInstance> {
    let (slot_vaddr, trampoline_base) = addressing.origin();
    let placed = matches!(addressing, SlotAddressing::Placed { .. });
    if slot.len() != metadata.slot_size_for_host(layout.host)
        || !slot_vaddr.is_multiple_of(super::GATE_ALIGNMENT as u64)
    {
        return None;
    }
    let word_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            slot.get(offset..offset + INSN_BYTES)?.try_into().ok()?,
        ))
    };

    let instance = extract(
        slot,
        metadata,
        layout,
        slot_vaddr,
        trampoline_base,
        placed,
        out,
    )?;
    build_into(&instance, layout, slot_vaddr, trampoline_base, out).ok()?;
    if out.len * INSN_BYTES != slot.len() {
        return None;
    }
    for index in 0..out.len {
        let expected = out.words[index];
        let actual = word_at(index * INSN_BYTES)?;
        let matches = match out.roles[index] {
            Role::Tls(field) => {
                actual & !LDST_UIMM12_IMM_MASK == expected & !LDST_UIMM12_IMM_MASK
                    && field.accepts(
                        ((actual & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT)
                            * u32::from(GUEST_TPIDR_OFFSET_ALIGN),
                    )
            }
            Role::ReturnPage if !placed => actual & ADRP_SHAPE_MASK == expected & ADRP_SHAPE_MASK,
            Role::ReturnOffset if !placed => {
                actual & ADD_IMM_SHAPE_MASK == expected & ADD_IMM_SHAPE_MASK
            }
            Role::AdrPage => actual & ADRP_SHAPE_MASK == expected & ADRP_SHAPE_MASK,
            Role::AdrOffset => actual & ADD_IMM_SHAPE_MASK == expected & ADD_IMM_SHAPE_MASK,
            _ => actual == expected,
        };
        if !matches {
            return None;
        }
    }
    Some(instance)
}

/// Extracts the parameters a slot was built with. Word positions do not
/// depend on the parameters, so a probe build locates the words carrying them.
/// The probe is built into `scratch`, which the caller reuses for the rebuild.
#[inline(never)]
fn extract(
    slot: &[u8],
    metadata: GateMetadata,
    layout: GateLayout,
    slot_vaddr: u64,
    trampoline_base: u64,
    placed: bool,
    probe: &mut BuiltSlot,
) -> Option<GateInstance> {
    let word_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            slot.get(offset..offset + INSN_BYTES)?.try_into().ok()?,
        ))
    };
    build_into(
        &probe_instance(metadata, slot_vaddr),
        layout,
        slot_vaddr,
        trampoline_base,
        probe,
    )
    .ok()?;
    // Start every target at the slot itself, which every PC-relative form can
    // reach. Targets that validation compares exactly are decoded below; the
    // `ADR X18` target is compared structurally and needs no decoding.
    let mut instance = GateInstance::new(metadata, slot_vaddr);
    let return_at = probe.offset_of(Role::Return)?;
    instance.return_addr =
        branch_target(word_at(return_at)?, slot_vaddr + return_at as u64, placed)?;
    if let Some(offset) = probe.offset_of(Role::Spill) {
        instance.anchor = ((word_at(offset)? >> RT2_SHIFT) & REG_MASK) as u8;
        let scratch = instance.scratch();
        if !(7..=17).contains(&scratch)
            || !(7..=17).contains(&instance.anchor)
            || instance.anchor == scratch
        {
            return None;
        }
    }
    if let Some(offset) = probe.offset_of(Role::Guest) {
        instance.guest = word_at(offset)?;
    }
    if let GateMetadata::X18StackWriteback { scratch } = metadata {
        // Rebuild the pair from the original instruction, which re-derives the
        // scratch choice and frame layout the gate must have used.
        let mut original = instance.guest;
        let substituted = super::decode_x18_stack_writeback(original)?;
        if substituted.rt == scratch {
            original = (original & !REG_MASK) | u32::from(super::X18_ENCODED);
        }
        if substituted.rt2 == scratch {
            original = (original & !(REG_MASK << RT2_SHIFT))
                | (u32::from(super::X18_ENCODED) << RT2_SHIFT);
        }
        let derived = classify_x18_stack_writeback(original)?;
        if derived.scratch != scratch {
            return None;
        }
        instance.guest = derived.word;
        instance.anchor = derived.anchor_scratch;
        instance.stack = derived.layout;
    }
    if let Some(offset) = probe.offset_of(Role::Test) {
        instance.test = decode_test(word_at(offset)?, instance.scratch())?;
    }
    if let Some(offset) = probe.offset_of(Role::Taken) {
        instance.taken = branch_target(word_at(offset)?, slot_vaddr + offset as u64, placed)?;
    }

    Some(instance)
}

/// Parameters that let a probe build of `metadata` at `slot_vaddr` succeed:
/// every target is the slot itself, so always within reach.
fn probe_instance(metadata: GateMetadata, slot_vaddr: u64) -> GateInstance {
    let mut instance = GateInstance::new(metadata, slot_vaddr);
    if let GateMetadata::X18 { scratch }
    | GateMetadata::X18StackWriteback { scratch }
    | GateMetadata::X18CompareBranch { scratch }
    | GateMetadata::X18Adr { scratch } = metadata
    {
        instance.anchor = if scratch == X16 { X17 } else { X16 };
    }
    instance
}

/// Decodes a `B` target. Before placement the slot is rebuilt at address zero,
/// so the target wraps rather than failing.
fn branch_target(word: u32, pc: u64, placed: bool) -> Option<u64> {
    if word & OPCODE_TOP6_MASK != Opcode::B.bits() {
        return None;
    }
    let displacement = pcrel_bytes(i64::from(word & IMM26_MASK), IMM26_BITS);
    if placed {
        pc.checked_add_signed(displacement)
    } else {
        Some(pc.wrapping_add_signed(displacement))
    }
}

/// Recovers the trampoline base from a placed SVC slot's callback literal,
/// using `probe` as scratch.
pub(crate) fn svc_trampoline_base(
    slot: &[u8],
    slot_vaddr: u64,
    host: TargetHost,
    probe: &mut BuiltSlot,
) -> Option<u64> {
    build_into(
        &probe_instance(GateMetadata::Svc, slot_vaddr),
        GateLayout::linux(host),
        slot_vaddr,
        slot_vaddr,
        probe,
    )
    .ok()?;
    let offset = probe.offset_of(Role::Callback)?;
    let word = u32::from_le_bytes(slot.get(offset..offset + INSN_BYTES)?.try_into().ok()?);
    decode_ldr_literal_target(word, slot_vaddr + offset as u64)
}

impl GateMetadata {
    /// First byte past the executable body of this gate on `host`.
    ///
    /// # Panics
    /// Panics if the metadata cannot describe an encodable gate for this host.
    pub fn executable_end_for_host(self, host: TargetHost) -> usize {
        let layout = if matches!(self, GateMetadata::HostAwareMrsTpidr { .. }) {
            GateLayout::darwin(host)
        } else {
            GateLayout::linux(host)
        };
        let slot = build(
            &probe_instance(self, 0x10_0000),
            layout,
            0x10_0000,
            0x10_0000,
        )
        .expect("probe build");
        slot.stages[..slot.len]
            .iter()
            .position(Option::is_none)
            .unwrap_or(slot.len)
            * INSN_BYTES
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! x18 gate construction. The old classifier remains the admission policy;
//! scratch selection here additionally reserves the island's x16/x30.

use super::super::{X18BranchKind, X18Classification, X18PcRelative, X18TransformResult};
use super::{
    GATE_ALIGNMENT, GateMetadata, Host, ISLAND_SLOT_BYTES, Insn, IslandPhase, IslandStage, Item,
    MAX_ISLAND_GATE_BYTES, Program, ProgramItems, SP, X16, X30, add_reg, before, tls_base,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct Spec {
    pub original: u32,
    pub metadata: GateMetadata,
    pub value: u8,
    pub anchor: u8,
    pub transformed: u32,
    pub entry: u16,
    pub exit: u16,
    pub target: Option<u64>,
    pub branch: Option<X18BranchKind>,
}

impl Spec {
    pub fn decode(original: u32, site: u64) -> Option<Self> {
        use crate::aarch64 as a;
        // These are deliberately unsupported by the existing Linux scanner.
        if original & a::MRS_TPIDR_EL0_MASK == a::MRS_TPIDR_EL0_BITS
            || original & a::MSR_TPIDR_EL0_MASK == a::MSR_TPIDR_EL0_BITS
        {
            return None;
        }
        let decoded = a::decode_instruction(original)?;
        let mut used = [false; 32];
        for operand in &decoded.operands {
            a::mark_operand_registers(operand, &mut used);
        }
        let mut available = (7..=17u8)
            .rev()
            .filter(|r| *r != X16 && !used[usize::from(*r)]);
        let value = available.next()?;
        let anchor = available.next()?;
        let mut spec = Self {
            original,
            metadata: GateMetadata::X18 { scratch: value },
            value,
            anchor,
            transformed: 0,
            entry: 16,
            exit: 16,
            target: None,
            branch: None,
        };
        if let Some(pair) = a::classify_decoded_x18_stack_writeback(original, Some(&decoded)) {
            spec.metadata = GateMetadata::X18StackWriteback { scratch: value };
            // Spill the entire island frame below BOTH pair elements, before
            // even the inbound STP. Post-index accesses start at original SP;
            // the extra depth for a negative post-index delta is conservative.
            let negative = if pair.layout.delta < 0 {
                pair.layout.delta.unsigned_abs()
            } else {
                0
            };
            spec.entry = (16u16 + negative).next_multiple_of(16);
            spec.exit = u16::try_from(i32::from(spec.entry) + i32::from(pair.layout.delta)).ok()?;
            spec.transformed = a::substitute_x18(original, value)?;
        } else if let Some(branch) = a::classify_x18_conditional_branch(Some(&decoded), site) {
            spec.metadata = GateMetadata::X18CompareBranch { scratch: value };
            spec.target = Some(branch.target);
            spec.branch = Some(branch.kind);
        } else if let Some(pc) = a::classify_pc_relative_x18(original, Some(&decoded), site) {
            // ADR materialization borrows x30 after saving out_k; it does not
            // borrow the value/anchor pair used by execute gates.
            spec.metadata = GateMetadata::X18Adr { scratch: X30 };
            spec.target = pc.pc_relative.map(|p| match p {
                X18PcRelative::Adr(t) | X18PcRelative::Adrp(t) => t,
            });
        } else {
            match a::classify_x18_with_decoded(original, Some(&decoded)) {
                X18Classification::Branch(kind) => spec.metadata = GateMetadata::X18Branch { kind },
                X18Classification::X18(X18TransformResult::Supported(_)) => {
                    spec.transformed = a::substitute_x18(original, value)?;
                }
                _ => return None,
            }
        }
        Some(spec)
    }

    pub fn slots(self) -> usize {
        if self.branch.is_some() { 2 } else { 1 }
    }
}

fn x18_access(insn: Insn, host: Host) -> Item {
    if host == Host::MacOs {
        Item::Fixed(insn)
    } else {
        Item::X18Tls(insn)
    }
}

pub(super) fn program(spec: Spec, host: Host) -> Option<Program> {
    let mut items = ProgramItems::new();
    let mut k_literal = None;
    let v = spec.value;
    let a = spec.anchor;
    let access = host.guest_x18_access_offset();
    let mut stage = before(0);
    match spec.metadata {
        GateMetadata::X18Branch { .. } => {
            items.push((
                Item::Fixed(Insn::Brk(super::super::X18_BRANCH_BRK_IMM)),
                stage,
            ));
        }
        GateMetadata::X18Adr { .. } => {
            items.push((Item::LoadK, stage));
            items.push((Item::Fixed(add_reg(X16, X16, X30)), stage));
            items.push((Item::Fixed(Insn::SubSp(16)), stage));
            stage.frame_offset = 16;
            items.push((
                Item::Fixed(Insn::StrUimm {
                    rt: X30,
                    rn: SP,
                    imm_bytes: 0,
                }),
                stage,
            ));
            stage.out_saved = Some(-16);
            items.push((Item::Fixed(Insn::MovReg { rd: X30, rs: X16 }), stage));
            tls_base(&mut items, host, stage);
            items.push((
                x18_access(
                    Insn::StrUimm {
                        rt: X30,
                        rn: X16,
                        imm_bytes: access,
                    },
                    host,
                ),
                stage,
            ));
            stage.phase = IslandPhase::After;
            items.push((
                Item::Fixed(Insn::LdrUimm {
                    rt: X30,
                    rn: SP,
                    imm_bytes: 0,
                }),
                stage,
            ));
            stage.out_saved = None;
            items.push((Item::Fixed(Insn::AddSp(16)), stage));
            stage.frame_offset = 0;
            items.push((Item::Fixed(Insn::Ret(X30)), stage));
            k_literal = Some((items.len() * 4).next_multiple_of(8));
        }
        GateMetadata::X18 { .. }
        | GateMetadata::X18StackWriteback { .. }
        | GateMetadata::X18CompareBranch { .. } => {
            items.push((Item::Fixed(Insn::SubSp(32)), stage));
            stage.frame_offset = 32;
            items.push((
                Item::Fixed(Insn::Stp {
                    rt: v,
                    rt2: a,
                    rn: SP,
                    imm_bytes: 0,
                }),
                stage,
            ));
            stage.scratches_saved = true;
            items.push((
                Item::Fixed(Insn::StrUimm {
                    rt: X30,
                    rn: SP,
                    imm_bytes: 16,
                }),
                stage,
            ));
            stage.out_saved = Some(-16);
            tls_base(&mut items, host, stage);
            items.push((
                x18_access(
                    Insn::LdrUimm {
                        rt: v,
                        rn: X16,
                        imm_bytes: access,
                    },
                    host,
                ),
                stage,
            ));
            if let Some(branch) = spec.branch {
                // Two distinct epilogues make the branch decision explicit in
                // each boundary descriptor (no re-reading a mutable TLS slot).
                let condition = conditional(branch, v, 16);
                items.push((Item::Fixed(condition), stage));
                stage.phase = IslandPhase::After;
                stage.out_saved = None; // x30 still contains primary out_k.
                branch_tail(&mut items, stage, v, a);
                stage.taken = true;
                items.push((
                    Item::Fixed(Insn::AddImm {
                        rd: X30,
                        rn: X30,
                        imm12: u16::try_from(ISLAND_SLOT_BYTES).ok()?,
                    }),
                    stage,
                ));
                branch_tail(&mut items, stage, v, a);
            } else {
                items.push((
                    Item::Fixed(Insn::AddImm {
                        rd: a,
                        rn: SP,
                        imm12: 0,
                    }),
                    stage,
                ));
                items.push((
                    Item::Fixed(Insn::Ldp {
                        rt: X16,
                        rt2: X30,
                        rn: SP,
                        imm_bytes: 32,
                    }),
                    stage,
                ));
                stage.guest_pair_live = true;
                items.push((Item::Fixed(Insn::AddSp(spec.entry + 32)), stage));
                stage.frame_base = a;
                items.push((Item::Raw(spec.transformed), stage));
                // The guest instruction (including memory/flags/SP writeback)
                // has executed. Recovery must finish, not replay, its commit.
                stage.phase = IslandPhase::After;
                stage.pending_x18 = Some(v);
                items.push((
                    Item::Fixed(Insn::AddImm {
                        rd: SP,
                        rn: a,
                        imm12: 0,
                    }),
                    stage,
                ));
                stage.frame_base = SP;
                items.push((
                    Item::Fixed(Insn::Stp {
                        rt: X16,
                        rt2: X30,
                        rn: SP,
                        imm_bytes: 32,
                    }),
                    stage,
                ));
                stage.guest_pair_live = false;
                tls_base(&mut items, host, stage);
                items.push((
                    x18_access(
                        Insn::StrUimm {
                            rt: v,
                            rn: X16,
                            imm_bytes: access,
                        },
                        host,
                    ),
                    stage,
                ));
                stage.pending_x18 = None;
                items.push((
                    Item::Fixed(Insn::LdrUimm {
                        rt: X30,
                        rn: SP,
                        imm_bytes: 16,
                    }),
                    stage,
                ));
                stage.out_saved = None;
                branch_tail(&mut items, stage, v, a);
            }
        }
        _ => return None,
    }
    let literal_end = k_literal.map_or(items.len() * 4, |at| at + 8);
    let slot_size = (literal_end + 8).next_multiple_of(GATE_ALIGNMENT);
    if items.overflow || slot_size > MAX_ISLAND_GATE_BYTES {
        return None;
    }
    Some(Program {
        items,
        k_literal,
        slot_size,
        original: Some(spec.original),
    })
}

fn branch_tail(items: &mut ProgramItems, mut stage: IslandStage, v: u8, a: u8) {
    items.push((
        Item::Fixed(Insn::Ldp {
            rt: v,
            rt2: a,
            rn: SP,
            imm_bytes: 0,
        }),
        stage,
    ));
    stage.scratches_saved = false;
    items.push((Item::Fixed(Insn::AddSp(32)), stage));
    stage.frame_offset = 0;
    items.push((Item::Fixed(Insn::Ret(X30)), stage));
}

fn conditional(kind: X18BranchKind, rt: u8, offset: i64) -> Insn {
    match kind {
        X18BranchKind::CbzW => Insn::CbzW { rt, offset },
        X18BranchKind::CbzX => Insn::CbzX { rt, offset },
        X18BranchKind::CbnzW => Insn::CbnzW { rt, offset },
        X18BranchKind::CbnzX => Insn::CbnzX { rt, offset },
        X18BranchKind::Tbz(bit) => Insn::TestBranch {
            rt,
            bit,
            offset,
            nonzero: false,
        },
        X18BranchKind::Tbnz(bit) => Insn::TestBranch {
            rt,
            bit,
            offset,
            nonzero: true,
        },
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent recovery for the AArch64 rewriter gate ABI.

use crate::PtRegs;
use litebox::utils::TruncateExt as _;
use litebox_syscall_rewriter::TargetHost;
use litebox_syscall_rewriter::aarch64::{
    GATE_ALIGNMENT, GATE_PC_CANDIDATE_COUNT, GATE_SLOT_SIZES, GateMetadata, MSR_FRAME_BYTES,
    MSR_FRAME_OFF_VALUE, MrsTpidrGateOffset, MrsTpidrValueSource, MsrTpidrFrameState,
    MsrTpidrGateOffset, RuntimeAccess, SVC_FRAME_BYTES, SVC_GATE_BYTES, SVC_SLOT_BYTES,
    SvcFrameState, SvcGateOffset, X18_FRAME_BYTES, X18AdrOffset, X18CompareBranchOffset,
    X18FaultAttribution, X18FrameState, X18GateOffset, X18Resume, X18StackWritebackFrameState,
    X18StackWritebackOffset, X18StackWritebackSpSource, X18ValueSource, x18_branch_recovery_plan,
};

// Keep recovered contexts stack-backed: boxing would allocate in a signal handler,
// violating the async-signal-safe contract.
#[allow(clippy::large_enum_variant)]
pub enum Aarch64GateSignalResult {
    NotGate,
    Canonicalized(PtRegs),
    ResumeGuest(PtRegs),
    PreserveSavedContext,
    InvalidRuntimeState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GateInterruption {
    /// A hardware fault attributed to the current gate instruction.
    Synchronous,
    /// A synchronous breakpoint caused by the current gate instruction.
    Breakpoint,
    /// An independently delivered signal interrupting the gate.
    Asynchronous,
}

#[derive(Clone, Copy)]
pub struct GateRuntimeState {
    pub guest_thread_pointer_addr: usize,
    pub expected_outbound_stub: usize,
    pub expected_outbound_pc: usize,
}

fn read_usize(read: &mut impl FnMut(usize, &mut [u8]) -> bool, address: usize) -> Option<usize> {
    let mut bytes = [0u8; size_of::<usize>()];
    read(address, &mut bytes).then(|| usize::from_ne_bytes(bytes))
}

fn recover_x18_frame(
    state: X18FrameState,
    signal_sp: usize,
    read: &mut impl FnMut(usize, &mut [u8]) -> bool,
) -> Option<(usize, Option<[usize; 2]>)> {
    let (frame_sp, restore_registers, pop_frame) = match state {
        X18FrameState::Absent => return Some((signal_sp, None)),
        X18FrameState::AtSpRegistersLive => (signal_sp, false, true),
        X18FrameState::AtSpRestoreRegisters => (signal_sp, true, true),
        X18FrameState::BelowSpRestoreRegisters => {
            let frame_sp = signal_sp.wrapping_sub(usize::from(X18_FRAME_BYTES));
            (frame_sp, true, false)
        }
    };
    let restored = if restore_registers {
        let mut frame = [[0u8; size_of::<usize>()]; 2];
        if !read(frame_sp, frame.as_flattened_mut()) {
            return None;
        }
        Some(frame.map(usize::from_ne_bytes))
    } else {
        None
    };
    let final_sp = if pop_frame {
        frame_sp.wrapping_add(usize::from(X18_FRAME_BYTES))
    } else {
        signal_sp
    };
    Some((final_sp, restored))
}

fn apply_x18_recovery(
    canonical: &mut PtRegs,
    scratch: u8,
    anchor_scratch: u8,
    restored_registers: Option<[usize; 2]>,
    guest_sp: usize,
    guest_x18: usize,
    resume_pc: usize,
) {
    if let Some([saved_scratch, saved_anchor]) = restored_registers {
        canonical.regs[usize::from(scratch)] = saved_scratch;
        canonical.regs[usize::from(anchor_scratch)] = saved_anchor;
    }
    canonical.sp = guest_sp;
    canonical.regs[18] = guest_x18;
    canonical.pc = resume_pc;
}

fn resolve_x18_recovery_pc(
    resume: X18Resume,
    site: usize,
    guest_x18: usize,
    conditional_target: Option<u64>,
) -> Option<usize> {
    Some(match resume {
        X18Resume::Original => site,
        X18Resume::Next => site.wrapping_add(4),
        X18Resume::TakenTarget => conditional_target?.trunc(),
        X18Resume::LogicalX18 => guest_x18,
    })
}

/// Recover an interrupted compact gate from normalized registers and fault-safe reads.
/// Non-gate candidates and invalid runtime state are reported separately.
pub fn canonicalize(
    context: &PtRegs,
    runtime: GateRuntimeState,
    interruption: GateInterruption,
    host: TargetHost,
    virtualize_x18: bool,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    const SVC_FRAME: usize = SVC_FRAME_BYTES as usize;
    const MSR_FRAME: usize = MSR_FRAME_BYTES as usize;
    let pc = context.pc as u64;
    if !pc.is_multiple_of(4) {
        return Aarch64GateSignalResult::NotGate;
    }
    let pc: usize = pc.trunc();

    let aligned = pc & !(GATE_ALIGNMENT - 1);
    let mut found = None;
    for candidate_index in 0..GATE_PC_CANDIDATE_COUNT {
        let Some(slot_start) = aligned.checked_sub(candidate_index * GATE_ALIGNMENT) else {
            continue;
        };
        for slot_size in GATE_SLOT_SIZES {
            let Some(slot_end) = slot_start.checked_add(slot_size) else {
                continue;
            };
            if pc < slot_start || pc >= slot_end {
                continue;
            }
            let mut metadata_bytes = [0u8; 4];
            if !read(slot_end - 4, &mut metadata_bytes) {
                continue;
            }
            let Some(metadata) = litebox_syscall_rewriter::aarch64::decode_gate_metadata_word(
                u32::from_le_bytes(metadata_bytes),
            ) else {
                continue;
            };
            if metadata.slot_size() != slot_size {
                continue;
            }
            let mut slot = [0u8; SVC_SLOT_BYTES];
            if !read(slot_start, &mut slot[..slot_size]) {
                continue;
            }
            // Metadata is guest-controlled. Unvalidated candidates are NotGate,
            // not corrupt runtime state: forged metadata at an arbitrary PC
            // must not cause the runtime to abort. This includes PCs in a real
            // slot's padding or metadata: no prologue ran, so retain the
            // interrupted registers.
            let Some(classified) =
                litebox_syscall_rewriter::aarch64::classify_copied_gate_slot_for_host(
                    &slot[..slot_size],
                    slot_start as u64,
                    pc as u64,
                    host,
                )
            else {
                continue;
            };
            if found.is_some() {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            found = Some((slot_start, classified));
        }
    }
    let Some((slot_start, gate)) = found else {
        return Aarch64GateSignalResult::NotGate;
    };

    // Check the inbound branch before treating unreadable state as a runtime error.
    let site = gate.original_site();
    if !site.is_multiple_of(4) {
        return Aarch64GateSignalResult::NotGate;
    }
    let site: usize = site.trunc();
    let mut original = [0u8; 4];
    if !read(site, &mut original) {
        return Aarch64GateSignalResult::NotGate;
    }
    let original = u32::from_le_bytes(original);
    if litebox_syscall_rewriter::aarch64::decode_branch_target(original, site as u64)
        != Some(slot_start as u64)
    {
        return Aarch64GateSignalResult::NotGate;
    }

    let metadata = gate.metadata();
    if matches!(
        metadata,
        GateMetadata::X18 { .. }
            | GateMetadata::X18StackWriteback { .. }
            | GateMetadata::X18CompareBranch { .. }
            | GateMetadata::X18Adr { .. }
            | GateMetadata::X18Branch { .. }
    ) {
        if !virtualize_x18 {
            return Aarch64GateSignalResult::NotGate;
        }
        if runtime
            .guest_thread_pointer_addr
            .checked_add(litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP)
            .is_none()
        {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        }
    }
    let offset = pc - slot_start;
    if matches!(metadata, GateMetadata::Svc) && offset >= SVC_GATE_BYTES {
        return if runtime.expected_outbound_stub == slot_start + SVC_GATE_BYTES
            && runtime.expected_outbound_pc == site + 4
        {
            Aarch64GateSignalResult::PreserveSavedContext
        } else {
            Aarch64GateSignalResult::NotGate
        };
    }

    let mut canonical = context.clone();
    canonical.pc = site;

    // The caller derived `orig_x0` from the interrupted `regs[0]`, which for
    // `mrs x0, tpidr_el0` is the host anchor. Whatever the arms below repair,
    // re-derive it afterwards rather than exposing a host address to the guest.
    match metadata {
        GateMetadata::MrsTpidr { destination, .. } => {
            let destination = usize::from(destination);
            let Some(stage) = MrsTpidrGateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(recovery) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if recovery.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            match recovery.value {
                MrsTpidrValueSource::Register => {}
                MrsTpidrValueSource::Slot => {
                    let Some(guest_tp) = read_usize(&mut read, runtime.guest_thread_pointer_addr)
                    else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    canonical.regs[destination] = guest_tp;
                }
            }
            if recovery.completed {
                canonical.pc = site + 4;
            }
        }
        GateMetadata::MsrTpidr { source, .. } => {
            let Some(stage) = MsrTpidrGateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(recovery) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if recovery.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let restored = if recovery.frame == MsrTpidrFrameState::RestoreRegisters {
                let mut frame = [[0u8; size_of::<usize>()]; 3];
                if !read(canonical.sp, frame.as_flattened_mut()) {
                    return Aarch64GateSignalResult::NotGate;
                }
                let saved_x16 = usize::from_ne_bytes(frame[0]);
                let saved_x17 = usize::from_ne_bytes(frame[1]);
                let captured = usize::from_ne_bytes(frame[2]);
                let architectural_source = match source {
                    16 => saved_x16,
                    17 => saved_x17,
                    31 => 0,
                    register => canonical.regs[usize::from(register)],
                };
                if captured != architectural_source {
                    return Aarch64GateSignalResult::NotGate;
                }
                Some([saved_x16, saved_x17])
            } else {
                // Before commit, the staged value cheaply checks consistency
                // with the interrupted frame. After LDP, recovery needs neither
                // the frame nor this check.
                if recovery.validate_capture {
                    let Some(captured) = read_usize(
                        &mut read,
                        canonical.sp.wrapping_add(usize::from(MSR_FRAME_OFF_VALUE)),
                    ) else {
                        return Aarch64GateSignalResult::NotGate;
                    };
                    let architectural_source = match source {
                        31 => 0,
                        register => canonical.regs[usize::from(register)],
                    };
                    if captured != architectural_source {
                        return Aarch64GateSignalResult::NotGate;
                    }
                }
                None
            };
            let guest_sp = match recovery.frame {
                MsrTpidrFrameState::Absent => canonical.sp,
                MsrTpidrFrameState::RegistersLive | MsrTpidrFrameState::RestoreRegisters => {
                    canonical.sp.wrapping_add(MSR_FRAME)
                }
            };
            if let Some([saved_x16, saved_x17]) = restored {
                canonical.regs[16] = saved_x16;
                canonical.regs[17] = saved_x17;
            }
            canonical.sp = guest_sp;
            if recovery.completed {
                canonical.pc = site + 4;
            }
        }
        GateMetadata::Svc => {
            let Some(stage) = SvcGateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            // SVC uses a template-fixed literal; supported MRS/MSR execution
            // uses the permanent host anchor read by the gate itself.
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let saved_x16 = match plan.frame {
                SvcFrameState::NoFrame | SvcFrameState::FrameAtSpX16Live => None,
                SvcFrameState::RestoreX16FromFrame => {
                    let Some(saved_x16) = read_usize(&mut read, canonical.sp) else {
                        return Aarch64GateSignalResult::NotGate;
                    };
                    Some(saved_x16)
                }
            };
            let guest_sp = match plan.frame {
                SvcFrameState::NoFrame => canonical.sp,
                SvcFrameState::FrameAtSpX16Live | SvcFrameState::RestoreX16FromFrame => {
                    canonical.sp.wrapping_add(SVC_FRAME)
                }
            };
            if let Some(saved_x16) = saved_x16 {
                canonical.regs[16] = saved_x16;
            }
            canonical.sp = guest_sp;
        }
        GateMetadata::X18 { scratch } => {
            let Some(anchor) = gate.anchor_scratch() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(stage) = X18GateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some((guest_sp, restored_registers)) =
                recover_x18_frame(plan.frame, canonical.sp, &mut read)
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            let guest_x18 = match plan.value {
                X18ValueSource::Scratch => context.regs[usize::from(scratch)].trunc(),
                X18ValueSource::Slot => {
                    let Some(value) = read_usize(
                        &mut read,
                        runtime.guest_thread_pointer_addr
                            + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
                    ) else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    value
                }
            };
            let Some(resume_pc) = resolve_x18_recovery_pc(plan.resume, site, guest_x18, None)
            else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            apply_x18_recovery(
                &mut canonical,
                scratch,
                anchor,
                restored_registers,
                guest_sp,
                guest_x18,
                resume_pc,
            );
        }
        GateMetadata::X18StackWriteback { scratch } => {
            let Some(plan) = X18StackWritebackOffset::from_offset(offset)
                .and_then(X18StackWritebackOffset::recovery_plan)
            else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some((delta, frame_bytes)) = gate.stack_writeback() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if interruption == GateInterruption::Synchronous
                && plan.fault_attribution != X18FaultAttribution::GuestInstruction
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }

            let Some(anchor) = gate.anchor_scratch() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let frame_bytes = usize::from(frame_bytes);
            let frame = match plan.frame {
                X18StackWritebackFrameState::Absent => None,
                X18StackWritebackFrameState::AtSpRegistersLive
                | X18StackWritebackFrameState::AtSpRestoreRegisters
                | X18StackWritebackFrameState::AtSpRegistersRestored => Some(canonical.sp),
                X18StackWritebackFrameState::AtAnchorRestoreRegisters => {
                    Some(context.regs[usize::from(anchor)].trunc())
                }
            };
            let restored = match plan.frame {
                X18StackWritebackFrameState::AtSpRestoreRegisters
                | X18StackWritebackFrameState::AtAnchorRestoreRegisters => {
                    const SCRATCH_REGISTER_COUNT: usize = 2;
                    let mut words = [[0u8; size_of::<usize>()]; SCRATCH_REGISTER_COUNT];
                    let Some(frame) = frame else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    if !read(frame, words.as_flattened_mut()) {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    }
                    Some(words.map(usize::from_ne_bytes))
                }
                X18StackWritebackFrameState::Absent
                | X18StackWritebackFrameState::AtSpRegistersLive
                | X18StackWritebackFrameState::AtSpRegistersRestored => None,
            };
            let guest_sp = match plan.sp {
                X18StackWritebackSpSource::Signal => canonical.sp,
                X18StackWritebackSpSource::FramePlusOriginal => {
                    let Some(frame) = frame else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    frame.wrapping_add(frame_bytes)
                }
                X18StackWritebackSpSource::FramePlusResult => {
                    let Some(frame) = frame else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    frame
                        .wrapping_add(frame_bytes)
                        .wrapping_add_signed(isize::from(delta))
                }
            };
            let guest_x18 = match plan.value {
                X18ValueSource::Scratch => context.regs[usize::from(scratch)].trunc(),
                X18ValueSource::Slot => {
                    let Some(value) = read_usize(
                        &mut read,
                        runtime.guest_thread_pointer_addr
                            + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
                    ) else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    value
                }
            };
            let Some(resume_pc) = resolve_x18_recovery_pc(plan.resume, site, guest_x18, None)
            else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            apply_x18_recovery(
                &mut canonical,
                scratch,
                anchor,
                restored,
                guest_sp,
                guest_x18,
                resume_pc,
            );
        }
        GateMetadata::X18CompareBranch { scratch } => {
            let Some(anchor) = gate.anchor_scratch() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(stage) = X18CompareBranchOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some((guest_sp, restored_registers)) =
                recover_x18_frame(plan.frame, canonical.sp, &mut read)
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            let Some(guest_x18) = read_usize(
                &mut read,
                runtime.guest_thread_pointer_addr
                    + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
            ) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(resume_pc) =
                resolve_x18_recovery_pc(plan.resume, site, guest_x18, gate.conditional_target())
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            apply_x18_recovery(
                &mut canonical,
                scratch,
                anchor,
                restored_registers,
                guest_sp,
                guest_x18,
                resume_pc,
            );
        }
        GateMetadata::X18Adr { scratch } => {
            let Some(anchor) = gate.anchor_scratch() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(stage) = X18AdrOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some((guest_sp, restored_registers)) =
                recover_x18_frame(plan.frame, canonical.sp, &mut read)
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            let guest_x18 = match plan.value {
                X18ValueSource::Scratch => context.regs[usize::from(scratch)].trunc(),
                X18ValueSource::Slot => {
                    let Some(value) = read_usize(
                        &mut read,
                        runtime.guest_thread_pointer_addr
                            + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
                    ) else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    value
                }
            };
            let Some(resume_pc) = resolve_x18_recovery_pc(plan.resume, site, guest_x18, None)
            else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            apply_x18_recovery(
                &mut canonical,
                scratch,
                anchor,
                restored_registers,
                guest_sp,
                guest_x18,
                resume_pc,
            );
        }
        GateMetadata::X18Branch { kind } => {
            let Some(plan) = x18_branch_recovery_plan(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.frame != X18FrameState::Absent
                || plan.value != X18ValueSource::Slot
                || plan.resume != X18Resume::LogicalX18
                || plan.runtime_access != RuntimeAccess::NoAccess
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some(guest_x18) = read_usize(
                &mut read,
                runtime.guest_thread_pointer_addr
                    + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
            ) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            canonical.regs[18] = guest_x18;
            if interruption == GateInterruption::Breakpoint {
                if kind.writes_link_register() {
                    canonical.regs[30] = site.wrapping_add(4);
                }
                let Some(resume_pc) = resolve_x18_recovery_pc(plan.resume, site, guest_x18, None)
                else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                canonical.pc = resume_pc;
                canonical.orig_x0 = canonical.regs[0];
                return Aarch64GateSignalResult::ResumeGuest(canonical);
            }
        }
    }
    canonical.orig_x0 = canonical.regs[0];
    Aarch64GateSignalResult::Canonicalized(canonical)
}

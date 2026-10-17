// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent recovery of interrupted AArch64 gates.
//!
//! Platforms retain their OS context types and supply only x0-x30, SP and PC.
//! Recovery modifies working registers; discard them unless recovery succeeds.

use crate::TargetHost;
use crate::{
    aarch64, aarch64::Frame, aarch64::FrameBase, aarch64::GATE_ALIGNMENT,
    aarch64::GATE_PC_CANDIDATE_COUNT, aarch64::GATE_SLOT_SIZES, aarch64::GateMetadata,
    aarch64::GuestSp, aarch64::MAX_GATE_SLOT_BYTES, aarch64::MSR_FRAME_BYTES,
    aarch64::MSR_FRAME_OFF_VALUE, aarch64::Resume, aarch64::SVC_FRAME_BYTES,
    aarch64::SVC_GATE_BYTES, aarch64::Stage, aarch64::Value, aarch64::X18_FRAME_BYTES,
};

// Keep recovered contexts stack-backed: boxing would allocate in a signal handler,
// violating the async-signal-safe contract.
/// Recovery outcome. The core returns unit payloads; platforms can attach
/// their own saved-context type to successful outcomes with [`Self::map`].
#[allow(clippy::large_enum_variant)]
pub enum Aarch64GateSignalResult<Context = ()> {
    NotGate,
    Canonicalized(Context),
    ResumeGuest(Context),
    PreserveSavedContext,
    InvalidRuntimeState,
}

impl<Context> Aarch64GateSignalResult<Context> {
    /// Attach a platform context to successful recovery without changing the outcome.
    pub fn map<T>(self, context: impl FnOnce(Context) -> T) -> Aarch64GateSignalResult<T> {
        match self {
            Self::NotGate => Aarch64GateSignalResult::NotGate,
            Self::Canonicalized(value) => Aarch64GateSignalResult::Canonicalized(context(value)),
            Self::ResumeGuest(value) => Aarch64GateSignalResult::ResumeGuest(context(value)),
            Self::PreserveSavedContext => Aarch64GateSignalResult::PreserveSavedContext,
            Self::InvalidRuntimeState => Aarch64GateSignalResult::InvalidRuntimeState,
        }
    }
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

/// The guest ABI determines which host and register-virtualization options
/// apply. Darwin gates always target macOS and do not virtualize x18.
#[derive(Clone, Copy)]
pub enum GateAbi {
    Linux {
        host: TargetHost,
        virtualize_x18: bool,
    },
    Darwin,
}

/// Recover a gate using working architectural registers and fault-safe reads.
///
/// Registers may be modified on failure. Publish the working context only for
/// `Canonicalized` or `ResumeGuest`; other outcomes must retain the original.
/// Platform-specific bookkeeping such as Linux `orig_x0` is not handled here.
pub fn canonicalize(
    regs: &mut [usize; 31],
    guest_sp: &mut usize,
    guest_pc: &mut usize,
    runtime: GateRuntimeState,
    interruption: GateInterruption,
    abi: GateAbi,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    let (host, virtualize_x18, svc_frame) = match abi {
        GateAbi::Linux {
            host,
            virtualize_x18,
        } => (host, virtualize_x18, SVC_FRAME_BYTES),
        GateAbi::Darwin => (
            TargetHost::MacOs,
            false,
            crate::aarch64::DARWIN_SVC_FRAME_BYTES,
        ),
    };
    let svc_frame = usize::from(svc_frame);
    let pc = *guest_pc as u64;
    let original_sp = *guest_sp;
    if !pc.is_multiple_of(4) {
        return Aarch64GateSignalResult::NotGate;
    }
    let pc = *guest_pc;

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
            let Some(metadata) =
                crate::aarch64::decode_gate_metadata_word(u32::from_le_bytes(metadata_bytes))
            else {
                continue;
            };
            if metadata.slot_size_for_host(host) != slot_size {
                continue;
            }
            let mut slot = [0u8; MAX_GATE_SLOT_BYTES];
            if !read(slot_start, &mut slot[..slot_size]) {
                continue;
            }
            // Metadata is guest-controlled. Unvalidated candidates are NotGate,
            // not corrupt runtime state: forged metadata at an arbitrary PC
            // must not cause the runtime to abort. This includes PCs in a real
            // slot's padding or metadata: no prologue ran, so retain the
            // interrupted registers.
            let classified = match abi {
                GateAbi::Darwin => aarch64::classify_copied_gate_slot_with_layout(
                    &slot[..slot_size],
                    slot_start as u64,
                    pc as u64,
                    aarch64::GateLayout::darwin(host),
                ),
                GateAbi::Linux { .. } => crate::aarch64::classify_copied_gate_slot_for_host(
                    &slot[..slot_size],
                    slot_start as u64,
                    pc as u64,
                    host,
                ),
            };
            let Some(classified) = classified else {
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
    let Ok(site) = usize::try_from(site) else {
        return Aarch64GateSignalResult::NotGate;
    };
    let mut original = [0u8; 4];
    if !read(site, &mut original) {
        return Aarch64GateSignalResult::NotGate;
    }
    let original = u32::from_le_bytes(original);
    if crate::aarch64::decode_branch_target(original, site as u64) != Some(slot_start as u64) {
        return Aarch64GateSignalResult::NotGate;
    }

    let metadata = gate.metadata();
    let is_x18 = aarch64::is_x18_gate(metadata);
    let guest_x18_addr = runtime
        .guest_thread_pointer_addr
        .checked_add(aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP);
    if is_x18 {
        if !virtualize_x18 {
            return Aarch64GateSignalResult::NotGate;
        }
        if guest_x18_addr.is_none() {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        }
    }
    let boundary = match gate.stage() {
        Stage::Recover(boundary) => boundary,
        Stage::Invalid => return Aarch64GateSignalResult::InvalidRuntimeState,
        Stage::SvcOutbound => {
            return if runtime.expected_outbound_stub == slot_start + SVC_GATE_BYTES
                && runtime.expected_outbound_pc == site + 4
            {
                Aarch64GateSignalResult::PreserveSavedContext
            } else {
                Aarch64GateSignalResult::NotGate
            };
        }
    };
    if boundary.runtime_fault && interruption == GateInterruption::Synchronous {
        return Aarch64GateSignalResult::InvalidRuntimeState;
    }

    // The gate's frame layout: its size, the registers it saves (in frame
    // order), and the register receiving the virtualized value.
    let anchor = gate.anchor_scratch();
    let mut stack_delta = 0;
    let mut staged_source = None;
    let (frame_bytes, saved, value_register): (usize, [Option<u8>; 2], Option<u8>) = match metadata
    {
        GateMetadata::Svc => (svc_frame, [Some(16), None], None),
        GateMetadata::MsrTpidr { source } => {
            staged_source = boundary.check_capture.then_some(source);
            (MSR_FRAME_BYTES.into(), [Some(16), Some(17)], None)
        }
        GateMetadata::MrsTpidr { destination }
        | GateMetadata::HostAwareMrsTpidr { destination } => (0, [None, None], Some(destination)),
        GateMetadata::X18StackWriteback { scratch } => {
            let Some((delta, frame_bytes)) = gate.stack_writeback() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            stack_delta = delta;
            (frame_bytes.into(), [Some(scratch), anchor], Some(18))
        }
        GateMetadata::X18 { scratch }
        | GateMetadata::X18CompareBranch { scratch }
        | GateMetadata::X18Adr { scratch } => {
            (X18_FRAME_BYTES.into(), [Some(scratch), anchor], Some(18))
        }
        GateMetadata::X18Branch { .. } => (0, [None, None], Some(18)),
    };
    // The SP-writeback frame is part of the runtime's displacement-aware
    // protocol; elsewhere an unreadable frame means the guest's stack is bad.
    let unreadable_frame = if matches!(metadata, GateMetadata::X18StackWriteback { .. }) {
        Aarch64GateSignalResult::InvalidRuntimeState
    } else {
        Aarch64GateSignalResult::NotGate
    };

    let scratch_value = match (boundary.value, saved) {
        (Value::Scratch, [Some(scratch), _]) => Some(regs[usize::from(scratch)]),
        _ => None,
    };
    let base = match boundary.frame {
        Frame::None => None,
        Frame::Live(base) | Frame::Restore(base) => Some(match base {
            FrameBase::Sp => original_sp,
            FrameBase::BelowSp => original_sp.wrapping_sub(frame_bytes),
            FrameBase::Anchor => {
                let Some(anchor) = anchor else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                regs[usize::from(anchor)]
            }
        }),
    };
    // Saved registers occupy the frame's leading words, followed by the MSR
    // gate's staged source. Read everything recovery needs with one access.
    let restore = matches!(boundary.frame, Frame::Restore(_));
    let saved_count = saved.iter().flatten().count();
    let mut frame = [0usize; 3];
    let (first, count) = match (restore, staged_source.is_some()) {
        (true, true) => (0, saved_count + 1),
        (true, false) => (0, saved_count),
        (false, true) => (usize::from(MSR_FRAME_OFF_VALUE) / size_of::<usize>(), 1),
        (false, false) => (0, 0),
    };
    if count != 0 {
        let Some(base) = base else {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        };
        let mut bytes = [[0u8; size_of::<usize>()]; 3];
        if !read(
            base.wrapping_add(first * size_of::<usize>()),
            bytes[..count].as_flattened_mut(),
        ) {
            return if restore {
                unreadable_frame
            } else {
                Aarch64GateSignalResult::NotGate
            };
        }
        for (index, word) in bytes[..count].iter().enumerate() {
            frame[first + index] = usize::from_ne_bytes(*word);
        }
    }
    if restore {
        for (register, value) in saved.iter().zip(frame) {
            if let Some(register) = register {
                regs[usize::from(*register)] = value;
            }
        }
    }
    if let Some(source) = staged_source {
        // The MSR gate staged its source before touching any register, so the
        // staged copy must equal the architectural source.
        let architectural = match source {
            31 => 0,
            register => regs[usize::from(register)],
        };
        if frame[usize::from(MSR_FRAME_OFF_VALUE) / size_of::<usize>()] != architectural {
            return Aarch64GateSignalResult::NotGate;
        }
    }
    *guest_sp = match (boundary.sp, base) {
        (GuestSp::Signal, _) => original_sp,
        (GuestSp::FrameEnd, Some(base)) => base.wrapping_add(frame_bytes),
        (GuestSp::FrameEndPlusDelta, Some(base)) => base
            .wrapping_add(frame_bytes)
            .wrapping_add_signed(isize::from(stack_delta)),
        (GuestSp::FrameEnd | GuestSp::FrameEndPlusDelta, None) => {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        }
    };

    let value = match boundary.value {
        Value::None => None,
        Value::Scratch => {
            let Some(value) = scratch_value else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            Some(value)
        }
        Value::Slot => {
            let slot = if is_x18 {
                guest_x18_addr
            } else {
                Some(runtime.guest_thread_pointer_addr)
            };
            let Some(slot) = slot else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let mut bytes = [0u8; size_of::<usize>()];
            if !read(slot, &mut bytes) {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            Some(usize::from_ne_bytes(bytes))
        }
    };
    if let (Some(register), Some(value)) = (value_register, value) {
        regs[usize::from(register)] = value;
    }

    *guest_pc = match boundary.resume {
        Resume::Site => site,
        Resume::Next => site.wrapping_add(4),
        Resume::Taken => {
            let Some(target) = gate
                .conditional_target()
                .and_then(|target| usize::try_from(target).ok())
            else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            target
        }
        Resume::LogicalX18 => {
            // An indirect branch through x18 is emulated at its breakpoint;
            // any other interruption reports the untaken branch.
            if interruption == GateInterruption::Breakpoint {
                let (GateMetadata::X18Branch { kind }, Some(target)) = (metadata, value) else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                if kind.writes_link_register() {
                    regs[30] = site.wrapping_add(4);
                }
                *guest_pc = target;
                return Aarch64GateSignalResult::ResumeGuest(());
            } else {
                site
            }
        }
    };
    Aarch64GateSignalResult::Canonicalized(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{self, GateLayout, gate};
    use alloc::vec::Vec;

    const SITE: usize = 0x1000_0000;
    const TRAMPOLINE: usize = 0x1000_4000;

    fn darwin_gate(metadata: GateMetadata) -> ([u8; 4], Vec<u8>) {
        let mut gates = Vec::new();
        aarch64::emit_shared_prologue(&mut gates, 0x1234);
        gate::build(
            &gate::GateInstance::new(metadata, (SITE + 4) as u64),
            GateLayout::darwin(TargetHost::MacOs),
            (TRAMPOLINE + 16) as u64,
            TRAMPOLINE as u64,
        )
        .unwrap()
        .append_to(&mut gates);
        aarch64::finalize_macho_trampoline(&mut gates, 96, TargetHost::MacOs).unwrap();
        let branch = aarch64::Insn::B(i64::try_from(TRAMPOLINE + 16 - SITE).unwrap())
            .encode()
            .unwrap();
        (branch.to_le_bytes(), gates)
    }

    #[test]
    fn host_aware_mrs_recovery_canonicalizes_middle_stages() {
        const GUEST_TP_SLOT: usize = 0x2000_0000;
        const GUEST_TP: usize = 0xfeed_1234;
        const DESTINATION: usize = 9;
        let (code, gates) = darwin_gate(GateMetadata::HostAwareMrsTpidr {
            destination: u8::try_from(DESTINATION).unwrap(),
        });
        let guest_tp = GUEST_TP.to_ne_bytes();
        let read = |address: usize, output: &mut [u8]| {
            for (base, bytes) in [
                (SITE, code.as_slice()),
                (TRAMPOLINE, gates.as_slice()),
                (GUEST_TP_SLOT, guest_tp.as_slice()),
            ] {
                if let Some(offset) = address.checked_sub(base)
                    && let Some(end) = offset.checked_add(output.len())
                    && let Some(source) = bytes.get(offset..end)
                {
                    output.copy_from_slice(source);
                    return true;
                }
            }
            false
        };
        let runtime = GateRuntimeState {
            guest_thread_pointer_addr: GUEST_TP_SLOT,
            expected_outbound_stub: 0,
            expected_outbound_pc: 0,
        };
        for offset in [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48] {
            let mut regs = [0; 31];
            let mut sp = 0;
            let mut pc = TRAMPOLINE + 16 + offset;
            regs[DESTINATION] = if offset >= 40 { GUEST_TP } else { 0xdead };
            assert!(
                matches!(
                    canonicalize(
                        &mut regs,
                        &mut sp,
                        &mut pc,
                        runtime,
                        GateInterruption::Asynchronous,
                        GateAbi::Darwin,
                        read,
                    ),
                    Aarch64GateSignalResult::Canonicalized(())
                ),
                "Darwin MRS recovery failed at offset {offset}"
            );
            assert_eq!(pc, SITE + 4);
            assert_eq!(regs[DESTINATION], GUEST_TP);
        }
    }

    #[test]
    fn darwin_svc_recovery_uses_the_real_gate_and_red_zone_frame() {
        const STACK: usize = 0x2000_0000;
        const GUEST_SP: usize = STACK + aarch64::DARWIN_SVC_FRAME_BYTES as usize;
        let (code, gates) = darwin_gate(GateMetadata::Svc);
        let mut frame = [0u8; aarch64::DARWIN_SVC_FRAME_BYTES as usize];
        frame[..8].copy_from_slice(&20usize.to_ne_bytes());
        let read = |address: usize, output: &mut [u8]| {
            for (base, bytes) in [
                (SITE, code.as_slice()),
                (TRAMPOLINE, gates.as_slice()),
                (STACK, frame.as_slice()),
            ] {
                if let Some(offset) = address.checked_sub(base)
                    && let Some(end) = offset.checked_add(output.len())
                    && let Some(source) = bytes.get(offset..end)
                {
                    output.copy_from_slice(source);
                    return true;
                }
            }
            false
        };
        let runtime = GateRuntimeState {
            guest_thread_pointer_addr: 0x3000_0000,
            expected_outbound_stub: 0,
            expected_outbound_pc: 0,
        };
        for (offset, interrupted_sp, x16) in [
            (0, GUEST_SP, 20),
            (4, STACK, 20),
            (12, STACK, 0xfeed),
            (32, STACK, 0x1234),
        ] {
            let mut regs = [0; 31];
            regs[0] = 77;
            regs[16] = x16;
            let mut sp = interrupted_sp;
            let mut pc = TRAMPOLINE + 16 + offset;
            let mut linux_regs = regs;
            let mut linux_sp = sp;
            let mut linux_pc = pc;
            assert!(
                matches!(
                    canonicalize(
                        &mut regs,
                        &mut sp,
                        &mut pc,
                        runtime,
                        GateInterruption::Asynchronous,
                        GateAbi::Darwin,
                        read,
                    ),
                    Aarch64GateSignalResult::Canonicalized(())
                ),
                "Darwin recovery failed at offset {offset}"
            );
            assert_eq!(pc, SITE);
            assert_eq!(sp, GUEST_SP);
            assert_eq!(regs[16], 20);
            assert_eq!(regs[0], 77);
            assert!(matches!(
                canonicalize(
                    &mut linux_regs,
                    &mut linux_sp,
                    &mut linux_pc,
                    runtime,
                    GateInterruption::Asynchronous,
                    GateAbi::Linux {
                        host: TargetHost::MacOs,
                        virtualize_x18: true
                    },
                    read,
                ),
                Aarch64GateSignalResult::NotGate
            ));
        }
    }

    #[test]
    fn context_mapping_only_runs_for_successful_recovery() {
        assert!(matches!(
            Aarch64GateSignalResult::Canonicalized(()).map(|()| 42),
            Aarch64GateSignalResult::Canonicalized(42)
        ));
        assert!(matches!(
            Aarch64GateSignalResult::ResumeGuest(()).map(|()| 43),
            Aarch64GateSignalResult::ResumeGuest(43)
        ));
        for result in [
            Aarch64GateSignalResult::NotGate,
            Aarch64GateSignalResult::PreserveSavedContext,
            Aarch64GateSignalResult::InvalidRuntimeState,
        ] {
            let _: Aarch64GateSignalResult<()> =
                result.map(|()| panic!("failure mapped a context"));
        }
    }
}

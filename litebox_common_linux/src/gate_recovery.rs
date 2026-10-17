// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent recovery for the AArch64 rewriter gate ABI.

// TODO: Move shared AArch64 gate recovery and register-context types into an
// OS-neutral module/crate: both Linux and native Darwin guests use them.

use crate::PtRegs;
use litebox::utils::TruncateExt as _;
use litebox_syscall_rewriter::TargetHost;
use litebox_syscall_rewriter::aarch64::{
    self, Frame, FrameBase, GATE_ALIGNMENT, GATE_PC_CANDIDATE_COUNT, GATE_SLOT_SIZES, GateMetadata,
    GuestSp, MAX_GATE_SLOT_BYTES, MSR_FRAME_BYTES, MSR_FRAME_OFF_VALUE, Resume, SVC_FRAME_BYTES,
    SVC_GATE_BYTES, Stage, Value, X18_FRAME_BYTES,
};

// Keep recovered contexts stack-backed: boxing would allocate in a signal handler,
// violating the async-signal-safe contract.
#[allow(clippy::large_enum_variant)]
pub enum Aarch64GateSignalResult {
    NotGate,
    Canonicalized(PtRegs),
    ResumeGuest(PtRegs),
    /// Consume an in-place MSR breakpoint. The platform commits `value` to its
    /// own thread's guest-TP slot, then resumes `context` without delivering the
    /// private breakpoint as a guest signal.
    WriteThreadPointer {
        context: PtRegs,
        value: usize,
    },
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

/// The guest ABI determines which host and register-virtualization options
/// apply. Darwin gates always target macOS and do not virtualize x18.
#[derive(Clone, Copy)]
enum GateAbi {
    Linux {
        host: TargetHost,
        virtualize_x18: bool,
    },
    Darwin,
}

/// Recover an interrupted compact gate from normalized registers and fault-safe reads.
/// Non-gate candidates and invalid runtime state are reported separately.
pub fn canonicalize(
    context: &PtRegs,
    runtime: GateRuntimeState,
    interruption: GateInterruption,
    host: TargetHost,
    virtualize_x18: bool,
    read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    canonicalize_impl(
        context,
        runtime,
        interruption,
        GateAbi::Linux {
            host,
            virtualize_x18,
        },
        read,
    )
}

/// Recover interrupted Darwin Mach-O gates using the macOS host ABI and
/// Darwin's red-zone-preserving frame layout.
pub fn canonicalize_darwin(
    context: &PtRegs,
    runtime: GateRuntimeState,
    interruption: GateInterruption,
    read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    canonicalize_impl(context, runtime, interruption, GateAbi::Darwin, read)
}

fn canonicalize_impl(
    context: &PtRegs,
    runtime: GateRuntimeState,
    interruption: GateInterruption,
    abi: GateAbi,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    // An asynchronous interruption at this instruction must leave it pending.
    // Only the actual private breakpoint commits the logical MSR. This path
    // needs no guest-stack access, and does not apply to native Darwin guests.
    if matches!(abi, GateAbi::Linux { .. }) && interruption == GateInterruption::Breakpoint {
        let mut instruction = [0u8; 4];
        if read(context.pc, &mut instruction)
            && let Some(source) = aarch64::decode_msr_tpidr_trap(u32::from_le_bytes(instruction))
        {
            let value = match source {
                31 => 0,
                18 if matches!(
                    abi,
                    GateAbi::Linux {
                        virtualize_x18: true,
                        ..
                    }
                ) =>
                {
                    let Some(value) = runtime
                        .guest_thread_pointer_addr
                        .checked_add(aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP)
                        .and_then(|address| read_usize(&mut read, address))
                    else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    value
                }
                register => context.regs[usize::from(register)],
            };
            let mut resumed = context.clone();
            resumed.pc = context.pc.wrapping_add(4);
            resumed.orig_x0 = resumed.regs[0];
            return Aarch64GateSignalResult::WriteThreadPointer {
                context: resumed,
                value,
            };
        }
    }
    let (host, virtualize_x18, svc_frame) = match abi {
        GateAbi::Linux {
            host,
            virtualize_x18,
        } => (host, virtualize_x18, SVC_FRAME_BYTES),
        GateAbi::Darwin => (
            TargetHost::MacOs,
            false,
            litebox_syscall_rewriter::aarch64::DARWIN_SVC_FRAME_BYTES,
        ),
    };
    let svc_frame = usize::from(svc_frame);
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
                GateAbi::Darwin => litebox_syscall_rewriter::macho::Rewriter::new(host)
                    .ok()
                    .and_then(|rewriter| {
                        rewriter.classify_gate_slot(
                            &slot[..slot_size],
                            slot_start as u64,
                            pc as u64,
                        )
                    }),
                GateAbi::Linux { .. } => {
                    litebox_syscall_rewriter::aarch64::classify_copied_gate_slot_for_host(
                        &slot[..slot_size],
                        slot_start as u64,
                        pc as u64,
                        host,
                    )
                }
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
        Stage::SvcTlsOutbound(boundary) => {
            if runtime.expected_outbound_stub != slot_start + SVC_GATE_BYTES
                || runtime.expected_outbound_pc != site + 4
            {
                return Aarch64GateSignalResult::NotGate;
            }
            boundary
        }
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
    let (frame_bytes, saved, value_register): (usize, [Option<u8>; 2], Option<u8>) = match metadata
    {
        GateMetadata::Svc => (svc_frame, [Some(16), None], None),
        GateMetadata::SvcTls => (svc_frame, [Some(16), None], Some(16)),
        GateMetadata::MsrTpidr { .. } => (MSR_FRAME_BYTES.into(), [Some(16), Some(17)], None),
        GateMetadata::MrsTpidr { destination }
        | GateMetadata::HostAwareMrsTpidr { destination } => (0, [None, None], Some(destination)),
        GateMetadata::X18StackWriteback { scratch } => {
            let Some((_, frame_bytes)) = gate.stack_writeback() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
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

    let mut canonical = context.clone();
    let base = match boundary.frame {
        Frame::None => None,
        Frame::Live(base) | Frame::Restore(base) => Some(match base {
            FrameBase::Sp => context.sp,
            FrameBase::BelowSp => context.sp.wrapping_sub(frame_bytes),
            FrameBase::Anchor => {
                let Some(anchor) = anchor else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                context.regs[usize::from(anchor)].trunc()
            }
        }),
    };
    // Saved registers occupy the frame's leading words, followed by the MSR
    // gate's staged source. Read everything recovery needs with one access.
    let restore = matches!(boundary.frame, Frame::Restore(_));
    let saved_count = saved.iter().flatten().count();
    let staged = boundary.check_capture && matches!(metadata, GateMetadata::MsrTpidr { .. });
    let mut frame = [0usize; 3];
    let (first, count) = match (restore, staged) {
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
                canonical.regs[usize::from(*register)] = value;
            }
        }
    }
    if boundary.check_capture {
        // The MSR gate staged its source before touching any register, so the
        // staged copy must equal the architectural source.
        let GateMetadata::MsrTpidr { source } = metadata else {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        };
        let architectural = match source {
            31 => 0,
            register => canonical.regs[usize::from(register)],
        };
        if frame[usize::from(MSR_FRAME_OFF_VALUE) / size_of::<usize>()] != architectural {
            return Aarch64GateSignalResult::NotGate;
        }
    }
    canonical.sp = match (boundary.sp, base) {
        (GuestSp::Signal, _) => context.sp,
        (GuestSp::FrameEnd, Some(base)) => base.wrapping_add(frame_bytes),
        (GuestSp::FrameEndPlusDelta, Some(base)) => {
            let Some((delta, _)) = gate.stack_writeback() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            base.wrapping_add(frame_bytes)
                .wrapping_add_signed(isize::from(delta))
        }
        (GuestSp::FrameEnd | GuestSp::FrameEndPlusDelta, None) => {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        }
    };

    let value = match boundary.value {
        Value::None => None,
        Value::Scratch => {
            let [Some(scratch), _] = saved else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            Some(context.regs[usize::from(scratch)].trunc())
        }
        Value::Slot => {
            let slot = if is_x18 {
                guest_x18_addr
            } else if metadata == GateMetadata::SvcTls {
                runtime
                    .guest_thread_pointer_addr
                    .checked_add(aarch64::SVC_X16_OFFSET_FROM_GUEST_TP.into())
            } else {
                Some(runtime.guest_thread_pointer_addr)
            };
            let Some(value) = slot.and_then(|slot| read_usize(&mut read, slot)) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            Some(value)
        }
    };
    if let (Some(register), Some(value)) = (value_register, value) {
        canonical.regs[usize::from(register)] = value;
    }

    canonical.pc = match boundary.resume {
        Resume::Site => site,
        Resume::Next => site.wrapping_add(4),
        Resume::Taken => {
            let Some(target) = gate.conditional_target() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            target.trunc()
        }
        Resume::LogicalX18 => {
            // An indirect branch through x18 is emulated at its breakpoint;
            // any other interruption reports the untaken branch.
            if interruption == GateInterruption::Breakpoint {
                let (GateMetadata::X18Branch { kind }, Some(target)) = (metadata, value) else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                if kind.writes_link_register() {
                    canonical.regs[30] = site.wrapping_add(4);
                }
                canonical.pc = target;
                canonical.orig_x0 = canonical.regs[0];
                return Aarch64GateSignalResult::ResumeGuest(canonical);
            } else {
                site
            }
        }
    };
    // The caller derived `orig_x0` from the interrupted `regs[0]`, which for
    // `mrs x0, tpidr_el0` is the host anchor. Re-derive it from the repaired
    // registers rather than exposing a host address to the guest.
    canonical.orig_x0 = canonical.regs[0];
    Aarch64GateSignalResult::Canonicalized(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_syscall_rewriter::{aarch64::DARWIN_SVC_FRAME_BYTES, macho::Rewriter};

    #[test]
    #[expect(clippy::single_range_in_vec_init, reason = "one executable code range")]
    fn tls_outbound_stubs_recover_without_reading_the_guest_stack() {
        const SITE: usize = 0x7f00_0000_1000;
        const TRAMP: usize = SITE + 0x4000;
        const TLS: usize = 0x5000;
        const SP: usize = 0x9000;
        const X16: usize = 0x1616_1234;
        for (host, darwin) in [
            (TargetHost::Linux, false),
            (TargetHost::MacOs, false),
            (TargetHost::MacOs, true),
        ] {
            let mut code = if darwin { 0xd4001001u32 } else { 0xd4000001 }.to_le_bytes();
            let (mut gates, trapped) = if darwin {
                Rewriter::new(host)
                    .unwrap()
                    .patch_code_segment(&mut code, SITE as u64, &[0..4], TRAMP as u64, 0x1234, 96)
                    .unwrap()
            } else {
                litebox_syscall_rewriter::patch_code_segment_with_options(
                    &mut code,
                    SITE as u64,
                    TRAMP as u64,
                    0x1234,
                    litebox_syscall_rewriter::RewriteOptions::new(host, false),
                )
                .unwrap()
            };
            assert_eq!(trapped, []);
            if !darwin {
                aarch64::finalize_trampoline_gates_for_host(&mut gates, 96, 104, host).unwrap();
            }
            let runtime = GateRuntimeState {
                guest_thread_pointer_addr: TLS,
                expected_outbound_stub: TRAMP + 16 + SVC_GATE_BYTES,
                expected_outbound_pc: SITE + 4,
            };
            let saved_x16 = X16.to_ne_bytes();
            let read = |address: usize, output: &mut [u8]| {
                for (base, bytes) in [
                    (SITE, code.as_slice()),
                    (TRAMP, gates.as_slice()),
                    (
                        TLS + usize::from(aarch64::SVC_X16_OFFSET_FROM_GUEST_TP),
                        saved_x16.as_slice(),
                    ),
                ] {
                    if let Some(start) = address.checked_sub(base)
                        && let Some(end) = start.checked_add(output.len())
                        && let Some(source) = bytes.get(start..end)
                    {
                        output.copy_from_slice(source);
                        return true;
                    }
                }
                false // No guest-stack mapping is supplied.
            };
            let pop = if host == TargetHost::MacOs { 52 } else { 44 };
            let frame = if darwin {
                DARWIN_SVC_FRAME_BYTES
            } else {
                SVC_FRAME_BYTES
            } as usize;
            for offset in (SVC_GATE_BYTES..=pop + 4).step_by(4) {
                let mut ctx = PtRegs {
                    pc: TRAMP + 16 + offset,
                    sp: if offset > pop { SP } else { SP - frame },
                    pstate: 0xa0000000,
                    ..PtRegs::default()
                };
                ctx.regs[16] = if offset < pop { 0xdeadbeef } else { X16 };
                ctx.regs[17] = 0x1717;
                let result = if darwin {
                    canonicalize_darwin(&ctx, runtime, GateInterruption::Asynchronous, read)
                } else {
                    canonicalize(
                        &ctx,
                        runtime,
                        GateInterruption::Asynchronous,
                        host,
                        false,
                        read,
                    )
                };
                let Aarch64GateSignalResult::Canonicalized(recovered) = result else {
                    panic!("{host:?} Darwin={darwin} outbound +{offset}")
                };
                assert_eq!(recovered.pc, SITE + 4);
                assert_eq!(recovered.sp, SP);
                assert_eq!(recovered.regs[16], X16);
                assert_eq!(recovered.regs[17], ctx.regs[17]);
                assert_eq!(recovered.pstate, ctx.pstate);
            }
        }
    }

    #[test]
    fn msr_breakpoints_preserve_registers_and_commit_only_on_breakpoint() {
        const SITE: usize = 0x7f00_0000_1000;
        const TLS: usize = 0x2000;
        const LOGICAL_X18: usize = 0x1818_1234;
        let runtime = GateRuntimeState {
            guest_thread_pointer_addr: TLS,
            expected_outbound_stub: 0,
            expected_outbound_pc: 0,
        };
        for (host, virtualize_x18) in [
            (TargetHost::Linux, false),
            (TargetHost::Linux, true),
            (TargetHost::MacOs, true),
        ] {
            for source in 0..32u32 {
                let mut code = (0xd51b_d040 | source).to_le_bytes();
                let (_, unpatched) = litebox_syscall_rewriter::patch_code_segment_with_options(
                    &mut code,
                    SITE as u64,
                    0x7f00_0000_4000,
                    0,
                    litebox_syscall_rewriter::RewriteOptions::new(host, virtualize_x18),
                )
                .unwrap();
                assert_eq!(unpatched, []);
                let saved = PtRegs {
                    regs: core::array::from_fn(|index| 0x1000 + index),
                    pc: SITE,
                    sp: 0, // no guest-stack access is allowed
                    pstate: 0xa000_0000,
                    ..PtRegs::default()
                };
                let logical_x18 = LOGICAL_X18.to_ne_bytes();
                let read = |address: usize, out: &mut [u8]| {
                    let bytes: &[u8] = if address == SITE {
                        &code
                    } else if address == TLS + 8 {
                        &logical_x18
                    } else {
                        return false;
                    };
                    if out.len() != bytes.len() {
                        return false;
                    }
                    out.copy_from_slice(bytes);
                    true
                };
                for interruption in [
                    GateInterruption::Asynchronous,
                    GateInterruption::Synchronous,
                ] {
                    assert!(matches!(
                        canonicalize(&saved, runtime, interruption, host, virtualize_x18, read),
                        Aarch64GateSignalResult::NotGate
                    ));
                }
                let Aarch64GateSignalResult::WriteThreadPointer { context, value } = canonicalize(
                    &saved,
                    runtime,
                    GateInterruption::Breakpoint,
                    host,
                    virtualize_x18,
                    read,
                ) else {
                    panic!("MSR source {source} was not emulated")
                };
                assert_eq!(
                    value,
                    match source {
                        31 => 0,
                        18 if virtualize_x18 => LOGICAL_X18,
                        _ => saved.regs[source as usize],
                    }
                );
                assert_eq!(context.regs, saved.regs);
                assert_eq!(context.sp, 0);
                assert_eq!(context.pstate, saved.pstate);
                assert_eq!(context.pc, SITE + 4);
                assert_eq!(context.orig_x0, saved.regs[0]);
                // A native Darwin guest cannot invoke this Linux-only trap ABI.
                assert!(matches!(
                    canonicalize_darwin(&saved, runtime, GateInterruption::Breakpoint, read),
                    Aarch64GateSignalResult::NotGate
                ));
            }
        }
        for word in [
            0xd420_0000u32,
            0xd420_0000 | (0xb220 << 5),
            0xd440_0000 | (0xb200 << 5),
        ] {
            assert!(aarch64::decode_msr_tpidr_trap(word).is_none());
        }
    }

    #[test]
    #[expect(clippy::single_range_in_vec_init, reason = "one executable code range")]
    fn host_aware_mrs_recovery_canonicalizes_middle_stages() {
        const SITE: usize = 0x1000_0000;
        const TRAMPOLINE: usize = 0x1000_4000;
        const GUEST_TP_SLOT: usize = 0x2000_0000;
        const GUEST_TP: usize = 0xfeed_1234;
        const DESTINATION: usize = 9;

        let mut code = 0xd53b_d069u32.to_le_bytes(); // mrs x9, tpidrro_el0
        let (gates, trapped) = Rewriter::new(TargetHost::MacOs)
            .unwrap()
            .patch_host_shared_cache_code(
                &mut code,
                SITE as u64,
                &[0..4],
                TRAMPOLINE as u64,
                0x1234,
                96,
            )
            .unwrap();
        assert_eq!(trapped, []);
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
        for offset in [4, 8, 12, 16, 20, 24, 28, 32, 36] {
            let mut ctx = PtRegs {
                pc: TRAMPOLINE + 16 + offset,
                ..PtRegs::default()
            };
            ctx.regs[DESTINATION] = 0xdead;
            let Aarch64GateSignalResult::Canonicalized(recovered) =
                canonicalize_darwin(&ctx, runtime, GateInterruption::Asynchronous, read)
            else {
                panic!("Darwin MRS recovery failed at offset {offset}")
            };
            assert_eq!(recovered.pc, SITE + 4);
            assert_eq!(recovered.regs[DESTINATION], GUEST_TP);
        }
        for offset in [40, 48] {
            let mut ctx = PtRegs {
                pc: TRAMPOLINE + 16 + offset,
                ..PtRegs::default()
            };
            ctx.regs[DESTINATION] = GUEST_TP;
            let Aarch64GateSignalResult::Canonicalized(recovered) =
                canonicalize_darwin(&ctx, runtime, GateInterruption::Asynchronous, read)
            else {
                panic!("Darwin MRS recovery failed at offset {offset}")
            };
            assert_eq!(recovered.pc, SITE + 4);
            assert_eq!(recovered.regs[DESTINATION], GUEST_TP);
        }
    }

    #[test]
    #[expect(clippy::single_range_in_vec_init, reason = "one executable code range")]
    fn darwin_svc_recovery_uses_the_real_gate_and_red_zone_frame() {
        const SITE: usize = 0x1000_0000;
        const TRAMPOLINE: usize = 0x1000_4000;
        const STACK: usize = 0x2000_0000;
        const GUEST_SP: usize = STACK + DARWIN_SVC_FRAME_BYTES as usize;
        let mut code = 0xd4001001u32.to_le_bytes();
        let (gates, trapped) = Rewriter::new(TargetHost::MacOs)
            .unwrap()
            .patch_code_segment(
                &mut code,
                SITE as u64,
                &[0..4],
                TRAMPOLINE as u64,
                0x1234,
                96,
            )
            .unwrap();
        assert_eq!(trapped, []);
        let mut frame = [0u8; DARWIN_SVC_FRAME_BYTES as usize];
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
        for (offset, sp, x16) in [
            (0, GUEST_SP, 20),
            (4, STACK, 20),
            (12, STACK, 0xfeed),
            (32, STACK, 0x1234),
        ] {
            let mut ctx = PtRegs {
                pc: TRAMPOLINE + 16 + offset,
                sp,
                ..PtRegs::default()
            };
            ctx.regs[0] = 77;
            ctx.regs[16] = x16;
            let Aarch64GateSignalResult::Canonicalized(recovered) =
                canonicalize_darwin(&ctx, runtime, GateInterruption::Asynchronous, read)
            else {
                panic!("Darwin recovery failed at offset {offset}")
            };
            assert_eq!(recovered.pc, SITE);
            assert_eq!(recovered.sp, GUEST_SP);
            assert_eq!(recovered.regs[16], 20);
            assert_eq!(recovered.regs[0], 77);
            assert_eq!(recovered.orig_x0, 77);
            // The Linux decoder must not accept a Darwin frame layout.
            assert!(matches!(
                canonicalize(
                    &ctx,
                    runtime,
                    GateInterruption::Asynchronous,
                    TargetHost::MacOs,
                    true,
                    read
                ),
                Aarch64GateSignalResult::NotGate
            ));
        }
    }
}

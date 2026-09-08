// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use alloc::vec::Vec;
use litebox_syscall_rewriter::{
    RewriteOptions, aarch64::decode_branch_target, patch_code_segment_with_options,
};

const CODE: usize = 0x1000;
const TRAMPOLINE: usize = 0x400000;
const FRAME: usize = 0x8000;
const TLS: usize = 0x500000;
const HOST_VALUE: usize = 0xfeed_f000_0000_0000;

struct Fixture {
    code: Vec<u8>,
    trampoline: Vec<u8>,
    frame: [u8; 32],
    tls: [u8; 16],
}

impl Fixture {
    fn new(instruction: u32, host: TargetHost) -> Self {
        let mut code = instruction.to_le_bytes().to_vec();
        let (trampoline, trapped) = patch_code_segment_with_options(
            &mut code,
            CODE as u64,
            TRAMPOLINE as u64,
            0,
            RewriteOptions::new(host, true),
        )
        .unwrap();
        assert!(trapped.is_empty());
        Self {
            code,
            trampoline,
            frame: [0; 32],
            tls: [0; 16],
        }
    }

    fn slot(&self) -> usize {
        decode_branch_target(
            u32::from_le_bytes(self.code[..4].try_into().unwrap()),
            CODE as u64,
        )
        .unwrap()
        .trunc()
    }

    fn context(&self, offset: usize) -> PtRegs {
        PtRegs {
            regs: core::array::from_fn(|index| 0x100 + index),
            sp: FRAME + 32,
            pc: self.slot() + offset,
            pstate: 0xa000_0000,
            syscallno: crate::arch::NO_SYSCALL,
            ..PtRegs::default()
        }
    }

    fn read(&self, address: usize, output: &mut [u8]) -> bool {
        for (base, bytes) in [
            (CODE, self.code.as_slice()),
            (TRAMPOLINE, self.trampoline.as_slice()),
            (FRAME, self.frame.as_slice()),
            (TLS, self.tls.as_slice()),
        ] {
            if let Some(offset) = address.checked_sub(base)
                && let Some(end) = offset.checked_add(output.len())
                && let Some(bytes) = bytes.get(offset..end)
            {
                output.copy_from_slice(bytes);
                return true;
            }
        }
        false
    }

    fn recover(
        &self,
        context: &PtRegs,
        host: TargetHost,
        kind: GateInterruption,
        x18: bool,
    ) -> Aarch64GateSignalResult {
        canonicalize(
            context,
            GateRuntimeState {
                guest_thread_pointer_addr: TLS,
                expected_outbound_stub: self.slot() + SVC_GATE_BYTES,
                expected_outbound_pc: CODE + 4,
            },
            kind,
            host,
            x18,
            |address, output| self.read(address, output),
        )
    }
}

#[test]
fn tpidr_and_svc_boundaries_on_both_hosts() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut fixture = Fixture::new(0xd53bd040, host); // MRS x0, TPIDR_EL0
        fixture.tls[..8].copy_from_slice(&0x1234usize.to_ne_bytes());
        for offset in [0, 4, 8] {
            let mut context = fixture.context(offset);
            context.regs[0] = if offset == 4 { HOST_VALUE } else { 0x1234 };
            let Aarch64GateSignalResult::Canonicalized(recovered) =
                fixture.recover(&context, host, GateInterruption::Asynchronous, true)
            else {
                panic!("MRS +{offset}");
            };
            assert_eq!(recovered.regs[0], 0x1234);
            assert_eq!(recovered.orig_x0, 0x1234);
            assert_eq!(recovered.pc, CODE + if offset == 0 { 0 } else { 4 });
            assert_eq!(recovered.sp, context.sp);
            assert_eq!(recovered.pstate, context.pstate);
        }

        let mut fixture = Fixture::new(0xd51bd045, host); // MSR TPIDR_EL0, x5
        let original = fixture.context(0);
        for (slot, value) in [original.regs[16], original.regs[17], original.regs[5]]
            .into_iter()
            .enumerate()
        {
            fixture.frame[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_ne_bytes());
        }
        for offset in (0..=32).step_by(4) {
            let mut context = fixture.context(offset);
            if (4..32).contains(&offset) {
                context.sp = FRAME;
            }
            if (16..28).contains(&offset) {
                context.regs[16] = HOST_VALUE;
            }
            if (20..28).contains(&offset) {
                context.regs[17] = HOST_VALUE;
            }
            let Aarch64GateSignalResult::Canonicalized(recovered) =
                fixture.recover(&context, host, GateInterruption::Asynchronous, true)
            else {
                panic!("MSR +{offset}");
            };
            assert_eq!(recovered.regs, original.regs);
            assert_eq!(recovered.sp, original.sp);
            assert_eq!(recovered.pc, CODE + if offset <= 20 { 0 } else { 4 });
        }

        let mut fixture = Fixture::new(0xd4000001, host); // SVC
        let original = fixture.context(0);
        fixture.frame[..8].copy_from_slice(&original.regs[16].to_ne_bytes());
        for offset in (0..=44).step_by(4) {
            let mut context = fixture.context(offset);
            if offset != 0 {
                context.sp = FRAME;
            }
            if offset > 8 {
                context.regs[16] = HOST_VALUE;
            }
            let recovered = fixture.recover(&context, host, GateInterruption::Asynchronous, true);
            if offset >= SVC_GATE_BYTES {
                assert!(matches!(
                    recovered,
                    Aarch64GateSignalResult::PreserveSavedContext
                ));
            } else {
                let Aarch64GateSignalResult::Canonicalized(recovered) = recovered else {
                    panic!("SVC +{offset}");
                };
                assert_eq!(recovered.regs, original.regs);
                assert_eq!(recovered.sp, original.sp);
                assert_eq!(recovered.pc, CODE);
            }
        }
    }
}

#[test]
fn unvalidated_candidates_are_not_runtime_errors() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut fixture = Fixture::new(0xd53bd040, host);
        let context = fixture.context(4);
        let slot_offset = fixture.slot() - TRAMPOLINE;
        // Leave valid metadata but break the instruction template.
        fixture.trampoline[slot_offset..slot_offset + 4]
            .copy_from_slice(&0xd503201fu32.to_le_bytes());
        assert!(matches!(
            fixture.recover(&context, host, GateInterruption::Synchronous, true),
            Aarch64GateSignalResult::NotGate
        ));

        let mut fixture = Fixture::new(0xd53bd040, host);
        fixture.code.copy_from_slice(&0xd503201fu32.to_le_bytes()); // no inbound branch
        assert!(matches!(
            canonicalize(
                &context,
                GateRuntimeState {
                    guest_thread_pointer_addr: TLS,
                    expected_outbound_stub: 0,
                    expected_outbound_pc: 0,
                },
                GateInterruption::Asynchronous,
                host,
                true,
                |address, output| fixture.read(address, output)
            ),
            Aarch64GateSignalResult::NotGate
        ));
    }
}

#[test]
fn validated_gate_with_unreadable_tls_is_invalid() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let fixture = Fixture::new(0xd53bd040, host);
        let context = fixture.context(4);
        let result = canonicalize(
            &context,
            GateRuntimeState {
                guest_thread_pointer_addr: TLS,
                expected_outbound_stub: 0,
                expected_outbound_pc: 0,
            },
            GateInterruption::Asynchronous,
            host,
            true,
            |address, output| address != TLS && fixture.read(address, output),
        );
        assert!(matches!(
            result,
            Aarch64GateSignalResult::InvalidRuntimeState
        ));
        assert_eq!(context.pc, fixture.slot() + 4);
        assert_eq!(context.regs[0], 0x100);
    }
}

#[test]
fn overflowing_runtime_slot_is_invalid() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let fixture = Fixture::new(0xd63f0240, host);
        let context = fixture.context(0);
        let result = canonicalize(
            &context,
            GateRuntimeState {
                guest_thread_pointer_addr: usize::MAX,
                expected_outbound_stub: 0,
                expected_outbound_pc: 0,
            },
            GateInterruption::Breakpoint,
            host,
            true,
            |address, output| fixture.read(address, output),
        );
        assert!(matches!(
            result,
            Aarch64GateSignalResult::InvalidRuntimeState
        ));
    }
}

#[test]
fn disabled_outbound_stubs_do_not_preserve_saved_context() {
    let fixture = Fixture::new(0xd4000001, TargetHost::MacOs);
    let context = fixture.context(SVC_GATE_BYTES);
    let result = canonicalize(
        &context,
        GateRuntimeState {
            guest_thread_pointer_addr: TLS,
            expected_outbound_stub: 0,
            expected_outbound_pc: 0,
        },
        GateInterruption::Asynchronous,
        TargetHost::MacOs,
        true,
        |address, output| fixture.read(address, output),
    );
    assert!(matches!(result, Aarch64GateSignalResult::NotGate));
}

#[test]
fn x18_indirect_branch_on_both_hosts() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut fixture = Fixture::new(0xd63f0240, host); // BLR x18
        fixture.tls[8..16].copy_from_slice(&0x12340000usize.to_ne_bytes());
        let context = fixture.context(0);
        let Aarch64GateSignalResult::ResumeGuest(recovered) =
            fixture.recover(&context, host, GateInterruption::Breakpoint, true)
        else {
            panic!("BLR x18");
        };
        assert_eq!(recovered.pc, 0x12340000);
        assert_eq!(recovered.regs[18], 0x12340000);
        assert_eq!(recovered.regs[30], CODE + 4);
        assert_eq!(recovered.sp, context.sp);
        assert!(matches!(
            fixture.recover(&context, host, GateInterruption::Breakpoint, false),
            Aarch64GateSignalResult::NotGate
        ));
    }
}

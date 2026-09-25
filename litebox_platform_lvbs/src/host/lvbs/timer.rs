// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS execution-budget policy and Hyper-V STIMER mechanism.
//!
//! This is not a scheduler. One budget spans a VTL1 residency touching user
//! code, including reentries and syscalls. The VTL switch loop owns disarming
//! before returning to VTL0, not the shared kernel/user execution loop.
//! User-mode expiry is acknowledged before the unchanged exception reaches
//! the shim; kernel-mode expiry rearms only an active residency.

use super::per_cpu_variables::with_per_cpu_variables;
use crate::arch::{apic, instrs::wrmsr};
use crate::execution::ExecutionTimer;
use crate::mshv::{
    HV_FEATURE_REFERENCE_COUNTER, HV_FEATURE_STIMER_DIRECT, HV_FEATURE_SYNTHETIC_TIMER,
    HV_STIMER_CONFIG_DIRECT_MODE, HV_STIMER_CONFIG_ENABLE, HV_STIMER_CONFIG_VECTOR_SHIFT,
    HV_X64_MSR_STIMER0_CONFIG, HV_X64_MSR_STIMER0_COUNT, HYPERV_CPUID_FEATURES,
    HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, HYPERV_HYPERVISOR_PRESENT_BIT,
    clock::{REF_TICKS_PER_MICRO, reference_time_100ns},
};
use core::{arch::x86_64::__cpuid_count as cpuid_count, cell::Cell};
use litebox::shim::Exception;

/// Timer vector installed by the LVBS IDT and programmed into STIMER0.
pub(crate) const STIMER_VECTOR: u8 = 0x40;
const CPUID_FEATURE_INFO: u32 = 1;

/// Stay below VTL0's first RCU stall warning (60 s on Azure Linux), with margin
/// for termination and return. This residency budget is LVBS policy.
// TODO: make the quantum configurable for different VTL0 distributions.
#[cfg(not(feature = "preemption_test_quantum"))]
const QUANTUM_MICROS: u64 = 50_000_000;
#[cfg(feature = "preemption_test_quantum")]
const QUANTUM_MICROS: u64 = 10_000;
const QUANTUM_100NS: u64 = QUANTUM_MICROS * REF_TICKS_PER_MICRO;

/// Per-CPU LVBS state. All-zero initialization means disabled and unarmed.
#[repr(C)]
#[derive(Default)]
pub(crate) struct PreemptionState {
    enabled: Cell<bool>,
    armed: Cell<bool>,
    killed_user: Cell<bool>,
}

impl PreemptionState {
    fn arm(&self, program: impl FnOnce()) {
        if !self.enabled.get() || self.armed.get() {
            return;
        }
        // Publish before programming: an immediate fire must see an armed window.
        self.armed.set(true);
        program();
    }

    fn on_kernel_interrupt(&self, acknowledge: impl FnOnce(), program: impl FnOnce()) {
        acknowledge();
        // The one-shot timer auto-disables on expiry. Rearm only for a live
        // window; a stale interrupt after disarm is acknowledged but not rearmed.
        if self.enabled.get() && self.armed.get() {
            program();
        }
    }

    fn on_user_exception(&self, exception: Exception, acknowledge: impl FnOnce()) {
        if exception.0 == STIMER_VECTOR {
            acknowledge();
            // Preserve the existing policy even for a stale user-mode expiry:
            // it is forwarded to the shim as an unhandled exception to terminate.
            self.killed_user.set(true);
        }
    }

    fn disarm(&self, disable: impl FnOnce()) {
        if !self.enabled.get() || !self.armed.get() {
            return;
        }
        // Clear before disabling hardware so a stale kernel interrupt cannot rearm.
        self.armed.set(false);
        disable();
    }

    fn take_user_timeout_kill(&self) -> bool {
        self.killed_user.replace(false)
    }
}

/// Runner-selected timer for LVBS user execution. State belongs to the current
/// CPU's LVBS extension, not to this handle or the shared kernel prefix.
pub struct LvbsTimer;

impl ExecutionTimer for LvbsTimer {
    fn arm(&self) {
        with_per_cpu_variables(|pcv| pcv.timer.arm(program_stimer_deadline));
    }

    fn on_user_exception(&self, exception: Exception) {
        with_per_cpu_variables(|pcv| pcv.timer.on_user_exception(exception, apic::eoi));
    }
}

/// Configure this CPU's timer after loading the LVBS IDT. Preserve the existing
/// behavior: unavailable x2APIC/STIMER is logged and leaves preemption disabled.
pub fn init() {
    if !apic::enable_x2apic() {
        crate::serial_println!("preemption disabled: x2APIC unavailable");
        return;
    }
    if init_stimer() {
        with_per_cpu_variables(|pcv| pcv.timer.enabled.set(true));
        crate::debug_serial_println!("STIMER direct-mode (quantum {QUANTUM_MICROS} us)");
    } else {
        crate::serial_println!("preemption disabled: no STIMER direct-mode");
    }
}

fn init_stimer() -> bool {
    if cpuid_count(CPUID_FEATURE_INFO, 0x0).ecx & HYPERV_HYPERVISOR_PRESENT_BIT == 0
        || cpuid_count(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0x0).eax < HYPERV_CPUID_FEATURES
    {
        return false;
    }
    let feat = cpuid_count(HYPERV_CPUID_FEATURES, 0x0);
    crate::debug_serial_println!(
        "HV feature leaf {HYPERV_CPUID_FEATURES:#x}: eax={:#010x} edx={:#010x}",
        feat.eax,
        feat.edx
    );
    if feat.eax & HV_FEATURE_REFERENCE_COUNTER == 0
        || feat.eax & HV_FEATURE_SYNTHETIC_TIMER == 0
        || feat.edx & HV_FEATURE_STIMER_DIRECT == 0
    {
        return false;
    }
    wrmsr(HV_X64_MSR_STIMER0_CONFIG, 0);
    true
}

/// Write COUNT before CONFIG.Enable; the software armed flag is already set.
#[inline]
fn program_stimer_deadline() {
    let now = reference_time_100ns();
    wrmsr(HV_X64_MSR_STIMER0_COUNT, now.wrapping_add(QUANTUM_100NS));
    let cfg = HV_STIMER_CONFIG_ENABLE
        | HV_STIMER_CONFIG_DIRECT_MODE
        | (u64::from(STIMER_VECTOR) << HV_STIMER_CONFIG_VECTOR_SHIFT);
    wrmsr(HV_X64_MSR_STIMER0_CONFIG, cfg);
}

/// Kernel-mode IRQ entry, called with IF clear by the LVBS ISR. Only the bounded
/// init/reenter prologue is expected to be interrupted in an armed window.
pub(crate) fn on_kernel_interrupt() {
    with_per_cpu_variables(|pcv| {
        pcv.timer
            .on_kernel_interrupt(apic::eoi, program_stimer_deadline);
    });
}

/// Called at the VTL0-return boundary, including service dispatches that never
/// entered user mode. Such unarmed dispatches do not touch timer hardware.
pub(crate) fn disarm_preemption() {
    with_per_cpu_variables(|pcv| pcv.timer.disarm(|| wrmsr(HV_X64_MSR_STIMER0_CONFIG, 0)));
}

pub(crate) fn take_user_timeout_kill() -> bool {
    with_per_cpu_variables(|pcv| pcv.timer.take_user_timeout_kill())
}

#[cfg(test)]
mod tests;

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V synthetic-timer (STIMER) preemption timer: VTL1 preempts a runaway TA.
//!
//! VTL0 cannot interrupt VTL1 and OP-TEE has no scheduler, so a TA that
//! spins without returning would hold the VP forever and freeze VTL0 too.
//! VTL1 arms a VTL1-local Hyper-V synthetic timer (STIMER0 in direct mode)
//! that the TA cannot tamper with; on expiry it is delivered as
//! `STIMER_VECTOR` and the shim kills the TA with
//! `TEE_ERROR_TARGET_DEAD`.
//!
//! `scoped` brackets a whole TA entry: arm before `run_thread_arch`,
//! disarm once it fully returns to the VTL1 kernel: i.e., after the TA has
//! left ring 3, and before the VP is handed back to VTL0. The timer stays
//! armed across the TA's syscalls and faults (VTL1's own kernel work is
//! trusted and bounded), so it bounds the *cumulative* time the VP is held
//! in VTL1 per entry, which is what keeps VTL0 from tripping its
//! CPU lockup watchdog.
//!
//! Direct mode injects `STIMER_VECTOR` straight into the local APIC, so
//! the usual fire path is an ordinary user-mode interrupt (ISR ->
//! exception_callback -> kill) with a rare in-kernel safety net
//! (`interrupts::stimer_handler_impl`).

use super::instrs::{rdmsr, wrmsr};
use crate::host::per_cpu_variables::with_per_cpu_variables;
use crate::mshv::{
    HV_FEATURE_REFERENCE_COUNTER, HV_FEATURE_STIMER_DIRECT, HV_FEATURE_SYNTHETIC_TIMER,
    HV_STIMER_CONFIG_DIRECT_MODE, HV_STIMER_CONFIG_ENABLE, HV_STIMER_CONFIG_VECTOR_SHIFT,
    HV_X64_MSR_STIMER0_CONFIG, HV_X64_MSR_STIMER0_COUNT, HV_X64_MSR_TIME_REF_COUNT,
    HYPERV_CPUID_FEATURES, HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, HYPERV_HYPERVISOR_PRESENT_BIT,
};

/// Vector the preemption timer fires on. Above the 0..31 exception range and
/// clear of the Hyper-V SINT vector (0xf3).
pub(crate) const STIMER_VECTOR: u8 = 0x40;

/// Vector the local APIC delivers for a *spurious* interrupt (programmed
/// into the SVR). `0xff` is conventional (top of range). Requires no EOI;
/// handled by the bare `iretq` stub `isr_spurious`.
pub(crate) const SPURIOUS_VECTOR: u8 = 0xff;

// Architectural x86 local-APIC (x2APIC) MSRs and the bit fields we use.
const IA32_APIC_BASE: u32 = 0x1b;
const IA32_APIC_BASE_EN: u64 = 1 << 11; // xAPIC global enable
const IA32_APIC_BASE_EXTD: u64 = 1 << 10; // x2APIC mode enable
const X2APIC_SVR: u32 = 0x80f; // Spurious Interrupt Vector Register
const X2APIC_SVR_ENABLE: u64 = 1 << 8; // APIC software-enable
const X2APIC_EOI: u32 = 0x80b; // End-of-interrupt (write 0)

// CPUID standard feature-information leaf (EAX=1) and the ECX bits we read.
const CPUID_FEATURE_INFO: u32 = 1;
const CPUID_FEATURE_INFO_ECX_X2APIC: u32 = 1 << 21;

/// Per-entry execution budget in microseconds. 8 s sits under Linux's default
/// 10 s hard-lockup watchdog, so VTL1 kills a runaway TA and returns the VP
/// before VTL0 declares its CPU locked, with margin for the kill/return path.
#[cfg(not(feature = "preemption_test_quantum"))]
const QUANTUM_MICROS: u64 = 8_000_000; // 8 s

/// Tight budget under the `preemption_test_quantum` feature so a runaway-TA
/// kill fires in ~10 ms. Test builds only.
#[cfg(feature = "preemption_test_quantum")]
const QUANTUM_MICROS: u64 = 10_000; // 10 ms

/// Partition reference counter granularity: 100 ns ticks, i.e., 10 per microsecond.
const REF_TICKS_PER_MICRO: u64 = 10;

/// Quantum as a reference-counter tick count (STIMER deadlines are in ticks).
const QUANTUM_100NS: u64 = QUANTUM_MICROS * REF_TICKS_PER_MICRO;

// TODO: This backend is Hyper-V specific (STIMER direct mode). For non-Hyper-V
// platforms, add alternative one-shot timer sources behind the same
// arm/disarm/is_armed/eoi interface and have `init` pick one per platform:
// - x86: the LAPIC TSC-deadline timer (deadline via the IA32_TSC_DEADLINE MSR,
//   armed through the LVT timer in TSC-deadline mode, delivered to the same
//   vector; x2APIC is already enabled here).
// - Arm: the architected generic timer (a CNTV/CNTP compare delivering a PPI
//   via the GIC).

/// Configure the preemption timer on the current CPU: enable x2APIC (for EOI)
/// and, if the hypervisor advertises STIMER direct mode, prepare STIMER0.
/// Idempotent and per-CPU; leaves the timer disabled (logged) rather than
/// crashing if any step is unsupported.
///
/// Call once per CPU after the IDT is loaded.
pub fn init() {
    use core::arch::x86_64::__cpuid;

    let leaf1 = __cpuid(CPUID_FEATURE_INFO);
    // x2APIC software-enable is needed to EOI the direct-mode STIMER interrupt.
    if leaf1.ecx & CPUID_FEATURE_INFO_ECX_X2APIC == 0 || !enable_x2apic() {
        crate::serial_println!("preemption disabled: x2APIC unavailable");
        return;
    }

    if leaf1.ecx & HYPERV_HYPERVISOR_PRESENT_BIT != 0
        && __cpuid(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS).eax >= HYPERV_CPUID_FEATURES
    {
        let feat = __cpuid(HYPERV_CPUID_FEATURES);
        crate::debug_serial_println!(
            "HV feature leaf {HYPERV_CPUID_FEATURES:#x}: eax={:#010x} edx={:#010x}",
            feat.eax,
            feat.edx
        );
    } else {
        crate::serial_println!("no Hyper-V timer-capability leaf");
    }

    if init_stimer() {
        with_per_cpu_variables(|pcv| pcv.preemption_timer_enabled.set(true));
        crate::debug_serial_println!("STIMER direct-mode (quantum {QUANTUM_MICROS} us)");
    } else {
        crate::serial_println!("preemption disabled: no STIMER direct-mode");
    }
}

/// Enable x2APIC mode (if not already) and software-enable the local APIC with
/// spurious vector [`SPURIOUS_VECTOR`]. Returns `false` if x2APIC did not enable.
fn enable_x2apic() -> bool {
    let apic_base = rdmsr(IA32_APIC_BASE);
    if apic_base & IA32_APIC_BASE_EXTD == 0 {
        wrmsr(
            IA32_APIC_BASE,
            apic_base | IA32_APIC_BASE_EN | IA32_APIC_BASE_EXTD,
        );
        if rdmsr(IA32_APIC_BASE) & IA32_APIC_BASE_EXTD == 0 {
            return false;
        }
    }
    // Software-enable the APIC with spurious vector SPURIOUS_VECTOR.
    let svr = rdmsr(X2APIC_SVR);
    wrmsr(
        X2APIC_SVR,
        svr | X2APIC_SVR_ENABLE | u64::from(SPURIOUS_VECTOR),
    );
    true
}

/// True if the hypervisor advertises everything STIMER needs.
fn stimer_direct_available() -> bool {
    use core::arch::x86_64::__cpuid;
    if __cpuid(CPUID_FEATURE_INFO).ecx & HYPERV_HYPERVISOR_PRESENT_BIT == 0
        || __cpuid(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS).eax < HYPERV_CPUID_FEATURES
    {
        return false;
    }
    let feat = __cpuid(HYPERV_CPUID_FEATURES);
    feat.eax & HV_FEATURE_REFERENCE_COUNTER != 0
        && feat.eax & HV_FEATURE_SYNTHETIC_TIMER != 0
        && feat.edx & HV_FEATURE_STIMER_DIRECT != 0
}

/// Prepare STIMER0: verify capabilities and leave it disabled (armed later via
/// [`arm_preemption`]). Returns `false` if unsupported.
fn init_stimer() -> bool {
    if !stimer_direct_available() {
        return false;
    }
    // Known-disabled starting state; arm_preemption writes the full config.
    wrmsr(HV_X64_MSR_STIMER0_CONFIG, 0);
    true
}

/// Arm the preemption timer to fire one quantum from now. Normally driven by
/// [`scoped`]; also re-armed by the kernel-mode-fire safety net
/// (`interrupts::stimer_handler_impl`). No-op if STIMER is not configured.
#[inline]
pub(crate) fn arm_preemption() {
    if !with_per_cpu_variables(|pcv| pcv.preemption_timer_enabled.get()) {
        return;
    }
    // One-shot at reference-now + quantum; write COUNT before CONFIG (Enable).
    let now = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
    wrmsr(HV_X64_MSR_STIMER0_COUNT, now.wrapping_add(QUANTUM_100NS));
    let cfg = HV_STIMER_CONFIG_ENABLE
        | HV_STIMER_CONFIG_DIRECT_MODE
        | (u64::from(STIMER_VECTOR) << HV_STIMER_CONFIG_VECTOR_SHIFT);
    wrmsr(HV_X64_MSR_STIMER0_CONFIG, cfg);
}

/// Run `f` with the preemption timer armed, disarming when it returns.
/// The single arm/disarm pairing; used to bracket a TA entry (see the module doc).
#[inline]
pub(crate) fn scoped<R>(f: impl FnOnce() -> R) -> R {
    /// Disarms on drop so an early return cannot leave the timer live.
    struct Disarm;
    impl Drop for Disarm {
        fn drop(&mut self) {
            disarm_preemption();
        }
    }

    arm_preemption();
    let _disarm = Disarm;
    f()
}

/// Disarm the preemption timer (clear STIMER0 CONFIG.Enable). Only
/// [`scoped`]'s drop guard disarms. No-op if STIMER is not configured.
#[inline]
fn disarm_preemption() {
    if !with_per_cpu_variables(|pcv| pcv.preemption_timer_enabled.get()) {
        return;
    }
    wrmsr(HV_X64_MSR_STIMER0_CONFIG, 0);
}

/// True if STIMER0 is still armed and has not fired. A one-shot STIMER
/// auto-clears Enable on fire, so false means it fired or was never armed.
#[inline]
pub(crate) fn is_armed() -> bool {
    if !with_per_cpu_variables(|pcv| pcv.preemption_timer_enabled.get()) {
        return false;
    }
    rdmsr(HV_X64_MSR_STIMER0_CONFIG) & HV_STIMER_CONFIG_ENABLE != 0
}

/// Signal end-of-interrupt to the local APIC. Must be called for every delivered
/// preemption timer interrupt or the APIC will not deliver further interrupts.
#[inline]
pub(crate) fn eoi() {
    wrmsr(X2APIC_EOI, 0);
}

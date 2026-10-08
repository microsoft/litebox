// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V synthetic-timer (STIMER) preemption timer: forcefully terminates
//! runaway user-mode code in VTL1.
//!
//! VTL1 has no preemptive scheduler and VTL0 cannot interrupt VTL1, so
//! user-mode code that spins without returning holds the VP forever and freezes
//! VTL0 too. In lieu of a scheduler, VTL1 arms a VTL1-local Hyper-V synthetic
//! timer (STIMER0 in direct mode) that user-mode code cannot tamper with; on
//! expiry it fires `STIMER_VECTOR` and the shim terminates the offending
//! thread.
//!
//! The timer is armed when entering user-mode code (`arm_preemption`) and
//! disarmed at the VTL0-return boundary (`vtl_switch`). Disarming there is
//! the hard invariant: VTL1 never hands the VP back to VTL0 with the timer
//! live. The deadline spans a whole dispatch, bounding the *cumulative* VTL1
//! residency which touches guest code. The timer stays armed across the
//! guest's syscalls and faults (VTL1's own kernel work is trusted and
//! bounded). This is what keeps VTL0's RCU from detecting a CPU stall
//! (`rcu_preempt detected stalls`) on the parked VP. See `QUANTUM_MICROS`.
//!
//! Direct mode injects `STIMER_VECTOR` straight into the local APIC, so the
//! usual fire path is an ordinary user-mode interrupt (ISR -> exception_callback
//! -> kill) with a rare in-kernel safety net (`interrupts::stimer_handler_impl`,
//! which re-arms via `rearm_preemption`).
//!
//! Direct mode needs x2APIC to EOI. Without it (or without direct mode), the
//! timer falls back to message mode: expiry posts to SINT `STIMER_SINT`
//! (`STIMER_VECTOR`, auto-EOI), so no APIC access is needed. The fire path is
//! the same; `eoi` frees the SIMP slot instead.

use super::instrs::{rdmsr, wrmsr};
use crate::host::per_cpu_variables::{PerCpuVariables, with_per_cpu_variables};
use crate::mshv::{
    HV_FEATURE_REFERENCE_COUNTER, HV_FEATURE_STIMER_DIRECT, HV_FEATURE_SYNIC,
    HV_FEATURE_SYNTHETIC_TIMER, HV_MESSAGE_FLAG_PENDING, HV_STIMER_CONFIG_DIRECT_MODE,
    HV_STIMER_CONFIG_ENABLE, HV_STIMER_CONFIG_SINTX_SHIFT, HV_STIMER_CONFIG_VECTOR_SHIFT,
    HV_X64_MSR_EOM, HV_X64_MSR_SINT0, HV_X64_MSR_STIMER0_CONFIG, HV_X64_MSR_STIMER0_COUNT,
    HV_X64_MSR_TIME_REF_COUNT, HYPERV_CPUID_FEATURES, HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS,
    HYPERV_HYPERVISOR_PRESENT_BIT, HvMessage, HvMessageHeader, HvSynicSint,
};
use core::arch::x86_64::{__cpuid_count as cpuid_count, CpuidResult};
use core::mem::{offset_of, size_of};
use core::sync::atomic::{Ordering, fence};

/// Vector the preemption timer fires on. Above the 0..31 exception range and
/// clear of the Hyper-V SINT vector (0xf3).
pub(crate) const STIMER_VECTOR: u8 = 0x40;

/// Vector the local APIC delivers for a *spurious* interrupt (programmed
/// into the SVR). `0xff` is conventional (top of range). Requires no EOI;
/// handled by the bare `iretq` stub `isr_spurious`.
pub(crate) const SPURIOUS_VECTOR: u8 = 0xff;

/// SynIC SINT used by the message-mode fallback (SINT0 carries VSM intercepts).
const STIMER_SINT: u8 = 1;

/// SIMP-page offsets of [`STIMER_SINT`]'s slot header fields.
const STIMER_SLOT_OFFSET: usize = STIMER_SINT as usize * size_of::<HvMessage>();
const STIMER_SLOT_TYPE_OFFSET: usize =
    STIMER_SLOT_OFFSET + offset_of!(HvMessage, header) + offset_of!(HvMessageHeader, message_type);
const STIMER_SLOT_FLAGS_OFFSET: usize =
    STIMER_SLOT_OFFSET + offset_of!(HvMessage, header) + offset_of!(HvMessageHeader, message_flags);
// SIMP is page-aligned: keep the volatile accesses aligned and in bounds.
const _: () = assert!(STIMER_SLOT_TYPE_OFFSET.is_multiple_of(align_of::<u32>()));
const _: () = assert!(STIMER_SLOT_OFFSET + size_of::<HvMessage>() <= 4096);

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

/// Per-entry execution budget in microseconds.
///
/// While VTL1 holds the VP, VTL0's RCU sees no quiescent state on that CPU and
/// trips its stall detector (`rcu_preempt detected stalls`). The binding
/// threshold is the first stall warning, at `CONFIG_RCU_CPU_STALL_TIMEOUT`
/// (60 s on Azure Linux). 50 s stays under it with margin for the kill/return path.
//
// TODO: Make the quantum configurable to support various distros.
#[cfg(not(feature = "preemption_test_quantum"))]
const QUANTUM_MICROS: u64 = 50_000_000; // 50 s

/// Tight budget under the `preemption_test_quantum` feature so a runaway-guest
/// kill fires in ~10 ms. Test builds only.
#[cfg(feature = "preemption_test_quantum")]
const QUANTUM_MICROS: u64 = 10_000; // 10 ms

/// Partition reference counter granularity: 100 ns ticks, i.e., 10 per microsecond.
const REF_TICKS_PER_MICRO: u64 = 10;

/// Quantum as a reference-counter tick count (STIMER deadlines are in ticks).
const QUANTUM_100NS: u64 = QUANTUM_MICROS * REF_TICKS_PER_MICRO;

/// Nanoseconds per partition reference-counter tick: the counter runs at
/// 10 MHz (`REF_TICKS_PER_MICRO` ticks per microsecond).
pub(crate) const REF_COUNTER_TICK_NANOS: u64 = 1_000 / REF_TICKS_PER_MICRO;

/// Read the Hyper-V partition reference counter (`HV_X64_MSR_TIME_REF_COUNT`).
///
/// A monotonic, frequency-invariant counter in 100 ns units, normalized by the
/// hypervisor across TSC scaling and live migration.
pub(crate) fn reference_time_100ns() -> u64 {
    rdmsr(HV_X64_MSR_TIME_REF_COUNT)
}

// TODO: This backend is Hyper-V specific (STIMER direct mode). For non-Hyper-V
// platforms, add alternative one-shot timer sources behind the same
// arm/disarm/eoi interface and have `init` pick one per platform:
// - x86: the LAPIC TSC-deadline timer (deadline via the IA32_TSC_DEADLINE MSR,
//   armed through the LVT timer in TSC-deadline mode, delivered to the same
//   vector; needs x2APIC or xAPIC MMIO).
// - Arm: the architected generic timer (a CNTV/CNTP compare delivering a PPI
//   via the GIC).

/// Configure the preemption timer on the current CPU: STIMER direct mode if
/// x2APIC is usable, else message mode. Leaves the timer disabled if neither
/// works. Idempotent; only the BSP logs.
///
/// Call once per CPU after the IDT is loaded and `hvcall::init` (SynIC).
pub fn init(is_bsp: bool) {
    let Some(hv_features) = stimer_features() else {
        if is_bsp {
            crate::serial_println!("preemption disabled: no Hyper-V synthetic timer");
        }
        return;
    };
    if is_bsp {
        crate::debug_serial_println!(
            "HV feature leaf {HYPERV_CPUID_FEATURES:#x}: eax={:#010x} edx={:#010x}",
            hv_features.eax,
            hv_features.edx
        );
    }
    // Start disabled; arm_preemption writes the full config.
    wrmsr(HV_X64_MSR_STIMER0_CONFIG, 0);

    // Direct mode needs x2APIC to EOI.
    let direct = hv_features.edx & HV_FEATURE_STIMER_DIRECT != 0
        && cpuid_count(CPUID_FEATURE_INFO, 0x0).ecx & CPUID_FEATURE_INFO_ECX_X2APIC != 0
        && enable_x2apic();
    if direct {
        with_per_cpu_variables(|pcv| {
            pcv.preemption_timer_message_mode.set(false);
            pcv.preemption_timer_enabled.set(true);
        });
        if is_bsp {
            crate::debug_serial_println!("STIMER direct-mode (quantum {QUANTUM_MICROS} us)");
        }
    } else if hv_features.eax & HV_FEATURE_SYNIC != 0 {
        // Leaves the APIC as-is: delivery relies on it being enabled already
        // (APIC_BASE.EN, SVR), as verified on Azure Hyper-V.
        init_stimer_sint();
        with_per_cpu_variables(|pcv| {
            pcv.preemption_timer_message_mode.set(true);
            pcv.preemption_timer_enabled.set(true);
        });
        if is_bsp {
            crate::debug_serial_println!(
                "STIMER message-mode via SINT{STIMER_SINT} (x2APIC/direct-mode unavailable; quantum {QUANTUM_MICROS} us)"
            );
        }
    } else if is_bsp {
        crate::serial_println!("preemption disabled: no x2APIC/direct-mode and no SynIC");
    }
}

/// Enable x2APIC mode (if not already) and software-enable the local APIC with
/// spurious vector [`SPURIOUS_VECTOR`]. Returns `false` if x2APIC did not enable.
fn enable_x2apic() -> bool {
    let base = rdmsr(IA32_APIC_BASE);
    if base & IA32_APIC_BASE_EXTD == 0 {
        // The SDM requires enabling xAPIC (EN) before x2APIC (EXTD); writing both
        // from a fully-disabled APIC is a documented #GP, so set EN first.
        if base & IA32_APIC_BASE_EN == 0 {
            wrmsr(IA32_APIC_BASE, base | IA32_APIC_BASE_EN);
        }
        wrmsr(
            IA32_APIC_BASE,
            base | IA32_APIC_BASE_EN | IA32_APIC_BASE_EXTD,
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

/// Hyper-V feature leaf, or `None` without the reference counter or STIMERs.
fn stimer_features() -> Option<CpuidResult> {
    if cpuid_count(CPUID_FEATURE_INFO, 0x0).ecx & HYPERV_HYPERVISOR_PRESENT_BIT == 0
        || cpuid_count(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0x0).eax < HYPERV_CPUID_FEATURES
    {
        return None;
    }
    let feat = cpuid_count(HYPERV_CPUID_FEATURES, 0x0);
    if feat.eax & HV_FEATURE_REFERENCE_COUNTER == 0 || feat.eax & HV_FEATURE_SYNTHETIC_TIMER == 0 {
        return None;
    }
    Some(feat)
}

/// Route [`STIMER_SINT`] to `STIMER_VECTOR` (auto-EOI) and free its slot.
fn init_stimer_sint() {
    let mut sint = HvSynicSint::new();
    sint.set_vector(STIMER_VECTOR);
    sint.set_auto_eoi(true);
    wrmsr(HV_X64_MSR_SINT0 + u32::from(STIMER_SINT), sint.as_uint64());
    with_per_cpu_variables(ack_stimer_message);
}

/// Free [`STIMER_SINT`]'s SIMP slot; signal EOM if a message is queued.
///
/// TLFS order (as Linux `vmbus_signal_eom`): clear the type, barrier, then
/// read the flags, so a pending bit set concurrently is not missed.
#[inline]
fn ack_stimer_message(pcv: &PerCpuVariables) {
    let simp = pcv.hv_simp_page_as_u64();
    let type_ptr = (simp + STIMER_SLOT_TYPE_OFFSET as u64) as *mut u32;
    let flags_ptr = (simp + STIMER_SLOT_FLAGS_OFFSET as u64) as *const u8;
    // SAFETY: live per-CPU SIMP page; offsets aligned and in bounds (asserted
    // above). Volatile, since the hypervisor writes this memory.
    let pending = unsafe {
        type_ptr.write_volatile(0); // HvMessageTypeNone
        fence(Ordering::SeqCst);
        flags_ptr.read_volatile() & HV_MESSAGE_FLAG_PENDING != 0
    };
    if pending {
        wrmsr(HV_X64_MSR_EOM, 0);
    }
}

/// Program STIMER0 to fire one quantum from now (one-shot); writes COUNT before
/// CONFIG, which carries the Enable bit. The caller owns the `preemption_armed`
/// flag and the `preemption_timer_enabled` gate.
#[inline]
fn program_stimer_deadline(pcv: &PerCpuVariables) {
    let cfg = if pcv.preemption_timer_message_mode.get() {
        // An occupied slot would block the expiry message (and interrupt).
        ack_stimer_message(pcv);
        HV_STIMER_CONFIG_ENABLE | (u64::from(STIMER_SINT) << HV_STIMER_CONFIG_SINTX_SHIFT)
    } else {
        HV_STIMER_CONFIG_ENABLE
            | HV_STIMER_CONFIG_DIRECT_MODE
            | (u64::from(STIMER_VECTOR) << HV_STIMER_CONFIG_VECTOR_SHIFT)
    };
    let now = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
    wrmsr(HV_X64_MSR_STIMER0_COUNT, now.wrapping_add(QUANTUM_100NS));
    wrmsr(HV_X64_MSR_STIMER0_CONFIG, cfg);
}

/// Arm the preemption timer for a VTL1 residency, one quantum from now.
/// Idempotent: while a residency is already armed (a nested re-entry) it
/// leaves the in-flight deadline in place, so the nested chain shares one
/// quantum. No-op if STIMER is not configured.
#[inline]
pub(crate) fn arm_preemption() {
    with_per_cpu_variables(|pcv| {
        if !pcv.preemption_timer_enabled.get() || pcv.preemption_armed.get() {
            return;
        }
        // Mark armed *before* programming the MSR: a fire is only possible once
        // the MSR is armed, so every in-residency fire sees the flag set.
        pcv.preemption_armed.set(true);
        program_stimer_deadline(pcv);
    });
}

/// Re-arm after a kernel-mode fire; the one-shot auto-disables on expiry. Only
/// the in-kernel safety net (`interrupts::stimer_handler_impl`) calls this, and
/// only while a residency is armed, to refresh the deadline so the entry/exit
/// prologue the fire landed in can finish. No-op if STIMER is not configured or
/// no residency is armed.
#[inline]
pub(crate) fn rearm_preemption() {
    with_per_cpu_variables(|pcv| {
        if !pcv.preemption_timer_enabled.get() || !pcv.preemption_armed.get() {
            return;
        }
        program_stimer_deadline(pcv);
    });
}

/// Record that a preemption timer fire killed user-mode code.
#[inline]
pub(crate) fn mark_user_timeout_kill() {
    with_per_cpu_variables(|pcv| pcv.preemption_timeout_killed_user.set(true));
}

/// Consume a pending user-timeout kill notification.
#[inline]
pub(crate) fn take_user_timeout_kill() -> bool {
    with_per_cpu_variables(|pcv| {
        let killed = pcv.preemption_timeout_killed_user.get();
        pcv.preemption_timeout_killed_user.set(false);
        killed
    })
}

/// Disarm the preemption timer (clear STIMER0 CONFIG.Enable) before the VP is
/// handed back to VTL0. Called at the VTL0-return boundary (the `vtl_switch`
/// loop); a dispatch that never armed (HVCI/HEKI) returns without touching the
/// MSR. No-op if STIMER is not configured.
#[inline]
pub(crate) fn disarm_preemption() {
    with_per_cpu_variables(|pcv| {
        if !pcv.preemption_timer_enabled.get() || !pcv.preemption_armed.get() {
            return;
        }
        // Clear armed *before* disarming the MSR: a stale fire in this window is
        // then ACKed without re-arming, and the MSR is never left armed.
        pcv.preemption_armed.set(false);
        wrmsr(HV_X64_MSR_STIMER0_CONFIG, 0);
    });
}

/// Acknowledge every delivered preemption timer interrupt: x2APIC EOI in direct
/// mode, free the SIMP slot in message mode. Not a general APIC EOI: no-op
/// while the timer is disabled.
#[inline]
pub(crate) fn eoi() {
    with_per_cpu_variables(|pcv| {
        if !pcv.preemption_timer_enabled.get() {
            return;
        }
        if pcv.preemption_timer_message_mode.get() {
            ack_stimer_message(pcv);
        } else {
            wrmsr(X2APIC_EOI, 0);
        }
    });
}

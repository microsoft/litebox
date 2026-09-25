// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local x2APIC mechanics shared by VM platforms. No timer source or budget
//! policy is selected here.

use super::instrs::{rdmsr, wrmsr};
use core::arch::x86_64::__cpuid_count as cpuid_count;

/// Conventional APIC spurious vector. It requires a bare IRET, with no EOI.
pub const SPURIOUS_VECTOR: u8 = 0xff;

const IA32_APIC_BASE: u32 = 0x1b;
const IA32_APIC_BASE_EN: u64 = 1 << 11;
const IA32_APIC_BASE_EXTD: u64 = 1 << 10;
const X2APIC_SVR: u32 = 0x80f;
const X2APIC_SVR_ENABLE: u64 = 1 << 8;
const X2APIC_EOI: u32 = 0x80b;
const CPUID_FEATURE_INFO: u32 = 1;
const CPUID_FEATURE_INFO_ECX_X2APIC: u32 = 1 << 21;

/// Enable x2APIC and software-enable the local APIC with [`SPURIOUS_VECTOR`].
/// Returns false if unsupported or mode enable fails. The caller must install
/// an appropriate spurious interrupt entry before enabling interrupts.
pub fn enable_x2apic() -> bool {
    if cpuid_count(CPUID_FEATURE_INFO, 0).ecx & CPUID_FEATURE_INFO_ECX_X2APIC == 0 {
        return false;
    }
    let base = rdmsr(IA32_APIC_BASE);
    if base & IA32_APIC_BASE_EXTD == 0 {
        // The SDM requires enabling xAPIC before x2APIC; setting both from a
        // fully disabled APIC can raise #GP.
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
    let svr = rdmsr(X2APIC_SVR);
    wrmsr(
        X2APIC_SVR,
        svr | X2APIC_SVR_ENABLE | u64::from(SPURIOUS_VECTOR),
    );
    true
}

/// Acknowledge an interrupt after x2APIC initialization. Never use for the
/// spurious vector, which does not have an in-service bit to clear.
#[inline]
pub fn eoi() {
    wrmsr(X2APIC_EOI, 0);
}

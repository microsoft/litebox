// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hardware speculation controls protecting the VTL1 kernel from userspace
//! (VTL0 -> VTL1 attacks are Hyper-V's job). Each control is enabled only if
//! the CPU, as exposed by Hyper-V, enumerates it:
//!
//! - Intel eIBRS or AMD AutoIBRS: Userspace cannot steer kernel indirect branches.
//! - `BHI_DIS_S`, `RRSBA_DIS_S`: close the BHI and RSB-underflow gaps in eIBRS.
//! - `VERW` in `switch_to_user` unless the CPU reports it is not affected by
//!   Intel MDS/TAA/RFDS or AMD TSA. Like Linux in a VM, Intel CPUs run it even
//!   without `MD_CLEAR`, since the host may have the microcode.
//!
//! Like Linux, SSBD stays off. `IA32_SPEC_CTRL` and `EFER` are VTL-private on
//! Hyper-V (verified on hardware; OpenHCL's `is_vtl_shared_reg` agrees), so
//! they are written once per core with no save/restore on VTL switches.

use super::instrs::{rdmsr, wrmsr};
use super::msr::MSR_EFER;
use core::arch::x86_64::__cpuid_count;

const MSR_IA32_SPEC_CTRL: u32 = 0x48;
const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x10a;

const SPEC_CTRL_IBRS: u64 = 1 << 0;
const SPEC_CTRL_RRSBA_DIS_S: u64 = 1 << 6;
const SPEC_CTRL_BHI_DIS_S: u64 = 1 << 10;

const ARCH_CAP_IBRS_ALL: u64 = 1 << 1;
const ARCH_CAP_MDS_NO: u64 = 1 << 5;
const ARCH_CAP_TAA_NO: u64 = 1 << 8;
const ARCH_CAP_BHI_NO: u64 = 1 << 20;
const ARCH_CAP_RFDS_NO: u64 = 1 << 27;

const EFER_AUTOIBRS: u64 = 1 << 21;

/// Test bit `n` of a CPUID register.
fn bit(reg: u32, n: u32) -> bool {
    reg & (1 << n) != 0
}

/// Read CPUID `leaf`/`subleaf` if `leaf` is within the supported range.
fn cpuid(leaf: u32, subleaf: u32) -> Option<core::arch::x86_64::CpuidResult> {
    let max = __cpuid_count(leaf & 0x8000_0000, 0).eax;
    (leaf <= max).then(|| __cpuid_count(leaf, subleaf))
}

fn srso_user_kernel_immune(eax: u32) -> bool {
    // CPUID.8000_0021:EAX: SRSO_NO[29], SRSO_USER_KERNEL_NO[30].
    bit(eax, 29) || bit(eax, 30)
}

fn bhi_protected(spec_ctrl: u64, arch_caps: u64) -> bool {
    spec_ctrl & SPEC_CTRL_BHI_DIS_S != 0 || arch_caps & ARCH_CAP_BHI_NO != 0
}

/// What VTL1 configures on each core.
struct Config {
    spec_ctrl: u64,
    auto_ibrs: bool,
    verw: bool,
    arch_caps: u64,
}

impl Config {
    fn detect() -> Self {
        let cpuid_info = raw_cpuid::CpuId::new();
        let is_intel = cpuid_info
            .get_vendor_info()
            .is_some_and(|v| v.as_str() == "GenuineIntel");
        let auto_ibrs = cpuid_info
            .get_extended_feature_identification_2()
            .is_some_and(|f| f.has_automatic_ibrs());

        // Leaf 7 bits that raw-cpuid does not expose.
        let l7_edx = cpuid(7, 0).map_or(0, |r| r.edx);
        let l7_2_edx = cpuid(7, 2).map_or(0, |r| r.edx);
        let arch_caps = if bit(l7_edx, 29) {
            rdmsr(MSR_IA32_ARCH_CAPABILITIES)
        } else {
            0
        };

        let mut spec_ctrl = 0;
        if bit(l7_edx, 26) && arch_caps & ARCH_CAP_IBRS_ALL != 0 && !auto_ibrs {
            spec_ctrl |= SPEC_CTRL_IBRS; // eIBRS
        }
        if bit(l7_2_edx, 2) {
            spec_ctrl |= SPEC_CTRL_RRSBA_DIS_S;
        }
        if bit(l7_2_edx, 4) {
            spec_ctrl |= SPEC_CTRL_BHI_DIS_S;
        }

        let verw = if is_intel {
            let not_affected = ARCH_CAP_MDS_NO | ARCH_CAP_TAA_NO | ARCH_CAP_RFDS_NO;
            arch_caps & not_affected != not_affected
        } else {
            // AMD TSA: needs VERW_CLEAR unless TSA_SQ_NO and TSA_L1_NO.
            cpuid(0x8000_0021, 0)
                .is_some_and(|r| bit(r.eax, 5) && !(bit(r.ecx, 1) && bit(r.ecx, 2)))
        };

        Config {
            spec_ctrl,
            auto_ibrs,
            verw,
            arch_caps,
        }
    }
}

/// Enable hardware speculation controls on the current core.
///
/// Must be called on every core after the GDT is set up.
///
/// # Panics
///
/// Panics if the GDT is not initialized for the current core.
pub fn init(is_bsp: bool) {
    let cfg = Config::detect();

    if cfg.auto_ibrs {
        let efer = rdmsr(MSR_EFER);
        if efer & EFER_AUTOIBRS == 0 {
            wrmsr(MSR_EFER, efer | EFER_AUTOIBRS);
        }
    }

    // A nonzero value implies the MSR exists (each bit is enumerated above).
    if cfg.spec_ctrl != 0 && rdmsr(MSR_IA32_SPEC_CTRL) != cfg.spec_ctrl {
        wrmsr(MSR_IA32_SPEC_CTRL, cfg.spec_ctrl);
    }

    if cfg.verw {
        crate::host::per_cpu_variables::with_per_cpu_variables(|pcv| {
            let sel = pcv
                .get_kernel_data_selector()
                .expect("GDT not initialized for the current core");
            pcv.asm.set_verw_sel(sel);
        });
    }

    if is_bsp {
        crate::serial_println!(
            "spec_ctrl: SPEC_CTRL={:#x} AutoIBRS={} VERW={} ARCH_CAPABILITIES={:#x}",
            cfg.spec_ctrl,
            cfg.auto_ibrs,
            cfg.verw,
            cfg.arch_caps
        );
        if cfg.spec_ctrl & SPEC_CTRL_IBRS == 0 && !cfg.auto_ibrs {
            crate::serial_println!("spec_ctrl: WARNING: no eIBRS/AutoIBRS (Spectre v2 exposed)");
        }
        let cpu = raw_cpuid::CpuId::new();
        if let Some(vendor) = cpu.get_vendor_info() {
            if vendor.as_str() == "AuthenticAMD"
                && !srso_user_kernel_immune(cpuid(0x8000_0021, 0).map_or(0, |r| r.eax))
            {
                crate::serial_println!(
                    "spec_ctrl: WARNING: SRSO user/kernel immunity not reported; kernel returns unmitigated"
                );
            }
            if vendor.as_str() == "GenuineIntel"
                && cfg.spec_ctrl & SPEC_CTRL_IBRS != 0
                && !bhi_protected(cfg.spec_ctrl, cfg.arch_caps)
            {
                crate::serial_println!("spec_ctrl: WARNING: eIBRS without BHI protection");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srso_immunity_requires_an_explicit_no_bit() {
        assert!(!srso_user_kernel_immune(0));
        assert!(!srso_user_kernel_immune(1 << 28)); // IBPB_BRTYPE alone is insufficient.
        assert!(srso_user_kernel_immune(1 << 29));
        assert!(srso_user_kernel_immune(1 << 30));
    }

    #[test]
    fn eibrs_alone_does_not_cover_bhi() {
        assert!(!bhi_protected(SPEC_CTRL_IBRS, 0));
        assert!(bhi_protected(SPEC_CTRL_IBRS | SPEC_CTRL_BHI_DIS_S, 0));
        assert!(bhi_protected(SPEC_CTRL_IBRS, ARCH_CAP_BHI_NO));
    }
}

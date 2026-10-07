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
//!
//! The PRK vault adds IBPB, STIBP, SSBD, L1D flush, and `VERW`; see `VaultControls`.

use super::instrs::{rdmsr, wrmsr};
use super::msr::MSR_EFER;
use core::arch::x86_64::__cpuid_count;

const MSR_IA32_SPEC_CTRL: u32 = 0x48;
const MSR_IA32_PRED_CMD: u32 = 0x49;
const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x10a;
const MSR_IA32_FLUSH_CMD: u32 = 0x10b;

const SPEC_CTRL_IBRS: u64 = 1 << 0;
const SPEC_CTRL_STIBP: u64 = 1 << 1;
const SPEC_CTRL_SSBD: u64 = 1 << 2;
const SPEC_CTRL_RRSBA_DIS_S: u64 = 1 << 6;
const SPEC_CTRL_BHI_DIS_S: u64 = 1 << 10;

const PRED_CMD_IBPB: u64 = 1 << 0;
const FLUSH_CMD_L1D: u64 = 1 << 0;

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

/// Costly controls used only around the (rarely entered) vault: IBPB on
/// entry and exit, STIBP and SSBD inside, and L1D flush on exit (the vault
/// trampoline also clears CPU buffers).
/// eIBRS also blocks branch-target injection from the sibling hyperthread;
/// AMD AutoIBRS does not, so STIBP is set explicitly.
pub(crate) struct VaultControls {
    ibpb: bool,
    /// IBPB also flushes return predictions (always on Intel; AMD needs
    /// IBPB_BRTYPE, else SRSO survives it).
    ibpb_brtype: bool,
    l1d_flush: bool,
    /// `IA32_SPEC_CTRL` bits set inside the vault.
    spec_ctrl: u64,
}

#[must_use = "pass to `VaultControls::exit`"]
pub(crate) struct VaultSpecState {
    saved_spec_ctrl: Option<u64>,
}

impl VaultControls {
    pub(crate) fn detect() -> Self {
        let l7_edx = cpuid(7, 0).map_or(0, |r| r.edx);
        let amd_ebx = cpuid(0x8000_0008, 0).map_or(0, |r| r.ebx);

        // Intel: CPUID.7.0:EDX[26] IBRS/IBPB, [27] STIBP, [28] L1D_FLUSH, [31] SSBD.
        // AMD: CPUID.8000_0008:EBX[12] IBPB, [15] STIBP, [24] SSBD.
        let mut spec_ctrl = 0;
        if bit(l7_edx, 27) || bit(amd_ebx, 15) {
            spec_ctrl |= SPEC_CTRL_STIBP;
        }
        if bit(l7_edx, 31) || bit(amd_ebx, 24) {
            spec_ctrl |= SPEC_CTRL_SSBD;
        }
        let ibpb = bit(l7_edx, 26) || bit(amd_ebx, 12);
        // AMD: IBPB_BRTYPE is CPUID.8000_0021:EAX[28].
        let is_amd = raw_cpuid::CpuId::new()
            .get_vendor_info()
            .is_some_and(|v| v.as_str() == "AuthenticAMD");
        let ibpb_brtype =
            ibpb && (!is_amd || cpuid(0x8000_0021, 0).is_some_and(|r| bit(r.eax, 28)));
        Self {
            ibpb,
            ibpb_brtype,
            l1d_flush: bit(l7_edx, 28),
            spec_ctrl,
        }
    }

    /// Apply vault controls. Call with interrupts disabled; pair with [`Self::exit`].
    pub(crate) fn enter(&self) -> VaultSpecState {
        let saved_spec_ctrl = (self.spec_ctrl != 0).then(|| {
            // STIBP/SSBD imply `IA32_SPEC_CTRL` exists.
            let saved = rdmsr(MSR_IA32_SPEC_CTRL);
            wrmsr(MSR_IA32_SPEC_CTRL, saved | self.spec_ctrl);
            saved
        });
        self.ibpb();
        VaultSpecState { saved_spec_ctrl }
    }

    /// Scrub microarchitectural state and undo [`Self::enter`].
    pub(crate) fn exit(&self, state: VaultSpecState) {
        self.flush_l1d();
        self.ibpb();
        if let Some(saved) = state.saved_spec_ctrl {
            wrmsr(MSR_IA32_SPEC_CTRL, saved);
        }
    }

    pub(crate) fn has_l1d_flush(&self) -> bool {
        self.l1d_flush
    }

    /// Flush L1D if supported.
    pub(crate) fn flush_l1d(&self) {
        if self.l1d_flush {
            wrmsr(MSR_IA32_FLUSH_CMD, FLUSH_CMD_L1D);
        }
    }

    fn ibpb(&self) {
        if self.ibpb {
            wrmsr(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
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
        let vault = VaultControls::detect();
        crate::serial_println!(
            "spec_ctrl: vault IBPB={} IBPB_BRTYPE={} STIBP={} SSBD={} L1D_FLUSH={}",
            vault.ibpb,
            vault.ibpb_brtype,
            vault.spec_ctrl & SPEC_CTRL_STIBP != 0,
            vault.spec_ctrl & SPEC_CTRL_SSBD != 0,
            vault.l1d_flush
        );
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

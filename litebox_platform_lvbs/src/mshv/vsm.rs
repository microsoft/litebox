//! VSM functions

use crate::{
    mshv::{
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HvCrInterceptControlFlags, HvPageProtFlags,
        VSM_VTL_CALL_FUNC_ID_BOOT_APS, VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY,
        VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL, VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT,
        VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE, VSM_VTL_CALL_FUNC_ID_LOAD_KDATA,
        VSM_VTL_CALL_FUNC_ID_LOCK_REGS, VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY,
        VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT, VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE,
        VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE, X86Cr0Flags, X86Cr4Flags,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_set_vp_registers, init_vtl_aps},
    },
    serial_println,
};
use num_enum::TryFromPrimitive;

/// VTL call parameters (param[0]: function ID, param[1-3]: parameters)
pub const NUM_VTLCALL_PARAMS: usize = 4;

/// VSM function for enabling VTL of APs
/// # Panics
/// Panics if hypercall for initializing VTL for APs fails
pub fn mshv_vsm_enable_aps(_cpu_present_mask: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Enable VTL of APs");

    let num_cores = 6; // TODO: use cpumask
    if let Err(result) = init_vtl_aps(num_cores) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }
    0
}

/// VSM function for booting APs
pub fn mshv_vsm_boot_aps(_cpu_online_mask_pfn: u64, _boot_signal_pfn: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Boot APs");
    // TODO: update boot signal page accordingly
    0
}

/// VSM function for locking control registers
pub fn mshv_vsm_lock_regs() -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Lock control registers");

    let flag = HvCrInterceptControlFlags::CR0_WRITE.bits()
        | HvCrInterceptControlFlags::CR4_WRITE.bits()
        | HvCrInterceptControlFlags::GDTR_WRITE.bits()
        | HvCrInterceptControlFlags::IDTR_WRITE.bits()
        | HvCrInterceptControlFlags::LDTR_WRITE.bits()
        | HvCrInterceptControlFlags::TR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_LSTAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_STAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_CSTAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_APIC_BASE_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_EFER_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_CS_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_ESP_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_EIP_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SFMASK_WRITE.bits();

    if let Err(result) = hvcall_set_vp_registers(HV_REGISTER_CR_INTERCEPT_CONTROL, flag, 0) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    if let Err(result) = hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR4_MASK,
        X86Cr4Flags::CR4_PIN_MASK.bits().into(),
        0,
    ) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    if let Err(result) = hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        X86Cr0Flags::CR0_PIN_MASK.bits().into(),
        0,
    ) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    0
}

/// VSM function for signaling end of boot
pub fn mshv_vsm_end_of_boot() -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: End of boot");
    // TODO: update global data structure
    0
}

/// VSM function for protecting certain memory range
pub fn mshv_vsm_protect_memory(_pa: u64, nranges: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Protect memory");

    // TODO: mmap pa

    // TODO: walk the ranges and apply the permissions for each guest page
    for _r in 0..nranges {
        // TODO: get the range info from pa
        let start = 0;
        let num = 0;
        let prot = HvPageProtFlags::HV_PAGE_FULL_ACCESS;

        if let Err(result) = hv_modify_vtl_protection_mask(start, num, prot) {
            serial_println!("Err: {:?}", result);
            let err: u32 = result.into();
            return err.into();
        }
    }

    0
}

/// VSM function for loading kernel data into VTL1
pub fn mshv_vsm_load_kdata(_pa: u64, _nranges: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Lock kernel data");
    // TODO: load kernel data
    0
}

/// VSM function for validating guest kernel module
pub fn mshv_vsm_validate_guest_module(_pa: u64, _nranges: u64, _flags: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Validate kernel module");
    // TODO: validate kernel module
    0
}

/// VSM function for initializing guest kernel module
pub fn mshv_vsm_free_guest_module_init(_token: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Free kernel module init");
    // TODO: free kernel module
    0
}

/// VSM function for unloading guest kernel module
pub fn mshv_vsm_unload_guest_module(_token: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Unload kernel module");
    // TODO: unload kernel module
    0
}

/// VSM function for copying secondary key
pub fn mshv_vsm_copy_secondary_key(_pa: u64, _nranges: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Copy secondary key");
    // TODO: copy secondary key
    0
}

/// VSM function for validating kexec
pub fn mshv_vsm_kexec_validate(_pa: u64, _nranges: u64, _crash: u64) -> u64 {
    #[cfg(debug_assertions)]
    serial_println!("VSM: Validate kexec");
    // TODO: validate kexec
    0
}

/// VSM function dispatcher
/// # Panics
/// Panics if VTL call parameter 0 is greater than u32::MAX
pub fn vsm_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> u64 {
    if params[0] > u32::MAX.into() {
        serial_println!("VSM: Unknown function ID {:#x}", params[0]);
        return 1;
    }

    match VSMFunction::try_from(u32::try_from(params[0]).expect("VTL call param 0"))
        .unwrap_or(VSMFunction::Unknown)
    {
        VSMFunction::EnableAPsVtl => mshv_vsm_enable_aps(params[1]),
        VSMFunction::BootAPs => mshv_vsm_boot_aps(params[1], params[2]),
        VSMFunction::LockRegs => mshv_vsm_lock_regs(),
        VSMFunction::SignalEndOfBoot => mshv_vsm_end_of_boot(),
        VSMFunction::ProtectMemory => mshv_vsm_protect_memory(params[1], params[2]),
        VSMFunction::LoadKData => mshv_vsm_load_kdata(params[1], params[2]),
        VSMFunction::ValidateModule => {
            mshv_vsm_validate_guest_module(params[1], params[2], params[3])
        }
        VSMFunction::FreeModuleInit => mshv_vsm_free_guest_module_init(params[1]),
        VSMFunction::UnloadModule => mshv_vsm_unload_guest_module(params[1]),
        VSMFunction::CopySecondaryKey => mshv_vsm_copy_secondary_key(params[1], params[2]),
        VSMFunction::KexecValidate => mshv_vsm_kexec_validate(params[1], params[2], params[3]),
        VSMFunction::Unknown => {
            serial_println!("VSM: Unknown function ID {:#x}", params[0]);

            1
        }
    }
}

/// VSM Functions
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum VSMFunction {
    EnableAPsVtl = VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL,
    BootAPs = VSM_VTL_CALL_FUNC_ID_BOOT_APS,
    LockRegs = VSM_VTL_CALL_FUNC_ID_LOCK_REGS,
    SignalEndOfBoot = VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT,
    ProtectMemory = VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY,
    LoadKData = VSM_VTL_CALL_FUNC_ID_LOAD_KDATA,
    ValidateModule = VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE,
    FreeModuleInit = VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT,
    UnloadModule = VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE,
    CopySecondaryKey = VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY,
    KexecValidate = VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE,
    Unknown = 0xffff_ffff,
}

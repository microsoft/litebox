//! VSM functions

use crate::{
    debug_serial_print, debug_serial_println,
    host::{
        bootparam::{get_num_possible_cpus, get_vtl1_memory_info},
        linux::CpuMask,
    },
    kernel_context::{get_core_id, get_per_core_kernel_context},
    mshv::{
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HV_REGISTER_VSM_PARTITION_CONFIG,
        HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, HV_SECURE_VTL_BOOT_TOKEN, HV_X64_REGISTER_APIC_BASE,
        HV_X64_REGISTER_CR0, HV_X64_REGISTER_CR4, HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER,
        HV_X64_REGISTER_LSTAR, HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR,
        HV_X64_REGISTER_SYSENTER_CS, HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP,
        HvCrInterceptControlFlags, HvPageProtFlags, HvRegisterVsmPartitionConfig,
        HvRegisterVsmVpSecureVtlConfig, VSM_VTL_CALL_FUNC_ID_BOOT_APS,
        VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY, VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL,
        VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT, VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE,
        VSM_VTL_CALL_FUNC_ID_LOAD_KDATA, VSM_VTL_CALL_FUNC_ID_LOCK_REGS,
        VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY, VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT,
        VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE, VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE, X86Cr0Flags,
        X86Cr4Flags,
        heki::{HEKI_MAX_RANGES, HekiPage, MemAttr},
        hvcall::HypervCallError,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers, init_vtl_aps},
        vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE},
    },
    serial_println,
};
use num_enum::TryFromPrimitive;

/// VTL call parameters (param[0]: function ID, param[1-3]: parameters)
pub const NUM_VTLCALL_PARAMS: usize = 4;

pub fn init() {
    if get_core_id() == 0 && mshv_vsm_configure_partition() != 0 {
        return;
    }

    if mshv_vsm_secure_config_vtl0() != 0 {
        return;
    }

    if get_core_id() == 0 {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            debug_serial_println!("VSM: Protect GPAs from {:#x} to {:#x}", start, start + size);
            let num_pages = size >> PAGE_SHIFT;
            let prot = HvPageProtFlags::HV_PAGE_ACCESS_NONE;
            if let Err(result) = hv_modify_vtl_protection_mask(start, num_pages, prot) {
                serial_println!("Err: {:?}", result);
            }
        } else {
            serial_println!("Failed to get memory info");
        }
    }
}

/// VSM function for enabling VTL of APs
/// # Panics
/// Panics if hypercall for initializing VTL for APs fails
pub fn mshv_vsm_enable_aps(cpu_present_mask_pfn: u64) -> u64 {
    debug_serial_println!("VSM: Enable VTL of APs");

    if let Some(cpu_mask) = unsafe {
        crate::platform_low().copy_from_vtl0_phys::<CpuMask>(x86_64::PhysAddr::new(
            cpu_present_mask_pfn << PAGE_SHIFT,
        ))
    } {
        debug_serial_print!("cpu_present_mask: ");
        for (i, elem) in cpu_mask.decode_cpu_mask().iter().enumerate() {
            if *elem {
                debug_serial_print!("{}, ", i);
            }
        }
        debug_serial_println!("");
    } else {
        serial_println!("Failed to get cpu_present_mask");
        return 1;
    }

    // TODO: cpu_present_mask vs num_possible_cpus in kernel command line. which one should we use?
    let Ok(num_cores) = get_num_possible_cpus() else {
        serial_println!("Failed to get number of possible cores");
        return 1;
    };

    debug_serial_println!("the number of possible cores: {}", num_cores);

    if let Err(result) = init_vtl_aps(num_cores) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }
    0
}

/// VSM function for booting APs
pub fn mshv_vsm_boot_aps(cpu_online_mask_pfn: u64, boot_signal_pfn: u64) -> u64 {
    debug_serial_println!("VSM: Boot APs");

    if let Some(cpu_mask) = unsafe {
        crate::platform_low().copy_from_vtl0_phys::<CpuMask>(x86_64::PhysAddr::new(
            cpu_online_mask_pfn << PAGE_SHIFT,
        ))
    } {
        debug_serial_print!("cpu_online_mask: ");
        for (i, elem) in cpu_mask.decode_cpu_mask().iter().enumerate() {
            if *elem {
                debug_serial_print!("{}, ", i);
            }
        }
        debug_serial_println!("");
    } else {
        serial_println!("Failed to get cpu_online_mask");
        return 1;
    }

    // boot_signal is an array of bytes whose length is the number of possible cores. Copy the entire page for now.
    if let Some(mut boot_signal_page) = unsafe {
        crate::platform_low().copy_from_vtl0_phys::<[u8; PAGE_SIZE]>(x86_64::PhysAddr::new(
            boot_signal_pfn << PAGE_SHIFT,
        ))
    } {
        // TODO: execute `init_vtl_ap` for each online core and update the corresponding boot signal byte.
        // Currently, we use `init_vtl_aps` to initialize all present cores which
        // takes a long time if we have a lot of cores.
        debug_serial_println!("updating boot signal page");
        for i in 0..get_num_possible_cpus().unwrap_or(0) {
            boot_signal_page[i as usize] = HV_SECURE_VTL_BOOT_TOKEN;
        }

        if !unsafe {
            crate::platform_low().copy_to_vtl0_phys::<[u8; PAGE_SIZE]>(
                x86_64::PhysAddr::new(boot_signal_pfn << PAGE_SHIFT),
                &boot_signal_page,
            )
        } {
            serial_println!("Failed to copy boot signal page to VTL0");
            return 1;
        }
    } else {
        serial_println!("Failed to get boot signal page");
        return 1;
    }

    0
}

pub fn mshv_vsm_secure_config_vtl0() -> u64 {
    debug_serial_println!("VSM: Secure VTL0 configuration");

    let mut config = HvRegisterVsmVpSecureVtlConfig::new();
    config.set_mbec_enabled();
    config.set_tlb_locked();

    if let Err(result) =
        hvcall_set_vp_registers(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, config.as_u64())
    {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    0
}

pub fn mshv_vsm_configure_partition() -> u64 {
    debug_serial_println!("VSM: Configure partition");

    let mut config = HvRegisterVsmPartitionConfig::new();
    config.set_default_vtl_protection_mask(HvPageProtFlags::HV_PAGE_FULL_ACCESS.bits().into());
    config.set_enable_vtl_protection();

    if let Err(result) = hvcall_set_vp_registers(HV_REGISTER_VSM_PARTITION_CONFIG, config.as_u64())
    {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    0
}

pub fn save_vtl0_locked_regs() -> Result<u64, HypervCallError> {
    let kernel_context = get_per_core_kernel_context();

    kernel_context.vtl0_locked_regs.init();
    let reg_names = kernel_context.vtl0_locked_regs.reg_names();

    for reg_name in reg_names {
        match hvcall_get_vp_vtl0_registers(reg_name) {
            Ok(value) => kernel_context.vtl0_locked_regs.set(reg_name, value),
            Err(err) => {
                return Err(err);
            }
        }
    }

    Ok(0)
}

/// VSM function for locking control registers
pub fn mshv_vsm_lock_regs() -> u64 {
    debug_serial_println!("VSM: Lock control registers");

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

    if let Err(result) = save_vtl0_locked_regs() {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    if let Err(result) = hvcall_set_vp_registers(HV_REGISTER_CR_INTERCEPT_CONTROL, flag) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    if let Err(result) = hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR4_MASK,
        X86Cr4Flags::CR4_PIN_MASK.bits().into(),
    ) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    if let Err(result) = hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        X86Cr0Flags::CR0_PIN_MASK.bits().into(),
    ) {
        serial_println!("Err: {:?}", result);
        let err: u32 = result.into();
        return err.into();
    }

    0
}

/// VSM function for signaling end of boot
pub fn mshv_vsm_end_of_boot() -> u64 {
    debug_serial_println!("VSM: End of boot");
    // TODO: update global data structure
    0
}

/// VSM function for protecting certain memory range
pub fn mshv_vsm_protect_memory(pa: u64, nranges: u64) -> u64 {
    if let Some(heki_page) =
        unsafe { crate::platform_low().copy_from_vtl0_phys::<HekiPage>(x86_64::PhysAddr::new(pa)) }
    {
        // TODO: handle multi-paged input by walking through the pages
        for i in 0..core::cmp::min(usize::try_from(nranges).unwrap(), HEKI_MAX_RANGES) {
            let va = heki_page.ranges[i].va;
            let pa = heki_page.ranges[i].pa;
            let epa = heki_page.ranges[i].epa;
            let attr = heki_page.ranges[i].attributes;
            let attr: MemAttr = MemAttr::from_bits(attr).unwrap_or(MemAttr::empty());
            // TODO: protect memory using hv_modify_protection_mask() once we implement the GPA intercept handler
            // (without a working GPA intercept handler, this memory protection hangs the kernel).
            // for now, this function is a no-op and just prints the memory range we should protect.
            debug_serial_println!(
                "VSM: Protect memory: va {:#x} pa {:#x} epa {:#x} {:?} (size: {})",
                va,
                pa,
                epa,
                attr,
                epa - pa
            );
        }
    } else {
        serial_println!("Failed to get VTL0 memory for mshv_vsm_protect_memory");
        return 1;
    }
    0
}

/// VSM function for loading kernel data into VTL1
pub fn mshv_vsm_load_kdata(pa: u64, nranges: u64) -> u64 {
    if let Some(heki_page) =
        unsafe { crate::platform_low().copy_from_vtl0_phys::<HekiPage>(x86_64::PhysAddr::new(pa)) }
    {
        // TODO: handle multi-paged input walking through the pages
        for i in 0..core::cmp::min(usize::try_from(nranges).unwrap(), HEKI_MAX_RANGES) {
            let va = heki_page.ranges[i].va;
            let pa = heki_page.ranges[i].pa;
            let epa = heki_page.ranges[i].epa;
            let attr = heki_page.ranges[i].attributes;
            let attr: MemAttr = MemAttr::from_bits(attr).unwrap_or(MemAttr::empty());
            // TODO: load kernel data (e.g., into `BTreeMap` or other data structures) once we implement data consumers like `mshv_vsm_validate_guest_module`.
            // for now, this function is a no-op and just prints the memory range we should load.
            debug_serial_println!(
                "VSM: Load kernel data: va {:#x} pa {:#x} epa {:#x} {:?} (size: {})",
                va,
                pa,
                epa,
                attr,
                epa - pa
            );
        }
    } else {
        serial_println!("Failed to get VTL0 memory for mshv_vsm_load_kdata");
        return 1;
    }
    0
}

/// VSM function for validating guest kernel module
pub fn mshv_vsm_validate_guest_module(_pa: u64, _nranges: u64, _flags: u64) -> u64 {
    debug_serial_println!("VSM: Validate kernel module");
    // TODO: validate kernel module
    0
}

/// VSM function for initializing guest kernel module
pub fn mshv_vsm_free_guest_module_init(_token: u64) -> u64 {
    debug_serial_println!("VSM: Free kernel module init");
    // TODO: free kernel module
    0
}

/// VSM function for unloading guest kernel module
pub fn mshv_vsm_unload_guest_module(_token: u64) -> u64 {
    debug_serial_println!("VSM: Unload kernel module");
    // TODO: unload kernel module
    0
}

/// VSM function for copying secondary key
pub fn mshv_vsm_copy_secondary_key(_pa: u64, _nranges: u64) -> u64 {
    debug_serial_println!("VSM: Copy secondary key");
    // TODO: copy secondary key
    0
}

/// VSM function for validating kexec
pub fn mshv_vsm_kexec_validate(_pa: u64, _nranges: u64, _crash: u64) -> u64 {
    debug_serial_println!("VSM: Validate kexec");
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

pub const NUM_CONTROL_REGS: usize = 11;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ControlRegMap {
    pub entries: [(u32, u64); NUM_CONTROL_REGS],
}

impl ControlRegMap {
    pub fn init(&mut self) {
        // A list of control registers whose values will be locked.
        [
            HV_X64_REGISTER_CR0,
            HV_X64_REGISTER_CR4,
            HV_X64_REGISTER_LSTAR,
            HV_X64_REGISTER_STAR,
            HV_X64_REGISTER_CSTAR,
            HV_X64_REGISTER_APIC_BASE,
            HV_X64_REGISTER_EFER,
            HV_X64_REGISTER_SYSENTER_CS,
            HV_X64_REGISTER_SYSENTER_ESP,
            HV_X64_REGISTER_SYSENTER_EIP,
            HV_X64_REGISTER_SFMASK,
        ]
        .iter()
        .enumerate()
        .for_each(|(i, &reg_name)| {
            self.entries[i] = (reg_name, 0);
        });
    }

    pub fn get(&self, reg_name: u32) -> Option<u64> {
        for entry in &self.entries {
            if entry.0 == reg_name {
                return Some(entry.1);
            }
        }
        None
    }

    pub fn set(&mut self, reg_name: u32, value: u64) {
        for entry in &mut self.entries {
            if entry.0 == reg_name {
                entry.1 = value;
                return;
            }
        }
    }

    // consider implementing a mutable iterator (if we plan to lock many control registers)
    pub fn reg_names(&self) -> [u32; NUM_CONTROL_REGS] {
        let mut names = [0; NUM_CONTROL_REGS];
        for (i, entry) in self.entries.iter().enumerate() {
            names[i] = entry.0;
        }
        names
    }
}

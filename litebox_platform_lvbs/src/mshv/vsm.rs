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
        heki::{
            HekiKdataType, HekiPage, MemAttr, ModMemType, mem_attr_to_hv_page_prot_flags,
            mod_mem_type_to_mem_attr,
        },
        hvcall::HypervCallError,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers, init_vtl_aps},
        vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE},
    },
    serial_println,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use x86_64::structures::paging::{PhysFrame, Size4KiB, frame::PhysFrameRange};

/// VTL call parameters (param[0]: function ID, param[1-3]: parameters)
pub const NUM_VTLCALL_PARAMS: usize = 4;

/// Error for VSM functions. This is just negative Linux error code but we use `u64`` as we return `u64` values to VTL0.
#[derive(Debug, IntoPrimitive)]
#[repr(u64)]
pub enum VsmError {
    NotPermitted = u64::MAX,
    NoMem = u64::MAX - 12 + 1,
    Fault = u64::MAX - 14 + 1,
    Invalid = u64::MAX - 22 + 1,
}

pub fn init() {
    assert!(
        !(get_core_id() == 0 && mshv_vsm_configure_partition() != 0),
        "Failed to configure VSM partition"
    );

    assert!(
        (mshv_vsm_secure_config_vtl0() == 0),
        "Failed to secure VTL0 configuration"
    );

    if get_core_id() == 0 {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            debug_serial_println!("VSM: Protect GPAs from {:#x} to {:#x}", start, start + size);
            if protect_physical_memory_range(
                PhysFrame::range(
                    PhysFrame::containing_address(x86_64::PhysAddr::new(start)),
                    PhysFrame::containing_address(x86_64::PhysAddr::new(start + size)),
                ),
                MemAttr::empty(),
            )
            .is_err()
            {
                panic!("Failed to protect VTL1 memory");
            }
        } else {
            panic!("Failed to get VTL1 memory info");
        }
    }
}

/// VSM function for enabling VTL of APs
/// `cpu_present_mask_pfn` indicates the page containing the VTL0's CPU present mask.
///
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
        return VsmError::Invalid.into();
    }

    // TODO: cpu_present_mask vs num_possible_cpus in kernel command line. which one should we use?
    let Ok(num_cores) = get_num_possible_cpus() else {
        serial_println!("Failed to get number of possible cores");
        return VsmError::Invalid.into();
    };

    debug_serial_println!("the number of possible cores: {}", num_cores);

    if let Err(result) = init_vtl_aps(num_cores) {
        serial_println!("Err: {:?}", result);
        return VsmError::Invalid.into();
    }
    0
}

/// VSM function for booting APs
/// `cpu_online_mask_pfn` indicates the page containing the VTL0's CPU online mask.
/// `boot_signal_pfn` indicates the boot signal page to let VTL0 know that VTL1 is ready.
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
        return VsmError::Invalid.into();
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
            return VsmError::Invalid.into();
        }
    } else {
        serial_println!("Failed to get boot signal page");
        return VsmError::Invalid.into();
    }

    0
}

/// VSM function for enforcing certain security features of VTL0
pub fn mshv_vsm_secure_config_vtl0() -> u64 {
    debug_serial_println!("VSM: Secure VTL0 configuration");

    let mut config = HvRegisterVsmVpSecureVtlConfig::new();
    config.set_mbec_enabled();
    config.set_tlb_locked();

    if let Err(result) =
        hvcall_set_vp_registers(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, config.as_u64())
    {
        serial_println!("Err: {:?}", result);
        return VsmError::Fault.into();
    }

    0
}

/// VSM function to configure a VSM partition for VTL1
pub fn mshv_vsm_configure_partition() -> u64 {
    debug_serial_println!("VSM: Configure partition");

    let mut config = HvRegisterVsmPartitionConfig::new();
    config.set_default_vtl_protection_mask(HvPageProtFlags::HV_PAGE_FULL_ACCESS.bits().into());
    config.set_enable_vtl_protection();

    if let Err(result) = hvcall_set_vp_registers(HV_REGISTER_VSM_PARTITION_CONFIG, config.as_u64())
    {
        serial_println!("Err: {:?}", result);
        return VsmError::Fault.into();
    }

    0
}

/// VSM function for locking VTL0's control registers.
pub fn mshv_vsm_lock_regs() -> u64 {
    debug_serial_println!("VSM: Lock control registers");

    if crate::platform_low().check_end_of_boot() {
        serial_println!(
            "VSM: VTL0 is not allowed to change control register locking after the end of boot process"
        );
        return VsmError::Invalid.into();
    }

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
        return VsmError::Fault.into();
    }

    if let Err(result) = hvcall_set_vp_registers(HV_REGISTER_CR_INTERCEPT_CONTROL, flag) {
        serial_println!("Err: {:?}", result);
        return VsmError::Fault.into();
    }

    if let Err(result) = hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR4_MASK,
        X86Cr4Flags::CR4_PIN_MASK.bits().into(),
    ) {
        serial_println!("Err: {:?}", result);
        return VsmError::Fault.into();
    }

    if let Err(result) = hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        X86Cr0Flags::CR0_PIN_MASK.bits().into(),
    ) {
        serial_println!("Err: {:?}", result);
        return VsmError::Fault.into();
    }

    0
}

/// VSM function for signaling the end of VTL0 boot process
pub fn mshv_vsm_end_of_boot() -> u64 {
    debug_serial_println!("VSM: End of boot");
    crate::platform_low().set_end_of_boot();
    0
}

/// VSM function for protecting certain memory ranges (e.g., kernel text, data, heap).
/// `pa` and `nranges` specify a memory area containing the information about the memory ranges to protect.
pub fn mshv_vsm_protect_memory(pa: u64, nranges: u64) -> u64 {
    if !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) || nranges == 0 {
        serial_println!("VSM: invalid input address");
        return VsmError::Invalid.into();
    }

    if crate::platform_low().check_end_of_boot() {
        serial_println!(
            "VSM: VTL0 is not allowed to change kernel memory protection after the end of boot process"
        );
        return VsmError::Invalid.into();
    }

    if let Some(heki_pages) = copy_heki_pages_from_vtl0(pa, nranges) {
        for heki_page in heki_pages {
            for i in 0..usize::try_from(heki_page.nranges).unwrap_or(0) {
                let va = heki_page.ranges[i].va;
                let pa = heki_page.ranges[i].pa;
                let epa = heki_page.ranges[i].epa;
                let attr = heki_page.ranges[i].attributes;
                let Some(mem_attr) = MemAttr::from_bits(attr) else {
                    serial_println!("VSM: Invalid memory attributes");
                    return VsmError::Invalid.into();
                };

                if !va.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                    || !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                    || !epa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                {
                    serial_println!("VSM: input address must be page-aligned");
                    return VsmError::Invalid.into();
                }

                debug_serial_println!(
                    "VSM: Protect memory: va {:#x} pa {:#x} epa {:#x} {:?} (size: {})",
                    va,
                    pa,
                    epa,
                    mem_attr,
                    epa - pa
                );

                if protect_physical_memory_range(
                    PhysFrame::range(
                        PhysFrame::containing_address(x86_64::PhysAddr::new(pa)),
                        PhysFrame::containing_address(x86_64::PhysAddr::new(epa)),
                    ),
                    mem_attr,
                )
                .is_err()
                {
                    return VsmError::Fault.into();
                }
            }
        }
        0
    } else {
        VsmError::Invalid.into()
    }
}

/// VSM function for loading kernel data (e.g., certificates, blocklist, kernel symbols) into VTL1.
/// `pa` and `nranges` specify memory areas containing the information about the memory ranges to load.
pub fn mshv_vsm_load_kdata(pa: u64, nranges: u64) -> u64 {
    if !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) || nranges == 0 {
        serial_println!("VSM: invalid input address");
        return VsmError::Invalid.into();
    }

    if crate::platform_low().check_end_of_boot() {
        serial_println!(
            "VSM: VTL0 is not allowed to load kernel data after the end of boot process"
        );
        return VsmError::Invalid.into();
    }

    if let Some(heki_pages) = copy_heki_pages_from_vtl0(pa, nranges) {
        for heki_page in heki_pages {
            for i in 0..usize::try_from(heki_page.nranges).unwrap_or(0) {
                let va = heki_page.ranges[i].va;
                let pa = heki_page.ranges[i].pa;
                let epa = heki_page.ranges[i].epa;
                let attr = heki_page.ranges[i].attributes;
                let kdata_type = HekiKdataType::try_from(attr).unwrap_or(HekiKdataType::Unknown);
                // TODO: load kernel data (e.g., into `BTreeMap` or other data structures) once we implement data consumers like `mshv_vsm_validate_guest_module`.
                // for now, this function is a no-op and just prints the memory range we should load.
                debug_serial_println!(
                    "VSM: Load kernel data: va {:#x} pa {:#x} epa {:#x} {:?} (size: {})",
                    va,
                    pa,
                    epa,
                    kdata_type,
                    epa - pa
                );
            }
        }
        0
    } else {
        VsmError::Invalid.into()
    }

    // TODO: create trusted keys
    // TODO: create blocklist keys
    // TODO: save blocklist hashes
    // TODO: get kernel info (i.e., kernel symbols)
}

/// VSM function for validating a guest kernel module and applying specified protection to its memory ranges after validation.
/// `pa` and `nranges` specify a memory area containing the information about the kernel module to validate or protect.
/// `flags` controls the validation process (unused for now).
/// This function returns a unique `token` to VTL0, which is used to identify the module in subsequent calls.
pub fn mshv_vsm_validate_guest_module(pa: u64, nranges: u64, _flags: u64) -> u64 {
    if !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) || nranges == 0 {
        serial_println!("VSM: invalid input address");
        return VsmError::Invalid.into();
    }

    debug_serial_println!(
        "VSM: Validate kernel module: pa {:#x} nranges {}",
        pa,
        nranges,
    );

    // collect and maintain the memory ranges of a module locally until the module is validated and registered in the global map
    let mut module_memory = ModuleMemory::new();

    if let Some(heki_pages) = copy_heki_pages_from_vtl0(pa, nranges) {
        for heki_page in heki_pages {
            for i in 0..usize::try_from(heki_page.nranges).unwrap_or(0) {
                let va = heki_page.ranges[i].va;
                let pa = heki_page.ranges[i].pa;
                let epa = heki_page.ranges[i].epa;
                let attr = heki_page.ranges[i].attributes;
                let mod_mem_type = ModMemType::try_from(attr).unwrap_or(ModMemType::Unknown);
                match mod_mem_type {
                    ModMemType::Unknown => {
                        serial_println!("VSM: Invalid module memory type");
                        return VsmError::Invalid.into();
                    }
                    ModMemType::ElfBuffer => { // TODO: store the ElfBuffer in a local data structure for validation.
                    }
                    _ => {
                        // if input memory range's type is neither `Unknown` nor `ElfBuffer`, its addresses must be page-aligned
                        if !va.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                            || !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                            || !epa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                        {
                            serial_println!("VSM: input address must be page-aligned");
                            return VsmError::Invalid.into();
                        }

                        module_memory.insert_memory_range(ModuleMemoryRange::new(
                            va,
                            pa,
                            epa,
                            mod_mem_type,
                        ));
                    }
                }
            }
        }
    } else {
        return VsmError::Invalid.into();
    }

    // TODO: validate a kernel module by analyzing its ELF binary and memory content. For now, we just assume the module is valid.

    // protect the memory ranges of a module based on their section types
    for mod_mem_range in &module_memory {
        if protect_physical_memory_range(
            mod_mem_range.phys_frame_range,
            mod_mem_type_to_mem_attr(mod_mem_range.mod_mem_type),
        )
        .is_err()
        {
            return VsmError::Fault.into();
        }
    }

    // register the module memory in the global map and obtain a unique token for it
    crate::platform_low()
        .vtl0_module_memory
        .register_module_memory(module_memory)
}

/// VSM function for supporting the initialization of a guest kernel module.
/// `token` is the unique identifier for the module.
pub fn mshv_vsm_free_guest_module_init(token: u64) -> u64 {
    debug_serial_println!("VSM: Free kernel module's init (token: {})", token);

    if !crate::platform_low().vtl0_module_memory.contains_key(token) {
        serial_println!("VSM: invalid module token");
        return VsmError::Invalid.into();
    }

    if let Some(entry) = crate::platform_low().vtl0_module_memory.iter_entry(token) {
        for mod_mem_range in entry.iter_mem_ranges() {
            match mod_mem_range.mod_mem_type {
                ModMemType::InitText | ModMemType::InitData | ModMemType::InitRoData => {
                    // make this memory range readable, writable, and non-executable after initialization to let the VTL0 kernel free it
                    if let Err(result) = protect_physical_memory_range(
                        mod_mem_range.phys_frame_range,
                        MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
                    ) {
                        return result;
                    }
                }
                ModMemType::RoAfterInit => {
                    // make this memory range read-only after initialization
                    if let Err(result) = protect_physical_memory_range(
                        mod_mem_range.phys_frame_range,
                        MemAttr::MEM_ATTR_READ,
                    ) {
                        return result;
                    }
                }
                _ => {}
            }
        }
    }

    0
}

/// VSM function for supporting the unloading of a guest kernel module.
/// `token` is the unique identifier for the module.
pub fn mshv_vsm_unload_guest_module(token: u64) -> u64 {
    debug_serial_println!("VSM: Unload kernel module (token: {})", token);

    if !crate::platform_low().vtl0_module_memory.contains_key(token) {
        serial_println!("VSM: invalid module token");
        return VsmError::Invalid.into();
    }

    if let Some(entry) = crate::platform_low().vtl0_module_memory.iter_entry(token) {
        // make the memory ranges of a module readable, writable, and non-executable to let the VTL0 kernel unload the module
        for mod_mem_range in entry.iter_mem_ranges() {
            if let Err(result) = protect_physical_memory_range(
                mod_mem_range.phys_frame_range,
                MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
            ) {
                return result;
            }
        }
    }

    crate::platform_low().vtl0_module_memory.remove(token);
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
pub fn vsm_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> u64 {
    if params[0] > u32::MAX.into() {
        serial_println!("VSM: Unknown function ID {:#x}", params[0]);
        return VsmError::Invalid.into();
    }

    match VSMFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
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
            VsmError::Invalid.into()
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

/// Data structure for maintaining MSRs and control registers whose values are locked.
/// This structure is expected to be stored in per-core kernel context, so we do not protect it with a lock.
#[derive(Debug, Clone, Copy)]
pub struct ControlRegMap {
    pub entries: [(u32, u64); NUM_CONTROL_REGS],
}

impl ControlRegMap {
    pub fn init(&mut self) {
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

fn save_vtl0_locked_regs() -> Result<u64, HypervCallError> {
    let kernel_context = get_per_core_kernel_context();

    kernel_context.vtl0_locked_regs.init();

    for reg_name in kernel_context.vtl0_locked_regs.reg_names() {
        let value = hvcall_get_vp_vtl0_registers(reg_name)?;
        kernel_context.vtl0_locked_regs.set(reg_name, value);
    }

    Ok(0)
}

/// Data structure for maintaining the memory ranges of each VTL0 kernel module and their types
pub struct ModuleMemoryMap {
    inner: spin::mutex::SpinMutex<BTreeMap<u64, ModuleMemory>>,
    key_gen: AtomicU64,
}

pub struct ModuleMemory {
    ranges: Vec<ModuleMemoryRange>,
}

impl ModuleMemory {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn insert_memory_range(&mut self, mem_range: ModuleMemoryRange) {
        self.ranges.push(mem_range);
    }
}

impl Default for ModuleMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a ModuleMemory {
    type Item = &'a ModuleMemoryRange;
    type IntoIter = core::slice::Iter<'a, ModuleMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct ModuleMemoryRange {
    pub virt_addr: x86_64::VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
    pub mod_mem_type: ModMemType,
}

impl ModuleMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64, mod_mem_type: ModMemType) -> Self {
        Self {
            virt_addr: x86_64::VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(x86_64::PhysAddr::new(phys_start)),
                PhysFrame::containing_address(x86_64::PhysAddr::new(phys_end)),
            ),
            mod_mem_type,
        }
    }
}

impl Default for ModuleMemoryRange {
    fn default() -> Self {
        Self::new(
            0,
            0,
            u64::try_from(PAGE_SIZE).unwrap_or(0),
            ModMemType::Unknown,
        )
    }
}

impl ModuleMemoryMap {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(BTreeMap::new()),
            key_gen: AtomicU64::new(0),
        }
    }

    fn gen_unique_key(&self) -> u64 {
        self.key_gen.fetch_add(1, Ordering::Relaxed)
    }

    pub fn contains_key(&self, key: u64) -> bool {
        self.inner.lock().contains_key(&key)
    }

    /// Register a new module memory structure in the map and return a unique key/token for it.
    pub fn register_module_memory(&self, module_memory: ModuleMemory) -> u64 {
        let key = self.gen_unique_key();

        let mut map = self.inner.lock();
        assert!(
            !map.contains_key(&key),
            "VSM: Key {key} already exists in the module memory map",
        );
        let _ = map.insert(key, module_memory);

        key
    }

    pub fn remove(&self, key: u64) -> bool {
        let mut map = self.inner.lock();
        map.remove(&key).is_some()
    }

    pub fn iter_entry(&self, key: u64) -> Option<ModuleMemoryIters> {
        let guard = self.inner.lock();
        if guard.contains_key(&key) {
            Some(ModuleMemoryIters {
                guard,
                key,
                phantom: core::marker::PhantomData,
            })
        } else {
            None
        }
    }
}

impl Default for ModuleMemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ModuleMemoryIters<'a> {
    guard: spin::mutex::SpinMutexGuard<'a, BTreeMap<u64, ModuleMemory>>,
    key: u64,
    phantom: core::marker::PhantomData<&'a PhysFrameRange<Size4KiB>>,
}

impl<'a> ModuleMemoryIters<'a> {
    pub fn iter_mem_ranges(&'a self) -> impl Iterator<Item = &'a ModuleMemoryRange> {
        self.guard.get(&self.key).unwrap().ranges.iter()
    }
}

/// This function copies `HekiPage` structures from VTL0 and returns a vector of them.
/// `pa` and `nranges` specify the physical address range containing one or more than one `HekiPage` structures.
fn copy_heki_pages_from_vtl0(pa: u64, nranges: u64) -> Option<Vec<Box<HekiPage>>> {
    let mut next_pa: u64 = pa;
    let mut heki_pages = Vec::new();
    let mut range: u64 = 0;

    while range < nranges {
        let Some(heki_page) = (unsafe {
            crate::platform_low().copy_from_vtl0_phys::<HekiPage>(x86_64::PhysAddr::new(next_pa))
        }) else {
            serial_println!("Failed to get VTL0 memory for heki page");
            return None;
        };

        range += heki_page.nranges;
        next_pa = heki_page.next_pa;
        heki_pages.push(heki_page);
    }

    Some(heki_pages)
}

/// This function protects a physical memory range. It is a safe wrapper for `hv_modify_vtl_protection_mask`.
/// `phys_frame_range` specifies the physical frame range to protect
/// `mem_attr` specifies the memory attributes to be applied to the range
#[inline]
fn protect_physical_memory_range(
    phys_frame_range: PhysFrameRange<Size4KiB>,
    mem_attr: MemAttr,
) -> Result<(), u64> {
    let pa = phys_frame_range.start.start_address().as_u64();
    let num_pages = u64::try_from(phys_frame_range.count()).unwrap_or(0);
    if num_pages == 0 {
        return Ok(());
    }

    if let Err(result) =
        hv_modify_vtl_protection_mask(pa, num_pages, mem_attr_to_hv_page_prot_flags(mem_attr))
    {
        serial_println!("Err: {:?}", result);
        Err(VsmError::Fault.into())
    } else {
        Ok(())
    }
}

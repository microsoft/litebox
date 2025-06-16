//! VSM functions

use crate::{
    debug_serial_print, debug_serial_println,
    host::{
        bootparam::{get_num_possible_cpus, get_vtl1_memory_info},
        linux::{CpuMask, KSYM_NAME_LEN, KernelSymbol},
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
            HekiKdataType, HekiKinfo, HekiPage, MemAttr, ModMemType,
            mem_attr_to_hv_page_prot_flags, mod_mem_type_to_mem_attr,
        },
        hvcall::HypervCallError,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers, init_vtl_aps},
        kernel_elf::{parse_modinfo, validate_module_elf},
        vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE},
    },
    serial_println,
};
use alloc::{boxed::Box, collections::BTreeMap, string::String, vec, vec::Vec};
use core::{
    ffi::{CStr, c_char},
    ops::Range,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
};
use hashbrown::HashMap;
use litebox_common_linux::errno::Errno;
use memoffset::offset_of;
use num_enum::TryFromPrimitive;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageOffset, PhysFrame, Size4KiB, frame::PhysFrameRange},
};

/// VTL call parameters (param[0]: function ID, param[1-3]: parameters)
pub const NUM_VTLCALL_PARAMS: usize = 4;

pub fn init() {
    assert!(
        !(get_core_id() == 0 && mshv_vsm_configure_partition().is_err()),
        "Failed to configure VSM partition"
    );

    assert!(
        (mshv_vsm_secure_config_vtl0().is_ok()),
        "Failed to secure VTL0 configuration"
    );

    if get_core_id() == 0 {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            debug_serial_println!("VSM: Protect GPAs from {:#x} to {:#x}", start, start + size);
            if protect_physical_memory_range(
                PhysFrame::range(
                    PhysFrame::containing_address(PhysAddr::new(start)),
                    PhysFrame::containing_address(PhysAddr::new(start + size)),
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
pub fn mshv_vsm_enable_aps(cpu_present_mask_pfn: u64) -> Result<i64, Errno> {
    debug_serial_println!("VSM: Enable VTL of APs");

    if let Some(cpu_mask) = unsafe {
        crate::platform_low()
            .copy_from_vtl0_phys::<CpuMask>(PhysAddr::new(cpu_present_mask_pfn << PAGE_SHIFT))
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
        return Err(Errno::EINVAL);
    }

    // TODO: cpu_present_mask vs num_possible_cpus in kernel command line. which one should we use?
    if let Ok(num_cores) = get_num_possible_cpus() {
        debug_serial_println!("the number of possible cores: {num_cores}");
        init_vtl_aps(num_cores).map_err(|_| Errno::EINVAL)?;
        Ok(0)
    } else {
        Err(Errno::EINVAL)
    }
}

/// VSM function for booting APs
/// `cpu_online_mask_pfn` indicates the page containing the VTL0's CPU online mask.
/// `boot_signal_pfn` indicates the boot signal page to let VTL0 know that VTL1 is ready.
pub fn mshv_vsm_boot_aps(cpu_online_mask_pfn: u64, boot_signal_pfn: u64) -> Result<i64, Errno> {
    debug_serial_println!("VSM: Boot APs");

    if let Some(cpu_mask) = unsafe {
        crate::platform_low()
            .copy_from_vtl0_phys::<CpuMask>(PhysAddr::new(cpu_online_mask_pfn << PAGE_SHIFT))
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
        return Err(Errno::EINVAL);
    }

    // boot_signal is an array of bytes whose length is the number of possible cores. Copy the entire page for now.
    if let Some(mut boot_signal_page) = unsafe {
        crate::platform_low()
            .copy_from_vtl0_phys::<[u8; PAGE_SIZE]>(PhysAddr::new(boot_signal_pfn << PAGE_SHIFT))
    } {
        // TODO: execute `init_vtl_ap` for each online core and update the corresponding boot signal byte.
        // Currently, we use `init_vtl_aps` to initialize all present cores which
        // takes a long time if we have a lot of cores.
        debug_serial_println!("updating boot signal page");
        for i in 0..get_num_possible_cpus().unwrap_or(0) {
            boot_signal_page[i as usize] = HV_SECURE_VTL_BOOT_TOKEN;
        }

        if unsafe {
            crate::platform_low().copy_to_vtl0_phys::<[u8; PAGE_SIZE]>(
                PhysAddr::new(boot_signal_pfn << PAGE_SHIFT),
                &boot_signal_page,
            )
        } {
            Ok(0)
        } else {
            serial_println!("Failed to copy boot signal page to VTL0");
            Err(Errno::EINVAL)
        }
    } else {
        serial_println!("Failed to get boot signal page");
        Err(Errno::EINVAL)
    }
}

/// VSM function for enforcing certain security features of VTL0
pub fn mshv_vsm_secure_config_vtl0() -> Result<i64, Errno> {
    debug_serial_println!("VSM: Secure VTL0 configuration");

    let mut config = HvRegisterVsmVpSecureVtlConfig::new();
    config.set_mbec_enabled();
    config.set_tlb_locked();

    hvcall_set_vp_registers(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, config.as_u64())
        .map_err(|_| Errno::EFAULT)?;

    Ok(0)
}

/// VSM function to configure a VSM partition for VTL1
pub fn mshv_vsm_configure_partition() -> Result<i64, Errno> {
    debug_serial_println!("VSM: Configure partition");

    let mut config = HvRegisterVsmPartitionConfig::new();
    config.set_default_vtl_protection_mask(HvPageProtFlags::HV_PAGE_FULL_ACCESS.bits().into());
    config.set_enable_vtl_protection();

    hvcall_set_vp_registers(HV_REGISTER_VSM_PARTITION_CONFIG, config.as_u64())
        .map_err(|_| Errno::EFAULT)?;

    Ok(0)
}

/// VSM function for locking VTL0's control registers.
pub fn mshv_vsm_lock_regs() -> Result<i64, Errno> {
    debug_serial_println!("VSM: Lock control registers");

    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
        serial_println!(
            "VSM: VTL0 is not allowed to change control register locking after the end of boot process"
        );
        return Err(Errno::EINVAL);
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

    save_vtl0_locked_regs().map_err(|_| Errno::EFAULT)?;

    hvcall_set_vp_registers(HV_REGISTER_CR_INTERCEPT_CONTROL, flag).map_err(|_| Errno::EFAULT)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR4_MASK,
        X86Cr4Flags::CR4_PIN_MASK.bits().into(),
    )
    .map_err(|_| Errno::EFAULT)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        X86Cr0Flags::CR0_PIN_MASK.bits().into(),
    )
    .map_err(|_| Errno::EFAULT)?;

    Ok(0)
}

/// VSM function for signaling the end of VTL0 boot process
pub fn mshv_vsm_end_of_boot() -> i64 {
    debug_serial_println!("VSM: End of boot");
    crate::platform_low().vtl0_kernel_info.set_end_of_boot();
    0
}

/// VSM function for protecting certain memory ranges (e.g., kernel text, data, heap).
/// `pa` and `nranges` specify a memory area containing the information about the memory ranges to protect.
pub fn mshv_vsm_protect_memory(pa: u64, nranges: u64) -> Result<i64, Errno> {
    if !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) || nranges == 0 {
        serial_println!("VSM: invalid input address");
        return Err(Errno::EINVAL);
    }

    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
        serial_println!(
            "VSM: VTL0 is not allowed to change kernel memory protection after the end of boot process"
        );
        return Err(Errno::EINVAL);
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
                    return Err(Errno::EINVAL);
                };

                if !va.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                    || !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                    || !epa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                {
                    serial_println!("VSM: input address must be page-aligned");
                    return Err(Errno::EINVAL);
                }

                debug_serial_println!(
                    "VSM: Protect memory: va {:#x} pa {:#x} epa {:#x} {:?} (size: {})",
                    va,
                    pa,
                    epa,
                    mem_attr,
                    epa - pa
                );

                protect_physical_memory_range(
                    PhysFrame::range(
                        PhysFrame::containing_address(PhysAddr::new(pa)),
                        PhysFrame::containing_address(PhysAddr::new(epa)),
                    ),
                    mem_attr,
                )?;
            }
        }
        Ok(0)
    } else {
        Err(Errno::EINVAL)
    }
}

/// VSM function for loading kernel data (e.g., certificates, blocklist, kernel symbols) into VTL1.
/// `pa` and `nranges` specify memory areas containing the information about the memory ranges to load.
pub fn mshv_vsm_load_kdata(pa: u64, nranges: u64) -> Result<i64, Errno> {
    if !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) || nranges == 0 {
        serial_println!("VSM: invalid input address");
        return Err(Errno::EINVAL);
    }

    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
        serial_println!(
            "VSM: VTL0 is not allowed to load kernel data after the end of boot process"
        );
        return Err(Errno::EINVAL);
    }

    let mut heki_kernel_info_mem = MemoryContent::new();
    let mut heki_kernel_data_mem = MemoryContent::new();

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

                match kdata_type {
                    HekiKdataType::KernelInfo => {
                        heki_kernel_info_mem
                            .write_vtl0_phys_bytes(
                                VirtAddr::new(va),
                                PhysAddr::new(pa),
                                PhysAddr::new(epa),
                            )
                            .map_err(|_| Errno::EINVAL)?;
                    }
                    HekiKdataType::KernelData => {
                        heki_kernel_data_mem
                            .write_vtl0_phys_bytes(
                                VirtAddr::new(va),
                                PhysAddr::new(pa),
                                PhysAddr::new(epa),
                            )
                            .map_err(|_| Errno::EINVAL)?;
                    }
                    _ => {}
                }
            }
        }
    } else {
        return Err(Errno::EINVAL);
    }

    if heki_kernel_info_mem.is_empty() || heki_kernel_data_mem.is_empty() {
        serial_println!("VSM: No kernel info or data loaded");
        return Err(Errno::EINVAL);
    }

    if let Some(heki_kernel_info) =
        heki_kernel_info_mem.read_value::<HekiKinfo>(heki_kernel_info_mem.start().unwrap())
    {
        crate::platform_low()
            .vtl0_kernel_info
            .populate_kernel_symbol_maps(
                Range {
                    start: VirtAddr::new(heki_kernel_info.ksymtab_start as u64),
                    end: VirtAddr::new(heki_kernel_info.ksymtab_end as u64),
                },
                Range {
                    start: VirtAddr::new(heki_kernel_info.ksymtab_gpl_start as u64),
                    end: VirtAddr::new(heki_kernel_info.ksymtab_gpl_end as u64),
                },
                &heki_kernel_data_mem,
            )
            .map_err(|_| Errno::EINVAL)?;
    } else {
        return Err(Errno::EINVAL);
    }

    // TODO: create trusted keys
    // TODO: create blocklist keys
    // TODO: save blocklist hashes

    Ok(0)
}

/// VSM function for validating a guest kernel module and applying specified protection to its memory ranges after validation.
/// `pa` and `nranges` specify a memory area containing the information about the kernel module to validate or protect.
/// `flags` controls the validation process (unused for now).
/// This function returns a unique `token` to VTL0, which is used to identify the module in subsequent calls.
#[allow(clippy::too_many_lines)]
pub fn mshv_vsm_validate_guest_module(pa: u64, nranges: u64, _flags: u64) -> Result<i64, Errno> {
    if !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap()) || nranges == 0 {
        serial_println!("VSM: invalid input address");
        return Err(Errno::EINVAL);
    }

    debug_serial_println!(
        "VSM: Validate kernel module: pa {:#x} nranges {}",
        pa,
        nranges,
    );

    let mut module_memory_metadata = ModuleMemoryMetadata::new();

    // collect and maintain the memory ranges of a module locally until the module is validated and its metadata is registered in the global map
    // we don't matain this content in the global map due to memory overhead. Instead, we could add its hash value to the global map to check the integrity.
    let mut module_memory_content = ModuleMemoryContent::new();
    let mut memory_elf = MemoryContent::new();

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
                        return Err(Errno::EINVAL);
                    }
                    ModMemType::ElfBuffer => {
                        // this capture the original ELF binary in memory which is provided by the VTL0 kernel for validation.
                        memory_elf
                            .write_vtl0_phys_bytes(
                                VirtAddr::new(va),
                                PhysAddr::new(pa),
                                PhysAddr::new(epa),
                            )
                            .map_err(|_| Errno::EINVAL)?;
                    }
                    _ => {
                        // if input memory range's type is neither `Unknown` nor `ElfBuffer`, its addresses must be page-aligned
                        if !va.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                            || !pa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                            || !epa.is_multiple_of(u64::try_from(PAGE_SIZE).unwrap())
                        {
                            serial_println!("VSM: input address must be page-aligned");
                            return Err(Errno::EINVAL);
                        }

                        module_memory_content
                            .write_vtl0_phys_bytes_by_type(
                                VirtAddr::new(va),
                                PhysAddr::new(pa),
                                PhysAddr::new(epa),
                                mod_mem_type,
                            )
                            .map_err(|_| Errno::EINVAL)?;

                        module_memory_metadata.insert_memory_range(ModuleMemoryRange::new(
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
        return Err(Errno::EINVAL);
    }

    // TODO: validate a kernel module by analyzing its ELF binary and memory content.
    let elf_buf_to_validate = {
        // TODO: For now, we ignore large kernel modules, but we should consider how to handle them.
        const MODULE_VALIDATION_MAX_SIZE: usize = 300 * 1024;

        let elf_size = memory_elf.len();
        if elf_size < MODULE_VALIDATION_MAX_SIZE {
            let mut elf_buf = vec![0u8; elf_size];
            memory_elf
                .read_bytes(memory_elf.start().unwrap(), &mut elf_buf)
                .map_err(|_| Errno::EINVAL)?;
            memory_elf.clear();
            Some(elf_buf)
        } else {
            memory_elf.clear();
            None
        }
    };

    if let Some(elf_buf) = elf_buf_to_validate {
        parse_modinfo(&elf_buf);

        let _ = validate_module_elf(
            &elf_buf,
            &module_memory_content,
            crate::platform_low().vtl0_kernel_info.ksymtab_map.as_ref(),
            crate::platform_low()
                .vtl0_kernel_info
                .ksymtab_gpl_map
                .as_ref(),
        );
    }

    // protect the memory ranges of a module based on their section types
    for mod_mem_range in &module_memory_metadata {
        protect_physical_memory_range(
            mod_mem_range.phys_frame_range,
            mod_mem_type_to_mem_attr(mod_mem_range.mod_mem_type),
        )?;
    }

    // register the module memory in the global map and obtain a unique token for it
    let token = crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .register_module_memory_metadata(module_memory_metadata);
    Ok(token)
}

/// VSM function for supporting the initialization of a guest kernel module including
/// freeing the memory ranges that were used only for initialization and
/// write-protecting the memory ranges that should be read-only after initialization.
/// `token` is the unique identifier for the module.
pub fn mshv_vsm_free_guest_module_init(token: i64) -> Result<i64, Errno> {
    debug_serial_println!("VSM: Free kernel module's init (token: {})", token);

    if !crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .contains_key(token)
    {
        serial_println!("VSM: invalid module token");
        return Err(Errno::EINVAL);
    }

    if let Some(entry) = crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .iter_entry(token)
    {
        for mod_mem_range in entry.iter_mem_ranges() {
            match mod_mem_range.mod_mem_type {
                ModMemType::InitText | ModMemType::InitData | ModMemType::InitRoData => {
                    // make this memory range readable, writable, and non-executable after initialization to let the VTL0 kernel free it
                    protect_physical_memory_range(
                        mod_mem_range.phys_frame_range,
                        MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
                    )?;
                }
                ModMemType::RoAfterInit => {
                    // make this memory range read-only after initialization
                    protect_physical_memory_range(
                        mod_mem_range.phys_frame_range,
                        MemAttr::MEM_ATTR_READ,
                    )?;
                }
                _ => {}
            }
        }
    }

    Ok(0)
}

/// VSM function for supporting the unloading of a guest kernel module.
/// `token` is the unique identifier for the module.
pub fn mshv_vsm_unload_guest_module(token: i64) -> Result<i64, Errno> {
    debug_serial_println!("VSM: Unload kernel module (token: {})", token);

    if !crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .contains_key(token)
    {
        serial_println!("VSM: invalid module token");
        return Err(Errno::EINVAL);
    }

    if let Some(entry) = crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .iter_entry(token)
    {
        // make the memory ranges of a module readable, writable, and non-executable to let the VTL0 kernel unload the module
        for mod_mem_range in entry.iter_mem_ranges() {
            protect_physical_memory_range(
                mod_mem_range.phys_frame_range,
                MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
            )?;
        }
    }

    crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .remove(token);
    Ok(0)
}

/// VSM function for copying secondary key
#[allow(clippy::unnecessary_wraps)]
pub fn mshv_vsm_copy_secondary_key(_pa: u64, _nranges: u64) -> Result<i64, Errno> {
    debug_serial_println!("VSM: Copy secondary key");
    // TODO: copy secondary key
    Ok(0)
}

/// VSM function for validating kexec
#[allow(clippy::unnecessary_wraps)]
pub fn mshv_vsm_kexec_validate(_pa: u64, _nranges: u64, _crash: u64) -> Result<i64, Errno> {
    debug_serial_println!("VSM: Validate kexec");
    // TODO: validate kexec
    Ok(0)
}

/// VSM function dispatcher
pub fn vsm_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    if params[0] > u32::MAX.into() {
        serial_println!("VSM: Unknown function ID {:#x}", params[0]);
        return Errno::EINVAL.as_neg().into();
    }

    let result = match VSMFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
        .unwrap_or(VSMFunction::Unknown)
    {
        VSMFunction::EnableAPsVtl => mshv_vsm_enable_aps(params[1]),
        VSMFunction::BootAPs => mshv_vsm_boot_aps(params[1], params[2]),
        VSMFunction::LockRegs => mshv_vsm_lock_regs(),
        VSMFunction::SignalEndOfBoot => Ok(mshv_vsm_end_of_boot()),
        VSMFunction::ProtectMemory => mshv_vsm_protect_memory(params[1], params[2]),
        VSMFunction::LoadKData => mshv_vsm_load_kdata(params[1], params[2]),
        VSMFunction::ValidateModule => {
            mshv_vsm_validate_guest_module(params[1], params[2], params[3])
        }
        #[allow(clippy::cast_possible_wrap)]
        VSMFunction::FreeModuleInit => mshv_vsm_free_guest_module_init(params[1] as i64),
        #[allow(clippy::cast_possible_wrap)]
        VSMFunction::UnloadModule => mshv_vsm_unload_guest_module(params[1] as i64),
        VSMFunction::CopySecondaryKey => mshv_vsm_copy_secondary_key(params[1], params[2]),
        VSMFunction::KexecValidate => mshv_vsm_kexec_validate(params[1], params[2], params[3]),
        VSMFunction::Unknown => {
            serial_println!("VSM: Unknown function ID {:#x}", params[0]);
            Err(Errno::EINVAL)
        }
    };
    match result {
        Ok(value) => value,
        Err(errno) => errno.as_neg().into(),
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

/// Data structure for maintaining the kernel information in VTL0.
/// It should be prepared by copying kernel data from VTL0 to VTL1 instead of
/// relying on shared memory access to VTL0 which suffers from security issues.
pub struct Vtl0KernelInfo {
    module_memory_metadata: ModuleMemoryMetadataMap,
    boot_done: AtomicBool,
    ksymtab_map: KernelSymbolMap,
    ksymtab_gpl_map: KernelSymbolMap,
    // TODO: certificates, blocklist, etc.
}

impl Vtl0KernelInfo {
    pub fn new() -> Self {
        Self {
            module_memory_metadata: ModuleMemoryMetadataMap::new(),
            boot_done: AtomicBool::new(false),
            ksymtab_map: KernelSymbolMap::new(),
            ksymtab_gpl_map: KernelSymbolMap::new(),
        }
    }

    /// This function records the end of the VTL0 boot process.
    pub fn set_end_of_boot(&self) {
        self.boot_done
            .store(true, core::sync::atomic::Ordering::SeqCst);
    }

    /// This function checks whether the VTL0 boot process is done. VTL1 kernel relies on this function
    /// to lock down certain security-critical VSM functions.
    pub fn check_end_of_boot(&self) -> bool {
        self.boot_done.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// This function implements Linux kernel's `offset_to_ptr` macro to identify
    /// the addresses of kernel symbols and their null-terminated names, and
    /// returns a map of symbol names to their addresses. `offset_to_ptr` is needed
    /// only if `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y`.
    #[allow(clippy::unused_self)]
    fn parse_ksymtab(
        &self,
        ksymtab_range: Range<VirtAddr>,
        kernel_data_mem: &MemoryContent,
        ksymtab_map: &mut HashMap<String, VirtAddr>,
    ) -> Result<(), Vtl0KernelInfoError> {
        let mut current = ksymtab_range.start;
        while current < ksymtab_range.end {
            let value_offset = kernel_data_mem
                .read_value::<i32>(
                    current + u64::try_from(offset_of!(KernelSymbol, value_offset)).unwrap(),
                )
                .ok_or(Vtl0KernelInfoError::MemoryError)?;
            let name_offset = kernel_data_mem
                .read_value::<i32>(
                    current + u64::try_from(offset_of!(KernelSymbol, name_offset)).unwrap(),
                )
                .ok_or(Vtl0KernelInfoError::MemoryError)?;

            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_possible_wrap)]
            #[allow(clippy::cast_sign_loss)]
            let value_addr = VirtAddr::new(
                (current.as_u64() as isize)
                    .wrapping_add(offset_of!(KernelSymbol, value_offset) as isize)
                    .wrapping_add(value_offset as isize) as u64,
            );

            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_possible_wrap)]
            #[allow(clippy::cast_sign_loss)]
            let name_addr = VirtAddr::new(
                (current.as_u64() as isize)
                    .wrapping_add(offset_of!(KernelSymbol, name_offset) as isize)
                    .wrapping_add(name_offset as isize) as u64,
            );

            let mut buf = [0u8; KSYM_NAME_LEN];
            kernel_data_mem
                .read_bytes(name_addr, &mut buf)
                .map_err(|_| Vtl0KernelInfoError::MemoryError)?;
            if let Some(name) =
                unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()).to_str().ok() }
            {
                ksymtab_map.insert(String::from(name), value_addr);
            } else {
                return Err(Vtl0KernelInfoError::MemoryError);
            }

            // unclear whether we need the `namespace` field to support the relocation.
            // We can add it later if needed.

            current += core::mem::size_of::<KernelSymbol>() as u64;
        }

        Ok(())
    }

    pub fn populate_kernel_symbol_maps(
        &self,
        ksymtab_range: Range<VirtAddr>,
        ksymtab_gpl_range: Range<VirtAddr>,
        kernel_data_mem: &MemoryContent,
    ) -> Result<(), Vtl0KernelInfoError> {
        let mut ksymtab_map: HashMap<String, VirtAddr> = HashMap::new();
        let mut ksymtab_gpl_map: HashMap<String, VirtAddr> = HashMap::new();

        self.parse_ksymtab(ksymtab_range, kernel_data_mem, &mut ksymtab_map)?;
        self.ksymtab_map.populate(&mut ksymtab_map);

        self.parse_ksymtab(ksymtab_gpl_range, kernel_data_mem, &mut ksymtab_gpl_map)?;
        self.ksymtab_gpl_map.populate(&mut ksymtab_gpl_map);

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum Vtl0KernelInfoError {
    MemoryError,
}

/// Data structure for maintaining the memory ranges of each VTL0 kernel module and their types
pub struct ModuleMemoryMetadataMap {
    inner: spin::mutex::SpinMutex<HashMap<i64, ModuleMemoryMetadata>>,
    key_gen: AtomicI64,
}

pub struct ModuleMemoryMetadata {
    ranges: Vec<ModuleMemoryRange>,
    // exported symbols?
}

impl ModuleMemoryMetadata {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn insert_memory_range(&mut self, mem_range: ModuleMemoryRange) {
        self.ranges.push(mem_range);
    }
}

impl Default for ModuleMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a ModuleMemoryMetadata {
    type Item = &'a ModuleMemoryRange;
    type IntoIter = core::slice::Iter<'a, ModuleMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct ModuleMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
    pub mod_mem_type: ModMemType,
}

impl ModuleMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64, mod_mem_type: ModMemType) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
            mod_mem_type,
        }
    }
}

impl Default for ModuleMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0, ModMemType::Unknown)
    }
}

impl ModuleMemoryMetadataMap {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
            key_gen: AtomicI64::new(0),
        }
    }

    /// Generate a unique key for representing each loaded kernel module.
    /// It assumes a 64-bit atomic counter is sufficient and there is no run out of keys.
    fn gen_unique_key(&self) -> i64 {
        self.key_gen.fetch_add(1, Ordering::Relaxed)
    }

    pub fn contains_key(&self, key: i64) -> bool {
        self.inner.lock().contains_key(&key)
    }

    /// Register a new module memory metadata structure in the map and return a unique key/token for it.
    pub fn register_module_memory_metadata(&self, module_memory: ModuleMemoryMetadata) -> i64 {
        let key = self.gen_unique_key();

        let mut map = self.inner.lock();
        assert!(
            !map.contains_key(&key),
            "VSM: Key {key} already exists in the module memory map",
        );
        let _ = map.insert(key, module_memory);

        key
    }

    pub fn remove(&self, key: i64) -> bool {
        let mut map = self.inner.lock();
        map.remove(&key).is_some()
    }

    pub fn iter_entry(&self, key: i64) -> Option<ModuleMemoryIters> {
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

impl Default for ModuleMemoryMetadataMap {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ModuleMemoryIters<'a> {
    guard: spin::mutex::SpinMutexGuard<'a, HashMap<i64, ModuleMemoryMetadata>>,
    key: i64,
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
            crate::platform_low().copy_from_vtl0_phys::<HekiPage>(PhysAddr::new(next_pa))
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
) -> Result<(), Errno> {
    let pa = phys_frame_range.start.start_address().as_u64();
    let num_pages = u64::try_from(phys_frame_range.count()).unwrap();
    if num_pages > 0 {
        hv_modify_vtl_protection_mask(pa, num_pages, mem_attr_to_hv_page_prot_flags(mem_attr))
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(())
}

/// Data structure for maintaining kernel symbols and their addresses, populated by parsing `ksymtab` and `ksymtab_gpl`.
/// We should re-populate these kernel symbol maps after each `kexec` call.
pub struct KernelSymbolMap {
    inner: spin::rwlock::RwLock<HashMap<String, VirtAddr>>,
}

impl KernelSymbolMap {
    pub fn new() -> Self {
        Self {
            inner: spin::rwlock::RwLock::new(HashMap::new()),
        }
    }

    pub fn populate(&self, other_map: &mut HashMap<String, VirtAddr>) {
        let mut inner = self.inner.write();
        inner.clear();
        inner.extend(other_map.drain());
    }

    pub fn get(&self, symbol: &str) -> Option<VirtAddr> {
        let inner = self.inner.read();
        inner.get(symbol).copied()
    }

    pub fn as_ref(&self) -> &KernelSymbolMap {
        self
    }
}

pub struct ModuleMemoryContent {
    pub text: MemoryContent,
    pub init_text: MemoryContent,
    pub data: MemoryContent,
    pub ro_data: MemoryContent,
    pub ro_after_init: MemoryContent,
    pub init_data: MemoryContent,
    pub init_ro_data: MemoryContent,
}

impl ModuleMemoryContent {
    pub fn new() -> Self {
        Self {
            text: MemoryContent::new(),
            init_text: MemoryContent::new(),
            data: MemoryContent::new(),
            ro_data: MemoryContent::new(),
            ro_after_init: MemoryContent::new(),
            init_data: MemoryContent::new(),
            init_ro_data: MemoryContent::new(),
        }
    }

    pub fn write_vtl0_phys_bytes_by_type(
        &mut self,
        addr: VirtAddr,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
        mod_mem_type: ModMemType,
    ) -> Result<(), MemoryContentError> {
        match mod_mem_type {
            ModMemType::Text => self.text.write_vtl0_phys_bytes(addr, phys_start, phys_end),
            ModMemType::InitText => self
                .init_text
                .write_vtl0_phys_bytes(addr, phys_start, phys_end),
            ModMemType::Data => self.data.write_vtl0_phys_bytes(addr, phys_start, phys_end),
            ModMemType::RoData => self
                .ro_data
                .write_vtl0_phys_bytes(addr, phys_start, phys_end),
            ModMemType::RoAfterInit => self
                .ro_after_init
                .write_vtl0_phys_bytes(addr, phys_start, phys_end),
            ModMemType::InitData => self
                .init_data
                .write_vtl0_phys_bytes(addr, phys_start, phys_end),
            ModMemType::InitRoData => self
                .init_ro_data
                .write_vtl0_phys_bytes(addr, phys_start, phys_end),
            _ => Err(MemoryContentError::Unknown),
        }
    }
}

/// Data structure for abstracting addressable paged memory. Unlike `ModuleMemoryMetadataMap` which maintains
/// physical/virtual address ranges and their access permissions, this structure contain actual data in memory pages.
/// This structure allows us to handle data copied from VTL0 without mapping them at VTL1 (e.g., for virtual-address-based page sorting).
/// The memory mapping is faster than this data structure but it lets the adversaries guess or even control
/// their target addresses. We could implement ASLR to mitigate this but ASLR is in general meaningless
/// against local adversaries.
pub struct MemoryContent {
    pages: BTreeMap<VirtAddr, Box<[u8; PAGE_SIZE]>>,
    range: Range<VirtAddr>,
}

impl MemoryContent {
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            range: Range {
                start: VirtAddr::new(0),
                end: VirtAddr::new(0),
            },
        }
    }

    pub fn start(&self) -> Option<VirtAddr> {
        if self.range.is_empty() {
            None
        } else {
            Some(self.range.start)
        }
    }

    pub fn len(&self) -> usize {
        if self.range.is_empty() {
            0
        } else {
            usize::try_from(self.range.end - self.range.start).unwrap()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        self.range.contains(&addr)
            && self
                .pages
                .contains_key(&addr.align_down(u64::try_from(PAGE_SIZE).unwrap()))
    }

    fn extend_range(&mut self, start: VirtAddr, end: VirtAddr) {
        assert!(start <= end, "Invalid range: start > end");
        if self.range.is_empty() {
            self.range.start = start;
            self.range.end = end;
        } else {
            self.range.start = core::cmp::min(self.range.start, start);
            self.range.end = core::cmp::max(self.range.end, end);
        }
    }

    pub fn get_or_alloc_page(&mut self, addr: VirtAddr) -> &mut Box<[u8; PAGE_SIZE]> {
        let page_base = addr.align_down(u64::try_from(PAGE_SIZE).unwrap_or(4096));
        self.pages
            .entry(page_base)
            .or_insert_with(|| Box::new([0; PAGE_SIZE]))
    }

    #[expect(dead_code)]
    pub fn write_byte(&mut self, addr: VirtAddr, value: u8) {
        let page_offset: usize = addr.page_offset().into();
        self.get_or_alloc_page(addr)[page_offset] = value;

        self.extend_range(addr, addr + 1);
    }

    pub fn write_vtl0_phys_bytes(
        &mut self,
        addr: VirtAddr,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
    ) -> Result<(), MemoryContentError> {
        let mut phys_cur = phys_start;
        while phys_cur < phys_end {
            if let Some(data) =
                unsafe { crate::platform_low().copy_from_vtl0_phys::<[u8; PAGE_SIZE]>(phys_cur) }
            {
                let to_write = if phys_cur + u64::try_from(PAGE_SIZE).unwrap() < phys_end {
                    PAGE_SIZE
                } else {
                    usize::try_from(phys_end - phys_cur).unwrap()
                };

                self.write_bytes(addr + (phys_cur - phys_start), &data[..to_write])?;
                phys_cur += u64::try_from(to_write).unwrap();
            } else {
                return Err(MemoryContentError::Copy);
            }
        }

        self.extend_range(addr, addr + (phys_end - phys_start));
        Ok(())
    }

    pub fn read_byte(&self, addr: VirtAddr) -> Option<u8> {
        let page_base = addr.align_down(u64::try_from(PAGE_SIZE).unwrap_or(4096));
        let page_offset: usize = addr.page_offset().into();
        self.pages.get(&page_base).map(|page| page[page_offset])
    }

    pub fn preallocate_pages(&mut self, start: VirtAddr, end: VirtAddr) {
        let start_page = start.align_down(u64::try_from(PAGE_SIZE).unwrap_or(4096));
        let end_page = end.align_up(u64::try_from(PAGE_SIZE).unwrap_or(4096));

        let mut page_addr = start_page;
        while page_addr < end_page {
            let _ = self.get_or_alloc_page(page_addr);
            page_addr += u64::try_from(PAGE_SIZE).unwrap_or(4096);
        }
    }

    pub fn write_bytes(&mut self, addr: VirtAddr, data: &[u8]) -> Result<(), MemoryContentError> {
        self.preallocate_pages(addr, addr + data.len() as u64);

        let start = addr;
        let end = addr + data.len() as u64;

        let mut num_bytes = 0;

        for (&page_addr, page) in self.pages.range_mut(
            start.align_down(u64::try_from(PAGE_SIZE).unwrap_or(4096))
                ..end.align_up(u64::try_from(PAGE_SIZE).unwrap_or(4096)),
        ) {
            let page_start = page_addr;
            let page_end = page_addr + u64::try_from(PAGE_SIZE).unwrap_or(4096);

            let copy_start = core::cmp::max(start, page_start);
            let copy_end = core::cmp::min(end, page_end);

            let len = usize::try_from(copy_end - copy_start).unwrap_or(0);
            if len == 0 {
                break;
            }

            let page_offset: usize =
                PageOffset::new_truncate(u16::try_from(copy_start - page_start).unwrap_or(0))
                    .into();

            let data_offset = usize::try_from(copy_start - start).expect("data offset error");

            page[page_offset..page_offset + len]
                .copy_from_slice(&data[data_offset..data_offset + len]);

            num_bytes += len;
        }

        if num_bytes == data.len() {
            self.extend_range(start, end);
            Ok(())
        } else {
            Err(MemoryContentError::Write)
        }
    }

    pub fn read_value<T: Copy>(&self, addr: VirtAddr) -> Option<T> {
        let mut buf = vec![0u8; core::mem::size_of::<T>()];
        if self.read_bytes(addr, &mut buf).is_err() {
            return None;
        }

        let mut value = core::mem::MaybeUninit::<T>::uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().cast::<T>(), value.as_mut_ptr(), 1);
            Some(value.assume_init())
        }
    }

    pub fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<(), MemoryContentError> {
        let start = addr;
        let end = addr + buf.len() as u64;

        let mut num_bytes = 0;

        for (&page_addr, page) in self.pages.range(
            start.align_down(u64::try_from(PAGE_SIZE).unwrap_or(4096))
                ..end.align_up(u64::try_from(PAGE_SIZE).unwrap_or(4096)),
        ) {
            let page_start = page_addr;
            let page_end = page_addr + u64::try_from(PAGE_SIZE).unwrap_or(4096);

            let copy_start = core::cmp::max(start, page_start);
            let copy_end = core::cmp::min(end, page_end);

            let len = usize::try_from(copy_end - copy_start).unwrap_or(0);
            if len == 0 {
                break;
            }

            let page_offset: usize =
                PageOffset::new_truncate(u16::try_from(copy_start - page_start).unwrap_or(0))
                    .into();

            let buf_offset = usize::try_from(copy_start - start).expect("buffer offset error");

            buf[buf_offset..buf_offset + len]
                .copy_from_slice(&page[page_offset..page_offset + len]);

            num_bytes += len;
        }

        if num_bytes == buf.len() {
            Ok(())
        } else {
            Err(MemoryContentError::Read)
        }
    }

    pub fn clear(&mut self) {
        self.pages.clear();
        self.range = Range {
            start: VirtAddr::new(0),
            end: VirtAddr::new(0),
        };
    }
}

#[derive(Debug, PartialEq)]
pub enum MemoryContentError {
    Copy,
    Read,
    Write,
    Unknown,
}

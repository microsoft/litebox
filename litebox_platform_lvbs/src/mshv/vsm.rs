// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM functions

#[cfg(debug_assertions)]
use crate::mshv::mem_integrity::parse_modinfo;
use crate::{
    arch::get_core_id,
    debug_serial_print, debug_serial_println,
    host::{
        bootparam::get_vtl1_memory_info,
        linux::{CpuMask, KEXEC_SEGMENT_MAX, Kimage},
        per_cpu_variables::with_per_cpu_variables_mut,
    },
    mshv::{
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HV_REGISTER_VSM_PARTITION_CONFIG,
        HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, HV_SECURE_VTL_BOOT_TOKEN, HV_X64_REGISTER_APIC_BASE,
        HV_X64_REGISTER_CR0, HV_X64_REGISTER_CR4, HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER,
        HV_X64_REGISTER_LSTAR, HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR,
        HV_X64_REGISTER_SYSENTER_CS, HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP,
        HvCrInterceptControlFlags, HvPageProtFlags, HvRegisterVsmPartitionConfig,
        HvRegisterVsmVpSecureVtlConfig, VsmFunction, X86Cr0Flags, X86Cr4Flags,
        heki::{
            HekiKdataType, HekiKernelInfo, HekiKernelSymbol, HekiKexecType, HekiPage, HekiPatch,
            HekiPatchInfo, HekiRange, MemAttr, ModMemType, mem_attr_to_hv_page_prot_flags,
            mod_mem_type_to_mem_attr,
        },
        hvcall::HypervCallError,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers, init_vtl_ap},
        mem_integrity::{
            validate_kernel_module_against_elf, validate_text_patch,
            verify_kernel_module_signature, verify_kernel_pe_signature,
        },
        vtl_switch::mshv_vsm_get_code_page_offsets,
        vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE},
    },
    serial_println,
};
use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
use core::{
    mem,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
};
use hashbrown::HashMap;
use litebox_common_linux::errno::Errno;
use spin::Once;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB, frame::PhysFrameRange},
};
use x509_cert::{Certificate, der::Decode};

#[derive(Copy, Clone)]
#[repr(align(4096))]
struct AlignedPage([u8; PAGE_SIZE]);

// For now, we do not validate large kernel modules due to the VTL1's memory size limitation.
const MODULE_VALIDATION_MAX_SIZE: usize = 64 * 1024 * 1024;

static CPU_ONLINE_MASK: Once<Box<CpuMask>> = Once::new();

pub(crate) fn init() {
    assert!(
        !(get_core_id() == 0 && mshv_vsm_configure_partition().is_err()),
        "Failed to configure VSM partition"
    );

    assert!(
        mshv_vsm_get_code_page_offsets().is_ok(),
        "Failed to retrieve Hypercall page offsets to execute VTL returns"
    );

    assert!(
        mshv_vsm_secure_config_vtl0().is_ok(),
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
/// Not supported in this implementation.
#[allow(clippy::unnecessary_wraps)]
pub fn mshv_vsm_enable_aps(_cpu_present_mask_pfn: u64) -> Result<i64, Errno> {
    serial_println!("mshv_vsm_enable_aps() not supported");
    Ok(0)
}

/// VSM function for enabling VTL and booting APs
/// `cpu_online_mask_pfn` indicates the page containing the VTL0's CPU online mask.
/// `boot_signal_pfn` indicates the boot signal page to let VTL0 know that VTL1 is ready.
///
/// # Panics
/// Panics if hypercall for initializing VTL for any AP fails
pub fn mshv_vsm_boot_aps(cpu_online_mask_pfn: u64, boot_signal_pfn: u64) -> Result<i64, Errno> {
    debug_serial_println!("VSM: Boot APs");
    let cpu_online_mask_page_addr =
        PhysAddr::try_new(cpu_online_mask_pfn << PAGE_SHIFT).map_err(|_| Errno::EINVAL)?;
    let boot_signal_page_addr =
        PhysAddr::try_new(boot_signal_pfn << PAGE_SHIFT).map_err(|_| Errno::EINVAL)?;

    if let Some(cpu_mask) =
        unsafe { crate::platform_low().copy_from_vtl0_phys::<CpuMask>(cpu_online_mask_page_addr) }
    {
        debug_serial_print!("cpu_online_mask: ");
        cpu_mask.for_each_cpu(|cpu_id| {
            debug_serial_print!("{}, ", cpu_id);
        });
        debug_serial_println!("");

        // boot_signal is an array of bytes whose length is the number of possible cores. Copy the entire page for now.
        let Some(mut boot_signal_page_buf) = (unsafe {
            crate::platform_low().copy_from_vtl0_phys::<AlignedPage>(boot_signal_page_addr)
        }) else {
            serial_println!("Failed to get boot signal page");
            return Err(Errno::EINVAL);
        };

        let mut error = None;

        // Initialize VTL for each online CPU and update its boot signal byte
        cpu_mask.for_each_cpu(|cpu_id| {
            if let Err(e) = init_vtl_ap(u32::try_from(cpu_id).expect("cpu_id exceeds u32 range")) {
                error = Some(e);
            }
            boot_signal_page_buf.0[cpu_id] = HV_SECURE_VTL_BOOT_TOKEN;
        });

        if let Some(e) = error {
            serial_println!("Failed to initialize one or more APs: {:?}", e);
            return Err(Errno::EINVAL);
        }

        // Store the cpu_online_mask for later use
        CPU_ONLINE_MASK.call_once(|| cpu_mask);

        if unsafe {
            crate::platform_low()
                .copy_to_vtl0_phys::<AlignedPage>(boot_signal_page_addr, &boot_signal_page_buf)
        } {
            Ok(0)
        } else {
            serial_println!("Failed to copy boot signal page to VTL0");
            Err(Errno::EINVAL)
        }
    } else {
        serial_println!("Failed to get cpu_online_mask");
        Err(Errno::EINVAL)
    }
}

/// VSM function for enforcing certain security features of VTL0
pub fn mshv_vsm_secure_config_vtl0() -> Result<i64, Errno> {
    debug_serial_println!("VSM: Secure VTL0 configuration");

    let mut config = HvRegisterVsmVpSecureVtlConfig::new();
    config.set_mbec_enabled(true);
    config.set_tlb_locked(true);

    hvcall_set_vp_registers(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, config.as_u64())
        .map_err(|_| Errno::EFAULT)?;

    Ok(0)
}

/// VSM function to configure a VSM partition for VTL1
pub fn mshv_vsm_configure_partition() -> Result<i64, Errno> {
    debug_serial_println!("VSM: Configure partition");

    let mut config = HvRegisterVsmPartitionConfig::new();
    config.set_default_vtl_protection_mask(HvPageProtFlags::HV_PAGE_FULL_ACCESS.bits());
    config.set_enable_vtl_protection(true);

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
    if PhysAddr::try_new(pa)
        .ok()
        .filter(|p| p.is_aligned(Size4KiB::SIZE))
        .is_none()
        || nranges == 0
    {
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
            for heki_range in &heki_page {
                let pa = heki_range.pa;
                let epa = heki_range.epa;
                let Some(mem_attr) = heki_range.mem_attr() else {
                    serial_println!("VSM: Invalid memory attributes");
                    return Err(Errno::EINVAL);
                };

                if !heki_range.is_aligned(Size4KiB::SIZE) {
                    serial_println!("VSM: input address must be page-aligned");
                    return Err(Errno::EINVAL);
                }

                #[cfg(debug_assertions)]
                let va = heki_range.va;
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

fn parse_certs(mut buf: &[u8]) -> Vec<Certificate> {
    let mut certs = Vec::new();

    while buf.len() >= 4 && buf[0] == 0x30 && buf[1] == 0x82 {
        let der_len = ((buf[2] as usize) << 8) | (buf[3] as usize);
        let total_len = der_len + 4;

        if buf.len() < total_len {
            serial_println!(
                "Invalid DER data (expected {}, got {})",
                total_len,
                buf.len()
            );
            break;
        }

        let cert_bytes = &buf[..total_len];
        match Certificate::from_der(cert_bytes) {
            Ok(cert) => {
                certs.push(cert);
            }
            Err(e) => {
                serial_println!("Failed to parse one certificate: {:?}", e);
                break;
            }
        }
        buf = &buf[total_len..];
    }
    certs
}

/// VSM function for loading kernel data (e.g., certificates, blocklist, kernel symbols) into VTL1.
/// `pa` and `nranges` specify memory areas containing the information about the memory ranges to load.
pub fn mshv_vsm_load_kdata(pa: u64, nranges: u64) -> Result<i64, Errno> {
    if PhysAddr::try_new(pa)
        .ok()
        .filter(|p| p.is_aligned(Size4KiB::SIZE))
        .is_none()
        || nranges == 0
    {
        serial_println!("VSM: invalid input address");
        return Err(Errno::EINVAL);
    }

    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
        serial_println!(
            "VSM: VTL0 is not allowed to load kernel data after the end of boot process"
        );
        return Err(Errno::EINVAL);
    }

    let vtl0_info = &crate::platform_low().vtl0_kernel_info;

    let mut system_certs_mem = MemoryContainer::new();
    let mut kexec_trampoline_metadata = KexecMemoryMetadata::new();
    let mut patch_info_mem = MemoryContainer::new();
    let mut kinfo_mem = MemoryContainer::new();
    let mut kdata_mem = MemoryContainer::new();

    let Some(heki_pages) = copy_heki_pages_from_vtl0(pa, nranges) else {
        return Err(Errno::EINVAL);
    };

    for heki_page in &heki_pages {
        for heki_range in heki_page {
            debug_serial_println!("VSM: Load kernel data {heki_range:?}");
            match heki_range.heki_kdata_type() {
                HekiKdataType::SystemCerts => system_certs_mem.extend_range(heki_range)?,
                HekiKdataType::KexecTrampoline => {
                    kexec_trampoline_metadata.insert_heki_range(heki_range);
                }
                HekiKdataType::PatchInfo => patch_info_mem.extend_range(heki_range)?,
                HekiKdataType::KernelInfo => kinfo_mem.extend_range(heki_range)?,
                HekiKdataType::KernelData => kdata_mem.extend_range(heki_range)?,
                HekiKdataType::Unknown => {
                    serial_println!("VSM: Invalid kernel data type",);
                    return Err(Errno::EINVAL);
                }
                _ => {
                    debug_serial_println!("VSM: Unsupported kernel data not loaded {heki_range:?}");
                }
            }
        }
    }

    system_certs_mem
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;
    patch_info_mem
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;
    kinfo_mem
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;
    kdata_mem
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;

    if system_certs_mem.is_empty() {
        serial_println!("VSM: No system certificate found");
        return Err(Errno::EINVAL);
    } else {
        let cert_buf = &system_certs_mem[..];

        let certs = parse_certs(cert_buf);

        if certs.is_empty() {
            serial_println!("VSM: No valid system certificates parsed");
            return Err(Errno::EINVAL);
        }

        // The system certificate is loaded into VTL1 and locked down before `end_of_boot` is signaled.
        // Its integrity depends on UEFI Secure Boot which ensures only trusted software is loaded during
        // the boot process.
        vtl0_info.set_system_certificates(certs.clone());
        serial_println!("VSM: Loaded {} system certificate(s)", certs.len());
    }

    for kexec_trampoline_range in &kexec_trampoline_metadata {
        protect_physical_memory_range(
            kexec_trampoline_range.phys_frame_range,
            MemAttr::MEM_ATTR_READ,
        )?;
    }

    // pre-computed patch data for the kernel text
    if !patch_info_mem.is_empty() {
        let patch_info_buf = &patch_info_mem[..];
        vtl0_info
            .precomputed_patches
            .insert_patch_data_from_bytes(patch_info_buf, None)
            .map_err(|_| Errno::EINVAL)?;
    }

    if kinfo_mem.is_empty() || kdata_mem.is_empty() {
        serial_println!("VSM: No kernel symbol table found");
        return Err(Errno::EINVAL);
    }

    let kinfo_buf = &kinfo_mem[..];
    let kdata_buf = &kdata_mem[..];
    let kinfo = HekiKernelInfo::from_bytes(kinfo_buf)?;

    vtl0_info.gpl_symbols.build_from_container(
        VirtAddr::from_ptr(kinfo.ksymtab_gpl_start),
        VirtAddr::from_ptr(kinfo.ksymtab_gpl_end),
        &kdata_mem,
        kdata_buf,
    )?;

    vtl0_info.symbols.build_from_container(
        VirtAddr::from_ptr(kinfo.ksymtab_start),
        VirtAddr::from_ptr(kinfo.ksymtab_end),
        &kdata_mem,
        kdata_buf,
    )?;

    Ok(0)
    // TODO: create blocklist keys
    // TODO: save blocklist hashes
}

/// VSM function for validating a guest kernel module and applying specified protection to its memory ranges after validation.
/// `pa` and `nranges` specify a memory area containing the information about the kernel module to validate or protect.
/// `flags` controls the validation process (unused for now).
/// This function returns a unique `token` to VTL0, which is used to identify the module in subsequent calls.
pub fn mshv_vsm_validate_guest_module(pa: u64, nranges: u64, _flags: u64) -> Result<i64, Errno> {
    if PhysAddr::try_new(pa)
        .ok()
        .filter(|p| p.is_aligned(Size4KiB::SIZE))
        .is_none()
        || nranges == 0
    {
        serial_println!("VSM: invalid input address");
        return Err(Errno::EINVAL);
    }

    debug_serial_println!(
        "VSM: Validate kernel module: pa {:#x} nranges {}",
        pa,
        nranges,
    );

    // collect and maintain the memory ranges of a module locally until the module is validated and its metadata is registered in the global map
    // we don't maintain this content in the global map due to memory overhead. Instead, we could add its hash value to the global map to check the integrity.
    let mut module_memory_metadata = ModuleMemoryMetadata::new();
    // a kernel module loaded in memory with relocations and patches
    let mut module_in_memory = ModuleMemory::new();
    // the kernel module's original ELF binary which is signed by the kernel build pipeline
    let mut module_as_elf = MemoryContainer::new();
    // patch info for the kernel module
    let mut patch_info_for_module = MemoryContainer::new();

    let Some(heki_pages) = copy_heki_pages_from_vtl0(pa, nranges) else {
        return Err(Errno::EINVAL);
    };

    for heki_page in &heki_pages {
        for heki_range in heki_page {
            match heki_range.mod_mem_type() {
                ModMemType::Unknown => {
                    serial_println!("VSM: Invalid module memory type");
                    return Err(Errno::EINVAL);
                }
                ModMemType::ElfBuffer => module_as_elf.extend_range(heki_range)?,
                ModMemType::Patch => patch_info_for_module.extend_range(heki_range)?,
                _ => {
                    // if input memory range's type is neither `Unknown` nor `ElfBuffer`, its addresses must be page-aligned
                    if !heki_range.is_aligned(Size4KiB::SIZE) {
                        serial_println!("VSM: input address must be page-aligned");
                        return Err(Errno::EINVAL);
                    }
                    module_memory_metadata.insert_heki_range(heki_range);
                    module_in_memory.extend_range(heki_range.mod_mem_type(), heki_range)?;
                }
            }
        }
    }

    module_as_elf
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;
    patch_info_for_module
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;
    module_in_memory
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;

    let elf_size = (module_as_elf[..]).len();
    assert!(
        elf_size <= MODULE_VALIDATION_MAX_SIZE,
        "Module ELF size exceeds the maximum allowed size"
    );

    let original_elf_data = &module_as_elf[..];

    #[cfg(debug_assertions)]
    parse_modinfo(original_elf_data).map_err(|_| Errno::EINVAL)?;

    if let Err(result) = verify_kernel_module_signature(
        original_elf_data,
        crate::platform_low()
            .vtl0_kernel_info
            .get_system_certificates()
            .expect("No system certificates loaded"),
    ) {
        serial_println!("VSM: Failed to verify the module signature");
        return Err(result.into());
    }

    if !validate_kernel_module_against_elf(&module_in_memory, original_elf_data)
        .map_err(|_| Errno::EINVAL)?
    {
        serial_println!("VSM: Found unexpected relocations in the loaded module");
        return Err(Errno::EINVAL);
    }

    // pre-computed patch data for a module
    if !patch_info_for_module.is_empty() {
        let patch_info_buf = &patch_info_for_module[..];
        crate::platform_low()
            .vtl0_kernel_info
            .precomputed_patches
            .insert_patch_data_from_bytes(patch_info_buf, Some(&mut module_memory_metadata))
            .map_err(|_| Errno::EINVAL)?;
    }

    // once a module is verified and validated, change the permission of its memory ranges based on their types
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

    if let Some(patch_targets) = crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .get_patch_targets(token)
    {
        crate::platform_low()
            .vtl0_kernel_info
            .precomputed_patches
            .remove_patch_data(&patch_targets);
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

/// VSM function for write protecting the memory regions of a verified kernel image for kexec.
/// This function protects the kexec kernel blob (PE) only if it has a valid signature.
/// Note: this function does not make kexec kernel pages executable, which should be done by
/// another VTL1 method that can intercept the kexec/reset signal.
pub fn mshv_vsm_kexec_validate(pa: u64, nranges: u64, crash: u64) -> Result<i64, Errno> {
    debug_serial_println!(
        "VSM: Validate kexec pa {:#x} nranges {} crash {}",
        pa,
        nranges,
        crash
    );

    let is_crash = crash != 0;
    let kexec_metadata_ref = if is_crash {
        &crate::platform_low().vtl0_kernel_info.crash_kexec_metadata
    } else {
        &crate::platform_low().vtl0_kernel_info.kexec_metadata
    };

    // invalidate (i.e., remove protection and clear) the kexec memory ranges which were loaded in the past
    for old_kexec_mem_range in kexec_metadata_ref.iter_guarded().iter_mem_ranges() {
        protect_physical_memory_range(
            old_kexec_mem_range.phys_frame_range,
            MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
        )?;
    }
    kexec_metadata_ref.clear_memory();

    if pa == 0 {
        // invalidation only
        return Ok(0);
    }

    let mut kexec_memory_metadata = KexecMemoryMetadata::new();
    let mut kexec_image = MemoryContainer::new();
    let mut kexec_kernel_blob = MemoryContainer::new();

    let Some(heki_pages) = copy_heki_pages_from_vtl0(pa, nranges) else {
        return Err(Errno::EINVAL);
    };

    for heki_page in &heki_pages {
        for heki_range in heki_page {
            match heki_range.heki_kexec_type() {
                HekiKexecType::KexecImage => {
                    kexec_memory_metadata.insert_heki_range(heki_range);
                    kexec_image.extend_range(heki_range)?;
                }
                HekiKexecType::KexecKernelBlob =>
                // we do not protect kexec kernel blob memory
                {
                    kexec_kernel_blob.extend_range(heki_range)?;
                }

                HekiKexecType::KexecPages => kexec_memory_metadata.insert_heki_range(heki_range),
                HekiKexecType::Unknown => {
                    serial_println!("VSM: Invalid kexec type");
                    return Err(Errno::EINVAL);
                }
            }
        }
    }

    kexec_image
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;
    kexec_kernel_blob
        .write_bytes_from_heki_range()
        .map_err(|_| Errno::EINVAL)?;

    // If this function is called for crash kexec, we protect its kimage segments as well.
    if is_crash {
        let mut kimage = core::mem::MaybeUninit::<Kimage>::uninit();
        let kimage_slice: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                kimage.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<Kimage>(),
            )
        };
        kimage_slice.copy_from_slice(&kexec_image[..core::mem::size_of::<Kimage>()]);
        let kimage = unsafe { kimage.assume_init() };
        if kimage.nr_segments > u64::try_from(KEXEC_SEGMENT_MAX).unwrap() {
            serial_println!("VSM: Invalid kexec image segments");
            return Err(Errno::EINVAL);
        }
        for i in 0..usize::try_from(kimage.nr_segments).unwrap_or(0) {
            let va = kimage.segment[i].buf as u64;
            let pa = kimage.segment[i].mem;
            if let Some(epa) = pa.checked_add(kimage.segment[i].memsz) {
                kexec_memory_metadata.insert_memory_range(KexecMemoryRange::new(va, pa, epa));
            } else {
                serial_println!("VSM: Invalid kexec segment memory range");
                return Err(Errno::EINVAL);
            }
        }
    }

    // write protect the kexec memory ranges first to avoid the race condition during verification
    for kexec_mem_range in &kexec_memory_metadata {
        protect_physical_memory_range(kexec_mem_range.phys_frame_range, MemAttr::MEM_ATTR_READ)?;
    }

    // verify the signature of kexec blob
    let kexec_kernel_blob_data = &kexec_kernel_blob[..];

    if let Err(result) = verify_kernel_pe_signature(
        kexec_kernel_blob_data,
        crate::platform_low()
            .vtl0_kernel_info
            .get_system_certificates()
            .expect("No system certificates loaded"),
    ) {
        serial_println!("VSM: Failed to verify the signature of kexec kernel blob");
        for kexec_mem_range in &kexec_memory_metadata {
            protect_physical_memory_range(
                kexec_mem_range.phys_frame_range,
                MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
            )?;
        }
        return Err(result.into());
    }

    // register the protected kexec memory ranges to support possible invalidation in the future
    kexec_metadata_ref.register_memory(kexec_memory_metadata);

    Ok(0)
}

/// VSM function for patching kernel or module text. VTL0 kernel calls this function to patch certain kernel or module
/// text region (which it does not have a permission to modify). It passes `HekiPatch` structure which can be stored
/// within one or across two likely non-contiguous physical pages.
pub fn mshv_vsm_patch_text(patch_pa_0: u64, patch_pa_1: u64) -> Result<i64, Errno> {
    let heki_patch = copy_heki_patch_from_vtl0(patch_pa_0, patch_pa_1)?;
    debug_serial_println!("VSM: {:?}", heki_patch);

    let Some(precomputed_patch) = crate::platform_low()
        .vtl0_kernel_info
        .find_precomputed_patch(&heki_patch)
    else {
        serial_println!("VSM: precomputed patch data not found");
        return Err(Errno::ENOENT);
    };

    if !validate_text_patch(&heki_patch, &precomputed_patch) {
        serial_println!(
            "VSM: text patch looks suspicious. current: {:?}, precomputed: {:?}",
            heki_patch,
            precomputed_patch
        );
        return Err(Errno::EINVAL);
    }

    apply_vtl0_text_patch(heki_patch)?;
    Ok(0)
}

/// This function copies patch data in `HekiPatch` structure from VTL0 to VTL1. This patch data can be
/// stored within a physical page or across two likely non-contiguous physical pages.
fn copy_heki_patch_from_vtl0(patch_pa_0: u64, patch_pa_1: u64) -> Result<HekiPatch, Errno> {
    let patch_pa_0 = PhysAddr::try_new(patch_pa_0).map_err(|_| Errno::EINVAL)?;
    let patch_pa_1 = PhysAddr::try_new(patch_pa_1).map_err(|_| Errno::EINVAL)?;
    if patch_pa_0.is_null() || patch_pa_0 == patch_pa_1 || !patch_pa_1.is_aligned(Size4KiB::SIZE) {
        return Err(Errno::EINVAL);
    }
    let bytes_in_first_page = if patch_pa_0.is_aligned(Size4KiB::SIZE) {
        core::cmp::min(PAGE_SIZE, core::mem::size_of::<HekiPatch>())
    } else {
        core::cmp::min(
            usize::try_from(patch_pa_0.align_up(Size4KiB::SIZE) - patch_pa_0).unwrap(),
            core::mem::size_of::<HekiPatch>(),
        )
    };

    if (bytes_in_first_page < core::mem::size_of::<HekiPatch>() && patch_pa_1.is_null())
        || (bytes_in_first_page == core::mem::size_of::<HekiPatch>() && !patch_pa_1.is_null())
    {
        return Err(Errno::EINVAL);
    }

    if patch_pa_1.is_null()
        || (patch_pa_0.align_up(Size4KiB::SIZE) == patch_pa_1.align_down(Size4KiB::SIZE))
    {
        unsafe { crate::platform_low().copy_from_vtl0_phys::<HekiPatch>(patch_pa_0) }
            .map(|boxed| *boxed)
            .ok_or(Errno::EINVAL)
    } else {
        let mut heki_patch = core::mem::MaybeUninit::<HekiPatch>::uninit();
        let heki_patch_slice: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                heki_patch.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<HekiPatch>(),
            )
        };
        unsafe {
            if !crate::platform_low().copy_slice_from_vtl0_phys(
                patch_pa_0,
                heki_patch_slice.get_unchecked_mut(..bytes_in_first_page),
            ) || !crate::platform_low().copy_slice_from_vtl0_phys(
                patch_pa_1,
                heki_patch_slice.get_unchecked_mut(bytes_in_first_page..),
            ) {
                return Err(Errno::EINVAL);
            }
        }
        let heki_patch = unsafe { heki_patch.assume_init() };
        if heki_patch.is_valid() {
            Ok(heki_patch)
        } else {
            Err(Errno::EINVAL)
        }
    }
}

/// This function apply the given `HekiPatch` patch data to VTL0 text.
/// It assumes the caller has confirmed the validity of `HekiPatch` by invoking the `is_valid()` member function.
fn apply_vtl0_text_patch(heki_patch: HekiPatch) -> Result<(), Errno> {
    let heki_patch_pa_0 = PhysAddr::new(heki_patch.pa[0]);
    let heki_patch_pa_1 = PhysAddr::new(heki_patch.pa[1]);

    let patch_target_page_offset =
        usize::try_from(heki_patch_pa_0 - heki_patch_pa_0.align_down(Size4KiB::SIZE)).unwrap();
    let bytes_in_first_page = PAGE_SIZE - patch_target_page_offset;

    if heki_patch_pa_1.is_null()
        || (heki_patch_pa_0.align_up(Size4KiB::SIZE) == heki_patch_pa_1.align_down(Size4KiB::SIZE))
    {
        if !unsafe {
            crate::platform_low().copy_slice_to_vtl0_phys(
                heki_patch_pa_0,
                &heki_patch.code[..usize::from(heki_patch.size)],
            )
        } {
            return Err(Errno::EINVAL);
        }
    } else {
        let (patch_first, patch_second) = heki_patch.code.split_at(bytes_in_first_page);

        unsafe {
            if !crate::platform_low().copy_slice_to_vtl0_phys(
                heki_patch_pa_0 + u64::try_from(patch_target_page_offset).unwrap(),
                patch_first,
            ) || !crate::platform_low().copy_slice_to_vtl0_phys(heki_patch_pa_1, patch_second)
            {
                return Err(Errno::EINVAL);
            }
        }
    }
    Ok(())
}

/// VSM function dispatcher
pub fn vsm_dispatch(func_id: VsmFunction, params: &[u64]) -> i64 {
    let result = match func_id {
        VsmFunction::EnableAPsVtl => mshv_vsm_enable_aps(params[0]),
        VsmFunction::BootAPs => mshv_vsm_boot_aps(params[0], params[1]),
        VsmFunction::LockRegs => mshv_vsm_lock_regs(),
        VsmFunction::SignalEndOfBoot => Ok(mshv_vsm_end_of_boot()),
        VsmFunction::ProtectMemory => mshv_vsm_protect_memory(params[0], params[1]),
        VsmFunction::LoadKData => mshv_vsm_load_kdata(params[0], params[1]),
        VsmFunction::ValidateModule => {
            mshv_vsm_validate_guest_module(params[0], params[1], params[2])
        }
        #[allow(clippy::cast_possible_wrap)]
        VsmFunction::FreeModuleInit => mshv_vsm_free_guest_module_init(params[0] as i64),
        #[allow(clippy::cast_possible_wrap)]
        VsmFunction::UnloadModule => mshv_vsm_unload_guest_module(params[0] as i64),
        VsmFunction::CopySecondaryKey => mshv_vsm_copy_secondary_key(params[0], params[1]),
        VsmFunction::KexecValidate => mshv_vsm_kexec_validate(params[0], params[1], params[2]),
        VsmFunction::PatchText => mshv_vsm_patch_text(params[0], params[1]),
        _ => {
            serial_println!("VSM: Unknown function ID {:?}", func_id);
            Err(Errno::EINVAL)
        }
    };
    match result {
        Ok(value) => value,
        Err(errno) => errno.as_neg().into(),
    }
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

#[allow(clippy::unnecessary_wraps)]
fn save_vtl0_locked_regs() -> Result<u64, HypervCallError> {
    let reg_names = with_per_cpu_variables_mut(|per_cpu_variables| {
        per_cpu_variables.vtl0_locked_regs.init();
        per_cpu_variables.vtl0_locked_regs.reg_names()
    });
    for reg_name in reg_names {
        if let Ok(value) = hvcall_get_vp_vtl0_registers(reg_name) {
            with_per_cpu_variables_mut(|per_cpu_variables| {
                per_cpu_variables.vtl0_locked_regs.set(reg_name, value);
            });
        }
    }

    Ok(0)
}

/// Data structure for maintaining the kernel information in VTL0.
/// It should be prepared by copying kernel data from VTL0 to VTL1 instead of
/// relying on shared memory access to VTL0 which suffers from security issues.
pub struct Vtl0KernelInfo {
    module_memory_metadata: ModuleMemoryMetadataMap,
    boot_done: AtomicBool,
    system_certs: once_cell::race::OnceBox<Box<[Certificate]>>,
    kexec_metadata: KexecMemoryMetadataWrapper,
    crash_kexec_metadata: KexecMemoryMetadataWrapper,
    precomputed_patches: PatchDataMap,
    symbols: SymbolTable,
    gpl_symbols: SymbolTable,
    // TODO: revocation cert, blocklist, etc.
}

impl Vtl0KernelInfo {
    pub fn new() -> Self {
        Self {
            module_memory_metadata: ModuleMemoryMetadataMap::new(),
            boot_done: AtomicBool::new(false),
            system_certs: once_cell::race::OnceBox::new(),
            kexec_metadata: KexecMemoryMetadataWrapper::new(),
            crash_kexec_metadata: KexecMemoryMetadataWrapper::new(),
            precomputed_patches: PatchDataMap::new(),
            symbols: SymbolTable::new(),
            gpl_symbols: SymbolTable::new(),
        }
    }

    /// This function records the end of the VTL0 boot process.
    pub(crate) fn set_end_of_boot(&self) {
        self.boot_done
            .store(true, core::sync::atomic::Ordering::SeqCst);
    }

    /// This function checks whether the VTL0 boot process is done. VTL1 kernel relies on this function
    /// to lock down certain security-critical VSM functions.
    pub fn check_end_of_boot(&self) -> bool {
        self.boot_done.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_system_certificates(&self, certs: Vec<Certificate>) {
        let boxed_slice = certs.into_boxed_slice();
        let _ = self.system_certs.set(boxed_slice.into());
    }

    pub fn get_system_certificates(&self) -> Option<&[Certificate]> {
        self.system_certs.get().map(|b| &**b)
    }

    // This function finds the precomputed patch data corresponding to the input patch data.
    // We need this because each step of `mshv_vsm_patch_data`/`text_poke_bp_batch` only
    // provides a part of the patch data and addresses (`patch[0]` or `patch[1..patch_size-1]`).
    pub fn find_precomputed_patch(&self, patch_data: &HekiPatch) -> Option<HekiPatch> {
        self.precomputed_patches
            .get(PhysAddr::new(patch_data.pa[0]))
            .or_else(|| {
                self.precomputed_patches
                    .get(PhysAddr::new(patch_data.pa[0].saturating_sub(1)))
            })
            .or_else(|| {
                self.precomputed_patches
                    .get(PhysAddr::new(patch_data.pa[1]))
            })
            .or(None)
    }
}

/// Data structure for maintaining the memory ranges of each VTL0 kernel module and their types
pub struct ModuleMemoryMetadataMap {
    inner: spin::mutex::SpinMutex<HashMap<i64, ModuleMemoryMetadata>>,
    key_gen: AtomicI64,
}

pub struct ModuleMemoryMetadata {
    ranges: Vec<ModuleMemoryRange>,
    patch_targets: Vec<PhysAddr>,
}

impl ModuleMemoryMetadata {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            patch_targets: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(ModuleMemoryRange::new(
            va,
            pa,
            epa,
            heki_range.mod_mem_type(),
        ));
    }

    #[inline]
    pub(crate) fn insert_memory_range(&mut self, mem_range: ModuleMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub(crate) fn insert_patch_target(&mut self, patch_target: PhysAddr) {
        self.patch_targets.push(patch_target);
    }

    // This function returns patch targets belonging to this module to remove them
    // from the precomputed patch data map when the module is unloaded.
    #[inline]
    pub(crate) fn get_patch_targets(&self) -> &Vec<PhysAddr> {
        &self.patch_targets
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
    pub(crate) fn register_module_memory_metadata(
        &self,
        module_memory: ModuleMemoryMetadata,
    ) -> i64 {
        let key = self.gen_unique_key();

        let mut map = self.inner.lock();
        assert!(
            !map.contains_key(&key),
            "VSM: Key {key} already exists in the module memory map",
        );
        let _ = map.insert(key, module_memory);

        key
    }

    pub(crate) fn remove(&self, key: i64) -> bool {
        let mut map = self.inner.lock();
        map.remove(&key).is_some()
    }

    /// Return the addresses of patch targets belonging to a module identified by `key`
    pub(crate) fn get_patch_targets(&self, key: i64) -> Option<Vec<PhysAddr>> {
        let guard = self.inner.lock();
        guard
            .get(&key)
            .map(|metadata| metadata.get_patch_targets().clone())
    }

    pub fn iter_entry(&self, key: i64) -> Option<ModuleMemoryMetadataIters<'_>> {
        let guard = self.inner.lock();
        if guard.contains_key(&key) {
            Some(ModuleMemoryMetadataIters {
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

pub struct ModuleMemoryMetadataIters<'a> {
    guard: spin::mutex::SpinMutexGuard<'a, HashMap<i64, ModuleMemoryMetadata>>,
    key: i64,
    phantom: core::marker::PhantomData<&'a PhysFrameRange<Size4KiB>>,
}

impl<'a> ModuleMemoryMetadataIters<'a> {
    pub fn iter_mem_ranges(&'a self) -> impl Iterator<Item = &'a ModuleMemoryRange> {
        self.guard.get(&self.key).unwrap().ranges.iter()
    }
}

/// This function copies `HekiPage` structures from VTL0 and returns a vector of them.
/// `pa` and `nranges` specify the physical address range containing one or more than one `HekiPage` structures.
fn copy_heki_pages_from_vtl0(pa: u64, nranges: u64) -> Option<Vec<HekiPage>> {
    let mut next_pa = PhysAddr::new(pa);
    let mut heki_pages = Vec::with_capacity(usize::try_from(nranges).unwrap());
    let mut range: u64 = 0;

    while range < nranges {
        let Some(heki_page) =
            (unsafe { crate::platform_low().copy_from_vtl0_phys::<HekiPage>(next_pa) })
        else {
            serial_println!("Failed to get VTL0 memory for heki page");
            return None;
        };
        if !heki_page.is_valid() {
            return None;
        }

        range += heki_page.nranges;
        next_pa = PhysAddr::new(heki_page.next_pa);
        heki_pages.push(*heki_page);
    }

    Some(heki_pages)
}

/// This function protects a physical memory range. It is a safe wrapper for `hv_modify_vtl_protection_mask`.
/// `phys_frame_range` specifies the physical frame range to protect
/// `mem_attr` specifies the memory attributes to be applied to the range
#[inline]
pub(crate) fn protect_physical_memory_range(
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

/// Data structure for maintaining the memory content of a kernel module by its sections. Currently, it only maintains
/// certain sections like `.text` and `.init.text` which are needed for module validation.
pub struct ModuleMemory {
    text: MemoryContainer,
    init_text: MemoryContainer,
    init_rodata: MemoryContainer,
}

impl ModuleMemory {
    pub fn new() -> Self {
        Self {
            text: MemoryContainer::new(),
            init_text: MemoryContainer::new(),
            init_rodata: MemoryContainer::new(),
        }
    }

    /// Return a memory container for a section of the module memory by its name
    pub fn find_section_by_name(&self, name: &str) -> Option<&MemoryContainer> {
        match name {
            ".text" => Some(&self.text),
            ".init.text" => Some(&self.init_text),
            ".init.rodata" => Some(&self.init_rodata),
            _ => None,
        }
    }

    /// Write physical memory bytes from VTL0 specified in `HekiRange` at the specified virtual address of
    /// a certain memory container based on the memory/section type.
    #[inline]
    pub(crate) fn write_bytes_from_heki_range(&mut self) -> Result<(), MemoryContainerError> {
        self.text.write_bytes_from_heki_range()?;
        self.init_text.write_bytes_from_heki_range()?;
        self.init_rodata.write_bytes_from_heki_range()?;
        Ok(())
    }

    pub(crate) fn extend_range(
        &mut self,
        mod_mem_type: ModMemType,
        heki_range: &HekiRange,
    ) -> Result<(), Errno> {
        match mod_mem_type {
            ModMemType::Text => self.text.extend_range(heki_range)?,
            ModMemType::InitText => self.init_text.extend_range(heki_range)?,
            ModMemType::InitRoData => self.init_rodata.extend_range(heki_range)?,
            _ => {}
        }
        Ok(())
    }
}

/// Data structure for abstracting addressable paged memory. Unlike `ModuleMemoryMetadataMap` which maintains
/// physical/virtual address ranges and their access permissions, this structure stores actual data in memory pages.
/// This structure allows us to handle data copied from VTL0 (e.g., for virtual-address-based page sorting) without
/// explicit page mappings at VTL1.
/// This structure is expected to be used locally and temporarily, so we do not protect it with a lock.
#[derive(Clone, Copy)]
struct MemoryRange {
    addr: VirtAddr,
    phys_addr: PhysAddr,
    len: u64,
}

pub struct MemoryContainer {
    range: Vec<MemoryRange>,
    buf: Vec<u8>,
}

impl MemoryContainer {
    pub fn new() -> Self {
        Self {
            range: Vec::new(),
            buf: Vec::new(),
        }
    }

    /// Return the byte length of the memory container
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if the memory container is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_range(&self) -> Option<Range<VirtAddr>> {
        let start_range = self.range.first()?;
        let end_range = self.range.last()?;
        Some(Range {
            start: start_range.addr,
            end: end_range.addr + end_range.len,
        })
    }

    pub(crate) fn extend_range(&mut self, heki_range: &HekiRange) -> Result<(), Errno> {
        let addr = VirtAddr::try_new(heki_range.va).map_err(|_| Errno::EINVAL)?;
        let phys_addr = PhysAddr::try_new(heki_range.pa).map_err(|_| Errno::EINVAL)?;
        if let Some(last_range) = self.range.last()
            && last_range.addr + last_range.len != addr
        {
            serial_println!("Discontiguous address found {heki_range:?}");
            // TODO: This should be an error once patch_info is fixed from VTL0
            // It will simplify patch_info and heki_range parsing as well
        }
        self.range.push(MemoryRange {
            addr,
            phys_addr,
            len: heki_range.epa - heki_range.pa,
        });
        Ok(())
    }

    /// Write physical memory bytes from VTL0 specified in `HekiRange` at the specified virtual address
    #[inline]
    pub(crate) fn write_bytes_from_heki_range(&mut self) -> Result<(), MemoryContainerError> {
        let mut len = 0;
        if self.buf.is_empty() {
            for range in &self.range {
                len += usize::try_from(range.len).unwrap();
            }
            self.buf.reserve_exact(len);
        }

        let range = self.range.clone();
        for range in range {
            self.write_vtl0_phys_bytes(range.phys_addr, range.phys_addr + range.len)?;
        }
        Ok(())
    }

    /// Write physical memory bytes from VTL0 at the specified physical address
    pub(crate) fn write_vtl0_phys_bytes(
        &mut self,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
    ) -> Result<(), MemoryContainerError> {
        let mut bytes_to_copy = usize::try_from(phys_end - phys_start).unwrap();
        let mut phys_cur = phys_start;

        while phys_cur < phys_end {
            let phys_aligned = phys_cur.align_down(Size4KiB::SIZE);
            let Some(page) =
                (unsafe { crate::platform_low().copy_from_vtl0_phys::<AlignedPage>(phys_aligned) })
            else {
                return Err(MemoryContainerError::CopyFromVtl0Failed);
            };

            let src_offset = usize::try_from(phys_cur - phys_aligned).unwrap();
            let src_len = core::cmp::min(
                bytes_to_copy,
                usize::try_from(Size4KiB::SIZE).unwrap() - src_offset,
            );
            let src = &page.0[src_offset..src_offset + src_len];

            self.buf.extend_from_slice(src);
            phys_cur += src_len as u64;
            bytes_to_copy -= src_len;
        }
        Ok(())
    }
}

impl core::ops::Deref for MemoryContainer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

#[derive(Debug, PartialEq)]
pub enum MemoryContainerError {
    CopyFromVtl0Failed,
}

pub struct KexecMemoryMetadataWrapper {
    inner: spin::mutex::SpinMutex<KexecMemoryMetadata>,
}

impl KexecMemoryMetadataWrapper {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(KexecMemoryMetadata::new()),
        }
    }

    pub(crate) fn clear_memory(&self) {
        let mut inner = self.inner.lock();
        inner.clear();
    }

    pub(crate) fn register_memory(&self, kexec_memory: KexecMemoryMetadata) {
        let mut inner = self.inner.lock();
        inner.ranges = kexec_memory.ranges;
    }

    pub fn iter_guarded(&self) -> KexecMemoryMetadataIters<'_> {
        KexecMemoryMetadataIters {
            guard: self.inner.lock(),
            phantom: core::marker::PhantomData,
        }
    }
}

// TODO: `ModuleMemoryMetadata` and `KexecMemoryMetadata` are similar. consider merging them into a single structure if possible.
pub struct KexecMemoryMetadata {
    ranges: Vec<KexecMemoryRange>,
}

impl KexecMemoryMetadata {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    #[inline]
    pub(crate) fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(KexecMemoryRange::new(va, pa, epa));
    }

    #[inline]
    pub(crate) fn insert_memory_range(&mut self, mem_range: KexecMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }
}

impl Default for KexecMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a KexecMemoryMetadata {
    type Item = &'a KexecMemoryRange;
    type IntoIter = core::slice::Iter<'a, KexecMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

pub struct KexecMemoryMetadataIters<'a> {
    guard: spin::mutex::SpinMutexGuard<'a, KexecMemoryMetadata>,
    phantom: core::marker::PhantomData<&'a PhysFrameRange<Size4KiB>>,
}

impl<'a> KexecMemoryMetadataIters<'a> {
    pub fn iter_mem_ranges(&'a self) -> impl Iterator<Item = &'a KexecMemoryRange> {
        self.guard.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct KexecMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
}

impl KexecMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
        }
    }
}

impl Default for KexecMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

pub struct PatchDataMap {
    inner: spin::rwlock::RwLock<HashMap<PhysAddr, HekiPatch>>,
}

impl PatchDataMap {
    pub fn new() -> Self {
        Self {
            inner: spin::rwlock::RwLock::new(HashMap::new()),
        }
    }

    #[inline]
    pub fn remove_patch_data(&self, patch_targets: &Vec<PhysAddr>) {
        let mut inner = self.inner.write();
        for key in patch_targets {
            inner.remove(key);
        }
    }

    #[inline]
    pub fn get(&self, addr: PhysAddr) -> Option<HekiPatch> {
        let inner = self.inner.read();
        inner.get(&addr).copied()
    }

    // Add patch data from a buffer containing `HekiPatchInfo` and `HekiPatch` structures.
    // If this patch data is from a module (`module_memory_metadata` is `Some`), this function
    // denies any patch target addresses not within the module's executable memory ranges.
    pub fn insert_patch_data_from_bytes(
        &self,
        patch_info_buf: &[u8],
        mut module_memory_metadata: Option<&mut ModuleMemoryMetadata>,
    ) -> Result<(), PatchDataMapError> {
        if patch_info_buf.len() < core::mem::size_of::<HekiPatchInfo>() {
            return Err(PatchDataMapError::InvalidHekiPatchInfo);
        }
        let mut inner = self.inner.write();

        // the buffer looks like below:
        // [`HekiPatchInfo`, [`HekiPatch`, ...], `HekiPatchInfo`, [`HekiPatch`, ...], ...]
        // each `HekiPatchInfo` contains the number of `HekiPatch` structures (`patch_index`) that follow it.
        let mut index: usize = 0;
        while index <= patch_info_buf.len() - core::mem::size_of::<HekiPatchInfo>() {
            let patch_info = HekiPatchInfo::try_from_bytes(
                &patch_info_buf[index..index + core::mem::size_of::<HekiPatchInfo>()],
            )
            .ok_or(PatchDataMapError::InvalidHekiPatchInfo)?;

            let Some(total_patch_size) = core::mem::size_of::<HekiPatch>()
                .checked_mul(usize::try_from(patch_info.patch_index).unwrap())
            else {
                return Err(PatchDataMapError::InvalidHekiPatchInfo);
            };
            index = index
                .checked_add(core::mem::size_of::<HekiPatchInfo>() + total_patch_size)
                .filter(|&x| x <= patch_info_buf.len())
                .ok_or(PatchDataMapError::InvalidHekiPatchInfo)?;

            for patch in patch_info_buf[index - total_patch_size..index]
                .chunks(core::mem::size_of::<HekiPatch>())
                .map(HekiPatch::try_from_bytes)
            {
                let patch = patch.ok_or(PatchDataMapError::InvalidHekiPatch)?;
                let patch_target_pa_0 = PhysAddr::new(patch.pa[0]);
                let patch_target_pa_1 = PhysAddr::new(patch.pa[1]);

                if let Some(ref mut mod_mem_meta) = module_memory_metadata {
                    for mod_mem_range in &**mod_mem_meta {
                        let in_range = |pa: PhysAddr| {
                            mod_mem_range.phys_frame_range.start.start_address() <= pa
                                && mod_mem_range.phys_frame_range.end.start_address() > pa
                        };
                        if matches!(
                            mod_mem_range.mod_mem_type,
                            ModMemType::Text | ModMemType::InitText
                        ) && in_range(patch_target_pa_0)
                            && (patch_target_pa_1.is_null() || in_range(patch_target_pa_1))
                        {
                            mod_mem_meta.insert_patch_target(patch_target_pa_0);
                            inner.insert(patch_target_pa_0, patch);

                            // If the first byte of a patch target is in the first (physical) page while the remaining bytes
                            // are in the second page, we use the second page as an additional key for the patch to deal with
                            // Step 2 of `text_poke_bp_batch` where we only know the second to last bytes of the patch such
                            // that cannot know the address of the first page. Details are in `validate_text_poke_bp_batch`.
                            if !patch_target_pa_1.is_null()
                                && (patch_target_pa_0 + 1).is_aligned(Size4KiB::SIZE)
                            {
                                mod_mem_meta.insert_patch_target(patch_target_pa_1);
                                inner.insert(patch_target_pa_1, patch);
                            }
                            break;
                        }
                    }
                } else {
                    inner.insert(patch_target_pa_0, patch);
                    if !patch_target_pa_1.is_null()
                        && (patch_target_pa_0 + 1).is_aligned(Size4KiB::SIZE)
                    {
                        inner.insert(patch_target_pa_1, patch);
                    }
                }
            }
            index += total_patch_size;
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum PatchDataMapError {
    InvalidHekiPatchInfo,
    InvalidHekiPatch,
}

// TODO: Use this to resolve symbols in modules
pub struct Symbol {
    _value: u64,
}

impl Symbol {
    pub fn from_bytes(
        kinfo_start: usize,
        start: VirtAddr,
        bytes: &[u8],
    ) -> Result<(String, Self), Errno> {
        let kinfo_bytes = &bytes[kinfo_start..];
        let ksym = HekiKernelSymbol::from_bytes(kinfo_bytes)?;

        let value_addr = start + mem::offset_of!(HekiKernelSymbol, value_offset) as u64;
        let value = value_addr
            .as_u64()
            .wrapping_add_signed(i64::from(ksym.value_offset));

        let name_offset = kinfo_start
            + mem::offset_of!(HekiKernelSymbol, name_offset)
            + usize::try_from(ksym.name_offset).map_err(|_| Errno::EINVAL)?;

        if name_offset >= bytes.len() {
            return Err(Errno::EINVAL);
        }
        let name_len = bytes[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(Errno::EBADR)?;
        if name_len >= HekiKernelSymbol::KSY_NAME_LEN {
            return Err(Errno::EINVAL);
        }

        // SAFETY:
        // - offset is within bytes (checked above)
        // - there is a NUL terminator within bytes[offset..] (checked above)
        // - Length of name string is within spec range (checked above)
        // - bytes is still valid for the duration of this function
        let name_str = unsafe {
            let name_ptr = bytes.as_ptr().add(name_offset).cast::<c_char>();
            CStr::from_ptr(name_ptr)
        };
        let name = CString::new(name_str.to_str().unwrap()).unwrap();
        let name = name.into_string().unwrap();
        Ok((name, Symbol { _value: value }))
    }
}
pub struct SymbolTable {
    inner: spin::rwlock::RwLock<HashMap<String, Symbol>>,
}
use core::ffi::{CStr, c_char};

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            inner: spin::rwlock::RwLock::new(HashMap::new()),
        }
    }
    pub fn build_from_container(
        &self,
        start: VirtAddr,
        end: VirtAddr,
        mem: &MemoryContainer,
        buf: &[u8],
    ) -> Result<u64, Errno> {
        if mem.is_empty() {
            serial_println!("VSM: Symbol table data empty");
            return Err(Errno::EINVAL);
        }
        let Some(range) = mem.get_range() else {
            return Err(Errno::EINVAL);
        };
        if start < range.start || end > range.end {
            serial_println!("VSM: Symbol table data not found");
            return Err(Errno::EINVAL);
        }

        let kinfo_len = usize::try_from(end - start).unwrap();
        if kinfo_len % HekiKernelSymbol::KSYM_LEN != 0 {
            return Err(Errno::EINVAL);
        }

        let mut kinfo_offset = usize::try_from(start - range.start).unwrap();
        let mut kinfo_addr = start;
        let ksym_count = kinfo_len / HekiKernelSymbol::KSYM_LEN;
        let mut inner = self.inner.write();
        inner.reserve(ksym_count);

        for _ in 0..ksym_count {
            let (name, sym) = Symbol::from_bytes(kinfo_offset, kinfo_addr, buf).unwrap();
            inner.insert(name, sym);
            kinfo_offset += HekiKernelSymbol::KSYM_LEN;
            kinfo_addr += HekiKernelSymbol::KSYM_LEN as u64;
        }
        Ok(0)
    }
}

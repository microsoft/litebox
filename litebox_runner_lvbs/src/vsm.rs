// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM dispatch functions — dispatcher and all VSM service handlers.
//!
//! These functions were migrated from `litebox_platform_lvbs::mshv::vsm`
//! to the runner crate where dispatch logic belongs.

use alloc::vec::Vec;
use litebox::utils::TruncateExt;
use litebox_common_linux::errno::Errno;
#[cfg(debug_assertions)]
use litebox_platform_lvbs::mshv::mem_integrity::parse_modinfo;
use litebox_platform_lvbs::mshv::ringbuffer::set_ringbuffer;
use litebox_platform_lvbs::{
    arch::get_core_id,
    debug_serial_print, debug_serial_println,
    host::{
        bootparam::get_vtl1_memory_info,
        linux::{CpuMask, Kimage, KEXEC_SEGMENT_MAX},
        per_cpu_variables::with_per_cpu_variables_mut,
    },
    mshv::{
        error::VsmError,
        heki::{
            mem_attr_to_hv_page_prot_flags, mod_mem_type_to_mem_attr, HekiKdataType,
            HekiKernelInfo, HekiKexecType, HekiPage, HekiPatch, MemAttr, ModMemType,
        },
        hvcall::HypervCallError,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers, init_vtl_ap},
        mem_integrity::{
            validate_kernel_module_against_elf, validate_text_patch,
            verify_kernel_module_signature, verify_kernel_pe_signature,
        },
        vsm::{
            AlignedPage, KexecMemoryMetadata, KexecMemoryRange, MemoryContainer, ModuleMemory,
            ModuleMemoryMetadata, CPU_ONLINE_MASK, MODULE_VALIDATION_MAX_SIZE,
        },
        vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE},
        vtl_switch::mshv_vsm_get_code_page_offsets,
        HvCrInterceptControlFlags, HvPageProtFlags, HvRegisterVsmPartitionConfig,
        HvRegisterVsmVpSecureVtlConfig, VsmFunction, X86Cr0Flags, X86Cr4Flags,
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HV_REGISTER_VSM_PARTITION_CONFIG,
        HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, HV_SECURE_VTL_BOOT_TOKEN,
    },
};
use litebox_platform_multiplex::platform;
use x509_cert::{der::Decode, Certificate};
use x86_64::{
    structures::paging::{frame::PhysFrameRange, PageSize, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};
use zerocopy::{FromBytes, FromZeros, IntoBytes};

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
fn mshv_vsm_enable_aps(_cpu_present_mask_pfn: u64) -> Result<i64, VsmError> {
    debug_serial_println!("mshv_vsm_enable_aps() not supported");
    Ok(0)
}

/// VSM function for enabling VTL and booting APs
/// `cpu_online_mask_pfn` indicates the page containing the VTL0's CPU online mask.
/// `boot_signal_pfn` indicates the boot signal page to let VTL0 know that VTL1 is ready.
fn mshv_vsm_boot_aps(cpu_online_mask_pfn: u64, boot_signal_pfn: u64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Boot APs");
    let cpu_online_mask_page_addr = PhysAddr::try_new(cpu_online_mask_pfn << PAGE_SHIFT)
        .map_err(|_| VsmError::InvalidPhysicalAddress)?;
    let boot_signal_page_addr = PhysAddr::try_new(boot_signal_pfn << PAGE_SHIFT)
        .map_err(|_| VsmError::InvalidPhysicalAddress)?;

    let Some(cpu_mask) =
        (unsafe { platform().copy_from_vtl0_phys::<CpuMask>(cpu_online_mask_page_addr) })
    else {
        return Err(VsmError::CpuOnlineMaskCopyFailed);
    };

    debug_serial_print!("cpu_online_mask: ");
    cpu_mask.for_each_cpu(|cpu_id| {
        debug_serial_print!("{}, ", cpu_id);
    });
    debug_serial_println!("");

    // boot_signal is an array of bytes whose length is the number of possible cores. Copy the entire page for now.
    let Some(mut boot_signal_page_buf) =
        (unsafe { platform().copy_from_vtl0_phys::<AlignedPage>(boot_signal_page_addr) })
    else {
        return Err(VsmError::BootSignalPageCopyFailed);
    };

    let mut error = None;

    // Initialize VTL for each online CPU and update its boot signal byte
    cpu_mask.for_each_cpu(|cpu_id| {
        if cpu_id > boot_signal_page_buf.0.len() - 1 {
            error = Some(HypervCallError::InvalidInput);
            return;
        }
        let cpu_id_u32: u32 = cpu_id.truncate();
        if let Err(e) = init_vtl_ap(cpu_id_u32) {
            error = Some(e);
        }
        boot_signal_page_buf.0[cpu_id] = HV_SECURE_VTL_BOOT_TOKEN;
    });

    if let Some(e) = error {
        return Err(VsmError::ApInitFailed(e));
    }

    // Store the cpu_online_mask for later use
    CPU_ONLINE_MASK.call_once(|| cpu_mask);

    if unsafe {
        platform().copy_to_vtl0_phys::<AlignedPage>(boot_signal_page_addr, &boot_signal_page_buf)
    } {
        Ok(0)
    } else {
        Err(VsmError::BootSignalWriteFailed)
    }
}

/// VSM function for enforcing certain security features of VTL0
fn mshv_vsm_secure_config_vtl0() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Secure VTL0 configuration");

    let mut config = HvRegisterVsmVpSecureVtlConfig::new();
    config.set_mbec_enabled(true);
    config.set_tlb_locked(true);

    hvcall_set_vp_registers(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, config.as_u64())
        .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

/// VSM function to configure a VSM partition for VTL1
fn mshv_vsm_configure_partition() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Configure partition");

    let mut config = HvRegisterVsmPartitionConfig::new();
    config.set_default_vtl_protection_mask(HvPageProtFlags::HV_PAGE_FULL_ACCESS.bits());
    config.set_enable_vtl_protection(true);

    hvcall_set_vp_registers(HV_REGISTER_VSM_PARTITION_CONFIG, config.as_u64())
        .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

/// VSM function for locking VTL0's control registers.
fn mshv_vsm_lock_regs() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Lock control registers");

    if platform().vtl0_kernel_info.check_end_of_boot() {
        return Err(VsmError::OperationAfterEndOfBoot(
            "control register locking",
        ));
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

    save_vtl0_locked_regs().map_err(VsmError::HypercallFailed)?;

    hvcall_set_vp_registers(HV_REGISTER_CR_INTERCEPT_CONTROL, flag)
        .map_err(VsmError::HypercallFailed)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR4_MASK,
        X86Cr4Flags::CR4_PIN_MASK.bits().into(),
    )
    .map_err(VsmError::HypercallFailed)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        X86Cr0Flags::CR0_PIN_MASK.bits().into(),
    )
    .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

/// VSM function for signaling the end of VTL0 boot process
fn mshv_vsm_end_of_boot() -> i64 {
    debug_serial_println!("VSM: End of boot");
    platform().vtl0_kernel_info.set_end_of_boot();
    0
}

/// VSM function for protecting certain memory ranges (e.g., kernel text, data, heap).
/// `pa` and `nranges` specify a memory area containing the information about the memory ranges to protect.
fn mshv_vsm_protect_memory(pa: u64, nranges: u64) -> Result<i64, VsmError> {
    if PhysAddr::try_new(pa)
        .ok()
        .filter(|p| p.is_aligned(Size4KiB::SIZE))
        .is_none()
        || nranges == 0
    {
        return Err(VsmError::InvalidInputAddress);
    }

    if platform().vtl0_kernel_info.check_end_of_boot() {
        return Err(VsmError::OperationAfterEndOfBoot(
            "kernel memory protection",
        ));
    }

    let heki_pages = copy_heki_pages_from_vtl0(pa, nranges).ok_or(VsmError::HekiPagesCopyFailed)?;

    for heki_page in heki_pages {
        for heki_range in &heki_page {
            let pa = heki_range.pa;
            let epa = heki_range.epa;
            let mem_attr = heki_range
                .mem_attr()
                .ok_or(VsmError::MemoryAttributeInvalid)?;

            if !heki_range.is_aligned(Size4KiB::SIZE) {
                return Err(VsmError::AddressNotPageAligned);
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
}

fn parse_certs(mut buf: &[u8]) -> Result<Vec<Certificate>, VsmError> {
    let mut certs = Vec::new();

    while buf.len() >= 4 && buf[0] == 0x30 && buf[1] == 0x82 {
        let der_len = ((buf[2] as usize) << 8) | (buf[3] as usize);
        let total_len = der_len + 4;

        if buf.len() < total_len {
            return Err(VsmError::CertificateDerLengthInvalid {
                expected: total_len,
                actual: buf.len(),
            });
        }

        let cert_bytes = &buf[..total_len];
        let cert =
            Certificate::from_der(cert_bytes).map_err(|_| VsmError::CertificateParseFailed)?;
        certs.push(cert);
        buf = &buf[total_len..];
    }
    Ok(certs)
}

/// VSM function for loading kernel data (e.g., certificates, blocklist, kernel symbols) into VTL1.
/// `pa` and `nranges` specify memory areas containing the information about the memory ranges to load.
fn mshv_vsm_load_kdata(pa: u64, nranges: u64) -> Result<i64, VsmError> {
    if PhysAddr::try_new(pa)
        .ok()
        .filter(|p| p.is_aligned(Size4KiB::SIZE))
        .is_none()
        || nranges == 0
    {
        return Err(VsmError::InvalidInputAddress);
    }

    if platform().vtl0_kernel_info.check_end_of_boot() {
        return Err(VsmError::OperationAfterEndOfBoot("loading kernel data"));
    }

    let vtl0_info = &platform().vtl0_kernel_info;

    let mut system_certs_mem = MemoryContainer::new();
    let mut kexec_trampoline_metadata = KexecMemoryMetadata::new();
    let mut patch_info_mem = MemoryContainer::new();
    let mut kinfo_mem = MemoryContainer::new();
    let mut kdata_mem = MemoryContainer::new();

    let heki_pages = copy_heki_pages_from_vtl0(pa, nranges).ok_or(VsmError::HekiPagesCopyFailed)?;

    for heki_page in &heki_pages {
        for heki_range in heki_page {
            debug_serial_println!("VSM: Load kernel data {heki_range:?}");
            match heki_range.heki_kdata_type() {
                HekiKdataType::SystemCerts => system_certs_mem
                    .extend_range(heki_range)
                    .map_err(|_| VsmError::InvalidInputAddress)?,
                HekiKdataType::KexecTrampoline => {
                    kexec_trampoline_metadata.insert_heki_range(heki_range);
                }
                HekiKdataType::PatchInfo => patch_info_mem
                    .extend_range(heki_range)
                    .map_err(|_| VsmError::InvalidInputAddress)?,
                HekiKdataType::KernelInfo => kinfo_mem
                    .extend_range(heki_range)
                    .map_err(|_| VsmError::InvalidInputAddress)?,
                HekiKdataType::KernelData => kdata_mem
                    .extend_range(heki_range)
                    .map_err(|_| VsmError::InvalidInputAddress)?,
                HekiKdataType::Unknown => {
                    return Err(VsmError::KernelDataTypeInvalid);
                }
                _ => {
                    debug_serial_println!("VSM: Unsupported kernel data not loaded {heki_range:?}");
                }
            }
        }
    }

    system_certs_mem
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
    patch_info_mem
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
    kinfo_mem
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
    kdata_mem
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;

    if system_certs_mem.is_empty() {
        return Err(VsmError::SystemCertificatesNotFound);
    }

    let cert_buf = &system_certs_mem[..];
    let certs = parse_certs(cert_buf)?;

    if certs.is_empty() {
        return Err(VsmError::SystemCertificatesInvalid);
    }

    // The system certificate is loaded into VTL1 and locked down before `end_of_boot` is signaled.
    // Its integrity depends on UEFI Secure Boot which ensures only trusted software is loaded during
    // the boot process.
    vtl0_info.set_system_certificates(certs.clone());
    debug_serial_println!("VSM: Loaded {} system certificate(s)", certs.len());

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
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
    }

    if kinfo_mem.is_empty() || kdata_mem.is_empty() {
        return Err(VsmError::KernelSymbolTableNotFound);
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
fn mshv_vsm_validate_guest_module(pa: u64, nranges: u64, _flags: u64) -> Result<i64, VsmError> {
    if PhysAddr::try_new(pa)
        .ok()
        .filter(|p| p.is_aligned(Size4KiB::SIZE))
        .is_none()
        || nranges == 0
    {
        return Err(VsmError::InvalidInputAddress);
    }

    debug_serial_println!(
        "VSM: Validate kernel module: pa {:#x} nranges {}",
        pa,
        nranges,
    );

    let certs = platform()
        .vtl0_kernel_info
        .get_system_certificates()
        .ok_or(VsmError::SystemCertificatesNotLoaded)?;

    // collect and maintain the memory ranges of a module locally until the module is validated and its metadata is registered in the global map
    // we don't maintain this content in the global map due to memory overhead. Instead, we could add its hash value to the global map to check the integrity.
    let mut module_memory_metadata = ModuleMemoryMetadata::new();
    // a kernel module loaded in memory with relocations and patches
    let mut module_in_memory = ModuleMemory::new();
    // the kernel module's original ELF binary which is signed by the kernel build pipeline
    let mut module_as_elf = MemoryContainer::new();
    // patch info for the kernel module
    let mut patch_info_for_module = MemoryContainer::new();

    let heki_pages = copy_heki_pages_from_vtl0(pa, nranges).ok_or(VsmError::HekiPagesCopyFailed)?;

    for heki_page in &heki_pages {
        for heki_range in heki_page {
            match heki_range.mod_mem_type() {
                ModMemType::Unknown => {
                    return Err(VsmError::ModuleMemoryTypeInvalid);
                }
                ModMemType::ElfBuffer => module_as_elf
                    .extend_range(heki_range)
                    .map_err(|_| VsmError::InvalidInputAddress)?,
                ModMemType::Patch => patch_info_for_module
                    .extend_range(heki_range)
                    .map_err(|_| VsmError::InvalidInputAddress)?,
                _ => {
                    // if input memory range's type is neither `Unknown` nor `ElfBuffer`, its addresses must be page-aligned
                    if !heki_range.is_aligned(Size4KiB::SIZE) {
                        return Err(VsmError::AddressNotPageAligned);
                    }
                    module_memory_metadata.insert_heki_range(heki_range);
                    module_in_memory
                        .extend_range(heki_range.mod_mem_type(), heki_range)
                        .map_err(|_| VsmError::InvalidInputAddress)?;
                }
            }
        }
    }

    module_as_elf
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
    patch_info_for_module
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
    module_in_memory
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;

    let elf_size = (module_as_elf[..]).len();
    if elf_size > MODULE_VALIDATION_MAX_SIZE {
        return Err(VsmError::ModuleElfSizeExceeded {
            size: elf_size,
            max: MODULE_VALIDATION_MAX_SIZE,
        });
    }

    let original_elf_data = &module_as_elf[..];

    #[cfg(debug_assertions)]
    parse_modinfo(original_elf_data).map_err(|_| VsmError::Vtl0CopyFailed)?;

    verify_kernel_module_signature(original_elf_data, certs)?;

    if !validate_kernel_module_against_elf(&module_in_memory, original_elf_data)
        .map_err(|_| VsmError::Vtl0CopyFailed)?
    {
        return Err(VsmError::ModuleRelocationInvalid);
    }

    // pre-computed patch data for a module
    if !patch_info_for_module.is_empty() {
        let patch_info_buf = &patch_info_for_module[..];
        platform()
            .vtl0_kernel_info
            .precomputed_patches
            .insert_patch_data_from_bytes(patch_info_buf, Some(&mut module_memory_metadata))
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
    }

    // once a module is verified and validated, change the permission of its memory ranges based on their types
    for mod_mem_range in &module_memory_metadata {
        protect_physical_memory_range(
            mod_mem_range.phys_frame_range,
            mod_mem_type_to_mem_attr(mod_mem_range.mod_mem_type),
        )?;
    }

    // register the module memory in the global map and obtain a unique token for it
    let token = platform()
        .vtl0_kernel_info
        .module_memory_metadata
        .register_module_memory_metadata(module_memory_metadata);
    Ok(token)
}

/// VSM function for supporting the initialization of a guest kernel module including
/// freeing the memory ranges that were used only for initialization and
/// write-protecting the memory ranges that should be read-only after initialization.
/// `token` is the unique identifier for the module.
fn mshv_vsm_free_guest_module_init(token: i64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Free kernel module's init (token: {})", token);

    if !platform()
        .vtl0_kernel_info
        .module_memory_metadata
        .contains_key(token)
    {
        return Err(VsmError::ModuleTokenInvalid);
    }

    if let Some(entry) = platform()
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
fn mshv_vsm_unload_guest_module(token: i64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Unload kernel module (token: {})", token);

    if !platform()
        .vtl0_kernel_info
        .module_memory_metadata
        .contains_key(token)
    {
        return Err(VsmError::ModuleTokenInvalid);
    }

    if let Some(entry) = platform()
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

    if let Some(patch_targets) = platform()
        .vtl0_kernel_info
        .module_memory_metadata
        .get_patch_targets(token)
    {
        platform()
            .vtl0_kernel_info
            .precomputed_patches
            .remove_patch_data(&patch_targets);
    }

    platform()
        .vtl0_kernel_info
        .module_memory_metadata
        .remove(token);
    Ok(0)
}

/// VSM function for copying secondary key
#[allow(clippy::unnecessary_wraps)]
fn mshv_vsm_copy_secondary_key(_pa: u64, _nranges: u64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Copy secondary key");
    // TODO: copy secondary key
    Ok(0)
}

/// VSM function for write protecting the memory regions of a verified kernel image for kexec.
/// This function protects the kexec kernel blob (PE) only if it has a valid signature.
/// Note: this function does not make kexec kernel pages executable, which should be done by
/// another VTL1 method that can intercept the kexec/reset signal.
fn mshv_vsm_kexec_validate(pa: u64, nranges: u64, crash: u64) -> Result<i64, VsmError> {
    debug_serial_println!(
        "VSM: Validate kexec pa {:#x} nranges {} crash {}",
        pa,
        nranges,
        crash
    );

    let certs = platform()
        .vtl0_kernel_info
        .get_system_certificates()
        .ok_or(VsmError::SystemCertificatesNotLoaded)?;

    let is_crash = crash != 0;
    let kexec_metadata_ref = if is_crash {
        &platform().vtl0_kernel_info.crash_kexec_metadata
    } else {
        &platform().vtl0_kernel_info.kexec_metadata
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

    let heki_pages = copy_heki_pages_from_vtl0(pa, nranges).ok_or(VsmError::HekiPagesCopyFailed)?;

    for heki_page in &heki_pages {
        for heki_range in heki_page {
            match heki_range.heki_kexec_type() {
                HekiKexecType::KexecImage => {
                    kexec_memory_metadata.insert_heki_range(heki_range);
                    kexec_image
                        .extend_range(heki_range)
                        .map_err(|_| VsmError::InvalidInputAddress)?;
                }
                HekiKexecType::KexecKernelBlob =>
                // we do not protect kexec kernel blob memory
                {
                    kexec_kernel_blob
                        .extend_range(heki_range)
                        .map_err(|_| VsmError::InvalidInputAddress)?;
                }

                HekiKexecType::KexecPages => kexec_memory_metadata.insert_heki_range(heki_range),
                HekiKexecType::Unknown => {
                    return Err(VsmError::KexecTypeInvalid);
                }
            }
        }
    }

    kexec_image
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
    kexec_kernel_blob
        .write_bytes_from_heki_range()
        .map_err(|_| VsmError::Vtl0CopyFailed)?;

    // If this function is called for crash kexec, we protect its kimage segments as well.
    if is_crash {
        let kimage = Kimage::read_from_bytes(&kexec_image[..core::mem::size_of::<Kimage>()])
            .map_err(|_| VsmError::KexecImageSegmentsInvalid)?;
        if kimage.nr_segments > KEXEC_SEGMENT_MAX as u64 {
            return Err(VsmError::KexecImageSegmentsInvalid);
        }
        for i in 0..usize::try_from(kimage.nr_segments).unwrap_or(0) {
            let va = kimage.segment[i].buf;
            let pa = kimage.segment[i].mem;
            if let Some(epa) = pa.checked_add(kimage.segment[i].memsz) {
                kexec_memory_metadata.insert_memory_range(KexecMemoryRange::new(va, pa, epa));
            } else {
                return Err(VsmError::KexecSegmentRangeInvalid);
            }
        }
    }

    // write protect the kexec memory ranges first to avoid the race condition during verification
    for kexec_mem_range in &kexec_memory_metadata {
        protect_physical_memory_range(kexec_mem_range.phys_frame_range, MemAttr::MEM_ATTR_READ)?;
    }

    // verify the signature of kexec blob
    let kexec_kernel_blob_data = &kexec_kernel_blob[..];

    if let Err(result) = verify_kernel_pe_signature(kexec_kernel_blob_data, certs) {
        for kexec_mem_range in &kexec_memory_metadata {
            protect_physical_memory_range(
                kexec_mem_range.phys_frame_range,
                MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE,
            )?;
        }
        return Err(VsmError::SignatureVerificationFailed(result));
    }

    // register the protected kexec memory ranges to support possible invalidation in the future
    kexec_metadata_ref.register_memory(kexec_memory_metadata);

    Ok(0)
}

/// VSM function for patching kernel or module text. VTL0 kernel calls this function to patch certain kernel or module
/// text region (which it does not have a permission to modify). It passes `HekiPatch` structure which can be stored
/// within one or across two likely non-contiguous physical pages.
fn mshv_vsm_patch_text(patch_pa_0: u64, patch_pa_1: u64) -> Result<i64, VsmError> {
    let heki_patch = copy_heki_patch_from_vtl0(patch_pa_0, patch_pa_1)?;
    debug_serial_println!("VSM: {:?}", heki_patch);

    let precomputed_patch = platform()
        .vtl0_kernel_info
        .find_precomputed_patch(&heki_patch)
        .ok_or(VsmError::PrecomputedPatchNotFound)?;

    if !validate_text_patch(&heki_patch, &precomputed_patch) {
        return Err(VsmError::TextPatchSuspicious);
    }

    apply_vtl0_text_patch(heki_patch)?;
    Ok(0)
}

/// This function copies patch data in `HekiPatch` structure from VTL0 to VTL1. This patch data can be
/// stored within a physical page or across two likely non-contiguous physical pages.
fn copy_heki_patch_from_vtl0(patch_pa_0: u64, patch_pa_1: u64) -> Result<HekiPatch, VsmError> {
    let patch_pa_0 = PhysAddr::try_new(patch_pa_0).map_err(|_| VsmError::InvalidPhysicalAddress)?;
    let patch_pa_1 = PhysAddr::try_new(patch_pa_1).map_err(|_| VsmError::InvalidPhysicalAddress)?;
    if patch_pa_0.is_null() || patch_pa_0 == patch_pa_1 || !patch_pa_1.is_aligned(Size4KiB::SIZE) {
        return Err(VsmError::InvalidInputAddress);
    }
    let bytes_in_first_page = if patch_pa_0.is_aligned(Size4KiB::SIZE) {
        core::cmp::min(PAGE_SIZE, core::mem::size_of::<HekiPatch>())
    } else {
        core::cmp::min(
            (patch_pa_0.align_up(Size4KiB::SIZE) - patch_pa_0).truncate(),
            core::mem::size_of::<HekiPatch>(),
        )
    };

    if (bytes_in_first_page < core::mem::size_of::<HekiPatch>() && patch_pa_1.is_null())
        || (bytes_in_first_page == core::mem::size_of::<HekiPatch>() && !patch_pa_1.is_null())
    {
        return Err(VsmError::InvalidInputAddress);
    }

    if patch_pa_1.is_null()
        || (patch_pa_0.align_up(Size4KiB::SIZE) == patch_pa_1.align_down(Size4KiB::SIZE))
    {
        unsafe { platform().copy_from_vtl0_phys::<HekiPatch>(patch_pa_0) }
            .map(|boxed| *boxed)
            .ok_or(VsmError::Vtl0CopyFailed)
    } else {
        let mut heki_patch = HekiPatch::new_zeroed();
        let heki_patch_bytes = heki_patch.as_mut_bytes();
        unsafe {
            if !platform().copy_slice_from_vtl0_phys(
                patch_pa_0,
                heki_patch_bytes.get_unchecked_mut(..bytes_in_first_page),
            ) || !platform().copy_slice_from_vtl0_phys(
                patch_pa_1,
                heki_patch_bytes.get_unchecked_mut(bytes_in_first_page..),
            ) {
                return Err(VsmError::Vtl0CopyFailed);
            }
        }
        if heki_patch.is_valid() {
            Ok(heki_patch)
        } else {
            Err(VsmError::InvalidInputAddress)
        }
    }
}

/// This function apply the given `HekiPatch` patch data to VTL0 text.
/// It assumes the caller has confirmed the validity of `HekiPatch` by invoking the `is_valid()` member function.
fn apply_vtl0_text_patch(heki_patch: HekiPatch) -> Result<(), VsmError> {
    let heki_patch_pa_0 = PhysAddr::new(heki_patch.pa[0]);
    let heki_patch_pa_1 = PhysAddr::new(heki_patch.pa[1]);

    let patch_target_page_offset: usize =
        (heki_patch_pa_0 - heki_patch_pa_0.align_down(Size4KiB::SIZE)).truncate();
    let bytes_in_first_page = PAGE_SIZE - patch_target_page_offset;

    if heki_patch_pa_1.is_null()
        || (heki_patch_pa_0.align_up(Size4KiB::SIZE) == heki_patch_pa_1.align_down(Size4KiB::SIZE))
    {
        if !unsafe {
            platform().copy_slice_to_vtl0_phys(
                heki_patch_pa_0,
                &heki_patch.code[..usize::from(heki_patch.size)],
            )
        } {
            return Err(VsmError::Vtl0CopyFailed);
        }
    } else {
        let (patch_first, patch_second) = heki_patch.code.split_at(bytes_in_first_page);

        unsafe {
            if !platform().copy_slice_to_vtl0_phys(
                heki_patch_pa_0 + patch_target_page_offset as u64,
                patch_first,
            ) || !platform().copy_slice_to_vtl0_phys(heki_patch_pa_1, patch_second)
            {
                return Err(VsmError::Vtl0CopyFailed);
            }
        }
    }
    Ok(())
}

fn mshv_vsm_allocate_ringbuffer_memory(phys_addr: u64, size: usize) -> Result<i64, VsmError> {
    set_ringbuffer(PhysAddr::new(phys_addr), size);
    protect_physical_memory_range(
        PhysFrame::range(
            PhysFrame::containing_address(PhysAddr::new(phys_addr)),
            PhysFrame::containing_address(PhysAddr::new(phys_addr + (size as u64))),
        ),
        MemAttr::MEM_ATTR_READ,
    )?;
    debug_serial_println!("VSM: Ring buffer allocated");
    Ok(0)
}

/// VSM function dispatcher
pub(crate) fn vsm_dispatch(func_id: VsmFunction, params: &[u64]) -> i64 {
    let result: Result<i64, VsmError> = match func_id {
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
        VsmFunction::AllocateRingbufferMemory => {
            let size: usize = params[1].truncate();
            mshv_vsm_allocate_ringbuffer_memory(params[0], size)
        }
        VsmFunction::OpteeMessage => Err(VsmError::OperationNotSupported("OP-TEE communication")),
    };
    match result {
        Ok(value) => value,
        Err(e) => Errno::from(e).as_neg().into(),
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

/// This function copies `HekiPage` structures from VTL0 and returns a vector of them.
/// `pa` and `nranges` specify the physical address range containing one or more than one `HekiPage` structures.
fn copy_heki_pages_from_vtl0(pa: u64, nranges: u64) -> Option<Vec<HekiPage>> {
    let mut next_pa = PhysAddr::new(pa);
    let mut heki_pages = Vec::with_capacity(nranges.truncate());
    let mut range: u64 = 0;

    while range < nranges {
        let heki_page = (unsafe { platform().copy_from_vtl0_phys::<HekiPage>(next_pa) })?;
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
fn protect_physical_memory_range(
    phys_frame_range: PhysFrameRange<Size4KiB>,
    mem_attr: MemAttr,
) -> Result<(), VsmError> {
    let pa = phys_frame_range.start.start_address().as_u64();
    let num_pages = phys_frame_range.count() as u64;
    if num_pages > 0 {
        hv_modify_vtl_protection_mask(pa, num_pages, mem_attr_to_hv_page_prot_flags(mem_attr))
            .map_err(VsmError::HypercallFailed)?;
    }
    Ok(())
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM HEKI service functions

#[cfg(debug_assertions)]
use crate::mshv::heki_service::mem_integrity::parse_modinfo;
use crate::mshv::heki_service::mem_integrity::{
    validate_kernel_module_against_elf, validate_text_patch, verify_kernel_module_signature,
    verify_kernel_pe_signature,
};
use crate::mshv::heki_service::state::{
    KexecMemoryMetadata, KexecMemoryRange, MemoryContainer, ModuleMemory, ModuleMemoryMetadata,
};
use crate::mshv::ringbuffer::set_ringbuffer;
use crate::mshv::vsm::{
    FrameReservation, ReservationStatus, protect_physical_memory_range,
    unprotect_physical_memory_range,
};
use crate::mshv::{PrivilegedVtl0PhysMutPtr, Vtl0PhysConstPtr};
use crate::{
    debug_serial_println,
    host::{linux::CpuMask, set_platform_root_key},
    mshv::{
        hvcall_vp::init_vtl_ap,
        vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE},
    },
};
use litebox_common_lvbs::{
    HekiKdataType, HekiKernelInfo, HekiKexecType, HekiPage, HekiPatch, KEXEC_SEGMENT_MAX, Kimage,
    MemAttr, ModMemType, PRK_LEN, VsmError, mod_mem_type_to_mem_attr,
};

use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashSet;
use litebox::utils::TruncateExt;
use litebox_common_linux::vmap::PhysPageAddr;
use spin::Once;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB},
};
use x509_cert::{Certificate, der::Decode};
use zerocopy::{FromBytes, FromZeros, IntoBytes};
use zeroize::Zeroizing;

// For now, we do not validate large kernel modules due to the VTL1's memory size limitation.
const MODULE_VALIDATION_MAX_SIZE: usize = 64 * 1024 * 1024;

static CPU_ONLINE_MASK: Once<Box<CpuMask>> = Once::new();

/// VSM function for enabling VTL of APs
/// Not supported in this implementation.
#[allow(clippy::unnecessary_wraps)]
pub fn mshv_vsm_enable_aps(_cpu_present_mask_pfn: u64) -> Result<i64, VsmError> {
    debug_serial_println!("mshv_vsm_enable_aps() not supported");
    Ok(0)
}

/// VSM function for enabling VTL and booting APs
/// `cpu_online_mask_pfn` indicates the page containing the VTL0's CPU online mask.
pub fn mshv_vsm_boot_aps(cpu_online_mask_pfn: u64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Boot APs");
    let cpu_online_mask_page_addr = cpu_online_mask_pfn
        .checked_shl(PAGE_SHIFT.trunc())
        .and_then(|pa| PhysAddr::try_new(pa).ok())
        .ok_or(VsmError::InvalidPhysicalAddress)?;

    let cpu_mask_ptr = Vtl0PhysConstPtr::<CpuMask, PAGE_SIZE>::with_usize(
        cpu_online_mask_page_addr.as_u64().trunc(),
    )
    .map_err(|_| VsmError::CpuOnlineMaskCopyFailed)?;
    let cpu_mask = cpu_mask_ptr
        .read_at_offset(0)
        .map_err(|_| VsmError::CpuOnlineMaskCopyFailed)?;

    #[cfg(debug_assertions)]
    {
        crate::debug_serial_print!("cpu_online_mask: ");
        cpu_mask.for_each_cpu(|cpu_id| {
            crate::debug_serial_print!("{}, ", cpu_id);
        });
        debug_serial_println!("");
    }

    let mut error = None;

    // Initialize VTL for each online CPU and update its boot signal byte
    cpu_mask.for_each_cpu(|cpu_id| {
        let cpu_id_u32: u32 = cpu_id.trunc();
        if let Err(e) = init_vtl_ap(cpu_id_u32) {
            error = Some(e);
        }
    });

    if let Some(e) = error {
        return Err(VsmError::ApInitFailed(e));
    }

    // Store the cpu_online_mask for later use
    CPU_ONLINE_MASK.call_once(|| cpu_mask);

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
pub fn mshv_vsm_protect_memory(pa: u64, nranges: u64) -> Result<i64, VsmError> {
    if PhysAddr::try_new(pa)
        .ok()
        .as_ref()
        .is_none_or(|p| !p.is_aligned(Size4KiB::SIZE))
        || nranges == 0
    {
        return Err(VsmError::InvalidInputAddress);
    }

    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
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

            if pa == epa {
                continue;
            }

            protect_physical_memory_range(
                PhysFrame::range(
                    // `HekiRange::is_valid` already validated both physical addresses.
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
pub fn mshv_vsm_load_kdata(pa: u64, nranges: u64) -> Result<i64, VsmError> {
    if PhysAddr::try_new(pa)
        .ok()
        .as_ref()
        .is_none_or(|p| !p.is_aligned(Size4KiB::SIZE))
        || nranges == 0
    {
        return Err(VsmError::InvalidInputAddress);
    }

    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
        return Err(VsmError::OperationAfterEndOfBoot("loading kernel data"));
    }

    let vtl0_info = &crate::platform_low().vtl0_kernel_info;

    let mut system_certs_mem = MemoryContainer::new();
    let mut kexec_trampoline_metadata = KexecMemoryMetadata::new();
    let mut kexec_trampoline_insert_failed = false;
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
                    if let Err(e) = kexec_trampoline_metadata.insert_heki_range(heki_range) {
                        debug_serial_println!(
                            "VSM: KexecTrampoline insert_heki_range failed ({e:?}); skipping kexec trampoline protection"
                        );
                        kexec_trampoline_insert_failed = true;
                    }
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

    // ToDo: Remove kexec_trampoline_insert_failed and protect kexec_trampoline_metadata
    // once we have a better solution to handle the non-page-aligned kexec trampoline metadata.
    // The current solution is to skip protecting kexec trampoline metadata if its insert_heki_range
    // fails, letting kdata load proceed so that heki is not broken.
    if !kexec_trampoline_insert_failed {
        for kexec_trampoline_range in &kexec_trampoline_metadata {
            protect_physical_memory_range(
                kexec_trampoline_range.phys_frame_range,
                MemAttr::MEM_ATTR_READ,
            )?;
        }
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
pub fn mshv_vsm_validate_guest_module(pa: u64, nranges: u64, _flags: u64) -> Result<i64, VsmError> {
    if PhysAddr::try_new(pa)
        .ok()
        .as_ref()
        .is_none_or(|p| !p.is_aligned(Size4KiB::SIZE))
        || nranges == 0
    {
        return Err(VsmError::InvalidInputAddress);
    }

    debug_serial_println!(
        "VSM: Validate kernel module: pa {:#x} nranges {}",
        pa,
        nranges,
    );

    let certs = crate::platform_low()
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

    // Reject overlap and reserve this module's frames. Legitimate module frames are never shared.
    let mut frame_guard = FrameReservation::new();
    let _ = frame_guard.reserve(module_memory_metadata.iter().map(|r| r.phys_frame_range))?;

    // Freeze frames that require immutable copy/validation to avoid TOCTOU.
    for mod_mem_range in &module_memory_metadata {
        if !mod_mem_type_to_mem_attr(mod_mem_range.mod_mem_type).contains(MemAttr::MEM_ATTR_WRITE) {
            protect_physical_memory_range(mod_mem_range.phys_frame_range, MemAttr::MEM_ATTR_READ)?;
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

    // Both read-only and executable frames have been frozen above.
    // Thus, only promote executable frames to RX.
    for mod_mem_range in &module_memory_metadata {
        if matches!(
            mod_mem_range.mod_mem_type,
            ModMemType::Text | ModMemType::InitText
        ) {
            protect_physical_memory_range(
                mod_mem_range.phys_frame_range,
                mod_mem_type_to_mem_attr(mod_mem_range.mod_mem_type),
            )?;
        }
    }

    // Commit the module's pre-computed patch data (transactional).
    if !patch_info_for_module.is_empty() {
        let patch_info_buf = &patch_info_for_module[..];
        crate::platform_low()
            .vtl0_kernel_info
            .precomputed_patches
            .insert_patch_data_from_bytes(patch_info_buf, Some(&mut module_memory_metadata))
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
    }

    // Fully validated and committed: disarm the guard and register the module.
    frame_guard.commit();
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
pub fn mshv_vsm_free_guest_module_init(token: i64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Free kernel module's init (token: {})", token);

    if !crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .contains_key(token)
    {
        return Err(VsmError::ModuleTokenInvalid);
    }

    let mut result: Result<(), VsmError> = Ok(());
    if let Some(entry) = crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .iter_entry(token)
    {
        for mod_mem_range in entry.iter_mem_ranges() {
            let range_result = match mod_mem_range.mod_mem_type {
                ModMemType::InitText | ModMemType::InitData | ModMemType::InitRoData => {
                    unprotect_physical_memory_range(mod_mem_range.phys_frame_range)
                }
                ModMemType::RoAfterInit => {
                    // make this memory range read-only after initialization
                    protect_physical_memory_range(
                        mod_mem_range.phys_frame_range,
                        MemAttr::MEM_ATTR_READ,
                    )
                }
                _ => Ok(()),
            };
            if range_result.is_err() {
                result = range_result;
                break;
            }
        }
    }

    // Drop the init ranges from the module's metadata regardless of failures. This is intentional
    // since hypercalls shouldn't fail and avoiding double release is more important.
    let freed_init_patch_targets = crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .remove_init_ranges(token);
    // Remove the precomputed patches targeting those freed init frames so a stale init patch cannot
    // later be applied to recycled frames (no patch-after-free).
    if !freed_init_patch_targets.is_empty() {
        crate::platform_low()
            .vtl0_kernel_info
            .precomputed_patches
            .remove_patch_data(&freed_init_patch_targets);
    }

    result.map(|()| 0)
}

/// VSM function for supporting the unloading of a guest kernel module.
/// `token` is the unique identifier for the module.
pub fn mshv_vsm_unload_guest_module(token: i64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Unload kernel module (token: {})", token);

    if !crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .contains_key(token)
    {
        return Err(VsmError::ModuleTokenInvalid);
    }

    if let Some(entry) = crate::platform_low()
        .vtl0_kernel_info
        .module_memory_metadata
        .iter_entry(token)
    {
        for mod_mem_range in entry.iter_mem_ranges() {
            unprotect_physical_memory_range(mod_mem_range.phys_frame_range)?;
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
pub fn mshv_vsm_copy_secondary_key(_pa: u64, _nranges: u64) -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Copy secondary key");
    // TODO: copy secondary key
    Ok(0)
}

/// VSM function for write protecting the memory regions of a verified kernel image for kexec.
/// This function protects the kexec kernel blob (PE) only if it has a valid signature.
/// Note: this function does not make kexec kernel pages executable, which should be done by
/// another VTL1 method that can intercept the kexec/reset signal.
pub fn mshv_vsm_kexec_validate(pa: u64, nranges: u64, crash: u64) -> Result<i64, VsmError> {
    debug_serial_println!(
        "VSM: Validate kexec pa {:#x} nranges {} crash {}",
        pa,
        nranges,
        crash
    );

    let certs = crate::platform_low()
        .vtl0_kernel_info
        .get_system_certificates()
        .ok_or(VsmError::SystemCertificatesNotLoaded)?;

    let is_crash = crash != 0;
    let kexec_metadata_ref = if is_crash {
        &crate::platform_low().vtl0_kernel_info.crash_kexec_metadata
    } else {
        &crate::platform_low().vtl0_kernel_info.kexec_metadata
    };

    // invalidate (i.e., remove protection and clear) the kexec memory ranges which were loaded in the past
    for old_kexec_mem_range in kexec_metadata_ref.iter_guarded().iter_mem_ranges() {
        unprotect_physical_memory_range(old_kexec_mem_range.phys_frame_range)?;
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
                    kexec_memory_metadata.insert_heki_range(heki_range)?;
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

                HekiKexecType::KexecPages => kexec_memory_metadata.insert_heki_range(heki_range)?,
                HekiKexecType::Unknown => {
                    return Err(VsmError::KexecTypeInvalid);
                }
            }
        }
    }

    // Reserve then freeze the protected kexec frames, rejecting overlap with VTL1 or other
    // protected frames.
    let mut frame_guard = FrameReservation::new();
    let _ = frame_guard.reserve(kexec_memory_metadata.iter().map(|r| r.phys_frame_range))?;
    for kexec_mem_range in &kexec_memory_metadata {
        protect_physical_memory_range(kexec_mem_range.phys_frame_range, MemAttr::MEM_ATTR_READ)?;
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
        let mut segment_ranges = Vec::new();
        for i in 0..usize::try_from(kimage.nr_segments).unwrap_or(0) {
            let va = kimage.segment[i].buf;
            let pa = kimage.segment[i].mem;
            if let Some(epa) = pa.checked_add(kimage.segment[i].memsz) {
                segment_ranges.push(KexecMemoryRange::new(va, pa, epa)?);
            } else {
                return Err(VsmError::KexecSegmentRangeInvalid);
            }
        }
        let reservation_statuses =
            frame_guard.reserve(segment_ranges.iter().map(|r| r.phys_frame_range))?;
        for (segment_range, status) in segment_ranges.into_iter().zip(reservation_statuses) {
            if status == ReservationStatus::New {
                protect_physical_memory_range(
                    segment_range.phys_frame_range,
                    MemAttr::MEM_ATTR_READ,
                )?;
                kexec_memory_metadata.insert_memory_range(segment_range);
            }
        }
    }

    // verify the signature of the kexec blob
    if let Err(result) = verify_kernel_pe_signature(&kexec_kernel_blob[..], certs) {
        return Err(VsmError::SignatureVerificationFailed(result));
    }

    frame_guard.commit();
    // register the protected kexec memory ranges to support possible invalidation in the future
    kexec_metadata_ref.register_memory(kexec_memory_metadata);

    Ok(0)
}

/// VSM function for patching kernel or module text. VTL0 kernel calls this function to patch certain kernel or module
/// text region (which it does not have a permission to modify). It passes `HekiPatch` structure which can be stored
/// within one or across two likely non-contiguous physical pages.
pub fn mshv_vsm_patch_text(patch_pa_0: u64, patch_pa_1: u64) -> Result<i64, VsmError> {
    let heki_patch = copy_heki_patch_from_vtl0(patch_pa_0, patch_pa_1)?;
    debug_serial_println!("VSM: {:?}", heki_patch);

    let precomputed_patch = crate::platform_low()
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
            (patch_pa_0.align_up(Size4KiB::SIZE) - patch_pa_0).trunc(),
            core::mem::size_of::<HekiPatch>(),
        )
    };

    if (bytes_in_first_page < core::mem::size_of::<HekiPatch>() && patch_pa_1.is_null())
        || (bytes_in_first_page == core::mem::size_of::<HekiPatch>() && !patch_pa_1.is_null())
    {
        return Err(VsmError::InvalidInputAddress);
    }

    let heki_patch = if patch_pa_1.is_null()
        || (patch_pa_0.align_up(Size4KiB::SIZE) == patch_pa_1.align_down(Size4KiB::SIZE))
    {
        let ptr = Vtl0PhysConstPtr::<HekiPatch, PAGE_SIZE>::with_usize(patch_pa_0.as_u64().trunc())
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.read_at_offset(0)
            .map(|boxed| *boxed)
            .map_err(|_| VsmError::Vtl0CopyFailed)
    } else {
        let mut heki_patch = HekiPatch::new_zeroed();
        let heki_patch_bytes = heki_patch.as_mut_bytes();
        let pages = [
            PhysPageAddr::<PAGE_SIZE>::new(patch_pa_0.align_down(Size4KiB::SIZE).as_u64().trunc())
                .ok_or(VsmError::Vtl0CopyFailed)?,
            PhysPageAddr::<PAGE_SIZE>::new(patch_pa_1.as_u64().trunc())
                .ok_or(VsmError::Vtl0CopyFailed)?,
        ];
        let ptr = Vtl0PhysConstPtr::<u8, PAGE_SIZE>::new(
            &pages,
            (patch_pa_0 - patch_pa_0.align_down(Size4KiB::SIZE)).trunc(),
        )
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.read_slice_at_offset(0, heki_patch_bytes)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        Ok(heki_patch)
    }?;

    if heki_patch.is_valid() {
        Ok(heki_patch)
    } else {
        Err(VsmError::InvalidInputAddress)
    }
}

/// Apply a `HekiPatch` to VTL0 text after the caller has validated it against VTL1's precomputed
/// HEKI patch data.
fn apply_vtl0_text_patch(heki_patch: HekiPatch) -> Result<(), VsmError> {
    // `HekiPatch::is_valid` already validated both physical addresses.
    let heki_patch_pa_0 = PhysAddr::new(heki_patch.pa[0]);
    let heki_patch_pa_1 = PhysAddr::new(heki_patch.pa[1]);

    let patch = &heki_patch.code[..usize::from(heki_patch.size)];
    if patch.is_empty() {
        return Ok(());
    }

    if heki_patch_pa_1.is_null()
        || (heki_patch_pa_0.align_up(Size4KiB::SIZE) == heki_patch_pa_1.align_down(Size4KiB::SIZE))
    {
        // Single contiguous span: either fits in one page (pa_1 null) or pa_1 is the
        // adjacent next page. `HekiPatch::is_valid` enforces this; assert in debug builds.
        debug_assert!(
            !heki_patch_pa_1.is_null()
                || heki_patch_pa_0.as_u64() + patch.len() as u64
                    <= heki_patch_pa_0.align_down(Size4KiB::SIZE).as_u64() + Size4KiB::SIZE,
            "patch crosses page boundary but pa_1 is null"
        );
        // The patch was validated against VTL1's precomputed HEKI patch data.
        let ptr = PrivilegedVtl0PhysMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
            heki_patch_pa_0.as_u64().trunc(),
            patch.len(),
        )
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.write_slice_at_offset(0, patch)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
    } else {
        let pages = [
            PhysPageAddr::<PAGE_SIZE>::new(
                heki_patch_pa_0.align_down(Size4KiB::SIZE).as_u64().trunc(),
            )
            .ok_or(VsmError::Vtl0CopyFailed)?,
            PhysPageAddr::<PAGE_SIZE>::new(heki_patch_pa_1.as_u64().trunc())
                .ok_or(VsmError::Vtl0CopyFailed)?,
        ];
        // The patch was validated against VTL1's precomputed HEKI patch data.
        let ptr = PrivilegedVtl0PhysMutPtr::<u8, PAGE_SIZE>::new(
            &pages,
            (heki_patch_pa_0 - heki_patch_pa_0.align_down(Size4KiB::SIZE)).trunc(),
        )
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.write_slice_at_offset(0, patch)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
    }
    Ok(())
}

pub(crate) fn mshv_vsm_allocate_ringbuffer_memory(
    phys_addr: u64,
    size: usize,
) -> Result<i64, VsmError> {
    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
        return Err(VsmError::OperationAfterEndOfBoot("ring buffer allocation"));
    }

    let end = phys_addr
        .checked_add(size as u64)
        .ok_or(VsmError::IntegerOverflow)
        .and_then(|end| PhysAddr::try_new(end).map_err(|_| VsmError::InvalidPhysicalAddress))?;
    let phys_addr = PhysAddr::new(phys_addr);
    protect_physical_memory_range(
        PhysFrame::range(
            PhysFrame::from_start_address(phys_addr)
                .map_err(|_| VsmError::AddressNotPageAligned)?,
            PhysFrame::from_start_address(end).map_err(|_| VsmError::AddressNotPageAligned)?,
        ),
        MemAttr::MEM_ATTR_READ,
    )?;
    set_ringbuffer(phys_addr, size);
    debug_serial_println!("VSM: Ring buffer allocated");
    Ok(0)
}

/// This function sets the platform root key by copying key data from VTL0.
///
/// - `key_pa`: Physical address (VTL0) that the platform root key is stored at.
///
/// This function assumes that the caller stores key bytes in a single or
/// contiguous physical memory page(s), whose length is equal to `PRK_LEN`.
pub(crate) fn mshv_vsm_set_platform_root_key(key_pa: u64) -> Result<i64, VsmError> {
    if crate::platform_low().vtl0_kernel_info.check_end_of_boot() {
        return Err(VsmError::OperationAfterEndOfBoot("set platform root key"));
    }

    let key_pa = PhysAddr::try_new(key_pa).map_err(|_| VsmError::InvalidPhysicalAddress)?;

    let mut keybuf = Zeroizing::new([0u8; PRK_LEN]);
    let key_ptr =
        Vtl0PhysConstPtr::<u8, PAGE_SIZE>::with_contiguous_pages(key_pa.as_u64().trunc(), PRK_LEN)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
    key_ptr
        .read_slice_at_offset(0, &mut *keybuf)
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
    set_platform_root_key(&*keybuf);
    Ok(0)
}

/// This function copies `HekiPage` structures from VTL0 and returns a vector of them.
/// `pa` and `nranges` specify the physical address range containing one or more than one `HekiPage` structures.
fn copy_heki_pages_from_vtl0(pa: u64, nranges: u64) -> Option<Vec<HekiPage>> {
    let mut heki_pages = Vec::with_capacity(nranges.trunc());
    let mut visited_pages = HashSet::new();
    let mut range: u64 = 0;

    let mut cur_pa = PhysAddr::try_new(pa).ok()?;
    while range < nranges {
        if visited_pages.contains(&cur_pa.as_u64()) {
            return None;
        }
        let ptr =
            Vtl0PhysConstPtr::<HekiPage, PAGE_SIZE>::with_usize(cur_pa.as_u64().trunc()).ok()?;
        let heki_page = ptr.read_at_offset(0).ok()?;
        if !heki_page.is_valid() {
            return None;
        }
        visited_pages.insert(cur_pa.as_u64());

        range = range.checked_add(heki_page.nranges)?;
        if range < nranges && (heki_page.next_pa == 0 || visited_pages.contains(&heki_page.next_pa))
        {
            return None;
        }
        // `HekiPage::is_valid` already validated `next_pa`.
        cur_pa = PhysAddr::new(heki_page.next_pa);
        heki_pages.push(*heki_page);
    }

    Some(heki_pages)
}

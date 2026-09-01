// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The VTL call entry points — one [`Heki`] method per HEKI function the runner
//! dispatches — and the helpers they are built from.

#[cfg(debug_assertions)]
use crate::mem_integrity::parse_modinfo;
use crate::mem_integrity::{
    validate_kernel_module_against_elf, validate_text_patch, verify_kernel_module_signature,
    verify_kernel_pe_signature,
};
use crate::{
    Heki, KexecMemoryMetadata, KexecMemoryRange, MemoryContainer, ModuleMemory,
    ModuleMemoryMetadata,
};

use alloc::vec::Vec;
use hashbrown::HashSet;
use litebox::utils::TruncateExt;
use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{
    HekiKdataType, HekiKernelInfo, HekiKexecType, HekiPage, HekiPatch, KEXEC_SEGMENT_MAX, Kimage,
    MemAttr, ModMemType, PAGE_SIZE, ReservationStatus, VsmError, Vtl0Gate, Vtl0PrivilegedWrite,
    mod_mem_type_to_mem_attr,
};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB, frame::PhysFrameRange},
};
use x509_cert::{Certificate, der::Decode};
use zerocopy::{FromBytes, FromZeros, IntoBytes};

// For now, we do not validate large kernel modules due to the VTL1's memory size limitation.
const MODULE_VALIDATION_MAX_SIZE: usize = 64 * 1024 * 1024;

/// HEKI handlers for individual VTL call entry points.
impl<P: Vtl0Gate> Heki<P> {
    /// HEKI handler for locking VTL0's control registers
    pub fn lock_regs(&self) -> Result<i64, VsmError> {
        self.gate.lock_control_registers()?;
        Ok(0)
    }

    /// HEKI handler for protecting certain memory ranges (e.g., kernel text, data, heap).
    /// `pa` and `nranges` specify a memory area containing the information about the memory ranges to protect.
    pub fn protect_memory(&self, pa: u64, nranges: u64) -> Result<i64, VsmError> {
        if PhysAddr::try_new(pa)
            .ok()
            .as_ref()
            .is_none_or(|p| !p.is_aligned(Size4KiB::SIZE))
            || nranges == 0
        {
            return Err(VsmError::InvalidInputAddress);
        }

        if self.gate.end_of_boot_reached() {
            return Err(VsmError::OperationAfterEndOfBoot(
                "kernel memory protection",
            ));
        }

        let heki_pages = copy_heki_pages_from_vtl0(&self.gate, pa, nranges)
            .ok_or(VsmError::HekiPagesCopyFailed)?;

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

                let va = heki_range.va;
                log::debug!(
                    "HEKI: Protect memory: va {:#x} pa {:#x} epa {:#x} {:?} (size: {})",
                    va,
                    pa,
                    epa,
                    mem_attr,
                    epa - pa
                );

                if pa == epa {
                    continue;
                }

                self.gate.protect_frames(
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

    /// HEKI handler for loading kernel data (e.g., certificates, blocklist, kernel symbols) into VTL1.
    /// `pa` and `nranges` specify memory areas containing the information about the memory ranges to load.
    pub fn load_kdata(&self, pa: u64, nranges: u64) -> Result<i64, VsmError> {
        if PhysAddr::try_new(pa)
            .ok()
            .as_ref()
            .is_none_or(|p| !p.is_aligned(Size4KiB::SIZE))
            || nranges == 0
        {
            return Err(VsmError::InvalidInputAddress);
        }

        if self.gate.end_of_boot_reached() {
            return Err(VsmError::OperationAfterEndOfBoot("loading kernel data"));
        }

        let mut system_certs_mem = MemoryContainer::new();
        let mut kexec_trampoline_metadata = KexecMemoryMetadata::new();
        let mut kexec_trampoline_insert_failed = false;
        let mut patch_info_mem = MemoryContainer::new();
        let mut kinfo_mem = MemoryContainer::new();
        let mut kdata_mem = MemoryContainer::new();

        let heki_pages = copy_heki_pages_from_vtl0(&self.gate, pa, nranges)
            .ok_or(VsmError::HekiPagesCopyFailed)?;

        for heki_page in &heki_pages {
            for heki_range in heki_page {
                log::debug!("HEKI: Load kernel data {heki_range:?}");
                match heki_range.heki_kdata_type() {
                    HekiKdataType::SystemCerts => system_certs_mem
                        .extend_range(heki_range)
                        .map_err(|_| VsmError::InvalidInputAddress)?,
                    HekiKdataType::KexecTrampoline => {
                        if let Err(e) = kexec_trampoline_metadata.insert_heki_range(heki_range) {
                            log::debug!(
                                "HEKI: KexecTrampoline insert_heki_range failed ({e:?}); skipping kexec trampoline protection"
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
                        log::debug!("HEKI: Unsupported kernel data not loaded {heki_range:?}");
                    }
                }
            }
        }

        system_certs_mem
            .write_bytes_from_heki_range(&self.gate)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        patch_info_mem
            .write_bytes_from_heki_range(&self.gate)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        kinfo_mem
            .write_bytes_from_heki_range(&self.gate)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        kdata_mem
            .write_bytes_from_heki_range(&self.gate)
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
        self.set_system_certificates(certs.clone());
        log::debug!("HEKI: Loaded {} system certificate(s)", certs.len());

        // ToDo: Remove kexec_trampoline_insert_failed and protect kexec_trampoline_metadata
        // once we have a better solution to handle the non-page-aligned kexec trampoline metadata.
        // The current solution is to skip protecting kexec trampoline metadata if its insert_heki_range
        // fails, letting kdata load proceed so that heki is not broken.
        if !kexec_trampoline_insert_failed {
            for kexec_trampoline_range in &kexec_trampoline_metadata {
                self.gate.protect_frames(
                    kexec_trampoline_range.phys_frame_range,
                    MemAttr::MEM_ATTR_READ,
                )?;
            }
        }

        // pre-computed patch data for the kernel text
        if !patch_info_mem.is_empty() {
            let patch_info_buf = &patch_info_mem[..];
            self.precomputed_patches
                .insert_patch_data_from_bytes(patch_info_buf, None)
                .map_err(|error| match error {
                    crate::PatchDataMapError::AllocationFailed => VsmError::AllocationFailed,
                    _ => VsmError::Vtl0CopyFailed,
                })?;
        }

        if kinfo_mem.is_empty() || kdata_mem.is_empty() {
            return Err(VsmError::KernelSymbolTableNotFound);
        }

        let kinfo_buf = &kinfo_mem[..];
        let kdata_buf = &kdata_mem[..];
        let kinfo = HekiKernelInfo::from_bytes(kinfo_buf)?;

        self.gpl_symbols.build_from_container(
            VirtAddr::from_ptr(kinfo.ksymtab_gpl_start),
            VirtAddr::from_ptr(kinfo.ksymtab_gpl_end),
            &kdata_mem,
            kdata_buf,
        )?;

        self.symbols.build_from_container(
            VirtAddr::from_ptr(kinfo.ksymtab_start),
            VirtAddr::from_ptr(kinfo.ksymtab_end),
            &kdata_mem,
            kdata_buf,
        )?;

        Ok(0)
        // TODO: create blocklist keys
        // TODO: save blocklist hashes
    }

    /// HEKI handler for validating a guest kernel module and applying specified protection to its memory ranges after validation.
    /// `pa` and `nranges` specify a memory area containing the information about the kernel module to validate or protect.
    /// `flags` controls the validation process (unused for now).
    /// This function returns a unique `token` to VTL0, which is used to identify the module in subsequent calls.
    pub fn validate_guest_module(
        &self,
        pa: u64,
        nranges: u64,
        _flags: u64,
    ) -> Result<i64, VsmError> {
        if PhysAddr::try_new(pa)
            .ok()
            .as_ref()
            .is_none_or(|p| !p.is_aligned(Size4KiB::SIZE))
            || nranges == 0
        {
            return Err(VsmError::InvalidInputAddress);
        }

        log::debug!("HEKI: Validate kernel module: pa {pa:#x} nranges {nranges}");

        let certs = self
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

        let heki_pages = copy_heki_pages_from_vtl0(&self.gate, pa, nranges)
            .ok_or(VsmError::HekiPagesCopyFailed)?;

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
        // The reserve + freeze + validate + promote + patch-commit sequence runs transactionally: the
        // gate reserves `initial`, commits on `Ok`, and rolls back (unprotecting every newly
        // reserved range) on `Err`.
        let initial: Vec<PhysFrameRange<Size4KiB>> = module_memory_metadata
            .iter()
            .map(|r| r.phys_frame_range)
            .collect();
        self.gate
            .protect_frames_transactionally(&initial, &mut |txn| {
                // Freeze frames that require immutable copy/validation to avoid TOCTOU.
                for mod_mem_range in &module_memory_metadata {
                    if !mod_mem_type_to_mem_attr(mod_mem_range.mod_mem_type)
                        .contains(MemAttr::MEM_ATTR_WRITE)
                    {
                        txn.protect(mod_mem_range.phys_frame_range, MemAttr::MEM_ATTR_READ)?;
                    }
                }

                module_as_elf
                    .write_bytes_from_heki_range(&self.gate)
                    .map_err(|_| VsmError::Vtl0CopyFailed)?;
                patch_info_for_module
                    .write_bytes_from_heki_range(&self.gate)
                    .map_err(|_| VsmError::Vtl0CopyFailed)?;
                module_in_memory
                    .write_bytes_from_heki_range(&self.gate)
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
                        txn.protect(
                            mod_mem_range.phys_frame_range,
                            mod_mem_type_to_mem_attr(mod_mem_range.mod_mem_type),
                        )?;
                    }
                }

                // Commit the module's pre-computed patch data (transactional).
                if !patch_info_for_module.is_empty() {
                    let patch_info_buf = &patch_info_for_module[..];
                    self.precomputed_patches
                        .insert_patch_data_from_bytes(
                            patch_info_buf,
                            Some(&mut module_memory_metadata),
                        )
                        .map_err(|error| match error {
                            crate::PatchDataMapError::AllocationFailed => {
                                VsmError::AllocationFailed
                            }
                            _ => VsmError::Vtl0CopyFailed,
                        })?;
                }
                Ok(())
            })?;

        // Fully validated and committed: register the module.
        // register the module memory in the global map and obtain a unique token for it
        let token = self
            .module_memory_metadata
            .register_module_memory_metadata(module_memory_metadata)?;
        Ok(token)
    }

    /// HEKI handler for supporting the initialization of a guest kernel module including
    /// freeing the memory ranges that were used only for initialization and
    /// write-protecting the memory ranges that should be read-only after initialization.
    /// `token` is the unique identifier for the module.
    pub fn free_guest_module_init(&self, token: i64) -> Result<i64, VsmError> {
        log::debug!("HEKI: Free kernel module's init (token: {token})");

        if !self.module_memory_metadata.contains_key(token) {
            return Err(VsmError::ModuleTokenInvalid);
        }

        let mut result: Result<(), VsmError> = Ok(());
        if let Some(entry) = self.module_memory_metadata.iter_entry(token) {
            for mod_mem_range in entry.iter_mem_ranges() {
                let range_result = match mod_mem_range.mod_mem_type {
                    ModMemType::InitText | ModMemType::InitData | ModMemType::InitRoData => {
                        self.gate.unprotect_frames(mod_mem_range.phys_frame_range)
                    }
                    ModMemType::RoAfterInit => {
                        // make this memory range read-only after initialization
                        self.gate
                            .protect_frames(mod_mem_range.phys_frame_range, MemAttr::MEM_ATTR_READ)
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
        let freed_init_patch_targets = self.module_memory_metadata.remove_init_ranges(token);
        // Remove the precomputed patches targeting those freed init frames so a stale init patch cannot
        // later be applied to recycled frames (no patch-after-free).
        if !freed_init_patch_targets.is_empty() {
            self.precomputed_patches
                .remove_patch_data(&freed_init_patch_targets);
        }

        result.map(|()| 0)
    }

    /// HEKI handler for supporting the unloading of a guest kernel module.
    /// `token` is the unique identifier for the module.
    pub fn unload_guest_module(&self, token: i64) -> Result<i64, VsmError> {
        log::debug!("HEKI: Unload kernel module (token: {token})");

        if !self.module_memory_metadata.contains_key(token) {
            return Err(VsmError::ModuleTokenInvalid);
        }

        if let Some(entry) = self.module_memory_metadata.iter_entry(token) {
            for mod_mem_range in entry.iter_mem_ranges() {
                self.gate.unprotect_frames(mod_mem_range.phys_frame_range)?;
            }
        }

        if let Some(patch_targets) = self.module_memory_metadata.get_patch_targets(token) {
            self.precomputed_patches.remove_patch_data(&patch_targets);
        }

        self.module_memory_metadata.remove(token);
        Ok(0)
    }

    /// HEKI handler for copying secondary key
    #[allow(clippy::unnecessary_wraps)]
    pub fn copy_secondary_key(&self, _pa: u64, _nranges: u64) -> Result<i64, VsmError> {
        log::debug!("HEKI: Copy secondary key");
        // TODO: copy secondary key
        Ok(0)
    }

    /// HEKI handler for write protecting the memory regions of a verified kernel image for kexec.
    /// This function protects the kexec kernel blob (PE) only if it has a valid signature.
    /// Note: this function does not make kexec kernel pages executable, which should be done by
    /// another VTL1 method that can intercept the kexec/reset signal.
    pub fn kexec_validate(&self, pa: u64, nranges: u64, crash: u64) -> Result<i64, VsmError> {
        log::debug!("HEKI: Validate kexec pa {pa:#x} nranges {nranges} crash {crash}");

        let certs = self
            .get_system_certificates()
            .ok_or(VsmError::SystemCertificatesNotLoaded)?;

        let is_crash = crash != 0;
        let kexec_metadata_ref = if is_crash {
            &self.crash_kexec_metadata
        } else {
            &self.kexec_metadata
        };

        // invalidate (i.e., remove protection and clear) the kexec memory ranges which were loaded in the past
        for old_kexec_mem_range in kexec_metadata_ref.iter_guarded().iter_mem_ranges() {
            self.gate
                .unprotect_frames(old_kexec_mem_range.phys_frame_range)?;
        }
        kexec_metadata_ref.clear_memory();

        if pa == 0 {
            // invalidation only
            return Ok(0);
        }

        let mut kexec_memory_metadata = KexecMemoryMetadata::new();
        let mut kexec_image = MemoryContainer::new();
        let mut kexec_kernel_blob = MemoryContainer::new();

        let heki_pages = copy_heki_pages_from_vtl0(&self.gate, pa, nranges)
            .ok_or(VsmError::HekiPagesCopyFailed)?;

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

                    HekiKexecType::KexecPages => {
                        kexec_memory_metadata.insert_heki_range(heki_range)?;
                    }
                    HekiKexecType::Unknown => {
                        return Err(VsmError::KexecTypeInvalid);
                    }
                }
            }
        }

        // Reserve then freeze the protected kexec frames, rejecting overlap with VTL1 or other
        // protected frames. The reserve/protect (incl. the mid-flow segment reserve for crash kexec),
        // blob copy, and signature check run transactionally: commit on `Ok`, rollback on `Err`.
        let initial: Vec<PhysFrameRange<Size4KiB>> = kexec_memory_metadata
            .iter()
            .map(|r| r.phys_frame_range)
            .collect();
        self.gate
            .protect_frames_transactionally(&initial, &mut |txn| {
                for kexec_mem_range in &kexec_memory_metadata {
                    txn.protect(kexec_mem_range.phys_frame_range, MemAttr::MEM_ATTR_READ)?;
                }

                kexec_image
                    .write_bytes_from_heki_range(&self.gate)
                    .map_err(|_| VsmError::Vtl0CopyFailed)?;
                kexec_kernel_blob
                    .write_bytes_from_heki_range(&self.gate)
                    .map_err(|_| VsmError::Vtl0CopyFailed)?;

                // If this function is called for crash kexec, we protect its kimage segments as well.
                if is_crash {
                    let kimage =
                        Kimage::read_from_bytes(&kexec_image[..core::mem::size_of::<Kimage>()])
                            .map_err(|_| VsmError::KexecImageSegmentsInvalid)?;
                    if kimage.nr_segments > KEXEC_SEGMENT_MAX as u64 {
                        return Err(VsmError::KexecImageSegmentsInvalid);
                    }
                    let mut segment_ranges = Vec::new();
                    for i in 0..usize::try_from(kimage.nr_segments).unwrap_or(0) {
                        VirtAddr::try_new(kimage.segment[i].buf)
                            .map_err(|_| VsmError::InvalidVirtualAddress)?;
                        let pa = kimage.segment[i].mem;
                        if let Some(epa) = pa.checked_add(kimage.segment[i].memsz) {
                            segment_ranges.push(KexecMemoryRange::new(pa, epa)?);
                        } else {
                            return Err(VsmError::KexecSegmentRangeInvalid);
                        }
                    }
                    let segment_frame_ranges: Vec<PhysFrameRange<Size4KiB>> =
                        segment_ranges.iter().map(|r| r.phys_frame_range).collect();
                    let reservation_statuses = txn.reserve(&segment_frame_ranges)?;
                    for (segment_range, status) in
                        segment_ranges.into_iter().zip(reservation_statuses)
                    {
                        if status == ReservationStatus::New {
                            txn.protect(segment_range.phys_frame_range, MemAttr::MEM_ATTR_READ)?;
                            kexec_memory_metadata.insert_memory_range(segment_range);
                        }
                    }
                }

                // verify the signature of the kexec blob
                if let Err(result) = verify_kernel_pe_signature(&kexec_kernel_blob[..], certs) {
                    return Err(VsmError::SignatureVerificationFailed(result));
                }
                Ok(())
            })?;

        // register the protected kexec memory ranges to support possible invalidation in the future
        kexec_metadata_ref.register_memory(kexec_memory_metadata);

        Ok(0)
    }

    /// HEKI handler for patching kernel or module text. VTL0 kernel calls this function to patch certain kernel or module
    /// text region (which it does not have a permission to modify). It passes `HekiPatch` structure which can be stored
    /// within one or across two likely non-contiguous physical pages.
    pub fn patch_text<W: Vtl0PrivilegedWrite>(
        &self,
        writer: &W,
        patch_pa_0: u64,
        patch_pa_1: u64,
    ) -> Result<i64, VsmError> {
        let heki_patch = copy_heki_patch_from_vtl0(&self.gate, patch_pa_0, patch_pa_1)?;
        log::debug!("HEKI: {heki_patch:?}");

        let precomputed_patch = self
            .find_precomputed_patch(&heki_patch)
            .ok_or(VsmError::PrecomputedPatchNotFound)?;

        if let Some(validated) = ValidatedTextPatch::prepare(&heki_patch, &precomputed_patch)? {
            validated.apply(writer)?;
        }
        Ok(0)
    }

    pub fn allocate_ringbuffer_memory(&self, phys_addr: u64, size: u64) -> Result<i64, VsmError> {
        if self.gate.end_of_boot_reached() {
            return Err(VsmError::OperationAfterEndOfBoot("ring buffer allocation"));
        }

        let end = phys_addr
            .checked_add(size)
            .ok_or(VsmError::IntegerOverflow)
            .and_then(|end| PhysAddr::try_new(end).map_err(|_| VsmError::InvalidPhysicalAddress))?;
        let phys_addr = PhysAddr::new(phys_addr);
        let frame_range = PhysFrame::range(
            PhysFrame::from_start_address(phys_addr)
                .map_err(|_| VsmError::AddressNotPageAligned)?,
            PhysFrame::from_start_address(end).map_err(|_| VsmError::AddressNotPageAligned)?,
        );
        self.gate
            .protect_frames(frame_range, MemAttr::MEM_ATTR_READ)?;
        self.gate.install_ringbuffer(phys_addr.as_u64(), size);
        log::debug!("HEKI: Ring buffer allocated");
        Ok(0)
    }
} // impl Heki

/// Copies patch data in a `HekiPatch` structure from VTL0 to VTL1. The patch
/// data can live within one physical page or across two likely
/// non-contiguous physical pages.
fn copy_heki_patch_from_vtl0<P: Vtl0Gate>(
    gate: &P,
    patch_pa_0: u64,
    patch_pa_1: u64,
) -> Result<HekiPatch, VsmError> {
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
        gate.read_vtl0_val::<HekiPatch>(patch_pa_0.as_u64())
    } else {
        let mut heki_patch = HekiPatch::new_zeroed();
        let heki_patch_bytes = heki_patch.as_mut_bytes();
        let pages = [
            PhysPageAddr::<PAGE_SIZE>::new(patch_pa_0.align_down(Size4KiB::SIZE).as_u64().trunc())
                .ok_or(VsmError::Vtl0CopyFailed)?,
            PhysPageAddr::<PAGE_SIZE>::new(patch_pa_1.as_u64().trunc())
                .ok_or(VsmError::Vtl0CopyFailed)?,
        ];
        gate.read_vtl0_pages(
            &pages,
            (patch_pa_0 - patch_pa_0.align_down(Size4KiB::SIZE)).trunc(),
            heki_patch_bytes,
        )
        .map_err(|_| VsmError::Vtl0CopyFailed)?;
        Ok(heki_patch)
    }?;

    if heki_patch.is_valid() {
        Ok(heki_patch)
    } else {
        Err(VsmError::InvalidInputAddress)
    }
}
/// Copies `HekiPage` structures from VTL0 and returns a vector of them. `pa` and
/// `nranges` specify the physical address range holding one or more `HekiPage`s.
fn copy_heki_pages_from_vtl0<P: Vtl0Gate>(
    gate: &P,
    pa: u64,
    nranges: u64,
) -> Option<Vec<HekiPage>> {
    let mut heki_pages = Vec::new();
    heki_pages.try_reserve(nranges.trunc()).ok()?;
    let mut visited_pages = HashSet::new();
    visited_pages.try_reserve(nranges.trunc()).ok()?;
    let mut range: u64 = 0;

    let mut cur_pa = PhysAddr::try_new(pa).ok()?;
    while range < nranges {
        if visited_pages.contains(&cur_pa.as_u64()) {
            return None;
        }
        let heki_page = gate.read_vtl0_val::<HekiPage>(cur_pa.as_u64()).ok()?;
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
        heki_pages.push(heki_page);
    }

    Some(heki_pages)
}

/// Parse a concatenated run of DER-encoded X.509 certificates.
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

/// A text patch that matched VTL1's precomputed patch data, bundled with the
/// VTL0 write parameters it authorizes.
///
/// Its fields are private and it is constructible only via `prepare`, which
/// performs the `validate_text_patch` check, so this answers *what* may be
/// written. *Whether* the caller may bypass protection masks at all is a
/// separate question, answered by holding a [`Vtl0PrivilegedWrite`].
pub(crate) struct ValidatedTextPatch<'a> {
    pages: [PhysPageAddr<PAGE_SIZE>; 2],
    page_count: usize,
    offset: usize,
    bytes: &'a [u8],
}

impl<'a> ValidatedTextPatch<'a> {
    /// Validate `patch` against `precomputed`; on success, compute the target
    /// page(s), in-page offset, and bytes. Returns `Err(TextPatchSuspicious)` if
    /// validation fails, or `Ok(None)` if the patch is empty (nothing to write).
    fn prepare(patch: &'a HekiPatch, precomputed: &HekiPatch) -> Result<Option<Self>, VsmError> {
        if !validate_text_patch(patch, precomputed) {
            return Err(VsmError::TextPatchSuspicious);
        }
        let bytes = &patch.code[..usize::from(patch.size)];
        if bytes.is_empty() {
            return Ok(None);
        }

        let pa_0 = PhysAddr::new(patch.pa[0]);
        let pa_0_page = pa_0.align_down(Size4KiB::SIZE);
        let offset = (pa_0 - pa_0_page).trunc();
        let page0 = PhysPageAddr::<PAGE_SIZE>::new(pa_0_page.as_u64().trunc())
            .ok_or(VsmError::Vtl0CopyFailed)?;

        // Page count comes from the write extent, not `pa[1]`, so prepare stays
        // self-contained instead of depending on the `HekiPatch::is_valid`
        // coupling (`pa[1].is_null()` iff the patch fits one page). A straddling
        // write's second page is `pa[1]`, which step-2 validation pins.
        let (target_pages, page_count) = if offset + bytes.len() > PAGE_SIZE {
            let pa_1_page = PhysAddr::new(patch.pa[1]).align_down(Size4KiB::SIZE);
            let page1 = PhysPageAddr::<PAGE_SIZE>::new(pa_1_page.as_u64().trunc())
                .ok_or(VsmError::Vtl0CopyFailed)?;
            ([page0, page1], 2)
        } else {
            ([page0, page0], 1)
        };

        Ok(Some(Self {
            pages: target_pages,
            page_count,
            offset,
            bytes,
        }))
    }

    /// Perform the write this patch authorizes, consuming the proof.
    ///
    /// The write parameters are never handed out separately, so a validated
    /// page list cannot be paired with some other patch's offset or bytes.
    fn apply(self, writer: &impl Vtl0PrivilegedWrite) -> Result<(), VsmError> {
        writer.write_vtl0_pages(&self.pages[..self.page_count], self.offset, self.bytes)
    }
}

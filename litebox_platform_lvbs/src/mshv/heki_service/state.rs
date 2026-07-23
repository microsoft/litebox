// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pure data types for the VSM/HEKI service.
//!
//! These maintain the VTL0 kernel information copied into VTL1 (module/kexec
//! memory metadata, precomputed patches, symbol tables, system certificates).
//! Memory-touching helpers reach VTL0 through the [`Vsm`] they are passed.

use crate::mshv::heki_service::vsm::Vsm;
use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
use core::ffi::{CStr, c_char};
use core::{
    mem,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
};
use hashbrown::HashMap;
use litebox::utils::TruncateExt;
use litebox_common_lvbs::{
    HekiKernelSymbol, HekiPatch, HekiPatchInfo, HekiRange, ModMemType, VsmError, Vtl0Mediation,
};
use thiserror::Error;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB, frame::PhysFrameRange},
};
use x509_cert::Certificate;

/// Data structure for maintaining the kernel information in VTL0.
/// It should be prepared by copying kernel data from VTL0 to VTL1 instead of
/// relying on shared memory access to VTL0 which suffers from security issues.
pub struct HekiState {
    pub(crate) module_memory_metadata: ModuleMemoryMetadataMap,
    boot_done: AtomicBool,
    system_certs: once_cell::race::OnceBox<Box<[Certificate]>>,
    pub(crate) kexec_metadata: KexecMemoryMetadataWrapper,
    pub(crate) crash_kexec_metadata: KexecMemoryMetadataWrapper,
    pub(crate) precomputed_patches: PatchDataMap,
    pub(crate) symbols: SymbolTable,
    pub(crate) gpl_symbols: SymbolTable,
    // TODO: revocation cert, blocklist, etc.
}

impl Default for HekiState {
    fn default() -> Self {
        Self::new()
    }
}

impl HekiState {
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

    pub(crate) fn set_system_certificates(&self, certs: Vec<Certificate>) {
        let boxed_slice = certs.into_boxed_slice();
        let _ = self.system_certs.set(boxed_slice.into());
    }

    pub(crate) fn get_system_certificates(&self) -> Option<&[Certificate]> {
        self.system_certs.get().map(|b| &**b)
    }

    /// This function finds the precomputed patch data corresponding to the input patch data.
    ///
    /// Each step of `text_poke_bp_batch` only exposes a portion of the target's address range,
    /// so we look up in the precomputed map by two keys derived from `patch_data.pa[0]`:
    /// - `pa[0]` matches step 1 or 3 (target's first byte) and, for a precomputed patch that
    ///   straddles at offset 1, step 2.
    /// - `pa[0] - 1` matches step 2 where `patch.pa[0] == precomputed.pa[0] + 1`.
    ///
    /// No legitimate step requires looking up by `patch.pa[1]`.
    pub fn find_precomputed_patch(&self, patch_data: &HekiPatch) -> Option<HekiPatch> {
        // `HekiPatch::is_valid` already validated both physical addresses.
        let patch_pa_0 = PhysAddr::new(patch_data.pa[0]);
        let patch_pa_0_prev = patch_data.pa[0].checked_sub(1).map(PhysAddr::new);

        self.precomputed_patches
            .get(patch_pa_0)
            .or_else(|| patch_pa_0_prev.and_then(|pa| self.precomputed_patches.get(pa)))
    }
}

/// Data structure for maintaining the memory ranges of each VTL0 kernel module and their types
pub(crate) struct ModuleMemoryMetadataMap {
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
        // `HekiRange::is_valid` already validated these addresses.
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(ModuleMemoryRange::new_checked(
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

impl ModuleMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, ModuleMemoryRange> {
        self.ranges.iter()
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
    /// Create a memory range from values which are already validated.
    pub(crate) fn new_checked(
        virt_addr: u64,
        phys_start: u64,
        phys_end: u64,
        mod_mem_type: ModMemType,
    ) -> Self {
        let phys_start = PhysAddr::new(phys_start);
        let phys_end = PhysAddr::new(phys_end);
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(phys_start),
                PhysFrame::containing_address(phys_end),
            ),
            mod_mem_type,
        }
    }

    pub fn new(
        virt_addr: u64,
        phys_start: u64,
        phys_end: u64,
        mod_mem_type: ModMemType,
    ) -> Result<Self, VsmError> {
        Ok(Self {
            virt_addr: VirtAddr::try_new(virt_addr).map_err(|_| VsmError::InvalidVirtualAddress)?,
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(
                    PhysAddr::try_new(phys_start).map_err(|_| VsmError::InvalidPhysicalAddress)?,
                ),
                PhysFrame::containing_address(
                    PhysAddr::try_new(phys_end).map_err(|_| VsmError::InvalidPhysicalAddress)?,
                ),
            ),
            mod_mem_type,
        })
    }
}

impl Default for ModuleMemoryRange {
    fn default() -> Self {
        Self {
            virt_addr: VirtAddr::zero(),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::zero()),
                PhysFrame::containing_address(PhysAddr::zero()),
            ),
            mod_mem_type: ModMemType::Unknown,
        }
    }
}

impl ModuleMemoryMetadataMap {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn contains_key(&self, key: i64) -> bool {
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

    /// Drop a module's freed init ranges from its metadata after [`super::vsm::Vsm::free_guest_module_init`]
    /// hands them back to VTL0, so a later free/unload does not re-release them.
    ///
    /// It also returns patch targets that fell within this freed init frames. These patch targets
    /// are no longer valid (i.e., potential patch-after-free) and thus their corresponding
    /// precomputed patches should be removed (we can't remove them here due to locks).
    pub(crate) fn remove_init_ranges(&self, key: i64) -> Vec<PhysAddr> {
        let is_init = |t| {
            matches!(
                t,
                ModMemType::InitText | ModMemType::InitData | ModMemType::InitRoData
            )
        };
        let mut map = self.inner.lock();
        let Some(metadata) = map.get_mut(&key) else {
            return Vec::new();
        };
        let init_ranges: Vec<PhysFrameRange<Size4KiB>> = metadata
            .ranges
            .iter()
            .filter(|r| is_init(r.mod_mem_type))
            .map(|r| r.phys_frame_range)
            .collect();
        metadata.ranges.retain(|r| !is_init(r.mod_mem_type));
        let mut freed_patch_targets = Vec::new();
        metadata.patch_targets.retain(|&pa| {
            let freed = init_ranges
                .iter()
                .any(|fr| fr.start.start_address() <= pa && fr.end.start_address() > pa);
            if freed {
                freed_patch_targets.push(pa);
                false
            } else {
                true
            }
        });
        freed_patch_targets
    }

    /// Return the addresses of patch targets belonging to a module identified by `key`
    pub(crate) fn get_patch_targets(&self, key: i64) -> Option<Vec<PhysAddr>> {
        let guard = self.inner.lock();
        guard
            .get(&key)
            .map(|metadata| metadata.get_patch_targets().clone())
    }

    pub(crate) fn iter_entry(&self, key: i64) -> Option<ModuleMemoryMetadataIters<'_>> {
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

pub(crate) struct ModuleMemoryMetadataIters<'a> {
    guard: spin::mutex::SpinMutexGuard<'a, HashMap<i64, ModuleMemoryMetadata>>,
    key: i64,
    phantom: core::marker::PhantomData<&'a PhysFrameRange<Size4KiB>>,
}

impl<'a> ModuleMemoryMetadataIters<'a> {
    /// Returns an iterator over the memory ranges.
    ///
    /// # Panics
    ///
    /// Panics if the key is not found in the guard.
    pub(crate) fn iter_mem_ranges(&'a self) -> impl Iterator<Item = &'a ModuleMemoryRange> {
        self.guard.get(&self.key).unwrap().ranges.iter()
    }
}

/// Data structure for maintaining the memory content of a kernel module by its sections. Currently, it only maintains
/// certain sections like `.text` and `.init.text` which are needed for module validation.
pub(crate) struct ModuleMemory {
    text: MemoryContainer,
    init_text: MemoryContainer,
    init_rodata: MemoryContainer,
}

impl Default for ModuleMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleMemory {
    pub(crate) fn new() -> Self {
        Self {
            text: MemoryContainer::new(),
            init_text: MemoryContainer::new(),
            init_rodata: MemoryContainer::new(),
        }
    }

    /// Return a memory container for a section of the module memory by its name
    pub(crate) fn find_section_by_name(&self, name: &str) -> Option<&MemoryContainer> {
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
    pub(crate) fn write_bytes_from_heki_range<P: Vtl0Mediation>(
        &mut self,
        vsm: &Vsm<P>,
    ) -> Result<(), MemoryContainerError> {
        self.text.write_bytes_from_heki_range(vsm)?;
        self.init_text.write_bytes_from_heki_range(vsm)?;
        self.init_rodata.write_bytes_from_heki_range(vsm)?;
        Ok(())
    }

    pub(crate) fn extend_range(
        &mut self,
        mod_mem_type: ModMemType,
        heki_range: &HekiRange,
    ) -> Result<(), VsmError> {
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

pub(crate) struct MemoryContainer {
    range: Vec<MemoryRange>,
    buf: Vec<u8>,
}

impl Default for MemoryContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryContainer {
    pub(crate) fn new() -> Self {
        Self {
            range: Vec::new(),
            buf: Vec::new(),
        }
    }

    /// Return the byte length of the memory container
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if the memory container is empty
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn get_range(&self) -> Option<Range<VirtAddr>> {
        let start_range = self.range.first()?;
        let end_range = self.range.last()?;
        let end = end_range.addr.as_u64().checked_add(end_range.len)?;
        Some(Range {
            start: start_range.addr,
            end: VirtAddr::try_new(end).ok()?,
        })
    }

    pub(crate) fn extend_range(&mut self, heki_range: &HekiRange) -> Result<(), VsmError> {
        // `HekiRange::is_valid` already validated the addresses and `pa <= epa`.
        let addr = VirtAddr::new(heki_range.va);
        let phys_addr = PhysAddr::new(heki_range.pa);
        let len = heki_range.epa - heki_range.pa;
        if let Some(last_range) = self.range.last()
            && VirtAddr::try_new(
                last_range
                    .addr
                    .as_u64()
                    .checked_add(last_range.len)
                    .ok_or(VsmError::IntegerOverflow)?,
            )
            .map_err(|_| VsmError::InvalidVirtualAddress)?
                != addr
        {
            log::debug!("Discontiguous address found {heki_range:?}");
            // NOTE: Intentionally not returning an error here.
            // TODO: This should be an error once patch_info is fixed from VTL0
            // It will simplify patch_info and heki_range parsing as well
        }
        self.range.push(MemoryRange {
            addr,
            phys_addr,
            len,
        });
        Ok(())
    }

    /// Write physical memory bytes from VTL0 specified in `HekiRange` at the specified virtual address
    #[inline]
    pub(crate) fn write_bytes_from_heki_range<P: Vtl0Mediation>(
        &mut self,
        vsm: &Vsm<P>,
    ) -> Result<(), MemoryContainerError> {
        let mut len: usize = 0;
        if self.buf.is_empty() {
            for range in &self.range {
                let range_len: usize = range.len.trunc();
                len = len
                    .checked_add(range_len)
                    .ok_or(MemoryContainerError::Overflow)?;
            }
            self.buf.reserve_exact(len);
        }

        let range = self.range.clone();
        for range in range {
            let phys_end = range
                .phys_addr
                .as_u64()
                .checked_add(range.len)
                .and_then(|end| PhysAddr::try_new(end).ok())
                .ok_or(MemoryContainerError::Overflow)?;
            self.write_vtl0_phys_bytes(vsm, range.phys_addr, phys_end)?;
        }
        Ok(())
    }

    /// Write physical memory bytes from VTL0 at the specified physical address
    pub(crate) fn write_vtl0_phys_bytes<P: Vtl0Mediation>(
        &mut self,
        vsm: &Vsm<P>,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
    ) -> Result<(), MemoryContainerError> {
        let bytes_to_copy: usize = (phys_end - phys_start).trunc();
        if bytes_to_copy == 0 {
            return Ok(());
        }

        let old_len = self.buf.len();
        self.buf.resize(old_len + bytes_to_copy, 0);
        if vsm
            .read_vtl0_contiguous(phys_start.as_u64(), &mut self.buf[old_len..])
            .is_err()
        {
            self.buf.truncate(old_len);
            return Err(MemoryContainerError::CopyFromVtl0Failed);
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

/// Errors for memory container operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub(crate) enum MemoryContainerError {
    #[error("failed to copy data from VTL0")]
    CopyFromVtl0Failed,
    #[error("integer overflow while processing VTL0 memory")]
    Overflow,
}

pub(crate) struct KexecMemoryMetadataWrapper {
    inner: spin::mutex::SpinMutex<KexecMemoryMetadata>,
}

impl Default for KexecMemoryMetadataWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecMemoryMetadataWrapper {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn iter_guarded(&self) -> KexecMemoryMetadataIters<'_> {
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
    pub(crate) fn insert_heki_range(&mut self, heki_range: &HekiRange) -> Result<(), VsmError> {
        // `HekiRange::is_valid` already validated these addresses.
        if !heki_range.is_aligned(Size4KiB::SIZE) {
            return Err(VsmError::AddressNotPageAligned);
        }
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(KexecMemoryRange::new_checked(va, pa, epa));
        Ok(())
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

impl KexecMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, KexecMemoryRange> {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a KexecMemoryMetadata {
    type Item = &'a KexecMemoryRange;
    type IntoIter = core::slice::Iter<'a, KexecMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

pub(crate) struct KexecMemoryMetadataIters<'a> {
    guard: spin::mutex::SpinMutexGuard<'a, KexecMemoryMetadata>,
    phantom: core::marker::PhantomData<&'a PhysFrameRange<Size4KiB>>,
}

impl<'a> KexecMemoryMetadataIters<'a> {
    pub(crate) fn iter_mem_ranges(&'a self) -> impl Iterator<Item = &'a KexecMemoryRange> {
        self.guard.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct KexecMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
}

impl KexecMemoryRange {
    /// Create a memory range from values which are already validated.
    pub(crate) fn new_checked(virt_addr: u64, phys_start: u64, phys_end: u64) -> Self {
        let phys_start = PhysAddr::new(phys_start);
        let phys_end = PhysAddr::new(phys_end);
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::from_start_address(phys_start)
                    .expect("kexec memory start address is not page-aligned"),
                PhysFrame::from_start_address(phys_end)
                    .expect("kexec memory end address is not page-aligned"),
            ),
        }
    }

    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64) -> Result<Self, VsmError> {
        let phys_start =
            PhysAddr::try_new(phys_start).map_err(|_| VsmError::InvalidPhysicalAddress)?;
        let phys_end = PhysAddr::try_new(phys_end).map_err(|_| VsmError::InvalidPhysicalAddress)?;
        Ok(Self {
            virt_addr: VirtAddr::try_new(virt_addr).map_err(|_| VsmError::InvalidVirtualAddress)?,
            phys_frame_range: PhysFrame::range(
                PhysFrame::from_start_address(phys_start)
                    .map_err(|_| VsmError::AddressNotPageAligned)?,
                PhysFrame::from_start_address(phys_end)
                    .map_err(|_| VsmError::AddressNotPageAligned)?,
            ),
        })
    }
}

impl Default for KexecMemoryRange {
    fn default() -> Self {
        Self {
            virt_addr: VirtAddr::zero(),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::zero()),
                PhysFrame::containing_address(PhysAddr::zero()),
            ),
        }
    }
}

pub(crate) struct PatchDataMap {
    inner: spin::rwlock::RwLock<HashMap<PhysAddr, HekiPatch>>,
}

impl Default for PatchDataMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchDataMap {
    pub(crate) fn new() -> Self {
        Self {
            inner: spin::rwlock::RwLock::new(HashMap::new()),
        }
    }

    #[inline]
    pub(crate) fn remove_patch_data(&self, patch_targets: &Vec<PhysAddr>) {
        let mut inner = self.inner.write();
        for key in patch_targets {
            inner.remove(key);
        }
    }

    #[inline]
    pub(crate) fn get(&self, addr: PhysAddr) -> Option<HekiPatch> {
        let inner = self.inner.read();
        inner.get(&addr).copied()
    }

    /// Add patch data from a buffer containing `HekiPatchInfo` and `HekiPatch` structures.
    /// If this patch data is from a module (`module_memory_metadata` is `Some`), this function
    /// denies any patch target addresses not within the module's executable memory ranges.
    pub(crate) fn insert_patch_data_from_bytes(
        &self,
        patch_info_buf: &[u8],
        mut module_memory_metadata: Option<&mut ModuleMemoryMetadata>,
    ) -> Result<(), PatchDataMapError> {
        if patch_info_buf.len() < core::mem::size_of::<HekiPatchInfo>() {
            return Err(PatchDataMapError::InvalidHekiPatchInfo);
        }

        let mut parsed: Vec<(PhysAddr, HekiPatch)> = Vec::new();

        // the buffer looks like below:
        // [`HekiPatchInfo`, [`HekiPatch`, ...], `HekiPatchInfo`, [`HekiPatch`, ...], ...]
        // Each `HekiPatchInfo`'s `patch_index` field specifies the number of `HekiPatch` entries that follow it.
        // The buffer may have trailing bytes (from page-aligned VTL0 ranges) that don't form a valid record.
        let mut index: usize = 0;
        while index + core::mem::size_of::<HekiPatchInfo>() <= patch_info_buf.len() {
            let Some(patch_info) = HekiPatchInfo::try_from_bytes(
                &patch_info_buf[index..index + core::mem::size_of::<HekiPatchInfo>()],
            ) else {
                // Remaining bytes don't form a valid header. End of meaningful patch data.
                break;
            };

            let patch_index: usize = patch_info.patch_index.trunc();
            let total_patch_size = core::mem::size_of::<HekiPatch>()
                .checked_mul(patch_index)
                .ok_or(PatchDataMapError::InvalidHekiPatchInfo)?;
            let patches_start = index
                .checked_add(core::mem::size_of::<HekiPatchInfo>())
                .ok_or(PatchDataMapError::InvalidHekiPatchInfo)?;
            let patches_end = patches_start
                .checked_add(total_patch_size)
                .filter(|&end| end <= patch_info_buf.len())
                .ok_or(PatchDataMapError::InvalidHekiPatchInfo)?;

            for patch in patch_info_buf[patches_start..patches_end]
                .chunks(core::mem::size_of::<HekiPatch>())
                .map(HekiPatch::try_from_bytes)
            {
                let patch = patch.ok_or(PatchDataMapError::InvalidHekiPatch)?;
                // `HekiPatch::try_from_bytes` already validated both physical addresses.
                let patch_target_pa_0 = PhysAddr::new(patch.pa[0]);
                let patch_target_pa_1 = PhysAddr::new(patch.pa[1]);

                // The second page is used as an additional key when a patch straddles two physical
                // pages (see `validate_text_poke_bp_batch`).
                let straddles_second_page = !patch_target_pa_1.is_null()
                    && patch_target_pa_0
                        .as_u64()
                        .checked_add(1)
                        .and_then(|next| PhysAddr::try_new(next).ok())
                        .is_some_and(|next| next.is_aligned(Size4KiB::SIZE));

                if let Some(ref mod_mem_meta) = module_memory_metadata {
                    // Only accept patch targets within the module's executable ranges.
                    let in_executable_range = mod_mem_meta.iter().any(|mod_mem_range| {
                        let in_range = |pa: PhysAddr| {
                            mod_mem_range.phys_frame_range.start.start_address() <= pa
                                && mod_mem_range.phys_frame_range.end.start_address() > pa
                        };
                        matches!(
                            mod_mem_range.mod_mem_type,
                            ModMemType::Text | ModMemType::InitText
                        ) && in_range(patch_target_pa_0)
                            && (patch_target_pa_1.is_null() || in_range(patch_target_pa_1))
                    });
                    if !in_executable_range {
                        continue;
                    }
                }

                parsed.push((patch_target_pa_0, patch));
                if straddles_second_page {
                    parsed.push((patch_target_pa_1, patch));
                }
            }
            index = patches_end;
        }

        // Commit every parsed patch and record its targets for later unload cleanup.
        let mut inner = self.inner.write();
        for (target, patch) in parsed {
            inner.insert(target, patch);
            if let Some(ref mut mod_mem_meta) = module_memory_metadata {
                mod_mem_meta.insert_patch_target(target);
            }
        }

        Ok(())
    }
}

/// Errors for patch data map operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub(crate) enum PatchDataMapError {
    #[error("invalid HEKI patch info")]
    InvalidHekiPatchInfo,
    #[error("invalid HEKI patch")]
    InvalidHekiPatch,
}

// TODO: Use this to resolve symbols in modules
pub(crate) struct Symbol {
    _value: u64,
}

impl Symbol {
    /// Parse a symbol from a byte buffer.
    pub(crate) fn from_bytes(
        kinfo_start: usize,
        start: VirtAddr,
        bytes: &[u8],
    ) -> Result<(String, Self), VsmError> {
        let kinfo_bytes = &bytes[kinfo_start..];
        let ksym = HekiKernelSymbol::from_bytes(kinfo_bytes)?;

        let value_addr = start + mem::offset_of!(HekiKernelSymbol, value_offset) as u64;
        let value = value_addr
            .as_u64()
            .wrapping_add_signed(i64::from(ksym.value_offset));

        let name_offset = kinfo_start
            + mem::offset_of!(HekiKernelSymbol, name_offset)
            + usize::try_from(ksym.name_offset).map_err(|_| VsmError::SymbolNameOffsetInvalid)?;

        if name_offset >= bytes.len() {
            return Err(VsmError::SymbolNameOffsetInvalid);
        }
        let name_len = bytes[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(VsmError::SymbolNameNoTerminator)?;
        if name_len >= HekiKernelSymbol::KSY_NAME_LEN {
            return Err(VsmError::SymbolNameTooLong);
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
        let name = CString::new(
            name_str
                .to_str()
                .map_err(|_| VsmError::SymbolNameInvalidUtf8)?,
        )
        .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        let name = name
            .into_string()
            .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        Ok((name, Symbol { _value: value }))
    }
}

pub(crate) struct SymbolTable {
    inner: spin::rwlock::RwLock<HashMap<String, Symbol>>,
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolTable {
    pub(crate) fn new() -> Self {
        Self {
            inner: spin::rwlock::RwLock::new(HashMap::new()),
        }
    }

    /// Build a symbol table from a memory container.
    pub(crate) fn build_from_container(
        &self,
        start: VirtAddr,
        end: VirtAddr,
        mem: &MemoryContainer,
        buf: &[u8],
    ) -> Result<u64, VsmError> {
        if mem.is_empty() {
            return Err(VsmError::SymbolTableEmpty);
        }
        let Some(range) = mem.get_range() else {
            return Err(VsmError::SymbolTableEmpty);
        };
        if start < range.start || end > range.end {
            return Err(VsmError::SymbolTableOutOfRange);
        }

        let kinfo_len: usize = (end - start).trunc();
        if !kinfo_len.is_multiple_of(HekiKernelSymbol::KSYM_LEN) {
            return Err(VsmError::SymbolTableLengthInvalid);
        }

        let mut kinfo_offset: usize = (start - range.start).trunc();
        let mut kinfo_addr = start;
        let ksym_count = kinfo_len / HekiKernelSymbol::KSYM_LEN;
        let mut inner = self.inner.write();
        inner.reserve(ksym_count);

        for _ in 0..ksym_count {
            let (name, sym) = Symbol::from_bytes(kinfo_offset, kinfo_addr, buf)?;
            inner.insert(name, sym);
            kinfo_offset += HekiKernelSymbol::KSYM_LEN;
            kinfo_addr += HekiKernelSymbol::KSYM_LEN as u64;
        }
        Ok(0)
    }
}

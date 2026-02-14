// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM functions

use crate::{
    debug_serial_println,
    host::linux::CpuMask,
    mshv::{
        error::VsmError,
        heki::{
            HekiKernelSymbol, HekiPatch, HekiPatchInfo, HekiRange, ModMemType,
        },
        vtl1_mem_layout::PAGE_SIZE,
    },
};
use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
use core::{
    mem,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
};
use hashbrown::HashMap;
use litebox::utils::TruncateExt;
use spin::Once;
use thiserror::Error;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, Size4KiB, frame::PhysFrameRange},
};
use x509_cert::Certificate;
pub use litebox_common_lvbs::vsm::{
    AlignedPage, KexecMemoryMetadata, KexecMemoryRange, ModuleMemoryMetadata, ModuleMemoryRange,
    MODULE_VALIDATION_MAX_SIZE,
};

pub static CPU_ONLINE_MASK: Once<Box<CpuMask>> = Once::new();

pub use litebox_common_lvbs::mshv::{ControlRegMap, NUM_CONTROL_REGS};

/// Data structure for maintaining the kernel information in VTL0.
/// It should be prepared by copying kernel data from VTL0 to VTL1 instead of
/// relying on shared memory access to VTL0 which suffers from security issues.
pub struct Vtl0KernelInfo {
    pub module_memory_metadata: ModuleMemoryMetadataMap,
    boot_done: AtomicBool,
    system_certs: once_cell::race::OnceBox<Box<[Certificate]>>,
    pub kexec_metadata: KexecMemoryMetadataWrapper,
    pub crash_kexec_metadata: KexecMemoryMetadataWrapper,
    pub precomputed_patches: PatchDataMap,
    pub symbols: SymbolTable,
    pub gpl_symbols: SymbolTable,
    // TODO: revocation cert, blocklist, etc.
}

impl Default for Vtl0KernelInfo {
    fn default() -> Self {
        Self::new()
    }
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
    pub fn set_end_of_boot(&self) {
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
    pub fn register_module_memory_metadata(
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

    pub fn remove(&self, key: i64) -> bool {
        let mut map = self.inner.lock();
        map.remove(&key).is_some()
    }

    /// Return the addresses of patch targets belonging to a module identified by `key`
    pub fn get_patch_targets(&self, key: i64) -> Option<Vec<PhysAddr>> {
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
    /// Returns an iterator over the memory ranges.
    ///
    /// # Panics
    ///
    /// Panics if the key is not found in the guard.
    pub fn iter_mem_ranges(&'a self) -> impl Iterator<Item = &'a ModuleMemoryRange> {
        self.guard.get(&self.key).unwrap().ranges.iter()
    }
}

/// Data structure for maintaining the memory content of a kernel module by its sections. Currently, it only maintains
/// certain sections like `.text` and `.init.text` which are needed for module validation.
pub struct ModuleMemory {
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
    pub fn write_bytes_from_heki_range(&mut self) -> Result<(), MemoryContainerError> {
        self.text.write_bytes_from_heki_range()?;
        self.init_text.write_bytes_from_heki_range()?;
        self.init_rodata.write_bytes_from_heki_range()?;
        Ok(())
    }

    pub fn extend_range(
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

pub struct MemoryContainer {
    range: Vec<MemoryRange>,
    buf: Vec<u8>,
}

impl Default for MemoryContainer {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn extend_range(&mut self, heki_range: &HekiRange) -> Result<(), VsmError> {
        let addr = VirtAddr::try_new(heki_range.va).map_err(|_| VsmError::InvalidVirtualAddress)?;
        let phys_addr =
            PhysAddr::try_new(heki_range.pa).map_err(|_| VsmError::InvalidPhysicalAddress)?;
        if let Some(last_range) = self.range.last()
            && last_range.addr + last_range.len != addr
        {
            debug_serial_println!("Discontiguous address found {heki_range:?}");
            // NOTE: Intentionally not returning an error here.
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
    pub fn write_bytes_from_heki_range(&mut self) -> Result<(), MemoryContainerError> {
        let mut len: usize = 0;
        if self.buf.is_empty() {
            for range in &self.range {
                let range_len: usize = range.len.truncate();
                len += range_len;
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
    pub fn write_vtl0_phys_bytes(
        &mut self,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
    ) -> Result<(), MemoryContainerError> {
        let mut bytes_to_copy: usize = (phys_end - phys_start).truncate();
        let mut phys_cur = phys_start;

        while phys_cur < phys_end {
            let phys_aligned = phys_cur.align_down(Size4KiB::SIZE);
            let Some(page) =
                (unsafe { crate::platform_low().copy_from_vtl0_phys::<AlignedPage>(phys_aligned) })
            else {
                return Err(MemoryContainerError::CopyFromVtl0Failed);
            };

            let src_offset: usize = (phys_cur - phys_aligned).truncate();
            let src_len = core::cmp::min(bytes_to_copy, PAGE_SIZE - src_offset);
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

/// Errors for memory container operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum MemoryContainerError {
    #[error("failed to copy data from VTL0")]
    CopyFromVtl0Failed,
}

pub struct KexecMemoryMetadataWrapper {
    inner: spin::mutex::SpinMutex<KexecMemoryMetadata>,
}

impl Default for KexecMemoryMetadataWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecMemoryMetadataWrapper {
    pub fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(KexecMemoryMetadata::new()),
        }
    }

    pub fn clear_memory(&self) {
        let mut inner = self.inner.lock();
        inner.clear();
    }

    pub fn register_memory(&self, kexec_memory: KexecMemoryMetadata) {
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

pub struct KexecMemoryMetadataIters<'a> {
    guard: spin::mutex::SpinMutexGuard<'a, KexecMemoryMetadata>,
    phantom: core::marker::PhantomData<&'a PhysFrameRange<Size4KiB>>,
}

impl<'a> KexecMemoryMetadataIters<'a> {
    pub fn iter_mem_ranges(&'a self) -> impl Iterator<Item = &'a KexecMemoryRange> {
        self.guard.ranges.iter()
    }
}

pub struct PatchDataMap {
    inner: spin::rwlock::RwLock<HashMap<PhysAddr, HekiPatch>>,
}

impl Default for PatchDataMap {
    fn default() -> Self {
        Self::new()
    }
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

    /// Add patch data from a buffer containing `HekiPatchInfo` and `HekiPatch` structures.
    /// If this patch data is from a module (`module_memory_metadata` is `Some`), this function
    /// denies any patch target addresses not within the module's executable memory ranges.
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

            let patch_index: usize = patch_info.patch_index.truncate();
            let total_patch_size = core::mem::size_of::<HekiPatch>()
                .checked_mul(patch_index)
                .ok_or(PatchDataMapError::InvalidHekiPatchInfo)?;
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

/// Errors for patch data map operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum PatchDataMapError {
    #[error("invalid HEKI patch info")]
    InvalidHekiPatchInfo,
    #[error("invalid HEKI patch")]
    InvalidHekiPatch,
}

// TODO: Use this to resolve symbols in modules
pub struct Symbol {
    _value: u64,
}

impl Symbol {
    /// Parse a symbol from a byte buffer.
    pub fn from_bytes(
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
pub struct SymbolTable {
    inner: spin::rwlock::RwLock<HashMap<String, Symbol>>,
}
use core::ffi::{CStr, c_char};

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            inner: spin::rwlock::RwLock::new(HashMap::new()),
        }
    }

    /// Build a symbol table from a memory container.
    pub fn build_from_container(
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

        let kinfo_len: usize = (end - start).truncate();
        if !kinfo_len.is_multiple_of(HekiKernelSymbol::KSYM_LEN) {
            return Err(VsmError::SymbolTableLengthInvalid);
        }

        let mut kinfo_offset: usize = (start - range.start).truncate();
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

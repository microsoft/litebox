// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use litebox::{
    mm::linux::{MappingError, PAGE_SIZE, PageRange},
    platform::{
        PageManagementProvider, RawConstPointer, RawMutPointer, SystemInfoProvider,
        page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions},
    },
};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

use crate::MutPtr;
use crate::ShimFS;
use crate::Task;

/// ELF program header type for loadable segments.
const PT_LOAD: u32 = 1;
/// ELF type for shared objects and position-independent executables (PIE).
const ET_DYN: u16 = 3;

/// Per-fd state for the shim's runtime ELF syscall rewriter.
///
/// Tracks base address and trampoline write cursor for each ELF file that
/// has executable segments mapped via `do_mmap_file()`.
///
/// TODO (wdcui): This Elf patching inside the shim is not a perfect solution.
/// We will revisit it in the future.
pub(crate) struct ElfPatchState {
    /// Whether this file is already pre-patched (trampoline magic found at file tail).
    pub pre_patched: bool,
    /// For pre-patched binaries: file offset and size of the trampoline data.
    pub trampoline_file_offset: u64,
    pub trampoline_file_size: usize,
    /// Start address of the trampoline region (runtime).
    pub trampoline_addr: usize,
    /// Current write position within the trampoline (byte offset from `trampoline_addr`).
    pub trampoline_cursor: usize,
    /// Whether the trampoline region has been allocated.
    pub trampoline_mapped: bool,
    /// Total number of trampoline bytes currently mapped.
    pub trampoline_mapped_len: usize,
    /// Whether any runtime-generated stubs were successfully linked from code
    /// in this fd to the trampoline.
    pub runtime_patches_committed: bool,
    /// File offsets of segments that have already been patched. Guards against
    /// double-patching if the same segment is re-mapped (e.g. MAP_FIXED).
    pub patched_offsets: BTreeSet<usize>,
}

/// Per-process collection of ELF patching state, keyed by fd number.
pub(crate) type ElfPatchCache = BTreeMap<i32, ElfPatchState>;

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[expect(
    dead_code,
    reason = "unused but exists to be symmetric to `align_up` here"
)]
#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl<FS: ShimFS> Task<FS> {
    #[inline]
    fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        ensure_space_after: bool,
        op: impl FnOnce(MutPtr<u8>) -> Result<usize, MappingError>,
    ) -> Result<MutPtr<u8>, MappingError> {
        litebox_common_linux::mm::do_mmap(
            &self.global.pm,
            suggested_addr,
            len,
            prot,
            flags,
            ensure_space_after,
            op,
        )
    }

    #[inline]
    fn do_mmap_anonymous(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<MutPtr<u8>, MappingError> {
        let op = |_| Ok(0);
        self.do_mmap(suggested_addr, len, prot, flags, false, op)
    }

    fn do_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<MutPtr<u8>, MappingError> {
        let is_exec = prot.contains(ProtFlags::PROT_EXEC);

        // Perform the normal mmap first (CoW or memcpy fallback).
        let result = if let Some(cow_result) =
            self.try_cow_mmap_file(suggested_addr, len, &prot, &flags, fd, offset)
        {
            cow_result?
        } else {
            self.do_mmap_file_memcpy(suggested_addr, len, prot, flags, fd, offset)?
        };

        // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
        if is_exec {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0
                && !self.maybe_patch_exec_segment(result, len, fd, offset, syscall_entry)
            {
                // Trampoline setup failed for a pre-patched binary whose
                // .text already contains JMPs to the trampoline address.
                // Continuing would guarantee a SIGSEGV on the first
                // rewritten syscall, so fail the mmap instead.
                let _ = self.sys_munmap(result, len);
                return Err(MappingError::OutOfMemory);
            }
        } else if !self.global.elf_patch_cache.lock().contains_key(&fd) {
            // First mmap for this fd (non-exec): record patch state for later
            // exec segment mappings.
            self.init_elf_patch_state(fd, result.as_usize());
        }

        Ok(result)
    }

    /// Attempt to create a CoW mapping for a file with static backing data.
    ///
    /// Returns `Some(result)` if CoW was attempted (success or failure),
    /// `None` if CoW is not applicable (fall back to memcpy).
    // TODO(jb): does this need to be Option-Result or can it just be Option?
    fn try_cow_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: &ProtFlags,
        flags: &MapFlags,
        fd: i32,
        offset: usize,
    ) -> Option<Result<MutPtr<u8>, MappingError>> {
        if !len.is_multiple_of(PAGE_SIZE) {
            return None;
        }

        let Ok(fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return None;
        };

        let files = self.files.borrow();
        let raw_fd = fd;

        let static_data = files
            .run_on_raw_fd(
                raw_fd,
                |typed_fd| files.fs.get_static_backing_data(typed_fd),
                |_| None,
                |_| None,
                |_| None,
                |_| None,
                |_| None,
            )
            .ok()??;

        if offset > static_data.len() {
            return None;
        }

        let available_len = static_data.len().saturating_sub(offset);
        if available_len < len {
            // Cannot fill full page
            return None;
        }

        let fixed_behavior = if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) {
            FixedAddressBehavior::NoReplace
        } else if flags.contains(MapFlags::MAP_FIXED) {
            FixedAddressBehavior::Replace
        } else {
            FixedAddressBehavior::Hint
        };

        let permissions = {
            let mut perms = MemoryRegionPermissions::empty();
            perms.set(
                MemoryRegionPermissions::READ,
                prot.contains(ProtFlags::PROT_READ),
            );
            perms.set(
                MemoryRegionPermissions::WRITE,
                prot.contains(ProtFlags::PROT_WRITE),
            );
            perms.set(
                MemoryRegionPermissions::EXEC,
                prot.contains(ProtFlags::PROT_EXEC),
            );
            perms
        };

        // XXX: `try_allocate_cow_pages` and `register_existing_mapping` are not called under a
        // unified lock, so there is a theoretical race if two threads concurrently attempt a
        // fixed-address mapping with replacement at the same address. In practice this is benign:
        // if a program races like this both threads will register the same mapping anyway. Updating
        // to a begin/attempt/commit scheme could close this race window entirely.
        match <_ as PageManagementProvider<{ PAGE_SIZE }>>::try_allocate_cow_pages(
            litebox_platform_multiplex::platform(),
            suggested_addr.unwrap_or(0),
            &static_data[offset..offset + len],
            permissions,
            fixed_behavior,
        ) {
            Ok(ptr) => {
                let range =
                    PageRange::new(ptr.as_usize(), ptr.as_usize().checked_add(len).unwrap())
                        .unwrap();
                // SAFETY: ptr is the freshly CoW-mapped region of exactly `len` bytes with
                // `permissions`.
                unsafe {
                    self.global.pm.register_existing_mapping(
                        range,
                        permissions,
                        true,
                        fixed_behavior == FixedAddressBehavior::Replace,
                        flags.contains(MapFlags::MAP_SHARED),
                    )
                }
                .unwrap();
                Some(Ok(ptr))
            }
            Err(_cow_not_supported) => None,
        }
    }

    /// Fallback mmap implementation using page-by-page memcpy, for files where the CoW attempt
    /// fails (either due to lack of support on platform, or non-static-backed data, etc.)
    fn do_mmap_file_memcpy(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<MutPtr<u8>, MappingError> {
        let op = |ptr: MutPtr<u8>| -> Result<usize, MappingError> {
            // Note a malicious user may unmap ptr while we are reading.
            // `sys_read` does not handle page faults, so we need to use a
            // temporary buffer to read the data from fs (without worrying page
            // faults) and write it to the user buffer with page fault handling.
            let mut file_offset = offset;
            let mut buffer = [0; PAGE_SIZE];
            let mut copied = 0;
            while copied < len {
                let size =
                    self.sys_read(fd, &mut buffer, Some(file_offset))
                        .map_err(|e| match e {
                            Errno::EBADF => MappingError::BadFD(fd),
                            Errno::EISDIR => MappingError::NotAFile,
                            Errno::EACCES => MappingError::NotForReading,
                            _ => unimplemented!(),
                        })?;
                if size == 0 {
                    break;
                }
                // ptr is a valid pointer returned by do_mmap.
                ptr.copy_from_slice(copied, &buffer[..size]).unwrap();
                copied += size;
                file_offset += size;
            }
            Ok(copied)
        };
        let fixed_addr = flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE);
        self.do_mmap(
            suggested_addr,
            len,
            prot,
            flags,
            // Note we need to ensure that the space after the mapping is available
            // so that we could load trampoline code right after the mapping.
            offset == 0 && !fixed_addr,
            op,
        )
    }

    /// Handle syscall `mmap`
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<MutPtr<u8>, Errno> {
        // check alignment
        if !offset.is_multiple_of(PAGE_SIZE) || !addr.is_multiple_of(PAGE_SIZE) || len == 0 {
            return Err(Errno::EINVAL);
        }

        // MAP_SHARED is partially supported:
        // - Anonymous shared mappings are fully supported (no backing file concerns).
        //   Note: since fork is not yet supported, shared anonymous mappings behave
        //   identically to private ones (no cross-process sharing occurs).
        // - File-backed shared mappings are read-only: writable permission is rejected
        //   upfront and cannot be added later via mprotect, because writes cannot be
        //   propagated back to the underlying file.
        if flags.contains(MapFlags::MAP_SHARED)
            && prot.contains(ProtFlags::PROT_WRITE)
            && !flags.contains(MapFlags::MAP_ANONYMOUS)
        {
            todo!("MAP_SHARED with PROT_WRITE on file-backed mappings is not supported");
        }

        if flags.intersects(
            MapFlags::MAP_32BIT
                | MapFlags::MAP_GROWSDOWN
                | MapFlags::MAP_LOCKED
                | MapFlags::MAP_NONBLOCK
                | MapFlags::MAP_SYNC
                | MapFlags::MAP_HUGETLB
                | MapFlags::MAP_HUGE_2MB
                | MapFlags::MAP_HUGE_1GB,
        ) {
            todo!("Unsupported flags {:?}", flags);
        }

        let aligned_len = align_up(len, PAGE_SIZE);
        if aligned_len == 0 {
            return Err(Errno::ENOMEM);
        }
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        let suggested_addr = if addr == 0 { None } else { Some(addr) };
        if flags.contains(MapFlags::MAP_ANONYMOUS) {
            self.do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
        } else {
            self.do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
        }
        .map_err(Errno::from)
    }

    /// Handle syscall `munmap`
    #[inline]
    pub(crate) fn sys_munmap(&self, addr: crate::MutPtr<u8>, len: usize) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_munmap(&self.global.pm, addr, len)
    }

    /// Handle syscall `mprotect`
    #[inline]
    pub(crate) fn sys_mprotect(
        &self,
        addr: crate::MutPtr<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_mprotect(&self.global.pm, addr, len, prot)
    }

    #[inline]
    pub(crate) fn sys_mremap(
        &self,
        old_addr: crate::MutPtr<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    ) -> Result<crate::MutPtr<u8>, Errno> {
        litebox_common_linux::mm::sys_mremap(
            &self.global.pm,
            old_addr,
            old_size,
            new_size,
            flags,
            new_addr,
        )
    }

    /// Handle syscall `brk`
    #[inline]
    pub(crate) fn sys_brk(&self, addr: MutPtr<u8>) -> Result<usize, Errno> {
        litebox_common_linux::mm::sys_brk(&self.global.pm, addr)
    }

    /// Handle syscall `madvise`
    #[inline]
    pub(crate) fn sys_madvise(
        &self,
        addr: MutPtr<u8>,
        len: usize,
        advice: litebox_common_linux::MadviseBehavior,
    ) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_madvise(&self.global.pm, addr, len, advice)
    }

    // ── Runtime ELF syscall patching ─────────────────────────────────────

    /// Initialize ELF patch state for an fd on its first mmap at offset 0.
    ///
    /// Reads the ELF header to determine the trampoline address (page-aligned
    /// end of the highest PT_LOAD segment) and checks the file tail for the
    /// trampoline magic to determine if it's pre-patched.
    ///
    /// x86_64 only: assumes 64-bit ELF layout and program header offsets.
    #[allow(clippy::cast_possible_truncation)]
    fn init_elf_patch_state(&self, fd: i32, base_addr: usize) {
        // Quick check: skip if already initialized.
        if self.global.elf_patch_cache.lock().contains_key(&fd) {
            return;
        }

        // Read the ELF header (first 64 bytes covers both 32-bit and 64-bit).
        let mut ehdr_buf = [0u8; 64];
        match self.sys_read(fd, &mut ehdr_buf, Some(0)) {
            Ok(n) if n == ehdr_buf.len() => {}
            _ => return, // Not readable or short read, skip
        }

        // Verify ELF magic
        if &ehdr_buf[0..4] != b"\x7fELF" {
            return; // Not an ELF file
        }

        // Parse as 64-bit ELF (runtime patching is x86-64 only).
        let e_phoff = u64::from_le_bytes(ehdr_buf[32..40].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes(ehdr_buf[54..56].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(ehdr_buf[56..58].try_into().unwrap()) as usize;
        let e_type = u16::from_le_bytes(ehdr_buf[16..18].try_into().unwrap());

        // Validate e_phentsize: must be at least sizeof(Elf64_Phdr) = 56 bytes,
        // otherwise the field accesses (e.g. ph[40..48] for p_memsz) will panic.
        if e_phentsize < 56 {
            return;
        }

        // Read program headers to find max PT_LOAD end
        let Some(phdrs_size) = e_phentsize.checked_mul(e_phnum) else {
            return;
        };
        if phdrs_size == 0 || phdrs_size > 0x10000 {
            return; // Sanity check
        }
        let mut phdrs_buf = alloc::vec![0u8; phdrs_size];
        match self.sys_read(fd, &mut phdrs_buf, Some(e_phoff)) {
            Ok(n) if n == phdrs_buf.len() => {}
            _ => return,
        }

        // Find highest PT_LOAD end (p_vaddr + p_memsz)
        let mut max_load_end: u64 = 0;
        for i in 0..e_phnum {
            let ph = &phdrs_buf[i * e_phentsize..][..e_phentsize];
            let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
            if p_type != PT_LOAD {
                continue;
            }
            let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
            let Some(end) = p_vaddr.checked_add(p_memsz) else {
                litebox_util_log::warn!(
                    p_vaddr:? = p_vaddr, p_memsz:? = p_memsz;
                    "PT_LOAD p_vaddr + p_memsz overflow, skipping segment"
                );
                continue;
            };
            if end > max_load_end {
                max_load_end = end;
            }
        }

        if max_load_end == 0 {
            return; // No PT_LOAD segments
        }

        // For ET_DYN (PIE/shared libs), p_vaddr is relative to base_addr.
        // For ET_EXEC, p_vaddr is absolute and base_addr is 0.
        let trampoline_vaddr = if e_type == ET_DYN {
            // ET_DYN
            base_addr + (max_load_end as usize).next_multiple_of(PAGE_SIZE)
        } else {
            // ET_EXEC
            (max_load_end as usize).next_multiple_of(PAGE_SIZE)
        };

        // Check if file is pre-patched by reading the last 32 bytes for magic
        let (pre_patched, tramp_file_offset, tramp_vaddr, tramp_file_size) =
            self.check_trampoline_magic(fd);

        // For pre-patched binaries, use the vaddr from the header instead.
        let trampoline_vaddr = if pre_patched {
            if e_type == ET_DYN {
                base_addr + tramp_vaddr as usize
            } else {
                tramp_vaddr as usize
            }
        } else {
            trampoline_vaddr
        };

        // Insert under lock (re-check for races).
        let mut cache = self.global.elf_patch_cache.lock();
        cache.entry(fd).or_insert(ElfPatchState {
            pre_patched,
            trampoline_file_offset: tramp_file_offset,
            trampoline_file_size: tramp_file_size as usize,
            trampoline_addr: trampoline_vaddr,
            trampoline_cursor: 0,
            trampoline_mapped: false,
            trampoline_mapped_len: 0,
            runtime_patches_committed: false,
            patched_offsets: BTreeSet::new(),
        });
    }

    /// Check if a file has the LITEBOX trampoline magic at its tail.
    /// Returns (is_pre_patched, file_offset, vaddr, trampoline_size).
    fn check_trampoline_magic(&self, fd: i32) -> (bool, u64, u64, u64) {
        const HEADER_SIZE: usize = 32; // TrampolineHeader64: magic(8) + file_offset(8) + vaddr(8) + size(8)
        let Ok(stat) = self.sys_fstat(fd) else {
            return (false, 0, 0, 0);
        };
        let file_size = stat.st_size;
        if file_size < HEADER_SIZE {
            return (false, 0, 0, 0);
        }
        let mut tail = [0u8; HEADER_SIZE];
        match self.sys_read(fd, &mut tail, Some(file_size - HEADER_SIZE)) {
            Ok(n) if n == HEADER_SIZE => {}
            _ => return (false, 0, 0, 0),
        }
        if &tail[0..8] != litebox_syscall_rewriter::TRAMPOLINE_MAGIC {
            return (false, 0, 0, 0);
        }
        let file_offset = u64::from_le_bytes(tail[8..16].try_into().unwrap());
        let vaddr = u64::from_le_bytes(tail[16..24].try_into().unwrap());
        let trampoline_size = u64::from_le_bytes(tail[24..32].try_into().unwrap());
        (true, file_offset, vaddr, trampoline_size)
    }

    /// Patch an executable segment in-place after it has been mapped.
    ///
    /// For pre-patched binaries: maps the trampoline from the file and writes
    /// the syscall entry point.
    /// For unpatched binaries: calls `patch_code_segment()` to rewrite syscall
    /// instructions and places the generated stubs in the trampoline region.
    ///
    /// Returns `true` on success or non-fatal skip. Returns `false` when a
    /// pre-patched binary's trampoline could not be set up — the caller must
    /// fail the mapping because the code already contains JMPs to the
    /// trampoline address.
    #[allow(clippy::cast_possible_truncation)]
    fn maybe_patch_exec_segment(
        &self,
        mapped_addr: MutPtr<u8>,
        len: usize,
        fd: i32,
        offset: usize,
        syscall_entry: usize,
    ) -> bool {
        // Initialize patch state if this is the first mmap for this fd.
        // Typically the first mapping is at offset 0 (the ELF header), but
        // some loaders may map an executable segment at a non-zero offset first.
        if !self.global.elf_patch_cache.lock().contains_key(&fd) {
            self.init_elf_patch_state(fd, mapped_addr.as_usize());
        }

        // This lock guards the elf_patch_cache and is held for the entire
        // patching operation. In practice this is fine because the dynamic
        // linker loads shared libraries sequentially.
        let mut cache = self.global.elf_patch_cache.lock();
        let Some(state) = cache.get_mut(&fd) else {
            return true; // No patch state — not an ELF we're tracking
        };

        if state.pre_patched {
            // Pre-patched binary: map the trampoline data from the file.
            if !state.trampoline_mapped && state.trampoline_file_size > 0 {
                let tramp_addr = state.trampoline_addr;
                let tramp_len = align_up(state.trampoline_file_size, PAGE_SIZE);

                // Allocate RW region at the trampoline address. Use MAP_FIXED
                // because the code already contains JMPs to this exact address
                // and we MUST map here. The region may already be reserved as
                // PROT_NONE by the ElfLoader's reserve() call, which would
                // cause MAP_FIXED_NOREPLACE to fail with EEXIST.
                let alloc_result = self.do_mmap_anonymous(
                    Some(tramp_addr),
                    tramp_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                );
                let Ok(alloc_ptr) = alloc_result else {
                    return false;
                };
                let actual_addr = alloc_ptr.as_usize();
                if actual_addr != tramp_addr {
                    let _ = self.sys_munmap(MutPtr::<u8>::from_usize(actual_addr), tramp_len);
                    return false;
                }

                // Read trampoline data from the file.
                let mut tramp_data = alloc::vec![0u8; state.trampoline_file_size];
                let file_off = state.trampoline_file_offset as usize;
                let tramp_ptr = MutPtr::<u8>::from_usize(tramp_addr);
                match self.sys_read(fd, &mut tramp_data, Some(file_off)) {
                    Ok(n) if n == tramp_data.len() => {}
                    _ => {
                        let _ = self.sys_munmap(tramp_ptr, tramp_len);
                        return false;
                    }
                }

                // Write syscall entry point to the first 8 bytes.
                if tramp_data.len() >= 8 {
                    tramp_data[..8].copy_from_slice(&syscall_entry.to_le_bytes());
                }

                // Write to the mapped region.
                if tramp_ptr.copy_from_slice(0, &tramp_data).is_none() {
                    let _ = self.sys_munmap(tramp_ptr, tramp_len);
                    return false;
                }

                // Protect as RX immediately.
                if self
                    .sys_mprotect(
                        tramp_ptr,
                        tramp_len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    )
                    .is_err()
                {
                    let _ = self.sys_munmap(tramp_ptr, tramp_len);
                    return false;
                }

                state.trampoline_mapped = true;
                state.trampoline_mapped_len = tramp_len;
            }
            return true;
        }

        // ── Runtime patching path (unpatched binaries) ───────────────

        // Allocate the trampoline region if not yet done.
        let addr_usize = mapped_addr.as_usize();
        if !state.trampoline_mapped {
            let tramp_addr = state.trampoline_addr;

            // Try MAP_FIXED first — works when ensure_space_after reserved
            // PROT_NONE space (shared libraries). Falls back to a hint-based
            // allocation for the ElfLoader path where no headroom is reserved.
            let actual_addr = self
                .do_mmap_anonymous(
                    Some(tramp_addr),
                    PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                )
                .or_else(|_| {
                    self.do_mmap_anonymous(
                        Some(tramp_addr),
                        PAGE_SIZE,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    )
                });
            let Ok(actual_addr_ptr) = actual_addr else {
                litebox_util_log::warn!("failed to allocate trampoline region");
                return true;
            };
            let actual_addr = actual_addr_ptr.as_usize();

            // Verify the trampoline is within JMP rel32 range (+-2GB) of the
            // entire code segment, not just its start.
            let far_end = addr_usize.saturating_add(len);
            let distance = actual_addr
                .abs_diff(addr_usize)
                .max(actual_addr.abs_diff(far_end));
            if distance > 0x7FFF_0000 {
                litebox_util_log::warn!(
                    distance:? = distance;
                    "trampoline too far from code segment, skipping patching"
                );
                let _ = self.sys_munmap(MutPtr::<u8>::from_usize(actual_addr), PAGE_SIZE);
                return true;
            }

            state.trampoline_addr = actual_addr;

            // Write the 8-byte syscall entry point at the start.
            let entry_ptr = MutPtr::<u8>::from_usize(actual_addr);
            if entry_ptr
                .copy_from_slice(0, &syscall_entry.to_le_bytes())
                .is_none()
            {
                litebox_util_log::warn!("failed to write syscall entry point to trampoline");
                let _ = self.sys_munmap(MutPtr::<u8>::from_usize(actual_addr), PAGE_SIZE);
                return true;
            }
            state.trampoline_cursor = 8; // stubs start after the 8-byte entry
            state.trampoline_mapped = true;
            state.trampoline_mapped_len = PAGE_SIZE;
        }

        // Guard against double-patching the same segment (e.g. MAP_FIXED
        // re-mapping). Feeding already-rewritten JMP instructions back into
        // the rewriter would corrupt code.
        if !state.patched_offsets.insert(offset) {
            return true;
        }

        let restore_trampoline_rx = |task: &Self, state: &ElfPatchState| {
            if state.trampoline_mapped_len > 0 {
                let _ = task.sys_mprotect(
                    MutPtr::<u8>::from_usize(state.trampoline_addr),
                    state.trampoline_mapped_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                );
            }
        };

        // Make the trampoline RW for writing stubs.
        if state.trampoline_mapped_len > 0
            && self
                .sys_mprotect(
                    MutPtr::<u8>::from_usize(state.trampoline_addr),
                    state.trampoline_mapped_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )
                .is_err()
        {
            litebox_util_log::warn!("failed to mprotect trampoline to RW");
            return true;
        }
        if self
            .sys_mprotect(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .is_err()
        {
            litebox_util_log::warn!("failed to mprotect code segment to RW for patching");
            restore_trampoline_rx(self, state);
            return true;
        }

        // Read the mapped code into a buffer, patch it, write back.
        let Some(code_owned) = mapped_addr.to_owned_slice(len) else {
            litebox_util_log::warn!("failed to read code segment for patching");
            let _ = self.sys_mprotect(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            );
            restore_trampoline_rx(self, state);
            return true;
        };
        let mut code_buf = code_owned.into_vec();
        let original_code = code_buf.clone();

        let code_vaddr = addr_usize as u64;
        let trampoline_write_vaddr = (state.trampoline_addr + state.trampoline_cursor) as u64;
        let syscall_entry_addr = state.trampoline_addr as u64;

        let patch_result = litebox_syscall_rewriter::patch_code_segment(
            &mut code_buf,
            code_vaddr,
            trampoline_write_vaddr,
            syscall_entry_addr,
        );
        let patch_result = match patch_result {
            Ok((stubs, skipped_addrs)) => {
                if !skipped_addrs.is_empty() {
                    litebox_util_log::warn!(
                        count:? = skipped_addrs.len(), addrs:? = skipped_addrs;
                        "syscall instruction(s) could not be patched"
                    );
                }
                Ok(stubs)
            }
            Err(e) => Err(e),
        };
        match patch_result {
            Ok(stubs) if !stubs.is_empty() => {
                let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
                    litebox_util_log::warn!("trampoline cursor overflow");
                    let _ = self.sys_mprotect(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    return true;
                };
                let tramp_pages_needed = align_up(new_cursor, PAGE_SIZE);
                if tramp_pages_needed > state.trampoline_mapped_len {
                    let extra_start = state.trampoline_addr + state.trampoline_mapped_len;
                    let extra_len = tramp_pages_needed - state.trampoline_mapped_len;
                    if self
                        .do_mmap_anonymous(
                            Some(extra_start),
                            extra_len,
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                            MapFlags::MAP_ANONYMOUS
                                | MapFlags::MAP_PRIVATE
                                | MapFlags::MAP_FIXED_NOREPLACE,
                        )
                        .is_err()
                    {
                        litebox_util_log::warn!("failed to expand trampoline region");
                        let _ = self.sys_mprotect(
                            mapped_addr,
                            len,
                            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                        );
                        restore_trampoline_rx(self, state);
                        return true;
                    }
                    state.trampoline_mapped_len = tramp_pages_needed;
                }

                // Write stubs before patching the code so rewritten jumps
                // never target an uninitialized trampoline.
                let tramp_write_ptr =
                    MutPtr::<u8>::from_usize(state.trampoline_addr + state.trampoline_cursor);
                if tramp_write_ptr.copy_from_slice(0, &stubs).is_none() {
                    litebox_util_log::warn!("failed to write trampoline stubs");
                    let _ = self.sys_mprotect(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    return true;
                }

                // Write patched code back to the mapped region.
                if mapped_addr.copy_from_slice(0, &code_buf).is_none() {
                    litebox_util_log::warn!("failed to write patched code back to code segment");
                    let _ = mapped_addr.copy_from_slice(0, &original_code);
                    let _ = self.sys_mprotect(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    return true;
                }
                state.trampoline_cursor = new_cursor;
                state.runtime_patches_committed = true;
            }
            Ok(_) => {
                // No syscalls found — no patching needed.
            }
            Err(e) => {
                litebox_util_log::warn!(err:? = e; "failed to patch code segment");
                let _ = self.sys_mprotect(
                    mapped_addr,
                    len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                );
                restore_trampoline_rx(self, state);
                return true;
            }
        }

        // Restore the code segment to RX.
        let _ = self.sys_mprotect(
            mapped_addr,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        );
        restore_trampoline_rx(self, state);
        true
    }

    /// Finalize the ELF patching state for `fd`.
    ///
    /// If the fd has a trampoline region that was allocated (RW), mprotect it
    /// to RX so the trampoline stubs become executable and non-writable.
    /// The cache entry is removed regardless.
    pub(crate) fn finalize_elf_patch(&self, fd: i32) {
        let state = self.global.elf_patch_cache.lock().remove(&fd);
        if let Some(state) = state
            && state.trampoline_mapped
            && !state.pre_patched
        {
            let tramp_len = state.trampoline_mapped_len;
            if tramp_len > 0 {
                if !state.runtime_patches_committed {
                    let _ =
                        self.sys_munmap(MutPtr::<u8>::from_usize(state.trampoline_addr), tramp_len);
                    return;
                }
                let _ = self.sys_mprotect(
                    MutPtr::<u8>::from_usize(state.trampoline_addr),
                    tramp_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use litebox::{
        fs::{Mode, OFlags},
        platform::{PageManagementProvider, RawConstPointer, RawMutPointer},
    };
    use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

    use crate::syscalls::tests::init_platform;

    #[test]
    fn test_anonymous_mmap() {
        let task = init_platform(None);

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();
        addr.write_slice_at_offset(0, &[0xff; 0x2000]).unwrap();
        assert_eq!(addr.read_at_offset(0x1000).unwrap(), 0xff,);
        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_file_backed_mmap() {
        let task = init_platform(None);

        let content = b"Hello, world!";
        let fd = task
            .sys_open("test.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_write(fd, content, None).unwrap(), content.len());
        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        assert_eq!(
            addr.to_owned_slice(content.len()).unwrap().as_ref(),
            content.as_slice(),
        );
        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_mremap() {
        let task = init_platform(None);

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();

        assert!(matches!(
            task.sys_mremap(
                addr,
                0x1000,
                0x2000,
                litebox_common_linux::MRemapFlags::empty(),
                0
            ),
            Err(litebox_common_linux::errno::Errno::ENOMEM)
        ),);
        let new_addr = task
            .sys_mremap(
                addr,
                0x1000,
                0x2000,
                litebox_common_linux::MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        task.sys_munmap(addr, 0x2000).unwrap();
        task.sys_munmap(new_addr, 0x2000).unwrap();
    }

    #[test]
    fn test_mmap_fixed_noreplace() {
        let task = init_platform(None);

        // First, create an initial mapping at a specific address away from boundaries
        let base_addr = 0x1000_0000usize; // 256 MiB - safe middle ground
        let addr1 = task
            .sys_mmap(
                base_addr,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(
            addr1.as_usize(),
            base_addr,
            "First mapping should be at exact address"
        );

        // Test 1: Full overlap - should fail with EEXIST
        let err = task
            .sys_mmap(
                addr1.as_usize(),
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 2: Partial overlap at end - should fail with EEXIST
        // Existing: [addr1, addr1 + 0x2000), New: [addr1 + 0x1000, addr1 + 0x3000)
        let err = task
            .sys_mmap(
                addr1.as_usize() + 0x1000,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 3: Partial overlap at start - should fail with EEXIST
        // Existing: [addr1, addr1 + 0x2000), New: [addr1 - 0x1000, addr1 + 0x1000)
        let err = task
            .sys_mmap(
                addr1.as_usize() - 0x1000,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 4: Adjacent mapping (right after) - should succeed
        let addr2 = task
            .sys_mmap(
                addr1.as_usize() + 0x2000,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(addr2.as_usize(), addr1.as_usize() + 0x2000);

        // Test 5: Adjacent mapping (right before) - should succeed
        let addr3 = task
            .sys_mmap(
                addr1.as_usize() - 0x1000,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(addr3.as_usize(), addr1.as_usize() - 0x1000);

        // Test 6: Zero address with MAP_FIXED_NOREPLACE - should fail with EPERM
        // (matches Linux behavior where vm.mmap_min_addr prevents mapping at address 0)
        let err = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EPERM);

        // Clean up
        task.sys_munmap(addr3, 0x1000).unwrap();
        task.sys_munmap(addr1, 0x2000).unwrap();
        task.sys_munmap(addr2, 0x1000).unwrap();
    }

    #[cfg(any(
        feature = "platform_linux_userland",
        feature = "platform_windows_userland"
    ))]
    #[test]
    fn test_collision_with_global_allocator() {
        let task = init_platform(None);
        let platform = task.global.platform;
        let mut data = alloc::vec::Vec::new();
        // Find an address that is allocated to the global allocator but not in reserved regions.
        // LiteBox's page manager is not aware of the global allocator's allocations.
        let addr = loop {
            #[allow(
                unused_variables,
                reason = "the following features are mutually exclusive"
            )]
            #[cfg(feature = "platform_windows_userland")]
            let addr = {
                let buf = alloc::vec::Vec::<u8>::with_capacity(0x10_0000);
                let addr = buf.as_ptr() as usize;
                data.push(buf);
                addr
            };
            #[cfg(feature = "platform_linux_userland")]
            let addr = {
                let addr = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        0x10_000,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                } as usize;
                data.push(alloc::vec::Vec::<u8>::from(unsafe {
                    core::slice::from_raw_parts(addr as *const u8, 0x10_000)
                }));
                addr
            };

            let mut included = false;
            for r in <litebox_platform_multiplex::Platform as PageManagementProvider<4096>>::reserved_pages(platform) {
                if r.contains(&addr) {
                    included = true;
                    break;
                }
            }

            if !included {
                // Also ensure that [addr - 0x1000, addr) is available, which is needed in the test below.
                if let Ok(ptr) = task.sys_mmap(
                    addr - 0x1000,
                    0x1000,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                    -1,
                    0,
                ) {
                    if ptr.as_usize() != addr - 0x1000 {
                        task.sys_munmap(ptr, 0x1000).unwrap();
                        continue;
                    }
                    break addr;
                }
            }
        };

        // mmap with the found address should still succeed but not at the exact address.
        let res = task
            .sys_mmap(
                addr,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                -1,
                0,
            )
            .unwrap();
        assert_ne!(res.as_usize(), 0);
        assert_ne!(res.as_usize(), addr);

        // grow the mapping without MREMAP_MAYMOVE should fail as the new region collides with the global allocator
        let err = task
            .sys_mremap(
                crate::MutPtr::from_usize(addr - 0x1000),
                0x1000,
                0x2000,
                MRemapFlags::empty(),
                addr - 0x1000,
            )
            .unwrap_err();
        assert_eq!(err, Errno::ENOMEM);
    }

    #[test]
    fn test_map_shared_anonymous() {
        let task = init_platform(None);

        // MAP_SHARED | MAP_ANON with PROT_READ should succeed
        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_SHARED,
                -1,
                0,
            )
            .unwrap();

        // Reading should work
        let _val: u8 = addr.read_at_offset(0).unwrap();

        // Anonymous shared mappings allow permission changes including write
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap();
        addr.write_slice_at_offset(0, &[0xab; 0x10]).unwrap();
        assert_eq!(addr.read_at_offset(0).unwrap(), 0xab_u8);

        // mprotect to read-only or read-exec should also succeed
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ)
            .unwrap();
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ_EXEC)
            .unwrap();

        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_map_shared_anonymous_writable() {
        let task = init_platform(None);

        // MAP_SHARED | MAP_ANON with PROT_WRITE should succeed
        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_SHARED,
                -1,
                0,
            )
            .unwrap();

        addr.write_slice_at_offset(0, &[0xcd; 0x10]).unwrap();
        assert_eq!(addr.read_at_offset(0).unwrap(), 0xcd_u8);

        task.sys_munmap(addr, 0x1000).unwrap();
    }

    #[test]
    fn test_map_shared_readonly_file() {
        let task = init_platform(None);

        let content = b"Hello, shared!";
        let fd = task
            .sys_open("shared.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_write(fd, content, None).unwrap(), content.len());

        // MAP_SHARED with PROT_READ on a file should succeed
        let addr = task
            .sys_mmap(0, 0x1000, ProtFlags::PROT_READ, MapFlags::MAP_SHARED, fd, 0)
            .unwrap();

        // Data should match
        assert_eq!(
            addr.to_owned_slice(content.len()).unwrap().as_ref(),
            content.as_slice(),
        );

        // mprotect to add write permission should fail
        let err = task
            .sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);

        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_madvise() {
        let task = init_platform(None);

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();

        addr.write_slice_at_offset(0, &[0xff; 0x10]).unwrap();

        // Test MADV_NORMAL
        assert!(
            task.sys_madvise(addr, 0x2000, litebox_common_linux::MadviseBehavior::Normal)
                .is_ok()
        );

        // Test MADV_DONTNEED
        assert!(
            task.sys_madvise(
                addr,
                0x2000,
                litebox_common_linux::MadviseBehavior::DontNeed
            )
            .is_ok()
        );

        addr.to_owned_slice(0x10).unwrap().iter().for_each(|&x| {
            assert_eq!(x, 0); // Should be zeroed after MADV_DONTNEED
        });

        task.sys_munmap(addr, 0x2000).unwrap();
    }

    // Signal support for Windows is not ready yet.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_fallible_read() {
        let _ = init_platform(None);

        let ptr = crate::MutPtr::<u8>::from_usize(0xdeadbeef);
        let result = ptr.read_at_offset(0);
        assert!(result.is_none());
    }
}

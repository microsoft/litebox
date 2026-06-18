// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use alloc::collections::BTreeMap;
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

/// Per-fd state for the shim's runtime ELF syscall rewriter.
///
/// Tracks base address and trampoline write cursor for each ELF file that
/// has executable segments mapped via `do_mmap_file()`.
pub(crate) struct ElfPatchState {
    /// Base virtual address of the ELF (recorded from first mmap at offset ≈ 0).
    pub _base_addr: usize,
    /// Whether this file is already pre-patched (trampoline magic found at file tail).
    pub pre_patched: bool,
    /// For pre-patched binaries: file offset and size of the trampoline data.
    pub trampoline_file_offset: u64,
    pub trampoline_file_size: usize,
    /// For pre-patched binaries: virtual address offset of the trampoline in the ELF.
    pub _trampoline_vaddr: usize,
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
    /// File path of the ELF (from the fd→path table, if available).
    #[allow(dead_code)]
    pub file_path: Option<alloc::string::String>,
}

/// Per-process collection of ELF patching state, keyed by fd number.
pub(crate) type ElfPatchCache = BTreeMap<i32, ElfPatchState>;

/// Tracks a `MAP_SHARED` file-backed mapping from a writable fd so that
/// dirty data can be written back to the underlying file on `munmap` or
/// `msync`.
///
/// LLD (and other tools) write output files via `mmap(MAP_SHARED)` + memory
/// stores + `munmap`. In the sandbox, file-backed shared mappings are backed
/// by anonymous memory (the 9P transport has no kernel-level page cache), so
/// we must explicitly flush modified data back to the file.
///
/// # Known limitation: no per-page dirty tracking
///
/// Writeback granularity is per-fragment, not per-page. When a fragment has
/// `needs_writeback == true`, its entire range is flushed. Because the
/// backing memory is an anonymous snapshot taken at `mmap()` time, pages
/// the guest never modified still hold stale file contents from that point.
/// If another path (e.g. `write()`) updates the same file region after the
/// mapping was created, writeback can overwrite those newer bytes with the
/// stale snapshot.
///
/// True per-page dirty tracking would require write-protecting mapped pages
/// and trapping on first write (page-fault-based dirty bitmap), which is a
/// platform-layer change well beyond this writeback mechanism. The primary
/// use case — tool output files created via `ftruncate` + `mmap` — is
/// unaffected because the file is freshly created and there are no
/// concurrent modifications to race against.
pub(crate) struct SharedFileMapping {
    /// Guest virtual address of the mapping.
    pub addr: usize,
    /// Length of the mapping (page-aligned).
    pub len: usize,
    /// Internal file handle for writeback. This is a duplicate created via
    /// `Descriptors::duplicate()` that lives only in the global descriptor
    /// table — it is NOT stored in the per-process `RawDescriptorStorage`,
    /// so the guest cannot enumerate, close, or otherwise interfere with it.
    ///
    /// Contains a `TypedFd<FS>` type-erased as `Box<dyn Any + Send + Sync>`.
    /// Writeback and close operations downcast back to `&TypedFd<FS>` and
    /// call `fs.write()` / `fs.close()` directly.
    internal_fd: InternalHandle,
    /// File offset that was passed to `mmap`.
    pub file_offset: usize,
    /// Whether this mapping has been writable (and thus potentially dirty).
    /// Set at mmap time if `PROT_WRITE` is requested, or later by
    /// `sys_mprotect` when write permission is added. Writeback is skipped
    /// for entries where this is `false` to avoid overwriting newer file
    /// data with stale CoW pages.
    pub(crate) needs_writeback: bool,
}

/// Per-process collection of shared file mappings pending writeback.
pub(crate) type SharedFileMappings = alloc::vec::Vec<SharedFileMapping>;

/// Type-erased internal file handle (contains `TypedFd<FS>`).
type InternalHandle = alloc::boxed::Box<dyn core::any::Any + Send + Sync>;

/// Read `len` bytes from guest address `addr` for MAP_SHARED writeback.
///
/// Fast path: the pages are already readable — `to_owned_slice()` succeeds.
/// Slow path: the pages may have been made inaccessible via `mprotect(PROT_NONE)`.
/// In that case we temporarily upgrade them to `PROT_READ`, read the data,
/// and **restore them to inaccessible** so the caller's mapping permissions
/// are not permanently altered.
fn read_for_writeback(
    pm: &litebox::mm::PageManager<litebox_platform_multiplex::Platform, { PAGE_SIZE }>,
    addr: usize,
    len: usize,
) -> Option<alloc::boxed::Box<[u8]>> {
    let src = crate::ConstPtr::<u8>::from_usize(addr);
    if let Some(data) = src.to_owned_slice(len) {
        return Some(data);
    }
    // Slow path: temporarily make pages readable.
    // SAFETY: upgrading existing mapped pages to readable for writeback.
    let ptr = crate::MutPtr::<u8>::from_usize(addr);
    unsafe { pm.make_pages_readable(ptr, len) }.ok()?;
    let data = src.to_owned_slice(len);
    // Restore pages to inaccessible — the only non-readable state that
    // could have caused the fast path to fail is PROT_NONE.
    let _ = unsafe { pm.make_pages_inaccessible(ptr, len) };
    data
}

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl<FS: ShimFS> Task<FS> {
    // ── Internal fd helpers for MAP_SHARED writeback ────────────────────

    /// Create an internal file handle by duplicating `raw_fd` (a guest fd)
    /// in the global descriptor table. The new entry is NOT stored in
    /// `RawDescriptorStorage`, so the guest cannot see or close it.
    fn duplicate_internal_fs_fd(&self, raw_fd: i32) -> Result<InternalHandle, Errno> {
        let raw_fd_usize = usize::try_from(u32::try_from(raw_fd).map_err(|_| Errno::EBADF)?)
            .map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        // Retrieve the TypedFd for the guest fd, then release the RDS lock
        // before taking the DT write lock (consistent lock ordering).
        let arc_fd: alloc::sync::Arc<litebox::fd::TypedFd<FS>> = {
            let rds = files.raw_descriptor_store.read();
            rds.fd_from_raw_integer::<FS>(raw_fd_usize)
                .map_err(|_| Errno::EBADF)?
        };
        let mut dt = self.global.litebox.descriptor_table_mut();
        let new_fd = dt.duplicate(&*arc_fd).ok_or(Errno::EBADF)?;
        drop(dt);
        Ok(alloc::boxed::Box::new(new_fd))
    }

    /// Create a new internal file handle by duplicating an existing one.
    /// Used when a partial munmap or mremap splits a mapping into fragments
    /// that each need their own independent handle.
    fn duplicate_internal_handle(
        &self,
        handle: &dyn core::any::Any,
    ) -> Result<InternalHandle, Errno> {
        let fd = handle
            .downcast_ref::<litebox::fd::TypedFd<FS>>()
            .ok_or(Errno::EBADF)?;
        let mut dt = self.global.litebox.descriptor_table_mut();
        let new_fd = dt.duplicate(fd).ok_or(Errno::EBADF)?;
        drop(dt);
        Ok(alloc::boxed::Box::new(new_fd))
    }

    /// Write to the file referenced by an internal handle.
    fn internal_fs_write(
        &self,
        handle: &dyn core::any::Any,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let fd = handle
            .downcast_ref::<litebox::fd::TypedFd<FS>>()
            .ok_or(Errno::EBADF)?;
        let files = self.files.borrow();
        files.fs.write(fd, buf, offset).map_err(Errno::from)
    }

    /// Check whether the file referenced by an internal handle was opened
    /// with write access. Pure metadata query — no I/O side effects.
    fn internal_fs_is_writable(&self, handle: &dyn core::any::Any) -> bool {
        let Some(fd) = handle.downcast_ref::<litebox::fd::TypedFd<FS>>() else {
            return false;
        };
        let files = self.files.borrow();
        files.fs.is_writable(fd)
    }

    /// Close an internal file handle. Takes ownership to ensure the handle
    /// is dropped after the descriptor table entry is removed.
    fn internal_fs_close(&self, handle: InternalHandle) {
        if let Ok(fd) = handle.downcast::<litebox::fd::TypedFd<FS>>() {
            let files = self.files.borrow();
            let _ = files.fs.close(&*fd);
            // `fd` is dropped here; OwnedFd::Drop is safe because
            // fs.close() already called mark_as_closed().
        }
    }

    /// Validate that `fd` refers to a readable regular file for file-backed
    /// mmap operations. This preserves Linux-style errno precedence for invalid
    /// fds, non-file descriptors, directories, and write-only descriptors.
    fn validate_file_backed_mmap_fd(&self, fd: i32) -> Result<(), Errno> {
        let raw_fd = usize::try_from(u32::try_from(fd).map_err(|_| Errno::EBADF)?)
            .map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(typed_fd) => {
                let status = files.fs.fd_file_status(typed_fd).map_err(Errno::from)?;
                if status.file_type != litebox::fs::FileType::RegularFile {
                    return Err(Errno::ENODEV);
                }
                let mut probe = [];
                files
                    .fs
                    .read(typed_fd, &mut probe, Some(0))
                    .map_err(Errno::from)?;
                Ok(())
            }
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::Eventfd(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::Epoll(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::Unix(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::BrokerSocketPair(_)
            | crate::RawFdRef::BrokerSocketDgram(_)
            | crate::RawFdRef::BrokerUnixStream(_)
            | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::BrokerPty(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::Signalfd(_)
            | crate::RawFdRef::Inotify(_)
            | crate::RawFdRef::BrokerInetListener(_)
            | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
            crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENODEV), // real Linux: ENODEV for mmap on non-mmapable fd
        })?
    }

    // ── End of internal fd helpers ─────────────────────────────────────

    /// Get the FS-level path for a raw fd, if it's a filesystem fd.
    pub(crate) fn fd_path_for_raw(&self, fd: i32) -> Option<alloc::string::String> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return None;
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(typed_fd) => files.fs.fd_path(typed_fd),
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(_) => None, // non-FS descriptor has no filesystem path
                crate::RawFdRef::Eventfd(_) => None, // non-FS descriptor has no filesystem path
                crate::RawFdRef::Epoll(_) => None,   // non-FS descriptor has no filesystem path
                crate::RawFdRef::Unix(_) => None,    // non-FS descriptor has no filesystem path
                crate::RawFdRef::HostPassthroughFd(_) => None, // non-FS descriptor has no filesystem path
                crate::RawFdRef::BrokerPipe(_) => None, // non-FS descriptor has no filesystem path
                crate::RawFdRef::BrokerSocketPair(_)
                | crate::RawFdRef::BrokerSocketDgram(_)
                | crate::RawFdRef::BrokerUnixStream(_)
                | crate::RawFdRef::BrokerSocketSeqPacket(_) => None, // non-FS descriptor has no filesystem path
                crate::RawFdRef::BrokerTcpConn(_) => None, // non-FS descriptor has no filesystem path
                crate::RawFdRef::BrokerPty(_) => None, // non-FS descriptor has no filesystem path
                crate::RawFdRef::Signalfd(_)
                | crate::RawFdRef::Inotify(_)
                | crate::RawFdRef::BrokerInetListener(_)
                | crate::RawFdRef::BrokerInetDgram(_) => None, // non-FS descriptor has no filesystem path,
                crate::RawFdRef::BrokerInetRaw(_) => None, // non-FS descriptor has no filesystem path,
            })
            .ok()
            .flatten()
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        ensure_space_after: bool,
        fd_writable: bool,
        op: impl FnOnce(MutPtr<u8>) -> Result<usize, MappingError>,
    ) -> Result<MutPtr<u8>, MappingError> {
        litebox_common_linux::mm::do_mmap(
            &self.process_state.borrow().pm,
            suggested_addr,
            len,
            prot,
            flags,
            ensure_space_after,
            fd_writable,
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
        self.do_mmap(suggested_addr, len, prot, flags, false, false, op)
    }

    #[allow(clippy::too_many_arguments)]
    fn do_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
        fd_writable: bool,
    ) -> Result<MutPtr<u8>, MappingError> {
        let is_exec = prot.contains(ProtFlags::PROT_EXEC);

        // Perform the normal mmap first (CoW or memcpy fallback).
        let result = if let Some(cow_result) =
            self.try_cow_mmap_file(suggested_addr, len, &prot, &flags, fd, offset, fd_writable)
        {
            cow_result?
        } else {
            self.do_mmap_file_memcpy(suggested_addr, len, prot, flags, fd, offset, fd_writable)?
        };

        // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
        if is_exec {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0 {
                self.maybe_patch_exec_segment(result, len, fd, offset, syscall_entry);
            }
        } else if offset == 0 {
            // First mmap at offset 0: record the base address for later patching.
            self.init_elf_patch_state(fd, result.as_usize());
        }

        Ok(result)
    }

    /// Initialize ELF patch state for an fd on its first mmap at offset 0.
    ///
    /// Reads the ELF header to determine the trampoline address (page-aligned
    /// end of the highest PT_LOAD segment) and checks the file tail for the
    /// trampoline magic to determine if it's pre-patched.
    #[allow(clippy::cast_possible_truncation)]
    fn init_elf_patch_state(&self, fd: i32, base_addr: usize) {
        // Quick check: skip if already initialized.
        {
            let ps = self.process_state.borrow();
            if ps.elf_patch_cache.lock().contains_key(&fd) {
                return;
            }
        }

        // Read the ELF header (first 64 bytes covers both 32-bit and 64-bit).
        let mut ehdr_buf = [0u8; 64];
        if self.sys_read(fd, &mut ehdr_buf, Some(0)).is_err() {
            return; // Not readable, skip
        }

        // Verify ELF magic
        if &ehdr_buf[0..4] != b"\x7fELF" {
            return; // Not an ELF file
        }

        // Parse as 64-bit ELF (runtime patching is x86-64 only).
        // e_phoff at offset 32 (8 bytes), e_phentsize at 54 (2 bytes), e_phnum at 56 (2 bytes)
        let e_phoff = u64::from_le_bytes(ehdr_buf[32..40].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes(ehdr_buf[54..56].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(ehdr_buf[56..58].try_into().unwrap()) as usize;
        let e_type = u16::from_le_bytes(ehdr_buf[16..18].try_into().unwrap());

        // Read program headers to find max PT_LOAD end
        let phdrs_size = e_phentsize * e_phnum;
        if phdrs_size == 0 || phdrs_size > 0x10000 {
            return; // Sanity check
        }
        let mut phdrs_buf = alloc::vec![0u8; phdrs_size];
        if self.sys_read(fd, &mut phdrs_buf, Some(e_phoff)).is_err() {
            return;
        }

        // Find highest PT_LOAD end (p_vaddr + p_memsz)
        let mut max_load_end: u64 = 0;
        for i in 0..e_phnum {
            let ph = &phdrs_buf[i * e_phentsize..][..e_phentsize];
            let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
            if p_type != 1 {
                // PT_LOAD = 1
                continue;
            }
            let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
            let end = p_vaddr + p_memsz;
            if end > max_load_end {
                max_load_end = end;
            }
        }

        if max_load_end == 0 {
            return; // No PT_LOAD segments
        }

        // For ET_DYN (PIE/shared libs), p_vaddr is relative to base_addr.
        // For ET_EXEC, p_vaddr is absolute and base_addr is 0.
        let trampoline_vaddr = if e_type == 3 {
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
            if e_type == 3 {
                base_addr + tramp_vaddr as usize
            } else {
                tramp_vaddr as usize
            }
        } else {
            trampoline_vaddr
        };

        // Insert under lock (re-check for races).
        let ps = self.process_state.borrow();
        let file_path = self.fd_path_for_raw(fd);
        let mut cache = ps.elf_patch_cache.lock();
        let state = cache.entry(fd).or_insert(ElfPatchState {
            _base_addr: base_addr,
            pre_patched,
            trampoline_file_offset: tramp_file_offset,
            trampoline_file_size: tramp_file_size as usize,
            _trampoline_vaddr: tramp_vaddr as usize,
            trampoline_addr: trampoline_vaddr,
            trampoline_cursor: 0,
            trampoline_mapped: false,
            trampoline_mapped_len: 0,
            runtime_patches_committed: false,
            file_path,
        });
        #[cfg(not(feature = "trace_syscalls"))]
        let _ = &state;
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[TRACE-ELF-PATCH] init fd={} path={:?} base={:#x} tramp={:#x} pre_patched={} tramp_file_off={:#x} tramp_file_size={:#x}",
            fd,
            state.file_path,
            base_addr,
            state.trampoline_addr,
            state.pre_patched,
            state.trampoline_file_offset,
            state.trampoline_file_size,
        );
    }

    /// Check if a file has the LITEBOX trampoline magic at its tail.
    /// Returns (is_pre_patched, file_offset, vaddr, trampoline_size).
    fn check_trampoline_magic(&self, fd: i32) -> (bool, u64, u64, u64) {
        let Ok(stat) = self.sys_fstat(fd) else {
            return (false, 0, 0, 0);
        };
        let file_size = stat.st_size;
        if file_size < 32 {
            return (false, 0, 0, 0);
        }
        let mut tail = [0u8; 32];
        if self.sys_read(fd, &mut tail, Some(file_size - 32)).is_err() {
            return (false, 0, 0, 0);
        }
        if &tail[0..8] != litebox_syscall_rewriter::TRAMPOLINE_MAGIC {
            return (false, 0, 0, 0);
        }
        // Parse header: magic(8) | file_offset(8) | vaddr(8) | size(8)
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
    #[allow(clippy::cast_possible_truncation)]
    fn maybe_patch_exec_segment(
        &self,
        mapped_addr: MutPtr<u8>,
        len: usize,
        fd: i32,
        offset: usize,
        syscall_entry: usize,
    ) {
        // Initialize patch state if this is the first mmap for this fd.
        // This handles the case where the first mmap IS the PROT_EXEC one
        // (e.g., MAP_FIXED from the ElfLoader at offset 0).
        if offset == 0 {
            self.init_elf_patch_state(fd, mapped_addr.as_usize());
        }

        let ps = self.process_state.borrow();
        let mut cache = ps.elf_patch_cache.lock();
        let Some(state) = cache.get_mut(&fd) else {
            return; // No patch state — not an ELF we're tracking
        };
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[TRACE-ELF-PATCH] exec fd={} path={:?} map={:#x}-{:#x} offset={:#x} tramp={:#x} tramp_len={:#x} cursor={:#x} pre_patched={}",
            fd,
            state.file_path,
            mapped_addr.as_usize(),
            mapped_addr.as_usize() + len,
            offset,
            state.trampoline_addr,
            state.trampoline_mapped_len,
            state.trampoline_cursor,
            state.pre_patched,
        );

        if state.pre_patched {
            // Pre-patched binary: map the trampoline data from the file.
            // The trampoline contains the rewriting stubs; we just need to
            // map them at the correct address and write the syscall entry.
            if !state.trampoline_mapped && state.trampoline_file_size > 0 {
                let tramp_addr = state.trampoline_addr;
                let tramp_len = align_up(state.trampoline_file_size, PAGE_SIZE);

                // Allocate RW region at the trampoline address.
                let alloc_result = self
                    .do_mmap_anonymous(
                        Some(tramp_addr),
                        tramp_len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    )
                    .or_else(|_| {
                        self.do_mmap_anonymous(
                            Some(tramp_addr),
                            tramp_len,
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                        )
                    });
                let actual_addr = match alloc_result {
                    Ok(ptr) => ptr.as_usize(),
                    Err(_) => return,
                };
                if actual_addr != tramp_addr {
                    let _ = self.sys_munmap(MutPtr::<u8>::from_usize(actual_addr), tramp_len);
                    return;
                }

                // Read trampoline data from the file.
                let mut tramp_data = alloc::vec![0u8; state.trampoline_file_size];
                let file_off = state.trampoline_file_offset as usize;
                let tramp_ptr = MutPtr::<u8>::from_usize(tramp_addr);
                match self.sys_read(fd, &mut tramp_data, Some(file_off)) {
                    Ok(n) if n == tramp_data.len() => {}
                    _ => {
                        let _ = self.sys_munmap(tramp_ptr, tramp_len);
                        return;
                    }
                }

                // Write syscall entry point to the first 8 bytes.
                if tramp_data.len() >= 8 {
                    tramp_data[..8].copy_from_slice(&syscall_entry.to_le_bytes());
                }

                // Write to the mapped region.
                if tramp_ptr.copy_from_slice(0, &tramp_data).is_none() {
                    let _ = self.sys_munmap(tramp_ptr, tramp_len);
                    return;
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
                    return;
                }

                state.trampoline_mapped = true;
                state.trampoline_mapped_len = tramp_len;
            }
            return;
        }

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
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                )
                .or_else(|_| {
                    // Fallback: hint-based allocation (no MAP_FIXED).
                    self.do_mmap_anonymous(
                        Some(tramp_addr),
                        PAGE_SIZE,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    )
                });
            let actual_addr = match actual_addr {
                Ok(ptr) => ptr.as_usize(),
                Err(_) => return,
            };

            // Verify the trampoline is within JMP rel32 range (±2GB) of the code.
            let distance = actual_addr.abs_diff(addr_usize);
            if distance > 0x7FFF_0000 {
                // Too far — unmap and bail.
                let _ = self.sys_munmap(MutPtr::<u8>::from_usize(actual_addr), PAGE_SIZE);
                return;
            }

            state.trampoline_addr = actual_addr;

            // Write the 8-byte syscall entry point at the start.
            let entry_ptr = MutPtr::<u8>::from_usize(actual_addr);
            if entry_ptr
                .copy_from_slice(0, &syscall_entry.to_le_bytes())
                .is_none()
            {
                let _ = self.sys_munmap(MutPtr::<u8>::from_usize(actual_addr), PAGE_SIZE);
                return;
            }
            state.trampoline_cursor = 8; // stubs start after the 8-byte entry
            state.trampoline_mapped = true;
            state.trampoline_mapped_len = PAGE_SIZE;
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

        if state.trampoline_mapped_len > 0
            && self
                .sys_mprotect(
                    MutPtr::<u8>::from_usize(state.trampoline_addr),
                    state.trampoline_mapped_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )
                .is_err()
        {
            return;
        }

        // Make the code segment writable for in-place patching.
        if self
            .sys_mprotect(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .is_err()
        {
            return;
        }

        // Read the mapped code into a buffer, patch it, write back.
        let Some(code_owned) = mapped_addr.to_owned_slice(len) else {
            // Restore permissions and bail.
            let _ = self.sys_mprotect(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            );
            restore_trampoline_rx(self, state);
            return;
        };
        let mut code_buf = code_owned.into_vec();
        let original_code = code_buf.clone();

        let code_vaddr = addr_usize as u64;
        let trampoline_write_vaddr = (state.trampoline_addr + state.trampoline_cursor) as u64;
        let syscall_entry_addr = state.trampoline_addr as u64; // entry at offset 0

        let mut skipped_addrs = alloc::vec::Vec::new();
        let patch_result = litebox_syscall_rewriter::patch_code_segment(
            &mut code_buf,
            code_vaddr,
            trampoline_write_vaddr,
            syscall_entry_addr,
            &mut skipped_addrs,
        );
        if !skipped_addrs.is_empty() {
            litebox::log_println!(
                self.global.platform,
                "warning: {} syscall instruction(s) in {:?} could not be patched (addresses: {:?})",
                skipped_addrs.len(),
                state.file_path,
                skipped_addrs,
            );
        }
        match patch_result {
            Ok(stubs) if !stubs.is_empty() => {
                let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
                    let _ = self.sys_mprotect(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    return;
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
                            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                        )
                        .is_err()
                    {
                        let _ = self.sys_mprotect(
                            mapped_addr,
                            len,
                            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                        );
                        restore_trampoline_rx(self, state);
                        return;
                    }
                    state.trampoline_mapped_len = tramp_pages_needed;
                }

                // Write stubs before patching the code so rewritten jumps never
                // target an uninitialized trampoline.
                let tramp_write_ptr =
                    MutPtr::<u8>::from_usize(state.trampoline_addr + state.trampoline_cursor);
                if tramp_write_ptr.copy_from_slice(0, &stubs).is_none() {
                    let _ = self.sys_mprotect(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    return;
                }

                // Write patched code back to the mapped region.
                if mapped_addr.copy_from_slice(0, &code_buf).is_none() {
                    let _ = mapped_addr.copy_from_slice(0, &original_code);
                    let _ = self.sys_mprotect(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    return;
                }
                state.trampoline_cursor = new_cursor;
                state.runtime_patches_committed = true;
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE-ELF-PATCH] updated fd={} path={:?} tramp={:#x} tramp_len={:#x} cursor={:#x}",
                    fd,
                    state.file_path,
                    state.trampoline_addr,
                    state.trampoline_mapped_len,
                    state.trampoline_cursor,
                );
            }
            Ok(_) => {
                // No syscalls found — no patching needed.
            }
            Err(e) => {
                #[cfg(not(feature = "trace_syscalls"))]
                let _ = &e;
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE-ELF-PATCH] failed fd={} path={:?} map={:#x}-{:#x} error={}",
                    fd,
                    state.file_path,
                    mapped_addr.as_usize(),
                    mapped_addr.as_usize() + len,
                    e,
                );
                let _ = self.sys_mprotect(
                    mapped_addr,
                    len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                );
                restore_trampoline_rx(self, state);
                return;
            }
        }

        // Restore the code segment to RX.
        let _ = self.sys_mprotect(
            mapped_addr,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        );
        restore_trampoline_rx(self, state);
    }

    /// Finalize the ELF patching state for `fd`.
    ///
    /// If the fd has a trampoline region that was allocated (RW), mprotect it
    /// to RX so the trampoline stubs become executable and non-writable.
    /// The cache entry is removed regardless.
    pub(crate) fn finalize_elf_patch(&self, fd: i32) {
        let ps = self.process_state.borrow();
        let state = ps.elf_patch_cache.lock().remove(&fd);
        drop(ps);
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

                // Push the program break past the trampoline so that brk
                // growth does not collide with the now-RX trampoline pages.
                // The pre-patched loader path does this in loader.rs
                // (load_trampoline), but the runtime path must do it here
                // only when the trampoline actually sits at the heap frontier.
                //
                // Shared objects (e.g. native Node addons) can be patched at
                // high unrelated addresses; advancing the logical brk to those
                // trampoline pages would create a huge unmapped hole in the
                // heap and break later brk() growth.
                let tramp_end = state.trampoline_addr + tramp_len;
                let ps = self.process_state.borrow();
                let brk_before = ps.pm.current_brk();
                let frontier_before = ps.pm.current_brk_frontier();
                let should_push_brk = brk_before != 0
                    && state.trampoline_addr <= frontier_before
                    && brk_before < tramp_end;
                if should_push_brk {
                    ps.pm.ensure_brk_past(tramp_end);
                }
            }
        }
    }

    /// Attempt to create a CoW mapping for a file with static backing data.
    ///
    /// Returns `Some(result)` if CoW was attempted (success or failure),
    /// `None` if CoW is not applicable (fall back to memcpy).
    // TODO(jb): does this need to be Option-Result or can it just be Option?
    #[allow(clippy::too_many_arguments)]
    fn try_cow_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: &ProtFlags,
        flags: &MapFlags,
        fd: i32,
        offset: usize,
        fd_writable: bool,
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
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(typed_fd) => files.fs.get_static_backing_data(typed_fd),
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::Eventfd(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::Epoll(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::Unix(_) => None,  // CoW fast path only supports FS static backing
                crate::RawFdRef::HostPassthroughFd(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::BrokerPipe(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::BrokerSocketPair(_)
                | crate::RawFdRef::BrokerSocketDgram(_)
                | crate::RawFdRef::BrokerUnixStream(_)
                | crate::RawFdRef::BrokerSocketSeqPacket(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::BrokerTcpConn(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::BrokerPty(_) => None, // CoW fast path only supports FS static backing
                crate::RawFdRef::Signalfd(_)
                | crate::RawFdRef::Inotify(_)
                | crate::RawFdRef::BrokerInetListener(_)
                | crate::RawFdRef::BrokerInetDgram(_) => None, // CoW fast path only supports FS static backing,
                crate::RawFdRef::BrokerInetRaw(_) => None, // CoW fast path only supports FS static backing,
            })
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
                    self.process_state.borrow().pm.register_existing_mapping(
                        range,
                        permissions,
                        true,
                        fixed_behavior == FixedAddressBehavior::Replace,
                        flags.contains(MapFlags::MAP_SHARED),
                        fd_writable,
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
    #[allow(clippy::too_many_arguments)]
    fn do_mmap_file_memcpy(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
        fd_writable: bool,
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
                let remaining = len - copied;
                let size = self
                    .sys_read(
                        fd,
                        &mut buffer[..remaining.min(PAGE_SIZE)],
                        Some(file_offset),
                    )
                    .map_err(|e| match e {
                        Errno::EBADF => MappingError::BadFD(fd),
                        Errno::EISDIR => MappingError::NotAFile,
                        Errno::EACCES => MappingError::NotForReading,
                        _ => unimplemented!(),
                    })?;
                if size == 0 {
                    break;
                }
                self.park_if_deferred();
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
            fd_writable,
            op,
        )
    }

    /// Handle syscall `mmap`
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        len: usize,
        prot: ProtFlags,
        mut flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<MutPtr<u8>, Errno> {
        self.reject_shared_vfork_vm_mutation("mmap")?;
        // check alignment
        if !offset.is_multiple_of(PAGE_SIZE) || !addr.is_multiple_of(PAGE_SIZE) || len == 0 {
            return Err(Errno::EINVAL);
        }

        // MAP_SHARED file-backed mappings are executed with MAP_PRIVATE
        // semantics (the sandbox has no kernel page cache for 9P files).
        // We track the mapping so that `sys_munmap` can write back the dirty
        // data to the underlying file, making tools like LLD (which write
        // output via mmap + munmap) work correctly.
        let is_shared_file =
            flags.contains(MapFlags::MAP_SHARED) && !flags.contains(MapFlags::MAP_ANONYMOUS);

        if flags.contains(MapFlags::MAP_SYNC) {
            if flags.contains(MapFlags::MAP_ANONYMOUS) {
                if flags.contains(MapFlags::MAP_SHARED_VALIDATE) {
                    log_unsupported!("mmap MAP_SYNC with MAP_SHARED_VALIDATE|MAP_ANONYMOUS");
                    return Err(Errno::EINVAL);
                }
                flags.remove(MapFlags::MAP_SYNC);
            } else {
                self.validate_file_backed_mmap_fd(fd)?;
                log_unsupported!("mmap MAP_SYNC");
                return Err(Errno::EOPNOTSUPP);
            }
        }

        if flags.intersects(
            MapFlags::MAP_GROWSDOWN
                | MapFlags::MAP_HUGETLB
                | MapFlags::MAP_HUGE_2MB
                | MapFlags::MAP_HUGE_1GB,
        ) {
            log_unsupported!("mmap flags {:?}", flags);
            return Err(Errno::EINVAL);
        }
        if flags.contains(MapFlags::MAP_NONBLOCK) && !flags.contains(MapFlags::MAP_ANONYMOUS) {
            log_unsupported!("mmap MAP_NONBLOCK for file-backed mapping");
            return Err(Errno::EINVAL);
        }
        if flags.contains(MapFlags::MAP_32BIT)
            && !flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE)
            && self.process_state.borrow().pm.addr_min() >= 0x8000_0000
        {
            // This process's managed VA partition does not intersect Linux's
            // low-2G MAP_32BIT range, so there is no representable result.
            return Err(Errno::ENOMEM);
        }

        let aligned_len = align_up(len, PAGE_SIZE);
        if aligned_len == 0 {
            return Err(Errno::ENOMEM);
        }
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        let suggested_addr = if addr == 0 { None } else { Some(addr) };

        // For shared file-backed mappings, create an internal file handle and
        // probe whether the fd is writable. Only writable fds get writeback
        // tracking and VM_MAYWRITE on the VMA; read-only fds remain
        // restricted so `mprotect(PROT_WRITE)` correctly fails.
        let (internal_handle, fd_writable) = if is_shared_file {
            let handle = self.duplicate_internal_fs_fd(fd)?;
            let writable = self.internal_fs_is_writable(&*handle);
            if writable {
                (Some(handle), true)
            } else {
                self.internal_fs_close(handle);
                (None, false)
            }
        } else {
            (None, false)
        };

        // MAP_FIXED replaces any existing mapping in the target range.
        // Snapshot overlapping MAP_SHARED tracking data while pages are still
        // live; the actual writeback and tracking removal happen only after a
        // successful mmap (so a failed mmap leaves tracking intact).
        let fixed_snapshots = if flags.contains(MapFlags::MAP_FIXED)
            && let Some(suggested) = suggested_addr
        {
            self.snapshot_shared_mappings(suggested, aligned_len)
        } else {
            alloc::vec::Vec::new()
        };

        let prot_write = prot.contains(ProtFlags::PROT_WRITE);

        let result = if flags.contains(MapFlags::MAP_ANONYMOUS) {
            self.do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
        } else {
            self.do_mmap_file(
                suggested_addr,
                aligned_len,
                prot,
                flags,
                fd,
                offset,
                fd_writable,
            )
        };

        let mapped_addr = match result {
            Ok(addr) => addr,
            Err(e) => {
                // Discard snapshots — tracking entries are still intact.
                for (handle, _, _) in fixed_snapshots {
                    self.internal_fs_close(handle);
                }
                // Clean up the internal handle if mmap itself failed.
                if let Some(handle) = internal_handle {
                    self.internal_fs_close(handle);
                }
                return Err(Errno::from(e));
            }
        };

        // MAP_FIXED succeeded: write back displaced mapping data and remove
        // their tracking entries.
        if !fixed_snapshots.is_empty() {
            for (handle, file_offset, data) in &fixed_snapshots {
                let mut written = 0;
                while written < data.len() {
                    match self.internal_fs_write(
                        &**handle,
                        &data[written..],
                        Some(*file_offset + written),
                    ) {
                        Ok(n) => written += n,
                        Err(_) => break,
                    }
                }
            }
            for (handle, _, _) in fixed_snapshots {
                self.internal_fs_close(handle);
            }
            // Remove tracking entries for the displaced range.
            // The snapshot handles were temporary duplicates; the original
            // tracking handles are closed by remove_shared_tracking.
            self.remove_shared_tracking(suggested_addr.unwrap(), aligned_len);
        }

        // Record the mapping for writeback on munmap/exit/exec.
        if let Some(handle) = internal_handle {
            self.process_state
                .borrow()
                .shared_file_mappings
                .lock()
                .push(SharedFileMapping {
                    addr: mapped_addr.as_usize(),
                    len: aligned_len,
                    internal_fd: handle,
                    file_offset: offset,
                    needs_writeback: prot_write,
                });
        }

        Ok(mapped_addr)
    }

    /// Write back dirty data from `MAP_SHARED` file-backed mappings that
    /// overlap `[unmap_start, unmap_start + unmap_len)`, then remove their
    /// tracking entries. Must be called **before** the pages are deallocated.
    fn writeback_shared_mappings(&self, unmap_start: usize, unmap_len: usize) {
        let unmap_end = unmap_start + unmap_len;
        let ps = self.process_state.borrow();
        let mut mappings = ps.shared_file_mappings.lock();

        // Collect handles to close after releasing the mappings lock.
        let mut to_close: alloc::vec::Vec<InternalHandle> = alloc::vec::Vec::new();

        // Drain entries that overlap the unmapped range.
        let mut i = 0;
        while i < mappings.len() {
            let m = &mappings[i];
            let m_end = m.addr + m.len;

            // No overlap → skip.
            if m.addr >= unmap_end || m_end <= unmap_start {
                i += 1;
                continue;
            }

            // Compute the overlapping region.
            let wb_start = m.addr.max(unmap_start);
            let wb_end = m_end.min(unmap_end);
            let wb_file_offset = m.file_offset + (wb_start - m.addr);
            let wb_len = wb_end - wb_start;

            // Only write back if the mapping was ever writable (and thus
            // potentially dirty). Read-only mappings are tracked for
            // potential mprotect upgrades but contain unmodified CoW pages.
            if m.needs_writeback {
                let mut written = 0;
                while written < wb_len {
                    let chunk = (wb_len - written).min(PAGE_SIZE);
                    if let Some(buf) = read_for_writeback(&ps.pm, wb_start + written, chunk) {
                        let file_off = wb_file_offset + written;
                        match self.internal_fs_write(&*m.internal_fd, &buf, Some(file_off)) {
                            Ok(n) => written += n,
                            Err(_) => break,
                        }
                    } else {
                        break;
                    }
                }
            }

            // If the unmap covers the entire mapping, remove it.
            if unmap_start <= m.addr && unmap_end >= m_end {
                let removed = mappings.swap_remove(i);
                to_close.push(removed.internal_fd);
                // Don't increment i — swap_remove moved the last element here.
            } else {
                // Partial unmap: split the entry. The original handle goes to
                // the first fragment; additional fragments get new duplicates.
                let orig = mappings.remove(i);
                let orig_addr = orig.addr;
                let orig_file_offset = orig.file_offset;
                let orig_needs_wb = orig.needs_writeback;

                let need_left = orig_addr < unmap_start;
                let need_right = m_end > unmap_end;

                if need_left && need_right {
                    // Two fragments: left gets original handle, right gets dup.
                    let right_handle = self.duplicate_internal_handle(&*orig.internal_fd);
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: orig_addr,
                            len: unmap_start - orig_addr,
                            internal_fd: orig.internal_fd,
                            file_offset: orig_file_offset,
                            needs_writeback: orig_needs_wb,
                        },
                    );
                    i += 1;
                    if let Ok(rh) = right_handle {
                        mappings.insert(
                            i,
                            SharedFileMapping {
                                addr: unmap_end,
                                len: m_end - unmap_end,
                                internal_fd: rh,
                                file_offset: orig_file_offset + (unmap_end - orig_addr),
                                needs_writeback: orig_needs_wb,
                            },
                        );
                        i += 1;
                    }
                } else if need_left {
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: orig_addr,
                            len: unmap_start - orig_addr,
                            internal_fd: orig.internal_fd,
                            file_offset: orig_file_offset,
                            needs_writeback: orig_needs_wb,
                        },
                    );
                    i += 1;
                } else if need_right {
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: unmap_end,
                            len: m_end - unmap_end,
                            internal_fd: orig.internal_fd,
                            file_offset: orig_file_offset + (unmap_end - orig_addr),
                            needs_writeback: orig_needs_wb,
                        },
                    );
                    i += 1;
                } else {
                    to_close.push(orig.internal_fd);
                }
            }
        }

        // Release the mappings lock before closing handles (close takes the
        // DT write lock; holding both is safe but releasing early is cleaner).
        drop(mappings);
        drop(ps);
        for handle in to_close {
            self.internal_fs_close(handle);
        }
    }

    /// Remove and close tracking entries that overlap `[start, start + len)`
    /// **without** reading from the mapped pages. Used after MAP_FIXED
    /// replacement, where the pages have already been replaced and the data
    /// was previously snapshotted.
    fn remove_shared_tracking(&self, start: usize, len: usize) {
        let end = start + len;
        let ps = self.process_state.borrow();
        let mut mappings = ps.shared_file_mappings.lock();
        let mut to_close: alloc::vec::Vec<InternalHandle> = alloc::vec::Vec::new();

        let mut i = 0;
        while i < mappings.len() {
            let m = &mappings[i];
            let m_end = m.addr + m.len;

            if m.addr >= end || m_end <= start {
                i += 1;
                continue;
            }

            // Fully covered → remove.
            if start <= m.addr && end >= m_end {
                let removed = mappings.swap_remove(i);
                to_close.push(removed.internal_fd);
            } else {
                let orig = mappings.remove(i);
                let orig_addr = orig.addr;
                let orig_file_offset = orig.file_offset;
                let orig_needs_wb = orig.needs_writeback;
                let need_left = orig_addr < start;
                let need_right = m_end > end;

                if need_left && need_right {
                    let right_handle = self.duplicate_internal_handle(&*orig.internal_fd);
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: orig_addr,
                            len: start - orig_addr,
                            internal_fd: orig.internal_fd,
                            file_offset: orig_file_offset,
                            needs_writeback: orig_needs_wb,
                        },
                    );
                    i += 1;
                    if let Ok(rh) = right_handle {
                        mappings.insert(
                            i,
                            SharedFileMapping {
                                addr: end,
                                len: m_end - end,
                                internal_fd: rh,
                                file_offset: orig_file_offset + (end - orig_addr),
                                needs_writeback: orig_needs_wb,
                            },
                        );
                        i += 1;
                    }
                } else if need_left {
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: orig_addr,
                            len: start - orig_addr,
                            internal_fd: orig.internal_fd,
                            file_offset: orig_file_offset,
                            needs_writeback: orig_needs_wb,
                        },
                    );
                    i += 1;
                } else if need_right {
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: end,
                            len: m_end - end,
                            internal_fd: orig.internal_fd,
                            file_offset: orig_file_offset + (end - orig_addr),
                            needs_writeback: orig_needs_wb,
                        },
                    );
                    i += 1;
                } else {
                    to_close.push(orig.internal_fd);
                }
            }
        }

        drop(mappings);
        drop(ps);
        for handle in to_close {
            self.internal_fs_close(handle);
        }
    }

    /// Write back and close **all** tracked `MAP_SHARED` file-backed mappings.
    /// Called before `release_memory()` on exit and exec so dirty data is not
    /// silently dropped.
    pub(crate) fn flush_all_shared_mappings(&self) {
        let ps = self.process_state.borrow();
        let mut mappings = ps.shared_file_mappings.lock();

        // Write back all fragments that were ever writable.
        for m in mappings.iter() {
            if !m.needs_writeback {
                continue;
            }
            let mut written = 0;
            while written < m.len {
                let chunk = (m.len - written).min(PAGE_SIZE);
                if let Some(buf) = read_for_writeback(&ps.pm, m.addr + written, chunk) {
                    let file_off = m.file_offset + written;
                    match self.internal_fs_write(&*m.internal_fd, &buf, Some(file_off)) {
                        Ok(n) => written += n,
                        Err(_) => break,
                    }
                } else {
                    break;
                }
            }
        }

        // Drain all entries and collect handles for closing.
        let handles: alloc::vec::Vec<_> = mappings.drain(..).map(|m| m.internal_fd).collect();
        drop(mappings);
        drop(ps);

        // Close each handle (each is independent — no shared-fd concern).
        for handle in handles {
            self.internal_fs_close(handle);
        }
    }

    /// Write back all tracked `MAP_SHARED` file-backed mappings without
    /// removing tracking entries or closing handles.
    ///
    /// Used in the shared-fork (vfork) path: the child flushes dirty data
    /// while still sharing the parent's `ProcessState`, so the parent's
    /// tracking and handles must remain intact for future use. The parent's
    /// CoW restore will revert the in-memory pages after this flush, but the
    /// file will already have the child's writes.
    pub(crate) fn sync_all_shared_mappings(&self) {
        let ps = self.process_state.borrow();
        let mappings = ps.shared_file_mappings.lock();

        for m in mappings.iter() {
            if !m.needs_writeback {
                continue;
            }
            let mut written = 0;
            while written < m.len {
                let chunk = (m.len - written).min(PAGE_SIZE);
                if let Some(buf) = read_for_writeback(&ps.pm, m.addr + written, chunk) {
                    let file_off = m.file_offset + written;
                    match self.internal_fs_write(&*m.internal_fd, &buf, Some(file_off)) {
                        Ok(n) => written += n,
                        Err(_) => break,
                    }
                } else {
                    break;
                }
            }
        }
    }

    fn sync_shared_mappings_in_range(&self, start: usize, len: usize) {
        let end = start + len;
        let ps = self.process_state.borrow();
        let mappings = ps.shared_file_mappings.lock();

        for m in mappings.iter() {
            if !m.needs_writeback {
                continue;
            }
            let m_end = m.addr + m.len;
            let wb_start = start.max(m.addr);
            let wb_end = end.min(m_end);
            if wb_start >= wb_end {
                continue;
            }

            let mut written = 0usize;
            let wb_len = wb_end - wb_start;
            while written < wb_len {
                let chunk = (wb_len - written).min(PAGE_SIZE);
                if let Some(buf) = read_for_writeback(&ps.pm, wb_start + written, chunk) {
                    let file_off = m.file_offset + (wb_start - m.addr) + written;
                    match self.internal_fs_write(&*m.internal_fd, &buf, Some(file_off)) {
                        Ok(n) => written += n,
                        Err(_) => break,
                    }
                } else {
                    break;
                }
            }
        }
    }

    /// Handle syscall `msync`
    pub(crate) fn sys_msync(
        &self,
        addr: crate::MutPtr<u8>,
        len: usize,
        flags: i32,
    ) -> Result<(), Errno> {
        const MS_ASYNC: i32 = 1;
        const MS_INVALIDATE: i32 = 2;
        const MS_SYNC: i32 = 4;
        const SUPPORTED_FLAGS: i32 = MS_ASYNC | MS_INVALIDATE | MS_SYNC;

        if !addr.as_usize().is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if flags & !SUPPORTED_FLAGS != 0 || (flags & MS_ASYNC != 0 && flags & MS_SYNC != 0) {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Ok(());
        }
        let Some(aligned_len) = len.checked_add(PAGE_SIZE - 1).map(|v| v & !(PAGE_SIZE - 1)) else {
            return Err(Errno::EINVAL);
        };
        let Some(end) = addr.as_usize().checked_add(aligned_len) else {
            return Err(Errno::EINVAL);
        };

        let ps = self.process_state.borrow();
        let mappings = ps.pm.mappings();
        let mut cursor = addr.as_usize();
        while cursor < end {
            let Some((range, _)) = mappings
                .iter()
                .find(|(range, _)| range.start <= cursor && cursor < range.end)
            else {
                return Err(Errno::ENOMEM);
            };
            cursor = range.end.min(end);
        }
        drop(mappings);
        drop(ps);

        self.sync_shared_mappings_in_range(addr.as_usize(), aligned_len);
        Ok(())
    }

    /// Handle syscall `munmap`
    pub(crate) fn sys_munmap(&self, addr: crate::MutPtr<u8>, len: usize) -> Result<(), Errno> {
        self.reject_shared_vfork_vm_mutation("munmap")?;
        if len == 0 || !addr.as_usize().is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        let aligned_len = align_up(len, PAGE_SIZE);
        if addr.as_usize().checked_add(aligned_len).is_none() {
            return Err(Errno::EINVAL);
        }

        // Write back any MAP_SHARED file-backed data before deallocating pages.
        self.writeback_shared_mappings(addr.as_usize(), aligned_len);

        litebox_common_linux::mm::sys_munmap(&self.process_state.borrow().pm, addr, aligned_len)
    }

    /// Handle syscall `mprotect`
    ///
    /// CoW-aware: if a vfork child adds WRITE permission to CoW-protected
    /// pages, snapshot them first so the parent's original content can be
    /// restored after the child execs or exits. Other parent threads are
    /// parked during the vfork window and cannot reach here.
    pub(crate) fn sys_mprotect(
        &self,
        addr: crate::MutPtr<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        self.reject_shared_vfork_vm_mutation("mprotect")?;
        if prot.contains(ProtFlags::PROT_WRITE)
            && let Some(cow) = self.top_cow_layer()
        {
            let req_start = addr.as_usize();
            let req_end = req_start + len;

            let mut dirty = cow.dirty_pages.lock();
            for &(base, plen, _) in &cow.protected_ranges {
                let prot_end = base + plen;
                if req_start < prot_end && req_end > base {
                    let overlap_start = req_start.max(base);
                    let overlap_end = req_end.min(prot_end);
                    for page_addr in
                        (overlap_start & !(PAGE_SIZE - 1)..overlap_end).step_by(PAGE_SIZE)
                    {
                        if dirty.contains_key(&page_addr) {
                            continue;
                        }
                        let mut buf = alloc::vec![0u8; PAGE_SIZE];
                        // SAFETY: page is mapped (CoW-protected).
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                page_addr as *const u8,
                                buf.as_mut_ptr(),
                                PAGE_SIZE,
                            );
                        }
                        dirty.insert(page_addr, buf);
                    }
                }
            }
        }
        let adding_write = prot.contains(ProtFlags::PROT_WRITE);
        litebox_common_linux::mm::sys_mprotect(&self.process_state.borrow().pm, addr, len, prot)?;

        // When PROT_WRITE is added to a range that overlaps a tracked
        // MAP_SHARED file-backed mapping, mark the overlapping sub-range as
        // needing writeback. We split entries so that only the portion made
        // writable is flagged — this avoids writing back stale CoW pages
        // from ranges that were never writable.
        if adding_write {
            let ps = self.process_state.borrow();
            let mut mappings = ps.shared_file_mappings.lock();
            let prot_start = addr.as_usize();
            let prot_end = prot_start + align_up(len, PAGE_SIZE);

            let mut i = 0;
            while i < mappings.len() {
                let m = &mappings[i];
                let m_end = m.addr + m.len;

                // Skip non-overlapping or already-dirty entries.
                if m.needs_writeback || m.addr >= prot_end || m_end <= prot_start {
                    i += 1;
                    continue;
                }

                // Fully covered → just flip the flag, no split needed.
                if prot_start <= m.addr && prot_end >= m_end {
                    mappings[i].needs_writeback = true;
                    i += 1;
                    continue;
                }

                // Partial overlap → split into up to 3 fragments.
                let orig = mappings.remove(i);
                let orig_addr = orig.addr;
                let orig_file_offset = orig.file_offset;

                let need_left = orig_addr < prot_start;
                let need_right = m_end > prot_end;

                // Determine how many fragments need a handle.
                // Left (clean) + middle (dirty) + right (clean).
                let fragment_count = usize::from(need_left) + 1 + usize::from(need_right);
                let mut handles = alloc::vec::Vec::with_capacity(fragment_count);
                handles.push(orig.internal_fd);
                for _ in 1..fragment_count {
                    if let Ok(h) = self.duplicate_internal_handle(&*handles[0]) {
                        handles.push(h);
                    }
                }
                let mut h_iter = handles.into_iter();

                if need_left && let Some(handle) = h_iter.next() {
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: orig_addr,
                            len: prot_start - orig_addr,
                            internal_fd: handle,
                            file_offset: orig_file_offset,
                            needs_writeback: false,
                        },
                    );
                    i += 1;
                }

                // Middle fragment: the portion being made writable.
                let mid_start = orig_addr.max(prot_start);
                let mid_end = m_end.min(prot_end);
                if let Some(handle) = h_iter.next() {
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: mid_start,
                            len: mid_end - mid_start,
                            internal_fd: handle,
                            file_offset: orig_file_offset + (mid_start - orig_addr),
                            needs_writeback: true,
                        },
                    );
                    i += 1;
                }

                if need_right && let Some(handle) = h_iter.next() {
                    mappings.insert(
                        i,
                        SharedFileMapping {
                            addr: prot_end,
                            len: m_end - prot_end,
                            internal_fd: handle,
                            file_offset: orig_file_offset + (prot_end - orig_addr),
                            needs_writeback: false,
                        },
                    );
                    i += 1;
                }

                // Close any leftover handles (defensive).
                for leftover in h_iter {
                    self.internal_fs_close(leftover);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn sys_mremap(
        &self,
        old_addr: crate::MutPtr<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    ) -> Result<crate::MutPtr<u8>, Errno> {
        self.reject_shared_vfork_vm_mutation("mremap")?;
        // Replicate the common layer's cheap O(1) validation checks so that
        // obviously-invalid requests are rejected before we allocate a
        // potentially large tail snapshot buffer.
        let valid_flags =
            MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_MAYMOVE | MRemapFlags::MREMAP_DONTUNMAP;
        if flags.intersects(valid_flags.complement()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MRemapFlags::MREMAP_FIXED) && !flags.contains(MRemapFlags::MREMAP_MAYMOVE)
        {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MRemapFlags::MREMAP_DONTUNMAP)
            && (!flags.contains(MRemapFlags::MREMAP_MAYMOVE) || old_size != new_size)
        {
            return Err(Errno::EINVAL);
        }
        let old_start = old_addr.as_usize();
        if !old_start.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        // The common layer aligns sizes down to PAGE_SIZE; mirror that here.
        let old_aligned = align_down(old_size, PAGE_SIZE);
        let new_aligned = align_down(new_size, PAGE_SIZE);
        if new_aligned == 0 {
            return Err(Errno::EINVAL);
        }

        // If shrinking, snapshot dirty tail data while pages are still live.
        // After the remap the tail pages are freed (anonymous memory), so we
        // capture them now and only write back if the remap succeeds.
        // Each snapshot gets a temporary DT duplicate so we can write back
        // after releasing the mappings lock.
        let tail_snapshots = if new_aligned < old_aligned {
            self.snapshot_shared_mappings(old_start + new_aligned, old_aligned - new_aligned)
        } else {
            alloc::vec::Vec::new()
        };

        // Perform the remap — validates parameters and deallocates/moves pages.
        let result = match litebox_common_linux::mm::sys_mremap(
            &self.process_state.borrow().pm,
            old_addr,
            old_size,
            new_size,
            flags,
            new_addr,
        ) {
            Ok(r) => r,
            Err(e) => {
                // Clean up temporary snapshot handles on failure.
                for (handle, _, _) in tail_snapshots {
                    self.internal_fs_close(handle);
                }
                return Err(e);
            }
        };

        // Write back the snapshotted tail data now that the remap succeeded.
        for (handle, file_offset, data) in &tail_snapshots {
            let mut written = 0;
            while written < data.len() {
                match self.internal_fs_write(
                    &**handle,
                    &data[written..],
                    Some(*file_offset + written),
                ) {
                    Ok(n) => written += n,
                    Err(_) => break,
                }
            }
        }
        // Close the temporary snapshot handles.
        for (handle, _, _) in tail_snapshots {
            self.internal_fs_close(handle);
        }

        // Update tracking: relocate, split, and remove entries as needed.
        let new_start = result.as_usize();
        self.update_shared_tracking_for_remap(old_start, old_aligned, new_start, new_aligned);

        Ok(result)
    }

    /// Snapshot data from tracked `MAP_SHARED` mappings overlapping
    /// `[start, start+len)`.
    ///
    /// Returns `(temporary_handle, file_offset, owned_data)` tuples. Each
    /// temporary handle is a DT duplicate of the mapping's internal fd so
    /// it can be used after the mappings lock is released. The caller must
    /// close these handles when done.
    fn snapshot_shared_mappings(
        &self,
        start: usize,
        len: usize,
    ) -> alloc::vec::Vec<(InternalHandle, usize, alloc::boxed::Box<[u8]>)> {
        if len == 0 {
            return alloc::vec::Vec::new();
        }
        let end = start + len;
        let ps = self.process_state.borrow();
        let mappings = ps.shared_file_mappings.lock();
        let mut snapshots = alloc::vec::Vec::new();

        for m in mappings.iter() {
            let m_end = m.addr + m.len;
            if m.addr >= end || m_end <= start || !m.needs_writeback {
                continue;
            }
            let wb_start = m.addr.max(start);
            let wb_end = m_end.min(end);
            let wb_file_offset = m.file_offset + (wb_start - m.addr);
            let wb_len = wb_end - wb_start;

            // Try fast path: read the entire overlap at once.
            let src = crate::ConstPtr::<u8>::from_usize(wb_start);
            let data = if let Some(data) = src.to_owned_slice(wb_len) {
                data
            } else {
                // Slow path: some pages may be PROT_NONE. Read page by page
                // so that read_for_writeback only touches individual pages
                // (avoiding a bulk permission change on a mixed-permission range).
                let mut buf = alloc::vec![0u8; wb_len];
                let mut ok = true;
                let mut offset = 0;
                while offset < wb_len {
                    let chunk = (wb_len - offset).min(PAGE_SIZE);
                    if let Some(page) = read_for_writeback(&ps.pm, wb_start + offset, chunk) {
                        buf[offset..offset + chunk].copy_from_slice(&page);
                        offset += chunk;
                    } else {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    continue;
                }
                buf.into_boxed_slice()
            };

            // Create a temporary DT duplicate for this snapshot.
            if let Ok(temp_handle) = self.duplicate_internal_handle(&*m.internal_fd) {
                snapshots.push((temp_handle, wb_file_offset, data));
            }
        }

        snapshots
    }

    /// Update shared mapping tracking after a successful `mremap`.
    ///
    /// Handles relocation (move), shrinking (tail removal), and subrange
    /// remaps (splitting tracking entries that partially overlap the remapped
    /// range).
    fn update_shared_tracking_for_remap(
        &self,
        old_start: usize,
        old_aligned: usize,
        new_start: usize,
        new_aligned: usize,
    ) {
        if old_aligned == 0 {
            return;
        }
        let old_end = old_start + old_aligned;
        let ps = self.process_state.borrow();
        let mut mappings = ps.shared_file_mappings.lock();

        let mut replacements: alloc::vec::Vec<SharedFileMapping> = alloc::vec::Vec::new();
        let mut to_close: alloc::vec::Vec<InternalHandle> = alloc::vec::Vec::new();
        let mut i = 0;

        while i < mappings.len() {
            let m = &mappings[i];
            let m_end = m.addr + m.len;

            if m_end <= old_start || m.addr >= old_end {
                i += 1;
                continue;
            }

            let orig = mappings.swap_remove(i);
            let orig_addr = orig.addr;
            let orig_end = orig_addr + orig.len;
            let orig_file_offset = orig.file_offset;
            let orig_needs_wb = orig.needs_writeback;

            // Count how many replacement fragments need this handle.
            let need_left = orig_addr < old_start;
            let overlap_start = orig_addr.max(old_start);
            let overlap_end = orig_end.min(old_end);
            let delta = overlap_start - old_start;
            let need_overlap = delta < new_aligned && {
                let kept = (overlap_end - overlap_start).min(new_aligned - delta);
                kept > 0
            };
            let need_right = orig_end > old_end;

            // Determine which fragment gets the original handle and which
            // get new duplicates. Priority: first fragment gets original.
            let fragment_count =
                usize::from(need_left) + usize::from(need_overlap) + usize::from(need_right);

            if fragment_count == 0 {
                to_close.push(orig.internal_fd);
            } else {
                // Distribute handles: first fragment gets the original,
                // subsequent fragments get duplicates.
                let mut handles = alloc::vec::Vec::with_capacity(fragment_count);
                handles.push(orig.internal_fd); // original for first fragment
                for _ in 1..fragment_count {
                    if let Ok(h) = self.duplicate_internal_handle(&*handles[0]) {
                        handles.push(h);
                    }
                }
                let mut h_iter = handles.into_iter();

                if need_left && let Some(handle) = h_iter.next() {
                    replacements.push(SharedFileMapping {
                        addr: orig_addr,
                        len: old_start - orig_addr,
                        internal_fd: handle,
                        file_offset: orig_file_offset,
                        needs_writeback: orig_needs_wb,
                    });
                }

                if need_overlap {
                    let kept_len = (overlap_end - overlap_start).min(new_aligned - delta);
                    if let Some(handle) = h_iter.next() {
                        replacements.push(SharedFileMapping {
                            addr: new_start + delta,
                            len: kept_len,
                            internal_fd: handle,
                            file_offset: orig_file_offset + (overlap_start - orig_addr),
                            needs_writeback: orig_needs_wb,
                        });
                    }
                }

                if need_right && let Some(handle) = h_iter.next() {
                    replacements.push(SharedFileMapping {
                        addr: old_end,
                        len: orig_end - old_end,
                        internal_fd: handle,
                        file_offset: orig_file_offset + (old_end - orig_addr),
                        needs_writeback: orig_needs_wb,
                    });
                }

                // Close any leftover handles (shouldn't happen, but defensive).
                for leftover in h_iter {
                    to_close.push(leftover);
                }
            }

            // Don't increment i — swap_remove moved the last element here.
        }

        mappings.extend(replacements);
        drop(mappings);
        drop(ps);

        for handle in to_close {
            self.internal_fs_close(handle);
        }
    }

    /// Handle syscall `brk`
    pub(crate) fn sys_brk(&self, addr: MutPtr<u8>) -> Result<usize, Errno> {
        self.reject_shared_vfork_vm_mutation("brk")?;
        litebox_common_linux::mm::sys_brk(&self.process_state.borrow().pm, addr)
    }

    /// Handle syscall `madvise`
    #[inline]
    pub(crate) fn sys_madvise(
        &self,
        addr: MutPtr<u8>,
        len: usize,
        advice: litebox_common_linux::MadviseBehavior,
    ) -> Result<(), Errno> {
        if matches!(
            advice,
            litebox_common_linux::MadviseBehavior::DontNeed
                | litebox_common_linux::MadviseBehavior::DontNeedLocked
                | litebox_common_linux::MadviseBehavior::Free
        ) {
            self.reject_shared_vfork_vm_mutation("madvise")?;
        }
        litebox_common_linux::mm::sys_madvise(&self.process_state.borrow().pm, addr, len, advice)
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
    fn test_anonymous_mmap_rwx() {
        let task = init_platform(None);

        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ_WRITE_EXEC,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();
        addr.write_slice_at_offset(0, &[0xaa; 0x10]).unwrap();
        assert_eq!(addr.read_at_offset(0).unwrap(), 0xaa,);
        task.sys_munmap(addr, 0x1000).unwrap();
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
        // With partitioned VA ranges, the guest range may be much smaller than the host's
        // preferred mmap range, so we use MAP_FIXED_NOREPLACE with a hint inside the guest range.
        let pm_min = task.process_state.borrow().pm.addr_min();
        let pm_max = task.process_state.borrow().pm.addr_max();
        let mut search_addr = pm_min + 0x1000_0000; // start 256 MiB into the partition
        let addr = loop {
            if search_addr >= pm_max {
                // Could not find a suitable address — skip the test.
                return;
            }
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
                // Use MAP_FIXED_NOREPLACE at a specific address within the guest range
                // so we get a host allocation that the guest PM doesn't know about.
                let addr = unsafe {
                    libc::mmap(
                        search_addr as *mut libc::c_void,
                        0x10_000,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    )
                } as usize;
                if addr == usize::MAX {
                    // MAP_FIXED_NOREPLACE failed (address occupied), try next page.
                    search_addr += 0x10_000;
                    continue;
                }
                data.push(alloc::vec::Vec::<u8>::from(unsafe {
                    core::slice::from_raw_parts(addr as *const u8, 0x10_000)
                }));
                search_addr = addr + 0x10_000; // advance for next iteration if needed
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

        // Create and write the file.
        let content = b"Hello, shared!";
        let fd = task
            .sys_open("shared.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_write(fd, content, None).unwrap(), content.len());
        task.sys_close(fd).unwrap();

        // Re-open read-only — mprotect(PROT_WRITE) must fail.
        let fd = task
            .sys_open("shared.txt", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let fd = i32::try_from(fd).unwrap();

        // MAP_SHARED with PROT_READ on a file should succeed
        let addr = task
            .sys_mmap(0, 0x1000, ProtFlags::PROT_READ, MapFlags::MAP_SHARED, fd, 0)
            .unwrap();

        // Data should match
        assert_eq!(
            addr.to_owned_slice(content.len()).unwrap().as_ref(),
            content.as_slice(),
        );

        // mprotect to add write permission should fail (fd is read-only)
        let err = task
            .sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);

        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_msync_shared_file_mapping() {
        let task = init_platform(None);

        let fd = task
            .sys_open("shared-msync.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        let initial = [0u8; 0x1000];
        assert_eq!(task.sys_write(fd, &initial, None).unwrap(), initial.len());
        task.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToBeginning)
            .unwrap();

        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                fd,
                0,
            )
            .unwrap();

        addr.write_slice_at_offset(0, b"hello").unwrap();
        task.sys_msync(addr, 0x1000, 4).unwrap();

        task.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToBeginning)
            .unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(task.sys_read(fd, &mut buf, None).unwrap(), buf.len());
        assert_eq!(&buf, b"hello");

        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_mmap_anonymous_ignores_map_sync() {
        let task = init_platform(None);

        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON | MapFlags::MAP_SYNC,
                -1,
                0,
            )
            .unwrap();
        task.sys_munmap(addr, 0x1000).unwrap();
    }

    #[test]
    fn test_mmap_file_map_sync_returns_eopnotsupp() {
        let task = init_platform(None);

        let fd = task
            .sys_open(
                "shared-map-sync.txt",
                OFlags::RDWR | OFlags::CREAT,
                Mode::RWXU,
            )
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        let initial = [0u8; 0x1000];
        assert_eq!(task.sys_write(fd, &initial, None).unwrap(), initial.len());
        task.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToBeginning)
            .unwrap();

        assert_eq!(
            task.sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED | MapFlags::MAP_SYNC,
                fd,
                0,
            )
            .unwrap_err(),
            Errno::EOPNOTSUPP
        );
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_mmap_shared_validate_anon_map_sync_returns_einval() {
        let task = init_platform(None);

        assert_eq!(
            task.sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED_VALIDATE | MapFlags::MAP_ANON | MapFlags::MAP_SYNC,
                -1,
                0,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn test_mmap_file_map_sync_invalid_fd_returns_ebadf() {
        let task = init_platform(None);

        assert_eq!(
            task.sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_SYNC,
                -1,
                0,
            )
            .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn test_mmap_growsdown_returns_einval() {
        let task = init_platform(None);

        assert_eq!(
            task.sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON | MapFlags::MAP_GROWSDOWN,
                -1,
                0,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn test_mmap_accepts_locked_and_nonblock_flags() {
        let task = init_platform(None);

        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE
                    | MapFlags::MAP_ANON
                    | MapFlags::MAP_LOCKED
                    | MapFlags::MAP_POPULATE
                    | MapFlags::MAP_NONBLOCK,
                -1,
                0,
            )
            .unwrap();

        task.sys_munmap(addr, 0x1000).unwrap();
    }

    #[test]
    fn test_mmap_file_nonblock_returns_einval() {
        let task = init_platform(None);

        let fd = task
            .sys_open("nonblock-map.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        let initial = [0u8; 0x1000];
        assert_eq!(task.sys_write(fd, &initial, None).unwrap(), initial.len());

        assert_eq!(
            task.sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_NONBLOCK,
                fd,
                0,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
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

        // Advisory-only hints should succeed even when the sandbox does not
        // implement their optional kernel-side bookkeeping.
        assert!(
            task.sys_madvise(
                addr,
                0x2000,
                litebox_common_linux::MadviseBehavior::DontDump
            )
            .is_ok()
        );
        assert!(
            task.sys_madvise(addr, 0x2000, litebox_common_linux::MadviseBehavior::DoDump)
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

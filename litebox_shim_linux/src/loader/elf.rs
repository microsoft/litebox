// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox

use alloc::{
    ffi::CString,
    string::{String, ToString as _},
    vec::Vec,
};
use core::mem::size_of;
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{CreatePagesFlags, MappingError, PAGE_SIZE, PageRange},
    platform::{
        RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _,
        page_mgmt::MemoryRegionPermissions,
    },
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::{
    MapFlags,
    errno::Errno,
    loader::{ElfParsedFile, MapMemory as _, ReadAt as _},
};
use thiserror::Error;

use crate::{
    MutPtr,
    loader::auxv::{AuxKey, AuxVec},
};

use super::stack::UserStack;
use crate::{ShimFS, Task};

// An opened elf file
struct ElfFile<'a, FS: ShimFS> {
    task: &'a Task<FS>,
    fd: i32,
    /// When `true`, [`reserve`](litebox_common_linux::loader::MapMemory::reserve)
    /// places this image at the top of the address space (top-down)
    /// instead of at [`PIE_LOAD_OFFSET`](super::PIE_LOAD_OFFSET). Set for
    /// the ELF interpreter so it does not cap a low-loaded ET_EXEC main's
    /// brk heap.
    load_high: bool,
}

impl<'a, FS: ShimFS> ElfFile<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, Errno> {
        let fd = task
            .sys_open(
                path,
                OFlags::RDONLY | OFlags::LITEBOX_NO_ELF_PATCH,
                Mode::empty(),
            )?
            .reinterpret_as_signed();
        Ok(ElfFile {
            task,
            fd,
            load_high: false,
        })
    }
}

impl<FS: ShimFS> Drop for ElfFile<'_, FS> {
    fn drop(&mut self) {
        // Fork/exec fd-bridge restore can repurpose the temporary loader fd slot
        // before this guard drops; the descriptor table entry has still been
        // transferred to its intended guest fd, so EBADF is benign here.
        // (Phase E.2 independently rediscovered this via cross-worker PTY exec.)
        if let Err(err) = self.task.sys_close(self.fd)
            && err != Errno::EBADF
        {
            panic!("failed to close fd: {err:?}");
        }
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::ReadAt for &'_ ElfFile<'_, FS> {
    type Error = Errno;

    fn read_at(&mut self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            // Try to read the remaining bytes
            let bytes_read = self.task.sys_read(self.fd, buf, Some(offset.truncate()))?;
            if bytes_read == 0 {
                // reached the end of the file
                return Err(Errno::ENODATA);
            } else {
                // Successfully read some bytes
                buf = &mut buf[bytes_read..];
                offset += bytes_read as u64;
            }
        }
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.task.sys_fstat(self.fd)?.st_size as u64)
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::MapMemory for ElfFile<'_, FS> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        let hint = {
            let process_state = self.task.process_state.borrow();
            if self.load_high {
                // Load the ELF interpreter at the top of the address
                // space (top-down), mirroring how the kernel places
                // `ld.so` for an ET_EXEC main. Hinting at `addr_max()` is
                // out of range, so `sys_mmap` falls through to its
                // top-down search — the same path a PIE main's
                // interpreter already takes when the `PIE_LOAD_OFFSET`
                // slot is occupied. This keeps the gap above a
                // low-loaded ET_EXEC main free for the brk heap to grow
                // into, instead of capping it at `PIE_LOAD_OFFSET`.
                process_state.pm.addr_max()
            } else {
                // Start PIE binaries at a fixed offset into the partition
                // so that the low addresses remain unmapped
                // (NULL-dereference guard region).
                process_state.pm.addr_min() + super::PIE_LOAD_OFFSET
            }
        };

        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let mapping_ptr = self
            .task
            .sys_mmap(
                hint,
                mapping_len,
                litebox_common_linux::ProtFlags::PROT_NONE,
                litebox_common_linux::MapFlags::MAP_ANONYMOUS
                    | litebox_common_linux::MapFlags::MAP_PRIVATE,
                -1,
                0,
            )?
            .as_usize();

        let ptr = mapping_ptr.next_multiple_of(align);
        let end = ptr + len;
        let mapping_end = mapping_ptr + mapping_len;
        // `mmap(2)` and `munmap(2)` operate at page granularity. `len` (the
        // ELF's `max_vaddr - min_vaddr` span) is in general NOT page-aligned
        // — e.g. node.js's prebuilt linux-x64 binary has a span of 0x6403D68
        // (104,911,080 bytes), so `end` ends mid-page. Calling munmap with a
        // non-page-aligned start address fails with EINVAL on Linux, which
        // surfaced as `execve` ↦ ENOEXEC for any guest fork+exec of node.
        //
        // The kernel's mmap call rounds the allocation up to a whole number
        // of pages, so the *actual* mapped region is
        // [mapping_ptr, mapping_end.next_multiple_of(PAGE_SIZE)). The head
        // munmap is naturally page-aligned (mapping_ptr is page-aligned and
        // align ≥ PAGE_SIZE), so it stays as-is. The tail munmap is
        // recomputed in page units: release everything from the first page
        // strictly after `end` to the actual end of the mapping.
        let tail_start = end.next_multiple_of(PAGE_SIZE);
        let tail_end = mapping_end.next_multiple_of(PAGE_SIZE);
        if ptr != mapping_ptr {
            self.task
                .sys_munmap(MutPtr::from_usize(mapping_ptr), ptr - mapping_ptr)?;
        }
        if tail_start < tail_end {
            self.task
                .sys_munmap(MutPtr::from_usize(tail_start), tail_end - tail_start)?;
        }
        Ok(ptr)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            self.fd,
            offset.truncate(),
        )?;
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            -1,
            0,
        )?;
        Ok(())
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let addr = crate::MutPtr::<u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// A [`MapMemory`] wrapper that reads file-backed data from an in-memory buffer
/// instead of from a file descriptor. Used when the loader has patched the ELF
/// binary on the fly (e.g. syscall rewriting of the dynamic linker).
///
/// `reserve`, `map_zero`, and `protect` are delegated to the underlying
/// [`ElfFile`]; `map_file` is replaced by `map_zero` + a memory copy from the
/// patched buffer.
struct PatchedMapper<'a, 'b, FS: ShimFS> {
    inner: &'b mut ElfFile<'a, FS>,
    data: &'b [u8],
}

struct HostFileMapper<'a, 'b, FS: ShimFS> {
    inner: &'b mut ElfFile<'a, FS>,
    path: &'b str,
}

impl<FS: ShimFS> litebox_common_linux::loader::MapMemory for PatchedMapper<'_, '_, FS> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        self.inner.reserve(len, align)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        // Allocate anonymous pages, copy from the in-memory buffer, then apply
        // the requested protection.
        let result = self.inner.map_zero(
            address,
            len,
            &litebox_common_linux::loader::Protection {
                read: true,
                write: true,
                execute: false,
            },
        );
        #[cfg(feature = "trace_syscalls")]
        if let Err(err) = &result {
            litebox::log_println!(
                self.inner.task.global.platform,
                "[TRACE-EXEC-BIAS] patched map_zero addr={:#x} len={:#x} err={:?}",
                address,
                len,
                err,
            );
        }
        result?;

        let offset: usize = offset.truncate();
        if offset < self.data.len() {
            let end = core::cmp::min(offset + len, self.data.len());
            let src = &self.data[offset..end];
            let dest = MutPtr::<u8>::from_usize(address);
            dest.copy_from_slice(0, src).ok_or(Errno::EFAULT)?;
        }

        // Set final permissions if different from the writable mapping above.
        if !prot.write || prot.execute {
            let result = self.inner.protect(address, len, prot);
            #[cfg(feature = "trace_syscalls")]
            if let Err(err) = &result {
                litebox::log_println!(
                    self.inner.task.global.platform,
                    "[TRACE-EXEC-BIAS] patched protect addr={:#x} len={:#x} r={} w={} x={} err={:?}",
                    address,
                    len,
                    prot.read,
                    prot.write,
                    prot.execute,
                    err,
                );
            }
            result?;
        }
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let result = self.inner.map_zero(address, len, prot);
        #[cfg(feature = "trace_syscalls")]
        if let Err(err) = &result {
            litebox::log_println!(
                self.inner.task.global.platform,
                "[TRACE-EXEC-BIAS] direct map_zero addr={:#x} len={:#x} r={} w={} x={} err={:?}",
                address,
                len,
                prot.read,
                prot.write,
                prot.execute,
                err,
            );
        }
        result
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let result = self.inner.protect(address, len, prot);
        #[cfg(feature = "trace_syscalls")]
        if let Err(err) = &result {
            litebox::log_println!(
                self.inner.task.global.platform,
                "[TRACE-EXEC-BIAS] direct protect addr={:#x} len={:#x} r={} w={} x={} err={:?}",
                address,
                len,
                prot.read,
                prot.write,
                prot.execute,
                err,
            );
        }
        result
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::MapMemory for HostFileMapper<'_, '_, FS> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        self.inner.reserve(len, align)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let resolved = self.inner.task.resolve_exe_path(self.path);
        let mapped = self
            .inner
            .task
            .global
            .platform
            .mmap_host_file(&resolved, address, len, prot.flags(), offset.truncate())
            .map_err(|()| Errno::EFAULT)?;
        if mapped != address {
            return Err(Errno::ENOMEM);
        }

        let mut permissions = MemoryRegionPermissions::empty();
        permissions.set(MemoryRegionPermissions::READ, prot.read);
        permissions.set(MemoryRegionPermissions::WRITE, prot.write);
        permissions.set(MemoryRegionPermissions::EXEC, prot.execute);
        let range = PageRange::new(address, address.checked_add(len).ok_or(Errno::ENOMEM)?)
            .ok_or(Errno::ENOMEM)?;
        // SAFETY: mmap_host_file just installed a MAP_FIXED file mapping for exactly this range
        // with the permissions computed above.
        unsafe {
            self.inner
                .task
                .process_state
                .borrow()
                .pm
                .register_existing_mapping(range, permissions, true, true, false, false)
        }
        .ok_or(Errno::ENOMEM)?;
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.inner.map_zero(address, len, prot)
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.inner.protect(address, len, prot)
    }
}

/// Struct to hold the information needed to start the program
/// (entry point and user stack top).
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub user_stack_top: usize,
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a, FS: ShimFS> {
    path: &'a str,
    main: FileAndParsed<'a, FS>,
    interp: Option<FileAndParsed<'a, FS>>,
}

struct FileAndParsed<'a, FS: ShimFS> {
    path: String,
    file: ElfFile<'a, FS>,
    parsed: ElfParsedFile,
    /// When the rewriter backend is active and the binary was not pre-patched,
    /// the loader patches it on the fly and loads from this in-memory copy.
    patched_data: Option<Vec<u8>>,
    needs_syscall_patch: bool,
    host_mmap_large: bool,
    exec_bias_applied: bool,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct Elf64ProgramHeader {
    offset: usize,
    p_type: u32,
    p_offset: usize,
    p_vaddr: usize,
    p_paddr: usize,
    p_filesz: usize,
    _p_memsz: usize,
}

#[cfg(target_arch = "x86_64")]
struct Elf64ExecLayout {
    phdrs: Vec<Elf64ProgramHeader>,
    dynamic: Option<Elf64ProgramHeader>,
    entry: usize,
    min_vaddr: usize,
    max_vaddr: usize,
    align: usize,
}

#[cfg(target_arch = "x86_64")]
impl Elf64ExecLayout {
    fn span_len(&self) -> usize {
        self.max_vaddr - self.min_vaddr
    }

    fn contains(&self, value: usize) -> bool {
        (self.min_vaddr..self.max_vaddr).contains(&value)
    }
}

#[cfg(target_arch = "x86_64")]
fn invalid_program_header() -> ElfLoaderError {
    ElfLoaderError::LoadError(litebox_common_linux::loader::ElfLoadError::InvalidProgramHeader)
}

#[cfg(target_arch = "x86_64")]
fn read_bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ElfLoaderError> {
    data.get(offset..offset + N)
        .ok_or_else(invalid_program_header)?
        .try_into()
        .map_err(|_| invalid_program_header())
}

#[cfg(target_arch = "x86_64")]
fn read_u16(data: &[u8], offset: usize) -> Result<u16, ElfLoaderError> {
    Ok(u16::from_le_bytes(read_bytes::<2>(data, offset)?))
}

#[cfg(target_arch = "x86_64")]
fn read_u32(data: &[u8], offset: usize) -> Result<u32, ElfLoaderError> {
    Ok(u32::from_le_bytes(read_bytes::<4>(data, offset)?))
}

#[cfg(target_arch = "x86_64")]
fn read_u64(data: &[u8], offset: usize) -> Result<u64, ElfLoaderError> {
    Ok(u64::from_le_bytes(read_bytes::<8>(data, offset)?))
}

#[cfg(target_arch = "x86_64")]
fn read_i64(data: &[u8], offset: usize) -> Result<i64, ElfLoaderError> {
    Ok(i64::from_le_bytes(read_bytes::<8>(data, offset)?))
}

#[cfg(target_arch = "x86_64")]
fn write_u64(data: &mut [u8], offset: usize, value: usize) -> Result<(), ElfLoaderError> {
    data.get_mut(offset..offset + 8)
        .ok_or_else(invalid_program_header)?
        .copy_from_slice(&(value as u64).to_le_bytes());
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn write_i64(data: &mut [u8], offset: usize, value: usize) -> Result<(), ElfLoaderError> {
    let value = i64::try_from(value).map_err(|_| invalid_program_header())?;
    data.get_mut(offset..offset + 8)
        .ok_or_else(invalid_program_header)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn patch_elf64_relocation_entries(
    data: &mut [u8],
    layout: &Elf64ExecLayout,
    add_bias: &impl Fn(usize) -> Result<usize, ElfLoaderError>,
    table_offset: usize,
    table_size: usize,
    entry_size: usize,
    has_addend: bool,
) -> Result<(), ElfLoaderError> {
    const R_X86_64_RELATIVE: u32 = 8;
    const R_X86_64_IRELATIVE: u32 = 37;

    let table_end = table_offset
        .checked_add(table_size)
        .ok_or_else(invalid_program_header)?;
    if entry_size == 0 || !table_size.is_multiple_of(entry_size) || table_end > data.len() {
        return Err(invalid_program_header());
    }

    for index in 0..(table_size / entry_size) {
        let entry_offset = table_offset
            .checked_add(index * entry_size)
            .ok_or_else(invalid_program_header)?;
        let r_offset = read_u64(data, entry_offset)?.truncate();
        if layout.contains(r_offset) {
            write_u64(data, entry_offset, add_bias(r_offset)?)?;
        }
        let r_info = read_u64(data, entry_offset + 8)?;
        let r_type = u32::try_from(r_info & 0xffff_ffff).map_err(|_| invalid_program_header())?;
        if !matches!(r_type, R_X86_64_RELATIVE | R_X86_64_IRELATIVE) {
            continue;
        }
        if has_addend {
            let r_addend = read_i64(data, entry_offset + 16)?;
            if r_addend < 0 {
                continue;
            }
            let addend = usize::try_from(r_addend).map_err(|_| invalid_program_header())?;
            if layout.contains(addend) {
                write_i64(data, entry_offset + 16, add_bias(addend)?)?;
            }
            continue;
        }
        if !layout.contains(r_offset) {
            continue;
        }
        let target_offset = vaddr_to_file_offset(layout, r_offset)?;
        let value = read_u64(data, target_offset)?.truncate();
        if layout.contains(value) {
            write_u64(data, target_offset, add_bias(value)?)?;
        }
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn parse_elf64_exec_layout(data: &[u8]) -> Result<Elf64ExecLayout, ElfLoaderError> {
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const TRAMPOLINE_HEADER_SIZE: usize = 32;
    if data.get(0..4) != Some(&b"\x7fELF"[..]) || data.get(4) != Some(&2) || data.get(5) != Some(&1)
    {
        return Err(invalid_program_header());
    }
    let e_phoff: usize = read_u64(data, 32)?
        .try_into()
        .map_err(|_| invalid_program_header())?;
    let entry: usize = read_u64(data, 24)?
        .try_into()
        .map_err(|_| invalid_program_header())?;
    let e_phentsize = usize::from(read_u16(data, 54)?);
    let e_phnum = usize::from(read_u16(data, 56)?);
    if e_phentsize < 56 || e_phnum == 0 {
        return Err(invalid_program_header());
    }
    let phdr_bytes = e_phentsize
        .checked_mul(e_phnum)
        .and_then(|size| e_phoff.checked_add(size))
        .ok_or_else(invalid_program_header)?;
    if phdr_bytes > data.len() {
        return Err(invalid_program_header());
    }

    let mut phdrs = Vec::with_capacity(e_phnum);
    let mut dynamic = None;
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;
    let mut align = PAGE_SIZE;
    for i in 0..e_phnum {
        let offset = e_phoff + i * e_phentsize;
        let p_type = read_u32(data, offset)?;
        let p_offset: usize = read_u64(data, offset + 8)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let p_vaddr: usize = read_u64(data, offset + 16)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let phys_addr: usize = read_u64(data, offset + 24)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let p_filesz: usize = read_u64(data, offset + 32)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let p_memsz: usize = read_u64(data, offset + 40)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let p_align: usize = read_u64(data, offset + 48)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let phdr = Elf64ProgramHeader {
            offset,
            p_type,
            p_offset,
            p_vaddr,
            p_paddr: phys_addr,
            p_filesz,
            _p_memsz: p_memsz,
        };
        if p_type == PT_LOAD {
            min_vaddr = min_vaddr.min(p_vaddr);
            max_vaddr = max_vaddr.max(
                p_vaddr
                    .checked_add(p_memsz)
                    .ok_or_else(invalid_program_header)?,
            );
            if p_align.is_power_of_two() {
                align = align.max(p_align);
            }
        } else if p_type == PT_DYNAMIC {
            dynamic = Some(phdr);
        }
        phdrs.push(phdr);
    }
    if min_vaddr >= max_vaddr {
        return Err(invalid_program_header());
    }
    if data.len() >= TRAMPOLINE_HEADER_SIZE
        && data[data.len() - TRAMPOLINE_HEADER_SIZE..data.len() - TRAMPOLINE_HEADER_SIZE + 8]
            == b"LITEBOX0"[..]
    {
        let trampoline_vaddr: usize = read_u64(data, data.len() - 16)?.truncate();
        let trampoline_size: usize = read_u64(data, data.len() - 8)?.truncate();
        max_vaddr = max_vaddr.max(
            trampoline_vaddr
                .checked_add(trampoline_size)
                .ok_or_else(invalid_program_header)?,
        );
    }
    Ok(Elf64ExecLayout {
        phdrs,
        dynamic,
        entry,
        min_vaddr,
        max_vaddr,
        align,
    })
}

#[cfg(target_arch = "x86_64")]
fn vaddr_to_file_offset(layout: &Elf64ExecLayout, vaddr: usize) -> Result<usize, ElfLoaderError> {
    for phdr in &layout.phdrs {
        if phdr.p_type != 1 {
            continue;
        }
        let Some(file_end) = phdr.p_vaddr.checked_add(phdr.p_filesz) else {
            continue;
        };
        if (phdr.p_vaddr..file_end).contains(&vaddr) {
            return phdr
                .p_offset
                .checked_add(vaddr - phdr.p_vaddr)
                .ok_or_else(invalid_program_header);
        }
    }
    Err(invalid_program_header())
}

#[cfg(target_arch = "x86_64")]
fn patch_elf64_exec_image_with_bias(
    data: &mut [u8],
    layout: &Elf64ExecLayout,
    bias: u64,
    platform: &impl litebox::platform::DebugLogProvider,
) -> Result<(), ElfLoaderError> {
    const DT_PLTRELSZ: i64 = 2;
    const DT_PLTGOT: i64 = 3;
    const DT_HASH: i64 = 4;
    const DT_STRTAB: i64 = 5;
    const DT_SYMTAB: i64 = 6;
    const DT_RELA: i64 = 7;
    const DT_RELASZ: i64 = 8;
    const DT_RELAENT: i64 = 9;
    const DT_SYMENT: i64 = 11;
    const DT_INIT: i64 = 12;
    const DT_FINI: i64 = 13;
    const DT_REL: i64 = 17;
    const DT_RELSZ: i64 = 18;
    const DT_RELENT: i64 = 19;
    const DT_JMPREL: i64 = 23;
    const DT_INIT_ARRAY: i64 = 25;
    const DT_FINI_ARRAY: i64 = 26;
    const DT_INIT_ARRAYSZ: i64 = 27;
    const DT_FINI_ARRAYSZ: i64 = 28;
    const DT_PREINIT_ARRAY: i64 = 32;
    const DT_PREINIT_ARRAYSZ: i64 = 33;
    const DT_GNU_HASH: i64 = 0x6fff_fef5;
    const DT_VERSYM: i64 = 0x6fff_fff0;
    const DT_VERDEF: i64 = 0x6fff_fffc;
    const DT_VERNEED: i64 = 0x6fff_fffe;
    const SHF_WRITE: u64 = 0x1;
    const SHF_ALLOC: u64 = 0x2;
    const SHF_EXECINSTR: u64 = 0x4;
    const SHT_RELA: u32 = 4;
    const SHT_REL: u32 = 9;
    const SHT_NOBITS: u32 = 8;
    const TRAMPOLINE_HEADER_SIZE: usize = 32;

    let _ = platform;
    let bias = usize::try_from(bias).map_err(|_| invalid_program_header())?;

    let add_bias = |value: usize| -> Result<usize, ElfLoaderError> {
        if layout.contains(value) {
            value.checked_add(bias).ok_or_else(invalid_program_header)
        } else {
            Ok(value)
        }
    };

    write_u64(data, 24, add_bias(read_u64(data, 24)?.truncate())?)?;

    // Non-PIE glibc crt1 on x86_64 commonly loads `main` with
    // `mov $imm32, %rdi` in `_start` before calling `__libc_start_main`.
    // That encoding cannot represent a rebased address above 4 GiB. When we
    // bias ET_EXEC into a higher VA slot, rewrite the instruction to the
    // same-length RIP-relative `lea main(%rip), %rdi`.
    if layout.contains(layout.entry) {
        let entry_offset = vaddr_to_file_offset(layout, layout.entry)?;
        let scan_end = entry_offset
            .checked_add(64)
            .ok_or_else(invalid_program_header)?
            .min(data.len());
        let mut cursor = entry_offset;
        while cursor + 13 <= scan_end {
            let window = &mut data[cursor..cursor + 13];
            if window[0] == 0x48
                && window[1] == 0xc7
                && window[2] == 0xc7
                && window[7] == 0xff
                && window[8] == 0x15
            {
                let imm =
                    <[u8; 4]>::try_from(&window[3..7]).map_err(|_| invalid_program_header())?;
                let main = usize::try_from(u32::from_le_bytes(imm))
                    .map_err(|_| invalid_program_header())?;
                if layout.contains(main) {
                    let instr_vaddr = layout
                        .entry
                        .checked_add(cursor - entry_offset)
                        .ok_or_else(invalid_program_header)?;
                    let biased_instr = add_bias(instr_vaddr)?;
                    let biased_main = add_bias(main)?;
                    let next_ip = biased_instr
                        .checked_add(7)
                        .ok_or_else(invalid_program_header)?;
                    let disp = i64::try_from(biased_main).map_err(|_| invalid_program_header())?
                        - i64::try_from(next_ip).map_err(|_| invalid_program_header())?;
                    let disp32 = i32::try_from(disp).map_err(|_| invalid_program_header())?;
                    window[1] = 0x8d;
                    window[2] = 0x3d;
                    window[3..7].copy_from_slice(&disp32.to_le_bytes());
                    #[cfg(feature = "trace_syscalls")]
                    litebox::log_println!(
                        platform,
                        "[ELF-LOAD] rewrote _start main pointer entry={:#x} instr={:#x} main={:#x} biased_main={:#x}",
                        layout.entry,
                        instr_vaddr,
                        main,
                        biased_main,
                    );
                    break;
                }
            }
            cursor += 1;
        }
    }

    for phdr in &layout.phdrs {
        if phdr.p_vaddr != 0 {
            write_u64(data, phdr.offset + 16, add_bias(phdr.p_vaddr)?)?;
        }
        if phdr.p_paddr != 0 {
            write_u64(data, phdr.offset + 24, add_bias(phdr.p_paddr)?)?;
        }
    }

    let mut dyn_entries = Vec::new();
    if let Some(dynamic) = layout.dynamic {
        let dyn_len = dynamic
            .p_offset
            .checked_add(dynamic.p_filesz)
            .ok_or_else(invalid_program_header)?;
        if dyn_len > data.len() || dynamic.p_filesz % 16 != 0 {
            return Err(invalid_program_header());
        }
        for idx in 0..(dynamic.p_filesz / 16) {
            let entry_offset = dynamic.p_offset + idx * 16;
            let tag = read_i64(data, entry_offset)?;
            let value = read_u64(data, entry_offset + 8)?.truncate();
            dyn_entries.push((tag, value));
            if matches!(
                tag,
                DT_PLTGOT
                    | DT_HASH
                    | DT_STRTAB
                    | DT_SYMTAB
                    | DT_RELA
                    | DT_REL
                    | DT_JMPREL
                    | DT_INIT
                    | DT_FINI
                    | DT_INIT_ARRAY
                    | DT_FINI_ARRAY
                    | DT_PREINIT_ARRAY
                    | DT_GNU_HASH
                    | DT_VERSYM
                    | DT_VERDEF
                    | DT_VERNEED
            ) {
                write_u64(data, entry_offset + 8, add_bias(value)?)?;
            }
        }
    }

    let dyn_value = |tag: i64| {
        dyn_entries
            .iter()
            .find(|(entry_tag, _)| *entry_tag == tag)
            .map(|(_, value)| *value)
    };

    for (array_tag, size_tag) in [
        (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
        (DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
        (DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
    ] {
        let Some(array_addr) = dyn_value(array_tag) else {
            continue;
        };
        let Some(array_size) = dyn_value(size_tag) else {
            continue;
        };
        let array_offset = vaddr_to_file_offset(layout, array_addr)?;
        for item in (0..array_size).step_by(size_of::<u64>()) {
            let value_offset = array_offset
                .checked_add(item)
                .ok_or_else(invalid_program_header)?;
            write_u64(
                data,
                value_offset,
                add_bias(read_u64(data, value_offset)?.truncate())?,
            )?;
        }
    }

    if let (Some(symtab_addr), Some(strtab_addr), Some(sym_ent)) = (
        dyn_value(DT_SYMTAB),
        dyn_value(DT_STRTAB),
        dyn_value(DT_SYMENT),
    ) && strtab_addr > symtab_addr
        && sym_ent >= size_of::<u64>() * 2
    {
        let symtab_offset = vaddr_to_file_offset(layout, symtab_addr)?;
        let sym_count = (strtab_addr - symtab_addr) / sym_ent;
        for index in 0..sym_count {
            let symbol_offset = symtab_offset
                .checked_add(index * sym_ent)
                .ok_or_else(invalid_program_header)?;
            let shndx = read_u16(data, symbol_offset + 6)?;
            let value = read_u64(data, symbol_offset + 8)?.truncate();
            if shndx != 0 && layout.contains(value) {
                write_u64(data, symbol_offset + 8, add_bias(value)?)?;
            }
        }
    }

    for (rela_tag, rela_size, rela_ent, has_addend) in [
        (
            DT_RELA,
            dyn_value(DT_RELASZ),
            dyn_value(DT_RELAENT).unwrap_or(24),
            true,
        ),
        (
            DT_REL,
            dyn_value(DT_RELSZ),
            dyn_value(DT_RELENT).unwrap_or(16),
            false,
        ),
        (
            DT_JMPREL,
            dyn_value(DT_PLTRELSZ),
            dyn_value(DT_RELAENT).unwrap_or(24),
            true,
        ),
    ] {
        let Some(rela_addr) = dyn_value(rela_tag) else {
            continue;
        };
        let Some(rela_bytes) = rela_size else {
            continue;
        };
        let rela_offset = vaddr_to_file_offset(layout, rela_addr)?;
        patch_elf64_relocation_entries(
            data,
            layout,
            &add_bias,
            rela_offset,
            rela_bytes,
            rela_ent,
            has_addend,
        )?;
    }

    let e_shoff: usize = read_u64(data, 40)?
        .try_into()
        .map_err(|_| invalid_program_header())?;
    let e_shentsize = usize::from(read_u16(data, 58)?);
    let e_shnum = usize::from(read_u16(data, 60)?);
    let e_shstrndx = usize::from(read_u16(data, 62)?);
    if e_shoff != 0 && e_shentsize >= 64 && e_shnum != 0 && e_shstrndx < e_shnum {
        let shdr_bytes = e_shoff
            .checked_add(
                e_shentsize
                    .checked_mul(e_shnum)
                    .ok_or_else(invalid_program_header)?,
            )
            .ok_or_else(invalid_program_header)?;
        if shdr_bytes > data.len() {
            return Err(invalid_program_header());
        }
        let shstr_offset = e_shoff + e_shentsize * e_shstrndx;
        let shstr_data_offset: usize = read_u64(data, shstr_offset + 24)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let shstr_size: usize = read_u64(data, shstr_offset + 32)?
            .try_into()
            .map_err(|_| invalid_program_header())?;
        let shstr_end = shstr_data_offset
            .checked_add(shstr_size)
            .ok_or_else(invalid_program_header)?;
        let shstr = data
            .get(shstr_data_offset..shstr_end)
            .ok_or_else(invalid_program_header)?
            .to_vec();
        for index in 0..e_shnum {
            let sh_offset = e_shoff + e_shentsize * index;
            let name_offset = usize::try_from(read_u32(data, sh_offset)?)
                .map_err(|_| invalid_program_header())?;
            let sh_type = read_u32(data, sh_offset + 4)?;
            let sh_flags = read_u64(data, sh_offset + 8)?;
            let sh_addr: usize = read_u64(data, sh_offset + 16)?
                .try_into()
                .map_err(|_| invalid_program_header())?;
            let sh_file_offset: usize = read_u64(data, sh_offset + 24)?
                .try_into()
                .map_err(|_| invalid_program_header())?;
            let sh_size: usize = read_u64(data, sh_offset + 32)?
                .try_into()
                .map_err(|_| invalid_program_header())?;
            let sh_entsize: usize = read_u64(data, sh_offset + 56)?
                .try_into()
                .map_err(|_| invalid_program_header())?;
            if layout.dynamic.is_none() && matches!(sh_type, SHT_RELA | SHT_REL) {
                patch_elf64_relocation_entries(
                    data,
                    layout,
                    &add_bias,
                    sh_file_offset,
                    sh_size,
                    if sh_entsize != 0 {
                        sh_entsize
                    } else if sh_type == SHT_RELA {
                        24
                    } else {
                        16
                    },
                    sh_type == SHT_RELA,
                )?;
                continue;
            }
            if sh_type == SHT_NOBITS || sh_size < size_of::<u64>() || sh_flags & SHF_ALLOC == 0 {
                continue;
            }
            let name = shstr
                .get(name_offset..)
                .and_then(|tail| tail.split(|&b| b == 0).next())
                .ok_or_else(invalid_program_header)?;
            if name == b".dynamic" {
                continue;
            }
            let section_end = sh_file_offset
                .checked_add(sh_size)
                .ok_or_else(invalid_program_header)?;
            if section_end > data.len() {
                return Err(invalid_program_header());
            }
            if matches!(name, b".init_array" | b".fini_array" | b".preinit_array") {
                if layout.dynamic.is_none() {
                    for word_offset in
                        (sh_file_offset..=section_end - size_of::<u64>()).step_by(size_of::<u64>())
                    {
                        let value = read_u64(data, word_offset)?.truncate();
                        if layout.contains(value) {
                            write_u64(data, word_offset, add_bias(value)?)?;
                        }
                    }
                }
                continue;
            }
            if sh_flags & SHF_EXECINSTR != 0 {
                let mut cursor = 0usize;
                while cursor + 7 <= sh_size {
                    let instr_offset = sh_file_offset + cursor;
                    // Keep executable rewrites self-contained to a single
                    // instruction. Multi-instruction pattern rewrites can
                    // accidentally delete control flow in unrelated ET_EXEC
                    // startup code, which is especially risky for Linux-on-Linux
                    // rebias paths that still use this loader logic.
                    let rex = data[instr_offset];
                    let opcode = data[instr_offset + 1];
                    let modrm = data[instr_offset + 2];
                    if rex & 0xf8 == 0x48
                        && opcode == 0xc7
                        && rex & 0x08 != 0
                        && modrm & 0b11_111_000 == 0b11_000_000
                    {
                        let imm = <[u8; 4]>::try_from(&data[instr_offset + 3..instr_offset + 7])
                            .map_err(|_| invalid_program_header())?;
                        let target = usize::try_from(u32::from_le_bytes(imm))
                            .map_err(|_| invalid_program_header())?;
                        if layout.contains(target) {
                            let instr_vaddr = sh_addr
                                .checked_add(cursor)
                                .ok_or_else(invalid_program_header)?;
                            let biased_instr = add_bias(instr_vaddr)?;
                            let biased_target = add_bias(target)?;
                            let next_ip = biased_instr
                                .checked_add(7)
                                .ok_or_else(invalid_program_header)?;
                            let disp = i64::try_from(biased_target)
                                .map_err(|_| invalid_program_header())?
                                - i64::try_from(next_ip).map_err(|_| invalid_program_header())?;
                            let disp32 =
                                i32::try_from(disp).map_err(|_| invalid_program_header())?;
                            let reg_low3 = modrm & 0x7;
                            let new_rex = 0x40 | (rex & 0x08) | ((rex & 0x1) << 2);
                            data[instr_offset] = new_rex;
                            data[instr_offset + 1] = 0x8d;
                            data[instr_offset + 2] = (reg_low3 << 3) | 0x05;
                            data[instr_offset + 3..instr_offset + 7]
                                .copy_from_slice(&disp32.to_le_bytes());
                        }
                    }
                    cursor += 1;
                }
                continue;
            }
            if sh_flags & SHF_WRITE == 0 {
                continue;
            }
            for word_offset in
                (sh_file_offset..=section_end - size_of::<u64>()).step_by(size_of::<u64>())
            {
                let value = read_u64(data, word_offset)?.truncate();
                if layout.contains(value) {
                    write_u64(data, word_offset, add_bias(value)?)?;
                }
            }
        }
    }

    if data.len() >= TRAMPOLINE_HEADER_SIZE
        && data[data.len() - TRAMPOLINE_HEADER_SIZE..data.len() - TRAMPOLINE_HEADER_SIZE + 8]
            == b"LITEBOX0"[..]
    {
        let vaddr_offset = data.len() - 16;
        let vaddr = read_u64(data, vaddr_offset)?.truncate();
        if layout.contains(vaddr) {
            write_u64(data, vaddr_offset, add_bias(vaddr)?)?;
        }
    }

    Ok(())
}

impl<'a, FS: ShimFS> FileAndParsed<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, ElfLoaderError> {
        let path_string = path.as_rust_str().map_err(|_| Errno::EINVAL)?.to_string();
        let file = ElfFile::new(task, path).map_err(ElfLoaderError::OpenError)?;
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
            .map_err(ElfLoaderError::ParseError)?;

        let file_size: usize = (&mut &file)
            .size()
            .map_err(ElfLoaderError::OpenError)?
            .truncate();
        let syscall_entry_point = task.global.platform.get_syscall_entry_point();
        let missing_trampoline = syscall_entry_point != 0
            && parsed
                .parse_trampoline(&mut &file, syscall_entry_point)
                .is_err();
        let host_mmap_large = file_size > 32 * 1024 * 1024;

        Ok(Self {
            path: path_string,
            file,
            parsed,
            patched_data: None,
            needs_syscall_patch: missing_trampoline,
            host_mmap_large,
            exec_bias_applied: false,
        })
    }

    fn materialize_file_data(&mut self) -> Result<Vec<u8>, ElfLoaderError> {
        if let Some(data) = self.patched_data.take() {
            return Ok(data);
        }
        let resolved_path = self.file.task.resolve_exe_path(&self.path);
        if let Ok(data) = self
            .file
            .task
            .global
            .platform
            .read_host_file(&resolved_path)
        {
            return Ok(data);
        }
        let size: usize = (&mut &self.file)
            .size()
            .map_err(ElfLoaderError::OpenError)?
            .truncate();
        let mut data = alloc::vec![0u8; size];
        (&mut &self.file)
            .read_at(0, &mut data)
            .map_err(ElfLoaderError::OpenError)?;
        Ok(data)
    }

    fn ensure_syscall_trampoline(
        &mut self,
        platform: &(impl litebox::platform::SystemInfoProvider + litebox::platform::DebugLogProvider),
    ) -> Result<(), ElfLoaderError> {
        if !self.needs_syscall_patch {
            return Ok(());
        }

        let data = self.materialize_file_data()?;
        let mut skipped_addrs = alloc::vec::Vec::new();
        match litebox_syscall_rewriter::hook_syscalls_in_elf(&data, None, &mut skipped_addrs) {
            Ok(patched) => {
                if !skipped_addrs.is_empty() {
                    litebox::log_println!(
                        platform,
                        "warning: {} unpatchable syscall instruction(s) in {:?} (addresses: {:?})",
                        skipped_addrs.len(),
                        self.path,
                        skipped_addrs,
                    );
                }
                let mut parsed =
                    litebox_common_linux::loader::ElfParsedFile::parse(&mut patched.as_slice())
                        .map_err(ElfLoaderError::ParseError)?;
                parsed
                    .parse_trampoline(&mut patched.as_slice(), platform.get_syscall_entry_point())
                    .map_err(ElfLoaderError::ParseError)?;
                self.parsed = parsed;
                self.patched_data = Some(patched);
            }
            Err(_) => {
                // Patching failed (e.g. ET_REL, no .text). Proceed without a
                // trampoline — the binary may simply have no syscalls.
                self.patched_data = Some(data);
            }
        }
        self.needs_syscall_patch = false;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn ensure_biased_exec_image(
        &mut self,
        platform: &(impl litebox::platform::SystemInfoProvider + litebox::platform::DebugLogProvider),
    ) -> Result<(), ElfLoaderError> {
        if self.exec_bias_applied {
            return Ok(());
        }
        self.ensure_syscall_trampoline(platform)?;
        let mut data = self.materialize_file_data()?;
        let layout = parse_elf64_exec_layout(&data)?;
        let reserved_start = self
            .file
            .reserve(layout.span_len(), layout.align)
            .map_err(ElfLoaderError::OpenError)?;
        let bias = u64::try_from(
            reserved_start
                .checked_sub(layout.min_vaddr)
                .ok_or(ElfLoaderError::OutOfRange)?,
        )
        .map_err(|_| ElfLoaderError::OutOfRange)?;
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.file.task.global.platform,
            "[TRACE-EXEC-BIAS] path={} min={:#x} max={:#x} align={:#x} reserve={:#x} bias={:#x}",
            self.path,
            layout.min_vaddr,
            layout.max_vaddr,
            layout.align,
            reserved_start,
            bias,
        );
        patch_elf64_exec_image_with_bias(&mut data, &layout, bias, platform)?;
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut data.as_slice())
            .map_err(ElfLoaderError::ParseError)?;
        match parsed.parse_trampoline(&mut data.as_slice(), platform.get_syscall_entry_point()) {
            Ok(()) | Err(litebox_common_linux::loader::ElfParseError::UnpatchedBinary) => {}
            Err(err) => return Err(ElfLoaderError::ParseError(err)),
        }
        self.parsed = parsed;
        self.patched_data = Some(data);
        self.exec_bias_applied = true;
        Ok(())
    }

    /// Load the ELF into guest memory, choosing the right mapper depending on
    /// whether the binary was patched in memory.
    fn load_mapped(
        &mut self,
        platform: &(
             impl litebox::platform::RawPointerProvider
             + litebox::platform::SystemInfoProvider
             + litebox::platform::DebugLogProvider
         ),
        bias_exec: bool,
    ) -> Result<litebox_common_linux::loader::MappingInfo, ElfLoaderError> {
        if bias_exec {
            #[cfg(target_arch = "x86_64")]
            self.ensure_biased_exec_image(platform)?;
            #[cfg(not(target_arch = "x86_64"))]
            return Err(ElfLoaderError::OutOfRange);
        } else {
            self.ensure_syscall_trampoline(platform)?;
        }
        if let Some(ref data) = self.patched_data {
            let mut mapper = PatchedMapper {
                inner: &mut self.file,
                data,
            };
            Ok(self.parsed.load(&mut mapper, &mut &*platform)?)
        } else if self.host_mmap_large && !self.parsed.has_trampoline() {
            let mut mapper = HostFileMapper {
                inner: &mut self.file,
                path: &self.path,
            };
            Ok(self.parsed.load(&mut mapper, &mut &*platform)?)
        } else {
            Ok(self.parsed.load(&mut self.file, &mut &*platform)?)
        }
    }
}

impl<'a, FS: ShimFS> ElfLoader<'a, FS> {
    fn file_bytes(file: &FileAndParsed<'_, FS>) -> Result<Vec<u8>, Errno> {
        let mut elf_file = &file.file;
        let size = usize::try_from(elf_file.size()?).map_err(|_| Errno::EFBIG)?;
        let mut data = alloc::vec![0; size];
        elf_file.read_at(0, &mut data)?;
        Ok(data)
    }

    /// Parses an ELF file from the given path.
    pub fn new(task: &'a Task<FS>, path: &'a str) -> Result<Self, ElfLoaderError> {
        // Parse the main ELF file.
        let main = FileAndParsed::new(task, path)?;

        // Parse the interpreter ELF file, if any.
        let interp = if let Some(interp_name) = main.parsed.interp(&mut &main.file)? {
            let mut interp = FileAndParsed::new(task, interp_name)?;
            // Load the interpreter top-down (high in the address space)
            // so it does not cap a low-loaded ET_EXEC main's brk heap.
            // See `ElfFile::reserve` / `ElfFile::load_high`.
            interp.file.load_high = true;
            Some(interp)
        } else {
            None
        };

        Ok(Self { path, main, interp })
    }

    /// Returns the fixed load address range for the main ELF, if it is an
    /// ET_EXEC (non-PIE) binary. Returns `None` for ET_DYN (PIE) binaries.
    pub fn fixed_load_range(&self) -> Option<core::ops::Range<usize>> {
        self.main.parsed.fixed_load_range()
    }

    /// Returns whether the main ELF has a `PT_INTERP` dynamic loader.
    pub fn has_interpreter(&self) -> bool {
        self.interp.is_some()
    }

    /// Read the current executable bytes from the already-open main ELF file.
    pub fn main_file_bytes(&self) -> Result<Vec<u8>, Errno> {
        Self::file_bytes(&self.main)
    }

    /// Read the resolved PT_INTERP image, if any, from the already-open file.
    pub fn interp_file_bytes(&self) -> Result<Option<(String, Vec<u8>)>, Errno> {
        self.interp
            .as_ref()
            .map(|interp| Ok((interp.path.clone(), Self::file_bytes(interp)?)))
            .transpose()
    }

    /// Load an ELF file and prepare the stack for the new process.
    pub fn load(
        &mut self,
        argv: Vec<CString>,
        envp: Vec<CString>,
        mut aux: AuxVec,
        exec_filename: Option<&CString>,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let global = &self.main.file.task.global;
        let process_state = self.main.file.task.process_state.borrow();

        let bias_main_exec = if let Some(fixed_range) = self.main.parsed.fixed_load_range() {
            let pm_min = process_state.pm.addr_min();
            let pm_max = process_state.pm.addr_max();
            fixed_range.start < pm_min || fixed_range.end > pm_max
        } else {
            false
        };
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            global.platform,
            "[ELF-LOAD] path={} fixed_range={:?} bias_main_exec={} pm=[{:#x},{:#x})",
            self.main.path,
            self.main.parsed.fixed_load_range(),
            bias_main_exec,
            process_state.pm.addr_min(),
            process_state.pm.addr_max(),
        );

        // Load the main ELF file first so that it gets privileged addresses.
        let info = self.main.load_mapped(global.platform, bias_main_exec)?;
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            global.platform,
            "[ELF-LOAD] mapped path={} base={:#x} entry={:#x} brk={:#x}",
            self.main.path,
            info.base_addr,
            info.entry_point,
            info.brk,
        );

        // Load the interpreter ELF file, if any.
        let interp = if let Some(interp) = &mut self.interp {
            let bias_interp_exec = if let Some(fixed_range) = interp.parsed.fixed_load_range() {
                let pm_min = process_state.pm.addr_min();
                let pm_max = process_state.pm.addr_max();
                fixed_range.start < pm_min || fixed_range.end > pm_max
            } else {
                false
            };
            Some(interp.load_mapped(global.platform, bias_interp_exec)?)
        } else {
            None
        };

        {
            let mut proc_map_paths = process_state.proc_map_paths.lock();
            proc_map_paths.clear();
            if info.base_addr < info.brk {
                proc_map_paths.push((
                    info.base_addr..info.brk,
                    self.main.file.task.resolve_exe_path(&self.main.path),
                ));
            }
            if let (Some(interp_info), Some(interp_file)) = (interp.as_ref(), self.interp.as_ref())
                && interp_info.base_addr < interp_info.brk
            {
                proc_map_paths.push((
                    interp_info.base_addr..interp_info.brk,
                    self.main.file.task.resolve_exe_path(&interp_file.path),
                ));
            }
        }

        process_state.pm.set_initial_brk(info.brk);
        #[cfg(target_os = "windows")]
        {
            const INITIAL_HEAP_RUNWAY: usize = 0x0100_0000;
            if let Some(clean_brk) = litebox_platform_multiplex::platform()
                .reserve_clean_heap_runway(info.brk, INITIAL_HEAP_RUNWAY)
                && clean_brk > info.brk
            {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    global.platform,
                    "[ELF-LOAD] adjusted initial brk from {:#x} to {:#x} and reserved a clean heap runway",
                    info.brk,
                    clean_brk,
                );
                process_state.pm.ensure_brk_past(clean_brk);
            }
        }
        process_state
            .main_bss_start
            .store(info.bss_start, core::sync::atomic::Ordering::Relaxed);
        process_state
            .main_bss_end
            .store(info.bss_end, core::sync::atomic::Ordering::Relaxed);
        aux.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
        aux.insert(AuxKey::AT_PHDR, info.phdrs_addr);
        aux.insert(AuxKey::AT_PHENT, info.phent_size());
        aux.insert(AuxKey::AT_PHNUM, info.num_phdrs);
        aux.insert(AuxKey::AT_ENTRY, info.entry_point);
        let entry = if let Some(interp) = &interp {
            aux.insert(AuxKey::AT_BASE, interp.base_addr);
            interp.entry_point
        } else {
            info.entry_point
        };

        let sp = unsafe {
            let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            process_state
                .pm
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::new(sp, super::DEFAULT_STACK_SIZE)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
        let mut at_random = [0u8; 16];
        <_ as litebox::platform::CrngProvider>::fill_bytes_crng(global.platform, &mut at_random);
        stack
            .init(argv, envp, aux, exec_filename, at_random)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;

        Ok(ElfLoadInfo {
            entry_point: entry,
            user_stack_top: stack.get_cur_stack_top(),
        })
    }

    /// Returns the command name from the ELF path.
    pub fn comm(&self) -> &[u8] {
        self.path.rsplit('/').next().unwrap_or("unknown").as_bytes()
    }
}

#[derive(Error, Debug)]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file")]
    OpenError(#[from] Errno),
    #[error("failed to parse the ELF file")]
    ParseError(#[from] litebox_common_linux::loader::ElfParseError<Errno>),
    #[error("failed to load the ELF file")]
    LoadError(#[from] litebox_common_linux::loader::ElfLoadError<Errno>),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap")]
    MappingError(#[from] MappingError),
    #[error("ET_EXEC load addresses outside process VA range")]
    OutOfRange,
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            // Non-ELF files that also lack a #! shebang (handled earlier in
            // sys_execve) reach here. Map to ENOENT to prevent glibc from
            // retrying execution via /bin/sh for opaque binaries.
            ElfLoaderError::ParseError(_) => litebox_common_linux::errno::Errno::ENOENT,
            ElfLoaderError::InvalidStackAddr | ElfLoaderError::MappingError(_) => {
                litebox_common_linux::errno::Errno::ENOMEM
            }
            ElfLoaderError::LoadError(e) => e.into(),
            // OutOfRange means the binary's load address doesn't fit in the
            // current VA partition (e.g. non-PIE at 0x400000 in a child slot).
            ElfLoaderError::OutOfRange => litebox_common_linux::errno::Errno::ENOMEM,
        }
    }
}

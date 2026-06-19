// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::syscalls::Cleanup;
use crate::{Task, UserMutPtr};
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{RawConstPointer, RawMutPointer, SystemInfoProvider as _};
use litebox_common_linux::{MapFlags, ProtFlags};
use litebox_common_optee::{LdelfMapFlags, TeeResult, TeeUuid};

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

/// Calls `sys_munmap(addr, len)` when dropped, unless `disarm()` has been called first.
///
/// Used to ensure a mapping created by `sys_mmap` is released on every error
/// path of `sys_map_zi` / `sys_map_bin`. After the syscall has fully succeeded
/// and ownership of the mapping has been transferred to the caller, call
/// `disarm()` to suppress the unmap.
#[must_use = "MmapGuard unmaps on drop unless disarm() is called; bind it"]
struct MmapGuard<'a> {
    task: &'a Task,
    addr: UserMutPtr<u8>,
    len: usize,
}

impl<'a> MmapGuard<'a> {
    fn new(task: &'a Task, addr: UserMutPtr<u8>, len: usize) -> Self {
        Self { task, addr, len }
    }

    fn disarm(self) {
        core::mem::forget(self);
    }
}

impl Drop for MmapGuard<'_> {
    fn drop(&mut self) {
        let _ = self.task.sys_munmap(self.addr, self.len);
    }
}

impl Task {
    #[inline]
    fn checked_map_size(
        num_bytes: usize,
        pad_begin: usize,
        pad_end: usize,
    ) -> Result<usize, TeeResult> {
        num_bytes
            .checked_add(pad_begin)
            .and_then(|t| t.checked_add(pad_end))
            .and_then(|t| t.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(TeeResult::BadParameters)
    }

    #[inline]
    fn get_aligned_start_of_pad_end(
        padded_start: usize,
        num_bytes: usize,
    ) -> Result<usize, TeeResult> {
        padded_start
            .checked_add(num_bytes)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(TeeResult::BadParameters)
    }

    /// OP-TEE's syscall to map zero-initialized memory with padding.
    ///
    /// Maps `pad_begin + num_bytes + pad_end` bytes (rounded up to a page) and
    /// zero-initializes the `num_bytes` usable region. `va` is a page-aligned
    /// hint for the *base of the whole mapping* (`0` means no hint). The usable
    /// region thus starts at `start = va + pad_begin`; the `pad_begin`/`pad_end`
    /// regions are reserved and must not be accessed.
    ///
    /// On success, returns `start` plus a `Cleanup` that unmaps the usable
    /// region. The caller communicates the address back to userspace and must
    /// run the cleanup if that write-back fails.
    pub fn sys_map_zi(
        &self,
        va: usize,
        num_bytes: usize,
        pad_begin: usize,
        pad_end: usize,
        flags: LdelfMapFlags,
    ) -> Result<(usize, Cleanup), TeeResult> {
        #[cfg(debug_assertions)]
        litebox_util_log::debug!(
            va:% = format_args!("{:#x}", va),
            num_bytes:% = num_bytes,
            flags:% = format_args!("{:#x}", flags);
            "sys_map_zi"
        );

        let accept_flags = LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE;
        if flags.bits() & !accept_flags.bits() != 0 {
            return Err(TeeResult::BadParameters);
        }
        // TODO: Check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` once we support sharing of file-based mappings.

        // OP-TEE requires the address hint and padding to be page-aligned.
        if !va.is_multiple_of(PAGE_SIZE)
            || !pad_begin.is_multiple_of(PAGE_SIZE)
            || !pad_end.is_multiple_of(PAGE_SIZE)
        {
            return Err(TeeResult::AccessConflict);
        }

        let total_size = Self::checked_map_size(num_bytes, pad_begin, pad_end)?;
        if va.checked_add(total_size).is_none() {
            return Err(TeeResult::BadParameters);
        }
        // `sys_map_zi` always creates read/writeable mapping.
        //
        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE.
        let mut flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        if va != 0 {
            flags |= MapFlags::MAP_FIXED;
        }

        let addr = self
            .sys_mmap(va, total_size, ProtFlags::PROT_READ_WRITE, flags, -1, 0)
            .map_err(|_| TeeResult::OutOfMemory)?;
        let guard = MmapGuard::new(self, addr, total_size);

        let padded_start = addr
            .as_usize()
            .checked_add(pad_begin)
            .ok_or(TeeResult::BadParameters)?;

        // Unmap the padding regions to free physical memory.
        // Using munmap instead of mprotect(PROT_NONE) actually deallocates the frames.
        // pad_begin region: [addr, align_down(padded_start, PAGE_SIZE))
        let pad_begin_end = align_down(padded_start, PAGE_SIZE);
        if addr.as_usize() < pad_begin_end {
            let _ = self.sys_munmap(addr, pad_begin_end - addr.as_usize());
        }
        // pad_end region: [align_up(padded_start + num_bytes, PAGE_SIZE), addr + total_size)
        let pad_end_start = Self::get_aligned_start_of_pad_end(padded_start, num_bytes)?;
        let region_end = addr
            .as_usize()
            .checked_add(total_size)
            .ok_or(TeeResult::BadParameters)?;
        if pad_end_start < region_end {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start),
                region_end - pad_end_start,
            );
        }

        guard.disarm();
        let cleanup = Cleanup::Unmap {
            addr: padded_start,
            len: pad_end_start - padded_start,
        };
        Ok((padded_start, cleanup))
    }

    /// OP-TEE's syscall to open a TA binary.
    pub fn sys_open_bin(&self, ta_uuid: TeeUuid, handle: UserMutPtr<u32>) -> Result<(), TeeResult> {
        #[cfg(debug_assertions)]
        litebox_util_log::debug!(
            ta_uuid:? = ta_uuid,
            handle:% = format_args!("{:#x}", handle.as_usize());
            "sys_open_bin"
        );

        if self.global.get_ta_bin(&ta_uuid).is_none() {
            return Err(TeeResult::ItemNotFound);
        }
        let new_handle = self.ta_handle_map.insert(ta_uuid);
        let _ = handle.write_at_offset(0, new_handle);

        Ok(())
    }

    /// OP-TEE's syscall to close a TA binary.
    pub fn sys_close_bin(&self, handle: u32) -> Result<(), TeeResult> {
        #[cfg(debug_assertions)]
        litebox_util_log::debug!(handle:% = handle; "sys_close_bin");

        if self.ta_handle_map.get(handle).is_none() {
            Err(TeeResult::BadParameters)
        } else {
            self.ta_handle_map.remove(handle);
            Ok(())
        }
    }

    /// OP-TEE's syscall to map a portion of a TA binary into memory.
    #[allow(clippy::too_many_arguments)]
    pub fn sys_map_bin(
        &self,
        va: UserMutPtr<usize>,
        num_bytes: usize,
        handle: u32,
        offs: usize,
        pad_begin: usize,
        pad_end: usize,
        flags: LdelfMapFlags,
    ) -> Result<(), TeeResult> {
        let Some(addr) = va.read_at_offset(0) else {
            return Err(TeeResult::BadParameters);
        };

        #[cfg(debug_assertions)]
        litebox_util_log::debug!(
            va:% = format_args!("{:#x}", va.as_usize()),
            addr:% = format_args!("{:#x}", addr),
            num_bytes:% = num_bytes,
            handle:% = handle,
            offs:% = offs,
            pad_begin:% = pad_begin,
            pad_end:% = pad_end,
            flags:% = format_args!("{:#x}", flags);
            "sys_map_bin"
        );

        let accept_flags = LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE
            | LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE
            | LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE;
        if flags.bits() & !accept_flags.bits() != 0 {
            return Err(TeeResult::BadParameters);
        }

        // OP-TEE requires the address hint and padding to be page-aligned.
        if !addr.is_multiple_of(PAGE_SIZE)
            || !pad_begin.is_multiple_of(PAGE_SIZE)
            || !pad_end.is_multiple_of(PAGE_SIZE)
        {
            return Err(TeeResult::AccessConflict);
        }

        if self.ta_handle_map.get(handle).is_none() {
            return Err(TeeResult::BadParameters);
        }

        if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE)
            && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE)
        {
            return Err(TeeResult::BadParameters);
        }
        if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
            && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE)
        {
            return Err(TeeResult::BadParameters);
        }

        let total_size = Self::checked_map_size(num_bytes, pad_begin, pad_end)?;
        if addr.checked_add(total_size).is_none() {
            return Err(TeeResult::BadParameters);
        }
        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE as
        // explained in `sys_map_zi`.
        let mut flags_internal = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        if addr != 0 {
            flags_internal |= MapFlags::MAP_FIXED;
        }
        // TODO: on Arm, check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` to control cache behaviors

        // Avoiding TA trampoline address conflict based on heuristics.
        // Grow the underlying mmap by one page but keep trimming based on
        // the original total_size so the extra page survives unseen by
        // ldelf. ldelf reserves the address space for TA ELF via the main
        // `sys_map_bin` call: addr=0 (PM picks the base), at least one of
        // pad_begin/pad_end > 0 (reservation room around the first
        // segment; ASLR-enabled builds put it in pad_begin, ASLR-disabled
        // may put it entirely in pad_end), and LDELF_MAP_FLAG_EXECUTABLE
        // (the first segment is .text). Skip on kernel-mode platforms
        // which don't use a syscall trampoline.
        //
        // TODO: consider a reliable solution.
        let should_extend_ta_reservation = addr == 0
            && (pad_begin > 0 || pad_end > 0)
            && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
            && self.global.platform.get_syscall_entry_point() != 0;
        let mmap_size = if should_extend_ta_reservation {
            // The size of OP-TEE TA trampoline is 0x3f8, so one page is enough.
            total_size
                .checked_add(PAGE_SIZE)
                .ok_or(TeeResult::OutOfMemory)?
        } else {
            total_size
        };

        // Currently, we do not support TA binary mapping. So, we create an anonymous mapping and copy
        // the content of the TA binary into it.
        let addr = self
            .sys_mmap(
                addr,
                mmap_size,
                ProtFlags::PROT_READ_WRITE,
                flags_internal,
                -1,
                0,
            )
            .map_err(|_| TeeResult::OutOfMemory)?;
        let guard = MmapGuard::new(self, addr, mmap_size);

        let padded_start = addr
            .as_usize()
            .checked_add(pad_begin)
            .ok_or(TeeResult::BadParameters)?;
        if padded_start == 0 {
            return Err(TeeResult::BadFormat);
        }

        if self
            .read_ta_bin(
                handle,
                UserMutPtr::from_usize(padded_start),
                offs,
                num_bytes,
            )
            .is_none()
        {
            return Err(TeeResult::ShortBuffer);
        }

        // Set final permissions for the usable region
        let mut prot = ProtFlags::PROT_READ;
        if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE) {
            prot |= ProtFlags::PROT_WRITE;
        } else if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE) {
            prot |= ProtFlags::PROT_EXEC;
        }
        let prot_start = align_down(padded_start, PAGE_SIZE);
        let prot_len = padded_start
            .checked_sub(prot_start)
            .and_then(|offset| offset.checked_add(num_bytes))
            .and_then(|len| len.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(TeeResult::BadParameters)?;
        if self
            .sys_mprotect(UserMutPtr::from_usize(prot_start), prot_len, prot)
            .is_err()
        {
            return Err(TeeResult::AccessDenied);
        }

        // Unmap the padding regions to free physical memory.
        // Using munmap instead of mprotect(PROT_NONE) actually deallocates the frames.
        // pad_begin region: [addr, align_down(padded_start, PAGE_SIZE))
        let pad_begin_end = align_down(padded_start, PAGE_SIZE);
        if addr.as_usize() < pad_begin_end {
            let _ = self.sys_munmap(addr, pad_begin_end - addr.as_usize());
        }
        // pad_end region: [align_up(padded_start + num_bytes, PAGE_SIZE), addr + total_size)
        let pad_end_start = Self::get_aligned_start_of_pad_end(padded_start, num_bytes)?;
        let region_end = addr
            .as_usize()
            .checked_add(total_size)
            .ok_or(TeeResult::BadParameters)?;
        if pad_end_start < region_end {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start),
                region_end - pad_end_start,
            );
        }

        let _ = va.write_at_offset(0, padded_start);
        guard.disarm();

        Ok(())
    }

    /// OP-TEE's syscall to copy data from the TA binary to memory.
    pub fn sys_cp_from_bin(
        &self,
        dst: usize,
        offs: usize,
        num_bytes: usize,
        handle: u32,
    ) -> Result<(), TeeResult> {
        #[cfg(debug_assertions)]
        litebox_util_log::debug!(
            dst:% = format_args!("{:#x}", dst),
            offs:% = offs,
            num_bytes:% = num_bytes,
            handle:% = handle;
            "sys_cp_from_bin"
        );

        self.read_ta_bin(handle, UserMutPtr::from_usize(dst), offs, num_bytes)
            .ok_or(TeeResult::ShortBuffer)?;

        Ok(())
    }

    /// Read `count` bytes of the TA binary of the current task from `offset` into
    /// userspace `dst`.
    fn read_ta_bin(
        &self,
        handle: u32,
        dst: UserMutPtr<u8>,
        offset: usize,
        count: usize,
    ) -> Option<()> {
        if let Some(ta_uuid) = self.ta_handle_map.get(handle)
            && let Some(ta_bin) = self.global.get_ta_bin(&ta_uuid)
        {
            let end_offset = offset.checked_add(count)?;
            if end_offset <= ta_bin.len() {
                dst.copy_from_slice(0, &ta_bin[offset..end_offset])
            } else {
                None
            }
        } else {
            None
        }
    }
}

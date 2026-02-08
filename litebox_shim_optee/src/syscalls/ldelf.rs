// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{Task, UserMutPtr};
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{RawConstPointer, RawMutPointer};
use litebox_common_linux::{MapFlags, ProtFlags};
use litebox_common_optee::{LdelfMapFlags, TeeResult, TeeUuid};

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl Task {
    /// OP-TEE's syscall to map zero-initialized memory with padding.
    /// This function pads `pad_begin` bytes before and `pad_end` bytes after the
    /// zero-initialized `num_bytes` bytes. `va` can contain a hint address which
    /// is `pad_begin` bytes lower than the starting address of the memory region.
    /// (`start - pad_begin`, ...,  `start`, ..., `start + num_bytes`, ..., `start + num_bytes + pad_end`)
    /// Memory regions between `start - pad_begin` and `start` and between
    /// `start + num_bytes` and `start + num_bytes + pad_end` are reserved and must not be used.
    pub fn sys_map_zi(
        &self,
        va: UserMutPtr<usize>,
        num_bytes: usize,
        pad_begin: usize,
        pad_end: usize,
        flags: LdelfMapFlags,
    ) -> Result<(), TeeResult> {
        let Some(addr) = va.read_at_offset(0) else {
            return Err(TeeResult::BadParameters);
        };

        #[cfg(debug_assertions)]
        litebox::log_println!(
            self.global.platform,
            "sys_map_zi: va {:#x} (addr {:#x}), num_bytes {}, flags {:#x}",
            va.as_usize(),
            addr,
            num_bytes,
            flags
        );

        let accept_flags = LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE;
        if flags.bits() & !accept_flags.bits() != 0 {
            return Err(TeeResult::BadParameters);
        }
        // TODO: Check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` once we support sharing of file-based mappings.

        let total_size = num_bytes
            .checked_add(pad_begin)
            .and_then(|t| t.checked_add(pad_end))
            .ok_or(TeeResult::BadParameters)?
            .next_multiple_of(PAGE_SIZE);
        if addr.checked_add(total_size).is_none() {
            return Err(TeeResult::BadParameters);
        }
        // `sys_map_zi` always creates read/writeable mapping
        // Use MAP_POPULATE to ensure pages are allocated immediately (required for platforms
        // that don't support demand paging, e.g., LVBS).
        //
        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE.
        // This is because our mmap with MAP_POPULATE and PROT_NONE create pages without
        // USER_ACCESSIBLE bit, making them inaccessible even to mprotect.
        let mut flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE;
        if addr != 0 {
            flags |= MapFlags::MAP_FIXED;
        }

        let addr = self
            .sys_mmap(addr, total_size, ProtFlags::PROT_READ_WRITE, flags, -1, 0)
            .map_err(|_| TeeResult::OutOfMemory)?;
        let padded_start = addr.as_usize() + pad_begin;

        // Unmap the padding regions to free physical memory.
        // Using munmap instead of mprotect(PROT_NONE) actually deallocates the frames.
        // pad_begin region: [addr, align_down(padded_start, PAGE_SIZE))
        let pad_begin_end = align_down(padded_start, PAGE_SIZE);
        if addr.as_usize() < pad_begin_end {
            let _ = self.sys_munmap(addr, pad_begin_end - addr.as_usize());
        }
        // pad_end region: [align_up(padded_start + num_bytes, PAGE_SIZE), addr + total_size)
        let pad_end_start = (padded_start + num_bytes).next_multiple_of(PAGE_SIZE);
        let region_end = addr.as_usize() + total_size;
        if pad_end_start < region_end {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start),
                region_end - pad_end_start,
            );
        }

        let _ = va.write_at_offset(0, padded_start);
        Ok(())
    }

    /// OP-TEE's syscall to open a TA binary.
    pub fn sys_open_bin(&self, ta_uuid: TeeUuid, handle: UserMutPtr<u32>) -> Result<(), TeeResult> {
        #[cfg(debug_assertions)]
        litebox::log_println!(
            self.global.platform,
            "sys_open_bin: ta_uuid {:?}, handle {:#x}",
            ta_uuid,
            handle.as_usize()
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
        litebox::log_println!(self.global.platform, "sys_close_bin: handle {}", handle);

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
        litebox::log_println!(
            self.global.platform,
            "sys_map_bin: va {:#x} (addr {:#x}), num_bytes {}, handle {}, offs {}, pad_begin {}, pad_end {}, flags {:#x}",
            va.as_usize(),
            addr,
            num_bytes,
            handle,
            offs,
            pad_begin,
            pad_end,
            flags
        );

        let accept_flags = LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE
            | LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE
            | LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE;
        if flags.bits() & !accept_flags.bits() != 0 {
            return Err(TeeResult::BadParameters);
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

        let total_size = num_bytes
            .checked_add(pad_begin)
            .and_then(|t| t.checked_add(pad_end))
            .ok_or(TeeResult::BadParameters)?
            .next_multiple_of(PAGE_SIZE);
        if addr.checked_add(total_size).is_none() {
            return Err(TeeResult::BadParameters);
        }
        // Use MAP_POPULATE to ensure pages are allocated immediately (required for platforms
        // that don't support demand paging, e.g., LVBS).
        //
        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE as
        // explained in `sys_map_zi`.
        let mut flags_internal =
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE;
        if addr != 0 {
            flags_internal |= MapFlags::MAP_FIXED;
        }
        // TODO: on Arm, check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` to control cache behaviors

        // Currently, we do not support TA binary mapping. So, we create an anonymous mapping and copy
        // the content of the TA binary into it.
        let addr = self
            .sys_mmap(
                addr,
                total_size,
                ProtFlags::PROT_READ_WRITE,
                flags_internal,
                -1,
                0,
            )
            .map_err(|_| TeeResult::OutOfMemory)?;
        let padded_start = addr.as_usize() + pad_begin;
        if padded_start == 0 {
            let _ = self.sys_munmap(addr, total_size).ok();
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
        if self
            .sys_mprotect(
                UserMutPtr::from_usize(align_down(padded_start, PAGE_SIZE)),
                (num_bytes + padded_start - align_down(padded_start, PAGE_SIZE))
                    .next_multiple_of(PAGE_SIZE),
                prot,
            )
            .is_err()
        {
            let _ = self.sys_munmap(addr, total_size).ok();
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
        let pad_end_start = (padded_start + num_bytes).next_multiple_of(PAGE_SIZE);
        let region_end = addr.as_usize() + total_size;
        if pad_end_start < region_end {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start),
                region_end - pad_end_start,
            );
        }

        let _ = va.write_at_offset(0, padded_start);

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
        litebox::log_println!(
            self.global.platform,
            "sys_cp_from_bin: dst {:#x}, offs {}, num_bytes {}, handle {}",
            dst,
            offs,
            num_bytes,
            handle,
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

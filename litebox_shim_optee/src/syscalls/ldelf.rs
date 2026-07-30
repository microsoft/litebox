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

    /// `ldelf` keeps `pad_end` free for the segments that follow. We map only
    /// the segment, so check that room is still free.
    ///
    /// The check stops at the end of the image reservation. `ldelf` rounds a
    /// segment and its `pad_end` separately, so the two together can reach a
    /// page past the image, onto memory we never placed.
    ///
    /// It only reports a collision sooner: the mapping itself is `NOREPLACE`, so
    /// a segment cannot overwrite anything whether or not the check ran.
    fn check_room_is_free(&self, start: usize, pad_end: usize) -> Result<(), TeeResult> {
        let mut end = start.checked_add(pad_end).ok_or(TeeResult::BadParameters)?;
        match self.ta_reserved_end.get() {
            // We hold no reservation, so there is nothing of ours to check.
            0 => return Ok(()),
            reserved_end => end = end.min(reserved_end),
        }
        let Some(len) = end.checked_sub(start).filter(|l| *l != 0) else {
            return Ok(());
        };
        match self.sys_mmap(
            start,
            len,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED_NOREPLACE,
            -1,
            0,
        ) {
            // Leaving the probe mapped would make the next segment collide with it.
            Ok(p) => {
                debug_assert_eq!(p.as_usize(), start);
                self.sys_munmap(p, len).map_err(TeeResult::from)
            }
            Err(e) => Err(e.into()),
        }
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
            pad_begin:% = pad_begin,
            pad_end:% = pad_end,
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
        let seg_size = Self::checked_map_size(num_bytes, 0, 0)?;

        // `sys_map_zi` always creates read/writeable mapping.
        //
        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE.
        let mut flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        // The padding is not part of this mapping, see `sys_map_bin`.
        let (region_size, region_pad_begin) = if va == 0 {
            (total_size, pad_begin)
        } else {
            if pad_begin != 0 {
                return Err(TeeResult::BadParameters);
            }
            let start = va.checked_add(seg_size).ok_or(TeeResult::BadParameters)?;
            self.check_room_is_free(start, pad_end)?;
            flags |= MapFlags::MAP_FIXED_NOREPLACE;
            (seg_size, 0)
        };

        let addr = self
            .sys_mmap(va, region_size, ProtFlags::PROT_READ_WRITE, flags, -1, 0)
            .map_err(TeeResult::from)?;
        let guard = MmapGuard::new(self, addr, region_size);

        let padded_start = addr
            .as_usize()
            .checked_add(region_pad_begin)
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
            .checked_add(region_size)
            .ok_or(TeeResult::BadParameters)?;
        if pad_end_start < region_end {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start),
                region_end - pad_end_start,
            );
        }

        guard.disarm();
        // This call reserves the range the later segments map into. Remember
        // where it ends, to bound their room checks. Record after the mapping
        // commits, so a rolled back one is not.
        if va == 0 && pad_end != 0 {
            self.ta_reserved_end.set(region_end);
        }
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
        let seg_size = Self::checked_map_size(num_bytes, 0, 0)?;

        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE as
        // explained in `sys_map_zi`.
        let mut flags_internal = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        // TODO: on Arm, check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` to control cache behaviors

        // `ldelf` either lets us place the region (`addr == 0`) or names the
        // address itself.
        //
        // `pad_begin` is a random offset `ldelf` puts before the image for ASLR,
        // `pad_end` reserves room for the segments that follow (`get_pad_begin()`
        // and `populate_segments()` in `ldelf/ta_elf.c`). Neither is part of this
        // mapping: OP-TEE only inserts `ROUNDUP(num_bytes)` into the region list
        // (`umap_add_region()` in `core/mm/vm.c`). The reservations are not
        // disjoint and each one covers the rest of the image.
        let (region_size, region_pad_begin, should_extend_ta_reservation) = if addr == 0 {
            // Map the room as well, so the allocator finds a gap wide enough for
            // the whole image.
            //
            // Reserve a page past the image for the LiteBox trampoline, which
            // `ldelf` does not account for. Recognize the call that reserves the
            // TA's address space by heuristics: it asks for room around the
            // first segment, which is `.text` and so executable. Kernel-mode
            // platforms report no syscall entry point and need no trampoline.
            //
            // TODO: consider a reliable solution.
            let extend = (pad_begin > 0 || pad_end > 0)
                && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
                && self.global.platform.get_syscall_entry_point() != 0;
            (total_size, pad_begin, extend)
        } else {
            // The slot is already chosen, so map the segment alone and check the
            // room is still free instead.
            if pad_begin != 0 {
                // `ldelf` pads the start only when it lets us pick the address.
                return Err(TeeResult::BadParameters);
            }
            let start = addr.checked_add(seg_size).ok_or(TeeResult::BadParameters)?;
            self.check_room_is_free(start, pad_end)?;
            // `NOREPLACE` so a segment cannot silently replace an existing
            // mapping: nothing holds the room for us any more.
            flags_internal |= MapFlags::MAP_FIXED_NOREPLACE;
            (seg_size, 0, false)
        };
        let mmap_size = if should_extend_ta_reservation {
            // The OP-TEE TA trampoline is 0x3f8 bytes, so one page is enough.
            // Everything below keeps trimming by `region_size`, leaving the
            // extra page mapped and unseen by `ldelf`.
            region_size
                .checked_add(PAGE_SIZE)
                .ok_or(TeeResult::OutOfMemory)?
        } else {
            region_size
        };

        // Currently, we do not support TA binary mapping. So, we create an anonymous mapping and copy
        // the content of the TA binary into it.
        let base = self
            .sys_mmap(
                addr,
                mmap_size,
                ProtFlags::PROT_READ_WRITE,
                flags_internal,
                -1,
                0,
            )
            .map_err(TeeResult::from)?;
        let guard = MmapGuard::new(self, base, mmap_size);

        let padded_start = base
            .as_usize()
            .checked_add(region_pad_begin)
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
        // pad_begin region: [base, align_down(padded_start, PAGE_SIZE))
        let pad_begin_end = align_down(padded_start, PAGE_SIZE);
        if base.as_usize() < pad_begin_end {
            let _ = self.sys_munmap(base, pad_begin_end - base.as_usize());
        }
        // pad_end region: [align_up(padded_start + num_bytes, PAGE_SIZE), base + region_size)
        let pad_end_start = Self::get_aligned_start_of_pad_end(padded_start, num_bytes)?;
        let region_end = base
            .as_usize()
            .checked_add(region_size)
            .ok_or(TeeResult::BadParameters)?;
        if pad_end_start < region_end {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start),
                region_end - pad_end_start,
            );
        }

        let _ = va.write_at_offset(0, padded_start);
        guard.disarm();
        // This call reserves the range the later segments map into. Remember
        // where it ends, to bound their room checks. Record after the mapping
        // commits, so a rolled back one is not.
        if addr == 0 && pad_end != 0 {
            self.ta_reserved_end.set(region_end);
        }

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

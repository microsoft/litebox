// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::syscalls::Cleanup;
use crate::{Platform, Task, UserMutPtr};
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::page_mgmt::PageManagementProvider;
use litebox::platform::{RawConstPointer, RawMutPointer};
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
    fn checked_map_len(
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
        usable_start_addr: usize,
        num_bytes: usize,
    ) -> Result<usize, TeeResult> {
        usable_start_addr
            .checked_add(num_bytes)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(TeeResult::BadParameters)
    }

    /// Check that the `pad_begin` bytes below `usable_start_addr` and the
    /// `pad_end` bytes above `usable_start_addr + segment_len` are free, as
    /// OP-TEE's `select_va_in_range` does for a caller-named address.
    ///
    /// Mapping the segment alone would only validate `ROUNDUP(num_bytes)`. The
    /// TA's trampoline pages are excluded, since OP-TEE believes that address
    /// space is unmapped.
    ///
    /// Under the userland runner, LiteBox's own mappings (its binary, libc, the
    /// heap) share this address space; they are tracked as of start-up, but not
    /// what it allocates afterwards.
    fn ensure_pads_are_unmapped(
        &self,
        usable_start_addr: usize,
        segment_len: usize,
        pad_begin: usize,
        pad_end: usize,
    ) -> Result<(), TeeResult> {
        if pad_begin == 0 && pad_end == 0 {
            return Ok(());
        }
        let usable_end_addr = usable_start_addr
            .checked_add(segment_len)
            .ok_or(TeeResult::BadParameters)?;
        // Either gap can be empty, which `RangeSet::insert` rejects.
        let mut pads = rangemap::RangeSet::new();
        if pad_begin != 0 {
            pads.insert(
                usable_start_addr
                    .checked_sub(pad_begin)
                    .ok_or(TeeResult::BadParameters)?..usable_start_addr,
            );
        }
        if pad_end != 0 {
            pads.insert(
                usable_end_addr
                    ..usable_end_addr
                        .checked_add(pad_end)
                        .ok_or(TeeResult::BadParameters)?,
            );
        }
        // The gaps must fall inside the task's address range; padding that runs
        // past either end is an access conflict rather than a fit.
        if pads.iter().any(|pad| {
            pad.start < <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
                || pad.end > <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX
        }) {
            return Err(TeeResult::AccessConflict);
        }
        // Cut the trampoline pages out of the gaps rather than skipping the
        // mappings inside them: `RangeMap` coalesces adjacent ranges that share
        // flags, so they are routinely merged into a segment's VMA.
        if let Some((start, end)) = self.ta_trampoline_page_range.get() {
            pads.remove(start..end);
        }

        if self
            .global
            .pm
            .mappings()
            .iter()
            .any(|(range, _flags)| pads.overlaps(range))
        {
            return Err(TeeResult::AccessConflict);
        }
        Ok(())
    }

    /// OP-TEE's syscall to map zero-initialized memory with padding.
    ///
    /// `va` is either `0` (OP-TEE picks the address) or a fixed address. Padding
    /// only steers that choice: OP-TEE maps and records just
    /// `ROUNDUP(num_bytes)` and leaves the padding unmapped (see `vm_map_pad()`
    /// in `core/mm/vm.c`).
    ///
    /// The usable region is `num_bytes` long and zero-initialized. With `va ==
    /// 0` it starts `pad_begin` bytes into the span OP-TEE picked; with a fixed
    /// `va` it starts at `va` itself and `pad_begin` merely demands that many
    /// free bytes below it, matching `vm_map_pad`'s in/out `va`.
    ///
    /// On success, returns that usable start address plus a [`Cleanup`] that
    /// unmaps the usable region. The caller communicates the address back to
    /// userspace and must run the cleanup if that write-back fails.
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

        let padded_len = Self::checked_map_len(num_bytes, pad_begin, pad_end)?;
        if va.checked_add(padded_len).is_none() {
            return Err(TeeResult::BadParameters);
        }
        let segment_len = Self::checked_map_len(num_bytes, 0, 0)?;

        // `sys_map_zi` always creates read/writeable mapping.
        //
        // With `va == 0`, map the padded span so LiteBox's allocator picks a gap
        // wide enough for it, mirroring `select_va_in_range`, then unmap the
        // padding. With a fixed `va` there is no placement to influence, so map
        // only the segment and check the gaps instead.
        let mut flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        let (map_len, map_pad_begin_len) = if va == 0 {
            (padded_len, pad_begin)
        } else {
            self.ensure_pads_are_unmapped(va, segment_len, pad_begin, pad_end)?;
            flags |= MapFlags::MAP_FIXED_NOREPLACE;
            (segment_len, 0)
        };

        let addr = self
            .sys_mmap(va, map_len, ProtFlags::PROT_READ_WRITE, flags, -1, 0)
            .map_err(TeeResult::from)?;
        let guard = MmapGuard::new(self, addr, map_len);

        let usable_start_addr = addr
            .as_usize()
            .checked_add(map_pad_begin_len)
            .ok_or(TeeResult::BadParameters)?;

        // Unmap the padding regions to free physical memory.
        // Using munmap instead of mprotect(PROT_NONE) actually deallocates the frames.
        // pad_begin region: [addr, align_down(usable_start_addr, PAGE_SIZE))
        let pad_begin_end_addr = align_down(usable_start_addr, PAGE_SIZE);
        if addr.as_usize() < pad_begin_end_addr {
            let _ = self.sys_munmap(addr, pad_begin_end_addr - addr.as_usize());
        }
        // pad_end region: [align_up(usable_start_addr + num_bytes, PAGE_SIZE), addr + map_len)
        let pad_end_start_addr = Self::get_aligned_start_of_pad_end(usable_start_addr, num_bytes)?;
        let map_end_addr = addr
            .as_usize()
            .checked_add(map_len)
            .ok_or(TeeResult::BadParameters)?;
        if pad_end_start_addr < map_end_addr {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start_addr),
                map_end_addr - pad_end_start_addr,
            );
        }

        guard.disarm();
        let cleanup = Cleanup::Unmap {
            addr: usable_start_addr,
            len: pad_end_start_addr - usable_start_addr,
        };
        Ok((usable_start_addr, cleanup))
    }

    /// OP-TEE's syscall to open a TA binary.
    pub fn sys_open_bin(&self, ta_uuid: TeeUuid, handle: UserMutPtr<u32>) -> Result<(), TeeResult> {
        #[cfg(debug_assertions)]
        litebox_util_log::debug!(
            ta_uuid:? = ta_uuid,
            handle:% = format_args!("{:#x}", handle.as_usize());
            "sys_open_bin"
        );

        if ta_uuid != self.ta_app_id && self.global.get_ta_bin(&ta_uuid).is_none() {
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

        let padded_len = Self::checked_map_len(num_bytes, pad_begin, pad_end)?;
        if addr.checked_add(padded_len).is_none() {
            return Err(TeeResult::BadParameters);
        }
        let segment_len = Self::checked_map_len(num_bytes, 0, 0)?;

        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE as
        // explained in `sys_map_zi`.
        let mut flags_internal = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        // TODO: on Arm, check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` to control cache behaviors

        // `pad_begin` is the ASLR offset `ldelf` puts before the image; `pad_end`
        // covers the segments that follow. Neither is mapped, so every segment's
        // `pad_end` overlaps the rest of the image and only the last has none.
        let (map_len, map_pad_begin_len, trampoline_relative_page_range) = if addr == 0 {
            // The call that establishes the load address is the one that must
            // also keep the trampoline pages: it has padding and an executable
            // segment, unlike the bare one-page map `ldelf` makes to read the
            // ELF header. Only the first such call counts, so that the pages
            // already kept stay tracked.
            //
            // TODO: consider a reliable solution.
            let trampoline_page_range = if (pad_begin > 0 || pad_end > 0)
                && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
                && self.ta_trampoline_page_range.get().is_none()
            {
                let ta_uuid = self
                    .ta_handle_map
                    .get(handle)
                    .ok_or(TeeResult::BadParameters)?;
                // Fail here rather than let `ldelf` allocate over the
                // trampoline and report something unrelated later.
                crate::loader::elf::ElfLoader::ta_trampoline_relative_page_range(self, &ta_uuid)
                    .map_err(|_| TeeResult::BadFormat)?
            } else {
                None
            };
            (padded_len, pad_begin, trampoline_page_range)
        } else {
            // `NOREPLACE` so a segment cannot silently replace an existing
            // mapping: the padding is unmapped, so nothing guards the span.
            //
            // The trampoline pages are cut out of the padding checks but not
            // out of this map, so a segment overlapping them fails here where
            // OP-TEE would succeed. `ldelf` never gets that far: they start at
            // `roundup(max p_vaddr + p_memsz)`, exactly where the last segment
            // ends. A TA naming such an address via `PTA_SYSTEM_MAP_ZI` would be
            // mapping over its own trampoline, so refuse this.
            self.ensure_pads_are_unmapped(addr, segment_len, pad_begin, pad_end)?;
            flags_internal |= MapFlags::MAP_FIXED_NOREPLACE;
            (segment_len, 0, None)
        };
        // `map_len` is the span `ldelf` knows about; `alloc_len` is what we
        // actually request. The trampoline sits past the image, so it falls
        // inside `pad_end` or just beyond: widen the request to cover it, so the
        // allocator finds a gap that fits both. The trim below releases the
        // padding but leaves the trampoline pages mapped, so they stay free
        // until `load_ta_context` loads the trampoline into them.
        let alloc_len = match &trampoline_relative_page_range {
            Some(range) => map_len.max(
                pad_begin
                    .checked_add(range.end)
                    .ok_or(TeeResult::OutOfMemory)?,
            ),
            None => map_len,
        };
        // Currently, we do not support TA binary mapping. So, we create an anonymous mapping and copy
        // the content of the TA binary into it.
        let map_base_addr = self
            .sys_mmap(
                addr,
                alloc_len,
                ProtFlags::PROT_READ_WRITE,
                flags_internal,
                -1,
                0,
            )
            .map_err(TeeResult::from)?;
        let guard = MmapGuard::new(self, map_base_addr, alloc_len);

        let usable_start_addr = map_base_addr
            .as_usize()
            .checked_add(map_pad_begin_len)
            .ok_or(TeeResult::BadParameters)?;
        if usable_start_addr == 0 {
            return Err(TeeResult::BadFormat);
        }

        if self
            .read_ta_bin(
                handle,
                UserMutPtr::from_usize(usable_start_addr),
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
        let prot_start_addr = align_down(usable_start_addr, PAGE_SIZE);
        let prot_len = usable_start_addr
            .checked_sub(prot_start_addr)
            .and_then(|offset| offset.checked_add(num_bytes))
            .and_then(|len| len.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(TeeResult::BadParameters)?;
        if self
            .sys_mprotect(UserMutPtr::from_usize(prot_start_addr), prot_len, prot)
            .is_err()
        {
            return Err(TeeResult::AccessDenied);
        }

        // Unmap the padding regions to free physical memory.
        // Using munmap instead of mprotect(PROT_NONE) actually deallocates the frames.
        // pad_begin region: [map_base_addr, align_down(usable_start_addr, PAGE_SIZE))
        let pad_begin_end_addr = align_down(usable_start_addr, PAGE_SIZE);
        if map_base_addr.as_usize() < pad_begin_end_addr {
            let _ = self.sys_munmap(map_base_addr, pad_begin_end_addr - map_base_addr.as_usize());
        }
        // pad_end region: [align_up(usable_start_addr + num_bytes, PAGE_SIZE), map_base_addr + alloc_len),
        // except the trampoline pages, which stay mapped.
        let pad_end_start_addr = Self::get_aligned_start_of_pad_end(usable_start_addr, num_bytes)?;
        let alloc_end_addr = map_base_addr
            .as_usize()
            .checked_add(alloc_len)
            .ok_or(TeeResult::BadParameters)?;
        let trampoline_page_range = match trampoline_relative_page_range {
            Some(range) => Some(
                usable_start_addr
                    .checked_add(range.start)
                    .ok_or(TeeResult::BadParameters)?
                    ..usable_start_addr
                        .checked_add(range.end)
                        .ok_or(TeeResult::BadParameters)?,
            ),
            None => None,
        };
        if pad_end_start_addr < alloc_end_addr {
            let mut to_release = rangemap::RangeSet::new();
            to_release.insert(pad_end_start_addr..alloc_end_addr);
            if let Some(range) = &trampoline_page_range {
                to_release.remove(range.clone());
            }
            for range in to_release.iter() {
                let _ =
                    self.sys_munmap(UserMutPtr::from_usize(range.start), range.end - range.start);
            }
        }

        let _ = va.write_at_offset(0, usable_start_addr);
        guard.disarm();
        // Record the trampoline pages so the padding checks treat them as unmapped.
        if let Some(range) = trampoline_page_range {
            self.ta_trampoline_page_range
                .set(Some((range.start, range.end)));
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

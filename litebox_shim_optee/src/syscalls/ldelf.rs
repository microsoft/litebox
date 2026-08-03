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

    /// Ensure the `pad_end` placement constraint holds for a fixed-address map.
    ///
    /// OP-TEE keeps an ordered list of a TA's mapped regions and places a new
    /// one in the first gap that fits `pad_begin + ROUNDUP(num_bytes) +
    /// pad_end`, then records only `ROUNDUP(num_bytes)`. The padding is never
    /// mapped or tracked; it just pushes the region away from its neighbors.
    ///
    /// The constraint still applies once `ldelf` names the address: OP-TEE
    /// requires `pad_end` to clear the next region and reports an access
    /// conflict otherwise. Mapping the segment alone would only check
    /// `ROUNDUP(num_bytes)`, so probe the padding as well and reject what
    /// OP-TEE would reject. (The userland runner shares a page table with the
    /// host, so a host allocation can take the padding too, but that runner is
    /// for testing.)
    fn ensure_pad_end_is_unmapped(
        &self,
        pad_end_start_addr: usize,
        pad_end_len: usize,
    ) -> Result<(), TeeResult> {
        let mut pad_end_limit_addr = pad_end_start_addr
            .checked_add(pad_end_len)
            .ok_or(TeeResult::BadParameters)?;
        match self.ta_initial_map_end_addr.get() {
            // No initial map was made, so there is nothing of ours to check.
            0 => return Ok(()),
            ta_initial_map_end_addr => {
                // `ldelf` rounds `pad_end` and the segment separately, so an uncapped
                // probe can reach one page past the image. Cap it.
                pad_end_limit_addr = pad_end_limit_addr.min(ta_initial_map_end_addr);
            }
        }
        let Some(probe_len) = pad_end_limit_addr
            .checked_sub(pad_end_start_addr)
            .filter(|probe_len| *probe_len != 0)
        else {
            return Ok(());
        };
        match self.sys_mmap(
            pad_end_start_addr,
            probe_len,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED_NOREPLACE,
            -1,
            0,
        ) {
            // Leaving the probe mapped would make the next segment collide with it.
            Ok(probe_addr) => {
                debug_assert_eq!(probe_addr.as_usize(), pad_end_start_addr);
                self.sys_munmap(probe_addr, probe_len)
                    .map_err(TeeResult::from)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// OP-TEE's syscall to map zero-initialized memory with padding.
    ///
    /// `va` is either `0` (OP-TEE should select the address) or the fixed address
    /// `ldelf` derived. `pad_begin` and `pad_end` only steer that selection: only
    /// `ROUNDUP(num_bytes)` is mapped, and the padding must not be accessed by
    /// the TA.
    ///
    /// The usable region is `num_bytes` long and is zero-initialized. It starts
    /// at the mapping base selected or supplied for this call plus `pad_begin`;
    /// fixed-address calls require `pad_begin == 0`.
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
        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE.
        let mut flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        // When LiteBox gets the initial `va == 0` call, it maps the padded span
        // so its allocator can pick a large enough gap and then unmaps the
        // padding. Later fixed-address calls map only the usable region.
        let (map_len, map_pad_begin_len) = if va == 0 {
            (padded_len, pad_begin)
        } else {
            if pad_begin != 0 {
                return Err(TeeResult::BadParameters);
            }
            let pad_end_start_addr = va
                .checked_add(segment_len)
                .ok_or(TeeResult::BadParameters)?;
            self.ensure_pad_end_is_unmapped(pad_end_start_addr, pad_end)?;
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
        // Record the initial location-selecting map's upper address so later
        // pad_end collision probes stop at the span `ldelf` originally
        // selected. Commit it only after the mapping succeeds.
        if va == 0 && pad_end != 0 {
            self.ta_initial_map_end_addr.set(map_end_addr);
        }
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

        let padded_len = Self::checked_map_len(num_bytes, pad_begin, pad_end)?;
        if addr.checked_add(padded_len).is_none() {
            return Err(TeeResult::BadParameters);
        }
        let segment_len = Self::checked_map_len(num_bytes, 0, 0)?;

        // We map with PROT_READ_WRITE first, then mprotect padding regions to PROT_NONE as
        // explained in `sys_map_zi`.
        let mut flags_internal = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        // TODO: on Arm, check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` to control cache behaviors

        // `ldelf` either asks OP-TEE to select `va` (`addr == 0`) or supplies
        // the fixed address chosen by the first map.
        //
        // `pad_begin` is a random offset `ldelf` puts before the image for ASLR;
        // `pad_end` covers the segments that follow. Both only widen the gap
        // OP-TEE looks for when placing this segment — it maps just
        // `ROUNDUP(num_bytes)` — so every segment's `pad_end` overlaps the rest
        // of the image.
        let (map_len, map_pad_begin_len, should_add_trampoline_page) = if addr == 0 {
            // Temporarily map the padded span so LiteBox's allocator picks a
            // gap wide enough for the whole image, then unmap the padding.
            //
            // Map one extra page for the LiteBox trampoline beyond the span
            // OP-TEE asked for. Identify this call heuristically: it has
            // nonzero padding and an executable first segment. Kernel-mode
            // platforms report no syscall entry point and need no trampoline.
            //
            // TODO: consider a reliable solution.
            let needs_trampoline = (pad_begin > 0 || pad_end > 0)
                && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
                && self.global.platform.get_syscall_entry_point() != 0;
            (padded_len, pad_begin, needs_trampoline)
        } else {
            // The slot is already chosen, so map only the segment and probe the
            // trailing padding for collisions instead.
            if pad_begin != 0 {
                // `ldelf` pads the start only when it lets us pick the address.
                return Err(TeeResult::BadParameters);
            }
            let pad_end_start_addr = addr
                .checked_add(segment_len)
                .ok_or(TeeResult::BadParameters)?;
            self.ensure_pad_end_is_unmapped(pad_end_start_addr, pad_end)?;
            // `NOREPLACE` so a segment cannot silently replace an existing
            // mapping: the padding is unmapped, so nothing guards the span.
            flags_internal |= MapFlags::MAP_FIXED_NOREPLACE;
            (segment_len, 0, false)
        };
        // `map_len` is the span `ldelf` knows about; `alloc_len` is what we
        // actually request from `mmap`.
        let alloc_len = if should_add_trampoline_page {
            // The OP-TEE TA trampoline is 0x3f8 bytes, so one page is enough.
            // Everything below keeps trimming by `map_len`, leaving the extra
            // page mapped and unseen by `ldelf`.
            map_len
                .checked_add(PAGE_SIZE)
                .ok_or(TeeResult::OutOfMemory)?
        } else {
            map_len
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
        // pad_end region: [align_up(usable_start_addr + num_bytes, PAGE_SIZE), map_base_addr + map_len)
        let pad_end_start_addr = Self::get_aligned_start_of_pad_end(usable_start_addr, num_bytes)?;
        let map_end_addr = map_base_addr
            .as_usize()
            .checked_add(map_len)
            .ok_or(TeeResult::BadParameters)?;
        if pad_end_start_addr < map_end_addr {
            let _ = self.sys_munmap(
                UserMutPtr::from_usize(pad_end_start_addr),
                map_end_addr - pad_end_start_addr,
            );
        }

        let _ = va.write_at_offset(0, usable_start_addr);
        guard.disarm();
        // Record the initial location-selecting map's upper address so later
        // pad_end collision probes stop at the span `ldelf` originally
        // selected. Commit it only after the mapping succeeds.
        if addr == 0 && pad_end != 0 {
            self.ta_initial_map_end_addr.set(map_end_addr);
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

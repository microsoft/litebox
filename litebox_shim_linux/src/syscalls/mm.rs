// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].
//!
//! Runtime ELF syscall patching of file mappings lives in [`crate::loader::patch`].

use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox_common_linux::PAGE_SIZE;
use litebox_common_linux::{
    IoReadVec, MRemapFlags, MapFlags, ProtFlags,
    errno::Errno,
    mm::MmapPlacement,
    vmem::{MappingError, SharedObjectMapping, VmemProtectError},
};
use litebox_platform::buffer::Buffer as _;

use crate::ShimPlatform;
use crate::Task;
use crate::UserPtrMut;
use crate::guest_buffer::GuestReadBuffer;
use crate::syscalls::file::AnyTypedFd;
use litebox_broker_protocol::fs::FileAccessMode;

pub(crate) fn prot_flags_from_permissions(permissions: MemoryRegionPermissions) -> ProtFlags {
    let mut prot = ProtFlags::PROT_NONE;
    prot.set(
        ProtFlags::PROT_READ,
        permissions.contains(MemoryRegionPermissions::READ),
    );
    prot.set(
        ProtFlags::PROT_WRITE,
        permissions.contains(MemoryRegionPermissions::WRITE),
    );
    prot.set(
        ProtFlags::PROT_EXEC,
        permissions.contains(MemoryRegionPermissions::EXEC),
    );
    prot
}

impl<Platform: ShimPlatform> Task<Platform> {
    pub(crate) fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        op: impl FnOnce(UserPtrMut<u8>) -> Result<usize, MappingError>,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let fixed_start = suggested_addr.filter(|_| flags.contains(MapFlags::MAP_FIXED));
        self.global.mm.do_mmap(
            suggested_addr,
            len,
            prot,
            flags,
            MmapPlacement {
                direction: litebox::platform::page_mgmt::AllocationDirection::TopDown,
                allowed_range: None,
            },
            |pointer| {
                if let Some(start) = fixed_start {
                    self.clear_file_mappings_for_range(start, len);
                }
                op(pointer)
            },
        )
    }

    /// Map a file, applying runtime ELF syscall patching to the new mapping.
    pub(crate) fn do_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        let typed_fd = self.typed_fd(fd)?;
        let AnyTypedFd::File(file_fd) = &typed_fd else {
            return Err(Errno::ENODEV);
        };

        let patch = self.begin_file_patch(file_fd, suggested_addr, len, prot, flags, offset)?;
        let (addr, flags) = patch.placement(suggested_addr, flags);
        let mapped = match self.do_mmap_file_memcpy(addr, len, prot, flags, &typed_fd, offset) {
            Ok(mapped) => mapped,
            Err(error) => {
                self.abort_file_patch(patch);
                return Err(error.into());
            }
        };
        self.complete_file_patch(patch, mapped)?;
        Ok(mapped)
    }

    /// Map a file by reading its contents through the filesystem API into allocated pages.
    fn do_mmap_file_memcpy(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: &AnyTypedFd<Platform>,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |ptr: UserPtrMut<u8>| -> Result<usize, MappingError> {
            // A malicious user may unmap ptr while we are reading, which the
            // guest buffer's copies survive as faults.
            let iov = IoReadVec {
                iov_base: ptr,
                iov_len: len,
            };
            let mut buffer = GuestReadBuffer::<Platform>::single(&iov);
            let mut copied = 0;
            while copied < len {
                let size = self
                    .do_read(
                        fd,
                        (&mut buffer).sub_buffer(copied, len - copied),
                        Some(offset + copied),
                    )
                    .map_err(|e| match e {
                        // The raw fd was resolved once at syscall entry and is intentionally
                        // not retained; this payload is discarded when converted to EBADF.
                        Errno::EBADF => MappingError::BadFD(-1),
                        Errno::EISDIR => MappingError::NotAFile,
                        Errno::EACCES => MappingError::NotForReading,
                        Errno::EFAULT => MappingError::MemoryAccess,
                        _ => unimplemented!(),
                    })?;
                if size == 0 {
                    break;
                }
                copied += size;
            }
            Ok(copied)
        };
        let ptr = self.do_mmap(suggested_addr, len, ProtFlags::PROT_READ_WRITE, flags, op)?;
        if prot != ProtFlags::PROT_READ_WRITE && self.sys_mprotect_raw(ptr, len, prot).is_err() {
            // TODO: Protection may be unsupported (e.g. write-only), or another thread may
            // have unmapped the range. Best-effort cleanup may unmap a replacement
            // mapping if another thread unmaps and remaps this range before cleanup.
            let _ = self.sys_munmap_raw(ptr, len);
            return Err(VmemProtectError::UnsupportedProtection.into());
        }
        Ok(ptr)
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
    ) -> Result<UserPtrMut<u8>, Errno> {
        // check alignment
        if !offset.is_multiple_of(PAGE_SIZE) || !addr.is_multiple_of(PAGE_SIZE) || len == 0 {
            return Err(Errno::EINVAL);
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

        let aligned_len = len
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::ENOMEM)?;
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        // MAP_SHARED is supported as follows:
        // - Anonymous shared mappings are fully supported. Where the platform supports shared
        //   pages, a native fork child shares them; elsewhere `fork` fails with `EAGAIN` rather
        //   than copying them.
        // - File-backed shared mappings map the host shared object holding the file's contents
        //   where the platform and file system support it, as described in
        //   `do_mmap_shared_file`.
        let suggested_addr = if addr == 0 { None } else { Some(addr) };
        if flags.contains(MapFlags::MAP_ANONYMOUS) {
            self.do_mmap(suggested_addr, aligned_len, prot, flags, |_| Ok(0))
                .map_err(Errno::from)
        } else if flags.contains(MapFlags::MAP_SHARED) {
            self.do_mmap_shared_file(suggested_addr, aligned_len, prot, flags, fd, offset)
        } else {
            self.do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
        }
    }

    /// Maps a file `MAP_SHARED`.
    ///
    /// Where the platform and the file system support it, the mapping maps the host shared
    /// object that holds the file's contents. Every mapping of the file, in this or any other
    /// process, including native fork children, then shares its pages, and `read`, `write`, and
    /// `ftruncate` on the file see and change the same bytes.
    ///
    /// Otherwise, as for files that never change, a mapping that can never become writable is a
    /// private copy of the file, and a writable one fails with `ENODEV`. So is a mapping with
    /// `PROT_EXEC` but not `PROT_WRITE`, which keeps runtime syscall patching for code.
    fn do_mmap_shared_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        use litebox::fs::errors::MapSharedError;

        let typed_fd = self.typed_fd(fd)?;
        let AnyTypedFd::File(file_fd) = &typed_fd else {
            return Err(Errno::ENODEV);
        };
        let writable = prot.contains(ProtFlags::PROT_WRITE);
        let copy = || {
            // As on Linux, a shared mapping needs a readable file, and a writable one needs a
            // file open for writing too.
            let may_write = match self
                .global
                .with_file(file_fd, super::file::File::access_mode)?
            {
                FileAccessMode::ReadOnly => false,
                FileAccessMode::ReadWrite => true,
                _ => return Err(Errno::EACCES),
            };
            if !writable {
                self.do_mmap_file(suggested_addr, len, prot, flags, fd, offset)
            } else if may_write {
                Err(Errno::ENODEV)
            } else {
                Err(Errno::EACCES)
            }
        };
        if (prot.contains(ProtFlags::PROT_EXEC) && !writable)
            || !self.global.platform.supports_shared_objects()
        {
            return copy();
        }
        let object = match self
            .global
            .with_file(file_fd, |file| Ok(file.map_shared(true)))?
        {
            Ok(object) => object,
            Err(MapSharedError::Unsupported) => return copy(),
            Err(MapSharedError::ClosedFd) => return Err(Errno::EBADF),
            Err(MapSharedError::IsDirectory) => return Err(Errno::ENODEV),
            Err(MapSharedError::NotForReading) => return Err(Errno::EACCES),
            Err(MapSharedError::NoMemory | MapSharedError::Io) => return Err(Errno::ENOMEM),
        };
        // The broker delivers the object writable exactly when the file is open for writing,
        // which Linux requires of a writable shared mapping, or one `mprotect` may make writable.
        if writable && !object.writable {
            // SAFETY: The broker just delivered this token, and nothing else consumes it.
            unsafe { self.global.platform.release_shared_object(object.token) };
            return Err(Errno::EACCES);
        }
        // SAFETY: The broker just delivered this token, and nothing else consumes it.
        let mapped = unsafe {
            self.global.mm.do_mmap_shared_object(
                suggested_addr,
                len,
                prot,
                flags,
                MmapPlacement {
                    direction: litebox::platform::page_mgmt::AllocationDirection::TopDown,
                    allowed_range: None,
                },
                SharedObjectMapping {
                    memory: object.memory,
                    token: object.token,
                    offset: offset as u64,
                    may_write: object.writable,
                },
            )
        }?;
        if flags.contains(MapFlags::MAP_FIXED) {
            self.clear_file_mappings_for_range(mapped.as_usize(), len);
        }
        Ok(mapped)
    }

    /// Handle syscall `munmap`
    #[inline]
    pub(crate) fn sys_munmap(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        let result = self.sys_munmap_raw(addr, len);
        if result.is_ok() {
            self.clear_file_mappings_for_range(addr.as_usize(), len.next_multiple_of(PAGE_SIZE));
        }
        result
    }

    /// Raw munmap without clearing file_mappings — used internally by the
    /// patching logic to avoid deadlocks (the patch path holds elf_patch_cache).
    #[inline]
    pub(crate) fn sys_munmap_raw(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        self.global.mm.sys_munmap(addr, len)
    }

    /// Handle syscall `mprotect`
    #[inline]
    pub(crate) fn sys_mprotect(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        if !addr.as_usize().is_multiple_of(PAGE_SIZE)
            || !len.is_multiple_of(PAGE_SIZE)
            || addr.as_usize().checked_add(len).is_none()
            || prot.bits() & !ProtFlags::PROT_READ_WRITE_EXEC.bits() != 0
        {
            return Err(Errno::EINVAL);
        }

        // Intercept transitions to PROT_EXEC: patch unpatched file mappings.
        if prot.contains(ProtFlags::PROT_EXEC) {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0 {
                self.maybe_patch_on_mprotect_exec(addr, len, syscall_entry)?;
            }
        }
        self.mprotect_around_trampolines(addr.as_usize(), len, prot)
    }

    /// Raw mprotect without exec interception — used internally by the
    /// patching logic to avoid deadlocks (the patch path holds elf_patch_cache).
    #[inline]
    pub(crate) fn sys_mprotect_raw(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        self.global.mm.sys_mprotect(addr, len, prot)
    }

    #[inline]
    pub(crate) fn sys_mremap(
        &self,
        old_addr: UserPtrMut<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        let result = self
            .global
            .mm
            .sys_mremap(old_addr, old_size, new_size, flags, new_addr)?;
        let old_size = old_size.next_multiple_of(PAGE_SIZE);
        let new_size = new_size.next_multiple_of(PAGE_SIZE);
        if result.as_usize() != old_addr.as_usize() {
            self.clear_file_mappings_for_range(old_addr.as_usize(), old_size);
            self.clear_file_mappings_for_range(result.as_usize(), new_size);
        } else if new_size < old_size {
            self.clear_file_mappings_for_range(old_addr.as_usize() + new_size, old_size - new_size);
        }
        Ok(result)
    }

    /// Handle syscall `brk`
    #[inline]
    pub(crate) fn sys_brk(&self, addr: UserPtrMut<u8>) -> Result<usize, Errno> {
        // On failure, Linux returns the current break rather than a negative errno.
        unsafe {
            self.global
                .mm
                .brk(addr.as_usize())
                .or_else(|_| self.global.mm.brk(0))
        }
        .map_err(Errno::from)
    }

    /// Handle syscall `madvise`
    #[inline]
    pub(crate) fn sys_madvise(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        advice: litebox_common_linux::MadviseBehavior,
    ) -> Result<(), Errno> {
        self.global.mm.sys_madvise(addr, len, advice)
    }

    /// Handle syscall `msync`
    pub(crate) fn sys_msync(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        flags: i32,
    ) -> Result<(), Errno> {
        self.global.mm.sys_msync(addr, len, flags)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::PAGE_SIZE;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    use litebox::platform::PageManagementProvider;
    use litebox_broker_protocol::fs::FileMode as Mode;
    use litebox_common_linux::MRemapFlags;
    use litebox_common_linux::{MapFlags, OFlags, ProtFlags, errno::Errno};

    use crate::UserPtrMut;
    use crate::syscalls::tests::{TestPlatform as Platform, create_file, init_platform};

    #[test]
    fn brk_respects_initial_break_and_shrinks_within_current_page() {
        let task = init_platform();
        let initial = 0x4000_0123;
        let below_initial = 0x4000_0042;
        let grown = 0x4000_0321;
        let requested = 0x4000_0246;
        task.global.mm.set_initial_brk(initial);

        assert_eq!(
            task.sys_brk(UserPtrMut::from_usize(below_initial)),
            Ok(initial)
        );
        assert_eq!(
            task.sys_brk(UserPtrMut::from_usize(usize::MAX)),
            Ok(initial)
        );
        assert_eq!(task.sys_brk(UserPtrMut::from_usize(0)), Ok(initial));
        assert_eq!(task.sys_brk(UserPtrMut::from_usize(grown)), Ok(grown));
        assert_eq!(
            task.sys_brk(UserPtrMut::from_usize(requested)),
            Ok(requested)
        );
        assert_eq!(task.sys_brk(UserPtrMut::from_usize(0)), Ok(requested));
    }

    #[test]
    fn test_anonymous_mmap() {
        let task = init_platform();

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
        addr.write_slice_at_offset::<Platform>(0, &[0xff; 0x2000])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0x1000).unwrap(), 0xff,);
        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_file_backed_mmap() {
        let content = b"Hello, world!";
        let task = init_platform();
        create_file(&task, "/test.txt", content);
        let fd = i32::try_from(
            task.sys_open("/test.txt", OFlags::RDONLY, Mode::empty())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            task.sys_mmap(
                0,
                usize::MAX - super::PAGE_SIZE + 1,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap_err(),
            Errno::ENOMEM
        );
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
            addr.to_owned_slice::<Platform>(content.len())
                .unwrap()
                .as_ref(),
            content.as_slice(),
        );
        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_mremap() {
        let task = init_platform();

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
            task.sys_mremap(addr, 0x1000, 0x2000, MRemapFlags::empty(), 0),
            Err(litebox_common_linux::errno::Errno::ENOMEM)
        ),);
        let new_addr = task
            .sys_mremap(addr, 0x1000, 0x2000, MRemapFlags::MREMAP_MAYMOVE, 0)
            .unwrap();
        task.sys_munmap(addr, 0x2000).unwrap();
        task.sys_munmap(new_addr, 0x2000).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn self_placed_mappings_stay_below_placement_limit() {
        let task = init_platform();
        let limit = <Platform as PageManagementProvider<PAGE_SIZE>>::PLACEMENT_ADDR_MAX;
        assert!(limit < <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX);
        let below_limit = |address: UserPtrMut<u8>, len: usize| {
            assert!(
                address.as_usize() + len <= limit,
                "mapping at {:#x} crosses the placement limit {limit:#x}",
                address.as_usize(),
            );
        };
        let read_write = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
        let anonymous = MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE;

        let unhinted = task
            .sys_mmap(0, 2 * PAGE_SIZE, read_write, anonymous, -1, 0)
            .unwrap();
        below_limit(unhinted, 2 * PAGE_SIZE);

        let hinted = task
            .sys_mmap(limit, PAGE_SIZE, read_write, anonymous, -1, 0)
            .unwrap();
        below_limit(hinted, PAGE_SIZE);

        // Native remapping must honor the destination vmem chose instead of letting the host
        // kernel pick one, and must still carry the contents along.
        unhinted
            .write_slice_at_offset::<Platform>(0, &[0xa5; 0x10])
            .unwrap();
        let moved = task
            .sys_mremap(
                unhinted,
                PAGE_SIZE,
                4 * PAGE_SIZE,
                MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        below_limit(moved, 4 * PAGE_SIZE);
        assert_eq!(moved.read_at_offset::<Platform>(0).unwrap(), 0xa5_u8);

        let fixed = task
            .sys_mmap(
                limit,
                PAGE_SIZE,
                read_write,
                anonymous | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(fixed.as_usize(), limit);

        for (address, len) in [
            (unhinted, 2 * PAGE_SIZE),
            (hinted, PAGE_SIZE),
            (moved, 4 * PAGE_SIZE),
            (fixed, PAGE_SIZE),
        ] {
            task.sys_munmap(address, len).unwrap();
        }
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn repeated_moving_growth_keeps_contents() {
        const PAGE: isize = PAGE_SIZE.cast_signed();
        let task = init_platform();
        let read_write = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
        let anonymous = MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE;
        // Occupies the page after a mapping so that growing it has to move it.
        let block_after = |address: UserPtrMut<u8>, len: usize| {
            task.sys_mmap(
                address.as_usize() + len,
                PAGE_SIZE,
                ProtFlags::PROT_NONE,
                anonymous | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .ok()
        };

        let first = task
            .sys_mmap(0, 2 * PAGE_SIZE, read_write, anonymous, -1, 0)
            .unwrap();
        first
            .write_slice_at_offset::<Platform>(0, &[0xa5; 0x10])
            .unwrap();
        let first_block = block_after(first, 2 * PAGE_SIZE);
        let second = task
            .sys_mremap(
                first,
                2 * PAGE_SIZE,
                4 * PAGE_SIZE,
                MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        assert_ne!(second.as_usize(), first.as_usize());
        second
            .write_slice_at_offset::<Platform>(3 * PAGE, &[0x5a; 0x10])
            .unwrap();

        // The moved pages and the grown tail are separate host mappings that must move together.
        let second_block = block_after(second, 4 * PAGE_SIZE);
        let third = task
            .sys_mremap(
                second,
                4 * PAGE_SIZE,
                8 * PAGE_SIZE,
                MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        assert_ne!(third.as_usize(), second.as_usize());
        assert_eq!(third.read_at_offset::<Platform>(0).unwrap(), 0xa5_u8);
        assert_eq!(third.read_at_offset::<Platform>(3 * PAGE).unwrap(), 0x5a_u8);
        assert_eq!(third.read_at_offset::<Platform>(5 * PAGE).unwrap(), 0_u8);

        task.sys_munmap(third, 8 * PAGE_SIZE).unwrap();
        for block in [first_block, second_block].into_iter().flatten() {
            task.sys_munmap(block, PAGE_SIZE).unwrap();
        }
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "fixed address lies in Darwin's PAGEZERO"
    )]
    fn test_mmap_fixed_noreplace() {
        let task = init_platform();

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

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_collision_with_global_allocator() {
        let task = init_platform();
        let external_platform = Platform::new();
        let mut data = alloc::vec::Vec::new();
        let mut count = 0;
        // Model an external allocator allocation that LiteBox's page manager does not track.
        let addr = loop {
            assert!(
                count < 100,
                "Failed to find a suitable address after 100 attempts"
            );
            count += 1;
            let addr = {
                use litebox::platform::page_mgmt::{
                    AllocationDirection, AllocationOptions, FixedAddressBehavior,
                    MemoryRegionPermissions, PageReservation as _,
                };

                let task_addr_min = <Platform as PageManagementProvider<4096>>::TASK_ADDR_MIN;
                let reservation_alignment =
                    <Platform as PageManagementProvider<4096>>::RESERVATION_ALIGNMENT;
                let suggested_start = task_addr_min + count * reservation_alignment;
                // SAFETY: The hint is aligned and within task bounds; no mappings are replaced.
                let reservation = unsafe {
                    <Platform as PageManagementProvider<4096>>::reserve_and_commit_pages(
                        external_platform,
                        core::iter::empty,
                        suggested_start..suggested_start + 0x1000,
                        MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                        AllocationOptions::empty(),
                        FixedAddressBehavior::Hint(AllocationDirection::TopDown),
                    )
                }
                .unwrap();
                let allocation = reservation.range().start;
                data.push(reservation);
                allocation
            };

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

        // Growing without MREMAP_MAYMOVE must fail because the next page belongs to the
        // independently managed external allocation.
        let err = task
            .sys_mremap(
                UserPtrMut::from_usize(addr - 0x1000),
                0x1000,
                0x2000,
                MRemapFlags::empty(),
                addr - 0x1000,
            )
            .unwrap_err();
        assert_eq!(err, Errno::ENOMEM);

        task.sys_munmap(res, 0x1000).unwrap();
        task.sys_munmap(UserPtrMut::from_usize(addr - 0x1000), 0x1000)
            .unwrap();
        #[cfg_attr(
            target_os = "windows",
            expect(
                clippy::useless_conversion,
                reason = "tracked Windows reservations are their own release target"
            )
        )]
        for reservation in data {
            // SAFETY: The page belongs to the external provider and has no outstanding references.
            unsafe {
                <Platform as PageManagementProvider<4096>>::release_pages(
                    external_platform,
                    reservation.into(),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn test_map_shared_anonymous() {
        let task = init_platform();

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
        let _val: u8 = addr.read_at_offset::<Platform>(0).unwrap();

        // Anonymous shared mappings allow permission changes including write
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap();
        addr.write_slice_at_offset::<Platform>(0, &[0xab; 0x10])
            .unwrap();
        addr.write_slice_at_offset::<Platform>(0x1000, &[0xcd; 0x10])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0).unwrap(), 0xab_u8);

        // mprotect to read-only or read-exec should also succeed
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ)
            .unwrap();
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ_EXEC)
            .unwrap();

        // Partially unmapping a shared mapping keeps the rest and its contents.
        task.sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ)
            .unwrap();
        task.sys_munmap(addr, 0x1000).unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0x1000).unwrap(), 0xcd_u8);
        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_protect_private_shared_boundaries() {
        let task = init_platform();
        let writable = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
        let private = MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE;
        let base = task.sys_mmap(0, 0x4000, writable, private, -1, 0).unwrap();
        let middle = UserPtrMut::from_usize(base.as_usize() + 0x1000);
        task.sys_munmap(middle, 0x2000).unwrap();
        assert_eq!(
            task.sys_mmap(
                middle.as_usize(),
                0x2000,
                writable,
                MapFlags::MAP_ANON | MapFlags::MAP_SHARED | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap()
            .as_usize(),
            middle.as_usize()
        );
        for detached in [false, true] {
            if detached {
                task.sys_munmap(middle, 0x2000).unwrap();
                assert_eq!(
                    task.sys_mmap(
                        middle.as_usize(),
                        0x2000,
                        writable,
                        private | MapFlags::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    )
                    .unwrap()
                    .as_usize(),
                    middle.as_usize()
                );
            }
            task.sys_mprotect(middle, 0x1000, ProtFlags::PROT_READ)
                .unwrap();
            task.sys_mprotect(base, 0x4000, ProtFlags::PROT_READ)
                .unwrap();
            task.sys_mprotect(base, 0x4000, writable).unwrap();
            for offset in [0, 0x1000, 0x2000, 0x3000] {
                base.write_slice_at_offset::<Platform>(offset, &[0x42])
                    .unwrap();
                assert_eq!(base.read_at_offset::<Platform>(offset).unwrap(), 0x42_u8);
            }
        }
        task.sys_munmap(base, 0x4000).unwrap();
    }

    #[test]
    fn test_map_shared_anonymous_writable() {
        let task = init_platform();

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

        addr.write_slice_at_offset::<Platform>(0, &[0xcd; 0x10])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0).unwrap(), 0xcd_u8);

        task.sys_munmap(addr, 0x1000).unwrap();
    }

    #[test]
    fn test_map_shared_readonly_file() {
        let content = b"Hello, shared!";
        let task = init_platform();
        create_file(&task, "/shared.txt", content);
        let fd = i32::try_from(
            task.sys_open("/shared.txt", OFlags::RDONLY, Mode::empty())
                .unwrap(),
        )
        .unwrap();

        // MAP_SHARED with PROT_READ on a file should succeed
        let addr = task
            .sys_mmap(0, 0x1000, ProtFlags::PROT_READ, MapFlags::MAP_SHARED, fd, 0)
            .unwrap();

        // Data should match
        assert_eq!(
            addr.to_owned_slice::<Platform>(content.len())
                .unwrap()
                .as_ref(),
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
    fn shared_file_mappings_check_access_and_need_shared_objects_to_write() {
        let task = init_platform();
        create_file(&task, "/shared.txt", b"shared");
        let open = |flags| {
            i32::try_from(task.sys_open("/shared.txt", flags, Mode::empty()).unwrap()).unwrap()
        };
        let read_write = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;

        // As on Linux, a shared mapping needs a readable file, and a writable one a file that
        // is open for writing too.
        let read_only = open(OFlags::RDONLY);
        assert_eq!(
            task.sys_mmap(0, 0x1000, read_write, MapFlags::MAP_SHARED, read_only, 0)
                .err(),
            Some(Errno::EACCES)
        );
        let write_only = open(OFlags::WRONLY);
        assert_eq!(
            task.sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                write_only,
                0
            )
            .err(),
            Some(Errno::EACCES)
        );

        // This platform has no channel for host shared objects, so a writable shared mapping
        // cannot be coherent with the file and fails, while a read-only one is a copy.
        let read_write_fd = open(OFlags::RDWR);
        assert_eq!(
            task.sys_mmap(
                0,
                0x1000,
                read_write,
                MapFlags::MAP_SHARED,
                read_write_fd,
                0
            )
            .err(),
            Some(Errno::ENODEV)
        );
        let copy = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                read_write_fd,
                0,
            )
            .unwrap();
        assert_eq!(copy.read_at_offset::<Platform>(0), Some(b's'));
        assert!(!task.global.mm.has_shared_pages());
        task.sys_munmap(copy, 0x1000).unwrap();
        for fd in [read_only, write_only, read_write_fd] {
            task.sys_close(fd).unwrap();
        }
    }

    #[test]
    fn msync_validates_its_arguments() {
        const MS_ASYNC: i32 = 1;
        const MS_SYNC: i32 = 4;
        let task = init_platform();
        let mapping = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(task.sys_msync(mapping, 0x2000, MS_SYNC), Ok(()));
        assert_eq!(task.sys_msync(mapping, 1, MS_ASYNC), Ok(()));
        assert_eq!(
            task.sys_msync(mapping, 0x1000, MS_SYNC | MS_ASYNC),
            Err(Errno::EINVAL)
        );
        assert_eq!(task.sys_msync(mapping, 0x1000, 8), Err(Errno::EINVAL));
        let unaligned = UserPtrMut::from_usize(mapping.as_usize() + 1);
        assert_eq!(
            task.sys_msync(unaligned, 0x1000, MS_SYNC),
            Err(Errno::EINVAL)
        );
        task.sys_munmap(mapping, 0x2000).unwrap();
        assert_eq!(task.sys_msync(mapping, 0x1000, MS_SYNC), Err(Errno::ENOMEM));
    }

    #[test]
    fn test_madvise() {
        let task = init_platform();

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

        addr.write_slice_at_offset::<Platform>(0, &[0xff; 0x10])
            .unwrap();

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

        addr.to_owned_slice::<Platform>(0x10)
            .unwrap()
            .iter()
            .for_each(|&x| {
                assert_eq!(x, 0); // Should be zeroed after MADV_DONTNEED
            });

        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_fallible_read() {
        let _ = init_platform();
        // The faulting read is recovered only on a LiteBox-managed thread.
        <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let ptr = UserPtrMut::<u8>::from_usize(0xdeadbeef);
            let result = ptr.read_at_offset::<Platform>(0);
            assert!(result.is_none());
        });
    }

    #[test]
    fn shared_anonymous_memory_survives_madvise_and_can_shrink_but_not_grow() {
        const PAGE: usize = litebox_common_linux::PAGE_SIZE;
        let task = init_platform();
        let mapping = task
            .sys_mmap(
                0,
                2 * PAGE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED | MapFlags::MAP_ANONYMOUS,
                -1,
                0,
            )
            .unwrap();
        mapping.write_at_offset::<Platform>(0, 42).unwrap();
        task.sys_madvise(
            mapping,
            PAGE,
            litebox_common_linux::MadviseBehavior::DontNeed,
        )
        .unwrap();
        // Like Linux shared memory, the contents remain for every process sharing them.
        assert_eq!(mapping.read_at_offset::<Platform>(0), Some(42));

        // Unlike Linux, which grows shared anonymous mappings, LiteBox refuses.
        for flags in [MRemapFlags::empty(), MRemapFlags::MREMAP_MAYMOVE] {
            assert_eq!(
                task.sys_mremap(mapping, 2 * PAGE, 4 * PAGE, flags, 0).err(),
                Some(Errno::ENOMEM)
            );
        }
        let shrunk = task
            .sys_mremap(mapping, 2 * PAGE, PAGE, MRemapFlags::empty(), 0)
            .unwrap();
        assert_eq!(shrunk.as_usize(), mapping.as_usize());
        assert_eq!(shrunk.read_at_offset::<Platform>(0), Some(42));
        task.sys_munmap(mapping, PAGE).unwrap();
    }
}

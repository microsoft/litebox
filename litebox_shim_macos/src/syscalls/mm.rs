// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin virtual-memory syscalls.

use litebox::{
    fs::errors::ReadError,
    mm::linux::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmemProtectError,
    },
    platform::{
        RawConstPointer as _, RawMutPointer as _, page_mgmt::MemoryRegionPermissions as Permissions,
    },
};
use litebox_common_macos::{MmapFlags, PAGE_SIZE, VmProtection, errno::Errno};

use crate::{ShimPlatform, Task};

fn permissions(protection: VmProtection) -> Permissions {
    let mut permissions = Permissions::empty();
    permissions.set(Permissions::READ, protection.contains(VmProtection::READ));
    permissions.set(Permissions::WRITE, protection.contains(VmProtection::WRITE));
    permissions.set(
        Permissions::EXEC,
        protection.contains(VmProtection::EXECUTE),
    );
    permissions
}

fn mapping_flags(flags: MmapFlags, file_backed: bool) -> CreatePagesFlags {
    let mut result = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
    result.set(
        CreatePagesFlags::FIXED_ADDR,
        flags.contains(MmapFlags::FIXED),
    );
    result.set(CreatePagesFlags::SHARED, flags.contains(MmapFlags::SHARED));
    result.set(CreatePagesFlags::MAP_FILE, file_backed);
    result
}

fn mapping_error(error: MappingError) -> Errno {
    match error {
        MappingError::BadFD(_) => Errno::EBADF,
        MappingError::NotForReading => Errno::EACCES,
        MappingError::OutOfMemory | MappingError::MapError(_) => Errno::ENOMEM,
        _ => Errno::EINVAL,
    }
}

fn mmap_read_error(error: ReadError) -> Errno {
    match error {
        ReadError::ClosedFd => Errno::EBADF,
        ReadError::NotAFile => Errno::EINVAL,
        ReadError::NotForReading => Errno::EACCES,
        _ => Errno::EIO,
    }
}

fn protection_error(error: VmemProtectError) -> Errno {
    use litebox::platform::page_mgmt::PermissionUpdateError;

    match error {
        VmemProtectError::InvalidRange(_) => Errno::ENOMEM,
        VmemProtectError::NoAccess { .. } => Errno::EACCES,
        VmemProtectError::UnAligned(_) => Errno::EINVAL,
        VmemProtectError::ProtectError(error) => match error {
            PermissionUpdateError::Unallocated | PermissionUpdateError::OutOfMemory => {
                Errno::ENOMEM
            }
            PermissionUpdateError::PermissionDenied => Errno::EACCES,
            PermissionUpdateError::Unaligned | PermissionUpdateError::PlatformFailure => {
                Errno::EINVAL
            }
            _ => Errno::EINVAL,
        },
    }
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_mmap(
        &self,
        address: usize,
        length: usize,
        protection: VmProtection,
        flags: MmapFlags,
        fd: i32,
        offset: i64,
    ) -> Result<usize, Errno> {
        if length == 0
            || !address.is_multiple_of(PAGE_SIZE)
            || flags.contains(MmapFlags::SHARED) == flags.contains(MmapFlags::PRIVATE)
        {
            return Err(Errno::EINVAL);
        }
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::ENOMEM)?;
        let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        if !offset.is_multiple_of(PAGE_SIZE)
            || offset.checked_add(length).is_none()
            || address.checked_add(length).is_none()
        {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MmapFlags::SHARED)
            && protection.contains(VmProtection::WRITE)
            && !flags.contains(MmapFlags::ANONYMOUS)
        {
            return Err(Errno::ENOTSUP);
        }
        let suggested = NonZeroAddress::new(address);
        let length = NonZeroPageSize::new(length).ok_or(Errno::EINVAL)?;
        if flags.contains(MmapFlags::ANONYMOUS) {
            // SAFETY: MAP_FIXED has Darwin's replacement semantics; otherwise
            // PageManager treats `suggested` only as an allocation hint.
            return unsafe {
                self.global.pm.create_pages_with_permissions(
                    suggested,
                    length,
                    mapping_flags(flags, false),
                    permissions(protection),
                    |_| Ok(0),
                )
            }
            .map(|pointer| pointer.as_usize())
            .map_err(mapping_error);
        }

        let file = self.files.typed_fd(fd)?;
        let mut file_offset = offset;
        let mut buffer = [0; PAGE_SIZE];
        let mut initialization_error = None;
        // SAFETY: MAP_FIXED has Darwin's replacement semantics. Initialization
        // runs while the new mapping is private to this syscall and still RW.
        let result = unsafe {
            self.global.pm.create_pages_with_permissions(
                suggested,
                length,
                mapping_flags(flags, true),
                permissions(protection),
                |pointer| {
                    let mut copied = 0;
                    while copied < length.as_usize() {
                        let chunk = (length.as_usize() - copied).min(buffer.len());
                        let read = self
                            .global
                            .litebox
                            .read_file(&file, &mut buffer[..chunk], Some(file_offset))
                            .map_err(|error| {
                                initialization_error = Some(error);
                                MappingError::NotForReading
                            })?;
                        if read == 0 {
                            break;
                        }
                        pointer
                            .copy_from_slice(copied, &buffer[..read])
                            .ok_or(MappingError::OutOfMemory)?;
                        copied += read;
                        file_offset = file_offset
                            .checked_add(read)
                            .ok_or(MappingError::OutOfMemory)?;
                    }
                    Ok(copied)
                },
            )
        };
        match (result, initialization_error) {
            (_, Some(error)) => Err(mmap_read_error(error)),
            (Ok(pointer), None) => Ok(pointer.as_usize()),
            (Err(error), None) => Err(mapping_error(error)),
        }
    }

    pub(crate) fn sys_munmap(&self, address: usize, length: usize) -> Result<(), Errno> {
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .filter(|length| *length != 0)
            .ok_or(Errno::EINVAL)?;
        address.checked_add(length).ok_or(Errno::EINVAL)?;
        // SAFETY: Darwin munmap relinquishes the caller-selected guest range.
        unsafe {
            self.global
                .pm
                .remove_pages(P::RawMutPointer::from_usize(address), length)
        }
        .map_err(|_| Errno::EINVAL)
    }

    pub(crate) fn sys_mprotect(
        &self,
        address: usize,
        length: usize,
        protection: VmProtection,
    ) -> Result<(), Errno> {
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if length == 0 {
            return Ok(());
        }
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        address.checked_add(length).ok_or(Errno::EINVAL)?;
        // SAFETY: PageManager validates the tracked range and maximum allowed
        // permissions.
        unsafe {
            self.global.pm.change_page_permissions(
                P::RawMutPointer::from_usize(address),
                length,
                permissions(protection),
            )
        }
        .map_err(protection_error)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    extern crate std;

    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicI32;
    use litebox_common_macos::TaskParams;
    use litebox_platform_macos_userland::MacosUserland as Platform;

    use crate::{MacosShimBuilder, Process};

    #[test]
    fn mprotect_validates_ranges() {
        let platform = Platform::new();
        let shim = MacosShimBuilder::new(platform).build();
        let task = Task {
            global: shim.global,
            files: shim.files,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
        };

        assert_eq!(
            task.sys_mprotect(PAGE_SIZE, PAGE_SIZE, VmProtection::READ),
            Err(Errno::ENOMEM)
        );
        assert_eq!(
            task.sys_mprotect(1, 0, VmProtection::READ),
            Err(Errno::EINVAL)
        );
    }
}

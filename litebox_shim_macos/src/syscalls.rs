// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall and Mach trap implementations.

use crate::{ShimPlatform, Task};
use core::sync::atomic::Ordering;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    KernReturn,
    syscall::MachTimebaseInfo,
    user_pointers::{UserPtr, UserPtrMut},
};

pub(crate) mod file;
pub(crate) mod mach;
pub(crate) mod mach_ipc;
pub(crate) mod mig;
pub mod misc;
pub(crate) mod mm;
pub(crate) mod process;

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_exit(&self, status: i32) {
        self.process.exit(status & 0xff);
    }

    pub(crate) fn sys_getpid(&self) -> i32 {
        self.params.pid
    }
    pub(crate) fn sys_getppid(&self) -> i32 {
        self.params.ppid
    }
    pub(crate) fn sys_getuid(&self) -> u32 {
        self.params.uid
    }
    pub(crate) fn sys_geteuid(&self) -> u32 {
        self.params.euid
    }
    pub(crate) fn sys_getgid(&self) -> u32 {
        self.params.gid
    }
    pub(crate) fn sys_getegid(&self) -> u32 {
        self.params.egid
    }

    pub(crate) fn sys_shared_region_check_np(
        &self,
        start_address: UserPtrMut<usize>,
    ) -> Result<(), litebox_common_macos::errno::Errno> {
        use litebox_common_macos::errno::Errno;

        let base = self.global.shared_cache_base.load(Ordering::Acquire);
        if base == 0 {
            return Err(Errno::EINVAL);
        }
        // XNU accepts this exact sentinel without copying out a cache base.
        if start_address.as_usize() == usize::MAX {
            return Ok(());
        }
        start_address
            .write_at_offset::<P>(0, base)
            .ok_or(Errno::EFAULT)
    }

    /// `shared_region_map_and_slide_2_np`: dyld maps a cache into the
    /// task's shared region only when it cannot reuse one. The guest's region
    /// already holds its private instance, and no other region can be
    /// mapped, so this never reaches the host. Like XNU
    /// (`bsd/vm/vm_unix.c`), empty requests succeed and oversized counts or
    /// unreadable file arrays fail first; then `vm_shared_region_map_file`
    /// fails a region that is already mapped with `KERN_FAILURE`, which the
    /// syscall returns as is: the guest sees errno 5 (`EIO`). Without an instance, the request is refused
    /// with `EINVAL` (`_shared_region_map_and_slide`'s conversion of
    /// `KERN_INVALID_ARGUMENT`).
    pub(crate) fn sys_shared_region_map_and_slide_2_np(
        &self,
        files_count: u32,
        files: UserPtr<u8>,
        mappings_count: u32,
    ) -> Result<(), litebox_common_macos::errno::Errno> {
        use litebox_common_macos::errno::Errno;
        /// `_SR_FILE_MAPPINGS_MAX_FILES`.
        const MAX_FILES: u32 = 256;
        /// `SFM_MAX`.
        const MAX_MAPPINGS: u32 = MAX_FILES * 8;
        /// `sizeof(struct shared_file_np)`.
        const FILE_BYTES: usize = 12;
        // XNU returns these kern_return_t values as errno values.
        const KERN_FAILURE: Errno = Errno::EIO;

        if files_count == 0 || mappings_count == 0 {
            return Ok(());
        }
        if files_count > MAX_FILES || mappings_count > MAX_MAPPINGS {
            return Err(KERN_FAILURE);
        }
        files
            .to_owned_slice::<P>(files_count as usize * FILE_BYTES)
            .ok_or(Errno::EFAULT)?;
        if self.global.shared_cache_base.load(Ordering::Acquire) != 0 {
            return Err(KERN_FAILURE);
        }
        Err(Errno::EINVAL)
    }

    pub(crate) fn sys_mach_absolute_time(&self) -> usize {
        self.global.platform.mach_absolute_time().trunc()
    }

    pub(crate) fn sys_mach_timebase_info(&self, info: UserPtrMut<MachTimebaseInfo>) -> KernReturn {
        // XNU deliberately ignores copyout failure for this trap.
        let _ = info.write_at_offset::<P>(0, self.global.platform.mach_timebase_info());
        KernReturn::SUCCESS
    }

    pub(crate) fn sys_mach_wait_until(&self, deadline: u64) -> KernReturn {
        self.global.platform.mach_wait_until(deadline)
    }
}

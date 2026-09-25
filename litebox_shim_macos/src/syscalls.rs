// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall implementations.

use crate::{ShimPlatform, Task};
use core::sync::atomic::Ordering;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{KernReturn, syscall::MachTimebaseInfo, user_pointers::UserPtrMut};

pub(crate) mod file;
pub(crate) mod mach;
pub(crate) mod misc;
pub(crate) mod mm;

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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall implementations.

use crate::{ShimPlatform, Task};
use litebox::{
    platform::page_mgmt::MemoryRegionPermissions as Permissions, utils::TruncateExt as _,
};
use litebox_common_macos::{KernReturn, syscall::MachTimebaseInfo, user_pointers::UserPtrMut};

pub(crate) mod file;

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

    pub(crate) fn sys_mach_absolute_time(&self) -> usize {
        self.global.platform.mach_absolute_time().trunc()
    }

    pub(crate) fn sys_mach_timebase_info(&self, info: UserPtrMut<MachTimebaseInfo>) -> KernReturn {
        if self
            .check_user_buffer(
                info.as_usize(),
                size_of::<MachTimebaseInfo>(),
                Permissions::WRITE,
            )
            .is_err()
        {
            // XNU deliberately ignores copyout failure for this trap.
            return KernReturn::SUCCESS;
        }
        let written = info.write_at_offset::<P>(0, self.global.platform.mach_timebase_info());
        debug_assert!(
            written.is_some(),
            "validated Mach timebase output became invalid"
        );
        KernReturn::SUCCESS
    }

    pub(crate) fn sys_mach_wait_until(&self, deadline: u64) -> KernReturn {
        self.global.platform.mach_wait_until(deadline)
    }
}

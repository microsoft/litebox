// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall implementations.

use crate::{ShimPlatform, Task};
use core::sync::atomic::Ordering;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{KernReturn, syscall::MachTimebaseInfo, user_pointers::UserPtrMut};
use litebox_platform::sync::RawMutex as _;

pub(crate) mod file;
pub(crate) mod mach;
pub(crate) mod misc;
pub(crate) mod mm;
pub(crate) mod thread;

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_exit(&self, status: i32) {
        if !self.process.exit(status & 0xff) {
            return;
        }
        let mut threads: alloc::vec::Vec<_> = self
            .global
            .threads
            .lock()
            .iter()
            .filter(|(id, _)| **id != self.thread.id)
            .map(|(id, handle)| (*id, handle.clone()))
            .collect();
        // A signal delivered in host code can precede an indefinite native wait.
        // Retry until the targets retire; checking exit just before waiting would
        // still leave a signal-before-wait window. Only the exit winner waits here.
        // Later registrations observe exit in init before they can enter guest code.
        let retry = P::RawMutex::INIT;
        while !threads.is_empty() {
            for (_, thread) in &threads {
                self.global.platform.interrupt_thread(thread);
            }
            threads.retain(|(id, _)| self.global.threads.lock().contains_key(id));
            if !threads.is_empty() {
                let _ = retry.block_or_timeout(0, core::time::Duration::from_millis(10));
            }
        }
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

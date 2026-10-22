// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD syscall and Mach trap implementations.

use crate::{ShimPlatform, Task};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    KernReturn,
    errno::Errno,
    syscall::MachTimebaseInfo,
    user_pointers::{UserPtr, UserPtrMut},
};

pub(crate) mod file;
pub(crate) mod mach;
pub(crate) mod mach_ipc;
pub(crate) mod mig;
pub(crate) mod misc;
pub(crate) mod mm;
pub(crate) mod process;

/// The only sysctl nodes the shim exposes: read-only system identity that
/// any sandboxed process can read, which the guest's own OS components
/// (libignition in dyld) cross-check. A runtime provider mirrors each from
/// the host it runs on with [`HostSysctl`], including its MIB and read error.
pub const HOST_SYSCTL_NAMES: [&str; 4] = [
    "kern.bootuuid",
    "hw.target",
    "hw.osenvironment",
    "security.mac.img4.ignition_blob",
];

/// One host sysctl node mirrored read-only into the guest.
#[derive(Clone, Debug)]
pub struct HostSysctl {
    /// One of [`HOST_SYSCTL_NAMES`].
    pub name: &'static str,
    /// The host's MIB for `name`.
    pub mib: Vec<i32>,
    /// The host's read result: the value, or the errno reading it fails with.
    pub value: Result<Vec<u8>, Errno>,
}

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

    /// `shared_region_map_and_slide_2_np`: the guest's region is its private
    /// instance, so no other cache is mapped. Empty requests, count limits and
    /// the file- and mapping-array copy-ins behave like XNU
    /// (`bsd/vm/vm_unix.c`: success, raw `KERN_FAILURE`, seen as errno 5, and
    /// `EFAULT`); anything else fails with `EINVAL`, which
    /// `_shared_region_map_and_slide` returns when `vm_shared_region_map_file`
    /// finds a mapping in the region.
    #[expect(
        clippy::unused_self,
        reason = "dispatched like every other syscall; the result never depends on the task"
    )]
    pub(crate) fn sys_shared_region_map_and_slide_2_np(
        &self,
        files_count: u32,
        files: UserPtr<u8>,
        mappings_count: u32,
        mappings: UserPtr<u8>,
    ) -> Result<(), Errno> {
        /// `_SR_FILE_MAPPINGS_MAX_FILES`.
        const MAX_FILES: u32 = 256;
        /// `SFM_MAX`.
        const MAX_MAPPINGS: u32 = MAX_FILES * 8;
        /// `sizeof(struct shared_file_np)`.
        const FILE_BYTES: usize = 12;
        /// `sizeof(struct shared_file_mapping_slide_np)`.
        const MAPPING_BYTES: usize = 48;
        // XNU returns the count-limit kern_return_t as an errno value.
        const KERN_FAILURE: Errno = Errno::EIO;

        // vm_unix.c checks each count in this order.
        if files_count == 0 {
            return Ok(());
        }
        if files_count > MAX_FILES {
            return Err(KERN_FAILURE);
        }
        if mappings_count == 0 {
            return Ok(());
        }
        if mappings_count > MAX_MAPPINGS {
            return Err(KERN_FAILURE);
        }
        files
            .to_owned_slice::<P>(files_count as usize * FILE_BYTES)
            .ok_or(Errno::EFAULT)?;
        mappings
            .to_owned_slice::<P>(mappings_count as usize * MAPPING_BYTES)
            .ok_or(Errno::EFAULT)?;
        // TODO: XNU also checks before the region: it copies in and sanitizes
        // each mapping in turn (`shared_region_map_and_slide_2_np_sanitize`),
        // then checks the files' `sf_mappings_count` against `mappings_count`,
        // slide overflow, and the files (`shared_region_map_and_slide_setup`).
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

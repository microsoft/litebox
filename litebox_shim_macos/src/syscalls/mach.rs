// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal Mach trap compatibility used by dyld startup.
//!
//! LiteBox does not expose host Mach rights. Port-returning traps use stable
//! synthetic names, and VM traps operate only on the shim's PageManager.

use crate::{ShimPlatform, Task};
use litebox_common_macos::{
    KernReturn, MmapFlags, VmProtection,
    errno::Errno,
    syscall::{MachMessageOptions, MachPortName, MachVmFlags, synthetic_port},
    user_pointers::UserPtrMut,
};

fn errno_to_kern_return(error: Errno) -> KernReturn {
    match error {
        Errno::ENOMEM => KernReturn::RESOURCE_SHORTAGE,
        Errno::EACCES => KernReturn::PROTECTION_FAILURE,
        _ => KernReturn::INVALID_ARGUMENT,
    }
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_mach_vm_allocate_compat(
        &self,
        target: MachPortName,
        address: UserPtrMut<usize>,
        size: usize,
        flags: MachVmFlags,
    ) -> usize {
        // Approximation: VM tags are ignored. Fixed-address allocation is not
        // needed by the supported dyld path and fails closed.
        self.sys_mach_vm_map_compat(
            target,
            address,
            size,
            flags,
            VmProtection::READ | VmProtection::WRITE,
        )
    }

    pub(crate) fn sys_mach_vm_map_compat(
        &self,
        target: MachPortName,
        address: UserPtrMut<usize>,
        size: usize,
        flags: MachVmFlags,
        current_protection: VmProtection,
    ) -> usize {
        // Approximation: memory objects, masks, copy semantics, inheritance,
        // and max protection are not modeled. Current protection is enforced
        // for the anonymous mapping used by the supported bootstrap path.
        if target != synthetic_port::TASK_SELF || !flags.anywhere() {
            return KernReturn::INVALID_ARGUMENT.into();
        }
        let Some(desired) = address.read_at_offset::<P>(0) else {
            return KernReturn::INVALID_ADDRESS.into();
        };
        let mapped = match self.sys_mmap(
            desired,
            size,
            current_protection,
            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
            -1,
            0,
        ) {
            Ok(mapped) => mapped,
            Err(error) => return errno_to_kern_return(error).into(),
        };
        if address.write_at_offset::<P>(0, mapped).is_none() {
            return KernReturn::INVALID_ADDRESS.into();
        }
        KernReturn::SUCCESS.into()
    }

    pub(crate) fn sys_mach_vm_deallocate_compat(
        &self,
        target: MachPortName,
        address: usize,
        size: usize,
    ) -> usize {
        if target != synthetic_port::TASK_SELF {
            return KernReturn::INVALID_ARGUMENT.into();
        }
        match self.sys_munmap(address, size) {
            Ok(()) => KernReturn::SUCCESS,
            Err(error) => errno_to_kern_return(error),
        }
        .into()
    }

    pub(crate) fn sys_mach_vm_protect_compat(
        &self,
        target: MachPortName,
        address: usize,
        size: usize,
        set_maximum: bool,
        protection: VmProtection,
    ) -> usize {
        if target != synthetic_port::TASK_SELF || set_maximum {
            // Maximum-protection changes are not modeled; accepting one would
            // overstate rights that PageManager cannot subsequently enforce.
            return KernReturn::INVALID_ARGUMENT.into();
        }
        let Some(end) = address.checked_add(size) else {
            return KernReturn::INVALID_ARGUMENT.into();
        };
        if self
            .global
            .shared_cache_range
            .lock()
            .as_ref()
            .is_some_and(|cache| address >= cache.start && end <= cache.end)
        {
            // The host cache is already mapped with boot-time protections.
            // dyld probes TPRO/cache ranges; changing them through PageManager
            // would either fail or damage the runner's host runtime.
            return KernReturn::SUCCESS.into();
        }
        match self.sys_mprotect(address, size, protection) {
            Ok(()) => KernReturn::SUCCESS,
            Err(error) => errno_to_kern_return(error),
        }
        .into()
    }

    pub(crate) const fn synthetic_reply_port() -> MachPortName {
        synthetic_port::REPLY
    }

    pub(crate) const fn synthetic_thread_port() -> MachPortName {
        synthetic_port::THREAD_SELF
    }

    pub(crate) const fn synthetic_task_port() -> MachPortName {
        synthetic_port::TASK_SELF
    }

    pub(crate) const fn synthetic_host_port() -> MachPortName {
        synthetic_port::HOST_SELF
    }

    pub(crate) fn sys_mach_msg2_compat(options: MachMessageOptions) -> usize {
        if options.contains(MachMessageOptions::SEND) {
            // No message was sent and no host Mach port was touched. Returning
            // KERN_INVALID_ARGUMENT is preferable to pretending IPC succeeded.
            KernReturn::INVALID_ARGUMENT.into()
        } else {
            // dyld issues a receive-only probe before constructing its first
            // request. There is no queued synthetic message, but dyld only
            // needs the trap to be accepted during this bootstrap path.
            KernReturn::SUCCESS.into()
        }
    }
}

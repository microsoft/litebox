// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal Mach trap compatibility used by dyld startup.
//!
//! LiteBox does not expose host Mach rights. Port-returning traps use stable
//! synthetic names, and VM traps operate only on the shim's PageManager.
//!
//! TODO: Replace these bootstrap-only approximations when guests require
//! observable Mach port, IPC, memory-object, or task semantics.

use crate::{ShimPlatform, Task};
use litebox_common_macos::{
    KernReturn, MmapFlags, PAGE_SIZE, VmProtection,
    errno::Errno,
    syscall::{MachPortName, MachVmAddressMask, MachVmFlags, MachVmProtection, synthetic_port},
    user_pointers::UserPtrMut,
};

fn errno_to_kern_return(error: Errno) -> KernReturn {
    match error {
        Errno::ENOMEM => KernReturn::RESOURCE_SHORTAGE,
        Errno::EACCES => KernReturn::PROTECTION_FAILURE,
        Errno::EFAULT => KernReturn::INVALID_ADDRESS,
        _ => KernReturn::INVALID_ARGUMENT,
    }
}

enum MachPageRange {
    Empty,
    NonEmpty { address: usize, size: usize },
}

fn mach_page_range(address: usize, size: usize) -> Result<MachPageRange, ()> {
    if size == 0 {
        return Ok(MachPageRange::Empty);
    }
    let start = address & !(PAGE_SIZE - 1);
    let end = address
        .checked_add(size)
        .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
        .ok_or(())?;
    Ok(MachPageRange::NonEmpty {
        address: start,
        size: end - start,
    })
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
            MachVmAddressMask(0),
            flags,
            MachVmProtection::new(VmProtection::READ | VmProtection::WRITE, false),
        )
    }

    pub(crate) fn sys_mach_vm_map_compat(
        &self,
        target: MachPortName,
        address: UserPtrMut<usize>,
        size: usize,
        mask: MachVmAddressMask,
        flags: MachVmFlags,
        current_protection: MachVmProtection,
    ) -> usize {
        // Approximation: memory objects, copy semantics, inheritance, and max
        // protection are not modeled. Current protection is enforced for the
        // anonymous mapping used by the supported bootstrap path.
        if target != synthetic_port::TASK_SELF
            || !mask.is_zero()
            || !flags.contains(MachVmFlags::ANYWHERE)
        {
            return KernReturn::INVALID_ARGUMENT.into();
        }
        let Some(desired) = address.read_at_offset::<P>(0) else {
            return KernReturn::INVALID_ADDRESS.into();
        };
        if size == 0 {
            return if address.write_at_offset::<P>(0, 0).is_some() {
                KernReturn::SUCCESS
            } else {
                KernReturn::INVALID_ADDRESS
            }
            .into();
        }
        let Some(length) = size.checked_next_multiple_of(PAGE_SIZE) else {
            return KernReturn::INVALID_ARGUMENT.into();
        };
        let hint = desired & !(PAGE_SIZE - 1);
        let mapped = match self.sys_mmap(
            hint,
            length,
            current_protection.permissions(),
            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
            -1,
            0,
        ) {
            Ok(mapped) => mapped,
            Err(error) => return errno_to_kern_return(error).into(),
        };
        if address.write_at_offset::<P>(0, mapped).is_none() {
            if let Err(error) = self.sys_munmap(mapped, length) {
                litebox_util_log::warn!(error:? = error; "failed to roll back Mach VM mapping after copyout fault");
            }
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
        let Ok(range) = mach_page_range(address, size) else {
            return KernReturn::INVALID_ADDRESS.into();
        };
        let MachPageRange::NonEmpty { address, size } = range else {
            return KernReturn::SUCCESS.into();
        };
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
        protection: MachVmProtection,
    ) -> usize {
        if target != synthetic_port::TASK_SELF || set_maximum {
            // Maximum-protection changes are not modeled; accepting one would
            // overstate rights that PageManager cannot subsequently enforce.
            return KernReturn::INVALID_ARGUMENT.into();
        }
        let Ok(range) = mach_page_range(address, size) else {
            return KernReturn::INVALID_ADDRESS.into();
        };
        let MachPageRange::NonEmpty { address, size } = range else {
            return KernReturn::SUCCESS.into();
        };
        let end = address + size;
        let permissions = protection.permissions();
        if self
            .global
            .shared_cache_range
            .lock()
            .as_ref()
            .is_some_and(|cache| address >= cache.start && end <= cache.end)
        {
            let mappings = self.global.shared_cache_mappings.lock();
            let mut covered = address;
            for (range, current) in mappings.iter() {
                if range.end <= covered || range.start > covered {
                    continue;
                }
                if *current != permissions {
                    break;
                }
                covered = covered.max(range.end);
                if covered >= end {
                    break;
                }
            }
            let unchanged = covered >= end;
            return if unchanged {
                KernReturn::SUCCESS
            } else {
                KernReturn::PROTECTION_FAILURE
            }
            .into();
        }
        match self.sys_mprotect(address, size, permissions) {
            Ok(()) => KernReturn::SUCCESS,
            Err(error) => errno_to_kern_return(error),
        }
        .into()
    }

    pub(crate) const fn synthetic_task_port() -> MachPortName {
        synthetic_port::TASK_SELF
    }
}

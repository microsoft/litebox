// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal Mach VM traps used by dyld startup.
//!
//! The target must be the guest's task port; requests operate only on the
//! shim's PageManager. Only anonymous ANYWHERE mappings are supported, and
//! maximum protection is not modeled.

use crate::{ShimPlatform, Task};
use litebox_common_macos::{
    KernReturn, MmapFlags, PAGE_SIZE, VmProtection,
    errno::Errno,
    mach::msg_return,
    syscall::{MachPortName, MachVmAddressMask, MachVmFlags, MachVmProtection},
    user_pointers::UserPtrMut,
};

/// `port_name_to_current_task` failure.
pub(crate) const INVALID_TASK_DEST: KernReturn =
    KernReturn::from_raw(msg_return::SEND_INVALID_DEST.cast_signed());

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
        if size == 0 {
            if !self.is_own_task(target) || !flags.contains(MachVmFlags::ANYWHERE) {
                return KernReturn::INVALID_ARGUMENT.into();
            }
            return if address.write_at_offset::<P>(0, 0).is_some() {
                KernReturn::SUCCESS
            } else {
                KernReturn::INVALID_ADDRESS
            }
            .into();
        }
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
        if !self.is_own_task(target) || !mask.is_zero() || !flags.contains(MachVmFlags::ANYWHERE) {
            return KernReturn::INVALID_ARGUMENT.into();
        }
        if size == 0 {
            return KernReturn::INVALID_ARGUMENT.into();
        }
        let Some(desired) = address.read_at_offset::<P>(0) else {
            return KernReturn::INVALID_ADDRESS.into();
        };
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
        if !self.is_own_task(target) {
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
        if !self.is_own_task(target) || set_maximum {
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
        let permissions = protection.permissions();
        match self.sys_mprotect(address, size, permissions) {
            Ok(()) => KernReturn::SUCCESS,
            Err(error) => errno_to_kern_return(error),
        }
        .into()
    }
}

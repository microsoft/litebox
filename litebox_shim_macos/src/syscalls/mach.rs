// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach VM traps on the guest's own address space.
//!
//! The target must be the guest's task port; requests operate only on the
//! shim's page manager, following `xnu/osfmk/vm/vm_user.c` and `vm_map.c`.

use super::mm::AnonymousPlacement;
use crate::{ShimPlatform, Task};
use litebox::platform::page_mgmt::AllocationError;
use litebox_common_linux::vmem::MappingError;
use litebox_common_macos::{
    KernReturn, PAGE_SIZE, VmProtection,
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

/// An anonymous `vm_map_enter` request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnonymousMapRequest {
    pub address: usize,
    pub size: usize,
    pub mask: usize,
    pub flags: MachVmFlags,
    pub protection: VmProtection,
    /// `mach_vm_allocate` lets a zero size succeed with address 0;
    /// `mach_vm_map` rejects it.
    pub zero_size_succeeds: bool,
}

impl<P: ShimPlatform> Task<P> {
    /// `vm_map_enter` of zero-filled memory: FIXED (optionally OVERWRITE) or
    /// ANYWHERE at or above the address hint, aligned to `mask | page mask`.
    pub(crate) fn mach_vm_map_anonymous(
        &self,
        request: AnonymousMapRequest,
    ) -> Result<usize, KernReturn> {
        let AnonymousMapRequest {
            address,
            size,
            mask,
            flags,
            protection,
            zero_size_succeeds,
        } = request;
        let anywhere = flags.contains(MachVmFlags::ANYWHERE);
        if flags.intersects(MachVmFlags::SUPERPAGE_MASK) {
            // No superpage size exists on arm64 (`vm_superpage_size`).
            return Err(KernReturn::INVALID_ARGUMENT);
        }
        if flags.intersects(MachVmFlags::TPRO | MachVmFlags::MTE) {
            // Neither hardware feature exists on this machine.
            return Err(KernReturn::INVALID_ARGUMENT);
        }
        if anywhere && flags.contains(MachVmFlags::OVERWRITE) {
            return Err(KernReturn::INVALID_ARGUMENT);
        }
        if size == 0 {
            return if zero_size_succeeds {
                Ok(0)
            } else {
                Err(KernReturn::INVALID_ARGUMENT)
            };
        }
        // VM_SANITIZE_FLAGS_REALIGN_START: a FIXED start is truncated to its
        // page and the size is rounded on its own, so the discarded offset
        // does not extend the range.
        let Some(length) = size.checked_next_multiple_of(PAGE_SIZE) else {
            return Err(KernReturn::INVALID_ARGUMENT);
        };
        let mask = mask | (PAGE_SIZE - 1);
        let map_error = |error: MappingError| match error {
            MappingError::MapError(
                AllocationError::BelowMinAddress | AllocationError::AboveMaxAddress,
            ) => KernReturn::INVALID_ADDRESS,
            MappingError::MapError(AllocationError::OutOfMemory) | MappingError::OutOfMemory => {
                KernReturn::RESOURCE_SHORTAGE
            }
            _ => KernReturn::NO_SPACE,
        };
        if !anywhere {
            let start = address & !(PAGE_SIZE - 1);
            if start & mask != 0 {
                return Err(KernReturn::NO_SPACE);
            }
            if start < P::TASK_ADDR_MIN
                || start
                    .checked_add(length)
                    .is_none_or(|end| end > P::TASK_ADDR_MAX)
            {
                return Err(KernReturn::INVALID_ADDRESS);
            }
            if self.overlaps_shared_cache(start..start + length) {
                // The shared region is not part of the task's own map.
                return Err(KernReturn::NO_SPACE);
            }
            let replace = flags.contains(MachVmFlags::OVERWRITE);
            return self
                .map_anonymous(
                    start,
                    length,
                    AnonymousPlacement::Fixed { replace },
                    protection,
                )
                .map_err(map_error);
        }
        let hint = address & !(PAGE_SIZE - 1);
        if mask == PAGE_SIZE - 1 {
            return self
                .map_anonymous(hint, length, AnonymousPlacement::Hint, protection)
                .map_err(map_error);
        }
        // Over-reserve so a start with no `mask` bits exists, then keep only
        // that range. The mask need not be contiguous: like
        // vm_map_locate_space, the start is `(reserved + mask) & !mask`,
        // which lies at most `mask + 1 - PAGE_SIZE` above a page-aligned
        // `reserved`.
        let padded = length
            .checked_add(mask - (PAGE_SIZE - 1))
            .ok_or(KernReturn::NO_SPACE)?;
        let reserved = self
            .map_anonymous(
                hint,
                padded,
                AnonymousPlacement::Hint,
                VmProtection::empty(),
            )
            .map_err(map_error)?;
        let start = reserved
            .checked_add(mask)
            .map(|start| start & !mask)
            .filter(|start| {
                start & mask == 0
                    && start
                        .checked_add(length)
                        .is_some_and(|end| end <= reserved + padded)
            });
        let Some(start) = start else {
            let _ = self.sys_munmap(reserved, padded);
            return Err(KernReturn::NO_SPACE);
        };
        for (from, to) in [(reserved, start), (start + length, reserved + padded)] {
            if from < to && self.sys_munmap(from, to - from).is_err() {
                // The slack stays reserved; it is ours either way.
                litebox_util_log::warn!(range:? = from..to; "failed to trim Mach VM alignment slack");
            }
        }
        self.map_anonymous(
            start,
            length,
            AnonymousPlacement::Fixed { replace: true },
            protection,
        )
        .map_err(map_error)
    }

    pub(crate) fn sys_mach_vm_allocate(
        &self,
        target: MachPortName,
        address: UserPtrMut<usize>,
        size: usize,
        flags: MachVmFlags,
    ) -> KernReturn {
        if !self.is_own_task(target) {
            return INVALID_TASK_DEST;
        }
        let Some(desired) = address.read_at_offset::<P>(0) else {
            return KernReturn::MEMORY_ERROR;
        };
        if !MachVmFlags::USER_ALLOCATE.contains(flags) {
            return KernReturn::INVALID_ARGUMENT;
        }
        let result = self.mach_vm_map_anonymous(AnonymousMapRequest {
            address: desired,
            size,
            mask: 0,
            flags,
            protection: VmProtection::READ | VmProtection::WRITE,
            zero_size_succeeds: true,
        });
        Self::copyout_mapped_address(address, result)
    }

    pub(crate) fn sys_mach_vm_map(
        &self,
        target: MachPortName,
        address: UserPtrMut<usize>,
        size: usize,
        mask: MachVmAddressMask,
        flags: MachVmFlags,
        current_protection: MachVmProtection,
    ) -> KernReturn {
        if !self.is_own_task(target) {
            return INVALID_TASK_DEST;
        }
        let Some(desired) = address.read_at_offset::<P>(0) else {
            return KernReturn::MEMORY_ERROR;
        };
        if !MachVmFlags::USER_MAP.contains(flags) {
            return KernReturn::INVALID_ARGUMENT;
        }
        // The trap maps anonymous memory with maximum protection VM_PROT_ALL;
        // VM_PROT_COPY has no effect without a memory object.
        let result = self.mach_vm_map_anonymous(AnonymousMapRequest {
            address: desired,
            size,
            mask: mask.0,
            flags,
            protection: current_protection.permissions(),
            zero_size_succeeds: false,
        });
        Self::copyout_mapped_address(address, result)
    }

    fn copyout_mapped_address(
        address: UserPtrMut<usize>,
        result: Result<usize, KernReturn>,
    ) -> KernReturn {
        let mapped = match result {
            Ok(mapped) => mapped,
            Err(error) => return error,
        };
        if address.write_at_offset::<P>(0, mapped).is_some() {
            return KernReturn::SUCCESS;
        }
        // XNU keeps the mapping and reports the copyout failure.
        KernReturn::MEMORY_ERROR
    }

    pub(crate) fn sys_mach_vm_deallocate(
        &self,
        target: MachPortName,
        address: usize,
        size: usize,
    ) -> KernReturn {
        if !self.is_own_task(target) {
            return INVALID_TASK_DEST;
        }
        self.mach_vm_deallocate(address, size)
    }

    /// `mach_vm_deallocate` on the guest's own map.
    pub(crate) fn mach_vm_deallocate(&self, address: usize, size: usize) -> KernReturn {
        let Ok(range) = mach_page_range(address, size) else {
            return KernReturn::INVALID_ARGUMENT;
        };
        let MachPageRange::NonEmpty { address, size } = range else {
            return KernReturn::SUCCESS;
        };
        if self.overlaps_shared_cache(address..address + size) {
            // The shared region is not part of the task's own map.
            return KernReturn::INVALID_ADDRESS;
        }
        match self.sys_munmap(address, size) {
            Ok(()) => KernReturn::SUCCESS,
            Err(error) => errno_to_kern_return(error),
        }
    }

    pub(crate) fn sys_mach_vm_protect(
        &self,
        target: MachPortName,
        address: usize,
        size: usize,
        set_maximum: bool,
        protection: MachVmProtection,
    ) -> KernReturn {
        if !self.is_own_task(target) {
            return INVALID_TASK_DEST;
        }
        if set_maximum {
            // Maximum protections are not tracked outside the shared cache;
            // accepting one would promise a restriction that is not enforced.
            self.log_unsupported_once("mach_vm_protect(set_maximum)", format_args!(""));
            return KernReturn::NOT_SUPPORTED;
        }
        let Ok(range) = mach_page_range(address, size) else {
            return KernReturn::INVALID_ADDRESS;
        };
        let MachPageRange::NonEmpty { address, size } = range else {
            return KernReturn::SUCCESS;
        };
        match self.sys_mprotect(address, size, protection.permissions()) {
            Ok(()) => KernReturn::SUCCESS,
            Err(error) => errno_to_kern_return(error),
        }
    }
}

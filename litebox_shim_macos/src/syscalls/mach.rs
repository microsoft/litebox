// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach VM traps on the guest's own address space.
//!
//! The target must be the guest's task port; requests operate only on the
//! shim's page manager, following `xnu/osfmk/vm/vm_user.c` and `vm_map.c`.

use super::mm::AnonymousPlacement;
use crate::{ShimPlatform, Task};
use alloc::vec::Vec;
use core::ops::Range;
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

/// Host collisions tolerated by one aligned ANYWHERE placement before it
/// reports `KERN_NO_SPACE`. The guest map does not show host memory (such as
/// the host's own multi-GiB shared region), so consecutive collisions move
/// the search up by a doubling stride: any host region is crossed within
/// this bound, at the cost of possibly skipping free space.
const ALIGNED_PLACEMENT_ATTEMPTS: usize = 64;

/// Result of trying to map one candidate range of an aligned placement.
#[derive(Debug, PartialEq, Eq)]
enum PlacementAttempt {
    Mapped(usize),
    /// Part of the range is in use, for example by the host.
    Conflict,
}

/// ANYWHERE placement of `length` bytes at a start with no `mask` bits, in
/// `search`, avoiding `mapped` (sorted, disjoint), like XNU's
/// `vm_map_locate_space_anywhere`: each gap's only candidate is
/// `(gap start + mask) & !mask`, which is at or above the gap start even for
/// a non-contiguous mask. `try_map` gets exactly `length` bytes, never
/// alignment slack, so a huge mask costs nothing.
fn place_aligned(
    mapped: &[Range<usize>],
    search: Range<usize>,
    length: usize,
    mask: usize,
    mut try_map: impl FnMut(Range<usize>) -> Result<PlacementAttempt, KernReturn>,
) -> Result<usize, KernReturn> {
    debug_assert_eq!(mask & (PAGE_SIZE - 1), PAGE_SIZE - 1);
    let mut cursor = search.start;
    let mut next = mapped.partition_point(|range| range.end <= cursor);
    let mut conflicts = 0;
    let mut stride = PAGE_SIZE;
    loop {
        while let Some(range) = mapped.get(next).filter(|range| range.start <= cursor) {
            cursor = cursor.max(range.end);
            next += 1;
        }
        let gap_end = mapped
            .get(next)
            .map_or(search.end, |range| range.start.min(search.end));
        let candidate = cursor
            .checked_add(mask)
            .map(|start| start & !mask)
            .and_then(|start| Some(start..start.checked_add(length)?))
            .filter(|range| range.end <= gap_end);
        let Some(candidate) = candidate else {
            // Try the gap after the next mapping, if it starts in `search`.
            let range = mapped
                .get(next)
                .filter(|range| range.start < search.end)
                .ok_or(KernReturn::NO_SPACE)?;
            cursor = range.end;
            next += 1;
            continue;
        };
        match try_map(candidate.clone())? {
            PlacementAttempt::Mapped(address) => return Ok(address),
            PlacementAttempt::Conflict => {
                conflicts += 1;
                if conflicts == ALIGNED_PLACEMENT_ATTEMPTS {
                    return Err(KernReturn::NO_SPACE);
                }
                // The next candidate, `(cursor + mask) & !mask`, is above
                // the refused start.
                cursor = candidate
                    .start
                    .checked_add(stride)
                    .ok_or(KernReturn::NO_SPACE)?;
                stride = stride.saturating_mul(2);
            }
        }
    }
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
        // Like XNU, the search runs upward from the hint without wrapping.
        let mapped: Vec<Range<usize>> = self
            .global
            .mm
            .mappings()
            .into_iter()
            .map(|(range, _)| range)
            .collect();
        place_aligned(
            &mapped,
            hint.max(P::TASK_ADDR_MIN)..P::PLACEMENT_ADDR_MAX,
            length,
            mask,
            |range| match self.map_anonymous(
                range.start,
                range.len(),
                AnonymousPlacement::Fixed { replace: false },
                protection,
            ) {
                Ok(address) => Ok(PlacementAttempt::Mapped(address)),
                Err(MappingError::MapError(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                )) => Ok(PlacementAttempt::Conflict),
                Err(error) => Err(map_error(error)),
            },
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn aligned_placement_requests_only_the_mapping_length() {
        // A one-page request with a 1 TiB alignment: every request is one
        // page, never the alignment slack.
        let mask = (1usize << 40) - 1;
        let search = 0x1_0000_0000..0x7fff_fe00_0000;
        let mapped = [
            0x1_0000_0000..0x1_0000_4000,
            0x100_0000_0000..0x100_0001_0000,
        ];
        let mut requests = Vec::new();
        let address = place_aligned(&mapped, search.clone(), PAGE_SIZE, mask, |range| {
            requests.push(range.clone());
            // The host holds the first aligned start outside the guest map.
            Ok(if requests.len() == 1 {
                PlacementAttempt::Conflict
            } else {
                PlacementAttempt::Mapped(range.start)
            })
        })
        .unwrap();
        assert_eq!(
            requests,
            vec![
                0x200_0000_0000..0x200_0000_4000,
                0x300_0000_0000..0x300_0000_4000
            ],
            "the guest-mapped 1 TiB boundary is skipped without a request"
        );
        assert_eq!(address, 0x300_0000_0000);

        // Host conflicts everywhere end with KERN_NO_SPACE after a bounded
        // number of one-page requests: at the end of the search range, or
        // after ALIGNED_PLACEMENT_ATTEMPTS collisions.
        for (mask, search) in [(mask, search), (PAGE_SIZE - 1, 0x4000..usize::MAX)] {
            let mut count = 0;
            let result = place_aligned(&[], search, PAGE_SIZE, mask, |range| {
                assert_eq!(range.len(), PAGE_SIZE);
                count += 1;
                Ok(PlacementAttempt::Conflict)
            });
            assert_eq!(result, Err(KernReturn::NO_SPACE));
            assert!(count <= ALIGNED_PLACEMENT_ATTEMPTS);
        }
    }

    #[test]
    fn aligned_placement_crosses_a_large_host_region_in_bounded_steps() {
        // 8 GiB of host memory the guest map does not show.
        let host = 0x1_0000_0000..0x3_0000_0000;
        let mut count = 0;
        let address = place_aligned(
            &[],
            0x1_0000_0000..0x7fff_fe00_0000,
            PAGE_SIZE,
            0xffff,
            |range| {
                count += 1;
                Ok(if range.start < host.end {
                    PlacementAttempt::Conflict
                } else {
                    PlacementAttempt::Mapped(range.start)
                })
            },
        )
        .unwrap();
        assert!(address >= host.end && address.trailing_zeros() >= 16);
        assert!(count < 40, "{count} requests");
    }

    #[test]
    fn aligned_placement_follows_xnu_gap_rules() {
        let mapped = |range: Range<usize>| Ok(PlacementAttempt::Mapped(range.start));
        // A gap too small for the aligned start moves on to the next gap.
        let gaps = [0x1_0000..0x1_8000, 0x2_4000..0x10_0000];
        assert_eq!(
            place_aligned(&gaps, 0x4000..0x20_0000, 0x8000, 0xffff, mapped),
            Ok(0x10_0000)
        );
        // The hint bounds the search from below; nothing wraps around.
        assert_eq!(
            place_aligned(&[], 0x1_4000..0x4_0000, PAGE_SIZE, 0xffff, mapped),
            Ok(0x2_0000)
        );
        assert_eq!(
            place_aligned(&[], 0x3_4000..0x4_0000, PAGE_SIZE, 0xffff, mapped),
            Err(KernReturn::NO_SPACE)
        );
        // A non-contiguous mask: the start has none of its bits.
        let mask = 0x8000 | (PAGE_SIZE - 1);
        let address =
            place_aligned(&[], 0x2_0001_c000..0x3_0000_0000, PAGE_SIZE, mask, mapped).unwrap();
        assert_eq!(address & mask, 0);
        assert!(address >= 0x2_0001_c000);
        // Overflowing candidates fail instead of wrapping.
        assert_eq!(
            place_aligned(
                &[],
                usize::MAX - 0x8000..usize::MAX,
                PAGE_SIZE,
                usize::MAX >> 1,
                mapped
            ),
            Err(KernReturn::NO_SPACE)
        );
        // Errors other than conflicts are returned as they are.
        assert_eq!(
            place_aligned(&[], 0x4000..0x10_0000, PAGE_SIZE, 0xffff, |_| Err(
                KernReturn::RESOURCE_SHORTAGE
            )),
            Err(KernReturn::RESOURCE_SHORTAGE)
        );
    }
}

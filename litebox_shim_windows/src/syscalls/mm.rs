// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::BTreeMap;
use core::mem::size_of;

use int_enum::IntEnum;
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::page_mgmt::{AllocationError, MemoryRegionPermissions};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_linux::vmem::{CreatePagesFlags, MappingError, VmFlags, VmemProtectError};
use litebox_common_windows::nt_status::NtStatus;
use rangemap::RangeMap;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::page_manager::{PrivatePages, WindowsVmem};
use crate::syscalls::{ProcessHandle, section::pagefile_view_protection_is_compatible};
use crate::{
    ConstPtr, MutPtr, PAGE_SIZE, ShimPlatform, Task, WindowsPageManager, WindowsPlaceholderState,
    WindowsVirtualAllocation,
};

pub(crate) const ALLOCATION_GRANULARITY: usize = 0x1_0000;
const MEMORY_WORKING_SET_LIST_MIN_SIZE: usize = 16;
const MEM_EXTENDED_PARAMETER_TYPE_MASK: u64 = 0xff;
const READ_VIRTUAL_MEMORY_CHUNK_BYTES: usize = 4 * 1024;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct PageProtection: u32 {
        const PAGE_NOACCESS = 0x01;
        const PAGE_READONLY = 0x02;
        const PAGE_READWRITE = 0x04;
        const PAGE_WRITECOPY = 0x08;
        const PAGE_EXECUTE = 0x10;
        const PAGE_EXECUTE_READ = 0x20;
        const PAGE_EXECUTE_READWRITE = 0x40;
        const PAGE_EXECUTE_WRITECOPY = 0x80;
        const PAGE_GUARD = 0x100;
        const PAGE_NOCACHE = 0x200;
        const PAGE_WRITECOMBINE = 0x400;
        const PAGE_TARGETS_INVALID = 0x40000000;
    }
}

impl PageProtection {
    pub(super) const BASE_MASK: u32 = 0xff;

    fn base(self) -> u32 {
        self.bits() & Self::BASE_MASK
    }

    fn has_valid_modifier_combination(self) -> bool {
        let noaccess = self.base() == Self::PAGE_NOACCESS.bits();
        let guard = self.contains(Self::PAGE_GUARD);
        let nocache = self.contains(Self::PAGE_NOCACHE);
        let writecombine = self.contains(Self::PAGE_WRITECOMBINE);
        // TODO(windows-cfg): Enforce target invalidation for allocations and no-update semantics
        // for protection changes; currently this operation flag is only validated.
        let targets_invalid = self.contains(Self::PAGE_TARGETS_INVALID);
        let executable = matches!(
            self.base(),
            value if value == Self::PAGE_EXECUTE.bits()
                || value == Self::PAGE_EXECUTE_READ.bits()
                || value == Self::PAGE_EXECUTE_READWRITE.bits()
                || value == Self::PAGE_EXECUTE_WRITECOPY.bits()
        );

        !(noaccess && (guard || nocache || writecombine)
            || guard && (nocache || writecombine)
            || nocache && writecombine
            || targets_invalid && !executable)
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct AllocationType: u32 {
        const MEM_COMMIT = 0x1000;
        const MEM_RESERVE = 0x2000;
        const MEM_REPLACE_PLACEHOLDER = 0x4000;
        const MEM_RESERVE_PLACEHOLDER = 0x40000;
        const MEM_RESET = 0x80000;
        const MEM_TOP_DOWN = 0x100000;
        const MEM_WRITE_WATCH = 0x200000;
        const MEM_PHYSICAL = 0x400000;
        const MEM_RESET_UNDO = 0x1000000;
        const MEM_LARGE_PAGES = 0x20000000;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FreeType: u32 {
        const MEM_COALESCE_PLACEHOLDERS = 0x1;
        const MEM_PRESERVE_PLACEHOLDER = 0x2;
        const MEM_DECOMMIT = 0x4000;
        const MEM_RELEASE = 0x8000;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MemoryState: u32 {
        const MEM_COMMIT = 0x1000;
        const MEM_RESERVE = 0x2000;
        const MEM_FREE = 0x10000;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct MemoryType: u32 {
        const MEM_PRIVATE = 0x20000;
        const MEM_MAPPED = 0x40000;
        const MEM_IMAGE = 0x1000000;
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum MemoryInformationClass {
    Basic = 0,
    WorkingSetList = 4,
    Image = 6,
    ImageExtension = 14,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct MemoryImageInformation {
    image_base: usize,
    size_of_image: usize,
    image_flags: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, FromBytes, Immutable, IntoBytes)]
struct MemoryImageExtensionInformation {
    extension_type: u32,
    flags: u32,
    extension_image_base_rva: usize,
    extension_size: usize,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum MemoryExtendedParameterType {
    AddressRequirements = 1,
    NumaNode = 2,
    AttributeFlags = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    _padding0: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
    _padding1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct MemoryExtendedParameter {
    type_: u64,
    value: usize,
}

pub(crate) struct MemoryExtendedParameters<Platform: ShimPlatform> {
    pub(crate) parameters: Option<ConstPtr<Platform, MemoryExtendedParameter>>,
    pub(crate) count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct MemoryAddressRequirements {
    lowest_starting_address: usize,
    highest_ending_address: usize,
    alignment: usize,
}

fn validate_memory_extended_parameters<Platform: ShimPlatform>(
    extended_parameters: MemoryExtendedParameters<Platform>,
) -> Result<(), NtStatus> {
    if extended_parameters.count == 0 {
        return Ok(());
    }

    let Some(parameters) = extended_parameters.parameters else {
        return Err(NtStatus::INVALID_PARAMETER);
    };

    let mut present = 0u32;
    for index in 0..extended_parameters.count {
        let parameter = parameters
            .read_at_offset(index.try_into().map_err(|_| NtStatus::INVALID_PARAMETER)?)
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
        validate_memory_extended_parameter::<Platform>(parameter, &mut present)?;
    }

    Ok(())
}

fn validate_memory_extended_parameter<Platform: ShimPlatform>(
    parameter: MemoryExtendedParameter,
    present: &mut u32,
) -> Result<(), NtStatus> {
    if parameter.type_ & !MEM_EXTENDED_PARAMETER_TYPE_MASK != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    let parameter_type_raw = parameter.type_ & MEM_EXTENDED_PARAMETER_TYPE_MASK;
    let parameter_type = MemoryExtendedParameterType::try_from(parameter_type_raw)
        .map_err(|_| NtStatus::INVALID_PARAMETER)?;
    let parameter_bit = u32::try_from(parameter_type_raw)
        .ok()
        .and_then(|parameter_type| 1u32.checked_shl(parameter_type))
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    if *present & parameter_bit != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    *present |= parameter_bit;

    match parameter_type {
        MemoryExtendedParameterType::AddressRequirements => {
            let address_requirements =
                ConstPtr::<Platform, MemoryAddressRequirements>::from_usize(parameter.value)
                    .read_at_offset(0)
                    .ok_or(NtStatus::ACCESS_VIOLATION)?;
            if address_requirements.lowest_starting_address != 0
                || address_requirements.highest_ending_address != 0
                || !matches!(address_requirements.alignment, 0 | ALLOCATION_GRANULARITY)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        }
        MemoryExtendedParameterType::NumaNode => Ok(()),
        MemoryExtendedParameterType::AttributeFlags => {
            if parameter.value == 0 {
                Ok(())
            } else {
                Err(NtStatus::INVALID_PARAMETER)
            }
        }
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    pub(crate) fn sys_nt_allocate_virtual_memory_ex(
        &self,
        process_handle: ProcessHandle,
        base_address: MutPtr<Platform, usize>,
        region_size: MutPtr<Platform, usize>,
        allocation_type: u32,
        protect: u32,
        extended_parameters: MemoryExtendedParameters<Platform>,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        if let Err(status) = validate_memory_extended_parameters::<Platform>(extended_parameters) {
            return status;
        }

        self.sys_nt_allocate_virtual_memory_inner(
            process_handle,
            base_address,
            0,
            region_size,
            allocation_type,
            protect,
        )
    }

    pub(crate) fn sys_nt_allocate_virtual_memory(
        &self,
        process_handle: ProcessHandle,
        base_address: MutPtr<Platform, usize>,
        zero_bits: usize,
        region_size: MutPtr<Platform, usize>,
        allocation_type: u32,
        protect: u32,
    ) -> NtStatus {
        if allocation_type
            & (AllocationType::MEM_RESERVE_PLACEHOLDER | AllocationType::MEM_REPLACE_PLACEHOLDER)
                .bits()
            != 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        self.sys_nt_allocate_virtual_memory_inner(
            process_handle,
            base_address,
            zero_bits,
            region_size,
            allocation_type,
            protect,
        )
    }

    fn sys_nt_allocate_virtual_memory_inner(
        &self,
        process_handle: ProcessHandle,
        base_address: MutPtr<Platform, usize>,
        zero_bits: usize,
        region_size: MutPtr<Platform, usize>,
        allocation_type: u32,
        protect: u32,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let (base, size) = match probe_region_inputs::<Platform>(base_address, region_size) {
            Ok(inputs) => inputs,
            Err(status) => return status,
        };
        let Some(allocation_type) = AllocationType::from_bits(allocation_type) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let supported_allocation_types = AllocationType::MEM_COMMIT
            | AllocationType::MEM_RESERVE
            | AllocationType::MEM_RESERVE_PLACEHOLDER
            | AllocationType::MEM_REPLACE_PLACEHOLDER
            | AllocationType::MEM_RESET
            | AllocationType::MEM_TOP_DOWN;
        if size == 0
            || !supported_allocation_types.contains(allocation_type)
            || (zero_bits > 21 && zero_bits < 32)
            || (zero_bits != 0 && base != 0)
        {
            litebox_util_log::debug!(
                base:% = format_args!("{base:#x}"),
                size,
                zero_bits:% = format_args!("{zero_bits:#x}"),
                allocation_type:% = format_args!("{:#x}", allocation_type.bits()),
                protect:% = format_args!("{protect:#x}");
                "Rejected NtAllocateVirtualMemory parameters"
            );
            return NtStatus::INVALID_PARAMETER;
        }
        if allocation_type.contains(AllocationType::MEM_RESET) {
            if allocation_type != AllocationType::MEM_RESET {
                return NtStatus::INVALID_PARAMETER;
            }
            return self.reset_virtual_memory(base, size, protect, base_address, region_size);
        }
        if !allocation_type.intersects(AllocationType::MEM_COMMIT | AllocationType::MEM_RESERVE) {
            return NtStatus::INVALID_PARAMETER;
        }

        let is_placeholder = allocation_type.contains(AllocationType::MEM_RESERVE_PLACEHOLDER);
        let replace_placeholder = allocation_type.contains(AllocationType::MEM_REPLACE_PLACEHOLDER);
        if is_placeholder && !is_valid_placeholder_reservation(allocation_type, protect) {
            return NtStatus::INVALID_PARAMETER;
        }
        if replace_placeholder {
            if !is_valid_placeholder_replacement(allocation_type, base, size) {
                return NtStatus::INVALID_PARAMETER;
            }
            // Windows reports a missing placeholder at address zero as a conflict.
            if base == 0 {
                return NtStatus::CONFLICTING_ADDRESSES;
            }
        }
        let new_allocation = base == 0 || allocation_type.contains(AllocationType::MEM_RESERVE);
        let Some((aligned_base, aligned_len)) = (if new_allocation && !replace_placeholder {
            reserve_allocation_region(base, size)
        } else {
            page_aligned_region(base, size)
        }) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some((protect, permissions)) = parse_page_protection(protect) else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };

        if replace_placeholder {
            if let Err(status) = self.replace_placeholder(
                aligned_base,
                aligned_len,
                allocation_type.contains(AllocationType::MEM_COMMIT),
                protect,
                permissions,
            ) {
                return status;
            }
            if !write_region_outputs::<Platform>(
                base_address,
                region_size,
                aligned_base,
                aligned_len,
            ) {
                return NtStatus::ACCESS_VIOLATION;
            }
            return NtStatus::SUCCESS;
        }

        if !new_allocation {
            let status = self.commit_existing_virtual_memory(
                aligned_base,
                aligned_len,
                protect,
                permissions,
                base_address,
                region_size,
            );
            if status != NtStatus::SUCCESS {
                litebox_util_log::debug!(
                    base:% = format_args!("{base:#x}"),
                    aligned_base:% = format_args!("{aligned_base:#x}"),
                    aligned_len,
                    status:? = status;
                    "NtAllocateVirtualMemory commit failed"
                );
            }
            return status;
        }

        let Some(length) = NonZeroPageSize::new(aligned_len) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let top_down = allocation_type.contains(AllocationType::MEM_TOP_DOWN);
        let (address_bounds, flags) = if base == 0 {
            let upper_bound = zero_bits_address_limit(zero_bits)
                .unwrap_or(Platform::TASK_ADDR_MAX)
                .min(Platform::TASK_ADDR_MAX);
            (
                Platform::TASK_ADDR_MIN..upper_bound,
                if top_down {
                    CreatePagesFlags::TOP_DOWN
                } else {
                    CreatePagesFlags::empty()
                },
            )
        } else {
            (
                Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            )
        };
        // SAFETY: The manager acquires fresh aligned address space without replacement, and the
        // allocation remains unpublished until output writeback succeeds.
        let commit = allocation_type.contains(AllocationType::MEM_COMMIT);
        let pages = if is_placeholder {
            PrivatePages::Mergeable
        } else if commit {
            PrivatePages::Committed(permissions)
        } else {
            PrivatePages::Reserved
        };
        let allocation = unsafe {
            self.global.page_manager.create_private_pages(
                NonZeroAddress::new(aligned_base),
                address_bounds,
                length,
                ALLOCATION_GRANULARITY,
                flags,
                pages,
            )
        }
        .map_err(mapping_error_to_nt_status);
        let ptr = match allocation {
            Ok(ptr) => ptr,
            Err(status) => {
                litebox_util_log::debug!(
                    base:% = format_args!("{base:#x}"),
                    aligned_base:% = format_args!("{aligned_base:#x}"),
                    aligned_len,
                    status:? = status;
                    "NtAllocateVirtualMemory allocation failed"
                );
                return status;
            }
        };

        if base_address.write_at_offset(0, ptr.as_usize()).is_none()
            || region_size.write_at_offset(0, aligned_len).is_none()
        {
            let ptr = MutPtr::<Platform, u8>::from_usize(ptr.as_usize());
            // SAFETY: The mapping was just created by this syscall and has not been published in
            // the allocation table. Removing it rolls back failed output writeback.
            let _ = unsafe { self.global.page_manager.remove_pages(ptr, aligned_len) };
            return NtStatus::ACCESS_VIOLATION;
        }
        // The record is published only after output writeback succeeds: until then no other
        // thread can free or reuse the range, so a failed writeback can roll back safely.
        self.global
            .page_manager
            .write_vmem()
            .allocations_mut()
            .insert(
                ptr.as_usize(),
                WindowsVirtualAllocation::new(
                    ptr.as_usize(),
                    aligned_len,
                    MemoryType::MEM_PRIVATE,
                    protect,
                    if is_placeholder {
                        WindowsPlaceholderState::Reserved
                    } else {
                        WindowsPlaceholderState::None
                    },
                    commit.then_some(protect),
                ),
            );

        litebox_util_log::debug!(
            base:% = format_args!("{:#x}", base),
            aligned_base:% = format_args!("{:#x}", ptr.as_usize()),
            aligned_len,
            allocation_type:% = format_args!("{:#x}", allocation_type.bits()),
            protect:% = format_args!("{:#x}", protect.bits());
            "Handled NtAllocateVirtualMemory syscall"
        );
        NtStatus::SUCCESS
    }

    fn reset_virtual_memory(
        &self,
        base: usize,
        size: usize,
        protect: u32,
        base_address: MutPtr<Platform, usize>,
        region_size: MutPtr<Platform, usize>,
    ) -> NtStatus {
        if parse_page_protection(protect).is_none() {
            return NtStatus::INVALID_PAGE_PROTECTION;
        }
        let Some((aligned_base, aligned_len)) = page_aligned_region(base, size) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let vmem = self.global.page_manager.read_vmem();
        if !find_virtual_allocation(vmem.allocations(), aligned_base, aligned_len)
            .is_some_and(|allocation| allocation.type_ == MemoryType::MEM_PRIVATE)
        {
            return NtStatus::INVALID_PARAMETER;
        }
        if !vmem.is_range_mapped(&(aligned_base..aligned_base + aligned_len)) {
            return NtStatus::CONFLICTING_ADDRESSES;
        }
        drop(vmem);

        if !write_region_outputs::<Platform>(base_address, region_size, aligned_base, aligned_len) {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn commit_existing_virtual_memory(
        &self,
        aligned_base: usize,
        aligned_len: usize,
        protect: PageProtection,
        permissions: MemoryRegionPermissions,
        base_address: MutPtr<Platform, usize>,
        region_size: MutPtr<Platform, usize>,
    ) -> NtStatus {
        let mut vmem = self.global.page_manager.write_vmem();
        let Some(allocation) =
            find_virtual_allocation(vmem.allocations(), aligned_base, aligned_len)
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        if !matches!(
            allocation.type_,
            MemoryType::MEM_PRIVATE | MemoryType::MEM_MAPPED
        ) {
            return NtStatus::INVALID_PARAMETER;
        }
        if allocation.placeholder_state == WindowsPlaceholderState::Reserved {
            return NtStatus::CONFLICTING_ADDRESSES;
        }
        if allocation.type_ == MemoryType::MEM_MAPPED
            && !pagefile_view_protection_is_compatible(allocation.allocation_protect, protect)
        {
            return NtStatus::SECTION_PROTECTION;
        }
        let ptr = MutPtr::<Platform, u8>::from_usize(aligned_base);
        // SAFETY: The range lies within a tracked private or mapped allocation, and the
        // page-manager lock serializes the commit with the protection metadata update.
        if unsafe { vmem.commit_pages(ptr, aligned_len, permissions) }.is_err() {
            return NtStatus::INVALID_PARAMETER;
        }
        update_page_protections(
            vmem.allocations_mut(),
            aligned_base,
            aligned_len,
            Some(protect),
        );
        drop(vmem);
        if !write_region_outputs::<Platform>(base_address, region_size, aligned_base, aligned_len) {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_free_virtual_memory(
        &self,
        process_handle: ProcessHandle,
        base_address: MutPtr<Platform, usize>,
        region_size: MutPtr<Platform, usize>,
        free_type: u32,
    ) -> NtStatus {
        if !process_handle.is_current() {
            litebox_util_log::debug!(
                process_handle:? = process_handle;
                "Unsupported NtFreeVirtualMemory process handle"
            );
            return NtStatus::INVALID_HANDLE;
        }

        let (base, size) = match probe_region_inputs::<Platform>(base_address, region_size) {
            Ok(inputs) => inputs,
            Err(status) => return status,
        };
        let Some(free_type) = FreeType::from_bits(free_type) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if free_type
            .intersects(FreeType::MEM_PRESERVE_PLACEHOLDER | FreeType::MEM_COALESCE_PLACEHOLDERS)
        {
            return match self.free_placeholder_memory(base, size, free_type) {
                Ok((base, size)) => {
                    if write_region_outputs::<Platform>(base_address, region_size, base, size) {
                        NtStatus::SUCCESS
                    } else {
                        NtStatus::ACCESS_VIOLATION
                    }
                }
                Err(status) => status,
            };
        }
        if base == 0 || !matches!(free_type, FreeType::MEM_DECOMMIT | FreeType::MEM_RELEASE) {
            return NtStatus::INVALID_PARAMETER;
        }

        let mut vmem = self.global.page_manager.write_vmem();
        let Some((aligned_base, aligned_len, placeholder_state)) =
            free_region(vmem.allocations(), base, size)
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        let ptr = MutPtr::<Platform, u8>::from_usize(aligned_base);
        if free_type == FreeType::MEM_DECOMMIT {
            if placeholder_state == WindowsPlaceholderState::Reserved {
                return NtStatus::MEMORY_NOT_ALLOCATED;
            }
            // SAFETY: The range is page-aligned and belongs to a private allocation tracked for
            // this process. Decommit discards page contents while leaving the address range
            // reserved for later recommit.
            if unsafe { vmem.decommit_pages(ptr, aligned_len) }.is_err() {
                return NtStatus::UNABLE_TO_FREE_VM;
            }
            update_page_protections(vmem.allocations_mut(), aligned_base, aligned_len, None);
        } else {
            // SAFETY: The range is page-aligned and belongs to an allocation tracked for this
            // process. The guest requested release, so the pages must not be used after success.
            if unsafe { vmem.remove_pages(ptr, aligned_len) }.is_err() {
                return NtStatus::UNABLE_TO_FREE_VM;
            }
            split_virtual_allocation_around_released_region(
                vmem.allocations_mut(),
                aligned_base,
                aligned_len,
            );
        }
        drop(vmem);
        if !write_region_outputs::<Platform>(base_address, region_size, aligned_base, aligned_len) {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    /// Replaces the reserved placeholder exactly covering the range with a private allocation,
    /// optionally committing it.
    fn replace_placeholder(
        &self,
        aligned_base: usize,
        aligned_len: usize,
        commit: bool,
        protect: PageProtection,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), NtStatus> {
        let mut vmem = self.global.page_manager.write_vmem();
        if !vmem
            .allocations()
            .get(&aligned_base)
            .is_some_and(|allocation| {
                allocation.placeholder_state == WindowsPlaceholderState::Reserved
                    && allocation.size == aligned_len
            })
        {
            return Err(NtStatus::CONFLICTING_ADDRESSES);
        }
        if commit {
            // SAFETY: The exact placeholder range remains exclusively reserved while the
            // page-manager lock serializes its replacement.
            unsafe {
                vmem.commit_pages(
                    MutPtr::<Platform, u8>::from_usize(aligned_base),
                    aligned_len,
                    permissions,
                )
            }
            .map_err(|_| NtStatus::NO_MEMORY)?;
        }
        let allocation = vmem
            .allocations_mut()
            .get_mut(&aligned_base)
            .expect("placeholder record was checked under the same lock");
        if commit {
            allocation.page_protections =
                initial_page_protections(aligned_base, aligned_len, protect);
        }
        allocation.placeholder_state = WindowsPlaceholderState::Replaced;
        allocation.allocation_protect = protect;
        Ok(())
    }

    /// Splits/coalesces logical placeholders without releasing their backing reservations.
    ///
    /// Parameter checks follow the order and status codes of the host `NtFreeVirtualMemory`.
    fn free_placeholder_memory(
        &self,
        base: usize,
        size: usize,
        free_type: FreeType,
    ) -> Result<(usize, usize), NtStatus> {
        let preserve = FreeType::MEM_RELEASE | FreeType::MEM_PRESERVE_PLACEHOLDER;
        let coalesce = FreeType::MEM_RELEASE | FreeType::MEM_COALESCE_PLACEHOLDERS;
        if !free_type.contains(FreeType::MEM_RELEASE) || free_type.contains(FreeType::MEM_DECOMMIT)
        {
            return Err(NtStatus::INVALID_PARAMETER_4);
        }
        if free_type != preserve && free_type != coalesce {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if size == 0 || !size.is_multiple_of(PAGE_SIZE) {
            return Err(NtStatus::INVALID_PARAMETER_3);
        }
        if !base.is_multiple_of(PAGE_SIZE) {
            return Err(NtStatus::INVALID_PARAMETER_2);
        }
        let end = base.checked_add(size).ok_or(NtStatus::INVALID_PARAMETER)?;
        let mut vmem = self.global.page_manager.write_vmem();
        if free_type == coalesce {
            let mut covered_until = base;
            let mut count = 0;
            for (&start, allocation) in vmem.allocations().range(base..end) {
                if start != covered_until
                    || allocation.placeholder_state != WindowsPlaceholderState::Reserved
                {
                    return Err(NtStatus::CONFLICTING_ADDRESSES);
                }
                covered_until = start
                    .checked_add(allocation.size)
                    .ok_or(NtStatus::CONFLICTING_ADDRESSES)?;
                count += 1;
            }
            if covered_until != end || count < 2 {
                return Err(NtStatus::CONFLICTING_ADDRESSES);
            }
            // SAFETY: Every piece is an uncommitted guest placeholder reserved as mergeable, and
            // the page-manager lock excludes competing placeholder transitions.
            unsafe { vmem.merge_reservations(MutPtr::<Platform, u8>::from_usize(base), size) }
                .map_err(|_| NtStatus::CONFLICTING_ADDRESSES)?;
            // The first piece starts at `base` and absorbs the others.
            let allocations = vmem.allocations_mut();
            while let Some((&start, _)) = allocations.range(base + 1..end).next() {
                allocations.remove(&start);
            }
            allocations
                .get_mut(&base)
                .expect("coalesced placeholders start at the requested base")
                .size = size;
            return Ok((base, size));
        }

        let allocation = find_virtual_allocation_containing(vmem.allocations(), base)
            .ok_or(NtStatus::MEMORY_NOT_ALLOCATED)?;
        if allocation.type_ != MemoryType::MEM_PRIVATE
            || allocation.placeholder_state == WindowsPlaceholderState::None
        {
            return Err(NtStatus::CONFLICTING_ADDRESSES);
        }
        let placeholder_state = allocation.placeholder_state;
        let allocation_end = allocation
            .base
            .checked_add(allocation.size)
            .ok_or(NtStatus::CONFLICTING_ADDRESSES)?;
        // Like Windows, a replaced allocation may restore any page-aligned sub-range; the
        // remaining pieces stay replaced and keep their contents.
        if end > allocation_end {
            return Err(NtStatus::UNABLE_TO_FREE_VM);
        }
        // A reserved placeholder can only be split, not "preserved" as a whole.
        if placeholder_state == WindowsPlaceholderState::Reserved
            && base == allocation.base
            && end == allocation_end
        {
            return Err(NtStatus::CONFLICTING_ADDRESSES);
        }
        if placeholder_state == WindowsPlaceholderState::Replaced {
            // SAFETY: The restored sub-range of the private allocation is retained while its
            // committed contents are discarded. The page-manager lock prevents competing
            // placeholder transitions.
            unsafe { vmem.decommit_pages(MutPtr::<Platform, u8>::from_usize(base), size) }
                .map_err(|_| NtStatus::UNABLE_TO_FREE_VM)?;
        }
        let allocations = vmem.allocations_mut();
        split_virtual_allocation_around_released_region(allocations, base, size);
        allocations.insert(
            base,
            WindowsVirtualAllocation::new(
                base,
                size,
                MemoryType::MEM_PRIVATE,
                PageProtection::PAGE_NOACCESS,
                WindowsPlaceholderState::Reserved,
                None,
            ),
        );
        Ok((base, size))
    }

    pub(crate) fn sys_nt_protect_virtual_memory(
        &self,
        process_handle: ProcessHandle,
        base_address: MutPtr<Platform, usize>,
        region_size: MutPtr<Platform, usize>,
        new_protect: u32,
        old_protect: MutPtr<Platform, u32>,
    ) -> NtStatus {
        if !process_handle.is_current() {
            litebox_util_log::debug!(
                process_handle:? = process_handle;
                "Unsupported NtProtectVirtualMemory process handle"
            );
            return NtStatus::INVALID_HANDLE;
        }

        let Some(base) = base_address.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(size) = region_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(old_protect_probe) = old_protect.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if !write_region_outputs::<Platform>(base_address, region_size, base, size)
            || old_protect.write_at_offset(0, old_protect_probe).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if base == 0 || size == 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some((aligned_base, aligned_len)) = page_aligned_region(base, size) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some((new_protect, new_permissions)) = parse_page_protection(new_protect) else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };
        let mut vmem = self.global.page_manager.write_vmem();
        let old_protect_value = match scan_protect_range(&vmem, aligned_base, aligned_len) {
            Some(PageRangeScan::FullyCommitted {
                first_protect,
                section_protect,
            }) => {
                if section_protect.is_some_and(|section_protect| {
                    !pagefile_view_protection_is_compatible(section_protect, new_protect)
                }) {
                    return NtStatus::SECTION_PROTECTION;
                }
                first_protect
            }
            Some(PageRangeScan::ContainsUncommitted) => {
                drop(vmem);
                if old_protect
                    .write_at_offset(0, PageProtection::PAGE_NOACCESS.bits())
                    .is_none()
                {
                    return NtStatus::ACCESS_VIOLATION;
                }
                return NtStatus::NOT_COMMITTED;
            }
            None => return NtStatus::NOT_COMMITTED,
        };

        if update_permissions(&mut vmem, aligned_base, aligned_len, new_permissions).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }
        update_page_protections(
            vmem.allocations_mut(),
            aligned_base,
            aligned_len,
            Some(new_protect),
        );
        drop(vmem);

        // ReactOS NtProtectVirtualMemory writes OldProtection, BaseAddress, then RegionSize after
        // MiProtectVirtualMemory succeeds; failed writeback does not roll back the protection.
        if old_protect
            .write_at_offset(0, old_protect_value.bits())
            .is_none()
            || !write_region_outputs::<Platform>(
                base_address,
                region_size,
                aligned_base,
                aligned_len,
            )
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            process_handle:? = process_handle,
            base:% = format_args!("{:#x}", base),
            size = size,
            aligned_base:% = format_args!("{:#x}", aligned_base),
            aligned_len = aligned_len,
            new_protect:% = format_args!("{:#x}", new_protect),
            old_protect:% = format_args!("{:#x}", old_protect_value);
            "Handled NtProtectVirtualMemory syscall"
        );

        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_read_virtual_memory(
        process_handle: ProcessHandle,
        base_address: ConstPtr<Platform, u8>,
        buffer: MutPtr<Platform, u8>,
        number_of_bytes_to_read: usize,
        number_of_bytes_read: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        fn write_bytes_read<Platform: ShimPlatform>(
            number_of_bytes_read: Option<MutPtr<Platform, usize>>,
            bytes_copied: usize,
        ) -> Result<(), NtStatus> {
            if number_of_bytes_read
                .is_some_and(|bytes_read| bytes_read.write_at_offset(0, bytes_copied).is_none())
            {
                Err(NtStatus::ACCESS_VIOLATION)
            } else {
                Ok(())
            }
        }

        if !process_handle.is_current() {
            litebox_util_log::debug!(
                process_handle:? = process_handle;
                "Unsupported NtReadVirtualMemory process handle"
            );
            return NtStatus::INVALID_HANDLE;
        }
        if base_address
            .as_usize()
            .checked_add(number_of_bytes_to_read)
            .is_none()
            || buffer
                .as_usize()
                .checked_add(number_of_bytes_to_read)
                .is_none()
        {
            return write_bytes_read::<Platform>(number_of_bytes_read, 0)
                .map_or_else(|status| status, |()| NtStatus::PARTIAL_COPY);
        }

        let mut bytes_copied = 0;
        while bytes_copied < number_of_bytes_to_read {
            let chunk_address = base_address.as_usize() + bytes_copied;
            let remaining = number_of_bytes_to_read - bytes_copied;
            let Some(copied) = copy_virtual_memory_array::<Platform>(
                chunk_address,
                buffer,
                bytes_copied,
                remaining,
            ) else {
                return write_bytes_read::<Platform>(number_of_bytes_read, bytes_copied)
                    .map_or_else(|status| status, |()| NtStatus::PARTIAL_COPY);
            };
            bytes_copied += copied;
        }
        if let Err(status) =
            write_bytes_read::<Platform>(number_of_bytes_read, number_of_bytes_to_read)
        {
            return status;
        }

        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_virtual_memory(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
        memory_information_class: u32,
        memory_information: MutPtr<Platform, u8>,
        memory_information_length: usize,
        return_length: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let Ok(memory_information_class) =
            MemoryInformationClass::try_from(memory_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };

        match memory_information_class {
            MemoryInformationClass::Basic => self.write_memory_basic_information(
                base_address,
                memory_information,
                memory_information_length,
                return_length,
            ),
            MemoryInformationClass::WorkingSetList => Self::write_memory_working_set_list(
                memory_information,
                memory_information_length,
                return_length,
            ),
            MemoryInformationClass::Image => self.write_memory_image_information(
                process_handle,
                base_address,
                memory_information,
                memory_information_length,
                return_length,
            ),
            MemoryInformationClass::ImageExtension => self
                .write_memory_image_extension_information(
                    process_handle,
                    base_address,
                    memory_information,
                    memory_information_length,
                    return_length,
                ),
        }
    }

    fn write_memory_basic_information(
        &self,
        base_address: usize,
        memory_information: MutPtr<Platform, u8>,
        memory_information_length: usize,
        return_length: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        if let Err(status) = check_and_write_length::<Platform>(
            return_length,
            memory_information_length,
            size_of::<MemoryBasicInformation>(),
        ) {
            return status;
        }

        let Some(info) = query_memory_basic_information::<Platform>(
            &self.global.page_manager.read_vmem(),
            base_address,
        ) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let output =
            MutPtr::<Platform, MemoryBasicInformation>::from_usize(memory_information.as_usize());
        if output.write_at_offset(0, info).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn write_memory_image_information(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
        memory_information: MutPtr<Platform, u8>,
        memory_information_length: usize,
        return_length: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        if let Err(status) = check_and_write_length::<Platform>(
            return_length,
            memory_information_length,
            size_of::<MemoryImageInformation>(),
        ) {
            return status;
        }

        let Some((image_base, image_size)) = self.image_allocation_containing(base_address) else {
            return NtStatus::INVALID_PARAMETER;
        };

        let info = MemoryImageInformation {
            image_base,
            size_of_image: image_size,
            image_flags: 0,
            _padding: 0,
        };
        let output =
            MutPtr::<Platform, MemoryImageInformation>::from_usize(memory_information.as_usize());
        if output.write_at_offset(0, info).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            process_handle:? = process_handle,
            base:% = format_args!("{base_address:#x}"),
            image_base:% = format_args!("{image_base:#x}"),
            image_size;
            "Handled NtQueryVirtualMemory MemoryImageInformation syscall"
        );

        NtStatus::SUCCESS
    }

    /// Returns the base and size of the image allocation containing `address`.
    fn image_allocation_containing(&self, address: usize) -> Option<(usize, usize)> {
        let vmem = self.global.page_manager.read_vmem();
        find_image_allocation_containing(vmem.allocations(), address)
            .map(|allocation| (allocation.base, allocation.size))
    }

    fn write_memory_image_extension_information(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
        memory_information: MutPtr<Platform, u8>,
        memory_information_length: usize,
        return_length: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        if let Err(status) = check_and_write_length::<Platform>(
            return_length,
            memory_information_length,
            size_of::<MemoryImageExtensionInformation>(),
        ) {
            return status;
        }

        let Some((image_base, image_size)) = self.image_allocation_containing(base_address) else {
            return NtStatus::INVALID_PARAMETER;
        };

        let image_extension_information =
            MutPtr::<Platform, MemoryImageExtensionInformation>::from_usize(
                memory_information.as_usize(),
            );
        let Some(request) = image_extension_information.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        // TODO: The buffer is an input request before it becomes output; only the default request for
        // absent image extension information is supported for now.
        if request != MemoryImageExtensionInformation::default() {
            return NtStatus::INVALID_PARAMETER;
        }

        // TODO: Report real image extension metadata when PE image extension data is modeled.
        if image_extension_information
            .write_at_offset(0, MemoryImageExtensionInformation::default())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            process_handle:? = process_handle,
            base:% = format_args!("{base_address:#x}"),
            image_base:% = format_args!("{image_base:#x}"),
            image_size;
            "Handled NtQueryVirtualMemory MemoryImageExtensionInformation syscall"
        );

        NtStatus::SUCCESS
    }

    fn write_memory_working_set_list(
        memory_information: MutPtr<Platform, u8>,
        memory_information_length: usize,
        return_length: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        if memory_information_length < MEMORY_WORKING_SET_LIST_MIN_SIZE {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if let Some(return_length) = return_length
            && return_length
                .write_at_offset(0, memory_information_length)
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        // TODO: Model working set residency and report real entries instead of an empty list.
        for offset in 0..memory_information_length {
            let Ok(offset) = isize::try_from(offset) else {
                return NtStatus::INVALID_PARAMETER;
            };
            if memory_information.write_at_offset(offset, 0).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
        }

        litebox_util_log::debug!(
            memory_information_length;
            "Handled NtQueryVirtualMemory MemoryWorkingSetList syscall"
        );

        NtStatus::SUCCESS
    }
}

fn copy_virtual_memory_array<Platform: ShimPlatform>(
    source_address: usize,
    destination: MutPtr<Platform, u8>,
    destination_offset: usize,
    remaining: usize,
) -> Option<usize> {
    match remaining {
        READ_VIRTUAL_MEMORY_CHUNK_BYTES.. => copy_virtual_memory_array_exact::<
            Platform,
            READ_VIRTUAL_MEMORY_CHUNK_BYTES,
        >(
            source_address, destination, destination_offset
        ),
        2048.. => copy_virtual_memory_array_exact::<Platform, 2048>(
            source_address,
            destination,
            destination_offset,
        ),
        1024.. => copy_virtual_memory_array_exact::<Platform, 1024>(
            source_address,
            destination,
            destination_offset,
        ),
        512.. => copy_virtual_memory_array_exact::<Platform, 512>(
            source_address,
            destination,
            destination_offset,
        ),
        256.. => copy_virtual_memory_array_exact::<Platform, 256>(
            source_address,
            destination,
            destination_offset,
        ),
        128.. => copy_virtual_memory_array_exact::<Platform, 128>(
            source_address,
            destination,
            destination_offset,
        ),
        64.. => copy_virtual_memory_array_exact::<Platform, 64>(
            source_address,
            destination,
            destination_offset,
        ),
        32.. => copy_virtual_memory_array_exact::<Platform, 32>(
            source_address,
            destination,
            destination_offset,
        ),
        16.. => copy_virtual_memory_array_exact::<Platform, 16>(
            source_address,
            destination,
            destination_offset,
        ),
        8.. => copy_virtual_memory_array_exact::<Platform, 8>(
            source_address,
            destination,
            destination_offset,
        ),
        4.. => copy_virtual_memory_array_exact::<Platform, 4>(
            source_address,
            destination,
            destination_offset,
        ),
        2.. => copy_virtual_memory_array_exact::<Platform, 2>(
            source_address,
            destination,
            destination_offset,
        ),
        _ => copy_virtual_memory_array_exact::<Platform, 1>(
            source_address,
            destination,
            destination_offset,
        ),
    }
}

fn copy_virtual_memory_array_exact<Platform: ShimPlatform, const N: usize>(
    source_address: usize,
    destination: MutPtr<Platform, u8>,
    destination_offset: usize,
) -> Option<usize>
where
    [u8; N]: FromBytes,
{
    let bytes = ConstPtr::<Platform, [u8; N]>::from_usize(source_address).read_at_offset(0)?;
    destination.copy_from_slice(destination_offset, &bytes)?;
    Some(N)
}

fn check_and_write_length<Platform: ShimPlatform>(
    return_length: Option<MutPtr<Platform, usize>>,
    memory_information_length: usize,
    required_len: usize,
) -> Result<(), NtStatus> {
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    if memory_information_length < required_len {
        return Err(NtStatus::INFO_LENGTH_MISMATCH);
    }
    Ok(())
}

/// Reads the guest's in/out base address and region size and probes both for writability.
fn probe_region_inputs<Platform: ShimPlatform>(
    base_address: MutPtr<Platform, usize>,
    region_size: MutPtr<Platform, usize>,
) -> Result<(usize, usize), NtStatus> {
    let base = base_address
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    let size = region_size
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    if !write_region_outputs::<Platform>(base_address, region_size, base, size) {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    Ok((base, size))
}

/// Writes the guest's base address and region size outputs, returning whether both succeeded.
fn write_region_outputs<Platform: ShimPlatform>(
    base_address: MutPtr<Platform, usize>,
    region_size: MutPtr<Platform, usize>,
    base: usize,
    size: usize,
) -> bool {
    base_address.write_at_offset(0, base).is_some()
        && region_size.write_at_offset(0, size).is_some()
}

fn page_aligned_region(base: usize, size: usize) -> Option<(usize, usize)> {
    let aligned_base = base & !(PAGE_SIZE - 1);
    let end = base.checked_add(size)?;
    let aligned_end = end.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    let aligned_len = aligned_end.checked_sub(aligned_base)?;
    if aligned_base == 0 || aligned_len == 0 {
        return None;
    }
    Some((aligned_base, aligned_len))
}

fn reserve_allocation_region(base: usize, size: usize) -> Option<(usize, usize)> {
    let aligned_base = if base == 0 {
        0
    } else {
        base & !(ALLOCATION_GRANULARITY - 1)
    };
    if base != 0 && aligned_base == 0 {
        return None;
    }
    let end = base.checked_add(size)?;
    let aligned_end = end.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    let aligned_len = aligned_end.checked_sub(aligned_base)?;
    if aligned_len == 0 {
        return None;
    }
    Some((aligned_base, aligned_len))
}

/// A placeholder reservation must be exactly `MEM_RESERVE | MEM_RESERVE_PLACEHOLDER`
/// (optionally `MEM_TOP_DOWN`) with `PAGE_NOACCESS`.
fn is_valid_placeholder_reservation(allocation_type: AllocationType, protect: u32) -> bool {
    allocation_type - AllocationType::MEM_TOP_DOWN
        == AllocationType::MEM_RESERVE | AllocationType::MEM_RESERVE_PLACEHOLDER
        && protect == PageProtection::PAGE_NOACCESS.bits()
}

/// A placeholder replacement needs `MEM_RESERVE`, a page-aligned range, and must not request
/// a new placeholder or a top-down placement.
fn is_valid_placeholder_replacement(
    allocation_type: AllocationType,
    base: usize,
    size: usize,
) -> bool {
    base.is_multiple_of(PAGE_SIZE)
        && size.is_multiple_of(PAGE_SIZE)
        && allocation_type.contains(AllocationType::MEM_RESERVE)
        && !allocation_type
            .intersects(AllocationType::MEM_TOP_DOWN | AllocationType::MEM_RESERVE_PLACEHOLDER)
}

/// Resolves the private allocation range to free and the placeholder state of its allocation.
fn free_region(
    virtual_allocations: &BTreeMap<usize, WindowsVirtualAllocation>,
    base: usize,
    size: usize,
) -> Option<(usize, usize, WindowsPlaceholderState)> {
    if size == 0 {
        let allocation_base = base & !(PAGE_SIZE - 1);
        let allocation = virtual_allocations
            .get(&allocation_base)
            .filter(|allocation| allocation.type_ == MemoryType::MEM_PRIVATE)?;
        return Some((
            allocation.base,
            allocation.size,
            allocation.placeholder_state,
        ));
    }

    let (aligned_base, aligned_len) = page_aligned_region(base, size)?;
    let allocation =
        find_private_virtual_allocation(virtual_allocations, aligned_base, aligned_len)?;
    Some((aligned_base, aligned_len, allocation.placeholder_state))
}

fn split_virtual_allocation_around_released_region(
    allocations: &mut alloc::collections::BTreeMap<usize, WindowsVirtualAllocation>,
    released_base: usize,
    released_size: usize,
) {
    let Some(released_end) = released_base.checked_add(released_size) else {
        return;
    };
    let Some((&allocation_key, allocation)) = allocations.range(..=released_base).next_back()
    else {
        return;
    };
    let Some(allocation_end) = allocation.base.checked_add(allocation.size) else {
        return;
    };
    let Some(allocation) = allocations.remove(&allocation_key) else {
        return;
    };

    for (base, end) in [
        (allocation.base, released_base),
        (released_end, allocation_end),
    ] {
        if base >= end {
            continue;
        }
        let mut pages = RangeMap::new();
        for (range, protect) in allocation.page_protections.overlapping(base..end) {
            pages.insert(range.start.max(base)..range.end.min(end), *protect);
        }
        allocations.insert(
            base,
            WindowsVirtualAllocation {
                base,
                size: end - base,
                allocation_protect: allocation.allocation_protect,
                type_: allocation.type_,
                placeholder_state: allocation.placeholder_state,
                page_protections: pages,
            },
        );
    }
}

/// Records committed pages created directly through the page manager, such as loader-created
/// process structures or shim-owned views, as a guest-visible Windows allocation.
pub(crate) fn record_committed_allocation<Platform: ShimPlatform>(
    page_manager: &WindowsPageManager<Platform>,
    base: usize,
    size: usize,
    type_: MemoryType,
    protect: PageProtection,
) {
    page_manager.write_vmem().allocations_mut().insert(
        base,
        WindowsVirtualAllocation::new(
            base,
            size,
            type_,
            protect,
            WindowsPlaceholderState::None,
            Some(protect),
        ),
    );
}

pub(crate) fn initial_page_protections(
    base: usize,
    size: usize,
    protect: PageProtection,
) -> RangeMap<usize, PageProtection> {
    let mut pages = RangeMap::new();
    let Some(end) = base.checked_add(size) else {
        return pages;
    };
    pages.insert(base..end, protect);
    pages
}

fn find_virtual_allocation(
    virtual_allocations: &BTreeMap<usize, WindowsVirtualAllocation>,
    base: usize,
    size: usize,
) -> Option<&WindowsVirtualAllocation> {
    let end = base.checked_add(size)?;
    virtual_allocations
        .range(..=base)
        .next_back()
        .map(|(_, allocation)| allocation)
        .filter(|allocation| {
            allocation
                .base
                .checked_add(allocation.size)
                .is_some_and(|allocation_end| end <= allocation_end)
        })
}

fn find_private_virtual_allocation(
    virtual_allocations: &BTreeMap<usize, WindowsVirtualAllocation>,
    base: usize,
    size: usize,
) -> Option<&WindowsVirtualAllocation> {
    find_virtual_allocation(virtual_allocations, base, size)
        .filter(|allocation| allocation.type_ == MemoryType::MEM_PRIVATE)
}

fn find_image_allocation_containing(
    virtual_allocations: &BTreeMap<usize, WindowsVirtualAllocation>,
    base: usize,
) -> Option<&WindowsVirtualAllocation> {
    find_virtual_allocation(virtual_allocations, base, 1)
        .filter(|allocation| allocation.type_ == MemoryType::MEM_IMAGE)
}

fn find_virtual_allocation_containing(
    virtual_allocations: &BTreeMap<usize, WindowsVirtualAllocation>,
    base: usize,
) -> Option<&WindowsVirtualAllocation> {
    find_virtual_allocation(virtual_allocations, base, 1)
}

enum PageRangeScan {
    FullyCommitted {
        first_protect: PageProtection,
        /// Protection of the backing section for mapped views, which bounds later changes.
        section_protect: Option<PageProtection>,
    },
    ContainsUncommitted,
}

fn scan_protect_range<Platform: ShimPlatform>(
    vmem: &WindowsVmem<Platform>,
    base: usize,
    size: usize,
) -> Option<PageRangeScan> {
    let allocation = find_virtual_allocation_containing(vmem.allocations(), base)?;
    let end = base.checked_add(size)?;
    let allocation_end = allocation.base.checked_add(allocation.size)?;
    if end > allocation_end || !vmem.is_range_mapped(&(base..end)) {
        return Some(PageRangeScan::ContainsUncommitted);
    }
    let first_protect =
        if let Some(protect) = allocation.page_protections.get(&base) {
            *protect
        } else {
            permissions_to_page_protect(vmem.get_memory_permissions(
                NonZeroAddress::new(base)?,
                NonZeroPageSize::new(PAGE_SIZE)?,
            )?)
        };
    Some(PageRangeScan::FullyCommitted {
        first_protect,
        section_protect: (allocation.type_ == MemoryType::MEM_MAPPED)
            .then_some(allocation.allocation_protect),
    })
}

/// Updates Windows protection metadata after a successful page manager operation.
fn update_page_protections(
    allocations: &mut BTreeMap<usize, WindowsVirtualAllocation>,
    base: usize,
    size: usize,
    protect: Option<PageProtection>,
) {
    let Some(end) = base.checked_add(size) else {
        return;
    };
    let Some((_, allocation)) = allocations.range_mut(..=base).next_back() else {
        return;
    };
    match protect {
        Some(protect) => allocation.page_protections.insert(base..end, protect),
        None => allocation.page_protections.remove(base..end),
    }
}

pub(super) fn parse_page_protection(
    protect: u32,
) -> Option<(PageProtection, MemoryRegionPermissions)> {
    let protect = PageProtection::from_bits(protect)?;
    let permissions = page_protect_to_permissions(protect)?;
    Some((protect - PageProtection::PAGE_TARGETS_INVALID, permissions))
}

fn page_protect_to_permissions(protect: PageProtection) -> Option<MemoryRegionPermissions> {
    if !protect.has_valid_modifier_combination() {
        return None;
    }

    match protect.base() {
        value if value == PageProtection::PAGE_NOACCESS.bits() => {
            Some(MemoryRegionPermissions::empty())
        }
        value if value == PageProtection::PAGE_READONLY.bits() => {
            Some(MemoryRegionPermissions::READ)
        }
        value
            if value == PageProtection::PAGE_READWRITE.bits()
                || value == PageProtection::PAGE_WRITECOPY.bits() =>
        {
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE)
        }
        value
            if value == PageProtection::PAGE_EXECUTE.bits()
                || value == PageProtection::PAGE_EXECUTE_READ.bits() =>
        {
            Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC)
        }
        value
            if value == PageProtection::PAGE_EXECUTE_READWRITE.bits()
                || value == PageProtection::PAGE_EXECUTE_WRITECOPY.bits() =>
        {
            Some(
                MemoryRegionPermissions::READ
                    | MemoryRegionPermissions::WRITE
                    | MemoryRegionPermissions::EXEC,
            )
        }
        _ => None,
    }
}

fn permissions_to_page_protect(permissions: MemoryRegionPermissions) -> PageProtection {
    match (
        permissions.contains(MemoryRegionPermissions::READ),
        permissions.contains(MemoryRegionPermissions::WRITE),
        permissions.contains(MemoryRegionPermissions::EXEC),
    ) {
        (false, false, false) => PageProtection::PAGE_NOACCESS,
        (true, false, false) => PageProtection::PAGE_READONLY,
        (_, true, false) => PageProtection::PAGE_READWRITE,
        (false, false, true) => PageProtection::PAGE_EXECUTE,
        (true, false, true) => PageProtection::PAGE_EXECUTE_READ,
        (_, true, true) => PageProtection::PAGE_EXECUTE_READWRITE,
    }
}

fn zero_bits_address_limit(zero_bits: usize) -> Option<usize> {
    if zero_bits > 32 {
        // NtAllocateVirtualMemory treats ZeroBits as a bitmask when > 32.
        zero_bits.checked_add(1)
    } else if zero_bits < usize::BITS as usize {
        let shift = (usize::BITS as usize - zero_bits).try_into().ok()?;
        1usize.checked_shl(shift)
    } else {
        None
    }
}

fn mapping_error_to_nt_status(error: MappingError) -> NtStatus {
    match error {
        MappingError::UnAligned
        | MappingError::BadFD(_)
        | MappingError::NotAFile
        | MappingError::NotForReading
        | MappingError::MapError(
            AllocationError::Unaligned
            | AllocationError::BelowMinAddress
            | AllocationError::AboveMaxAddress,
        ) => NtStatus::INVALID_PARAMETER,
        MappingError::MapError(
            AllocationError::AddressInUse
            | AllocationError::AddressInUseByPlatform
            | AllocationError::AddressPartiallyInUse,
        ) => NtStatus::CONFLICTING_ADDRESSES,
        MappingError::OutOfMemory | MappingError::MapError(AllocationError::OutOfMemory) | _ => {
            NtStatus::NO_MEMORY
        }
    }
}

fn update_permissions<Platform: ShimPlatform>(
    vmem: &mut WindowsVmem<Platform>,
    aligned_base: usize,
    aligned_len: usize,
    permissions: MemoryRegionPermissions,
) -> Result<(), VmemProtectError> {
    let ptr = MutPtr::<Platform, u8>::from_usize(aligned_base);
    // SAFETY: This applies the guest's explicit VM protection request to a page-aligned range
    // tracked by the LiteBox page manager, whose lock the caller holds.
    unsafe { vmem.protect_pages(ptr, aligned_len, permissions) }
}

fn query_memory_basic_information<Platform: ShimPlatform>(
    vmem: &WindowsVmem<Platform>,
    base_address: usize,
) -> Option<MemoryBasicInformation> {
    let query_base = base_address & !(PAGE_SIZE - 1);
    if query_base >= Platform::TASK_ADDR_MAX {
        return None;
    }

    let mappings = vmem.mappings();
    if let Some(allocation) = find_virtual_allocation_containing(vmem.allocations(), query_base) {
        return query_allocation_basic_information(allocation, query_base, mappings);
    }

    if let Some((range, flags)) = mappings.get_key_value(&base_address) {
        let protect = permissions_to_page_protect(MemoryRegionPermissions::from(*flags));
        return Some(MemoryBasicInformation {
            base_address: query_base,
            allocation_base: range.start,
            allocation_protect: protect.bits(),
            partition_id: 0,
            _padding0: 0,
            region_size: range.end - query_base,
            state: MemoryState::MEM_COMMIT.bits(),
            protect: protect.bits(),
            type_: MemoryType::MEM_PRIVATE.bits(),
            _padding1: 0,
        });
    }

    if let Some(range) = vmem.reservation_containing(base_address) {
        return Some(MemoryBasicInformation {
            base_address: query_base,
            allocation_base: range.start,
            allocation_protect: 0,
            partition_id: 0,
            _padding0: 0,
            region_size: range.end - query_base,
            state: MemoryState::MEM_RESERVE.bits(),
            protect: 0,
            type_: MemoryType::MEM_PRIVATE.bits(),
            _padding1: 0,
        });
    }

    let next_mapping_start = mappings
        .overlapping(query_base..Platform::TASK_ADDR_MAX)
        .map(|(range, _)| range.start)
        .find(|&start| start > query_base)
        .unwrap_or(Platform::TASK_ADDR_MAX);
    let next_reservation_start = vmem
        .next_reservation_start(query_base, Platform::TASK_ADDR_MAX)
        .unwrap_or(Platform::TASK_ADDR_MAX);

    Some(MemoryBasicInformation {
        base_address: query_base,
        allocation_base: 0,
        allocation_protect: 0,
        partition_id: 0,
        _padding0: 0,
        region_size: next_mapping_start
            .min(next_reservation_start)
            .saturating_sub(query_base),
        state: MemoryState::MEM_FREE.bits(),
        protect: 0,
        type_: 0,
        _padding1: 0,
    })
}

fn query_allocation_basic_information(
    allocation: &WindowsVirtualAllocation,
    query_base: usize,
    mappings: &RangeMap<usize, VmFlags>,
) -> Option<MemoryBasicInformation> {
    let allocation_end = allocation.base.checked_add(allocation.size)?;
    let mut mappings = mappings.overlapping(query_base..allocation_end);
    let first = mappings.next();
    let (state, protect, region_end) = if let Some((first_range, first_flags)) =
        first.filter(|(range, _)| range.contains(&query_base))
    {
        let mut region_end = first_range.end.min(allocation_end);
        for (range, _) in mappings {
            if region_end == allocation_end || range.start != region_end {
                break;
            }
            region_end = range.end.min(allocation_end);
        }
        if let Some((range, protect)) = allocation.page_protections.get_key_value(&query_base) {
            region_end = region_end.min(range.end);
            (MemoryState::MEM_COMMIT.bits(), protect.bits(), region_end)
        } else {
            if let Some((range, _)) = allocation
                .page_protections
                .overlapping(query_base..region_end)
                .next()
            {
                region_end = region_end.min(range.start);
            }
            let protect = permissions_to_page_protect(MemoryRegionPermissions::from(*first_flags));
            (MemoryState::MEM_COMMIT.bits(), protect.bits(), region_end)
        }
    } else {
        let region_end = first.map_or(allocation_end, |(range, _)| range.start.min(allocation_end));
        (MemoryState::MEM_RESERVE.bits(), 0, region_end)
    };

    Some(MemoryBasicInformation {
        base_address: query_base,
        allocation_base: allocation.base,
        allocation_protect: allocation.allocation_protect.bits(),
        partition_id: 0,
        _padding0: 0,
        region_size: region_end - query_base,
        state,
        protect,
        type_: allocation.type_.bits(),
        _padding1: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{mut_byte_ptr, mut_ptr, run_with_test_platform_pointers};

    extern crate std;

    type TestPlatform = crate::tests::TestPlatform;
    type TestTask = Task<TestPlatform>;

    fn allocate_committed_rw(task: &TestTask, size: usize) -> (usize, usize) {
        let mut base = 0usize;
        let mut region_size = size;
        assert_eq!(
            task.sys_nt_allocate_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut base),
                0,
                mut_ptr(&mut region_size),
                (AllocationType::MEM_RESERVE | AllocationType::MEM_COMMIT).bits(),
                PageProtection::PAGE_READWRITE.bits(),
            ),
            NtStatus::SUCCESS
        );
        (base, region_size)
    }

    fn release_allocation(task: &TestTask, base: usize) {
        let mut release_base = base;
        let mut release_size = 0usize;
        assert_eq!(
            task.sys_nt_free_virtual_memory(
                ProcessHandle::CURRENT,
                mut_ptr(&mut release_base),
                mut_ptr(&mut release_size),
                FreeType::MEM_RELEASE.bits(),
            ),
            NtStatus::SUCCESS
        );
    }

    fn query_basic_information(task: &TestTask, base: usize) -> MemoryBasicInformation {
        let mut info = MemoryBasicInformation::default();
        let mut return_length = 0usize;
        assert_eq!(
            task.sys_nt_query_virtual_memory(
                ProcessHandle::CURRENT,
                base,
                MemoryInformationClass::Basic as u32,
                mut_byte_ptr(&mut info),
                size_of::<MemoryBasicInformation>(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length, size_of::<MemoryBasicInformation>());
        info
    }

    #[test]
    fn thread_environment_is_recorded_as_private_allocations() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let environment = crate::loader::create_thread_environment(
                &task.global.page_manager,
                0,
                0,
                crate::nt_types::ClientId {
                    unique_process: 0,
                    unique_thread: 0,
                },
                false,
            )
            .unwrap();
            let teb = query_basic_information(&task, environment.teb);
            assert_eq!(teb.allocation_base, environment.teb);
            assert_eq!(teb.type_, MemoryType::MEM_PRIVATE.bits());
            assert_eq!(
                teb.allocation_protect,
                PageProtection::PAGE_READWRITE.bits()
            );

            // Like Windows, the stack is an ordinary allocation whose pages can be reprotected.
            let stack_page = (environment.stack_top - 1) & !(PAGE_SIZE - 1);
            let mut protect_base = stack_page;
            let mut protect_size = PAGE_SIZE;
            let mut old_protect = 0u32;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(old_protect, PageProtection::PAGE_READWRITE.bits());
            let stack = query_basic_information(&task, stack_page);
            assert_eq!(stack.type_, MemoryType::MEM_PRIVATE.bits());
            assert_eq!(stack.protect, PageProtection::PAGE_READONLY.bits());
        });
    }

    #[test]
    fn placeholder_split_replace_restore_and_coalesce() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let allocate =
                |mut base, mut size, flags: AllocationType, protection: PageProtection| {
                    let status = task.sys_nt_allocate_virtual_memory_ex(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut base),
                        mut_ptr(&mut size),
                        flags.bits(),
                        protection.bits(),
                        MemoryExtendedParameters {
                            parameters: None,
                            count: 0,
                        },
                    );
                    (status, base, size)
                };
            let free = |mut base, mut size, flags: FreeType| {
                task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    mut_ptr(&mut size),
                    flags.bits(),
                )
            };
            let reserve = AllocationType::MEM_RESERVE | AllocationType::MEM_RESERVE_PLACEHOLDER;
            let replace = AllocationType::MEM_RESERVE | AllocationType::MEM_REPLACE_PLACEHOLDER;
            let preserve = FreeType::MEM_RELEASE | FreeType::MEM_PRESERVE_PLACEHOLDER;
            let coalesce = FreeType::MEM_RELEASE | FreeType::MEM_COALESCE_PLACEHOLDERS;
            let noaccess = PageProtection::PAGE_NOACCESS;
            let rw = PageProtection::PAGE_READWRITE;
            let unit = ALLOCATION_GRANULARITY;
            let (status, base, size) = allocate(0, unit * 4, reserve, noaccess);
            assert_eq!(status, NtStatus::SUCCESS);
            assert_eq!(size, unit * 4);
            let initial = query_basic_information(&task, base);
            assert_eq!(initial.allocation_protect, noaccess.bits());
            assert_eq!(initial.state, MemoryState::MEM_RESERVE.bits());
            assert_eq!(initial.protect, 0);
            let mut legacy_base = 0;
            let mut legacy_size = unit;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut legacy_base),
                    0,
                    mut_ptr(&mut legacy_size),
                    reserve.bits(),
                    noaccess.bits(),
                ),
                NtStatus::INVALID_PARAMETER
            );

            assert_eq!(
                allocate(base, PAGE_SIZE, AllocationType::MEM_COMMIT, rw).0,
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                allocate(base, unit, replace, rw).0,
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                free(base, PAGE_SIZE, FreeType::MEM_DECOMMIT),
                NtStatus::MEMORY_NOT_ALLOCATED
            );
            assert_eq!(free(base, 0, preserve), NtStatus::INVALID_PARAMETER_3);
            assert_eq!(free(base, size, coalesce), NtStatus::CONFLICTING_ADDRESSES);

            let middle = base + unit;
            assert_eq!(free(middle, unit, preserve), NtStatus::SUCCESS);
            for (start, length) in [(base, unit), (middle, unit), (base + unit * 2, unit * 2)] {
                let info = query_basic_information(&task, start);
                assert_eq!(info.allocation_base, start);
                assert_eq!(info.region_size, length);
                assert_eq!(info.state, MemoryState::MEM_RESERVE.bits());
            }
            assert_eq!(
                allocate(middle, unit, replace | AllocationType::MEM_COMMIT, rw).0,
                NtStatus::SUCCESS
            );
            assert_eq!(query_basic_information(&task, middle).protect, rw.bits());
            // SAFETY: The replacement committed this page for reading and writing.
            unsafe { core::ptr::write_bytes(middle as *mut u8, 0xa5, PAGE_SIZE) };
            assert_eq!(free(base, size, coalesce), NtStatus::CONFLICTING_ADDRESSES);
            assert_eq!(free(middle, unit, preserve), NtStatus::SUCCESS);
            assert_eq!(query_basic_information(&task, middle).protect, 0);
            assert_eq!(
                allocate(middle, unit, replace | AllocationType::MEM_COMMIT, rw).0,
                NtStatus::SUCCESS
            );
            // SAFETY: Replacing the placeholder recommitted this page for reading.
            assert_eq!(unsafe { *(middle as *const u8) }, 0);
            assert_eq!(free(middle, unit, preserve), NtStatus::SUCCESS);

            // Re-reserving a released slice creates a separate backing reservation.
            assert_eq!(free(middle, 0, FreeType::MEM_RELEASE), NtStatus::SUCCESS);
            assert_eq!(
                allocate(middle, unit, reserve, noaccess).0,
                NtStatus::SUCCESS
            );
            assert_eq!(free(base, size, coalesce), NtStatus::SUCCESS);
            // Coalescing joins the separately reserved slice into one backing reservation.
            assert!(
                task.global
                    .page_manager
                    .read_vmem()
                    .reservation_ranges()
                    .any(|range| range == (base..base + size))
            );
            assert_eq!(query_basic_information(&task, base).region_size, size);
            assert_eq!(
                allocate(base, size, replace | AllocationType::MEM_COMMIT, rw).0,
                NtStatus::SUCCESS
            );
            assert_eq!(query_basic_information(&task, base).region_size, size);
            assert_eq!(free(base, size, preserve), NtStatus::SUCCESS);
            release_allocation(&task, base);

            let (ordinary, ordinary_size) = allocate_committed_rw(&task, unit);
            assert_eq!(
                free(ordinary, ordinary_size, preserve),
                NtStatus::CONFLICTING_ADDRESSES
            );
            release_allocation(&task, ordinary);
        });
    }

    #[test]
    fn placeholder_flag_validation_and_edge_cases() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let allocate =
                |mut base, mut size, flags: AllocationType, protection: PageProtection| {
                    task.sys_nt_allocate_virtual_memory_ex(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut base),
                        mut_ptr(&mut size),
                        flags.bits(),
                        protection.bits(),
                        MemoryExtendedParameters {
                            parameters: None,
                            count: 0,
                        },
                    )
                };
            let free = |mut base, mut size, flags: FreeType| {
                task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    mut_ptr(&mut size),
                    flags.bits(),
                )
            };
            let reserve = AllocationType::MEM_RESERVE | AllocationType::MEM_RESERVE_PLACEHOLDER;
            let replace = AllocationType::MEM_RESERVE | AllocationType::MEM_REPLACE_PLACEHOLDER;
            let preserve = FreeType::MEM_RELEASE | FreeType::MEM_PRESERVE_PLACEHOLDER;
            let coalesce = FreeType::MEM_RELEASE | FreeType::MEM_COALESCE_PLACEHOLDERS;
            let noaccess = PageProtection::PAGE_NOACCESS;
            let rw = PageProtection::PAGE_READWRITE;
            let unit = ALLOCATION_GRANULARITY;

            assert_eq!(allocate(0, unit, reserve, rw), NtStatus::INVALID_PARAMETER);
            assert_eq!(
                allocate(0, unit, reserve | AllocationType::MEM_COMMIT, noaccess),
                NtStatus::INVALID_PARAMETER
            );

            let mut base = 0usize;
            let mut size = unit * 4;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory_ex(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    mut_ptr(&mut size),
                    (reserve | AllocationType::MEM_TOP_DOWN).bits(),
                    noaccess.bits(),
                    MemoryExtendedParameters {
                        parameters: None,
                        count: 0,
                    },
                ),
                NtStatus::SUCCESS
            );
            let middle = base + unit;
            let tail = base + unit * 2;

            assert_eq!(
                allocate(base, unit, replace | AllocationType::MEM_TOP_DOWN, rw),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(
                allocate(0, unit, replace, rw),
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                allocate(0, unit + 1, replace, rw),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(
                allocate(
                    base,
                    unit,
                    AllocationType::MEM_REPLACE_PLACEHOLDER | AllocationType::MEM_COMMIT,
                    rw
                ),
                NtStatus::INVALID_PARAMETER
            );
            // Parameter checks follow the host order: free type, size, then base.
            assert_eq!(
                free(base, unit, FreeType::MEM_PRESERVE_PLACEHOLDER),
                NtStatus::INVALID_PARAMETER_4
            );
            assert_eq!(
                free(
                    base,
                    unit,
                    FreeType::MEM_DECOMMIT | FreeType::MEM_PRESERVE_PLACEHOLDER
                ),
                NtStatus::INVALID_PARAMETER_4
            );
            assert_eq!(
                free(base + 1, unit, FreeType::MEM_COALESCE_PLACEHOLDERS),
                NtStatus::INVALID_PARAMETER_4
            );
            assert_eq!(
                free(base, unit, preserve | FreeType::MEM_COALESCE_PLACEHOLDERS),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(free(base, 0, preserve), NtStatus::INVALID_PARAMETER_3);
            assert_eq!(
                free(base, unit + 1, preserve),
                NtStatus::INVALID_PARAMETER_3
            );
            assert_eq!(
                free(base + 1, unit + 1, coalesce),
                NtStatus::INVALID_PARAMETER_3
            );
            assert_eq!(
                free(base + 1, unit, preserve),
                NtStatus::INVALID_PARAMETER_2
            );
            assert_eq!(
                free(base + 1, unit, coalesce),
                NtStatus::INVALID_PARAMETER_2
            );
            assert_eq!(free(0, unit, preserve), NtStatus::MEMORY_NOT_ALLOCATED);
            assert_eq!(free(0, unit, coalesce), NtStatus::CONFLICTING_ADDRESSES);
            assert_eq!(
                free(base + unit * 3, unit * 2, preserve),
                NtStatus::UNABLE_TO_FREE_VM
            );
            // A whole reserved placeholder can only be split, not preserved.
            assert_eq!(
                free(base, unit * 4, preserve),
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                free(usize::MAX & !(PAGE_SIZE - 1), PAGE_SIZE * 2, coalesce),
                NtStatus::INVALID_PARAMETER
            );

            assert_eq!(free(middle, unit, preserve), NtStatus::SUCCESS);
            assert_eq!(
                free(middle, unit, preserve),
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                free(middle, unit * 2, preserve),
                NtStatus::UNABLE_TO_FREE_VM
            );
            assert_eq!(
                free(base + PAGE_SIZE, unit * 2 - PAGE_SIZE, coalesce),
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                free(base, unit * 5, coalesce),
                NtStatus::CONFLICTING_ADDRESSES
            );

            // Replacing without MEM_COMMIT leaves the range reserved until a later commit.
            assert_eq!(allocate(middle, unit, replace, rw), NtStatus::SUCCESS);
            let replaced = query_basic_information(&task, middle);
            assert_eq!(replaced.allocation_base, middle);
            assert_eq!(replaced.allocation_protect, rw.bits());
            assert_eq!(replaced.state, MemoryState::MEM_RESERVE.bits());
            assert_eq!(
                allocate(middle, unit, replace, rw),
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                allocate(middle, PAGE_SIZE, AllocationType::MEM_COMMIT, rw),
                NtStatus::SUCCESS
            );
            assert_eq!(
                query_basic_information(&task, middle).state,
                MemoryState::MEM_COMMIT.bits()
            );
            // SAFETY: The page was just committed for reading and writing.
            unsafe { core::ptr::write_bytes(middle as *mut u8, 0x5a, PAGE_SIZE) };

            // Like Windows, restoring part of a replaced allocation splits it and keeps the
            // remaining replaced pieces intact.
            assert_eq!(
                free(middle + PAGE_SIZE, PAGE_SIZE, preserve),
                NtStatus::SUCCESS
            );
            // SAFETY: The first page of the replaced allocation is still committed.
            assert_eq!(unsafe { *(middle as *const u8) }, 0x5a);
            let head = query_basic_information(&task, middle);
            assert_eq!(head.allocation_base, middle);
            assert_eq!(head.region_size, PAGE_SIZE);
            assert_eq!(head.state, MemoryState::MEM_COMMIT.bits());
            assert_eq!(head.protect, rw.bits());
            let restored = query_basic_information(&task, middle + PAGE_SIZE);
            assert_eq!(restored.allocation_base, middle + PAGE_SIZE);
            assert_eq!(restored.region_size, PAGE_SIZE);
            assert_eq!(restored.state, MemoryState::MEM_RESERVE.bits());
            assert_eq!(restored.allocation_protect, noaccess.bits());
            let rest = query_basic_information(&task, middle + PAGE_SIZE * 2);
            assert_eq!(rest.allocation_base, middle + PAGE_SIZE * 2);
            assert_eq!(rest.allocation_protect, rw.bits());
            assert_eq!(free(middle, PAGE_SIZE, preserve), NtStatus::SUCCESS);
            assert_eq!(
                free(middle + PAGE_SIZE * 2, unit - PAGE_SIZE * 2, preserve),
                NtStatus::SUCCESS
            );
            assert_eq!(free(middle, unit, coalesce), NtStatus::SUCCESS);
            assert_eq!(query_basic_information(&task, middle).region_size, unit);

            // A released slice leaves a gap that cannot be coalesced across.
            assert_eq!(free(middle, 0, FreeType::MEM_RELEASE), NtStatus::SUCCESS);
            assert_eq!(free(base, size, coalesce), NtStatus::CONFLICTING_ADDRESSES);

            let after_coalesce_attempt = query_basic_information(&task, tail);
            assert_eq!(after_coalesce_attempt.allocation_base, tail);
            assert_eq!(after_coalesce_attempt.region_size, unit * 2);
            release_allocation(&task, base);
            release_allocation(&task, tail);
        });
    }

    #[test]
    fn page_manager_distinguishes_platform_collisions_from_guest_overlaps() {
        run_with_test_platform_pointers(|| {
            let platform = crate::tests::test_platform();
            let host_manager = WindowsPageManager::<TestPlatform>::new(platform);
            let guest_manager = WindowsPageManager::<TestPlatform>::new(platform);
            let length = NonZeroPageSize::new(ALLOCATION_GRANULARITY).unwrap();
            // SAFETY: Both managers request fresh reservations without replacing mappings.
            let (host, guest) = unsafe {
                (
                    host_manager.create_reserved_pages(
                        None,
                        length,
                        ALLOCATION_GRANULARITY,
                        CreatePagesFlags::TOP_DOWN,
                    ),
                    guest_manager.create_reserved_pages(
                        None,
                        length,
                        ALLOCATION_GRANULARITY,
                        CreatePagesFlags::TOP_DOWN,
                    ),
                )
            };
            let host = host.unwrap();
            let guest = guest.unwrap();
            for permissions in [
                None,
                Some(MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE),
            ] {
                // SAFETY: Both requests use fixed ranges without replacing existing mappings.
                let host_result = unsafe {
                    match permissions {
                        Some(permissions) => guest_manager.create_reserved_and_committed_pages(
                            NonZeroAddress::new(host.as_usize()),
                            length,
                            ALLOCATION_GRANULARITY,
                            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                            permissions,
                        ),
                        None => guest_manager.create_reserved_pages(
                            NonZeroAddress::new(host.as_usize()),
                            length,
                            ALLOCATION_GRANULARITY,
                            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                        ),
                    }
                };
                assert!(matches!(
                    host_result,
                    Err(MappingError::MapError(
                        AllocationError::AddressInUseByPlatform
                    ))
                ));
                // SAFETY: Both requests use fixed ranges without replacing existing mappings.
                let guest_result = unsafe {
                    match permissions {
                        Some(permissions) => guest_manager.create_reserved_and_committed_pages(
                            NonZeroAddress::new(guest.as_usize()),
                            length,
                            ALLOCATION_GRANULARITY,
                            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                            permissions,
                        ),
                        None => guest_manager.create_reserved_pages(
                            NonZeroAddress::new(guest.as_usize()),
                            length,
                            ALLOCATION_GRANULARITY,
                            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                        ),
                    }
                };
                assert!(matches!(
                    guest_result,
                    Err(MappingError::MapError(AllocationError::AddressInUse))
                ));
            }
            // SAFETY: These unpublished reservations have no users and remain owned by their managers.
            unsafe {
                host_manager.remove_pages(host, length.as_usize()).unwrap();
                guest_manager
                    .remove_pages(guest, length.as_usize())
                    .unwrap();
            }
        });
    }

    #[test]
    fn page_manager_allocates_with_bounds_alignment_and_directional_host_retries() {
        run_with_test_platform_pointers(|| {
            let platform = crate::tests::test_platform();
            let host_manager = WindowsPageManager::<TestPlatform>::new(platform);
            let guest_manager = WindowsPageManager::<TestPlatform>::new(platform);
            let alignment = ALLOCATION_GRANULARITY * 2;
            let length = NonZeroPageSize::new(ALLOCATION_GRANULARITY).unwrap();
            // SAFETY: The fixture retains exclusive ownership of the fresh envelope reservation.
            let host = unsafe {
                host_manager.create_reserved_pages(
                    None,
                    NonZeroPageSize::new(alignment * 3).unwrap(),
                    alignment,
                    CreatePagesFlags::empty(),
                )
            }
            .unwrap();
            let base = host.as_usize();
            let middle = MutPtr::<TestPlatform, u8>::from_usize(base + alignment);
            let suffix = MutPtr::<TestPlatform, u8>::from_usize(base + alignment * 2);
            // SAFETY: The fixture owns the envelope and releases its unused middle segment.
            unsafe { host_manager.remove_pages(middle, alignment) }.unwrap();
            let _cleanup = litebox::utils::defer(|| {
                // SAFETY: Both retained host segments are unused and exclusively fixture-owned.
                unsafe {
                    host_manager.remove_pages(host, alignment).unwrap();
                    host_manager.remove_pages(suffix, alignment).unwrap();
                }
            });
            for pages in [
                PrivatePages::Reserved,
                PrivatePages::Committed(
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                ),
            ] {
                for flags in [CreatePagesFlags::empty(), CreatePagesFlags::TOP_DOWN] {
                    // SAFETY: The manager selects fresh bounded address space without replacement.
                    let guest = unsafe {
                        guest_manager.create_private_pages(
                            None,
                            base..base + alignment * 3,
                            length,
                            alignment,
                            flags,
                            pages,
                        )
                    }
                    .unwrap();
                    let _release = litebox::utils::defer(|| {
                        // SAFETY: The test relinquishes its guest allocation after all assertions.
                        unsafe { guest_manager.remove_pages(guest, length.as_usize()) }.unwrap();
                    });
                    assert_eq!(guest.as_usize(), middle.as_usize());
                    assert_eq!(guest.as_usize() % alignment, 0);
                    assert_eq!(
                        guest_manager.read_vmem().get_memory_permissions(
                            NonZeroAddress::new(guest.as_usize()).unwrap(),
                            length,
                        ),
                        match pages {
                            PrivatePages::Committed(permissions) => Some(permissions),
                            PrivatePages::Reserved | PrivatePages::Mergeable => None,
                        },
                    );
                }
            }
        });
    }

    #[test]
    fn query_untracked_mapping_distinguishes_reservation_from_noaccess() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let length = NonZeroPageSize::new(PAGE_SIZE * 2).unwrap();
            // SAFETY: The manager chooses a fresh address without replacing existing mappings.
            let ptr = unsafe {
                task.global.page_manager.create_reserved_pages(
                    None,
                    length,
                    ALLOCATION_GRANULARITY,
                    CreatePagesFlags::empty(),
                )
            }
            .unwrap();
            let base = ptr.as_usize();
            let info = query_basic_information(&task, base + PAGE_SIZE + 1);
            assert_eq!(info.base_address, base + PAGE_SIZE);
            assert_eq!(info.region_size, PAGE_SIZE);
            assert_eq!(info.state, MemoryState::MEM_RESERVE.bits());
            assert_eq!(info.protect, 0);

            // SAFETY: The range is reserved and remains inaccessible throughout this failed call.
            assert!(matches!(
                unsafe {
                    task.global.page_manager.write_vmem().protect_pages(
                        ptr,
                        PAGE_SIZE * 2,
                        MemoryRegionPermissions::READ,
                    )
                },
                Err(VmemProtectError::InvalidRange(_))
            ));

            // SAFETY: This test owns the reservation and does not access its contents.
            unsafe {
                task.global.page_manager.write_vmem().commit_pages(
                    ptr,
                    PAGE_SIZE * 2,
                    MemoryRegionPermissions::empty(),
                )
            }
            .unwrap();
            let info = query_basic_information(&task, base);
            assert_eq!(info.state, MemoryState::MEM_COMMIT.bits());
            assert_eq!(info.protect, PageProtection::PAGE_NOACCESS.bits());

            // SAFETY: The test owns this allocation and will not access it after release.
            unsafe { task.global.page_manager.remove_pages(ptr, PAGE_SIZE * 2) }.unwrap();
        });
    }

    #[test]
    fn query_regions_follow_core_state_and_windows_protection_boundaries() {
        let base = ALLOCATION_GRANULARITY;
        let mut pages = RangeMap::new();
        let copy_protect = PageProtection::PAGE_WRITECOPY | PageProtection::PAGE_NOCACHE;
        pages.insert(base..base + 2 * PAGE_SIZE, copy_protect);
        pages.insert(
            base + 2 * PAGE_SIZE..base + 3 * PAGE_SIZE,
            PageProtection::PAGE_READWRITE,
        );
        pages.insert(
            base + 3 * PAGE_SIZE..base + 4 * PAGE_SIZE,
            PageProtection::PAGE_READONLY,
        );
        pages.insert(
            base + 4 * PAGE_SIZE..base + 5 * PAGE_SIZE,
            PageProtection::PAGE_EXECUTE_READ,
        );
        pages.insert(
            base + 5 * PAGE_SIZE..base + 6 * PAGE_SIZE,
            PageProtection::PAGE_NOACCESS,
        );
        let allocation = WindowsVirtualAllocation {
            base,
            size: PAGE_SIZE * 6,
            allocation_protect: PageProtection::PAGE_READWRITE,
            type_: MemoryType::MEM_PRIVATE,
            placeholder_state: WindowsPlaceholderState::None,
            page_protections: pages,
        };
        let mut mappings = RangeMap::new();
        for (range, flags) in [
            (base..base + PAGE_SIZE, VmFlags::VM_READ | VmFlags::VM_WRITE),
            (
                base + PAGE_SIZE..base + 3 * PAGE_SIZE,
                VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD,
            ),
            (base + 5 * PAGE_SIZE..base + 6 * PAGE_SIZE, VmFlags::empty()),
        ] {
            mappings.insert(range, flags);
        }
        for (offset, count, state, protect) in [
            (0, 2, MemoryState::MEM_COMMIT, copy_protect.bits()),
            (1, 1, MemoryState::MEM_COMMIT, copy_protect.bits()),
            (
                2,
                1,
                MemoryState::MEM_COMMIT,
                PageProtection::PAGE_READWRITE.bits(),
            ),
            (3, 2, MemoryState::MEM_RESERVE, 0),
            (4, 1, MemoryState::MEM_RESERVE, 0),
            (
                5,
                1,
                MemoryState::MEM_COMMIT,
                PageProtection::PAGE_NOACCESS.bits(),
            ),
        ] {
            let query_base = base + offset * PAGE_SIZE;
            let info =
                query_allocation_basic_information(&allocation, query_base, &mappings).unwrap();
            assert_eq!(info.base_address, query_base);
            assert_eq!(info.region_size, count * PAGE_SIZE);
            assert_eq!(info.state, state.bits());
            assert_eq!(info.protect, protect);
            assert_eq!(info.allocation_base, base);
            assert_eq!(
                info.allocation_protect,
                PageProtection::PAGE_READWRITE.bits()
            );
            assert_eq!(info.type_, MemoryType::MEM_PRIVATE.bits());
        }
    }

    #[test]
    fn tracked_allocation_checks_core_commitment_not_protection_entries() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, _) = allocate_committed_rw(&task, PAGE_SIZE * 3);
            let middle = MutPtr::<TestPlatform, u8>::from_usize(base + PAGE_SIZE);
            // SAFETY: The test owns the allocation and does not access the page being decommitted.
            unsafe {
                task.global
                    .page_manager
                    .write_vmem()
                    .decommit_pages(middle, PAGE_SIZE)
            }
            .unwrap();

            for (offset, state, protect) in [
                (
                    0,
                    MemoryState::MEM_COMMIT,
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                (1, MemoryState::MEM_RESERVE, 0),
                (
                    2,
                    MemoryState::MEM_COMMIT,
                    PageProtection::PAGE_READWRITE.bits(),
                ),
            ] {
                let info = query_basic_information(&task, base + offset * PAGE_SIZE);
                assert_eq!(info.state, state.bits());
                assert_eq!(info.protect, protect);
                assert_eq!(info.region_size, PAGE_SIZE);
                assert_eq!(info.allocation_base, base);
            }
            let mut protect_base = base;
            let mut protect_size = PAGE_SIZE * 3;
            let mut old_protect = u32::MAX;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::NOT_COMMITTED
            );
            assert_eq!(old_protect, PageProtection::PAGE_NOACCESS.bits());
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    0,
                    mut_ptr(&mut protect_size),
                    AllocationType::MEM_RESET.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::CONFLICTING_ADDRESSES
            );
            assert_eq!(
                query_basic_information(&task, base).protect,
                PageProtection::PAGE_READWRITE.bits()
            );

            task.global
                .page_manager
                .write_vmem()
                .allocations_mut()
                .get_mut(&base)
                .unwrap()
                .page_protections
                .clear();
            let info = query_basic_information(&task, base);
            assert_eq!(info.state, MemoryState::MEM_COMMIT.bits());
            assert_eq!(info.protect, PageProtection::PAGE_READWRITE.bits());
            assert_eq!(info.region_size, PAGE_SIZE);
            protect_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(old_protect, PageProtection::PAGE_READWRITE.bits());
            release_allocation(&task, base);
        });
    }

    #[test]
    fn commit_mixed_reserved_and_committed_pages_preserves_contents() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, size) = allocate_committed_rw(&task, PAGE_SIZE * 3);
            let _cleanup = litebox::utils::defer(|| release_allocation(&task, base));
            let first = MutPtr::<TestPlatform, u8>::from_usize(base);
            let middle = MutPtr::<TestPlatform, u8>::from_usize(base + PAGE_SIZE);
            let last = MutPtr::<TestPlatform, u8>::from_usize(base + 2 * PAGE_SIZE);
            first.write_at_offset(0, 0x5a).unwrap();
            middle.write_at_offset(0, 0xff).unwrap();
            last.write_at_offset(0, 0xa5).unwrap();
            let mut middle_base = middle.as_usize();
            let mut middle_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut middle_base),
                    mut_ptr(&mut middle_size),
                    FreeType::MEM_DECOMMIT.bits(),
                ),
                NtStatus::SUCCESS
            );
            let mut last_base = last.as_usize();
            let mut last_size = PAGE_SIZE;
            let mut old_protect = 0;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut last_base),
                    mut_ptr(&mut last_size),
                    PageProtection::PAGE_NOACCESS.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );
            for expected_middle in [0, 0x3c] {
                let mut commit_base = base;
                let mut commit_size = size;
                assert_eq!(
                    task.sys_nt_allocate_virtual_memory(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut commit_base),
                        0,
                        mut_ptr(&mut commit_size),
                        AllocationType::MEM_COMMIT.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ),
                    NtStatus::SUCCESS
                );
                assert_eq!(commit_base, base);
                assert_eq!(first.read_at_offset(0), Some(0x5a));
                assert_eq!(middle.read_at_offset(0), Some(expected_middle));
                assert_eq!(last.read_at_offset(0), Some(0xa5));
                middle.write_at_offset(0, 0x3c).unwrap();
            }
        });
    }

    #[test]
    fn commit_writeback_failure_preserves_exact_page_protections() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            for fail_base_write in [true, false] {
                let mut base = 0;
                let mut size = PAGE_SIZE;
                assert_eq!(
                    task.sys_nt_allocate_virtual_memory(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut base),
                        0,
                        mut_ptr(&mut size),
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ),
                    NtStatus::SUCCESS
                );
                let allocation_base = base;
                let protect = PageProtection::PAGE_EXECUTE;
                let (_, permissions) = parse_page_protection(protect.bits()).unwrap();
                let base_output = if fail_base_write {
                    crate::tests::null_mut_ptr()
                } else {
                    mut_ptr(&mut base)
                };
                let size_output = if fail_base_write {
                    mut_ptr(&mut size)
                } else {
                    crate::tests::null_mut_ptr()
                };
                assert_eq!(
                    task.commit_existing_virtual_memory(
                        allocation_base,
                        PAGE_SIZE,
                        protect,
                        permissions,
                        base_output,
                        size_output,
                    ),
                    NtStatus::ACCESS_VIOLATION
                );
                let info = query_basic_information(&task, allocation_base);
                assert_eq!(info.state, MemoryState::MEM_COMMIT.bits());
                assert_eq!(info.protect, protect.bits());
                assert_eq!(info.allocation_base, allocation_base);
                assert_eq!(
                    info.allocation_protect,
                    PageProtection::PAGE_READWRITE.bits()
                );
                assert_eq!(
                    task.global.page_manager.read_vmem().allocations()[&allocation_base]
                        .page_protections
                        .get(&allocation_base),
                    Some(&protect)
                );
                release_allocation(&task, allocation_base);
            }
        });
    }

    #[test]
    fn page_targets_invalid_is_not_reported_as_page_protection() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    (AllocationType::MEM_RESERVE | AllocationType::MEM_COMMIT).bits(),
                    (PageProtection::PAGE_EXECUTE_READ | PageProtection::PAGE_TARGETS_INVALID)
                        .bits(),
                ),
                NtStatus::SUCCESS
            );

            let info = query_basic_information(&task, base);
            assert_eq!(
                info.allocation_protect,
                PageProtection::PAGE_EXECUTE_READ.bits()
            );
            assert_eq!(info.protect, PageProtection::PAGE_EXECUTE_READ.bits());

            release_allocation(&task, base);
        });
    }

    #[test]
    fn read_virtual_memory_copies_across_chunks() {
        run_with_test_platform_pointers(|| {
            let source = std::vec![0x5au8; READ_VIRTUAL_MEMORY_CHUNK_BYTES + 1];
            let mut destination = std::vec![0u8; source.len()];
            let mut bytes_read = 0usize;

            assert_eq!(
                TestTask::sys_nt_read_virtual_memory(
                    ProcessHandle::CURRENT,
                    ConstPtr::<TestPlatform, u8>::from_usize(source.as_ptr() as usize),
                    MutPtr::<TestPlatform, u8>::from_usize(destination.as_mut_ptr() as usize),
                    source.len(),
                    Some(mut_ptr(&mut bytes_read)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(destination, source);
            assert_eq!(bytes_read, source.len());
        });
    }

    #[test]
    fn allocate_virtual_memory_commit_only_null_base_creates_committed_region() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    AllocationType::MEM_COMMIT.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_ne!(base, 0);
            assert_eq!(region_size, PAGE_SIZE);

            let info = query_basic_information(&task, base);
            assert_eq!(info.state, MemoryState::MEM_COMMIT.bits());
            assert_eq!(info.protect, PageProtection::PAGE_READWRITE.bits());

            release_allocation(&task, base);
        });
    }

    #[test]
    fn allocate_virtual_memory_fixed_reserve_rounds_base_to_allocation_granularity() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let requested_base = ALLOCATION_GRANULARITY * 8 + PAGE_SIZE + 123;
            let expected_base = requested_base & !(ALLOCATION_GRANULARITY - 1);
            let mut base = requested_base;
            let mut region_size = 1usize;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(base, expected_base);
            assert_eq!(region_size, PAGE_SIZE * 2);

            release_allocation(&task, base);
        });
    }

    #[test]
    fn allocate_virtual_memory_zero_bits_is_allowed_for_null_base() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    1,
                    mut_ptr(&mut region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_ne!(base, 0);
            assert_eq!(region_size, PAGE_SIZE);

            release_allocation(&task, base);
        });
    }

    #[test]
    fn allocate_virtual_memory_fixed_collision_returns_conflicting_addresses() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );

            let mut fixed_base = base;
            let mut fixed_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut fixed_base),
                    0,
                    mut_ptr(&mut fixed_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::CONFLICTING_ADDRESSES
            );

            release_allocation(&task, base);
        });
    }

    #[test]
    fn allocate_virtual_memory_mem_top_down_prefers_higher_addresses() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();

            let mut bottom_base = 0usize;
            let mut bottom_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut bottom_base),
                    0,
                    mut_ptr(&mut bottom_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );

            let mut top_base = 0usize;
            let mut top_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut top_base),
                    0,
                    mut_ptr(&mut top_size),
                    (AllocationType::MEM_RESERVE | AllocationType::MEM_TOP_DOWN).bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );

            assert!(top_base > bottom_base);

            release_allocation(&task, top_base);
            release_allocation(&task, bottom_base);
        });
    }

    #[test]
    fn allocate_virtual_memory_mem_reset_preserves_committed_state_and_protection() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, _) = allocate_committed_rw(&task, PAGE_SIZE);

            let mut reset_base = base + 1;
            let mut reset_size = 1usize;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut reset_base),
                    0,
                    mut_ptr(&mut reset_size),
                    AllocationType::MEM_RESET.bits(),
                    PageProtection::PAGE_NOACCESS.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(reset_base, base);
            assert_eq!(reset_size, PAGE_SIZE);

            let info = query_basic_information(&task, base);
            assert_eq!(info.state, MemoryState::MEM_COMMIT.bits());
            assert_eq!(info.protect, PageProtection::PAGE_READWRITE.bits());

            release_allocation(&task, base);
        });
    }

    #[test]
    fn allocate_virtual_memory_mem_reset_rejects_combined_flags() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, _) = allocate_committed_rw(&task, PAGE_SIZE);

            let mut reset_base = base;
            let mut reset_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut reset_base),
                    0,
                    mut_ptr(&mut reset_size),
                    (AllocationType::MEM_RESET | AllocationType::MEM_COMMIT).bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::INVALID_PARAMETER
            );

            release_allocation(&task, base);
        });
    }

    #[test]
    fn protect_virtual_memory_rounds_outputs_and_reports_old_protection() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, allocation_size) = allocate_committed_rw(&task, PAGE_SIZE * 2 - 1);
            assert_eq!(base % ALLOCATION_GRANULARITY, 0);
            assert_eq!(allocation_size, PAGE_SIZE * 2);

            let mut protect_base = base + 1;
            let mut protect_size = 1usize;
            let mut old_protect = 0u32;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(protect_base, base);
            assert_eq!(protect_size, PAGE_SIZE);
            assert_eq!(old_protect, PageProtection::PAGE_READWRITE.bits());

            let info = query_basic_information(&task, base);
            assert_eq!(info.base_address, base);
            assert_eq!(info.allocation_base, base);
            assert_eq!(
                info.allocation_protect,
                PageProtection::PAGE_READWRITE.bits()
            );
            assert_eq!(info.region_size, PAGE_SIZE);
            assert_eq!(info.state, MemoryState::MEM_COMMIT.bits());
            assert_eq!(info.protect, PageProtection::PAGE_READONLY.bits());
            assert_eq!(info.type_, MemoryType::MEM_PRIVATE.bits());

            release_allocation(&task, base);
        });
    }

    #[test]
    fn protect_virtual_memory_allows_committed_page_noaccess() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    (AllocationType::MEM_RESERVE | AllocationType::MEM_COMMIT).bits(),
                    PageProtection::PAGE_NOACCESS.bits(),
                ),
                NtStatus::SUCCESS
            );

            let info = query_basic_information(&task, base);
            assert_eq!(info.state, MemoryState::MEM_COMMIT.bits());
            assert_eq!(info.protect, PageProtection::PAGE_NOACCESS.bits());

            let mut protect_base = base;
            let mut protect_size = PAGE_SIZE;
            let mut old_protect = 0u32;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(old_protect, PageProtection::PAGE_NOACCESS.bits());

            release_allocation(&task, base);
        });
    }

    #[test]
    fn protect_virtual_memory_rejects_reserved_pages() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );

            let mut protect_base = base;
            let mut protect_size = PAGE_SIZE;
            let mut old_protect = u32::MAX;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::NOT_COMMITTED
            );
            assert_eq!(old_protect, PageProtection::PAGE_NOACCESS.bits());

            for invalid_protect in [
                PageProtection::PAGE_NOACCESS | PageProtection::PAGE_GUARD,
                PageProtection::PAGE_NOACCESS | PageProtection::PAGE_NOCACHE,
                PageProtection::PAGE_NOACCESS | PageProtection::PAGE_WRITECOMBINE,
                PageProtection::PAGE_READWRITE
                    | PageProtection::PAGE_NOCACHE
                    | PageProtection::PAGE_WRITECOMBINE,
                PageProtection::PAGE_READWRITE
                    | PageProtection::PAGE_GUARD
                    | PageProtection::PAGE_NOCACHE,
            ] {
                let mut protect_base = base;
                let mut protect_size = PAGE_SIZE;
                let mut old_protect = u32::MAX;
                assert_eq!(
                    task.sys_nt_protect_virtual_memory(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut protect_base),
                        mut_ptr(&mut protect_size),
                        invalid_protect.bits(),
                        mut_ptr(&mut old_protect),
                    ),
                    NtStatus::INVALID_PAGE_PROTECTION
                );
                assert_eq!(old_protect, u32::MAX);
            }

            release_allocation(&task, base);
        });
    }

    #[test]
    fn protect_virtual_memory_rejects_partly_reserved_range() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE * 2;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            let mut commit_base = base;
            let mut commit_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut commit_base),
                    0,
                    mut_ptr(&mut commit_size),
                    AllocationType::MEM_COMMIT.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );

            let mut protect_base = base;
            let mut protect_size = PAGE_SIZE * 2;
            let mut old_protect = u32::MAX;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::NOT_COMMITTED
            );
            assert_eq!(old_protect, PageProtection::PAGE_NOACCESS.bits());
            assert_eq!(
                query_basic_information(&task, base).protect,
                PageProtection::PAGE_READWRITE.bits()
            );

            release_allocation(&task, base);
        });
    }

    #[test]
    fn free_virtual_memory_decommit_zero_size_at_allocation_base_decommits_whole_region() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, allocation_size) = allocate_committed_rw(&task, PAGE_SIZE * 2);

            let mut decommit_base = base;
            let mut decommit_size = 0usize;
            assert_eq!(
                task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut decommit_base),
                    mut_ptr(&mut decommit_size),
                    FreeType::MEM_DECOMMIT.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(decommit_base, base);
            assert_eq!(decommit_size, allocation_size);

            let info = query_basic_information(&task, base);
            assert_eq!(info.state, MemoryState::MEM_RESERVE.bits());
            assert_eq!(info.protect, 0);
            assert_eq!(info.region_size, allocation_size);

            release_allocation(&task, base);
        });
    }

    #[test]
    fn free_virtual_memory_partial_release_preserves_suffix_for_commit() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut first_base = 0usize;
            let mut first_size = 0x100000usize;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut first_base),
                    0,
                    mut_ptr(&mut first_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            let mut second_base = 0usize;
            let mut second_size = 28080usize;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut second_base),
                    0,
                    mut_ptr(&mut second_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            let mut base = 0usize;
            let mut region_size = 0x1d0000usize;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );

            let mut release_base = base;
            let mut release_size = 0x1c0000usize;
            assert_eq!(
                task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut release_base),
                    mut_ptr(&mut release_size),
                    FreeType::MEM_RELEASE.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(release_base, base);
            assert_eq!(release_size, 0x1c0000);

            let suffix_base = base + 0x1c0000;
            let mut commit_base = suffix_base;
            let mut commit_size = PAGE_SIZE * 2;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut commit_base),
                    0,
                    mut_ptr(&mut commit_size),
                    AllocationType::MEM_COMMIT.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(commit_base, suffix_base);
            assert_eq!(commit_size, PAGE_SIZE * 2);
            let committed = MutPtr::<TestPlatform, u8>::from_usize(commit_base);
            assert_eq!(committed.write_at_offset(0, 0x5a), Some(()));
            assert_eq!(committed.read_at_offset(0), Some(0x5a));

            release_allocation(&task, first_base);
            release_allocation(&task, second_base);
            release_allocation(&task, suffix_base);
        });
    }

    #[test]
    fn free_virtual_memory_middle_release_preserves_fragment_protections() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, _) = allocate_committed_rw(&task, PAGE_SIZE * 3);

            let mut prefix_base = base;
            let mut prefix_size = PAGE_SIZE;
            let mut old_protect = 0u32;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut prefix_base),
                    mut_ptr(&mut prefix_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );

            let suffix_base = base + PAGE_SIZE * 2;
            let mut protect_suffix_base = suffix_base;
            let mut suffix_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_suffix_base),
                    mut_ptr(&mut suffix_size),
                    PageProtection::PAGE_EXECUTE_READ.bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );

            let mut release_base = base + PAGE_SIZE;
            let mut release_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut release_base),
                    mut_ptr(&mut release_size),
                    FreeType::MEM_RELEASE.bits(),
                ),
                NtStatus::SUCCESS
            );

            let prefix = query_basic_information(&task, base);
            assert_eq!(prefix.allocation_base, base);
            assert_eq!(prefix.region_size, PAGE_SIZE);
            assert_eq!(prefix.protect, PageProtection::PAGE_READONLY.bits());

            let released = query_basic_information(&task, base + PAGE_SIZE);
            assert_eq!(released.allocation_base, 0);
            assert_eq!(released.region_size, PAGE_SIZE);
            assert_eq!(released.state, MemoryState::MEM_FREE.bits());

            let suffix = query_basic_information(&task, suffix_base);
            assert_eq!(suffix.allocation_base, suffix_base);
            assert_eq!(suffix.region_size, PAGE_SIZE);
            assert_eq!(suffix.protect, PageProtection::PAGE_EXECUTE_READ.bits());

            release_allocation(&task, base);
            release_allocation(&task, suffix_base);
        });
    }

    #[test]
    fn free_virtual_memory_decommit_discards_page_contents() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, _) = allocate_committed_rw(&task, PAGE_SIZE);
            let ptr = MutPtr::<TestPlatform, u8>::from_usize(base);
            assert_eq!(ptr.write_at_offset(0, 0xa5), Some(()));

            let mut decommit_base = base;
            let mut decommit_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut decommit_base),
                    mut_ptr(&mut decommit_size),
                    FreeType::MEM_DECOMMIT.bits(),
                ),
                NtStatus::SUCCESS
            );

            let mut commit_base = base;
            let mut commit_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut commit_base),
                    0,
                    mut_ptr(&mut commit_size),
                    AllocationType::MEM_COMMIT.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(ptr.read_at_offset(0), Some(0));

            release_allocation(&task, base);
        });
    }

    #[test]
    fn protect_virtual_memory_preserves_page_modifier_bits() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut base = 0usize;
            let mut region_size = PAGE_SIZE;
            assert_eq!(
                task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut base),
                    0,
                    mut_ptr(&mut region_size),
                    (AllocationType::MEM_RESERVE | AllocationType::MEM_COMMIT).bits(),
                    (PageProtection::PAGE_READWRITE | PageProtection::PAGE_NOCACHE).bits(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                query_basic_information(&task, base).protect,
                (PageProtection::PAGE_READWRITE | PageProtection::PAGE_NOCACHE).bits()
            );

            let mut protect_base = base;
            let mut protect_size = PAGE_SIZE;
            let mut old_protect = 0u32;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    (PageProtection::PAGE_READONLY | PageProtection::PAGE_WRITECOMBINE).bits(),
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                old_protect,
                (PageProtection::PAGE_READWRITE | PageProtection::PAGE_NOCACHE).bits()
            );
            assert_eq!(
                query_basic_information(&task, base).protect,
                (PageProtection::PAGE_READONLY | PageProtection::PAGE_WRITECOMBINE).bits()
            );

            release_allocation(&task, base);
        });
    }

    #[test]
    fn protect_virtual_memory_rejects_invalid_page_protection() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (base, _) = allocate_committed_rw(&task, PAGE_SIZE);

            let mut protect_base = base;
            let mut protect_size = PAGE_SIZE;
            let mut old_protect = u32::MAX;
            assert_eq!(
                task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut protect_base),
                    mut_ptr(&mut protect_size),
                    0,
                    mut_ptr(&mut old_protect),
                ),
                NtStatus::INVALID_PAGE_PROTECTION
            );
            assert_eq!(old_protect, u32::MAX);

            release_allocation(&task, base);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mod host_fidelity {
        use super::*;
        use core::ffi::c_void;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtAllocateVirtualMemory(
                process_handle: *mut c_void,
                base_address: *mut *mut c_void,
                zero_bits: usize,
                region_size: *mut usize,
                allocation_type: u32,
                protect: u32,
            ) -> i32;

            fn NtProtectVirtualMemory(
                process_handle: *mut c_void,
                base_address: *mut *mut c_void,
                region_size: *mut usize,
                new_protect: u32,
                old_protect: *mut u32,
            ) -> i32;

            fn NtQueryVirtualMemory(
                process_handle: *mut c_void,
                base_address: *const c_void,
                memory_information_class: u32,
                memory_information: *mut c_void,
                memory_information_length: usize,
                return_length: *mut usize,
            ) -> i32;

            fn NtFreeVirtualMemory(
                process_handle: *mut c_void,
                base_address: *mut *mut c_void,
                region_size: *mut usize,
                free_type: u32,
            ) -> i32;

            fn NtAllocateVirtualMemoryEx(
                process_handle: *mut c_void,
                base_address: *mut *mut c_void,
                region_size: *mut usize,
                allocation_type: u32,
                page_protection: u32,
                extended_parameters: *mut c_void,
                extended_parameter_count: u32,
            ) -> i32;
        }

        fn current_process() -> *mut c_void {
            usize::MAX as *mut c_void
        }

        fn host_status(status: i32) -> NtStatus {
            NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
        }

        #[test]
        fn placeholder_split_coalesce_statuses_match_host_ntdll() {
            run_with_test_platform_pointers(|| {
                let task = crate::tests::test_task();
                let unit = ALLOCATION_GRANULARITY;
                let reserve = AllocationType::MEM_RESERVE | AllocationType::MEM_RESERVE_PLACEHOLDER;
                let replace = AllocationType::MEM_RESERVE | AllocationType::MEM_REPLACE_PLACEHOLDER;
                let preserve = FreeType::MEM_RELEASE | FreeType::MEM_PRESERVE_PLACEHOLDER;
                let coalesce = FreeType::MEM_RELEASE | FreeType::MEM_COALESCE_PLACEHOLDERS;

                let host_allocate = |base: usize, size: usize, flags: AllocationType| {
                    let mut base = base as *mut c_void;
                    let mut size = size;
                    // SAFETY: The output pointers are valid locals and the current-process pseudo
                    // handle targets this process.
                    let status = unsafe {
                        host_status(NtAllocateVirtualMemoryEx(
                            current_process(),
                            &raw mut base,
                            &raw mut size,
                            flags.bits(),
                            if flags.contains(AllocationType::MEM_RESERVE_PLACEHOLDER) {
                                PageProtection::PAGE_NOACCESS.bits()
                            } else {
                                PageProtection::PAGE_READWRITE.bits()
                            },
                            core::ptr::null_mut(),
                            0,
                        ))
                    };
                    (status, base as usize)
                };
                let guest_allocate = |base: usize, size: usize, flags: AllocationType| {
                    let mut base = base;
                    let mut size = size;
                    let status = task.sys_nt_allocate_virtual_memory_ex(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut base),
                        mut_ptr(&mut size),
                        flags.bits(),
                        if flags.contains(AllocationType::MEM_RESERVE_PLACEHOLDER) {
                            PageProtection::PAGE_NOACCESS.bits()
                        } else {
                            PageProtection::PAGE_READWRITE.bits()
                        },
                        MemoryExtendedParameters {
                            parameters: None,
                            count: 0,
                        },
                    );
                    (status, base)
                };
                let host_free = |base: usize, size: usize, flags: FreeType| {
                    let mut base = base as *mut c_void;
                    let mut size = size;
                    // SAFETY: The output pointers are valid locals; the range only ever names
                    // this test's own placeholder or unowned addresses.
                    unsafe {
                        host_status(NtFreeVirtualMemory(
                            current_process(),
                            &raw mut base,
                            &raw mut size,
                            flags.bits(),
                        ))
                    }
                };
                let guest_free = |base: usize, size: usize, flags: FreeType| {
                    let mut base = base;
                    let mut size = size;
                    task.sys_nt_free_virtual_memory(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut base),
                        mut_ptr(&mut size),
                        flags.bits(),
                    )
                };

                let (host_status_value, host_base) = host_allocate(0, unit * 4, reserve);
                assert_eq!(host_status_value, NtStatus::SUCCESS);
                let (guest_status_value, guest_base) = guest_allocate(0, unit * 4, reserve);
                assert_eq!(guest_status_value, NtStatus::SUCCESS);

                // `None` targets address zero; `Some(offset)` is relative to each placeholder.
                let frees: &[(Option<usize>, usize, FreeType)] = &[
                    (Some(0), unit, FreeType::MEM_PRESERVE_PLACEHOLDER),
                    (
                        Some(0),
                        unit,
                        FreeType::MEM_DECOMMIT | FreeType::MEM_COALESCE_PLACEHOLDERS,
                    ),
                    (
                        Some(0),
                        unit,
                        preserve | FreeType::MEM_COALESCE_PLACEHOLDERS,
                    ),
                    (Some(0), 0, preserve),
                    (Some(1), unit + 1, preserve),
                    (Some(1), unit, preserve),
                    (Some(1), unit, coalesce),
                    (None, unit, preserve),
                    (None, unit, coalesce),
                    (Some(0), unit * 4, preserve),
                    (Some(0), unit * 4, coalesce),
                    (Some(unit * 3), unit * 2, preserve),
                    (Some(unit), unit, preserve),
                    (Some(unit), unit, preserve),
                    (Some(unit), unit * 2, preserve),
                    (Some(0), unit * 2, coalesce),
                ];
                for &(offset, size, flags) in frees {
                    let host =
                        host_free(offset.map_or(0, |offset| host_base + offset), size, flags);
                    let guest =
                        guest_free(offset.map_or(0, |offset| guest_base + offset), size, flags);
                    assert_eq!(
                        guest, host,
                        "free offset={offset:?} size={size:#x} flags={flags:?}"
                    );
                }

                assert_eq!(
                    guest_allocate(0, unit, replace).0,
                    host_allocate(0, unit, replace).0
                );
                // Replacing must name a whole placeholder; the remaining piece is [2u, 4u).
                for size in [unit, unit * 2] {
                    assert_eq!(
                        guest_allocate(
                            guest_base + unit * 2,
                            size,
                            replace | AllocationType::MEM_COMMIT
                        )
                        .0,
                        host_allocate(
                            host_base + unit * 2,
                            size,
                            replace | AllocationType::MEM_COMMIT
                        )
                        .0,
                        "replace size={size:#x}"
                    );
                }
                for &(offset, size) in &[
                    (unit * 3, unit * 2),
                    (unit * 2 + PAGE_SIZE, unit * 2),
                    (unit * 2, unit * 2),
                ] {
                    assert_eq!(
                        guest_free(guest_base + offset, size, preserve),
                        host_free(host_base + offset, size, preserve),
                        "replaced preserve offset={offset:#x} size={size:#x}"
                    );
                }
                assert_eq!(
                    guest_free(guest_base, unit * 4, coalesce),
                    host_free(host_base, unit * 4, coalesce)
                );

                assert_eq!(
                    host_free(host_base, 0, FreeType::MEM_RELEASE),
                    NtStatus::SUCCESS
                );
                assert_eq!(
                    guest_free(guest_base, 0, FreeType::MEM_RELEASE),
                    NtStatus::SUCCESS
                );
            });
        }

        #[test]
        fn allocate_query_free_outputs_match_host_ntdll() {
            run_with_test_platform_pointers(|| {
                let mut host_base = core::ptr::null_mut::<c_void>();
                let mut host_region_size = PAGE_SIZE;
                // SAFETY: The output pointers are valid locals and the current-process pseudo
                // handle targets this process. The allocation is released before return.
                let host_allocate_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        0,
                        &raw mut host_region_size,
                        AllocationType::MEM_COMMIT.bits(),
                        PageProtection::PAGE_NOACCESS.bits(),
                    ))
                };
                assert_eq!(host_allocate_status, NtStatus::SUCCESS);

                let mut host_info = MemoryBasicInformation::default();
                let mut host_return_length = 0usize;
                // SAFETY: The host allocation is live, and the output buffer and return length are
                // valid locals that ntdll writes synchronously.
                let host_query_status = unsafe {
                    host_status(NtQueryVirtualMemory(
                        current_process(),
                        host_base,
                        MemoryInformationClass::Basic as u32,
                        (&raw mut host_info).cast(),
                        size_of::<MemoryBasicInformation>(),
                        &raw mut host_return_length,
                    ))
                };
                assert_eq!(host_query_status, NtStatus::SUCCESS);

                let task = crate::tests::test_task();
                let mut guest_base = 0usize;
                let mut guest_region_size = PAGE_SIZE;
                let guest_allocate_status = task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_base),
                    0,
                    mut_ptr(&mut guest_region_size),
                    AllocationType::MEM_COMMIT.bits(),
                    PageProtection::PAGE_NOACCESS.bits(),
                );
                assert_eq!(guest_allocate_status, host_allocate_status);
                assert_eq!(guest_region_size, host_region_size);

                let guest_info = query_basic_information(&task, guest_base);
                assert_eq!(guest_info.base_address, guest_base);
                assert_eq!(host_info.base_address, host_base as usize);
                assert_eq!(guest_info.allocation_base, guest_base);
                assert_eq!(host_info.allocation_base, host_base as usize);
                assert_eq!(guest_info.allocation_protect, host_info.allocation_protect);
                assert_eq!(guest_info.region_size, host_info.region_size);
                assert_eq!(guest_info.state, host_info.state);
                assert_eq!(guest_info.protect, host_info.protect);
                assert_eq!(guest_info.type_, host_info.type_);

                let mut guest_release_base = guest_base;
                let mut guest_release_size = 0usize;
                let guest_free_status = task.sys_nt_free_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_release_base),
                    mut_ptr(&mut guest_release_size),
                    FreeType::MEM_RELEASE.bits(),
                );
                let mut host_release_size = 0usize;
                // SAFETY: Releases the host allocation created by this test.
                let host_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        &raw mut host_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(guest_free_status, host_free_status);
                assert_eq!(guest_release_size, host_release_size);
            });
        }

        #[test]
        fn reserve_alignment_outputs_match_host_ntdll() {
            run_with_test_platform_pointers(|| {
                let task = crate::tests::test_task();
                let mut probe_base = core::ptr::null_mut::<c_void>();
                let mut probe_region_size = ALLOCATION_GRANULARITY * 2;
                // SAFETY: The output pointers are valid locals and the current-process pseudo
                // handle targets this process. The allocation is released before reuse below.
                let probe_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut probe_base,
                        0,
                        &raw mut probe_region_size,
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(probe_status, NtStatus::SUCCESS);

                let mut probe_release_base = probe_base;
                let mut probe_release_size = 0usize;
                // SAFETY: Releases the host allocation created above so the fixed-address probe
                // can reuse the same address range.
                let probe_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut probe_release_base,
                        &raw mut probe_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(probe_free_status, NtStatus::SUCCESS);

                let requested_base = probe_base.wrapping_byte_add(PAGE_SIZE + 123);
                let mut host_base = requested_base;
                let mut host_region_size = 1usize;
                // SAFETY: The fixed address range was just released and the output pointers are
                // valid locals. The allocation is released before the guest probe runs.
                let host_allocate_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        0,
                        &raw mut host_region_size,
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(host_allocate_status, NtStatus::SUCCESS);

                let mut host_release_base = host_base;
                let mut host_release_size = 0usize;
                // SAFETY: Releases the fixed host allocation created by this test.
                let host_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut host_release_base,
                        &raw mut host_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(host_free_status, NtStatus::SUCCESS);

                let mut guest_base = requested_base as usize;
                let mut guest_region_size = 1usize;
                let guest_allocate_status = task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_base),
                    0,
                    mut_ptr(&mut guest_region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                );
                assert_eq!(guest_allocate_status, host_allocate_status);
                assert_eq!(guest_base, host_base as usize);
                assert_eq!(guest_region_size, host_region_size);

                release_allocation(&task, guest_base);
            });
        }

        #[test]
        fn allocate_virtual_memory_zero_bits_bitmask_matches_host_ntdll() {
            run_with_test_platform_pointers(|| {
                // When ZeroBits > 32, Windows treats it as the maximum virtual address for the
                // allocation (exclusive upper bound = zero_bits + 1). A value of 0x7FFF_FFFF
                // restricts the allocation to below 2 GiB.
                let zero_bits_max_addr: usize = 0x7FFF_FFFF;
                let limit: usize = zero_bits_max_addr + 1;

                let mut host_base = core::ptr::null_mut::<c_void>();
                let mut host_region_size = PAGE_SIZE;
                // SAFETY: Output pointers are valid locals and the current-process pseudo handle
                // targets this process. The allocation is released before return.
                let host_allocate_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        zero_bits_max_addr,
                        &raw mut host_region_size,
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(host_allocate_status, NtStatus::SUCCESS);
                assert!(
                    host_base as usize + host_region_size <= limit,
                    "host allocation exceeds ZeroBits max address"
                );

                let task = crate::tests::test_task();
                let mut guest_base = 0usize;
                let mut guest_region_size = PAGE_SIZE;
                let guest_allocate_status = task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_base),
                    zero_bits_max_addr,
                    mut_ptr(&mut guest_region_size),
                    AllocationType::MEM_RESERVE.bits(),
                    PageProtection::PAGE_READWRITE.bits(),
                );
                assert_eq!(guest_allocate_status, host_allocate_status);
                assert!(
                    guest_base + guest_region_size <= limit,
                    "guest allocation exceeds ZeroBits max address"
                );

                release_allocation(&task, guest_base);

                let mut host_release_size = 0usize;
                // SAFETY: Releases the host allocation created by this test.
                let host_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        &raw mut host_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(host_free_status, NtStatus::SUCCESS);
            });
        }

        #[test]
        fn mem_reset_reserved_pages_matches_host_ntdll() {
            run_with_test_platform_pointers(|| {
                let mut host_base = core::ptr::null_mut::<c_void>();
                let mut host_region_size = PAGE_SIZE;
                // SAFETY: The output pointers are valid locals and the current-process pseudo
                // handle targets this process. The allocation is released before return.
                let host_reserve_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        0,
                        &raw mut host_region_size,
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(host_reserve_status, NtStatus::SUCCESS);

                let mut host_reset_base = host_base.wrapping_byte_add(1);
                let mut host_reset_size = 1usize;
                // SAFETY: The host allocation is reserved but uncommitted; the output pointers are
                // valid locals and ntdll does not retain them.
                let host_reset_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_reset_base,
                        0,
                        &raw mut host_reset_size,
                        AllocationType::MEM_RESET.bits(),
                        PageProtection::PAGE_NOACCESS.bits(),
                    ))
                };
                assert_eq!(host_reset_status, NtStatus::CONFLICTING_ADDRESSES);

                let task = crate::tests::test_task();
                let mut guest_base = 0usize;
                let mut guest_region_size = PAGE_SIZE;
                assert_eq!(
                    task.sys_nt_allocate_virtual_memory(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut guest_base),
                        0,
                        mut_ptr(&mut guest_region_size),
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ),
                    host_reserve_status
                );

                let mut guest_reset_base = guest_base + 1;
                let mut guest_reset_size = 1usize;
                let guest_reset_status = task.sys_nt_allocate_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_reset_base),
                    0,
                    mut_ptr(&mut guest_reset_size),
                    AllocationType::MEM_RESET.bits(),
                    PageProtection::PAGE_NOACCESS.bits(),
                );
                assert_eq!(guest_reset_status, host_reset_status);
                assert_eq!(
                    guest_reset_base - guest_base,
                    host_reset_base as usize - host_base as usize
                );
                assert_eq!(guest_reset_size, host_reset_size);

                release_allocation(&task, guest_base);

                let mut host_release_size = 0usize;
                // SAFETY: Releases the host allocation created by this test.
                let host_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        &raw mut host_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(host_free_status, NtStatus::SUCCESS);
            });
        }

        #[test]
        fn protect_virtual_memory_outputs_match_host_ntdll() {
            run_with_test_platform_pointers(|| {
                let mut host_base = core::ptr::null_mut::<c_void>();
                let mut host_region_size = PAGE_SIZE * 2 - 1;
                // SAFETY: The output pointers are valid local variables and the pseudo process
                // handle targets the current process. The allocation is released before return.
                let host_allocate_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        0,
                        &raw mut host_region_size,
                        (AllocationType::MEM_RESERVE | AllocationType::MEM_COMMIT).bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(host_allocate_status, NtStatus::SUCCESS);

                let mut host_protect_base = host_base.wrapping_byte_add(1);
                let mut host_protect_size = 1usize;
                let mut host_old_protect = 0u32;
                // SAFETY: The host allocation above covers the requested byte; all output pointers
                // are valid locals and ntdll does not retain them.
                let host_protect_status = unsafe {
                    host_status(NtProtectVirtualMemory(
                        current_process(),
                        &raw mut host_protect_base,
                        &raw mut host_protect_size,
                        PageProtection::PAGE_READONLY.bits(),
                        &raw mut host_old_protect,
                    ))
                };

                let task = crate::tests::test_task();
                let (guest_base, _) = allocate_committed_rw(&task, PAGE_SIZE * 2 - 1);
                let mut guest_protect_base = guest_base + 1;
                let mut guest_protect_size = 1usize;
                let mut guest_old_protect = 0u32;
                let guest_protect_status = task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_protect_base),
                    mut_ptr(&mut guest_protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut guest_old_protect),
                );

                assert_eq!(guest_protect_status, host_protect_status);
                assert_eq!(guest_old_protect, host_old_protect);
                assert_eq!(guest_protect_base, guest_base);
                assert_eq!(guest_protect_size, host_protect_size);

                release_allocation(&task, guest_base);

                let mut host_release_size = 0usize;
                // SAFETY: Releases the host allocation created by this test.
                let host_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        &raw mut host_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(host_free_status, NtStatus::SUCCESS);
            });
        }

        #[test]
        fn protect_virtual_memory_mixed_committed_protections_match_host_ntdll() {
            run_with_test_platform_pointers(|| {
                let mut host_base = core::ptr::null_mut::<c_void>();
                let mut host_region_size = PAGE_SIZE * 2;
                // SAFETY: The output pointers are valid local variables and the pseudo process
                // handle targets the current process. The allocation is released before return.
                let host_allocate_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        0,
                        &raw mut host_region_size,
                        (AllocationType::MEM_RESERVE | AllocationType::MEM_COMMIT).bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(host_allocate_status, NtStatus::SUCCESS);

                let mut host_second_page_base = host_base.wrapping_byte_add(PAGE_SIZE);
                let mut host_second_page_size = PAGE_SIZE;
                let mut host_second_old_protect = 0u32;
                // SAFETY: The host allocation above covers the requested second page; output
                // pointers are valid locals and ntdll does not retain them.
                let host_second_protect_status = unsafe {
                    host_status(NtProtectVirtualMemory(
                        current_process(),
                        &raw mut host_second_page_base,
                        &raw mut host_second_page_size,
                        PageProtection::PAGE_READONLY.bits(),
                        &raw mut host_second_old_protect,
                    ))
                };
                assert_eq!(host_second_protect_status, NtStatus::SUCCESS);

                let task = crate::tests::test_task();
                let (guest_base, _) = allocate_committed_rw(&task, PAGE_SIZE * 2);
                let mut guest_second_page_base = guest_base + PAGE_SIZE;
                let mut guest_second_page_size = PAGE_SIZE;
                let mut guest_second_old_protect = 0u32;
                let guest_second_protect_status = task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_second_page_base),
                    mut_ptr(&mut guest_second_page_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut guest_second_old_protect),
                );
                assert_eq!(guest_second_protect_status, host_second_protect_status);
                assert_eq!(guest_second_old_protect, host_second_old_protect);
                assert_eq!(
                    guest_second_page_base - guest_base,
                    host_second_page_base as usize - host_base as usize
                );
                assert_eq!(guest_second_page_size, host_second_page_size);

                let mut host_mixed_base = host_base;
                let mut host_mixed_size = PAGE_SIZE * 2;
                let mut host_mixed_old_protect = 0u32;
                // SAFETY: The host range is fully committed with mixed protections; output
                // pointers are valid locals and ntdll does not retain them.
                let host_mixed_protect_status = unsafe {
                    host_status(NtProtectVirtualMemory(
                        current_process(),
                        &raw mut host_mixed_base,
                        &raw mut host_mixed_size,
                        PageProtection::PAGE_EXECUTE_READ.bits(),
                        &raw mut host_mixed_old_protect,
                    ))
                };

                let mut guest_mixed_base = guest_base;
                let mut guest_mixed_size = PAGE_SIZE * 2;
                let mut guest_mixed_old_protect = 0u32;
                let guest_mixed_protect_status = task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_mixed_base),
                    mut_ptr(&mut guest_mixed_size),
                    PageProtection::PAGE_EXECUTE_READ.bits(),
                    mut_ptr(&mut guest_mixed_old_protect),
                );
                assert_eq!(guest_mixed_protect_status, host_mixed_protect_status);
                assert_eq!(guest_mixed_old_protect, host_mixed_old_protect);
                assert_eq!(guest_mixed_base, guest_base);
                assert_eq!(host_mixed_base, host_base);
                assert_eq!(guest_mixed_size, host_mixed_size);

                release_allocation(&task, guest_base);

                let mut host_release_size = 0usize;
                // SAFETY: Releases the host allocation created by this test.
                let host_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        &raw mut host_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(host_free_status, NtStatus::SUCCESS);
            });
        }

        #[test]
        fn protect_virtual_memory_uncommitted_ranges_match_host_ntdll() {
            run_with_test_platform_pointers(|| {
                let mut host_base = core::ptr::null_mut::<c_void>();
                let mut host_region_size = PAGE_SIZE * 2;
                // SAFETY: The output pointers are valid locals and the current-process pseudo
                // handle targets this process. The allocation is released before return.
                let host_reserve_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        0,
                        &raw mut host_region_size,
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(host_reserve_status, NtStatus::SUCCESS);

                let task = crate::tests::test_task();
                let mut guest_base = 0usize;
                let mut guest_region_size = PAGE_SIZE * 2;
                assert_eq!(
                    task.sys_nt_allocate_virtual_memory(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut guest_base),
                        0,
                        mut_ptr(&mut guest_region_size),
                        AllocationType::MEM_RESERVE.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ),
                    host_reserve_status
                );

                let mut host_protect_base = host_base;
                let mut host_protect_size = PAGE_SIZE;
                let mut host_old_protect = u32::MAX;
                // SAFETY: The host range is reserved but uncommitted; output pointers are valid
                // locals and ntdll does not retain them.
                let host_reserved_protect_status = unsafe {
                    host_status(NtProtectVirtualMemory(
                        current_process(),
                        &raw mut host_protect_base,
                        &raw mut host_protect_size,
                        PageProtection::PAGE_READONLY.bits(),
                        &raw mut host_old_protect,
                    ))
                };

                let mut guest_protect_base = guest_base;
                let mut guest_protect_size = PAGE_SIZE;
                let mut guest_old_protect = u32::MAX;
                let guest_reserved_protect_status = task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_protect_base),
                    mut_ptr(&mut guest_protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut guest_old_protect),
                );
                assert_eq!(guest_reserved_protect_status, host_reserved_protect_status);
                assert_eq!(
                    guest_protect_base - guest_base,
                    host_protect_base as usize - host_base as usize
                );
                assert_eq!(guest_protect_size, host_protect_size);
                assert_eq!(guest_old_protect, host_old_protect);

                let mut host_commit_base = host_base;
                let mut host_commit_size = PAGE_SIZE;
                // SAFETY: Commits the first page inside the live host reservation; output pointers
                // are valid locals and the reservation is released before return.
                let host_commit_status = unsafe {
                    host_status(NtAllocateVirtualMemory(
                        current_process(),
                        &raw mut host_commit_base,
                        0,
                        &raw mut host_commit_size,
                        AllocationType::MEM_COMMIT.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ))
                };
                assert_eq!(host_commit_status, NtStatus::SUCCESS);

                let mut guest_commit_base = guest_base;
                let mut guest_commit_size = PAGE_SIZE;
                assert_eq!(
                    task.sys_nt_allocate_virtual_memory(
                        ProcessHandle::CURRENT,
                        mut_ptr(&mut guest_commit_base),
                        0,
                        mut_ptr(&mut guest_commit_size),
                        AllocationType::MEM_COMMIT.bits(),
                        PageProtection::PAGE_READWRITE.bits(),
                    ),
                    host_commit_status
                );

                let mut host_mixed_protect_base = host_base;
                let mut host_mixed_protect_size = PAGE_SIZE * 2;
                let mut host_mixed_old_protect = u32::MAX;
                // SAFETY: The host range spans one committed page and one reserved page; output
                // pointers are valid locals and ntdll does not retain them.
                let host_mixed_protect_status = unsafe {
                    host_status(NtProtectVirtualMemory(
                        current_process(),
                        &raw mut host_mixed_protect_base,
                        &raw mut host_mixed_protect_size,
                        PageProtection::PAGE_READONLY.bits(),
                        &raw mut host_mixed_old_protect,
                    ))
                };

                let mut guest_mixed_protect_base = guest_base;
                let mut guest_mixed_protect_size = PAGE_SIZE * 2;
                let mut guest_mixed_old_protect = u32::MAX;
                let guest_mixed_protect_status = task.sys_nt_protect_virtual_memory(
                    ProcessHandle::CURRENT,
                    mut_ptr(&mut guest_mixed_protect_base),
                    mut_ptr(&mut guest_mixed_protect_size),
                    PageProtection::PAGE_READONLY.bits(),
                    mut_ptr(&mut guest_mixed_old_protect),
                );
                assert_eq!(guest_mixed_protect_status, host_mixed_protect_status);
                assert_eq!(
                    guest_mixed_protect_base - guest_base,
                    host_mixed_protect_base as usize - host_base as usize
                );
                assert_eq!(guest_mixed_protect_size, host_mixed_protect_size);
                assert_eq!(guest_mixed_old_protect, host_mixed_old_protect);

                release_allocation(&task, guest_base);

                let mut host_release_size = 0usize;
                // SAFETY: Releases the host allocation created by this test.
                let host_free_status = unsafe {
                    host_status(NtFreeVirtualMemory(
                        current_process(),
                        &raw mut host_base,
                        &raw mut host_release_size,
                        FreeType::MEM_RELEASE.bits(),
                    ))
                };
                assert_eq!(host_free_status, NtStatus::SUCCESS);
            });
        }
    }
}

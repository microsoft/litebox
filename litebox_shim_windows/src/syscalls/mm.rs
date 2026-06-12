// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::mm::linux::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize};
use litebox::platform::page_mgmt::{AllocationError, MemoryRegionPermissions};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use rangemap::RangeMap;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::ProcessHandle;
use crate::{
    ConstPtr, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform, Task, WindowsPageManager,
    WindowsVirtualAllocation, WindowsVirtualAllocations,
};

const ALLOCATION_GRANULARITY: usize = 0x1_0000;
const ALLOCATION_SEARCH_ATTEMPTS: usize = 8;
const MEMORY_WORKING_SET_LIST_MIN_SIZE: usize = 16;
const MEM_EXTENDED_PARAMETER_TYPE_MASK: u64 = 0xff;

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
    }
}

impl PageProtection {
    const BASE_MASK: u32 = 0xff;

    fn base(self) -> u32 {
        self.bits() & Self::BASE_MASK
    }

    fn has_valid_modifier_combination(self) -> bool {
        let noaccess = self.base() == Self::PAGE_NOACCESS.bits();
        let guard = self.contains(Self::PAGE_GUARD);
        let nocache = self.contains(Self::PAGE_NOCACHE);
        let writecombine = self.contains(Self::PAGE_WRITECOMBINE);

        !(noaccess && (guard || nocache || writecombine)
            || guard && (nocache || writecombine)
            || nocache && writecombine)
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct AllocationType: u32 {
        const MEM_COMMIT = 0x1000;
        const MEM_RESERVE = 0x2000;
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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
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

        // TODO: Apply supported extended parameters (especially MEM_ADDRESS_REQUIREMENTS) to the
        // allocation search once PageManager can honor caller-specified placement constraints.
        self.sys_nt_allocate_virtual_memory(
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
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let Some(base) = base_address.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(size) = region_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if base_address.write_at_offset(0, base).is_none()
            || region_size.write_at_offset(0, size).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Some(allocation_type) = AllocationType::from_bits(allocation_type) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let supported_allocation_types = AllocationType::MEM_COMMIT
            | AllocationType::MEM_RESERVE
            | AllocationType::MEM_RESET
            | AllocationType::MEM_TOP_DOWN;
        if size == 0
            || !supported_allocation_types.contains(allocation_type)
            || (zero_bits > 21 && zero_bits < 32)
            || (zero_bits != 0 && base != 0)
        {
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

        let new_allocation = base == 0 || allocation_type.contains(AllocationType::MEM_RESERVE);
        let Some((aligned_base, aligned_len)) = (if new_allocation {
            reserve_allocation_region(base, size)
        } else {
            page_aligned_region(base, size)
        }) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some((protect, permissions)) = parse_page_protection(protect) else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };

        if !new_allocation {
            return self.commit_existing_virtual_memory(
                aligned_base,
                aligned_len,
                protect,
                permissions,
                base_address,
                region_size,
            );
        }

        let Some(length) = NonZeroPageSize::new(aligned_len) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let initial_permissions = if allocation_type.contains(AllocationType::MEM_COMMIT) {
            permissions
        } else {
            MemoryRegionPermissions::empty()
        };
        let top_down = allocation_type.contains(AllocationType::MEM_TOP_DOWN);
        let allocation = if base == 0 {
            create_allocation_granularity_aligned_pages::<Platform>(
                &self.global.page_manager,
                length,
                initial_permissions,
                zero_bits,
                top_down,
            )
        } else {
            create_pages::<Platform>(
                &self.global.page_manager,
                NonZeroAddress::new(aligned_base),
                length,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                initial_permissions,
                |_| Ok(0),
            )
            .map_err(mapping_error_to_nt_status)
        };
        let ptr = match allocation {
            Ok(ptr) => ptr,
            Err(status) => return status,
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
        self.process.virtual_allocations.write().insert(
            ptr.as_usize(),
            WindowsVirtualAllocation {
                base: ptr.as_usize(),
                size: aligned_len,
                allocation_protect: protect,
                type_: MemoryType::MEM_PRIVATE,
                pages: if allocation_type.contains(AllocationType::MEM_COMMIT) {
                    committed_pages(ptr.as_usize(), aligned_len, protect)
                } else {
                    RangeMap::new()
                },
            },
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
        let Some(allocation) =
            find_virtual_allocation(&self.process.virtual_allocations, aligned_base, aligned_len)
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        if allocation.type_ != MemoryType::MEM_PRIVATE {
            return NtStatus::INVALID_PARAMETER;
        }
        if !matches!(
            scan_allocation_pages(&allocation, aligned_base, aligned_len),
            Some(PageRangeScan::FullyCommitted(_))
        ) {
            return NtStatus::CONFLICTING_ADDRESSES;
        }

        if base_address.write_at_offset(0, aligned_base).is_none()
            || region_size.write_at_offset(0, aligned_len).is_none()
        {
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
        if find_private_virtual_allocation(
            &self.process.virtual_allocations,
            aligned_base,
            aligned_len,
        )
        .is_none()
        {
            return NtStatus::INVALID_PARAMETER;
        }
        if update_permissions(
            &self.global.page_manager,
            aligned_base,
            aligned_len,
            permissions,
        )
        .is_err()
        {
            return NtStatus::INVALID_PARAMETER;
        }
        if base_address.write_at_offset(0, aligned_base).is_none()
            || region_size.write_at_offset(0, aligned_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        set_committed_pages_protect(
            &self.process.virtual_allocations,
            aligned_base,
            aligned_len,
            protect,
        );
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
            return NtStatus::INVALID_HANDLE;
        }

        let Some(base) = base_address.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(size) = region_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if base_address.write_at_offset(0, base).is_none()
            || region_size.write_at_offset(0, size).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Some(free_type) = FreeType::from_bits(free_type) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if base == 0 || !matches!(free_type, FreeType::MEM_DECOMMIT | FreeType::MEM_RELEASE) {
            return NtStatus::INVALID_PARAMETER;
        }

        let Some((aligned_base, aligned_len)) =
            free_region(&self.process.virtual_allocations, base, size, free_type)
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        let ptr = MutPtr::<Platform, u8>::from_usize(aligned_base);
        if free_type == FreeType::MEM_DECOMMIT {
            // SAFETY: The range is page-aligned and belongs to a private allocation tracked for
            // this process. Decommit discards page contents while leaving the address range
            // reserved for later recommit.
            if unsafe { self.global.page_manager.reset_pages(ptr, aligned_len, true) }.is_err() {
                return NtStatus::UNABLE_TO_FREE_VM;
            }
            if update_permissions(
                &self.global.page_manager,
                aligned_base,
                aligned_len,
                MemoryRegionPermissions::empty(),
            )
            .is_err()
            {
                return NtStatus::UNABLE_TO_FREE_VM;
            }
            mark_pages_decommitted(&self.process.virtual_allocations, aligned_base, aligned_len);
        } else {
            // SAFETY: The range is page-aligned and belongs to an allocation tracked for this
            // process. The guest requested release, so the pages must not be used after success.
            if unsafe { self.global.page_manager.remove_pages(ptr, aligned_len) }.is_err() {
                return NtStatus::UNABLE_TO_FREE_VM;
            }
            self.process
                .virtual_allocations
                .write()
                .remove(&aligned_base);
        }
        if base_address.write_at_offset(0, aligned_base).is_none()
            || region_size.write_at_offset(0, aligned_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
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
        if base_address.write_at_offset(0, base).is_none()
            || region_size.write_at_offset(0, size).is_none()
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
        let old_protect_value = match scan_protect_range(
            &self.process.virtual_allocations,
            aligned_base,
            aligned_len,
        ) {
            Some(PageRangeScan::FullyCommitted(first_protect)) => first_protect,
            Some(PageRangeScan::ContainsUncommitted) => {
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

        if update_permissions(
            &self.global.page_manager,
            aligned_base,
            aligned_len,
            new_permissions,
        )
        .is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        set_committed_pages_protect(
            &self.process.virtual_allocations,
            aligned_base,
            aligned_len,
            new_protect,
        );

        // ReactOS NtProtectVirtualMemory writes OldProtection, BaseAddress, then RegionSize after
        // MiProtectVirtualMemory succeeds; failed writeback does not roll back the protection.
        if old_protect
            .write_at_offset(0, old_protect_value.bits())
            .is_none()
            || base_address.write_at_offset(0, aligned_base).is_none()
            || region_size.write_at_offset(0, aligned_len).is_none()
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
            &self.global.page_manager,
            &self.process.virtual_allocations,
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

        let Some(allocation) =
            find_image_allocation_containing(&self.process.virtual_allocations, base_address)
        else {
            return NtStatus::INVALID_PARAMETER;
        };

        let info = MemoryImageInformation {
            image_base: allocation.base,
            size_of_image: allocation.size,
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
            image_base:% = format_args!("{:#x}", allocation.base),
            image_size = allocation.size;
            "Handled NtQueryVirtualMemory MemoryImageInformation syscall"
        );

        NtStatus::SUCCESS
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

        let Some(allocation) =
            find_image_allocation_containing(&self.process.virtual_allocations, base_address)
        else {
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
            image_base:% = format_args!("{:#x}", allocation.base),
            image_size = allocation.size;
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

fn free_region<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
    size: usize,
    free_type: FreeType,
) -> Option<(usize, usize)> {
    if size == 0 {
        let allocation = virtual_allocations
            .read()
            .get(&base)
            .filter(|allocation| allocation.type_ == MemoryType::MEM_PRIVATE)
            .cloned()?;
        return Some((allocation.base, allocation.size));
    }

    if free_type == FreeType::MEM_RELEASE {
        return None;
    }

    let (aligned_base, aligned_len) = page_aligned_region(base, size)?;
    find_private_virtual_allocation(virtual_allocations, aligned_base, aligned_len)?;
    Some((aligned_base, aligned_len))
}

fn committed_pages(
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

fn find_virtual_allocation<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
    size: usize,
) -> Option<WindowsVirtualAllocation> {
    let end = base.checked_add(size)?;
    virtual_allocations
        .read()
        .range(..=base)
        .next_back()
        .map(|(_, allocation)| allocation.clone())
        .filter(|allocation| {
            allocation
                .base
                .checked_add(allocation.size)
                .is_some_and(|allocation_end| end <= allocation_end)
        })
}

fn find_private_virtual_allocation<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
    size: usize,
) -> Option<WindowsVirtualAllocation> {
    find_virtual_allocation(virtual_allocations, base, size)
        .filter(|allocation| allocation.type_ == MemoryType::MEM_PRIVATE)
}

fn find_image_allocation_containing<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
) -> Option<WindowsVirtualAllocation> {
    find_virtual_allocation(virtual_allocations, base, 1)
        .filter(|allocation| allocation.type_ == MemoryType::MEM_IMAGE)
}

fn find_virtual_allocation_containing<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
) -> Option<WindowsVirtualAllocation> {
    find_virtual_allocation(virtual_allocations, base, 1)
}

enum PageRangeScan {
    FullyCommitted(PageProtection),
    ContainsUncommitted,
}

fn scan_allocation_pages(
    allocation: &WindowsVirtualAllocation,
    base: usize,
    size: usize,
) -> Option<PageRangeScan> {
    let end = base.checked_add(size)?;
    let allocation_end = allocation.base.checked_add(allocation.size)?;
    let scan_end = end.min(allocation_end);
    let mut first_protect = None;
    let mut cursor = base;
    for (range, protect) in allocation.pages.overlapping(base..scan_end) {
        let range_start = range.start.max(base);
        if cursor < range_start {
            return Some(PageRangeScan::ContainsUncommitted);
        }
        first_protect.get_or_insert(*protect);
        cursor = cursor.max(range.end.min(scan_end));
        if cursor == end {
            break;
        }
    }

    if cursor == end {
        Some(PageRangeScan::FullyCommitted(first_protect?))
    } else {
        Some(PageRangeScan::ContainsUncommitted)
    }
}

fn scan_protect_range<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
    size: usize,
) -> Option<PageRangeScan> {
    let allocation = find_virtual_allocation_containing(virtual_allocations, base)?;
    scan_allocation_pages(&allocation, base, size)
}

fn set_committed_pages_protect<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
    size: usize,
    protect: PageProtection,
) {
    let Some(end) = base.checked_add(size) else {
        return;
    };
    let mut allocations = virtual_allocations.write();
    let Some((_, allocation)) = allocations.range_mut(..=base).next_back() else {
        return;
    };
    allocation.pages.insert(base..end, protect);
}

fn mark_pages_decommitted<Platform: ShimPlatform>(
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base: usize,
    size: usize,
) {
    let Some(end) = base.checked_add(size) else {
        return;
    };
    let mut allocations = virtual_allocations.write();
    let Some((_, allocation)) = allocations.range_mut(..=base).next_back() else {
        return;
    };
    allocation.pages.remove(base..end);
}

fn parse_page_protection(protect: u32) -> Option<(PageProtection, MemoryRegionPermissions)> {
    let protect = PageProtection::from_bits(protect)?;
    let permissions = page_protect_to_permissions(protect)?;
    Some((protect, permissions))
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

fn create_pages<Platform: ShimPlatform>(
    page_manager: &WindowsPageManager<Platform>,
    suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
    length: NonZeroPageSize<PAGE_SIZE>,
    flags: CreatePagesFlags,
    permissions: MemoryRegionPermissions,
    op: impl FnOnce(MutPtr<Platform, u8>) -> Result<usize, MappingError>,
) -> Result<MutPtr<Platform, u8>, MappingError> {
    // SAFETY: This creates guest mappings through the LiteBox page manager. The caller controls
    // fixed-address behavior, and `op` only initializes the new mapping before it is exposed.
    unsafe {
        match permissions {
            permissions if permissions.is_empty() => {
                page_manager.create_inaccessible_pages(suggested_address, length, flags, op)
            }
            MemoryRegionPermissions::READ => {
                page_manager.create_readable_pages(suggested_address, length, flags, op)
            }
            permissions
                if permissions
                    == MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE =>
            {
                page_manager.create_writable_pages(suggested_address, length, flags, op)
            }
            permissions
                if permissions == MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC =>
            {
                page_manager.create_executable_pages(suggested_address, length, flags, op)
            }
            permissions
                if permissions
                    == MemoryRegionPermissions::READ
                        | MemoryRegionPermissions::WRITE
                        | MemoryRegionPermissions::EXEC =>
            {
                let ptr =
                    page_manager.create_writable_pages(suggested_address, length, flags, op)?;
                page_manager
                    .make_pages_rwx(ptr, length.as_usize())
                    .map_err(|_| MappingError::OutOfMemory)?;
                Ok(ptr)
            }
            _ => unreachable!("Windows page protection parser produced unsupported permissions"),
        }
    }
}

enum HoleSearchResult<Platform: ShimPlatform> {
    Allocated(MutPtr<Platform, u8>),
    RetryWithFreshMappings,
    Exhausted,
}

fn create_aligned_pages_in_hole<Platform: ShimPlatform>(
    page_manager: &WindowsPageManager<Platform>,
    hole_start: usize,
    hole_end: usize,
    length: NonZeroPageSize<PAGE_SIZE>,
    permissions: MemoryRegionPermissions,
    top_down: bool,
) -> Result<HoleSearchResult<Platform>, MappingError> {
    let Some(mut candidate) =
        allocation_granularity_aligned_candidate(hole_start, hole_end, length.as_usize(), top_down)
    else {
        return Ok(HoleSearchResult::Exhausted);
    };

    loop {
        match create_pages(
            page_manager,
            NonZeroAddress::new(candidate),
            length,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            permissions,
            |_| Ok(0),
        ) {
            Ok(ptr) => return Ok(HoleSearchResult::Allocated(ptr)),
            Err(MappingError::MapError(AllocationError::AddressInUse)) => {
                return Ok(HoleSearchResult::RetryWithFreshMappings);
            }
            Err(MappingError::MapError(AllocationError::AddressInUseByPlatform)) => {}
            Err(error) => return Err(error),
        }

        let Some(next_candidate) = next_allocation_granularity_candidate(
            candidate,
            length.as_usize(),
            hole_start,
            hole_end,
            top_down,
        ) else {
            return Ok(HoleSearchResult::Exhausted);
        };
        candidate = next_candidate;
    }
}

fn next_allocation_granularity_candidate(
    candidate: usize,
    length: usize,
    hole_start: usize,
    hole_end: usize,
    top_down: bool,
) -> Option<usize> {
    if top_down {
        candidate
            .checked_sub(ALLOCATION_GRANULARITY)
            .filter(|next| *next >= hole_start)
    } else {
        let next_candidate = candidate.checked_add(ALLOCATION_GRANULARITY)?;
        let next_end = next_candidate.checked_add(length)?;
        (next_end <= hole_end).then_some(next_candidate)
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

fn create_allocation_granularity_aligned_pages<Platform: ShimPlatform>(
    page_manager: &WindowsPageManager<Platform>,
    length: NonZeroPageSize<PAGE_SIZE>,
    permissions: MemoryRegionPermissions,
    zero_bits: usize,
    top_down: bool,
) -> Result<MutPtr<Platform, u8>, NtStatus> {
    let mut max_start = Platform::TASK_ADDR_MAX
        .checked_sub(length.as_usize())
        .ok_or(NtStatus::NO_MEMORY)?;
    if let Some(limit) = zero_bits_address_limit(zero_bits) {
        max_start = max_start.min(
            limit
                .checked_sub(length.as_usize())
                .ok_or(NtStatus::NO_MEMORY)?,
        );
    }
    let min_start = Platform::TASK_ADDR_MIN.next_multiple_of(ALLOCATION_GRANULARITY);
    let search_end = max_start
        .checked_add(length.as_usize())
        .ok_or(NtStatus::NO_MEMORY)?;

    // TODO: consider adding support for different allocation strategies and granularity to page manager
    'search: for _ in 0..ALLOCATION_SEARCH_ATTEMPTS {
        let mut mappings = page_manager.mappings();
        mappings.sort_by_key(|(range, _)| range.start);

        if top_down {
            let mut hole_end = search_end;
            for (range, _) in mappings.iter().rev() {
                if range.end <= min_start {
                    break;
                }
                if range.start >= search_end {
                    continue;
                }
                if range.end < hole_end {
                    match create_aligned_pages_in_hole(
                        page_manager,
                        range.end.max(min_start),
                        hole_end,
                        length,
                        permissions,
                        true,
                    )
                    .map_err(mapping_error_to_nt_status)?
                    {
                        HoleSearchResult::Allocated(ptr) => return Ok(ptr),
                        HoleSearchResult::RetryWithFreshMappings => continue 'search,
                        HoleSearchResult::Exhausted => {}
                    }
                }
                if range.start < hole_end {
                    hole_end = range.start;
                }
                if hole_end <= min_start {
                    break;
                }
            }

            match create_aligned_pages_in_hole(
                page_manager,
                min_start,
                hole_end,
                length,
                permissions,
                true,
            )
            .map_err(mapping_error_to_nt_status)?
            {
                HoleSearchResult::Allocated(ptr) => return Ok(ptr),
                HoleSearchResult::RetryWithFreshMappings => continue 'search,
                HoleSearchResult::Exhausted => {}
            }
        } else {
            let mut hole_start = min_start;
            for (range, _) in &mappings {
                if range.start >= search_end {
                    break;
                }
                if range.end <= hole_start {
                    continue;
                }
                if range.start > hole_start {
                    match create_aligned_pages_in_hole(
                        page_manager,
                        hole_start,
                        range.start.min(search_end),
                        length,
                        permissions,
                        false,
                    )
                    .map_err(mapping_error_to_nt_status)?
                    {
                        HoleSearchResult::Allocated(ptr) => return Ok(ptr),
                        HoleSearchResult::RetryWithFreshMappings => continue 'search,
                        HoleSearchResult::Exhausted => {}
                    }
                }
                if range.end > hole_start {
                    hole_start = range.end;
                }
                if hole_start >= search_end {
                    break;
                }
            }

            match create_aligned_pages_in_hole(
                page_manager,
                hole_start,
                search_end,
                length,
                permissions,
                false,
            )
            .map_err(mapping_error_to_nt_status)?
            {
                HoleSearchResult::Allocated(ptr) => return Ok(ptr),
                HoleSearchResult::RetryWithFreshMappings => continue 'search,
                HoleSearchResult::Exhausted => {}
            }
        }

        return Err(NtStatus::NO_MEMORY);
    }

    Err(NtStatus::NO_MEMORY)
}

fn allocation_granularity_aligned_candidate(
    hole_start: usize,
    hole_end: usize,
    length: usize,
    top_down: bool,
) -> Option<usize> {
    if top_down {
        let max_candidate = hole_end.checked_sub(length)? & !(ALLOCATION_GRANULARITY - 1);
        (max_candidate >= hole_start).then_some(max_candidate)
    } else {
        let min_candidate = hole_start.next_multiple_of(ALLOCATION_GRANULARITY);
        min_candidate
            .checked_add(length)
            .is_some_and(|end| end <= hole_end)
            .then_some(min_candidate)
    }
}

fn update_permissions<Platform: ShimPlatform>(
    page_manager: &WindowsPageManager<Platform>,
    aligned_base: usize,
    aligned_len: usize,
    permissions: MemoryRegionPermissions,
) -> Result<(), ()> {
    let ptr = MutPtr::<Platform, u8>::from_usize(aligned_base);
    // SAFETY: This applies the guest's explicit VM protection/free request to a page-aligned range
    // tracked by the LiteBox page manager. The page manager serializes the VMA update.
    let result = unsafe {
        match permissions {
            permissions if permissions.is_empty() => {
                page_manager.make_pages_inaccessible(ptr, aligned_len)
            }
            MemoryRegionPermissions::READ => page_manager.make_pages_readable(ptr, aligned_len),
            permissions
                if permissions
                    == MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE =>
            {
                page_manager.make_pages_writable(ptr, aligned_len)
            }
            permissions
                if permissions == MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC =>
            {
                page_manager.make_pages_executable(ptr, aligned_len)
            }
            permissions
                if permissions
                    == MemoryRegionPermissions::READ
                        | MemoryRegionPermissions::WRITE
                        | MemoryRegionPermissions::EXEC =>
            {
                page_manager.make_pages_rwx(ptr, aligned_len)
            }
            _ => return Err(()),
        }
    };

    result.map_err(|_| ())
}

fn query_memory_basic_information<Platform: ShimPlatform>(
    page_manager: &WindowsPageManager<Platform>,
    virtual_allocations: &WindowsVirtualAllocations<Platform>,
    base_address: usize,
) -> Option<MemoryBasicInformation> {
    let query_base = base_address & !(PAGE_SIZE - 1);
    if query_base >= Platform::TASK_ADDR_MAX {
        return None;
    }

    let mut mappings = page_manager.mappings();
    mappings.sort_by_key(|(range, _)| range.start);
    if let Some(allocation) = find_virtual_allocation_containing(virtual_allocations, query_base) {
        return query_allocation_basic_information(allocation, query_base);
    }

    if let Some((range, flags)) = mappings
        .iter()
        .find(|(range, _)| range.contains(&base_address))
    {
        let protect = permissions_to_page_protect(MemoryRegionPermissions::from(*flags));
        return Some(MemoryBasicInformation {
            base_address: range.start,
            allocation_base: range.start,
            allocation_protect: protect.bits(),
            partition_id: 0,
            _padding0: 0,
            region_size: range.end - range.start,
            state: MemoryState::MEM_COMMIT.bits(),
            protect: protect.bits(),
            type_: MemoryType::MEM_PRIVATE.bits(),
            _padding1: 0,
        });
    }

    let next_mapping_start = mappings
        .iter()
        .find(|(range, _)| range.start > query_base)
        .map_or(Platform::TASK_ADDR_MAX, |(range, _)| range.start);

    Some(MemoryBasicInformation {
        base_address: query_base,
        allocation_base: 0,
        allocation_protect: 0,
        partition_id: 0,
        _padding0: 0,
        region_size: next_mapping_start.saturating_sub(query_base),
        state: MemoryState::MEM_FREE.bits(),
        protect: 0,
        type_: 0,
        _padding1: 0,
    })
}

fn query_allocation_basic_information(
    allocation: WindowsVirtualAllocation,
    query_base: usize,
) -> Option<MemoryBasicInformation> {
    let allocation_end = allocation.base.checked_add(allocation.size)?;
    let (state, protect) = private_page_state_and_protect(&allocation, query_base);
    let mut region_end = query_base.checked_add(PAGE_SIZE)?;
    while region_end < allocation_end {
        if private_page_state_and_protect(&allocation, region_end) != (state, protect) {
            break;
        }
        region_end = region_end.checked_add(PAGE_SIZE)?;
    }

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

fn private_page_state_and_protect(
    allocation: &WindowsVirtualAllocation,
    page: usize,
) -> (u32, u32) {
    allocation
        .pages
        .get(&page)
        .map_or((MemoryState::MEM_RESERVE.bits(), 0), |protect| {
            (MemoryState::MEM_COMMIT.bits(), protect.bits())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{mut_byte_ptr, mut_ptr};
    use litebox::platform::ThreadProvider;

    extern crate std;

    type TestPlatform = crate::tests::TestPlatform;
    type TestTask = Task<TestPlatform, crate::tests::TestFS>;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

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
        }

        fn current_process() -> *mut c_void {
            usize::MAX as *mut c_void
        }

        fn host_status(status: i32) -> NtStatus {
            NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
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

                let task = crate::tests::test_task();
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

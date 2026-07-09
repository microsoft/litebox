// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use int_enum::IntEnum;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use rangemap::RangeMap;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{AccessMask, ObjectAttributes};
use crate::syscalls::mm::{MemoryType, PageProtection, create_pages, parse_page_protection};
use crate::syscalls::{Handle, ProcessHandle};
use crate::{ConstPtr, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform, Task, WindowsSectionView};

const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;
const MEM_TOP_DOWN: u32 = 0x0010_0000;
const MEM_PHYSICAL: u32 = 0x0040_0000;
const MEM_DIFFERENT_IMAGE_BASE_OK: u32 = 0x0080_0000;
const SUPPORTED_MAP_ALLOCATION_TYPES: u32 =
    MEM_TOP_DOWN | MEM_PHYSICAL | MEM_DIFFERENT_IMAGE_BASE_OK;
pub(crate) const WINDOWS_SHARED_SECTION_OBJECT: &str = r"\Windows\SharedSection";
pub(crate) const WINDOWS_SESSION_SHARED_SECTION_OBJECT: &str = r"\Sessions\0\Windows\SharedSection";
pub(crate) const WINDOWS_SHARED_SECTION_SIZE: usize = 0x1_0000;

enum SectionBacking {
    /// LiteBox lacks shared anonymous backing, so a pagefile section is
    /// metadata-only until its single allowed view is mapped. Remap after unmap
    /// is rejected instead of storing contents in shim memory or a file.
    ///
    /// Shared write-through backing across concurrent views is the deferred
    /// capability (see `TODO(section-subsystem)`); until it lands, a single view
    /// is the only observable-faithful case, which is why both the
    /// second-concurrent-view and the remap-after-unmap rejects exist. They are
    /// one missing feature, not two unrelated limitations.
    Pagefile,
    /// CSR shared section is created by kernel and shared across process. For now,
    /// we create it in userland for a process during initialization, and thus the first
    /// map request would return the pre-mapped address. Subsequent map requests would
    /// be rejected as LiteBox lacks shared mapping support.
    CsrSharedSection {
        base: usize,
    },
    ImageFile,
}

pub(crate) struct SectionSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: ShimPlatform> FdEnabledSubsystem for SectionSubsystem<Platform> {
    type Entry = SectionHandleObject<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for SectionHandleObject<Platform> {}

pub(crate) struct SectionHandleObject<Platform: ShimPlatform> {
    section: Arc<SectionObject<Platform>>,
    granted_access: SectionAccess,
}

pub(crate) struct SectionObject<Platform: ShimPlatform> {
    fs_path: Option<String>,
    size: usize,
    attributes: SectionAllocationAttributes,
    protection: PageProtection,
    backing: SectionBacking,
    pagefile_view_active: AtomicBool,
    _platform: PhantomData<fn(Platform)>,
}

pub(crate) struct MapViewOfSectionParameters<Platform: ShimPlatform> {
    pub(crate) section_handle: Handle,
    pub(crate) process_handle: ProcessHandle,
    pub(crate) base_address: MutPtr<Platform, usize>,
    pub(crate) zero_bits: usize,
    pub(crate) commit_size: usize,
    pub(crate) section_offset: Option<ConstPtr<Platform, i64>>,
    pub(crate) view_size: MutPtr<Platform, usize>,
    pub(crate) inherit_disposition: u32,
    pub(crate) allocation_type: u32,
    pub(crate) page_protection: u32,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SectionAllocationAttributes: u32 {
        const SEC_FILE = 0x0080_0000;
        const SEC_IMAGE = 0x0100_0000;
        const SEC_RESERVE = 0x0400_0000;
        const SEC_COMMIT = 0x0800_0000;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SectionAccess: u32 {
        const QUERY = 0x0001;
        const MAP_WRITE = 0x0002;
        const MAP_READ = 0x0004;
        const MAP_EXECUTE = 0x0008;
        const EXTEND_SIZE = 0x0010;
        const MAP_EXECUTE_EXPLICIT = 0x0020;

        const GENERIC_READ_EXPANSION = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::QUERY.bits()
            | Self::MAP_READ.bits();
        const GENERIC_WRITE_EXPANSION = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::MAP_WRITE.bits()
            | Self::EXTEND_SIZE.bits();
        const GENERIC_EXECUTE_EXPANSION = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | Self::MAP_EXECUTE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::QUERY.bits()
            | Self::MAP_WRITE.bits()
            | Self::MAP_READ.bits()
            | Self::MAP_EXECUTE.bits()
            | Self::EXTEND_SIZE.bits();
        const GENERIC_ALL = AccessMask::GENERIC_ALL.bits();
        const GENERIC_EXECUTE = AccessMask::GENERIC_EXECUTE.bits();
        const GENERIC_WRITE = AccessMask::GENERIC_WRITE.bits();
        const GENERIC_READ = AccessMask::GENERIC_READ.bits();

        const _ = !0;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct UnmapViewOfSectionFlags: u32 {
        const _ = 0;
    }
}

impl SectionAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if access.contains(Self::GENERIC_READ) {
            access.remove(Self::GENERIC_READ);
            access.insert(Self::GENERIC_READ_EXPANSION);
        }
        if access.contains(Self::GENERIC_WRITE) {
            access.remove(Self::GENERIC_WRITE);
            access.insert(Self::GENERIC_WRITE_EXPANSION);
        }
        if access.contains(Self::GENERIC_EXECUTE) {
            access.remove(Self::GENERIC_EXECUTE);
            access.insert(Self::GENERIC_EXECUTE_EXPANSION);
        }
        if access.contains(Self::GENERIC_ALL) {
            access.remove(Self::GENERIC_ALL);
            access.insert(Self::ALL_ACCESS);
        }
        access
    }

    fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum SectionInformationClass {
    Basic = 0,
    Image = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SectionBasicInformation {
    base_address: usize,
    attributes: u32,
    _padding: u32,
    size: i64,
}

const _: () = assert!(size_of::<SectionBasicInformation>() == 24);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SectionImageInformation {
    transfer_address: usize,
    zero_bits: u32,
    _padding0: u32,
    maximum_stack_size: usize,
    committed_stack_size: usize,
    subsystem_type: u32,
    subsystem_minor_version: u16,
    subsystem_major_version: u16,
    gp_value: u32,
    image_characteristics: u16,
    dll_characteristics: u16,
    machine: u16,
    image_contains_code: u8,
    image_flags: u8,
    loader_flags: u32,
    image_file_size: u32,
    checksum: u32,
}

const _: () = assert!(size_of::<SectionImageInformation>() == 64);

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn section_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, SectionSubsystem<Platform>>, NtStatus> {
        self.typed_handle_entry::<SectionSubsystem<Platform>>(handle)
    }

    fn insert_section_handle(
        &self,
        section: Arc<SectionObject<Platform>>,
        granted_access: SectionAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<SectionSubsystem<Platform>>(
            SectionHandleObject {
                section,
                granted_access,
            },
            drop,
        )
    }

    pub(crate) fn close_section_handle(&self, handle: Handle) {
        self.close_typed_handle::<SectionSubsystem<Platform>>(handle, drop);
    }

    pub(crate) fn close_section(section: SectionHandleObject<Platform>) {
        drop(section);
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtCreateSection has seven ABI parameters; keeping ABI args explicit avoids reshuffling"
    )]
    pub(crate) fn sys_nt_create_section(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        maximum_size: Option<ConstPtr<Platform, i64>>,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: Handle,
    ) -> NtStatus {
        // Host ntdll preserves the output handle for pre-creation validation failures such as a
        // NULL MaximumSize pagefile section.
        if let Err(status) =
            crate::probe_guest_output_preserving_value::<Platform, _>(section_handle)
        {
            return status;
        }
        let granted_access = SectionAccess::from_desired_access(desired_access);
        if granted_access.is_empty() {
            return NtStatus::ACCESS_DENIED;
        }
        let Some((protection, _)) = parse_page_protection(section_page_protection) else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };
        // NtCreateSection currently supports only pagefile-backed sections. File-backed image
        // sections are synthesized by NtOpenSection for KnownDlls; accepting a file handle here
        // requires section lifetime/sharing to be keyed by the underlying file object identity.
        if !file_handle.is_null() {
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw(),
                allocation_attributes:% = format_args!("{allocation_attributes:#x}"),
                section_page_protection:% = format_args!("{section_page_protection:#x}"),
                desired_access:% = format_args!("{desired_access:#x}");
                "Unsupported file-backed NtCreateSection"
            );
            return NtStatus::INVALID_HANDLE;
        }
        let allocation_attributes =
            SectionAllocationAttributes::from_bits_retain(allocation_attributes);
        let supported_create_attributes =
            SectionAllocationAttributes::SEC_RESERVE | SectionAllocationAttributes::SEC_COMMIT;
        if !allocation_attributes
            .difference(supported_create_attributes)
            .is_empty()
        {
            return NtStatus::INVALID_PARAMETER;
        }
        if !allocation_attributes.intersects(supported_create_attributes) {
            return NtStatus::INVALID_PARAMETER;
        }

        let Some(maximum_size) = maximum_size else {
            return NtStatus::INVALID_PARAMETER_4;
        };
        let maximum_size = match maximum_size.read_at_offset(0) {
            Some(value) if value > 0 => value,
            Some(_) => return NtStatus::INVALID_PARAMETER,
            None => return NtStatus::ACCESS_VIOLATION,
        };
        let Ok(size) = usize::try_from(maximum_size) else {
            return NtStatus::SECTION_TOO_BIG;
        };
        let Some(size) = size.checked_next_multiple_of(PAGE_SIZE) else {
            return NtStatus::SECTION_TOO_BIG;
        };
        if NonZeroPageSize::<PAGE_SIZE>::new(size).is_none() {
            return NtStatus::INVALID_PARAMETER;
        }

        let name = match self.read_section_name(object_attributes) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let attributes = if allocation_attributes.contains(SectionAllocationAttributes::SEC_RESERVE)
        {
            SectionAllocationAttributes::SEC_RESERVE
        } else {
            SectionAllocationAttributes::SEC_COMMIT
        };
        let section = Arc::new(SectionObject {
            fs_path: None,
            size,
            attributes,
            protection,
            backing: SectionBacking::Pagefile,
            pagefile_view_active: AtomicBool::new(false),
            _platform: PhantomData,
        });
        if let Some(name) = &name {
            let status = self.process.object_manager.create_section(name, &section);
            if status != NtStatus::SUCCESS {
                return status;
            }
        }
        self.publish_section_handle(section_handle, section, granted_access)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtCreateSectionEx extends NtCreateSection with two ABI parameters"
    )]
    pub(crate) fn sys_nt_create_section_ex(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        maximum_size: Option<ConstPtr<Platform, i64>>,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: Handle,
        extended_parameters: Option<ConstPtr<Platform, u8>>,
        extended_parameter_count: u32,
    ) -> NtStatus {
        if extended_parameters.is_some() || extended_parameter_count != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        self.sys_nt_create_section(
            section_handle,
            desired_access,
            object_attributes,
            maximum_size,
            section_page_protection,
            allocation_attributes,
            file_handle,
        )
    }

    pub(crate) fn sys_nt_open_section(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        // Host ntdll zeroes the output handle before resolving a missing section name.
        if section_handle
            .write_at_offset(0, Handle::default())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let granted_access = SectionAccess::from_desired_access(desired_access);
        if granted_access.is_empty() {
            return NtStatus::ACCESS_DENIED;
        }
        if object_attributes.is_none() {
            return NtStatus::INVALID_PARAMETER;
        }
        let name = match self.read_required_section_name(object_attributes) {
            Ok(name) => name,
            Err(status) => return status,
        };
        match self.process.object_manager.resolve_section(&name) {
            Ok(section) => {
                return self.publish_section_handle(section_handle, section, granted_access);
            }
            Err(NtStatus::OBJECT_NAME_NOT_FOUND | NtStatus::OBJECT_PATH_NOT_FOUND) => {}
            Err(status) => return status,
        }
        // TODO: Windows creates one image section per known DLL during boot and lets every process
        // map the same section. LiteBox currently lacks a shared image section subsystem, so we create
        // a new section for each process that opens a known DLL.
        let Some(fs_path) = known_dll_section_fs_path(&name) else {
            return section_missing_status(
                self.process.object_manager.parent_directory_exists(&name),
            );
        };
        litebox_util_log::debug!(
            section_name:% = name,
            fs_path:% = fs_path;
            "NtOpenSection: creating section for KnownDlls image"
        );
        let Ok(file_status) = self.fs.file_status(&fs_path) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        let section = Arc::new(SectionObject {
            fs_path: Some(fs_path),
            size: file_status.size,
            attributes: SectionAllocationAttributes::SEC_FILE
                | SectionAllocationAttributes::SEC_IMAGE,
            protection: PageProtection::PAGE_EXECUTE_WRITECOPY,
            backing: SectionBacking::ImageFile,
            pagefile_view_active: AtomicBool::new(false),
            _platform: PhantomData,
        });
        self.publish_section_handle(section_handle, section, granted_access)
    }

    pub(crate) fn sys_nt_query_section(
        &self,
        section_handle: Handle,
        section_information_class: u32,
        section_information: MutPtr<Platform, u8>,
        section_information_length: usize,
        return_length: Option<MutPtr<Platform, usize>>,
    ) -> NtStatus {
        let Ok(information_class) = SectionInformationClass::try_from(section_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        let entry = match self.section_entry(section_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let result = entry.with_entry(|entry| {
            entry
                .granted_access
                .require(SectionAccess::QUERY)
                .map(|()| Arc::clone(&entry.section))
        });
        let section = match result {
            Ok(section) => section,
            Err(status) => return status,
        };
        match information_class {
            SectionInformationClass::Basic => write_section_basic_information::<Platform>(
                &section,
                section_information,
                section_information_length,
                return_length,
            ),
            SectionInformationClass::Image => write_section_image_information::<Platform, FS>(
                &section,
                Arc::clone(&self.fs),
                section_information,
                section_information_length,
                return_length,
            ),
        }
    }

    pub(crate) fn sys_nt_map_view_of_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
    ) -> NtStatus {
        if !request.process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let Some(base) = request.base_address.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(requested_view_size) = request.view_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let section_offset = match request.section_offset {
            Some(section_offset) => match section_offset.read_at_offset(0) {
                Some(value) if value >= 0 => usize::try_from(value).unwrap_or(usize::MAX),
                Some(_) => return NtStatus::INVALID_PARAMETER,
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => 0,
        };
        if base != 0
            || request.zero_bits != 0
            || request.commit_size != 0
            || !section_offset.is_multiple_of(PAGE_SIZE)
            || !matches!(request.inherit_disposition, VIEW_SHARE | VIEW_UNMAP)
            || request.allocation_type & !SUPPORTED_MAP_ALLOCATION_TYPES != 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some((page_protection, permissions)) = parse_page_protection(request.page_protection)
        else {
            return NtStatus::INVALID_PAGE_PROTECTION;
        };
        let entry = match self.section_entry(request.section_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let result = entry.with_entry(|entry| {
            entry
                .granted_access
                .require(required_map_access(page_protection))
                .map(|()| Arc::clone(&entry.section))
        });
        let section = match result {
            Ok(section) => section,
            Err(status) => return status,
        };
        match section.backing {
            SectionBacking::Pagefile => self.map_pagefile_section(
                request,
                &section,
                requested_view_size,
                section_offset,
                page_protection,
                permissions,
            ),
            SectionBacking::CsrSharedSection { .. } => self.map_csr_shared_section(
                request,
                &section,
                requested_view_size,
                section_offset,
                page_protection,
            ),
            SectionBacking::ImageFile => self.map_image_section(request, &section, page_protection),
        }
    }

    pub(crate) fn sys_nt_map_view_of_section_ex(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        extended_parameters: Option<ConstPtr<Platform, u8>>,
        extended_parameter_count: u32,
    ) -> NtStatus {
        if extended_parameters.is_some() || extended_parameter_count != 0 {
            // TODO(section-subsystem): model MEM_EXTENDED_PARAMETER address requirements.
            return NtStatus::INVALID_PARAMETER;
        }
        self.sys_nt_map_view_of_section(request)
    }

    pub(crate) fn sys_nt_unmap_view_of_section(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }
        let Some((view_base, view)) = self.remove_section_view_for_address(base_address) else {
            return NtStatus::NOT_MAPPED_VIEW;
        };
        let owns_pages = view.section.as_ref().is_none_or(|section| {
            !matches!(section.backing, SectionBacking::CsrSharedSection { .. })
        });
        if owns_pages {
            let ptr = MutPtr::<Platform, u8>::from_usize(view_base);
            // SAFETY: Section views are tracked only after this shim successfully creates the pages;
            // unmapping consumes the tracked view and removes the exact owned range.
            if unsafe { self.global.page_manager.remove_pages(ptr, view.size) }.is_err() {
                self.process.section_views.write().insert(view_base, view);
                return NtStatus::UNABLE_TO_FREE_VM;
            }
        }
        self.process.virtual_allocations.write().remove(&view_base);
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_unmap_view_of_section_ex(
        &self,
        process_handle: ProcessHandle,
        base_address: usize,
        flags: u32,
    ) -> NtStatus {
        let flags = UnmapViewOfSectionFlags::from_bits_retain(flags);
        if !flags.is_empty() {
            return NtStatus::INVALID_PARAMETER;
        }
        self.sys_nt_unmap_view_of_section(process_handle, base_address)
    }

    fn publish_section_handle(
        &self,
        section_handle: MutPtr<Platform, Handle>,
        section: Arc<SectionObject<Platform>>,
        granted_access: SectionAccess,
    ) -> NtStatus {
        let handle = match self.insert_section_handle(section, granted_access) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        if section_handle.write_at_offset(0, handle).is_none() {
            self.close_section_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn map_pagefile_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        section: &Arc<SectionObject<Platform>>,
        requested_view_size: usize,
        section_offset: usize,
        page_protection: PageProtection,
        permissions: MemoryRegionPermissions,
    ) -> NtStatus {
        if section_offset > section.size {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let remaining = section.size - section_offset;
        let view_size = if requested_view_size == 0 {
            remaining
        } else {
            requested_view_size
        };
        if view_size == 0 || view_size > remaining {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let Some(mapped_size) = view_size.checked_next_multiple_of(PAGE_SIZE) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        let Some(length) = NonZeroPageSize::<PAGE_SIZE>::new(mapped_size) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        match section.backing {
            SectionBacking::Pagefile => {}
            SectionBacking::CsrSharedSection { .. } | SectionBacking::ImageFile => {
                return NtStatus::INVALID_FILE_FOR_SECTION;
            }
        }
        if !pagefile_view_protection_is_compatible(section.protection, page_protection) {
            litebox_util_log::debug!(
                section_protection:% = format_args!("{:#x}", section.protection.bits()),
                page_protection:% = format_args!("{:#x}", page_protection.bits());
                "Rejected pagefile section view protection incompatible with section protection"
            );
            return NtStatus::SECTION_PROTECTION;
        }
        if section.pagefile_view_active.swap(true, Ordering::AcqRel) {
            litebox_util_log::debug!(
                section_size = section.size,
                requested_view_size,
                section_offset;
                "Rejected additional pagefile section view"
            );
            // Host 25H2 allows repeated and simultaneous pagefile views. LiteBox
            // returns NOT_SUPPORTED until PageManager has first-class shared
            // anonymous backing that avoids kernel-side content storage.
            return NtStatus::NOT_SUPPORTED;
        }
        let Ok(mapping) = create_pages(
            &self.global.page_manager,
            None,
            length,
            CreatePagesFlags::empty(),
            permissions,
            |_| Ok(0),
        ) else {
            section.pagefile_view_active.store(false, Ordering::Release);
            return NtStatus::NO_MEMORY;
        };
        let base = mapping.as_usize();
        if request.base_address.write_at_offset(0, base).is_none()
            || request.view_size.write_at_offset(0, view_size).is_none()
        {
            let _ = remove_view_pages::<Platform>(&self.global.page_manager, base, mapped_size);
            section.pagefile_view_active.store(false, Ordering::Release);
            return NtStatus::ACCESS_VIOLATION;
        }
        self.process.section_views.write().insert(
            base,
            WindowsSectionView {
                size: mapped_size,
                section_offset,
                section: Some(Arc::clone(section)),
            },
        );
        self.process.virtual_allocations.write().insert(
            base,
            crate::WindowsVirtualAllocation {
                base,
                size: mapped_size,
                allocation_protect: section.protection,
                type_: MemoryType::MEM_MAPPED,
                pages: committed_pages(base, mapped_size, page_protection),
            },
        );
        NtStatus::SUCCESS
    }

    fn map_csr_shared_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        section: &Arc<SectionObject<Platform>>,
        requested_view_size: usize,
        section_offset: usize,
        page_protection: PageProtection,
    ) -> NtStatus {
        if section_offset != 0 {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let view_size = if requested_view_size == 0 {
            section.size
        } else {
            requested_view_size
        };
        if view_size == 0 || view_size > section.size {
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let Some(mapped_size) = view_size.checked_next_multiple_of(PAGE_SIZE) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        if mapped_size > WINDOWS_SHARED_SECTION_SIZE {
            litebox_util_log::debug!(
                section_size = section.size,
                requested_view_size,
                section_offset;
                "Rejected CSR shared section view larger than host limit"
            );
            return NtStatus::INVALID_VIEW_SIZE;
        }
        if !pagefile_view_protection_is_compatible(section.protection, page_protection) {
            return NtStatus::SECTION_PROTECTION;
        }
        if section.pagefile_view_active.swap(true, Ordering::AcqRel) {
            litebox_util_log::debug!(
                section_size = section.size,
                requested_view_size,
                section_offset;
                "Rejected additional CSR shared section view"
            );
            return NtStatus::NOT_SUPPORTED;
        }
        // TODO: we just return the pre-mapped base address for now, but we should support mapping at a different base address in the future.
        let base = match section.backing {
            SectionBacking::CsrSharedSection { base } => base,
            SectionBacking::Pagefile | SectionBacking::ImageFile => unreachable!(),
        };
        if request.base_address.write_at_offset(0, base).is_none()
            || request.view_size.write_at_offset(0, view_size).is_none()
        {
            section.pagefile_view_active.store(false, Ordering::Release);
            return NtStatus::ACCESS_VIOLATION;
        }
        self.process.section_views.write().insert(
            base,
            WindowsSectionView {
                size: mapped_size,
                section_offset,
                section: Some(Arc::clone(section)),
            },
        );
        self.process.virtual_allocations.write().insert(
            base,
            crate::WindowsVirtualAllocation {
                base,
                size: mapped_size,
                allocation_protect: section.protection,
                type_: MemoryType::MEM_MAPPED,
                // TODO(section-subsystem): honor per-view CSR protections only after
                // the backing is no longer aliased by PEB direct-deref pointers.
                pages: committed_pages(base, mapped_size, section.protection),
            },
        );
        NtStatus::SUCCESS
    }

    fn map_image_section(
        &self,
        request: MapViewOfSectionParameters<Platform>,
        section: &SectionObject<Platform>,
        page_protection: PageProtection,
    ) -> NtStatus {
        let Some(fs_path) = &section.fs_path else {
            return NtStatus::INVALID_FILE_FOR_SECTION;
        };
        if required_map_access(page_protection).contains(SectionAccess::MAP_WRITE) {
            litebox_util_log::debug!(
                page_protection:% = format_args!("{:#x}", page_protection.bits()),
                fs_path:% = fs_path;
                "Rejected writable image section view"
            );
            // Host 25H2 maps SEC_IMAGE with PAGE_READWRITE/PAGE_EXECUTE_READWRITE successfully
            // (NtMapViewOfSection returns STATUS_IMAGE_NOT_AT_BASE in the probe). LiteBox rejects
            // TODO(section-subsystem): allow this once image mappings support writable
            // copy-on-write/shared image pages.
            return NtStatus::SECTION_PROTECTION;
        }
        let mapping = match crate::loader::load_image_section(
            self.global.platform,
            Arc::clone(&self.fs),
            fs_path,
            &self.global.page_manager,
            &self.process.virtual_allocations,
        ) {
            Ok(mapping) => mapping,
            Err(crate::loader::WindowsLoadError::Access(_)) => {
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            }
            Err(crate::loader::WindowsLoadError::Load(_)) => return NtStatus::NO_MEMORY,
            Err(_) => return NtStatus::INVALID_FILE_FOR_SECTION,
        };
        if request
            .base_address
            .write_at_offset(0, mapping.base_addr)
            .is_none()
            || request
                .view_size
                .write_at_offset(0, mapping.image_size)
                .is_none()
        {
            let _ = remove_view_pages::<Platform>(
                &self.global.page_manager,
                mapping.base_addr,
                mapping.mapping_size,
            );
            self.process
                .virtual_allocations
                .write()
                .remove(&mapping.base_addr);
            return NtStatus::ACCESS_VIOLATION;
        }
        self.process.section_views.write().insert(
            mapping.base_addr,
            WindowsSectionView {
                size: mapping.mapping_size,
                section_offset: 0,
                section: None,
            },
        );
        NtStatus::SUCCESS
    }

    fn remove_section_view_for_address(
        &self,
        base_address: usize,
    ) -> Option<(usize, WindowsSectionView<Platform>)> {
        let mut views = self.process.section_views.write();
        let (&view_base, view) = views.range(..=base_address).next_back()?;
        let view = view.clone();
        let view_end = view_base.checked_add(view.size)?;
        if base_address < view_end {
            views.remove(&view_base);
            Some((view_base, view))
        } else {
            None
        }
    }

    fn read_section_name(
        &self,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> Result<Option<String>, NtStatus> {
        let (_, directory_name) =
            self.read_directory_object_attributes(object_attributes, false)?;
        Ok(directory_name.map(|name| name.original_path))
    }

    fn read_required_section_name(
        &self,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> Result<String, NtStatus> {
        let (_, Some(directory_name)) =
            self.read_directory_object_attributes(object_attributes, true)?
        else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        Ok(directory_name.original_path)
    }
}

fn section_missing_status(parent_exists: bool) -> NtStatus {
    if parent_exists {
        NtStatus::OBJECT_NAME_NOT_FOUND
    } else {
        NtStatus::OBJECT_PATH_NOT_FOUND
    }
}

fn known_dll_section_fs_path(object_path: &str) -> Option<String> {
    let (dll_name, fs_directory) =
        if let Some(rest) = strip_case_insensitive_prefix(object_path, r"\KnownDlls\") {
            (rest, "/Windows/System32/")
        } else if let Some(rest) = strip_case_insensitive_prefix(object_path, r"\KnownDlls32\") {
            (rest, "/Windows/SysWOW64/")
        } else {
            return None;
        };
    if dll_name.contains(['\\', '/']) || !ends_with_ignore_ascii_case(dll_name, ".dll") {
        return None;
    }
    let mut fs_path = String::from(fs_directory);
    fs_path.push_str(&dll_name.to_ascii_lowercase());
    Some(fs_path)
}

pub(crate) fn load_time_windows_shared_section<Platform: ShimPlatform>(
    base: usize,
) -> Arc<SectionObject<Platform>> {
    // CSRSS creates this named section for the CSR client/server contract. LiteBox
    // synthesizes it from the same static server data shape used for the PEB CSR
    // pointers instead of exposing a zeroed generic pagefile section.
    Arc::new(SectionObject {
        fs_path: None,
        size: WINDOWS_SHARED_SECTION_SIZE,
        attributes: SectionAllocationAttributes::SEC_COMMIT,
        protection: PageProtection::PAGE_READWRITE,
        backing: SectionBacking::CsrSharedSection { base },
        pagefile_view_active: AtomicBool::new(false),
        _platform: PhantomData,
    })
}

fn strip_case_insensitive_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        value.get(prefix.len()..)
    } else {
        None
    }
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn required_map_access(protection: PageProtection) -> SectionAccess {
    let base = protection.bits() & PageProtection::BASE_MASK;
    if base == PageProtection::PAGE_NOACCESS.bits() {
        SectionAccess::MAP_READ
    } else if matches!(
        base,
        value if value == PageProtection::PAGE_READWRITE.bits()
            || value == PageProtection::PAGE_EXECUTE_READWRITE.bits()
    ) {
        SectionAccess::MAP_WRITE
    } else if matches!(
        base,
        value if value == PageProtection::PAGE_EXECUTE.bits()
            || value == PageProtection::PAGE_EXECUTE_READ.bits()
            || value == PageProtection::PAGE_EXECUTE_WRITECOPY.bits()
    ) {
        SectionAccess::MAP_EXECUTE
    } else {
        SectionAccess::MAP_READ
    }
}

fn pagefile_view_protection_is_compatible(
    section_protection: PageProtection,
    view_protection: PageProtection,
) -> bool {
    let view_base = view_protection.bits() & PageProtection::BASE_MASK;
    if view_base == PageProtection::PAGE_NOACCESS.bits() {
        return true;
    }

    if page_protection_has_read(view_protection) && !page_protection_has_read(section_protection) {
        return false;
    }
    if page_protection_has_direct_write(view_protection)
        && !page_protection_has_direct_write(section_protection)
    {
        return false;
    }
    if page_protection_has_execute(view_protection)
        && !page_protection_has_execute(section_protection)
    {
        return false;
    }
    true
}

fn page_protection_has_read(protection: PageProtection) -> bool {
    matches!(
        protection.bits() & PageProtection::BASE_MASK,
        value if value == PageProtection::PAGE_READONLY.bits()
            || value == PageProtection::PAGE_READWRITE.bits()
            || value == PageProtection::PAGE_WRITECOPY.bits()
            || value == PageProtection::PAGE_EXECUTE_READ.bits()
            || value == PageProtection::PAGE_EXECUTE_READWRITE.bits()
            || value == PageProtection::PAGE_EXECUTE_WRITECOPY.bits()
    )
}

fn page_protection_has_direct_write(protection: PageProtection) -> bool {
    matches!(
        protection.bits() & PageProtection::BASE_MASK,
        value if value == PageProtection::PAGE_READWRITE.bits()
            || value == PageProtection::PAGE_EXECUTE_READWRITE.bits()
    )
}

fn page_protection_has_execute(protection: PageProtection) -> bool {
    matches!(
        protection.bits() & PageProtection::BASE_MASK,
        value if value == PageProtection::PAGE_EXECUTE.bits()
            || value == PageProtection::PAGE_EXECUTE_READ.bits()
            || value == PageProtection::PAGE_EXECUTE_READWRITE.bits()
            || value == PageProtection::PAGE_EXECUTE_WRITECOPY.bits()
    )
}

fn write_section_basic_information<Platform: ShimPlatform>(
    section: &SectionObject<Platform>,
    section_information: MutPtr<Platform, u8>,
    section_information_length: usize,
    return_length: Option<MutPtr<Platform, usize>>,
) -> NtStatus {
    let required_len = size_of::<SectionBasicInformation>();
    if section_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }
    let Ok(size) = i64::try_from(section.size) else {
        return NtStatus::SECTION_TOO_BIG;
    };
    let info = SectionBasicInformation {
        base_address: 0,
        attributes: section.attributes.bits(),
        _padding: 0,
        size,
    };
    let output =
        MutPtr::<Platform, SectionBasicInformation>::from_usize(section_information.as_usize());
    if output.write_at_offset(0, info).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    NtStatus::SUCCESS
}

fn write_section_image_information<Platform: ShimPlatform, FS: ShimFS>(
    section: &SectionObject<Platform>,
    fs: Arc<FS>,
    section_information: MutPtr<Platform, u8>,
    section_information_length: usize,
    return_length: Option<MutPtr<Platform, usize>>,
) -> NtStatus {
    if !matches!(section.backing, SectionBacking::ImageFile) {
        return NtStatus::SECTION_NOT_IMAGE;
    }
    let required_len = size_of::<SectionImageInformation>();
    if section_information_length < required_len {
        return NtStatus::INFO_LENGTH_MISMATCH;
    }
    let Some(fs_path) = &section.fs_path else {
        return NtStatus::INVALID_FILE_FOR_SECTION;
    };
    let metadata = match crate::loader::image_section_metadata(fs, fs_path) {
        Ok(metadata) => metadata,
        Err(crate::loader::WindowsLoadError::Access(_)) => return NtStatus::OBJECT_NAME_NOT_FOUND,
        Err(_) => return NtStatus::INVALID_FILE_FOR_SECTION,
    };
    // Host ntdll reports ReturnLength=64 for SectionImageInformation on x64; the public
    // winternl.h layout ends at CheckSum and has no trailing extension fields.
    let info = SectionImageInformation {
        transfer_address: metadata.transfer_address,
        zero_bits: 0,
        _padding0: 0,
        maximum_stack_size: 0,
        committed_stack_size: 0,
        subsystem_type: metadata.subsystem,
        subsystem_minor_version: metadata.subsystem_minor_version,
        subsystem_major_version: metadata.subsystem_major_version,
        gp_value: 0,
        image_characteristics: metadata.image_characteristics,
        dll_characteristics: metadata.dll_characteristics,
        machine: metadata.machine,
        image_contains_code: 1,
        image_flags: 0,
        loader_flags: 0,
        image_file_size: metadata.file_size,
        checksum: 0,
    };
    let output =
        MutPtr::<Platform, SectionImageInformation>::from_usize(section_information.as_usize());
    if output.write_at_offset(0, info).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if let Some(return_length) = return_length
        && return_length.write_at_offset(0, required_len).is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    NtStatus::SUCCESS
}

fn committed_pages(
    base: usize,
    size: usize,
    protect: PageProtection,
) -> RangeMap<usize, PageProtection> {
    let mut pages = RangeMap::new();
    if let Some(end) = base.checked_add(size) {
        pages.insert(base..end, protect);
    }
    pages
}

fn remove_view_pages<Platform: ShimPlatform>(
    page_manager: &crate::WindowsPageManager<Platform>,
    base: usize,
    size: usize,
) -> Result<(), ()> {
    let ptr = MutPtr::<Platform, u8>::from_usize(base);
    // SAFETY: The caller passes a section view range created by this module and not yet exposed,
    // or a tracked view being rolled back after output write failure.
    unsafe { page_manager.remove_pages(ptr, size) }.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::mem::{size_of, size_of_val};

    use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::{ObjectAttributes, UnicodeString};
    use crate::syscalls::event::EventType;
    use crate::tests::{TestFS, TestPlatform, const_ptr, mut_byte_ptr, mut_ptr, test_task};

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const IMAGE_SUBSYSTEM_WINDOWS_CUI: u32 = 3;

    fn wide(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    fn unicode(value: &[u16]) -> UnicodeString {
        UnicodeString {
            length: u16::try_from(size_of_val(value)).unwrap(),
            maximum_length: u16::try_from(size_of_val(value)).unwrap(),
            padding_0: [0; 4],
            buffer: value.as_ptr() as usize,
        }
    }

    fn object_attributes(name: &UnicodeString) -> ObjectAttributes {
        ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::from_raw(0),
            object_name: core::ptr::from_ref(name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    fn create_pagefile_section(
        task: &Task<TestPlatform, TestFS>,
        access: u32,
        size: i64,
        protection: PageProtection,
    ) -> Handle {
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut handle),
                access,
                None,
                Some(const_ptr(&size)),
                protection.bits(),
                SectionAllocationAttributes::SEC_COMMIT.bits(),
                Handle::default(),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn map_pagefile_section(task: &Task<TestPlatform, TestFS>, handle: Handle) -> (usize, usize) {
        let mut base = 0usize;
        let mut view_size = 0usize;
        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_READWRITE.bits(),
            }),
            NtStatus::SUCCESS
        );
        (base, view_size)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_kernel32_image() -> std::vec::Vec<u8> {
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
        std::fs::read(
            std::path::PathBuf::from(system_root)
                .join("System32")
                .join("kernel32.dll"),
        )
        .expect("host kernel32.dll is readable")
    }

    #[test]
    fn nt_create_section_creates_queryable_pagefile_section() {
        let task = test_task();
        let handle = create_pagefile_section(
            &task,
            SectionAccess::ALL_ACCESS.bits(),
            0x2345,
            PageProtection::PAGE_READWRITE,
        );
        let mut info = SectionBasicInformation {
            base_address: usize::MAX,
            attributes: u32::MAX,
            _padding: u32::MAX,
            size: -1,
        };
        let mut return_length = 0usize;

        assert_eq!(
            task.sys_nt_query_section(
                handle,
                SectionInformationClass::Basic as u32,
                mut_byte_ptr(&mut info),
                size_of::<SectionBasicInformation>(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length, size_of::<SectionBasicInformation>());
        assert_eq!(info.base_address, 0);
        assert_eq!(
            info.attributes,
            SectionAllocationAttributes::SEC_COMMIT.bits()
        );
        assert_eq!(info.size, 0x3000);

        let mut too_small = [0xcc; size_of::<SectionBasicInformation>() - 1];
        let too_small_len = too_small.len();
        return_length = 0x5555_5555;
        // Host 25H2 leaves ReturnLength untouched on INFO_LENGTH_MISMATCH
        // (Basic len=23 -> ret stays sentinel) and writes 0x18 only on success.
        assert_eq!(
            task.sys_nt_query_section(
                handle,
                SectionInformationClass::Basic as u32,
                mut_byte_ptr(&mut too_small),
                too_small_len,
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(return_length, 0x5555_5555);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_section_image_information_uses_pe_headers() {
        let image = host_kernel32_image();
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", &image)]);
        let name = wide(r"\KnownDlls\kernel32.dll");
        let unicode = unicode(&name);
        let attrs = object_attributes(&unicode);
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut handle),
                SectionAccess::QUERY.bits(),
                Some(const_ptr(&attrs)),
            ),
            NtStatus::SUCCESS
        );

        let mut info = <SectionImageInformation as zerocopy::FromZeros>::new_zeroed();
        let mut return_length = 0usize;
        assert_eq!(
            task.sys_nt_query_section(
                handle,
                SectionInformationClass::Image as u32,
                mut_byte_ptr(&mut info),
                size_of::<SectionImageInformation>(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(return_length, size_of::<SectionImageInformation>());
        assert_eq!(info.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(info.subsystem_type, IMAGE_SUBSYSTEM_WINDOWS_CUI);
        assert_eq!(info.image_contains_code, 1);
        assert_eq!(info.image_file_size, u32::try_from(image.len()).unwrap());

        let mut too_small = [0xcc; size_of::<SectionImageInformation>() - 1];
        let too_small_len = too_small.len();
        return_length = 0x5555_5555;
        // Host 25H2 leaves ReturnLength untouched on INFO_LENGTH_MISMATCH
        // (Image len=63 -> ret stays sentinel) and writes 0x40 only on success.
        assert_eq!(
            task.sys_nt_query_section(
                handle,
                SectionInformationClass::Image as u32,
                mut_byte_ptr(&mut too_small),
                too_small_len,
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
        assert_eq!(return_length, 0x5555_5555);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn image_section_rejects_writable_view_protection() {
        let image = host_kernel32_image();
        let task =
            crate::tests::test_task_with_nls_files(&[("/Windows/System32/kernel32.dll", &image)]);
        let name = wide(r"\KnownDlls\kernel32.dll");
        let unicode = unicode(&name);
        let attrs = object_attributes(&unicode);
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut handle),
                SectionAccess::ALL_ACCESS.bits(),
                Some(const_ptr(&attrs)),
            ),
            NtStatus::SUCCESS
        );

        let mut base = 0usize;
        let mut view_size = 0usize;
        // Host 25H2 maps SEC_IMAGE with PAGE_READWRITE successfully
        // (NtMapViewOfSection returns STATUS_IMAGE_NOT_AT_BASE). LiteBox rejects writable image
        // views until image mappings are backed by real shared image pages.
        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_READWRITE.bits(),
            }),
            NtStatus::SECTION_PROTECTION
        );
        assert_eq!(base, 0);
        assert_eq!(view_size, 0);

        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_EXECUTE_READ.bits(),
            }),
            NtStatus::SUCCESS
        );
        assert_ne!(base, 0);
        assert_ne!(view_size, 0);
    }

    #[test]
    fn section_output_handles_follow_host_probe_contracts() {
        let task = test_task();
        let name = wide(r"\KnownDlls\DefinitelyMissingLiteBoxProbe.dll");
        let unicode = unicode(&name);
        let attrs = object_attributes(&unicode);
        let mut open_handle = Handle::from_raw(0x1111_2222);
        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut open_handle),
                SectionAccess::QUERY.bits(),
                Some(const_ptr(&attrs)),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(open_handle, Handle::default());

        let mut create_handle = Handle::from_raw(0x3333_4444);
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut create_handle),
                SectionAccess::ALL_ACCESS.bits(),
                None,
                None,
                PageProtection::PAGE_READWRITE.bits(),
                SectionAllocationAttributes::SEC_COMMIT.bits(),
                Handle::default(),
            ),
            NtStatus::INVALID_PARAMETER_4
        );
        assert_eq!(create_handle, Handle::from_raw(0x3333_4444));
    }

    #[test]
    fn nt_map_view_of_section_maps_writable_pagefile_section() {
        let task = test_task();
        let handle = create_pagefile_section(
            &task,
            SectionAccess::ALL_ACCESS.bits(),
            0x2000,
            PageProtection::PAGE_READWRITE,
        );
        let (base, view_size) = map_pagefile_section(&task, handle);
        assert_ne!(base, 0);
        assert_eq!(view_size, 0x2000);

        let mapped = MutPtr::<TestPlatform, u32>::from_usize(base);
        assert_eq!(mapped.read_at_offset(0), Some(0));
        assert!(mapped.write_at_offset(0, 0xfeed_cafe).is_some());
        assert_eq!(mapped.read_at_offset(0), Some(0xfeed_cafe));

        assert_eq!(
            task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, base + 0x100),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, base),
            NtStatus::NOT_MAPPED_VIEW
        );
    }

    #[test]
    fn pagefile_map_rejects_protection_incompatible_with_section_protection() {
        let task = test_task();
        let readonly = create_pagefile_section(
            &task,
            SectionAccess::ALL_ACCESS.bits(),
            0x2000,
            PageProtection::PAGE_READONLY,
        );
        let execute = create_pagefile_section(
            &task,
            SectionAccess::ALL_ACCESS.bits(),
            0x2000,
            PageProtection::PAGE_EXECUTE,
        );
        let readwrite = create_pagefile_section(
            &task,
            SectionAccess::ALL_ACCESS.bits(),
            0x2000,
            PageProtection::PAGE_READWRITE,
        );

        for (handle, page_protection) in [
            (readonly, PageProtection::PAGE_READWRITE),
            (execute, PageProtection::PAGE_READONLY),
            (readwrite, PageProtection::PAGE_EXECUTE_READ),
        ] {
            let mut base = 0usize;
            let mut view_size = 0usize;
            assert_eq!(
                task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                    section_handle: handle,
                    process_handle: ProcessHandle::CURRENT,
                    base_address: mut_ptr(&mut base),
                    zero_bits: 0,
                    commit_size: 0,
                    section_offset: None,
                    view_size: mut_ptr(&mut view_size),
                    inherit_disposition: VIEW_SHARE,
                    allocation_type: 0,
                    page_protection: page_protection.bits(),
                }),
                NtStatus::SECTION_PROTECTION
            );
            assert_eq!(base, 0);
            assert_eq!(view_size, 0);
        }
    }

    #[test]
    fn pagefile_map_accepts_compatible_noaccess_and_copy_protections() {
        let task = test_task();
        // Host 25H2 and ReactOS allow PAGE_WRITECOPY and PAGE_NOACCESS views of
        // a PAGE_READONLY pagefile section.
        for page_protection in [
            PageProtection::PAGE_WRITECOPY,
            PageProtection::PAGE_NOACCESS,
        ] {
            let readonly = create_pagefile_section(
                &task,
                SectionAccess::ALL_ACCESS.bits(),
                0x2000,
                PageProtection::PAGE_READONLY,
            );
            let mut base = 0usize;
            let mut view_size = 0usize;
            assert_eq!(
                task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                    section_handle: readonly,
                    process_handle: ProcessHandle::CURRENT,
                    base_address: mut_ptr(&mut base),
                    zero_bits: 0,
                    commit_size: 0,
                    section_offset: None,
                    view_size: mut_ptr(&mut view_size),
                    inherit_disposition: VIEW_SHARE,
                    allocation_type: 0,
                    page_protection: page_protection.bits(),
                }),
                NtStatus::SUCCESS
            );
            assert_ne!(base, 0);
            assert_eq!(view_size, 0x2000);
            assert_eq!(
                task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, base),
                NtStatus::SUCCESS
            );
        }
    }

    #[test]
    fn pagefile_noaccess_view_requires_map_read_access() {
        let task = test_task();
        let handle = create_pagefile_section(
            &task,
            SectionAccess::QUERY.bits(),
            0x2000,
            PageProtection::PAGE_READWRITE,
        );
        let mut base = 0usize;
        let mut view_size = 0usize;

        // Host 25H2 returns STATUS_ACCESS_DENIED for PAGE_NOACCESS maps unless
        // the section handle has SECTION_MAP_READ.
        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: handle,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut view_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_NOACCESS.bits(),
            }),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(base, 0);
        assert_eq!(view_size, 0);
    }

    #[test]
    fn pagefile_section_rejects_additional_views_across_handles_and_unmap() {
        let task = test_task();
        let name = wide(r"\BaseNamedObjects\LiteBoxSingleViewSection");
        let unicode = unicode(&name);
        let attrs = object_attributes(&unicode);
        let size = 0x2000i64;
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut handle),
                SectionAccess::ALL_ACCESS.bits(),
                Some(const_ptr(&attrs)),
                Some(const_ptr(&size)),
                PageProtection::PAGE_READWRITE.bits(),
                SectionAllocationAttributes::SEC_COMMIT.bits(),
                Handle::default(),
            ),
            NtStatus::SUCCESS
        );
        let mut opened = Handle::default();
        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut opened),
                SectionAccess::ALL_ACCESS.bits(),
                Some(const_ptr(&attrs)),
            ),
            NtStatus::SUCCESS
        );
        let (first_base, first_size) = map_pagefile_section(&task, handle);
        assert_eq!(first_size, 0x2000);

        let mut second_base = 0usize;
        let mut second_size = 0usize;
        // Host 25H2 permits this second simultaneous pagefile view (STATUS_SUCCESS). LiteBox
        // deliberately returns STATUS_NOT_SUPPORTED until shared anonymous backing exists.
        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: opened,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut second_base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut second_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_READWRITE.bits(),
            }),
            NtStatus::NOT_SUPPORTED
        );
        assert_eq!(second_base, 0);
        assert_eq!(second_size, 0);

        assert_eq!(
            task.sys_nt_unmap_view_of_section(ProcessHandle::CURRENT, first_base),
            NtStatus::SUCCESS
        );
        second_base = 0;
        second_size = 0;
        assert_eq!(
            task.sys_nt_map_view_of_section(MapViewOfSectionParameters {
                section_handle: opened,
                process_handle: ProcessHandle::CURRENT,
                base_address: mut_ptr(&mut second_base),
                zero_bits: 0,
                commit_size: 0,
                section_offset: None,
                view_size: mut_ptr(&mut second_size),
                inherit_disposition: VIEW_SHARE,
                allocation_type: 0,
                page_protection: PageProtection::PAGE_READWRITE.bits(),
            }),
            NtStatus::NOT_SUPPORTED
        );
        assert_eq!(second_base, 0);
        assert_eq!(second_size, 0);
    }

    #[test]
    fn nt_open_section_opens_existing_named_pagefile_section() {
        let task = test_task();
        let name = wide(r"\BaseNamedObjects\LiteBoxNamedSection");
        let unicode = unicode(&name);
        let attrs = object_attributes(&unicode);
        let size = 0x1000i64;
        let mut created = Handle::default();
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut created),
                SectionAccess::ALL_ACCESS.bits(),
                Some(const_ptr(&attrs)),
                Some(const_ptr(&size)),
                PageProtection::PAGE_READWRITE.bits(),
                SectionAllocationAttributes::SEC_COMMIT.bits(),
                Handle::default(),
            ),
            NtStatus::SUCCESS
        );

        let mut opened = Handle::default();
        assert_eq!(
            task.sys_nt_open_section(
                mut_ptr(&mut opened),
                SectionAccess::QUERY.bits(),
                Some(const_ptr(&attrs)),
            ),
            NtStatus::SUCCESS
        );
        assert_ne!(opened, Handle::default());
        assert_ne!(opened, created);
    }

    #[test]
    fn event_and_section_names_collide_in_object_namespace() {
        let task = test_task();
        let name = wide(r"\BaseNamedObjects\LiteBoxSharedLeafName");
        let unicode = unicode(&name);
        let attrs = object_attributes(&unicode);
        let mut event = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut event),
                0x001f_0003,
                Some(const_ptr(&attrs)),
                EventType::Notification as u32,
                0,
            ),
            NtStatus::SUCCESS
        );

        let size = 0x1000i64;
        let mut section = Handle::from_raw(0xffff_ffff);
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut section),
                SectionAccess::ALL_ACCESS.bits(),
                Some(const_ptr(&attrs)),
                Some(const_ptr(&size)),
                PageProtection::PAGE_READWRITE.bits(),
                SectionAllocationAttributes::SEC_COMMIT.bits(),
                Handle::default(),
            ),
            NtStatus::OBJECT_NAME_EXISTS
        );
        assert_eq!(section, Handle::from_raw(0xffff_ffff));
    }
}

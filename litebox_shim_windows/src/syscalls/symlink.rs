// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT object-manager symbolic-link syscalls.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes, UnicodeString};
use crate::syscalls::directory::ObjectNode;
use crate::syscalls::{Handle, directory::DirectoryName};
use crate::{ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value};

const OBJ_OPENIF: u32 = 0x0000_0080;
const OBJ_OPENLINK: u32 = 0x0000_0100;
const STANDARD_RIGHTS_REQUIRED: u32 = AccessMask::DELETE.bits()
    | AccessMask::READ_CONTROL.bits()
    | AccessMask::WRITE_DAC.bits()
    | AccessMask::WRITE_OWNER.bits();

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct SymbolicLinkAccess: u32 {
        const QUERY = 0x0001;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits() | Self::QUERY.bits();
        const ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | Self::QUERY.bits();

        const _ = !0;
    }
}

impl SymbolicLinkAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if desired_access & AccessMask::GENERIC_READ.bits() != 0 {
            access.insert(Self::READ);
        }
        if desired_access & AccessMask::GENERIC_WRITE.bits() != 0 {
            access.insert(Self::WRITE);
        }
        if desired_access & AccessMask::GENERIC_EXECUTE.bits() != 0 {
            access.insert(Self::EXECUTE);
        }
        if desired_access & AccessMask::GENERIC_ALL.bits() != 0 {
            access.insert(Self::ALL_ACCESS);
        }
        access.remove(Self::from_bits_retain(
            AccessMask::GENERIC_READ.bits()
                | AccessMask::GENERIC_WRITE.bits()
                | AccessMask::GENERIC_EXECUTE.bits()
                | AccessMask::GENERIC_ALL.bits(),
        ));
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

pub(crate) struct SymbolicLinkSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for SymbolicLinkSubsystem<Platform> {
    type Entry = SymbolicLinkHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for SymbolicLinkHandleObject<Platform> {}

pub(crate) struct SymbolicLinkHandleObject<Platform: crate::ShimPlatform> {
    link: Arc<ObjectNode<Platform>>,
    granted_access: SymbolicLinkAccess,
}

fn utf16_units(value: &str) -> Result<Vec<u16>, NtStatus> {
    let units: Vec<u16> = value.encode_utf16().collect();
    if units
        .len()
        .checked_mul(size_of::<u16>())
        .is_none_or(|len| len > usize::from(u16::MAX))
    {
        return Err(NtStatus::NAME_TOO_LONG);
    }
    Ok(units)
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn symbolic_link_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, SymbolicLinkSubsystem<Platform>>, NtStatus> {
        self.typed_handle_entry::<SymbolicLinkSubsystem<Platform>>(handle)
    }

    fn insert_symbolic_link_handle(
        &self,
        link: Arc<ObjectNode<Platform>>,
        granted_access: SymbolicLinkAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<SymbolicLinkSubsystem<Platform>>(SymbolicLinkHandleObject {
            link,
            granted_access,
        })
    }

    fn close_symbolic_link_handle(&self, handle: Handle) {
        self.close_typed_handle::<SymbolicLinkSubsystem<Platform>>(handle);
    }

    pub(crate) fn close_symbolic_link(link: SymbolicLinkHandleObject<Platform>) {
        drop(link);
    }

    pub(crate) fn sys_nt_create_symbolic_link_object(
        &self,
        link_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        link_target: ConstPtr<Platform, UnicodeString>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(link_handle) {
            return status;
        }
        let (object_attributes, link_name) =
            match self.read_directory_object_attributes(object_attributes, true) {
                Ok((Some(object_attributes), Some(link_name))) => (object_attributes, link_name),
                Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
                Ok((None, Some(_))) => return NtStatus::INVALID_PARAMETER,
                Err(status) => return status,
            };
        let target = match link_target.read_at_offset(0) {
            Some(target) => match target.read_string::<Platform>() {
                Ok(target) => target,
                Err(status) => return status,
            },
            None => return NtStatus::ACCESS_VIOLATION,
        };
        if target.is_empty() {
            return NtStatus::INVALID_PARAMETER;
        }
        if object_attributes.attributes & OBJ_OPENLINK != 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        let granted_access = SymbolicLinkAccess::from_desired_access(desired_access);
        self.create_symbolic_link(
            link_handle,
            granted_access,
            link_name,
            target,
            object_attributes.attributes & OBJ_OPENIF != 0,
        )
    }

    fn create_symbolic_link(
        &self,
        link_handle: MutPtr<Platform, Handle>,
        granted_access: SymbolicLinkAccess,
        link_name: DirectoryName,
        target: String,
        open_if: bool,
    ) -> NtStatus {
        self.process.directory_namespace.create_symlink(
            &link_name.path,
            target,
            |link| {
                if !open_if {
                    return NtStatus::OBJECT_NAME_COLLISION;
                }
                let Ok(handle) = self.insert_symbolic_link_handle(link, granted_access) else {
                    return NtStatus::QUOTA_EXCEEDED;
                };
                if link_handle.write_at_offset(0, handle).is_none() {
                    self.close_symbolic_link_handle(handle);
                    return NtStatus::ACCESS_VIOLATION;
                }
                NtStatus::OBJECT_NAME_EXISTS
            },
            |link| {
                let Ok(handle) = self.insert_symbolic_link_handle(link, granted_access) else {
                    return NtStatus::QUOTA_EXCEEDED;
                };
                if link_handle.write_at_offset(0, handle).is_none() {
                    self.close_symbolic_link_handle(handle);
                    return NtStatus::ACCESS_VIOLATION;
                }
                NtStatus::SUCCESS
            },
        )
    }

    pub(crate) fn sys_nt_open_symbolic_link_object(
        &self,
        link_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(link_handle) {
            return status;
        }
        let (open_link, link_name) =
            match self.read_directory_object_attributes(object_attributes, true) {
                Ok((Some(object_attributes), Some(link_name))) => {
                    (object_attributes.attributes & OBJ_OPENLINK != 0, link_name)
                }
                Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
                Ok((None, Some(_))) => return NtStatus::INVALID_PARAMETER,
                Err(status) => return status,
            };
        let link = match self
            .process
            .directory_namespace
            .resolve_symlink(&link_name.path, open_link)
        {
            Ok(link) => link,
            Err(status) => return status,
        };
        let Ok(handle) = self.insert_symbolic_link_handle(
            link,
            SymbolicLinkAccess::from_desired_access(desired_access),
        ) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if link_handle.write_at_offset(0, handle).is_none() {
            self.close_symbolic_link_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_symbolic_link_object(
        &self,
        link_handle: Handle,
        link_target: MutPtr<Platform, UnicodeString>,
        returned_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let entry = match self.symbolic_link_entry(link_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        if let Err(status) =
            entry.with_entry(|entry| entry.granted_access.require(SymbolicLinkAccess::QUERY))
        {
            return status;
        }
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(link_target) {
            return status;
        }
        if let Some(returned_length) = returned_length
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(returned_length)
        {
            return status;
        }

        let target = entry.with_entry(|entry| entry.link.symlink_target());
        let target = match target {
            Ok(target) => target,
            Err(status) => return status,
        };
        let units = match utf16_units(&target) {
            Ok(units) => units,
            Err(status) => return status,
        };
        let required = u32::try_from(units.len() * size_of::<u16>()).expect("USHORT fits in ULONG");
        let Some(mut unicode) = link_target.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };

        if let Some(returned_length) = returned_length
            && returned_length.write_at_offset(0, required).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if required > u32::from(unicode.maximum_length) {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        if required != 0 && unicode.buffer == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }

        let target_buffer = MutPtr::<Platform, u16>::from_usize(unicode.buffer);
        target_buffer
            .write_slice_at_offset(0, &units)
            .ok_or(NtStatus::ACCESS_VIOLATION)
            .map_or_else(
                |status| status,
                |()| {
                    unicode.length = u16::try_from(required).expect("required length fits");
                    if link_target.write_at_offset(0, unicode).is_none() {
                        NtStatus::ACCESS_VIOLATION
                    } else {
                        NtStatus::SUCCESS
                    }
                },
            )
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of_val;

    use litebox::platform::ThreadProvider;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::{ObjectAttributes, UnicodeString};
    use crate::tests::{
        TestPlatform, const_ptr, mut_ptr, object_attributes, test_task, unicode_string,
    };

    const SYMBOLIC_LINK_QUERY: u32 = 0x0000_0001;
    const SYMBOLIC_LINK_ALL_ACCESS: u32 = 0x000f_0001;
    const DIRECTORY_QUERY: u32 = 0x0000_0001;
    const DIRECTORY_ALL_ACCESS: u32 = 0x000f_000f;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const OBJ_OPENLINK: u32 = 0x0000_0100;
    const OBJ_OPENIF: u32 = 0x0000_0080;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn link_target(value: &str) -> (Vec<u16>, UnicodeString) {
        let units: Vec<u16> = value.encode_utf16().collect();
        let unicode = unicode_string(&units);
        (units, unicode)
    }

    fn create_link(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        path: &str,
        target: &str,
    ) -> Handle {
        let path_units: Vec<u16> = path.encode_utf16().collect();
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
        let (_target_units, target) = link_target(target);
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_symbolic_link_object(
                mut_ptr(&mut handle),
                SYMBOLIC_LINK_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                const_ptr(&target),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn create_directory(task: &Task<TestPlatform, crate::tests::TestFS>, path: &str) -> Handle {
        let path_units: Vec<u16> = path.encode_utf16().collect();
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_directory_object(
                mut_ptr(&mut handle),
                DIRECTORY_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                Handle::default(),
                0,
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn open_directory(task: &Task<TestPlatform, crate::tests::TestFS>, path: &str) -> Handle {
        let path_units: Vec<u16> = path.encode_utf16().collect();
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_directory_object(
                mut_ptr(&mut handle),
                DIRECTORY_QUERY,
                Some(const_ptr(&attrs)),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn open_link(task: &Task<TestPlatform, crate::tests::TestFS>, path: &str) -> Handle {
        let path_units: Vec<u16> = path.encode_utf16().collect();
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE | OBJ_OPENLINK);
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_symbolic_link_object(
                mut_ptr(&mut handle),
                SYMBOLIC_LINK_QUERY,
                Some(const_ptr(&attrs)),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn query_link(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        handle: Handle,
        output_units: &mut [u16],
    ) -> (UnicodeString, u32) {
        let mut target = UnicodeString {
            length: u16::MAX,
            maximum_length: u16::try_from(size_of_val(output_units)).expect("test buffer fits"),
            padding_0: [0; 4],
            buffer: output_units.as_mut_ptr() as usize,
        };
        let original_buffer = target.buffer;
        let original_maximum_length = target.maximum_length;
        let mut returned_length = u32::MAX;
        assert_eq!(
            task.sys_nt_query_symbolic_link_object(
                handle,
                mut_ptr(&mut target),
                Some(mut_ptr(&mut returned_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(target.buffer, original_buffer);
        assert_eq!(target.maximum_length, original_maximum_length);
        assert!(usize::from(target.length) <= size_of_val(output_units));
        (target, returned_length)
    }

    #[test]
    fn create_open_and_query_symbolic_link_round_trips_target() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let target = r"\BaseNamedObjects\LiteBoxTarget";
            let created = create_link(&task, r"\BaseNamedObjects\LiteBoxSymlink", target);
            let opened = open_link(&task, r"\BaseNamedObjects\LiteBoxSymlink");
            let mut output = alloc::vec![0u16; target.encode_utf16().count()];
            let (target, returned_length) = query_link(&task, opened, &mut output);
            assert_eq!(returned_length, u32::from(target.length));
            assert_eq!(
                String::from_utf16_lossy(&output[..usize::from(target.length) / 2]),
                r"\BaseNamedObjects\LiteBoxTarget"
            );
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(created), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_symbolic_link_rejects_empty_target() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let path_units: Vec<u16> = r"\BaseNamedObjects\LiteBoxEmptyTarget"
                .encode_utf16()
                .collect();
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let empty_target = unicode_string(&[]);
            let mut handle = Handle::default();

            assert_eq!(
                task.sys_nt_create_symbolic_link_object(
                    mut_ptr(&mut handle),
                    SYMBOLIC_LINK_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    const_ptr(&empty_target),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(handle, Handle::default());
        });
    }

    #[test]
    fn open_symbolic_link_without_openlink_follows_and_detects_cycle() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let first = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxCycleA",
                r"\BaseNamedObjects\LiteBoxCycleB",
            );
            let second = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxCycleB",
                r"\BaseNamedObjects\LiteBoxCycleA",
            );
            let path_units: Vec<u16> = r"\BaseNamedObjects\LiteBoxCycleA".encode_utf16().collect();
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let mut handle = Handle::default();

            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut handle),
                    DIRECTORY_QUERY,
                    Some(const_ptr(&attrs)),
                ),
                NtStatus::NAME_TOO_LONG
            );
            assert_eq!(handle, Handle::default());
            assert_eq!(task.sys_nt_close(second), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(first), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn open_symbolic_link_openlink_returns_final_link_itself() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let created = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxOpenLinkFinal",
                r"\BaseNamedObjects\MissingTarget",
            );
            let opened = open_link(&task, r"\BaseNamedObjects\LiteBoxOpenLinkFinal");
            let mut output = [0u16; 64];
            let (target, _) = query_link(&task, opened, &mut output);

            assert_eq!(
                String::from_utf16_lossy(&output[..usize::from(target.length) / 2]),
                r"\BaseNamedObjects\MissingTarget"
            );
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(created), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn directory_open_follows_intermediate_symbolic_link() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let real = create_directory(&task, r"\BaseNamedObjects\LiteBoxRealDir");
            let child = create_directory(&task, r"\BaseNamedObjects\LiteBoxRealDir\Child");
            let link = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxDirLink",
                r"\BaseNamedObjects\LiteBoxRealDir",
            );

            let opened = open_directory(&task, r"\BaseNamedObjects\LiteBoxDirLink\Child");
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(link), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(child), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(real), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn directory_create_follows_symlinked_parent() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let real = create_directory(&task, r"\BaseNamedObjects\LiteBoxCreateRealDir");
            let link = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxCreateDirLink",
                r"\BaseNamedObjects\LiteBoxCreateRealDir",
            );
            let created = create_directory(&task, r"\BaseNamedObjects\LiteBoxCreateDirLink\Child");
            let opened = open_directory(&task, r"\BaseNamedObjects\LiteBoxCreateRealDir\Child");

            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(created), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(link), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(real), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn dos_device_style_symbolic_link_resolves_through_seeded_directory() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let real = create_directory(&task, r"\BaseNamedObjects\LiteBoxDriveTarget");
            let child = create_directory(&task, r"\BaseNamedObjects\LiteBoxDriveTarget\Child");
            let link = create_link(&task, r"\??\C:", r"\BaseNamedObjects\LiteBoxDriveTarget");

            let opened = open_directory(&task, r"\??\C:\Child");
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(link), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(child), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(real), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn open_symbolic_link_rejects_directory_type() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let path_units: Vec<u16> = r"\BaseNamedObjects".encode_utf16().collect();
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let mut handle = Handle::default();

            assert_eq!(
                task.sys_nt_open_symbolic_link_object(
                    mut_ptr(&mut handle),
                    SYMBOLIC_LINK_QUERY,
                    Some(const_ptr(&attrs)),
                ),
                NtStatus::OBJECT_TYPE_MISMATCH
            );
            assert_eq!(handle, Handle::default());
        });
    }

    #[test]
    fn create_symbolic_link_obeys_collision_and_openif() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let first = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxOpenIfSymlink",
                r"\BaseNamedObjects\Target",
            );
            let path_units: Vec<u16> = r"\BaseNamedObjects\LiteBoxOpenIfSymlink"
                .encode_utf16()
                .collect();
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let (_target_units, target) = link_target(r"\BaseNamedObjects\Target");
            let mut collision = Handle::default();

            assert_eq!(
                task.sys_nt_create_symbolic_link_object(
                    mut_ptr(&mut collision),
                    SYMBOLIC_LINK_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    const_ptr(&target),
                ),
                NtStatus::OBJECT_NAME_COLLISION
            );
            assert_eq!(collision, Handle::default());

            let openif_attrs = ObjectAttributes {
                attributes: OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
                ..attrs
            };
            let mut opened = Handle::default();
            assert_eq!(
                task.sys_nt_create_symbolic_link_object(
                    mut_ptr(&mut opened),
                    SYMBOLIC_LINK_ALL_ACCESS,
                    Some(const_ptr(&openif_attrs)),
                    const_ptr(&target),
                ),
                NtStatus::OBJECT_NAME_EXISTS
            );
            assert_ne!(opened, Handle::default());
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(first), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_symbolic_link_rejects_existing_directory_type() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let path_units: Vec<u16> = r"\BaseNamedObjects\LiteBoxSymlinkTypeDirectory"
                .encode_utf16()
                .collect();
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let mut directory = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut directory),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    Handle::default(),
                    0,
                ),
                NtStatus::SUCCESS
            );

            let (_target_units, target) = link_target(r"\BaseNamedObjects\Target");
            let mut link = Handle::default();
            assert_eq!(
                task.sys_nt_create_symbolic_link_object(
                    mut_ptr(&mut link),
                    SYMBOLIC_LINK_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    const_ptr(&target),
                ),
                NtStatus::OBJECT_TYPE_MISMATCH
            );
            assert_eq!(link, Handle::default());
            assert_eq!(task.sys_nt_close(directory), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn query_symbolic_link_reports_too_small_without_mutating_output() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let handle = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxSmallSymlink",
                r"\BaseNamedObjects\LongTarget",
            );
            let mut output = [0xeeeeu16; 2];
            let mut target = UnicodeString {
                length: 0x1234,
                maximum_length: u16::try_from(size_of_val(&output)).expect("test buffer fits"),
                padding_0: [0; 4],
                buffer: output.as_mut_ptr() as usize,
            };
            let original = target;
            let mut returned_length = 0;

            assert_eq!(
                task.sys_nt_query_symbolic_link_object(
                    handle,
                    mut_ptr(&mut target),
                    Some(mut_ptr(&mut returned_length)),
                ),
                NtStatus::BUFFER_TOO_SMALL
            );
            assert_eq!(target.length, original.length);
            assert_eq!(target.maximum_length, original.maximum_length);
            assert_eq!(target.buffer, original.buffer);
            assert_eq!(output, [0xeeeeu16; 2]);
            assert_eq!(
                returned_length,
                u32::try_from(r"\BaseNamedObjects\LongTarget".encode_utf16().count() * 2)
                    .expect("target fits")
            );
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }
}

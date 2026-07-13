// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT object-manager symbolic-link syscalls.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes, ObjectAttributesFlags, UnicodeString};
use crate::syscalls::Handle;
use crate::syscalls::object_manager::{DirectoryName, ObjectNode};
use crate::{ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value};

const STANDARD_RIGHTS_REQUIRED: u32 = AccessMask::DELETE.bits()
    | AccessMask::READ_CONTROL.bits()
    | AccessMask::WRITE_DAC.bits()
    | AccessMask::WRITE_OWNER.bits();

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SymbolicLinkAccess: u32 {
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
        Self::from_bits_retain(AccessMask::expand_generic_access(
            desired_access,
            Self::READ.bits(),
            Self::WRITE.bits(),
            Self::EXECUTE.bits(),
            Self::ALL_ACCESS.bits(),
        ))
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
        .is_none_or(|len| len > u16::MAX as usize)
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
        self.insert_typed_handle::<SymbolicLinkSubsystem<Platform>>(
            SymbolicLinkHandleObject {
                link,
                granted_access,
            },
            drop,
        )
    }

    fn close_symbolic_link_handle(&self, handle: Handle) {
        self.close_typed_handle::<SymbolicLinkSubsystem<Platform>>(handle, drop);
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
            Some(target) => match read_symbolic_link_target::<Platform>(target) {
                Ok(target) => target,
                Err(status) => return status,
            },
            None => return NtStatus::ACCESS_VIOLATION,
        };
        let attributes = ObjectAttributesFlags::from_bits_retain(object_attributes.attributes);
        if attributes.contains(ObjectAttributesFlags::OPENLINK) {
            return NtStatus::INVALID_PARAMETER;
        }

        // NT stores the target as an opaque string at creation time. Wine's
        // create_symlink only copies the target and ReactOS leaves LinkTargetObject
        // null; both defer namespace lookup until the link is traversed.
        let granted_access = SymbolicLinkAccess::from_desired_access(desired_access);
        self.create_symbolic_link(
            link_handle,
            granted_access,
            link_name,
            target,
            attributes.contains(ObjectAttributesFlags::OPENIF),
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
        self.process.object_manager.create_symlink(
            &link_name.original_path,
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
        let link_name = match self.read_directory_object_attributes(object_attributes, true) {
            Ok((Some(_), Some(link_name))) => link_name,
            Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
            Ok((None, Some(_))) => return NtStatus::INVALID_PARAMETER,
            Err(status) => return status,
        };
        let link = match self
            .process
            .object_manager
            .resolve_symlink(&link_name.original_path, false)
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

        let target = match entry.with_entry(|entry| entry.link.symlink_target().into_result()) {
            Ok(target) => target,
            Err(status) => return status,
        };
        let units = match utf16_units(&target) {
            Ok(units) => units,
            Err(status) => return status,
        };
        let required_len = units
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or(NtStatus::NAME_TOO_LONG);
        let Ok(required_len) = required_len else {
            return NtStatus::NAME_TOO_LONG;
        };
        let required = match units
            .len()
            .checked_add(1)
            .and_then(|units| units.checked_mul(size_of::<u16>()))
            .and_then(|bytes| u32::try_from(bytes).ok())
        {
            Some(required) if u16::try_from(required).is_ok() => required,
            _ => return NtStatus::NAME_TOO_LONG,
        };
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

        let mut output_units = units;
        output_units.push(0);
        let target_buffer = MutPtr::<Platform, u16>::from_usize(unicode.buffer);
        target_buffer
            .write_slice_at_offset(0, &output_units)
            .ok_or(NtStatus::ACCESS_VIOLATION)
            .map_or_else(
                |status| status,
                |()| {
                    unicode.length = required_len.trunc();
                    if link_target.write_at_offset(0, unicode).is_none() {
                        NtStatus::ACCESS_VIOLATION
                    } else {
                        NtStatus::SUCCESS
                    }
                },
            )
    }
}

fn read_symbolic_link_target<Platform: RawPointerProvider>(
    target: UnicodeString,
) -> Result<String, NtStatus> {
    // ReactOS rounds odd MaximumLength down before validating this UNICODE_STRING;
    // Wine's object-manager tests cover the zero MaximumLength rejection.
    let maximum_length = target.maximum_length & !1u16;
    if !target.length.is_multiple_of(2) || maximum_length < target.length || maximum_length == 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    let target = target.read_string::<Platform>()?;
    if target.is_empty() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use core::mem::size_of_val;

    use litebox::platform::ThreadProvider;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::{ObjectAttributes, ObjectAttributesFlags, UnicodeString};
    use crate::tests::{
        TestPlatform, const_ptr, mut_ptr, object_attributes, test_task, unicode_string,
        utf16_units as test_utf16_units,
    };

    const SYMBOLIC_LINK_QUERY: u32 = 0x0000_0001;
    const SYMBOLIC_LINK_ALL_ACCESS: u32 = 0x000f_0001;
    const DIRECTORY_QUERY: u32 = 0x0000_0001;
    const DIRECTORY_ALL_ACCESS: u32 = 0x000f_000f;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn link_target(value: &str) -> (Vec<u16>, UnicodeString) {
        let units = test_utf16_units(value);
        let unicode = unicode_string(&units);
        (units, unicode)
    }

    fn create_link(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        path: &str,
        target: &str,
    ) -> Handle {
        let path_units = test_utf16_units(path);
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
        let path_units = test_utf16_units(path);
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
        let path_units = test_utf16_units(path);
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
        let path_units = test_utf16_units(path);
        let name = unicode_string(&path_units);
        let attrs = object_attributes(
            &name,
            (ObjectAttributesFlags::CASE_INSENSITIVE | ObjectAttributesFlags::OPENLINK).bits(),
        );
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

    fn open_link_without_openlink(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        path: &str,
    ) -> Handle {
        let path_units = test_utf16_units(path);
        let name = unicode_string(&path_units);
        let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
            maximum_length: size_of_val(output_units).trunc(),
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
        assert!(target.length as usize <= size_of_val(output_units));
        assert_eq!(output_units[target.length as usize / 2], 0);
        (target, returned_length)
    }

    #[test]
    fn create_open_and_query_symbolic_link_round_trips_target() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let target = r"\BaseNamedObjects\LiteBoxTarget";
            let created = create_link(&task, r"\BaseNamedObjects\LiteBoxSymlink", target);
            let opened = open_link(&task, r"\BaseNamedObjects\LiteBoxSymlink");
            let mut output = alloc::vec![0u16; target.encode_utf16().count() + 1];
            let (target, returned_length) = query_link(&task, opened, &mut output);
            assert_eq!(returned_length, u32::from(target.length) + 2);
            assert_eq!(
                String::from_utf16_lossy(&output[..target.length as usize / 2]),
                r"\BaseNamedObjects\LiteBoxTarget"
            );
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(created), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn predefined_known_dll_path_symbolic_link_matches_loader_contract() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let opened = open_link(&task, r"\KnownDlls\KnownDllPath");
            let target = r"C:\Windows\System32";
            let mut output = alloc::vec![0u16; target.encode_utf16().count() + 1];
            let (target_string, returned_length) = query_link(&task, opened, &mut output);

            assert_eq!(returned_length, u32::from(target_string.length) + 2);
            assert_eq!(
                String::from_utf16_lossy(&output[..target_string.length as usize / 2]),
                target
            );
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_symbolic_link_rejects_empty_target() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let path_units = test_utf16_units(r"\BaseNamedObjects\LiteBoxEmptyTarget");
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
    fn create_symbolic_link_rejects_zero_target_maximum_length() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let path_units = test_utf16_units(r"\BaseNamedObjects\LiteBoxZeroTargetMax");
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let (_target_units, mut target) = link_target(r"\BaseNamedObjects\Target");
            let mut handle = Handle::default();
            target.maximum_length = 0;

            assert_eq!(
                task.sys_nt_create_symbolic_link_object(
                    mut_ptr(&mut handle),
                    SYMBOLIC_LINK_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    const_ptr(&target),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(handle, Handle::default());
        });
    }

    #[test]
    fn create_symbolic_link_rejects_target_maximum_length_shorter_than_length() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let path_units = test_utf16_units(r"\BaseNamedObjects\LiteBoxShortTargetMax");
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let (_target_units, mut target) = link_target(r"\BaseNamedObjects\Target");
            let mut handle = Handle::default();
            target.maximum_length = target.length - 2;

            assert_eq!(
                task.sys_nt_create_symbolic_link_object(
                    mut_ptr(&mut handle),
                    SYMBOLIC_LINK_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    const_ptr(&target),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(handle, Handle::default());
        });
    }

    #[test]
    fn create_symbolic_link_allows_odd_target_maximum_length_after_rounding() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let path_units = test_utf16_units(r"\BaseNamedObjects\LiteBoxOddTargetMax");
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let (_target_units, mut target) = link_target(r"\BaseNamedObjects\Target");
            let mut handle = Handle::default();
            target.maximum_length = target.length + 1;

            assert_eq!(
                task.sys_nt_create_symbolic_link_object(
                    mut_ptr(&mut handle),
                    SYMBOLIC_LINK_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    const_ptr(&target),
                ),
                NtStatus::SUCCESS
            );
            assert_ne!(handle, Handle::default());
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn open_symbolic_link_without_openlink_returns_final_link_itself() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let created = create_link(
                &task,
                r"\BaseNamedObjects\LiteBoxNoOpenLinkFinal",
                r"\BaseNamedObjects\MissingTarget",
            );
            let opened =
                open_link_without_openlink(&task, r"\BaseNamedObjects\LiteBoxNoOpenLinkFinal");
            let mut output = [0u16; 64];
            let (target, _) = query_link(&task, opened, &mut output);

            assert_eq!(
                String::from_utf16_lossy(&output[..target.length as usize / 2]),
                r"\BaseNamedObjects\MissingTarget"
            );
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(created), NtStatus::SUCCESS);
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
                String::from_utf16_lossy(&output[..target.length as usize / 2]),
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
            let link = create_link(&task, r"\??\Z:", r"\BaseNamedObjects\LiteBoxDriveTarget");

            let opened = open_directory(&task, r"\??\Z:\Child");
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
            let path_units = test_utf16_units(r"\BaseNamedObjects");
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
            let path_units = test_utf16_units(r"\BaseNamedObjects\LiteBoxOpenIfSymlink");
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
                attributes: (ObjectAttributesFlags::CASE_INSENSITIVE
                    | ObjectAttributesFlags::OPENIF)
                    .bits(),
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
            let path_units = test_utf16_units(r"\BaseNamedObjects\LiteBoxSymlinkTypeDirectory");
            let name = unicode_string(&path_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
                maximum_length: size_of_val(&output).trunc(),
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
                ((r"\BaseNamedObjects\LongTarget".encode_utf16().count() + 1) * 2).trunc()
            );
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn query_symbolic_link_requires_space_for_trailing_nul() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let target = r"\BaseNamedObjects\ExactLengthTarget";
            let handle = create_link(&task, r"\BaseNamedObjects\LiteBoxExactSymlink", target);
            let mut output = alloc::vec![0xeeeeu16; target.encode_utf16().count()];
            let mut target_string = UnicodeString {
                length: 0x1234,
                maximum_length: size_of_val(output.as_slice()).trunc(),
                padding_0: [0; 4],
                buffer: output.as_mut_ptr() as usize,
            };
            let mut returned_length = 0;

            assert_eq!(
                task.sys_nt_query_symbolic_link_object(
                    handle,
                    mut_ptr(&mut target_string),
                    Some(mut_ptr(&mut returned_length)),
                ),
                NtStatus::BUFFER_TOO_SMALL
            );
            assert_eq!(
                returned_length,
                ((target.encode_utf16().count() + 1) * 2).trunc()
            );
            assert!(output.iter().all(|unit| *unit == 0xeeee));
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }
}

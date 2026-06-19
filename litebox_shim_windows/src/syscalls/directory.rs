// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT object-manager directory syscalls.

use alloc::string::{String, ToString as _};
use alloc::sync::Arc;
use core::marker::PhantomData;

use litebox::fd::{ErrRawIntFd, FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes, UnicodeString, read_object_attributes};
use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, insert_raw_handle, probe_guest_output_preserving_value,
    remove_raw_handle,
};

const OBJ_OPENIF: u32 = 0x0000_0080;
const OBJ_OPENLINK: u32 = 0x0000_0100;
const STANDARD_RIGHTS_REQUIRED: u32 = AccessMask::DELETE.bits()
    | AccessMask::READ_CONTROL.bits()
    | AccessMask::WRITE_DAC.bits()
    | AccessMask::WRITE_OWNER.bits();

// Wine's server seeds these object-manager directories during init_directories/create_session;
// ReactOS initializes the same root-style namespace through ObpRootDirectoryObject.
pub(crate) const SEEDED_DIRECTORY_PATHS: &[&str] = &[
    r"\",
    r"\??",
    r"\BaseNamedObjects",
    r"\Device",
    r"\Driver",
    r"\KnownDlls",
    r"\KernelObjects",
    r"\NLS",
    r"\ObjectTypes",
    r"\Sessions",
    r"\Sessions\0",
    r"\Sessions\0\BaseNamedObjects",
    r"\Sessions\0\DosDevices",
    r"\Sessions\0\Windows",
    r"\Sessions\0\Windows\WindowStations",
    r"\Sessions\BNOLINKS",
];

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct DirectoryAccess: u32 {
        const QUERY = 0x0001;
        const TRAVERSE = 0x0002;
        const CREATE_OBJECT = 0x0004;
        const CREATE_SUBDIRECTORY = 0x0008;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::QUERY.bits()
            | Self::TRAVERSE.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::CREATE_OBJECT.bits()
            | Self::CREATE_SUBDIRECTORY.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | Self::QUERY.bits()
            | Self::TRAVERSE.bits();
        const ALL_ACCESS = STANDARD_RIGHTS_REQUIRED
            | Self::QUERY.bits()
            | Self::TRAVERSE.bits()
            | Self::CREATE_OBJECT.bits()
            | Self::CREATE_SUBDIRECTORY.bits();

        const _ = !0;
    }
}

impl DirectoryAccess {
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

pub(crate) struct DirectoryObjectSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for DirectoryObjectSubsystem<Platform> {
    type Entry = DirectoryHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for DirectoryHandleObject<Platform> {}

pub(crate) struct DirectoryHandleObject<Platform: crate::ShimPlatform> {
    directory: Arc<DirectoryObject<Platform>>,
    granted_access: DirectoryAccess,
}

pub(crate) struct DirectoryObject<Platform: crate::ShimPlatform> {
    path: String,
    _not_send_without_platform: PhantomData<fn(Platform)>,
}

pub(crate) struct DirectoryCreateParameters<Platform: RawPointerProvider> {
    pub(crate) directory_handle: MutPtr<Platform, Handle>,
    pub(crate) desired_access: u32,
    pub(crate) object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    pub(crate) shadow_directory_handle: Handle,
    pub(crate) flags: u32,
}

pub(crate) struct DirectoryQueryParameters<Platform: RawPointerProvider> {
    pub(crate) directory_handle: Handle,
    pub(crate) buffer: MutPtr<Platform, u8>,
    pub(crate) buffer_length: u32,
    pub(crate) return_single_entry: u8,
    pub(crate) restart_scan: u8,
    pub(crate) context: MutPtr<Platform, u32>,
    pub(crate) return_length: Option<MutPtr<Platform, u32>>,
}

impl<Platform: crate::ShimPlatform> DirectoryObject<Platform> {
    fn new(path: String) -> Self {
        Self {
            path,
            _not_send_without_platform: PhantomData,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryName {
    path: String,
}

fn normalize_directory_path(path: &str) -> String {
    if path == r"\" {
        return r"\".to_string();
    }
    path.trim_end_matches('\\').to_ascii_lowercase()
}

fn parent_directory_path(path: &str) -> Option<String> {
    if path == r"\" {
        return None;
    }
    let index = path.rfind('\\')?;
    if index == 0 {
        Some(r"\".to_string())
    } else {
        Some(path[..index].to_string())
    }
}

fn join_directory_path(root_path: &str, name: &str) -> String {
    if root_path == r"\" {
        alloc::format!(r"\{name}")
    } else {
        alloc::format!(r"{root_path}\{name}")
    }
}

fn read_directory_name_string<Platform: RawPointerProvider>(
    object_name: usize,
) -> Result<Option<String>, NtStatus> {
    if object_name == 0 {
        return Ok(None);
    }
    let unicode_string = ConstPtr::<Platform, UnicodeString>::from_usize(object_name)
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    if unicode_string.length == 0 {
        return Ok(None);
    }
    if !unicode_string.length.is_multiple_of(2) {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    if unicode_string.buffer == 0 {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    Ok(Some(unicode_string.read_string::<Platform>()?))
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn directory_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, DirectoryObjectSubsystem<Platform>>, NtStatus>
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<DirectoryObjectSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn directory_object_for_name_resolution(
        &self,
        handle: Handle,
    ) -> Result<Arc<DirectoryObject<Platform>>, NtStatus> {
        let entry = self.directory_entry(handle)?;
        Ok(entry.with_entry(|entry| Arc::clone(&entry.directory)))
    }

    fn read_directory_object_attributes(
        &self,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        require_name: bool,
    ) -> Result<(Option<ObjectAttributes>, Option<DirectoryName>), NtStatus> {
        let Some(object_attributes_ptr) = object_attributes else {
            if require_name {
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            return Ok((None, None));
        };
        let object_attributes = read_object_attributes::<Platform>(object_attributes_ptr)?;
        if object_attributes.attributes & OBJ_OPENLINK != 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        let Some(raw_name) = read_directory_name_string::<Platform>(object_attributes.object_name)?
        else {
            if require_name {
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            return Ok((Some(object_attributes), None));
        };
        if raw_name.is_empty() {
            if require_name {
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            return Ok((Some(object_attributes), None));
        }

        let path = if object_attributes.root_directory.is_null() {
            if !raw_name.starts_with('\\') {
                return Err(NtStatus::OBJECT_PATH_SYNTAX_BAD);
            }
            raw_name
        } else {
            if raw_name.starts_with('\\') {
                return Err(NtStatus::OBJECT_PATH_SYNTAX_BAD);
            }
            let root =
                self.directory_object_for_name_resolution(object_attributes.root_directory)?;
            join_directory_path(&root.path, &raw_name)
        };
        if path.len() > 1 && path[1..].contains(r"\\") {
            return Err(NtStatus::OBJECT_NAME_INVALID);
        }
        // The initial directory namespace follows the NT default of case-insensitive lookup.
        let path = normalize_directory_path(&path);
        Ok((Some(object_attributes), Some(DirectoryName { path })))
    }

    fn insert_directory_handle(
        &self,
        directory: Arc<DirectoryObject<Platform>>,
        granted_access: DirectoryAccess,
    ) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<DirectoryObjectSubsystem<Platform>>(DirectoryHandleObject {
                directory,
                granted_access,
            });
        insert_raw_handle::<Platform, DirectoryObjectSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_directory_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, DirectoryObjectSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_directory(directory: DirectoryHandleObject<Platform>) {
        drop(directory);
    }

    pub(crate) fn sys_nt_create_directory_object(
        &self,
        params: DirectoryCreateParameters<Platform>,
    ) -> NtStatus {
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, _>(params.directory_handle)
        {
            return status;
        }
        if params.flags != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        if !params.shadow_directory_handle.is_null()
            && let Err(status) = self.directory_entry(params.shadow_directory_handle)
        {
            return status;
        }
        let (object_attributes, directory_name) =
            match self.read_directory_object_attributes(params.object_attributes, false) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let granted_access = DirectoryAccess::from_desired_access(params.desired_access);

        if let Some(directory_name) = directory_name {
            let mut namespace = self.process.directory_namespace.write();
            if let Some(directory) = namespace.get(&directory_name.path).cloned() {
                let Some(object_attributes) = object_attributes else {
                    return NtStatus::INVALID_PARAMETER;
                };
                if object_attributes.attributes & OBJ_OPENIF == 0 {
                    return NtStatus::OBJECT_NAME_COLLISION;
                }
                let Ok(handle) = self.insert_directory_handle(directory, granted_access) else {
                    return NtStatus::QUOTA_EXCEEDED;
                };
                if params.directory_handle.write_at_offset(0, handle).is_none() {
                    self.close_directory_handle(handle);
                    return NtStatus::ACCESS_VIOLATION;
                }
                return NtStatus::OBJECT_NAME_EXISTS;
            }
            let Some(parent) = parent_directory_path(&directory_name.path) else {
                return NtStatus::OBJECT_NAME_COLLISION;
            };
            if !namespace.contains_key(&parent) {
                return NtStatus::OBJECT_PATH_NOT_FOUND;
            }
            // TODO: model non-permanent directory lifetime instead of keeping created names
            // alive until process teardown.
            let directory = Arc::new(DirectoryObject::new(directory_name.path.clone()));
            let Ok(handle) = self.insert_directory_handle(directory.clone(), granted_access) else {
                return NtStatus::QUOTA_EXCEEDED;
            };
            if params.directory_handle.write_at_offset(0, handle).is_none() {
                self.close_directory_handle(handle);
                return NtStatus::ACCESS_VIOLATION;
            }
            namespace.insert(directory_name.path, directory);
            return NtStatus::SUCCESS;
        }

        let directory = Arc::new(DirectoryObject::new(String::new()));
        let Ok(handle) = self.insert_directory_handle(directory, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if params.directory_handle.write_at_offset(0, handle).is_none() {
            self.close_directory_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_open_directory_object(
        &self,
        directory_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(directory_handle) {
            return status;
        }
        let directory_name = match self.read_directory_object_attributes(object_attributes, true) {
            Ok((_, Some(directory_name))) => directory_name,
            Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
            Err(status) => return status,
        };
        let directory = {
            let namespace = self.process.directory_namespace.read();
            let Some(directory) = namespace.get(&directory_name.path) else {
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            };
            directory.clone()
        };
        let Ok(handle) = self.insert_directory_handle(
            directory,
            DirectoryAccess::from_desired_access(desired_access),
        ) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if directory_handle.write_at_offset(0, handle).is_none() {
            self.close_directory_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        litebox_util_log::debug!(
            object_name:% = directory_name.path.as_str(),
            desired_access:% = format_args!("{desired_access:#x}");
            "Handled NtOpenDirectoryObject syscall"
        );
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_directory_object(
        &self,
        params: DirectoryQueryParameters<Platform>,
    ) -> NtStatus {
        let entry = match self.directory_entry(params.directory_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        if let Err(status) =
            entry.with_entry(|entry| entry.granted_access.require(DirectoryAccess::QUERY))
        {
            return status;
        }
        let _ = params.buffer_length;
        let _ = params.return_single_entry;

        if params.buffer.write_at_offset(0, 0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if params.restart_scan == 0 && params.context.read_at_offset(0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if params.context.write_at_offset(0, 0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = params.return_length
            && return_length.write_at_offset(0, 0).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        // TODO: track directory membership and write OBJECT_DIRECTORY_INFORMATION records.
        // This initial object-manager subset honestly reports seeded directories as empty.
        NtStatus::NO_MORE_ENTRIES
    }
}

pub(crate) fn seed_directory_namespace<Platform: crate::ShimPlatform>()
-> crate::WindowsDirectoryNamespace<Platform> {
    let mut namespace = alloc::collections::BTreeMap::new();
    for path in SEEDED_DIRECTORY_PATHS {
        let path = normalize_directory_path(path);
        namespace.insert(path.clone(), Arc::new(DirectoryObject::new(path)));
    }
    crate::WindowsDirectoryNamespace::<Platform>::new(namespace)
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::platform::ThreadProvider;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::ObjectAttributes;
    use crate::tests::{
        TestPlatform, const_ptr, mut_ptr, null_mut_ptr, object_attributes, test_task,
        unicode_string,
    };

    const DIRECTORY_QUERY: u32 = 0x0000_0001;
    const DIRECTORY_TRAVERSE: u32 = 0x0000_0002;
    const DIRECTORY_ALL_ACCESS: u32 = 0x000f_000f;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn directory_create_params(
        handle: &mut Handle,
        object_attributes: Option<ConstPtr<TestPlatform, ObjectAttributes>>,
    ) -> DirectoryCreateParameters<TestPlatform> {
        DirectoryCreateParameters {
            directory_handle: mut_ptr(handle),
            desired_access: DIRECTORY_ALL_ACCESS,
            object_attributes,
            shadow_directory_handle: Handle::default(),
            flags: 0,
        }
    }

    #[test]
    fn open_seeded_root_directory_succeeds() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units: alloc::vec::Vec<u16> = r"\".encode_utf16().collect();
            let name = unicode_string(&name_units);
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
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_and_open_directory_relative_to_root_directory() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let root_units: alloc::vec::Vec<u16> = r"\BaseNamedObjects".encode_utf16().collect();
            let root_name = unicode_string(&root_units);
            let root_attrs = object_attributes(&root_name, OBJ_CASE_INSENSITIVE);
            let mut root = Handle::default();
            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut root),
                    DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
                    Some(const_ptr(&root_attrs)),
                ),
                NtStatus::SUCCESS
            );

            let child_units: alloc::vec::Vec<u16> = "LiteBoxDirectory".encode_utf16().collect();
            let child_name = unicode_string(&child_units);
            let child_attrs = ObjectAttributes {
                length: u32::try_from(size_of::<ObjectAttributes>()).expect("fits in ULONG"),
                root_directory: root,
                object_name: core::ptr::from_ref(&child_name) as usize,
                attributes: OBJ_CASE_INSENSITIVE,
                security_descriptor: 0,
                security_quality_of_service: 0,
            };
            let mut created = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(directory_create_params(
                    &mut created,
                    Some(const_ptr(&child_attrs)),
                )),
                NtStatus::SUCCESS
            );

            let mut opened = Handle::default();
            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut opened),
                    DIRECTORY_QUERY,
                    Some(const_ptr(&child_attrs)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(created), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(root), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_existing_directory_obeys_openif() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units: alloc::vec::Vec<u16> = r"\BaseNamedObjects\LiteBoxOpenIfDirectory"
                .encode_utf16()
                .collect();
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let mut first = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(directory_create_params(
                    &mut first,
                    Some(const_ptr(&attrs)),
                )),
                NtStatus::SUCCESS
            );

            let mut collision = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(directory_create_params(
                    &mut collision,
                    Some(const_ptr(&attrs)),
                )),
                NtStatus::OBJECT_NAME_COLLISION
            );
            assert_eq!(collision, Handle::default());

            let openif_attrs = ObjectAttributes {
                attributes: OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
                ..attrs
            };
            let mut opened = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(directory_create_params(
                    &mut opened,
                    Some(const_ptr(&openif_attrs)),
                )),
                NtStatus::OBJECT_NAME_EXISTS
            );
            assert_ne!(opened, Handle::default());
            assert_eq!(task.sys_nt_close(opened), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(first), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn query_empty_directory_reports_no_more_entries() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units: alloc::vec::Vec<u16> = r"\BaseNamedObjects".encode_utf16().collect();
            let name = unicode_string(&name_units);
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

            let mut buffer = [0xffu8; 32];
            let mut context = 99u32;
            let mut return_length = u32::MAX;
            assert_eq!(
                task.sys_nt_query_directory_object(DirectoryQueryParameters {
                    directory_handle: handle,
                    buffer: mut_ptr(&mut buffer[0]),
                    buffer_length: u32::try_from(buffer.len()).expect("test buffer fits in ULONG"),
                    return_single_entry: 0,
                    restart_scan: 1,
                    context: mut_ptr(&mut context),
                    return_length: Some(mut_ptr(&mut return_length)),
                },),
                NtStatus::NO_MORE_ENTRIES
            );
            assert_eq!(buffer[0], 0);
            assert_eq!(context, 0);
            assert_eq!(return_length, 0);
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn query_requires_directory_query_access() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units: alloc::vec::Vec<u16> = r"\BaseNamedObjects".encode_utf16().collect();
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let mut handle = Handle::default();
            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut handle),
                    DIRECTORY_TRAVERSE,
                    Some(const_ptr(&attrs)),
                ),
                NtStatus::SUCCESS
            );
            let mut buffer = 0u8;
            let mut context = 0u32;
            assert_eq!(
                task.sys_nt_query_directory_object(DirectoryQueryParameters {
                    directory_handle: handle,
                    buffer: mut_ptr(&mut buffer),
                    buffer_length: 1,
                    return_single_entry: 0,
                    restart_scan: 1,
                    context: mut_ptr(&mut context),
                    return_length: None,
                },),
                NtStatus::ACCESS_DENIED
            );
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_probes_output_before_name_resolution() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units: alloc::vec::Vec<u16> = r"\MissingParent\Child".encode_utf16().collect();
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);

            assert_eq!(
                task.sys_nt_create_directory_object(DirectoryCreateParameters {
                    directory_handle: null_mut_ptr(),
                    desired_access: DIRECTORY_ALL_ACCESS,
                    object_attributes: Some(const_ptr(&attrs)),
                    shadow_directory_handle: Handle::default(),
                    flags: 0,
                }),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_open_root_directory_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtOpenDirectoryObject(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units: alloc::vec::Vec<u16> = r"\".encode_utf16().collect();
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
            let mut host_handle = core::ptr::null_mut();
            let host_status = unsafe {
                NtOpenDirectoryObject(&raw mut host_handle, DIRECTORY_QUERY, &raw const attrs)
            };
            if host_status == NtStatus::SUCCESS.as_raw() && !host_handle.is_null() {
                unsafe {
                    NtClose(host_handle);
                }
            }

            let mut litebox_handle = Handle::default();
            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut litebox_handle),
                    DIRECTORY_QUERY,
                    Some(const_ptr(&attrs)),
                )
                .as_raw(),
                host_status
            );
            if litebox_handle != Handle::default() {
                assert_eq!(task.sys_nt_close(litebox_handle), NtStatus::SUCCESS);
            }
        });
    }
}

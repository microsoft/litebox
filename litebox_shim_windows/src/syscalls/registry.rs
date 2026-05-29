// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows registry syscalls backed by a private file-system-shaped store (i.e.,
//! a layered file system with in-mem and tar filesystems).
//!
//! Registry keys are represented as directories and values as files under each
//! key's `.values` directory:
//!
//! ```text
//! /registry/machine/system/currentcontrolset/control/nls/codepage/
//!     .values/
//!         acp
//!         oemcp
//!         maccp
//!         ...
//!     EUDCCodeRange/
//!         .values/
//!             932
//!             ...
//!     ...
//! ```
//!
//! This is only an implementation detail: syscall handlers must expose registry
//! object semantics rather than file semantics.

use core::mem::{offset_of, size_of};

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use int_enum::IntEnum;
use litebox::LiteBox;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::fs::errors::{
    FileStatusError, MkdirError, OpenError, PathError, ReadError, WriteError,
};
use litebox::fs::{FileSystem as _, FileType, Mode, OFlags};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt;
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, insert_raw_handle, raw_handle_entry, remove_raw_handle,
};

use crate::nt_types::{ObjectAttributes, UnicodeString, read_object_attributes};

struct RegistryKeySubsystem;

impl FdEnabledSubsystem for RegistryKeySubsystem {
    type Entry = RegistryKeyObject;
}

impl FdEnabledSubsystemEntry for RegistryKeyObject {}

struct RegistryKeyObject {
    path: String,
}

type RegistryFileSystem = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::tar_ro::FileSystem<Platform>,
>;

pub(crate) struct RegistryStore {
    fs: RegistryFileSystem,
}

const VALUES_DIR_NAME: &str = ".values";
const DEFAULT_CODE_PAGE_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage";
const DEFAULT_SESSION_MANAGER_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager";
const DEFAULT_SEGMENT_HEAP_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
const DEFAULT_IMAGE_FILE_EXECUTION_OPTIONS_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
const DEFAULT_ACP_VALUE: &[u8] = &[b'1', 0, b'2', 0, b'5', 0, b'2', 0, 0, 0];
const DEFAULT_OEMCP_VALUE: &[u8] = &[b'4', 0, b'3', 0, b'7', 0, 0, 0];
const DEFAULT_MACCP_VALUE: &[u8] = &[b'1', 0, b'0', 0, b'0', 0, b'0', 0, b'0', 0, 0, 0];
const REGISTRY_VALUE_TYPE_SIZE: usize = size_of::<u32>();

/// System-defined `REG_*` value types stored in `KEY_VALUE_*_INFORMATION::Type`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum RegistryValueType {
    /// `REG_NONE`: data with no particular type.
    None = 0,
    /// `REG_SZ`: a null-terminated Unicode string.
    Sz = 1,
    /// `REG_EXPAND_SZ`: a null-terminated Unicode string with unexpanded environment references.
    ExpandSz = 2,
    /// `REG_BINARY`: binary data in any form.
    Binary = 3,
    /// `REG_DWORD` / `REG_DWORD_LITTLE_ENDIAN`: a little-endian 4-byte value.
    Dword = 4,
    /// `REG_DWORD_BIG_ENDIAN`: a big-endian 4-byte value.
    DwordBigEndian = 5,
    /// `REG_LINK`: a Unicode string naming a symbolic link.
    Link = 6,
    /// `REG_MULTI_SZ`: null-terminated strings terminated by another zero.
    MultiSz = 7,
    /// `REG_RESOURCE_LIST`: a device driver's hardware resource list.
    ResourceList = 8,
    /// `REG_FULL_RESOURCE_DESCRIPTOR`: hardware resources used by a physical device.
    FullResourceDescriptor = 9,
    /// `REG_RESOURCE_REQUIREMENTS_LIST`: possible hardware resources for a device.
    ResourceRequirementsList = 10,
    /// `REG_QWORD` / `REG_QWORD_LITTLE_ENDIAN`: a little-endian 8-byte value.
    Qword = 11,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum KeyValueInformationClass {
    Basic = 0,
    Full = 1,
    Partial = 2,
}

/// The `KEY_VALUE_BASIC_INFORMATION` structure defines a subset of the full
/// information available for a value entry of a registry key.
///
/// The variable-length `Name` field follows this fixed-size header.
/// See <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_basic_information>.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyValueBasicInformation {
    title_index: u32,
    value_type: u32,
    name_length: u32,
    // Followed by a variable-length name.
    name: [u8; 0],
}

/// The `KEY_VALUE_FULL_INFORMATION` structure defines information available
/// for a value entry of a registry key.
///
/// The variable-length `Name` field follows this fixed-size header. The value
/// data starts at `data_offset` after any alignment padding.
/// See <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_full_information>.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyValueFullInformation {
    title_index: u32,
    value_type: u32,
    data_offset: u32,
    data_length: u32,
    name_length: u32,
    // Followed by a variable-length name and aligned value data.
    name: [u8; 0],
    // Followed by aligned value data.
    // ...
    // Data[u8; data_length];
}

/// The `KEY_VALUE_PARTIAL_INFORMATION` structure defines a subset of the value
/// information available for a value entry of a registry key.
///
/// The variable-length `Data` field follows this fixed-size header.
/// See <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_partial_information>.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyValuePartialInformation {
    title_index: u32,
    value_type: u32,
    data_length: u32,
    // Followed by variable-length value data.
    data: [u8; 0],
}

struct RegistryValue {
    value_type: RegistryValueType,
    data: Vec<u8>,
}

impl RegistryStore {
    pub(crate) fn new(litebox: &LiteBox<Platform>) -> Self {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            for key in [
                DEFAULT_SESSION_MANAGER_KEY,
                DEFAULT_SEGMENT_HEAP_KEY,
                DEFAULT_IMAGE_FILE_EXECUTION_OPTIONS_KEY,
            ] {
                if let Err(status) = create_key_in_fs(fs, key) {
                    litebox_util_log::error!(key:% = key, status:? = status; "failed to initialize registry key");
                    break;
                }
            }
            for (name, value) in [
                ("ACP", DEFAULT_ACP_VALUE),
                ("OEMCP", DEFAULT_OEMCP_VALUE),
                ("MACCP", DEFAULT_MACCP_VALUE),
            ] {
                if let Err(status) =
                    write_value_in_fs(fs, DEFAULT_CODE_PAGE_KEY, name, RegistryValueType::Sz, value)
                {
                    litebox_util_log::error!(name:% = name, status:? = status; "failed to initialize registry value");
                    break;
                }
            }
        });

        let fs = litebox::fs::layered::FileSystem::new(
            litebox,
            in_mem,
            litebox::fs::tar_ro::FileSystem::new(
                litebox,
                // TODO: Replace with tar file provided by the user
                litebox::fs::tar_ro::EMPTY_TAR_FILE.into(),
            ),
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        );

        Self { fs }
    }

    fn key_exists(&self, path: &str) -> Result<bool, NtStatus> {
        match self.fs.file_status(path) {
            Ok(status) => Ok(status.file_type == FileType::Directory),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => Ok(false),
            Err(FileStatusError::PathError(error)) => {
                Err(map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND))
            }
            Err(_) => Err(NtStatus::UNSUCCESSFUL),
        }
    }

    fn read_value(&self, key_path: &str, value_name: &str) -> Result<RegistryValue, NtStatus> {
        let value_path = value_path(key_path, value_name)?;
        let status = self
            .fs
            .file_status(&*value_path)
            .map_err(map_file_status_error)?;
        if status.file_type != FileType::RegularFile {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        if status.size < REGISTRY_VALUE_TYPE_SIZE {
            return Err(NtStatus::UNSUCCESSFUL);
        }

        let fd = self
            .fs
            .open(&*value_path, OFlags::RDONLY, Mode::empty())
            .map_err(map_open_error)?;
        let mut data = vec![0; status.size];
        let read = self
            .fs
            .read(&fd, &mut data, Some(0))
            .map_err(map_read_error)?;
        let _ = self.fs.close(&fd);
        if read != data.len() {
            return Err(NtStatus::UNSUCCESSFUL);
        }

        let value_type = RegistryValueType::try_from(u32::from_le_bytes(
            data[..REGISTRY_VALUE_TYPE_SIZE]
                .try_into()
                .map_err(|_| NtStatus::UNSUCCESSFUL)?,
        ))
        .map_err(|_| NtStatus::UNSUCCESSFUL)?;
        data.drain(..REGISTRY_VALUE_TYPE_SIZE);

        Ok(RegistryValue { value_type, data })
    }
}

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn sys_nt_open_key(
        &self,
        key_handle: MutPtr<Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<ObjectAttributes>>,
    ) -> NtStatus {
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        match self.do_nt_open_key(desired_access, object_attributes) {
            Ok(handle) => {
                if key_handle.write_at_offset(0, handle).is_none() {
                    remove_raw_handle::<RegistryKeySubsystem>(
                        &self.global.litebox,
                        &self.process.handles,
                        handle,
                    );
                    return NtStatus::ACCESS_VIOLATION;
                }

                NtStatus::SUCCESS
            }
            Err(status) => status,
        }
    }

    fn do_nt_open_key(
        &self,
        desired_access: u32,
        object_attributes: ObjectAttributes,
    ) -> Result<Handle, NtStatus> {
        if object_attributes.object_name == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        let object_name_ptr = ConstPtr::<UnicodeString>::from_usize(object_attributes.object_name);
        let object_name = object_name_ptr
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
        let key_name = String::try_from(object_name)?;
        let path = if object_attributes.root_directory.is_null() || key_name.starts_with('\\') {
            absolute_nt_key_name_to_fs_path(&key_name)?
        } else {
            let root_key = raw_handle_entry::<RegistryKeySubsystem>(
                &self.global.litebox,
                &self.process.handles,
                object_attributes.root_directory,
            )
            .ok_or(NtStatus::INVALID_HANDLE)?;
            root_key
                .with_entry(|root_key| relative_nt_key_name_to_fs_path(&root_key.path, &key_name))?
        };

        match self.global.registry.key_exists(&path) {
            Ok(true) => {}
            Ok(false) => {
                return Err(NtStatus::OBJECT_NAME_NOT_FOUND);
            }
            Err(status) => {
                litebox_util_log::debug!(
                    desired_access:% = format_args!("{desired_access:#x}"),
                    root_directory:% = format_args!("{:#x}", object_attributes.root_directory.as_raw()),
                    name:% = key_name,
                    path:% = path,
                    status:? = status;
                    "NtOpenKey failed"
                );
                return Err(status);
            }
        }

        let key = RegistryKeyObject { path };
        let mut descriptor_table = self.global.litebox.descriptor_table_mut();
        let typed = descriptor_table.insert::<RegistryKeySubsystem>(key);
        drop(descriptor_table);

        insert_raw_handle(&self.global.litebox, &self.process.handles, typed)
    }

    pub(crate) fn sys_nt_query_value_key(
        &self,
        key_handle: Handle,
        value_name: ConstPtr<UnicodeString>,
        key_value_information_class: u32,
        key_value_information: MutPtr<u8>,
        length: u32,
        result_length: MutPtr<u32>,
    ) -> NtStatus {
        let Some(value_name) = value_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Ok(key_value_information_class) =
            KeyValueInformationClass::try_from(key_value_information_class)
        else {
            litebox_util_log::debug!(
                key_value_information_class = key_value_information_class;
                "Unsupported NtQueryValueKey class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };
        match self.do_nt_query_value_key(
            key_handle,
            value_name,
            key_value_information_class,
            key_value_information,
            length,
            result_length,
        ) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    fn do_nt_query_value_key(
        &self,
        key_handle: Handle,
        value_name: UnicodeString,
        key_value_information_class: KeyValueInformationClass,
        key_value_information: MutPtr<u8>,
        length: u32,
        result_length: MutPtr<u32>,
    ) -> Result<(), NtStatus> {
        let key = raw_handle_entry::<RegistryKeySubsystem>(
            &self.global.litebox,
            &self.process.handles,
            key_handle,
        )
        .ok_or(NtStatus::INVALID_HANDLE)?;
        let value_name = String::try_from(value_name)?;
        let value =
            key.with_entry(|key| self.global.registry.read_value(&key.path, &value_name))?;
        let name = utf16le(&value_name);
        match key_value_information_class {
            KeyValueInformationClass::Basic => {
                let required_length = size_of::<KeyValueBasicInformation>()
                    .checked_add(name.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let information = KeyValueBasicInformation {
                    title_index: 0,
                    value_type: value.value_type.into(),
                    name_length: name.len().trunc(),
                    name: [0u8; 0],
                };
                write_query_result_length(result_length, length, required_length)?;
                write_query_information(
                    key_value_information,
                    information.as_bytes(),
                    &[(offset_of!(KeyValueBasicInformation, name), name.as_slice())],
                )?;
            }
            KeyValueInformationClass::Full => {
                let name_end = offset_of!(KeyValueFullInformation, name)
                    .checked_add(name.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let data_offset = name_end
                    .checked_next_multiple_of(4)
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let required_length = data_offset
                    .checked_add(value.data.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                write_query_result_length(result_length, length, required_length)?;
                let information = KeyValueFullInformation {
                    title_index: 0,
                    value_type: value.value_type.into(),
                    data_offset: data_offset.trunc(),
                    data_length: value.data.len().trunc(),
                    name_length: name.len().trunc(),
                    name: [0u8; 0],
                };

                write_query_information(
                    key_value_information,
                    information.as_bytes(),
                    &[
                        (offset_of!(KeyValueFullInformation, name), name.as_slice()),
                        (data_offset, value.data.as_slice()),
                    ],
                )?;
            }
            KeyValueInformationClass::Partial => {
                let required_length = size_of::<KeyValuePartialInformation>()
                    .checked_add(value.data.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                write_query_result_length(result_length, length, required_length)?;
                let information = KeyValuePartialInformation {
                    title_index: 0,
                    value_type: value.value_type.into(),
                    data_length: value.data.len().trunc(),
                    data: [0u8; 0],
                };

                write_query_information(
                    key_value_information,
                    information.as_bytes(),
                    &[(
                        offset_of!(KeyValuePartialInformation, data),
                        value.data.as_slice(),
                    )],
                )?;
            }
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", key_handle.as_raw()),
            value_name:% = value_name,
            key_value_information_class:? = key_value_information_class,
            length = length;
            "Handled NtQueryValueKey syscall"
        );

        Ok(())
    }
}

fn write_query_result_length(
    result_length: MutPtr<u32>,
    buffer_length: u32,
    required_length: usize,
) -> Result<(), NtStatus> {
    result_length
        .write_at_offset(0, required_length.trunc())
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    if (buffer_length as usize) < required_length {
        return Err(NtStatus::BUFFER_OVERFLOW);
    }
    Ok(())
}

fn write_query_information(
    key_value_information: MutPtr<u8>,
    header: &[u8],
    trailing_slices: &[(usize, &[u8])],
) -> Result<(), NtStatus> {
    key_value_information
        .write_slice_at_offset(0, header)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    for &(offset, bytes) in trailing_slices {
        key_value_information
            .write_slice_at_offset(offset.cast_signed(), bytes)
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
    }
    Ok(())
}

fn utf16le(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes
}

fn absolute_nt_key_name_to_fs_path(name: &str) -> Result<String, NtStatus> {
    if !name.starts_with('\\') {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let mut path = String::from("/");
    append_registry_components(&mut path, name.trim_start_matches('\\'))?;
    Ok(path)
}

fn relative_nt_key_name_to_fs_path(root: &str, name: &str) -> Result<String, NtStatus> {
    if name.starts_with('\\') {
        return absolute_nt_key_name_to_fs_path(name);
    }
    let mut path = String::from(root);
    append_registry_components(&mut path, name)?;
    Ok(path)
}

fn append_registry_components(path: &mut String, name: &str) -> Result<(), NtStatus> {
    if name.is_empty() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    for component in name.split('\\') {
        if !is_valid_key_component(component) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(&component.to_ascii_lowercase());
    }
    Ok(())
}

fn is_valid_key_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.eq_ignore_ascii_case(VALUES_DIR_NAME)
        && !component.contains('/')
}

fn write_value_in_fs<FS: litebox::fs::FileSystem>(
    fs: &FS,
    key_nt_path: &str,
    value_name: &str,
    value_type: RegistryValueType,
    value: &[u8],
) -> Result<(), NtStatus> {
    let key_path = create_key_in_fs(fs, key_nt_path)?;
    let value_path = value_path(&key_path, value_name)?;
    let fd = fs
        .open(
            &*value_path,
            OFlags::CREAT | OFlags::WRONLY | OFlags::TRUNC,
            Mode::RUSR | Mode::WUSR | Mode::ROTH | Mode::WOTH,
        )
        .map_err(map_open_error)?;
    let written = fs
        .write(&fd, &u32::from(value_type).to_le_bytes(), Some(0))
        .map_err(map_write_error)?;
    if written != REGISTRY_VALUE_TYPE_SIZE {
        return Err(NtStatus::DISK_FULL);
    }
    let written = fs
        .write(&fd, value, Some(REGISTRY_VALUE_TYPE_SIZE))
        .map_err(map_write_error)?;
    if written != value.len() {
        return Err(NtStatus::DISK_FULL);
    }
    let _ = fs.close(&fd);
    Ok(())
}

fn create_key_in_fs<FS: litebox::fs::FileSystem>(
    fs: &FS,
    nt_path: &str,
) -> Result<String, NtStatus> {
    let path = absolute_nt_key_name_to_fs_path(nt_path)?;
    create_key_path_in_fs(fs, &path)?;
    Ok(path)
}

fn create_key_path_in_fs<FS: litebox::fs::FileSystem>(fs: &FS, path: &str) -> Result<(), NtStatus> {
    let mut current = String::new();
    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() {
            continue;
        }
        current.push('/');
        current.push_str(component);
        ensure_directory_in_fs(fs, &current)?;

        let mut values_dir = current.clone();
        values_dir.push('/');
        values_dir.push_str(VALUES_DIR_NAME);
        ensure_directory_in_fs(fs, &values_dir)?;
    }
    Ok(())
}

fn ensure_directory_in_fs<FS: litebox::fs::FileSystem>(
    fs: &FS,
    path: &str,
) -> Result<(), NtStatus> {
    match fs.file_status(path) {
        Ok(status) if status.file_type == FileType::Directory => Ok(()),
        Ok(_) => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        Err(FileStatusError::PathError(
            PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
        )) => match fs.mkdir(
            path,
            Mode::RUSR | Mode::WUSR | Mode::XUSR | Mode::ROTH | Mode::WOTH | Mode::XOTH,
        ) {
            Ok(()) | Err(MkdirError::AlreadyExists) => Ok(()),
            Err(error) => Err(map_mkdir_error(error)),
        },
        Err(FileStatusError::PathError(error)) => {
            Err(map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND))
        }
        Err(_) => Err(NtStatus::UNSUCCESSFUL),
    }
}

fn value_path(key_path: &str, value_name: &str) -> Result<String, NtStatus> {
    if !is_valid_value_name(value_name) {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    let mut path = String::from(key_path);
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(VALUES_DIR_NAME);
    path.push('/');
    path.push_str(&value_name.to_ascii_lowercase());
    Ok(path)
}

fn is_valid_value_name(value_name: &str) -> bool {
    !value_name.is_empty()
        && value_name != "."
        && value_name != ".."
        && !value_name.contains('/')
        && !value_name.contains('\\')
}

fn map_open_error(error: OpenError) -> NtStatus {
    match error {
        OpenError::PathError(error) => map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND),
        OpenError::AccessNotAllowed | OpenError::NoWritePerms | OpenError::ReadOnlyFileSystem => {
            NtStatus::ACCESS_DENIED
        }
        OpenError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_file_status_error(error: FileStatusError) -> NtStatus {
    match error {
        FileStatusError::PathError(error) => map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND),
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_mkdir_error(error: MkdirError) -> NtStatus {
    match error {
        MkdirError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        MkdirError::PathError(error) => map_path_error(error, NtStatus::OBJECT_PATH_NOT_FOUND),
        MkdirError::NoWritePerms | MkdirError::ReadOnlyFileSystem => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_path_error(error: PathError, not_found_status: NtStatus) -> NtStatus {
    match error {
        PathError::NoSuchFileOrDirectory | PathError::MissingComponent => not_found_status,
        PathError::ComponentNotADirectory => NtStatus::NOT_A_DIRECTORY,
        PathError::InvalidPathname => NtStatus::INVALID_PARAMETER,
        PathError::NoSearchPerms { .. } => NtStatus::UNSUCCESSFUL,
    }
}

fn map_write_error(error: WriteError) -> NtStatus {
    match error {
        WriteError::NotForWriting => NtStatus::ACCESS_DENIED,
        WriteError::NotAFile => NtStatus::OBJECT_TYPE_MISMATCH,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_read_error(error: ReadError) -> NtStatus {
    match error {
        ReadError::NotForReading => NtStatus::ACCESS_DENIED,
        ReadError::NotAFile => NtStatus::OBJECT_TYPE_MISMATCH,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::init_platform;

    use super::*;
    use core::mem::size_of;
    use litebox::LiteBox;
    use zerocopy::{FromBytes, IntoBytes};

    extern crate std;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const ERROR_SUCCESS: i32 = 0;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const HKEY_LOCAL_MACHINE: *mut core::ffi::c_void = 0xffffffff80000002usize as _;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const KEY_QUERY_VALUE: u32 = 0x0001;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const HOST_CODE_PAGE_KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage";

    const KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET: usize =
        offset_of!(KeyValuePartialInformation, data);

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[allow(non_snake_case)]
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            hKey: *mut core::ffi::c_void,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut *mut core::ffi::c_void,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: *mut core::ffi::c_void,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: *mut core::ffi::c_void) -> i32;
    }

    fn const_ptr<T: FromBytes>(value: &T) -> ConstPtr<T> {
        ConstPtr::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn mut_ptr<T: FromBytes + IntoBytes>(value: &mut T) -> MutPtr<T> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn mut_byte_ptr<T>(value: &mut T) -> MutPtr<u8> {
        MutPtr::from_usize(core::ptr::from_mut(value).cast::<u8>() as usize)
    }

    fn unicode_string(value: &[u16]) -> UnicodeString {
        let byte_len = u16::try_from(core::mem::size_of_val(value)).unwrap();
        UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            padding_0: [0; 4],
            buffer: value.as_ptr() as usize,
        }
    }

    fn utf16(value: &str) -> std::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    fn object_attributes(name: &UnicodeString) -> ObjectAttributes {
        ObjectAttributes {
            length: u32::try_from(size_of::<ObjectAttributes>()).unwrap(),
            root_directory: Handle::default(),
            object_name: core::ptr::from_ref(name) as usize,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }

    fn test_registry() -> (LiteBox<Platform>, RegistryStore) {
        init_platform();
        let litebox = LiteBox::new(litebox_platform_multiplex::platform());
        let registry = RegistryStore::new(&litebox);
        (litebox, registry)
    }

    fn open_key(
        task: &Task<crate::DefaultFS>,
        object_attributes: ObjectAttributes,
    ) -> Result<Handle, NtStatus> {
        task.do_nt_open_key(0x20019, object_attributes)
    }

    fn open_code_page_key(task: &Task<crate::DefaultFS>) -> Handle {
        let code_page_name = utf16(DEFAULT_CODE_PAGE_KEY);
        let code_page_name = unicode_string(&code_page_name);
        let object_attributes = object_attributes(&code_page_name);
        open_key(task, object_attributes).expect("Failed to open code page key")
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn nul_terminated_utf16(value: &str) -> Vec<u16> {
        let mut value: Vec<u16> = value.encode_utf16().collect();
        value.push(0);
        value
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_registry_value(key_path: &str, value_name: &str) -> RegistryValue {
        let key_path = nul_terminated_utf16(key_path);
        let value_name = nul_terminated_utf16(value_name);
        let mut key = core::ptr::null_mut();
        // SAFETY: The key path is NUL-terminated, `phkResult` points to a live output
        // slot, and `HKEY_LOCAL_MACHINE` is the documented predefined registry handle.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &raw mut key,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to open host registry key");

        let mut value_type = 0;
        let mut data_len = 0;
        // SAFETY: The key handle was returned by `RegOpenKeyExW`, the value name is
        // NUL-terminated, and the null data buffer requests the required byte length.
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                core::ptr::null_mut(),
                &raw mut value_type,
                core::ptr::null_mut(),
                &raw mut data_len,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to size host registry value");

        let mut data = vec![0; data_len as usize];
        // SAFETY: `data` has exactly the byte length returned by the sizing query,
        // and all other pointers remain valid for the duration of the call.
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                core::ptr::null_mut(),
                &raw mut value_type,
                data.as_mut_ptr(),
                &raw mut data_len,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to read host registry value");
        data.truncate(data_len as usize);

        // SAFETY: The key handle was returned by `RegOpenKeyExW` and has not been closed yet.
        let status = unsafe { RegCloseKey(key) };
        assert_eq!(status, ERROR_SUCCESS, "failed to close host registry key");

        RegistryValue {
            value_type: RegistryValueType::try_from(value_type).expect("known registry value type"),
            data,
        }
    }

    #[test]
    fn registry_store_separates_values_from_subkeys() {
        let (_litebox, registry) = test_registry();
        let key_path = absolute_nt_key_name_to_fs_path(DEFAULT_CODE_PAGE_KEY).unwrap();
        let value_path = value_path(&key_path, "ACP").unwrap();

        assert_eq!(registry.key_exists(&key_path), Ok(true));
        assert_eq!(
            registry.fs.file_status(&*value_path).unwrap().file_type,
            FileType::RegularFile
        );
        assert_eq!(
            registry.fs.file_status(&*value_path).unwrap().size,
            REGISTRY_VALUE_TYPE_SIZE + DEFAULT_ACP_VALUE.len()
        );
        let value = registry.read_value(&key_path, "ACP").unwrap();
        assert_eq!(value.value_type, RegistryValueType::Sz);
        assert_eq!(value.data, DEFAULT_ACP_VALUE);

        let values_dir = absolute_nt_key_name_to_fs_path(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage\\.values",
        );
        assert_eq!(values_dir, Err(NtStatus::INVALID_PARAMETER));
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn registry_default_code_page_values_match_host() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);

        for name in ["ACP", "OEMCP", "MACCP"] {
            let host_value = host_registry_value(HOST_CODE_PAGE_KEY, name);
            let value_name = utf16(name);
            let value_name = unicode_string(&value_name);
            let mut information = [0u8; 64];
            let mut result_length = 0;

            assert!(
                task.do_nt_query_value_key(
                    key_handle,
                    value_name,
                    KeyValueInformationClass::Partial,
                    mut_byte_ptr(&mut information),
                    u32::try_from(information.len()).unwrap(),
                    mut_ptr(&mut result_length),
                )
                .is_ok()
            );

            let information = &information[..(result_length as usize)];
            let (information, data) =
                KeyValuePartialInformation::read_from_prefix(information).unwrap();

            assert_eq!(host_value.value_type, RegistryValueType::Sz);
            assert_eq!(information.value_type, host_value.value_type.into());
            assert_eq!(information.data_length as usize, host_value.data.len());
            assert_eq!(data, host_value.data.as_slice());
        }
    }

    #[test]
    fn nt_open_key_opens_existing_absolute_and_relative_keys() {
        let task = crate::tests::test_task();
        let nls_name = utf16("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls");
        let nls_name = unicode_string(&nls_name);
        let nls_object_attributes = object_attributes(&nls_name);
        let nls_handle = open_key(&task, nls_object_attributes).expect("Failed to open NLS key");
        assert_ne!(nls_handle, Handle::default());

        let code_page_name = utf16("CodePage");
        let code_page_name = unicode_string(&code_page_name);
        let mut code_page_object_attributes = object_attributes(&code_page_name);
        code_page_object_attributes.root_directory = nls_handle;
        let code_page_handle =
            open_key(&task, code_page_object_attributes).expect("Failed to open code page key");
        assert_ne!(code_page_handle, Handle::default());
    }

    #[test]
    fn nt_open_key_reports_missing_absolute_key() {
        let task = crate::tests::test_task();
        let name = utf16("\\Registry\\Machine\\Software\\Missing");
        let name = unicode_string(&name);
        let object_attributes = object_attributes(&name);
        assert_eq!(
            open_key(&task, object_attributes).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn nt_open_key_rejects_invalid_relative_root() {
        let task = crate::tests::test_task();
        let name = utf16("Child");
        let name = unicode_string(&name);
        let mut object_attributes = object_attributes(&name);
        object_attributes.root_directory = Handle::from_raw(0x1234);
        assert_eq!(
            open_key(&task, object_attributes).unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn nt_query_value_key_reports_partial_information() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);
        let value_name = utf16("ACP");
        let value_name = unicode_string(&value_name);
        let mut information = [0u8; 64];
        let mut result_length = 0;

        assert!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );

        assert_eq!(
            result_length as usize,
            size_of::<KeyValuePartialInformation>() + DEFAULT_ACP_VALUE.len()
        );
        let information = &information[..(result_length as usize)];
        let (information, data) =
            KeyValuePartialInformation::read_from_prefix(information).unwrap();
        assert_eq!(information.title_index, 0);
        assert_eq!(information.value_type, RegistryValueType::Sz.into());
        assert_eq!(
            information.data_length,
            u32::try_from(DEFAULT_ACP_VALUE.len()).unwrap()
        );
        assert_eq!(data, DEFAULT_ACP_VALUE);
    }

    #[test]
    fn nt_query_value_key_reports_basic_and_full_information() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);
        let value_name = utf16("OEMCP");
        let value_name = unicode_string(&value_name);
        let mut basic_information = [0u8; 64];
        let mut full_information = [0u8; 64];
        let mut result_length = 0;

        assert!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Basic,
                mut_byte_ptr(&mut basic_information),
                u32::try_from(basic_information.len()).unwrap(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );
        let name = utf16le("OEMCP");
        assert_eq!(
            result_length as usize,
            size_of::<KeyValueBasicInformation>() + name.len()
        );
        let basic_information = &basic_information[..(result_length as usize)];
        let (basic_information, basic_name) =
            KeyValueBasicInformation::read_from_prefix(basic_information).unwrap();
        assert_eq!(basic_information.title_index, 0);
        assert_eq!(basic_information.value_type, RegistryValueType::Sz.into());
        assert_eq!(basic_information.name_length as usize, name.len());
        assert_eq!(basic_name, name.as_slice());

        assert!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Full,
                mut_byte_ptr(&mut full_information),
                u32::try_from(full_information.len()).unwrap(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );
        let full_information = &full_information[..(result_length as usize)];
        let (full_header, full_tail) =
            KeyValueFullInformation::read_from_prefix(full_information).unwrap();
        let data_offset = usize::try_from(full_header.data_offset).unwrap();
        assert_eq!(full_header.title_index, 0);
        assert_eq!(full_header.value_type, RegistryValueType::Sz.into());
        assert_eq!(full_header.data_length as usize, DEFAULT_OEMCP_VALUE.len());
        assert_eq!(full_header.name_length as usize, name.len());
        assert_eq!(&full_tail[..name.len()], name.as_slice());
        assert_eq!(
            &full_information[data_offset..data_offset + DEFAULT_OEMCP_VALUE.len()],
            DEFAULT_OEMCP_VALUE
        );
    }

    #[test]
    fn nt_query_value_key_rejects_invalid_arguments() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);
        let value_name = utf16("ACP");
        let value_name = unicode_string(&value_name);
        let missing_value_name = utf16("Missing");
        let missing_value_name = unicode_string(&missing_value_name);
        let mut information = [0u8; 64];
        let mut short_information = [0u8; KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET - 1];
        let mut result_length = 0;

        assert_eq!(
            task.do_nt_query_value_key(
                Handle::from_raw(0x1234),
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::INVALID_HANDLE
        );

        assert_eq!(
            task.do_nt_query_value_key(
                key_handle,
                missing_value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );

        assert_eq!(
            task.sys_nt_query_value_key(
                key_handle,
                const_ptr(&value_name),
                0xffff,
                mut_byte_ptr(&mut information),
                u32::try_from(information.len()).unwrap(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::INVALID_INFO_CLASS
        );

        assert_eq!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut short_information),
                u32::try_from(short_information.len()).unwrap(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::BUFFER_OVERFLOW
        );
        assert_eq!(result_length, 22);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT object-manager directory syscalls.
//!
//! Object-manager directories are not filesystem directories. They name typed
//! kernel objects such as directories, symbolic links, sections, events, and
//! devices inside the NT object namespace; filesystem files only enter the
//! picture after a real NT object-manager walk reaches a device object and the
//! I/O manager hands the remaining path to a filesystem driver.
//!
//! This subset keeps the object namespace in a purpose-built in-memory tree
//! keyed by normalized path components. That makes the NT rule structural: a
//! named node can exist only if every ancestor exists, so the component walk
//! distinguishes a missing leaf from an earlier path-component miss in
//! `NtOpenDirectoryObject`.
//!
//! The tree is still an object-manager tree, not a `litebox::fs` filesystem:
//! `litebox::fs` is a byte-stream interface, while object-manager directories
//! hold typed kernel objects with object-specific handle semantics rather than
//! file contents. Symbolic-link traversal hangs off this tree in a later
//! increment; `NtQueryDirectoryObject` enumerates the tree's direct children.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString as _};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{ErrRawIntFd, FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

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
    directory: Arc<ObjectNode<Platform>>,
    granted_access: DirectoryAccess,
}

struct ObjectNode<Platform: crate::ShimPlatform> {
    path: String,
    parent: Option<Weak<ObjectNode<Platform>>>,
    body: litebox::sync::RwLock<Platform, NamedObject<Platform>>,
    _not_send_without_platform: PhantomData<fn(Platform)>,
}

pub(crate) struct DirectoryNamespace<Platform: crate::ShimPlatform> {
    root: Arc<ObjectNode<Platform>>,
}

enum NamedObject<Platform: crate::ShimPlatform> {
    Directory {
        children: BTreeMap<String, Arc<ObjectNode<Platform>>>,
    },
    #[expect(
        dead_code,
        reason = "symbolic-link nodes are inserted by the next object-manager increment"
    )]
    Symlink { target: String },
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
struct ObjectDirectoryInformation {
    name: UnicodeString,
    type_name: UnicodeString,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryEntrySnapshot {
    name: String,
    type_name: &'static str,
}

impl ObjectDirectoryInformation {
    const fn new(name: UnicodeString, type_name: UnicodeString) -> Self {
        Self { name, type_name }
    }

    const fn zero() -> Self {
        Self {
            name: UnicodeString {
                length: 0,
                maximum_length: 0,
                padding_0: [0; 4],
                buffer: 0,
            },
            type_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                padding_0: [0; 4],
                buffer: 0,
            },
        }
    }
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

impl<Platform: crate::ShimPlatform> ObjectNode<Platform> {
    fn new_directory(path: String, parent: Option<Weak<ObjectNode<Platform>>>) -> Self {
        Self {
            path,
            parent,
            body: litebox::sync::RwLock::<Platform, _>::new(NamedObject::Directory {
                children: BTreeMap::new(),
            }),
            _not_send_without_platform: PhantomData,
        }
    }

    fn child(&self, name: &str) -> Option<Arc<Self>> {
        match &*self.body.read() {
            NamedObject::Directory { children } => children.get(name).cloned(),
            NamedObject::Symlink { .. } => None,
        }
    }

    fn children_snapshot(&self) -> Result<Vec<DirectoryEntrySnapshot>, NtStatus> {
        match &*self.body.read() {
            NamedObject::Directory { children } => Ok(children
                .iter()
                .map(|(name, child)| DirectoryEntrySnapshot {
                    name: name.clone(),
                    type_name: child.type_name(),
                })
                .collect()),
            NamedObject::Symlink { .. } => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        }
    }

    fn is_directory(&self) -> bool {
        matches!(&*self.body.read(), NamedObject::Directory { .. })
    }

    fn type_name(&self) -> &'static str {
        match &*self.body.read() {
            NamedObject::Directory { .. } => "Directory",
            NamedObject::Symlink { .. } => "SymbolicLink",
        }
    }

    fn parent(&self) -> Option<Arc<Self>> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }
}

impl<Platform: crate::ShimPlatform> DirectoryNamespace<Platform> {
    fn new() -> Self {
        Self {
            root: Arc::new(ObjectNode::new_directory(r"\".to_string(), None)),
        }
    }

    fn resolve_directory(&self, path: &str) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let node = self.resolve_node(path)?;
        if node.is_directory() {
            Ok(node)
        } else {
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        }
    }

    fn create_directory(
        &self,
        path: &str,
        on_exists: impl FnOnce(Arc<ObjectNode<Platform>>) -> NtStatus,
        on_created: impl FnOnce(Arc<ObjectNode<Platform>>) -> NtStatus,
    ) -> NtStatus {
        let tail = match absolute_path_tail(path) {
            Ok(tail) => tail,
            Err(status) => return status,
        };
        if tail.is_empty() {
            return on_exists(Arc::clone(&self.root));
        }

        let (parent_tail, leaf_name) = match tail.rsplit_once('\\') {
            Some((parent, leaf)) => (parent, leaf),
            None => ("", tail),
        };
        if leaf_name.is_empty() {
            return NtStatus::OBJECT_NAME_INVALID;
        }

        let parent = match self.resolve_tail(parent_tail, NtStatus::OBJECT_PATH_NOT_FOUND) {
            Ok(parent) => parent,
            Err(status) => return status,
        };
        let mut body = parent.body.write();
        let NamedObject::Directory { children } = &mut *body else {
            return NtStatus::OBJECT_TYPE_MISMATCH;
        };
        if let Some(existing) = children.get(leaf_name) {
            if !existing.is_directory() {
                return NtStatus::OBJECT_TYPE_MISMATCH;
            }
            return on_exists(Arc::clone(existing));
        }

        let node = Arc::new(ObjectNode::new_directory(
            join_directory_path(&parent.path, leaf_name),
            Some(Arc::downgrade(&parent)),
        ));
        debug_assert!(node.parent().is_some());
        let status = on_created(Arc::clone(&node));
        if status == NtStatus::SUCCESS {
            children.insert(leaf_name.to_string(), node);
        }
        status
    }

    fn seed_directory(&self, path: &str) {
        let status = self.create_directory(path, |_| NtStatus::SUCCESS, |_| NtStatus::SUCCESS);
        assert!(
            status == NtStatus::SUCCESS,
            "seeded NT object directory must have seeded ancestors: {status:?}"
        );
    }

    fn resolve_node(&self, path: &str) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let tail = absolute_path_tail(path)?;
        if tail.is_empty() {
            return Ok(Arc::clone(&self.root));
        }

        let mut current = Arc::clone(&self.root);
        let mut components = tail.split('\\').peekable();
        while let Some(component) = components.next() {
            if component.is_empty() {
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            let missing_status = if components.peek().is_some() {
                NtStatus::OBJECT_PATH_NOT_FOUND
            } else {
                NtStatus::OBJECT_NAME_NOT_FOUND
            };
            current = current.child(component).ok_or(missing_status)?;
        }
        Ok(current)
    }

    fn resolve_tail(
        &self,
        tail: &str,
        missing_status: NtStatus,
    ) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let mut current = Arc::clone(&self.root);
        if tail.is_empty() {
            return Ok(current);
        }

        for component in tail.split('\\') {
            if component.is_empty() {
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            current = current.child(component).ok_or(missing_status)?;
        }
        Ok(current)
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

fn absolute_path_tail(path: &str) -> Result<&str, NtStatus> {
    if path == r"\" {
        return Ok("");
    }
    path.strip_prefix('\\')
        .ok_or(NtStatus::OBJECT_PATH_SYNTAX_BAD)
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

fn utf16_byte_len(value: &str) -> Result<usize, NtStatus> {
    let len = value
        .encode_utf16()
        .count()
        .checked_mul(size_of::<u16>())
        .ok_or(NtStatus::NAME_TOO_LONG)?;
    if len > usize::from(u16::MAX) {
        return Err(NtStatus::NAME_TOO_LONG);
    }
    Ok(len)
}

fn directory_record_size(entry: &DirectoryEntrySnapshot) -> Result<usize, NtStatus> {
    size_of::<ObjectDirectoryInformation>()
        .checked_add(utf16_byte_len(&entry.name)?)
        .and_then(|size| size.checked_add(utf16_byte_len(entry.type_name).ok()?))
        .ok_or(NtStatus::NAME_TOO_LONG)
}

fn byte_offset(offset: usize) -> Result<isize, NtStatus> {
    isize::try_from(offset).map_err(|_| NtStatus::BUFFER_TOO_SMALL)
}

fn write_utf16_bytes<Platform: RawPointerProvider>(
    buffer: MutPtr<Platform, u8>,
    offset: usize,
    value: &str,
) -> Result<(), NtStatus> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    buffer
        .write_slice_at_offset(byte_offset(offset)?, &bytes)
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

fn output_unicode_string(
    buffer_base: usize,
    offset: usize,
    len: usize,
) -> Result<UnicodeString, NtStatus> {
    let len = u16::try_from(len).map_err(|_| NtStatus::NAME_TOO_LONG)?;
    Ok(UnicodeString {
        length: len,
        maximum_length: len,
        padding_0: [0; 4],
        buffer: buffer_base
            .checked_add(offset)
            .ok_or(NtStatus::NAME_TOO_LONG)?,
    })
}

fn write_directory_record<Platform: RawPointerProvider>(
    buffer: MutPtr<Platform, u8>,
    buffer_base: usize,
    offset: usize,
    entry: &DirectoryEntrySnapshot,
) -> Result<usize, NtStatus> {
    let header_size = size_of::<ObjectDirectoryInformation>();
    let name_len = utf16_byte_len(&entry.name)?;
    let type_len = utf16_byte_len(entry.type_name)?;
    let name_offset = offset
        .checked_add(header_size)
        .ok_or(NtStatus::NAME_TOO_LONG)?;
    let type_offset = name_offset
        .checked_add(name_len)
        .ok_or(NtStatus::NAME_TOO_LONG)?;
    let record = ObjectDirectoryInformation::new(
        output_unicode_string(buffer_base, name_offset, name_len)?,
        output_unicode_string(buffer_base, type_offset, type_len)?,
    );
    buffer
        .write_slice_at_offset(byte_offset(offset)?, record.as_bytes())
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    write_utf16_bytes::<Platform>(buffer, name_offset, &entry.name)?;
    write_utf16_bytes::<Platform>(buffer, type_offset, entry.type_name)?;
    type_offset
        .checked_add(type_len)
        .ok_or(NtStatus::NAME_TOO_LONG)
}

fn write_directory_terminator<Platform: RawPointerProvider>(
    buffer: MutPtr<Platform, u8>,
    offset: usize,
) -> Result<usize, NtStatus> {
    let record = ObjectDirectoryInformation::zero();
    buffer
        .write_slice_at_offset(byte_offset(offset)?, record.as_bytes())
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    offset
        .checked_add(size_of::<ObjectDirectoryInformation>())
        .ok_or(NtStatus::NAME_TOO_LONG)
}

fn probe_output_buffer<Platform: RawPointerProvider>(
    buffer: MutPtr<Platform, u8>,
    buffer_length: usize,
) -> Result<(), NtStatus> {
    if buffer_length == 0 {
        return Ok(());
    }
    let Some(bytes) = buffer.to_owned_slice(buffer_length) else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    buffer
        .write_slice_at_offset(0, &bytes)
        .ok_or(NtStatus::ACCESS_VIOLATION)
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
    ) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let entry = self.directory_entry(handle)?;
        // TODO: enforce DIRECTORY_TRAVERSE on root handles before resolving relative
        // object-manager paths.
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
        directory: Arc<ObjectNode<Platform>>,
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
        directory_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        shadow_directory_handle: Handle,
        flags: u32,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(directory_handle) {
            return status;
        }
        if flags != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        if !shadow_directory_handle.is_null()
            && let Err(status) = self.directory_entry(shadow_directory_handle)
        {
            return status;
        }
        let (object_attributes, directory_name) =
            match self.read_directory_object_attributes(object_attributes, false) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let granted_access = DirectoryAccess::from_desired_access(desired_access);

        if let Some(directory_name) = directory_name {
            return self.process.directory_namespace.create_directory(
                &directory_name.path,
                |directory| {
                    let Some(object_attributes) = object_attributes else {
                        return NtStatus::INVALID_PARAMETER;
                    };
                    if object_attributes.attributes & OBJ_OPENIF == 0 {
                        return NtStatus::OBJECT_NAME_COLLISION;
                    }
                    let Ok(handle) = self.insert_directory_handle(directory, granted_access) else {
                        return NtStatus::QUOTA_EXCEEDED;
                    };
                    if directory_handle.write_at_offset(0, handle).is_none() {
                        self.close_directory_handle(handle);
                        return NtStatus::ACCESS_VIOLATION;
                    }
                    NtStatus::OBJECT_NAME_EXISTS
                },
                |directory| {
                    let Ok(handle) = self.insert_directory_handle(directory, granted_access) else {
                        return NtStatus::QUOTA_EXCEEDED;
                    };
                    if directory_handle.write_at_offset(0, handle).is_none() {
                        self.close_directory_handle(handle);
                        return NtStatus::ACCESS_VIOLATION;
                    }
                    NtStatus::SUCCESS
                },
            );
        }

        let directory = Arc::new(ObjectNode::new_directory(String::new(), None));
        let Ok(handle) = self.insert_directory_handle(directory, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if directory_handle.write_at_offset(0, handle).is_none() {
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
            match self
                .process
                .directory_namespace
                .resolve_directory(&directory_name.path)
            {
                Ok(directory) => directory,
                Err(status) => return status,
            }
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
        let directory = entry.with_entry(|entry| Arc::clone(&entry.directory));
        let entries = match directory.children_snapshot() {
            Ok(entries) => entries,
            Err(status) => return status,
        };
        let buffer_length =
            usize::try_from(params.buffer_length).expect("ULONG buffer length fits in usize");
        if let Err(status) = probe_output_buffer::<Platform>(params.buffer, buffer_length) {
            return status;
        }

        let start_index = if params.restart_scan != 0 {
            0
        } else {
            let Some(context) = params.context.read_at_offset(0) else {
                return NtStatus::ACCESS_VIOLATION;
            };
            usize::try_from(context).expect("ULONG context fits in usize")
        };
        if start_index >= entries.len() {
            let context =
                u32::try_from(entries.len()).expect("directory entry count fits in ULONG");
            // Saturate the opaque resume cookie at end-of-directory so repeated
            // continuation calls remain stable.
            if params.context.write_at_offset(0, context).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
            if let Some(return_length) = params.return_length
                && return_length.write_at_offset(0, 0).is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            return NtStatus::NO_MORE_ENTRIES;
        }

        let first_required = match directory_record_size(&entries[start_index]) {
            Ok(size) => size,
            Err(status) => return status,
        };
        if buffer_length < first_required {
            if let Some(return_length) = params.return_length {
                let required = u32::try_from(first_required).map_err(|_| NtStatus::NAME_TOO_LONG);
                let Ok(required) = required else {
                    return NtStatus::NAME_TOO_LONG;
                };
                if return_length.write_at_offset(0, required).is_none() {
                    return NtStatus::ACCESS_VIOLATION;
                }
            }
            return NtStatus::BUFFER_TOO_SMALL;
        }

        let buffer_base = params.buffer.as_usize();
        let mut next_index = start_index;
        let mut bytes_written = 0usize;
        while next_index < entries.len() {
            let entry_size = match directory_record_size(&entries[next_index]) {
                Ok(size) => size,
                Err(status) => return status,
            };
            if bytes_written
                .checked_add(entry_size)
                .is_none_or(|needed| needed > buffer_length)
            {
                break;
            }
            bytes_written = match write_directory_record::<Platform>(
                params.buffer,
                buffer_base,
                bytes_written,
                &entries[next_index],
            ) {
                Ok(bytes_written) => bytes_written,
                Err(status) => return status,
            };
            next_index += 1;
            if params.return_single_entry != 0 {
                break;
            }
        }

        let status = if next_index < entries.len() {
            NtStatus::MORE_ENTRIES
        } else {
            if buffer_length
                .checked_sub(bytes_written)
                .is_some_and(|remaining| remaining >= size_of::<ObjectDirectoryInformation>())
            {
                bytes_written =
                    match write_directory_terminator::<Platform>(params.buffer, bytes_written) {
                        Ok(bytes_written) => bytes_written,
                        Err(status) => return status,
                    };
            }
            NtStatus::SUCCESS
        };

        let context = u32::try_from(next_index).expect("directory entry count fits in ULONG");
        if params.context.write_at_offset(0, context).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = params.return_length {
            let Ok(returned) = u32::try_from(bytes_written) else {
                return NtStatus::NAME_TOO_LONG;
            };
            if return_length.write_at_offset(0, returned).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
        }
        status
    }
}

pub(crate) fn seed_directory_namespace<Platform: crate::ShimPlatform>()
-> crate::WindowsDirectoryNamespace<Platform> {
    let namespace = DirectoryNamespace::new();
    for path in SEEDED_DIRECTORY_PATHS {
        let path = normalize_directory_path(path);
        namespace.seed_directory(&path);
    }
    namespace
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

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ParsedDirectoryInformation {
        name: String,
        type_name: String,
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn read_u16(buffer: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(buffer[offset..offset + 2].try_into().expect("u16 bytes"))
    }

    fn read_usize(buffer: &[u8], offset: usize) -> usize {
        usize::from_le_bytes(
            buffer[offset..offset + size_of::<usize>()]
                .try_into()
                .expect("usize bytes"),
        )
    }

    fn read_utf16_string(
        buffer: &[u8],
        buffer_base: usize,
        address: usize,
        length: usize,
    ) -> String {
        let offset = address
            .checked_sub(buffer_base)
            .expect("string buffer points into output buffer");
        assert!(
            offset
                .checked_add(length)
                .is_some_and(|end| end <= buffer.len()),
            "string buffer range stays inside output buffer"
        );
        let units: alloc::vec::Vec<u16> = buffer[offset..offset + length]
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("u16 bytes")))
            .collect();
        String::from_utf16_lossy(&units)
    }

    fn read_directory_information(buffer: &[u8], offset: usize) -> ParsedDirectoryInformation {
        let buffer_base = buffer.as_ptr() as usize;
        let name_len = usize::from(read_u16(buffer, offset));
        let name_buffer = read_usize(buffer, offset + 8);
        let type_len = usize::from(read_u16(buffer, offset + 16));
        let type_buffer = read_usize(buffer, offset + 24);
        ParsedDirectoryInformation {
            name: read_utf16_string(buffer, buffer_base, name_buffer, name_len),
            type_name: read_utf16_string(buffer, buffer_base, type_buffer, type_len),
        }
    }

    fn assert_zero_directory_information(buffer: &[u8], offset: usize) {
        assert_eq!(read_u16(buffer, offset), 0);
        assert_eq!(read_u16(buffer, offset + 2), 0);
        assert_eq!(read_usize(buffer, offset + 8), 0);
        assert_eq!(read_u16(buffer, offset + 16), 0);
        assert_eq!(read_u16(buffer, offset + 18), 0);
        assert_eq!(read_usize(buffer, offset + 24), 0);
    }

    fn create_named_directory(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        path: &str,
    ) -> Handle {
        let name_units: alloc::vec::Vec<u16> = path.encode_utf16().collect();
        let name = unicode_string(&name_units);
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

    fn open_named_directory(task: &Task<TestPlatform, crate::tests::TestFS>, path: &str) -> Handle {
        let name_units: alloc::vec::Vec<u16> = path.encode_utf16().collect();
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
        handle
    }

    fn expected_record_size(name: &str, type_name: &str) -> usize {
        size_of::<ObjectDirectoryInformation>()
            + name.encode_utf16().count() * size_of::<u16>()
            + type_name.encode_utf16().count() * size_of::<u16>()
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
    fn open_directory_distinguishes_missing_leaf_from_missing_parent() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            for (path, expected_status) in [
                (
                    r"\BaseNamedObjects\DefinitelyMissingLiteBoxDir",
                    NtStatus::OBJECT_NAME_NOT_FOUND,
                ),
                (
                    r"\KnownDlls\DefinitelyMissingLiteBoxDir",
                    NtStatus::OBJECT_NAME_NOT_FOUND,
                ),
                (
                    r"\MissingParentLiteBox\Child",
                    NtStatus::OBJECT_PATH_NOT_FOUND,
                ),
                (
                    r"\DefinitelyMissingLiteBoxDir",
                    NtStatus::OBJECT_NAME_NOT_FOUND,
                ),
            ] {
                let name_units: alloc::vec::Vec<u16> = path.encode_utf16().collect();
                let name = unicode_string(&name_units);
                let attrs = object_attributes(&name, OBJ_CASE_INSENSITIVE);
                let mut handle = Handle::default();

                assert_eq!(
                    task.sys_nt_open_directory_object(
                        mut_ptr(&mut handle),
                        DIRECTORY_QUERY,
                        Some(const_ptr(&attrs)),
                    ),
                    expected_status,
                    "unexpected status opening {path}",
                );
                assert_eq!(handle, Handle::default());
            }
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
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut created),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&child_attrs)),
                    Handle::default(),
                    0,
                ),
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
    fn create_nested_directory_after_parent_exists() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let parent_units: alloc::vec::Vec<u16> = r"\BaseNamedObjects\LiteBoxTreeParent"
                .encode_utf16()
                .collect();
            let parent_name = unicode_string(&parent_units);
            let parent_attrs = object_attributes(&parent_name, OBJ_CASE_INSENSITIVE);
            let mut parent = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut parent),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&parent_attrs)),
                    Handle::default(),
                    0,
                ),
                NtStatus::SUCCESS
            );

            let child_units: alloc::vec::Vec<u16> =
                r"\BaseNamedObjects\LiteBoxTreeParent\LiteBoxTreeChild"
                    .encode_utf16()
                    .collect();
            let child_name = unicode_string(&child_units);
            let child_attrs = object_attributes(&child_name, OBJ_CASE_INSENSITIVE);
            let mut child = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut child),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&child_attrs)),
                    Handle::default(),
                    0,
                ),
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
            assert_eq!(task.sys_nt_close(child), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(parent), NtStatus::SUCCESS);
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
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut first),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    Handle::default(),
                    0,
                ),
                NtStatus::SUCCESS
            );

            let mut collision = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut collision),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    Handle::default(),
                    0,
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
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut opened),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&openif_attrs)),
                    Handle::default(),
                    0,
                ),
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
            assert_eq!(buffer[0], 0xff);
            assert_eq!(context, 0);
            assert_eq!(return_length, 0);
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn query_directory_enumerates_children_in_stable_order() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let first = create_named_directory(&task, r"\BaseNamedObjects\LiteBoxEnumB");
            let second = create_named_directory(&task, r"\BaseNamedObjects\LiteBoxEnumA");
            let handle = open_named_directory(&task, r"\BaseNamedObjects");
            let mut buffer = [0u8; 512];
            let mut context = u32::MAX;
            let mut return_length = 0u32;

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
                NtStatus::SUCCESS
            );

            let first_record = read_directory_information(&buffer, 0);
            assert_eq!(
                first_record,
                ParsedDirectoryInformation {
                    name: "liteboxenuma".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            let second_offset = expected_record_size("liteboxenuma", "Directory");
            let second_record = read_directory_information(&buffer, second_offset);
            assert_eq!(
                second_record,
                ParsedDirectoryInformation {
                    name: "liteboxenumb".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            assert_zero_directory_information(
                &buffer,
                second_offset + expected_record_size("liteboxenumb", "Directory"),
            );
            assert_eq!(context, 2);
            assert_eq!(
                usize::try_from(return_length).unwrap(),
                expected_record_size("liteboxenuma", "Directory")
                    + expected_record_size("liteboxenumb", "Directory")
                    + size_of::<ObjectDirectoryInformation>()
            );
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(second), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(first), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn query_directory_single_entry_uses_context_cookie() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let first = create_named_directory(&task, r"\BaseNamedObjects\LiteBoxSingleA");
            let second = create_named_directory(&task, r"\BaseNamedObjects\LiteBoxSingleB");
            let handle = open_named_directory(&task, r"\BaseNamedObjects");
            let mut buffer = [0u8; 256];
            let mut context = 123u32;
            let mut return_length = 0u32;

            assert_eq!(
                task.sys_nt_query_directory_object(DirectoryQueryParameters {
                    directory_handle: handle,
                    buffer: mut_ptr(&mut buffer[0]),
                    buffer_length: u32::try_from(buffer.len()).expect("test buffer fits in ULONG"),
                    return_single_entry: 1,
                    restart_scan: 1,
                    context: mut_ptr(&mut context),
                    return_length: Some(mut_ptr(&mut return_length)),
                },),
                NtStatus::MORE_ENTRIES
            );
            assert_eq!(context, 1);
            assert_eq!(
                read_directory_information(&buffer, 0),
                ParsedDirectoryInformation {
                    name: "liteboxsinglea".to_string(),
                    type_name: "Directory".to_string(),
                }
            );

            buffer.fill(0);
            assert_eq!(
                task.sys_nt_query_directory_object(DirectoryQueryParameters {
                    directory_handle: handle,
                    buffer: mut_ptr(&mut buffer[0]),
                    buffer_length: u32::try_from(buffer.len()).expect("test buffer fits in ULONG"),
                    return_single_entry: 1,
                    restart_scan: 0,
                    context: mut_ptr(&mut context),
                    return_length: Some(mut_ptr(&mut return_length)),
                },),
                NtStatus::SUCCESS
            );
            assert_eq!(context, 2);
            assert_eq!(
                read_directory_information(&buffer, 0),
                ParsedDirectoryInformation {
                    name: "liteboxsingleb".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            assert_zero_directory_information(
                &buffer,
                expected_record_size("liteboxsingleb", "Directory"),
            );
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(second), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(first), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn query_directory_too_small_reports_required_length_without_advancing_context() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let child = create_named_directory(&task, r"\BaseNamedObjects\LiteBoxSmall");
            let handle = open_named_directory(&task, r"\BaseNamedObjects");
            let mut buffer = [0xffu8; 8];
            let mut context = 99u32;
            let mut return_length = 0u32;

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
                NtStatus::BUFFER_TOO_SMALL
            );
            assert_eq!(context, 99);
            assert_eq!(
                usize::try_from(return_length).unwrap(),
                expected_record_size("liteboxsmall", "Directory")
            );
            assert_eq!(buffer, [0xffu8; 8]);
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(child), NtStatus::SUCCESS);
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
                task.sys_nt_create_directory_object(
                    null_mut_ptr(),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    Handle::default(),
                    0,
                ),
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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT object-manager directory syscalls.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString as _};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{
    AccessMask, ObjectAttributes, ObjectAttributesFlags, UnicodeString, read_object_attributes,
};
use crate::syscalls::Handle;
use crate::{ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value};

const MAX_SYMLINK_REPARSE_DEPTH: usize = 64;
const STANDARD_RIGHTS_REQUIRED: u32 = AccessMask::DELETE.bits()
    | AccessMask::READ_CONTROL.bits()
    | AccessMask::WRITE_DAC.bits()
    | AccessMask::WRITE_OWNER.bits();

// Wine's server seeds these object-manager directories during init_directories/create_session;
// ReactOS initializes the same root-style namespace through ObpRootDirectoryObject.
const SEEDED_DIRECTORY_PATHS: &[&str] = &[
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
    struct DirectoryAccess: u32 {
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

pub(crate) struct DirectoryObjectSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for DirectoryObjectSubsystem<Platform> {
    type Entry = DirectoryHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for DirectoryHandleObject<Platform> {}

pub(crate) struct DirectoryHandleObject<Platform: crate::ShimPlatform> {
    directory: Arc<ObjectNode<Platform>>,
    granted_access: DirectoryAccess,
}

pub(super) struct ObjectNode<Platform: crate::ShimPlatform> {
    path: String,
    name: String,
    parent: Option<Weak<ObjectNode<Platform>>>,
    body: litebox::sync::RwLock<Platform, NamedObject<Platform>>,
    _not_send_without_platform: PhantomData<fn(Platform)>,
}

pub(crate) struct DirectoryNamespace<Platform: crate::ShimPlatform> {
    root: Arc<ObjectNode<Platform>>,
}

enum NamedObject<Platform: crate::ShimPlatform> {
    Directory {
        children: BTreeMap<ObjectName, Arc<ObjectNode<Platform>>>,
    },
    Symlink {
        target: String,
    },
}

#[derive(Clone, Debug)]
struct ObjectName(String);

impl ObjectName {
    // ReactOS and Wine keep the creator's object name but compare through a
    // case-insensitive object-manager lookup key.
    fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl PartialEq for ObjectName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for ObjectName {}

impl PartialOrd for ObjectName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(other.0.bytes().map(|byte| byte.to_ascii_lowercase()))
    }
}

impl Hash for ObjectName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            byte.to_ascii_lowercase().hash(state);
        }
    }
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
    fn new_directory(
        path: String,
        parent: Option<Weak<ObjectNode<Platform>>>,
        name: String,
    ) -> Self {
        Self {
            path,
            name,
            parent,
            body: litebox::sync::RwLock::<Platform, _>::new(NamedObject::Directory {
                children: BTreeMap::new(),
            }),
            _not_send_without_platform: PhantomData,
        }
    }

    fn new_symlink(
        path: String,
        parent: Option<Weak<ObjectNode<Platform>>>,
        name: String,
        target: String,
    ) -> Self {
        Self {
            path,
            name,
            parent,
            body: litebox::sync::RwLock::<Platform, _>::new(NamedObject::Symlink { target }),
            _not_send_without_platform: PhantomData,
        }
    }

    fn child(&self, name: &str) -> Option<Arc<Self>> {
        match &*self.body.read() {
            NamedObject::Directory { children } => children.get(&ObjectName::new(name)).cloned(),
            NamedObject::Symlink { .. } => None,
        }
    }

    fn children_snapshot(&self) -> Result<Vec<DirectoryEntrySnapshot>, NtStatus> {
        match &*self.body.read() {
            NamedObject::Directory { children } => Ok(children
                .values()
                .map(|child| DirectoryEntrySnapshot {
                    name: child.name.clone(),
                    type_name: child.type_name(),
                })
                .collect()),
            NamedObject::Symlink { .. } => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        }
    }

    pub(super) fn is_directory(&self) -> bool {
        matches!(&*self.body.read(), NamedObject::Directory { .. })
    }

    pub(super) fn is_symlink(&self) -> bool {
        matches!(&*self.body.read(), NamedObject::Symlink { .. })
    }

    pub(super) fn symlink_target(&self) -> Result<String, NtStatus> {
        match &*self.body.read() {
            NamedObject::Symlink { target } => Ok(target.clone()),
            NamedObject::Directory { .. } => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        }
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
            root: Arc::new(ObjectNode::new_directory(
                r"\".to_string(),
                None,
                String::new(),
            )),
        }
    }

    fn resolve_directory(&self, path: &str) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let tail = absolute_path_tail(path)?;
        let node = self.resolve_tail(tail, NtStatus::OBJECT_NAME_NOT_FOUND, false)?;
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
        self.create_child(
            path,
            ObjectNode::is_directory,
            ObjectNode::new_directory,
            on_exists,
            on_created,
        )
    }

    pub(super) fn create_symlink(
        &self,
        path: &str,
        target: String,
        on_exists: impl FnOnce(Arc<ObjectNode<Platform>>) -> NtStatus,
        on_created: impl FnOnce(Arc<ObjectNode<Platform>>) -> NtStatus,
    ) -> NtStatus {
        self.create_child(
            path,
            ObjectNode::is_symlink,
            |path, parent, name| ObjectNode::new_symlink(path, parent, name, target),
            on_exists,
            on_created,
        )
    }

    fn create_child(
        &self,
        path: &str,
        existing_matches: impl Fn(&ObjectNode<Platform>) -> bool,
        construct: impl FnOnce(
            String,
            Option<Weak<ObjectNode<Platform>>>,
            String,
        ) -> ObjectNode<Platform>,
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

        let parent = match self.resolve_tail(parent_tail, NtStatus::OBJECT_PATH_NOT_FOUND, false) {
            Ok(parent) => parent,
            Err(status) => return status,
        };
        let mut body = parent.body.write();
        let NamedObject::Directory { children } = &mut *body else {
            return NtStatus::OBJECT_TYPE_MISMATCH;
        };
        let leaf_key = ObjectName::new(leaf_name);
        if let Some(existing) = children.get(&leaf_key) {
            if !existing_matches(existing) {
                return NtStatus::OBJECT_TYPE_MISMATCH;
            }
            return on_exists(Arc::clone(existing));
        }

        let node = Arc::new(construct(
            join_directory_path(&parent.path, leaf_name),
            Some(Arc::downgrade(&parent)),
            leaf_name.to_string(),
        ));
        debug_assert!(node.parent().is_some());
        let status = on_created(Arc::clone(&node));
        if status == NtStatus::SUCCESS {
            children.insert(leaf_key, node);
        }
        status
    }

    pub(super) fn resolve_symlink(
        &self,
        path: &str,
        open_final_symlink: bool,
    ) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let tail = absolute_path_tail(path)?;
        let node = self.resolve_tail(tail, NtStatus::OBJECT_NAME_NOT_FOUND, open_final_symlink)?;
        if node.is_symlink() {
            Ok(node)
        } else {
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        }
    }

    fn seed_directory(&self, path: &str) {
        let status = self.create_directory(path, |_| NtStatus::SUCCESS, |_| NtStatus::SUCCESS);
        assert!(
            status == NtStatus::SUCCESS,
            "seeded NT object directory must have seeded ancestors: {status:?}"
        );
    }

    fn resolve_tail(
        &self,
        tail: &str,
        final_missing_status: NtStatus,
        open_final_symlink: bool,
    ) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let mut tail = tail.to_string();
        for _ in 0..=MAX_SYMLINK_REPARSE_DEPTH {
            match self.resolve_tail_once(&tail, final_missing_status, open_final_symlink)? {
                TailResolution::Resolved(node) => return Ok(node),
                TailResolution::Reparse(next_tail) => tail = next_tail,
            }
        }
        Err(NtStatus::NAME_TOO_LONG)
    }

    fn resolve_tail_once(
        &self,
        tail: &str,
        final_missing_status: NtStatus,
        open_final_symlink: bool,
    ) -> Result<TailResolution<Platform>, NtStatus> {
        if tail.is_empty() {
            return Ok(TailResolution::Resolved(Arc::clone(&self.root)));
        }

        let mut current = Arc::clone(&self.root);
        let mut components = tail.split('\\').peekable();
        while let Some(component) = components.next() {
            if component.is_empty() {
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            let final_component = components.peek().is_none();
            let missing_status = if final_component {
                final_missing_status
            } else {
                NtStatus::OBJECT_PATH_NOT_FOUND
            };
            let child = current.child(component).ok_or(missing_status)?;
            if child.is_symlink() && (!final_component || !open_final_symlink) {
                // This is the lazy-resolution point paired with
                // NtCreateSymbolicLinkObject storing the target without lookup.
                let target = normalize_reparse_target(&child.symlink_target()?)?;
                let target_tail = absolute_path_tail(&target)?;
                let remaining = components.collect::<Vec<_>>().join("\\");
                let next_tail = if target_tail.is_empty() {
                    remaining
                } else if remaining.is_empty() {
                    target_tail.to_string()
                } else {
                    alloc::format!("{target_tail}\\{remaining}")
                };
                return Ok(TailResolution::Reparse(next_tail));
            }
            current = child;
        }
        Ok(TailResolution::Resolved(current))
    }
}

enum TailResolution<Platform: crate::ShimPlatform> {
    Resolved(Arc<ObjectNode<Platform>>),
    Reparse(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DirectoryName {
    pub(super) original_path: String,
}

fn trim_trailing_directory_path(path: &str) -> &str {
    if path == r"\" {
        path
    } else {
        path.trim_end_matches('\\')
    }
}

fn normalize_reparse_target(path: &str) -> Result<String, NtStatus> {
    if !path.starts_with('\\') {
        return Err(NtStatus::OBJECT_PATH_SYNTAX_BAD);
    }
    if path.len() > 1 && path[1..].contains(r"\\") {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    Ok(trim_trailing_directory_path(path).to_string())
}

fn absolute_path_tail(path: &str) -> Result<&str, NtStatus> {
    let path = trim_trailing_directory_path(path);
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
    debug_assert!(object_name != 0);
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
    if len > u16::MAX as usize {
        return Err(NtStatus::NAME_TOO_LONG);
    }
    Ok(len)
}

fn directory_record_size(entry: &DirectoryEntrySnapshot) -> Result<usize, NtStatus> {
    size_of::<ObjectDirectoryInformation>()
        .checked_add(utf16_byte_len(&entry.name)?)
        .and_then(|size| size.checked_add(size_of::<u16>()))
        .and_then(|size| size.checked_add(utf16_byte_len(entry.type_name).ok()?))
        .and_then(|size| size.checked_add(size_of::<u16>()))
        .ok_or(NtStatus::NAME_TOO_LONG)
}

fn directory_query_required_size(entries: &[DirectoryEntrySnapshot]) -> Result<usize, NtStatus> {
    entries
        .iter()
        .try_fold(size_of::<ObjectDirectoryInformation>(), |size, entry| {
            size.checked_add(directory_record_size(entry)?)
                .ok_or(NtStatus::NAME_TOO_LONG)
        })
}

fn byte_offset(offset: usize) -> Result<isize, NtStatus> {
    isize::try_from(offset).map_err(|_| NtStatus::BUFFER_TOO_SMALL)
}

fn write_utf16_nul_terminated<Platform: RawPointerProvider>(
    buffer: MutPtr<Platform, u8>,
    offset: usize,
    value: &str,
) -> Result<(), NtStatus> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
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
    let maximum_length = len
        .checked_add(u16::try_from(size_of::<u16>()).expect("WCHAR size fits in USHORT"))
        .ok_or(NtStatus::NAME_TOO_LONG)?;
    Ok(UnicodeString {
        length: len,
        maximum_length,
        padding_0: [0; 4],
        buffer: buffer_base
            .checked_add(offset)
            .ok_or(NtStatus::NAME_TOO_LONG)?,
    })
}

fn write_directory_records<Platform: RawPointerProvider>(
    buffer: MutPtr<Platform, u8>,
    buffer_base: usize,
    entries: &[DirectoryEntrySnapshot],
) -> Result<(), NtStatus> {
    let header_size = size_of::<ObjectDirectoryInformation>();
    let mut string_offset = entries
        .len()
        .checked_add(1)
        .and_then(|records| records.checked_mul(header_size))
        .ok_or(NtStatus::NAME_TOO_LONG)?;

    for (index, entry) in entries.iter().enumerate() {
        let name_len = utf16_byte_len(&entry.name)?;
        let type_len = utf16_byte_len(entry.type_name)?;
        let name_offset = string_offset;
        let type_offset = name_offset
            .checked_add(name_len)
            .and_then(|offset| offset.checked_add(size_of::<u16>()))
            .ok_or(NtStatus::NAME_TOO_LONG)?;
        let record = ObjectDirectoryInformation::new(
            output_unicode_string(buffer_base, name_offset, name_len)?,
            output_unicode_string(buffer_base, type_offset, type_len)?,
        );
        buffer
            .write_slice_at_offset(
                byte_offset(
                    index
                        .checked_mul(header_size)
                        .ok_or(NtStatus::NAME_TOO_LONG)?,
                )?,
                record.as_bytes(),
            )
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
        write_utf16_nul_terminated::<Platform>(buffer, name_offset, &entry.name)?;
        write_utf16_nul_terminated::<Platform>(buffer, type_offset, entry.type_name)?;
        string_offset = type_offset
            .checked_add(type_len)
            .and_then(|offset| offset.checked_add(size_of::<u16>()))
            .ok_or(NtStatus::NAME_TOO_LONG)?;
    }

    let terminator_offset = entries
        .len()
        .checked_mul(header_size)
        .ok_or(NtStatus::NAME_TOO_LONG)?;
    buffer
        .write_slice_at_offset(
            byte_offset(terminator_offset)?,
            ObjectDirectoryInformation::zero().as_bytes(),
        )
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    Ok(())
}

fn probe_output_buffer<Platform: RawPointerProvider>(
    buffer: MutPtr<Platform, u8>,
    buffer_length: usize,
) -> Result<(), NtStatus> {
    if buffer_length == 0 {
        return Ok(());
    }
    let value = buffer.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION)?;
    buffer
        .write_at_offset(0, value)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    let last_offset = byte_offset(buffer_length - 1)?;
    let value = buffer
        .read_at_offset(last_offset)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    buffer
        .write_at_offset(last_offset, value)
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn directory_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, DirectoryObjectSubsystem<Platform>>, NtStatus>
    {
        self.typed_handle_entry::<DirectoryObjectSubsystem<Platform>>(handle)
    }

    fn directory_object_for_name_resolution(
        &self,
        handle: Handle,
    ) -> Result<Arc<ObjectNode<Platform>>, NtStatus> {
        let entry = self.directory_entry(handle)?;
        entry.with_entry(|entry| {
            entry.granted_access.require(DirectoryAccess::TRAVERSE)?;
            Ok(Arc::clone(&entry.directory))
        })
    }

    pub(super) fn read_directory_object_attributes(
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

        if object_attributes.object_name == 0 {
            if require_name {
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            if !object_attributes.root_directory.is_null() {
                // Wine and ReactOS match Windows: a NULL ObjectName plus RootDirectory
                // is invalid, while a present zero-length UNICODE_STRING creates unnamed.
                return Err(NtStatus::OBJECT_NAME_INVALID);
            }
            return Ok((Some(object_attributes), None));
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

        let original_path = if object_attributes.root_directory.is_null() {
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
        if original_path.len() > 1 && original_path[1..].contains(r"\\") {
            return Err(NtStatus::OBJECT_NAME_INVALID);
        }
        Ok((
            Some(object_attributes),
            Some(DirectoryName { original_path }),
        ))
    }

    fn insert_directory_handle(
        &self,
        directory: Arc<ObjectNode<Platform>>,
        granted_access: DirectoryAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<DirectoryObjectSubsystem<Platform>>(
            DirectoryHandleObject {
                directory,
                granted_access,
            },
            drop,
        )
    }

    pub(crate) fn close_directory_handle(&self, handle: Handle) {
        self.close_typed_handle::<DirectoryObjectSubsystem<Platform>>(handle, drop);
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
        if let Some(object_attributes) = object_attributes
            && ObjectAttributesFlags::from_bits_retain(object_attributes.attributes)
                .contains(ObjectAttributesFlags::OPENLINK)
        {
            return NtStatus::INVALID_PARAMETER;
        }
        let granted_access = DirectoryAccess::from_desired_access(desired_access);

        if let Some(directory_name) = directory_name {
            return self.process.directory_namespace.create_directory(
                &directory_name.original_path,
                |directory| {
                    let Some(object_attributes) = object_attributes else {
                        return NtStatus::INVALID_PARAMETER;
                    };
                    if !ObjectAttributesFlags::from_bits_retain(object_attributes.attributes)
                        .contains(ObjectAttributesFlags::OPENIF)
                    {
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

        let directory = Arc::new(ObjectNode::new_directory(
            String::new(),
            None,
            String::new(),
        ));
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
            Ok((Some(object_attributes), Some(directory_name))) => {
                if ObjectAttributesFlags::from_bits_retain(object_attributes.attributes)
                    .contains(ObjectAttributesFlags::OPENLINK)
                {
                    return NtStatus::INVALID_PARAMETER;
                }
                directory_name
            }
            Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
            Ok((None, Some(_))) => return NtStatus::INVALID_PARAMETER,
            Err(status) => return status,
        };
        let directory = {
            match self
                .process
                .directory_namespace
                .resolve_directory(&directory_name.original_path)
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
            object_name:% = directory_name.original_path.as_str(),
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
        let buffer_length = params.buffer_length as usize;
        if let Err(status) = probe_output_buffer::<Platform>(params.buffer, buffer_length) {
            return status;
        }

        let start_index = if params.restart_scan != 0 {
            0
        } else {
            let Some(context) = params.context.read_at_offset(0) else {
                return NtStatus::ACCESS_VIOLATION;
            };
            context as usize
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

        let end_for_required = if params.return_single_entry != 0 {
            start_index + 1
        } else {
            entries.len()
        };
        let total_required =
            match directory_query_required_size(&entries[start_index..end_for_required]) {
                Ok(size) => size,
                Err(status) => return status,
            };
        let first_required =
            match directory_query_required_size(core::slice::from_ref(&entries[start_index])) {
                Ok(size) => size,
                Err(status) => return status,
            };
        if buffer_length < first_required {
            if let Some(return_length) = params.return_length {
                let required = u32::try_from(total_required).map_err(|_| NtStatus::NAME_TOO_LONG);
                let Ok(required) = required else {
                    return NtStatus::NAME_TOO_LONG;
                };
                if return_length.write_at_offset(0, required).is_none() {
                    return NtStatus::ACCESS_VIOLATION;
                }
            }
            return if params.return_single_entry != 0 {
                NtStatus::BUFFER_TOO_SMALL
            } else {
                NtStatus::MORE_ENTRIES
            };
        }

        let buffer_base = params.buffer.as_usize();
        let mut next_index = start_index;
        let mut required_for_written = size_of::<ObjectDirectoryInformation>();
        while next_index < entries.len() {
            let entry_size = match directory_record_size(&entries[next_index]) {
                Ok(size) => size,
                Err(status) => return status,
            };
            if required_for_written
                .checked_add(entry_size)
                .is_none_or(|needed| needed > buffer_length)
            {
                break;
            }
            required_for_written += entry_size;
            next_index += 1;
            if params.return_single_entry != 0 {
                break;
            }
        }

        if let Err(status) = write_directory_records::<Platform>(
            params.buffer,
            buffer_base,
            &entries[start_index..next_index],
        ) {
            return status;
        }
        let status = if next_index < entries.len() {
            NtStatus::MORE_ENTRIES
        } else {
            NtStatus::SUCCESS
        };

        let context = u32::try_from(next_index).expect("directory entry count fits in ULONG");
        if params.context.write_at_offset(0, context).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = params.return_length {
            let Ok(returned) = u32::try_from(total_required) else {
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
        namespace.seed_directory(path);
    }
    namespace
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::platform::ThreadProvider;
    use litebox::utils::TruncateExt as _;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::{ObjectAttributes, ObjectAttributesFlags};
    use crate::tests::{
        TestPlatform, const_ptr, mut_ptr, null_mut_ptr, object_attributes, test_task,
        unicode_string, utf16_units,
    };

    const DIRECTORY_QUERY: u32 = 0x0000_0001;
    const DIRECTORY_TRAVERSE: u32 = 0x0000_0002;
    const DIRECTORY_ALL_ACCESS: u32 = 0x000f_000f;

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
        let name_len = read_u16(buffer, offset) as usize;
        let name_max = read_u16(buffer, offset + 2) as usize;
        let name_buffer = read_usize(buffer, offset + 8);
        let type_len = read_u16(buffer, offset + 16) as usize;
        let type_max = read_u16(buffer, offset + 18) as usize;
        let type_buffer = read_usize(buffer, offset + 24);
        assert_eq!(name_max, name_len + size_of::<u16>());
        assert_eq!(type_max, type_len + size_of::<u16>());
        let name_offset = name_buffer
            .checked_sub(buffer_base)
            .expect("name buffer points into output buffer");
        let type_offset = type_buffer
            .checked_sub(buffer_base)
            .expect("type buffer points into output buffer");
        assert_eq!(read_u16(buffer, name_offset + name_len), 0);
        assert_eq!(read_u16(buffer, type_offset + type_len), 0);
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
        let name_units = utf16_units(path);
        let name = unicode_string(&name_units);
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

    fn open_named_directory(task: &Task<TestPlatform, crate::tests::TestFS>, path: &str) -> Handle {
        let name_units = utf16_units(path);
        let name = unicode_string(&name_units);
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

    fn expected_record_size(name: &str, type_name: &str) -> usize {
        size_of::<ObjectDirectoryInformation>()
            + name.encode_utf16().count() * size_of::<u16>()
            + size_of::<u16>()
            + type_name.encode_utf16().count() * size_of::<u16>()
            + size_of::<u16>()
    }

    fn expected_query_size(entries: &[(&str, &str)]) -> usize {
        size_of::<ObjectDirectoryInformation>()
            + entries
                .iter()
                .map(|(name, type_name)| expected_record_size(name, type_name))
                .sum::<usize>()
    }

    #[test]
    fn open_seeded_root_directory_succeeds() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units = utf16_units(r"\");
            let name = unicode_string(&name_units);
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
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn open_directory_rejects_openlink_attribute() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let name_units = utf16_units(r"\BaseNamedObjects");
            let name = unicode_string(&name_units);
            let attrs = object_attributes(
                &name,
                (ObjectAttributesFlags::CASE_INSENSITIVE | ObjectAttributesFlags::OPENLINK).bits(),
            );
            let mut handle = Handle::default();

            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut handle),
                    DIRECTORY_QUERY,
                    Some(const_ptr(&attrs)),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(handle, Handle::default());
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
                let name_units = utf16_units(path);
                let name = unicode_string(&name_units);
                let attrs =
                    object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
    fn create_directory_distinguishes_null_object_name_from_empty_name() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let root_units = utf16_units(r"\BaseNamedObjects");
            let root_name = unicode_string(&root_units);
            let root_attrs =
                object_attributes(&root_name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let mut root = Handle::default();
            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut root),
                    DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
                    Some(const_ptr(&root_attrs)),
                ),
                NtStatus::SUCCESS
            );

            let null_name_with_root = ObjectAttributes {
                length: size_of::<ObjectAttributes>().trunc(),
                root_directory: root,
                object_name: 0,
                attributes: ObjectAttributesFlags::CASE_INSENSITIVE.bits(),
                security_descriptor: 0,
                security_quality_of_service: 0,
            };
            let mut handle = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut handle),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&null_name_with_root)),
                    Handle::default(),
                    0,
                ),
                NtStatus::OBJECT_NAME_INVALID
            );
            assert_eq!(handle, Handle::default());

            let null_name_without_root = ObjectAttributes {
                root_directory: Handle::default(),
                ..null_name_with_root
            };
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut handle),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&null_name_without_root)),
                    Handle::default(),
                    0,
                ),
                NtStatus::SUCCESS
            );
            assert_ne!(handle, Handle::default());
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);

            let empty_name_units: [u16; 0] = [];
            let empty_name = unicode_string(&empty_name_units);
            let empty_name_with_root = ObjectAttributes {
                root_directory: root,
                object_name: core::ptr::from_ref(&empty_name) as usize,
                ..null_name_with_root
            };
            handle = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut handle),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&empty_name_with_root)),
                    Handle::default(),
                    0,
                ),
                NtStatus::SUCCESS
            );
            assert_ne!(handle, Handle::default());
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(root), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_and_open_directory_relative_to_root_directory() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let root_units = utf16_units(r"\BaseNamedObjects");
            let root_name = unicode_string(&root_units);
            let root_attrs =
                object_attributes(&root_name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let mut root = Handle::default();
            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut root),
                    DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
                    Some(const_ptr(&root_attrs)),
                ),
                NtStatus::SUCCESS
            );

            let child_units = utf16_units("LiteBoxDirectory");
            let child_name = unicode_string(&child_units);
            let child_attrs = ObjectAttributes {
                length: size_of::<ObjectAttributes>().trunc(),
                root_directory: root,
                object_name: core::ptr::from_ref(&child_name) as usize,
                attributes: ObjectAttributesFlags::CASE_INSENSITIVE.bits(),
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
    fn directory_lookup_is_case_insensitive_and_case_preserving() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let mixed = create_named_directory(&task, r"\BaseNamedObjects\LiteBoxCaseMixed");
            let lower_open = open_named_directory(&task, r"\basenamedobjects\liteboxcasemixed");
            let trailing_open = open_named_directory(&task, r"\BaseNamedObjects\LiteBoxCaseMixed\");
            let lower_created =
                create_named_directory(&task, r"\BaseNamedObjects\liteboxcaselower");
            let upper_open = open_named_directory(&task, r"\BASENAMEDOBJECTS\LITEBOXCASELOWER");

            let duplicate_units = utf16_units(r"\basenamedobjects\liteboxcasemixed\");
            let duplicate_name = unicode_string(&duplicate_units);
            let duplicate_attrs = object_attributes(
                &duplicate_name,
                ObjectAttributesFlags::CASE_INSENSITIVE.bits(),
            );
            let mut duplicate = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut duplicate),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&duplicate_attrs)),
                    Handle::default(),
                    0,
                ),
                NtStatus::OBJECT_NAME_COLLISION
            );
            assert_eq!(duplicate, Handle::default());

            let parent = open_named_directory(&task, r"\BaseNamedObjects");
            let mut buffer = [0u8; 512];
            let mut context = 0u32;
            let mut return_length = 0u32;
            assert_eq!(
                task.sys_nt_query_directory_object(DirectoryQueryParameters {
                    directory_handle: parent,
                    buffer: mut_ptr(&mut buffer[0]),
                    buffer_length: buffer.len().trunc(),
                    return_single_entry: 0,
                    restart_scan: 1,
                    context: mut_ptr(&mut context),
                    return_length: Some(mut_ptr(&mut return_length)),
                }),
                NtStatus::SUCCESS
            );

            let first_record = read_directory_information(&buffer, 0);
            assert_eq!(
                first_record,
                ParsedDirectoryInformation {
                    name: "liteboxcaselower".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            let second_offset = size_of::<ObjectDirectoryInformation>();
            let second_record = read_directory_information(&buffer, second_offset);
            assert_eq!(
                second_record,
                ParsedDirectoryInformation {
                    name: "LiteBoxCaseMixed".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            assert_zero_directory_information(
                &buffer,
                second_offset + size_of::<ObjectDirectoryInformation>(),
            );
            assert_eq!(context, 2);
            assert_eq!(
                return_length as usize,
                expected_query_size(&[
                    ("liteboxcaselower", "Directory"),
                    ("LiteBoxCaseMixed", "Directory")
                ])
            );

            assert_eq!(task.sys_nt_close(parent), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(upper_open), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(lower_created), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(trailing_open), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(lower_open), NtStatus::SUCCESS);
            assert_eq!(task.sys_nt_close(mixed), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn relative_directory_name_requires_root_traverse_access() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let root_units = utf16_units(r"\BaseNamedObjects");
            let root_name = unicode_string(&root_units);
            let root_attrs =
                object_attributes(&root_name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let mut root = Handle::default();
            assert_eq!(
                task.sys_nt_open_directory_object(
                    mut_ptr(&mut root),
                    DIRECTORY_QUERY,
                    Some(const_ptr(&root_attrs)),
                ),
                NtStatus::SUCCESS
            );

            let child_units = utf16_units("LiteBoxTraverseDenied");
            let child_name = unicode_string(&child_units);
            let child_attrs = ObjectAttributes {
                length: size_of::<ObjectAttributes>().trunc(),
                root_directory: root,
                object_name: core::ptr::from_ref(&child_name) as usize,
                attributes: ObjectAttributesFlags::CASE_INSENSITIVE.bits(),
                security_descriptor: 0,
                security_quality_of_service: 0,
            };
            let mut child = Handle::default();
            assert_eq!(
                task.sys_nt_create_directory_object(
                    mut_ptr(&mut child),
                    DIRECTORY_ALL_ACCESS,
                    Some(const_ptr(&child_attrs)),
                    Handle::default(),
                    0,
                ),
                NtStatus::ACCESS_DENIED
            );
            assert_eq!(child, Handle::default());
            assert_eq!(task.sys_nt_close(root), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_nested_directory_after_parent_exists() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let parent_units = utf16_units(r"\BaseNamedObjects\LiteBoxTreeParent");
            let parent_name = unicode_string(&parent_units);
            let parent_attrs =
                object_attributes(&parent_name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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

            let child_units = utf16_units(r"\BaseNamedObjects\LiteBoxTreeParent\LiteBoxTreeChild");
            let child_name = unicode_string(&child_units);
            let child_attrs =
                object_attributes(&child_name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
            let name_units = utf16_units(r"\BaseNamedObjects\LiteBoxOpenIfDirectory");
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
                attributes: (ObjectAttributesFlags::CASE_INSENSITIVE
                    | ObjectAttributesFlags::OPENIF)
                    .bits(),
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
            let name_units = utf16_units(r"\BaseNamedObjects");
            let name = unicode_string(&name_units);
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

            let mut buffer = [0xffu8; 32];
            let mut context = 99u32;
            let mut return_length = u32::MAX;
            assert_eq!(
                task.sys_nt_query_directory_object(DirectoryQueryParameters {
                    directory_handle: handle,
                    buffer: mut_ptr(&mut buffer[0]),
                    buffer_length: buffer.len().trunc(),
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
                    buffer_length: buffer.len().trunc(),
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
                    name: "LiteBoxEnumA".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            let second_offset = size_of::<ObjectDirectoryInformation>();
            let second_record = read_directory_information(&buffer, second_offset);
            assert_eq!(
                second_record,
                ParsedDirectoryInformation {
                    name: "LiteBoxEnumB".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            assert_zero_directory_information(
                &buffer,
                second_offset + size_of::<ObjectDirectoryInformation>(),
            );
            assert_eq!(context, 2);
            assert_eq!(
                return_length as usize,
                expected_query_size(&[
                    ("LiteBoxEnumA", "Directory"),
                    ("LiteBoxEnumB", "Directory")
                ])
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
                    buffer_length: buffer.len().trunc(),
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
                    name: "LiteBoxSingleA".to_string(),
                    type_name: "Directory".to_string(),
                }
            );

            buffer.fill(0);
            assert_eq!(
                task.sys_nt_query_directory_object(DirectoryQueryParameters {
                    directory_handle: handle,
                    buffer: mut_ptr(&mut buffer[0]),
                    buffer_length: buffer.len().trunc(),
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
                    name: "LiteBoxSingleB".to_string(),
                    type_name: "Directory".to_string(),
                }
            );
            assert_zero_directory_information(&buffer, size_of::<ObjectDirectoryInformation>());
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
                    buffer_length: buffer.len().trunc(),
                    return_single_entry: 0,
                    restart_scan: 1,
                    context: mut_ptr(&mut context),
                    return_length: Some(mut_ptr(&mut return_length)),
                },),
                NtStatus::MORE_ENTRIES
            );
            assert_eq!(context, 99);
            assert_eq!(
                return_length as usize,
                expected_query_size(&[("LiteBoxSmall", "Directory")])
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
            let name_units = utf16_units(r"\BaseNamedObjects");
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
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
            let name_units = utf16_units(r"\MissingParent\Child");
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());

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
            let name_units = utf16_units(r"\");
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let mut host_handle = core::ptr::null_mut();
            // SAFETY: The object attributes and output handle point to live test
            // stack values for the duration of the host ntdll call.
            let host_status = unsafe {
                NtOpenDirectoryObject(&raw mut host_handle, DIRECTORY_QUERY, &raw const attrs)
            };
            if host_status == NtStatus::SUCCESS.as_raw() && !host_handle.is_null() {
                // SAFETY: NtOpenDirectoryObject returned this non-null handle with
                // STATUS_SUCCESS, so it is valid to close once here.
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

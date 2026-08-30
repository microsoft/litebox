// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::{align_of, offset_of, size_of};

use int_enum::IntEnum;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd};
use litebox::fs::errors::{
    FileStatusError, MkdirError, OpenError, PathError, ReadDirError, ReadError, SeekError,
    WriteError,
};
use litebox::fs::{FileStatus, FileType, Mode, OFlags, SeekWhence};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::byteorder::native_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::nt_types::{
    AccessMask, IoStatusBlock, ObjectAttributes, UnicodeString, read_object_attributes,
    read_unicode_string_at,
};
use crate::syscalls::Handle;
use crate::syscalls::condrv::{self, CondrvObject, CondrvStreamDirection, CondrvStreamObject};
use crate::syscalls::event::{EventAccess, EventSubsystem};
use crate::syscalls::file_path::{FilePathResolver, FilePathRoot, FileTarget};
use crate::syscalls::ksecdd;
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_buffer, probe_guest_output_preserving_value,
    raw_handle_entry, write_slice,
};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileAttributes: u32 {
        const READONLY = 0x0000_0001;
        const DIRECTORY = 0x0000_0010;
        const ARCHIVE = 0x0000_0020;
        const _ = !0;
    }
}

const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// Bound guest-controlled file I/O allocations while keeping backend call overhead reasonable.
const FILE_IO_CHUNK_SIZE: usize = 0x80_000;

/// Append at the current end of file
const FILE_WRITE_TO_END_OF_FILE: i64 = -1;

/// Use the file object's current position
const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

// These names and values are Windows ABI constants from WDK headers; Wine's
// regular file/directory branch and ReactOS' filesystem device query path use
// the same FILE_DEVICE_* and FILE_DEVICE_IS_MOUNTED vocabulary.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum FileDeviceType {
    Disk = 0x0000_0007,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileDeviceCharacteristics: u32 {
        const IS_MOUNTED = 0x0000_0020;
        const _ = !0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileCreateInformation {
    /// An existing file was deleted and a new file was created in its place.
    Superseded,
    /// An existing file was opened.
    Opened,
    Created,
    /// An existing file was overwritten.
    Overwritten,
    Exists,
    DoesNotExist,
    /// A value whose semantics are not described by the standard FILE_* results.
    Raw(usize),
}

impl From<FileCreateInformation> for usize {
    fn from(information: FileCreateInformation) -> Self {
        match information {
            FileCreateInformation::Superseded => 0,
            FileCreateInformation::Opened => 1,
            FileCreateInformation::Created => 2,
            FileCreateInformation::Overwritten => 3,
            FileCreateInformation::Exists => 4,
            FileCreateInformation::DoesNotExist => 5,
            FileCreateInformation::Raw(information) => information,
        }
    }
}

// TODO: NtSetVolumeInformationFile and sibling query classes
// (FileFsVolumeInformation=1, FileFsSizeInformation=3, FileFsAttributeInformation=5)
// are deferred until a guest exercises them; each needs host-grounded volume
// metadata LiteBox does not model yet. Add the variant and match arm when that boundary lands.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum FsInformationClass {
    FileFsDeviceInformation = 4,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
struct FileFsDeviceInformation {
    device_type: u32,
    characteristics: u32,
}

#[repr(u32)]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum FileHandleInformationClass {
    FileStandardInformation = 5,
    FilePositionInformation = 14,
}

#[repr(u32)]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum FileByNameInformationClass {
    FileStatBasicInformation = 77,
}

#[repr(u32)]
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum FileInformationClass {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileNamesInformation = 12,
    FileIdBothDirectoryInformation = 37,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct DirectoryInformationHeader {
    next_entry_offset: U32,
    file_index: U32,
}

impl DirectoryInformationHeader {
    fn new(file_index: u32) -> Self {
        Self {
            file_index: U32::new(file_index),
            ..Default::default()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct DirectoryInformationMetadata {
    header: DirectoryInformationHeader,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: u32,
    file_name_length: u32,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryQueryFlags: u32 {
        const RESTART_SCAN = 0x0000_0001;
        const RETURN_SINGLE_ENTRY = 0x0000_0002;
        const INDEX_SPECIFIED = 0x0000_0004;
        const RETURN_ON_DISK_ENTRIES_ONLY = 0x0000_0008;
        const NO_CURSOR_UPDATE_QUERY = 0x0000_0010;
        const _ = !0;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct FileDirectoryInformation {
    metadata: DirectoryInformationMetadata,
    // Placeholder for the first code unit of the variable-length UTF-16 name.
    file_name: [u16; 1],
    // Explicit trailing padding preserves native sizeof and keeps all bytes initialized.
    padding: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct FileFullDirectoryInformation {
    metadata: DirectoryInformationMetadata,
    ea_size: u32,
    // Placeholder for the first code unit of the variable-length UTF-16 name.
    file_name: [u16; 1],
    // Explicit trailing padding preserves native sizeof and keeps all bytes initialized.
    padding: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct FileBothDirectoryInformation {
    metadata: DirectoryInformationMetadata,
    ea_size: u32,
    short_name_length: u8,
    reserved: u8,
    short_name: [u16; 12],
    // Placeholder for the first code unit of the variable-length UTF-16 name.
    file_name: [u16; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct FileNamesInformation {
    header: DirectoryInformationHeader,
    file_name_length: u32,
    // Placeholder for the first code unit of the variable-length UTF-16 name.
    file_name: [u16; 1],
    // Explicit trailing padding preserves native sizeof and keeps all bytes initialized.
    padding: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct FileIdBothDirectoryInformation {
    metadata: DirectoryInformationMetadata,
    ea_size: u32,
    short_name_length: u8,
    reserved: u8,
    short_name: [u16; 12],
    // Explicit padding aligns file_id with the native ABI layout.
    padding: [u8; 2],
    file_id: i64,
    // Placeholder for the first code unit of the variable-length UTF-16 name.
    file_name: [u16; 1],
    // Explicit trailing padding preserves native sizeof and keeps all bytes initialized.
    trailing_padding: [u8; 6],
}

struct DirectoryEntry {
    name: String,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: FileAttributes,
    file_id: i64,
}

struct FileStatusMetadata {
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: FileAttributes,
    file_id: Option<u64>,
    file_id_128: [u8; 16],
}

impl FileStatusMetadata {
    fn from_status(status: &FileStatus) -> Self {
        let mut file_attributes = if status.file_type == FileType::Directory {
            FileAttributes::DIRECTORY
        } else {
            FileAttributes::ARCHIVE
        };
        if !status.mode.intersects(Mode::WUSR | Mode::WGRP | Mode::WOTH) {
            file_attributes.insert(FileAttributes::READONLY);
        }
        let end_of_file = i64::try_from(status.size).unwrap_or(i64::MAX);
        let allocation_size = status
            .size
            .checked_next_multiple_of(status.blksize.max(1))
            .and_then(|size| i64::try_from(size).ok())
            .unwrap_or(i64::MAX);
        let file_id = u64::try_from(status.node_info.ino).ok();
        let mut file_id_128 = [0; 16];
        if let Some(file_id) = file_id {
            file_id_128[..size_of::<u64>()].copy_from_slice(&file_id.to_ne_bytes());
        }
        Self {
            end_of_file,
            allocation_size,
            file_attributes,
            file_id,
            file_id_128,
        }
    }
}

impl DirectoryEntry {
    fn from_status(name: String, status: &FileStatus) -> Self {
        let metadata = FileStatusMetadata::from_status(status);
        Self {
            name,
            end_of_file: metadata.end_of_file,
            allocation_size: metadata.allocation_size,
            file_attributes: metadata.file_attributes,
            file_id: metadata
                .file_id
                .map_or(-1, |file_id| i64::from_ne_bytes(file_id.to_ne_bytes())),
        }
    }
}

impl DirectoryInformationMetadata {
    fn new(file_index: u32, file_name_length: u32, entry: &DirectoryEntry) -> Self {
        Self {
            header: DirectoryInformationHeader::new(file_index),
            end_of_file: entry.end_of_file,
            allocation_size: entry.allocation_size,
            file_attributes: entry.file_attributes.bits(),
            file_name_length,
            ..Default::default()
        }
    }
}

impl FileInformationClass {
    const fn minimum_size(self) -> usize {
        match self {
            Self::FileDirectoryInformation => size_of::<FileDirectoryInformation>(),
            Self::FileFullDirectoryInformation => size_of::<FileFullDirectoryInformation>(),
            Self::FileBothDirectoryInformation => size_of::<FileBothDirectoryInformation>(),
            Self::FileNamesInformation => size_of::<FileNamesInformation>(),
            Self::FileIdBothDirectoryInformation => size_of::<FileIdBothDirectoryInformation>(),
        }
    }

    fn encode_entry(self, entry: &DirectoryEntry, index: usize) -> Vec<u8> {
        let file_name_length =
            u32::try_from(entry.name.encode_utf16().count() * size_of::<u16>()).unwrap();
        let file_index = u32::try_from(index).unwrap_or(u32::MAX);
        // TODO(dir-timestamps): Populate timestamps, EA sizes, and short names once FileSystem
        // exposes them; the current API only supplies size, type, mode, and inode.
        let mut record = match self {
            Self::FileDirectoryInformation => {
                let information = FileDirectoryInformation {
                    metadata: DirectoryInformationMetadata::new(
                        file_index,
                        file_name_length,
                        entry,
                    ),
                    ..Default::default()
                };
                information.as_bytes()[..offset_of!(FileDirectoryInformation, file_name)].to_vec()
            }
            Self::FileFullDirectoryInformation => {
                let information = FileFullDirectoryInformation {
                    metadata: DirectoryInformationMetadata::new(
                        file_index,
                        file_name_length,
                        entry,
                    ),
                    ..Default::default()
                };
                information.as_bytes()[..offset_of!(FileFullDirectoryInformation, file_name)]
                    .to_vec()
            }
            Self::FileBothDirectoryInformation => {
                let information = FileBothDirectoryInformation {
                    metadata: DirectoryInformationMetadata::new(
                        file_index,
                        file_name_length,
                        entry,
                    ),
                    ..Default::default()
                };
                information.as_bytes()[..offset_of!(FileBothDirectoryInformation, file_name)]
                    .to_vec()
            }
            Self::FileNamesInformation => {
                let information = FileNamesInformation {
                    header: DirectoryInformationHeader::new(file_index),
                    file_name_length,
                    ..Default::default()
                };
                information.as_bytes()[..offset_of!(FileNamesInformation, file_name)].to_vec()
            }
            Self::FileIdBothDirectoryInformation => {
                let information = FileIdBothDirectoryInformation {
                    metadata: DirectoryInformationMetadata::new(
                        file_index,
                        file_name_length,
                        entry,
                    ),
                    file_id: entry.file_id,
                    ..Default::default()
                };
                information.as_bytes()[..offset_of!(FileIdBothDirectoryInformation, file_name)]
                    .to_vec()
            }
        };
        for unit in entry.name.encode_utf16() {
            record.extend_from_slice(&unit.to_ne_bytes());
        }
        record
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct FileBasicInformation {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
    _reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct FileStatBasicInformation {
    file_id: i64,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    allocation_size: i64,
    end_of_file: i64,
    file_attributes: u32,
    reparse_tag: u32,
    number_of_links: u32,
    device_type: u32,
    device_characteristics: u32,
    reserved: u32,
    volume_serial_number: i64,
    file_id_128: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, Immutable, IntoBytes)]
struct FileStandardInformation {
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
    padding: [u8; 2],
}

pub(crate) struct FileObjectSubsystem<FS>(PhantomData<fn(FS)>);

impl<FS: ShimFS> FdEnabledSubsystem for FileObjectSubsystem<FS> {
    type Entry = FileObject<FS>;
}

impl<FS: ShimFS> FdEnabledSubsystemEntry for FileObject<FS> {}

impl<FS: ShimFS> crate::WindowsHandleSubsystem for FileObjectSubsystem<FS> {
    fn normalize_desired_access(desired_access: u32) -> u32 {
        FileAccess::from_desired_access(desired_access).bits()
    }

    fn resolve_duplicate_access(entry: &Self::Entry, desired_access: u32) -> Result<u32, NtStatus> {
        let maximum_allowed = desired_access & AccessMask::MAXIMUM_ALLOWED.bits() != 0;
        let explicit_access =
            FileAccess::from_desired_access(desired_access & !AccessMask::MAXIMUM_ALLOWED.bits());
        if !entry.create_time_access.contains(explicit_access) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        Ok(if maximum_allowed {
            // TODO(dacl-access-check): Replace this original-open ceiling with a token and
            // security-descriptor access check when the shim models DACLs.
            entry.create_time_access.bits()
        } else {
            explicit_access.bits()
        })
    }
}

pub(crate) struct FileObject<FS: ShimFS> {
    path: String,
    backing: FileObjectBacking<FS>,
    create_time_access: FileAccess,
    share_access: FileShareAccess,
    create_options: FileCreateOptions,
    directory_query: DirectoryQueryState,
}

#[derive(Default)]
struct DirectoryQueryState {
    initialized: bool,
    pattern: Option<String>,
    position: usize,
    entries: Vec<DirectoryEntry>,
}

enum FileObjectBacking<FS: ShimFS> {
    Filesystem {
        fd: TypedFd<FS>,
        is_directory: bool,
    },
    CondrvStream {
        object: CondrvObject,
        stream_object: Arc<CondrvStreamObject>,
        fd: TypedFd<FS>,
    },
    CondrvControl(CondrvObject),
    /// A handle to `\Device\KsecDD`.
    KsecDevice,
}

/// The device a file handle routes `NtDeviceIoControlFile` to.
enum IoctlTarget {
    Condrv(CondrvObject),
    KsecDevice,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileIoOperation {
    Read,
    Write,
}

/// Result of [`Task::prepare_file_io`]: the resolved file entry handle together
/// with the resolved absolute byte offset (`None` when the current file-pointer
/// position should be used).
type PreparedFileIo<Platform, FS> = (
    litebox::fd::EntryHandle<Platform, FileObjectSubsystem<FS>>,
    Option<usize>,
);

#[derive(Clone, Copy)]
enum FileSharingIdentity<'a> {
    Path(&'a str),
    // TODO(condrv-share-access): native CONIN$/CONOUT$ permits multiple share-access-zero opens
    // of the same bound object; determine which ConDrv opens ignore sharing before enforcing it.
    CondrvObject(u64),
}

impl FileSharingIdentity<'_> {
    fn matches<FS: ShimFS>(self, file: &FileObject<FS>) -> bool {
        match self {
            Self::Path(path) => file.condrv_stream_object_id().is_none() && file.path == path,
            Self::CondrvObject(object_id) => file.condrv_stream_object_id() == Some(object_id),
        }
    }
}

impl<FS: ShimFS> FileObject<FS> {
    fn condrv_object(&self) -> Option<CondrvObject> {
        match self.backing {
            FileObjectBacking::CondrvStream { object, .. }
            | FileObjectBacking::CondrvControl(object) => Some(object),
            FileObjectBacking::Filesystem { .. } | FileObjectBacking::KsecDevice => None,
        }
    }

    fn ioctl_target(&self) -> IoctlTarget {
        match self.backing {
            FileObjectBacking::CondrvStream { object, .. }
            | FileObjectBacking::CondrvControl(object) => IoctlTarget::Condrv(object),
            FileObjectBacking::KsecDevice => IoctlTarget::KsecDevice,
            FileObjectBacking::Filesystem { .. } => IoctlTarget::Unsupported,
        }
    }

    fn condrv_stream_object_id(&self) -> Option<u64> {
        match &self.backing {
            FileObjectBacking::CondrvStream { stream_object, .. } => Some(stream_object.id()),
            FileObjectBacking::Filesystem { .. }
            | FileObjectBacking::CondrvControl(_)
            | FileObjectBacking::KsecDevice => None,
        }
    }

    fn is_directory(&self) -> bool {
        matches!(
            self.backing,
            FileObjectBacking::Filesystem {
                is_directory: true,
                ..
            }
        )
    }
}

bitflags::bitflags! {
    /// File object `ACCESS_MASK` rights accepted by `NtOpenFile`/`NtCreateFile`.
    ///
    /// Generic-right mappings and create/open disposition behavior follow
    /// Microsoft Learn's `NtCreateFile` documentation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct FileAccess: u32 {
        const READ_DATA = 0x0001;
        const LIST_DIRECTORY = Self::READ_DATA.bits();
        const WRITE_DATA = 0x0002;
        const ADD_FILE = Self::WRITE_DATA.bits();
        const APPEND_DATA = 0x0004;
        const ADD_SUBDIRECTORY = Self::APPEND_DATA.bits();
        const READ_EA = 0x0008;
        const WRITE_EA = 0x0010;
        const EXECUTE = 0x0020;
        const TRAVERSE = Self::EXECUTE.bits();
        const DELETE_CHILD = 0x0040;
        const READ_ATTRIBUTES = 0x0080;
        const WRITE_ATTRIBUTES = 0x0100;
        const DELETE = AccessMask::DELETE.bits();
        const SYNCHRONIZE = AccessMask::SYNCHRONIZE.bits();

        const GENERIC_READ_EXPANSION = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::READ_DATA.bits()
            | Self::READ_ATTRIBUTES.bits()
            | Self::READ_EA.bits()
            | Self::SYNCHRONIZE.bits();
        const GENERIC_WRITE_EXPANSION = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::WRITE_DATA.bits()
            | Self::WRITE_ATTRIBUTES.bits()
            | Self::WRITE_EA.bits()
            | Self::APPEND_DATA.bits()
            | Self::SYNCHRONIZE.bits();
        const GENERIC_EXECUTE_EXPANSION = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | Self::EXECUTE.bits()
            | Self::READ_ATTRIBUTES.bits()
            | Self::SYNCHRONIZE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::READ_DATA.bits()
            | Self::WRITE_DATA.bits()
            | Self::APPEND_DATA.bits()
            | Self::READ_EA.bits()
            | Self::WRITE_EA.bits()
            | Self::EXECUTE.bits()
            | Self::DELETE_CHILD.bits()
            | Self::READ_ATTRIBUTES.bits()
            | Self::WRITE_ATTRIBUTES.bits();

        const FS_READ_ACCESS = Self::READ_DATA.bits()
            | Self::READ_EA.bits()
            | Self::READ_ATTRIBUTES.bits()
            | Self::EXECUTE.bits();
        const FS_WRITE_ACCESS = Self::WRITE_DATA.bits()
            | Self::APPEND_DATA.bits()
            | Self::WRITE_EA.bits()
            | Self::WRITE_ATTRIBUTES.bits()
            | Self::DELETE.bits()
            | AccessMask::WRITE_DAC.bits()
            | AccessMask::WRITE_OWNER.bits();

        const SHARE_READ_ACCESS = Self::READ_DATA.bits()
            | Self::READ_EA.bits()
            | Self::READ_ATTRIBUTES.bits()
            | Self::EXECUTE.bits();
        const SHARE_WRITE_ACCESS = Self::WRITE_DATA.bits()
            | Self::APPEND_DATA.bits()
            | Self::WRITE_EA.bits()
            | Self::WRITE_ATTRIBUTES.bits();
        const SHARE_DELETE_ACCESS = Self::DELETE.bits()
            | Self::DELETE_CHILD.bits();

        const _ = !0;
    }
}

impl FileAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        Self::from_bits_retain(AccessMask::expand_generic_access(
            desired_access,
            Self::GENERIC_READ_EXPANSION.bits(),
            Self::GENERIC_WRITE_EXPANSION.bits(),
            Self::GENERIC_EXECUTE_EXPANSION.bits(),
            Self::ALL_ACCESS.bits(),
        ))
    }

    fn open_flags(
        self,
        create_disposition: CreateDisposition,
        create_options: FileCreateOptions,
    ) -> OFlags {
        let wants_read = self.intersects(Self::FS_READ_ACCESS);
        let wants_write = self.intersects(Self::FS_WRITE_ACCESS)
            || matches!(
                create_disposition,
                CreateDisposition::Supersede
                    | CreateDisposition::Overwrite
                    | CreateDisposition::OverwriteIf
            );

        let mut flags = match (wants_read, wants_write) {
            (true, true) => OFlags::RDWR,
            (false, true) => OFlags::WRONLY,
            _ => OFlags::RDONLY,
        };

        match create_disposition {
            CreateDisposition::Overwrite => {
                flags.insert(OFlags::TRUNC);
            }
            CreateDisposition::Supersede | CreateDisposition::OverwriteIf => {
                flags.insert(OFlags::CREAT | OFlags::TRUNC);
            }
            CreateDisposition::Create => flags.insert(OFlags::CREAT | OFlags::EXCL),
            CreateDisposition::OpenIf => flags.insert(OFlags::CREAT),
            CreateDisposition::Open => {}
        }

        if create_options.contains(FileCreateOptions::DIRECTORY_FILE) {
            flags.insert(OFlags::DIRECTORY);
        }
        if create_options.contains(FileCreateOptions::NON_DIRECTORY_FILE) {
            flags.insert(OFlags::NOFOLLOW);
        }

        flags
    }

    fn conflicts_with_share(self, share_access: FileShareAccess) -> bool {
        self.intersects(Self::SHARE_READ_ACCESS) && !share_access.contains(FileShareAccess::READ)
            || self.intersects(Self::SHARE_WRITE_ACCESS)
                && !share_access.contains(FileShareAccess::WRITE)
            || self.intersects(Self::SHARE_DELETE_ACCESS)
                && !share_access.contains(FileShareAccess::DELETE)
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct FileShareAccess: u32 {
        const READ = FILE_SHARE_READ;
        const WRITE = FILE_SHARE_WRITE;
        const DELETE = FILE_SHARE_DELETE;
        const _ = !0;
    }
}

impl FileShareAccess {
    const VALID_BITS: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    fn from_share_access(share_access: u32) -> Result<Self, NtStatus> {
        if share_access & !Self::VALID_BITS != 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self::from_bits_retain(share_access))
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct FileCreateOptions: u32 {
        const DIRECTORY_FILE = 0x0000_0001;
        const WRITE_THROUGH = 0x0000_0002;
        const SEQUENTIAL_ONLY = 0x0000_0004;
        const NO_INTERMEDIATE_BUFFERING = 0x0000_0008;
        const SYNCHRONOUS_IO_ALERT = 0x0000_0010;
        const SYNCHRONOUS_IO_NONALERT = 0x0000_0020;
        const NON_DIRECTORY_FILE = 0x0000_0040;
        const CREATE_TREE_CONNECTION = 0x0000_0080;
        const COMPLETE_IF_OPLOCKED = 0x0000_0100;
        const NO_EA_KNOWLEDGE = 0x0000_0200;
        const OPEN_REMOTE_INSTANCE = 0x0000_0400;
        const RANDOM_ACCESS = 0x0000_0800;
        const DELETE_ON_CLOSE = 0x0000_1000;
        const OPEN_BY_FILE_ID = 0x0000_2000;
        const OPEN_FOR_BACKUP_INTENT = 0x0000_4000;
        const NO_COMPRESSION = 0x0000_8000;
        const OPEN_REQUIRING_OPLOCK = 0x0001_0000;
        const DISALLOW_EXCLUSIVE = 0x0002_0000;
        const SESSION_AWARE = 0x0004_0000;
        const RESERVE_OPFILTER = 0x0010_0000;
        const OPEN_REPARSE_POINT = 0x0020_0000;
        const OPEN_NO_RECALL = 0x0040_0000;
        const OPEN_FOR_FREE_SPACE_QUERY = 0x0080_0000;
        const CONTAINS_EXTENDED_CREATE_INFORMATION = 0x1000_0000;

        const _ = !0;
    }
}

impl FileCreateOptions {
    const SYNCHRONOUS_IO: Self = Self::SYNCHRONOUS_IO_ALERT.union(Self::SYNCHRONOUS_IO_NONALERT);

    const DIRECTORY_COMPATIBLE: Self = Self::DIRECTORY_FILE
        .union(Self::SYNCHRONOUS_IO_ALERT)
        .union(Self::SYNCHRONOUS_IO_NONALERT)
        .union(Self::WRITE_THROUGH)
        .union(Self::COMPLETE_IF_OPLOCKED)
        .union(Self::OPEN_FOR_BACKUP_INTENT)
        .union(Self::DELETE_ON_CLOSE)
        .union(Self::OPEN_BY_FILE_ID)
        .union(Self::NO_COMPRESSION)
        .union(Self::OPEN_REPARSE_POINT)
        .union(Self::OPEN_FOR_FREE_SPACE_QUERY);
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum CreateDisposition {
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5,
}

impl CreateDisposition {
    fn success_information(self, existed_before_open: bool) -> FileCreateInformation {
        match (self, existed_before_open) {
            (Self::Supersede, true) => FileCreateInformation::Superseded,
            (Self::Supersede | Self::Create | Self::OpenIf | Self::OverwriteIf, false) => {
                FileCreateInformation::Created
            }
            (Self::Overwrite | Self::OverwriteIf, true) => FileCreateInformation::Overwritten,
            _ => FileCreateInformation::Opened,
        }
    }
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn file_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, FileObjectSubsystem<FS>>, NtStatus> {
        raw_handle_entry::<Platform, FileObjectSubsystem<FS>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
        )
        .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn file_io_entry(
        &self,
        handle: Handle,
        operation: FileIoOperation,
    ) -> Result<
        (
            litebox::fd::EntryHandle<Platform, FileObjectSubsystem<FS>>,
            bool,
        ),
        NtStatus,
    > {
        let mut append_only = false;
        let file = self.typed_handle_entry_with_access_check::<FileObjectSubsystem<FS>>(
            handle,
            |granted_access| match operation {
                FileIoOperation::Read => granted_access & FileAccess::READ_DATA.bits() != 0,
                FileIoOperation::Write => {
                    append_only = granted_access & FileAccess::WRITE_DATA.bits() == 0
                        && granted_access & FileAccess::APPEND_DATA.bits() != 0;
                    granted_access & (FileAccess::WRITE_DATA | FileAccess::APPEND_DATA).bits() != 0
                }
            },
        )?;
        Ok((file, append_only))
    }

    pub(crate) fn image_section_file_path(&self, handle: Handle) -> Result<String, NtStatus> {
        let entry = self.typed_handle_entry_with_access::<FileObjectSubsystem<FS>>(
            handle,
            FileAccess::EXECUTE.bits(),
        )?;
        entry.with_entry(|file| match &file.backing {
            FileObjectBacking::Filesystem {
                is_directory: false,
                ..
            } => Ok(file.path.clone()),
            FileObjectBacking::Filesystem {
                is_directory: true, ..
            }
            | FileObjectBacking::CondrvStream { .. }
            | FileObjectBacking::CondrvControl(_)
            | FileObjectBacking::KsecDevice => Err(NtStatus::INVALID_FILE_FOR_SECTION),
        })
    }

    fn insert_file_handle(&self, file: FileObject<FS>) -> Result<Handle, NtStatus> {
        let granted_access = file.create_time_access.bits();
        self.insert_typed_handle::<FileObjectSubsystem<FS>>(file, granted_access, |file| {
            self.close_file(file);
        })
    }

    pub(crate) fn close_file_handle(&self, handle: Handle) {
        self.close_typed_handle::<FileObjectSubsystem<FS>>(handle, |file| self.close_file(file));
    }

    pub(crate) fn close_file(&self, file: FileObject<FS>) {
        match file.backing {
            FileObjectBacking::Filesystem { fd, is_directory } => {
                let _ = self.fs.close(&fd);
                if file
                    .create_options
                    .contains(FileCreateOptions::DELETE_ON_CLOSE)
                {
                    if is_directory {
                        let _ = self.fs.rmdir(&file.path);
                    } else {
                        let _ = self.fs.unlink(&file.path);
                    }
                }
            }
            FileObjectBacking::CondrvStream { fd, .. } => {
                let _ = self.fs.close(&fd);
            }
            FileObjectBacking::CondrvControl(_) | FileObjectBacking::KsecDevice => {}
        }
    }

    pub(crate) fn sys_nt_open_file(
        &self,
        file_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        share_access: u32,
        open_options: u32,
    ) -> NtStatus {
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes::<Platform>(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        if let Err(status) = probe_file_outputs::<Platform>(file_handle, io_status_block) {
            return status;
        }

        let result = self.do_nt_create_file(
            desired_access,
            object_attributes,
            io_status_block,
            FileAttributes::READONLY.bits(),
            share_access,
            CreateDisposition::Open,
            open_options,
            None,
            0,
        );
        write_file_result::<Platform>(file_handle, io_status_block, result, |handle| {
            self.close_file_handle(handle);
        })
    }

    pub(crate) fn sys_nt_query_attributes_file(
        &self,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        file_information: MutPtr<Platform, FileBasicInformation>,
    ) -> NtStatus {
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, FileBasicInformation>(file_information)
        {
            return status;
        }
        let object_attributes = match read_object_attributes::<Platform>(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        let path = match self.object_attributes_to_file_target(object_attributes) {
            Ok(FileTarget::Filesystem(path)) => path,
            // TODO(condrv-attributes): Model native attributes for ConDrv objects.
            Ok(FileTarget::Condrv(object)) => {
                litebox_util_log::debug!(
                    object:? = object;
                    "NtQueryAttributesFile does not support ConDrv objects"
                );
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            }
            Ok(FileTarget::KsecDevice) => {
                litebox_util_log::debug!("NtQueryAttributesFile does not support \\Device\\KsecDD");
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            }
            Err(status) => return status,
        };
        let status = match self.fs.file_status(&path) {
            Ok(status) => status,
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)) => {
                let parent = parent_directory_path(&path);
                return if self.fs.file_status(parent).is_ok() {
                    NtStatus::OBJECT_NAME_NOT_FOUND
                } else {
                    NtStatus::OBJECT_PATH_NOT_FOUND
                };
            }
            Err(error) => return map_file_status_error(error),
        };
        let readonly = !status.mode.intersects(Mode::WUSR | Mode::WGRP | Mode::WOTH);
        let mut file_attributes = match status.file_type {
            FileType::Directory => FileAttributes::DIRECTORY,
            FileType::RegularFile => FileAttributes::ARCHIVE,
            // TODO(chardev-attributes): Probe native attributes for character devices and
            // future filesystem node types; regular files are host-grounded as ARCHIVE.
            file_type => {
                litebox_util_log::debug!(
                    path = path.as_str(),
                    file_type:? = file_type;
                    "Using archive attributes for nonstandard filesystem node"
                );
                FileAttributes::ARCHIVE
            }
        };
        if readonly {
            file_attributes |= FileAttributes::READONLY;
        }
        // TODO(fs-timestamps): Populate timestamps when FileStatus exposes them.
        litebox_util_log::debug!(
            path = path.as_str();
            "Using zero timestamps for file attributes"
        );
        let information = FileBasicInformation {
            file_attributes: file_attributes.bits(),
            ..FileBasicInformation::default()
        };
        if file_information.write_at_offset(0, information).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_information_by_name(
        &self,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_information: MutPtr<Platform, u8>,
        length: u32,
        file_information_class: u32,
    ) -> NtStatus {
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Ok(file_information_class) =
            FileByNameInformationClass::try_from(file_information_class)
        else {
            litebox_util_log::debug!(
                file_information_class = file_information_class;
                "Unsupported NtQueryInformationByName class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };
        match file_information_class {
            FileByNameInformationClass::FileStatBasicInformation => self
                .query_file_stat_basic_information(
                    object_attributes,
                    io_status_block,
                    file_information,
                    length,
                ),
        }
    }

    fn query_file_stat_basic_information(
        &self,
        object_attributes: ConstPtr<Platform, ObjectAttributes>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_information: MutPtr<Platform, u8>,
        length: u32,
    ) -> NtStatus {
        if length < size_of::<FileStatBasicInformation>().trunc() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
            || probe_guest_output_buffer::<Platform>(file_information, length as usize).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let object_attributes = match read_object_attributes::<Platform>(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        let path = match self.object_attributes_to_file_target(object_attributes) {
            Ok(FileTarget::Filesystem(path)) => path,
            Ok(FileTarget::Condrv(_) | FileTarget::KsecDevice) => {
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            }
            Err(status) => return status,
        };
        let status = match self.fs.file_status(&path) {
            Ok(status) => status,
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)) => {
                let parent = parent_directory_path(&path);
                return if self.fs.file_status(parent).is_ok() {
                    NtStatus::OBJECT_NAME_NOT_FOUND
                } else {
                    NtStatus::OBJECT_PATH_NOT_FOUND
                };
            }
            Err(error) => return map_file_status_error(error),
        };
        let metadata = FileStatusMetadata::from_status(&status);
        // TODO(fs-timestamps): Populate timestamps when FileStatus exposes them.
        let information = FileStatBasicInformation {
            file_id: metadata
                .file_id
                .map_or(0, |file_id| i64::from_ne_bytes(file_id.to_ne_bytes())),
            allocation_size: metadata.allocation_size,
            end_of_file: metadata.end_of_file,
            file_attributes: metadata.file_attributes.bits(),
            number_of_links: 1,
            device_type: FileDeviceType::Disk as u32,
            file_id_128: metadata.file_id_128,
            ..FileStatBasicInformation::default()
        };
        let output =
            MutPtr::<Platform, FileStatBasicInformation>::from_usize(file_information.as_usize());
        if output.write_at_offset(0, information).is_none()
            || io_status_block
                .write_at_offset(
                    0,
                    IoStatusBlock::success(size_of::<FileStatBasicInformation>()),
                )
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_information_file(
        &self,
        file_handle: Handle,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_information: MutPtr<Platform, u8>,
        length: u32,
        file_information_class: u32,
    ) -> NtStatus {
        let Ok(file_information_class) =
            FileHandleInformationClass::try_from(file_information_class)
        else {
            litebox_util_log::debug!(
                file_information_class = file_information_class;
                "Unsupported NtQueryInformationFile class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };
        match file_information_class {
            FileHandleInformationClass::FileStandardInformation => self
                .query_file_standard_information(
                    file_handle,
                    io_status_block,
                    file_information,
                    length,
                ),
            FileHandleInformationClass::FilePositionInformation => self
                .query_file_position_information(
                    file_handle,
                    io_status_block,
                    file_information,
                    length,
                ),
        }
    }

    fn query_file_standard_information(
        &self,
        file_handle: Handle,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_information: MutPtr<Platform, u8>,
        length: u32,
    ) -> NtStatus {
        if length < size_of::<FileStandardInformation>().trunc() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
            || probe_guest_output_buffer::<Platform>(file_information, length as usize).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let file = match self.file_entry(file_handle) {
            Ok(file) => file,
            Err(status) => return status,
        };
        let status = match file.with_entry(|file| match &file.backing {
            FileObjectBacking::Filesystem { fd, .. }
            | FileObjectBacking::CondrvStream { fd, .. } => {
                self.fs.fd_file_status(fd).map_err(map_file_status_error)
            }
            FileObjectBacking::CondrvControl(_) | FileObjectBacking::KsecDevice => {
                Err(NtStatus::INVALID_DEVICE_REQUEST)
            }
        }) {
            Ok(status) => status,
            Err(status) => return status,
        };
        let metadata = FileStatusMetadata::from_status(&status);
        let information = FileStandardInformation {
            allocation_size: metadata.allocation_size,
            end_of_file: metadata.end_of_file,
            number_of_links: 1,
            directory: u8::from(status.file_type == FileType::Directory),
            ..FileStandardInformation::default()
        };
        let output =
            MutPtr::<Platform, FileStandardInformation>::from_usize(file_information.as_usize());
        if output.write_at_offset(0, information).is_none()
            || io_status_block
                .write_at_offset(
                    0,
                    IoStatusBlock::success(size_of::<FileStandardInformation>()),
                )
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn query_file_position_information(
        &self,
        file_handle: Handle,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_information: MutPtr<Platform, u8>,
        length: u32,
    ) -> NtStatus {
        if length < size_of::<i64>().trunc() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
            || probe_guest_output_buffer::<Platform>(file_information, length as usize).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let file = match self.typed_handle_entry_with_access_check::<FileObjectSubsystem<FS>>(
            file_handle,
            |granted_access| {
                granted_access & (FileAccess::READ_DATA | FileAccess::WRITE_DATA).bits() != 0
            },
        ) {
            Ok(file) => file,
            Err(status) => return status,
        };
        let result = file.with_entry(|file| {
            if !file
                .create_options
                .intersects(FileCreateOptions::SYNCHRONOUS_IO)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let seek = match &file.backing {
                FileObjectBacking::Filesystem { fd, is_directory } => {
                    if *is_directory {
                        return Err(NtStatus::INVALID_DEVICE_REQUEST);
                    }
                    self.fs.seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                }
                FileObjectBacking::CondrvStream { fd, .. } => {
                    self.fs.seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                }
                FileObjectBacking::CondrvControl(_) | FileObjectBacking::KsecDevice => {
                    return Err(NtStatus::INVALID_DEVICE_REQUEST);
                }
            };
            match seek {
                Ok(position) => Ok(position),
                Err(SeekError::ClosedFd) => Err(NtStatus::INVALID_HANDLE),
                Err(SeekError::NonSeekable | SeekError::InvalidOffset) => {
                    Err(NtStatus::INVALID_DEVICE_REQUEST)
                }
                Err(_) => Err(NtStatus::UNSUCCESSFUL),
            }
        });
        let position = match result {
            Ok(position) => i64::try_from(position).unwrap_or(i64::MAX),
            Err(status) => return status,
        };
        let output = MutPtr::<Platform, i64>::from_usize(file_information.as_usize());
        if output.write_at_offset(0, position).is_none()
            || io_status_block
                .write_at_offset(0, IoStatusBlock::success(size_of::<i64>()))
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_set_information_file(
        &self,
        file_handle: Handle,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_information: ConstPtr<Platform, u8>,
        length: u32,
        file_information_class: u32,
    ) -> NtStatus {
        // TODO(windows-file-completion): Support FileCompletionInformation to associate a file
        // handle with an IO completion port and its completion key.
        if FileHandleInformationClass::try_from(file_information_class)
            != Ok(FileHandleInformationClass::FilePositionInformation)
        {
            litebox_util_log::debug!(
                file_information_class = file_information_class;
                "Unsupported NtSetInformationFile class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        }
        if length < size_of::<i64>().trunc() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let position = ConstPtr::<Platform, i64>::from_usize(file_information.as_usize());
        let Some(position) = position.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Ok(position) = isize::try_from(position) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if position < 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let file = match self.typed_handle_entry_with_access_check::<FileObjectSubsystem<FS>>(
            file_handle,
            |granted_access| {
                granted_access & (FileAccess::READ_DATA | FileAccess::WRITE_DATA).bits() != 0
            },
        ) {
            Ok(file) => file,
            Err(status) => return status,
        };
        let result = file.with_entry(|file| {
            if !file
                .create_options
                .intersects(FileCreateOptions::SYNCHRONOUS_IO)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let seek = match &file.backing {
                FileObjectBacking::Filesystem { fd, is_directory } => {
                    if *is_directory {
                        return Err(NtStatus::INVALID_DEVICE_REQUEST);
                    }
                    self.fs.seek(fd, position, SeekWhence::RelativeToBeginning)
                }
                FileObjectBacking::CondrvStream { fd, .. } => {
                    self.fs.seek(fd, position, SeekWhence::RelativeToBeginning)
                }
                FileObjectBacking::CondrvControl(_) | FileObjectBacking::KsecDevice => {
                    return Err(NtStatus::INVALID_DEVICE_REQUEST);
                }
            };
            match seek {
                Ok(_) => Ok(()),
                Err(SeekError::ClosedFd) => Err(NtStatus::INVALID_HANDLE),
                Err(SeekError::InvalidOffset) => Err(NtStatus::INVALID_PARAMETER),
                Err(SeekError::NonSeekable) => Err(NtStatus::INVALID_DEVICE_REQUEST),
                Err(_) => Err(NtStatus::UNSUCCESSFUL),
            }
        });
        let completion = match result {
            Ok(()) => IoStatusBlock::success(0),
            Err(status) => IoStatusBlock::failure(status),
        };
        if io_status_block.write_at_offset(0, completion).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::from_raw(completion.status.cast_unsigned())
    }

    // TODO(query-full-attributes): Implement NtQueryFullAttributesFile when a guest needs
    // allocation size and end-of-file metadata in addition to basic attributes.

    #[expect(
        clippy::too_many_arguments,
        reason = "NtCreateFile has eleven ABI parameters; keeping the syscall handler aligned with that shape avoids argument reshuffling bugs"
    )]
    pub(crate) fn sys_nt_create_file(
        &self,
        file_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        _allocation_size: Option<ConstPtr<Platform, i64>>,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: Option<ConstPtr<Platform, u8>>,
        ea_length: u32,
    ) -> NtStatus {
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes::<Platform>(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        let Ok(create_disposition) = CreateDisposition::try_from(create_disposition) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if let Err(status) = probe_file_outputs::<Platform>(file_handle, io_status_block) {
            return status;
        }
        let result = self.do_nt_create_file(
            desired_access,
            object_attributes,
            io_status_block,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea_buffer,
            ea_length,
        );
        write_file_result::<Platform>(file_handle, io_status_block, result, |handle| {
            self.close_file_handle(handle);
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtWriteFile has nine ABI parameters; keeping them explicit preserves syscall ordering"
    )]
    pub(crate) fn sys_nt_write_file(
        &self,
        file_handle: Handle,
        event: Handle,
        apc_routine: Option<ConstPtr<Platform, u8>>,
        apc_context: Option<ConstPtr<Platform, u8>>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        buffer: ConstPtr<Platform, u8>,
        length: u32,
        byte_offset: Option<ConstPtr<Platform, i64>>,
        key: Option<ConstPtr<Platform, u32>>,
    ) -> NtStatus {
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let input_length = length as usize;
        if buffer.as_usize().checked_add(input_length).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        let (file, offset) = match self.prepare_file_io(
            file_handle,
            event,
            apc_routine,
            apc_context,
            byte_offset,
            key,
            FileIoOperation::Write,
            input_length,
        ) {
            Ok(prepared) => prepared,
            Err(status) => return status,
        };
        let mut total_written = 0;
        let result = loop {
            if total_written == input_length {
                break Ok(total_written);
            }
            let chunk_length = (input_length - total_written).min(FILE_IO_CHUNK_SIZE);
            let chunk_address = buffer.as_usize() + total_written;
            let Some(bytes) =
                ConstPtr::<Platform, u8>::from_usize(chunk_address).to_owned_slice(chunk_length)
            else {
                return NtStatus::ACCESS_VIOLATION;
            };
            let chunk_offset = offset.map(|offset| offset + total_written);
            let write = file.with_entry(|file| match &file.backing {
                FileObjectBacking::Filesystem { fd, is_directory } => {
                    if *is_directory {
                        return Err(WriteError::NotAFile);
                    }
                    self.fs.write(fd, &bytes, chunk_offset)
                }
                FileObjectBacking::CondrvStream { fd, .. } => {
                    self.fs.write(fd, &bytes, chunk_offset)
                }
                FileObjectBacking::CondrvControl(_) | FileObjectBacking::KsecDevice => {
                    Err(WriteError::NotAFile)
                }
            });
            let written = match write {
                Ok(0) => break Ok(total_written),
                Ok(written) => written,
                Err(_) if total_written != 0 => break Ok(total_written),
                Err(error) => break Err(error),
            };
            total_written += written;
            if written < chunk_length {
                break Ok(total_written);
            }
        };
        if result.is_ok()
            && let Some(offset) = offset
        {
            file.with_entry(|file| {
                if let FileObjectBacking::Filesystem { fd, .. } = &file.backing
                    && file
                        .create_options
                        .intersects(FileCreateOptions::SYNCHRONOUS_IO)
                    && input_length != 0
                {
                    let _ = self.fs.seek(
                        fd,
                        (offset + total_written).cast_signed(),
                        SeekWhence::RelativeToBeginning,
                    );
                }
            });
        }
        let completion = match result {
            Ok(written) => IoStatusBlock::success(written),
            Err(WriteError::ClosedFd) => IoStatusBlock::failure(NtStatus::INVALID_HANDLE),
            Err(WriteError::NotForWriting) => IoStatusBlock::failure(NtStatus::ACCESS_DENIED),
            Err(WriteError::NotAFile) => IoStatusBlock::failure(NtStatus::INVALID_DEVICE_REQUEST),
            Err(_) => IoStatusBlock::failure(NtStatus::UNSUCCESSFUL),
        };
        self.complete_file_io(event, io_status_block, completion)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtReadFile has nine ABI parameters; keeping them explicit preserves syscall ordering"
    )]
    pub(crate) fn sys_nt_read_file(
        &self,
        file_handle: Handle,
        event: Handle,
        apc_routine: Option<ConstPtr<Platform, u8>>,
        apc_context: Option<ConstPtr<Platform, u8>>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        buffer: MutPtr<Platform, u8>,
        length: u32,
        byte_offset: Option<ConstPtr<Platform, i64>>,
        key: Option<ConstPtr<Platform, u32>>,
    ) -> NtStatus {
        let output_length = length as usize;
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
            || buffer.as_usize().checked_add(output_length).is_none()
            || probe_guest_output_buffer::<Platform>(buffer, output_length).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let mut bytes = match file_io_buffer(output_length) {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let (file, offset) = match self.prepare_file_io(
            file_handle,
            event,
            apc_routine,
            apc_context,
            byte_offset,
            key,
            FileIoOperation::Read,
            output_length,
        ) {
            Ok(prepared) => prepared,
            Err(status) => return status,
        };
        let mut total_read = 0;
        let mut guest_write_failed = false;
        let result = file.with_entry(|file| {
            loop {
                if total_read == output_length {
                    break;
                }
                let chunk_length = (output_length - total_read).min(bytes.len());
                let chunk_offset = offset.map(|offset| offset + total_read);
                let (read, continue_after_full_chunk) = match &file.backing {
                    FileObjectBacking::Filesystem { fd, is_directory } => {
                        if *is_directory {
                            return Err(ReadError::NotAFile);
                        }
                        (
                            self.fs.read(fd, &mut bytes[..chunk_length], chunk_offset),
                            true,
                        )
                    }
                    // TODO(condrv-large-read): Continue with per-operation nonblocking reads
                    // after the first chunk once FileSystem can report WouldBlock.
                    FileObjectBacking::CondrvStream { fd, .. } => (
                        self.fs.read(fd, &mut bytes[..chunk_length], chunk_offset),
                        false,
                    ),
                    FileObjectBacking::CondrvControl(_) | FileObjectBacking::KsecDevice => {
                        return Err(ReadError::NotAFile);
                    }
                };
                let read = match read {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(_) if total_read != 0 => break,
                    Err(error) => return Err(error),
                };
                if buffer.copy_from_slice(total_read, &bytes[..read]).is_none() {
                    guest_write_failed = true;
                    return Err(ReadError::Io);
                }
                total_read += read;
                if read < chunk_length || !continue_after_full_chunk {
                    break;
                }
            }
            if let Some(offset) = offset
                && let FileObjectBacking::Filesystem { fd, .. } = &file.backing
                && file
                    .create_options
                    .intersects(FileCreateOptions::SYNCHRONOUS_IO)
                && output_length != 0
            {
                let _ = self.fs.seek(
                    fd,
                    (offset + total_read).cast_signed(),
                    SeekWhence::RelativeToBeginning,
                );
            }
            Ok(total_read)
        });
        if guest_write_failed {
            return NtStatus::ACCESS_VIOLATION;
        }
        let completion = match result {
            Ok(0) if output_length == 0 => IoStatusBlock::success(0),
            Ok(0) => IoStatusBlock::failure(NtStatus::END_OF_FILE),
            Ok(read) => IoStatusBlock::success(read),
            Err(ReadError::ClosedFd) => IoStatusBlock::failure(NtStatus::INVALID_HANDLE),
            Err(ReadError::NotForReading) => IoStatusBlock::failure(NtStatus::ACCESS_DENIED),
            Err(ReadError::NotAFile) => IoStatusBlock::failure(NtStatus::INVALID_DEVICE_REQUEST),
            Err(_) => IoStatusBlock::failure(NtStatus::UNSUCCESSFUL),
        };
        self.complete_file_io(event, io_status_block, completion)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "shared NtReadFile/NtWriteFile ABI preparation keeps validation order consistent"
    )]
    fn prepare_file_io(
        &self,
        file_handle: Handle,
        event: Handle,
        apc_routine: Option<ConstPtr<Platform, u8>>,
        apc_context: Option<ConstPtr<Platform, u8>>,
        byte_offset: Option<ConstPtr<Platform, i64>>,
        key: Option<ConstPtr<Platform, u32>>,
        operation: FileIoOperation,
        length: usize,
    ) -> Result<PreparedFileIo<Platform, FS>, NtStatus> {
        if !event.is_null() {
            self.check_event_modify_access(event)?;
        }
        let (file, append_only) = self.file_io_entry(file_handle, operation)?;
        let requested_offset = match byte_offset {
            Some(byte_offset) => Some(
                byte_offset
                    .read_at_offset(0)
                    .ok_or(NtStatus::ACCESS_VIOLATION)?,
            ),
            None => None,
        };
        let offset = match requested_offset {
            requested_offset
                if append_only
                    || requested_offset == Some(FILE_WRITE_TO_END_OF_FILE)
                        && operation == FileIoOperation::Write =>
            {
                let status = file
                    .with_entry(|file| self.fs.file_status(&file.path))
                    .map_err(map_file_status_error)?;
                Some(status.size)
            }
            Some(FILE_USE_FILE_POINTER_POSITION) | None => None,
            Some(offset) if offset >= 0 => {
                Some(usize::try_from(offset).map_err(|_| NtStatus::INVALID_PARAMETER)?)
            }
            Some(_) => return Err(NtStatus::INVALID_PARAMETER),
        };
        if let Some(key) = key {
            let Some(key) = key.read_at_offset(0) else {
                return Err(NtStatus::ACCESS_VIOLATION);
            };
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw(),
                key = key,
                operation:? = operation;
                "Ignoring file I/O byte-range lock key; byte-range locking is not supported yet"
            );
        }
        if offset.is_some_and(|offset| offset.checked_add(length).is_none()) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !event.is_null() {
            self.clear_event(event)?;
        }
        if apc_routine.is_some() || apc_context.is_some() {
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw(),
                operation:? = operation;
                "Ignoring file I/O APC completion arguments for synchronous completion"
            );
        }
        Ok((file, offset))
    }

    fn complete_file_io(
        &self,
        event: Handle,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        completion: IoStatusBlock,
    ) -> NtStatus {
        if io_status_block.write_at_offset(0, completion).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if !event.is_null() {
            let event_status = self.set_event(event);
            if event_status != NtStatus::SUCCESS {
                return event_status;
            }
        }
        NtStatus::from_raw(completion.status.cast_unsigned())
    }

    pub(crate) fn sys_nt_query_volume_information_file(
        &self,
        file_handle: Handle,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        fs_information: MutPtr<Platform, u8>,
        length: u32,
        fs_information_class: u32,
    ) -> NtStatus {
        let Ok(fs_information_class) = FsInformationClass::try_from(fs_information_class) else {
            litebox_util_log::debug!(
                fs_information_class = fs_information_class;
                "Unsupported NtQueryVolumeInformationFile class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match fs_information_class {
            FsInformationClass::FileFsDeviceInformation => self.write_file_fs_device_information(
                file_handle,
                io_status_block,
                fs_information,
                length,
            ),
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw(),
                length = length,
                fs_information_class:? = fs_information_class;
                "Handled NtQueryVolumeInformationFile syscall"
            );
        }

        status
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtQueryDirectoryFileEx has ten ABI parameters; keeping them explicit preserves syscall ordering"
    )]
    pub(crate) fn sys_nt_query_directory_file_ex(
        &self,
        file_handle: Handle,
        event: Handle,
        apc_routine: Option<ConstPtr<Platform, u8>>,
        apc_context: Option<ConstPtr<Platform, u8>>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_information: MutPtr<Platform, u8>,
        length: u32,
        file_information_class: u32,
        query_flags: u32,
        file_name: Option<ConstPtr<Platform, UnicodeString>>,
    ) -> NtStatus {
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if !file_information
            .as_usize()
            .is_multiple_of(align_of::<u32>())
        {
            return NtStatus::DATATYPE_MISALIGNMENT;
        }
        if probe_guest_output_buffer::<Platform>(file_information, length as usize).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }
        let supplied_pattern = match file_name {
            Some(file_name) => match file_name
                .read_at_offset(0)
                .ok_or(NtStatus::ACCESS_VIOLATION)
                .and_then(UnicodeString::read_string::<Platform>)
            {
                Ok(pattern) => Some(pattern),
                Err(status) => return status,
            },
            None => None,
        };
        let Ok(file_information_class) = FileInformationClass::try_from(file_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        if (length as usize) < file_information_class.minimum_size() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        let file = match self.typed_handle_entry_with_access::<FileObjectSubsystem<FS>>(
            file_handle,
            FileAccess::LIST_DIRECTORY.bits(),
        ) {
            Ok(file) => file,
            Err(status) => return status,
        };
        if !event.is_null() {
            if let Err(status) = self.check_event_modify_access(event) {
                return status;
            }
            if let Err(status) = self.clear_event(event) {
                return status;
            }
        }
        if apc_routine.is_some() || apc_context.is_some() {
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw();
                "Ignoring NtQueryDirectoryFileEx APC completion arguments for synchronous completion"
            );
        }

        let flags = DirectoryQueryFlags::from_bits_retain(query_flags);
        let result = file.with_entry_mut(|file| {
            self.query_directory(
                file,
                supplied_pattern,
                file_information_class,
                flags,
                length as usize,
            )
        });
        let (status, output) = match result {
            Ok(result) => result,
            Err(status) => (status, Vec::new()),
        };
        litebox_util_log::debug!(
            file_handle = file_handle.as_raw(),
            file_information_class:? = file_information_class,
            query_flags:% = format_args!("{query_flags:#x}"),
            status:% = status,
            information = output.len();
            "Handled NtQueryDirectoryFileEx syscall"
        );
        if write_slice::<Platform, u8>(file_information.as_usize(), &output).is_none()
            || io_status_block
                .write_at_offset(0, IoStatusBlock::new(status, output.len()))
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if !event.is_null() {
            let event_status = self.set_event(event);
            if event_status != NtStatus::SUCCESS {
                return event_status;
            }
        }
        status
    }

    fn query_directory(
        &self,
        file: &mut FileObject<FS>,
        supplied_pattern: Option<String>,
        information_class: FileInformationClass,
        flags: DirectoryQueryFlags,
        length: usize,
    ) -> Result<(NtStatus, Vec<u8>), NtStatus> {
        let first_query = !file.directory_query.initialized;
        let restarts = flags.intersects(
            DirectoryQueryFlags::RESTART_SCAN | DirectoryQueryFlags::NO_CURSOR_UPDATE_QUERY,
        );
        let mut fresh_entries = if first_query || restarts {
            Some(self.read_directory_entries(file)?)
        } else {
            None
        };
        if first_query {
            file.directory_query.initialized = true;
            file.directory_query.pattern = supplied_pattern;
        }
        if first_query
            || flags.contains(DirectoryQueryFlags::RESTART_SCAN)
            || file.directory_query.entries.is_empty()
        {
            file.directory_query.entries = fresh_entries.take().unwrap_or_default();
        }
        let entries = if flags.contains(DirectoryQueryFlags::NO_CURSOR_UPDATE_QUERY) && !first_query
        {
            fresh_entries
                .as_deref()
                .unwrap_or(&file.directory_query.entries)
        } else {
            &file.directory_query.entries
        };
        let pattern = file.directory_query.pattern.as_deref();
        let matching_entries: Vec<_> = entries
            .iter()
            .filter(|entry| directory_name_matches(pattern, &entry.name))
            .collect();
        let start = if restarts {
            0
        } else {
            file.directory_query.position
        };
        if start >= matching_entries.len() {
            let status = if first_query || restarts {
                NtStatus::NO_SUCH_FILE
            } else {
                NtStatus::NO_MORE_FILES
            };
            return Ok((status, Vec::new()));
        }

        let mut output = Vec::new();
        let mut next_position = start;
        let mut previous_record_start = None;
        for (relative_index, entry) in matching_entries[start..].iter().enumerate() {
            let record = information_class.encode_entry(entry, start + relative_index);
            let record_start = align_up(output.len(), 8);
            if record_start + record.len() > length {
                if output.is_empty() {
                    output.resize(length, 0);
                    output.copy_from_slice(&record[..length]);
                    return Ok((NtStatus::BUFFER_OVERFLOW, output));
                }
                break;
            }
            if let Some(previous_record_start) = previous_record_start {
                output.resize(record_start, 0);
                let previous_record = &mut output[previous_record_start..record_start];
                let (previous_header, _) =
                    DirectoryInformationHeader::mut_from_prefix(previous_record)
                        .map_err(|_| NtStatus::INVALID_PARAMETER)?;
                let next_entry_offset = u32::try_from(record_start - previous_record_start)
                    .map_err(|_| NtStatus::INVALID_PARAMETER)?;
                previous_header.next_entry_offset.set(next_entry_offset);
            }
            output.extend_from_slice(&record);
            previous_record_start = Some(record_start);
            next_position += 1;
            if flags.contains(DirectoryQueryFlags::RETURN_SINGLE_ENTRY) {
                break;
            }
        }
        if !flags.contains(DirectoryQueryFlags::NO_CURSOR_UPDATE_QUERY) {
            file.directory_query.position = next_position;
        }
        Ok((NtStatus::SUCCESS, output))
    }

    fn read_directory_entries(
        &self,
        file: &FileObject<FS>,
    ) -> Result<Vec<DirectoryEntry>, NtStatus> {
        let FileObjectBacking::Filesystem { fd, is_directory } = &file.backing else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if !is_directory {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        let current_status = self.fs.fd_file_status(fd).map_err(map_file_status_error)?;
        let parent_path = parent_directory_path(&file.path);
        let parent_status = self
            .fs
            .file_status(parent_path)
            .map_err(map_file_status_error)?;
        let mut entries = alloc::vec![
            DirectoryEntry::from_status(String::from("."), &current_status),
            DirectoryEntry::from_status(String::from(".."), &parent_status),
        ];
        for entry in self.fs.read_dir(fd).map_err(map_read_dir_error)? {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let path = child_path(&file.path, &entry.name);
            let status = self.fs.file_status(path).map_err(map_file_status_error)?;
            entries.push(DirectoryEntry::from_status(entry.name, &status));
        }
        Ok(entries)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "NtDeviceIoControlFile has ten ABI parameters; keeping them explicit preserves syscall ordering"
    )]
    pub(crate) fn sys_nt_device_io_control_file(
        &self,
        file_handle: Handle,
        event: Handle,
        apc_routine: Option<ConstPtr<Platform, u8>>,
        apc_context: Option<ConstPtr<Platform, u8>>,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        io_control_code: u32,
        input_buffer: Option<ConstPtr<Platform, u8>>,
        input_buffer_length: u32,
        output_buffer: Option<MutPtr<Platform, u8>>,
        output_buffer_length: u32,
    ) -> NtStatus {
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block)
        {
            return status;
        }
        if !event.is_null()
            && let Err(status) = self.check_event_modify_access(event)
        {
            return status;
        }

        let ioctl_target = match self.file_entry(file_handle) {
            Ok(entry) => entry.with_entry(FileObject::ioctl_target),
            Err(status) => return status,
        };
        if !event.is_null()
            && let Err(status) = self.clear_event(event)
        {
            return status;
        }
        if apc_routine.is_some() || apc_context.is_some() {
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw(),
                apc_context = apc_context.map_or(0, |context| context.as_usize());
                "Ignoring NtDeviceIoControlFile APC completion arguments for synchronous completion"
            );
        }
        let status = match ioctl_target {
            IoctlTarget::Condrv(condrv_object) => condrv::handle_ioctl::<Platform>(
                condrv_object,
                io_control_code,
                input_buffer,
                input_buffer_length,
                output_buffer,
                output_buffer_length,
            ),
            IoctlTarget::KsecDevice => ksecdd::handle_ioctl::<Platform>(
                self.global.platform,
                io_control_code,
                input_buffer,
                input_buffer_length,
                output_buffer,
                output_buffer_length,
                |event| {
                    self.require_handle_access::<EventSubsystem<Platform>>(
                        event,
                        EventAccess::ALL_ACCESS.bits(),
                    )
                },
            ),
            IoctlTarget::Unsupported => {
                litebox_util_log::debug!(
                    file_handle = file_handle.as_raw(),
                    io_control_code:% = format_args!("{io_control_code:#x}");
                    "Unsupported NtDeviceIoControlFile for file handle"
                );
                return NtStatus::INVALID_DEVICE_REQUEST;
            }
        };
        if io_status_block.write_at_offset(0, status).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if !event.is_null() {
            let event_status = self.set_event(event);
            if event_status != NtStatus::SUCCESS {
                return event_status;
            }
        }
        NtStatus::from_raw(status.status.cast_unsigned())
    }

    fn write_file_fs_device_information(
        &self,
        file_handle: Handle,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        fs_information: MutPtr<Platform, u8>,
        length: u32,
    ) -> NtStatus {
        if length < u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        let fs_information =
            MutPtr::<Platform, FileFsDeviceInformation>::from_usize(fs_information.as_usize());
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
            || probe_guest_output_preserving_value::<Platform, FileFsDeviceInformation>(
                fs_information,
            )
            .is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        let Ok(_file) = self.file_entry(file_handle) else {
            return NtStatus::INVALID_HANDLE;
        };

        let info = FileFsDeviceInformation {
            device_type: FileDeviceType::Disk as u32,
            characteristics: FileDeviceCharacteristics::IS_MOUNTED.bits(),
        };
        if fs_information.write_at_offset(0, info).is_none()
            || io_status_block
                .write_at_offset(
                    0,
                    IoStatusBlock::success(size_of::<FileFsDeviceInformation>()),
                )
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    // Microsoft Learn documents `NtCreateFile` as the common create/open primitive,
    // with `NtOpenFile` being its open-existing subset.
    #[expect(
        clippy::too_many_arguments,
        reason = "This helper carries the parsed NtCreateFile ABI fields through one shared NtOpenFile/NtCreateFile path"
    )]
    fn do_nt_create_file(
        &self,
        desired_access: u32,
        object_attributes: ObjectAttributes,
        io_status_block: MutPtr<Platform, IoStatusBlock>,
        file_attributes: u32,
        share_access: u32,
        create_disposition: CreateDisposition,
        create_options: u32,
        ea_buffer: Option<ConstPtr<Platform, u8>>,
        ea_length: u32,
    ) -> Result<(Handle, FileCreateInformation), NtStatus> {
        if io_status_block.as_usize() == 0 {
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        if object_attributes.object_name == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let desired_access = FileAccess::from_desired_access(desired_access);
        let create_options = FileCreateOptions::from_bits_retain(create_options);
        validate_create_options(desired_access, create_disposition, create_options)?;

        let share_access = FileShareAccess::from_share_access(share_access)?;
        let (file, information) = match self.object_attributes_to_file_target(object_attributes)? {
            FileTarget::Filesystem(path) => {
                if ea_buffer.is_some() || ea_length != 0 {
                    return Err(NtStatus::EAS_NOT_SUPPORTED);
                }
                self.open_filesystem_target(
                    path,
                    desired_access,
                    share_access,
                    create_disposition,
                    create_options,
                    file_attributes,
                )
            }
            FileTarget::Condrv(object) => self.open_condrv_target(
                object,
                desired_access,
                share_access,
                create_disposition,
                create_options,
                ea_buffer,
                ea_length,
            ),
            FileTarget::KsecDevice => {
                Self::open_ksecdd_target(desired_access, share_access, create_options)
            }
        }?;
        let handle = self.insert_file_handle(file)?;
        Ok((handle, information))
    }

    fn open_filesystem_target(
        &self,
        path: String,
        desired_access: FileAccess,
        share_access: FileShareAccess,
        create_disposition: CreateDisposition,
        create_options: FileCreateOptions,
        file_attributes: u32,
    ) -> Result<(FileObject<FS>, FileCreateInformation), NtStatus> {
        self.check_file_sharing(
            FileSharingIdentity::Path(&path),
            desired_access,
            share_access,
        )?;
        if create_options.contains(FileCreateOptions::DIRECTORY_FILE) {
            return self.open_or_create_directory(
                &path,
                desired_access,
                share_access,
                create_disposition,
                create_options,
                file_attributes,
            );
        }

        let (fd, is_directory, information) = self.open_backing_fd(
            &path,
            desired_access,
            create_disposition,
            create_options,
            create_mode(file_attributes),
        )?;
        Ok((
            FileObject {
                path,
                backing: FileObjectBacking::Filesystem { fd, is_directory },
                create_time_access: desired_access,
                share_access,
                create_options,
                directory_query: DirectoryQueryState::default(),
            },
            information,
        ))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "ConDrv creation validates the parsed NtCreateFile fields at the device boundary"
    )]
    fn open_condrv_target(
        &self,
        object: CondrvObject,
        desired_access: FileAccess,
        share_access: FileShareAccess,
        create_disposition: CreateDisposition,
        create_options: FileCreateOptions,
        ea_buffer: Option<ConstPtr<Platform, u8>>,
        ea_length: u32,
    ) -> Result<(FileObject<FS>, FileCreateInformation), NtStatus> {
        if object == CondrvObject::Connect {
            condrv::validate_connect_server_ea::<Platform>(ea_buffer, ea_length)?;
        } else if ea_buffer.is_some() || ea_length != 0 {
            return Err(NtStatus::EAS_NOT_SUPPORTED);
        }
        if create_options.contains(FileCreateOptions::DIRECTORY_FILE) {
            return Err(NtStatus::NOT_A_DIRECTORY);
        }

        let path = String::from(object.handle_path());
        let (backing, information) = if let Some(direction) = object.stream_direction() {
            let stream_object = self.process.condrv_console.open_stream(object)?;
            self.check_file_sharing(
                FileSharingIdentity::CondrvObject(stream_object.id()),
                desired_access,
                share_access,
            )?;
            let backing_access = match direction {
                CondrvStreamDirection::Input => FileAccess::READ_DATA,
                CondrvStreamDirection::Output => FileAccess::WRITE_DATA,
            };
            // Native ConDrv applies FILE_CREATE to the logical stream, not its transport.
            let backing_disposition = match create_disposition {
                CreateDisposition::Create => CreateDisposition::Open,
                disposition => disposition,
            };
            let (fd, _, _) = self.open_backing_fd(
                &path,
                backing_access,
                backing_disposition,
                create_options,
                Mode::empty(),
            )?;
            (
                FileObjectBacking::CondrvStream {
                    object,
                    stream_object,
                    fd,
                },
                // TODO(condrv-create-information): Determine the meaning of native ConDrv's
                // opaque IoStatusBlock.Information values and model them if guests require them.
                FileCreateInformation::Raw(0),
            )
        } else {
            self.check_file_sharing(
                FileSharingIdentity::Path(&path),
                desired_access,
                share_access,
            )?;
            (
                FileObjectBacking::CondrvControl(object),
                FileCreateInformation::Opened,
            )
        };
        Ok((
            FileObject {
                path,
                backing,
                create_time_access: desired_access,
                share_access,
                create_options,
                directory_query: DirectoryQueryState::default(),
            },
            information,
        ))
    }

    fn open_ksecdd_target(
        desired_access: FileAccess,
        share_access: FileShareAccess,
        create_options: FileCreateOptions,
    ) -> Result<(FileObject<FS>, FileCreateInformation), NtStatus> {
        if create_options.contains(FileCreateOptions::DIRECTORY_FILE) {
            return Err(NtStatus::NOT_A_DIRECTORY);
        }
        Ok((
            FileObject {
                path: String::from(r"\Device\KsecDD"),
                backing: FileObjectBacking::KsecDevice,
                create_time_access: desired_access,
                share_access,
                create_options,
                directory_query: DirectoryQueryState::default(),
            },
            FileCreateInformation::Opened,
        ))
    }

    fn open_backing_fd(
        &self,
        path: &str,
        desired_access: FileAccess,
        create_disposition: CreateDisposition,
        create_options: FileCreateOptions,
        mode: Mode,
    ) -> Result<(TypedFd<FS>, bool, FileCreateInformation), NtStatus> {
        let existed_before_open = self.fs.file_status(path).is_ok();
        if create_disposition == CreateDisposition::Supersede
            && existed_before_open
            && !desired_access.contains(FileAccess::DELETE)
        {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let flags = desired_access.open_flags(create_disposition, create_options);
        let fd = self
            .fs
            .open(path, flags, mode)
            .map_err(|error| map_open_error(error, create_disposition))?;
        let file_status = match self.fs.fd_file_status(&fd) {
            Ok(file_status) => file_status,
            Err(error) => {
                let _ = self.fs.close(&fd);
                return Err(map_file_status_error(error));
            }
        };
        if create_options.contains(FileCreateOptions::NON_DIRECTORY_FILE)
            && file_status.file_type == FileType::Directory
        {
            let _ = self.fs.close(&fd);
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        let information = create_disposition.success_information(existed_before_open);
        Ok((
            fd,
            file_status.file_type == FileType::Directory,
            information,
        ))
    }

    fn open_or_create_directory(
        &self,
        path: &str,
        desired_access: FileAccess,
        share_access: FileShareAccess,
        create_disposition: CreateDisposition,
        create_options: FileCreateOptions,
        file_attributes: u32,
    ) -> Result<(FileObject<FS>, FileCreateInformation), NtStatus> {
        if matches!(
            create_disposition,
            CreateDisposition::Supersede
                | CreateDisposition::Overwrite
                | CreateDisposition::OverwriteIf
        ) {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        let existed_before_open = match self.fs.file_status(path) {
            Ok(status) => {
                if status.file_type != FileType::Directory {
                    return Err(NtStatus::NOT_A_DIRECTORY);
                }
                true
            }
            Err(_)
                if matches!(
                    create_disposition,
                    CreateDisposition::Create | CreateDisposition::OpenIf
                ) =>
            {
                self.fs
                    .mkdir(path, create_directory_mode(file_attributes))
                    .map_err(map_mkdir_error)?;
                false
            }
            Err(error) => return Err(map_file_status_error(error)),
        };

        let open_disposition = if existed_before_open {
            create_disposition
        } else {
            CreateDisposition::Open
        };
        let flags = desired_access.open_flags(open_disposition, create_options);
        let fd = self
            .fs
            .open(path, flags, Mode::empty())
            .map_err(|error| map_open_error(error, create_disposition))?;
        let information = create_disposition.success_information(existed_before_open);
        Ok((
            FileObject {
                path: String::from(path),
                backing: FileObjectBacking::Filesystem {
                    fd,
                    is_directory: true,
                },
                create_time_access: desired_access,
                share_access,
                create_options,
                directory_query: DirectoryQueryState::default(),
            },
            information,
        ))
    }

    fn object_attributes_to_file_target(
        &self,
        object_attributes: ObjectAttributes,
    ) -> Result<FileTarget, NtStatus> {
        let object_name = read_unicode_string_at::<Platform>(object_attributes.object_name)?;
        let resolver = FilePathResolver::new(&self.process.object_manager);
        if object_attributes.root_directory.is_null() {
            return resolver.resolve(FilePathRoot::Namespace, &object_name);
        }

        let root_file = self.file_entry(object_attributes.root_directory)?;
        root_file.with_entry(|root_file| {
            if let Some(parent) = root_file.condrv_object() {
                return resolver.resolve(FilePathRoot::Condrv(parent), &object_name);
            }
            resolver.resolve(
                FilePathRoot::Filesystem {
                    path: &root_file.path,
                    is_directory: root_file.is_directory(),
                },
                &object_name,
            )
        })
    }

    fn check_file_sharing(
        &self,
        identity: FileSharingIdentity<'_>,
        desired_access: FileAccess,
        share_access: FileShareAccess,
    ) -> Result<(), NtStatus> {
        let raw_handles: alloc::vec::Vec<usize> =
            self.process.handles.read().iter_alive().collect();
        for raw_handle in raw_handles {
            let Some(handle) = Handle::from_raw_fd(raw_handle) else {
                continue;
            };
            let Some(entry) = raw_handle_entry::<Platform, FileObjectSubsystem<FS>>(
                &self.global.litebox,
                &self.process.handles,
                handle,
            ) else {
                continue;
            };
            let conflicts = entry.with_entry(|file| {
                identity.matches(file)
                    && (desired_access.conflicts_with_share(file.share_access)
                        || file.create_time_access.conflicts_with_share(share_access))
            });
            if conflicts {
                return Err(NtStatus::SHARING_VIOLATION);
            }
        }
        Ok(())
    }
}

fn probe_file_outputs<Platform: RawPointerProvider>(
    file_handle: MutPtr<Platform, Handle>,
    io_status_block: MutPtr<Platform, IoStatusBlock>,
) -> Result<(), NtStatus> {
    probe_guest_output_preserving_value::<Platform, Handle>(file_handle)?;
    probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block)
}

fn file_io_buffer(length: usize) -> Result<Vec<u8>, NtStatus> {
    let capacity = length.min(FILE_IO_CHUNK_SIZE);
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(capacity)
        .map_err(|_| NtStatus::NO_MEMORY)?;
    buffer.resize(capacity, 0);
    Ok(buffer)
}

fn write_file_result<Platform: RawPointerProvider>(
    file_handle: MutPtr<Platform, Handle>,
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    result: Result<(Handle, FileCreateInformation), NtStatus>,
    cleanup_handle: impl FnOnce(Handle),
) -> NtStatus {
    match result {
        Ok((handle, information)) => {
            if write_file_success::<Platform>(file_handle, io_status_block, handle, information)
                .is_none()
            {
                cleanup_handle(handle);
                return NtStatus::ACCESS_VIOLATION;
            }
            NtStatus::SUCCESS
        }
        Err(status) => {
            let _ = io_status_block.write_at_offset(
                0,
                IoStatusBlock::new(status, failure_information(status).into()),
            );
            status
        }
    }
}

fn write_file_success<Platform: RawPointerProvider>(
    file_handle: MutPtr<Platform, Handle>,
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    handle: Handle,
    information: FileCreateInformation,
) -> Option<()> {
    file_handle.write_at_offset(0, Handle::default())?;
    io_status_block
        .write_at_offset(0, IoStatusBlock::new(NtStatus::SUCCESS, information.into()))?;
    file_handle.write_at_offset(0, handle)
}

fn failure_information(status: NtStatus) -> FileCreateInformation {
    match status {
        NtStatus::OBJECT_NAME_COLLISION => FileCreateInformation::Exists,
        NtStatus::OBJECT_NAME_NOT_FOUND | NtStatus::OBJECT_PATH_NOT_FOUND => {
            FileCreateInformation::DoesNotExist
        }
        _ => FileCreateInformation::Raw(0),
    }
}

fn validate_create_options(
    desired_access: FileAccess,
    create_disposition: CreateDisposition,
    create_options: FileCreateOptions,
) -> Result<(), NtStatus> {
    if create_options.contains(FileCreateOptions::DIRECTORY_FILE)
        && matches!(
            create_disposition,
            CreateDisposition::Supersede
                | CreateDisposition::Overwrite
                | CreateDisposition::OverwriteIf
        )
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    if create_options.contains(FileCreateOptions::DIRECTORY_FILE)
        && !create_options
            .difference(FileCreateOptions::DIRECTORY_COMPATIBLE)
            .is_empty()
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    if create_options.contains(FileCreateOptions::SYNCHRONOUS_IO) {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    if create_options.intersects(FileCreateOptions::SYNCHRONOUS_IO)
        && !desired_access.contains(FileAccess::SYNCHRONIZE)
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    if create_options.contains(FileCreateOptions::NO_INTERMEDIATE_BUFFERING)
        && desired_access.contains(FileAccess::APPEND_DATA)
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    if create_options.contains(FileCreateOptions::DELETE_ON_CLOSE)
        && !desired_access.contains(FileAccess::DELETE)
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    Ok(())
}

fn create_mode(file_attributes: u32) -> Mode {
    if FileAttributes::from_bits_retain(file_attributes).contains(FileAttributes::READONLY) {
        Mode::RUSR
    } else {
        Mode::RUSR | Mode::WUSR
    }
}

fn create_directory_mode(file_attributes: u32) -> Mode {
    create_mode(file_attributes) | Mode::XUSR
}

fn align_up(value: usize, alignment: usize) -> usize {
    value
        .checked_next_multiple_of(alignment)
        .unwrap_or(usize::MAX)
}

fn parent_directory_path(path: &str) -> &str {
    let path = path.trim_end_matches('/');
    path.rsplit_once('/').map_or(
        "/",
        |(parent, _)| if parent.is_empty() { "/" } else { parent },
    )
}

fn child_path(parent: &str, child: &str) -> String {
    if parent == "/" {
        alloc::format!("/{child}")
    } else {
        alloc::format!("{parent}/{child}")
    }
}

fn directory_name_matches(pattern: Option<&str>, name: &str) -> bool {
    let Some(pattern) = pattern else {
        return true;
    };
    // TODO(nt-directory-collation): Use the guest NT upcase table when it becomes available
    // instead of Rust Unicode lowercase mappings for non-ASCII case-insensitive matching.
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let name: Vec<char> = name.to_lowercase().chars().collect();
    let mut memo = alloc::vec![alloc::vec![None; name.len() + 1]; pattern.len() + 1];
    directory_name_matches_at(&pattern, &name, 0, 0, &mut memo)
}

fn directory_name_matches_at(
    pattern: &[char],
    name: &[char],
    pattern_index: usize,
    name_index: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    if let Some(result) = memo[pattern_index][name_index] {
        return result;
    }
    let result = match pattern.get(pattern_index).copied() {
        None => name_index == name.len(),
        Some('*') => {
            directory_name_matches_at(pattern, name, pattern_index + 1, name_index, memo)
                || name_index < name.len()
                    && directory_name_matches_at(pattern, name, pattern_index, name_index + 1, memo)
        }
        Some('?') => {
            name_index < name.len()
                && directory_name_matches_at(pattern, name, pattern_index + 1, name_index + 1, memo)
        }
        Some('<') => {
            directory_name_matches_at(pattern, name, pattern_index + 1, name_index, memo)
                || name_index < name.len()
                    && (name[name_index] != '.' || name[name_index + 1..].contains(&'.'))
                    && directory_name_matches_at(pattern, name, pattern_index, name_index + 1, memo)
        }
        Some('>') => {
            if name_index == name.len() || name[name_index] == '.' {
                directory_name_matches_at(pattern, name, pattern_index + 1, name_index, memo)
            } else {
                directory_name_matches_at(pattern, name, pattern_index + 1, name_index + 1, memo)
            }
        }
        Some('"') => {
            (name_index == name.len()
                && directory_name_matches_at(pattern, name, pattern_index + 1, name_index, memo))
                || (name.get(name_index) == Some(&'.')
                    && directory_name_matches_at(
                        pattern,
                        name,
                        pattern_index + 1,
                        name_index + 1,
                        memo,
                    ))
        }
        Some(character) => {
            name.get(name_index) == Some(&character)
                && directory_name_matches_at(pattern, name, pattern_index + 1, name_index + 1, memo)
        }
    };
    memo[pattern_index][name_index] = Some(result);
    result
}

fn map_open_error(error: OpenError, create_disposition: CreateDisposition) -> NtStatus {
    match error {
        OpenError::PathError(error) => match error {
            PathError::NoSuchFileOrDirectory => match create_disposition {
                CreateDisposition::Create
                | CreateDisposition::OpenIf
                | CreateDisposition::OverwriteIf
                | CreateDisposition::Supersede => NtStatus::OBJECT_PATH_NOT_FOUND,
                CreateDisposition::Open | CreateDisposition::Overwrite => {
                    NtStatus::OBJECT_NAME_NOT_FOUND
                }
            },
            PathError::MissingComponent => NtStatus::OBJECT_PATH_NOT_FOUND,
            PathError::ComponentNotADirectory => NtStatus::NOT_A_DIRECTORY,
            PathError::InvalidPathname => NtStatus::INVALID_PARAMETER,
            PathError::NoSearchPerms { .. } => NtStatus::UNSUCCESSFUL,
        },
        OpenError::AccessNotAllowed | OpenError::NoWritePerms | OpenError::ReadOnlyFileSystem => {
            NtStatus::ACCESS_DENIED
        }
        OpenError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_file_status_error(error: FileStatusError) -> NtStatus {
    match error {
        FileStatusError::PathError(PathError::NoSuchFileOrDirectory) => {
            NtStatus::OBJECT_NAME_NOT_FOUND
        }
        FileStatusError::PathError(PathError::MissingComponent) => NtStatus::OBJECT_PATH_NOT_FOUND,
        FileStatusError::PathError(PathError::ComponentNotADirectory) => NtStatus::NOT_A_DIRECTORY,
        FileStatusError::PathError(PathError::InvalidPathname) => NtStatus::INVALID_PARAMETER,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_read_dir_error(error: ReadDirError) -> NtStatus {
    match error {
        ReadDirError::ClosedFd => NtStatus::INVALID_HANDLE,
        ReadDirError::NotADirectory => NtStatus::NOT_A_DIRECTORY,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_mkdir_error(error: MkdirError) -> NtStatus {
    match error {
        MkdirError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        MkdirError::PathError(PathError::NoSuchFileOrDirectory | PathError::MissingComponent) => {
            NtStatus::OBJECT_PATH_NOT_FOUND
        }
        MkdirError::PathError(PathError::ComponentNotADirectory) => NtStatus::NOT_A_DIRECTORY,
        MkdirError::PathError(PathError::InvalidPathname) => NtStatus::INVALID_PARAMETER,
        MkdirError::NoWritePerms | MkdirError::ReadOnlyFileSystem => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        TestFS, TestPlatform, const_ptr, mut_byte_ptr, mut_ptr, null_mut_ptr, object_attributes,
        run_with_test_platform_pointers, unicode_string, utf16_units as utf16,
    };
    use litebox::fs::FileSystem as _;

    extern crate std;

    const FILE_GENERIC_READ: u32 = AccessMask::STANDARD_RIGHTS_READ.bits()
        | FileAccess::READ_DATA.bits()
        | FileAccess::READ_ATTRIBUTES.bits()
        | FileAccess::READ_EA.bits()
        | AccessMask::SYNCHRONIZE.bits();
    const FILE_GENERIC_WRITE: u32 = AccessMask::STANDARD_RIGHTS_WRITE.bits()
        | FileAccess::WRITE_DATA.bits()
        | FileAccess::WRITE_ATTRIBUTES.bits()
        | FileAccess::WRITE_EA.bits()
        | FileAccess::APPEND_DATA.bits()
        | AccessMask::SYNCHRONIZE.bits();
    const FILE_SUPERSEDE: u32 = 0;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_OVERWRITE: u32 = 4;

    fn open_object_attributes(
        path: &str,
    ) -> (
        std::vec::Vec<u16>,
        std::boxed::Box<UnicodeString>,
        ObjectAttributes,
    ) {
        let path = utf16(path);
        let name = std::boxed::Box::new(unicode_string(&path));
        let attributes = object_attributes(&name, 0);
        (path, name, attributes)
    }

    fn create_existing_file(task: &Task<TestPlatform, TestFS>, path: &str, data: &[u8]) {
        let fd = task
            .fs
            .open(path, OFlags::CREAT | OFlags::RDWR, Mode::RUSR | Mode::WUSR)
            .unwrap();
        assert_eq!(task.fs.write(&fd, data, Some(0)).unwrap(), data.len());
        task.fs.close(&fd).unwrap();
    }

    fn create_file(
        task: &Task<TestPlatform, TestFS>,
        path: &str,
        desired_access: u32,
        create_disposition: u32,
    ) -> (NtStatus, Handle, IoStatusBlock) {
        let (_path, _name, attributes) = open_object_attributes(path);
        let mut handle = Handle::default();
        let mut io_status = IoStatusBlock::default();
        let status = task.sys_nt_create_file(
            mut_ptr(&mut handle),
            desired_access,
            Some(const_ptr(&attributes)),
            mut_ptr(&mut io_status),
            None,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            create_disposition,
            FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
            None,
            0,
        );
        (status, handle, io_status)
    }

    fn open_fs_root(task: &Task<TestPlatform, TestFS>) -> Handle {
        let (_path, _name, attributes) = open_object_attributes("/");
        let mut handle = Handle::default();
        let mut io_status = IoStatusBlock::default();
        assert_eq!(
            task.sys_nt_open_file(
                mut_ptr(&mut handle),
                FILE_GENERIC_READ,
                Some(const_ptr(&attributes)),
                mut_ptr(&mut io_status),
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                (FileCreateOptions::DIRECTORY_FILE | FileCreateOptions::SYNCHRONOUS_IO_NONALERT)
                    .bits(),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    fn open_ksecdd(task: &Task<TestPlatform, TestFS>, desired_access: u32) -> Handle {
        let (_path, _name, attributes) = open_object_attributes(r"\Device\KsecDD");
        let mut handle = Handle::default();
        let mut io_status = IoStatusBlock::default();
        assert_eq!(
            task.sys_nt_open_file(
                mut_ptr(&mut handle),
                desired_access,
                Some(const_ptr(&attributes)),
                mut_ptr(&mut io_status),
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    #[test]
    fn ksecdd_delivers_entropy_and_rejects_unknown_controls() {
        run_with_test_platform_pointers(|| {
            const UNKNOWN_KSEC_IOCTL: u32 = 0x0039_0000;
            let task = crate::tests::test_task();
            let handle = open_ksecdd(&task, FILE_GENERIC_READ | FILE_GENERIC_WRITE);

            let mut first = [0u8; 32];
            let mut second = [0u8; 32];
            let mut io_status = IoStatusBlock::default();
            for output in [&mut first, &mut second] {
                assert_eq!(
                    task.sys_nt_device_io_control_file(
                        handle,
                        Handle::default(),
                        None,
                        None,
                        mut_ptr(&mut io_status),
                        ksecdd::KsecIoControlCode::RandomFillBuffer as u32,
                        None,
                        0,
                        Some(mut_byte_ptr(output)),
                        output.len().try_into().unwrap(),
                    ),
                    NtStatus::SUCCESS
                );
                assert_eq!(io_status.information, output.len());
            }
            assert_ne!(first, second, "successive random fills must differ");

            let mut chunked = [0u8; 4097];
            assert_eq!(
                task.sys_nt_device_io_control_file(
                    handle,
                    Handle::default(),
                    None,
                    None,
                    mut_ptr(&mut io_status),
                    ksecdd::KsecIoControlCode::RandomFillBuffer as u32,
                    None,
                    0,
                    Some(mut_byte_ptr(&mut chunked)),
                    chunked.len().try_into().unwrap(),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(io_status.information, chunked.len());
            assert!(chunked.iter().any(|&byte| byte != 0));

            let mut scratch = [0xa5; 8];
            assert_eq!(
                task.sys_nt_device_io_control_file(
                    handle,
                    Handle::default(),
                    None,
                    None,
                    mut_ptr(&mut io_status),
                    UNKNOWN_KSEC_IOCTL,
                    None,
                    0,
                    Some(mut_byte_ptr(&mut scratch)),
                    scratch.len().try_into().unwrap(),
                ),
                NtStatus::NOT_SUPPORTED
            );
            assert_eq!(io_status.status, NtStatus::NOT_SUPPORTED.as_raw());
            assert_eq!(io_status.information, 0);

            let request = ksecdd::KsecCngInitializeRequest {
                header: ksecdd::KsecCngRequestHeader {
                    magic: 0,
                    operation: ksecdd::KsecCngOperation::Initialize as u32,
                },
                opaque_arguments: [0; 11],
                event_handle: Handle::default(),
            };
            let mut output = [0xa5; size_of::<usize>()];
            assert_eq!(
                task.sys_nt_device_io_control_file(
                    handle,
                    Handle::default(),
                    None,
                    None,
                    mut_ptr(&mut io_status),
                    ksecdd::KsecIoControlCode::CngRequest as u32,
                    Some(ConstPtr::<TestPlatform, u8>::from_usize(
                        core::ptr::from_ref(&request) as usize,
                    )),
                    size_of::<ksecdd::KsecCngInitializeRequest>()
                        .try_into()
                        .unwrap(),
                    Some(mut_byte_ptr(&mut output)),
                    output.len().try_into().unwrap(),
                ),
                NtStatus::INVALID_DEVICE_REQUEST
            );
            assert_eq!(io_status.status, NtStatus::INVALID_DEVICE_REQUEST.as_raw());
            assert_eq!(io_status.information, 0);
        });
    }

    fn open_directory_with_access(
        task: &Task<TestPlatform, TestFS>,
        path: &str,
        desired_access: u32,
    ) -> Handle {
        let (_path, _name, attributes) = open_object_attributes(path);
        let mut io_status = IoStatusBlock::default();
        task.do_nt_create_file(
            desired_access,
            attributes,
            mut_ptr(&mut io_status),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            CreateDisposition::Open,
            (FileCreateOptions::DIRECTORY_FILE | FileCreateOptions::SYNCHRONOUS_IO_NONALERT).bits(),
            None,
            0,
        )
        .unwrap()
        .0
    }

    fn query_directory(
        task: &Task<TestPlatform, TestFS>,
        handle: Handle,
        information_class: FileInformationClass,
        flags: DirectoryQueryFlags,
        pattern: Option<&str>,
        io_status: &mut IoStatusBlock,
        output: &mut [u8],
    ) -> NtStatus {
        let pattern_units = pattern.map(utf16);
        let pattern = pattern_units.as_deref().map(unicode_string);
        let output_ptr = MutPtr::<TestPlatform, u8>::from_usize(output.as_mut_ptr() as usize);
        task.sys_nt_query_directory_file_ex(
            handle,
            Handle::default(),
            None,
            None,
            mut_ptr(io_status),
            output_ptr,
            output.len().try_into().unwrap(),
            information_class as u32,
            flags.bits(),
            pattern.as_ref().map(const_ptr),
        )
    }

    fn directory_record_names(
        output: &[u8],
        information_class: FileInformationClass,
        information: usize,
    ) -> std::vec::Vec<std::string::String> {
        let name_offset = match information_class {
            FileInformationClass::FileDirectoryInformation => {
                offset_of!(FileDirectoryInformation, file_name)
            }
            FileInformationClass::FileFullDirectoryInformation => {
                offset_of!(FileFullDirectoryInformation, file_name)
            }
            FileInformationClass::FileBothDirectoryInformation => {
                offset_of!(FileBothDirectoryInformation, file_name)
            }
            FileInformationClass::FileNamesInformation => {
                offset_of!(FileNamesInformation, file_name)
            }
            FileInformationClass::FileIdBothDirectoryInformation => {
                offset_of!(FileIdBothDirectoryInformation, file_name)
            }
        };
        let name_length_offset = if information_class == FileInformationClass::FileNamesInformation
        {
            8
        } else {
            60
        };
        let mut names = std::vec::Vec::new();
        let mut record_start = 0;
        while record_start + name_offset <= information {
            let name_length = u32::from_ne_bytes(
                output[record_start + name_length_offset..record_start + name_length_offset + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let name_start = record_start + name_offset;
            let name_end = name_start + name_length;
            assert!(name_end <= information);
            let name: std::vec::Vec<u16> = output[name_start..name_end]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|bytes| u16::from_ne_bytes(*bytes))
                .collect();
            names.push(std::string::String::from_utf16(&name).unwrap());
            let next_offset =
                u32::from_ne_bytes(output[record_start..record_start + 4].try_into().unwrap())
                    as usize;
            if next_offset == 0 {
                break;
            }
            assert!(next_offset.is_multiple_of(8));
            record_start += next_offset;
        }
        names
    }

    fn open_condrv_server(task: &Task<TestPlatform, TestFS>) -> Handle {
        let (_server_path, _server_name, server_attributes) =
            open_object_attributes(r"\Device\ConDrv\Server");
        let mut io_status = IoStatusBlock::default();
        task.do_nt_create_file(
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            server_attributes,
            mut_ptr(&mut io_status),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            CreateDisposition::Open,
            FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
            None,
            0,
        )
        .unwrap()
        .0
    }

    fn open_condrv_reference(task: &Task<TestPlatform, TestFS>, server_handle: Handle) -> Handle {
        let (_reference_path, _reference_name, mut reference_attributes) =
            open_object_attributes(r"\Reference");
        reference_attributes.root_directory = server_handle;
        let mut io_status = IoStatusBlock::default();
        task.do_nt_create_file(
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            reference_attributes,
            mut_ptr(&mut io_status),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            CreateDisposition::Open,
            FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
            None,
            0,
        )
        .unwrap()
        .0
    }

    fn open_condrv_child(
        task: &Task<TestPlatform, TestFS>,
        root: Handle,
        name: &str,
        desired_access: u32,
    ) -> (NtStatus, Handle) {
        let (_path, _name, mut attributes) = open_object_attributes(name);
        attributes.root_directory = root;
        let mut handle = Handle::default();
        let mut io_status = IoStatusBlock::default();
        let status = task.sys_nt_create_file(
            mut_ptr(&mut handle),
            desired_access,
            Some(const_ptr(&attributes)),
            mut_ptr(&mut io_status),
            None,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
            None,
            0,
        );
        (status, handle)
    }

    fn basic_information_sentinel() -> FileBasicInformation {
        FileBasicInformation {
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
            file_attributes: 0xcccc_cccc,
            _reserved: 0xdddd_dddd,
        }
    }

    #[test]
    fn directory_name_matches_dos_wildcards() {
        for (pattern, name, expected) in [
            ("<.txt", "report.txt", true),
            ("<.txt", "archive.part.txt", true),
            ("<.txt", "report.doc", false),
            ("file>.txt", "file1.txt", true),
            ("file>.txt", "file.txt", true),
            ("file>.txt", "file12.txt", false),
            ("file\"", "file.", true),
            ("file\"", "file", true),
            ("file\"", "file.txt", false),
        ] {
            assert_eq!(
                directory_name_matches(Some(pattern), name),
                expected,
                "pattern {pattern:?}, name {name:?}"
            );
        }
    }

    #[test]
    fn nt_query_attributes_file_reports_file_type_attributes() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/query-attributes.txt", b"data");
        task.fs
            .mkdir(
                "/tmp/query-attributes-dir",
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            )
            .unwrap();

        for (path, expected_attributes) in [
            ("/tmp/query-attributes.txt", FileAttributes::ARCHIVE.bits()),
            (
                "/tmp/query-attributes-dir",
                FileAttributes::DIRECTORY.bits(),
            ),
        ] {
            let (_path, _name, attributes) = open_object_attributes(path);
            let mut information = basic_information_sentinel();

            assert_eq!(
                task.sys_nt_query_attributes_file(
                    Some(const_ptr(&attributes)),
                    mut_ptr(&mut information),
                ),
                NtStatus::SUCCESS,
                "{path}"
            );
            assert_eq!(
                information,
                FileBasicInformation {
                    file_attributes: expected_attributes,
                    ..FileBasicInformation::default()
                },
                "{path}"
            );
        }
    }

    #[test]
    fn nt_duplicate_object_rejects_file_access_escalation() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/duplicate-read-only.txt", b"data");
        let (status, source, _) = create_file(
            &task,
            "/tmp/duplicate-read-only.txt",
            FILE_GENERIC_READ,
            FILE_OPEN,
        );
        assert_eq!(status, NtStatus::SUCCESS);

        let mut write_duplicate = Handle::default();
        assert_eq!(
            task.sys_nt_duplicate_object(
                crate::syscalls::ProcessHandle::CURRENT,
                source,
                crate::syscalls::ProcessHandle::CURRENT,
                Some(mut_ptr(&mut write_duplicate)),
                FileAccess::WRITE_DATA.bits(),
                0,
                0,
            ),
            NtStatus::ACCESS_DENIED
        );
        assert!(write_duplicate.is_null());

        let mut maximum_duplicate = Handle::default();
        assert_eq!(
            task.sys_nt_duplicate_object(
                crate::syscalls::ProcessHandle::CURRENT,
                source,
                crate::syscalls::ProcessHandle::CURRENT,
                Some(mut_ptr(&mut maximum_duplicate)),
                AccessMask::MAXIMUM_ALLOWED.bits(),
                0,
                0,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.typed_handle::<FileObjectSubsystem<TestFS>>(maximum_duplicate)
                .and_then(|typed| {
                    task.typed_handle_metadata(&typed)
                        .map(|metadata| metadata.granted_access)
                }),
            Ok(FileAccess::from_desired_access(FILE_GENERIC_READ).bits())
        );
        assert_eq!(task.sys_nt_close(source), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(maximum_duplicate), NtStatus::SUCCESS);
    }

    #[test]
    fn nt_write_file_forces_append_only_handles_to_end_of_file() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let path = "/tmp/append-only.txt";
            create_existing_file(&task, path, b"data");
            let (status, handle, _) = create_file(
                &task,
                path,
                (FileAccess::APPEND_DATA | FileAccess::SYNCHRONIZE).bits(),
                FILE_OPEN,
            );
            assert_eq!(status, NtStatus::SUCCESS);

            let input = b'!';
            let byte_offset = 0i64;
            let mut io_status = IoStatusBlock::default();
            assert_eq!(
                task.sys_nt_write_file(
                    handle,
                    Handle::default(),
                    None,
                    None,
                    mut_ptr(&mut io_status),
                    const_ptr(&input),
                    1,
                    Some(const_ptr(&byte_offset)),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(io_status.information, 1);
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);

            let fd = task.fs.open(path, OFlags::RDONLY, Mode::empty()).unwrap();
            let mut contents = [0; 5];
            assert_eq!(task.fs.read(&fd, &mut contents, Some(0)).unwrap(), 5);
            assert_eq!(&contents, b"data!");
            task.fs.close(&fd).unwrap();
        });
    }

    fn set_file_position(
        task: &Task<TestPlatform, TestFS>,
        handle: Handle,
        position: i64,
    ) -> (NtStatus, IoStatusBlock) {
        let mut io_status = IoStatusBlock::default();
        let status = task.sys_nt_set_information_file(
            handle,
            mut_ptr(&mut io_status),
            ConstPtr::<TestPlatform, u8>::from_usize(const_ptr(&position).as_usize()),
            u32::try_from(size_of::<i64>()).unwrap(),
            FileHandleInformationClass::FilePositionInformation as u32,
        );
        (status, io_status)
    }

    #[test]
    fn nt_query_standard_information_uses_open_file_metadata() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let path = "/tmp/query-standard-open-file.txt";
            create_existing_file(&task, path, b"original");
            let (status, handle, _) = create_file(&task, path, FILE_GENERIC_READ, FILE_OPEN);
            assert_eq!(status, NtStatus::SUCCESS);

            task.fs.unlink(path).unwrap();
            create_existing_file(&task, path, b"replacement is longer");

            let mut information = FileStandardInformation::default();
            let mut io_status = IoStatusBlock::default();
            assert_eq!(
                task.sys_nt_query_information_file(
                    handle,
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut information),
                    size_of::<FileStandardInformation>().try_into().unwrap(),
                    FileHandleInformationClass::FileStandardInformation as u32,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(information.end_of_file, 8);
            assert_eq!(io_status.information, size_of::<FileStandardInformation>());
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_set_position_information_updates_synchronous_position() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let path = "/tmp/set-position-sync.txt";
            create_existing_file(&task, path, b"0123456789");
            let (status, handle, _) = create_file(
                &task,
                path,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_OPEN,
            );
            assert_eq!(status, NtStatus::SUCCESS);

            let (status, io_status) = set_file_position(&task, handle, 4);
            assert_eq!(status, NtStatus::SUCCESS);
            assert_eq!(io_status.information, 0);

            let mut queried = -1i64;
            let mut query_io = IoStatusBlock::default();
            assert_eq!(
                task.sys_nt_query_information_file(
                    handle,
                    mut_ptr(&mut query_io),
                    mut_byte_ptr(&mut queried),
                    u32::try_from(size_of::<i64>()).unwrap(),
                    FileHandleInformationClass::FilePositionInformation as u32,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(queried, 4);
            assert_eq!(query_io.information, size_of::<i64>());

            let mut output = [0u8; 2];
            let mut read_io = IoStatusBlock::default();
            assert_eq!(
                task.sys_nt_read_file(
                    handle,
                    Handle::default(),
                    None,
                    None,
                    mut_ptr(&mut read_io),
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    None,
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(&output, b"45");
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_set_position_information_rejects_duplicate_without_data_access() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let path = "/tmp/set-position-no-access.txt";
            create_existing_file(&task, path, b"0123456789");
            let (status, handle, _) = create_file(
                &task,
                path,
                (FileAccess::READ_ATTRIBUTES | FileAccess::SYNCHRONIZE).bits(),
                FILE_OPEN,
            );
            assert_eq!(status, NtStatus::SUCCESS);

            let (status, io_status) = set_file_position(&task, handle, 4);
            assert_eq!(status, NtStatus::ACCESS_DENIED);
            assert_eq!(io_status.information, 0);
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_file_io_transfers_across_multiple_chunks() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let (status, handle, _) = create_file(
                &task,
                "/tmp/chunked-file-io.txt",
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_CREATE,
            );
            assert_eq!(status, NtStatus::SUCCESS);

            let length = FILE_IO_CHUNK_SIZE * 2 + 4096;
            let input: std::vec::Vec<u8> = (0..length)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            let byte_offset = 0i64;
            let mut io_status = IoStatusBlock::default();
            assert_eq!(
                task.sys_nt_write_file(
                    handle,
                    Handle::default(),
                    None,
                    None,
                    mut_ptr(&mut io_status),
                    const_ptr(&input[0]),
                    u32::try_from(input.len()).unwrap(),
                    Some(const_ptr(&byte_offset)),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(io_status.information, input.len());

            let mut output = std::vec![0xa5; length];
            let output_buffer =
                MutPtr::<TestPlatform, u8>::from_usize(output.as_mut_ptr() as usize);
            assert_eq!(
                task.sys_nt_read_file(
                    handle,
                    Handle::default(),
                    None,
                    None,
                    mut_ptr(&mut io_status),
                    output_buffer,
                    u32::try_from(output.len()).unwrap(),
                    Some(const_ptr(&byte_offset)),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(io_status.information, output.len());
            assert_eq!(output, input);
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_create_file_follows_condrv_connection_through_standard_streams() {
        let task = crate::tests::test_task();
        let server_handle = open_condrv_server(&task);
        let reference_handle = open_condrv_reference(&task, server_handle);
        let (_connect_path, _connect_name, mut connect_attributes) =
            open_object_attributes(r"\Connect");
        connect_attributes.root_directory = reference_handle;
        let ea = condrv::ea_buffer(b"server", 1340);
        let mut connect_handle = Handle::default();
        let mut io_status = IoStatusBlock::default();

        assert_eq!(
            task.file_entry(server_handle)
                .unwrap()
                .with_entry(FileObject::condrv_object),
            Some(CondrvObject::Server)
        );
        assert_eq!(
            task.file_entry(reference_handle)
                .unwrap()
                .with_entry(FileObject::condrv_object),
            Some(CondrvObject::Reference)
        );

        assert_eq!(
            task.sys_nt_create_file(
                mut_ptr(&mut connect_handle),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                Some(const_ptr(&connect_attributes)),
                mut_ptr(&mut io_status),
                None,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            ),
            NtStatus::EAS_NOT_SUPPORTED
        );
        assert!(connect_handle.is_null());

        assert_eq!(
            task.sys_nt_create_file(
                mut_ptr(&mut connect_handle),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                Some(const_ptr(&connect_attributes)),
                mut_ptr(&mut io_status),
                None,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                Some(const_ptr(&ea[0])),
                u32::try_from(ea.len()).unwrap(),
            ),
            NtStatus::PIPE_DISCONNECTED
        );
        assert!(connect_handle.is_null());

        assert_eq!(task.sys_nt_close(server_handle), NtStatus::SUCCESS);
        let mut ea = ea;
        *ea.last_mut().unwrap() = 1;
        assert_eq!(
            task.sys_nt_create_file(
                mut_ptr(&mut connect_handle),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                Some(const_ptr(&connect_attributes)),
                mut_ptr(&mut io_status),
                None,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                Some(const_ptr(&ea[0])),
                u32::try_from(ea.len()).unwrap(),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.file_entry(connect_handle)
                .unwrap()
                .with_entry(FileObject::condrv_object),
            Some(CondrvObject::Connect)
        );

        assert_eq!(connect_handle, server_handle);
        let (input_status, input_handle) =
            open_condrv_child(&task, connect_handle, r"\Input", FILE_GENERIC_READ);
        let (output_status, output_handle) =
            open_condrv_child(&task, connect_handle, r"\Output", FILE_GENERIC_WRITE);
        let (current_input_status, current_input_handle) =
            open_condrv_child(&task, connect_handle, r"\CurrentIn", FILE_GENERIC_READ);
        let (current_output_status, current_output_handle) =
            open_condrv_child(&task, connect_handle, r"\CurrentOut", FILE_GENERIC_WRITE);
        let (screen_buffer_status, screen_buffer_handle) =
            open_condrv_child(&task, connect_handle, r"\ScreenBuffer", FILE_GENERIC_WRITE);
        assert_eq!(input_status, NtStatus::SUCCESS);
        assert_eq!(output_status, NtStatus::SUCCESS);
        assert_eq!(current_input_status, NtStatus::SUCCESS);
        assert_eq!(current_output_status, NtStatus::SUCCESS);
        assert_eq!(screen_buffer_status, NtStatus::SUCCESS);
        let (_created_path, _created_name, created_attributes) =
            open_object_attributes(r"\Device\ConDrv\ScreenBuffer");
        let (created_handle, created_information) = task
            .do_nt_create_file(
                FILE_GENERIC_WRITE,
                created_attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CreateDisposition::Create,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .expect("ConDrv stream creation must open its existing host backing");
        assert_eq!(created_information, FileCreateInformation::Raw(0));
        assert_eq!(
            task.file_entry(created_handle)
                .unwrap()
                .with_entry(|file| (file.condrv_object(), file.path.clone())),
            (
                Some(CondrvObject::ScreenBuffer),
                String::from("/dev/stdout")
            )
        );
        assert_eq!(task.sys_nt_close(created_handle), NtStatus::SUCCESS);
        let stream_identity = |handle| {
            task.file_entry(handle).unwrap().with_entry(|file| {
                (
                    file.condrv_object().unwrap(),
                    file.condrv_stream_object_id().unwrap(),
                )
            })
        };
        let input_identity = stream_identity(input_handle);
        let output_identity = stream_identity(output_handle);
        let current_input_identity = stream_identity(current_input_handle);
        let current_output_identity = stream_identity(current_output_handle);
        let screen_buffer_identity = stream_identity(screen_buffer_handle);
        assert_eq!(current_input_identity.0, CondrvObject::CurrentInput);
        assert_eq!(current_output_identity.0, CondrvObject::CurrentOutput);
        assert_eq!(screen_buffer_identity.0, CondrvObject::ScreenBuffer);
        assert_ne!(input_identity.1, current_input_identity.1);
        assert_ne!(output_identity.1, current_output_identity.1);
        assert_ne!(output_identity.1, screen_buffer_identity.1);
        assert_ne!(current_output_identity.1, screen_buffer_identity.1);
        for handle in [output_handle, current_output_handle, screen_buffer_handle] {
            assert_eq!(
                task.file_entry(handle)
                    .unwrap()
                    .with_entry(|file| file.path.clone()),
                "/dev/stdout"
            );
        }

        for (path, desired_access, expected_object, expected_bound_id) in [
            (
                r"\Device\ConDrv\CurrentIn",
                FILE_GENERIC_READ,
                CondrvObject::CurrentInput,
                Some(current_input_identity.1),
            ),
            (
                r"\Device\ConDrv\CurrentOut",
                FILE_GENERIC_WRITE,
                CondrvObject::CurrentOutput,
                Some(current_output_identity.1),
            ),
            (
                r"\Device\ConDrv\ScreenBuffer",
                FILE_GENERIC_WRITE,
                CondrvObject::ScreenBuffer,
                None,
            ),
        ] {
            let (status, handle, _) = create_file(&task, path, desired_access, FILE_OPEN);
            assert_eq!(status, NtStatus::SUCCESS, "{path}");
            let identity = stream_identity(handle);
            assert_eq!(identity.0, expected_object, "{path}");
            if let Some(expected_bound_id) = expected_bound_id {
                assert_eq!(identity.1, expected_bound_id, "{path}");
            } else {
                assert_ne!(identity.1, screen_buffer_identity.1, "{path}");
            }
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        }

        assert_eq!(task.sys_nt_close(current_output_handle), NtStatus::SUCCESS);
        let mut exclusive_handles = alloc::vec::Vec::new();
        for path in [
            r"\Device\ConDrv\Output",
            r"\Device\ConDrv\CurrentOut",
            r"\Device\ConDrv\ScreenBuffer",
            r"\Device\ConDrv\ScreenBuffer",
        ] {
            let (_path, _name, attributes) = open_object_attributes(path);
            let mut handle = Handle::default();
            assert_eq!(
                task.sys_nt_create_file(
                    mut_ptr(&mut handle),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    Some(const_ptr(&attributes)),
                    mut_ptr(&mut io_status),
                    None,
                    0,
                    0,
                    FILE_OPEN,
                    FileCreateOptions::NON_DIRECTORY_FILE.bits(),
                    None,
                    0,
                ),
                NtStatus::SUCCESS,
                "{path}"
            );
            exclusive_handles.push(handle);
        }
        let exclusive_identities: alloc::vec::Vec<_> = exclusive_handles
            .iter()
            .map(|handle| stream_identity(*handle))
            .collect();
        assert_eq!(exclusive_identities[0].0, CondrvObject::Output);
        assert_eq!(exclusive_identities[1].0, CondrvObject::CurrentOutput);
        assert_eq!(
            exclusive_identities[1].1, current_output_identity.1,
            "CurrentOut must reference the active output object"
        );
        assert_ne!(exclusive_identities[0].1, exclusive_identities[1].1);
        assert_ne!(exclusive_identities[2].1, exclusive_identities[3].1);
        let closed_screen_buffer_id = exclusive_identities[2].1;
        for handle in exclusive_handles {
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        }
        let (status, reopened_screen_buffer, _) = create_file(
            &task,
            r"\Device\ConDrv\ScreenBuffer",
            FILE_GENERIC_WRITE,
            FILE_OPEN,
        );
        assert_eq!(status, NtStatus::SUCCESS);
        assert_ne!(
            stream_identity(reopened_screen_buffer).1,
            closed_screen_buffer_id
        );
        assert_eq!(task.sys_nt_close(reopened_screen_buffer), NtStatus::SUCCESS);

        assert_eq!(task.sys_nt_close(screen_buffer_handle), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(current_input_handle), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(output_handle), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(input_handle), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(connect_handle), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(reference_handle), NtStatus::SUCCESS);
    }

    #[test]
    fn nt_query_volume_information_file_returns_fs_device_information() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let handle = open_fs_root(&task);
            let mut io_status = IoStatusBlock::default();
            let mut output = FileFsDeviceInformation {
                device_type: 0,
                characteristics: 0,
            };

            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    handle,
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    FsInformationClass::FileFsDeviceInformation as u32,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                FileDeviceType::try_from(output.device_type),
                Ok(FileDeviceType::Disk),
                "Wine's regular file/directory branch reports FILE_DEVICE_DISK"
            );
            assert_eq!(
                FileDeviceCharacteristics::from_bits_retain(output.characteristics),
                FileDeviceCharacteristics::IS_MOUNTED,
                "Wine's regular file/directory branch reports FILE_DEVICE_IS_MOUNTED"
            );
            assert_eq!((output.device_type, output.characteristics), (0x7, 0x20));
            assert_eq!(io_status.status, NtStatus::SUCCESS.as_raw());
            assert_eq!(io_status.information, size_of::<FileFsDeviceInformation>());
        });
    }

    #[test]
    fn nt_query_directory_file_ex_tracks_restart_single_and_no_cursor_flags() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            task.fs.mkdir("/tmp/query-cursor", Mode::RWXU).unwrap();
            create_existing_file(&task, "/tmp/query-cursor/alpha", b"a");
            create_existing_file(&task, "/tmp/query-cursor/beta", b"b");
            let all_handle =
                open_directory_with_access(&task, "/tmp/query-cursor", FILE_GENERIC_READ);
            let mut all_status = IoStatusBlock::default();
            let mut all_output = [0; 256];
            assert_eq!(
                query_directory(
                    &task,
                    all_handle,
                    FileInformationClass::FileNamesInformation,
                    DirectoryQueryFlags::RESTART_SCAN,
                    None,
                    &mut all_status,
                    &mut all_output,
                ),
                NtStatus::SUCCESS
            );
            let all_names = directory_record_names(
                &all_output,
                FileInformationClass::FileNamesInformation,
                all_status.information,
            );
            assert_eq!(&all_names[..2], [".", ".."]);
            assert!(all_names[2..].contains(&String::from("alpha")));
            assert!(all_names[2..].contains(&String::from("beta")));
            assert_eq!(task.sys_nt_close(all_handle), NtStatus::SUCCESS);
            let handle = open_directory_with_access(&task, "/tmp/query-cursor", FILE_GENERIC_READ);
            let mut io_status = IoStatusBlock::default();
            let mut output = [0; 128];
            let class = FileInformationClass::FileNamesInformation;

            for (flags, expected, expected_position) in [
                (
                    DirectoryQueryFlags::RESTART_SCAN | DirectoryQueryFlags::RETURN_SINGLE_ENTRY,
                    Some("."),
                    1,
                ),
                (DirectoryQueryFlags::RETURN_SINGLE_ENTRY, Some(".."), 2),
                (
                    DirectoryQueryFlags::RETURN_SINGLE_ENTRY
                        | DirectoryQueryFlags::NO_CURSOR_UPDATE_QUERY,
                    Some("."),
                    2,
                ),
                (DirectoryQueryFlags::RETURN_SINGLE_ENTRY, None, 3),
                (
                    DirectoryQueryFlags::RESTART_SCAN | DirectoryQueryFlags::RETURN_SINGLE_ENTRY,
                    Some("."),
                    1,
                ),
                (DirectoryQueryFlags::RETURN_SINGLE_ENTRY, Some(".."), 2),
            ] {
                output.fill(0);
                assert_eq!(
                    query_directory(
                        &task,
                        handle,
                        class,
                        flags,
                        None,
                        &mut io_status,
                        &mut output,
                    ),
                    NtStatus::SUCCESS
                );
                assert_eq!(
                    task.file_entry(handle)
                        .unwrap()
                        .with_entry(|file| file.directory_query.position),
                    expected_position
                );
                let names = directory_record_names(&output, class, io_status.information);
                if let Some(expected) = expected {
                    assert_eq!(names, [expected]);
                } else {
                    assert_eq!(names.len(), 1);
                    assert!(names[0] == "alpha" || names[0] == "beta");
                }
            }
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn nt_query_volume_information_file_leaves_iosb_untouched_on_failures() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let handle = open_fs_root(&task);
            let sentinel = IoStatusBlock::new(NtStatus::from_raw(0x1111_1111), 0x2222_2222);
            let mut io_status = sentinel;
            let mut output = FileFsDeviceInformation {
                device_type: 0xcccc_cccc,
                characteristics: 0xcccc_cccc,
            };

            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    handle,
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap() - 1,
                    FsInformationClass::FileFsDeviceInformation as u32,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(io_status.status, sentinel.status);
            assert_eq!(io_status.information, sentinel.information);
            assert_eq!(
                (output.device_type, output.characteristics),
                (0xcccc_cccc, 0xcccc_cccc)
            );

            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    handle,
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    0xffff,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
            assert_eq!(io_status.status, sentinel.status);
            assert_eq!(io_status.information, sentinel.information);

            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    Handle::from_raw(0x1234),
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    FsInformationClass::FileFsDeviceInformation as u32,
                ),
                NtStatus::INVALID_HANDLE
            );
            assert_eq!(io_status.status, sentinel.status);
            assert_eq!(io_status.information, sentinel.information);

            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    Handle::from_raw(0x1234),
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap() - 1,
                    FsInformationClass::FileFsDeviceInformation as u32,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(io_status.status, sentinel.status);
            assert_eq!(io_status.information, sentinel.information);

            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    Handle::from_raw(0x1234),
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    0xffff,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
            assert_eq!(io_status.status, sentinel.status);
            assert_eq!(io_status.information, sentinel.information);

            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    handle,
                    null_mut_ptr::<IoStatusBlock>(),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    FsInformationClass::FileFsDeviceInformation as u32,
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_open_file_opens_existing_absolute_and_relative_files() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/dir-file-root.txt", b"root");
        task.fs
            .mkdir("/tmp/dir", Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .unwrap();
        create_existing_file(&task, "/tmp/dir/child.txt", b"child");

        let (_path, _name, attributes) =
            open_object_attributes(r"\Device\HarddiskVolume1\tmp\dir-file-root.txt");
        let mut handle = Handle::default();
        let mut io_status = IoStatusBlock::default();
        assert_eq!(
            task.sys_nt_open_file(
                mut_ptr(&mut handle),
                FILE_GENERIC_READ,
                Some(const_ptr(&attributes)),
                mut_ptr(&mut io_status),
                FILE_SHARE_READ,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
            ),
            NtStatus::SUCCESS
        );
        assert_ne!(handle, Handle::default());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::Opened)
        );

        let (_path, _name, directory_attributes) =
            open_object_attributes(r"\Device\HarddiskVolume1\tmp\dir");
        let directory_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                directory_attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ,
                CreateDisposition::Open,
                (FileCreateOptions::DIRECTORY_FILE | FileCreateOptions::SYNCHRONOUS_IO_NONALERT)
                    .bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        let (_path, _child_name, mut child_attributes) = open_object_attributes("child.txt");
        child_attributes.root_directory = directory_handle;
        let (child_handle, information) = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                child_attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap();
        assert_ne!(child_handle, Handle::default());
        assert_eq!(information, FileCreateInformation::Opened);
    }

    #[test]
    fn nt_create_file_reports_disposition_information() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/existing.txt", b"old");

        let (status, handle, io_status) =
            create_file(&task, "/tmp/existing.txt", FILE_GENERIC_READ, FILE_OPEN);
        assert_eq!(status, NtStatus::SUCCESS);
        assert_ne!(handle, Handle::default());
        assert_eq!(io_status.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::Opened)
        );

        let (status, handle, io_status) = create_file(
            &task,
            "/tmp/created.txt",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_CREATE,
        );
        assert_eq!(status, NtStatus::SUCCESS);
        assert_ne!(handle, Handle::default());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::Created)
        );

        let (status, handle, io_status) = create_file(
            &task,
            "/tmp/supersede-created.txt",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SUPERSEDE,
        );
        assert_eq!(status, NtStatus::SUCCESS);
        assert_ne!(handle, Handle::default());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::Created)
        );

        let (status, _handle, _io_status) = create_file(
            &task,
            "/tmp/existing.txt",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SUPERSEDE,
        );
        assert_eq!(status, NtStatus::ACCESS_DENIED);

        let (status, handle, io_status) = create_file(
            &task,
            "/tmp/existing.txt",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | AccessMask::DELETE.bits(),
            FILE_SUPERSEDE,
        );
        assert_eq!(status, NtStatus::SUCCESS);
        assert_ne!(handle, Handle::default());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::Superseded)
        );

        let (status, handle, io_status) = create_file(
            &task,
            "/tmp/created.txt",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_OVERWRITE,
        );
        assert_eq!(status, NtStatus::SUCCESS);
        assert_ne!(handle, Handle::default());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::Overwritten)
        );
    }

    #[test]
    fn nt_create_file_reports_missing_and_collision_information() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/existing-collision.txt", b"old");

        let (status, _handle, io_status) =
            create_file(&task, "/tmp/missing.txt", FILE_GENERIC_READ, FILE_OPEN);
        assert_eq!(status, NtStatus::OBJECT_NAME_NOT_FOUND);
        assert_eq!(io_status.status, NtStatus::OBJECT_NAME_NOT_FOUND.as_raw());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::DoesNotExist)
        );

        let (status, _handle, io_status) = create_file(
            &task,
            "/tmp/existing-collision.txt",
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_CREATE,
        );
        assert_eq!(status, NtStatus::OBJECT_NAME_COLLISION);
        assert_eq!(io_status.status, NtStatus::OBJECT_NAME_COLLISION.as_raw());
        assert_eq!(
            io_status.information,
            usize::from(FileCreateInformation::Exists)
        );
    }

    #[test]
    fn nt_create_file_rejects_invalid_share_access() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/invalid-share.txt", b"old");
        let (_path, _name, attributes) = open_object_attributes("/tmp/invalid-share.txt");
        let mut io_status = IoStatusBlock::default();

        assert_eq!(
            task.do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                0x8,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn nt_create_file_directory_handles_can_root_relative_opens() {
        let task = crate::tests::test_task();
        let (_path, _name, attributes) = open_object_attributes("/tmp/created-dir");
        let mut io_status = IoStatusBlock::default();
        let directory_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CreateDisposition::Create,
                (FileCreateOptions::DIRECTORY_FILE | FileCreateOptions::SYNCHRONOUS_IO_NONALERT)
                    .bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        let (_path, _name, mut child_attributes) = open_object_attributes("child.txt");
        child_attributes.root_directory = directory_handle;
        let child_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                child_attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CreateDisposition::Create,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        assert_ne!(child_handle, Handle::default());
    }

    #[test]
    fn nt_create_file_actual_directory_handles_can_root_relative_opens() {
        let task = crate::tests::test_task();
        task.fs
            .mkdir("/tmp/implicit-dir", Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .unwrap();
        create_existing_file(&task, "/tmp/implicit-dir/child.txt", b"child");
        let (_path, _name, attributes) = open_object_attributes("/tmp/implicit-dir");
        let mut io_status = IoStatusBlock::default();
        let directory_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        let (_path, _name, mut child_attributes) = open_object_attributes("child.txt");
        child_attributes.root_directory = directory_handle;

        let (child_handle, information) = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                child_attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap();
        assert_ne!(child_handle, Handle::default());
        assert_eq!(information, FileCreateInformation::Opened);
    }

    #[test]
    fn nt_create_file_validates_create_options() {
        let generic_read = FileAccess::from_desired_access(FILE_GENERIC_READ);
        let synchronize = FileAccess::SYNCHRONIZE;

        assert_eq!(
            validate_create_options(
                generic_read,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO,
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            validate_create_options(
                FileAccess::READ_DATA,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT,
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            validate_create_options(
                FileAccess::APPEND_DATA | synchronize,
                CreateDisposition::Open,
                FileCreateOptions::NO_INTERMEDIATE_BUFFERING,
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            validate_create_options(
                generic_read,
                CreateDisposition::Open,
                FileCreateOptions::DELETE_ON_CLOSE,
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            validate_create_options(
                generic_read,
                CreateDisposition::Overwrite,
                FileCreateOptions::DIRECTORY_FILE,
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            validate_create_options(
                generic_read,
                CreateDisposition::Open,
                FileCreateOptions::DIRECTORY_FILE | FileCreateOptions::SEQUENTIAL_ONLY,
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            validate_create_options(
                generic_read,
                CreateDisposition::Open,
                FileCreateOptions::DIRECTORY_FILE
                    | FileCreateOptions::WRITE_THROUGH
                    | FileCreateOptions::SYNCHRONOUS_IO_NONALERT,
            ),
            Ok(())
        );
        assert_eq!(
            validate_create_options(
                generic_read | FileAccess::DELETE,
                CreateDisposition::Open,
                FileCreateOptions::DIRECTORY_FILE
                    | FileCreateOptions::DELETE_ON_CLOSE
                    | FileCreateOptions::COMPLETE_IF_OPLOCKED
                    | FileCreateOptions::OPEN_REPARSE_POINT
                    | FileCreateOptions::OPEN_FOR_FREE_SPACE_QUERY
                    | FileCreateOptions::NO_COMPRESSION
                    | FileCreateOptions::SYNCHRONOUS_IO_NONALERT,
            ),
            Ok(())
        );
        assert!(
            generic_read
                .open_flags(
                    CreateDisposition::Open,
                    FileCreateOptions::NON_DIRECTORY_FILE
                )
                .contains(OFlags::NOFOLLOW)
        );
    }

    #[test]
    fn nt_create_file_enforces_share_access() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/shared.txt", b"old");
        let (_path, _name, attributes) = open_object_attributes("/tmp/shared.txt");
        let mut io_status = IoStatusBlock::default();
        let first_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                0,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        assert_ne!(first_handle, Handle::default());

        let (_path, _name, attributes) = open_object_attributes("/tmp/shared.txt");
        assert_eq!(
            task.do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap_err(),
            NtStatus::SHARING_VIOLATION
        );
    }

    #[test]
    fn nt_close_releases_file_handle_and_share_lock() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/close-shared.txt", b"old");
        let (_path, _name, attributes) = open_object_attributes("/tmp/close-shared.txt");
        let mut io_status = IoStatusBlock::default();
        let first_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                0,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap()
            .0;

        let (_path, _name, attributes) = open_object_attributes("/tmp/close-shared.txt");
        assert_eq!(
            task.do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap_err(),
            NtStatus::SHARING_VIOLATION
        );

        assert_eq!(task.sys_nt_close(first_handle), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(first_handle), NtStatus::INVALID_HANDLE);

        let (_path, _name, attributes) = open_object_attributes("/tmp/close-shared.txt");
        let second_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        assert_eq!(task.sys_nt_close(second_handle), NtStatus::SUCCESS);
    }

    #[test]
    fn nt_close_deletes_delete_on_close_file() {
        let task = crate::tests::test_task();
        create_existing_file(&task, "/tmp/delete-on-close.txt", b"old");
        let (_path, _name, attributes) = open_object_attributes("/tmp/delete-on-close.txt");
        let mut io_status = IoStatusBlock::default();
        let handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ | AccessMask::DELETE.bits(),
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CreateDisposition::Open,
                (FileCreateOptions::SYNCHRONOUS_IO_NONALERT | FileCreateOptions::DELETE_ON_CLOSE)
                    .bits(),
                None,
                0,
            )
            .unwrap()
            .0;

        assert!(task.fs.file_status("/tmp/delete-on-close.txt").is_ok());
        assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        assert!(matches!(
            task.fs.file_status("/tmp/delete-on-close.txt"),
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    fn nt_close_deletes_delete_on_close_directory() {
        let task = crate::tests::test_task();
        let (_path, _name, attributes) = open_object_attributes("/tmp/delete-on-close-dir");
        let mut io_status = IoStatusBlock::default();
        let handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ | AccessMask::DELETE.bits(),
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CreateDisposition::Create,
                (FileCreateOptions::DIRECTORY_FILE
                    | FileCreateOptions::SYNCHRONOUS_IO_NONALERT
                    | FileCreateOptions::DELETE_ON_CLOSE)
                    .bits(),
                None,
                0,
            )
            .unwrap()
            .0;

        assert!(task.fs.file_status("/tmp/delete-on-close-dir").is_ok());
        assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        assert!(matches!(
            task.fs.file_status("/tmp/delete-on-close-dir"),
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    fn write_file_result_clears_handle_output_when_iosb_write_fails() {
        let task = crate::tests::test_task();
        let (_path, _name, attributes) = open_object_attributes("/tmp/iosb-fault.txt");
        let mut io_status = IoStatusBlock::default();
        let created_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CreateDisposition::Create,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        let mut handle_output = created_handle;

        let status = run_with_test_platform_pointers(|| {
            write_file_result::<TestPlatform>(
                mut_ptr(&mut handle_output),
                null_mut_ptr::<IoStatusBlock>(),
                Ok((created_handle, FileCreateInformation::Created)),
                |handle| task.close_file_handle(handle),
            )
        });

        assert_eq!(status, NtStatus::ACCESS_VIOLATION);
        assert_eq!(handle_output, Handle::default());
        assert_eq!(task.sys_nt_close(created_handle), NtStatus::INVALID_HANDLE);
        let (_path, _name, attributes) = open_object_attributes("/tmp/iosb-fault.txt");
        let reopened_handle = task
            .do_nt_create_file(
                FILE_GENERIC_READ,
                attributes,
                mut_ptr(&mut io_status),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                CreateDisposition::Open,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            )
            .unwrap()
            .0;
        assert_eq!(task.sys_nt_close(reopened_handle), NtStatus::SUCCESS);
    }

    #[test]
    fn probe_file_outputs_preserves_handle_output_when_iosb_probe_fails() {
        let original_handle = Handle::from_raw_fd(0).unwrap();
        let mut handle = original_handle;

        let status = run_with_test_platform_pointers(|| {
            probe_file_outputs::<TestPlatform>(mut_ptr(&mut handle), null_mut_ptr())
        });

        assert_eq!(status, Err(NtStatus::ACCESS_VIOLATION));
        assert_eq!(handle, original_handle);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mod host_fidelity {
        use super::*;
        use crate::nt_types::{ProcessEnvironmentBlock, RtlUserProcessParameters};
        use core::ffi::c_void;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn RtlGetCurrentPeb() -> *const ProcessEnvironmentBlock;
            fn NtCreateFile(
                FileHandle: *mut *mut c_void,
                DesiredAccess: u32,
                ObjectAttributes: *const ObjectAttributes,
                IoStatusBlock: *mut IoStatusBlock,
                AllocationSize: *const i64,
                FileAttributes: u32,
                ShareAccess: u32,
                CreateDisposition: u32,
                CreateOptions: u32,
                EaBuffer: *const c_void,
                EaLength: u32,
            ) -> i32;
            fn NtOpenFile(
                FileHandle: *mut *mut c_void,
                DesiredAccess: u32,
                ObjectAttributes: *const ObjectAttributes,
                IoStatusBlock: *mut IoStatusBlock,
                ShareAccess: u32,
                OpenOptions: u32,
            ) -> i32;
            fn NtQueryVolumeInformationFile(
                FileHandle: *mut c_void,
                IoStatusBlock: *mut IoStatusBlock,
                FsInformation: *mut c_void,
                Length: u32,
                FsInformationClass: u32,
            ) -> i32;
            fn NtDuplicateObject(
                SourceProcessHandle: *mut c_void,
                SourceHandle: *mut c_void,
                TargetProcessHandle: *mut c_void,
                TargetHandle: *mut c_void,
                DesiredAccess: u32,
                HandleAttributes: u32,
                Options: u32,
            ) -> i32;
            fn NtClose(Handle: *mut c_void) -> i32;
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn AllocConsole() -> i32;
            fn GetLastError() -> u32;
        }

        fn host_nt_path(path: &std::path::Path) -> std::string::String {
            std::format!(r"\??\{}", path.display())
        }

        fn test_tmp_dir(name: &str) -> std::path::PathBuf {
            std::env::var_os("CARGO_TARGET_TMPDIR")
                .map_or_else(std::env::temp_dir, std::path::PathBuf::from)
                .join(name)
        }

        fn host_object_attributes(name: &UnicodeString) -> ObjectAttributes {
            object_attributes(name, 0)
        }

        fn close_host_handle(handle: *mut c_void) {
            if !handle.is_null() {
                // SAFETY: The handle was returned by `NtCreateFile`/`NtOpenFile` in this test.
                let status = unsafe { NtClose(handle) };
                assert_eq!(status, NtStatus::SUCCESS.as_raw());
            }
        }

        fn host_status(status: i32) -> NtStatus {
            NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
        }

        fn host_create_file(
            root: Handle,
            name: &str,
            create_disposition: u32,
        ) -> (NtStatus, *mut c_void, IoStatusBlock) {
            let path = utf16(name);
            let name = unicode_string(&path);
            let mut attributes = host_object_attributes(&name);
            attributes.root_directory = root;
            let mut handle = core::ptr::null_mut();
            let mut io_status = IoStatusBlock::default();
            // SAFETY: All pointers reference live local typed values for the call.
            let status = unsafe {
                NtCreateFile(
                    &raw mut handle,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    &raw const attributes,
                    &raw mut io_status,
                    core::ptr::null(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    create_disposition,
                    FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                    core::ptr::null(),
                    0,
                )
            };
            (host_status(status), handle, io_status)
        }

        #[test]
        fn connected_console_child_matrix_matches_host() {
            // SAFETY: RtlGetCurrentPeb returns the live typed PEB for this process.
            let mut peb = unsafe { &*RtlGetCurrentPeb() };
            // SAFETY: The current process owns a live RTL_USER_PROCESS_PARAMETERS block.
            let mut process_parameters =
                unsafe { &*(peb.process_parameters as *const RtlUserProcessParameters) };
            let console_handle = process_parameters.console_handle;
            // ReactOS and Wine model detached/new/no-window console states as null or
            // the reserved pseudo-handles -1 through -4.
            if console_handle == 0 || console_handle >= usize::MAX - 3 {
                // SAFETY: The test process has no connected console, so AllocConsole may attach one.
                let allocated = unsafe { AllocConsole() };
                assert_ne!(
                    allocated,
                    0,
                    "AllocConsole failed with Win32 error {}",
                    // SAFETY: GetLastError has no preconditions.
                    unsafe { GetLastError() }
                );
                // AllocConsole updates the live process parameters.
                // SAFETY: RtlGetCurrentPeb returns the live typed PEB for this process.
                peb = unsafe { &*RtlGetCurrentPeb() };
                // SAFETY: The PEB owns a live RTL_USER_PROCESS_PARAMETERS block.
                process_parameters =
                    unsafe { &*(peb.process_parameters as *const RtlUserProcessParameters) };
            }
            assert_ne!(
                process_parameters.console_handle, 0,
                "console handle remained null after ensuring a console"
            );
            let console_handle = Handle::from_raw(process_parameters.console_handle);

            let success = [NtStatus::SUCCESS];
            let screen_buffer = [NtStatus::SUCCESS, NtStatus::INVALID_PARAMETER];
            let invalid_handle = [NtStatus::INVALID_HANDLE];
            let not_found = [NtStatus::NOT_FOUND];
            for (name, expected) in [
                (r"\Input", success.as_slice()),
                (r"\Output", success.as_slice()),
                (r"\CurrentIn", success.as_slice()),
                (r"\CurrentOut", success.as_slice()),
                // Headless and pseudoconsole hosts may not support creating a bound legacy
                // screen buffer even though their connected root supports CurrentOut.
                (r"\ScreenBuffer", screen_buffer.as_slice()),
                (r"\Server", success.as_slice()),
                (r"\Reference", success.as_slice()),
                (r"\Connect", invalid_handle.as_slice()),
                (r"\Bogus", not_found.as_slice()),
            ] {
                let (status, handle, _) = host_create_file(console_handle, name, FILE_OPEN);
                assert!(
                    expected.contains(&status),
                    "{name:?} under console handle {:#x}: expected one of {expected:?}, got {status:?}",
                    console_handle.as_raw(),
                );
                if status == NtStatus::SUCCESS {
                    assert!(!handle.is_null());
                    close_host_handle(handle);
                } else {
                    assert!(handle.is_null());
                }
            }
        }

        #[test]
        fn nt_query_volume_information_file_device_information_matches_host_statuses() {
            let test_dir = test_tmp_dir(
                "nt_query_volume_information_file_device_information_matches_host_statuses",
            );
            let _ = std::fs::remove_dir_all(&test_dir);
            std::fs::create_dir_all(&test_dir).unwrap();
            let host_file = test_dir.join("existing.txt");
            std::fs::write(&host_file, b"host").unwrap();

            let host_name_units = utf16(&host_nt_path(&host_file));
            let host_name = unicode_string(&host_name_units);
            let host_attributes = host_object_attributes(&host_name);
            let mut host_handle = core::ptr::null_mut();
            let mut host_io_status = IoStatusBlock::default();
            // SAFETY: All pointers reference live test locals, and ObjectName is an NT path
            // to the temporary file created above.
            let host_open = unsafe {
                NtOpenFile(
                    &raw mut host_handle,
                    FILE_GENERIC_READ,
                    &raw const host_attributes,
                    &raw mut host_io_status,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    0,
                )
            };
            assert_eq!(host_open, NtStatus::SUCCESS.as_raw());

            let mut host_output = FileFsDeviceInformation {
                device_type: 0,
                characteristics: 0,
            };
            let mut host_query_iosb = IoStatusBlock::default();
            // SAFETY: The handle was opened above and output pointers reference live locals.
            let host_query = unsafe {
                NtQueryVolumeInformationFile(
                    host_handle,
                    &raw mut host_query_iosb,
                    (&raw mut host_output).cast::<c_void>(),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    FsInformationClass::FileFsDeviceInformation as u32,
                )
            };
            close_host_handle(host_handle);

            assert_eq!(host_status(host_query), NtStatus::SUCCESS);
            assert_eq!(host_query_iosb.status, NtStatus::SUCCESS.as_raw());
            assert_eq!(
                host_query_iosb.information,
                size_of::<FileFsDeviceInformation>()
            );
            assert_eq!(
                FileDeviceType::try_from(host_output.device_type),
                Ok(FileDeviceType::Disk)
            );
            assert!(
                FileDeviceCharacteristics::from_bits_retain(host_output.characteristics)
                    .contains(FileDeviceCharacteristics::IS_MOUNTED)
            );

            let task = crate::tests::test_task();
            let handle = open_fs_root(&task);
            let mut output = FileFsDeviceInformation {
                device_type: 0,
                characteristics: 0,
            };
            let mut io_status = IoStatusBlock::default();
            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    handle,
                    mut_ptr(&mut io_status),
                    mut_byte_ptr(&mut output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    FsInformationClass::FileFsDeviceInformation as u32,
                ),
                host_status(host_query)
            );
            assert_eq!(io_status.status, host_query_iosb.status);
            assert_eq!(io_status.information, host_query_iosb.information);
            assert_eq!(
                FileDeviceType::try_from(output.device_type),
                Ok(FileDeviceType::Disk)
            );
            assert_eq!(
                FileDeviceCharacteristics::from_bits_retain(output.characteristics),
                FileDeviceCharacteristics::IS_MOUNTED
            );
            assert_eq!((output.device_type, output.characteristics), (0x7, 0x20));

            let sentinel = IoStatusBlock::new(NtStatus::from_raw(0x1111_1111), 0x2222_2222);
            for (length, class, expected) in [
                (
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap() - 1,
                    FsInformationClass::FileFsDeviceInformation as u32,
                    NtStatus::INFO_LENGTH_MISMATCH,
                ),
                (
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    0xffff,
                    NtStatus::INVALID_INFO_CLASS,
                ),
            ] {
                let mut host_iosb = sentinel;
                let mut host_output = FileFsDeviceInformation {
                    device_type: 0xcccc_cccc,
                    characteristics: 0xcccc_cccc,
                };
                // SAFETY: `host_handle` is intentionally invalid only in the separate bad-handle
                // case below; here all pointers reference live locals.
                let host = unsafe {
                    NtQueryVolumeInformationFile(
                        core::ptr::null_mut(),
                        &raw mut host_iosb,
                        (&raw mut host_output).cast::<c_void>(),
                        length,
                        class,
                    )
                };
                let mut shim_iosb = sentinel;
                let mut shim_output = host_output;
                let shim = task.sys_nt_query_volume_information_file(
                    handle,
                    mut_ptr(&mut shim_iosb),
                    mut_byte_ptr(&mut shim_output),
                    length,
                    class,
                );

                assert_eq!(shim, expected);
                assert_eq!(shim, host_status(host));
                assert_eq!(shim_iosb.status, host_iosb.status);
                assert_eq!(shim_iosb.information, host_iosb.information);
            }

            let mut shim_iosb = sentinel;
            let mut shim_output = FileFsDeviceInformation {
                device_type: 0xcccc_cccc,
                characteristics: 0xcccc_cccc,
            };
            assert_eq!(
                task.sys_nt_query_volume_information_file(
                    Handle::from_raw(0x1234),
                    mut_ptr(&mut shim_iosb),
                    mut_byte_ptr(&mut shim_output),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    FsInformationClass::FileFsDeviceInformation as u32,
                ),
                NtStatus::INVALID_HANDLE
            );
            assert_eq!(shim_iosb.status, sentinel.status);
            assert_eq!(shim_iosb.information, sentinel.information);

            let mut host_iosb = sentinel;
            let mut host_output = FileFsDeviceInformation {
                device_type: 0xcccc_cccc,
                characteristics: 0xcccc_cccc,
            };
            // SAFETY: The bad handle is deliberately invalid to observe NTSTATUS; the output
            // pointers reference live locals and are not retained.
            let host_bad_handle = unsafe {
                NtQueryVolumeInformationFile(
                    0x1234usize as *mut c_void,
                    &raw mut host_iosb,
                    (&raw mut host_output).cast::<c_void>(),
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    FsInformationClass::FileFsDeviceInformation as u32,
                )
            };
            assert_eq!(host_status(host_bad_handle), NtStatus::INVALID_HANDLE);
            assert_eq!(host_iosb.status, sentinel.status);
            assert_eq!(host_iosb.information, sentinel.information);

            for (length, class, expected) in [
                (
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap() - 1,
                    FsInformationClass::FileFsDeviceInformation as u32,
                    NtStatus::INFO_LENGTH_MISMATCH,
                ),
                (
                    u32::try_from(size_of::<FileFsDeviceInformation>()).unwrap(),
                    0xffff,
                    NtStatus::INVALID_INFO_CLASS,
                ),
            ] {
                let mut host_iosb = sentinel;
                let mut host_output = FileFsDeviceInformation {
                    device_type: 0xcccc_cccc,
                    characteristics: 0xcccc_cccc,
                };
                // SAFETY: The bad handle is deliberately invalid to observe validation
                // precedence; output pointers reference live locals and are not retained.
                let host = unsafe {
                    NtQueryVolumeInformationFile(
                        0x1234usize as *mut c_void,
                        &raw mut host_iosb,
                        (&raw mut host_output).cast::<c_void>(),
                        length,
                        class,
                    )
                };
                let mut shim_iosb = sentinel;
                let mut shim_output = host_output;
                let shim = task.sys_nt_query_volume_information_file(
                    Handle::from_raw(0x1234),
                    mut_ptr(&mut shim_iosb),
                    mut_byte_ptr(&mut shim_output),
                    length,
                    class,
                );

                assert_eq!(shim, expected);
                assert_eq!(shim, host_status(host));
                assert_eq!(shim_iosb.status, host_iosb.status);
                assert_eq!(shim_iosb.information, host_iosb.information);
            }
        }

        #[test]
        fn nt_open_file_existing_file_matches_host_status_and_information() {
            let test_dir =
                test_tmp_dir("nt_open_file_existing_file_matches_host_status_and_information");
            let _ = std::fs::remove_dir_all(&test_dir);
            std::fs::create_dir_all(&test_dir).unwrap();
            let host_file = test_dir.join("existing.txt");
            std::fs::write(&host_file, b"host").unwrap();

            let host_name_units = utf16(&host_nt_path(&host_file));
            let host_name = unicode_string(&host_name_units);
            let host_attributes = host_object_attributes(&host_name);
            let mut host_handle = core::ptr::null_mut();
            let mut host_io_status = IoStatusBlock::default();
            // SAFETY: All pointers reference live test locals, and ObjectName is an NT path
            // to the temporary file created above.
            let host_status = unsafe {
                NtOpenFile(
                    &raw mut host_handle,
                    FILE_GENERIC_READ,
                    &raw const host_attributes,
                    &raw mut host_io_status,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    0,
                )
            };
            close_host_handle(host_handle);

            let task = crate::tests::test_task();
            create_existing_file(&task, "/tmp/existing.txt", b"litebox");
            let (_path, _name, attributes) = open_object_attributes("/tmp/existing.txt");
            let mut litebox_handle = Handle::default();
            let mut litebox_io_status = IoStatusBlock::default();
            let litebox_status = task.sys_nt_open_file(
                mut_ptr(&mut litebox_handle),
                FILE_GENERIC_READ,
                Some(const_ptr(&attributes)),
                mut_ptr(&mut litebox_io_status),
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
            );

            assert_eq!(host_status, litebox_status.as_raw());
            assert_eq!(host_io_status.status, litebox_io_status.status);
            assert_eq!(host_io_status.information, litebox_io_status.information);
        }

        #[test]
        fn nt_duplicate_object_file_access_matrix_matches_host() {
            let test_dir = test_tmp_dir("nt_duplicate_object_file_access_matrix_matches_host");
            let _ = std::fs::remove_dir_all(&test_dir);
            std::fs::create_dir_all(&test_dir).unwrap();
            let host_file = test_dir.join("read-only-source.txt");
            std::fs::write(&host_file, b"host").unwrap();

            let host_name_units = utf16(&host_nt_path(&host_file));
            let host_name = unicode_string(&host_name_units);
            let host_attributes = host_object_attributes(&host_name);
            let mut host_source = core::ptr::null_mut();
            let mut host_io_status = IoStatusBlock::default();
            // SAFETY: All pointers reference live locals and ObjectName names the test file.
            assert_eq!(
                unsafe {
                    NtOpenFile(
                        &raw mut host_source,
                        FILE_GENERIC_READ,
                        &raw const host_attributes,
                        &raw mut host_io_status,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        0,
                    )
                },
                NtStatus::SUCCESS.as_raw()
            );
            let mut host_write_duplicate: *mut c_void = core::ptr::null_mut();
            // SAFETY: The process pseudo-handles and source handle are valid; output is a local.
            assert_eq!(
                unsafe {
                    NtDuplicateObject(
                        usize::MAX as *mut c_void,
                        host_source,
                        usize::MAX as *mut c_void,
                        (&raw mut host_write_duplicate).cast(),
                        FileAccess::WRITE_DATA.bits(),
                        0,
                        0,
                    )
                },
                NtStatus::ACCESS_DENIED.as_raw()
            );
            assert!(host_write_duplicate.is_null());
            let mut host_maximum_duplicate: *mut c_void = core::ptr::null_mut();
            // SAFETY: The process pseudo-handles and source handle are valid; output is a local.
            assert_eq!(
                unsafe {
                    NtDuplicateObject(
                        usize::MAX as *mut c_void,
                        host_source,
                        usize::MAX as *mut c_void,
                        (&raw mut host_maximum_duplicate).cast(),
                        AccessMask::MAXIMUM_ALLOWED.bits(),
                        0,
                        0,
                    )
                },
                NtStatus::SUCCESS.as_raw()
            );
            close_host_handle(host_source);
            close_host_handle(host_maximum_duplicate);
        }

        #[test]
        fn nt_create_file_supersede_missing_matches_host_status_and_information() {
            let test_dir = test_tmp_dir(
                "nt_create_file_supersede_missing_matches_host_status_and_information",
            );
            let _ = std::fs::remove_dir_all(&test_dir);
            std::fs::create_dir_all(&test_dir).unwrap();
            let host_file = test_dir.join("created.txt");

            let host_name_units = utf16(&host_nt_path(&host_file));
            let host_name = unicode_string(&host_name_units);
            let host_attributes = host_object_attributes(&host_name);
            let mut host_handle = core::ptr::null_mut();
            let mut host_io_status = IoStatusBlock::default();
            // SAFETY: All pointers reference live test locals, the optional pointer
            // arguments are null, and ObjectName points to a path in the test directory.
            let host_status = unsafe {
                NtCreateFile(
                    &raw mut host_handle,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE | AccessMask::DELETE.bits(),
                    &raw const host_attributes,
                    &raw mut host_io_status,
                    core::ptr::null(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_SUPERSEDE,
                    FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                    core::ptr::null(),
                    0,
                )
            };
            close_host_handle(host_handle);

            let task = crate::tests::test_task();
            let (_path, _name, attributes) = open_object_attributes("/tmp/supersede-created.txt");
            let mut litebox_handle = Handle::default();
            let mut litebox_io_status = IoStatusBlock::default();
            let litebox_status = task.sys_nt_create_file(
                mut_ptr(&mut litebox_handle),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | AccessMask::DELETE.bits(),
                Some(const_ptr(&attributes)),
                mut_ptr(&mut litebox_io_status),
                None,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_SUPERSEDE,
                FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                None,
                0,
            );

            assert_eq!(host_status, litebox_status.as_raw());
            assert_eq!(host_io_status.status, litebox_io_status.status);
            assert_eq!(host_io_status.information, litebox_io_status.information);
        }
    }
}

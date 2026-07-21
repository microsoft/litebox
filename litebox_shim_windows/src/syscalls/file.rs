// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::mem::size_of;

use int_enum::IntEnum;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd};
use litebox::fs::errors::{FileStatusError, MkdirError, OpenError, PathError};
use litebox::fs::{FileType, Mode, OFlags};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{
    AccessMask, IoStatusBlock, ObjectAttributes, UnicodeString, read_object_attributes,
};
use crate::syscalls::Handle;
use crate::syscalls::condrv::{self, CondrvObject, CondrvStreamDirection, CondrvStreamObject};
use crate::syscalls::file_path::{FilePathResolver, FilePathRoot, FileTarget};
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value, raw_handle_entry,
};

const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;

const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;

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

#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum FileCreateInformation {
    /// An existing file was deleted and a new file was created in its place.
    Superseded = 0,
    /// An existing file was opened.
    Opened = 1,
    Created = 2,
    /// An existing file was overwritten.
    Overwritten = 3,
    Exists = 4,
    DoesNotExist = 5,
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

const _: () = assert!(size_of::<FileFsDeviceInformation>() == 8);

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
}

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
            FileObjectBacking::Filesystem { .. } => None,
        }
    }

    fn condrv_stream_object_id(&self) -> Option<u64> {
        match &self.backing {
            FileObjectBacking::CondrvStream { stream_object, .. } => Some(stream_object.id()),
            FileObjectBacking::Filesystem { .. } | FileObjectBacking::CondrvControl(_) => None,
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
    struct FileAccess: u32 {
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
    struct FileShareAccess: u32 {
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
    struct FileCreateOptions: u32 {
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
    Create = 1,
    Open = 2,
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
            FileObjectBacking::CondrvControl(_) => {}
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
            FILE_ATTRIBUTE_READONLY,
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

        let condrv_object = match self.file_entry(file_handle) {
            Ok(entry) => entry.with_entry(FileObject::condrv_object),
            Err(status) => return status,
        };
        if !event.is_null()
            && let Err(status) = self.clear_event(event)
        {
            return status;
        }
        let Some(condrv_object) = condrv_object else {
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw(),
                io_control_code:% = format_args!("{io_control_code:#x}");
                "Unsupported NtDeviceIoControlFile for non-ConDrv file handle"
            );
            return NtStatus::INVALID_DEVICE_REQUEST;
        };
        if apc_routine.is_some() || apc_context.is_some() {
            litebox_util_log::debug!(
                file_handle = file_handle.as_raw(),
                apc_context = apc_context.map_or(0, |context| context.as_usize());
                "Ignoring NtDeviceIoControlFile APC completion arguments for synchronous completion"
            );
        }
        let status = condrv::handle_ioctl::<Platform>(
            condrv_object,
            io_status_block,
            io_control_code,
            input_buffer,
            input_buffer_length,
            output_buffer,
            output_buffer_length,
        );
        if !event.is_null() {
            let event_status = self.set_event(event);
            if event_status != NtStatus::SUCCESS {
                return event_status;
            }
        }
        status
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
                    IoStatusBlock::new(NtStatus::SUCCESS, size_of::<FileFsDeviceInformation>()),
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
            let (fd, _, information) = self.open_backing_fd(
                &path,
                backing_access,
                create_disposition,
                create_options,
                Mode::empty(),
            )?;
            (
                FileObjectBacking::CondrvStream {
                    object,
                    stream_object,
                    fd,
                },
                information,
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
            },
            information,
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
            },
            information,
        ))
    }

    fn object_attributes_to_file_target(
        &self,
        object_attributes: ObjectAttributes,
    ) -> Result<FileTarget, NtStatus> {
        let object_name_ptr =
            ConstPtr::<Platform, UnicodeString>::from_usize(object_attributes.object_name);
        let object_name = object_name_ptr
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
        let object_name = object_name.read_string::<Platform>()?;
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
            let _ = io_status_block
                .write_at_offset(0, IoStatusBlock::new(status, failure_information(status)));
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

fn failure_information(status: NtStatus) -> usize {
    match status {
        NtStatus::OBJECT_NAME_COLLISION => FileCreateInformation::Exists.into(),
        NtStatus::OBJECT_NAME_NOT_FOUND | NtStatus::OBJECT_PATH_NOT_FOUND => {
            FileCreateInformation::DoesNotExist.into()
        }
        _ => 0,
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
    if file_attributes & FILE_ATTRIBUTE_READONLY == 0 {
        Mode::RUSR | Mode::WUSR
    } else {
        Mode::RUSR
    }
}

fn create_directory_mode(file_attributes: u32) -> Mode {
    create_mode(file_attributes) | Mode::XUSR
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
        unicode_string, utf16_units as utf16,
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
    const FILE_OPEN: u32 = 2;
    const FILE_CREATE: u32 = 1;
    const FILE_OVERWRITE: u32 = 4;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(f)
    }

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

        fn host_create_file(root: Handle, name: &str) -> (NtStatus, *mut c_void) {
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
                    FILE_OPEN,
                    FileCreateOptions::SYNCHRONOUS_IO_NONALERT.bits(),
                    core::ptr::null(),
                    0,
                )
            };
            (host_status(status), handle)
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
                let (status, handle) = host_create_file(console_handle, name);
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

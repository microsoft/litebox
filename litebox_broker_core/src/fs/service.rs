// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative file operations.

use alloc::{sync::Arc, vec::Vec};
use core::any::Any;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode, FileOpenFlags, FileSeekWhence,
    FileStatus, FileStatusFlags, FileUser, MAX_FILE_TRANSFER_SIZE,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::sync::{RawSyncPrimitivesProvider, RwLock};

use super::OFlags;
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use super::resolver::{Resolver, ResolverEntry};
use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink, ReadinessSource};
use crate::{BrokerError, BrokerProcess, Result};

/// Guest-visible result of a broker file operation.
pub type FileResult<T> = core::result::Result<T, FileError>;
type ServiceResult<T> = Result<FileResult<T>>;

/// Behaviorless type-erasure envelope for one broker-owned [`ResolverEntry`].
///
/// This does not introduce another open-file-description layer. The erased resolver entry remains
/// the only per-open semantic state. The surrounding lock serializes shared position and append
/// updates across duplicated broker references, while operations that cannot update position use
/// shared access so blocking device I/O does not prevent status and other stateless operations.
#[derive(Clone)]
pub struct File {
    state: Arc<dyn Any + Send + Sync>,
    /// Readiness of a file whose reads or writes can fail with `WouldBlock`.
    readiness: Option<Arc<dyn ReadinessSource>>,
}

impl File {
    fn state<State: Any + Send + Sync>(&self) -> Result<&State> {
        self.state
            .as_ref()
            .downcast_ref()
            .ok_or(BrokerError::Internal)
    }

    /// Returns a registration that publishes this file's readiness changes through
    /// `readiness_sink` for `handle` until it drops, or `None` if its reads and writes always make
    /// progress.
    pub(crate) fn watch(
        &self,
        handle: ObjectHandle,
        readiness_sink: &Arc<dyn ReadinessSink>,
    ) -> Result<Option<ReadinessRegistration>> {
        let Some(source) = &self.readiness else {
            return Ok(None);
        };
        let registration = ReadinessRegistration::new(handle, Arc::clone(readiness_sink));
        source.watch(&registration)?;
        Ok(Some(registration))
    }

    /// Returns this file's readiness, if its reads or writes can fail with `WouldBlock`.
    pub(crate) fn readiness(&self) -> Result<ReadinessFlags> {
        self.readiness
            .as_ref()
            .map(|source| source.readiness())
            .ok_or(BrokerError::InvalidRights)
    }
}

impl ObjectEntry {
    fn as_file(&self) -> Result<&File> {
        match self {
            Self::File(file) => Ok(file),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

mod private {
    use super::{
        BrokerError, File, FileAccessMode, FileDirectoryEntry, FileMode, FileOpenFlags,
        FileSeekWhence, FileStatus, FileStatusFlags, FileUser, Result, ServiceResult, Vec,
    };

    pub trait Service: Send + Sync {
        fn open(
            &self,
            _path: &str,
            _user: FileUser,
            _access: FileAccessMode,
            _flags: FileOpenFlags,
            _mode: FileMode,
        ) -> ServiceResult<File> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn read(
            &self,
            _file: &File,
            _output: &mut [u8],
            _offset: Option<u64>,
        ) -> ServiceResult<usize> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn write(&self, _file: &File, _input: &[u8], _offset: Option<u64>) -> ServiceResult<usize> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn seek(&self, _file: &File, _offset: i64, _whence: FileSeekWhence) -> ServiceResult<u64> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn truncate(&self, _file: &File, _length: u64, _reset_offset: bool) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn read_directory(&self, _file: &File) -> ServiceResult<Vec<FileDirectoryEntry>> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn handle_status(&self, _file: &File) -> ServiceResult<FileStatus> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn is_terminal(&self, _file: &File) -> ServiceResult<bool> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn get_status_flags(&self, _file: &File) -> Result<FileStatusFlags> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn set_status_flags(
            &self,
            _file: &File,
            _mask: FileOpenFlags,
            _flags: FileOpenFlags,
        ) -> Result<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn path_status(&self, _path: &str, _user: FileUser) -> ServiceResult<FileStatus> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chmod(&self, _path: &str, _user: FileUser, _mode: FileMode) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chown(
            &self,
            _path: &str,
            _acting_user: FileUser,
            _user: Option<u16>,
            _group: Option<u16>,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn unlink(&self, _path: &str, _user: FileUser) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn mkdir(&self, _path: &str, _user: FileUser, _mode: FileMode) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn rmdir(&self, _path: &str, _user: FileUser) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }
    }
}

/// Object-safe broker-wide file service.
///
/// Implementations are sealed so every broker-owned open state is created and interpreted by
/// broker core. Construct a [`Resolver`] for a real fs, or use
/// [`UnsupportedFileService`] when file operations are intentionally unavailable.
pub trait FileService: private::Service {}

impl<Service: private::Service> FileService for Service {}

/// File service for broker configurations that intentionally expose no file operations.
pub struct UnsupportedFileService;

impl private::Service for UnsupportedFileService {}

impl<Platform, Backend> private::Service for Resolver<Platform, Backend>
where
    Backend: super::backend::Backend + 'static,
    Platform: RawSyncPrimitivesProvider,
{
    fn open(
        &self,
        path: &str,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    ) -> ServiceResult<File> {
        let flags = open_flags(access, flags)?;
        let entry = match Resolver::open(self, user, path, flags, mode & FileMode::SUPPORTED) {
            Ok(entry) => entry,
            Err(error) => return Ok(Err(file_open_error(error))),
        };
        let readiness = Resolver::readiness_source(self, &entry);
        Ok(Ok(File {
            state: Arc::new(RwLock::<Platform, _>::new(entry)),
            readiness,
        }))
    }

    fn read(&self, file: &File, output: &mut [u8], offset: Option<u64>) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, output.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = file.state::<RwLock<Platform, ResolverEntry<Backend>>>()?;
        let entry = state.read();
        let nonblocking = entry.is_nonblocking();
        let read = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.read_without_position_update(&entry, output, offset)
                .map(|(read, _)| read)
        } else {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            Resolver::read(self, &mut entry, output, offset)
        };
        let read = match read {
            Ok(read) => read,
            Err(ReadError::WouldBlock) => return Err(would_block(nonblocking)),
            Err(error) => return Ok(Err(file_read_error(error))),
        };
        if read > output.len() {
            return Err(BrokerError::Internal);
        }
        Ok(Ok(read))
    }

    fn write(&self, file: &File, input: &[u8], offset: Option<u64>) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, input.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = file.state::<RwLock<Platform, ResolverEntry<Backend>>>()?;
        let entry = state.read();
        let nonblocking = entry.is_nonblocking();
        let written = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.write_without_position_update(&entry, input, offset)
                .map(|(written, _)| written)
        } else {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            Resolver::write(self, &mut entry, input, offset)
        };
        let written = match written {
            Ok(written) => written,
            Err(WriteError::WouldBlock) => return Err(would_block(nonblocking)),
            Err(error) => return Ok(Err(file_write_error(error))),
        };
        if written > input.len() {
            return Err(BrokerError::Internal);
        }
        Ok(Ok(written))
    }

    fn seek(&self, file: &File, offset: i64, whence: FileSeekWhence) -> ServiceResult<u64> {
        let Ok(offset) = isize::try_from(offset) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = file.state::<RwLock<Platform, ResolverEntry<Backend>>>()?;
        let entry = state.read();
        let seek = if entry.uses_position() {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            Resolver::seek(self, &mut entry, offset, whence)
        } else {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            Resolver::<Platform, Backend>::seek_without_position_update(&entry)
        };
        let offset = match seek {
            Ok(offset) => offset,
            Err(error) => return Ok(Err(file_seek_error(error))),
        };
        Ok(Ok(u64::try_from(offset).map_err(|_| BrokerError::Internal)?))
    }

    fn truncate(&self, file: &File, length: u64, reset_offset: bool) -> ServiceResult<()> {
        let Ok(length) = usize::try_from(length) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = file.state::<RwLock<Platform, ResolverEntry<Backend>>>()?;
        let entry = state.read();
        let truncate = if reset_offset && entry.uses_position() {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            Resolver::truncate(self, &mut entry, length, true)
        } else {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.truncate_without_position_update(&entry, length)
        };
        Ok(truncate.map_err(file_truncate_error))
    }

    fn read_directory(&self, file: &File) -> ServiceResult<Vec<FileDirectoryEntry>> {
        let entry = file
            .state::<RwLock<Platform, ResolverEntry<Backend>>>()?
            .read();
        if entry.is_path_only() {
            return Ok(Err(FileError::AccessNotAllowed));
        }
        if !entry.allows_read() {
            return Ok(Err(FileError::NotForReading));
        }
        let entries = match Resolver::read_dir(self, &entry) {
            Ok(entries) => entries,
            Err(error) => return Ok(Err(file_read_directory_error(error))),
        };
        Ok(Ok(entries))
    }

    fn handle_status(&self, file: &File) -> ServiceResult<FileStatus> {
        let entry = file
            .state::<RwLock<Platform, ResolverEntry<Backend>>>()?
            .read();
        let mut status = match Resolver::handle_status(self, &entry) {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        mask_status_mode(&mut status);
        Ok(Ok(status))
    }

    fn is_terminal(&self, file: &File) -> ServiceResult<bool> {
        let entry = file
            .state::<RwLock<Platform, ResolverEntry<Backend>>>()?
            .read();
        Ok(Ok(Resolver::is_terminal(self, &entry)))
    }

    fn get_status_flags(&self, file: &File) -> Result<FileStatusFlags> {
        let entry = file
            .state::<RwLock<Platform, ResolverEntry<Backend>>>()?
            .read();
        let access = match (entry.allows_read(), entry.allows_write()) {
            (true, true) => FileAccessMode::ReadWrite,
            (false, true) => FileAccessMode::WriteOnly,
            _ => FileAccessMode::ReadOnly,
        };
        let mut flags = FileOpenFlags::NONE;
        for (set, flag) in [
            (entry.is_nonblocking(), FileOpenFlags::NONBLOCKING),
            (entry.is_append(), FileOpenFlags::APPEND),
            (entry.is_path_only(), FileOpenFlags::PATH),
        ] {
            if set {
                flags = flags | flag;
            }
        }
        Ok(FileStatusFlags { access, flags })
    }

    fn set_status_flags(
        &self,
        file: &File,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<()> {
        let mut entry = file
            .state::<RwLock<Platform, ResolverEntry<Backend>>>()?
            .write();
        if entry.is_path_only() {
            return Err(BrokerError::InvalidRights);
        }
        if mask.contains(FileOpenFlags::NONBLOCKING) {
            entry.set_nonblocking(flags.contains(FileOpenFlags::NONBLOCKING));
        }
        if mask.contains(FileOpenFlags::APPEND) {
            entry.set_append(flags.contains(FileOpenFlags::APPEND));
        }
        Ok(())
    }

    fn path_status(&self, path: &str, user: FileUser) -> ServiceResult<FileStatus> {
        let mut status = match Resolver::file_status(self, user, path) {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        mask_status_mode(&mut status);
        Ok(Ok(status))
    }

    fn chmod(&self, path: &str, user: FileUser, mode: FileMode) -> ServiceResult<()> {
        Ok(Resolver::chmod(self, user, path, mode & FileMode::SUPPORTED).map_err(file_chmod_error))
    }

    fn chown(
        &self,
        path: &str,
        acting_user: FileUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> ServiceResult<()> {
        Ok(Resolver::chown(self, acting_user, path, user, group).map_err(file_chown_error))
    }

    fn unlink(&self, path: &str, user: FileUser) -> ServiceResult<()> {
        Ok(Resolver::unlink(self, user, path).map_err(file_unlink_error))
    }

    fn mkdir(&self, path: &str, user: FileUser, mode: FileMode) -> ServiceResult<()> {
        Ok(Resolver::mkdir(self, user, path, mode & FileMode::SUPPORTED).map_err(file_mkdir_error))
    }

    fn rmdir(&self, path: &str, user: FileUser) -> ServiceResult<()> {
        Ok(Resolver::rmdir(self, user, path).map_err(file_rmdir_error))
    }
}

/// Opens an absolute path and installs its broker-owned open state in `process`.
///
/// If reads or writes of the file can fail with [`BrokerError::WouldBlock`], the new reference
/// publishes the file's readiness through `readiness_sink`.
pub fn open(
    process: &BrokerProcess,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<FileResult<ObjectHandle>> {
    let rights = authorize(process, open_required_rights(access, flags)?)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    let reference = process.reserve_object_reference(rights)?;
    let file = match process.core.fs.open(path, user, access, flags, mode)? {
        Ok(file) => file,
        Err(error) => return Ok(Err(error)),
    };
    let readiness = file.watch(reference.handle(), readiness_sink)?;
    reference
        .commit_with_readiness(ObjectEntry::File(file), readiness)
        .map(Ok)
}

/// Reads bytes from a broker-owned open file.
///
/// Fails with [`BrokerError::WouldBlock`] while a file that publishes readiness has nothing to
/// read, or with [`BrokerError::NonBlockingWouldBlock`] if the file is also non-blocking.
pub fn read(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut [u8],
    offset: Option<u64>,
) -> Result<FileResult<usize>> {
    if output.len() > MAX_FILE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let file = file(process, handle, ObjectRights::WAIT)?;
    process.core.fs.read(&file, output, offset)
}

/// Writes bytes to a broker-owned open file.
///
/// Fails with [`BrokerError::WouldBlock`] while a file that publishes readiness cannot accept
/// bytes, or with [`BrokerError::NonBlockingWouldBlock`] if the file is also non-blocking.
pub fn write(
    process: &BrokerProcess,
    handle: ObjectHandle,
    input: &[u8],
    offset: Option<u64>,
) -> Result<FileResult<usize>> {
    if input.len() > MAX_FILE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let file = file(process, handle, ObjectRights::WRITE)?;
    process.core.fs.write(&file, input, offset)
}

/// Repositions the shared offset of a broker-owned open file.
pub fn seek(
    process: &BrokerProcess,
    handle: ObjectHandle,
    offset: i64,
    whence: FileSeekWhence,
) -> Result<FileResult<u64>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    process.core.fs.seek(&file, offset, whence)
}

/// Changes the length of a broker-owned open file.
pub fn truncate(
    process: &BrokerProcess,
    handle: ObjectHandle,
    length: u64,
    reset_offset: bool,
) -> Result<FileResult<()>> {
    let file = file(process, handle, ObjectRights::WRITE)?;
    process.core.fs.truncate(&file, length, reset_offset)
}

/// Returns a fresh enumeration of a broker-owned open directory.
pub fn read_directory(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<Vec<FileDirectoryEntry>>> {
    let file = file(process, handle, ObjectRights::WAIT)?;
    process.core.fs.read_directory(&file)
}

/// Returns status for a broker-owned open object.
pub fn handle_status(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<FileStatus>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    process.core.fs.handle_status(&file)
}

/// Returns whether a broker-owned open object refers to a terminal.
pub fn is_terminal(process: &BrokerProcess, handle: ObjectHandle) -> Result<FileResult<bool>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    process.core.fs.is_terminal(&file)
}

/// Returns the access mode and status flags of a broker-owned open file.
pub(crate) fn get_status_flags(process: &BrokerProcess, file: &File) -> Result<FileStatusFlags> {
    process.core.fs.get_status_flags(file)
}

/// Changes the status flags in `mask` of a broker-owned open file to their values in `flags`.
///
/// Fails with [`BrokerError::InvalidRights`] for a file opened only for path-based operations.
pub(crate) fn set_status_flags(
    process: &BrokerProcess,
    file: &File,
    mask: FileOpenFlags,
    flags: FileOpenFlags,
) -> Result<()> {
    process.core.fs.set_status_flags(file, mask, flags)
}

/// Returns status for an absolute path.
pub fn path_status(
    process: &BrokerProcess,
    path: &str,
    user: FileUser,
) -> Result<FileResult<FileStatus>> {
    authorize(process, ObjectRights::WAIT)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    process.core.fs.path_status(path, user)
}

/// Changes mode bits for an absolute path.
pub fn chmod(
    process: &BrokerProcess,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    authorize(process, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    process.core.fs.chmod(path, user, mode)
}

/// Changes ownership for an absolute path.
pub fn chown(
    process: &BrokerProcess,
    path: &str,
    acting_user: FileUser,
    user: Option<u16>,
    group: Option<u16>,
) -> Result<FileResult<()>> {
    authorize(process, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    process.core.fs.chown(path, acting_user, user, group)
}

/// Removes a file at an absolute path.
pub fn unlink(process: &BrokerProcess, path: &str, user: FileUser) -> Result<FileResult<()>> {
    authorize(process, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    process.core.fs.unlink(path, user)
}

/// Creates a directory at an absolute path.
pub fn mkdir(
    process: &BrokerProcess,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    authorize(process, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    process.core.fs.mkdir(path, user, mode)
}

/// Removes a directory at an absolute path.
pub fn rmdir(process: &BrokerProcess, path: &str, user: FileUser) -> Result<FileResult<()>> {
    authorize(process, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    process.core.fs.rmdir(path, user)
}

fn authorize(process: &BrokerProcess, required: ObjectRights) -> Result<ObjectRights> {
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    if rights.contains(required) {
        Ok(rights)
    } else {
        Err(BrokerError::PolicyDenied)
    }
}

fn open_required_rights(access: FileAccessMode, flags: FileOpenFlags) -> Result<ObjectRights> {
    if flags.contains(FileOpenFlags::PATH) {
        return Ok(ObjectRights::WAIT);
    }
    let mut rights = match access {
        FileAccessMode::ReadOnly => ObjectRights::WAIT,
        FileAccessMode::WriteOnly => ObjectRights::WRITE,
        FileAccessMode::ReadWrite => ObjectRights::WAIT | ObjectRights::WRITE,
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    if flags.contains(FileOpenFlags::CREATE) || flags.contains(FileOpenFlags::TRUNCATE) {
        rights |= ObjectRights::WRITE;
    }
    Ok(rights)
}

fn validate_path(path: &str) -> FileResult<()> {
    if path.starts_with('/') && !path.as_bytes().contains(&0) {
        Ok(())
    } else {
        Err(FileError::InvalidPathname)
    }
}

/// Returns the error for a read or write that would block on a file whose
/// [`FileOpenFlags::NONBLOCKING`] status flag is `nonblocking`.
fn would_block(nonblocking: bool) -> BrokerError {
    if nonblocking {
        BrokerError::NonBlockingWouldBlock
    } else {
        BrokerError::WouldBlock
    }
}

fn checked_offset(offset: Option<u64>, length: usize) -> FileResult<Option<usize>> {
    let Some(offset) = offset else {
        return Ok(None);
    };
    let offset = usize::try_from(offset).map_err(|_| FileError::InvalidOffset)?;
    offset.checked_add(length).ok_or(FileError::InvalidOffset)?;
    Ok(Some(offset))
}

fn file(
    process: &BrokerProcess,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<File> {
    let object = process.authorized_object(handle, required_rights)?;
    let object = object.read();
    object.as_file().cloned()
}

fn file_with_any_rights(
    process: &BrokerProcess,
    handle: ObjectHandle,
    allowed_rights: ObjectRights,
) -> Result<File> {
    let object = process.authorized_object_with_any_rights(handle, allowed_rights)?;
    let object = object.read();
    object.as_file().cloned()
}

fn open_flags(access: FileAccessMode, flags: FileOpenFlags) -> Result<OFlags> {
    let mut output = match access {
        FileAccessMode::ReadOnly => OFlags::RDONLY,
        FileAccessMode::WriteOnly => OFlags::WRONLY,
        FileAccessMode::ReadWrite => OFlags::RDWR,
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    for (file_flag, engine_flag) in [
        (FileOpenFlags::CREATE, OFlags::CREAT),
        (FileOpenFlags::TRUNCATE, OFlags::TRUNC),
        (FileOpenFlags::NO_CONTROLLING_TERMINAL, OFlags::NOCTTY),
        (FileOpenFlags::EXCLUSIVE, OFlags::EXCL),
        (FileOpenFlags::DIRECTORY, OFlags::DIRECTORY),
        (FileOpenFlags::NONBLOCKING, OFlags::NONBLOCK),
        (FileOpenFlags::LARGE_FILE, OFlags::LARGEFILE),
        (FileOpenFlags::NO_FOLLOW, OFlags::NOFOLLOW),
        (FileOpenFlags::APPEND, OFlags::APPEND),
        (FileOpenFlags::PATH, OFlags::PATH),
    ] {
        if flags.contains(file_flag) {
            output |= engine_flag;
        }
    }
    Ok(output)
}

fn mask_status_mode(status: &mut FileStatus) {
    status.mode &= FileMode::SUPPORTED;
}

// TODO: Define canonical per-operation protocol errors so these engine-to-protocol conversions can
// be removed while retaining operation-specific error sets.
fn file_path_error(error: PathError) -> FileError {
    match error {
        PathError::NoSuchFileOrDirectory => FileError::NoSuchFileOrDirectory,
        PathError::NoSearchPerms { .. } => FileError::NoSearchPermissions,
        PathError::InvalidPathname => FileError::InvalidPathname,
        PathError::MissingComponent => FileError::MissingComponent,
        PathError::ComponentNotADirectory => FileError::ComponentNotDirectory,
    }
}

fn file_open_error(error: OpenError) -> FileError {
    match error {
        OpenError::AccessNotAllowed => FileError::AccessNotAllowed,
        OpenError::NoWritePerms => FileError::NoWritePermissions,
        OpenError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        OpenError::AlreadyExists => FileError::AlreadyExists,
        OpenError::TruncateError(error) => file_truncate_error(error),
        OpenError::PathError(error) => file_path_error(error),
        OpenError::Io => FileError::Io,
    }
}

fn file_read_error(error: ReadError) -> FileError {
    match error {
        ReadError::NotAFile => FileError::NotFile,
        ReadError::NotForReading => FileError::NotForReading,
        ReadError::ClosedFd | ReadError::Io | ReadError::WouldBlock => FileError::Io,
    }
}

fn file_write_error(error: WriteError) -> FileError {
    match error {
        WriteError::NotAFile => FileError::NotFile,
        WriteError::NotForWriting => FileError::NotForWriting,
        WriteError::ClosedFd | WriteError::Io | WriteError::WouldBlock => FileError::Io,
    }
}

fn file_seek_error(error: SeekError) -> FileError {
    match error {
        SeekError::NotAFile => FileError::NotFile,
        SeekError::InvalidOffset => FileError::InvalidOffset,
        SeekError::NonSeekable => FileError::NonSeekable,
        SeekError::ClosedFd | SeekError::Io => FileError::Io,
    }
}

fn file_truncate_error(error: TruncateError) -> FileError {
    match error {
        TruncateError::IsDirectory => FileError::IsDirectory,
        TruncateError::NotForWriting => FileError::NotForWriting,
        TruncateError::IsTerminalDevice => FileError::IsTerminalDevice,
        TruncateError::ClosedFd | TruncateError::Io => FileError::Io,
    }
}

fn file_chmod_error(error: ChmodError) -> FileError {
    match error {
        ChmodError::NotTheOwner => FileError::NotOwner,
        ChmodError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        ChmodError::PathError(error) => file_path_error(error),
        ChmodError::Io => FileError::Io,
    }
}

fn file_chown_error(error: ChownError) -> FileError {
    match error {
        ChownError::NotTheOwner => FileError::NotOwner,
        ChownError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        ChownError::PathError(error) => file_path_error(error),
        ChownError::Io => FileError::Io,
    }
}

fn file_unlink_error(error: UnlinkError) -> FileError {
    match error {
        UnlinkError::NoWritePerms => FileError::NoWritePermissions,
        UnlinkError::IsADirectory => FileError::IsDirectory,
        UnlinkError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        UnlinkError::PathError(error) => file_path_error(error),
        UnlinkError::Io => FileError::Io,
    }
}

fn file_mkdir_error(error: MkdirError) -> FileError {
    match error {
        MkdirError::NoWritePerms => FileError::NoWritePermissions,
        MkdirError::AlreadyExists => FileError::AlreadyExists,
        MkdirError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        MkdirError::PathError(error) => file_path_error(error),
        MkdirError::Io => FileError::Io,
    }
}

fn file_rmdir_error(error: RmdirError) -> FileError {
    match error {
        RmdirError::NoWritePerms => FileError::NoWritePermissions,
        RmdirError::Busy => FileError::Busy,
        RmdirError::NotEmpty => FileError::NotEmpty,
        RmdirError::NotADirectory => FileError::NotDirectory,
        RmdirError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        RmdirError::PathError(error) => file_path_error(error),
        RmdirError::Io => FileError::Io,
    }
}

fn file_read_directory_error(error: ReadDirError) -> FileError {
    match error {
        ReadDirError::NotADirectory => FileError::NotDirectory,
        ReadDirError::ClosedFd | ReadDirError::Io => FileError::Io,
    }
}

fn file_status_error(error: FileStatusError) -> FileError {
    match error {
        FileStatusError::PathError(error) => file_path_error(error),
        FileStatusError::ClosedFd | FileStatusError::Io => FileError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use litebox_broker_protocol::fs::{FileNodeInfo, FileType};

    #[test]
    fn file_status_excludes_object_type_mode_bits() {
        let mut status = FileStatus {
            file_type: FileType::RegularFile,
            mode: FileMode::from_bits_retain(0o100644),
            size: u64::MAX,
            owner: FileUser::ROOT,
            node_info: FileNodeInfo {
                dev: u64::MAX,
                ino: u64::MAX - 1,
                rdev: NonZeroU64::new(u64::MAX),
            },
            blksize: u64::MAX,
        };
        let mut expected = status;
        expected.mode = FileMode::from_bits(0o644).unwrap();

        mask_status_mode(&mut status);

        assert_eq!(status, expected);
    }
}

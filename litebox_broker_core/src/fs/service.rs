// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative file operations.

use alloc::{sync::Arc, vec::Vec};
use core::{any::Any, marker::PhantomData};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode, FileNodeInfo, FileOpenFlags,
    FileSeekWhence, FileStatus as ProtocolFileStatus, FileType as ProtocolFileType, FileUser,
    MAX_FILE_TRANSFER_SIZE,
};
use litebox_broker_protocol::stdio::{MAX_STDIO_TRANSFER_SIZE, StdioOutputStream};
use litebox_platform::sync::{RawSyncPrimitivesProvider, RwLock};

use super::backend::DeviceIo;
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use super::resolver::{Engine, ResolverEntry};
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence, UserInfo};
use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result};

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
pub struct File(Arc<dyn Any + Send + Sync>);

impl File {
    fn state<State: Any + Send + Sync>(&self) -> Result<&State> {
        self.0.as_ref().downcast_ref().ok_or(BrokerError::Internal)
    }
}

mod private {
    use super::{
        BrokerError, BrokerSession, File, FileAccessMode, FileDirectoryEntry, FileMode,
        FileOpenFlags, FileSeekWhence, FileUser, ProtocolFileStatus, ServiceResult, Vec,
    };

    pub trait Service: Send + Sync {
        fn open(
            &self,
            _session: &BrokerSession,
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
            _session: &BrokerSession,
            _file: &File,
            _output: &mut [u8],
            _offset: Option<u64>,
        ) -> ServiceResult<usize> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn write(
            &self,
            _session: &BrokerSession,
            _file: &File,
            _input: &[u8],
            _offset: Option<u64>,
        ) -> ServiceResult<usize> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn seek(
            &self,
            _session: &BrokerSession,
            _file: &File,
            _offset: i64,
            _whence: FileSeekWhence,
        ) -> ServiceResult<u64> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn truncate(
            &self,
            _session: &BrokerSession,
            _file: &File,
            _length: u64,
            _reset_offset: bool,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn read_directory(
            &self,
            _session: &BrokerSession,
            _file: &File,
        ) -> ServiceResult<Vec<FileDirectoryEntry>> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn handle_status(
            &self,
            _session: &BrokerSession,
            _file: &File,
        ) -> ServiceResult<ProtocolFileStatus> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn path_status(
            &self,
            _session: &BrokerSession,
            _path: &str,
            _user: FileUser,
        ) -> ServiceResult<ProtocolFileStatus> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chmod(
            &self,
            _session: &BrokerSession,
            _path: &str,
            _user: FileUser,
            _mode: FileMode,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chown(
            &self,
            _session: &BrokerSession,
            _path: &str,
            _acting_user: FileUser,
            _user: Option<u16>,
            _group: Option<u16>,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn unlink(
            &self,
            _session: &BrokerSession,
            _path: &str,
            _user: FileUser,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn mkdir(
            &self,
            _session: &BrokerSession,
            _path: &str,
            _user: FileUser,
            _mode: FileMode,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn rmdir(
            &self,
            _session: &BrokerSession,
            _path: &str,
            _user: FileUser,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }
    }
}

/// Object-safe broker-wide file service.
///
/// Implementations are sealed so every broker-owned open state is created and interpreted by
/// broker core. Construct an [`EngineFileService`] for a real fs engine, or use
/// [`UnsupportedFileService`] when file operations are intentionally unavailable.
pub trait FileService: private::Service {}

impl<Service: private::Service> FileService for Service {}

/// File service backed by one broker-core [`Engine`].
pub struct EngineFileService<Backend: super::backend::Backend, Platform> {
    engine: Engine<Backend>,
    _sync: PhantomData<fn() -> Platform>,
}

impl<Backend: super::backend::Backend, Platform> EngineFileService<Backend, Platform> {
    /// Creates a file service over the global fs engine.
    ///
    /// `Platform` selects the blocking synchronization primitives used for shared per-open state.
    #[must_use]
    pub fn new(engine: Engine<Backend>) -> Self {
        Self {
            engine,
            _sync: PhantomData,
        }
    }
}

/// File service for broker configurations that intentionally expose no file operations.
pub struct UnsupportedFileService;

impl private::Service for UnsupportedFileService {}

impl<Backend, Platform> EngineFileService<Backend, Platform>
where
    Backend: super::backend::Backend + 'static,
    Platform: RawSyncPrimitivesProvider,
{
    fn state(file: &File) -> Result<&RwLock<Platform, ResolverEntry<Backend>>> {
        file.state()
    }
}

impl<Backend, Platform> private::Service for EngineFileService<Backend, Platform>
where
    Backend: super::backend::Backend + 'static,
    Platform: RawSyncPrimitivesProvider,
{
    fn open(
        &self,
        _session: &BrokerSession,
        path: &str,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
    ) -> ServiceResult<File> {
        let flags = open_flags(access, flags)?;
        let entry = match self
            .engine
            .open(user_info(user), path, flags, file_mode(mode))
        {
            Ok(entry) => entry,
            Err(error) => return Ok(Err(file_open_error(error))),
        };
        Ok(Ok(File(Arc::new(RwLock::<Platform, _>::new(entry)))))
    }

    fn read(
        &self,
        session: &BrokerSession,
        file: &File,
        output: &mut [u8],
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, output.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = Self::state(file)?;
        let entry = state.read();
        let read = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.engine.read_without_position_update(
                &SessionDeviceIo(session),
                &entry,
                output,
                offset,
            )
        } else {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.engine
                .read(&SessionDeviceIo(session), &mut entry, output, offset)
        };
        let read = match read {
            Ok(read) => read,
            Err(error) => return Ok(Err(file_read_error(error))),
        };
        if read > output.len() {
            return Err(BrokerError::Internal);
        }
        Ok(Ok(read))
    }

    fn write(
        &self,
        session: &BrokerSession,
        file: &File,
        input: &[u8],
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, input.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = Self::state(file)?;
        let entry = state.read();
        let written = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.engine.write_without_position_update(
                &SessionDeviceIo(session),
                &entry,
                input,
                offset,
            )
        } else {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.engine
                .write(&SessionDeviceIo(session), &mut entry, input, offset)
        };
        let written = match written {
            Ok(written) => written,
            Err(error) => return Ok(Err(file_write_error(error))),
        };
        if written > input.len() {
            return Err(BrokerError::Internal);
        }
        Ok(Ok(written))
    }

    fn seek(
        &self,
        _session: &BrokerSession,
        file: &File,
        offset: i64,
        whence: FileSeekWhence,
    ) -> ServiceResult<u64> {
        let Ok(offset) = isize::try_from(offset) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let whence = seek_whence(whence)?;
        let state = Self::state(file)?;
        let entry = state.read();
        let seek = if entry.uses_position() {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.engine.seek(&mut entry, offset, whence)
        } else {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            Engine::<Backend>::seek_without_position_update(&entry)
        };
        let offset = match seek {
            Ok(offset) => offset,
            Err(error) => return Ok(Err(file_seek_error(error))),
        };
        Ok(Ok(u64::try_from(offset).map_err(|_| BrokerError::Internal)?))
    }

    fn truncate(
        &self,
        _session: &BrokerSession,
        file: &File,
        length: u64,
        reset_offset: bool,
    ) -> ServiceResult<()> {
        let Ok(length) = usize::try_from(length) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = Self::state(file)?;
        let entry = state.read();
        let truncate = if reset_offset && entry.uses_position() {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.engine.truncate(&mut entry, length, true)
        } else {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.engine.truncate_without_position_update(&entry, length)
        };
        Ok(truncate.map_err(file_truncate_error))
    }

    fn read_directory(
        &self,
        _session: &BrokerSession,
        file: &File,
    ) -> ServiceResult<Vec<FileDirectoryEntry>> {
        let entry = Self::state(file)?.read();
        if entry.is_path_only() {
            return Ok(Err(FileError::AccessNotAllowed));
        }
        if !entry.allows_read() {
            return Ok(Err(FileError::NotForReading));
        }
        let entries = match self.engine.read_dir(&entry) {
            Ok(entries) => entries,
            Err(error) => return Ok(Err(file_read_directory_error(error))),
        };
        let entries = entries
            .into_iter()
            .map(directory_entry)
            .collect::<Result<Vec<_>>>()?;
        Ok(Ok(entries))
    }

    fn handle_status(
        &self,
        _session: &BrokerSession,
        file: &File,
    ) -> ServiceResult<ProtocolFileStatus> {
        let entry = Self::state(file)?.read();
        let status = match self.engine.handle_status(&entry) {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        Ok(Ok(file_status(status)?))
    }

    fn path_status(
        &self,
        _session: &BrokerSession,
        path: &str,
        user: FileUser,
    ) -> ServiceResult<ProtocolFileStatus> {
        let status = match self.engine.file_status(user_info(user), path) {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        Ok(Ok(file_status(status)?))
    }

    fn chmod(
        &self,
        _session: &BrokerSession,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> ServiceResult<()> {
        Ok(self
            .engine
            .chmod(user_info(user), path, file_mode(mode))
            .map_err(file_chmod_error))
    }

    fn chown(
        &self,
        _session: &BrokerSession,
        path: &str,
        acting_user: FileUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> ServiceResult<()> {
        Ok(self
            .engine
            .chown(user_info(acting_user), path, user, group)
            .map_err(file_chown_error))
    }

    fn unlink(&self, _session: &BrokerSession, path: &str, user: FileUser) -> ServiceResult<()> {
        Ok(self
            .engine
            .unlink(user_info(user), path)
            .map_err(file_unlink_error))
    }

    fn mkdir(
        &self,
        _session: &BrokerSession,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> ServiceResult<()> {
        Ok(self
            .engine
            .mkdir(user_info(user), path, file_mode(mode))
            .map_err(file_mkdir_error))
    }

    fn rmdir(&self, _session: &BrokerSession, path: &str, user: FileUser) -> ServiceResult<()> {
        Ok(self
            .engine
            .rmdir(user_info(user), path)
            .map_err(file_rmdir_error))
    }
}

/// Opens an absolute path and installs its broker-owned open state in `session`.
pub fn open(
    session: &BrokerSession,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
) -> Result<FileResult<ObjectHandle>> {
    let rights = authorize(session, open_required_rights(access, flags)?)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    let reference = session.reserve_object_reference(rights)?;
    let file = match session
        .core
        .fs
        .open(session, path, user, access, flags, mode)?
    {
        Ok(file) => file,
        Err(error) => return Ok(Err(error)),
    };
    reference.commit(ObjectEntry::File(file)).map(Ok)
}

/// Reads bytes from a broker-owned open file.
pub fn read(
    session: &BrokerSession,
    handle: ObjectHandle,
    output: &mut [u8],
    offset: Option<u64>,
) -> Result<FileResult<usize>> {
    if output.len() > MAX_FILE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let file = file(session, handle, ObjectRights::WAIT)?;
    session.core.fs.read(session, &file, output, offset)
}

/// Writes bytes to a broker-owned open file.
pub fn write(
    session: &BrokerSession,
    handle: ObjectHandle,
    input: &[u8],
    offset: Option<u64>,
) -> Result<FileResult<usize>> {
    if input.len() > MAX_FILE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let file = file(session, handle, ObjectRights::WRITE)?;
    session.core.fs.write(session, &file, input, offset)
}

/// Repositions the shared offset of a broker-owned open file.
pub fn seek(
    session: &BrokerSession,
    handle: ObjectHandle,
    offset: i64,
    whence: FileSeekWhence,
) -> Result<FileResult<u64>> {
    let file = file_with_any_rights(session, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    session.core.fs.seek(session, &file, offset, whence)
}

/// Changes the length of a broker-owned open file.
pub fn truncate(
    session: &BrokerSession,
    handle: ObjectHandle,
    length: u64,
    reset_offset: bool,
) -> Result<FileResult<()>> {
    let file = file(session, handle, ObjectRights::WRITE)?;
    session
        .core
        .fs
        .truncate(session, &file, length, reset_offset)
}

/// Returns a fresh enumeration of a broker-owned open directory.
pub fn read_directory(
    session: &BrokerSession,
    handle: ObjectHandle,
) -> Result<FileResult<Vec<FileDirectoryEntry>>> {
    let file = file(session, handle, ObjectRights::WAIT)?;
    session.core.fs.read_directory(session, &file)
}

/// Returns status for a broker-owned open object.
pub fn handle_status(
    session: &BrokerSession,
    handle: ObjectHandle,
) -> Result<FileResult<ProtocolFileStatus>> {
    let file = file_with_any_rights(session, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    session.core.fs.handle_status(session, &file)
}

/// Returns status for an absolute path.
pub fn path_status(
    session: &BrokerSession,
    path: &str,
    user: FileUser,
) -> Result<FileResult<ProtocolFileStatus>> {
    authorize(session, ObjectRights::WAIT)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    session.core.fs.path_status(session, path, user)
}

/// Changes mode bits for an absolute path.
pub fn chmod(
    session: &BrokerSession,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    authorize(session, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    session.core.fs.chmod(session, path, user, mode)
}

/// Changes ownership for an absolute path.
pub fn chown(
    session: &BrokerSession,
    path: &str,
    acting_user: FileUser,
    user: Option<u16>,
    group: Option<u16>,
) -> Result<FileResult<()>> {
    authorize(session, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    session
        .core
        .fs
        .chown(session, path, acting_user, user, group)
}

/// Removes a file at an absolute path.
pub fn unlink(session: &BrokerSession, path: &str, user: FileUser) -> Result<FileResult<()>> {
    authorize(session, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    session.core.fs.unlink(session, path, user)
}

/// Creates a directory at an absolute path.
pub fn mkdir(
    session: &BrokerSession,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    authorize(session, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    session.core.fs.mkdir(session, path, user, mode)
}

/// Removes a directory at an absolute path.
pub fn rmdir(session: &BrokerSession, path: &str, user: FileUser) -> Result<FileResult<()>> {
    authorize(session, ObjectRights::WRITE)?;
    if let Err(error) = validate_path(path) {
        return Ok(Err(error));
    }
    session.core.fs.rmdir(session, path, user)
}

fn authorize(session: &BrokerSession, required: ObjectRights) -> Result<ObjectRights> {
    let rights = session
        .core
        .policy
        .principal_object_rights(session.caller_credential)?;
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

fn checked_offset(offset: Option<u64>, length: usize) -> FileResult<Option<usize>> {
    let Some(offset) = offset else {
        return Ok(None);
    };
    let offset = usize::try_from(offset).map_err(|_| FileError::InvalidOffset)?;
    offset.checked_add(length).ok_or(FileError::InvalidOffset)?;
    Ok(Some(offset))
}

fn file(
    session: &BrokerSession,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<File> {
    let object = session.authorized_object(handle, required_rights)?;
    let object = object.read();
    match &*object {
        ObjectEntry::File(file) => Ok(file.clone()),
        ObjectEntry::Event(_) | ObjectEntry::Pipe(_) | ObjectEntry::Socket(_) => {
            Err(BrokerError::InvalidRights)
        }
        ObjectEntry::Reserved => Err(BrokerError::Internal),
    }
}

fn file_with_any_rights(
    session: &BrokerSession,
    handle: ObjectHandle,
    allowed_rights: ObjectRights,
) -> Result<File> {
    let object = session.authorized_object_with_any_rights(handle, allowed_rights)?;
    let object = object.read();
    match &*object {
        ObjectEntry::File(file) => Ok(file.clone()),
        ObjectEntry::Event(_) | ObjectEntry::Pipe(_) | ObjectEntry::Socket(_) => {
            Err(BrokerError::InvalidRights)
        }
        ObjectEntry::Reserved => Err(BrokerError::Internal),
    }
}

struct SessionDeviceIo<'session>(&'session BrokerSession);

impl DeviceIo for SessionDeviceIo<'_> {
    fn read_stdin(&self, output: &mut [u8]) -> core::result::Result<usize, ReadError> {
        let length = output.len().min(MAX_STDIO_TRANSFER_SIZE as usize);
        crate::stdio::read(self.0, &mut output[..length]).map_err(|_| ReadError::Io)
    }

    fn write_stdio(
        &self,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> core::result::Result<usize, WriteError> {
        let length = input.len().min(MAX_STDIO_TRANSFER_SIZE as usize);
        crate::stdio::write(self.0, stream, &input[..length]).map_err(|_| WriteError::Io)
    }

    fn fill_random(&self, output: &mut [u8]) -> core::result::Result<(), ReadError> {
        crate::random::fill(self.0, output).map_err(|_| ReadError::Io)
    }
}

const fn user_info(user: FileUser) -> UserInfo {
    UserInfo {
        user: user.user,
        group: user.group,
    }
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

fn file_mode(mode: FileMode) -> Mode {
    Mode::from_bits_retain(u32::from(mode.bits()))
}

fn seek_whence(whence: FileSeekWhence) -> Result<SeekWhence> {
    Ok(match whence {
        FileSeekWhence::Beginning => SeekWhence::RelativeToBeginning,
        FileSeekWhence::Current => SeekWhence::RelativeToCurrentOffset,
        FileSeekWhence::End => SeekWhence::RelativeToEnd,
        _ => return Err(BrokerError::UnsupportedOperation),
    })
}

fn file_status(status: FileStatus) -> Result<ProtocolFileStatus> {
    let mode_bits = u16::try_from(status.mode.bits() & u32::from(FileMode::SUPPORTED.bits()))
        .map_err(|_| BrokerError::Internal)?;
    let mode = FileMode::from_bits(mode_bits).ok_or(BrokerError::Internal)?;
    Ok(ProtocolFileStatus {
        file_type: file_type(status.file_type),
        mode,
        size: u64::try_from(status.size).map_err(|_| BrokerError::Internal)?,
        owner: FileUser {
            user: status.owner.user,
            group: status.owner.group,
        },
        node_info: node_info(status.node_info)?,
        block_size: u64::try_from(status.blksize).map_err(|_| BrokerError::Internal)?,
    })
}

fn directory_entry(entry: DirEntry) -> Result<FileDirectoryEntry> {
    Ok(FileDirectoryEntry {
        name: entry.name,
        file_type: file_type(entry.file_type),
        node_info: entry.ino_info.map(node_info).transpose()?,
    })
}

const fn file_type(file_type: FileType) -> ProtocolFileType {
    match file_type {
        FileType::RegularFile => ProtocolFileType::RegularFile,
        FileType::Directory => ProtocolFileType::Directory,
        FileType::CharacterDevice => ProtocolFileType::CharacterDevice,
    }
}

fn node_info(node_info: NodeInfo) -> Result<FileNodeInfo> {
    Ok(FileNodeInfo {
        dev: u64::try_from(node_info.dev).map_err(|_| BrokerError::Internal)?,
        ino: u64::try_from(node_info.ino).map_err(|_| BrokerError::Internal)?,
        rdev: node_info
            .rdev
            .map(|rdev| u64::try_from(rdev.get()).map_err(|_| BrokerError::Internal))
            .transpose()?,
    })
}

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
        ReadError::ClosedFd | ReadError::Io => FileError::Io,
    }
}

fn file_write_error(error: WriteError) -> FileError {
    match error {
        WriteError::NotAFile => FileError::NotFile,
        WriteError::NotForWriting => FileError::NotForWriting,
        WriteError::ClosedFd | WriteError::Io => FileError::Io,
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

    #[test]
    fn file_status_excludes_object_type_mode_bits() {
        let status = file_status(FileStatus {
            file_type: FileType::RegularFile,
            mode: Mode::from_bits_retain(0o100644),
            size: 1,
            owner: UserInfo::ROOT,
            node_info: NodeInfo {
                dev: 2,
                ino: 3,
                rdev: None,
            },
            blksize: 4096,
        })
        .unwrap();

        assert_eq!(status.mode, FileMode::from_bits(0o644).unwrap());
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative file operations.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::any::Any;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileLockOperation, FileMode, FileOpenFlags,
    FileSeekWhence, FileStatus, FileStatusFlags, FileUser, MAX_FILE_TRANSFER_SIZE, SetFileTimes,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::{TerminalOperation, TerminalResponse};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::{RawSyncPrimitivesProvider, RwLock};

use super::OFlags;
use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, RmdirError, SeekError, SetTimesError, SymlinkError,
    TruncateError, UnlinkError, WalkError, WriteError,
};
use super::resolver::{DirAnchor, Resolver, ResolverEntry};
use super::shared_storage::{SharedFileMapping, SharedMapping};
use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink, ReadinessSource};
use crate::terminal::TerminalEndpoint;
use crate::{BrokerError, BrokerProcess, Result};

/// Guest-visible result of a broker file operation.
pub type FileResult<T> = core::result::Result<T, FileError>;
type ServiceResult<T> = Result<FileResult<T>>;

/// One broker-owned open file description, shared by all references to it.
#[derive(Clone)]
pub struct File {
    state: Arc<dyn OpenFile>,
    /// Readiness of a file whose reads or writes can fail with `WouldBlock`.
    readiness: Option<Arc<dyn ReadinessSource>>,
    terminal: Option<Arc<dyn TerminalEndpoint>>,
}

impl File {
    pub(crate) fn read(
        &self,
        output: &mut dyn ReadBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        self.state.read(output, offset)
    }

    pub(crate) fn write(
        &self,
        input: &dyn WriteBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        self.state.write(input, offset)
    }

    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.state.get_status_flags()
    }

    /// Fails with [`BrokerError::InvalidRights`] for a file opened only for path-based operations.
    pub(crate) fn set_status_flags(&self, mask: FileOpenFlags, flags: FileOpenFlags) -> Result<()> {
        self.state.set_status_flags(mask, flags)
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

    /// Publishes this file's later readiness changes through `registration` until every clone of
    /// it drops, failing with `UnsupportedOperation` if its reads and writes always make progress.
    pub(crate) fn add_watcher(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.readiness
            .as_ref()
            .ok_or(BrokerError::UnsupportedOperation)?
            .watch(registration)
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

trait OpenFile: Send + Sync {
    fn read(&self, output: &mut dyn ReadBuffer, offset: Option<u64>) -> ServiceResult<usize>;
    fn write(&self, input: &dyn WriteBuffer, offset: Option<u64>) -> ServiceResult<usize>;
    fn seek(&self, offset: i64, whence: FileSeekWhence) -> ServiceResult<u64>;
    fn truncate(&self, length: u64, reset_offset: bool) -> ServiceResult<()>;
    fn map_shared(&self) -> ServiceResult<SharedMapping>;
    fn lock(self: Arc<Self>, operation: FileLockOperation) -> ServiceResult<()>;
    fn read_directory(&self) -> ServiceResult<Vec<FileDirectoryEntry>>;
    fn handle_status(&self) -> ServiceResult<FileStatus>;
    fn handle_path(&self) -> ServiceResult<String>;
    fn get_status_flags(&self) -> FileStatusFlags;
    fn set_status_flags(&self, mask: FileOpenFlags, flags: FileOpenFlags) -> Result<()>;
    fn set_times(&self, user: FileUser, times: &SetFileTimes) -> ServiceResult<()>;
    fn as_any(&self) -> &dyn Any;
}

struct ResolverFile<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend> {
    // Shared access lets status and other operations proceed during position-independent I/O.
    entry: RwLock<Platform, ResolverEntry<Backend>>,
    resolver: Arc<Resolver<Platform, Backend>>,
}

mod private {
    use super::{
        Arc, BrokerError, File, FileAccessMode, FileMode, FileOpenFlags, FileStatus, FileUser,
        ServiceResult, String, TerminalEndpoint,
    };

    pub trait Service: Send + Sync {
        /// Opens `path`, binding a file that refers to the opener's controlling terminal to
        /// `controlling_terminal()`.
        #[allow(
            clippy::too_many_arguments,
            reason = "one parameter per open request field, plus the terminal binding"
        )]
        fn open(
            self: Arc<Self>,
            _directory: Option<&File>,
            _path: &str,
            _user: FileUser,
            _access: FileAccessMode,
            _flags: FileOpenFlags,
            _mode: FileMode,
            _controlling_terminal: &dyn Fn() -> Option<Arc<dyn TerminalEndpoint>>,
        ) -> ServiceResult<File> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn path_status(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _user: FileUser,
            _follow_symlinks: bool,
        ) -> ServiceResult<FileStatus> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn read_link(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _user: FileUser,
        ) -> ServiceResult<String> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chmod(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _user: FileUser,
            _mode: FileMode,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chown(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _acting_user: FileUser,
            _user: Option<u16>,
            _group: Option<u16>,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn unlink(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _user: FileUser,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn rename(
            &self,
            _old_directory: Option<&File>,
            _old_path: &str,
            _new_directory: Option<&File>,
            _new_path: &str,
            _user: FileUser,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn mkdir(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _user: FileUser,
            _mode: FileMode,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn mount_in_mem(&self, _path: &str, _user: FileUser) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn symlink(
            &self,
            _target: &str,
            _directory: Option<&File>,
            _linkpath: &str,
            _user: FileUser,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn rmdir(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _user: FileUser,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }
    }
}

/// Object-safe filesystem used for a broker process's path operations and opens.
///
/// Implementations are sealed so every broker-owned open state is created and interpreted by
/// broker core. Construct a [`Resolver`] for a real fs, or use
/// [`UnsupportedFileService`] when opens and path operations are intentionally unavailable.
pub trait FileService: private::Service {}

impl<Service: private::Service> FileService for Service {}

/// A file service that rejects opens and path operations.
///
/// This does not disable operations on open file handles transferred from another process;
/// they remain subject to the receiver's handle rights.
pub struct UnsupportedFileService;

impl private::Service for UnsupportedFileService {}

impl<Platform, Backend> Resolver<Platform, Backend>
where
    Backend: super::backend::Backend + 'static,
    Platform: RawSyncPrimitivesProvider,
{
    // Take an independent snapshot before looking up another anchor (possibly a dup of
    // the same file). No open-description lock is held during the pathname walk.
    fn directory_anchor(&self, directory: Option<&File>) -> Result<Option<DirAnchor>> {
        directory
            .map(|file| {
                let state = file
                    .state
                    .as_any()
                    .downcast_ref::<ResolverFile<Platform, Backend>>()
                    .ok_or(BrokerError::InvalidRights)?;
                // A handle transferred from a process with another filesystem names nothing here.
                if !core::ptr::eq(Arc::as_ptr(&state.resolver), self) {
                    return Err(BrokerError::InvalidRights);
                }
                Ok(state.entry.read().anchor())
            })
            .transpose()
    }
}

impl<Platform, Backend> private::Service for Resolver<Platform, Backend>
where
    Backend: super::backend::Backend + 'static,
    Platform: RawSyncPrimitivesProvider,
{
    fn open(
        self: Arc<Self>,
        directory: Option<&File>,
        path: &str,
        user: FileUser,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
        controlling_terminal: &dyn Fn() -> Option<Arc<dyn TerminalEndpoint>>,
    ) -> ServiceResult<File> {
        let flags = open_flags(access, flags)?;
        let entry = match self.open_with_controlling_terminal(
            user,
            self.directory_anchor(directory)?,
            path,
            flags,
            mode & FileMode::SUPPORTED,
            controlling_terminal,
        ) {
            Ok(entry) => entry,
            Err(error) => return Ok(Err(file_open_error(error))),
        };
        let readiness = self.readiness_source(&entry);
        let terminal = self.terminal(&entry);
        Ok(Ok(File {
            state: Arc::new(ResolverFile {
                entry: RwLock::new(entry),
                resolver: self,
            }),
            readiness,
            terminal,
        }))
    }

    fn path_status(
        &self,
        directory: Option<&File>,
        path: &str,
        user: FileUser,
        follow_symlinks: bool,
    ) -> ServiceResult<FileStatus> {
        let mut status = match Resolver::file_status(
            self,
            user,
            self.directory_anchor(directory)?,
            path,
            follow_symlinks,
        ) {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        mask_status_mode(&mut status);
        Ok(Ok(status))
    }

    fn read_link(
        &self,
        directory: Option<&File>,
        path: &str,
        user: FileUser,
    ) -> ServiceResult<String> {
        Ok(
            Resolver::read_link(self, user, self.directory_anchor(directory)?, path)
                .map_err(file_walk_error),
        )
    }

    fn chmod(
        &self,
        directory: Option<&File>,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> ServiceResult<()> {
        Ok(Resolver::chmod(
            self,
            user,
            self.directory_anchor(directory)?,
            path,
            mode & FileMode::SUPPORTED,
        )
        .map_err(file_chmod_error))
    }

    fn chown(
        &self,
        directory: Option<&File>,
        path: &str,
        acting_user: FileUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> ServiceResult<()> {
        Ok(Resolver::chown(
            self,
            acting_user,
            self.directory_anchor(directory)?,
            path,
            user,
            group,
        )
        .map_err(file_chown_error))
    }

    fn unlink(&self, directory: Option<&File>, path: &str, user: FileUser) -> ServiceResult<()> {
        Ok(
            Resolver::unlink(self, user, self.directory_anchor(directory)?, path)
                .map_err(file_unlink_error),
        )
    }

    fn rename(
        &self,
        old_directory: Option<&File>,
        old_path: &str,
        new_directory: Option<&File>,
        new_path: &str,
        user: FileUser,
    ) -> ServiceResult<()> {
        Ok(Resolver::rename(
            self,
            user,
            self.directory_anchor(old_directory)?,
            old_path,
            self.directory_anchor(new_directory)?,
            new_path,
        )
        .map_err(file_rename_error))
    }

    fn mkdir(
        &self,
        directory: Option<&File>,
        path: &str,
        user: FileUser,
        mode: FileMode,
    ) -> ServiceResult<()> {
        Ok(Resolver::mkdir(
            self,
            user,
            self.directory_anchor(directory)?,
            path,
            mode & FileMode::SUPPORTED,
        )
        .map_err(file_mkdir_error))
    }

    fn mount_in_mem(&self, path: &str, user: FileUser) -> ServiceResult<()> {
        Ok(Resolver::mount_in_mem(self, user, path))
    }

    fn symlink(
        &self,
        target: &str,
        directory: Option<&File>,
        linkpath: &str,
        user: FileUser,
    ) -> ServiceResult<()> {
        Ok(Resolver::symlink(
            self,
            user,
            target,
            self.directory_anchor(directory)?,
            linkpath,
        )
        .map_err(file_symlink_error))
    }

    fn rmdir(&self, directory: Option<&File>, path: &str, user: FileUser) -> ServiceResult<()> {
        Ok(
            Resolver::rmdir(self, user, self.directory_anchor(directory)?, path)
                .map_err(file_rmdir_error),
        )
    }
}

impl<Platform, Backend> OpenFile for ResolverFile<Platform, Backend>
where
    Backend: super::backend::Backend,
    Platform: RawSyncPrimitivesProvider,
{
    fn read(&self, output: &mut dyn ReadBuffer, offset: Option<u64>) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, output.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let entry = self.entry.read();
        let nonblocking = entry.is_nonblocking();
        let read = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.resolver
                .read_without_position_update(&entry, output, offset)
                .map(|(read, _)| read)
        } else {
            drop(entry);
            let mut entry = self.entry.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.resolver.read(&mut entry, output, offset)
        };
        let read = match read {
            Ok(read) => read,
            Err(ReadError::WouldBlock) => return Err(BrokerError::would_block(nonblocking)),
            Err(ReadError::Broker(error)) => return Err(error),
            Err(error) => return Ok(Err(file_read_error(error))),
        };
        if read > output.len() {
            return Err(BrokerError::Internal);
        }
        Ok(Ok(read))
    }

    fn write(&self, input: &dyn WriteBuffer, offset: Option<u64>) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, input.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let entry = self.entry.read();
        let nonblocking = entry.is_nonblocking();
        let written = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.resolver
                .write_without_position_update(&entry, input, offset)
                .map(|(written, _)| written)
        } else {
            drop(entry);
            let mut entry = self.entry.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.resolver.write(&mut entry, input, offset)
        };
        let written = match written {
            Ok(written) => written,
            Err(WriteError::WouldBlock) => return Err(BrokerError::would_block(nonblocking)),
            Err(WriteError::Broker(error)) => return Err(error),
            Err(error) => return Ok(Err(file_write_error(error))),
        };
        if written > input.len() {
            return Err(BrokerError::Internal);
        }
        Ok(Ok(written))
    }

    fn seek(&self, offset: i64, whence: FileSeekWhence) -> ServiceResult<u64> {
        let Ok(offset) = isize::try_from(offset) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let entry = self.entry.read();
        let seek = if entry.uses_position() {
            drop(entry);
            let mut entry = self.entry.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.resolver.seek(&mut entry, offset, whence)
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

    fn truncate(&self, length: u64, reset_offset: bool) -> ServiceResult<()> {
        let Ok(length) = usize::try_from(length) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let entry = self.entry.read();
        let truncate = if reset_offset && entry.uses_position() {
            drop(entry);
            let mut entry = self.entry.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.resolver.truncate(&mut entry, length, true)
        } else {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            self.resolver
                .truncate_without_position_update(&entry, length)
        };
        Ok(truncate.map_err(file_truncate_error))
    }

    fn map_shared(&self) -> ServiceResult<SharedMapping> {
        let entry = self.entry.read();
        Ok(self
            .resolver
            .map_shared(&entry)
            .map_err(file_map_shared_error))
    }

    fn lock(self: Arc<Self>, operation: FileLockOperation) -> ServiceResult<()> {
        let entry = self.entry.read();
        if entry.is_path_only() {
            return Ok(Err(FileError::PathOnly));
        }
        let owner = Arc::downgrade(&self);
        Ok(self
            .resolver
            .lock(&entry, owner, operation)?
            .map_err(file_status_error))
    }

    fn read_directory(&self) -> ServiceResult<Vec<FileDirectoryEntry>> {
        let entry = self.entry.read();
        if entry.is_path_only() {
            return Ok(Err(FileError::AccessNotAllowed));
        }
        if !entry.allows_read() {
            return Ok(Err(FileError::NotForReading));
        }
        let entries = match self.resolver.read_dir(&entry) {
            Ok(entries) => entries,
            Err(error) => return Ok(Err(file_read_directory_error(error))),
        };
        Ok(Ok(entries))
    }

    fn handle_status(&self) -> ServiceResult<FileStatus> {
        let entry = self.entry.read();
        let mut status = match self.resolver.handle_status(&entry) {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        mask_status_mode(&mut status);
        Ok(Ok(status))
    }

    fn handle_path(&self) -> ServiceResult<String> {
        let entry = self.entry.read();
        Ok(self.resolver.handle_path(&entry).map_err(file_walk_error))
    }

    fn get_status_flags(&self) -> FileStatusFlags {
        let entry = self.entry.read();
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
        FileStatusFlags { access, flags }
    }

    fn set_status_flags(&self, mask: FileOpenFlags, flags: FileOpenFlags) -> Result<()> {
        let mut entry = self.entry.write();
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

    fn set_times(&self, user: FileUser, times: &SetFileTimes) -> ServiceResult<()> {
        let entry = self.entry.read();
        Ok(self
            .resolver
            .set_times(user, &entry, times)
            .map_err(file_set_times_error))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Opens a path and installs its broker-owned open state in `process`, resolving a relative
/// `path` from `directory`. `directory` must be given exactly when `path` is relative.
///
/// If reads or writes of the file can fail with [`BrokerError::WouldBlock`], the new reference
/// publishes the file's readiness through `readiness_sink`. A file that refers to the opener's
/// controlling terminal refers to the controlling terminal of `process`'s session. Unless `flags`
/// contain [`FileOpenFlags::NO_CONTROLLING_TERMINAL`], opening a terminal for reading makes it the
/// controlling terminal of the session that `process` leads, if that session has none and the
/// terminal controls no other session.
#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per open request field, plus the readiness sink"
)]
pub fn open(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<FileResult<ObjectHandle>> {
    let rights = process.require_object_rights(open_required_rights(access, flags)?)?;
    with_directory(process, directory, path, |directory| {
        let reference = process.reserve_object_reference(rights)?;
        let file = match Arc::clone(&process.fs).open(
            directory,
            path,
            user,
            access,
            flags,
            mode,
            &|| crate::process_group::controlling_terminal(process),
        )? {
            Ok(file) => file,
            Err(error) => return Ok(Err(error)),
        };
        let readiness = file.watch(reference.handle(), readiness_sink)?;
        let terminal = file.terminal.clone().filter(|_| {
            !flags.contains(FileOpenFlags::NO_CONTROLLING_TERMINAL) && readable(access)
        });
        let handle = reference.commit_with_readiness(ObjectEntry::File(file), readiness)?;
        if let Some(terminal) = terminal {
            // The open succeeds whether or not the session acquires the terminal.
            let _ = crate::process_group::acquire(process, &terminal);
        }
        Ok(Ok(handle))
    })
}

fn readable(access: FileAccessMode) -> bool {
    matches!(access, FileAccessMode::ReadOnly | FileAccessMode::ReadWrite)
}

/// Opens `path` for broker-internal use, returning the open file and its
/// status without installing a reference.
///
/// Requires the same rights as [`open`]. Dropping the file can reach the
/// backend, so callers drop it outside their locks.
pub(crate) fn open_without_reference(
    process: &BrokerProcess,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
) -> Result<FileResult<(File, FileStatus)>> {
    process.require_object_rights(open_required_rights(access, flags)?)?;
    if let Err(error) = validate_path(None, path) {
        return Ok(Err(error));
    }
    let file = match Arc::clone(&process.fs).open(None, path, user, access, flags, mode, &|| {
        crate::process_group::controlling_terminal(process)
    })? {
        Ok(file) => file,
        Err(error) => return Ok(Err(error)),
    };
    let status = match file.state.handle_status()? {
        Ok(status) => status,
        Err(error) => return Ok(Err(error)),
    };
    Ok(Ok((file, status)))
}

/// Reads bytes from a broker-owned open file.
///
/// Fails with [`BrokerError::WouldBlock`] while a file that publishes readiness has nothing to
/// read, or with [`BrokerError::NonBlockingWouldBlock`] if the file is also non-blocking.
pub fn read(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut dyn ReadBuffer,
    offset: Option<u64>,
) -> Result<FileResult<usize>> {
    if output.len() > MAX_FILE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let file = file(process, handle, ObjectRights::WAIT)?;
    file.read(output, offset)
}

/// Writes bytes to a broker-owned open file.
///
/// Fails with [`BrokerError::WouldBlock`] while a file that publishes readiness cannot accept
/// bytes, or with [`BrokerError::NonBlockingWouldBlock`] if the file is also non-blocking.
pub fn write(
    process: &BrokerProcess,
    handle: ObjectHandle,
    input: &dyn WriteBuffer,
    offset: Option<u64>,
) -> Result<FileResult<usize>> {
    if input.len() > MAX_FILE_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let file = file(process, handle, ObjectRights::WRITE)?;
    file.write(input, offset)
}

/// Repositions the shared offset of a broker-owned open file.
pub fn seek(
    process: &BrokerProcess,
    handle: ObjectHandle,
    offset: i64,
    whence: FileSeekWhence,
) -> Result<FileResult<u64>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.state.seek(offset, whence)
}

/// Changes the length of a broker-owned open file.
pub fn truncate(
    process: &BrokerProcess,
    handle: ObjectHandle,
    length: u64,
    reset_offset: bool,
) -> Result<FileResult<()>> {
    let file = file(process, handle, ObjectRights::WRITE)?;
    file.state.truncate(length, reset_offset)
}

/// Returns the host shared object holding a broker-owned open file's contents, so that the
/// caller can map the file `MAP_SHARED`, and the ID naming it for futexes.
///
/// Fails with [`FileError::NoSuchDevice`] if the file system cannot share the file's pages.
pub fn map_shared(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<SharedFileMapping>> {
    let file = file(process, handle, ObjectRights::WAIT)?;
    let handle_writable = process
        .authorized_object(handle, ObjectRights::WRITE)
        .is_ok();
    let SharedMapping {
        file: shared,
        writable: file_writable,
    } = match file.state.map_shared()? {
        Ok(mapping) => mapping,
        Err(error) => return Ok(Err(error)),
    };
    let memory_id = shared.memory_id(|| crate::shared_futex::issue_shared_memory_id(process))?;
    Ok(Ok(SharedFileMapping {
        memory_id,
        object: Arc::clone(shared.object()),
        writable: handle_writable && file_writable,
    }))
}

/// Applies an advisory whole-file lock to a broker-owned open file description.
///
/// Conflicts fail with [`BrokerError::NonBlockingWouldBlock`], regardless of the file's status flags.
pub fn lock(
    process: &BrokerProcess,
    handle: ObjectHandle,
    operation: FileLockOperation,
) -> ServiceResult<()> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.state.lock(operation)
}

/// Returns a fresh enumeration of a broker-owned open directory.
pub fn read_directory(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<Vec<FileDirectoryEntry>>> {
    let file = file(process, handle, ObjectRights::WAIT)?;
    file.state.read_directory()
}

/// Returns status for a broker-owned open object.
pub fn handle_status(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<FileStatus>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.state.handle_status()
}

/// Returns the name of an open file; see
/// [`HandleFilePathRequest`](litebox_broker_protocol::fs::HandleFilePathRequest).
pub fn handle_path(process: &BrokerProcess, handle: ObjectHandle) -> Result<FileResult<String>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.state.handle_path()
}

/// Returns whether a broker-owned open object refers to a terminal, which it does exactly when it
/// has a terminal endpoint.
pub fn is_terminal(process: &BrokerProcess, handle: ObjectHandle) -> Result<FileResult<bool>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    Ok(Ok(file.terminal.is_some()))
}

/// Returns the terminal that a broker-owned open object refers to, if any.
pub(crate) fn handle_terminal(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<Option<Arc<dyn TerminalEndpoint>>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    Ok(file.terminal)
}

/// Returns the terminal that a broker-owned open object refers to, if any, and whether the object
/// is open for reading.
pub(crate) fn handle_terminal_access(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<Option<(Arc<dyn TerminalEndpoint>, bool)>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    let Some(terminal) = file.terminal.clone() else {
        return Ok(None);
    };
    let readable = readable(file.get_status_flags().access);
    drop(file);
    Ok(Some((terminal, readable)))
}

/// Controls a shared terminal through any open file handle that refers to it.
///
/// Like Linux, every operation only requires an open handle, not a particular access mode;
/// stricter guest rules belong in the guest's shim. Reports [`FileError::PathOnly`] for a file
/// opened only for path-based operations and [`FileError::NotTerminal`] for any other file that is
/// not a terminal, so a caller can classify a handle with a single request.
pub fn terminal_control(
    process: &BrokerProcess,
    handle: ObjectHandle,
    operation: TerminalOperation,
) -> Result<FileResult<TerminalResponse>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    let Some(terminal) = &file.terminal else {
        let flags = file.get_status_flags().flags;
        return Ok(Err(if flags.contains(FileOpenFlags::PATH) {
            FileError::PathOnly
        } else {
            FileError::NotTerminal
        }));
    };
    terminal.control(operation)
}

/// Returns status for a path, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn path_status(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    user: FileUser,
    follow_symlinks: bool,
) -> Result<FileResult<FileStatus>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    with_directory(process, directory, path, |dir| {
        process.fs.path_status(dir, path, user, follow_symlinks)
    })
}

/// Reads the target of a symbolic link, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn read_link(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    user: FileUser,
) -> Result<FileResult<String>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    with_directory(process, directory, path, |dir| {
        process.fs.read_link(dir, path, user)
    })
}

/// Changes timestamps through an open file or directory, regardless of its access mode.
pub fn set_times(
    process: &BrokerProcess,
    handle: ObjectHandle,
    user: FileUser,
    times: &SetFileTimes,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.state.set_times(user, times)
}

/// Changes mode bits, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn chmod(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_directory(process, directory, path, |dir| {
        process.fs.chmod(dir, path, user, mode)
    })
}

/// Changes ownership, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn chown(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    acting_user: FileUser,
    user: Option<u16>,
    group: Option<u16>,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_directory(process, directory, path, |dir| {
        process.fs.chown(dir, path, acting_user, user, group)
    })
}

/// Removes a file, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn unlink(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_directory(process, directory, path, |dir| {
        process.fs.unlink(dir, path, user)
    })
}

/// Renames a file or directory. Each relative path resolves from its own directory; each path
/// must have a directory exactly when it is relative.
pub fn rename(
    process: &BrokerProcess,
    old_directory: Option<ObjectHandle>,
    old_path: &str,
    new_directory: Option<ObjectHandle>,
    new_path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_directory(process, old_directory, old_path, |old_dir| {
        with_directory(process, new_directory, new_path, |new_dir| {
            process
                .fs
                .rename(old_dir, old_path, new_dir, new_path, user)
        })
    })
}

/// Creates a directory, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn mkdir(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_directory(process, directory, path, |dir| {
        process.fs.mkdir(dir, path, user, mode)
    })
}

/// Mounts a fresh in-memory filesystem on an existing directory at an absolute path.
pub fn mount_in_mem(process: &BrokerProcess, path: &str, user: FileUser) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = validate_path(None, path) {
        return Ok(Err(error));
    }
    process.fs.mount_in_mem(path, user)
}

/// Creates a symbolic link storing `target` without resolving it, resolving a relative
/// `linkpath` from `directory`. `directory` must be given exactly when `linkpath` is relative.
pub fn symlink(
    process: &BrokerProcess,
    target: &str,
    directory: Option<ObjectHandle>,
    linkpath: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_directory(process, directory, linkpath, |dir| {
        process.fs.symlink(target, dir, linkpath, user)
    })
}

/// Removes a directory, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn rmdir(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_directory(process, directory, path, |dir| {
        process.fs.rmdir(dir, path, user)
    })
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

fn validate_path(directory: Option<ObjectHandle>, path: &str) -> FileResult<()> {
    if !path.is_empty()
        && path.starts_with('/') == directory.is_none()
        && !path.as_bytes().contains(&0)
    {
        Ok(())
    } else {
        Err(FileError::InvalidPathname)
    }
}

fn with_directory<T>(
    process: &BrokerProcess,
    directory: Option<ObjectHandle>,
    path: &str,
    operation: impl FnOnce(Option<&File>) -> ServiceResult<T>,
) -> ServiceResult<T> {
    if let Err(error) = validate_path(directory, path) {
        return Ok(Err(error));
    }
    // The operation itself checks process rights. Using an open directory as a starting
    // point needs a live file reference, not a particular file access mode.
    let file = directory
        .map(|handle| {
            file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)
        })
        .transpose()?;
    operation(file.as_ref())
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
        PathError::TooManySymlinks => FileError::TooManySymlinks,
        PathError::NoSuchFileOrDirectory => FileError::NoSuchFileOrDirectory,
        PathError::NoSearchPerms => FileError::NoSearchPermissions,
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
        OpenError::IsDirectory => FileError::IsDirectory,
        OpenError::TruncateError(error) => file_truncate_error(error),
        OpenError::PathError(error) => file_path_error(error),
        OpenError::Io => FileError::Io,
        OpenError::NoSuchDevice => FileError::NoSuchDevice,
        OpenError::NoSpace => FileError::NoSpace,
    }
}

fn file_read_error(error: ReadError) -> FileError {
    match error {
        ReadError::NotAFile => FileError::NotFile,
        ReadError::NotForReading => FileError::NotForReading,
        ReadError::ClosedFd | ReadError::Io | ReadError::WouldBlock | ReadError::Broker(_) => {
            FileError::Io
        }
    }
}

fn file_write_error(error: WriteError) -> FileError {
    match error {
        WriteError::NotAFile => FileError::NotFile,
        WriteError::NotForWriting => FileError::NotForWriting,
        WriteError::NoSpace => FileError::NoSpace,
        WriteError::ClosedFd | WriteError::Io | WriteError::WouldBlock | WriteError::Broker(_) => {
            FileError::Io
        }
    }
}

fn file_seek_error(error: SeekError) -> FileError {
    match error {
        SeekError::NotAFile => FileError::NotFile,
        SeekError::InvalidOffset => FileError::InvalidOffset,
        SeekError::NonSeekable => FileError::NonSeekable,
        SeekError::NotOpenForSeeking => FileError::PathOnly,
        SeekError::ClosedFd | SeekError::Io => FileError::Io,
    }
}

fn file_truncate_error(error: TruncateError) -> FileError {
    match error {
        TruncateError::IsDirectory => FileError::IsDirectory,
        TruncateError::NotForWriting => FileError::NotForWriting,
        TruncateError::NotOpenForWriting => FileError::PathOnly,
        TruncateError::IsTerminalDevice => FileError::IsTerminalDevice,
        TruncateError::Busy => FileError::Busy,
        TruncateError::NoSpace => FileError::NoSpace,
        TruncateError::ClosedFd | TruncateError::Io => FileError::Io,
    }
}

fn file_set_times_error(error: SetTimesError) -> FileError {
    match error {
        SetTimesError::NotTheOwner => FileError::NotOwner,
        SetTimesError::AccessNotAllowed => FileError::AccessNotAllowed,
        SetTimesError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        SetTimesError::NotSupported => FileError::NotSupported,
        SetTimesError::Io => FileError::Io,
        SetTimesError::PathError(error) => file_path_error(error),
    }
}

fn file_map_shared_error(error: MapSharedError) -> FileError {
    match error {
        MapSharedError::IsDirectory => FileError::IsDirectory,
        MapSharedError::NotForReading => FileError::NotForReading,
        MapSharedError::PathOnly => FileError::PathOnly,
        MapSharedError::Unsupported => FileError::NoSuchDevice,
        MapSharedError::NoMemory => FileError::NoSpace,
        MapSharedError::Io => FileError::Io,
    }
}

fn file_chmod_error(error: ChmodError) -> FileError {
    match error {
        ChmodError::NotTheOwner => FileError::NotOwner,
        ChmodError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        ChmodError::PathError(error) => file_path_error(error),
        // Unreachable by path: chmod follows symbolic links.
        ChmodError::IsSymlink | ChmodError::Io => FileError::Io,
    }
}

fn file_chown_error(error: ChownError) -> FileError {
    match error {
        ChownError::NotTheOwner => FileError::NotOwner,
        ChownError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        ChownError::PathError(error) => file_path_error(error),
        // Unreachable by path: chown follows symbolic links.
        ChownError::IsSymlink | ChownError::Io => FileError::Io,
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

fn file_symlink_error(error: SymlinkError) -> FileError {
    match error {
        SymlinkError::NoWritePerms => FileError::NoWritePermissions,
        SymlinkError::AlreadyExists => FileError::AlreadyExists,
        SymlinkError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        SymlinkError::NotSupported => FileError::NotSupported,
        SymlinkError::PathError(error) => file_path_error(error),
        SymlinkError::Io => FileError::Io,
    }
}

fn file_rename_error(error: RenameError) -> FileError {
    match error {
        RenameError::NoWritePerms => FileError::NoWritePermissions,
        RenameError::Busy => FileError::Busy,
        RenameError::CrossDevice => FileError::CrossDevice,
        RenameError::InvalidArgument => FileError::InvalidArgument,
        RenameError::IsADirectory => FileError::IsDirectory,
        RenameError::NotADirectory => FileError::NotDirectory,
        RenameError::NotEmpty => FileError::NotEmpty,
        RenameError::ReadOnlyFileSystem => FileError::ReadOnlyFs,
        RenameError::Io => FileError::Io,
        RenameError::PathError(error) => file_path_error(error),
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
        ReadDirError::Removed => FileError::NoSuchFileOrDirectory,
        ReadDirError::NotOpenForReading => FileError::PathOnly,
        ReadDirError::ClosedFd | ReadDirError::Io => FileError::Io,
    }
}

fn file_status_error(error: FileStatusError) -> FileError {
    match error {
        FileStatusError::PathError(error) => file_path_error(error),
        FileStatusError::ClosedFd | FileStatusError::Io => FileError::Io,
    }
}

pub(super) fn file_walk_error(error: WalkError) -> FileError {
    match error {
        WalkError::PathError(error) => file_path_error(error),
        WalkError::Io => FileError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use litebox_broker_protocol::fs::{FileNodeInfo, FileType};

    #[test]
    fn relative_directory_handles_are_process_scoped() {
        use crate::fs::{in_mem::InMem, inode_allocator::InodeAllocators};
        use crate::readiness::tests::TestReadinessSink;
        use crate::test_platform::TestPlatform;
        use crate::test_support::TestBrokerBuilder;
        use crate::{CallerCredential, PolicyEngine};

        let fs = Resolver::<TestPlatform, _>::new(InMem::<TestPlatform>::new(
            InodeAllocators::new().next(),
        ));
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(fs))
        .build()
        .unwrap();
        let owner = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let sink: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        let user = FileUser::ROOT;
        let anchor = open(
            &owner,
            None,
            "/",
            user,
            FileAccessMode::ReadOnly,
            FileOpenFlags::PATH,
            FileMode::default(),
            &sink,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            mkdir(&other, Some(anchor), "old", user, FileMode::RWXU),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            mkdir(&owner, Some(anchor), "old", user, FileMode::RWXU),
            Ok(Ok(()))
        );
        assert_eq!(
            rename(&owner, Some(anchor), "old", Some(anchor), "new", user),
            Ok(Ok(()))
        );
        assert_eq!(
            path_status(&owner, Some(anchor), "new", user, true)
                .unwrap()
                .unwrap()
                .node_info,
            path_status(&owner, None, "/new", user, true)
                .unwrap()
                .unwrap()
                .node_info
        );
        let regular = open(
            &owner,
            Some(anchor),
            "file",
            user,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            FileMode::RWXU,
            &sink,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            path_status(&owner, Some(regular), ".", user, true),
            Ok(Err(FileError::ComponentNotDirectory))
        );
        owner.close_object_reference(regular).unwrap();

        for (dir, path) in [
            (Some(anchor), "/new"),
            (None, "new"),
            (Some(anchor), ""),
            (Some(anchor), "bad\0path"),
        ] {
            assert_eq!(
                path_status(&owner, dir, path, user, true),
                Ok(Err(FileError::InvalidPathname))
            );
            // Each side of a rename is checked against its own directory.
            assert_eq!(
                rename(&owner, Some(anchor), "new", dir, path, user),
                Ok(Err(FileError::InvalidPathname))
            );
        }
        owner.close_object_reference(anchor).unwrap();
        assert_eq!(
            path_status(&owner, Some(anchor), "new", user, true),
            Err(BrokerError::UnknownObject)
        );
    }

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
            times: None,
        };
        let mut expected = status;
        expected.mode = FileMode::from_bits(0o644).unwrap();

        mask_status_mode(&mut status);

        assert_eq!(status, expected);
    }
}

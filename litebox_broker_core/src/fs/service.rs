// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative file operations.

use alloc::{string::String, sync::Arc};
use core::any::Any;

use litebox_broker_protocol::fs::{
    DirectoryReadMode, DirectoryTransferError, FileAccessMode, FileError, FileLockOperation,
    FileMode, FileOpenFlags, FileSeekWhence, FileStatus, FileStatusFlags, FileUser,
    MAX_FILE_TRANSFER_SIZE, PathAnchor, ReadDirectoryResponse, SetFileTimes,
    encode_directory_entries_chunk,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::{TerminalOperation, TerminalResponse};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::{RawSyncPrimitivesProvider, RwLock};

use super::OFlags;
use super::backend::Caller;
use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, RmdirError, SeekError, SetTimesError, SymlinkError,
    TruncateError, UnlinkError, WalkError, WriteError,
};
use super::resolver::{Context, DirAnchor, Resolver, ResolverEntry};
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
    fn read_directory(
        &self,
        caller: Caller<'_>,
        output: &mut dyn ReadBuffer,
        mode: DirectoryReadMode,
    ) -> ServiceResult<ReadDirectoryResponse>;
    fn handle_status(&self, caller: Caller<'_>) -> ServiceResult<FileStatus>;
    fn handle_path(&self, caller: Caller<'_>) -> ServiceResult<String>;
    fn get_status_flags(&self) -> FileStatusFlags;
    fn set_status_flags(&self, mask: FileOpenFlags, flags: FileOpenFlags) -> Result<()>;
    fn set_times(&self, context: Context<'_>, times: &SetFileTimes) -> ServiceResult<()>;
    fn as_any(&self) -> &dyn Any;
}

struct ResolverFile<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend> {
    // Shared access lets status and other operations proceed during position-independent I/O.
    entry: RwLock<Platform, ResolverEntry<Backend>>,
    resolver: Arc<Resolver<Platform, Backend>>,
}

mod private {
    use super::{
        Arc, BrokerError, Context, File, FileAccessMode, FileMode, FileOpenFlags, FileStatus,
        ServiceResult, String, TerminalEndpoint,
    };

    pub trait Service: Send + Sync {
        fn check_anchor(&self, _file: &File) -> super::Result<()> {
            Err(BrokerError::InvalidRights)
        }

        /// Copy the mount layout without duplicating the filesystems or their locks.
        fn copy_mount_view(&self) -> crate::Result<Arc<dyn super::FileService>> {
            Err(BrokerError::UnsupportedOperation)
        }

        /// Opens `path`, binding a file that refers to the opener's controlling terminal to
        /// `controlling_terminal()`.
        #[expect(
            clippy::too_many_arguments,
            reason = "one parameter per open request field, plus the terminal binding"
        )]
        fn open(
            self: Arc<Self>,
            _directory: Option<&File>,
            _path: &str,
            _context: Context<'_>,
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
            _context: Context<'_>,
            _follow_symlinks: bool,
        ) -> ServiceResult<FileStatus> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn read_link(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _context: Context<'_>,
        ) -> ServiceResult<String> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chmod(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _context: Context<'_>,
            _mode: FileMode,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn chown(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _context: Context<'_>,
            _user: Option<u16>,
            _group: Option<u16>,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn unlink(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _context: Context<'_>,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn rename(
            &self,
            _old_directory: Option<&File>,
            _old_path: &str,
            _new_directory: Option<&File>,
            _new_path: &str,
            _context: Context<'_>,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn mkdir(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _context: Context<'_>,
            _mode: FileMode,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn mount_in_mem(&self, _path: &str, _context: Context<'_>) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn symlink(
            &self,
            _target: &str,
            _directory: Option<&File>,
            _linkpath: &str,
            _context: Context<'_>,
        ) -> ServiceResult<()> {
            Err(BrokerError::UnsupportedOperation)
        }

        fn rmdir(
            &self,
            _directory: Option<&File>,
            _path: &str,
            _context: Context<'_>,
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
                let entry = state.entry.read();
                if core::ptr::eq(Arc::as_ptr(&state.resolver), self) {
                    return Ok(entry.anchor());
                }
                // A handle transferred from a process with another filesystem names nothing here.
                // One opened through a copy of this service with another mount view is usable
                // only on an object both views contain, and later lookups from it use this
                // service's mounts.
                self.related_view_anchor(&state.resolver, &entry)
                    .ok_or(BrokerError::InvalidRights)
            })
            .transpose()
    }
}

impl<Platform, Backend> private::Service for Resolver<Platform, Backend>
where
    Backend: super::backend::Backend + 'static,
    Platform: RawSyncPrimitivesProvider,
{
    fn check_anchor(&self, file: &File) -> Result<()> {
        self.directory_anchor(Some(file)).map(|_| ())
    }

    fn copy_mount_view(&self) -> Result<Arc<dyn FileService>> {
        let copy = Resolver::copy_mount_view(self).ok_or(BrokerError::UnsupportedOperation)?;
        Ok(Arc::new(copy))
    }

    fn open(
        self: Arc<Self>,
        directory: Option<&File>,
        path: &str,
        context: Context<'_>,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: FileMode,
        controlling_terminal: &dyn Fn() -> Option<Arc<dyn TerminalEndpoint>>,
    ) -> ServiceResult<File> {
        let flags = open_flags(access, flags)?;
        let entry = match self.open_with_controlling_terminal(
            context,
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
        context: Context<'_>,
        follow_symlinks: bool,
    ) -> ServiceResult<FileStatus> {
        let mut status = match Resolver::file_status(
            self,
            context,
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
        context: Context<'_>,
    ) -> ServiceResult<String> {
        Ok(
            Resolver::read_link(self, context, self.directory_anchor(directory)?, path)
                .map_err(file_walk_error),
        )
    }

    fn chmod(
        &self,
        directory: Option<&File>,
        path: &str,
        context: Context<'_>,
        mode: FileMode,
    ) -> ServiceResult<()> {
        Ok(Resolver::chmod(
            self,
            context,
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
        context: Context<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> ServiceResult<()> {
        Ok(Resolver::chown(
            self,
            context,
            self.directory_anchor(directory)?,
            path,
            user,
            group,
        )
        .map_err(file_chown_error))
    }

    fn unlink(
        &self,
        directory: Option<&File>,
        path: &str,
        context: Context<'_>,
    ) -> ServiceResult<()> {
        Ok(
            Resolver::unlink(self, context, self.directory_anchor(directory)?, path)
                .map_err(file_unlink_error),
        )
    }

    fn rename(
        &self,
        old_directory: Option<&File>,
        old_path: &str,
        new_directory: Option<&File>,
        new_path: &str,
        context: Context<'_>,
    ) -> ServiceResult<()> {
        Ok(Resolver::rename(
            self,
            context,
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
        context: Context<'_>,
        mode: FileMode,
    ) -> ServiceResult<()> {
        Ok(Resolver::mkdir(
            self,
            context,
            self.directory_anchor(directory)?,
            path,
            mode & FileMode::SUPPORTED,
        )
        .map_err(file_mkdir_error))
    }

    fn mount_in_mem(&self, path: &str, context: Context<'_>) -> ServiceResult<()> {
        Ok(Resolver::mount_in_mem(self, context, path))
    }

    fn symlink(
        &self,
        target: &str,
        directory: Option<&File>,
        linkpath: &str,
        context: Context<'_>,
    ) -> ServiceResult<()> {
        Ok(Resolver::symlink(
            self,
            context,
            target,
            self.directory_anchor(directory)?,
            linkpath,
        )
        .map_err(file_symlink_error))
    }

    fn rmdir(
        &self,
        directory: Option<&File>,
        path: &str,
        context: Context<'_>,
    ) -> ServiceResult<()> {
        Ok(
            Resolver::rmdir(self, context, self.directory_anchor(directory)?, path)
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
        let seek = if entry.uses_position() || entry.is_directory() {
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

    fn read_directory(
        &self,
        caller: Caller<'_>,
        output: &mut dyn ReadBuffer,
        mode: DirectoryReadMode,
    ) -> ServiceResult<ReadDirectoryResponse> {
        // Cursor reads select, transfer, and advance under the same lock as seek and other
        // cursor reads; listings only need shared access.
        let read_guard;
        let mut write_guard = None;
        let entry = match mode {
            DirectoryReadMode::List(_) => {
                read_guard = self.entry.read();
                &*read_guard
            }
            DirectoryReadMode::Cursor(_) => &**write_guard.insert(self.entry.write()),
        };
        if entry.is_path_only() {
            return Ok(Err(FileError::AccessNotAllowed));
        }
        if !entry.allows_read() {
            return Ok(Err(FileError::NotForReading));
        }
        let mut entries = match self.resolver.read_dir(caller, entry) {
            Ok(entries) => entries,
            Err(error) => return Ok(Err(file_read_directory_error(error))),
        };
        let (start, end, first_index) = match mode {
            DirectoryReadMode::List(index) => {
                let Ok(start) = usize::try_from(index) else {
                    return Ok(Err(FileError::InvalidOffset));
                };
                (start.min(entries.len()), entries.len(), index)
            }
            DirectoryReadMode::Cursor(budget) => {
                // XXX: Page through the backend directly instead of sorting a fresh listing.
                entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
                let start = entry.directory_after_name.as_ref().map_or_else(
                    || entry.position.min(entries.len()),
                    |last| entries.partition_point(|entry| entry.name <= *last),
                );
                let mut remaining = budget.capacity as usize;
                let count = entries[start..]
                    .iter()
                    .take_while(|entry| {
                        let Some(rest) = budget
                            .record_size(entry.name.len())
                            .and_then(|len| remaining.checked_sub(len))
                        else {
                            return false;
                        };
                        remaining = rest;
                        true
                    })
                    .count();
                if count == 0 && start != entries.len() {
                    return Ok(Err(FileError::InvalidArgument));
                }
                (start, start + count, entry.position as u64)
            }
        };
        let (payload, next_index) =
            match encode_directory_entries_chunk(&entries[..end], start, output.len()) {
                Ok(page) => page,
                Err(DirectoryTransferError::OutOfMemory) => return Err(BrokerError::OutOfMemory),
                Err(DirectoryTransferError::Payload(_)) => return Ok(Err(FileError::Io)),
                Err(_) => return Err(BrokerError::Internal),
            };
        let cursor = matches!(mode, DirectoryReadMode::Cursor(_));
        let transferred_end = next_index.map_or(end, |index| usize::try_from(index).unwrap());
        let advance = if cursor && transferred_end > start {
            let Some(position) = entry.position.checked_add(transferred_end - start) else {
                return Ok(Err(FileError::InvalidOffset));
            };
            Some(position)
        } else {
            None
        };
        output.copy_from_slice_at(0, &payload)?;
        if let Some(position) = advance {
            let entry = write_guard
                .as_mut()
                .expect("cursor reads hold the write lock");
            entry.position = position;
            entry.directory_after_name =
                Some(core::mem::take(&mut entries[transferred_end - 1].name));
        }
        Ok(Ok(ReadDirectoryResponse {
            length: u32::try_from(payload.len()).expect("bounded by the shared buffer"),
            first_index,
            next_index: if cursor { None } else { next_index },
        }))
    }

    fn handle_status(&self, caller: Caller<'_>) -> ServiceResult<FileStatus> {
        let entry = self.entry.read();
        let mut status = match self.resolver.handle_status(caller, &entry) {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        mask_status_mode(&mut status);
        Ok(Ok(status))
    }

    fn handle_path(&self, caller: Caller<'_>) -> ServiceResult<String> {
        let entry = self.entry.read();
        Ok(self
            .resolver
            .handle_path(caller, &entry)
            .map_err(file_walk_error))
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

    fn set_times(&self, context: Context<'_>, times: &SetFileTimes) -> ServiceResult<()> {
        let entry = self.entry.read();
        Ok(self
            .resolver
            .set_times(context, &entry, times)
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
#[expect(
    clippy::too_many_arguments,
    reason = "one parameter per open request field, plus the readiness sink"
)]
pub fn open(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<FileResult<ObjectHandle>> {
    let rights = process.require_object_rights(open_required_rights(access, flags)?)?;
    with_path_anchor(process, directory, path, |directory| {
        let reference = process.reserve_object_reference(rights)?;
        let file = match process.file_service()?.open(
            directory,
            path,
            Context::new(user, Caller::new(process)),
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
    anchor: PathAnchor,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
) -> Result<FileResult<(File, FileStatus)>> {
    process.require_object_rights(open_required_rights(access, flags)?)?;
    with_path_anchor(process, anchor, path, |dir| {
        let caller = Caller::new(process);
        let file = match process.file_service()?.open(
            dir,
            path,
            Context::new(user, caller),
            access,
            flags,
            mode,
            &|| crate::process_group::controlling_terminal(process),
        )? {
            Ok(file) => file,
            Err(error) => return Ok(Err(error)),
        };
        let status = match file.state.handle_status(caller)? {
            Ok(status) => status,
            Err(error) => return Ok(Err(error)),
        };
        Ok(Ok((file, status)))
    })
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

/// Transfers a directory page, advancing the broker-owned cursor only in cursor mode.
pub fn read_directory(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut dyn ReadBuffer,
    mode: DirectoryReadMode,
) -> ServiceResult<ReadDirectoryResponse> {
    let file = file(process, handle, ObjectRights::WAIT)?;
    file.state
        .read_directory(Caller::new(process), output, mode)
}

/// Returns status for a broker-owned open object.
pub fn handle_status(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<FileStatus>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.state.handle_status(Caller::new(process))
}

fn with_cwd_process<T>(
    caller: &BrokerProcess,
    pending_child: Option<ProcessId>,
    operation: impl FnOnce(&BrokerProcess) -> T,
) -> Result<T> {
    if let Some(pid) = pending_child {
        let child = caller.with_pending_child(pid, Arc::clone)?;
        Ok(operation(&child))
    } else {
        Ok(operation(caller))
    }
}

/// Resolves `path` and installs the directory without allocating an object reference.
pub fn chdir(
    process: &BrokerProcess,
    pending_child: Option<ProcessId>,
    anchor: PathAnchor,
    path: &str,
    user: FileUser,
) -> ServiceResult<()> {
    with_cwd_process(process, pending_child, |target| {
        let (dir, status) = match open_without_reference(
            process,
            anchor,
            path,
            user,
            FileAccessMode::ReadOnly,
            FileOpenFlags::PATH | FileOpenFlags::DIRECTORY,
            FileMode::empty(),
        )? {
            Ok(dir) => dir,
            Err(error) => return Ok(Err(error)),
        };
        enter_directory(target, pending_child.is_some(), dir, status, user)
    })?
}

/// Installs a directory from a reference owned by the caller.
pub fn fchdir(
    process: &BrokerProcess,
    pending_child: Option<ProcessId>,
    handle: ObjectHandle,
    user: FileUser,
) -> ServiceResult<()> {
    let dir = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    process.file_service()?.check_anchor(&dir)?;
    let status = match dir.state.handle_status(Caller::new(process))? {
        Ok(status) => status,
        Err(error) => return Ok(Err(error)),
    };
    with_cwd_process(process, pending_child, |target| {
        enter_directory(target, pending_child.is_some(), dir, status, user)
    })?
}

fn enter_directory(
    target: &BrokerProcess,
    pending: bool,
    dir: File,
    status: FileStatus,
    user: FileUser,
) -> ServiceResult<()> {
    if status.file_type != super::FileType::Directory {
        return Ok(Err(FileError::ComponentNotDirectory));
    }
    let search = if user.user == status.owner.user {
        FileMode::XUSR
    } else if user.group == status.owner.group {
        FileMode::XGRP
    } else {
        FileMode::XOTH
    };
    if user.user != 0 && !status.mode.contains(search) {
        return Ok(Err(FileError::NoSearchPermissions));
    }
    target.replace_cwd(dir, pending)?;
    Ok(Ok(()))
}

/// Returns the current name of the caller's or its pending child's working directory.
pub fn getcwd(process: &BrokerProcess, pending_child: Option<ProcessId>) -> ServiceResult<String> {
    process.require_object_rights(ObjectRights::WAIT)?;
    with_cwd_process(process, pending_child, |target| {
        cwd_path(target, Caller::new(process))
    })?
}

pub(super) fn cwd_path(process: &BrokerProcess, caller: Caller<'_>) -> ServiceResult<String> {
    let dir = process.fs_state.cwd.lock().clone();
    match dir {
        Some(dir) => dir.state.handle_path(caller),
        None => Ok(Ok(String::from("/"))),
    }
}

/// Reads status of the working directory itself (including a removed directory).
pub fn cwd_status(
    process: &BrokerProcess,
    pending_child: Option<ProcessId>,
) -> ServiceResult<FileStatus> {
    process.require_object_rights(ObjectRights::WAIT)?;
    let dir = with_cwd_process(process, pending_child, |target| {
        target.fs_state.cwd.lock().clone()
    })?;
    let caller = Caller::new(process);
    match dir {
        Some(dir) => dir.state.handle_status(caller),
        None => process.file_service()?.path_status(
            None,
            "/",
            Context::new(FileUser::ROOT, caller),
            true,
        ),
    }
}

/// Changes timestamps of the working directory itself.
pub fn set_cwd_times(
    process: &BrokerProcess,
    pending_child: Option<ProcessId>,
    user: FileUser,
    times: &SetFileTimes,
) -> ServiceResult<()> {
    process.require_object_rights(ObjectRights::WRITE)?;
    let dir = with_cwd_process(process, pending_child, |target| {
        target.fs_state.cwd.lock().clone()
    })?;
    let dir = match dir {
        Some(dir) => dir,
        None => match open_without_reference(
            process,
            PathAnchor::None,
            "/",
            user,
            FileAccessMode::ReadOnly,
            FileOpenFlags::PATH | FileOpenFlags::DIRECTORY,
            FileMode::empty(),
        )? {
            Ok((dir, _)) => dir,
            Err(error) => return Ok(Err(error)),
        },
    };
    dir.state
        .set_times(Context::new(user, Caller::new(process)), times)
}

/// Returns the name of an open file; see
/// [`HandleFilePathRequest`](litebox_broker_protocol::fs::HandleFilePathRequest).
pub fn handle_path(process: &BrokerProcess, handle: ObjectHandle) -> Result<FileResult<String>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.state.handle_path(Caller::new(process))
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
    directory: impl Into<PathAnchor>,
    path: &str,
    user: FileUser,
    follow_symlinks: bool,
) -> Result<FileResult<FileStatus>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    with_path_anchor(process, directory, path, |dir| {
        process.file_service()?.path_status(
            dir,
            path,
            Context::new(user, Caller::new(process)),
            follow_symlinks,
        )
    })
}

/// Reads the target of a symbolic link, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn read_link(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    user: FileUser,
) -> Result<FileResult<String>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    with_path_anchor(process, directory, path, |dir| {
        process
            .file_service()?
            .read_link(dir, path, Context::new(user, Caller::new(process)))
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
    file.state
        .set_times(Context::new(user, Caller::new(process)), times)
}

/// Changes mode bits, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn chmod(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_path_anchor(process, directory, path, |dir| {
        process
            .file_service()?
            .chmod(dir, path, Context::new(user, Caller::new(process)), mode)
    })
}

/// Changes ownership, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn chown(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    acting_user: FileUser,
    user: Option<u16>,
    group: Option<u16>,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_path_anchor(process, directory, path, |dir| {
        process.file_service()?.chown(
            dir,
            path,
            Context::new(acting_user, Caller::new(process)),
            user,
            group,
        )
    })
}

/// Removes a file, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn unlink(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_path_anchor(process, directory, path, |dir| {
        process
            .file_service()?
            .unlink(dir, path, Context::new(user, Caller::new(process)))
    })
}

/// Renames a file or directory. Each relative path resolves from its own directory; each path
/// must have a directory exactly when it is relative.
pub fn rename(
    process: &BrokerProcess,
    old_directory: impl Into<PathAnchor>,
    old_path: &str,
    new_directory: impl Into<PathAnchor>,
    new_path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_path_anchor(process, old_directory, old_path, |old_dir| {
        with_path_anchor(process, new_directory, new_path, |new_dir| {
            process.file_service()?.rename(
                old_dir,
                old_path,
                new_dir,
                new_path,
                Context::new(user, Caller::new(process)),
            )
        })
    })
}

/// Creates a directory, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn mkdir(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_path_anchor(process, directory, path, |dir| {
        process
            .file_service()?
            .mkdir(dir, path, Context::new(user, Caller::new(process)), mode)
    })
}

/// Mounts a fresh in-memory filesystem on an existing directory at an absolute path.
pub fn mount_in_mem(process: &BrokerProcess, path: &str, user: FileUser) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = validate_path(PathAnchor::None, path) {
        return Ok(Err(error));
    }
    process
        .file_service()?
        .mount_in_mem(path, Context::new(user, Caller::new(process)))
}

/// Creates a symbolic link storing `target` without resolving it, resolving a relative
/// `linkpath` from `directory`. `directory` must be given exactly when `linkpath` is relative.
pub fn symlink(
    process: &BrokerProcess,
    target: &str,
    directory: impl Into<PathAnchor>,
    linkpath: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_path_anchor(process, directory, linkpath, |dir| {
        process.file_service()?.symlink(
            target,
            dir,
            linkpath,
            Context::new(user, Caller::new(process)),
        )
    })
}

/// Removes a directory, resolving a relative `path` from `directory`.
/// `directory` must be given exactly when `path` is relative.
pub fn rmdir(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    with_path_anchor(process, directory, path, |dir| {
        process
            .file_service()?
            .rmdir(dir, path, Context::new(user, Caller::new(process)))
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

fn validate_path(directory: PathAnchor, path: &str) -> FileResult<()> {
    if !path.is_empty()
        && path.starts_with('/') == (directory == PathAnchor::None)
        && !path.as_bytes().contains(&0)
    {
        Ok(())
    } else {
        Err(FileError::InvalidPathname)
    }
}

/// Runs `operation` with the open directory a validated `path` is resolved from, if any.
fn with_path_anchor<T>(
    process: &BrokerProcess,
    directory: impl Into<PathAnchor>,
    path: &str,
    operation: impl FnOnce(Option<&File>) -> ServiceResult<T>,
) -> ServiceResult<T> {
    let directory = directory.into();
    if let Err(error) = validate_path(directory, path) {
        return Ok(Err(error));
    }
    let file = match directory {
        PathAnchor::None => None,
        PathAnchor::Object(handle) => Some(file_with_any_rights(
            process,
            handle,
            ObjectRights::WAIT | ObjectRights::WRITE,
        )?),
        PathAnchor::Cwd { pending_child } => with_cwd_process(process, pending_child, |target| {
            target.fs_state.cwd.lock().clone()
        })?,
    };
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
    use crate::CallerCredential;
    use crate::fs::{in_mem::InMem, inode_allocator::InodeAllocators};
    use crate::test_platform::TestPlatform;
    use crate::test_support::TestBroker;
    use core::num::NonZeroU64;
    use litebox_broker_protocol::fs::{FileNodeInfo, FileType};

    /// A broker serving `fs`, one of its processes holding `/` open with `O_PATH`, that handle,
    /// and a readiness sink for further opens.
    fn broker_with_root_anchor(
        fs: Arc<dyn FileService>,
    ) -> (
        TestBroker,
        Arc<BrokerProcess>,
        ObjectHandle,
        Arc<dyn ReadinessSink>,
    ) {
        use crate::PolicyEngine;
        use crate::readiness::tests::TestReadinessSink;
        use crate::test_support::TestBrokerBuilder;

        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(fs)
        .build()
        .unwrap();
        let owner = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let sink: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        let anchor = open(
            &owner,
            None,
            "/",
            FileUser::ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::PATH,
            FileMode::default(),
            &sink,
        )
        .unwrap()
        .unwrap();
        (broker, owner, anchor, sink)
    }

    #[test]
    fn procfs_reports_broker_owned_cwd() {
        use crate::fs::{composer::Composer, procfs::ProcFs};
        use litebox_broker_protocol::fs::decode_directory_entries;
        use litebox_broker_protocol::process::{CpuTime, ProcessExitStatus};

        let fs = Composer::<TestPlatform>::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .mount("/proc", ProcFs::new)
            .build()
            .unwrap();
        let (broker, owner, root, sink) =
            broker_with_root_anchor(Arc::new(Resolver::<TestPlatform, _>::new(fs)));
        owner.complete_start().unwrap();
        let other = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let user = FileUser::ROOT;
        let open_dir = |path| {
            open(
                &owner,
                None,
                path,
                user,
                FileAccessMode::ReadOnly,
                FileOpenFlags::DIRECTORY,
                FileMode::empty(),
                &sink,
            )
            .unwrap()
            .unwrap()
        };
        mkdir(&owner, None, "/old", user, FileMode::RWXU)
            .unwrap()
            .unwrap();
        let cwd = open_dir("/old");
        assert_eq!(
            fchdir(&other, None, cwd, user),
            Err(BrokerError::UnknownObject)
        );
        let regular = open(
            &owner,
            None,
            "/file",
            user,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            FileMode::RWXU,
            &sink,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            fchdir(&owner, None, regular, user),
            Ok(Err(FileError::ComponentNotDirectory))
        );
        fchdir(&owner, None, cwd, user).unwrap().unwrap();
        owner.close_object_reference(cwd).unwrap();
        assert_eq!(
            fchdir(&owner, None, cwd, user),
            Err(BrokerError::UnknownObject)
        );

        let read_cwd = |path| read_link(&owner, None, path, user);
        let self_cwd = "/proc/self/cwd";
        let pid = alloc::format!("/proc/{}", owner.id().0);
        let pid_cwd = alloc::format!("{pid}/cwd");
        assert_eq!(read_cwd(self_cwd), Ok(Ok("/old".into())));
        assert_eq!(read_cwd(&pid_cwd), Ok(Ok("/old".into())));
        assert_eq!(
            read_link(&other, None, &pid_cwd, user),
            Ok(Err(FileError::NoSearchPermissions))
        );
        assert_eq!(
            path_status(&owner, PathAnchor::None, ".", user, true),
            Ok(Err(FileError::InvalidPathname))
        );
        assert_eq!(
            path_status(
                &owner,
                PathAnchor::Cwd {
                    pending_child: None
                },
                ".",
                user,
                true
            ),
            path_status(&owner, PathAnchor::None, "/old", user, true),
        );
        path_status(&owner, Some(root), "old", user, true)
            .unwrap()
            .unwrap();

        let link_status = || {
            path_status(&owner, None, self_cwd, user, false)
                .unwrap()
                .unwrap()
        };
        let link = link_status();
        assert_eq!(link.file_type, FileType::SymbolicLink);
        let mut bytes = [0; 128];
        let page = read_directory(
            &owner,
            open_dir(&pid),
            &mut bytes.as_mut_slice(),
            DirectoryReadMode::List(0),
        )
        .unwrap()
        .unwrap();
        let entries = decode_directory_entries(&bytes[..page.length as usize]).unwrap();
        assert!(entries.iter().any(|entry| entry.name == "cwd"
            && entry.file_type == FileType::SymbolicLink
            && entry.ino_info == Some(link.node_info)));

        rename(&owner, None, "/old", None, "/new", user)
            .unwrap()
            .unwrap();
        assert_eq!(read_cwd(self_cwd), Ok(Ok("/new".into())));
        assert_eq!(
            path_status(&owner, None, self_cwd, user, true),
            path_status(&owner, None, "/new", user, true)
        );
        rmdir(&owner, None, "/new", user).unwrap().unwrap();
        assert_eq!(
            read_cwd(self_cwd),
            Ok(Err(FileError::NoSuchFileOrDirectory))
        );

        assert_eq!(
            getcwd(&owner, None),
            Ok(Err(FileError::NoSuchFileOrDirectory))
        );
        chdir(&owner, None, PathAnchor::None, "/", user)
            .unwrap()
            .unwrap();
        assert_eq!(read_cwd(self_cwd), Ok(Ok("/".into())));
        assert_eq!(link_status().node_info, link.node_info);
        owner
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
        assert!(owner.fs_state.cwd.lock().is_none());
    }

    #[test]
    fn relative_directory_handles_are_process_scoped() {
        let fs = InMem::<TestPlatform>::new(InodeAllocators::new().next());
        let (broker, owner, anchor, sink) =
            broker_with_root_anchor(Arc::new(Resolver::<TestPlatform, _>::new(fs)));
        let other = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let user = FileUser::ROOT;
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
    fn relative_directory_handles_are_file_system_scoped() {
        use crate::fs::read_only::ReadOnly;

        let allocators = InodeAllocators::new();
        let in_mem = || InMem::<TestPlatform>::new(allocators.next());
        let (broker, owner, anchor, _sink) =
            broker_with_root_anchor(Arc::new(Resolver::<TestPlatform, _>::new(in_mem())));
        let user = FileUser::ROOT;

        // Another resolver of the same type fails the identity check; one over another backend
        // fails the downcast.
        let other_file_systems: [Arc<dyn FileService>; 2] = [
            Arc::new(Resolver::<TestPlatform, _>::new(in_mem())),
            Arc::new(Resolver::<TestPlatform, _>::new(ReadOnly::new(in_mem()))),
        ];
        for fs in &other_file_systems {
            let other = broker
                .core
                .create_process(
                    CallerCredential::Unauthenticated,
                    &broker.pid_namespace,
                    fs,
                    &broker.job,
                    broker.host_names.clone(),
                    None,
                )
                .unwrap();
            let transferred = owner
                .duplicate_object_reference_to(anchor, &other, ObjectRights::WAIT)
                .unwrap();
            assert_eq!(
                mkdir(&other, Some(transferred), "x", user, FileMode::RWXU),
                Err(BrokerError::InvalidRights)
            );
            assert_eq!(
                path_status(&other, Some(transferred), ".", user, true),
                Err(BrokerError::InvalidRights)
            );
            assert_eq!(
                path_status(&other, None, "/x", user, true),
                Ok(Err(FileError::NoSuchFileOrDirectory))
            );
        }
        assert_eq!(
            path_status(&owner, None, "/x", user, true),
            Ok(Err(FileError::NoSuchFileOrDirectory))
        );
    }

    #[test]
    fn inherited_relative_handles_walk_the_receivers_mount_view() {
        let fs: Arc<dyn FileService> = Arc::new(Resolver::<TestPlatform, _>::new(
            crate::fs::composer::Composer::<TestPlatform>::builder()
                .mount("/", InMem::<TestPlatform>::new)
                .build()
                .unwrap(),
        ));
        let (broker, owner, root, sink) = broker_with_root_anchor(Arc::clone(&fs));
        let user = FileUser::ROOT;
        assert_eq!(
            mkdir(&owner, None, "/work", user, FileMode::RWXU),
            Ok(Ok(()))
        );
        assert_eq!(mount_in_mem(&owner, "/work", user), Ok(Ok(())));
        assert_eq!(
            mkdir(&owner, None, "/work/m", user, FileMode::RWXU),
            Ok(Ok(()))
        );
        let work = open(
            &owner,
            None,
            "/work",
            user,
            FileAccessMode::ReadOnly,
            FileOpenFlags::PATH,
            FileMode::default(),
            &sink,
        )
        .unwrap()
        .unwrap();
        let file = open(
            &owner,
            None,
            "/work/file",
            user,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            FileMode::RWXU,
            &sink,
        )
        .unwrap()
        .unwrap();
        let child = broker
            .core
            .create_process(
                CallerCredential::Unauthenticated,
                &broker.pid_namespace,
                &fs.copy_mount_view().unwrap(),
                &broker.job,
                broker.host_names.clone(),
                None,
            )
            .unwrap();
        let [child_root, child_work, child_file] = [root, work, file].map(|handle| {
            owner
                .duplicate_object_reference_to(handle, &child, ObjectRights::WAIT)
                .unwrap()
        });
        assert_eq!(mount_in_mem(&child, "/work/m", user), Ok(Ok(())));
        let node = |process: &BrokerProcess, directory, path| {
            path_status(process, directory, path, user, true)
                .unwrap()
                .unwrap()
                .node_info
        };

        // Lookups through inherited handles see the receiver's later mount, not the sender's.
        let private_mount = node(&child, None, "/work/m");
        assert_ne!(node(&owner, Some(work), "m"), private_mount);
        for (directory, path) in [
            (child_work, "m"),
            (child_work, "../work/m"),
            (child_root, "work/m"),
        ] {
            assert_eq!(node(&child, Some(directory), path), private_mount);
        }
        let created = open(
            &child,
            Some(child_work),
            "m/f",
            user,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            FileMode::RWXU,
            &sink,
        )
        .unwrap()
        .unwrap();
        child.close_object_reference(created).unwrap();
        assert!(matches!(
            path_status(&child, None, "/work/m/f", user, true),
            Ok(Ok(_))
        ));
        assert_eq!(
            path_status(&owner, None, "/work/m/f", user, true),
            Ok(Err(FileError::NoSuchFileOrDirectory))
        );

        // The shared mount itself is one filesystem in both views.
        assert_eq!(
            mkdir(&child, Some(child_work), "both", user, FileMode::RWXU),
            Ok(Ok(()))
        );
        assert_eq!(
            node(&owner, None, "/work/both"),
            node(&child, None, "/work/both")
        );
        assert_eq!(
            path_status(&child, Some(child_file), ".", user, true),
            Ok(Err(FileError::ComponentNotDirectory))
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

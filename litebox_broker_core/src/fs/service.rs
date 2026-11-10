// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative file operations.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::any::Any;
use core::marker::PhantomData;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode, FileOpenFlags, FileSeekWhence,
    FileStatus, FileStatusFlags, FileType, FileUser, MAX_FILE_TRANSFER_SIZE, PathContext,
    PathStart,
};
use litebox_broker_protocol::mount::MountInfo;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::{TerminalOperation, TerminalResponse};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::{RawSyncPrimitivesProvider, RwLock};

use super::OFlags;
use super::backend::{Backend, Resolution};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, RmdirError, SeekError, SymlinkError, TruncateError, UnlinkError,
    WalkError, WriteError,
};
use super::in_mem::InMem;
use super::inode_allocator::InodeAllocator;
use super::mount::{HeldLocation, Location, MountId, MountNamespace, absolute_path};
use super::resolver::{Resolver, ResolverEntry, Start, resolve_location};
use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink, ReadinessSource};
use crate::terminal::TerminalEndpoint;
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
///
/// A file keeps the mount it was opened on, and the [`FileOps`] that interpret its state, so it
/// keeps working in any process, whichever file service that process has, and after its mount is
/// detached.
#[derive(Clone)]
pub struct File {
    state: Arc<dyn Any + Send + Sync>,
    ops: Arc<dyn FileOps>,
    /// Where the file was opened, which keeps its mount in use while any reference to the file
    /// lives.
    location: Arc<HeldLocation>,
    /// Readiness of a file whose reads or writes can fail with `WouldBlock`.
    readiness: Option<Arc<dyn ReadinessSource>>,
    terminal: Option<Arc<dyn TerminalEndpoint>>,
}

impl File {
    /// Wrap `entry` with `ops`, which can interpret it.
    fn new(ops: &Arc<dyn FileOps>, entry: ResolverEntry) -> Self {
        Self {
            location: Arc::new(HeldLocation::new(entry.location().clone())),
            readiness: entry.readiness_source(),
            terminal: entry.terminal(),
            state: ops.state(entry),
            ops: Arc::clone(ops),
        }
    }

    fn state<State: Any + Send + Sync>(&self) -> Result<&State> {
        self.state
            .as_ref()
            .downcast_ref()
            .ok_or(BrokerError::Internal)
    }

    /// Where the file was opened: for a directory, anchored on its own handle.
    pub(crate) fn location(&self) -> &Location {
        &self.location
    }

    pub(crate) fn read(
        &self,
        output: &mut dyn ReadBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        self.ops.read(self, output, offset)
    }

    pub(crate) fn write(
        &self,
        input: &dyn WriteBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        self.ops.write(self, input, offset)
    }

    pub(crate) fn seek(&self, offset: i64, whence: FileSeekWhence) -> ServiceResult<u64> {
        self.ops.seek(self, offset, whence)
    }

    pub(crate) fn truncate(&self, length: u64, reset_offset: bool) -> ServiceResult<()> {
        self.ops.truncate(self, length, reset_offset)
    }

    pub(crate) fn read_directory(&self) -> ServiceResult<Vec<FileDirectoryEntry>> {
        self.ops.read_directory(self)
    }

    pub(crate) fn status(&self) -> ServiceResult<FileStatus> {
        self.ops.status(self)
    }

    pub(crate) fn path(&self) -> ServiceResult<String> {
        self.ops.path(self)
    }

    /// Returns the access mode and status flags of the file.
    pub(crate) fn status_flags(&self) -> Result<FileStatusFlags> {
        self.ops.status_flags(self)
    }

    /// Changes the status flags in `mask` of the file to their values in `flags`.
    ///
    /// Fails with [`BrokerError::InvalidRights`] for a file opened only for path-based operations.
    pub(crate) fn set_status_flags(&self, mask: FileOpenFlags, flags: FileOpenFlags) -> Result<()> {
        self.ops.set_status_flags(self, mask, flags)
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

mod private {
    use super::{Arc, MountNamespace};

    pub trait Service: Send + Sync {
        /// The mount namespace that processes created with this service start in, or `None` if
        /// they have no file system, so their path requests fail as unsupported.
        fn initial_namespace(&self) -> Option<Arc<MountNamespace>> {
            None
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

/// Operations on open files, which build and interpret their `Platform`-typed state.
///
/// Implemented by [`PlatformFileOps`], which holds nothing, so mount namespaces and open files can
/// hold it without cycles. The handle operations, behind [`File`]'s methods of the same names, take
/// a file whose state this built.
pub(crate) trait FileOps: Send + Sync {
    /// The state of a file open as `entry`.
    fn state(&self, entry: ResolverEntry) -> Arc<dyn Any + Send + Sync>;

    /// A new, empty in-memory backend whose nodes `allocator` numbers.
    fn new_tmpfs(&self, allocator: InodeAllocator) -> Arc<dyn Backend>;

    fn read(
        &self,
        file: &File,
        output: &mut dyn ReadBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize>;

    fn write(
        &self,
        file: &File,
        input: &dyn WriteBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize>;

    fn seek(&self, file: &File, offset: i64, whence: FileSeekWhence) -> ServiceResult<u64>;

    fn truncate(&self, file: &File, length: u64, reset_offset: bool) -> ServiceResult<()>;

    fn read_directory(&self, file: &File) -> ServiceResult<Vec<FileDirectoryEntry>>;

    fn status(&self, file: &File) -> ServiceResult<FileStatus>;

    fn path(&self, file: &File) -> ServiceResult<String>;

    fn status_flags(&self, file: &File) -> Result<FileStatusFlags>;

    fn set_status_flags(
        &self,
        file: &File,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<()>;
}

/// The [`FileOps`] of files whose state a `Platform` lock guards.
pub(crate) struct PlatformFileOps<Platform>(PhantomData<fn() -> Platform>);

impl<Platform> PlatformFileOps<Platform> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Platform: RawSyncPrimitivesProvider> FileOps for PlatformFileOps<Platform> {
    fn state(&self, entry: ResolverEntry) -> Arc<dyn Any + Send + Sync> {
        Arc::new(RwLock::<Platform, _>::new(entry))
    }

    fn new_tmpfs(&self, allocator: InodeAllocator) -> Arc<dyn Backend> {
        Arc::new(InMem::<Platform>::new(allocator))
    }

    fn read(
        &self,
        file: &File,
        output: &mut dyn ReadBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, output.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = file.state::<RwLock<Platform, ResolverEntry>>()?;
        let entry = state.read();
        let nonblocking = entry.is_nonblocking();
        let read = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry
                .read_without_position_update(output, offset)
                .map(|(read, _)| read)
        } else {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry.read(output, offset)
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

    fn write(
        &self,
        file: &File,
        input: &dyn WriteBuffer,
        offset: Option<u64>,
    ) -> ServiceResult<usize> {
        let Ok(offset) = checked_offset(offset, input.len()) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = file.state::<RwLock<Platform, ResolverEntry>>()?;
        let entry = state.read();
        let nonblocking = entry.is_nonblocking();
        let written = if offset.is_some() || !entry.uses_position() {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry
                .write_without_position_update(input, offset)
                .map(|(written, _)| written)
        } else {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry.write(input, offset)
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

    fn seek(&self, file: &File, offset: i64, whence: FileSeekWhence) -> ServiceResult<u64> {
        let Ok(offset) = isize::try_from(offset) else {
            return Ok(Err(FileError::InvalidOffset));
        };
        let state = file.state::<RwLock<Platform, ResolverEntry>>()?;
        let entry = state.read();
        let seek = if entry.uses_position() {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry.seek(offset, whence)
        } else {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry.seek_without_position_update()
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
        let state = file.state::<RwLock<Platform, ResolverEntry>>()?;
        let entry = state.read();
        let truncate = if reset_offset && entry.uses_position() {
            drop(entry);
            let mut entry = state.write();
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry.truncate(length, true)
        } else {
            if entry.is_path_only() {
                return Ok(Err(FileError::AccessNotAllowed));
            }
            entry.truncate_without_position_update(length)
        };
        Ok(truncate.map_err(file_truncate_error))
    }

    fn read_directory(&self, file: &File) -> ServiceResult<Vec<FileDirectoryEntry>> {
        let entry = file.state::<RwLock<Platform, ResolverEntry>>()?.read();
        if entry.is_path_only() {
            return Ok(Err(FileError::AccessNotAllowed));
        }
        if !entry.allows_read() {
            return Ok(Err(FileError::NotForReading));
        }
        let entries = match entry.read_dir() {
            Ok(entries) => entries,
            Err(error) => return Ok(Err(file_read_directory_error(error))),
        };
        Ok(Ok(entries))
    }

    fn status(&self, file: &File) -> ServiceResult<FileStatus> {
        let entry = file.state::<RwLock<Platform, ResolverEntry>>()?.read();
        let mut status = match entry.status() {
            Ok(status) => status,
            Err(error) => return Ok(Err(file_status_error(error))),
        };
        mask_status_mode(&mut status);
        Ok(Ok(status))
    }

    fn path(&self, file: &File) -> ServiceResult<String> {
        let entry = file.state::<RwLock<Platform, ResolverEntry>>()?.read();
        Ok(Ok(String::from(entry.path())))
    }

    fn status_flags(&self, file: &File) -> Result<FileStatusFlags> {
        let entry = file.state::<RwLock<Platform, ResolverEntry>>()?.read();
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
        let mut entry = file.state::<RwLock<Platform, ResolverEntry>>()?.write();
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
}

impl<Platform> private::Service for Resolver<Platform>
where
    Platform: RawSyncPrimitivesProvider,
{
    fn initial_namespace(&self) -> Option<Arc<MountNamespace>> {
        Some(Arc::clone(self.namespace()))
    }
}

/// The locations a path request resolves from, and the operations of the files it opens.
struct Origin {
    root: Location,
    base: Location,
    ops: Arc<dyn FileOps>,
}

impl Origin {
    /// Where a path request of `process` from `start` resolves: in the context `start` names,
    /// which may be its pending child's, and relative paths from `start`'s base, which is one of
    /// `process`'s own handles, if given. The base may be on a mount of another namespace, or a
    /// detached one.
    ///
    /// Fails with `UnknownObject` if the context's thread or pending child isn't there, and with
    /// `UnsupportedOperation` if the context has no file system.
    fn of(process: &BrokerProcess, start: PathStart) -> Result<Self> {
        let context = process
            .path_context(start.context)?
            .ok_or(BrokerError::UnsupportedOperation)?;
        let snapshot = context.snapshot();
        let base = match start.base {
            Some(handle) => {
                file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?
                    .location()
                    .clone()
            }
            None => snapshot.cwd,
        };
        Ok(Self {
            root: snapshot.root,
            base,
            ops: Arc::clone(snapshot.namespace.ops()),
        })
    }

    fn start(&self) -> Start<'_> {
        Start {
            root: &self.root,
            base: &self.base,
        }
    }
}

/// Opens `path` from `start`, binding a file that refers to the opener's controlling terminal to
/// the controlling terminal of `process`'s session.
fn open_file(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
) -> ServiceResult<File> {
    let origin = Origin::of(process, start)?;
    let flags = open_flags(access, flags)?;
    let entry = match origin.start().open_with_controlling_terminal(
        user,
        path,
        flags,
        mode & FileMode::SUPPORTED,
        &|| crate::process_group::controlling_terminal(process),
    ) {
        Ok(entry) => entry,
        Err(error) => return Ok(Err(file_open_error(error))),
    };
    Ok(Ok(File::new(&origin.ops, entry)))
}

/// Opens `path` from `start` (see [`PathStart`]) and installs its broker-owned open state in
/// `process`.
///
/// If reads or writes of the file can fail with [`BrokerError::WouldBlock`], the new reference
/// publishes the file's readiness through `readiness_sink`. A file that refers to the opener's
/// controlling terminal refers to the controlling terminal of `process`'s session. Unless `flags`
/// contain [`FileOpenFlags::NO_CONTROLLING_TERMINAL`], opening a terminal for reading makes it the
/// controlling terminal of the session that `process` leads, if that session has none and the
/// terminal controls no other session.
#[expect(clippy::too_many_arguments, reason = "mirrors the open request")]
pub fn open(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<FileResult<ObjectHandle>> {
    let rights = process.require_object_rights(open_required_rights(access, flags)?)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    let reference = process.reserve_object_reference(rights)?;
    let file = match open_file(process, start, path, user, access, flags, mode)? {
        Ok(file) => file,
        Err(error) => return Ok(Err(error)),
    };
    let readiness = file.watch(reference.handle(), readiness_sink)?;
    let terminal = file
        .terminal
        .clone()
        .filter(|_| !flags.contains(FileOpenFlags::NO_CONTROLLING_TERMINAL) && readable(access));
    let handle = reference.commit_with_readiness(ObjectEntry::File(file), readiness)?;
    if let Some(terminal) = terminal {
        // The open succeeds whether or not the session acquires the terminal.
        let _ = crate::process_group::acquire(process, &terminal);
    }
    Ok(Ok(handle))
}

fn readable(access: FileAccessMode) -> bool {
    matches!(access, FileAccessMode::ReadOnly | FileAccessMode::ReadWrite)
}

/// Opens `path` from `start` for broker-internal use, returning the open file and its
/// status without installing a reference.
///
/// Requires the same rights as [`open`], and checks the path as it does. Dropping the file can
/// reach the backend, so callers drop it outside their locks.
pub(crate) fn open_without_reference(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    access: FileAccessMode,
    flags: FileOpenFlags,
    mode: FileMode,
) -> Result<FileResult<(File, FileStatus)>> {
    process.require_object_rights(open_required_rights(access, flags)?)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    let file = match open_file(process, start, path, user, access, flags, mode)? {
        Ok(file) => file,
        Err(error) => return Ok(Err(error)),
    };
    let status = match file.status()? {
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
    file.seek(offset, whence)
}

/// Changes the length of a broker-owned open file.
pub fn truncate(
    process: &BrokerProcess,
    handle: ObjectHandle,
    length: u64,
    reset_offset: bool,
) -> Result<FileResult<()>> {
    let file = file(process, handle, ObjectRights::WRITE)?;
    file.truncate(length, reset_offset)
}

/// Returns a fresh enumeration of a broker-owned open directory.
pub fn read_directory(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<Vec<FileDirectoryEntry>>> {
    let file = file(process, handle, ObjectRights::WAIT)?;
    file.read_directory()
}

/// Returns status for a broker-owned open object.
pub fn handle_status(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<FileResult<FileStatus>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.status()
}

/// Returns the absolute path of a broker-owned open object, with symbolic links resolved, as of
/// when it was opened.
pub fn handle_path(process: &BrokerProcess, handle: ObjectHandle) -> Result<FileResult<String>> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    file.path()
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
    let readable = readable(file.status_flags()?.access);
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
        let flags = file.status_flags()?.flags;
        return Ok(Err(if flags.contains(FileOpenFlags::PATH) {
            FileError::PathOnly
        } else {
            FileError::NotTerminal
        }));
    };
    terminal.control(operation)
}

/// The mount that an open file is on, as [`mount_info`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleMount {
    /// The mount's identifier.
    pub id: MountId,
    /// The type, source and options the mount was made with.
    pub info: MountInfo,
    /// Whether writes through the mount fail.
    pub read_only: bool,
    /// Whether the file is the mount's root.
    pub at_root: bool,
}

/// Returns the mount that a broker-owned open file is on, which it keeps after the mount is
/// unmounted or the file is passed to a process in another mount namespace.
pub fn mount_info(process: &BrokerProcess, handle: ObjectHandle) -> Result<HandleMount> {
    let file = file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    let location = file.location();
    let mount = &location.mount;
    Ok(HandleMount {
        id: mount.id(),
        info: mount.info().clone(),
        read_only: mount.is_read_only(),
        at_root: location.path.is_empty(),
    })
}

/// A thread's working directory, as [`working_directory`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkingDirectory {
    /// Its path from the thread's root.
    Reachable(String),
    /// It isn't at or below the thread's root (after a change of root, or an unmount): its path
    /// from the root of its mount tree, which Linux's `getcwd` reports after `(unreachable)`.
    Unreachable(String),
}

/// Returns the working directory of the file-system context `context` (see [`PathStart`]).
///
/// Fails with [`FileError::NoSuchFileOrDirectory`] if the directory's path inside its mount no
/// longer leads to it: Linux's `getcwd` fails so once the directory is removed, and, unlike
/// Linux's, once it or a directory above it in its mount is renamed, as the path is kept rather
/// than the directory's name. Mounts made on or above the directory since don't matter.
///
/// Returns `UnknownObject` if the context's thread or pending child isn't there, and
/// `UnsupportedOperation` if the context has no file system.
pub fn working_directory(
    process: &BrokerProcess,
    context: PathContext,
) -> Result<FileResult<WorkingDirectory>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    let snapshot = process
        .path_context(context)?
        .ok_or(BrokerError::UnsupportedOperation)?
        .snapshot();
    let cwd = &snapshot.cwd;
    if !still_named(cwd) {
        return Ok(Err(FileError::NoSuchFileOrDirectory));
    }
    let tree = cwd.mount.tree();
    if let Some(path) = tree.path_from(&snapshot.root, cwd) {
        return Ok(Ok(WorkingDirectory::Reachable(path)));
    }
    let tree_root = Location::root_of(Arc::clone(tree.root()));
    Ok(Ok(WorkingDirectory::Unreachable(
        tree.path_from(&tree_root, cwd)
            .unwrap_or_else(|| absolute_path(&cwd.path)),
    )))
}

/// Whether `location`'s path inside its mount, walked from the mount's root, still leads to the
/// node it holds (the same device and inode).
fn still_named(location: &Location) -> bool {
    let backend = location.mount.backend();
    let node = |resolution: Resolution<'_>| match resolution {
        Resolution::Found(target) => backend
            .resolved_status(&target)
            .ok()
            .map(|status| (status.node_info.dev, status.node_info.ino)),
        Resolution::MissingFinal { .. } => None,
    };
    let mut walked = Location::root_of(Arc::clone(&location.mount));
    walked.path.clone_from(&location.path);
    match (
        resolve_location(location, node),
        resolve_location(&walked, node),
    ) {
        (Ok(Some(held)), Ok(Some(named))) => held == named,
        _ => false,
    }
}

/// Returns status for `path` from `start` (see [`PathStart`]). With `allow_empty_path`, an empty
/// path names where it starts: the start's base, or else the context's working directory, without
/// a search check, as Linux's `AT_EMPTY_PATH` does.
pub fn path_status(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    follow_symlinks: bool,
    allow_empty_path: bool,
) -> Result<FileResult<FileStatus>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    if let Err(error) = check_path(process, start, path, allow_empty_path)? {
        return Ok(Err(error));
    }
    path_status_at(process, start, path, user, follow_symlinks)
}

/// Returns status for `path` from `start`, after the caller's checks.
pub(crate) fn path_status_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    follow_symlinks: bool,
) -> Result<FileResult<FileStatus>> {
    let origin = Origin::of(process, start)?;
    let mut status = match origin.start().file_status(user, path, follow_symlinks) {
        Ok(status) => status,
        Err(error) => return Ok(Err(file_status_error(error))),
    };
    mask_status_mode(&mut status);
    Ok(Ok(status))
}

/// Reads the target of the symbolic link at `path` from `start` (see [`PathStart`]).
pub fn read_link(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<String>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    read_link_at(process, start, path, user)
}

/// Reads the target of the symbolic link at `path` from `start`, after the caller's checks.
pub(crate) fn read_link_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<String>> {
    let origin = Origin::of(process, start)?;
    Ok(origin
        .start()
        .read_link(user, path)
        .map_err(file_walk_error))
}

/// Resolves `path` from `start` (see [`PathStart`]) to its physical location from the root,
/// following symbolic links.
pub fn resolve_path(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<String>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    resolve_path_at(process, start, path, user)
}

/// Resolves `path` from `start` to its physical location from the root, following symbolic
/// links, after the caller's checks.
pub(crate) fn resolve_path_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<String>> {
    let origin = Origin::of(process, start)?;
    Ok(origin
        .start()
        .resolve_following_symlinks(user, path)
        .map_err(file_walk_error))
}

/// Changes mode bits for `path` from `start` (see [`PathStart`]).
pub fn chmod(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    chmod_at(process, start, path, user, mode)
}

/// Changes mode bits for `path` from `start`, after the caller's checks.
pub(crate) fn chmod_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    let origin = Origin::of(process, start)?;
    Ok(origin
        .start()
        .chmod(user, path, mode & FileMode::SUPPORTED)
        .map_err(file_chmod_error))
}

/// Changes ownership for `path` from `start` (see [`PathStart`]).
pub fn chown(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    acting_user: FileUser,
    user: Option<u16>,
    group: Option<u16>,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    chown_at(process, start, path, acting_user, user, group)
}

/// Changes ownership for `path` from `start`, after the caller's checks.
pub(crate) fn chown_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    acting_user: FileUser,
    user: Option<u16>,
    group: Option<u16>,
) -> Result<FileResult<()>> {
    let origin = Origin::of(process, start)?;
    Ok(origin
        .start()
        .chown(acting_user, path, user, group)
        .map_err(file_chown_error))
}

/// Removes a file at `path` from `start` (see [`PathStart`]).
pub fn unlink(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    unlink_at(process, start, path, user)
}

/// Removes a file at `path` from `start`, after the caller's checks.
pub(crate) fn unlink_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    let origin = Origin::of(process, start)?;
    Ok(origin.start().unlink(user, path).map_err(file_unlink_error))
}

/// Renames a file or directory from `old_path` from `old_start` to `new_path` from `new_start`
/// (see [`PathStart`]).
pub fn rename(
    process: &BrokerProcess,
    old_start: PathStart,
    old_path: &str,
    new_start: PathStart,
    new_path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    for (start, path) in [(old_start, old_path), (new_start, new_path)] {
        if let Err(error) = check_path(process, start, path, false)? {
            return Ok(Err(error));
        }
    }
    rename_at(process, old_start, old_path, new_start, new_path, user)
}

/// Renames a file or directory from `old_path` from `old_start` to `new_path` from `new_start`,
/// after the caller's checks.
pub(crate) fn rename_at(
    process: &BrokerProcess,
    old_start: PathStart,
    old_path: &str,
    new_start: PathStart,
    new_path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    let old = Origin::of(process, old_start)?;
    let new = Origin::of(process, new_start)?;
    Ok(
        Start::rename(user, old.start(), old_path, new.start(), new_path)
            .map_err(file_rename_error),
    )
}

/// Creates a directory at `path` from `start` (see [`PathStart`]).
pub fn mkdir(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    mkdir_at(process, start, path, user, mode)
}

/// Creates a directory at `path` from `start`, after the caller's checks.
pub(crate) fn mkdir_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
    mode: FileMode,
) -> Result<FileResult<()>> {
    let origin = Origin::of(process, start)?;
    Ok(origin
        .start()
        .mkdir(user, path, mode & FileMode::SUPPORTED)
        .map_err(file_mkdir_error))
}

/// Creates a symbolic link at `linkpath` from `start` (see [`PathStart`]), storing `target`
/// without resolving it.
pub fn symlink(
    process: &BrokerProcess,
    target: &str,
    start: PathStart,
    linkpath: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = check_path(process, start, linkpath, false)? {
        return Ok(Err(error));
    }
    symlink_at(process, start, target, linkpath, user)
}

/// Creates a symbolic link at `linkpath` from `start`, storing `target` without resolving it,
/// after the caller's checks.
pub(crate) fn symlink_at(
    process: &BrokerProcess,
    start: PathStart,
    target: &str,
    linkpath: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    let origin = Origin::of(process, start)?;
    Ok(origin
        .start()
        .symlink(user, target, linkpath)
        .map_err(file_symlink_error))
}

/// Removes a directory at `path` from `start` (see [`PathStart`]).
pub fn rmdir(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    if let Err(error) = check_path(process, start, path, false)? {
        return Ok(Err(error));
    }
    rmdir_at(process, start, path, user)
}

/// Removes a directory at `path` from `start`, after the caller's checks.
pub(crate) fn rmdir_at(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    user: FileUser,
) -> Result<FileResult<()>> {
    let origin = Origin::of(process, start)?;
    Ok(origin.start().rmdir(user, path).map_err(file_rmdir_error))
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

/// Checks a path request's `path` and `start`, in Linux's order, before it resolves.
///
/// - A path with a NUL byte fails with [`FileError::InvalidPathname`].
/// - An empty path fails with [`FileError::NoSuchFileOrDirectory`], unless `allow_empty_path`.
/// - A start's base must be a file `process` holds, or this fails with `InvalidRights` (or
///   `UnknownObject`); for a nonempty relative path it must be a directory, or this fails with
///   [`FileError::NotDirectory`].
/// - A relative path needs a base or a context other than [`PathContext::Process`], or this fails
///   with [`FileError::InvalidPathname`].
pub(crate) fn check_path(
    process: &BrokerProcess,
    start: PathStart,
    path: &str,
    allow_empty_path: bool,
) -> Result<FileResult<()>> {
    if path.as_bytes().contains(&0) {
        return Ok(Err(FileError::InvalidPathname));
    }
    if path.is_empty() && !allow_empty_path {
        return Ok(Err(FileError::NoSuchFileOrDirectory));
    }
    let relative = !path.is_empty() && !path.starts_with('/');
    match start.base {
        Some(handle) => {
            let base =
                file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
            if relative {
                match base.status()? {
                    Ok(status) if status.file_type == FileType::Directory => {}
                    Ok(_) => return Ok(Err(FileError::NotDirectory)),
                    Err(error) => return Ok(Err(error)),
                }
            }
        }
        None if relative && start.context == PathContext::Process => {
            return Ok(Err(FileError::InvalidPathname));
        }
        None => {}
    }
    Ok(Ok(()))
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

pub(crate) fn file_with_any_rights(
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
        TruncateError::ClosedFd | TruncateError::Io => FileError::Io,
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
        UnlinkError::Busy => FileError::Busy,
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

pub(crate) fn file_walk_error(error: WalkError) -> FileError {
    match error {
        WalkError::PathError(error) => file_path_error(error),
        WalkError::Io => FileError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::in_mem::InMem;
    use crate::fs::inode_allocator::InodeAllocator;
    use crate::fs::mount::{Mount, MountRoot};
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_platform::TestPlatform;
    use crate::test_support::{TestBroker, TestBrokerBuilder};
    use crate::{CallerCredential, PolicyEngine};
    use core::num::NonZeroU64;
    use litebox_broker_protocol::fs::{FileNodeInfo, FileType};
    use litebox_broker_protocol::mount::MountInfo;
    use litebox_broker_protocol::process::NamespaceKinds;
    use litebox_broker_protocol::{ProcessId, ThreadId};

    #[test]
    fn files_keep_their_mount_across_file_services_and_detachment() {
        let fs = Arc::new(Resolver::<TestPlatform>::new(InMem::<TestPlatform>::new(
            InodeAllocator::for_device(1),
        )));
        fs.mkdir(FileUser::ROOT, "/mnt", FileMode::RWXU).unwrap();
        let namespace = fs.namespace();
        let mount = namespace.new_mount(
            Arc::new(InMem::<TestPlatform>::new(InodeAllocator::for_device(2))),
            MountRoot::Backend,
            Vec::new(),
            MountInfo::default(),
            None,
        );
        namespace
            .attach(
                &namespace.root().mount,
                alloc::vec![String::from("mnt")],
                Arc::clone(&mount),
            )
            .unwrap();
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::clone(&fs) as Arc<dyn FileService>)
        .build()
        .unwrap();
        // A process with no file service at all.
        let other = TestBroker {
            fs: Arc::new(UnsupportedFileService),
            ..broker.clone()
        };
        let opener = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let user = other
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let readiness: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        let original = open(
            &opener,
            PathStart::PROCESS,
            "/mnt/file",
            FileUser::ROOT,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            FileMode::RWXU,
            &readiness,
        )
        .unwrap()
        .unwrap();
        assert_eq!(mount.users(), 1);
        let handle = opener
            .duplicate_object_reference_to(
                original,
                &user,
                ObjectRights::WAIT | ObjectRights::WRITE,
            )
            .unwrap();
        opener.close_object_reference(original).unwrap();

        assert_eq!(write(&user, handle, b"data", None), Ok(Ok(4)));
        namespace.detach(&mount).unwrap();
        assert_eq!(
            seek(&user, handle, 0, FileSeekWhence::RelativeToBeginning),
            Ok(Ok(0))
        );
        let mut data = [0; 8];
        assert_eq!(read(&user, handle, &mut data, None), Ok(Ok(4)));
        assert_eq!(&data[..4], b"data");
        let status = handle_status(&user, handle).unwrap().unwrap();
        assert_eq!((status.node_info.dev, status.size), (2, 4));
        assert_eq!(
            handle_path(&user, handle),
            Ok(Ok(String::from("/mnt/file")))
        );
        let location = file(&user, handle, ObjectRights::WAIT)
            .unwrap()
            .location()
            .clone();
        assert!(Arc::ptr_eq(&location.mount, &mount));
        assert_eq!(location.path, [String::from("file")]);
        drop(location);
        assert_eq!(mount.users(), 1);
        user.close_object_reference(handle).unwrap();
        assert_eq!(mount.users(), 0);
    }

    /// A broker whose file system has `/file` and `/dir/file`, of different sizes.
    fn broker_with_files() -> TestBroker {
        let fs =
            Resolver::<TestPlatform>::new(InMem::<TestPlatform>::new(InodeAllocator::standalone()));
        fs.mkdir(FileUser::ROOT, "/dir", FileMode::RWXU).unwrap();
        for (path, data) in [("/file", &b"root"[..]), ("/dir/file", b"nested")] {
            let mut file = fs
                .open(
                    FileUser::ROOT,
                    path,
                    super::OFlags::CREAT | super::OFlags::WRONLY,
                    FileMode::RWXU,
                )
                .unwrap();
            fs.write(&mut file, &data, None).unwrap();
        }
        TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_file_service(Arc::new(fs))
        .build()
        .unwrap()
    }

    /// The size of what `path` from `start` names.
    fn size(process: &BrokerProcess, start: PathStart, path: &str) -> Result<FileResult<u64>> {
        Ok(path_status_at(process, start, path, FileUser::ROOT, true)?.map(|status| status.size))
    }

    /// Opens the directory at `path` for path-based operations.
    fn open_dir(process: &BrokerProcess, path: &str) -> ObjectHandle {
        let readiness: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        open(
            process,
            PathStart::PROCESS,
            path,
            FileUser::ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::DIRECTORY | FileOpenFlags::PATH,
            FileMode::empty(),
            &readiness,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn threads_share_a_context_and_children_get_a_copy() {
        let parent = broker_with_files()
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let thread = parent.create_thread().unwrap();
        let context = parent.fs_context(None).unwrap().unwrap();
        assert!(Arc::ptr_eq(
            &context,
            &parent.fs_context(Some(thread)).unwrap().unwrap()
        ));
        assert_eq!(context.threads(), 2);
        let child = parent.create_child().unwrap();
        let child_context = child.fs_context(None).unwrap().unwrap();
        assert!(!Arc::ptr_eq(&context, &child_context));
        assert_eq!(child_context.threads(), 1);

        // Relative paths start at each context's own working directory.
        let dir = open_dir(&parent, "/dir");
        context.set_cwd(
            file(&parent, dir, ObjectRights::WAIT)
                .unwrap()
                .location()
                .clone(),
        );
        assert_eq!(size(&parent, PathStart::default(), "file"), Ok(Ok(6)));
        assert_eq!(size(&child, PathStart::default(), "file"), Ok(Ok(4)));
        assert_eq!(
            resolve_path_at(&parent, PathStart::default(), "..", FileUser::ROOT),
            Ok(Ok(String::from("/")))
        );
    }

    #[test]
    fn relative_paths_resolve_from_a_base_handle() {
        let process = broker_with_files()
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let start = PathStart {
            context: PathContext::Thread(process.initial_thread_id()),
            base: Some(open_dir(&process, "/dir")),
        };
        assert_eq!(size(&process, start, "file"), Ok(Ok(6)));
        assert_eq!(size(&process, start, "../file"), Ok(Ok(4)));
        assert_eq!(size(&process, start, "/file"), Ok(Ok(4)));
        assert_eq!(
            resolve_path_at(&process, start, ".", FileUser::ROOT),
            Ok(Ok(String::from("/dir")))
        );
    }

    #[test]
    fn path_requests_check_their_start_and_path() {
        let process = broker_with_files()
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let thread = PathStart::thread(process.initial_thread_id());
        let node = |user, start, path, allow_empty_path| {
            path_status(&process, start, path, user, true, allow_empty_path)
                .unwrap()
                .map(|status| status.node_info)
        };
        let root = node(FileUser::ROOT, PathStart::PROCESS, "/", false).unwrap();
        assert_eq!(
            node(FileUser::ROOT, thread, "dir\0", false),
            Err(FileError::InvalidPathname)
        );
        assert_eq!(
            node(FileUser::ROOT, thread, "", false),
            Err(FileError::NoSuchFileOrDirectory)
        );
        // Relative paths need a thread's context or a base.
        assert_eq!(
            node(FileUser::ROOT, PathStart::PROCESS, "dir", false),
            Err(FileError::InvalidPathname)
        );
        let readiness: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        let file = open(
            &process,
            thread,
            "file",
            FileUser::ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            FileMode::empty(),
            &readiness,
        )
        .unwrap()
        .unwrap();
        let file = PathStart {
            context: PathContext::Process,
            base: Some(file),
        };
        // A base must be a directory for a nonempty relative path only.
        assert_eq!(
            node(FileUser::ROOT, file, "x", false),
            Err(FileError::NotDirectory)
        );
        assert_eq!(node(FileUser::ROOT, file, "/", false), Ok(root));
        assert_eq!(
            node(FileUser::ROOT, file, "", true),
            node(FileUser::ROOT, PathStart::PROCESS, "/file", false)
        );

        // An empty path names the working directory without a search check, unlike `.`.
        crate::fs::mounting::change_directory(
            &process,
            PathContext::Thread(process.initial_thread_id()),
            FileUser::ROOT,
            crate::fs::mounting::MountPath::path("dir"),
        )
        .unwrap()
        .unwrap();
        let user = FileUser {
            user: 1000,
            group: 1000,
        };
        let dir = node(FileUser::ROOT, PathStart::PROCESS, "/dir", false);
        assert_eq!(node(user, thread, "", true), dir);
        assert_eq!(
            node(user, thread, ".", false),
            Err(FileError::NoSearchPermissions)
        );
    }

    #[test]
    fn a_pending_childs_context_resolves_bases_among_the_callers_handles() {
        let parent = broker_with_files()
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        parent.complete_start().unwrap();
        let identity = parent.allocate_child_process().unwrap();
        let child = PathContext::PendingChild(identity.process_id);
        let dir = open_dir(&parent, "/dir");
        crate::fs::mounting::change_directory(
            &parent,
            child,
            FileUser::ROOT,
            crate::fs::mounting::MountPath::handle(dir),
        )
        .unwrap()
        .unwrap();
        let start = |base| PathStart {
            context: child,
            base,
        };
        assert_eq!(size(&parent, start(None), "file"), Ok(Ok(6)));
        assert_eq!(size(&parent, start(Some(dir)), "../file"), Ok(Ok(4)));
        assert_eq!(
            working_directory(&parent, PathContext::Process),
            Ok(Ok(WorkingDirectory::Reachable(String::from("/"))))
        );
        assert_eq!(
            working_directory(&parent, child),
            Ok(Ok(WorkingDirectory::Reachable(String::from("/dir"))))
        );
        let other = PathContext::PendingChild(ProcessId(identity.process_id.0 + 1));
        assert_eq!(
            working_directory(&parent, other),
            Err(BrokerError::UnknownObject)
        );
        // Once taken, the child is no longer pending, and keeps its working directory.
        let child_process = parent.take_child_process(identity.process_id).unwrap();
        assert_eq!(
            working_directory(&parent, child),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            working_directory(&child_process, PathContext::Process),
            Ok(Ok(WorkingDirectory::Reachable(String::from("/dir"))))
        );
    }

    #[test]
    fn threads_share_or_copy_their_creators_context() {
        let process = broker_with_files()
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let context = |thread| process.fs_context(Some(thread)).unwrap().unwrap();
        let creator = process.create_thread().unwrap();
        process
            .unshare(creator, NamespaceKinds::NONE.with_fs_context())
            .unwrap();
        let sharing = process.create_thread_with(Some(creator), true).unwrap();
        assert!(Arc::ptr_eq(&context(sharing), &context(creator)));
        assert_eq!(context(creator).threads(), 2);
        context(creator).set_cwd(
            file(&process, open_dir(&process, "/dir"), ObjectRights::WAIT)
                .unwrap()
                .location()
                .clone(),
        );
        let copying = process.create_thread_with(Some(creator), false).unwrap();
        assert!(!Arc::ptr_eq(&context(copying), &context(creator)));
        assert_eq!(
            working_directory(&process, PathContext::Thread(copying)),
            Ok(Ok(WorkingDirectory::Reachable(String::from("/dir"))))
        );
        // Without a creator, a thread starts with the default context.
        let default = process.create_thread_with(None, true).unwrap();
        assert!(Arc::ptr_eq(
            &context(default),
            &context(process.initial_thread_id())
        ));
        assert_eq!(
            process.create_thread_with(Some(ThreadId(u32::MAX)), true),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn requests_without_a_thread_outlive_the_initial_thread() {
        let process = broker_with_files()
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let initial = process.initial_thread_id();
        let thread = process.create_thread().unwrap();
        process.exit_thread(initial).unwrap();

        assert_eq!(size(&process, PathStart::default(), "/file"), Ok(Ok(4)));
        let start = PathStart {
            context: PathContext::Thread(thread),
            base: None,
        };
        assert_eq!(size(&process, start, "/dir/file"), Ok(Ok(6)));
        let exited = PathStart {
            context: PathContext::Thread(initial),
            base: None,
        };
        assert_eq!(
            size(&process, exited, "/file"),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(process.fs_context(None).unwrap().unwrap().threads(), 1);
    }

    /// A broker whose file system has a mount made with `info` at `/mnt`, with a directory `dir`
    /// in it.
    fn broker_with_mount(info: MountInfo) -> (TestBroker, Arc<Mount>) {
        let fs =
            Resolver::<TestPlatform>::new(InMem::<TestPlatform>::new(InodeAllocator::standalone()));
        fs.mkdir(FileUser::ROOT, "/mnt", FileMode::RWXU).unwrap();
        let namespace = fs.namespace();
        let mount = namespace.new_mount(
            Arc::new(InMem::<TestPlatform>::new(InodeAllocator::standalone())),
            MountRoot::Backend,
            Vec::new(),
            info,
            None,
        );
        namespace
            .attach(
                &namespace.root().mount,
                alloc::vec![String::from("mnt")],
                Arc::clone(&mount),
            )
            .unwrap();
        fs.mkdir(FileUser::ROOT, "/mnt/dir", FileMode::RWXU)
            .unwrap();
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(fs))
        .build()
        .unwrap();
        (broker, mount)
    }

    #[test]
    fn mount_info_reports_the_mount_of_a_handle() {
        let info = MountInfo {
            fs_type: String::from("tmpfs"),
            source: String::from("none"),
            options: String::from("rw"),
        };
        let (broker, mount) = broker_with_mount(info.clone());
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();

        let root = mount_info(&process, open_dir(&process, "/")).unwrap();
        assert_eq!((&root.info, root.at_root), (&MountInfo::default(), true));
        assert_eq!(
            mount_info(&process, open_dir(&process, "/mnt")),
            Ok(HandleMount {
                id: mount.id(),
                info,
                read_only: false,
                at_root: true,
            })
        );
        let below = mount_info(&process, open_dir(&process, "/mnt/dir")).unwrap();
        assert_eq!((below.id, below.at_root), (mount.id(), false));
        assert_ne!(root.id, mount.id());
    }

    #[test]
    fn working_directory_is_a_path_from_the_root_or_unreachable() {
        let (broker, mount) = broker_with_mount(MountInfo::default());
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            working_directory(&process, PathContext::Process),
            Ok(Ok(WorkingDirectory::Reachable(String::from("/"))))
        );

        let dir = open_dir(&process, "/mnt/dir");
        let cwd = file(&process, dir, ObjectRights::WAIT)
            .unwrap()
            .location()
            .clone();
        process.fs_context(None).unwrap().unwrap().set_cwd(cwd);
        assert_eq!(
            working_directory(&process, PathContext::Thread(process.initial_thread_id())),
            Ok(Ok(WorkingDirectory::Reachable(String::from("/mnt/dir"))))
        );

        // After the mount is detached, the working directory is on it, but not below the root.
        let namespace = process
            .fs_context(None)
            .unwrap()
            .unwrap()
            .snapshot()
            .namespace;
        namespace.detach(&mount).unwrap();
        assert_eq!(
            working_directory(&process, PathContext::Process),
            Ok(Ok(WorkingDirectory::Unreachable(String::from("/dir"))))
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
        };
        let mut expected = status;
        expected.mode = FileMode::from_bits(0o644).unwrap();

        mask_status_mode(&mut status);

        assert_eq!(status, expected);
    }
}

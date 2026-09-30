// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest file operations backed by broker-owned file objects.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode as Mode, FileOpenFlags,
    FileSeekWhence as SeekWhence, FileStatus, FileUser as UserInfo,
};

use litebox_platform::time::TimeProvider;

use crate::broker::error::BrokerControlError;
use crate::broker::{BrokerControl, BrokerPollableRegistry, readiness_events};
use crate::event::observer::Observer;
use crate::event::polling::{Pollee, TryOpError};
use crate::event::wait::{WaitContext, WaitState};
use crate::event::{Events, IOPollable};
use crate::path::Arg;
use crate::{LiteBox, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, IsTerminalError, MkdirError, OpenError,
    PathError, ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError,
    WriteError,
};

impl<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Read from a file descriptor at `offset` into a buffer.
    ///
    /// Waits, uninterruptibly, while the file has nothing to read; see
    /// [`read_file_with_wait`](Self::read_file_with_wait) for interruptible and nonblocking
    /// reads.
    pub fn read_file(
        &self,
        fd: &FileFd,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let file = self.broker_file(fd).ok_or(ReadError::ClosedFd)?;
        let mut read = || read_broker_file(&file, buf, offset);
        match read() {
            Err(TryOpError::TryAgain) => {}
            result => return result.map_err(uninterruptible),
        }
        let wait_state = WaitState::new(self.platform());
        self.wait_on_file(&wait_state.context(), &file, false, Events::IN, read)
            .map_err(uninterruptible)
    }

    /// Read from a file descriptor at `offset` into a buffer, waiting through `cx` while the file
    /// has nothing to read unless `nonblock` is set.
    pub fn read_file_with_wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &FileFd,
        buf: &mut [u8],
        offset: Option<usize>,
        nonblock: bool,
    ) -> Result<usize, TryOpError<ReadError>> {
        let file = self
            .broker_file(fd)
            .ok_or(TryOpError::Other(ReadError::ClosedFd))?;
        self.wait_on_file(cx, &file, nonblock, Events::IN, || {
            read_broker_file(&file, buf, offset)
        })
    }

    /// Write from a buffer to a file descriptor at `offset`.
    ///
    /// Waits, uninterruptibly, while the file cannot accept bytes; see
    /// [`write_file_with_wait`](Self::write_file_with_wait) for interruptible and nonblocking
    /// writes.
    pub fn write_file(
        &self,
        fd: &FileFd,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let file = self.broker_file(fd).ok_or(WriteError::ClosedFd)?;
        let write = || write_broker_file(&file, buf, offset);
        match write() {
            Err(TryOpError::TryAgain) => {}
            result => return result.map_err(uninterruptible),
        }
        let wait_state = WaitState::new(self.platform());
        self.wait_on_file(&wait_state.context(), &file, false, Events::OUT, write)
            .map_err(uninterruptible)
    }

    /// Write from a buffer to a file descriptor at `offset`, waiting through `cx` while the file
    /// cannot accept bytes unless `nonblock` is set.
    pub fn write_file_with_wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &FileFd,
        buf: &[u8],
        offset: Option<usize>,
        nonblock: bool,
    ) -> Result<usize, TryOpError<WriteError>> {
        let file = self
            .broker_file(fd)
            .ok_or(TryOpError::Other(WriteError::ClosedFd))?;
        self.wait_on_file(cx, &file, nonblock, Events::OUT, || {
            write_broker_file(&file, buf, offset)
        })
    }

    /// Returns the readiness of the file in a descriptor `entry` for polling.
    ///
    /// Files that never wait, such as regular files, report [`Events::OUT`].
    pub fn broker_file_pollable<'file>(
        &self,
        entry: &'file DescriptorEntry,
    ) -> impl IOPollable + use<'file, Platform> {
        let file = &*entry.entry;
        BrokerFilePollable {
            file,
            pollee: self.file_pollee(file),
        }
    }

    fn wait_on_file<R, E>(
        &self,
        cx: &WaitContext<'_, Platform>,
        file: &BrokerFile,
        nonblock: bool,
        events: Events,
        try_op: impl FnMut() -> Result<R, TryOpError<E>>,
    ) -> Result<R, TryOpError<E>> {
        cx.wait_on_events(
            nonblock,
            events,
            |observer, filter| {
                self.file_pollee(file).register_observer(observer, filter);
                Ok(())
            },
            try_op,
        )
    }

    /// Returns `file`'s pollee, registering it on first use to receive the file's broker
    /// readiness.
    fn file_pollee<'file>(&self, file: &'file BrokerFile) -> &'file Pollee<Platform> {
        let pollee = file.pollee.call_once(|| {
            let registry = self.broker_pollable_registry();
            let pollee = Arc::new(Pollee::new());
            registry.register_pollable(file.handle, &pollee);
            Box::new(FilePollee {
                registry,
                handle: file.handle,
                pollee,
            })
        });
        &pollee
            .downcast_ref::<FilePollee<Platform>>()
            .expect("a broker file belongs to one LiteBox")
            .pollee
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> LiteBox<Platform> {
    pub(crate) fn broker_file(&self, fd: &FileFd) -> Option<Arc<BrokerFile>> {
        self.descriptor_table()
            .with_entry(fd, |entry| Arc::clone(&entry.entry))
    }

    fn broker_path(context: &Context, path: impl Arg) -> Result<String, PathError> {
        Ok(context.resolve(path)?.to_string())
    }

    /// Opens a file.
    ///
    /// `access` and `flags` use the architecture-independent broker contract.
    /// The `mode` is only significant when creating a file.
    pub fn open_file(
        &self,
        context: &Context,
        path: impl Arg,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: Mode,
    ) -> Result<FileFd, OpenError> {
        let path = Self::broker_path(context, path)?;
        if FileOpenFlags::from_bits(flags.bits()).is_none() {
            return Err(OpenError::AccessNotAllowed);
        }
        let broker = self.broker_control().ok_or(OpenError::Io)?;
        let handle = broker
            .open_file(
                &path,
                context.acting_user(),
                access,
                flags,
                mode & Mode::SUPPORTED,
            )
            .map_err(|_| OpenError::Io)?
            .map_err(open_error)?;
        Ok(self
            .descriptor_table_mut()
            .insert(Arc::new(BrokerFile::new(broker, handle))))
    }

    /// Returns a descriptor for a file this process inherited from its parent
    /// through [`Process::inherit`](crate::process::Process::inherit).
    ///
    /// The descriptor owns `handle`, so callers adopt each handle once and
    /// duplicate the descriptor for every other use.
    pub fn adopt_inherited_file(
        &self,
        handle: ObjectHandle,
    ) -> Result<FileFd, crate::process::ProcessError> {
        let broker = self
            .broker_control()
            .ok_or(crate::process::ProcessError::Unavailable)?;
        Ok(self
            .descriptor_table_mut()
            .insert(Arc::new(BrokerFile::new(broker, handle))))
    }

    /// Close the file at `fd`.
    ///
    /// Future operations on the `fd` will start to return `ClosedFd` errors.
    pub fn close_file(&self, fd: &FileFd) -> Result<(), CloseError> {
        let mut descriptors = self.descriptor_table_mut();
        let removed = descriptors.remove(fd);
        drop(descriptors);
        drop(removed);
        Ok(())
    }

    /// Reposition the read/write file offset.
    pub fn seek_file(
        &self,
        fd: &FileFd,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let file = self.broker_file(fd).ok_or(SeekError::ClosedFd)?;
        let offset = i64::try_from(offset).map_err(|_| SeekError::InvalidOffset)?;
        let offset = file
            .broker
            .seek_file(file.handle, offset, whence)
            .map_err(seek_broker_error)?
            .map_err(seek_error)?;
        usize::try_from(offset).map_err(|_| SeekError::InvalidOffset)
    }

    /// Truncate the file to the specified length.
    pub fn truncate_file(
        &self,
        fd: &FileFd,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let file = self.broker_file(fd).ok_or(TruncateError::ClosedFd)?;
        file.broker
            .truncate_file(
                file.handle,
                u64::try_from(length).map_err(|_| TruncateError::Io)?,
                reset_offset,
            )
            .map_err(truncate_broker_error)?
            .map_err(truncate_error)
    }

    /// Change the permissions of a file.
    pub fn chmod_file(
        &self,
        context: &Context,
        path: impl Arg,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(ChmodError::Io)?
            .chmod_file(&path, context.acting_user(), mode & Mode::SUPPORTED)
            .map_err(|_| ChmodError::Io)?
            .map_err(chmod_error)
    }

    /// Change the owner of a file.
    pub fn chown_file(
        &self,
        context: &Context,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(ChownError::Io)?
            .chown_file(&path, context.acting_user(), user, group)
            .map_err(|_| ChownError::Io)?
            .map_err(chown_error)
    }

    /// Unlink a file.
    pub fn unlink_file(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(UnlinkError::Io)?
            .unlink_file(&path, context.acting_user())
            .map_err(|_| UnlinkError::Io)?
            .map_err(unlink_error)
    }

    /// Create a new directory.
    pub fn mkdir_file(
        &self,
        context: &Context,
        path: impl Arg,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(MkdirError::Io)?
            .mkdir_file(&path, context.acting_user(), mode & Mode::SUPPORTED)
            .map_err(|_| MkdirError::Io)?
            .map_err(mkdir_error)
    }

    /// Remove a directory.
    pub fn rmdir_file(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(RmdirError::Io)?
            .rmdir_file(&path, context.acting_user())
            .map_err(|_| RmdirError::Io)?
            .map_err(rmdir_error)
    }

    /// Read directory entries from a directory file descriptor.
    pub fn read_file_directory(
        &self,
        fd: &FileFd,
    ) -> Result<Vec<FileDirectoryEntry>, ReadDirError> {
        let file = self.broker_file(fd).ok_or(ReadDirError::ClosedFd)?;
        file.broker
            .read_directory(file.handle)
            .map_err(read_directory_broker_error)?
            .map_err(read_dir_error)
    }

    /// Obtain the status of a path.
    pub fn path_file_status(
        &self,
        context: &Context,
        path: impl Arg,
    ) -> Result<FileStatus, FileStatusError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(FileStatusError::Io)?
            .path_file_status(&path, context.acting_user())
            .map_err(|_| FileStatusError::Io)?
            .map_err(file_status_error)
    }

    /// Equivalent to [`Self::path_file_status`], but on an open `fd`.
    pub fn file_status(&self, fd: &FileFd) -> Result<FileStatus, FileStatusError> {
        let file = self.broker_file(fd).ok_or(FileStatusError::ClosedFd)?;
        file.broker
            .handle_file_status(file.handle)
            .map_err(|error| {
                broker_fd_error(
                    error,
                    FileStatusError::ClosedFd,
                    FileStatusError::Io,
                    FileStatusError::Io,
                )
            })?
            .map_err(file_status_error)
    }

    /// Determine whether an open `fd` is connected to a terminal.
    pub fn is_terminal(&self, fd: &FileFd) -> Result<bool, IsTerminalError> {
        let file = self.broker_file(fd).ok_or(IsTerminalError::ClosedFd)?;
        file.broker
            .is_terminal_file(file.handle)
            .map_err(|error| {
                broker_fd_error(
                    error,
                    IsTerminalError::ClosedFd,
                    IsTerminalError::Io,
                    IsTerminalError::Io,
                )
            })?
            .map_err(|_| IsTerminalError::Io)
    }
}

/// Caller-owned filesystem context containing a working directory and acting user.
#[derive(Clone, Debug)]
pub struct Context {
    cwd: Arc<ResolvedPath>,
    user_info: UserInfo,
}

impl Context {
    /// The user that operations on this context act as.
    #[must_use]
    pub fn acting_user(&self) -> UserInfo {
        self.user_info
    }

    /// Set the user that operations on this context act as.
    pub fn set_acting_user(&mut self, user: UserInfo) {
        self.user_info = user;
    }

    /// The current working directory.
    #[must_use]
    pub fn cwd(&self) -> &ResolvedPath {
        &self.cwd
    }

    /// Set the current working directory.
    pub fn set_cwd(&mut self, cwd: ResolvedPath) {
        self.cwd = Arc::new(cwd);
    }

    /// A new default context, anchored at `/` for a non-root user.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cwd: Arc::new(ResolvedPath { components: vec![] }),
            user_info: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }

    /// Resolve `path` against the current context.
    pub fn resolve(&self, path: impl Arg) -> Result<ResolvedPath, PathError> {
        let mut components = if path.as_rust_str()?.starts_with('/') {
            vec![]
        } else {
            self.cwd.components.clone()
        };
        for component in path.components()? {
            match component {
                "" | "." => {}
                ".." => {
                    let _ = components.pop();
                }
                _ => components.push(component.into()),
            }
        }
        Ok(ResolvedPath { components })
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Absolute normalized path, created from [`Context::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPath {
    components: Vec<String>,
}

impl core::fmt::Display for ResolvedPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for component in &self.components {
            write!(formatter, "/{component}")?;
        }
        if self.components.is_empty() {
            formatter.write_str("/")?;
        }
        Ok(())
    }
}

/// Guest-side reference to a broker-owned file and the subsystem type for [`FileFd`].
///
/// The broker object is closed when its last descriptor or in-flight operation releases its
/// reference.
pub struct BrokerFile {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    /// The owning [`LiteBox`]'s [`FilePollee`], created when the file is first waited on or
    /// polled.
    pollee: spin::Once<Box<dyn Any + Send + Sync>>,
}

impl BrokerFile {
    fn new(broker: Arc<dyn BrokerControl>, handle: ObjectHandle) -> Self {
        Self {
            broker,
            handle,
            pollee: spin::Once::new(),
        }
    }

    /// Returns the broker file reference, which identifies its open file description.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }
}

impl Drop for BrokerFile {
    fn drop(&mut self) {
        // Stop receiving the file's readiness before the broker releases its handle.
        drop(core::mem::replace(&mut self.pollee, spin::Once::new()));
        let _ = self.broker.close_object(self.handle);
    }
}

/// Waiters on a broker file, registered to receive the readiness the broker publishes for it.
struct FilePollee<Platform: sync::RawSyncPrimitivesProvider> {
    registry: Arc<BrokerPollableRegistry<Platform>>,
    handle: ObjectHandle,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider> Drop for FilePollee<Platform> {
    fn drop(&mut self) {
        self.registry.unregister_pollable(self.handle);
    }
}

struct BrokerFilePollable<'file, Platform: sync::RawSyncPrimitivesProvider> {
    file: &'file BrokerFile,
    pollee: &'file Pollee<Platform>,
}

impl<Platform> IOPollable for BrokerFilePollable<'_, Platform>
where
    Platform: sync::RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        match self.file.broker.check_readiness(self.file.handle) {
            Ok(readiness) => readiness_events(readiness),
            Err(BrokerControlError::Broker(ErrorCode::InvalidRights)) => Events::OUT,
            Err(_) => Events::ERR,
        }
    }
}

fn read_broker_file(
    file: &BrokerFile,
    buf: &mut [u8],
    offset: Option<usize>,
) -> Result<usize, TryOpError<ReadError>> {
    let offset = offset
        .map(u64::try_from)
        .transpose()
        .map_err(|_| TryOpError::Other(ReadError::Io))?;
    match file.broker.read_file(file.handle, buf, offset) {
        Ok(result) => result.map_err(|error| TryOpError::Other(read_error(error))),
        Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Err(TryOpError::TryAgain),
        Err(error) => Err(TryOpError::Other(read_broker_error(error))),
    }
}

fn write_broker_file(
    file: &BrokerFile,
    buf: &[u8],
    offset: Option<usize>,
) -> Result<usize, TryOpError<WriteError>> {
    let offset = offset
        .map(u64::try_from)
        .transpose()
        .map_err(|_| TryOpError::Other(WriteError::Io))?;
    match file.broker.write_file(file.handle, buf, offset) {
        Ok(result) => result.map_err(|error| TryOpError::Other(write_error(error))),
        Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Err(TryOpError::TryAgain),
        Err(error) => Err(TryOpError::Other(write_broker_error(error))),
    }
}

/// Returns the error that ended an uninterruptible wait without a deadline, which only ends with
/// the operation's own result.
fn uninterruptible<E>(error: TryOpError<E>) -> E {
    match error {
        TryOpError::Other(error) => error,
        TryOpError::TryAgain | TryOpError::WaitError(_) => {
            unreachable!("uninterruptible waits end only with the operation's result")
        }
    }
}

fn broker_fd_error<T>(error: BrokerControlError, closed: T, invalid_rights: T, io: T) -> T {
    match error {
        BrokerControlError::Broker(ErrorCode::UnknownObject) => closed,
        BrokerControlError::Broker(ErrorCode::InvalidRights) => invalid_rights,
        BrokerControlError::AssociationFailed | BrokerControlError::Broker(_) => io,
    }
}

fn read_broker_error(error: BrokerControlError) -> ReadError {
    broker_fd_error(
        error,
        ReadError::ClosedFd,
        ReadError::NotForReading,
        ReadError::Io,
    )
}

fn write_broker_error(error: BrokerControlError) -> WriteError {
    broker_fd_error(
        error,
        WriteError::ClosedFd,
        WriteError::NotForWriting,
        WriteError::Io,
    )
}

fn truncate_broker_error(error: BrokerControlError) -> TruncateError {
    broker_fd_error(
        error,
        TruncateError::ClosedFd,
        TruncateError::NotForWriting,
        TruncateError::Io,
    )
}

fn seek_broker_error(error: BrokerControlError) -> SeekError {
    broker_fd_error(
        error,
        SeekError::ClosedFd,
        SeekError::NotForSeeking,
        SeekError::Io,
    )
}

fn read_directory_broker_error(error: BrokerControlError) -> ReadDirError {
    broker_fd_error(
        error,
        ReadDirError::ClosedFd,
        ReadDirError::NotForReading,
        ReadDirError::Io,
    )
}

// TODO: Define canonical per-operation protocol errors so these conversions can be removed without
// broadening every LiteBox file API to the full set of `FileError` variants.
fn path_error(error: FileError) -> Option<PathError> {
    match error {
        FileError::NoSuchFileOrDirectory => Some(PathError::NoSuchFileOrDirectory),
        FileError::NoSearchPermissions => Some(PathError::NoSearchPerms {
            #[cfg(debug_assertions)]
            dir: String::new(),
            #[cfg(debug_assertions)]
            perms: Mode::empty(),
        }),
        FileError::InvalidPathname => Some(PathError::InvalidPathname),
        FileError::MissingComponent => Some(PathError::MissingComponent),
        FileError::ComponentNotDirectory => Some(PathError::ComponentNotADirectory),
        _ => None,
    }
}

fn open_error(error: FileError) -> OpenError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::AccessNotAllowed => OpenError::AccessNotAllowed,
        FileError::NoWritePermissions => OpenError::NoWritePerms,
        FileError::ReadOnlyFs => OpenError::ReadOnlyFileSystem,
        FileError::AlreadyExists => OpenError::AlreadyExists,
        FileError::IsDirectory => OpenError::TruncateError(TruncateError::IsDirectory),
        FileError::NotForWriting => OpenError::TruncateError(TruncateError::NotForWriting),
        FileError::IsTerminalDevice => OpenError::TruncateError(TruncateError::IsTerminalDevice),
        _ => OpenError::Io,
    }
}

fn read_error(error: FileError) -> ReadError {
    match error {
        FileError::NotFile => ReadError::NotAFile,
        FileError::AccessNotAllowed | FileError::NotForReading => ReadError::NotForReading,
        _ => ReadError::Io,
    }
}

fn write_error(error: FileError) -> WriteError {
    match error {
        FileError::NotFile => WriteError::NotAFile,
        FileError::AccessNotAllowed | FileError::NotForWriting => WriteError::NotForWriting,
        _ => WriteError::Io,
    }
}

fn seek_error(error: FileError) -> SeekError {
    match error {
        FileError::NotFile => SeekError::NotAFile,
        FileError::AccessNotAllowed => SeekError::NotForSeeking,
        FileError::InvalidOffset => SeekError::InvalidOffset,
        FileError::NonSeekable => SeekError::NonSeekable,
        _ => SeekError::Io,
    }
}

fn truncate_error(error: FileError) -> TruncateError {
    match error {
        FileError::IsDirectory => TruncateError::IsDirectory,
        FileError::AccessNotAllowed | FileError::NotForWriting => TruncateError::NotForWriting,
        FileError::IsTerminalDevice => TruncateError::IsTerminalDevice,
        _ => TruncateError::Io,
    }
}

fn chmod_error(error: FileError) -> ChmodError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NotOwner => ChmodError::NotTheOwner,
        FileError::ReadOnlyFs => ChmodError::ReadOnlyFileSystem,
        _ => ChmodError::Io,
    }
}

fn chown_error(error: FileError) -> ChownError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NotOwner => ChownError::NotTheOwner,
        FileError::ReadOnlyFs => ChownError::ReadOnlyFileSystem,
        _ => ChownError::Io,
    }
}

fn unlink_error(error: FileError) -> UnlinkError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NoWritePermissions => UnlinkError::NoWritePerms,
        FileError::IsDirectory => UnlinkError::IsADirectory,
        FileError::ReadOnlyFs => UnlinkError::ReadOnlyFileSystem,
        _ => UnlinkError::Io,
    }
}

fn mkdir_error(error: FileError) -> MkdirError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NoWritePermissions => MkdirError::NoWritePerms,
        FileError::AlreadyExists => MkdirError::AlreadyExists,
        FileError::ReadOnlyFs => MkdirError::ReadOnlyFileSystem,
        _ => MkdirError::Io,
    }
}

fn rmdir_error(error: FileError) -> RmdirError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NoWritePermissions => RmdirError::NoWritePerms,
        FileError::Busy => RmdirError::Busy,
        FileError::NotEmpty => RmdirError::NotEmpty,
        FileError::NotDirectory => RmdirError::NotADirectory,
        FileError::ReadOnlyFs => RmdirError::ReadOnlyFileSystem,
        _ => RmdirError::Io,
    }
}

fn read_dir_error(error: FileError) -> ReadDirError {
    match error {
        FileError::NotDirectory => ReadDirError::NotADirectory,
        FileError::AccessNotAllowed | FileError::NotForReading => ReadDirError::NotForReading,
        _ => ReadDirError::Io,
    }
}

fn file_status_error(error: FileError) -> FileStatusError {
    path_error(error).map_or(FileStatusError::Io, Into::into)
}

crate::fd::enable_fds_for_subsystem! {
    BrokerFile;
    Arc<BrokerFile>;
    -> FileFd;
}

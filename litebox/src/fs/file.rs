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
    FileSeekWhence as SeekWhence, FileStatus, FileStatusFlags, FileUser as UserInfo,
};

use litebox_platform::time::TimeProvider;

use crate::broker::error::BrokerControlError;
use crate::broker::{BrokerControl, BrokerPollableRegistry, readiness_events};
use crate::event::observer::Observer;
use crate::event::polling::{Pollee, TryOpError};
use crate::event::wait::WaitContext;
use crate::event::{Events, IOPollable};
use crate::path::Arg;
use crate::{LiteBox, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, IsTerminalError, MkdirError, OpenError,
    PathError, ReadDirError, ReadError, RmdirError, SeekError, StatusFlagsError, TruncateError,
    UnlinkError, WriteError,
};

impl<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
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
            .map_err(|_| OpenError::Io)??;
        Ok(self
            .descriptor_table_mut()
            .insert(Arc::new(BrokerFile::new(broker, handle))))
    }

    /// Returns a descriptor for a file this process inherited from its parent
    /// through [`PendingChild::inherit`](crate::process::PendingChild::inherit).
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

    /// Read from a file descriptor at `offset` into a buffer.
    ///
    /// While the file has nothing to read, waits through `wait`, or fails with
    /// [`ReadError::WouldBlock`] if `wait` is `None` or the file's status flags include
    /// [`FileOpenFlags::NONBLOCKING`].
    pub fn read_file(
        &self,
        fd: &FileFd,
        buf: &mut [u8],
        offset: Option<usize>,
        wait: Option<&WaitContext<'_, Platform>>,
    ) -> Result<usize, ReadError> {
        let file = self.broker_file(fd).ok_or(ReadError::ClosedFd)?;
        let offset = offset
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ReadError::Io)?;
        self.wait_on_file(wait, &file, Events::IN, || {
            file.broker
                .read_file(file.handle, buf, offset)?
                .map_err(|error| TryOpError::Other(error.into()))
        })
        .map_err(ReadError::from)
    }

    /// Write from a buffer to a file descriptor at `offset`.
    ///
    /// While the file cannot accept bytes, waits through `wait`, or fails with
    /// [`WriteError::WouldBlock`] if `wait` is `None` or the file's status flags include
    /// [`FileOpenFlags::NONBLOCKING`]. Given `wait`, keeps writing until the whole buffer is
    /// written or a failure or interruption follows partial progress, which then returns the bytes
    /// written.
    pub fn write_file(
        &self,
        fd: &FileFd,
        buf: &[u8],
        offset: Option<usize>,
        wait: Option<&WaitContext<'_, Platform>>,
    ) -> Result<usize, WriteError> {
        let file = self.broker_file(fd).ok_or(WriteError::ClosedFd)?;
        let offset = offset
            .map(u64::try_from)
            .transpose()
            .map_err(|_| WriteError::Io)?;
        let mut written = 0;
        loop {
            let rest = &buf[written..];
            let offset = offset.map(|offset| offset.saturating_add(written as u64));
            match self.wait_on_file(wait, &file, Events::OUT, || {
                file.broker
                    .write_file(file.handle, rest, offset)?
                    .map_err(|error| TryOpError::Other(error.into()))
            }) {
                Ok(count) => {
                    written += count;
                    if wait.is_none() || count == 0 || written == buf.len() {
                        return Ok(written);
                    }
                }
                Err(_) if written != 0 => return Ok(written),
                Err(error) => return Err(error.into()),
            }
        }
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
        let offset = file.broker.seek_file(file.handle, offset, whence)??;
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
            )?
            .map_err(TruncateError::from)
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
            .map_err(ChmodError::from)
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
            .map_err(ChownError::from)
    }

    /// Unlink a file.
    pub fn unlink_file(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(UnlinkError::Io)?
            .unlink_file(&path, context.acting_user())
            .map_err(|_| UnlinkError::Io)?
            .map_err(UnlinkError::from)
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
            .map_err(MkdirError::from)
    }

    /// Remove a directory.
    pub fn rmdir_file(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(RmdirError::Io)?
            .rmdir_file(&path, context.acting_user())
            .map_err(|_| RmdirError::Io)?
            .map_err(RmdirError::from)
    }

    /// Read directory entries from a directory file descriptor.
    pub fn read_file_directory(
        &self,
        fd: &FileFd,
    ) -> Result<Vec<FileDirectoryEntry>, ReadDirError> {
        let file = self.broker_file(fd).ok_or(ReadDirError::ClosedFd)?;
        file.broker
            .read_directory(file.handle)?
            .map_err(ReadDirError::from)
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
            .map_err(FileStatusError::from)
    }

    /// Equivalent to [`Self::path_file_status`], but on an open `fd`.
    pub fn file_status(&self, fd: &FileFd) -> Result<FileStatus, FileStatusError> {
        let file = self.broker_file(fd).ok_or(FileStatusError::ClosedFd)?;
        file.broker
            .handle_file_status(file.handle)?
            .map_err(FileStatusError::from)
    }

    /// Determine whether an open `fd` is connected to a terminal.
    pub fn is_terminal(&self, fd: &FileFd) -> Result<bool, IsTerminalError> {
        let file = self.broker_file(fd).ok_or(IsTerminalError::ClosedFd)?;
        file.broker
            .is_terminal_file(file.handle)?
            .map_err(|_| IsTerminalError::Io)
    }

    /// Returns the access mode and status flags of the open file description at `fd`.
    pub fn get_file_status_flags(&self, fd: &FileFd) -> Result<FileStatusFlags, StatusFlagsError> {
        let file = self.broker_file(fd).ok_or(StatusFlagsError::ClosedFd)?;
        Ok(file.broker.get_status_flags(file.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`], of the open file
    /// description at `fd` to their values in `flags`.
    ///
    /// Every descriptor and process sharing the open file description sees the change.
    pub fn set_file_status_flags(
        &self,
        fd: &FileFd,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        let file = self.broker_file(fd).ok_or(StatusFlagsError::ClosedFd)?;
        Ok(file.broker.set_status_flags(file.handle, mask, flags)?)
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

    /// Runs `try_op` once, or, given `wait`, until it stops returning [`TryOpError::TryAgain`],
    /// waiting for `events` on `file` in between.
    fn wait_on_file<R, E>(
        &self,
        wait: Option<&WaitContext<'_, Platform>>,
        file: &BrokerFile,
        events: Events,
        mut try_op: impl FnMut() -> Result<R, TryOpError<E>>,
    ) -> Result<R, TryOpError<E>> {
        let Some(cx) = wait else {
            return try_op();
        };
        cx.wait_on_events(
            false,
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

impl From<BrokerControlError> for TryOpError<ReadError> {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Broker(ErrorCode::WouldBlock) => Self::TryAgain,
            BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock) => {
                Self::Other(ReadError::WouldBlock)
            }
            error => Self::Other(error.into()),
        }
    }
}

impl From<BrokerControlError> for TryOpError<WriteError> {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Broker(ErrorCode::WouldBlock) => Self::TryAgain,
            BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock) => {
                Self::Other(WriteError::WouldBlock)
            }
            error => Self::Other(error.into()),
        }
    }
}

impl From<TryOpError<ReadError>> for ReadError {
    fn from(error: TryOpError<ReadError>) -> Self {
        match error {
            TryOpError::TryAgain => Self::WouldBlock,
            TryOpError::WaitError(error) => Self::WaitError(error),
            TryOpError::Other(error) => error,
        }
    }
}

impl From<TryOpError<WriteError>> for WriteError {
    fn from(error: TryOpError<WriteError>) -> Self {
        match error {
            TryOpError::TryAgain => Self::WouldBlock,
            TryOpError::WaitError(error) => Self::WaitError(error),
            TryOpError::Other(error) => error,
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

impl From<BrokerControlError> for ReadError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForReading, Self::Io)
    }
}

impl From<BrokerControlError> for WriteError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForWriting, Self::Io)
    }
}

impl From<BrokerControlError> for TruncateError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForWriting, Self::Io)
    }
}

impl From<BrokerControlError> for SeekError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForSeeking, Self::Io)
    }
}

impl From<BrokerControlError> for ReadDirError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForReading, Self::Io)
    }
}

impl From<BrokerControlError> for FileStatusError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::Io, Self::Io)
    }
}

impl From<BrokerControlError> for IsTerminalError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::Io, Self::Io)
    }
}

impl From<BrokerControlError> for StatusFlagsError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::PathOnly, Self::Io)
    }
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

impl From<FileError> for OpenError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::AccessNotAllowed => Self::AccessNotAllowed,
            FileError::NoWritePermissions => Self::NoWritePerms,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            FileError::AlreadyExists => Self::AlreadyExists,
            FileError::IsDirectory => Self::TruncateError(TruncateError::IsDirectory),
            FileError::NotForWriting => Self::TruncateError(TruncateError::NotForWriting),
            FileError::IsTerminalDevice => Self::TruncateError(TruncateError::IsTerminalDevice),
            _ => Self::Io,
        }
    }
}

impl From<FileError> for ReadError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::NotFile => Self::NotAFile,
            FileError::AccessNotAllowed | FileError::NotForReading => Self::NotForReading,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for WriteError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::NotFile => Self::NotAFile,
            FileError::AccessNotAllowed | FileError::NotForWriting => Self::NotForWriting,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for SeekError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::NotFile => Self::NotAFile,
            FileError::AccessNotAllowed => Self::NotForSeeking,
            FileError::InvalidOffset => Self::InvalidOffset,
            FileError::NonSeekable => Self::NonSeekable,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for TruncateError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::IsDirectory => Self::IsDirectory,
            FileError::AccessNotAllowed | FileError::NotForWriting => Self::NotForWriting,
            FileError::IsTerminalDevice => Self::IsTerminalDevice,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for ChmodError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NotOwner => Self::NotTheOwner,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for ChownError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NotOwner => Self::NotTheOwner,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for UnlinkError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NoWritePermissions => Self::NoWritePerms,
            FileError::IsDirectory => Self::IsADirectory,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for MkdirError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NoWritePermissions => Self::NoWritePerms,
            FileError::AlreadyExists => Self::AlreadyExists,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for RmdirError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NoWritePermissions => Self::NoWritePerms,
            FileError::Busy => Self::Busy,
            FileError::NotEmpty => Self::NotEmpty,
            FileError::NotDirectory => Self::NotADirectory,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for ReadDirError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::NotDirectory => Self::NotADirectory,
            FileError::AccessNotAllowed | FileError::NotForReading => Self::NotForReading,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for FileStatusError {
    fn from(error: FileError) -> Self {
        path_error(error).map_or(Self::Io, Into::into)
    }
}

crate::fd::enable_fds_for_subsystem! {
    BrokerFile;
    Arc<BrokerFile>;
    -> FileFd;
}

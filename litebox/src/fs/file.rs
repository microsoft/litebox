// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest file operations backed by broker-owned file objects.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileLockOperation, FileMode as Mode,
    FileOpenFlags, FileSeekWhence as SeekWhence, FileStatus, FileStatusFlags, FileUser as UserInfo,
    MAX_FILE_TRANSFER_SIZE, SetFileTimes,
};
use litebox_broker_protocol::terminal::{TerminalOperation, TerminalResponse};

use litebox_platform::time::TimeProvider;

use crate::broker::error::BrokerControlError;
use crate::broker::{BrokerControl, BrokerPollableRegistry, readiness_events};
use crate::event::observer::Observer;
use crate::event::polling::{Pollee, TryOpError};
use crate::event::wait::WaitContext;
use crate::event::{Events, IOPollable};
use crate::{LiteBox, sync};
use litebox_platform::buffer::{Buffer, ReadBuffer, WriteBuffer};

use super::errors::{
    ChmodError, ChownError, FilePathError, FileStatusError, IsTerminalError, LockError, MkdirError,
    OpenError, PathError, ReadDirError, ReadError, RenameError, RmdirError, SeekError,
    SetTimesError, SharedObjectError, StatusFlagsError, SymlinkError, TerminalControlError,
    TruncateError, UnlinkError, WalkError, WriteError,
};

/// A file's host shared object, as returned by [`File::request_shared_object`].
#[derive(Debug)]
pub struct SharedFileObject<Object> {
    /// Names the file's shared memory, the same in every process that maps it, so that futexes
    /// in it span those processes.
    pub memory: litebox_broker_protocol::shared_futex::SharedMemoryId,
    /// The platform's object, which mappings of it keep alive.
    pub object: Object,
    /// Whether the object may be mapped writable, which the broker allows exactly when the file
    /// is open for writing.
    pub may_write: bool,
}

impl<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Opens a file.
    ///
    /// `access` and `flags` use the architecture-independent broker contract.
    /// The `mode` is only significant when creating a file.
    pub fn open_file(
        &self,
        context: &Context,
        path: impl PathArg,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: Mode,
    ) -> Result<File<Platform>, OpenError> {
        let path = path.broker_path(context)?;
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
        Ok(File::new(self, broker, handle))
    }

    /// Returns the file this process inherited from its parent as `handle`
    /// through [`PendingChild::inherit`](crate::process::PendingChild::inherit).
    ///
    /// The file owns `handle`, so callers adopt each handle once and share the
    /// file for every other use.
    pub fn adopt_inherited_file(
        &self,
        handle: ObjectHandle,
    ) -> Result<File<Platform>, crate::process::ProcessError> {
        let broker = self
            .broker_control()
            .ok_or(crate::process::ProcessError::Unavailable)?;
        Ok(File::new(self, broker, handle))
    }

    /// Change the permissions of a file.
    pub fn chmod_file(
        &self,
        context: &Context,
        path: impl PathArg,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let path = path.broker_path(context)?;
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
        path: impl PathArg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = path.broker_path(context)?;
        self.broker_control()
            .ok_or(ChownError::Io)?
            .chown_file(&path, context.acting_user(), user, group)
            .map_err(|_| ChownError::Io)?
            .map_err(ChownError::from)
    }

    /// Create a symbolic link at `linkpath`, storing `target` verbatim.
    ///
    /// Only `linkpath` is resolved against the context's working directory. A relative target is
    /// interpreted relative to the link's parent when the link is subsequently followed.
    pub fn symlink_file(
        &self,
        target: &str,
        context: &Context,
        linkpath: impl PathArg,
    ) -> Result<(), SymlinkError> {
        let linkpath = linkpath.broker_path(context)?;
        self.broker_control()
            .ok_or(SymlinkError::Io)?
            .symlink_file(target, &linkpath, context.acting_user())
            .map_err(|_| SymlinkError::Io)?
            .map_err(SymlinkError::from)
    }

    /// Unlink a file.
    pub fn unlink_file(&self, context: &Context, path: impl PathArg) -> Result<(), UnlinkError> {
        let path = path.broker_path(context)?;
        self.broker_control()
            .ok_or(UnlinkError::Io)?
            .unlink_file(&path, context.acting_user())
            .map_err(|_| UnlinkError::Io)?
            .map_err(UnlinkError::from)
    }

    /// Rename a file or directory, replacing an existing destination when permitted.
    pub fn rename_file(
        &self,
        context: &Context,
        old_path: impl PathArg,
        new_path: impl PathArg,
    ) -> Result<(), RenameError> {
        let old_path = old_path.broker_path(context)?;
        let new_path = new_path.broker_path(context)?;
        self.broker_control()
            .ok_or(RenameError::Io)?
            .rename_file(&old_path, &new_path, context.acting_user())
            .map_err(|_| RenameError::Io)?
            .map_err(RenameError::from)
    }

    /// Create a new directory.
    pub fn mkdir_file(
        &self,
        context: &Context,
        path: impl PathArg,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let path = path.broker_path(context)?;
        self.broker_control()
            .ok_or(MkdirError::Io)?
            .mkdir_file(&path, context.acting_user(), mode & Mode::SUPPORTED)
            .map_err(|_| MkdirError::Io)?
            .map_err(MkdirError::from)
    }

    /// Mount a fresh in-memory filesystem at a directory path.
    pub fn mount_in_mem(&self, context: &Context, path: impl PathArg) -> Result<(), FileError> {
        let path = path.broker_path(context)?;
        self.broker_control()
            .ok_or(FileError::Io)?
            .mount_in_mem(&path, context.acting_user())
            .map_err(|_| FileError::Io)?
    }

    /// Remove a directory.
    pub fn rmdir_file(&self, context: &Context, path: impl PathArg) -> Result<(), RmdirError> {
        let path = path.broker_path(context)?;
        self.broker_control()
            .ok_or(RmdirError::Io)?
            .rmdir_file(&path, context.acting_user())
            .map_err(|_| RmdirError::Io)?
            .map_err(RmdirError::from)
    }

    /// Obtain the status of a path.
    ///
    /// If `follow_symlinks` is false, a final symbolic link is described itself unless the path
    /// ends in a slash.
    pub fn path_file_status(
        &self,
        context: &Context,
        path: impl PathArg,
        follow_symlinks: bool,
    ) -> Result<FileStatus, FileStatusError> {
        let path = path.broker_path(context)?;
        self.broker_control()
            .ok_or(FileStatusError::Io)?
            .path_file_status(&path, context.acting_user(), follow_symlinks)
            .map_err(|_| FileStatusError::Io)?
            .map_err(FileStatusError::from)
    }

    /// Read a symbolic link's stored target, without following the final link.
    pub fn read_link_file(
        &self,
        context: &Context,
        path: impl PathArg,
    ) -> Result<String, WalkError> {
        let path = path.broker_path(context)?;
        self.broker_control()
            .ok_or(WalkError::Io)?
            .read_link_file(&path, context.acting_user())
            .map_err(|_| WalkError::Io)?
            .map_err(WalkError::from)
    }

    /// Resolve a path to its physical location, following symbolic links.
    pub fn resolve_file_path(
        &self,
        context: &Context,
        path: impl PathArg,
    ) -> Result<ResolvedPath, WalkError> {
        let path = path.broker_path(context)?;
        let resolved = self
            .broker_control()
            .ok_or(WalkError::Io)?
            .resolve_file_path(&path, context.acting_user())
            .map_err(|_| WalkError::Io)?
            .map_err(WalkError::from)?;
        Ok(ResolvedPath::from_absolute(resolved))
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
            cwd: Arc::new(ResolvedPath(String::from("/"))),
            user_info: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }

    /// Join a relative path to the working directory without removing dots or trailing slashes.
    /// An absolute path is copied unchanged; an empty path returns the working directory itself.
    #[must_use]
    pub fn joined(&self, path: &str) -> BrokerPath {
        if path.starts_with('/') {
            return BrokerPath(String::from(path));
        }
        // XXX(jayb): cwd is a path snapshot and goes stale if an ancestor is renamed.
        let mut absolute = self.cwd.0.clone();
        if !path.is_empty() {
            if !absolute.ends_with('/') {
                absolute.push('/');
            }
            absolute.push_str(path);
        }
        BrokerPath(absolute)
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// An owned absolute path ready to send to the broker without normalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerPath(String);

impl BrokerPath {
    /// Keep the exact spelling of an absolute path.
    ///
    /// # Panics
    /// Panics if `path` does not start with `/`.
    #[must_use]
    pub fn verbatim(path: String) -> Self {
        assert!(path.starts_with('/'), "broker path must be absolute");
        Self(path)
    }

    /// Borrow the exact path to be sent to the broker.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BrokerPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<BrokerPath> for String {
    fn from(path: BrokerPath) -> Self {
        path.0
    }
}

/// A string to join to the working directory, or a prepared [`BrokerPath`] to use verbatim.
/// Shared references to either are also accepted. This trait is sealed.
pub trait PathArg: sealed::Sealed {}

impl<T: sealed::Sealed + ?Sized> PathArg for T {}

mod sealed {
    use super::{BrokerPath, Context, FileError, String};
    use alloc::borrow::Cow;

    pub trait Sealed: AsRef<str> {
        fn broker_path(&self, context: &Context) -> Result<Cow<'_, str>, FileError> {
            let path = self.as_ref();
            if path.is_empty() {
                Err(FileError::NoSuchFileOrDirectory)
            } else if path.starts_with('/') {
                Ok(Cow::Borrowed(path))
            } else {
                Ok(Cow::Owned(context.joined(path).0))
            }
        }
    }

    impl Sealed for str {}
    impl Sealed for String {}
    impl Sealed for BrokerPath {}
    impl<T: Sealed + ?Sized> Sealed for &T {}
}

/// An absolute physical path obtained from the broker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPath(String);

impl ResolvedPath {
    /// Restore a physical path previously obtained from the broker, e.g. an inherited cwd.
    ///
    /// # Panics
    /// Panics if `path` does not start with `/`.
    #[must_use]
    pub fn from_absolute(path: String) -> Self {
        assert!(path.starts_with('/'), "resolved path must be absolute");
        Self(path)
    }
}

impl core::fmt::Display for ResolvedPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A reference to a broker-owned open file, which closes its handle when
/// dropped.
///
/// The broker owns the open file description, such as its offset and status
/// flags, so every reference to it, in any process, shares them.
pub struct File<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    /// Waiters on the file, registered when the file is first waited on or
    /// polled to receive the readiness the broker publishes for it.
    pollee: spin::Once<Arc<Pollee<Platform>>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> File<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
    ) -> Self {
        Self {
            broker,
            handle,
            pollable_registry: litebox.broker_pollable_registry(),
            pollee: spin::Once::new(),
        }
    }

    /// The broker handle this file owns, which identifies its open file
    /// description.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Reads from the file at `offset`, or at its offset if `offset` is
    /// `None`, into `buf`.
    ///
    /// Reads a chunk at a time until the file runs short or `buf` is full. While the file has
    /// nothing to read, the first chunk waits through `wait`, or fails with
    /// [`ReadError::WouldBlock`] if `wait` is `None` or the file's status flags include
    /// [`FileOpenFlags::NONBLOCKING`]. A failure after partial progress returns the bytes read.
    pub fn read(
        &self,
        mut buf: impl ReadBuffer,
        offset: Option<usize>,
        wait: Option<&WaitContext<'_, Platform>>,
    ) -> Result<usize, ReadError> {
        let offset = offset
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ReadError::Io)?;
        let mut read = 0;
        loop {
            let length = (buf.len() - read).min(MAX_FILE_TRANSFER_SIZE as usize);
            let offset = offset.map(|offset| offset.saturating_add(read as u64));
            let wait = if read == 0 { wait } else { None };
            match self.wait(wait, Events::IN, || {
                self.broker
                    .read_file(
                        self.handle,
                        &mut (&mut buf).sub_buffer(read, length),
                        offset,
                    )?
                    .map_err(|error| TryOpError::Other(error.into()))
            }) {
                Ok(count) => {
                    read += count;
                    if count < length || read == buf.len() {
                        return Ok(read);
                    }
                }
                Err(_) if read != 0 => return Ok(read),
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Writes `buf` to the file at `offset`, or at its offset if `offset` is
    /// `None`.
    ///
    /// Writes a chunk at a time until the file takes a chunk short or the whole buffer is
    /// written. While the file cannot accept bytes, waits through `wait`, or fails with
    /// [`WriteError::WouldBlock`] if `wait` is `None` or the file's status flags include
    /// [`FileOpenFlags::NONBLOCKING`]. Given `wait`, a short chunk only ends the write once the
    /// file takes nothing. A failure or interruption after partial progress returns the bytes
    /// written.
    pub fn write(
        &self,
        buf: impl WriteBuffer,
        offset: Option<usize>,
        wait: Option<&WaitContext<'_, Platform>>,
    ) -> Result<usize, WriteError> {
        let offset = offset
            .map(u64::try_from)
            .transpose()
            .map_err(|_| WriteError::Io)?;
        let mut written = 0;
        loop {
            let length = (buf.len() - written).min(MAX_FILE_TRANSFER_SIZE as usize);
            let offset = offset.map(|offset| offset.saturating_add(written as u64));
            match self.wait(wait, Events::OUT, || {
                self.broker
                    .write_file(self.handle, &(&buf).sub_buffer(written, length), offset)?
                    .map_err(|error| TryOpError::Other(error.into()))
            }) {
                Ok(count) => {
                    written += count;
                    if count == 0 || written == buf.len() || (wait.is_none() && count < length) {
                        return Ok(written);
                    }
                }
                Err(_) if written != 0 => return Ok(written),
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Repositions the file's offset.
    pub fn seek(&self, offset: isize, whence: SeekWhence) -> Result<usize, SeekError> {
        let offset = i64::try_from(offset).map_err(|_| SeekError::InvalidOffset)?;
        let offset = self.broker.seek_file(self.handle, offset, whence)??;
        usize::try_from(offset).map_err(|_| SeekError::InvalidOffset)
    }

    /// Truncates the file to the specified length.
    pub fn truncate(&self, length: usize, reset_offset: bool) -> Result<(), TruncateError> {
        self.broker
            .truncate_file(
                self.handle,
                u64::try_from(length).map_err(|_| TruncateError::Io)?,
                reset_offset,
            )?
            .map_err(TruncateError::from)
    }

    /// Attempts to change the advisory whole-file lock shared by every reference to this open
    /// description, failing with [`LockError::WouldBlock`] on contention.
    pub fn try_lock(&self, operation: FileLockOperation) -> Result<(), LockError> {
        match self.broker.lock_file(self.handle, operation) {
            Ok(result) => result.map_err(LockError::from),
            Err(BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock)) => {
                Err(LockError::WouldBlock)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Asks the broker for the host shared object holding this file's contents, so that every
    /// process mapping it shares its pages. Each call delivers a new handle to the object, which
    /// covers the file's bytes up to `end`.
    ///
    /// Fails with [`SharedObjectError::Unsupported`] if `platform` cannot map shared objects or the
    /// broker cannot share this file's pages with this process.
    pub fn request_shared_object<Provider, const ALIGN: usize>(
        &self,
        platform: &Provider,
        end: u64,
    ) -> Result<SharedFileObject<Provider::SharedObject>, SharedObjectError>
    where
        Provider: crate::platform::SharedObjectProvider<ALIGN>,
    {
        let response = self.broker.map_file(self.handle, end)??;
        // SAFETY: The broker delivered the object under this token before answering, and the
        // token goes nowhere else.
        let object = unsafe { platform.take_shared_object(response.token) }?;
        Ok(SharedFileObject {
            memory: response.memory,
            object,
            may_write: response.writable,
        })
    }

    /// Reads the entries of the directory this file opens.
    pub fn read_directory(&self) -> Result<Vec<FileDirectoryEntry>, ReadDirError> {
        self.broker
            .read_directory(self.handle)?
            .map_err(ReadDirError::from)
    }

    /// Equivalent to [`LiteBox::path_file_status`], but on this open file.
    pub fn status(&self) -> Result<FileStatus, FileStatusError> {
        self.broker
            .handle_file_status(self.handle)?
            .map_err(FileStatusError::from)
    }

    /// Changes this open file's access and modification timestamps as `user`.
    pub fn set_times(&self, user: UserInfo, times: &SetFileTimes) -> Result<(), SetTimesError> {
        self.broker
            .set_file_times(self.handle, user, times)?
            .map_err(SetTimesError::from)
    }

    /// Returns the absolute path of the file, with symbolic links resolved, as of when it was
    /// opened.
    ///
    /// Later renames or removals of the file are not reflected.
    pub fn path(&self) -> Result<String, FilePathError> {
        self.broker
            .handle_file_path(self.handle)?
            .map_err(|_| FilePathError::Io)
    }

    /// Determines whether the file is connected to a terminal.
    pub fn is_terminal(&self) -> Result<bool, IsTerminalError> {
        self.broker
            .is_terminal_file(self.handle)?
            .map_err(|_| IsTerminalError::Io)
    }

    /// Controls the shared terminal, waiting interruptibly for output-draining
    /// operations through `wait`.
    pub fn terminal_control(
        &self,
        operation: TerminalOperation,
        wait: Option<&WaitContext<'_, Platform>>,
    ) -> Result<TerminalResponse, TerminalControlError> {
        self.wait(wait, Events::OUT, || {
            self.broker
                .terminal_control(self.handle, operation)?
                .map_err(|error| TryOpError::Other(error.into()))
        })
        .map_err(TerminalControlError::from)
    }

    /// Returns the access mode and status flags of the file's open file description.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`], of the file's open
    /// file description to their values in `flags`.
    ///
    /// Every reference to the open file description, in any process, sees the change.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }

    /// Runs `try_op` once, or, given `wait`, until it stops returning [`TryOpError::TryAgain`],
    /// waiting for `events` on the file in between.
    fn wait<R, E>(
        &self,
        wait: Option<&WaitContext<'_, Platform>>,
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
                self.pollee().register_observer(observer, filter);
                Ok(())
            },
            try_op,
        )
    }

    /// Returns the file's pollee, registering it on first use to receive the file's broker
    /// readiness.
    fn pollee(&self) -> &Pollee<Platform> {
        self.pollee.call_once(|| {
            let pollee = Arc::new(Pollee::new());
            self.pollable_registry
                .register_pollable(self.handle, &pollee);
            pollee
        })
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> IOPollable for File<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee().register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        match self.broker.check_readiness(self.handle) {
            Ok(readiness) => readiness_events(readiness),
            // Files that never wait, such as regular files, have no readiness.
            Err(BrokerControlError::Broker(ErrorCode::InvalidRights)) => Events::OUT,
            Err(_) => Events::ERR,
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> Drop for File<Platform> {
    fn drop(&mut self) {
        // Stop receiving the file's readiness before the broker releases its handle.
        if self.pollee.get().is_some() {
            self.pollable_registry.unregister_pollable(self.handle);
        }
        let _ = self.broker.close_object(self.handle);
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

impl From<BrokerControlError> for TryOpError<TerminalControlError> {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Broker(ErrorCode::WouldBlock) => Self::TryAgain,
            BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock) => {
                Self::Other(TerminalControlError::WouldBlock)
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

impl From<TryOpError<TerminalControlError>> for TerminalControlError {
    fn from(error: TryOpError<TerminalControlError>) -> Self {
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
        BrokerControlError::AssociationFailed
        | BrokerControlError::Broker(_)
        | BrokerControlError::Fault => io,
    }
}

impl From<BrokerControlError> for ReadError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Fault => Self::Fault,
            error => broker_fd_error(error, Self::ClosedFd, Self::NotForReading, Self::Io),
        }
    }
}

impl From<BrokerControlError> for WriteError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Fault => Self::Fault,
            error => broker_fd_error(error, Self::ClosedFd, Self::NotForWriting, Self::Io),
        }
    }
}

impl From<BrokerControlError> for LockError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForLocking, Self::Io)
    }
}

impl From<FileError> for LockError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::PathOnly => Self::NotForLocking,
            _ => Self::Io,
        }
    }
}

impl From<BrokerControlError> for TruncateError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForWriting, Self::Io)
    }
}

impl From<BrokerControlError> for SharedObjectError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::NotForReading, Self::Io)
    }
}

impl From<FileError> for SharedObjectError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::IsDirectory => Self::IsDirectory,
            FileError::PathOnly => Self::PathOnly,
            FileError::NotForReading | FileError::AccessNotAllowed => Self::NotForReading,
            FileError::NoSuchDevice => Self::Unsupported,
            FileError::NoSpace => Self::NoMemory,
            _ => Self::Io,
        }
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

impl From<BrokerControlError> for SetTimesError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::AccessNotAllowed, Self::Io)
    }
}

impl From<BrokerControlError> for FilePathError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::Io, Self::Io)
    }
}

impl From<BrokerControlError> for IsTerminalError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::Io, Self::Io)
    }
}

impl From<BrokerControlError> for TerminalControlError {
    fn from(error: BrokerControlError) -> Self {
        broker_fd_error(error, Self::ClosedFd, Self::PathOnly, Self::Io)
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
        FileError::NoSearchPermissions => Some(PathError::NoSearchPerms),
        FileError::InvalidPathname => Some(PathError::InvalidPathname),
        FileError::MissingComponent => Some(PathError::MissingComponent),
        FileError::ComponentNotDirectory => Some(PathError::ComponentNotADirectory),
        FileError::TooManySymlinks => Some(PathError::TooManySymlinks),
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
            FileError::Busy => Self::TruncateError(TruncateError::Busy),
            FileError::NoSuchDevice => Self::NoSuchDevice,
            FileError::NoSpace => Self::NoSpace,
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
            FileError::NoSpace => Self::NoSpace,
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
            FileError::PathOnly => Self::NotOpenForSeeking,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for TruncateError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::IsDirectory => Self::IsDirectory,
            FileError::AccessNotAllowed | FileError::NotForWriting => Self::NotForWriting,
            FileError::PathOnly => Self::NotOpenForWriting,
            FileError::IsTerminalDevice => Self::IsTerminalDevice,
            FileError::Busy => Self::Busy,
            FileError::NoSpace => Self::NoSpace,
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

impl From<FileError> for SetTimesError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NotOwner => Self::NotTheOwner,
            FileError::AccessNotAllowed => Self::AccessNotAllowed,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            FileError::NotSupported => Self::NotSupported,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for SymlinkError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NoWritePermissions => Self::NoWritePerms,
            FileError::AlreadyExists => Self::AlreadyExists,
            FileError::ReadOnlyFs => Self::ReadOnlyFileSystem,
            FileError::NotSupported => Self::NotSupported,
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

impl From<FileError> for RenameError {
    fn from(error: FileError) -> Self {
        if let Some(error) = path_error(error) {
            return error.into();
        }
        match error {
            FileError::NoWritePermissions => Self::NoWritePerms,
            FileError::Busy => Self::Busy,
            FileError::CrossDevice => Self::CrossDevice,
            FileError::InvalidArgument => Self::InvalidArgument,
            FileError::IsDirectory => Self::IsADirectory,
            FileError::NotDirectory => Self::NotADirectory,
            FileError::NotEmpty => Self::NotEmpty,
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
            FileError::PathOnly => Self::NotOpenForReading,
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

impl From<FileError> for TerminalControlError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::PathOnly => Self::PathOnly,
            FileError::NotTerminal => Self::NotATerminal,
            FileError::InvalidTerminalControl => Self::InvalidControl,
            _ => Self::Io,
        }
    }
}

impl From<FileError> for WalkError {
    fn from(error: FileError) -> Self {
        path_error(error).map_or(Self::Io, Into::into)
    }
}

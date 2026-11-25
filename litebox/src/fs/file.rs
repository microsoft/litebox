// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest file operations backed by broker-owned file objects.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    DirectoryReadMode, DirectoryRecordBudget, FileAccessMode, FileDirectoryEntry, FileError,
    FileLockOperation, FileMode as Mode, FileOpenFlags, FileSeekWhence as SeekWhence, FileStatus,
    FileStatusFlags, FileUser as UserInfo, MAX_FILE_TRANSFER_SIZE, PathAnchor, SetFileTimes,
};
use litebox_broker_protocol::terminal::{TerminalOperation, TerminalResponse};
use litebox_broker_protocol::{ObjectHandle, ProcessId};

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

/// The explicit directory from which to resolve a relative path.
pub enum DirectoryAnchor<'a, Platform: sync::RawSyncPrimitivesProvider + TimeProvider> {
    /// No directory; the path must be absolute.
    None,
    /// The broker-owned working directory.
    Cwd {
        /// Use the caller's pending child instead of the caller.
        pending_child: Option<ProcessId>,
    },
    /// An open directory owned by this connection.
    Object(&'a File<Platform>),
}

impl<'a, Platform: sync::RawSyncPrimitivesProvider + TimeProvider> From<Option<&'a File<Platform>>>
    for DirectoryAnchor<'a, Platform>
{
    fn from(file: Option<&'a File<Platform>>) -> Self {
        file.map_or(Self::None, Self::Object)
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    fn path_anchor<'a>(
        broker: &Arc<dyn BrokerControl>,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
    ) -> Result<PathAnchor, FileError> {
        if path.is_empty() {
            return Err(FileError::NoSuchFileOrDirectory);
        }
        if path.starts_with('/') {
            return Ok(PathAnchor::None);
        }
        match dir.into() {
            DirectoryAnchor::None => Err(FileError::InvalidPathname),
            DirectoryAnchor::Cwd { pending_child } => Ok(PathAnchor::Cwd { pending_child }),
            DirectoryAnchor::Object(file) if Arc::ptr_eq(broker, &file.broker) => {
                Ok(PathAnchor::Object(file.handle()))
            }
            DirectoryAnchor::Object(_) => Err(FileError::Io),
        }
    }

    /// Changes the broker-owned working directory by path.
    pub fn chdir<'a>(
        &self,
        context: &Context,
        pending_child: Option<ProcessId>,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
    ) -> Result<(), OpenError> {
        let broker = self.broker_control().ok_or(OpenError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        Ok(broker
            .chdir(pending_child, dir, path, context.acting_user())
            .map_err(|_| OpenError::Io)??)
    }

    /// Returns the current path of the broker-owned working directory.
    pub fn getcwd(&self, pending_child: Option<ProcessId>) -> Result<String, FilePathError> {
        let broker = self.broker_control().ok_or(FilePathError::Io)?;
        Ok(broker.getcwd(pending_child)??)
    }

    /// Returns status of the broker-owned working directory itself.
    pub fn cwd_status(
        &self,
        pending_child: Option<ProcessId>,
    ) -> Result<FileStatus, FileStatusError> {
        let broker = self.broker_control().ok_or(FileStatusError::Io)?;
        Ok(broker.cwd_status(pending_child)??)
    }

    /// Updates timestamps of the broker-owned working directory itself.
    pub fn set_cwd_times(
        &self,
        pending_child: Option<ProcessId>,
        user: UserInfo,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        let broker = self.broker_control().ok_or(SetTimesError::Io)?;
        Ok(broker.set_cwd_times(pending_child, user, times)??)
    }

    /// Opens a file. A relative `path` resolves from `dir`; an absolute path ignores `dir`.
    ///
    /// A relative `path` requires `dir`, which must be a directory opened through this same
    /// `LiteBox`; otherwise the call fails. The other path-taking methods share these rules.
    ///
    /// `access` and `flags` use the architecture-independent broker contract.
    /// The `mode` is only significant when creating a file.
    pub fn open_file<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: Mode,
    ) -> Result<File<Platform>, OpenError> {
        if FileOpenFlags::from_bits(flags.bits()).is_none() {
            return Err(OpenError::AccessNotAllowed);
        }
        let broker = self.broker_control().ok_or(OpenError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        let handle = broker
            .open_file(
                dir,
                path,
                context.acting_user(),
                access,
                flags,
                mode & Mode::SUPPORTED,
            )
            .map_err(|_| OpenError::Io)??;
        Ok(File::new(self, broker, handle))
    }

    /// Returns the file this process inherited from its parent as `handle`
    /// through [`PendingChild::inherit`](crate::process::PendingChild::inherit),
    /// or received with Unix socket data.
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

    /// Change the permissions of a file. See [`Self::open_file`] for the rules on `dir`.
    pub fn chmod_file<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let broker = self.broker_control().ok_or(ChmodError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        broker
            .chmod_file(dir, path, context.acting_user(), mode & Mode::SUPPORTED)
            .map_err(|_| ChmodError::Io)?
            .map_err(ChmodError::from)
    }

    /// Change the owner of a file. See [`Self::open_file`] for the rules on `dir`.
    pub fn chown_file<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let broker = self.broker_control().ok_or(ChownError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        broker
            .chown_file(dir, path, context.acting_user(), user, group)
            .map_err(|_| ChownError::Io)?
            .map_err(ChownError::from)
    }

    /// Create a symbolic link at `linkpath`, storing `target` verbatim. A relative `linkpath`
    /// resolves from `dir`; an absolute one ignores `dir`.
    /// See [`Self::open_file`] for the rules on `dir`.
    ///
    /// A relative target is interpreted relative to the link's parent when the link is
    /// subsequently followed.
    pub fn symlink_file<'a>(
        &self,
        target: &str,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        linkpath: &str,
    ) -> Result<(), SymlinkError> {
        let broker = self.broker_control().ok_or(SymlinkError::Io)?;
        let dir = Self::path_anchor(&broker, dir, linkpath)?;
        broker
            .symlink_file(target, dir, linkpath, context.acting_user())
            .map_err(|_| SymlinkError::Io)?
            .map_err(SymlinkError::from)
    }

    /// Unlink a file. See [`Self::open_file`] for the rules on `dir`.
    pub fn unlink_file<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
    ) -> Result<(), UnlinkError> {
        let broker = self.broker_control().ok_or(UnlinkError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        broker
            .unlink_file(dir, path, context.acting_user())
            .map_err(|_| UnlinkError::Io)?
            .map_err(UnlinkError::from)
    }

    /// Rename a file or directory, replacing an existing destination when permitted. Relative
    /// source and destination paths resolve from `old_dir` and `new_dir` respectively; absolute
    /// paths ignore them.
    /// See [`Self::open_file`] for the rules on `dir`.
    pub fn rename_file<'a>(
        &self,
        context: &Context,
        old_dir: impl Into<DirectoryAnchor<'a, Platform>>,
        old_path: &str,
        new_dir: impl Into<DirectoryAnchor<'a, Platform>>,
        new_path: &str,
    ) -> Result<(), RenameError> {
        let broker = self.broker_control().ok_or(RenameError::Io)?;
        let old_dir = Self::path_anchor(&broker, old_dir, old_path)?;
        let new_dir = Self::path_anchor(&broker, new_dir, new_path)?;
        broker
            .rename_file(old_dir, old_path, new_dir, new_path, context.acting_user())
            .map_err(|_| RenameError::Io)?
            .map_err(RenameError::from)
    }

    /// Create a new directory. See [`Self::open_file`] for the rules on `dir`.
    pub fn mkdir_file<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let broker = self.broker_control().ok_or(MkdirError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        broker
            .mkdir_file(dir, path, context.acting_user(), mode & Mode::SUPPORTED)
            .map_err(|_| MkdirError::Io)?
            .map_err(MkdirError::from)
    }

    /// Mount a fresh in-memory filesystem at an absolute directory path.
    // TODO: take a `dir` anchor like the other path methods. Callers name a relative target from
    // their cwd's current path, so a concurrent rename of that directory can mount at a stale
    // location. Needs a protocol change, since the broker's mount table is name-based.
    pub fn mount_in_mem(&self, context: &Context, path: &str) -> Result<(), FileError> {
        let broker = self.broker_control().ok_or(FileError::Io)?;
        // Validation only.
        Self::path_anchor(&broker, DirectoryAnchor::None, path)?;
        broker
            .mount_in_mem(path, context.acting_user())
            .map_err(|_| FileError::Io)?
    }

    /// Remove a directory. See [`Self::open_file`] for the rules on `dir`.
    pub fn rmdir_file<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
    ) -> Result<(), RmdirError> {
        let broker = self.broker_control().ok_or(RmdirError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        broker
            .rmdir_file(dir, path, context.acting_user())
            .map_err(|_| RmdirError::Io)?
            .map_err(RmdirError::from)
    }

    /// Obtain the status of a path. See [`Self::open_file`] for the rules on `dir`.
    ///
    /// If `follow_symlinks` is false, a final symbolic link is described itself unless the path
    /// ends in a slash.
    pub fn path_file_status<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
        follow_symlinks: bool,
    ) -> Result<FileStatus, FileStatusError> {
        let broker = self.broker_control().ok_or(FileStatusError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        broker
            .path_file_status(dir, path, context.acting_user(), follow_symlinks)
            .map_err(|_| FileStatusError::Io)?
            .map_err(FileStatusError::from)
    }

    /// Read a symbolic link's stored target, without following the final link.
    /// See [`Self::open_file`] for the rules on `dir`.
    pub fn read_link_file<'a>(
        &self,
        context: &Context,
        dir: impl Into<DirectoryAnchor<'a, Platform>>,
        path: &str,
    ) -> Result<String, WalkError> {
        let broker = self.broker_control().ok_or(WalkError::Io)?;
        let dir = Self::path_anchor(&broker, dir, path)?;
        broker
            .read_link_file(dir, path, context.acting_user())
            .map_err(|_| WalkError::Io)?
            .map_err(WalkError::from)
    }
}

/// Caller-owned filesystem context holding the acting user.
#[derive(Clone, Debug)]
pub struct Context {
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

    /// A new default context for a non-root user.
    #[must_use]
    pub fn new() -> Self {
        Self {
            user_info: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
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

    /// Lists the entries of the directory this file opens without changing its position.
    pub fn list_directory(&self) -> Result<Vec<FileDirectoryEntry>, ReadDirError> {
        let mut entries = Vec::new();
        let mut index = 0;
        loop {
            let (response, mut page) = self
                .broker
                .read_directory(self.handle, DirectoryReadMode::List(index))??;
            entries
                .try_reserve(page.len())
                .map_err(|_| ReadDirError::Io)?;
            entries.append(&mut page);
            let Some(next_index) = response.next_index else {
                return Ok(entries);
            };
            index = next_index;
        }
    }

    /// Reads one batch at the shared directory cursor and advances it in the same broker call.
    /// Returns the position before the first entry and the entries that fit the budget and transfer.
    pub fn read_directory(
        &self,
        budget: DirectoryRecordBudget,
    ) -> Result<(u64, Vec<FileDirectoryEntry>), ReadDirError> {
        let (response, entries) = self
            .broker
            .read_directory(self.handle, DirectoryReadMode::Cursor(budget))?
            .map_err(|error| match error {
                // The broker reports a budget too small for the next record as invalid.
                FileError::InvalidArgument => ReadDirError::BufferTooSmall,
                error => error.into(),
            })?;
        Ok((response.first_index, entries))
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

    /// Returns the absolute path of the file, with symbolic links resolved.
    ///
    /// A directory reports its current path where the backend can determine it, and fails with
    /// [`FilePathError::NoSuchFileOrDirectory`] once removed. Any other file keeps the name it was
    /// opened by, under the current path of the directory it was opened relative to; its own
    /// later renames or removals are not reflected.
    pub fn path(&self) -> Result<String, FilePathError> {
        Ok(self.broker.handle_file_path(self.handle)??)
    }

    /// Changes the working directory to this open directory.
    pub fn fchdir(
        &self,
        pending_child: Option<ProcessId>,
        user: UserInfo,
    ) -> Result<(), OpenError> {
        Ok(self
            .broker
            .fchdir(pending_child, self.handle, user)
            .map_err(|_| OpenError::Io)??)
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

impl From<FileError> for FilePathError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::NoSuchFileOrDirectory => Self::NoSuchFileOrDirectory,
            _ => Self::Io,
        }
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
            FileError::NoSuchFileOrDirectory => Self::Removed,
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

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};

    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, OpenFileResponse};
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, FileRequest, FileResponse,
    };
    use litebox_broker_protocol::{ObjectHandle, fs::PathAnchor};
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::HeapSharedMemory;

    use super::Context;
    use crate::LiteBox;
    use crate::platform::mock::MockPlatform;

    /// Serves only absolute opens, so any other request reaching it fails the test.
    struct OpenOnlyChannel {
        next_handle: AtomicU64,
    }

    impl LocalCallChannel for OpenOnlyChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            let result = match request.operation {
                BrokerOperation::File(FileRequest::Open(open)) if open.dir == PathAnchor::None => {
                    BrokerResult::File(FileResponse::Open(OpenFileResponse {
                        handle: ObjectHandle(self.next_handle.fetch_add(1, Ordering::SeqCst)),
                    }))
                }
                BrokerOperation::CloseObject(_) => BrokerResult::ObjectClosed,
                request => panic!("unexpected broker request: {request:?}"),
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }

    fn litebox() -> LiteBox<MockPlatform> {
        let local = test_broker_local(
            OpenOnlyChannel {
                next_handle: AtomicU64::new(1),
            },
            Arc::new(HeapSharedMemory::new(
                litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE,
            )),
        );
        LiteBox::new_with_broker_local(MockPlatform::new(), local)
    }

    /// Handle numbers are scoped to a broker connection, so a directory from another connection,
    /// whose number may name an unrelated object here, is refused without sending the request.
    #[test]
    fn relative_paths_refuse_a_directory_from_another_connection() {
        let (first, second) = (litebox(), litebox());
        let context = Context::new();
        let foreign = first
            .open_file(
                &context,
                None,
                "/",
                FileAccessMode::ReadOnly,
                FileOpenFlags::PATH | FileOpenFlags::DIRECTORY,
                FileMode::empty(),
            )
            .unwrap();
        assert!(
            second
                .mkdir_file(&context, Some(&foreign), "dir", FileMode::RWXU)
                .is_err()
        );
    }
}

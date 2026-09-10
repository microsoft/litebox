// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest file operations backed by broker-owned file objects.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode as Mode, FileOpenFlags,
    FileSeekWhence as SeekWhence, FileStatus, FileUser as UserInfo, ResolvedPath,
};

use crate::path::Arg;
use crate::{LiteBox, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};

impl<Platform: sync::RawSyncPrimitivesProvider> LiteBox<Platform> {
    fn broker_file(&self, fd: &FileFd) -> Option<Arc<BrokerFile>> {
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
            .insert(Arc::new(BrokerFile { broker, handle })))
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
    pub fn read_file(
        &self,
        fd: &FileFd,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let file = self.broker_file(fd).ok_or(ReadError::ClosedFd)?;
        file.broker
            .read_file(
                file.handle,
                buf,
                offset
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| ReadError::Io)?,
            )
            .map_err(|error| broker_fd_error(error, ReadError::ClosedFd, ReadError::Io))?
            .map_err(read_error)
    }

    /// Write from a buffer to a file descriptor at `offset`.
    pub fn write_file(
        &self,
        fd: &FileFd,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let file = self.broker_file(fd).ok_or(WriteError::ClosedFd)?;
        file.broker
            .write_file(
                file.handle,
                buf,
                offset
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| WriteError::Io)?,
            )
            .map_err(|error| broker_fd_error(error, WriteError::ClosedFd, WriteError::Io))?
            .map_err(write_error)
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
            .map_err(|error| broker_fd_error(error, SeekError::ClosedFd, SeekError::Io))?
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
            .map_err(|error| broker_fd_error(error, TruncateError::ClosedFd, TruncateError::Io))?
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
            .map_err(|error| broker_fd_error(error, ReadDirError::ClosedFd, ReadDirError::Io))?
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
                broker_fd_error(error, FileStatusError::ClosedFd, FileStatusError::Io)
            })?
            .map_err(file_status_error)
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
            cwd: Arc::new(ResolvedPath::root()),
            user_info: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }

    /// Resolve `path` against the current context.
    pub fn resolve(&self, path: impl Arg) -> Result<ResolvedPath, PathError> {
        Ok(self.cwd.resolve(path.as_rust_str()?))
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Guest-side reference to a broker-owned file and the subsystem type for [`FileFd`].
///
/// The broker object is closed when its last descriptor or in-flight operation releases its
/// reference.
pub struct BrokerFile {
    broker: Arc<dyn crate::broker::BrokerControl>,
    handle: ObjectHandle,
}

impl Drop for BrokerFile {
    fn drop(&mut self) {
        let _ = self.broker.close_object(self.handle);
    }
}

fn broker_fd_error<T>(error: crate::broker::error::BrokerControlError, closed: T, io: T) -> T {
    match error {
        crate::broker::error::BrokerControlError::Broker(
            ErrorCode::UnknownObject | ErrorCode::InvalidRights,
        ) => closed,
        crate::broker::error::BrokerControlError::AssociationFailed
        | crate::broker::error::BrokerControlError::Broker(_) => io,
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
        FileError::NotForReading => ReadError::NotForReading,
        _ => ReadError::Io,
    }
}

fn write_error(error: FileError) -> WriteError {
    match error {
        FileError::NotFile => WriteError::NotAFile,
        FileError::NotForWriting => WriteError::NotForWriting,
        _ => WriteError::Io,
    }
}

fn seek_error(error: FileError) -> SeekError {
    match error {
        FileError::NotFile => SeekError::NotAFile,
        FileError::InvalidOffset => SeekError::InvalidOffset,
        FileError::NonSeekable => SeekError::NonSeekable,
        _ => SeekError::Io,
    }
}

fn truncate_error(error: FileError) -> TruncateError {
    match error {
        FileError::IsDirectory => TruncateError::IsDirectory,
        FileError::NotForWriting => TruncateError::NotForWriting,
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

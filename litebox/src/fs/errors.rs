// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Possible errors from [`FileSystem`]

#[expect(
    unused_imports,
    reason = "used for doc string links to work out, but not for code"
)]
use super::FileSystem;

use thiserror::Error;

// XXX(jayb): We probably need to introduce a notion of `Stale` to many/most of these errors, in
// order to more correctly support network-attached file systems.

/// Possible errors from [`FileSystem::open`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum OpenError {
    #[error("requested access to the file is not allowed")]
    AccessNotAllowed,
    #[error("the requested operation is not permitted")]
    OperationNotPermitted,
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("write access requested for a file on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("file already exists")]
    AlreadyExists,
    #[error("the final path component is a symbolic link and O_NOFOLLOW was set")]
    TooManySymbolicLinks,
    #[error("error when truncating: {0}")]
    TruncateError(#[from] TruncateError),
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
    #[error("open flags not yet supported by this filesystem")]
    UnsupportedFlags,
}

/// Possible errors from [`FileSystem::close`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum CloseError {}

/// Possible errors from [`FileSystem::read`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for reading")]
    NotForReading,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`FileSystem::write`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum WriteError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for writing")]
    NotForWriting,
    #[error("write would require copy-up into a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`FileSystem::seek`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SeekError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("would seek to an invalid (negative or past end) of seekable positions")]
    InvalidOffset,
    #[error("non-seekable file")]
    NonSeekable,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`FileSystem::truncate`]
#[derive(Error, Debug)]
pub enum TruncateError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor points to a directory")]
    IsDirectory,
    #[error("file is not opened for writing")]
    NotForWriting,
    #[error("operation not permitted on an `O_PATH` fd")]
    PathOnlyFd,
    #[error("file descriptor points to a terminal device")]
    IsTerminalDevice,
    #[error("truncate would require copy-up into a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`FileSystem::chmod`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ChmodError {
    #[error(
        "the effective UID does not match the owner of the file, \
         and the process is not privileged"
    )]
    NotTheOwner,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
    /// Only relevant to [`FileSystem::fd_chmod`].
    #[error("fd has been closed already")]
    ClosedFd,
    /// Only relevant to [`FileSystem::fd_chmod`].
    #[error("operation not permitted on an `O_PATH` fd")]
    PathOnlyFd,
}

/// Possible errors from [`FileSystem::chown`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ChownError {
    #[error(
        "the effective UID does not match the owner of the file, \
         and the process is not privileged"
    )]
    NotTheOwner,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
    /// Only relevant to [`FileSystem::fd_chown`].
    #[error("fd has been closed already")]
    ClosedFd,
    /// Only relevant to [`FileSystem::fd_chown`].
    #[error("operation not permitted on an `O_PATH` fd")]
    PathOnlyFd,
}

/// Possible errors from [`FileSystem::utimensat`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum UtimeError {
    #[error("the file does not allow write permission for the current user")]
    NoWritePerms,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
    /// Only relevant to [`FileSystem::fd_utimensat`].
    #[error("fd has been closed already")]
    ClosedFd,
    /// Only relevant to [`FileSystem::fd_utimensat`].
    #[error("operation not permitted on an `O_PATH` fd")]
    PathOnlyFd,
}

/// Possible errors from [`FileSystem::unlink`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum UnlinkError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("the sticky-directory ownership rule forbids removal")]
    OperationNotPermitted,
    #[error("pathname is a directory")]
    IsADirectory,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::mkdir`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MkdirError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("pathname already exists, not necessarily a directory")]
    AlreadyExists,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::symlink`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SymlinkError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("pathname already exists")]
    AlreadyExists,
    #[error("the link would reside on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::readlink`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReadlinkError {
    #[error("the named file is not a symbolic link")]
    NotASymlink,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::rename`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RenameError {
    #[error("a directory in the rename does not allow write permission")]
    NoWritePerms,
    #[error("the sticky-directory ownership rule forbids the rename")]
    OperationNotPermitted,
    #[error("newpath is a non-empty directory")]
    NotEmpty,
    #[error("newpath is an existing directory but oldpath is not")]
    IsADirectory,
    #[error("oldpath is a directory but newpath is an existing non-directory")]
    NotADirectory,
    #[error("newpath already exists and RENAME_NOREPLACE was requested")]
    AlreadyExists,
    #[error("the rename would cross a filesystem/mount boundary")]
    CrossDevice,
    #[error("oldpath is a prefix of newpath, or another invalid-argument case")]
    InvalidArgument,
    #[error("the rename targets a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::rmdir`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RmdirError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("the sticky-directory ownership rule forbids removal")]
    OperationNotPermitted,
    #[error(
        "currently in use by the system, or something prevents its removal (e.g., is the root directory)"
    )]
    Busy,
    #[error("pathname contains entries other than . and ..")]
    NotEmpty,
    #[error("pathname is not a directory")]
    NotADirectory,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::read_dir`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReadDirError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("operation not permitted on an `O_PATH` fd")]
    PathOnlyFd,
    #[error("fd does not point to a directory")]
    NotADirectory,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`FileSystem::file_status`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum FileStatusError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from a backend walk
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum WalkError {
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors in any file-system function due to path errors.
#[derive(Error, Debug)]
pub enum PathError {
    #[error("no such file or directory")]
    NoSuchFileOrDirectory,
    #[error("one of the directories in pathname did not allow search permission")]
    NoSearchPerms {
        #[cfg(debug_assertions)]
        dir: alloc::string::String,
        #[cfg(debug_assertions)]
        perms: crate::fs::Mode,
    },
    #[error("invalid characters, not permitted by underlying file system")]
    InvalidPathname,
    #[error("a directory component in pathname does not exist or is a dangling symbolic link")]
    MissingComponent,
    #[error("a component used as a directory in pathname is not, in fact, a directory")]
    ComponentNotADirectory,
}

impl From<crate::path::ConversionError> for PathError {
    fn from(_value: crate::path::ConversionError) -> Self {
        Self::InvalidPathname
    }
}

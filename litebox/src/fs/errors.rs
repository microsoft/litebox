// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Possible errors from [`FileSystem`]

#[expect(
    unused_imports,
    reason = "used for doc string links to work out, but not for code"
)]
use super::FileSystem;

use thiserror::Error;

/// Possible errors from [`FileSystem::open`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum OpenError {
    #[error("requested access to the file is not allowed")]
    AccessNotAllowed,
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("write access requested for a file on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("file already exists")]
    AlreadyExists,
    #[error("error when truncating: {0}")]
    TruncateError(#[from] TruncateError),
    #[error(transparent)]
    PathError(#[from] PathError),
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
    #[error("file descriptor points to a terminal device")]
    IsTerminalDevice,
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
    #[error(transparent)]
    PathError(#[from] PathError),
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
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::unlink`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum UnlinkError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("pathname is a directory")]
    IsADirectory,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
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
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::rmdir`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RmdirError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
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
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::read_dir`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReadDirError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("fd does not point to a directory")]
    NotADirectory,
}

/// Possible errors from [`FileSystem::file_status`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum FileStatusError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`FileSystem::link`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum LinkError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("newpath already exists")]
    AlreadyExists,
    #[error("oldpath is a directory")]
    IsADirectory,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("oldpath and newpath are not on the same mounted filesystem")]
    CrossDeviceLink,
    #[error("too many links to the file")]
    TooManyLinks,
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

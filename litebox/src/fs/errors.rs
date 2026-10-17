// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Errors from LiteBox file operations.

use thiserror::Error;

use crate::event::wait::WaitError;

// XXX(jayb): We probably need to introduce a notion of `Stale` to many/most of these errors, in
// order to more correctly support network-attached file systems.

/// Possible errors from [`crate::LiteBox::open_file`].
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
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`super::File::read`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for reading")]
    NotForReading,
    #[error("read would block")]
    WouldBlock,
    #[error("wait error: {0}")]
    WaitError(WaitError),
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`super::File::write`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum WriteError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for writing")]
    NotForWriting,
    #[error("write would block")]
    WouldBlock,
    #[error("wait error: {0}")]
    WaitError(WaitError),
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`super::File::seek`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SeekError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file descriptor is not open for seeking")]
    NotForSeeking,
    #[error("would seek to an invalid (negative or past end) of seekable positions")]
    InvalidOffset,
    #[error("non-seekable file")]
    NonSeekable,
    #[error("file descriptor is not open for seeking")]
    NotOpenForSeeking,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`super::File::truncate`].
#[derive(Error, Debug)]
pub enum TruncateError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("file descriptor points to a directory")]
    IsDirectory,
    #[error("file is not opened for writing")]
    NotForWriting,
    #[error("file descriptor is not open for writing")]
    NotOpenForWriting,
    #[error("file descriptor points to a terminal device")]
    IsTerminalDevice,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`crate::LiteBox::chmod_file`].
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
}

/// Possible errors from [`crate::LiteBox::chown_file`].
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
}

/// Possible errors from [`crate::LiteBox::unlink_file`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum UnlinkError {
    #[error("the parent directory does not allow write permission")]
    NoWritePerms,
    #[error("pathname is a directory")]
    IsADirectory,
    #[error("the named file resides on a read-only filesystem")]
    ReadOnlyFileSystem,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`crate::LiteBox::mkdir_file`].
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

/// Possible errors from [`crate::LiteBox::rmdir_file`].
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
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`super::File::read_directory`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReadDirError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("fd does not point to a directory")]
    NotADirectory,
    #[error("file descriptor is not open for reading")]
    NotForReading,
    #[error("file descriptor is not open for reading")]
    NotOpenForReading,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`crate::LiteBox::path_file_status`] and [`super::File::status`].
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

/// Possible errors from [`crate::LiteBox::read_link_file`] and
/// [`crate::LiteBox::resolve_file_path`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum WalkError {
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

/// Possible errors from [`super::File::is_terminal`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum IsTerminalError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("I/O error")]
    Io,
}

/// Possible errors from [`super::File::get_status_flags`] and
/// [`super::File::set_status_flags`].
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum StatusFlagsError {
    #[error("fd has been closed already")]
    ClosedFd,
    #[error("fd is open only for path-based operations")]
    PathOnly,
    #[error("I/O error")]
    Io,
}

/// Possible errors in any file-system function due to path errors.
#[derive(Error, Debug)]
pub enum PathError {
    #[error("too many symbolic links encountered")]
    TooManySymlinks,
    #[error("no such file or directory")]
    NoSuchFileOrDirectory,
    #[error("one of the directories in pathname did not allow search permission")]
    NoSearchPerms,
    #[error("invalid characters, not permitted by underlying file system")]
    InvalidPathname,
    #[error("a directory component in pathname does not exist or is a dangling symbolic link")]
    MissingComponent,
    #[error("a component used as a directory in pathname is not, in fact, a directory")]
    ComponentNotADirectory,
}

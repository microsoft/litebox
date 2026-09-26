// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin `errno` values, and the mapping from LiteBox's file-system errors.
//!
//! These are XNU's numbers (`<sys/errno.h>`). The low ones agree with Linux,
//! but from `EAGAIN` (35 here, 11 on Linux) on the two diverge, so the Linux
//! shim's `Errno` cannot be reused.

use litebox::fs::errors::{CloseError, OpenError, PathError, ReadError, SeekError, WriteError};

/// A Darwin `errno` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Errno(pub(crate) u16);

impl Errno {
    pub(crate) const EPERM: Self = Self(1);
    pub(crate) const ENOENT: Self = Self(2);
    pub(crate) const EIO: Self = Self(5);
    pub(crate) const EBADF: Self = Self(9);
    pub(crate) const ENOMEM: Self = Self(12);
    pub(crate) const EACCES: Self = Self(13);
    pub(crate) const EFAULT: Self = Self(14);
    pub(crate) const EEXIST: Self = Self(17);
    pub(crate) const ENOTDIR: Self = Self(20);
    pub(crate) const EISDIR: Self = Self(21);
    pub(crate) const EINVAL: Self = Self(22);
    pub(crate) const EMFILE: Self = Self(24);
    pub(crate) const ESPIPE: Self = Self(29);
    pub(crate) const EROFS: Self = Self(30);
    pub(crate) const ENOTSUP: Self = Self(45);
    pub(crate) const ELOOP: Self = Self(62);
    pub(crate) const ENAMETOOLONG: Self = Self(63);
    pub(crate) const ENOSYS: Self = Self(78);
}

impl From<PathError> for Errno {
    fn from(error: PathError) -> Self {
        match error {
            PathError::NoSuchFileOrDirectory | PathError::MissingComponent => Self::ENOENT,
            PathError::NoSearchPerms { .. } => Self::EACCES,
            PathError::ComponentNotADirectory => Self::ENOTDIR,
            PathError::InvalidPathname => Self::EINVAL,
        }
    }
}

impl From<OpenError> for Errno {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::AccessNotAllowed | OpenError::NoWritePerms => Self::EACCES,
            OpenError::OperationNotPermitted => Self::EPERM,
            OpenError::ReadOnlyFileSystem => Self::EROFS,
            OpenError::AlreadyExists => Self::EEXIST,
            OpenError::TooManySymbolicLinks => Self::ELOOP,
            OpenError::PathError(error) => error.into(),
            OpenError::UnsupportedFlags => Self::EINVAL,
            OpenError::TruncateError(_) | OpenError::Io | _ => Self::EIO,
        }
    }
}

impl From<ReadError> for Errno {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::ClosedFd | ReadError::NotForReading => Self::EBADF,
            ReadError::NotAFile => Self::EISDIR,
            ReadError::Io | _ => Self::EIO,
        }
    }
}

impl From<WriteError> for Errno {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::ClosedFd | WriteError::NotForWriting => Self::EBADF,
            WriteError::NotAFile => Self::EISDIR,
            WriteError::ReadOnlyFileSystem => Self::EROFS,
            WriteError::Io | _ => Self::EIO,
        }
    }
}

impl From<SeekError> for Errno {
    fn from(error: SeekError) -> Self {
        match error {
            SeekError::ClosedFd => Self::EBADF,
            SeekError::NotAFile | SeekError::NonSeekable => Self::ESPIPE,
            SeekError::InvalidOffset => Self::EINVAL,
            SeekError::Io | _ => Self::EIO,
        }
    }
}

impl From<CloseError> for Errno {
    fn from(_: CloseError) -> Self {
        // `CloseError` has no variants today; any it gains are I/O failures.
        Self::EIO
    }
}

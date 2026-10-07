// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host `std::io::Error`s produced by LocalFs, and their conversions into LiteBox filesystem errors.

// TODO(jayb): Clean this up as part of the error handling cleanups.

use litebox_broker_core::fs::Mode;
#[cfg(unix)]
use litebox_broker_core::fs::errors::ChownError;
use litebox_broker_core::fs::errors::{
    ChmodError, MkdirError, OpenError, PathError, RmdirError, UnlinkError, WalkError,
};

pub(super) fn invalid_path() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "path escapes or is unsupported by LocalFs",
    )
}

pub(super) fn unsupported_object() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "LocalFs exposes only regular files and directories",
    )
}

fn unmapped<T: core::fmt::Debug>(error: &std::io::Error, fallback: T) -> T {
    litebox_util_log::debug!(
        error:? = error, mapped:? = fallback;
        "host error has no specific LiteBox mapping"
    );
    fallback
}

fn path_error(error: &std::io::Error) -> PathError {
    match error.kind() {
        std::io::ErrorKind::NotFound => PathError::NoSuchFileOrDirectory,
        std::io::ErrorKind::NotADirectory => PathError::ComponentNotADirectory,
        std::io::ErrorKind::PermissionDenied => PathError::NoSearchPerms {
            #[cfg(debug_assertions)]
            dir: String::new(),
            #[cfg(debug_assertions)]
            perms: Mode::empty(),
        },
        _ => PathError::InvalidPathname,
    }
}

pub(super) fn walk_error(error: std::io::Error) -> WalkError {
    match error.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::NotADirectory
        | std::io::ErrorKind::PermissionDenied
        | std::io::ErrorKind::InvalidInput => path_error(&error).into(),
        _ => unmapped(&error, WalkError::Io),
    }
}

pub(super) fn open_error(error: std::io::Error) -> OpenError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => OpenError::AlreadyExists,
        std::io::ErrorKind::PermissionDenied => OpenError::AccessNotAllowed,
        std::io::ErrorKind::ReadOnlyFilesystem => OpenError::ReadOnlyFileSystem,
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::NotADirectory
        | std::io::ErrorKind::InvalidInput => path_error(&error).into(),
        _ => unmapped(&error, OpenError::Io),
    }
}

pub(super) fn mkdir_error(error: std::io::Error) -> MkdirError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => MkdirError::AlreadyExists,
        std::io::ErrorKind::PermissionDenied => MkdirError::NoWritePerms,
        std::io::ErrorKind::ReadOnlyFilesystem => MkdirError::ReadOnlyFileSystem,
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::NotADirectory
        | std::io::ErrorKind::InvalidInput => path_error(&error).into(),
        _ => unmapped(&error, MkdirError::Io),
    }
}

pub(super) fn unlink_error(error: std::io::Error) -> UnlinkError {
    match error.kind() {
        std::io::ErrorKind::IsADirectory => UnlinkError::IsADirectory,
        std::io::ErrorKind::PermissionDenied => UnlinkError::NoWritePerms,
        std::io::ErrorKind::ReadOnlyFilesystem => UnlinkError::ReadOnlyFileSystem,
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::NotADirectory
        | std::io::ErrorKind::InvalidInput => path_error(&error).into(),
        _ => unmapped(&error, UnlinkError::Io),
    }
}

pub(super) fn rmdir_error(error: std::io::Error) -> RmdirError {
    match error.kind() {
        // POSIX permits EEXIST for a non-empty directory.
        std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::AlreadyExists => {
            RmdirError::NotEmpty
        }
        std::io::ErrorKind::NotADirectory => RmdirError::NotADirectory,
        std::io::ErrorKind::PermissionDenied => RmdirError::NoWritePerms,
        std::io::ErrorKind::ReadOnlyFilesystem => RmdirError::ReadOnlyFileSystem,
        std::io::ErrorKind::ResourceBusy => RmdirError::Busy,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput => {
            path_error(&error).into()
        }
        _ => unmapped(&error, RmdirError::Io),
    }
}

pub(super) fn chmod_error(error: std::io::Error) -> ChmodError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => ChmodError::NotTheOwner,
        std::io::ErrorKind::ReadOnlyFilesystem => ChmodError::ReadOnlyFileSystem,
        _ => unmapped(&error, ChmodError::Io),
    }
}

#[cfg(unix)]
pub(super) fn chown_error(error: std::io::Error) -> ChownError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => ChownError::NotTheOwner,
        std::io::ErrorKind::ReadOnlyFilesystem => ChownError::ReadOnlyFileSystem,
        _ => unmapped(&error, ChownError::Io),
    }
}

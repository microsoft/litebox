// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Possible errors from [`Resolver`]
//!
//! Every error is a payload-free kind; each operation's error type is the set of kinds it can
//! fail with. A kind has the same representation in every set, so moving an error between
//! operations is a checked [`OneOf::widen`] (or [`OneOf::narrow`]/[`OneOf::subset`] to handle
//! some kinds and pass the rest on), rather than a hand-written mapping.

#[expect(
    unused_imports,
    reason = "used for doc string links to work out, but not for code"
)]
use super::resolver::Resolver;

pub use litebox_util_errset::{OneOf, ResultExt, SubsetExt};

// XXX(jayb): We probably need to introduce a notion of `Stale` to many/most of these errors, in
// order to more correctly support network-attached file systems.

// All kinds are declared in one block so that their codes are distinct, which lets any of them
// share a set.
litebox_util_errset::kinds! {
    pub struct AccessNotAllowed => "requested access to the file is not allowed";
    pub struct NoWritePerms => "the parent directory does not allow write permission";
    pub struct ReadOnlyFileSystem => "the file resides on a read-only filesystem";
    pub struct AlreadyExists => "pathname already exists, not necessarily as the requested type";
    pub struct Io => "I/O error";
    pub struct ClosedFd => "fd has been closed already";
    pub struct NotAFile => "file descriptor does not point to a file";
    pub struct NotForReading => "file not open for reading";
    pub struct NotForWriting => "file not open for writing";
    pub struct InvalidOffset =>
        "would seek to an invalid (negative or past end) of seekable positions";
    pub struct NonSeekable => "non-seekable file";
    pub struct NotOpenForSeeking => "file descriptor is not open for seeking";
    pub struct NotOpenForReading => "file descriptor is not open for reading";
    pub struct NotOpenForWriting => "file descriptor is not open for writing";
    pub struct IsADirectory => "pathname or file descriptor is a directory";
    pub struct IsTerminalDevice => "file descriptor points to a terminal device";
    pub struct NotTheOwner =>
        "the effective UID does not match the owner of the file, and the process is not privileged";
    pub struct Busy =>
        "currently in use by the system, or something prevents its removal (e.g., is the root directory)";
    pub struct NotEmpty => "pathname contains entries other than . and ..";
    pub struct NotADirectory => "pathname or file descriptor is not a directory";
    pub struct NoSuchFileOrDirectory => "no such file or directory";
    pub struct NoSearchPerms =>
        "one of the directories in pathname did not allow search permission";
    pub struct InvalidPathname => "invalid characters, not permitted by underlying file system";
    pub struct MissingComponent =>
        "a directory component in pathname does not exist or is a dangling symbolic link";
    pub struct ComponentNotADirectory =>
        "a component used as a directory in pathname is not, in fact, a directory";
}

/// Possible errors from [`Resolver::open`]
pub type OpenError = OneOf<(
    AccessNotAllowed,
    NoWritePerms,
    ReadOnlyFileSystem,
    AlreadyExists,
    TruncateError,
    PathError,
)>;

/// Possible errors from [`Resolver::close`]
pub type CloseError = OneOf<()>;

/// Possible errors from [`Resolver::read`]
pub type ReadError = OneOf<(ClosedFd, NotAFile, NotForReading, Io)>;

/// Possible errors from [`Resolver::write`]
pub type WriteError = OneOf<(ClosedFd, NotAFile, NotForWriting, Io)>;

/// Possible errors from [`Resolver::seek`]
pub type SeekError = OneOf<(
    ClosedFd,
    NotAFile,
    InvalidOffset,
    NonSeekable,
    NotOpenForSeeking,
    Io,
)>;

/// Possible errors from [`Resolver::truncate`]
pub type TruncateError = OneOf<(
    ClosedFd,
    IsADirectory,
    NotForWriting,
    NotOpenForWriting,
    IsTerminalDevice,
    Io,
)>;

/// Possible errors from [`Resolver::chmod`]
pub type ChmodError = OneOf<(NotTheOwner, ReadOnlyFileSystem, Io, PathError)>;

/// Possible errors from [`Resolver::chown`]
pub type ChownError = ChmodError;

/// Possible errors from [`Resolver::unlink`]
pub type UnlinkError = OneOf<(
    NoWritePerms,
    IsADirectory,
    ReadOnlyFileSystem,
    Io,
    PathError,
)>;

/// Possible errors from [`Resolver::mkdir`]
pub type MkdirError = OneOf<(
    NoWritePerms,
    AlreadyExists,
    ReadOnlyFileSystem,
    Io,
    PathError,
)>;

/// Possible errors from [`Resolver::rmdir`]
pub type RmdirError = OneOf<(
    NoWritePerms,
    Busy,
    NotEmpty,
    NotADirectory,
    ReadOnlyFileSystem,
    Io,
    PathError,
)>;

/// Possible errors from [`Resolver::read_dir`]
pub type ReadDirError = OneOf<(ClosedFd, NotADirectory, NotOpenForReading, Io)>;

/// Possible errors from [`Resolver::file_status`]
pub type FileStatusError = OneOf<(ClosedFd, Io, PathError)>;

/// Possible errors from a backend walk
pub type WalkError = OneOf<(Io, PathError)>;

/// Possible errors in any file-system function due to path errors.
pub type PathError = OneOf<(
    NoSuchFileOrDirectory,
    NoSearchPerms,
    InvalidPathname,
    MissingComponent,
    ComponentNotADirectory,
)>;

impl From<crate::path::ConversionError> for PathError {
    fn from(_value: crate::path::ConversionError) -> Self {
        InvalidPathname.into_set()
    }
}

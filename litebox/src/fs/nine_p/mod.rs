// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A network file system, using the 9P2000.L protocol
//!
//! This module provides a [`FileSystem`] implementation that accesses files over a 9P2000.L
//! network connection. The 9P protocol is a simple, message-based protocol originally designed
//! for Plan 9 from Bell Labs. 9P2000.L is a Linux-specific variant that provides better
//! compatibility with POSIX semantics.
//!
//! # Submodules
//!
//! The 9P implementation is split into several submodules:
//! - `fcall` - Protocol message definitions and encoding/decoding
//! - `transport` - Transport layer traits and message I/O
//! - `client` - High-level 9P client for protocol operations

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use thiserror::Error;

use crate::fs::OFlags;
use crate::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use crate::fs::nine_p::fcall::Rlerror;
use crate::path::Arg;
use crate::{LiteBox, sync};

mod client;
mod fcall;

pub mod transport;

const DEVICE_ID: usize = u32::from_le_bytes(*b"NINE") as usize;

/// Error type for 9P operations
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error during transport
    #[error("I/O error")]
    Io,

    /// Invalid input (e.g., malformed protocol message)
    #[error("Invalid input")]
    InvalidInput,

    #[error("Invalid response from server")]
    InvalidResponse,

    #[error("Invalid pathname")]
    InvalidPathname,

    /// Path not found
    #[error("Path not found")]
    NotFound,

    /// File already exists
    #[error("File already exists")]
    AlreadyExists,

    /// Permission denied
    #[error("Permission denied")]
    PermissionDenied,

    /// Not a directory
    #[error("Not a directory")]
    NotADirectory,

    /// Is a directory
    #[error("Is a directory")]
    IsADirectory,

    /// Name too long
    #[error("Name too long")]
    NameTooLong,

    /// Connection error
    #[error("Connection error")]
    Connection,

    /// Operation not supported
    #[error("Operation not supported")]
    NotSupported,
}

impl From<Error> for OpenError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => OpenError::PathError(PathError::NoSuchFileOrDirectory),
            Error::AlreadyExists => OpenError::AlreadyExists,
            Error::PermissionDenied => OpenError::AccessNotAllowed,
            Error::NotADirectory => OpenError::PathError(PathError::ComponentNotADirectory),
            Error::InvalidPathname => OpenError::PathError(PathError::InvalidPathname),
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to OpenError"),
        }
    }
}

impl From<Error> for ReadError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => ReadError::NotAFile,
            Error::PermissionDenied => ReadError::NotForReading,
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::InvalidPathname
            | Error::AlreadyExists
            | Error::NotADirectory
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to ReadError"),
        }
    }
}

impl From<Error> for WriteError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => WriteError::NotAFile,
            Error::PermissionDenied => WriteError::NotForWriting,
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::InvalidPathname
            | Error::AlreadyExists
            | Error::NotADirectory
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to WriteError"),
        }
    }
}

impl From<Error> for MkdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => MkdirError::PathError(PathError::NoSuchFileOrDirectory),
            Error::AlreadyExists => MkdirError::AlreadyExists,
            Error::PermissionDenied => MkdirError::NoWritePerms,
            Error::NotADirectory => MkdirError::PathError(PathError::ComponentNotADirectory),
            Error::InvalidPathname => MkdirError::PathError(PathError::InvalidPathname),
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to MkdirError"),
        }
    }
}

impl From<Error> for ReadDirError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => ReadDirError::NotADirectory,
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::InvalidPathname
            | Error::AlreadyExists
            | Error::PermissionDenied
            | Error::NotADirectory
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to ReadDirError"),
        }
    }
}

impl From<Error> for UnlinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => UnlinkError::PathError(PathError::NoSuchFileOrDirectory),
            Error::IsADirectory => UnlinkError::IsADirectory,
            Error::PermissionDenied => UnlinkError::NoWritePerms,
            Error::NotADirectory => UnlinkError::PathError(PathError::ComponentNotADirectory),
            Error::InvalidPathname => UnlinkError::PathError(PathError::InvalidPathname),
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::AlreadyExists
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to UnlinkError"),
        }
    }
}

impl From<Error> for RmdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => RmdirError::PathError(PathError::NoSuchFileOrDirectory),
            Error::NotADirectory => RmdirError::NotADirectory,
            Error::PermissionDenied => RmdirError::NoWritePerms,
            Error::InvalidPathname => RmdirError::PathError(PathError::InvalidPathname),
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::AlreadyExists
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to RmdirError"),
        }
    }
}

impl From<Error> for FileStatusError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => FileStatusError::PathError(PathError::NoSuchFileOrDirectory),
            Error::InvalidPathname => FileStatusError::PathError(PathError::InvalidPathname),
            Error::NotADirectory => FileStatusError::PathError(PathError::ComponentNotADirectory),
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::AlreadyExists
            | Error::PermissionDenied
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to FileStatusError"),
        }
    }
}

impl From<Error> for SeekError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => SeekError::ClosedFd,
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::InvalidPathname
            | Error::AlreadyExists
            | Error::PermissionDenied
            | Error::NotADirectory
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to SeekError"),
        }
    }
}

impl From<Error> for TruncateError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => TruncateError::ClosedFd,
            Error::IsADirectory => TruncateError::IsDirectory,
            Error::PermissionDenied => TruncateError::NotForWriting,
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::InvalidPathname
            | Error::AlreadyExists
            | Error::NotADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to TruncateError"),
        }
    }
}

impl From<Error> for ChmodError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => ChmodError::PathError(PathError::NoSuchFileOrDirectory),
            Error::InvalidPathname => ChmodError::PathError(PathError::InvalidPathname),
            Error::NotADirectory => ChmodError::PathError(PathError::ComponentNotADirectory),
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::AlreadyExists
            | Error::PermissionDenied
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to ChmodError"),
        }
    }
}

impl From<Error> for ChownError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => ChownError::PathError(PathError::NoSuchFileOrDirectory),
            Error::InvalidPathname => ChownError::PathError(PathError::InvalidPathname),
            Error::NotADirectory => ChownError::PathError(PathError::ComponentNotADirectory),
            Error::Io
            | Error::InvalidInput
            | Error::InvalidResponse
            | Error::AlreadyExists
            | Error::PermissionDenied
            | Error::IsADirectory
            | Error::NameTooLong
            | Error::Connection
            | Error::NotSupported => unimplemented!("convert {e:?} to ChownError"),
        }
    }
}

/// Convert remote error code to our Error type
impl From<Rlerror> for Error {
    fn from(err: Rlerror) -> Self {
        // Common POSIX error codes
        const ENOENT: u32 = 2;
        const EACCES: u32 = 13;
        const EEXIST: u32 = 17;
        const ENOTDIR: u32 = 20;
        const EISDIR: u32 = 21;
        const ENAMETOOLONG: u32 = 36;
        const ENOSYS: u32 = 38;
        const EOPNOTSUPP: u32 = 95;

        match err.ecode {
            ENOENT => Error::NotFound,
            EACCES => Error::PermissionDenied,
            EEXIST => Error::AlreadyExists,
            ENOTDIR => Error::NotADirectory,
            EISDIR => Error::IsADirectory,
            ENAMETOOLONG => Error::NameTooLong,
            ENOSYS | EOPNOTSUPP => Error::NotSupported,
            // Unrecognized remote error codes are mapped to a generic I/O error.
            // This loses the specific error code but avoids panicking at runtime.
            _ => Error::Io,
        }
    }
}

/// A backing implementation for [`FileSystem`](super::FileSystem) using a 9P2000.L-based network
/// file system.
///
/// This filesystem implementation communicates with a 9P server to provide access to remote files.
/// All file operations are translated into 9P protocol messages that are sent to the server.
///
/// # Type Parameters
///
/// - `Platform`: The platform provider that supplies synchronization primitives and other
///   platform-specific functionality.
/// - `T`: The transport type that implements both `Read` and `Write` traits.
pub struct FileSystem<
    Platform: sync::RawSyncPrimitivesProvider,
    T: transport::Read + transport::Write,
> {
    /// Reference to the LiteBox instance
    litebox: LiteBox<Platform>,
    /// 9P client for protocol operations
    client: client::Client<Platform, T>,
    /// Root (attached to the root of the remote filesystem)
    root: (fcall::Qid, fcall::Fid, String),
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    /// Whether `unlinkat` is supported by the server
    unlinkat_supported: AtomicBool,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    FileSystem<Platform, T>
{
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    ///
    /// # Arguments
    ///
    /// * `litebox` - Reference to the LiteBox instance for platform access
    /// * `transport` - The transport for 9P communication
    /// * `msize` - Maximum message size to negotiate
    /// * `username` - Username for authentication
    /// * `path` - Attach path (typically the root directory path)
    ///
    /// # Errors
    ///
    /// Returns an error if version negotiation or attach fails.
    pub fn new(
        litebox: &LiteBox<Platform>,
        transport: T,
        msize: u32,
        username: &str,
        path: &str,
    ) -> Result<Self, Error> {
        let client = client::Client::new(transport, msize)?;
        let (qid, fid) = client.attach(username, path)?;

        Ok(Self {
            litebox: litebox.clone(),
            client,
            root: (qid, fid, String::from(path)),
            current_working_dir: String::from("/"),
            unlinkat_supported: AtomicBool::new(true),
        })
    }

    /// Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    /// for any relative paths from current working directory.
    ///
    /// Note: does NOT account for symlinks.
    fn absolute_path(&self, path: impl crate::path::Arg) -> Result<String, PathError> {
        assert!(self.current_working_dir.ends_with('/'));
        let path = path.as_rust_str()?;
        if path.starts_with('/') {
            // Absolute path
            Ok(path.normalized()?)
        } else {
            // Relative path
            Ok((self.current_working_dir.clone() + path.as_rust_str()?).normalized()?)
        }
    }

    /// Walk to a path and return the fid
    fn walk_to(&self, path: &str) -> Result<fcall::Fid, Error> {
        let components: Vec<&str> = path
            .normalized_components()
            .map_err(|_| Error::InvalidPathname)?
            .collect();
        if components.is_empty() {
            // Clone the root fid
            self.client.clone_fid(self.root.1)
        } else {
            let (_, fid) = self.client.walk(self.root.1, &components)?;
            Ok(fid)
        }
    }

    /// Walk to the parent of a path and return the parent fid and the name
    fn walk_to_parent<'a>(&self, path: &'a str) -> Result<(fcall::Fid, &'a str), Error> {
        let components: Vec<&str> = path
            .normalized_components()
            .map_err(|_| Error::InvalidPathname)?
            .collect();
        if components.is_empty() {
            return Err(Error::InvalidPathname);
        }

        let name = components.last().unwrap();
        let parent_components = &components[..components.len() - 1];

        if parent_components.is_empty() {
            let parent_fid = self.client.clone_fid(self.root.1)?;
            Ok((parent_fid, name))
        } else {
            let (_, parent_fid) = self.client.walk(self.root.1, parent_components)?;
            Ok((parent_fid, name))
        }
    }

    /// Convert FileSystem OFlags to 9P LOpenFlags
    fn oflags_to_lopen(flags: super::OFlags) -> fcall::LOpenFlags {
        let mut lflags = fcall::LOpenFlags::empty();

        // Access mode (RDONLY is 0, so we only check for WRONLY and RDWR)
        if flags.contains(super::OFlags::RDWR) {
            lflags |= fcall::LOpenFlags::O_RDWR;
        } else if flags.contains(super::OFlags::WRONLY) {
            lflags |= fcall::LOpenFlags::O_WRONLY;
        }
        // RDONLY is implicit if neither WRONLY nor RDWR

        if flags.contains(super::OFlags::CREAT) {
            lflags |= fcall::LOpenFlags::O_CREAT;
        }
        if flags.contains(super::OFlags::EXCL) {
            lflags |= fcall::LOpenFlags::O_EXCL;
        }
        if flags.contains(super::OFlags::TRUNC) {
            lflags |= fcall::LOpenFlags::O_TRUNC;
        }
        if flags.contains(super::OFlags::APPEND) {
            lflags |= fcall::LOpenFlags::O_APPEND;
        }
        if flags.contains(super::OFlags::DIRECTORY) {
            lflags |= fcall::LOpenFlags::O_DIRECTORY;
        }
        if flags.contains(super::OFlags::NOFOLLOW) {
            lflags |= fcall::LOpenFlags::O_NOFOLLOW;
        }
        if flags.contains(super::OFlags::NONBLOCK) {
            lflags |= fcall::LOpenFlags::O_NONBLOCK;
        }
        if flags.contains(super::OFlags::SYNC) {
            lflags |= fcall::LOpenFlags::O_SYNC;
        }
        if flags.contains(super::OFlags::DSYNC) {
            lflags |= fcall::LOpenFlags::O_DSYNC;
        }
        if flags.contains(super::OFlags::DIRECT) {
            lflags |= fcall::LOpenFlags::O_DIRECT;
        }
        if flags.contains(super::OFlags::NOATIME) {
            lflags |= fcall::LOpenFlags::O_NOATIME;
        }

        lflags
    }

    /// Convert a Qid type to our FileType
    fn qid_type_to_file_type(qid_type: fcall::QidType) -> super::FileType {
        if qid_type.contains(fcall::QidType::DIR) {
            super::FileType::Directory
        } else {
            super::FileType::RegularFile
        }
    }

    /// Convert getattr response to FileStatus
    fn rgetattr_to_file_status(attr: &fcall::Rgetattr) -> super::FileStatus {
        let file_type = Self::qid_type_to_file_type(attr.qid.typ);

        if attr.valid.contains(fcall::GetattrMask::BASIC) {
            super::FileStatus {
                file_type,
                mode: super::Mode::from_bits_truncate(attr.stat.mode),
                size: attr.stat.size as usize,
                owner: super::UserInfo {
                    user: attr.stat.uid as u16,
                    group: attr.stat.gid as u16,
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: attr.qid.path as usize,
                    rdev: NonZeroUsize::new(attr.stat.rdev as usize),
                },
                blksize: attr.stat.blksize as usize,
            }
        } else {
            super::FileStatus {
                file_type,
                mode: if attr.valid.contains(fcall::GetattrMask::MODE) {
                    super::Mode::from_bits_truncate(attr.stat.mode)
                } else {
                    super::Mode::empty()
                },
                size: if attr.valid.contains(fcall::GetattrMask::SIZE) {
                    attr.stat.size as usize
                } else {
                    0
                },
                owner: super::UserInfo {
                    user: if attr.valid.contains(fcall::GetattrMask::UID) {
                        attr.stat.uid as u16
                    } else {
                        0
                    },
                    group: if attr.valid.contains(fcall::GetattrMask::GID) {
                        attr.stat.gid as u16
                    } else {
                        0
                    },
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: attr.qid.path as usize,
                    rdev: if attr.valid.contains(fcall::GetattrMask::RDEV) {
                        NonZeroUsize::new(attr.stat.rdev as usize)
                    } else {
                        None
                    },
                },
                blksize: if attr.valid.contains(fcall::GetattrMask::BLOCKS) {
                    attr.stat.blksize as usize
                } else {
                    0
                },
            }
        }
    }

    fn remove_file_or_dir(&self, path: impl crate::path::Arg, is_file: bool) -> Result<(), Error> {
        const AT_REMOVEDIR: u32 = 0x200;

        let path = self
            .absolute_path(path)
            .map_err(|_| Error::InvalidPathname)?;
        if self.unlinkat_supported.load(Ordering::SeqCst) {
            let (parent_fid, name) = self.walk_to_parent(&path)?;

            let result =
                self.client
                    .unlinkat(parent_fid, name, if is_file { 0 } else { AT_REMOVEDIR });
            let _ = self.client.clunk(parent_fid);
            if let Err(Error::NotSupported) = &result {
                self.unlinkat_supported.store(false, Ordering::SeqCst);
                // fall back to to `remove`
            } else {
                return result;
            }
        }

        let fid = self.walk_to(&path)?;
        let result = self.client.remove(fid);
        self.client.free_fid(fid);
        result
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    super::private::Sealed for FileSystem<Platform, T>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    super::FileSystem for FileSystem<Platform, T>
{
    #[expect(clippy::similar_names)]
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform, T>, super::errors::OpenError> {
        let currently_supported_oflags: OFlags = OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::CREAT
            | OFlags::NOCTTY
            | OFlags::EXCL
            | OFlags::DIRECTORY
            | OFlags::LARGEFILE;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!("{flags:?}")
        }

        let path = self.absolute_path(path)?;
        let components: Vec<&str> = path.normalized_components().map_err(|_| OpenError::PathError(PathError::InvalidPathname))?.collect();
        let lflags = Self::oflags_to_lopen(flags);
        let needs_create = flags.contains(super::OFlags::CREAT);

        let (new_qid, new_fid) = if needs_create {
            let (_, dfid) = self
                .client
                .walk(self.root.1, &components[..components.len() - 1])?;
            self.client
                .create(dfid, components.last().unwrap(), lflags, mode.bits(), 0)?
        } else {
            let (_, new_fid) = self.client.walk(self.root.1, &components)?;
            let qid = self.client.open(new_fid, lflags)?;
            (qid, new_fid)
        };

        let descriptor = Descriptor {
            fid: new_fid,
            offset: AtomicU64::new(0),
            qid: new_qid,
        };

        let fd = self.litebox.descriptor_table_mut().insert(descriptor);
        Ok(fd)
    }

    fn close(&self, fd: &FileFd<Platform, T>) -> Result<(), super::errors::CloseError> {
        let entry = self.litebox.descriptor_table_mut().remove(fd);
        if let Some(entry) = entry {
            let _ = self.client.clunk(entry.entry.fid);
        }
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform, T>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::ReadError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(super::errors::ReadError::ClosedFd)?;
        let desc = &entry.entry;

        // Determine offset to use
        let read_offset = match offset {
            Some(o) => o as u64,
            None => desc.offset.load(Ordering::SeqCst),
        };

        // TODO: read might be blocking while holding up the descriptor table lock.
        // We should consider releasing the lock before doing the read.
        let bytes_read = self.client.read(desc.fid, read_offset, buf)?;

        // Update offset if not using explicit offset
        if offset.is_none() {
            desc.offset.fetch_add(bytes_read as u64, Ordering::SeqCst);
        }

        Ok(bytes_read)
    }

    fn write(
        &self,
        fd: &FileFd<Platform, T>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::WriteError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(super::errors::WriteError::ClosedFd)?;
        let desc = &entry.entry;

        // Determine offset to use
        let write_offset = match offset {
            Some(o) => o as u64,
            None => desc.offset.load(Ordering::SeqCst),
        };

        // TODO: write might be blocking while holding up the descriptor table lock.
        // We should consider releasing the lock before doing the write.
        let bytes_written = self.client.write(desc.fid, write_offset, buf)?;

        // Update offset if not using explicit offset
        if offset.is_none() {
            desc.offset
                .fetch_add(bytes_written as u64, Ordering::SeqCst);
        }

        Ok(bytes_written as usize)
    }

    fn seek(
        &self,
        fd: &FileFd<Platform, T>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd).ok_or(SeekError::ClosedFd)?;
        let desc = &entry.entry;

        let current_offset = desc.offset.load(Ordering::SeqCst);

        let base = match whence {
            super::SeekWhence::RelativeToBeginning => 0,
            super::SeekWhence::RelativeToCurrentOffset => current_offset,
            super::SeekWhence::RelativeToEnd => {
                // Need to get file size
                let attr = self.client.getattr(desc.fid, fcall::GetattrMask::SIZE)?;
                attr.stat.size
            }
        };
        let new_offset = base
            .checked_add_signed(offset as i64)
            .ok_or(SeekError::InvalidOffset)?;

        desc.offset.store(new_offset, Ordering::SeqCst);
        Ok(new_offset as usize)
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform, T>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), super::errors::TruncateError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(super::errors::TruncateError::ClosedFd)?;
        let desc = &entry.entry;

        if desc.qid.typ.contains(fcall::QidType::DIR) {
            return Err(super::errors::TruncateError::IsDirectory);
        }

        let stat = fcall::SetAttr {
            mode: 0,
            uid: 0,
            gid: 0,
            size: length as u64,
            atime: fcall::Time::default(),
            mtime: fcall::Time::default(),
        };

        self.client
            .setattr(desc.fid, fcall::SetattrMask::SIZE, stat)?;

        if reset_offset {
            desc.offset.store(0, Ordering::SeqCst);
        }

        Ok(())
    }

    fn chmod(
        &self,
        path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), super::errors::ChmodError> {
        let path = self.absolute_path(path)?;
        let fid = self.walk_to(&path)?;

        let stat = fcall::SetAttr {
            mode: mode.bits(),
            uid: 0,
            gid: 0,
            size: 0,
            atime: fcall::Time::default(),
            mtime: fcall::Time::default(),
        };

        let result = self.client.setattr(fid, fcall::SetattrMask::MODE, stat);
        let _ = self.client.clunk(fid);

        result.map_err(ChmodError::from)
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), super::errors::ChownError> {
        let path = self.absolute_path(path)?;
        let fid = self.walk_to(&path)?;

        let mut valid = fcall::SetattrMask::empty();
        let uid = match user {
            Some(u) => {
                valid |= fcall::SetattrMask::UID;
                u as u32
            }
            None => 0,
        };
        let gid = match group {
            Some(g) => {
                valid |= fcall::SetattrMask::GID;
                g as u32
            }
            None => 0,
        };
        let stat = fcall::SetAttr {
            mode: 0,
            uid,
            gid,
            size: 0,
            atime: fcall::Time::default(),
            mtime: fcall::Time::default(),
        };

        let result = self.client.setattr(fid, valid, stat);
        let _ = self.client.clunk(fid);

        result.map_err(ChownError::from)
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), super::errors::UnlinkError> {
        self.remove_file_or_dir(path, true)
            .map_err(UnlinkError::from)
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;

        let (parent_fid, name) = self.walk_to_parent(&path)?;

        let result = self.client.mkdir(parent_fid, name, mode.bits(), 0);
        let _ = self.client.clunk(parent_fid);

        result.map(|_| ()).map_err(MkdirError::from)
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        self.remove_file_or_dir(path, false)
            .map_err(RmdirError::from)
    }

    fn read_dir(
        &self,
        fd: &FileFd<Platform, T>,
    ) -> Result<Vec<crate::fs::DirEntry>, super::errors::ReadDirError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(super::errors::ReadDirError::ClosedFd)?;
        let desc = &entry.entry;

        if !desc.qid.typ.contains(fcall::QidType::DIR) {
            return Err(super::errors::ReadDirError::NotADirectory);
        }

        // TODO: read_dir might be blocking while holding up the descriptor table lock.
        // We should consider releasing the lock before doing the read_dir.
        let entries = self.client.readdir_all(desc.fid)?;

        let dir_entries: Vec<super::DirEntry> = entries
            .into_iter()
            .map(|e| {
                let file_type = if e.typ == fcall::QidType::DIR.bits() {
                    super::FileType::Directory
                } else {
                    super::FileType::RegularFile
                };

                super::DirEntry {
                    name: String::from_utf8_lossy(e.name.as_bytes()).into_owned(),
                    file_type,
                    ino_info: Some(super::NodeInfo {
                        dev: DEVICE_ID,
                        ino: e.qid.path as usize,
                        rdev: None,
                    }),
                }
            })
            .collect();

        Ok(dir_entries)
    }

    fn file_status(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<super::FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        let fid = self.walk_to(&path)?;

        let result = self.client.getattr(fid, fcall::GetattrMask::ALL);
        let _ = self.client.clunk(fid);

        result
            .map(|attr| Self::rgetattr_to_file_status(&attr))
            .map_err(FileStatusError::from)
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform, T>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(super::errors::FileStatusError::ClosedFd)?;
        let desc = &entry.entry;

        let attr = self.client.getattr(desc.fid, fcall::GetattrMask::ALL)?;

        Ok(Self::rgetattr_to_file_status(&attr))
    }
}

/// Internal descriptor state for a 9P file descriptor
#[derive(Debug)]
struct Descriptor {
    /// The 9P fid for this file
    fid: fcall::Fid,
    /// Current file offset (9P doesn't track this server-side)
    offset: AtomicU64,
    /// Whether this file is opened for reading
    // read_allowed: bool,
    /// Whether this file is opened for writing
    // write_allowed: bool,
    /// The qid of the file (contains type and unique ID)
    qid: fcall::Qid,
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, T: { transport::Read + transport::Write };
    FileSystem<Platform, T>;
    Descriptor;
    -> FileFd<Platform, T>;
}

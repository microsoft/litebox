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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

#[cfg(test)]
mod tests;

const DEVICE_ID: usize = u32::from_le_bytes(*b"NINE") as usize;

// Common POSIX error codes used when converting remote errors to specific FS error types.
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EACCES: u32 = 13;
const EEXIST: u32 = 17;
const ENOTDIR: u32 = 20;
const EISDIR: u32 = 21;
const EINVAL: u32 = 22;
const ESPIPE: u32 = 29;
const ENAMETOOLONG: u32 = 36;
const ENOSYS: u32 = 38;
const ENOTEMPTY: u32 = 39;
const EOPNOTSUPP: u32 = 95;

/// Error type for 9P operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io,

    #[error("Invalid response from server")]
    InvalidResponse,

    #[error("Invalid pathname")]
    InvalidPathname,

    /// Error reported by the 9P server, carrying the raw errno
    #[error("Remote error (errno={0})")]
    Remote(u32),
}

impl From<Error> for OpenError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => OpenError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => OpenError::PathError(PathError::NoSuchFileOrDirectory),
                EEXIST => OpenError::AlreadyExists,
                EPERM | EACCES => OpenError::AccessNotAllowed,
                ENOTDIR => OpenError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => OpenError::PathError(PathError::InvalidPathname),
                _ => OpenError::Io,
            },
            Error::Io | Error::InvalidResponse => OpenError::Io,
        }
    }
}

impl From<Error> for ReadError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | EISDIR => ReadError::NotAFile,
                EPERM | EACCES => ReadError::NotForReading,
                _ => ReadError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => ReadError::Io,
        }
    }
}

impl From<Error> for WriteError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | EISDIR => WriteError::NotAFile,
                EPERM | EACCES => WriteError::NotForWriting,
                _ => WriteError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => WriteError::Io,
        }
    }
}

impl From<Error> for MkdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => MkdirError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => MkdirError::PathError(PathError::NoSuchFileOrDirectory),
                EEXIST => MkdirError::AlreadyExists,
                EPERM | EACCES => MkdirError::NoWritePerms,
                ENOTDIR => MkdirError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => MkdirError::PathError(PathError::InvalidPathname),
                _ => MkdirError::Io,
            },
            Error::Io | Error::InvalidResponse => MkdirError::Io,
        }
    }
}

impl From<Error> for ReadDirError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | ENOTDIR => ReadDirError::NotADirectory,
                _ => ReadDirError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => ReadDirError::Io,
        }
    }
}

impl From<Error> for UnlinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => UnlinkError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => UnlinkError::PathError(PathError::NoSuchFileOrDirectory),
                EISDIR => UnlinkError::IsADirectory,
                EPERM | EACCES => UnlinkError::NoWritePerms,
                ENOTDIR => UnlinkError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => UnlinkError::PathError(PathError::InvalidPathname),
                _ => UnlinkError::Io,
            },
            Error::Io | Error::InvalidResponse => UnlinkError::Io,
        }
    }
}

impl From<Error> for RmdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => RmdirError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => RmdirError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => RmdirError::NotADirectory,
                EPERM | EACCES => RmdirError::NoWritePerms,
                ENAMETOOLONG => RmdirError::PathError(PathError::InvalidPathname),
                ENOTEMPTY => RmdirError::NotEmpty,
                _ => RmdirError::Io,
            },
            Error::Io | Error::InvalidResponse => RmdirError::Io,
        }
    }
}

impl From<Error> for FileStatusError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => FileStatusError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => FileStatusError::PathError(PathError::NoSuchFileOrDirectory),
                ENAMETOOLONG => FileStatusError::PathError(PathError::InvalidPathname),
                ENOTDIR => FileStatusError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => FileStatusError::PathError(PathError::NoSearchPerms {
                    #[cfg(debug_assertions)]
                    dir: String::new(),
                    #[cfg(debug_assertions)]
                    perms: super::Mode::empty(),
                }),
                _ => FileStatusError::Io,
            },
            Error::Io | Error::InvalidResponse => FileStatusError::Io,
        }
    }
}

impl From<Error> for SeekError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(e) => match e {
                ENOENT => SeekError::ClosedFd,
                EINVAL => SeekError::InvalidOffset,
                ESPIPE => SeekError::NonSeekable,
                _ => SeekError::Io,
            },
            _ => SeekError::Io,
        }
    }
}

impl From<Error> for TruncateError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT => TruncateError::ClosedFd,
                EISDIR => TruncateError::IsDirectory,
                EPERM | EACCES => TruncateError::NotForWriting,
                _ => TruncateError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => TruncateError::Io,
        }
    }
}

impl From<Error> for ChmodError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => ChmodError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => ChmodError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => ChmodError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => ChmodError::NotTheOwner,
                _ => ChmodError::Io,
            },
            Error::Io | Error::InvalidResponse => ChmodError::Io,
        }
    }
}

impl From<Error> for ChownError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => ChownError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => ChownError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => ChownError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => ChownError::NotTheOwner,
                _ => ChownError::Io,
            },
            Error::Io | Error::InvalidResponse => ChownError::Io,
        }
    }
}

impl From<Rlerror> for Error {
    fn from(err: Rlerror) -> Self {
        Error::Remote(err.ecode)
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
                size: usize::try_from(attr.stat.size).expect("file size exceeds usize"),
                owner: super::UserInfo {
                    user: u16::try_from(attr.stat.uid).expect("uid exceeds u16"),
                    group: u16::try_from(attr.stat.gid).expect("gid exceeds u16"),
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: usize::try_from(attr.qid.path).expect("inode number exceeds usize"),
                    rdev: NonZeroUsize::new(
                        usize::try_from(attr.stat.rdev).expect("rdev exceeds usize"),
                    ),
                },
                blksize: usize::try_from(attr.stat.blksize).expect("block size exceeds usize"),
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
                    usize::try_from(attr.stat.size).expect("file size exceeds usize")
                } else {
                    0
                },
                owner: super::UserInfo {
                    user: if attr.valid.contains(fcall::GetattrMask::UID) {
                        u16::try_from(attr.stat.uid).expect("uid exceeds u16")
                    } else {
                        0
                    },
                    group: if attr.valid.contains(fcall::GetattrMask::GID) {
                        u16::try_from(attr.stat.gid).expect("gid exceeds u16")
                    } else {
                        0
                    },
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: usize::try_from(attr.qid.path).expect("inode number exceeds usize"),
                    rdev: if attr.valid.contains(fcall::GetattrMask::RDEV) {
                        NonZeroUsize::new(
                            usize::try_from(attr.stat.rdev).expect("rdev exceeds usize"),
                        )
                    } else {
                        None
                    },
                },
                blksize: if attr.valid.contains(fcall::GetattrMask::BLOCKS) {
                    usize::try_from(attr.stat.blksize).expect("block size exceeds usize")
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
            if let Err(Error::Remote(ENOSYS | EOPNOTSUPP)) = &result {
                self.unlinkat_supported.store(false, Ordering::SeqCst);
                // fall back to `remove`
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

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write> Drop
    for FileSystem<Platform, T>
{
    fn drop(&mut self) {
        let _ = self.client.clunk(self.root.1);
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    super::private::Sealed for FileSystem<Platform, T>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    super::FileSystem for FileSystem<Platform, T>
{
    #[allow(clippy::similar_names)]
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
        let components: Vec<&str> = path
            .normalized_components()
            .map_err(|_| OpenError::PathError(PathError::InvalidPathname))?
            .collect();
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
            offset: AtomicUsize::new(0),
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
        // Extract fid and current offset, releasing the descriptor table lock
        // before performing potentially blocking I/O.
        let (fid, current_offset) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| {
                (desc.entry.fid, desc.entry.offset.load(Ordering::SeqCst))
            })
            .ok_or(super::errors::ReadError::ClosedFd)?;

        let read_offset = match offset {
            Some(o) => o,
            None => current_offset,
        };

        let bytes_read = self.client.read(fid, read_offset as u64, buf)?;

        // Update offset if not using explicit offset
        if offset.is_none() {
            self.litebox.descriptor_table().with_entry(fd, |desc| {
                desc.entry.offset.fetch_add(bytes_read, Ordering::SeqCst);
            });
        }

        Ok(bytes_read)
    }

    fn write(
        &self,
        fd: &FileFd<Platform, T>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::WriteError> {
        // Extract fid and current offset, releasing the descriptor table lock
        // before performing potentially blocking I/O.
        let (fid, current_offset) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| {
                (desc.entry.fid, desc.entry.offset.load(Ordering::SeqCst))
            })
            .ok_or(super::errors::WriteError::ClosedFd)?;

        let write_offset = match offset {
            Some(o) => o,
            None => current_offset,
        };

        let bytes_written = self.client.write(fid, write_offset as u64, buf)?;

        // Update offset if not using explicit offset
        if offset.is_none() {
            self.litebox.descriptor_table().with_entry(fd, |desc| {
                desc.entry.offset.fetch_add(bytes_written, Ordering::SeqCst);
            });
        }

        Ok(bytes_written)
    }

    fn seek(
        &self,
        fd: &FileFd<Platform, T>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        // Extract fid and current offset, releasing the descriptor table lock
        // before performing potentially blocking I/O (getattr for SeekWhence::RelativeToEnd).
        let (fid, current_offset) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| {
                (desc.entry.fid, desc.entry.offset.load(Ordering::SeqCst))
            })
            .ok_or(SeekError::ClosedFd)?;

        let base = match whence {
            super::SeekWhence::RelativeToBeginning => 0,
            super::SeekWhence::RelativeToCurrentOffset => current_offset,
            super::SeekWhence::RelativeToEnd => {
                let attr = self.client.getattr(fid, fcall::GetattrMask::SIZE)?;
                usize::try_from(attr.stat.size).expect("file size exceeds usize")
            }
        };
        let new_offset = base
            .checked_add_signed(offset)
            .ok_or(SeekError::InvalidOffset)?;

        self.litebox.descriptor_table().with_entry(fd, |desc| {
            desc.entry.offset.store(new_offset, Ordering::SeqCst);
        });
        Ok(new_offset)
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform, T>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), super::errors::TruncateError> {
        // Extract fid and qid, releasing the descriptor table lock
        // before performing potentially blocking I/O.
        let (fid, qid) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| (desc.entry.fid, desc.entry.qid))
            .ok_or(super::errors::TruncateError::ClosedFd)?;

        if qid.typ.contains(fcall::QidType::DIR) {
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

        self.client.setattr(fid, fcall::SetattrMask::SIZE, stat)?;

        if reset_offset {
            self.litebox.descriptor_table().with_entry(fd, |desc| {
                desc.entry.offset.store(0, Ordering::SeqCst);
            });
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
                u32::from(u)
            }
            None => 0,
        };
        let gid = match group {
            Some(g) => {
                valid |= fcall::SetattrMask::GID;
                u32::from(g)
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
        // Extract fid and qid, releasing the descriptor table lock
        // before performing potentially blocking I/O.
        let (fid, qid) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| (desc.entry.fid, desc.entry.qid))
            .ok_or(super::errors::ReadDirError::ClosedFd)?;

        if !qid.typ.contains(fcall::QidType::DIR) {
            return Err(super::errors::ReadDirError::NotADirectory);
        }

        // Perform blocking I/O without holding any locks.
        let entries = self.client.readdir_all(fid)?;

        let dir_entries: Vec<super::DirEntry> = entries
            .into_iter()
            .map(|e| {
                let file_type = if e.typ == fcall::QidType::DIR.bits() {
                    super::FileType::Directory
                } else {
                    super::FileType::RegularFile
                };

                super::DirEntry {
                    name: String::from_utf8_lossy(&e.name).into_owned(),
                    file_type,
                    ino_info: Some(super::NodeInfo {
                        dev: DEVICE_ID,
                        ino: usize::try_from(e.qid.path).expect("inode number exceeds usize"),
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
        // Extract fid, releasing the descriptor table lock
        // before performing potentially blocking I/O.
        let fid = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.fid)
            .ok_or(super::errors::FileStatusError::ClosedFd)?;

        // Perform blocking I/O without holding any locks.
        let attr = self.client.getattr(fid, fcall::GetattrMask::ALL)?;

        Ok(Self::rgetattr_to_file_status(&attr))
    }
}

/// Internal descriptor state for a 9P file descriptor
#[derive(Debug)]
struct Descriptor {
    /// The 9P fid for this file
    fid: fcall::Fid,
    /// Current file offset (9P doesn't track this server-side)
    offset: AtomicUsize,
    /// The qid of the file (contains type and unique ID)
    qid: fcall::Qid,
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, T: { transport::Read + transport::Write };
    FileSystem<Platform, T>;
    Descriptor;
    -> FileFd<Platform, T>;
}

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
//! - `cursor` - Write cursor utilities for message encoding
//! - `transport` - Transport layer traits and message I/O
//! - `client` - High-level 9P client for protocol operations

// Protocol implementation requires various casts that are known to be safe
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::{LiteBox, sync};

mod client;
mod cursor;
mod fcall;

pub mod transport;

/// Error type for 9P operations
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error during transport
    #[error("I/O error")]
    Io,

    /// Invalid input (e.g., malformed protocol message)
    #[error("Invalid input")]
    InvalidInput,

    /// Remote error from the 9P server
    #[error("Remote error: {0}")]
    Remote(u32),

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

/// Convert remote error code to our Error type
impl From<u32> for Error {
    fn from(ecode: u32) -> Self {
        // Common POSIX error codes
        const ENOENT: u32 = 2;
        const EACCES: u32 = 13;
        const EEXIST: u32 = 17;
        const ENOTDIR: u32 = 20;
        const EISDIR: u32 = 21;
        const ENAMETOOLONG: u32 = 36;
        const ENOSYS: u32 = 38;
        const EOPNOTSUPP: u32 = 95;

        match ecode {
            ENOENT => Error::NotFound,
            EACCES => Error::PermissionDenied,
            EEXIST => Error::AlreadyExists,
            ENOTDIR => Error::NotADirectory,
            EISDIR => Error::IsADirectory,
            ENAMETOOLONG => Error::NameTooLong,
            ENOSYS | EOPNOTSUPP => Error::NotSupported,
            _ => Error::Remote(ecode),
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
    /// Root fid (attached to the root of the remote filesystem)
    root_fid: fcall::Fid,
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
    /// * `aname` - Attach name (typically the root directory path)
    ///
    /// # Errors
    ///
    /// Returns an error if version negotiation or attach fails.
    pub fn new(
        litebox: &LiteBox<Platform>,
        transport: T,
        msize: u32,
        aname: &str,
    ) -> Result<Self, Error> {
        let client = client::Client::new(transport, msize)?;
        let (_, root_fid) = client.attach("", aname)?;

        Ok(Self {
            litebox: litebox.clone(),
            client,
            root_fid,
        })
    }

    /// Parse a path string and split it into path components
    fn parse_path(path: &str) -> Vec<&str> {
        path.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect()
    }

    /// Walk to a path and return the fid
    fn walk_to(&self, path: &str) -> Result<fcall::Fid, Error> {
        let components = Self::parse_path(path);
        if components.is_empty() {
            // Clone the root fid
            self.client.clone_fid(self.root_fid)
        } else {
            let (_, fid) = self.client.walk(self.root_fid, &components)?;
            Ok(fid)
        }
    }

    /// Walk to the parent of a path and return the parent fid and the name
    fn walk_to_parent<'a>(&self, path: &'a str) -> Result<(fcall::Fid, &'a str), Error> {
        let components = Self::parse_path(path);
        if components.is_empty() {
            return Err(Error::InvalidInput);
        }

        let name = components.last().unwrap();
        let parent_components = &components[..components.len() - 1];

        if parent_components.is_empty() {
            let parent_fid = self.client.clone_fid(self.root_fid)?;
            Ok((parent_fid, name))
        } else {
            let (_, parent_fid) = self.client.walk(self.root_fid, parent_components)?;
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

        super::FileStatus {
            file_type,
            mode: super::Mode::from_bits_truncate(attr.stat.mode),
            size: attr.stat.size as usize,
            owner: super::UserInfo {
                user: attr.stat.uid as u16,
                group: attr.stat.gid as u16,
            },
            node_info: super::NodeInfo {
                dev: attr.stat.rdev as usize,
                ino: attr.qid.path as usize,
                rdev: NonZeroUsize::new(attr.stat.rdev as usize),
            },
            blksize: attr.stat.blksize as usize,
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    super::private::Sealed for FileSystem<Platform, T>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    super::FileSystem for FileSystem<Platform, T>
{
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform, T>, super::errors::OpenError> {
        let path_str = path
            .as_rust_str()
            .map_err(|_| super::errors::PathError::InvalidPathname)?;

        let lflags = Self::oflags_to_lopen(flags);
        let needs_create = flags.contains(super::OFlags::CREAT);

        // Determine read/write permissions from flags
        let read_allowed = !flags.contains(super::OFlags::WRONLY);
        let write_allowed =
            flags.contains(super::OFlags::WRONLY) || flags.contains(super::OFlags::RDWR);

        let (fid, qid) = if needs_create {
            // Try to walk to the parent and create the file
            let (parent_fid, name) = self
                .walk_to_parent(path_str)
                .map_err(|_| super::errors::PathError::NoSuchFileOrDirectory)?;

            match self.client.create(parent_fid, name, lflags, mode.bits(), 0) {
                Ok(r) => {
                    // create() transforms the parent_fid into the file fid
                    (parent_fid, r.qid)
                }
                Err(Error::AlreadyExists) if !flags.contains(super::OFlags::EXCL) => {
                    // File exists and EXCL is not set, try to open it
                    let _ = self.client.clunk(parent_fid);
                    let fid = self
                        .walk_to(path_str)
                        .map_err(|_| super::errors::PathError::NoSuchFileOrDirectory)?;
                    let r = self.client.open(fid, lflags).map_err(|_| {
                        let _ = self.client.clunk(fid);
                        super::errors::OpenError::AccessNotAllowed
                    })?;
                    (fid, r.qid)
                }
                Err(Error::AlreadyExists) => {
                    let _ = self.client.clunk(parent_fid);
                    return Err(super::errors::OpenError::AlreadyExists);
                }
                Err(_) => {
                    let _ = self.client.clunk(parent_fid);
                    return Err(super::errors::OpenError::AccessNotAllowed);
                }
            }
        } else {
            // Just walk and open
            let fid = self
                .walk_to(path_str)
                .map_err(|_| super::errors::PathError::NoSuchFileOrDirectory)?;
            let r = self.client.open(fid, lflags).map_err(|_| {
                let _ = self.client.clunk(fid);
                super::errors::OpenError::AccessNotAllowed
            })?;
            (fid, r.qid)
        };

        // Wrap in a file descriptor
        let descriptor = Descriptor {
            fid,
            offset: AtomicU64::new(0),
            read_allowed,
            write_allowed,
            qid,
        };

        let fd = self.litebox.descriptor_table_mut().insert(descriptor);
        Ok(fd)
    }

    fn close(&self, fd: &FileFd<Platform, T>) -> Result<(), super::errors::CloseError> {
        let descriptor_table = self.litebox.descriptor_table();
        if let Some(entry) = descriptor_table.get_entry(fd) {
            let _ = self.client.clunk(entry.entry.fid);
        }
        self.litebox.descriptor_table_mut().remove(fd);
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

        if !desc.read_allowed {
            return Err(super::errors::ReadError::NotForReading);
        }

        // Determine offset to use
        let read_offset = match offset {
            Some(o) => o as u64,
            None => desc.offset.load(Ordering::SeqCst),
        };

        // Read data
        let count = buf
            .len()
            .min((self.client.msize() - fcall::IOHDRSZ) as usize);
        let data = self
            .client
            .read(desc.fid, read_offset, count as u32)
            .map_err(|_| super::errors::ReadError::ClosedFd)?;

        let bytes_read = data.len();
        buf[..bytes_read].copy_from_slice(&data);

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

        if !desc.write_allowed {
            return Err(super::errors::WriteError::NotForWriting);
        }

        // Determine offset to use
        let write_offset = match offset {
            Some(o) => o as u64,
            None => desc.offset.load(Ordering::SeqCst),
        };

        // Write data
        let bytes_written = self
            .client
            .write(desc.fid, write_offset, buf)
            .map_err(|_| super::errors::WriteError::ClosedFd)?;

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
    ) -> Result<usize, super::errors::SeekError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(super::errors::SeekError::ClosedFd)?;
        let desc = &entry.entry;

        let current_offset = desc.offset.load(Ordering::SeqCst);

        let new_offset = match whence {
            super::SeekWhence::RelativeToBeginning => {
                if offset < 0 {
                    return Err(super::errors::SeekError::InvalidOffset);
                }
                offset as u64
            }
            super::SeekWhence::RelativeToCurrentOffset => {
                if offset < 0 {
                    let neg_offset = (-offset) as u64;
                    if neg_offset > current_offset {
                        return Err(super::errors::SeekError::InvalidOffset);
                    }
                    current_offset - neg_offset
                } else {
                    current_offset + offset as u64
                }
            }
            super::SeekWhence::RelativeToEnd => {
                // Need to get file size
                let attr = self
                    .client
                    .getattr(desc.fid, fcall::GetattrMask::SIZE)
                    .map_err(|_| super::errors::SeekError::ClosedFd)?;
                let size = attr.stat.size;

                if offset < 0 {
                    let neg_offset = (-offset) as u64;
                    if neg_offset > size {
                        return Err(super::errors::SeekError::InvalidOffset);
                    }
                    size - neg_offset
                } else {
                    size + offset as u64
                }
            }
        };

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

        if !desc.write_allowed {
            return Err(super::errors::TruncateError::NotForWriting);
        }

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
            .setattr(desc.fid, fcall::SetattrMask::SIZE, stat)
            .map_err(|_| super::errors::TruncateError::ClosedFd)?;

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
        let path_str = path
            .as_rust_str()
            .map_err(|_| super::errors::PathError::InvalidPathname)?;

        let fid = self.walk_to(path_str).map_err(|e| match e {
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            _ => super::errors::ChmodError::ReadOnlyFileSystem,
        })?;

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

        result.map_err(|_| super::errors::ChmodError::NotTheOwner)
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), super::errors::ChownError> {
        let path_str = path
            .as_rust_str()
            .map_err(|_| super::errors::PathError::InvalidPathname)?;

        let fid = self.walk_to(path_str).map_err(|e| match e {
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            _ => super::errors::ChownError::ReadOnlyFileSystem,
        })?;

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

        result.map_err(|_| super::errors::ChownError::NotTheOwner)
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), super::errors::UnlinkError> {
        let path_str = path
            .as_rust_str()
            .map_err(|_| super::errors::PathError::InvalidPathname)?;

        let (parent_fid, name) = self.walk_to_parent(path_str).map_err(|e| match e {
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            _ => super::errors::UnlinkError::NoWritePerms,
        })?;

        let result = self.client.unlinkat(parent_fid, name, 0);
        let _ = self.client.clunk(parent_fid);

        result.map_err(|e| match e {
            Error::IsADirectory => super::errors::UnlinkError::IsADirectory,
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            Error::PermissionDenied => super::errors::UnlinkError::NoWritePerms,
            _ => super::errors::UnlinkError::ReadOnlyFileSystem,
        })
    }

    fn mkdir(
        &self,
        path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), super::errors::MkdirError> {
        let path_str = path
            .as_rust_str()
            .map_err(|_| super::errors::PathError::InvalidPathname)?;

        let (parent_fid, name) = self.walk_to_parent(path_str).map_err(|e| match e {
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            _ => super::errors::MkdirError::NoWritePerms,
        })?;

        let result = self.client.mkdir(parent_fid, name, mode.bits(), 0);
        let _ = self.client.clunk(parent_fid);

        result.map_err(|e| match e {
            Error::AlreadyExists => super::errors::MkdirError::AlreadyExists,
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            Error::PermissionDenied => super::errors::MkdirError::NoWritePerms,
            _ => super::errors::MkdirError::ReadOnlyFileSystem,
        })?;

        Ok(())
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), super::errors::RmdirError> {
        const AT_REMOVEDIR: u32 = 0x200;

        let path_str = path
            .as_rust_str()
            .map_err(|_| super::errors::PathError::InvalidPathname)?;

        let (parent_fid, name) = self.walk_to_parent(path_str).map_err(|e| match e {
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            _ => super::errors::RmdirError::NoWritePerms,
        })?;

        let result = self.client.unlinkat(parent_fid, name, AT_REMOVEDIR);
        let _ = self.client.clunk(parent_fid);

        result.map_err(|e| match e {
            Error::NotADirectory => super::errors::RmdirError::NotADirectory,
            Error::NotFound => super::errors::PathError::NoSuchFileOrDirectory.into(),
            Error::PermissionDenied => super::errors::RmdirError::NoWritePerms,
            _ => super::errors::RmdirError::ReadOnlyFileSystem,
        })
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

        let entries = self
            .client
            .readdir_all(desc.fid)
            .map_err(|_| super::errors::ReadDirError::ClosedFd)?;

        let dir_entries: Vec<super::DirEntry> = entries
            .into_iter()
            .filter(|e| {
                let name = e.name.as_bytes();
                name != b"." && name != b".."
            })
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
                        dev: 0,
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
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let path_str = path
            .as_rust_str()
            .map_err(|_| super::errors::PathError::InvalidPathname)?;

        let fid = self
            .walk_to(path_str)
            .map_err(|_| super::errors::PathError::NoSuchFileOrDirectory)?;

        let result = self.client.getattr(fid, fcall::GetattrMask::ALL);
        let _ = self.client.clunk(fid);

        let attr = result.map_err(|_| super::errors::PathError::NoSuchFileOrDirectory)?;
        Ok(Self::rgetattr_to_file_status(&attr))
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

        let attr = self
            .client
            .getattr(desc.fid, fcall::GetattrMask::ALL)
            .map_err(|_| super::errors::FileStatusError::ClosedFd)?;

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
    read_allowed: bool,
    /// Whether this file is opened for writing
    write_allowed: bool,
    /// The qid of the file (contains type and unique ID)
    qid: fcall::Qid,
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, T: { transport::Read + transport::Write };
    FileSystem<Platform, T>;
    Descriptor;
    -> FileFd<Platform, T>;
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A network file system, using the 9P2000.L protocol
//!
//! This module provides a [`FileSystem`] implementation that accesses files over a 9P2000.L
//! network connection. The 9P protocol is a simple, message-based protocol originally designed
//! for Plan 9 from Bell Labs. 9P2000.L is a Linux-specific variant that provides better
//! compatibility with POSIX semantics.

use alloc::collections::BTreeMap;
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

#[cfg(feature = "trace_fs")]
use crate::log_println;

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
const EROFS: u32 = 30;

/// Error type for 9P operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io,

    #[error("Operation interrupted")]
    Interrupted,

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
                EROFS => OpenError::ReadOnlyFileSystem,
                _ => OpenError::Io,
            },
            Error::Interrupted => OpenError::Interrupted,
            Error::Io | Error::InvalidResponse => OpenError::Io,
        }
    }
}

impl From<Error> for ReadError {
    fn from(e: Error) -> Self {
        match e {
            Error::Interrupted => ReadError::Interrupted,
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
            Error::Interrupted => WriteError::Interrupted,
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
                EROFS => MkdirError::ReadOnlyFileSystem,
                _ => MkdirError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::Interrupted => MkdirError::Io,
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
            Error::Io | Error::InvalidResponse | Error::InvalidPathname | Error::Interrupted => {
                ReadDirError::Io
            }
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
            Error::Io | Error::InvalidResponse | Error::Interrupted => UnlinkError::Io,
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
            Error::Io | Error::InvalidResponse | Error::Interrupted => RmdirError::Io,
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
            Error::Io | Error::InvalidResponse | Error::Interrupted => FileStatusError::Io,
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
            Error::Io | Error::InvalidResponse | Error::InvalidPathname | Error::Interrupted => {
                SeekError::Io
            }
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
            Error::Io | Error::InvalidResponse | Error::InvalidPathname | Error::Interrupted => {
                TruncateError::Io
            }
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
            Error::Io | Error::InvalidResponse | Error::Interrupted => ChmodError::Io,
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
            Error::Io | Error::InvalidResponse | Error::Interrupted => ChownError::Io,
        }
    }
}

impl From<Rlerror> for Error {
    fn from(err: Rlerror) -> Self {
        Error::Remote(err.ecode)
    }
}

/// Maximum write-behind buffer size per open file. Tuned to be large enough
/// to coalesce many small writes (e.g., cargo build emitting .d/.rmeta files)
/// while keeping total memory use reasonable across many open files.
const WRITE_BUFFER_CAPACITY: usize = 256 * 1024;

/// Per-fid write-behind buffer for coalescing small sequential writes into
/// fewer, larger 9P `Twrite` RPCs.
struct WriteBuffer {
    /// Buffered data waiting to be flushed.
    data: Vec<u8>,
    /// File offset where `data[0]` will be written.
    file_offset: usize,
    /// Unique file identity from the server qid (like an inode number).
    /// Used for cross-fid flush matching so that alias paths (e.g.
    /// symlinks) to the same file still observe each other's writes.
    qid_path: u64,
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
    /// Per-fid write-behind buffers. Keyed by fid so that close/read can
    /// flush the right buffer without scanning all open files.
    write_buffers: sync::Mutex<Platform, BTreeMap<fcall::Fid, WriteBuffer>>,
    /// Maximum single-RPC write payload (negotiated `msize - IOHDRSZ`).
    max_write_payload: usize,
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
        let max_write_payload = (client.msize() - fcall::IOHDRSZ) as usize;
        let (qid, fid) = client.attach(username, path)?;

        Ok(Self {
            litebox: litebox.clone(),
            client,
            root: (qid, fid, String::from(path)),
            current_working_dir: String::from("/"),
            unlinkat_supported: AtomicBool::new(true),
            write_buffers: sync::Mutex::new(BTreeMap::new()),
            max_write_payload,
        })
    }

    /// Flush the write-behind buffer for `fid` to the server.
    ///
    /// Sends the buffered data in a loop (in case it exceeds the per-RPC
    /// payload limit) and removes the buffer entry on success. On partial
    /// failure, the unwritten remainder is re-inserted so it is not lost.
    /// Returns `Ok(())` even if there was no buffer for this fid.
    fn flush_write_buffer(&self, fid: fcall::Fid) -> Result<(), Error> {
        let wb = self.write_buffers.lock().remove(&fid);
        if let Some(wb) = wb {
            self.do_flush_write_buffer(fid, wb)?;
        }
        Ok(())
    }

    /// Flush all write-behind buffers for the file identified by `qid_path`.
    ///
    /// Called before operations that need to see the latest server state
    /// for a file (read, seek, truncate, stat, open on same file). Matches
    /// on the server-assigned file identity so alias paths (symlinks) are
    /// handled correctly. Returns an error if any flush fails; unwritten
    /// remainders are preserved in the buffer map.
    fn flush_write_buffers_for_file(&self, qid_path: u64) -> Result<(), Error> {
        let to_flush: Vec<(fcall::Fid, WriteBuffer)> = {
            let mut buffers = self.write_buffers.lock();
            let fids: Vec<fcall::Fid> = buffers
                .iter()
                .filter(|(_, wb)| wb.qid_path == qid_path)
                .map(|(&fid, _)| fid)
                .collect();
            fids.into_iter()
                .filter_map(|fid| buffers.remove(&fid).map(|wb| (fid, wb)))
                .collect()
        };
        let mut first_err = None;
        for (fid, wb) in to_flush {
            if let Err(e) = self.do_flush_write_buffer(fid, wb)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Flush all write-behind buffers for the file identified by
    /// `qid_path`, **except** for `exclude_fid`. Used by `write()` to
    /// drain sibling-fid buffers before buffering new data, preserving
    /// cross-fid write ordering.
    fn flush_sibling_write_buffers(
        &self,
        qid_path: u64,
        exclude_fid: fcall::Fid,
    ) -> Result<(), Error> {
        let to_flush: Vec<(fcall::Fid, WriteBuffer)> = {
            let mut buffers = self.write_buffers.lock();
            let fids: Vec<fcall::Fid> = buffers
                .iter()
                .filter(|&(&f, wb)| wb.qid_path == qid_path && f != exclude_fid)
                .map(|(&fid, _)| fid)
                .collect();
            fids.into_iter()
                .filter_map(|fid| buffers.remove(&fid).map(|wb| (fid, wb)))
                .collect()
        };
        let mut first_err = None;
        for (fid, wb) in to_flush {
            if let Err(e) = self.do_flush_write_buffer(fid, wb)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// If `path` equals `old_prefix` or lives under it, return the
    /// corresponding path under `new_prefix`. Otherwise return `None`.
    fn rebase_path(path: &str, old_prefix: &str, new_prefix: &str) -> Option<String> {
        if path == old_prefix {
            Some(String::from(new_prefix))
        } else if let Some(suffix) = path.strip_prefix(old_prefix) {
            // Only match a real child (path separator immediately after prefix).
            if suffix.starts_with('/') {
                let mut new = String::from(new_prefix);
                new.push_str(suffix);
                Some(new)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Send the contents of a `WriteBuffer` to the server in a write loop.
    ///
    /// On partial failure, the unwritten remainder is re-inserted into the
    /// buffer map so that bytes acknowledged by earlier `write()` calls are
    /// not silently discarded.
    fn do_flush_write_buffer(&self, fid: fcall::Fid, wb: WriteBuffer) -> Result<(), Error> {
        let mut written = 0;
        while written < wb.data.len() {
            match self
                .client
                .write(fid, (wb.file_offset + written) as u64, &wb.data[written..])
            {
                Ok(0) => {
                    self.reinsert_remainder(fid, &wb, written);
                    return Err(Error::Io);
                }
                Ok(n) => {
                    written += n;
                }
                Err(e) => {
                    self.reinsert_remainder(fid, &wb, written);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Re-insert the unwritten tail of a partially flushed `WriteBuffer`.
    fn reinsert_remainder(&self, fid: fcall::Fid, wb: &WriteBuffer, written: usize) {
        if written < wb.data.len() {
            let remainder = WriteBuffer {
                data: wb.data[written..].to_vec(),
                file_offset: wb.file_offset + written,
                qid_path: wb.qid_path,
            };
            self.write_buffers.lock().insert(fid, remainder);
        }
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

    /// Get the stored path from any fd's Descriptor.
    fn descriptor_path(&self, dirfd: &FileFd<Platform, T>) -> Option<alloc::string::String> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(dirfd)?;
        Some(entry.entry.path.clone())
    }

    /// Get the stored path from a directory fd's Descriptor.
    fn dir_fd_path(
        &self,
        dirfd: &FileFd<Platform, T>,
    ) -> Result<alloc::string::String, super::DirFdError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(dirfd)
            .ok_or(super::DirFdError::ClosedFd)?;
        if entry.entry.qid.typ.contains(fcall::QidType::DIR) {
            Ok(entry.entry.path.clone())
        } else {
            Err(super::DirFdError::NotADirectory)
        }
    }

    /// Resolve a relative path against a base directory path.
    fn resolve_relative(base: &str, rel: &str) -> Result<alloc::string::String, PathError> {
        if rel.is_empty() || rel == "." {
            return Ok(base.into());
        }
        if rel.starts_with('/') {
            return Ok(rel.normalized()?);
        }
        let combined = if base.ends_with('/') {
            alloc::format!("{base}{rel}")
        } else {
            alloc::format!("{base}/{rel}")
        };
        Ok(combined.normalized()?)
    }

    /// Resolve symlinks in every component of `path` (like `realpath`).
    ///
    /// Walks each component, checking for symlinks at each prefix. When a
    /// symlink is found, its target's components are spliced into the work
    /// queue so nested symlinks within the target are also resolved.
    /// Returns `SymlinkLoop` if more than `max_hops` symlinks are followed.
    fn resolve_follow_symlinks(
        &self,
        path: alloc::string::String,
        max_hops: usize,
    ) -> Result<alloc::string::String, super::FileStatusError> {
        let mut resolved = alloc::string::String::from("/");
        let mut hops_remaining = max_hops;

        let mut remaining: alloc::vec::Vec<alloc::string::String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(alloc::string::String::from)
            .collect();
        let mut idx = 0;

        while idx < remaining.len() {
            let component = remaining[idx].clone();
            idx += 1;

            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    if let Some(pos) = resolved[..resolved.len().saturating_sub(1)].rfind('/') {
                        resolved.truncate(pos + 1);
                    }
                    continue;
                }
                _ => {}
            }

            if !resolved.ends_with('/') {
                resolved.push('/');
            }
            resolved.push_str(&component);

            if let Ok(t) = <Self as super::FileSystem>::read_link(self, &*resolved) {
                if hops_remaining == 0 {
                    return Err(super::FileStatusError::SymlinkLoop);
                }
                hops_remaining -= 1;

                if t.starts_with('/') {
                    resolved = alloc::string::String::from("/");
                } else {
                    let parent_end = resolved.rfind('/').unwrap_or(0).max(1);
                    resolved.truncate(parent_end);
                }

                let tail: alloc::vec::Vec<alloc::string::String> = remaining.drain(idx..).collect();
                remaining.truncate(0);
                remaining.extend(
                    t.split('/')
                        .filter(|c| !c.is_empty())
                        .map(alloc::string::String::from),
                );
                remaining.extend(tail);
                idx = 0;
            }
        }

        if resolved.len() > 1 && resolved.ends_with('/') {
            resolved.pop();
        }
        Ok(resolved)
    }

    /// Walk to a path and return the fid
    fn walk_to(&self, path: &str) -> Result<fcall::Fid, Error> {
        self.walk_to_with_qid(path).map(|(fid, _)| fid)
    }

    /// Walk to a path and return both the fid and the last qid.
    fn walk_to_with_qid(&self, path: &str) -> Result<(fcall::Fid, fcall::Qid), Error> {
        let components: Vec<&str> = path
            .normalized_components()
            .map_err(|_| Error::InvalidPathname)?
            .collect();
        if components.is_empty() {
            let fid = self.client.clone_fid(self.root.1)?;
            Ok((fid, self.root.0))
        } else {
            let (qids, fid) = self.client.walk(self.root.1, &components)?;
            let qid = qids.last().copied().ok_or(Error::InvalidResponse)?;
            Ok((fid, qid))
        }
    }

    /// Walk to the parent of a path and return the parent fid and the name of the final component
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
    fn rgetattr_to_file_status(attr: &fcall::Rgetattr) -> Result<super::FileStatus, Error> {
        let file_type = Self::qid_type_to_file_type(attr.qid.typ);

        if attr.valid.contains(fcall::GetattrMask::BASIC) {
            Ok(super::FileStatus {
                file_type,
                mode: super::Mode::from_bits_truncate(attr.stat.mode),
                size: usize::try_from(attr.stat.size).map_err(|_| Error::InvalidResponse)?,
                owner: super::UserInfo {
                    user: u16::try_from(attr.stat.uid).map_err(|_| Error::InvalidResponse)?,
                    group: u16::try_from(attr.stat.gid).map_err(|_| Error::InvalidResponse)?,
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: usize::try_from(attr.qid.path).map_err(|_| Error::InvalidResponse)?,
                    rdev: NonZeroUsize::new(
                        usize::try_from(attr.stat.rdev).map_err(|_| Error::InvalidResponse)?,
                    ),
                },
                blksize: usize::try_from(attr.stat.blksize).map_err(|_| Error::InvalidResponse)?,
            })
        } else {
            Ok(super::FileStatus {
                file_type,
                mode: if attr.valid.contains(fcall::GetattrMask::MODE) {
                    super::Mode::from_bits_truncate(attr.stat.mode)
                } else {
                    super::Mode::empty()
                },
                size: if attr.valid.contains(fcall::GetattrMask::SIZE) {
                    usize::try_from(attr.stat.size).map_err(|_| Error::InvalidResponse)?
                } else {
                    0
                },
                owner: super::UserInfo {
                    user: if attr.valid.contains(fcall::GetattrMask::UID) {
                        u16::try_from(attr.stat.uid).map_err(|_| Error::InvalidResponse)?
                    } else {
                        0
                    },
                    group: if attr.valid.contains(fcall::GetattrMask::GID) {
                        u16::try_from(attr.stat.gid).map_err(|_| Error::InvalidResponse)?
                    } else {
                        0
                    },
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: usize::try_from(attr.qid.path).map_err(|_| Error::InvalidResponse)?,
                    rdev: if attr.valid.contains(fcall::GetattrMask::RDEV) {
                        NonZeroUsize::new(
                            usize::try_from(attr.stat.rdev).map_err(|_| Error::InvalidResponse)?,
                        )
                    } else {
                        None
                    },
                },
                blksize: if attr.valid.contains(fcall::GetattrMask::BLOCKS) {
                    usize::try_from(attr.stat.blksize).map_err(|_| Error::InvalidResponse)?
                } else {
                    0
                },
            })
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
        // TODO: we don't support non-blocking, so ignore that flag instead of returning an error
        let flags = flags - OFlags::NONBLOCK;
        let currently_supported_oflags: OFlags = OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::CREAT
            | OFlags::NOCTTY
            | OFlags::EXCL
            | OFlags::TRUNC
            | OFlags::APPEND
            | OFlags::DIRECTORY
            | OFlags::NOFOLLOW
            | OFlags::LARGEFILE
            | OFlags::SYNC
            | OFlags::DSYNC
            | OFlags::DIRECT
            | OFlags::NOATIME;
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
            // Try to walk to the target first. If it already exists, fall
            // through to the regular open path which flushes write-behind
            // buffers and handles O_TRUNC correctly. Only use Tlcreate for
            // truly new files.
            let existing = self.client.walk(self.root.1, &components);
            if let Ok((_qids, existing_fid)) = existing {
                if flags.contains(super::OFlags::EXCL) {
                    let _ = self.client.clunk(existing_fid);
                    return Err(OpenError::AlreadyExists);
                }
                // File exists — strip O_TRUNC and open normally, then
                // flush buffers and apply truncation manually.
                let has_trunc = lflags.contains(fcall::LOpenFlags::O_TRUNC);
                let open_flags = lflags & !fcall::LOpenFlags::O_TRUNC & !fcall::LOpenFlags::O_CREAT;
                match self.client.open(existing_fid, open_flags) {
                    Ok(qid) => {
                        if self.flush_write_buffers_for_file(qid.path).is_err() {
                            let _ = self.client.clunk(existing_fid);
                            return Err(OpenError::Io);
                        }
                        if has_trunc {
                            let stat = fcall::SetAttr {
                                size: 0,
                                ..Default::default()
                            };
                            if let Err(e) =
                                self.client
                                    .setattr(existing_fid, fcall::SetattrMask::SIZE, stat)
                            {
                                let _ = self.client.clunk(existing_fid);
                                return Err(e.into());
                            }
                        }
                        (qid, existing_fid)
                    }
                    Err(e) => {
                        let _ = self.client.clunk(existing_fid);
                        return Err(e.into());
                    }
                }
            } else {
                // File does not exist — create it. No flush needed since
                // there can be no pending writes to a nonexistent file.
                let (_, dfid) = self
                    .client
                    .walk(self.root.1, &components[..components.len() - 1])?;
                match self
                    .client
                    .create(dfid, components.last().unwrap(), lflags, mode.bits(), 0)
                {
                    Ok(result) => result,
                    Err(e) => {
                        let _ = self.client.clunk(dfid);
                        return Err(e.into());
                    }
                }
            }
        } else {
            let walk_result = self.client.walk(self.root.1, &components);
            #[cfg(feature = "trace_fs")]
            if let Err(ref e) = walk_result {
                log_println!(
                    self.litebox.x.platform,
                    "[9P-TRACE] walk FAILED path={:?} err={:?}",
                    path,
                    e,
                );
            }
            let (_qids, new_fid) = walk_result?;

            // Strip O_TRUNC from the open flags — we apply it manually
            // after flushing pending write-behind buffers to avoid
            // truncating the file and then replaying stale buffered writes.
            let has_trunc = lflags.contains(fcall::LOpenFlags::O_TRUNC);
            let open_flags = lflags & !fcall::LOpenFlags::O_TRUNC;

            let open_result = self.client.open(new_fid, open_flags);
            #[cfg(feature = "trace_fs")]
            if let Err(ref e) = open_result {
                log_println!(
                    self.litebox.x.platform,
                    "[9P-TRACE] open FAILED path={:?} fid={} lflags={:?} err={:?}",
                    path,
                    new_fid,
                    lflags,
                    e,
                );
            }
            match open_result {
                Ok(qid) => {
                    // Flush any pending write-behind data for the opened file
                    // using the qid returned by open(), which is the target's
                    // qid after symlink resolution.
                    if self.flush_write_buffers_for_file(qid.path).is_err() {
                        let _ = self.client.clunk(new_fid);
                        return Err(OpenError::Io);
                    }
                    // Apply O_TRUNC now that buffered writes have been
                    // drained, so the truncate isn't undone by a later
                    // flush of stale data.
                    if has_trunc {
                        let stat = fcall::SetAttr {
                            size: 0,
                            ..Default::default()
                        };
                        if let Err(e) = self.client.setattr(new_fid, fcall::SetattrMask::SIZE, stat)
                        {
                            let _ = self.client.clunk(new_fid);
                            return Err(e.into());
                        }
                    }
                    (qid, new_fid)
                }
                Err(e) => {
                    // Clunk the fid from the walk to avoid leaking it on the
                    // server. Ignore clunk errors since the connection may
                    // already be broken.
                    let _ = self.client.clunk(new_fid);
                    return Err(e.into());
                }
            }
        };

        let descriptor = Descriptor {
            fid: new_fid,
            offset: AtomicUsize::new(0),
            qid: new_qid,
            path: path.clone(),
            direct_write: flags.intersects(OFlags::SYNC | OFlags::DSYNC | OFlags::APPEND),
        };

        let fd = self.litebox.descriptor_table_mut().insert(descriptor);
        Ok(fd)
    }

    fn close(&self, fd: &FileFd<Platform, T>) -> Result<(), super::errors::CloseError> {
        let entry = self.litebox.descriptor_table_mut().remove(fd);
        if let Some(entry) = entry {
            // Flush any pending write-behind data before releasing the fid.
            // Propagate flush errors so callers know about data loss.
            let flush_result = self.flush_write_buffer(entry.entry.fid);
            // On flush failure, do_flush_write_buffer re-inserts the
            // unwritten remainder. Remove it unconditionally — the fid is
            // about to be clunked, so the remainder can never be flushed.
            self.write_buffers.lock().remove(&entry.entry.fid);
            let _ = self.client.clunk(entry.entry.fid);
            if flush_result.is_err() {
                return Err(super::errors::CloseError::Io);
            }
        }
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform, T>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::ReadError> {
        // Extract fid, current offset, and qid, releasing the descriptor
        // table lock before performing potentially blocking I/O.
        let (fid, current_offset, qid_path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| {
                (
                    desc.entry.fid,
                    desc.entry.offset.load(Ordering::SeqCst),
                    desc.entry.qid.path,
                )
            })
            .ok_or(super::errors::ReadError::ClosedFd)?;

        // Flush all pending write-behind data for this file (across all
        // fids) so the read sees the latest bytes on the server.
        self.flush_write_buffers_for_file(qid_path)?;

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
        // Extract fid, current offset, sync flag, and qid from the
        // descriptor, releasing the table lock before any I/O.
        let (fid, current_offset, direct_write, qid_path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| {
                (
                    desc.entry.fid,
                    desc.entry.offset.load(Ordering::SeqCst),
                    desc.entry.direct_write,
                    desc.entry.qid.path,
                )
            })
            .ok_or(super::errors::WriteError::ClosedFd)?;

        // Flush any sibling-fid buffers for the same file so that earlier
        // writes from other fds reach the server before this one.  This
        // preserves cross-fid write ordering without draining our own
        // buffer (which we may still coalesce into).
        self.flush_sibling_write_buffers(qid_path, fid)?;

        let write_offset = match offset {
            Some(o) => o,
            None => current_offset,
        };

        let total = buf.len();

        // O_SYNC / O_DSYNC: bypass buffering entirely so data hits the
        // server before write() returns.
        if direct_write {
            let mut written = 0;
            while written < total {
                let n = self
                    .client
                    .write(fid, (write_offset + written) as u64, &buf[written..])?;
                if n == 0 {
                    break;
                }
                written += n;
            }
            if offset.is_none() {
                self.litebox.descriptor_table().with_entry(fd, |desc| {
                    desc.entry.offset.fetch_add(written, Ordering::SeqCst);
                });
            }
            return Ok(written);
        }

        let buf_cap = WRITE_BUFFER_CAPACITY.min(self.max_write_payload);

        // Try to coalesce into the write-behind buffer.
        let mut buffers = self.write_buffers.lock();
        if let Some(wb) = buffers.get_mut(&fid) {
            let expected_offset = wb.file_offset + wb.data.len();
            if write_offset == expected_offset && wb.data.len() + total <= buf_cap {
                // Sequential and fits — append without any RPC.
                wb.data.extend_from_slice(buf);
                drop(buffers);
                if offset.is_none() {
                    self.litebox.descriptor_table().with_entry(fd, |desc| {
                        desc.entry.offset.fetch_add(total, Ordering::SeqCst);
                    });
                }
                return Ok(total);
            }
            // Non-sequential or buffer full — flush the old buffer first.
            let old_wb = buffers.remove(&fid).unwrap();
            drop(buffers);
            self.do_flush_write_buffer(fid, old_wb)?;
        } else {
            drop(buffers);
        }

        // If the write is small enough, start a new buffer.
        if total <= buf_cap {
            self.write_buffers.lock().insert(
                fid,
                WriteBuffer {
                    data: Vec::from(buf),
                    file_offset: write_offset,
                    qid_path,
                },
            );
            if offset.is_none() {
                self.litebox.descriptor_table().with_entry(fd, |desc| {
                    desc.entry.offset.fetch_add(total, Ordering::SeqCst);
                });
            }
            return Ok(total);
        }

        // Large write — send directly in a loop (no point buffering).
        let mut written = 0;
        while written < total {
            let n = self
                .client
                .write(fid, (write_offset + written) as u64, &buf[written..])?;
            if n == 0 {
                break;
            }
            written += n;
        }

        if offset.is_none() {
            self.litebox.descriptor_table().with_entry(fd, |desc| {
                desc.entry.offset.fetch_add(written, Ordering::SeqCst);
            });
        }

        Ok(written)
    }

    fn seek(
        &self,
        fd: &FileFd<Platform, T>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        // Extract fid and current offset, releasing the descriptor table lock
        // before performing potentially blocking I/O (getattr for SeekWhence::RelativeToEnd).
        let (fid, current_offset, qid_path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| {
                (
                    desc.entry.fid,
                    desc.entry.offset.load(Ordering::SeqCst),
                    desc.entry.qid.path,
                )
            })
            .ok_or(SeekError::ClosedFd)?;

        // Flush all pending write-behind data for this file (across all
        // fids) since the seek changes the file position.
        self.flush_write_buffers_for_file(qid_path)?;

        let base = match whence {
            super::SeekWhence::RelativeToBeginning => 0,
            super::SeekWhence::RelativeToCurrentOffset => current_offset,
            super::SeekWhence::RelativeToEnd => {
                let attr = self.client.getattr(fid, fcall::GetattrMask::SIZE)?;
                usize::try_from(attr.stat.size).map_err(|_| Error::InvalidResponse)?
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

        // Flush all pending writes for this file (across all fids) before
        // truncating — buffered data from sibling fids past the new size
        // would otherwise be lost or re-applied after the truncate.
        self.flush_write_buffers_for_file(qid.path)?;

        if qid.typ.contains(fcall::QidType::DIR) {
            return Err(super::errors::TruncateError::IsDirectory);
        }

        let stat = fcall::SetAttr {
            mode: 0,
            uid: 0,
            gid: 0,
            size: length as u64,
            ..Default::default()
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
            ..Default::default()
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
            uid,
            gid,
            ..Default::default()
        };

        let result = self.client.setattr(fid, valid, stat);
        let _ = self.client.clunk(fid);

        result.map_err(ChownError::from)
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), super::errors::UnlinkError> {
        self.remove_file_or_dir(path, true)
            .map_err(UnlinkError::from)
    }

    fn rename(
        &self,
        old: impl crate::path::Arg,
        new: impl crate::path::Arg,
    ) -> Result<(), super::errors::RenameError> {
        let old_path = self
            .absolute_path(old)
            .map_err(|_| super::errors::RenameError::ReadOnlyFileSystem)?;
        let new_path = self
            .absolute_path(new)
            .map_err(|_| super::errors::RenameError::ReadOnlyFileSystem)?;

        // Walk to the source file to get its qid for buffer flushing.
        let (src_fid, source_qid) = self
            .walk_to_with_qid(&old_path)
            .map_err(|_| super::errors::RenameError::ReadOnlyFileSystem)?;

        // Flush any pending write-behind data for the source file so that
        // the server has the latest contents before the rename. Propagate
        // flush errors — a silent drop would lose acknowledged writes.
        if self.flush_write_buffers_for_file(source_qid.path).is_err() {
            let _ = self.client.clunk(src_fid);
            return Err(super::errors::RenameError::Io);
        }

        // Walk to the destination parent directory
        let new_components: Vec<&str> = new_path
            .normalized_components()
            .map_err(|_| {
                let _ = self.client.clunk(src_fid);
                super::errors::RenameError::ReadOnlyFileSystem
            })?
            .collect();

        if new_components.is_empty() {
            let _ = self.client.clunk(src_fid);
            return Err(super::errors::RenameError::ReadOnlyFileSystem);
        }

        let new_name = *new_components.last().unwrap();
        let parent_components = &new_components[..new_components.len() - 1];
        let dst_dir_fid = if parent_components.is_empty() {
            if let Ok(f) = self.client.clone_fid(self.root.1) {
                f
            } else {
                let _ = self.client.clunk(src_fid);
                return Err(super::errors::RenameError::ReadOnlyFileSystem);
            }
        } else if let Ok((_, f)) = self.client.walk(self.root.1, parent_components) {
            f
        } else {
            let _ = self.client.clunk(src_fid);
            return Err(super::errors::RenameError::ReadOnlyFileSystem);
        };

        let result = self.client.rename(src_fid, dst_dir_fid, new_name);
        let _ = self.client.clunk(src_fid);
        let _ = self.client.clunk(dst_dir_fid);

        if result.is_ok() {
            // Update the path stored in every open descriptor that still
            // refers to the old path (or a descendant). This keeps
            // Descriptor.path accurate for debugging/tracing. Write-behind
            // buffer matching uses qid_path (file identity), so renames
            // are transparent to cross-fid flush logic.
            let table = self.litebox.descriptor_table();
            for (_, mut desc) in table.iter_mut::<Self>() {
                if let Some(new) = Self::rebase_path(&desc.entry.path, &old_path, &new_path) {
                    desc.entry.path = new;
                }
            }
        }

        result.map_err(|_| super::errors::RenameError::ReadOnlyFileSystem)
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

                Ok(super::DirEntry {
                    name: String::from_utf8_lossy(&e.name).into_owned(),
                    file_type,
                    ino_info: Some(super::NodeInfo {
                        dev: DEVICE_ID,
                        ino: usize::try_from(e.qid.path).map_err(|_| Error::InvalidResponse)?,
                        rdev: None,
                    }),
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(dir_entries)
    }

    fn file_status(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<super::FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;

        let (fid, qid) = self.walk_to_with_qid(&path)?;

        // Flush any pending write-behind data for this file so the server
        // reports the correct file size and mtime.
        if self.flush_write_buffers_for_file(qid.path).is_err() {
            let _ = self.client.clunk(fid);
            return Err(FileStatusError::Io);
        }

        let result = self.client.getattr(fid, fcall::GetattrMask::ALL);
        let _ = self.client.clunk(fid);

        result
            .and_then(|attr| Self::rgetattr_to_file_status(&attr))
            .map_err(FileStatusError::from)
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform, T>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        // Extract fid and qid, releasing the descriptor table lock
        // before performing potentially blocking I/O.
        let (fid, qid_path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| (desc.entry.fid, desc.entry.qid.path))
            .ok_or(super::errors::FileStatusError::ClosedFd)?;

        // Flush all pending writes for this file (across all fids) so the
        // server reports the correct file size.
        self.flush_write_buffers_for_file(qid_path)?;

        // Perform blocking I/O without holding any locks.
        let attr = self.client.getattr(fid, fcall::GetattrMask::ALL)?;

        Ok(Self::rgetattr_to_file_status(&attr)?)
    }

    fn read_link(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        let abs = self
            .absolute_path(path)
            .map_err(super::errors::ReadLinkError::PathError)?;
        let fid = self
            .walk_to(&abs)
            .map_err(|_| super::errors::ReadLinkError::Io)?;
        let target = self.client.readlink(fid);
        let _ = self.client.clunk(fid);
        let target = target.map_err(|_| super::errors::ReadLinkError::Io)?;
        alloc::string::String::from_utf8(target).map_err(|_| super::errors::ReadLinkError::Io)
    }

    fn open_at(
        &self,
        dirfd: &FileFd<Platform, T>,
        rel_path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform, T>, super::errors::OpenError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::errors::OpenError::ClosedFd,
            super::DirFdError::NotADirectory => super::errors::OpenError::NotADirectory,
            super::DirFdError::Io => super::errors::OpenError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| super::errors::OpenError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(super::errors::OpenError::PathError)?;
        self.open(abs, flags, mode)
    }

    fn stat_at(
        &self,
        dirfd: &FileFd<Platform, T>,
        rel_path: impl crate::path::Arg,
        follow_symlinks: bool,
    ) -> Result<super::FileStatus, super::FileStatusError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::FileStatusError::ClosedFd,
            super::DirFdError::NotADirectory => super::FileStatusError::NotADirectory,
            super::DirFdError::Io => super::FileStatusError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| super::FileStatusError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(super::FileStatusError::PathError)?;
        // When following symlinks, resolve the full chain (up to 40 hops).
        // Relative targets are resolved against the symlink's parent
        // directory, not the process CWD.
        let resolved = if follow_symlinks {
            self.resolve_follow_symlinks(abs, 40)?
        } else {
            abs
        };
        self.file_status(resolved)
    }

    fn unlink_at(
        &self,
        dirfd: &FileFd<Platform, T>,
        rel_path: impl crate::path::Arg,
    ) -> Result<(), super::errors::UnlinkError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::errors::UnlinkError::ClosedFd,
            super::DirFdError::NotADirectory => super::errors::UnlinkError::NotADirectory,
            super::DirFdError::Io => super::errors::UnlinkError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| super::errors::UnlinkError::PathError(e.into()))?;
        let abs =
            Self::resolve_relative(&dir, rel).map_err(super::errors::UnlinkError::PathError)?;
        self.unlink(abs)
    }

    fn readlink_at(
        &self,
        dirfd: &FileFd<Platform, T>,
        rel_path: impl crate::path::Arg,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::errors::ReadLinkError::ClosedFd,
            super::DirFdError::NotADirectory => super::errors::ReadLinkError::NotADirectory,
            super::DirFdError::Io => super::errors::ReadLinkError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| super::errors::ReadLinkError::PathError(e.into()))?;
        let abs =
            Self::resolve_relative(&dir, rel).map_err(super::errors::ReadLinkError::PathError)?;
        self.read_link(abs)
    }

    fn rename_at(
        &self,
        old_dirfd: &FileFd<Platform, T>,
        old_rel: impl crate::path::Arg,
        new_dirfd: &FileFd<Platform, T>,
        new_rel: impl crate::path::Arg,
    ) -> Result<(), super::errors::RenameError> {
        let old_dir = self.dir_fd_path(old_dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::errors::RenameError::ClosedFd,
            super::DirFdError::NotADirectory => super::errors::RenameError::NotADirectory,
            super::DirFdError::Io => super::errors::RenameError::Io,
        })?;
        let old_r = old_rel
            .as_rust_str()
            .map_err(|e| super::errors::RenameError::PathError(e.into()))?;
        let old_abs = Self::resolve_relative(&old_dir, old_r)
            .map_err(super::errors::RenameError::PathError)?;
        let new_dir = self.dir_fd_path(new_dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::errors::RenameError::ClosedFd,
            super::DirFdError::NotADirectory => super::errors::RenameError::NotADirectory,
            super::DirFdError::Io => super::errors::RenameError::Io,
        })?;
        let new_r = new_rel
            .as_rust_str()
            .map_err(|e| super::errors::RenameError::PathError(e.into()))?;
        let new_abs = Self::resolve_relative(&new_dir, new_r)
            .map_err(super::errors::RenameError::PathError)?;
        self.rename(old_abs, new_abs)
    }

    fn fd_path(&self, fd: &FileFd<Platform, T>) -> Option<alloc::string::String> {
        self.descriptor_path(fd)
    }

    fn mkdir_at(
        &self,
        dirfd: &FileFd<Platform, T>,
        rel_path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), MkdirError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
            super::DirFdError::NotADirectory => {
                MkdirError::PathError(PathError::ComponentNotADirectory)
            }
            super::DirFdError::ClosedFd | super::DirFdError::Io => MkdirError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| MkdirError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(MkdirError::PathError)?;
        self.mkdir(abs, mode)
    }
}
#[derive(Debug)]
struct Descriptor {
    /// The 9P fid for this file
    fid: fcall::Fid,
    /// Current file offset (9P doesn't track this server-side)
    offset: AtomicUsize,
    /// The qid of the file (contains type and unique ID)
    qid: fcall::Qid,
    /// Path used to open this file
    path: alloc::string::String,
    /// Whether writes on this fd must bypass the write-behind buffer and
    /// go directly to the server. Set for O_SYNC, O_DSYNC (durability) and
    /// O_APPEND (atomicity of append point).
    direct_write: bool,
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, T: { transport::Read + transport::Write };
    FileSystem<Platform, T>;
    Descriptor;
    -> FileFd<Platform, T>;
}

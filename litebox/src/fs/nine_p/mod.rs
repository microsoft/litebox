// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A network file system, using the 9P2000.L protocol
//!
//! This module provides a [`FileSystem`] implementation that accesses files over a 9P2000.L
//! network connection. The 9P protocol is a simple, message-based protocol originally designed
//! for Plan 9 from Bell Labs. 9P2000.L is a Linux-specific variant that provides better
//! compatibility with POSIX semantics.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use thiserror::Error;

use crate::fs::OFlags;
use crate::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, SymlinkError, TruncateError, UnlinkError, WriteError,
};
use crate::fs::nine_p::fcall::Rlerror;
use crate::path::Arg;
use crate::{LiteBox, sync};

#[cfg(feature = "trace_fs")]
use crate::log_println;

mod client;
mod fcall;
mod pending_table;

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

impl From<Error> for SymlinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => SymlinkError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => SymlinkError::PathError(PathError::NoSuchFileOrDirectory),
                EEXIST => SymlinkError::AlreadyExists,
                EPERM | EACCES => SymlinkError::NoWritePerms,
                ENOTDIR => SymlinkError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG | EINVAL => SymlinkError::PathError(PathError::InvalidPathname),
                EROFS => SymlinkError::ReadOnlyFileSystem,
                ENOSYS | EOPNOTSUPP => SymlinkError::NotSupported,
                _ => SymlinkError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::Interrupted => SymlinkError::Io,
        }
    }
}

impl From<Error> for super::errors::ReadLinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => {
                super::errors::ReadLinkError::PathError(PathError::InvalidPathname)
            }
            Error::Remote(errno) => match errno {
                ENOENT => super::errors::ReadLinkError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => {
                    super::errors::ReadLinkError::PathError(PathError::ComponentNotADirectory)
                }
                ENAMETOOLONG => super::errors::ReadLinkError::PathError(PathError::InvalidPathname),
                EINVAL => super::errors::ReadLinkError::NotASymlink,
                EPERM | EACCES => {
                    super::errors::ReadLinkError::PathError(PathError::NoSearchPerms {
                        #[cfg(debug_assertions)]
                        dir: String::new(),
                        #[cfg(debug_assertions)]
                        perms: super::Mode::empty(),
                    })
                }
                _ => super::errors::ReadLinkError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::Interrupted => {
                super::errors::ReadLinkError::Io
            }
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

/// Maximum write-behind buffer size per open file.
///
/// **Set to 0 to disable buffering entirely**, restoring POSIX
/// read-after-write visibility semantics across processes.
///
/// History: this buffer was added as a perf optimization to coalesce
/// small sequential writes (e.g., cargo build emitting `.d`/`.rmeta`
/// files) into fewer 9P RPCs. But the buffer is per-litebox-client
/// (= per guest process — each runner instance has its own
/// `write_buffers: BTreeMap<Fid, WriteBuffer>` map), and the flush
/// triggers (`flush_write_buffers_for_file` on read/open/seek/truncate
/// from the same process, `flush_sibling_write_buffers` on writes to
/// sibling fids in the same process, `flush_write_buffer` on close)
/// only fire on intra-process events. A reader in a DIFFERENT guest
/// process opens a fresh fid, walks straight to the 9P server, reads
/// from the host file, and sees ONLY the bytes that have actually
/// been pwritten by the broker — NOT the writer's still-buffered
/// tail bytes.
///
/// When the writer process goes idle after the last write (e.g.
/// VS Code Server CLI sitting in its `epoll_pwait` accept loop, or
/// any logging process between log lines), the tail bytes of the
/// write_behind buffer sit there indefinitely. Cross-process readers
/// never see the writer's most recent writes.
///
/// Reproduced and fix-verified by
/// `CWF.full_visibility.{nonpie-glibc,non-pie-static-musl}.*` tests
/// (which writers `writeln!` 5 lines and a separate-process reader
/// validates the full 30-byte content). With the buffer enabled, the
/// non-PIE-writer-spawned variants reproducibly lose the final 1 byte
/// (the trailing `'\n'` of the last writeln). With the buffer disabled
/// here, they pass. The same fix transitively unblocks 3 of the 4
/// `vscode::*` litebox-pass trials (`server_listen`,
/// `connect_loopback`, `connect_cross_ssh`) — the VS Code Server's
/// `code` CLI was hitting the same root cause (the CLI's
/// `Listening on N.N.N.N:PORT` line was sitting in its write-buffer
/// after the CLI entered its epoll loop; the bash-subshell reader
/// never saw it).
///
/// Perf trade-off: small-write-heavy workloads (cargo builds) lose
/// the coalescing benefit and pay one 9P RPC per write. Mitigations
/// for the future: (a) keep a small buffer (e.g. 4 KB) with a
/// **debounced eager-flush timer** that fires Nms after the last
/// write, restoring perf for tight-loop writes while bounding the
/// cross-process visibility delay; (b) broker-side cross-client
/// pending-write tracking that proactively asks clients to flush
/// when any other client opens or reads the same file. Both are
/// strictly larger changes than the value 0 here and can land
/// incrementally without re-breaking correctness.
const WRITE_BUFFER_CAPACITY: usize = 0;

/// Maximum read-ahead size per `Tread` RPC. When a caller requests a small
/// read (e.g. 4 KB mmap page), we request this much from the server and
/// cache the surplus for subsequent sequential reads.
const READ_AHEAD_SIZE: usize = 1024 * 1024;

/// Per-fid read-ahead buffer for coalescing small sequential reads into
/// fewer, larger 9P `Tread` RPCs.
struct ReadBuffer {
    /// Cached data read ahead from the server.
    data: Vec<u8>,
    /// File offset where `data[0]` corresponds to.
    file_offset: usize,
    /// Unique file identity (qid.path) for cross-fid invalidation.
    qid_path: u64,
    /// True when the readahead RPC returned fewer bytes than requested,
    /// meaning we've seen EOF at `file_offset + data.len()`. Subsequent
    /// reads past the buffer range can return 0 without an RPC.
    ///
    /// Note: this memoization means that if the file is appended by
    /// another process or host-side writer after EOF is observed, this
    /// fd will continue to report EOF until the buffer is invalidated
    /// (e.g. by a write to the same qid) or the fd is reopened. This
    /// is acceptable in the sandbox model where the host export tree
    /// is not expected to grow files concurrently.
    eof_seen: bool,
}

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
/// - `W`: The transport write half type that implements the `Write` trait.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider, W: transport::Write> {
    /// Reference to the LiteBox instance
    litebox: LiteBox<Platform>,
    /// 9P client for protocol operations
    client: client::Client<Platform, W>,
    /// Root (attached to the root of the remote filesystem)
    root: (fcall::Qid, fcall::Fid, String),
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    /// Whether `unlinkat` is supported by the server
    unlinkat_supported: AtomicBool,
    /// Per-fid write-behind buffers. Keyed by fid so that close/read can
    /// flush the right buffer without scanning all open files.
    write_buffers: sync::Mutex<Platform, BTreeMap<fcall::Fid, WriteBuffer>>,
    /// Per-fid read-ahead buffers. Keyed by fid so that sequential reads
    /// can be served from a single large `Tread` RPC without re-issuing
    /// small requests to the server.
    read_buffers: sync::Mutex<Platform, BTreeMap<fcall::Fid, ReadBuffer>>,
    /// Client-side stat cache. Keyed by absolute path. Avoids repeated
    /// walk+getattr+clunk RPCs for files that are stat'd frequently
    /// (e.g. Cargo.toml, source files, target/ fingerprints).
    /// Invalidated on write, truncate, rename, unlink, and create.
    stat_cache: sync::Mutex<Platform, BTreeMap<String, super::FileStatus>>,
    /// Directory fid cache. Keyed by absolute directory path. Stores
    /// a server fid that remains alive so subsequent walks can start
    /// from a cached ancestor instead of walking all the way from root.
    dir_fid_cache: sync::Mutex<Platform, BTreeMap<String, (fcall::Fid, fcall::Qid)>>,
    /// Readlink result cache. Keyed by absolute symlink path, stores
    /// the target string returned by `readlink`. Avoids repeated
    /// readlinkpath RPCs for symlinks that are read many times during
    /// a build (e.g. `/usr/lib/libfoo.so` → `libfoo.so.1`).
    /// Invalidated on unlink, rename, and create (which can replace a
    /// symlink).
    readlink_cache: sync::Mutex<Platform, BTreeMap<String, String>>,
    /// Negative stat cache. Stores absolute paths for which `file_status`
    /// returned ENOENT. Avoids repeated walk+getattr RPCs for paths
    /// that don't exist (e.g. Cargo probing optional config files).
    /// Invalidated on create, mkdir, rename-to, and symlink which can
    /// make previously non-existent paths exist.
    negative_stat_cache: sync::Mutex<Platform, BTreeSet<String>>,
    /// Maximum single-RPC write payload (negotiated `msize - IOHDRSZ`).
    max_write_payload: usize,
    /// Monotonically increasing generation counter. Bumped on every write,
    /// truncate, or other mutation that invalidates cached data. Used to
    /// prevent stale RPC results from being cached when a concurrent write
    /// occurs during the RPC round-trip.
    cache_generation: AtomicUsize,
}

impl<Platform: sync::RawSyncPrimitivesProvider, W: transport::Write> FileSystem<Platform, W> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    ///
    /// Version negotiation and attach are performed synchronously using both
    /// the writer and reader halves. After construction the reader is returned
    /// for use by the response worker thread (see
    /// [`WorkerHandle::poll_responses`]).
    ///
    /// # Arguments
    ///
    /// * `litebox` - Reference to the LiteBox instance for platform access
    /// * `writer` - Write half of the 9P transport
    /// * `reader` - Read half of the 9P transport (returned after handshake)
    /// * `msize` - Maximum message size to negotiate
    /// * `username` - Username for authentication
    /// * `path` - Attach path (typically the root directory path)
    ///
    /// # Errors
    ///
    /// Returns an error if version negotiation or attach fails.
    pub fn new<R: transport::Read>(
        litebox: &LiteBox<Platform>,
        writer: W,
        reader: R,
        msize: u32,
        username: &str,
        path: &str,
    ) -> Result<(Self, R), Error> {
        let (client, reader, qid, fid) =
            client::Client::new_with_handshake(writer, reader, msize, username, path)?;
        let max_write_payload = (client.msize() - fcall::IOHDRSZ) as usize;

        Ok((
            Self {
                litebox: litebox.clone(),
                client,
                root: (qid, fid, String::from(path)),
                current_working_dir: String::from("/"),
                unlinkat_supported: AtomicBool::new(true),
                write_buffers: sync::Mutex::new(BTreeMap::new()),
                read_buffers: sync::Mutex::new(BTreeMap::new()),
                stat_cache: sync::Mutex::new(BTreeMap::new()),
                dir_fid_cache: sync::Mutex::new(BTreeMap::new()),
                readlink_cache: sync::Mutex::new(BTreeMap::new()),
                negative_stat_cache: sync::Mutex::new(BTreeSet::new()),
                max_write_payload,
                cache_generation: AtomicUsize::new(0),
            },
            reader,
        ))
    }

    /// Construct a synchronous (single-threaded) `FileSystem` instance.
    ///
    /// Unlike [`new`](Self::new), this variant stores the reader inside the
    /// client so that `fcall()` reads responses inline after each send.
    /// No background worker thread is needed.
    ///
    /// Use this for platforms that cannot spawn threads (e.g. SNP kernel).
    pub fn new_sync<R: transport::Read + Send + 'static>(
        litebox: &LiteBox<Platform>,
        writer: W,
        reader: R,
        msize: u32,
        username: &str,
        path: &str,
    ) -> Result<Self, Error> {
        let (fs, reader) = Self::new(litebox, writer, reader, msize, username, path)?;
        fs.client
            .set_inline_reader(alloc::boxed::Box::new(reader), fs.client.msize());
        Ok(fs)
    }

    /// Returns the negotiated maximum message size.
    pub fn msize(&self) -> u32 {
        self.client.msize()
    }

    /// Create a worker handle that can be sent to a background thread.
    ///
    /// The handle holds an `Arc` reference to the shared client inner
    /// state (pending table + poison flag) but **not** to the transport
    /// writer.  This ensures that dropping the `FileSystem` closes the
    /// writer, letting the worker observe EOF and exit cleanly.
    ///
    /// ```ignore
    /// let (fs, mut reader) = FileSystem::new(litebox, writer, reader, ...)?;
    /// let worker_handle = fs.worker_handle();
    /// let msize = fs.msize();
    /// std::thread::spawn(move || {
    ///     let mut buf = Vec::with_capacity(msize as usize);
    ///     while worker_handle.poll_responses(&mut reader, &mut buf) {}
    /// });
    /// ```
    pub fn worker_handle(&self) -> WorkerHandle {
        WorkerHandle {
            inner: self.client.shared_inner(),
        }
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

    /// Discard all read-ahead buffers for the file identified by `qid_path`.
    ///
    /// Called when writes (from any fid) modify the file, making cached
    /// read-ahead data potentially stale.
    fn invalidate_read_buffers_for_file(&self, qid_path: u64) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        let mut buffers = self.read_buffers.lock();
        buffers.retain(|_, rb| rb.qid_path != qid_path);
    }

    /// Invalidate all cached stat results for the file identified by
    /// `qid_path` (inode). This handles alias paths (e.g. symlinks)
    /// that refer to the same underlying file.
    fn invalidate_stat_cache_by_qid(&self, qid_path: u64) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        #[allow(clippy::cast_possible_truncation)]
        // ino is opaque identifier, truncation is acceptable
        let ino = qid_path as usize;
        let mut cache = self.stat_cache.lock();
        cache.retain(|_, status| status.node_info.ino != ino);
    }

    /// Invalidate cached stat for the parent directory of `path`.
    /// Namespace operations (create, unlink, rename, mkdir, rmdir) change
    /// the parent directory's mtime/nlink, so its cached stat must be
    /// discarded. Uses qid-based invalidation to handle symlinked parents.
    fn invalidate_parent_stat_cache(&self, path: &str) {
        if let Some(pos) = path.rfind('/') {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            // Try qid-based invalidation to cover all aliases of the parent.
            if let Ok((fid, qid)) = self.walk_to_with_qid(parent) {
                self.client.clunk_async(fid);
                self.invalidate_stat_cache_by_qid(qid.path);
            } else {
                // Fallback: remove by spelled path if walk fails.
                self.cache_generation.fetch_add(1, Ordering::SeqCst);
                let mut cache = self.stat_cache.lock();
                cache.remove(parent);
            }
        }
    }

    /// Invalidate cached stat results for the given path and all descendants.
    fn invalidate_stat_cache_tree(&self, path: &str) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        let mut cache = self.stat_cache.lock();
        cache.retain(|k, _| k != path && !k.starts_with(&alloc::format!("{path}/")));
    }

    /// Invalidate cached directory fids for the given path and all descendants.
    /// Clunks removed fids on the server.
    fn invalidate_dir_fid_cache_tree(&self, path: &str) {
        let mut cache = self.dir_fid_cache.lock();
        let to_remove: Vec<String> = cache
            .keys()
            .filter(|k| k.as_str() == path || k.starts_with(&alloc::format!("{path}/")))
            .cloned()
            .collect();
        for key in to_remove {
            if let Some((fid, _)) = cache.remove(&key) {
                self.client.clunk_async(fid);
            }
        }
    }

    /// Invalidate cached readlink results for specific paths.
    fn invalidate_readlink_cache(&self, paths: &[&str]) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        let mut cache = self.readlink_cache.lock();
        for path in paths {
            cache.remove(*path);
        }
    }

    /// Invalidate cached readlink results for a path and all descendants
    /// (e.g. when a directory is renamed or removed).
    fn invalidate_readlink_cache_tree(&self, path: &str) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        let prefix = alloc::format!("{path}/");
        let mut cache = self.readlink_cache.lock();
        cache.retain(|k, _| k != path && !k.starts_with(&prefix));
    }

    /// Invalidate negative stat cache entries for specific paths.
    fn invalidate_negative_stat_cache(&self, paths: &[&str]) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        let mut cache = self.negative_stat_cache.lock();
        for path in paths {
            cache.remove(*path);
        }
    }

    /// Invalidate negative stat cache entries for a path and all descendants
    /// (e.g. when a directory is created, previously non-existent children
    /// might now be reachable).
    fn invalidate_negative_stat_cache_tree(&self, path: &str) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        let prefix = alloc::format!("{path}/");
        let mut cache = self.negative_stat_cache.lock();
        cache.retain(|k| k.as_str() != path && !k.starts_with(&prefix));
    }

    /// Negative stat results are intentionally not cached for the mutable 9P
    /// backing store. Other agents may create the path through independent 9P
    /// connections, and this client has no cross-connection invalidation signal.
    fn try_cache_negative(&self, _path: &str, _err: &FileStatusError, _gen_before: usize) {}

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
    fn descriptor_path(&self, dirfd: &FileFd<Platform, W>) -> Option<alloc::string::String> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(dirfd)?;
        Some(entry.entry.path.clone())
    }

    /// Get the stored path from a directory fd's Descriptor.
    fn dir_fd_path(
        &self,
        dirfd: &FileFd<Platform, W>,
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

    /// Walk to a path and return the fid
    fn walk_to(&self, path: &str) -> Result<fcall::Fid, Error> {
        self.walk_to_with_qid(path).map(|(fid, _)| fid)
    }

    /// Find the longest cached directory prefix for a set of path components.
    /// Returns a **cloned** fid (caller must clunk it) and the index of the
    /// first uncached component. Cloning prevents use-after-clunk races with
    /// concurrent `invalidate_dir_fid_cache_tree`.
    fn find_cached_prefix(&self, components: &[&str]) -> Option<(fcall::Fid, usize)> {
        let mut best_prefix_len = 0;
        let mut best_fid = None;
        let cache = self.dir_fid_cache.lock();
        let mut prefix = String::new();
        for (i, comp) in components.iter().enumerate() {
            prefix.push('/');
            prefix.push_str(comp);
            if let Some(&(cached_fid, _)) = cache.get(&prefix) {
                best_prefix_len = i + 1;
                best_fid = Some(cached_fid);
            }
        }
        // Clone the best match so invalidation can safely clunk the original.
        if let Some(fid) = best_fid
            && let Ok(cloned) = self.client.clone_fid(fid)
        {
            return Some((cloned, best_prefix_len));
        }
        // No cache hit, or clone failed (fid already clunked by racing
        // invalidation) — fall back to root.
        None
    }

    /// Walk to a path and return both the fid and the last qid.
    fn walk_to_with_qid(&self, path: &str) -> Result<(fcall::Fid, fcall::Qid), Error> {
        let components: Vec<&str> = path
            .normalized_components()
            .map_err(|_| Error::InvalidPathname)?
            .collect();
        if components.is_empty() {
            let fid = self.client.clone_fid(self.root.1)?;
            return Ok((fid, self.root.0));
        }

        // Find the longest cached directory prefix to start from.
        let (best_fid, best_prefix_len, cloned_cache_fid) =
            if let Some((cloned, prefix_len)) = self.find_cached_prefix(&components) {
                (cloned, prefix_len, true)
            } else {
                (self.root.1, 0, false)
            };

        let remaining = &components[best_prefix_len..];
        if remaining.is_empty() {
            // Full path was cached as a directory — the cloned fid IS our result.
            if cloned_cache_fid {
                let cache = self.dir_fid_cache.lock();
                let prefix: String = components.iter().fold(String::new(), |mut a, c| {
                    a.push('/');
                    a.push_str(c);
                    a
                });
                let qid = cache.get(&prefix).map_or(self.root.0, |&(_, q)| q);
                return Ok((best_fid, qid));
            }
            let fid = self.client.clone_fid(self.root.1)?;
            return Ok((fid, self.root.0));
        }

        let (qids, fid) = match self.client.walk(best_fid, remaining) {
            Ok(r) => {
                if cloned_cache_fid {
                    self.client.clunk_async(best_fid);
                }
                r
            }
            Err(e) => {
                if cloned_cache_fid {
                    self.client.clunk_async(best_fid);
                }
                return Err(e);
            }
        };
        let qid = qids.last().copied().ok_or(Error::InvalidResponse)?;

        // Opportunistically cache the parent directory for future walks.
        // This costs 1 extra walk RPC on first visit but saves many RPCs
        // on subsequent walks to sibling files in the same directory.
        if components.len() > 1 && qids.len() >= 2 {
            let parent_qid = qids[qids.len() - 2];
            if parent_qid.typ.contains(fcall::QidType::DIR) {
                let parent_path: String =
                    components[..components.len() - 1]
                        .iter()
                        .fold(String::new(), |mut a, c| {
                            a.push('/');
                            a.push_str(c);
                            a
                        });
                let mut cache = self.dir_fid_cache.lock();
                if !cache.contains_key(&parent_path) {
                    drop(cache);
                    // Walk the full parent path from root — the cached prefix
                    // fid was already clunked above.
                    let parent_components = &components[..components.len() - 1];
                    if let Ok((_, parent_fid)) = self.client.walk(self.root.1, parent_components) {
                        // Recheck under lock to avoid leaking fids when two
                        // threads race to populate the same cache entry.
                        cache = self.dir_fid_cache.lock();
                        if let Some(&(existing_fid, _)) = cache.get(&parent_path) {
                            // Another thread won the race — clunk ours.
                            drop(cache);
                            self.client.clunk_async(parent_fid);
                            let _ = existing_fid; // keep the winner
                        } else {
                            cache.insert(parent_path, (parent_fid, parent_qid));
                        }
                    }
                }
            }
        }

        Ok((fid, qid))
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
        if flags.contains(super::OFlags::LITEBOX_NO_ELF_PATCH) {
            lflags |= fcall::LOpenFlags::LITEBOX_NO_ELF_PATCH;
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
        Self::stat_fields_to_file_status(attr.valid, attr.qid, &attr.stat)
    }

    fn stat_fields_to_file_status(
        valid: fcall::GetattrMask,
        qid: fcall::Qid,
        stat: &fcall::Stat,
    ) -> Result<super::FileStatus, Error> {
        let file_type = Self::qid_type_to_file_type(qid.typ);

        if valid.contains(fcall::GetattrMask::BASIC) {
            Ok(super::FileStatus {
                file_type,
                mode: super::Mode::from_bits_truncate(stat.mode),
                size: usize::try_from(stat.size).map_err(|_| Error::InvalidResponse)?,
                owner: super::UserInfo {
                    user: u16::try_from(stat.uid).map_err(|_| Error::InvalidResponse)?,
                    group: u16::try_from(stat.gid).map_err(|_| Error::InvalidResponse)?,
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: usize::try_from(qid.path).map_err(|_| Error::InvalidResponse)?,
                    rdev: NonZeroUsize::new(
                        usize::try_from(stat.rdev).map_err(|_| Error::InvalidResponse)?,
                    ),
                },
                blksize: usize::try_from(stat.blksize).map_err(|_| Error::InvalidResponse)?,
            })
        } else {
            Ok(super::FileStatus {
                file_type,
                mode: if valid.contains(fcall::GetattrMask::MODE) {
                    super::Mode::from_bits_truncate(stat.mode)
                } else {
                    super::Mode::empty()
                },
                size: if valid.contains(fcall::GetattrMask::SIZE) {
                    usize::try_from(stat.size).map_err(|_| Error::InvalidResponse)?
                } else {
                    0
                },
                owner: super::UserInfo {
                    user: if valid.contains(fcall::GetattrMask::UID) {
                        u16::try_from(stat.uid).map_err(|_| Error::InvalidResponse)?
                    } else {
                        0
                    },
                    group: if valid.contains(fcall::GetattrMask::GID) {
                        u16::try_from(stat.gid).map_err(|_| Error::InvalidResponse)?
                    } else {
                        0
                    },
                },
                node_info: super::NodeInfo {
                    dev: DEVICE_ID,
                    ino: usize::try_from(qid.path).map_err(|_| Error::InvalidResponse)?,
                    rdev: if valid.contains(fcall::GetattrMask::RDEV) {
                        NonZeroUsize::new(
                            usize::try_from(stat.rdev).map_err(|_| Error::InvalidResponse)?,
                        )
                    } else {
                        None
                    },
                },
                blksize: if valid.contains(fcall::GetattrMask::BLOCKS) {
                    usize::try_from(stat.blksize).map_err(|_| Error::InvalidResponse)?
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
            self.client.clunk_async(parent_fid);
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

impl<Platform: sync::RawSyncPrimitivesProvider, W: transport::Write> Drop
    for FileSystem<Platform, W>
{
    fn drop(&mut self) {
        // Clunk all cached directory fids.
        let cache = self.dir_fid_cache.lock();
        for (_, &(fid, _)) in cache.iter() {
            self.client.clunk_async(fid);
        }
        drop(cache);
        self.client.clunk_async(self.root.1);
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, W: transport::Write> super::private::Sealed
    for FileSystem<Platform, W>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider, W: transport::Write> super::FileSystem
    for FileSystem<Platform, W>
{
    fn walks_follow_symlinks(&self) -> bool {
        // The 9P broker walk canonicalizes every component via
        // fs::canonicalize(), so symlinks are always resolved server-side.
        true
    }

    fn allocate_fid_number(&self) -> Result<u32, super::errors::OpenError> {
        self.client
            .allocate_fid()
            .map_err(super::errors::OpenError::from)
    }

    fn free_fid_number(&self, fid: u32) {
        self.client.free_fid(fid);
    }

    fn clunk_fid_number(&self, fid: u32) {
        self.client.clunk_async(fid);
    }

    fn wrap_existing_fid(
        &self,
        remote_fid: u32,
        path: &str,
        status_flags: super::OFlags,
    ) -> Result<FileFd<Platform, W>, super::errors::OpenError> {
        use fcall::GetattrMask;

        let attr = self
            .client
            .getattr(remote_fid, GetattrMask::BASIC)
            .map_err(super::errors::OpenError::from)?;

        let descriptor = Descriptor {
            fid: remote_fid,
            offset: AtomicUsize::new(0),
            qid: attr.qid,
            path: alloc::string::String::from(path),
            direct_write: status_flags.intersects(OFlags::SYNC | OFlags::DSYNC | OFlags::APPEND),
        };

        let fd = self.litebox.descriptor_table_mut().insert(descriptor);
        Ok(fd)
    }

    fn descriptor_backend_fid(&self, fd: &FileFd<Platform, W>) -> Option<u32> {
        self.litebox
            .descriptor_table()
            .with_entry(fd, |desc| desc.entry.fid)
    }

    #[allow(clippy::similar_names)]
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform, W>, super::errors::OpenError> {
        // TODO: we don't support non-blocking, so ignore that flag instead of returning an error
        let flags = flags - OFlags::NONBLOCK - OFlags::PATH;
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
            | OFlags::NOATIME
            | OFlags::PATH;
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
                    self.client.clunk_async(existing_fid);
                    return Err(OpenError::AlreadyExists);
                }
                // File exists — strip O_TRUNC and open normally, then
                // flush buffers and apply truncation manually.
                let has_trunc = lflags.contains(fcall::LOpenFlags::O_TRUNC);
                let open_flags = lflags & !fcall::LOpenFlags::O_TRUNC & !fcall::LOpenFlags::O_CREAT;
                match self.client.open(existing_fid, open_flags) {
                    Ok(qid) => {
                        if self.flush_write_buffers_for_file(qid.path).is_err() {
                            self.client.clunk_async(existing_fid);
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
                                self.client.clunk_async(existing_fid);
                                return Err(e.into());
                            }
                            self.invalidate_read_buffers_for_file(qid.path);
                        }
                        (qid, existing_fid)
                    }
                    Err(e) => {
                        self.client.clunk_async(existing_fid);
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
                        self.client.clunk_async(dfid);
                        return Err(e.into());
                    }
                }
            }
        } else {
            // Standard walk + open sequence.
            let has_trunc = lflags.contains(fcall::LOpenFlags::O_TRUNC);
            let open_flags = lflags & !fcall::LOpenFlags::O_TRUNC;

            // Find the best cached directory prefix to minimize the walk.
            let (start_fid, prefix_len, cloned_cache_fid) =
                if let Some((cloned, plen)) = self.find_cached_prefix(&components) {
                    (cloned, plen, true)
                } else {
                    (self.root.1, 0, false)
                };
            let remaining = &components[prefix_len..];

            let (qid, opened_fid) = {
                let (_, walked_fid) = match self.client.walk(start_fid, remaining) {
                    Ok(r) => r,
                    Err(e) => {
                        if cloned_cache_fid {
                            self.client.clunk_async(start_fid);
                        }
                        return Err(e.into());
                    }
                };
                if cloned_cache_fid {
                    self.client.clunk_async(start_fid);
                }

                #[cfg(feature = "trace_fs")]
                let trace_fid = walked_fid;

                match self.client.open(walked_fid, open_flags) {
                    Ok(qid) => (qid, walked_fid),
                    Err(e) => {
                        #[cfg(feature = "trace_fs")]
                        log_println!(
                            self.litebox.x.platform,
                            "[9P-TRACE] open FAILED path={:?} fid={} lflags={:?} err={:?}",
                            path,
                            trace_fid,
                            lflags,
                            e,
                        );
                        self.client.clunk_async(walked_fid);
                        return Err(e.into());
                    }
                }
            };

            // Flush any pending write-behind data for the opened file
            // using the qid returned by open(), which is the target's
            // qid after symlink resolution.
            if self.flush_write_buffers_for_file(qid.path).is_err() {
                self.client.clunk_async(opened_fid);
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
                if let Err(e) = self
                    .client
                    .setattr(opened_fid, fcall::SetattrMask::SIZE, stat)
                {
                    self.client.clunk_async(opened_fid);
                    return Err(e.into());
                }
                // Truncation changes file content — invalidate all
                // read-ahead buffers for sibling fids on this file.
                self.invalidate_read_buffers_for_file(qid.path);
            }
            (qid, opened_fid)
        };

        // Clear negative and readlink caches FIRST so concurrent
        // file_status calls cannot observe a stale ENOENT while the
        // remaining stat-cache invalidation is still in progress.
        if flags.contains(OFlags::CREAT) {
            self.invalidate_negative_stat_cache(&[&path]);
            self.invalidate_readlink_cache(&[&path]);
        }
        // Invalidate stat cache when the file was created or truncated.
        if flags.intersects(OFlags::CREAT | OFlags::TRUNC) {
            self.invalidate_stat_cache_by_qid(new_qid.path);
        }
        // Creating a file changes the parent directory's mtime.
        if flags.contains(OFlags::CREAT) {
            self.invalidate_parent_stat_cache(&path);
        }

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

    fn close(&self, fd: &FileFd<Platform, W>) -> Result<(), super::errors::CloseError> {
        let entry = self.litebox.descriptor_table_mut().remove(fd);
        if let Some(entry) = entry {
            // Flush any pending write-behind data before releasing the fid.
            // Propagate flush errors so callers know about data loss.
            let flush_result = self.flush_write_buffer(entry.entry.fid);
            // On flush failure, do_flush_write_buffer re-inserts the
            // unwritten remainder. Remove it unconditionally — the fid is
            // about to be clunked, so the remainder can never be flushed.
            self.write_buffers.lock().remove(&entry.entry.fid);
            self.read_buffers.lock().remove(&entry.entry.fid);
            // Stat cache may be stale after a write-buffer flush.
            self.invalidate_stat_cache_by_qid(entry.entry.qid.path);
            self.client.clunk_async(entry.entry.fid);
            if flush_result.is_err() {
                return Err(super::errors::CloseError::Io);
            }
        }
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform, W>,
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

        // Try to serve the read from the read-ahead buffer.
        {
            let mut buffers = self.read_buffers.lock();
            if let Some(rb) = buffers.get_mut(&fid) {
                let buf_end = rb.file_offset + rb.data.len();
                if read_offset >= rb.file_offset && read_offset < buf_end {
                    let start = read_offset - rb.file_offset;
                    let available = rb.data.len() - start;
                    let n = buf.len().min(available);
                    buf[..n].copy_from_slice(&rb.data[start..start + n]);
                    if offset.is_none() {
                        self.litebox.descriptor_table().with_entry(fd, |desc| {
                            desc.entry.offset.fetch_add(n, Ordering::SeqCst);
                        });
                    }
                    return Ok(n);
                }
                // Read is past the buffer range. If we saw EOF, return 0
                // without issuing another RPC.
                if rb.eof_seen && read_offset >= buf_end {
                    return Ok(0);
                }
                // Read not in buffer range — discard stale buffer.
                buffers.remove(&fid);
            }
        }

        // Issue a read-ahead RPC: request more than the caller asked for
        // so that subsequent sequential reads can be served from the cache
        // without extra RPCs. Cap at READ_AHEAD_SIZE to avoid huge allocations.
        let readahead_size = if buf.len() >= READ_AHEAD_SIZE {
            // Caller already wants a large read — no extra readahead needed.
            buf.len()
        } else {
            READ_AHEAD_SIZE
        };
        let mut readahead_buf = alloc::vec![0u8; readahead_size];

        // Snapshot generation before the read RPC so we can detect
        // concurrent writes that would make the fetched data stale.
        let gen_before = self.cache_generation.load(Ordering::SeqCst);

        // client.read() returns at most msize-IOHDRSZ bytes per call, so we
        // must loop to fill the readahead buffer. A short read (fewer bytes
        // than the per-RPC limit) signals true EOF.
        let mut total_read = 0;
        let max_per_rpc = (self.client.msize() - fcall::IOHDRSZ) as usize;
        loop {
            let remaining = &mut readahead_buf[total_read..];
            let chunk = self
                .client
                .read(fid, (read_offset + total_read) as u64, remaining)?;
            if chunk == 0 {
                break;
            }
            total_read += chunk;
            if total_read >= readahead_size || chunk < remaining.len().min(max_per_rpc) {
                break;
            }
        }

        if total_read == 0 {
            return Ok(0);
        }

        let eof_seen = total_read < readahead_size;

        // Copy what the caller requested.
        let n = buf.len().min(total_read);
        buf[..n].copy_from_slice(&readahead_buf[..n]);

        // Cache any surplus (or just the EOF flag) for future reads,
        // but only if no concurrent write invalidated data during the RPC.
        if (total_read > n || eof_seen)
            && self.cache_generation.load(Ordering::SeqCst) == gen_before
        {
            self.read_buffers.lock().insert(
                fid,
                ReadBuffer {
                    data: readahead_buf[n..total_read].to_vec(),
                    file_offset: read_offset + n,
                    qid_path,
                    eof_seen,
                },
            );
        }

        // Update offset if not using explicit offset.
        if offset.is_none() {
            self.litebox.descriptor_table().with_entry(fd, |desc| {
                desc.entry.offset.fetch_add(n, Ordering::SeqCst);
            });
        }

        Ok(n)
    }

    fn write(
        &self,
        fd: &FileFd<Platform, W>,
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

        // Invalidate any read-ahead buffers for this file — the write
        // makes cached read data potentially stale.
        self.invalidate_read_buffers_for_file(qid_path);

        // Invalidate stat cache — file size/mtime will change.
        self.invalidate_stat_cache_by_qid(qid_path);

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
        fd: &FileFd<Platform, W>,
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
        fd: &FileFd<Platform, W>,
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

        // Invalidate read-ahead buffers — truncation changes file content.
        self.invalidate_read_buffers_for_file(qid.path);

        // Invalidate stat cache — file size will change.
        self.invalidate_stat_cache_by_qid(qid.path);

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
        let (fid, qid) = self.walk_to_with_qid(&path)?;

        let stat = fcall::SetAttr {
            mode: mode.bits(),
            ..Default::default()
        };

        let result = self.client.setattr(fid, fcall::SetattrMask::MODE, stat);
        self.client.clunk_async(fid);

        if result.is_ok() {
            self.invalidate_stat_cache_by_qid(qid.path);
        }

        result.map_err(ChmodError::from)
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), super::errors::ChownError> {
        let path = self.absolute_path(path)?;
        let (fid, qid) = self.walk_to_with_qid(&path)?;

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
        self.client.clunk_async(fid);

        if result.is_ok() {
            self.invalidate_stat_cache_by_qid(qid.path);
        }

        result.map_err(ChownError::from)
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), super::errors::UnlinkError> {
        let abs_path = self.absolute_path(&path).ok();
        // Get the file's qid before removing so we can invalidate all aliases.
        let qid = abs_path
            .as_deref()
            .and_then(|p| self.walk_to_with_qid(p).ok())
            .map(|(fid, qid)| {
                self.client.clunk_async(fid);
                qid
            });
        let result = self
            .remove_file_or_dir(path, true)
            .map_err(UnlinkError::from);
        if result.is_ok() {
            if let Some(q) = qid {
                self.invalidate_stat_cache_by_qid(q.path);
            }
            if let Some(ref p) = abs_path {
                self.invalidate_parent_stat_cache(p);
                // Unlink may remove a symlink — invalidate readlink cache.
                self.invalidate_readlink_cache(&[p]);
            }
        }
        result
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

        // Try to get the destination file's qid (if it exists) so we can
        // invalidate its cached aliases after rename overwrites it.
        let dest_qid = self.walk_to_with_qid(&new_path).ok().map(|(fid, qid)| {
            self.client.clunk_async(fid);
            qid
        });

        // Flush any pending write-behind data for the source file so that
        // the server has the latest contents before the rename. Propagate
        // flush errors — a silent drop would lose acknowledged writes.
        if self.flush_write_buffers_for_file(source_qid.path).is_err() {
            self.client.clunk_async(src_fid);
            return Err(super::errors::RenameError::Io);
        }

        // Walk to the destination parent directory
        let new_components: Vec<&str> = new_path
            .normalized_components()
            .map_err(|_| {
                self.client.clunk_async(src_fid);
                super::errors::RenameError::ReadOnlyFileSystem
            })?
            .collect();

        if new_components.is_empty() {
            self.client.clunk_async(src_fid);
            return Err(super::errors::RenameError::ReadOnlyFileSystem);
        }

        let new_name = *new_components.last().unwrap();
        let parent_components = &new_components[..new_components.len() - 1];
        let dst_dir_fid = if parent_components.is_empty() {
            if let Ok(f) = self.client.clone_fid(self.root.1) {
                f
            } else {
                self.client.clunk_async(src_fid);
                return Err(super::errors::RenameError::ReadOnlyFileSystem);
            }
        } else if let Ok((_, f)) = self.client.walk(self.root.1, parent_components) {
            f
        } else {
            self.client.clunk_async(src_fid);
            return Err(super::errors::RenameError::ReadOnlyFileSystem);
        };

        let result = self.client.rename(src_fid, dst_dir_fid, new_name);
        self.client.clunk_async(src_fid);
        self.client.clunk_async(dst_dir_fid);

        if result.is_ok() {
            // Clear negative and readlink caches FIRST so concurrent
            // file_status calls cannot observe a stale ENOENT while the
            // remaining stat/dir-fid invalidation is still in progress.
            self.invalidate_negative_stat_cache_tree(&old_path);
            self.invalidate_negative_stat_cache_tree(&new_path);
            self.invalidate_readlink_cache_tree(&old_path);
            self.invalidate_readlink_cache_tree(&new_path);
            // Invalidate stat cache for both old and new paths, including
            // any descendants (for directory renames) and all aliases via qid.
            self.invalidate_stat_cache_by_qid(source_qid.path);
            if let Some(dq) = dest_qid {
                self.invalidate_stat_cache_by_qid(dq.path);
            }
            self.invalidate_stat_cache_tree(&old_path);
            self.invalidate_stat_cache_tree(&new_path);
            // Invalidate parent directories — rename changes their mtime.
            self.invalidate_parent_stat_cache(&old_path);
            self.invalidate_parent_stat_cache(&new_path);
            // Invalidate dir fid cache for renamed directories.
            self.invalidate_dir_fid_cache_tree(&old_path);
            self.invalidate_dir_fid_cache_tree(&new_path);

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
        self.client.clunk_async(parent_fid);

        if result.is_ok() {
            // Clear negative cache FIRST so concurrent file_status calls
            // cannot observe a stale ENOENT during parent stat invalidation.
            self.invalidate_negative_stat_cache(&[&path]);
            self.invalidate_parent_stat_cache(&path);
        }

        result.map(|_| ()).map_err(MkdirError::from)
    }

    fn symlink(
        &self,
        target: impl crate::path::Arg,
        linkpath: impl crate::path::Arg,
    ) -> Result<(), SymlinkError> {
        let target = target
            .as_rust_str()
            .map_err(|_| SymlinkError::PathError(PathError::InvalidPathname))?;
        let linkpath = self.absolute_path(linkpath)?;
        let (parent_fid, name) = self.walk_to_parent(&linkpath)?;

        let result = self.client.symlink(parent_fid, name, target, 0);
        self.client.clunk_async(parent_fid);

        if result.is_ok() {
            self.invalidate_negative_stat_cache(&[&linkpath]);
            self.invalidate_parent_stat_cache(&linkpath);
            self.invalidate_readlink_cache(&[&linkpath]);
        }

        result.map(|_| ()).map_err(SymlinkError::from)
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        let abs_path = self.absolute_path(&path).ok();
        // Get the directory's qid before removing so we can invalidate all aliases.
        let qid = abs_path
            .as_deref()
            .and_then(|p| self.walk_to_with_qid(p).ok())
            .map(|(fid, qid)| {
                self.client.clunk_async(fid);
                qid
            });
        let result = self
            .remove_file_or_dir(path, false)
            .map_err(RmdirError::from);
        if result.is_ok() {
            if let Some(q) = qid {
                self.invalidate_stat_cache_by_qid(q.path);
            }
            if let Some(ref p) = abs_path {
                self.invalidate_stat_cache_tree(p);
                self.invalidate_parent_stat_cache(p);
                self.invalidate_dir_fid_cache_tree(p);
                // Removing a directory invalidates readlink entries under it
                // and any negative cache children are no longer reachable.
                self.invalidate_readlink_cache_tree(p);
            }
        }
        result
    }

    fn read_dir(
        &self,
        fd: &FileFd<Platform, W>,
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
                Ok(super::DirEntry {
                    name: String::from_utf8_lossy(&e.name).into_owned(),
                    file_type: Self::qid_type_to_file_type(e.qid.typ),
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

        // Check the stat cache first to avoid any RPCs.
        {
            let cache = self.stat_cache.lock();
            if let Some(cached) = cache.get(&path) {
                return Ok(cached.clone());
            }
        }

        // Snapshot generation before consulting other caches or issuing any
        // RPC so we can detect namespace mutations racing with this lookup.
        let gen_before = self.cache_generation.load(Ordering::SeqCst);

        // Check the negative stat cache — if we previously got ENOENT
        // for this path and no namespace mutations have invalidated it,
        // we can return the error without any RPCs.
        {
            let neg_cache = self.negative_stat_cache.lock();
            if neg_cache.contains(&path) {
                return Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory));
            }
        }

        // Validate the path before issuing RPCs.
        let _ = path
            .normalized_components()
            .map_err(|_| FileStatusError::PathError(PathError::InvalidPathname))?
            .count();

        // Check if there are any pending write buffers at all. If there
        // are, we must flush before querying attributes.
        let has_pending_writes = !self.write_buffers.lock().is_empty();

        if has_pending_writes {
            // Walk + flush + getattr + clunk to ensure
            // correct size/mtime after pending writes.
            let (fid, qid) = match self.walk_to_with_qid(&path) {
                Ok(r) => r,
                Err(e) => {
                    let e = FileStatusError::from(e);
                    self.try_cache_negative(&path, &e, gen_before);
                    return Err(e);
                }
            };
            if self.flush_write_buffers_for_file(qid.path).is_err() {
                self.client.clunk_async(fid);
                return Err(FileStatusError::Io);
            }
            let result = self.client.getattr(fid, fcall::GetattrMask::ALL);
            self.client.clunk_async(fid);
            let status = result
                .and_then(|attr| Self::rgetattr_to_file_status(&attr))
                .map_err(FileStatusError::from)?;
            // Only cache if no concurrent mutation occurred during the RPC.
            if self.cache_generation.load(Ordering::SeqCst) == gen_before {
                self.stat_cache.lock().insert(path, status.clone());
            }
            Ok(status)
        } else {
            // Standard walk + getattr + clunk sequence.
            let (fid, _) = match self.walk_to_with_qid(&path) {
                Ok(r) => r,
                Err(e) => {
                    let e = FileStatusError::from(e);
                    self.try_cache_negative(&path, &e, gen_before);
                    return Err(e);
                }
            };
            let result = self.client.getattr(fid, fcall::GetattrMask::ALL);
            self.client.clunk_async(fid);
            let status = result
                .and_then(|attr| Self::rgetattr_to_file_status(&attr))
                .map_err(FileStatusError::from)?;
            if self.cache_generation.load(Ordering::SeqCst) == gen_before {
                self.stat_cache.lock().insert(path, status.clone());
            }
            Ok(status)
        }
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform, W>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        // Extract fid, qid, and path from the descriptor.
        let (fid, qid_path, path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |desc| {
                (desc.entry.fid, desc.entry.qid.path, desc.entry.path.clone())
            })
            .ok_or(super::errors::FileStatusError::ClosedFd)?;

        // If there are no pending write buffers for this file, the
        // stat cache (populated by file_status) may be valid.
        // Verify the cached entry's inode matches the descriptor's qid
        // to avoid returning metadata for a different file that now
        // occupies the same path (e.g. after unlink + recreate or rename).
        let has_pending_writes = {
            let buffers = self.write_buffers.lock();
            buffers.values().any(|wb| wb.qid_path == qid_path)
        };
        if !has_pending_writes {
            let cache = self.stat_cache.lock();
            #[allow(clippy::cast_possible_truncation)] // ino is opaque identifier
            if let Some(cached) = cache.get(&path)
                && cached.node_info.ino == qid_path as usize
            {
                return Ok(cached.clone());
            }
        }

        // Flush all pending writes for this file (across all fids) so the
        // server reports the correct file size.
        self.flush_write_buffers_for_file(qid_path)?;

        // Perform blocking I/O without holding any locks.
        let attr = self.client.getattr(fid, fcall::GetattrMask::ALL)?;
        let status = Self::rgetattr_to_file_status(&attr)?;

        // Do NOT populate stat_cache here. The descriptor's path may be
        // stale if the file was unlinked and recreated — fstat() on the
        // open fd returns metadata for the deleted inode, which would
        // poison the path-keyed cache for the new file.

        Ok(status)
    }

    fn read_link(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        let abs = self
            .absolute_path(path)
            .map_err(super::errors::ReadLinkError::PathError)?;

        // Snapshot generation before consulting the cache or issuing any
        // RPC so we don't populate the cache with a target raced by a
        // concurrent namespace mutation.
        let gen_before = self.cache_generation.load(Ordering::SeqCst);

        // Check the readlink cache first to avoid any RPCs.
        {
            let cache = self.readlink_cache.lock();
            if let Some(cached) = cache.get(&abs) {
                return Ok(cached.clone());
            }
        }

        // Use standard walk + readlink + clunk sequence with
        // dir_fid_cache prefix lookup.
        let components: Vec<&str> = abs
            .normalized_components()
            .map_err(|_| super::errors::ReadLinkError::PathError(PathError::InvalidPathname))?
            .collect();
        let (start_fid, prefix_len, cloned_cache_fid) =
            if let Some((cloned, plen)) = self.find_cached_prefix(&components) {
                (cloned, plen, true)
            } else {
                (self.root.1, 0, false)
            };
        let remaining = &components[prefix_len..];

        let target = {
            let (_, walked_fid) = match self.client.walk(start_fid, remaining) {
                Ok(r) => r,
                Err(e) => {
                    if cloned_cache_fid {
                        self.client.clunk_async(start_fid);
                    }
                    return Err(e.into());
                }
            };
            if cloned_cache_fid {
                self.client.clunk_async(start_fid);
            }
            let result = self.client.readlink(walked_fid);
            self.client.clunk_async(walked_fid);
            result.map_err(super::errors::ReadLinkError::from)?
        };
        let target_str = alloc::string::String::from_utf8(target)
            .map_err(|_| super::errors::ReadLinkError::Io)?;

        // Cache the readlink result. Symlink targets are immutable unless
        // the symlink is replaced (unlink + symlink), which is handled by
        // cache invalidation in unlink/rename/create.
        if self.cache_generation.load(Ordering::SeqCst) == gen_before {
            self.readlink_cache.lock().insert(abs, target_str.clone());
        }

        Ok(target_str)
    }

    fn open_at(
        &self,
        dirfd: &FileFd<Platform, W>,
        rel_path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform, W>, super::errors::OpenError> {
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

    /// Note: `_follow_symlinks` is currently ignored because
    /// `walks_follow_symlinks()` returns `true` for 9P, meaning the
    /// shim already handles follow/nofollow at the syscall layer by
    /// choosing `stat_at` vs `lstat`. The 9P walk will follow
    /// symlinks regardless, so both stat and lstat end up resolving
    /// the same target. This is acceptable since the broker resolves
    /// all symlinks during walk anyway.
    fn stat_at(
        &self,
        dirfd: &FileFd<Platform, W>,
        rel_path: impl crate::path::Arg,
        _follow_symlinks: bool,
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
        // The 9P broker walk already follows symlinks (via
        // `fs::canonicalize` per component), so we can skip the
        // client-side symlink resolution chain. Just pass the path
        // directly — walk_to + getattr will see the target.
        self.file_status(abs)
    }

    fn unlink_at(
        &self,
        dirfd: &FileFd<Platform, W>,
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
        dirfd: &FileFd<Platform, W>,
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
        old_dirfd: &FileFd<Platform, W>,
        old_rel: impl crate::path::Arg,
        new_dirfd: &FileFd<Platform, W>,
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

    fn fd_path(&self, fd: &FileFd<Platform, W>) -> Option<alloc::string::String> {
        self.descriptor_path(fd)
    }

    fn mkdir_at(
        &self,
        dirfd: &FileFd<Platform, W>,
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

/// Handle for the 9P response worker thread.
///
/// Holds an `Arc` reference to the shared client inner state (pending table
/// and poison flag) so the worker can dispatch responses while the main
/// [`FileSystem`] is in use by guest threads.
///
/// Crucially, this does **not** hold a reference to the transport writer.
/// When the `FileSystem` is dropped the writer is closed immediately,
/// allowing the worker to observe EOF on the reader and exit.
pub struct WorkerHandle {
    inner: alloc::sync::Arc<client::ClientInner>,
}

impl WorkerHandle {
    /// Read one response from the reader and dispatch it to the pending table.
    ///
    /// Returns `false` when the connection is dead (EOF or error),
    /// signalling the worker to exit its loop.
    pub fn poll_responses<R: transport::Read>(
        &self,
        reader: &mut R,
        reader_buf: &mut Vec<u8>,
    ) -> bool {
        self.inner.poll_responses(reader, reader_buf)
    }

    /// Returns a string describing why the client was poisoned (for diagnostics).
    pub fn poison_reason_str(&self) -> &'static str {
        self.inner.poison_reason_str()
    }

    /// Returns true if the client is poisoned.
    pub fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, W: { transport::Write };
    FileSystem<Platform, W>;
    Descriptor;
    crate::fd::SubsystemKind::Fs;
    -> FileFd<Platform, W>;
}

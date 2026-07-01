// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system related functionality

use crate::event::IOPollable;
use crate::fd::{Descriptors, FdEnabledSubsystem, MetadataError, TypedFd};
use crate::path;
use crate::sync::RawSyncPrimitivesProvider;

use alloc::vec::Vec;
use bitflags::bitflags;

use core::ffi::c_uint;
use core::num::NonZeroUsize;

pub mod devices;
pub mod errors;
pub mod in_mem;
pub mod layered;
pub mod nine_p;
pub mod tar_ro;

#[cfg(test)]
mod tests;

use errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, ReadDirError,
    ReadError, RenameError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};

/// Error from resolving a directory file descriptor's path.
///
/// Used internally by `*_at` method implementations to distinguish a missing
/// fd (the table has no entry) from a valid fd that doesn't point to a
/// directory.
#[derive(Debug)]
pub(crate) enum DirFdError {
    /// The fd is not present in the descriptor table.
    ClosedFd,
    /// The fd exists but refers to a non-directory (regular file, device, etc.).
    NotADirectory,
    /// An I/O error occurred while querying the underlying backend.
    Io,
}

/// A private module, to help support writing sealed traits. This module should _itself_ never be
/// made public.
mod private {
    /// A trait to help seal the main `FileSystem` trait.
    ///
    /// This trait is explicitly public, but unnameable, thereby preventing code outside this crate
    /// from implementing this trait.
    pub trait Sealed {}
}

/// A `FileSystem` provides access to all file-system related functionality provided by LiteBox.
///
/// The design of the file-system is chosen by the specific underlying implementation of this trait
/// (e.g., [`in_mem::FileSystem`]), each of which are parametric in the platform they run on.
/// However, users of any of these file systems might find benefit in having most of their code
/// depend on this trait, rather than on any individual file system.
pub trait FileSystem: private::Sealed + FdEnabledSubsystem {
    /// The sync primitive provider used by the descriptor table that stores this
    /// filesystem's fd entries.
    type DescriptorPlatform: RawSyncPrimitivesProvider;

    /// Whether the FS backend automatically follows symlinks during walk.
    ///
    /// When `true`, callers should skip client-side `realpath`-like
    /// canonicalization because the backend already resolves symlinks.
    /// Defaults to `false` (conservative).
    fn walks_follow_symlinks(&self) -> bool {
        false
    }

    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file
    fn open(
        &self,
        path: impl path::Arg,
        flags: OFlags,
        mode: Mode,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<TypedFd<Self>, OpenError>;

    /// Create an anonymous regular file that has no namespace entry.
    ///
    /// This is used for Linux `memfd_create`-style descriptors: the file
    /// behaves like an ordinary seekable regular file, but only the returned
    /// file descriptor keeps it alive.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn create_anonymous_file(
        &self,
        name: &str,
        mode: Mode,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<TypedFd<Self>, errors::CreateAnonymousFileError> {
        Err(errors::CreateAnonymousFileError::NotSupported)
    }

    /// Allocate a fresh client-side fid number without issuing any
    /// 9P (or backend-equivalent) request.
    ///
    /// Used by the legacy-pipes Phase 3 D5-fs install path on
    /// 9P-backed file systems: the worker pre-allocates a fid that
    /// the broker will install state for via `CloneOfd`.
    ///
    /// Default implementation returns `Err(OpenError::Io)`
    /// — backends that don't expose externally-routable fid numbers
    /// (e.g. the in-memory test FS) opt out by inheriting the
    /// default.
    fn allocate_fid_number(&self) -> Result<u32, errors::OpenError> {
        Err(errors::OpenError::Io)
    }

    /// Release a fid number previously obtained from
    /// [`Self::allocate_fid_number`] without issuing a clunk.
    ///
    /// No-op by default.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn free_fid_number(&self, fid: u32) {}

    /// Issue a real close/clunk for an externally installed fid that was
    /// already made visible to the backing server but could not be wrapped in a
    /// guest descriptor.
    ///
    /// No-op by default.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn clunk_fid_number(&self, fid: u32) {}

    /// Wrap an externally installed 9P fid in a guest descriptor.
    ///
    /// See [`crate::fs::nine_p::FileSystem::wrap_existing_fid`] for the
    /// full semantics. Default implementation returns
    /// `Err(OpenError::Io)`.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn wrap_existing_fid(
        &self,
        remote_fid: u32,
        path: &str,
        status_flags: OFlags,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<TypedFd<Self>, errors::OpenError> {
        Err(errors::OpenError::Io)
    }

    /// Extract the externally-routable backend identifier for an
    /// existing open descriptor.
    ///
    /// For 9P-backed filesystems this returns the open Tlopen'd
    /// `fid` number, suitable for handing to the broker via
    /// `RegisterOfd` so that other processes can later
    /// `CloneOfd`/[`Self::wrap_existing_fid`] it into their own
    /// descriptor table while sharing the same open file
    /// description (POSIX shared offset semantics).
    ///
    /// Default implementation returns `None` — backends that don't
    /// expose externally-routable fid numbers (e.g. the in-memory
    /// test FS) opt out by inheriting the default.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn descriptor_backend_fid(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Option<u32> {
        None
    }

    /// Close the file at `fd`.
    ///
    /// Future operations on the `fd` will start to return `ClosedFd` errors.
    fn close(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<(), CloseError>;

    /// Read from a file descriptor at `offset` into a buffer
    ///
    /// If `offset` is None, the read will start at the current file offset and update the file offset
    /// to the end of the read.
    /// If `offset` is Some, the file offset is not changed.
    fn read(
        &self,
        fd: &TypedFd<Self>,
        buf: &mut [u8],
        offset: Option<usize>,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Result<usize, ReadError>;

    /// Write from a buffer to a file descriptor at `offset`
    ///
    /// If `offset` is None, the write will start at the current file offset and update the file offset
    /// to the end of the write.
    /// If `offset` is Some, the file offset is not changed.
    fn write(
        &self,
        fd: &TypedFd<Self>,
        buf: &[u8],
        offset: Option<usize>,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<usize, WriteError>;

    /// Reposition read/write file offset, by changing it to `offset` relative to `whence`.
    ///
    /// Returns the resulting offset (in bytes from start of file) on success.
    fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: SeekWhence,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Result<usize, SeekError>;

    /// Truncate the file to the specified length.
    ///
    /// If shorter than existing size, extra data is lost. If longer than existing size, resize by
    /// adding `\0`s.
    ///
    /// If `reset_offset` is true, the offset is reset to zero; otherwise, it remains unchanged.
    fn truncate(
        &self,
        fd: &TypedFd<Self>,
        length: usize,
        reset_offset: bool,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<(), TruncateError>;

    /// Change the permissions of a file
    fn chmod(&self, path: impl path::Arg, mode: Mode) -> Result<(), ChmodError>;

    /// Change the owner of a file
    fn chown(
        &self,
        path: impl path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError>;

    /// Unlink a file
    fn unlink(&self, path: impl path::Arg) -> Result<(), UnlinkError>;

    /// Rename (move) a file or directory
    fn rename(
        &self,
        old_path: impl path::Arg,
        new_path: impl path::Arg,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<(), RenameError>;

    /// Create a new directory
    fn mkdir(&self, path: impl path::Arg, mode: Mode) -> Result<(), MkdirError>;

    /// Remove a directory
    fn rmdir(&self, path: impl path::Arg) -> Result<(), RmdirError>;

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names (explicitly _not_ including `.` or `..`).
    fn read_dir(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<Vec<DirEntry>, ReadDirError>;

    /// Obtain the status of a file/directory/... on the file-system.
    fn file_status(&self, path: impl path::Arg) -> Result<FileStatus, FileStatusError>;

    /// Equivalent to [`Self::file_status`], but open an open `fd` instead.
    fn fd_file_status(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Result<FileStatus, FileStatusError>;

    /// Get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data (e.g., loaded via `initialize_primarily_read_heavy_file`).
    ///
    /// Returns `None` if indicating no static backing data is available/supported.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn get_static_backing_data(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Option<&'static [u8]> {
        None
    }

    /// Check whether the given fd was opened with write access (`O_WRONLY` or
    /// `O_RDWR`).
    ///
    /// This is a pure metadata query with no I/O side effects. The default
    /// implementation conservatively returns `true`.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn is_writable(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> bool {
        true
    }

    /// Synchronize per-open status flags to the backing file description.
    ///
    /// Most filesystem backends can ignore this because status flags are only
    /// tracked by higher layers for `F_GETFL`. Device-style backends that
    /// implement per-open blocking behavior should override it so `O_NONBLOCK`
    /// and similar flags remain visible on the real backing fd.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn set_open_status_flags(
        &self,
        fd: &TypedFd<Self>,
        flags: OFlags,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<(), MetadataError> {
        Ok(())
    }

    /// Get an `IOPollable` for a file descriptor, if the underlying device supports polling.
    ///
    /// Returns `Some(pollable)` for device types with async event support,
    /// or `None` for regular files that don't support async I/O notifications.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn get_io_pollable(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Option<alloc::boxed::Box<dyn IOPollable>> {
        None
    }

    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn read_link(
        &self,
        path: impl path::Arg,
    ) -> Result<alloc::string::String, errors::ReadLinkError> {
        Err(errors::ReadLinkError::NotSupported)
    }

    /// Create a symbolic link.
    ///
    /// Creates a symlink at `linkpath` pointing to `target`. The default
    /// implementation returns
    /// [`SymlinkError::NotSupported`](errors::SymlinkError::NotSupported),
    /// since most in-memory filesystems don't support symlinks.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn symlink(
        &self,
        target: impl path::Arg,
        linkpath: impl path::Arg,
    ) -> Result<(), errors::SymlinkError> {
        Err(errors::SymlinkError::NotSupported)
    }

    /// Create a hard link.
    ///
    /// Creates a new directory entry `newpath` that refers to the same inode
    /// as `oldpath`. The default implementation returns
    /// [`LinkError::NotSupported`](errors::LinkError::NotSupported).
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn link(
        &self,
        oldpath: impl path::Arg,
        newpath: impl path::Arg,
    ) -> Result<(), errors::LinkError> {
        Err(errors::LinkError::NotSupported)
    }

    // -- fd-relative (`*_at`) methods --
    //
    // These resolve a relative path starting from a directory file descriptor.
    // The path is stored in each FS Descriptor at open time; implementations
    // join it with the relative component and delegate to path-based methods.

    /// Open a file relative to a directory fd.
    fn open_at(
        &self,
        dirfd: &TypedFd<Self>,
        rel_path: impl path::Arg,
        flags: OFlags,
        mode: Mode,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<TypedFd<Self>, OpenError>;

    /// Obtain the status of a file relative to a directory fd.
    fn stat_at(
        &self,
        dirfd: &TypedFd<Self>,
        rel_path: impl path::Arg,
        follow_symlinks: bool,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Result<FileStatus, FileStatusError>;

    /// Unlink a file relative to a directory fd.
    fn unlink_at(
        &self,
        dirfd: &TypedFd<Self>,
        rel_path: impl path::Arg,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Result<(), UnlinkError>;

    /// Read a symbolic link relative to a directory fd.
    fn readlink_at(
        &self,
        dirfd: &TypedFd<Self>,
        rel_path: impl path::Arg,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Result<alloc::string::String, errors::ReadLinkError>;

    /// Rename a file, with source and destination relative to directory fds.
    fn rename_at(
        &self,
        old_dirfd: &TypedFd<Self>,
        old_rel: impl path::Arg,
        new_dirfd: &TypedFd<Self>,
        new_rel: impl path::Arg,
        descriptors: &mut Descriptors<Self::DescriptorPlatform>,
    ) -> Result<(), RenameError>;

    /// Create a directory relative to a directory fd.
    fn mkdir_at(
        &self,
        dirfd: &TypedFd<Self>,
        rel_path: impl path::Arg,
        mode: Mode,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Result<(), MkdirError>;

    /// Get the path associated with an open file descriptor, if available.
    ///
    /// Returns the path that was used to open the file. Used by the ELF
    /// patch cache and diagnostics. The caller supplies the descriptor-table
    /// view so path lookup does not re-acquire the global descriptor-table lock.
    fn fd_path(
        &self,
        fd: &TypedFd<Self>,
        descriptors: &Descriptors<Self::DescriptorPlatform>,
    ) -> Option<alloc::string::String>;
}

pub(crate) fn memfd_display_path(name: &str) -> alloc::string::String {
    alloc::format!("/memfd:{name} (deleted)")
}

bitflags! {
    /// `S_I*` constants for open, ...
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct Mode: c_uint {
        /// `S_IRWXU`: user (file owner) has read, write, and execute permission
        const RWXU = 0o00700;
        /// `S_IRUSR`: user has read permission
        const RUSR = 0o00400;
        /// `S_IWUSR`: user has write permission
        const WUSR = 0o00200;
        /// `S_IXUSR`: user has execute permission
        const XUSR = 0o00100;
        /// `S_IRWXG`: group has read, write, and execute permission
        const RWXG = 0o00070;
        /// `S_IRGRP`: group has read permission
        const RGRP = 0o00040;
        /// `S_IWGRP`: group has write permission
        const WGRP = 0o00020;
        /// `S_IXGRP`: group has execute permission
        const XGRP = 0o00010;
        /// `S_IRWXO`: others have read, write, and execute permission
        const RWXO = 0o00007;
        /// `S_IROTH`: others have read permission
        const ROTH = 0o00004;
        /// `S_IWOTH`: others have write permission
        const WOTH = 0o00002;
        /// `S_IXOTH`: others have execute permission
        const XOTH = 0o00001;
        /// `S_ISUID`: set-user-ID bit
        const SUID = 0o0004000;
        /// `S_ISGID`: set-group-ID bit (see inode(7)).
        const SGID = 0o0002000;
        /// `S_ISVTX`: sticky bit (see inode(7)).
        const SVTX = 0o0001000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// Types of files on a file-system.
///
/// See [`FileSystem::file_status`].
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum FileType {
    RegularFile,
    Directory,
    CharacterDevice,
    Symlink,
}

bitflags! {
    /// `O_*` constants for use with open, ...
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct OFlags: c_uint {
        /// `O_RDONLY`: read-only
        const RDONLY = 0x0;
        /// `O_WRONLY`: write-only
        const WRONLY = 0x1;
        /// `O_RDWR`: read/write.
        ///
        /// This is not equal to `RDONLY | WRONLY`. It's a distinct flag.
        const RDWR = 0x2;
        /// `O_APPEND`: append mode
        const APPEND = 0x400;
        /// `O_ASYNC`: signal-driven I/O
        const ASYNC = 0x2000;
        /// `O_CLOEXEC`: close-on-exec flag
        const CLOEXEC = 0x80000;
        /// `O_CREAT`: if path does not exist, create it as a regular file
        const CREAT = 0x40;
        /// `O_DIRECT`: try to minimize cache effects of I/O for this file
        const DIRECT = 0x4000;
        /// `O_DIRECTORY`: fail if not a directory
        const DIRECTORY = 0x10000;
        /// `O_DSYNC`: write operations on the file will complete according to the requirements of
        /// synchronized I/O *data* integrity completion.
        const DSYNC = 0x1000;
        /// `O_EXCL`: exclusive use
        const EXCL = 0x80;
        /// `O_LARGEFILE`: allow large file support
        const LARGEFILE = 0x8000;
        /// `O_NOATIME`: do not update access time
        const NOATIME = 0x40000;
        /// `O_NOCTTY`: do not assign controlling terminal
        const NOCTTY = 0x100;
        /// `O_NOFOLLOW`: fail if the path does not point to a regular file
        const NOFOLLOW = 0x20000;
        /// `O_NDELAY`: non-blocking mode (same as NONBLOCK)
        const NDELAY = 0x800;
        /// `O_NONBLOCK`: non-blocking mode (same as NDELAY)
        const NONBLOCK = 0x800;
        /// `O_PATH`: open a file descriptor for path resolution only
        const PATH = 0x200000;
        /// `O_SYNC`: write operations on the file will complete according to the requirements of
        /// synchronized I/O file integrity completion (by contrast with the synchronized I/O data
        /// integrity completion provided by `O_DSYNC`.)
        const SYNC = 0x101000;
        /// `O_TMPFILE`: create an unnamed temporary file
        const TMPFILE = 0x410000;
        /// Litebox-internal: open an ELF without broker-side syscall rewriting.
        const LITEBOX_NO_ELF_PATCH = 0x8000_0000;
        /// `O_TRUNC`: truncate the file to zero length
        const TRUNC = 0x200;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;

        /// All file status flags + access modes
        const STATUS_FLAGS_MASK = Self::APPEND.bits()
            | Self::NONBLOCK.bits()
            | Self::DSYNC.bits()
            | Self::ASYNC.bits()
            | Self::DIRECT.bits()
            | Self::LARGEFILE.bits()
            | Self::NOATIME.bits()
            | Self::SYNC.bits()
            | Self::PATH.bits()
            | Self::RDONLY.bits()
            | Self::WRONLY.bits()
            | Self::RDWR.bits();
    }
}

/// The `whence` directive to [`FileSystem::seek`]
pub enum SeekWhence {
    /// The file offset is set to `offset` bytes.
    RelativeToBeginning,
    /// The file offset is set to its current location plus `offset` bytes.
    RelativeToCurrentOffset,
    /// The file offset is set to the size of the file plus `offset` bytes.
    RelativeToEnd,
}

/// The status of a file/directory/... on the file-system, inspired by `stat(3type)`.
///
/// This is explicitly a non-exhaustive struct with public members. As LiteBox evolves, more
/// elements might be added to this struct, allowing file systems to provide richer information
/// about the status of files. However, users of LiteBox must not depend on the completeness or even
/// layout of this particular type.
#[derive(Clone)]
#[non_exhaustive]
pub struct FileStatus {
    /// File type
    pub file_type: FileType,
    /// Permissions for the file
    pub mode: Mode,
    /// Size of the file, in bytes. This value considered informative if this is a regular file.
    pub size: usize,
    /// Owner of the file
    pub owner: UserInfo,
    /// Information about this particular node
    pub node_info: NodeInfo,
    /// Block size for file system I/O
    pub blksize: usize,
}

/// User information
#[derive(Clone, Copy, Debug)]
pub struct UserInfo {
    /// User ID for the owner
    pub user: u16,
    /// Group ID for the owner
    pub group: u16,
}

/// Device/Inode information
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct NodeInfo {
    /// Device number
    pub dev: usize,
    /// Inode number
    pub ino: usize,
    /// Device that is being referred to (will be `Some(...)` only if special file)
    pub rdev: Option<NonZeroUsize>,
}

/// Directory entries returned by [`FileSystem::read_dir`]
#[derive(Debug)]
#[non_exhaustive]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub file_type: FileType,
    pub ino_info: Option<NodeInfo>,
}

impl UserInfo {
    /// The root user
    pub const ROOT: Self = Self { user: 0, group: 0 };
}

/// The size reported as the size of a directory.
const DEFAULT_DIRECTORY_SIZE: usize = 4096;

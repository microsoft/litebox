// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system related functionality
//!
//! A file-system consists of a [`Filesystem`](resolver::Filesystem) that works alongside one or more
//! [`Backend`](backend::Backend)s. Such backends can be composed together: mounted at distinct
//! paths via the [`Composer`](composer::Composer), or stacked as a writable upper over immutable
//! lowers via the [`Overlay`](overlay::Overlay).

use bitflags::bitflags;

use core::ffi::c_uint;
use core::num::NonZeroUsize;

pub mod backend;
pub mod composer;
pub mod devices;
pub mod errors;
pub mod in_mem;
#[doc(hidden)]
pub mod inode_allocator;
pub mod nine_p;
pub mod overlay;
mod provider;
pub mod resolver;
pub mod tar_ro;

pub use provider::{
    FilesystemProviderAdapter, NamespacedFilesystemProvider, create_windows_registry_provider,
};

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
/// See [`resolver::Filesystem::file_status`].
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum FileType {
    RegularFile,
    Directory,
    CharacterDevice,
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
        #[cfg(target_arch = "x86_64")]
        const DIRECT = 0x4000;
        #[cfg(target_arch = "aarch64")]
        const DIRECT = 0x10000;
        /// `O_DIRECTORY`: fail if not a directory
        #[cfg(target_arch = "x86_64")]
        const DIRECTORY = 0x10000;
        #[cfg(target_arch = "aarch64")]
        const DIRECTORY = 0x4000;
        /// `O_DSYNC`: write operations on the file will complete according to the requirements of
        /// synchronized I/O *data* integrity completion.
        const DSYNC = 0x1000;
        /// `O_EXCL`: exclusive use
        const EXCL = 0x80;
        /// `O_LARGEFILE`: allow large file support
        #[cfg(target_arch = "x86_64")]
        const LARGEFILE = 0x8000;
        #[cfg(target_arch = "aarch64")]
        const LARGEFILE = 0x20000;
        /// `O_NOATIME`: do not update access time
        const NOATIME = 0x40000;
        /// `O_NOCTTY`: do not assign controlling terminal
        const NOCTTY = 0x100;
        /// `O_NOFOLLOW`: fail if the path does not point to a regular file
        #[cfg(target_arch = "x86_64")]
        const NOFOLLOW = 0x20000;
        #[cfg(target_arch = "aarch64")]
        const NOFOLLOW = 0x8000;
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
        #[cfg(target_arch = "x86_64")]
        const TMPFILE = 0x410000;
        #[cfg(target_arch = "aarch64")]
        const TMPFILE = 0x404000;
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

/// The `whence` directive to [`resolver::Filesystem::seek`]
#[derive(Copy, Clone)]
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

/// Directory entries returned by [`resolver::Filesystem::read_dir`]
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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system related functionality
//!
//! A file-system consists of a [`Resolver`](resolver::Resolver) that works alongside one or more
//! [`Backend`](backend::Backend)s. Such backends can be composed together: mounted at distinct paths
//! via the [`Composer`](composer::Composer), or stacked as a writable upper over immutable lowers
//! via the [`Overlay`](overlay::Overlay).

use bitflags::bitflags;

use core::ffi::c_uint;

pub mod backend;
pub mod composer;
pub mod devices;
pub mod errors;
pub mod in_mem;
#[doc(hidden)]
pub mod inode_allocator;
pub mod nine_p;
pub mod overlay;
pub mod resolver;
mod service;
pub mod tar_ro;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub(crate) use service::File;
pub use service::{
    FileResult, FileService, UnsupportedFileService, chmod, chown, handle_status, mkdir, open,
    path_status, read, read_directory, rmdir, seek, truncate, unlink, write,
};

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

/// The size reported as the size of a directory.
const DEFAULT_DIRECTORY_SIZE: u64 = 4096;

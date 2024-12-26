//! File-system related functionality

use crate::fd::OwnedFd;
use crate::path;
use crate::platform;

use bitflags::bitflags;
use thiserror::Error;

use core::ffi::c_uint;

/// The `FileSystem` provides access to all file-system related functionality provided by LiteBox.
///
/// A LiteBox `FileSystem` is parametric in the platform it runs on.
pub struct FileSystem<Platform: platform::Provider> {
    platform: &'static Platform,
}

/// Possible errors from a [`FileSystem`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum FsError {}

/// A convenience type-alias for filesytem results
type Result<T> = core::result::Result<T, FsError>;

impl<Platform: platform::Provider> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(platform: &'static Platform) -> Self {
        Self { platform }
    }
}

impl<Platform: platform::Provider> FileSystem<Platform> {
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file
    #[allow(clippy::needless_pass_by_value)] // `path::Arg` already accounts for references
    pub fn open(&self, path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<OwnedFd> {
        // NOTE: It is in functions like this that the platform's functionality can be used through
        // `self.platform` as part of the LiteBox implementation. Users of LiteBox do not need to be
        // concerned with how things connect to each other inside LiteBox, they simply maintain the
        // filesystem object, thereby giving us access to the platform.
        todo!()
    }

    /// Close the file at `fd`
    pub fn close(&self, fd: OwnedFd) -> Result<()> {
        let mut fd = fd;
        fd.mark_as_closed();
        todo!()
    }

    /// Read from a file descriptor into a buffer
    pub fn read(&self, fd: &OwnedFd, buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    /// Write from a buffer to a file descriptor
    pub fn write(&self, fd: &OwnedFd, buf: &[u8]) -> Result<usize> {
        todo!()
    }

    /// Change the permissions of a file
    pub fn chmod(&self, path: impl path::Arg, mode: Mode) -> Result<()> {
        todo!()
    }

    /// Unlink a file
    pub fn unlink(&self, path: impl path::Arg) -> Result<()> {
        todo!()
    }

    /// Create a new directory
    pub fn mkdir(&self, path: impl path::Arg, mode: Mode) -> Result<()> {
        todo!()
    }

    /// Remove a directory
    pub fn rmdir(&self, path: impl path::Arg) -> Result<()> {
        todo!()
    }
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
        /// `O_TRUNC`: truncate the file to zero length
        const TRUNC = 0x200;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

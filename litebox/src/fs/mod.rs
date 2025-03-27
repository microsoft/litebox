//! File-system related functionality

use crate::fd::FileFd;
use crate::path;

use bitflags::bitflags;

use core::ffi::c_uint;

pub mod errors;
pub mod in_mem;
pub mod layered;
pub mod nine_p;
pub(crate) mod shared;
pub mod tar_ro;

#[cfg(test)]
mod tests;

use errors::{
    ChmodError, CloseError, FileStatusError, MkdirError, OpenError, ReadError, RmdirError,
    SeekError, UnlinkError, WriteError,
};

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
pub trait FileSystem: private::Sealed {
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file
    fn open(&self, path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<FileFd, OpenError>;
    /// Close the file at `fd`
    fn close(&self, fd: FileFd) -> Result<(), CloseError>;
    /// Read from a file descriptor at `offset` into a buffer
    ///
    /// If `offset` is None, the read will start at the current file offset and update the file offset
    /// to the end of the read.
    /// If `offset` is Some, the file offset is not changed.
    fn read(&self, fd: &FileFd, buf: &mut [u8], offset: Option<usize>) -> Result<usize, ReadError>;
    /// Write from a buffer to a file descriptor at `offset`
    ///
    /// If `offset` is None, the write will start at the current file offset and update the file offset
    /// to the end of the write.
    /// If `offset` is Some, the file offset is not changed.
    fn write(&self, fd: &FileFd, buf: &[u8], offset: Option<usize>) -> Result<usize, WriteError>;
    /// Reposition read/write file offset, by changing it to `offset` relative to `whence`.
    ///
    /// Returns the resulting offset (in bytes from start of file) on success.
    fn seek(&self, fd: &FileFd, offset: isize, whence: SeekWhence) -> Result<usize, SeekError>;
    /// Change the permissions of a file
    fn chmod(&self, path: impl path::Arg, mode: Mode) -> Result<(), ChmodError>;
    /// Unlink a file
    fn unlink(&self, path: impl path::Arg) -> Result<(), UnlinkError>;
    /// Create a new directory
    fn mkdir(&self, path: impl path::Arg, mode: Mode) -> Result<(), MkdirError>;
    /// Remove a directory
    fn rmdir(&self, path: impl path::Arg) -> Result<(), RmdirError>;
    /// Obtain the status of a file/directory/... on the file-system.
    fn file_status(&self, path: impl path::Arg) -> Result<FileStatus, FileStatusError>;
    /// Equivalent to [`Self::file_status`], but open an open `fd` instead.
    fn fd_file_status(&self, fd: &FileFd) -> Result<FileStatus, FileStatusError>;
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
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileType {
    RegularFile,
    Directory,
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
#[non_exhaustive]
pub struct FileStatus {
    /// File type
    pub file_type: FileType,
    /// Permissions for the file
    pub mode: Mode,
    /// Size of the file, in bytes. This value considered informative if this is a regular file.
    pub size: usize,
}

/// The size reported as the size of a directory.
const DEFAULT_DIRECTORY_SIZE: usize = 4096;

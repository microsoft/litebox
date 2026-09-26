// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system related functionality

use crate::fd::{FdEnabledSubsystem, TypedFd};
use crate::path;

use alloc::vec::Vec;
use bitflags::bitflags;

use core::ffi::c_uint;
use core::num::NonZeroUsize;

pub mod backend;
pub mod composer;
pub mod devices;
pub mod errors;
pub mod flock;
pub mod in_mem;
pub(crate) mod inode_allocator;
pub mod layered;
pub mod nine_p;
pub mod proc;
pub mod resolver;
pub mod tar_ro;

#[cfg(test)]
mod tests;

use errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, ReadDirError,
    ReadError, ReadlinkError, RenameError, RmdirError, SeekError, SymlinkError, TruncateError,
    UnlinkError, UtimeError, WriteError,
};

/// A private module, to help support writing sealed traits. This module should _itself_ never be
/// made public.
mod private {
    /// Capability required for physical upper-layer scaffolding during copy-up.
    ///
    /// The constructor is private to this module, so ordinary filesystem callers cannot bypass
    /// merged-namespace authorization checks.
    pub struct CopyUpToken(());

    pub const COPY_UP: CopyUpToken = CopyUpToken(());

    /// A trait to help seal the main `FileSystem` trait.
    ///
    /// This trait is explicitly public, but unnameable, thereby preventing code outside this crate
    /// from implementing this trait.
    pub trait Sealed {
        /// Materialize a directory that already exists in a lower layer. The default backend has no
        /// privileged copy-up facility and therefore performs an ordinary `mkdir`; writable upper
        /// backends may override this while keeping the capability inaccessible to callers.
        fn mkdir_for_copy_up(
            &self,
            _token: &CopyUpToken,
            path: &str,
            mode: super::Mode,
            _owner: super::UserInfo,
        ) -> Result<(), super::errors::MkdirError>
        where
            Self: super::FileSystem,
        {
            self.mkdir(path, mode)
        }

        /// Create a private regular-file staging node for copy-up. As with
        /// [`Self::mkdir_for_copy_up`], only a backend that can atomically install the supplied
        /// ownership should override the ordinary fallback.
        fn create_file_for_copy_up(
            &self,
            _token: &CopyUpToken,
            path: &str,
            mode: super::Mode,
            _owner: super::UserInfo,
        ) -> Result<crate::fd::TypedFd<Self>, super::errors::OpenError>
        where
            Self: super::FileSystem,
        {
            self.open(
                path,
                super::OFlags::CREAT | super::OFlags::EXCL | super::OFlags::WRONLY,
                mode,
            )
        }

        /// Publish a fully prepared private regular-file staging node. Writable upper backends may
        /// bypass physical-parent permissions here because the layered filesystem already checked
        /// authorization against the merged parent before it began copy-up.
        fn publish_file_for_copy_up(
            &self,
            _token: &CopyUpToken,
            staging_path: &str,
            destination_path: &str,
        ) -> Result<(), super::errors::RenameError>
        where
            Self: super::FileSystem,
        {
            self.rename(staging_path, destination_path, true)
        }

        /// Remove a private staging name while open descriptors retain its inode. This is used for
        /// detached copy-up and for rollback; it has the same narrow physical-parent bypass as the
        /// other copy-up capabilities.
        fn remove_file_for_copy_up(
            &self,
            _token: &CopyUpToken,
            staging_path: &str,
        ) -> Result<(), super::errors::UnlinkError>
        where
            Self: super::FileSystem,
        {
            self.unlink(staging_path)
        }

        /// Read an already-open regular-file object for copy-up without consulting that open
        /// description's guest-visible access mode or changing its offset. This is necessary for a
        /// write-only descriptor whose pathname may already have been unlinked or replaced.
        fn read_file_for_copy_up(
            &self,
            _token: &CopyUpToken,
            fd: &crate::fd::TypedFd<Self>,
            buf: &mut [u8],
            offset: usize,
        ) -> Result<usize, super::errors::ReadError>
        where
            Self: super::FileSystem,
        {
            self.read(fd, buf, Some(offset))
        }

        /// Preserve source timestamps on a private staging file. Backends with internal metadata
        /// access may override this to retain ctime and bypass permissions already authorized by the
        /// merged copy-up operation.
        fn set_times_for_copy_up(
            &self,
            _token: &CopyUpToken,
            fd: &crate::fd::TypedFd<Self>,
            atime: super::Timestamp,
            mtime: super::Timestamp,
            _ctime: super::Timestamp,
        ) -> Result<(), super::errors::UtimeError>
        where
            Self: super::FileSystem,
        {
            self.fd_utimensat(fd, Some(atime), Some(mtime))
        }
    }
}

/// A `FileSystem` provides access to all file-system related functionality provided by LiteBox.
///
/// The design of the file-system is chosen by the specific underlying implementation of this trait
/// (e.g., [`in_mem::FileSystem`]), each of which are parametric in the platform they run on.
/// However, users of any of these file systems might find benefit in having most of their code
/// depend on this trait, rather than on any individual file system.
pub trait FileSystem: private::Sealed + FdEnabledSubsystem {
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file
    fn open(
        &self,
        path: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<Self>, OpenError>;

    /// Close the file at `fd`.
    ///
    /// Future operations on the `fd` will start to return `ClosedFd` errors.
    fn close(&self, fd: &TypedFd<Self>) -> Result<(), CloseError>;

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
    ) -> Result<usize, WriteError>;

    /// Reposition read/write file offset, by changing it to `offset` relative to `whence`.
    ///
    /// Returns the resulting offset (in bytes from start of file) on success.
    fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: SeekWhence,
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
    ) -> Result<(), TruncateError>;

    /// Change the permissions of a file
    fn chmod(&self, path: impl path::Arg, mode: Mode) -> Result<(), ChmodError>;

    /// Equivalent to [`Self::chmod`], but operating on an already-open `fd` directly.
    ///
    /// Unlike [`Self::chmod`], this does not re-resolve a path, so (matching `fchmod(2)`) it keeps
    /// working even if the path used to open `fd` has since been unlinked or replaced by a
    /// different file.
    fn fd_chmod(&self, fd: &TypedFd<Self>, mode: Mode) -> Result<(), ChmodError>;

    /// Change the owner of a file
    fn chown(
        &self,
        path: impl path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError>;

    /// Change the owner of an already-open file descriptor.
    ///
    /// Unlike [`Self::chown`], this does not re-resolve a path, so (matching `fchown(2)`) it keeps
    /// working even if the path used to open `fd` has since been unlinked or replaced. `None` for
    /// either id leaves it unchanged.
    fn fd_chown(
        &self,
        fd: &TypedFd<Self>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError>;

    /// Update the access and/or modification time of a file/directory.
    ///
    /// `None` for either parameter leaves that timestamp unchanged (mirroring `UTIME_OMIT`).
    /// Resolving `UTIME_NOW` into a concrete [`Timestamp`] is the caller's responsibility: this
    /// subsystem has no clock of its own, matching how wall-clock time is already sourced only at
    /// the shim layer (see `Platform: TimeProvider`) rather than threaded through here.
    fn utimensat(
        &self,
        path: impl path::Arg,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError>;

    /// Equivalent to [`Self::utimensat`], but operating on an already-open `fd` directly.
    ///
    /// Unlike [`Self::utimensat`], this does not re-resolve a path, so (matching `futimens(2)`) it
    /// keeps working even if the path used to open `fd` has since been unlinked or replaced by a
    /// different file. See [`Self::utimensat`]'s docs for `None`/`Some` semantics.
    fn fd_utimensat(
        &self,
        fd: &TypedFd<Self>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError>;

    /// Unlink a file
    fn unlink(&self, path: impl path::Arg) -> Result<(), UnlinkError>;

    /// Create a new directory
    fn mkdir(&self, path: impl path::Arg, mode: Mode) -> Result<(), MkdirError>;

    /// Remove a directory
    fn rmdir(&self, path: impl path::Arg) -> Result<(), RmdirError>;

    /// Create a symbolic link at `linkpath` whose contents are the (uninterpreted)
    /// `target` string.
    ///
    /// The `target` is stored verbatim and is not resolved or validated here; a
    /// dangling link (target that does not exist) is allowed, matching `symlink(2)`.
    /// The default body rejects creation, which is the correct answer for a
    /// read-only backend.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn symlink(&self, target: &str, linkpath: impl path::Arg) -> Result<(), SymlinkError> {
        Err(SymlinkError::ReadOnlyFileSystem)
    }

    /// Read the target of the symbolic link at `path`, without following it.
    ///
    /// Returns [`ReadlinkError::NotASymlink`] if `path` is not a symlink. The
    /// default body reports that, which is the correct answer for a backend that
    /// stores no symlinks.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn readlink(&self, path: impl path::Arg) -> Result<alloc::string::String, ReadlinkError> {
        Err(ReadlinkError::NotASymlink)
    }

    /// Atomically rename `oldpath` to `newpath` within the same filesystem.
    ///
    /// If `newpath` already exists it is replaced (subject to the usual
    /// type/emptiness rules) unless `noreplace` is set, in which case an existing
    /// `newpath` is [`RenameError::AlreadyExists`]. A rename that would cross a
    /// filesystem boundary is [`RenameError::CrossDevice`]; the default body
    /// reports that unconditionally, which is the correct answer for any backend
    /// that cannot move an entry in place -- callers such as libuv/Node then fall
    /// back to copy-then-unlink.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn rename(
        &self,
        oldpath: impl path::Arg,
        newpath: impl path::Arg,
        noreplace: bool,
    ) -> Result<(), RenameError> {
        Err(RenameError::CrossDevice)
    }

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names (explicitly _not_ including `.` or `..`).
    fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<DirEntry>, ReadDirError>;

    /// Run `f` while holding exclusive access to a directory open-file description's position.
    ///
    /// Independent opens have independent positions, while duplicated descriptors share one
    /// position. Callers can therefore atomically consume a directory snapshot and publish the
    /// continuation position that a later directory read or [`Self::seek`] observes.
    fn with_dir_position<T>(
        &self,
        fd: &TypedFd<Self>,
        f: impl FnOnce(&mut usize) -> T,
    ) -> Result<T, ReadDirError>;

    /// Obtain the status of a file/directory/... on the file-system.
    fn file_status(&self, path: impl path::Arg) -> Result<FileStatus, FileStatusError>;

    /// Equivalent to [`Self::file_status`], but open an open `fd` instead.
    fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<FileStatus, FileStatusError>;

    /// Get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data (e.g., loaded via `initialize_primarily_read_heavy_file`).
    ///
    /// Returns `None` if indicating no static backing data is available/supported.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        None
    }

    fn open_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<Self>, OpenError> {
        self.open(path, flags, mode)
    }

    fn open_executable_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl path::Arg,
    ) -> Result<(TypedFd<Self>, FileStatus), OpenError> {
        let path = path
            .as_rust_str()
            .map_err(errors::PathError::from)
            .map_err(OpenError::from)?;
        let searched_status =
            self.file_status_as(credentials, path)
                .map_err(|error| match error {
                    FileStatusError::PathError(error) => OpenError::PathError(error),
                    FileStatusError::Io | FileStatusError::ClosedFd => OpenError::Io,
                })?;
        if !matches!(searched_status.file_type, FileType::RegularFile)
            || !dac_allows_as(
                credentials,
                searched_status.owner,
                searched_status.mode,
                DacAccessKind::NonDirectoryExecute,
            )
        {
            return Err(OpenError::AccessNotAllowed);
        }
        let fd = self.open_as(
            AccessCredentials::root(),
            path,
            OFlags::RDONLY,
            Mode::empty(),
        )?;
        let opened_status = self.fd_file_status(&fd).map_err(|_| OpenError::Io)?;
        if opened_status.node_info != searched_status.node_info {
            let _ = self.close(&fd);
            return Err(OpenError::Io);
        }
        Ok((fd, opened_status))
    }

    fn chmod_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        self.chmod(path, mode)
    }

    fn fd_chmod_as(
        &self,
        _credentials: AccessCredentials<'_>,
        fd: &TypedFd<Self>,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        self.fd_chmod(fd, mode)
    }

    fn chown_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.chown(path, user, group)
    }

    fn fd_chown_as(
        &self,
        _credentials: AccessCredentials<'_>,
        fd: &TypedFd<Self>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.fd_chown(fd, user, group)
    }

    fn utimensat_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        self.utimensat(path, atime, mtime)
    }

    fn fd_utimensat_as(
        &self,
        _credentials: AccessCredentials<'_>,
        fd: &TypedFd<Self>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        self.fd_utimensat(fd, atime, mtime)
    }

    fn unlink_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
    ) -> Result<(), UnlinkError> {
        self.unlink(path)
    }

    fn mkdir_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        self.mkdir(path, mode)
    }

    fn rmdir_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
    ) -> Result<(), RmdirError> {
        self.rmdir(path)
    }

    fn symlink_as(
        &self,
        _credentials: AccessCredentials<'_>,
        target: &str,
        linkpath: impl path::Arg,
    ) -> Result<(), SymlinkError> {
        self.symlink(target, linkpath)
    }

    fn readlink_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
    ) -> Result<alloc::string::String, ReadlinkError> {
        self.readlink(path)
    }

    fn rename_as(
        &self,
        _credentials: AccessCredentials<'_>,
        oldpath: impl path::Arg,
        newpath: impl path::Arg,
        noreplace: bool,
    ) -> Result<(), RenameError> {
        self.rename(oldpath, newpath, noreplace)
    }

    fn file_status_as(
        &self,
        _credentials: AccessCredentials<'_>,
        path: impl path::Arg,
    ) -> Result<FileStatus, FileStatusError> {
        self.file_status(path)
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

/// Types of files on a file-system.
///
/// See [`FileSystem::file_status`].
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum FileType {
    RegularFile,
    Directory,
    CharacterDevice,
    /// Symbolic link. The link's target path is read via [`FileSystem::readlink`];
    /// [`FileSystem::file_status`] reports this type without following the link
    /// (i.e. `lstat` semantics).
    SymLink,
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

impl OFlags {
    /// Apply Linux's `O_PATH` flag filtering before pathname lookup or open-time side effects.
    ///
    /// With `O_PATH`, only `O_CLOEXEC`, `O_DIRECTORY`, and `O_NOFOLLOW` remain meaningful; all
    /// other flag bits, including the access mode, `O_CREAT`, and `O_TRUNC`, are ignored.
    #[must_use]
    pub fn normalized_for_open(self) -> Self {
        if self.contains(Self::PATH) {
            self & (Self::PATH | Self::CLOEXEC | Self::DIRECTORY | Self::NOFOLLOW)
        } else {
            self
        }
    }
}

/// The `whence` directive to [`FileSystem::seek`]
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
    /// Last access time
    pub atime: Timestamp,
    /// Last modification time
    pub mtime: Timestamp,
    /// Last status-change time
    pub ctime: Timestamp,
}

/// A POSIX-style timestamp: seconds and nanoseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch.
    pub sec: i64,
    /// The sub-second remainder, in nanoseconds.
    pub nsec: i64,
}

/// User information
#[derive(Clone, Copy, Debug)]
pub struct UserInfo {
    /// User ID for the owner
    pub user: u16,
    /// Group ID for the owner
    pub group: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct AccessCredentials<'a> {
    user: u32,
    group: u32,
    supplementary_groups: &'a [u32],
}

impl<'a> AccessCredentials<'a> {
    pub const fn new(user: u32, group: u32, supplementary_groups: &'a [u32]) -> Self {
        Self {
            user,
            group,
            supplementary_groups,
        }
    }

    pub const fn root() -> AccessCredentials<'static> {
        AccessCredentials::new(0, 0, &[])
    }

    pub(crate) const fn user(self) -> u32 {
        self.user
    }

    pub(crate) fn as_user_info(self) -> Option<UserInfo> {
        Some(UserInfo {
            user: self.user.try_into().ok()?,
            group: self.group.try_into().ok()?,
        })
    }

    pub(crate) fn owns(self, owner: UserInfo) -> bool {
        self.user == u32::from(owner.user)
    }

    pub(crate) fn in_group(self, group: u16) -> bool {
        let group = u32::from(group);
        self.group == group || self.supplementary_groups.contains(&group)
    }
}

impl From<UserInfo> for AccessCredentials<'static> {
    fn from(value: UserInfo) -> Self {
        Self::new(u32::from(value.user), u32::from(value.group), &[])
    }
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

/// The operation whose discretionary-access-control permission is being evaluated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DacAccessKind {
    Read,
    Write,
    DirectorySearch,
    #[allow(
        dead_code,
        reason = "the filesystem has no regular-file execution permission caller yet"
    )]
    NonDirectoryExecute,
}

pub(crate) fn dac_allows_as(
    current: AccessCredentials<'_>,
    owner: UserInfo,
    mode: Mode,
    access: DacAccessKind,
) -> bool {
    if current.user() == 0 {
        return match access {
            DacAccessKind::Read | DacAccessKind::Write | DacAccessKind::DirectorySearch => true,
            DacAccessKind::NonDirectoryExecute => {
                mode.intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH)
            }
        };
    }

    let (owner_bit, group_bit, other_bit) = match access {
        DacAccessKind::Read => (Mode::RUSR, Mode::RGRP, Mode::ROTH),
        DacAccessKind::Write => (Mode::WUSR, Mode::WGRP, Mode::WOTH),
        DacAccessKind::DirectorySearch | DacAccessKind::NonDirectoryExecute => {
            (Mode::XUSR, Mode::XGRP, Mode::XOTH)
        }
    };
    if current.owns(owner) {
        mode.contains(owner_bit)
    } else if current.in_group(owner.group) {
        mode.contains(group_bit)
    } else {
        mode.contains(other_bit)
    }
}

pub(crate) fn sticky_directory_allows_removal(
    credentials: AccessCredentials<'_>,
    parent_owner: UserInfo,
    parent_mode: Mode,
    victim_owner: UserInfo,
) -> bool {
    !parent_mode.contains(Mode::SVTX)
        || credentials.user() == 0
        || credentials.owns(parent_owner)
        || credentials.owns(victim_owner)
}

/// The size reported as the size of a directory.
const DEFAULT_DIRECTORY_SIZE: usize = 4096;

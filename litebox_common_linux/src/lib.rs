// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common Linux-y items suitable for LiteBox

#![no_std]
#![allow(non_camel_case_types)]

use core::ffi::c_char;
use core::time::Duration;
use int_enum::IntEnum;
use litebox::{
    fs::OFlags,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use syscalls::Sysno;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::signal::SigSet;

pub mod errno;
pub mod loader;
pub mod mm;
pub mod physical_pointers;
pub mod signal;
pub mod user_pointers;
pub mod vmap;

extern crate alloc;

use user_pointers::{UserPtr, UserPtrMut};

/// Number of AArch64 general-purpose registers saved by the Linux user ABI
/// (`x0` through `x30`).
#[cfg(target_arch = "aarch64")]
pub const AARCH64_GENERAL_REGISTER_COUNT: usize = 31;

// TODO(jayb): Should errno::Errno be publicly re-exported?

pub const STDIN_FILENO: i32 = 0;
pub const STDOUT_FILENO: i32 = 1;
pub const STDERR_FILENO: i32 = 2;

// linux/futex.h
pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
pub const FUTEX_REQUEUE: i32 = 3;
pub const FUTEX_CMP_REQUEUE: i32 = 4;

// linux/time.h
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_REALTIME_COARSE: i32 = 5;
pub const CLOCK_MONOTONIC_COARSE: i32 = 6;

/// Special value `libc::AT_FDCWD` used to indicate openat should use
/// the current working directory.
pub const AT_FDCWD: i32 = -100;

/// Special value for `utimensat(2)`/`futimens(3)`'s `tv_nsec` field: set the corresponding
/// timestamp to the current time.
pub const UTIME_NOW: u64 = 0x3fff_ffff;
/// Special value for `utimensat(2)`/`futimens(3)`'s `tv_nsec` field: leave the corresponding
/// timestamp unchanged.
pub const UTIME_OMIT: u64 = 0x3fff_fffe;

/// Encoding for ioctl commands.
pub mod ioctl {
    /// The number of bits allocated for the ioctl command number field.
    pub const NRBITS: u32 = 8;
    /// The number of bits allocated for the ioctl command type field.
    pub const TYPEBITS: u32 = 8;
    /// The number of bits allocated for the ioctl command size field.
    pub const SIZEBITS: u32 = 14;
    /// The bit offset for the ioctl command number field.
    pub const NRSHIFT: u32 = 0;
    /// The bit offset for the ioctl command type field.
    pub const TYPESHIFT: u32 = NRSHIFT + NRBITS;
    /// The bit offset for the ioctl command size field.
    pub const SIZESHIFT: u32 = TYPESHIFT + TYPEBITS;
    /// The bit offset for the ioctl command direction field.
    pub const DIRSHIFT: u32 = SIZESHIFT + SIZEBITS;
    /// Represents no data transfer direction for the ioctl command.
    pub const NONE: u32 = 0;
    /// Represents the write data transfer direction for the ioctl command.
    pub const WRITE: u32 = 1;
    /// Represents the read data transfer direction for the ioctl command.
    pub const READ: u32 = 2;

    /// Encode an ioctl command.
    #[macro_export]
    macro_rules! ioc {
        ($direction:expr, $type:expr, $number:expr, $size:expr) => {
            (($direction as u32) << $crate::ioctl::DIRSHIFT)
                | (($type as u32) << $crate::ioctl::TYPESHIFT)
                | (($number as u32) << $crate::ioctl::NRSHIFT)
                | (($size as u32) << $crate::ioctl::SIZESHIFT)
        };
    }

    /// Encode an ioctl command that writes.
    #[macro_export]
    macro_rules! iow {
        ($ty:expr, $nr:expr, $sz:expr) => {
            $crate::ioc!($crate::ioctl::WRITE, $ty, $nr, $sz)
        };
    }
}

bitflags::bitflags! {
    /// Desired memory protection of a memory mapping.
    #[derive(PartialEq, Debug)]
    pub struct ProtFlags: core::ffi::c_int {
        /// Pages cannot be accessed.
        const PROT_NONE = 0;
        /// Pages can be read.
        const PROT_READ = 1 << 0;
        /// Pages can be written.
        const PROT_WRITE = 1 << 1;
        /// Pages can be executed
        const PROT_EXEC = 1 << 2;
        /// Apply the protection mode down to the beginning of a
        /// mapping that grows downward
        const PROT_GROWSDOWN = 1 << 24;
        /// Apply the protection mode up to the end of a mapping that
        /// grows upwards.
        const PROT_GROWSUP = 1 << 25;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;

        const PROT_READ_EXEC = Self::PROT_READ.bits() | Self::PROT_EXEC.bits();
        const PROT_READ_WRITE = Self::PROT_READ.bits() | Self::PROT_WRITE.bits();
        const PROT_READ_WRITE_EXEC = Self::PROT_READ.bits() | Self::PROT_WRITE.bits() | Self::PROT_EXEC.bits();
    }
}

bitflags::bitflags! {
    /// Additional parameters for [`mmap`].
    #[derive(Debug)]
    pub struct MapFlags: core::ffi::c_int {
        /// Share this mapping. Mutually exclusive with `MAP_PRIVATE`.
        const MAP_SHARED = 0x1;
        /// This flag provides the same behavior as MAP_SHARED except that
        /// MAP_SHARED mappings ignore unknown flags in flags.  By contrast,
        /// when creating a mapping using MAP_SHARED_VALIDATE, the kernel
        /// verifies all passed flags are known and fails the mapping with
        /// the error EOPNOTSUPP for unknown flags.
        const MAP_SHARED_VALIDATE = 0x3;
        /// Changes are private
        const MAP_PRIVATE = 0x2;
        /// Interpret addr exactly
        const MAP_FIXED = 0x10;
        /// don't use a file
        const MAP_ANONYMOUS = 0x20;
        /// Synonym for [`MAP_ANONYMOUS`]
        const MAP_ANON = 0x20;
        /// Put the mapping into the first 2GB of the process address space.
        const MAP_32BIT = 0x40;
        /// Used for stacks; indicates to the kernel that the mapping should extend downward in memory.
        const MAP_GROWSDOWN = 0x100;
        /// Mark the mmaped region to be locked in the same way as `mlock(2)`.
        const MAP_LOCKED = 0x2000;
        /// Do not reserve swap space for this mapping.
        const MAP_NORESERVE = 0x4000;
        /// Populate page tables for a mapping.
        const MAP_POPULATE = 0x8000;
        /// Only meaningful when used with `MAP_POPULATE`. Don't perform read-ahead.
        const MAP_NONBLOCK = 0x10000;
        /// Perform synchronous page faults for the mapping
        const MAP_SYNC = 0x80000;
        /// Allocate the mapping using "huge pages".
        const MAP_HUGETLB = 0x40000;
        /// Make use of 2MB huge page
        const MAP_HUGE_2MB = 0x54000000;
        /// Make use of 1GB huge page
        const MAP_HUGE_1GB = 0x78000000;
        /// Place the mapping at exactly the address specified in `addr`, but never clobber an existing range.
        const MAP_FIXED_NOREPLACE = 0x100000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// Options for access()
    #[derive(Debug, PartialEq)]
    pub struct AccessFlags: core::ffi::c_int {
        /// Test for existence of file.
        const F_OK = 0;
        /// Test for read permission.
        const R_OK = 4;
        /// Test for write permission.
        const W_OK = 2;
        /// Test for execute (search) permission.
        const X_OK = 1;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// Flags that control how the various *at syscalls behave.
    /// E.g., `openat`, `fstatat`, `unlinkat`, etc.
    #[derive(Debug)]
    pub struct AtFlags: core::ffi::c_int {
        /// Allow empty relative pathname, operate on the provided directory file
        /// descriptor instead.
        const AT_EMPTY_PATH = 0x1000;
        /// Don't automount the terminal ("basename") component of pathname if it is a directory
        /// that is an automount point.
        const AT_NO_AUTOMOUNT = 0x800;
        /// Follow symbolic links.
        const AT_SYMLINK_FOLLOW = 0x400;
        /// Used with `faccessat`, the checks for accessibility are performed using the
        /// effective user and group IDs instead of the real user and group ID
        const AT_EACCESS = 0x200;
        /// Do not follow symbolic links.
        const AT_SYMLINK_NOFOLLOW = 0x100;

        /// Type of synchronisation required from statx(), used to control what sort of
        /// synchronization the kernel will do when querying a file on a remote filesystem
        const AT_STATX_SYNC_TYPE = 0x6000;
        /// Do whatever stat() does
        const AT_STATX_SYNC_AS_STAT = 0x0;
        /// Force the attributes to be sync'd with the server
        const AT_STATX_FORCE_SYNC = 0x2000;
        /// Don't sync attributes with the server
        const AT_STATX_DONT_SYNC = 0x4000;

        /// Used with `unlinkat`, remove directory instead of unlinking a file.
        const AT_REMOVEDIR = 0x200;

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[repr(u32)]
#[derive(IntEnum)]
pub enum InodeType {
    /// FIFO (named pipe)
    NamedPipe = 0o010000,
    /// character device
    CharDevice = 0o020000,
    /// directory
    Dir = 0o040000,
    /// block device
    BlockDevice = 0o060000,
    /// regular file
    File = 0o100000,
    /// symbolic link
    SymLink = 0o120000,
    /// socket
    Socket = 0o140000,
}

impl From<litebox::fs::FileType> for InodeType {
    fn from(value: litebox::fs::FileType) -> Self {
        match value {
            litebox::fs::FileType::RegularFile => InodeType::File,
            litebox::fs::FileType::Directory => InodeType::Dir,
            litebox::fs::FileType::CharacterDevice => InodeType::CharDevice,
            litebox::fs::FileType::SymLink => InodeType::SymLink,
            _ => unimplemented!(),
        }
    }
}

#[repr(u8)]
pub enum DirentType {
    /// Unknown
    Unknown = 0,
    /// FIFO (named pipe)
    NamedPipe = 1,
    /// Character device
    CharDevice = 2,
    /// Directory
    Directory = 4,
    /// Block device
    BlockDevice = 6,
    /// Regular file
    Regular = 8,
    /// Symbolic link
    SymLink = 10,
    /// Socket
    Socket = 12,
}

impl From<litebox::fs::FileType> for DirentType {
    fn from(value: litebox::fs::FileType) -> Self {
        match value {
            litebox::fs::FileType::RegularFile => DirentType::Regular,
            litebox::fs::FileType::Directory => DirentType::Directory,
            litebox::fs::FileType::CharacterDevice => DirentType::CharDevice,
            litebox::fs::FileType::SymLink => DirentType::SymLink,
            _ => unimplemented!(),
        }
    }
}

/// Linux's `stat` struct
#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Clone, Default, PartialEq, Debug, FromBytes, IntoBytes)]
pub struct FileStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    #[expect(clippy::pub_underscore_fields)]
    pub __pad0: core::ffi::c_int,
    pub st_rdev: u64,
    pub st_size: usize,
    pub st_blksize: usize,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    #[expect(clippy::pub_underscore_fields)]
    pub __unused: [i64; 3],
}

/// Linux's `stat` struct for aarch64.
/// Uses the generic `struct stat` layout from <asm-generic/stat.h>.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Default, PartialEq, Debug, FromBytes, IntoBytes)]
pub struct FileStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    #[expect(clippy::pub_underscore_fields)]
    pub __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    #[expect(clippy::pub_underscore_fields)]
    pub __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    #[expect(clippy::pub_underscore_fields)]
    pub __unused: [u32; 2],
}

/// Linux's `iovec` struct for `writev`
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct IoWriteVec {
    pub iov_base: UserPtr<u8>,
    pub iov_len: usize,
}

/// Linux's `iovec` struct for `readv`
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct IoReadVec {
    pub iov_base: UserPtrMut<u8>,
    pub iov_len: usize,
}

/// `iovec` struct for both read and write
pub type IoVec = IoReadVec;

impl From<litebox::fs::FileStatus> for FileStat {
    fn from(value: litebox::fs::FileStatus) -> Self {
        // TODO: add more fields
        let litebox::fs::FileStatus {
            file_type,
            mode,
            size,
            owner: litebox::fs::UserInfo { user, group },
            node_info: litebox::fs::NodeInfo { dev, ino, rdev },
            blksize,
            atime,
            mtime,
            ctime,
            ..
        } = value;
        Self {
            st_dev: <_>::try_from(dev).unwrap(),
            st_ino: <_>::try_from(ino).unwrap(),
            st_nlink: 1,
            st_mode: (mode.bits() | InodeType::from(file_type) as u32).trunc(),
            st_uid: <_>::from(user),
            st_gid: <_>::from(group),
            st_rdev: rdev
                .map(|r| <_>::try_from(r.get()).unwrap())
                .unwrap_or_default(),
            #[cfg(target_arch = "x86_64")]
            #[allow(clippy::cast_possible_wrap)]
            st_size: size,
            #[cfg(target_arch = "aarch64")]
            #[allow(clippy::cast_possible_wrap)]
            st_size: size as i64,
            #[cfg(target_arch = "x86_64")]
            st_blksize: blksize,
            #[cfg(target_arch = "aarch64")]
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            st_blksize: blksize as i32,
            st_blocks: 0,
            st_atime: atime.sec,
            st_atime_nsec: atime.nsec,
            st_mtime: mtime.sec,
            st_mtime_nsec: mtime.nsec,
            st_ctime: ctime.sec,
            st_ctime_nsec: ctime.nsec,
            ..Default::default()
        }
    }
}

bitflags::bitflags! {
    /// Field-selection mask for [`statx`].
    ///
    /// Each bit asks the kernel to fill the corresponding field in [`Statx`].
    /// `STATX__RESERVED` (0x8000_0000) is rejected with `EINVAL` by Linux and
    /// must not appear in user input.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct StatxMask: u32 {
        const STATX_TYPE = 0x0000_0001;
        const STATX_MODE = 0x0000_0002;
        const STATX_NLINK = 0x0000_0004;
        const STATX_UID = 0x0000_0008;
        const STATX_GID = 0x0000_0010;
        const STATX_ATIME = 0x0000_0020;
        const STATX_MTIME = 0x0000_0040;
        const STATX_CTIME = 0x0000_0080;
        const STATX_INO = 0x0000_0100;
        const STATX_SIZE = 0x0000_0200;
        const STATX_BLOCKS = 0x0000_0400;
        const STATX_BASIC_STATS = Self::STATX_TYPE.bits()
            | Self::STATX_MODE.bits()
            | Self::STATX_NLINK.bits()
            | Self::STATX_UID.bits()
            | Self::STATX_GID.bits()
            | Self::STATX_ATIME.bits()
            | Self::STATX_MTIME.bits()
            | Self::STATX_CTIME.bits()
            | Self::STATX_INO.bits()
            | Self::STATX_SIZE.bits()
            | Self::STATX_BLOCKS.bits();
        const STATX_BTIME = 0x0000_0800;
        const STATX_MNT_ID = 0x0000_1000;
        const STATX_DIOALIGN = 0x0000_2000;
        const STATX_MNT_ID_UNIQUE = 0x0000_4000;
        const STATX_SUBVOL = 0x0000_8000;
        const STATX_WRITE_ATOMIC = 0x0001_0000;
        const STATX_DIO_READ_ALIGN = 0x0002_0000;

        /// Named constant so callers can spell out the EINVAL check explicitly.
        const STATX__RESERVED = 0x8000_0000;

        /// Accept unknown future bits without truncating; the kernel silently
        /// ignores them and reports the actual filled set via [`Statx::stx_mask`].
        const _ = !0;
    }
}

/// Linux's `struct statx_timestamp` (16 bytes, `linux/stat.h`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, FromBytes, IntoBytes, Immutable)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    #[expect(clippy::pub_underscore_fields)]
    pub __reserved: i32,
}

/// Linux's `struct statx` (256 bytes, `linux/stat.h`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, FromBytes, IntoBytes, Immutable)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    #[expect(clippy::pub_underscore_fields)]
    pub __spare0: [u16; 1],
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    #[expect(clippy::pub_underscore_fields)]
    pub __spare3: [u64; 12],
}

/// Extract the major component from a Linux `dev_t` (matches `major(3)` from glibc).
fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)).trunc()
}
/// Extract the minor component from a Linux `dev_t` (matches `minor(3)`).
fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)).trunc()
}

impl From<litebox::fs::FileStatus> for Statx {
    fn from(value: litebox::fs::FileStatus) -> Self {
        let litebox::fs::FileStatus {
            file_type,
            mode,
            size,
            owner: litebox::fs::UserInfo { user, group },
            node_info: litebox::fs::NodeInfo { dev, ino, rdev },
            blksize,
            atime,
            mtime,
            ctime,
            ..
        } = value;
        let dev = dev as u64;
        let rdev = rdev.map_or(0u64, |r| r.get() as u64);
        Self {
            stx_mask: StatxMask::STATX_BASIC_STATS.bits(),
            stx_blksize: blksize.trunc(),
            stx_nlink: 1,
            stx_uid: u32::from(user),
            stx_gid: u32::from(group),
            stx_mode: (mode.bits() | InodeType::from(file_type) as u32).trunc(),
            stx_ino: ino as u64,
            stx_size: size as u64,
            stx_atime: statx_timestamp(atime.sec, atime.nsec),
            stx_mtime: statx_timestamp(mtime.sec, mtime.nsec),
            stx_ctime: statx_timestamp(ctime.sec, ctime.nsec),
            stx_blocks: 0,
            stx_rdev_major: dev_major(rdev),
            stx_rdev_minor: dev_minor(rdev),
            stx_dev_major: dev_major(dev),
            stx_dev_minor: dev_minor(dev),
            ..Default::default()
        }
    }
}

fn statx_timestamp(seconds: i64, nanoseconds: i64) -> StatxTimestamp {
    StatxTimestamp {
        tv_sec: seconds,
        tv_nsec: u32::try_from(nanoseconds).unwrap_or(u32::MAX),
        ..Default::default()
    }
}

impl From<FileStat> for Statx {
    fn from(value: FileStat) -> Self {
        Self {
            stx_mask: StatxMask::STATX_BASIC_STATS.bits(),
            #[cfg(target_arch = "x86_64")]
            stx_blksize: value.st_blksize.trunc(),
            #[cfg(target_arch = "aarch64")]
            stx_blksize: value.st_blksize.reinterpret_as_unsigned(),
            stx_nlink: value.st_nlink.trunc(),
            stx_uid: value.st_uid,
            stx_gid: value.st_gid,
            stx_mode: value.st_mode.trunc(),
            stx_ino: value.st_ino,
            #[cfg(target_arch = "x86_64")]
            stx_size: value.st_size as u64,
            #[cfg(target_arch = "aarch64")]
            stx_size: value.st_size.reinterpret_as_unsigned(),
            stx_blocks: value.st_blocks.reinterpret_as_unsigned(),
            stx_atime: statx_timestamp(value.st_atime, value.st_atime_nsec),
            stx_ctime: statx_timestamp(value.st_ctime, value.st_ctime_nsec),
            stx_mtime: statx_timestamp(value.st_mtime, value.st_mtime_nsec),
            stx_rdev_major: dev_major(value.st_rdev),
            stx_rdev_minor: dev_minor(value.st_rdev),
            stx_dev_major: dev_major(value.st_dev),
            stx_dev_minor: dev_minor(value.st_dev),
            ..Default::default()
        }
    }
}

/// Commands for use with `fcntl`.
#[derive(Debug)]
#[non_exhaustive]
pub enum FcntlArg {
    /// Get the file descriptor flags
    GETFD,
    /// Set the file descriptor flags
    SETFD(FileDescriptorFlags),
    /// Get descriptor status flags
    GETFL,
    /// Set descriptor status flags
    SETFL(OFlags),
    /// Get a file lock
    GETLK(UserPtrMut<Flock>),
    /// Set a file lock
    SETLK(UserPtr<Flock>),
    /// Set a file lock and wait if blocked
    SETLKW(UserPtr<Flock>),
    /// Add seals to a memfd
    ADD_SEALS(u32),
    /// Get seals from a memfd
    GET_SEALS,
    /// Duplicate file descriptor
    DUPFD { cloexec: bool, min_fd: u32 },
}

#[repr(i16)]
#[derive(Debug, IntEnum)]
pub enum FlockType {
    /// Shared or read lock
    ReadLock = 0,
    /// Exclusive or write lock
    WriteLock = 1,
    /// Remove lock
    Unlock = 2,
}

#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes)]
pub struct Flock {
    /// Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK
    pub type_: i16,
    /// Where `start' is relative to
    pub whence: i16,
    #[cfg(target_pointer_width = "64")]
    #[doc(hidden)]
    pub __pad0: u32,
    /// Offset where the lock begins
    pub start: usize,
    /// Size of the locked area, 0 means until EOF
    pub len: isize,
    /// Process holding the lock
    pub pid: i32,
    #[cfg(target_pointer_width = "64")]
    #[doc(hidden)]
    pub __pad1: u32,
}

bitflags::bitflags! {
    /// The `operation` argument to `flock(2)`: a lock kind (`LOCK_SH`/`LOCK_EX`/`LOCK_UN`,
    /// mutually exclusive) optionally combined with `LOCK_NB`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FlockOperation: core::ffi::c_int {
        /// Place a shared lock.
        const LOCK_SH = 1;
        /// Place an exclusive lock.
        const LOCK_EX = 2;
        /// Don't block when locking.
        const LOCK_NB = 4;
        /// Remove an existing lock.
        const LOCK_UN = 8;
    }
}

const F_DUPFD: i32 = 0;
const F_DUPFD_CLOEXEC: i32 = 1030;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const F_GETLK: i32 = 5;
const F_SETLK: i32 = 6;
const F_SETLKW: i32 = 7;
const F_ADD_SEALS: i32 = 1033;
const F_GET_SEALS: i32 = 1034;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FileDescriptorFlags: u32 {
        /// Close-on-exec flag
        const FD_CLOEXEC = 0x1;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

impl FcntlArg {
    pub fn try_from(cmd: i32, arg: usize) -> Option<Self> {
        Some(match cmd {
            F_GETFD => Self::GETFD,
            F_SETFD => Self::SETFD(FileDescriptorFlags::from_bits_truncate(arg.trunc())),
            F_GETFL => Self::GETFL,
            F_SETFL => Self::SETFL(OFlags::from_bits_truncate(arg.trunc())),
            F_GETLK => Self::GETLK(UserPtrMut::from_usize(arg)),
            F_SETLK => Self::SETLK(UserPtr::from_usize(arg)),
            F_SETLKW => Self::SETLKW(UserPtr::from_usize(arg)),
            F_ADD_SEALS => Self::ADD_SEALS(arg.trunc()),
            F_GET_SEALS => Self::GET_SEALS,
            F_DUPFD => Self::DUPFD {
                cloexec: false,
                min_fd: arg.trunc(),
            },
            F_DUPFD_CLOEXEC => Self::DUPFD {
                cloexec: true,
                min_fd: arg.trunc(),
            },
            _ => return None,
        })
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct EfdFlags: core::ffi::c_uint {
        const SEMAPHORE = 1;
        const CLOEXEC = litebox::fs::OFlags::CLOEXEC.bits();
        const NONBLOCK = litebox::fs::OFlags::NONBLOCK.bits();
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

type cc_t = ::core::ffi::c_uchar;
type tcflag_t = ::core::ffi::c_uint;
#[repr(C)]
#[derive(Debug, Clone, FromBytes, IntoBytes)]
pub struct Termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 19usize],
}

impl Termios {
    /// A sensible "cooked" (canonical) mode default, matching what a typical Linux pty session
    /// starts in: canonical line editing, echo, signal-generating control characters, and
    /// `\n` -> `\r\n` translation on output. Real values from
    /// `include/uapi/asm-generic/termbits.h`.
    #[must_use]
    pub const fn default_cooked() -> Self {
        let mut c_cc = [0u8; 19];
        c_cc[VintrIdx::VINTR as usize] = 3; // ^C
        c_cc[VintrIdx::VQUIT as usize] = 28; // ^\
        c_cc[VintrIdx::VERASE as usize] = 127; // DEL
        c_cc[VintrIdx::VKILL as usize] = 21; // ^U
        c_cc[VintrIdx::VEOF as usize] = 4; // ^D
        c_cc[VintrIdx::VTIME as usize] = 0;
        c_cc[VintrIdx::VMIN as usize] = 1;
        c_cc[VintrIdx::VSTART as usize] = 17; // ^Q
        c_cc[VintrIdx::VSTOP as usize] = 19; // ^S
        c_cc[VintrIdx::VSUSP as usize] = 26; // ^Z
        c_cc[VintrIdx::VREPRINT as usize] = 18; // ^R
        c_cc[VintrIdx::VDISCARD as usize] = 15; // ^O
        c_cc[VintrIdx::VWERASE as usize] = 23; // ^W
        c_cc[VintrIdx::VLNEXT as usize] = 22; // ^V
        Self {
            c_iflag: IFlag::ICRNL.bits() | IFlag::IXON.bits(),
            c_oflag: OFlag::OPOST.bits() | OFlag::ONLCR.bits(),
            c_cflag: CFlag::CS8.bits() | CFlag::CREAD.bits(),
            c_lflag: LFlag::ISIG.bits()
                | LFlag::ICANON.bits()
                | LFlag::ECHO.bits()
                | LFlag::ECHOE.bits()
                | LFlag::ECHOK.bits()
                | LFlag::ECHOCTL.bits()
                | LFlag::ECHOKE.bits()
                | LFlag::IEXTEN.bits(),
            c_line: 0,
            c_cc,
        }
    }

    /// Whether canonical (line-buffered, editable) input mode is enabled.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        LFlag::from_bits_truncate(self.c_lflag).contains(LFlag::ICANON)
    }

    /// Whether the terminal driver is echoing typed input back.
    #[must_use]
    pub fn is_echoing(&self) -> bool {
        LFlag::from_bits_truncate(self.c_lflag).contains(LFlag::ECHO)
    }
}

impl Default for Termios {
    fn default() -> Self {
        Self::default_cooked()
    }
}

/// Indices into [`Termios::c_cc`], from `include/uapi/asm-generic/termbits.h`.
#[non_exhaustive]
#[repr(u8)]
pub enum VintrIdx {
    VINTR = 0,
    VQUIT = 1,
    VERASE = 2,
    VKILL = 3,
    VEOF = 4,
    VTIME = 5,
    VMIN = 6,
    VSWTC = 7,
    VSTART = 8,
    VSTOP = 9,
    VSUSP = 10,
    VEOL = 11,
    VREPRINT = 12,
    VDISCARD = 13,
    VWERASE = 14,
    VLNEXT = 15,
    VEOL2 = 16,
}

bitflags::bitflags! {
    /// `c_iflag` bits, from `include/uapi/asm-generic/termbits.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IFlag: tcflag_t {
        const IGNBRK = 0o000001;
        const BRKINT = 0o000002;
        const IGNPAR = 0o000004;
        const PARMRK = 0o000010;
        const INPCK  = 0o000020;
        const ISTRIP = 0o000040;
        const INLCR  = 0o000100;
        const IGNCR  = 0o000200;
        const ICRNL  = 0o000400;
        const IXON   = 0o002000;
        const IXANY  = 0o004000;
        const IXOFF  = 0o010000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// `c_oflag` bits, from `include/uapi/asm-generic/termbits.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OFlag: tcflag_t {
        const OPOST  = 0o000001;
        const ONLCR  = 0o000004;
        const OCRNL  = 0o000010;
        const ONOCR  = 0o000020;
        const ONLRET = 0o000040;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// `c_cflag` bits, from `include/uapi/asm-generic/termbits.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CFlag: tcflag_t {
        const CS5    = 0o000000;
        const CS6    = 0o000020;
        const CS7    = 0o000040;
        const CS8    = 0o000060;
        const CSTOPB = 0o000100;
        const CREAD  = 0o000200;
        const PARENB = 0o000400;
        const PARODD = 0o001000;
        const HUPCL  = 0o002000;
        const CLOCAL = 0o004000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// `c_lflag` bits, from `include/uapi/asm-generic/termbits.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LFlag: tcflag_t {
        const ISIG    = 0o000001;
        const ICANON  = 0o000002;
        const ECHO    = 0o000010;
        const ECHOE   = 0o000020;
        const ECHOK   = 0o000040;
        const ECHONL  = 0o000100;
        const NOFLSH  = 0o000200;
        const TOSTOP  = 0o000400;
        const ECHOCTL = 0o001000;
        const ECHOPRT = 0o002000;
        const ECHOKE  = 0o004000;
        const FLUSHO  = 0o010000;
        const PENDIN  = 0o040000;
        const IEXTEN  = 0o100000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes)]
#[repr(C)]
pub struct Winsize {
    pub row: u16,
    pub col: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCSCTTY: u32 = 0x540E;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const FIONBIO: u32 = 0x5421;
pub const FIOCLEX: u32 = 0x5451;
pub const TIOCGPTN: u32 = 0x80045430;
pub const TIOCSPTLCK: u32 = 0x40045431;
pub const FBIOGET_VSCREENINFO: u32 = 0x4600;
pub const FBIOPUT_VSCREENINFO: u32 = 0x4601;
pub const FBIOGET_FSCREENINFO: u32 = 0x4602;
pub const FBIOPAN_DISPLAY: u32 = 0x4606;
pub const FBIOBLANK: u32 = 0x4611;

/// `IFNAMSIZ` (`linux/if.h`): the fixed size of `ifr_name`/`ifc_ifcu.ifcu_req[].ifr_name`.
pub const IFNAMSIZ: usize = 16;

// Legacy socket ioctls (`linux/sockios.h`), the interface-enumeration path
// `getifaddrs(3)`/rtnetlink bypasses but tools built directly against BSD-style
// `ifreq`/`ifconf` (busybox `ifconfig`, `route`, ...) still use.
pub const SIOCGIFCONF: u32 = 0x8912;
pub const SIOCGIFFLAGS: u32 = 0x8913;
pub const SIOCGIFADDR: u32 = 0x8915;
pub const SIOCGIFNETMASK: u32 = 0x891b;
pub const SIOCGIFBRDADDR: u32 = 0x8919;
pub const SIOCGIFHWADDR: u32 = 0x8927;
pub const SIOCGIFMTU: u32 = 0x8921;
pub const SIOCGIFINDEX: u32 = 0x8933;
pub const SIOCGIFTXQLEN: u32 = 0x8942;

bitflags::bitflags! {
    /// `ifr_flags` bits this shim reports (`linux/if.h`).
    #[derive(Debug, Clone, Copy)]
    pub struct IfrFlags: u16 {
        const IFF_UP = 0x1;
        const IFF_BROADCAST = 0x2;
        const IFF_LOOPBACK = 0x8;
        const IFF_RUNNING = 0x40;
        const IFF_MULTICAST = 0x1000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// When a new terminal attribute value takes effect, per `tcsetattr(3)`'s
/// `TCSANOW`/`TCSADRAIN`/`TCSAFLUSH` distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalSetAction {
    /// Apply immediately (`TCSETS`/`TCSANOW`).
    Now,
    /// Apply after all pending output has been written (`TCSETSW`/`TCSADRAIN`).
    Drain,
    /// Apply after pending output is written, discarding unread input first
    /// (`TCSETSF`/`TCSAFLUSH`).
    Flush,
}

/// Commands for use with `ioctl`.
#[non_exhaustive]
#[derive(Debug)]
pub enum IoctlArg {
    /// Get the current serial port settings.
    TCGETS(UserPtrMut<Termios>),
    /// Set the current serial port settings.
    TCSETS(UserPtr<Termios>, TerminalSetAction),
    /// Set this terminal as the calling session's controlling terminal.
    TIOCSCTTY(u32),
    /// Get the foreground process group ID of the controlling terminal.
    TIOCGPGRP(UserPtrMut<i32>),
    /// Set the foreground process group ID of the controlling terminal.
    TIOCSPGRP(UserPtr<i32>),
    /// Get window size.
    TIOCGWINSZ(UserPtrMut<Winsize>),
    /// Set window size.
    TIOCSWINSZ(UserPtr<Winsize>),
    /// Obtain device unit number, which can be used to generate
    /// the filename of the pseudo-terminal slave device.
    TIOCGPTN(UserPtrMut<u32>),
    /// Lock or unlock a Unix98 pseudo-terminal slave device.
    TIOCSPTLCK(UserPtr<i32>),
    /// Enables or disables non-blocking mode
    FIONBIO(UserPtr<i32>),
    /// Set close on exec
    FIOCLEX,
    /// Get the framebuffer's variable (mode) screen info.
    FBIOGET_VSCREENINFO(UserPtrMut<litebox::fs::devices::FbVarScreeninfo>),
    /// Set the framebuffer's variable (mode) screen info. litebox clamps rather than rejects a
    /// request it cannot satisfy exactly -- see
    /// [`litebox::fs::devices::Framebuffer::put_var_screeninfo`]'s doc comment.
    FBIOPUT_VSCREENINFO(UserPtr<litebox::fs::devices::FbVarScreeninfo>),
    /// Get the framebuffer's fixed (hardware) screen info.
    FBIOGET_FSCREENINFO(UserPtrMut<litebox::fs::devices::FbFixScreeninfo>),
    /// Pan the framebuffer's visible window to a new offset within the virtual screen (double
    /// buffering / page flip).
    FBIOPAN_DISPLAY(UserPtr<litebox::fs::devices::FbVarScreeninfo>),
    /// Blank/unblank the display. litebox has no real hardware to blank; treated as a no-op that
    /// always succeeds, matching how a real fbdev driver treats an unsupported blank mode.
    FBIOBLANK,
    Raw {
        cmd: u32,
        arg: UserPtrMut<u8>,
    },
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct MRemapFlags: u32 {
        /// Permit the kernel to relocate the mapping to a new virtual address, if necessary.
        const MREMAP_MAYMOVE = 1;
        /// Place the mapping at exactly the address specified in `new_address`.
        const MREMAP_FIXED = 2;
        /// Don't unmap the old mapping.
        /// This is only valid when `MREMAP_FIXED` is also specified.
        const MREMAP_DONTUNMAP = 4;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[repr(u32)]
#[non_exhaustive]
#[derive(Debug, IntEnum)]
pub enum AddressFamily {
    UNIX = 1,
    INET = 2,
    INET6 = 10,
    NETLINK = 16,
}

#[repr(u32)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, IntEnum)]
pub enum SockType {
    Stream = 1,
    Datagram = 2,
    Raw = 3,
    SeqPacket = 5,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct SockFlags: core::ffi::c_uint {
        const NONBLOCK = OFlags::NONBLOCK.bits();
        const CLOEXEC = OFlags::CLOEXEC.bits();
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// struct for SO_LINGER option
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct Linger {
    pub onoff: u32,  /* Linger active		*/
    pub linger: u32, /* How long to linger for	*/
}

/// IP Protocols
#[repr(u8)]
#[non_exhaustive]
#[derive(IntEnum, Debug)]
pub enum IPProtocol {
    Default = 0,
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    RAW = 255,
}

#[repr(u8)]
#[derive(Debug, IntEnum)]
pub enum UnixProtocol {
    Default = 0,
    UNIX = 1,
}

#[repr(u32)]
#[derive(Debug, IntEnum, Clone, Copy)]
pub enum IpOption {
    TOS = 1,
    RETOPTS = 7,
    RECVTTL = 12,
}

#[repr(u32)]
#[derive(Debug, IntEnum, Clone, Copy)]
pub enum SocketOption {
    REUSEADDR = 2,
    TYPE = 3,
    ERROR = 4,
    BROADCAST = 6,
    SNDBUF = 7,
    RCVBUF = 8,
    KEEPALIVE = 9,
    /// This option controls the action taken when unsent messages queue on
    /// a socket and close() is performed. If SO_LINGER is set, the system
    /// shall block the process during close() until it can transmit the data
    /// or until the time expires.
    LINGER = 13,
    /// `SO_PASSCRED`: deliver an `SCM_CREDENTIALS` control message (the
    /// sender's `struct ucred`) with every `recvmsg` on an `AF_UNIX` socket.
    PASSCRED = 16,
    PEERCRED = 17,
    RCVTIMEO = 20,
    SNDTIMEO = 21,
}

#[repr(u32)]
#[derive(Debug, IntEnum, Clone, Copy)]
pub enum TcpOption {
    NODELAY = 1,
    CORK = 3,
    /// Start keeplives after this period
    KEEPIDLE = 4,
    /// Interval between keepalives
    KEEPINTVL = 5,
    /// Number of keepalives before death
    KEEPCNT = 6,
    INFO = 11,
    CONGESTION = 13,
}

#[derive(Debug, Clone, Copy)]
pub enum SocketOptionName {
    IP(IpOption),
    Socket(SocketOption),
    TCP(TcpOption),
}

#[repr(u32)]
#[derive(Debug, IntEnum)]
pub enum SocketOptionLevel {
    IP = 0,
    SOCKET = 1,
    TCP = 6,
    UDP = 17,
    RAW = 255,
}

impl SocketOptionName {
    pub fn try_from(level: u32, optname: u32) -> Option<Self> {
        let level = SocketOptionLevel::try_from(level).ok()?;
        match level {
            SocketOptionLevel::IP => Some(Self::IP(IpOption::try_from(optname).ok()?)),
            SocketOptionLevel::SOCKET => Some(Self::Socket(SocketOption::try_from(optname).ok()?)),
            SocketOptionLevel::TCP => Some(Self::TCP(TcpOption::try_from(optname).ok()?)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct Ucred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

// Following libc's definition of time_t and suseconds_t.
// They are not same as isize on all architectures, e.g.,
// `suseconds_t` is i64 on riscv32:
// https://github.com/rust-lang/libc/blob/151c3a971e423c76e7acb54aa2d21a6e2706c4e6/src/unix/linux_like/linux/gnu/b32/mod.rs#L22
cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))] {
        pub type time_t = i64;
        pub type suseconds_t = u64;
    } else {
        compile_error!("Unsupported architecture");
    }
}

/// timespec from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/time_types.h#L7)
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq, Eq, FromBytes, IntoBytes, Default)]
#[repr(C)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,

    /// Nanoseconds. Must be less than 1_000_000_000.
    pub tv_nsec: u64,
}

impl TryFrom<Timespec> for Duration {
    type Error = errno::Errno;

    fn try_from(value: Timespec) -> Result<Self, Self::Error> {
        // On 32-bit architectures, `tv_nsec` may be defined in user mode as
        // pointer sized. Ignore any high padding bits.
        let nsec: usize = value.tv_nsec.trunc();
        if nsec >= 1_000_000_000 {
            return Err(errno::Errno::EINVAL);
        }
        Ok(Duration::new(
            u64::try_from(value.tv_sec).map_err(|_| errno::Errno::EINVAL)?,
            nsec.trunc(),
        ))
    }
}

impl From<Duration> for Timespec {
    fn from(value: Duration) -> Self {
        Timespec {
            tv_sec: value.as_secs().reinterpret_as_signed(),
            tv_nsec: value.subsec_nanos().into(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
pub struct Timespec32 {
    pub tv_sec: i32,
    pub tv_nsec: u32,
}

impl From<Timespec32> for Timespec {
    fn from(value: Timespec32) -> Self {
        Timespec {
            tv_sec: value.tv_sec.into(),
            tv_nsec: value.tv_nsec.into(),
        }
    }
}

impl TryFrom<Timespec32> for Duration {
    type Error = errno::Errno;

    fn try_from(value: Timespec32) -> Result<Self, Self::Error> {
        Timespec::from(value).try_into()
    }
}

impl From<Duration> for Timespec32 {
    fn from(value: Duration) -> Self {
        Timespec32 {
            // Silently truncate if needed, just like Linux would do.
            tv_sec: value.as_secs().reinterpret_as_signed().trunc(),
            tv_nsec: value.subsec_nanos(),
        }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct TimeVal {
    tv_sec: time_t,
    tv_usec: suseconds_t,
}
/// Linux's `struct rusage` (`resource.h`), padded to musl's LP64 layout, which reserves 16 extra
/// `long`s past the POSIX-visible fields. `#[repr(C)]` is load-bearing here for the same reason
/// as `Sysinfo`: this is written into guest memory as raw bytes for the guest's libc to read back
/// as the real ABI struct. Only `ru_utime`/`ru_stime` currently carry a real, host-measured value
/// (see `Task::sys_wait4`); every other field is explicitly zeroed rather than left as
/// guest-visible uninitialized memory.
///
/// Exactly the 144-byte kernel ABI, deliberately WITHOUT musl's trailing
/// `__reserved[16]`: musl reserves that space in its own definition, but the
/// kernel never writes it, and glibc's `struct rusage` is only these 144
/// bytes -- copying a 272-byte musl-shaped struct into a glibc guest's stack
/// buffer overruns it by 128 bytes (witnessed: iperf3's `cpu_util()` canary
/// trip, "*** stack smashing detected ***", on the Linux CI runner).
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable)]
pub struct Rusage {
    pub ru_utime: TimeVal,
    pub ru_stime: TimeVal,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

#[repr(C)]
#[derive(Clone, Default, FromBytes, IntoBytes, Immutable)]
pub struct ItimerVal {
    /// Timer interval
    interval: TimeVal,
    /// Current value
    value: TimeVal,
}

impl ItimerVal {
    pub fn new(interval: TimeVal, value: TimeVal) -> Self {
        Self { interval, value }
    }

    /// `it_value = duration`, `it_interval = 0` (single-shot timer).
    pub fn single_shot(duration: Duration) -> Self {
        Self::new(TimeVal::from(Duration::ZERO), TimeVal::from(duration))
    }

    pub fn it_interval(&self) -> TimeVal {
        self.interval
    }

    pub fn it_value(&self) -> TimeVal {
        self.value
    }
}

impl TryFrom<TimeVal> for Duration {
    type Error = errno::Errno;

    fn try_from(value: TimeVal) -> Result<Self, Self::Error> {
        let usec: u32 = value.tv_usec.trunc();
        if usec >= 1_000_000 {
            return Err(errno::Errno::EINVAL);
        }
        Ok(Duration::new(
            u64::try_from(value.tv_sec).map_err(|_| errno::Errno::EINVAL)?,
            usec * 1000,
        ))
    }
}

impl From<Duration> for TimeVal {
    fn from(value: Duration) -> Self {
        TimeVal {
            // Silently truncate if needed, just like Linux would do.
            tv_sec: value.as_secs().reinterpret_as_signed().trunc(),
            #[cfg_attr(target_pointer_width = "32", expect(clippy::useless_conversion))]
            tv_usec: value.subsec_micros().into(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes)]
pub struct TimeZone {
    tz_minuteswest: i32,
    tz_dsttime: i32,
}

impl TimeZone {
    /// Create a new TimeZone with the given minutes west of UTC and DST time flag
    pub fn new(tz_minuteswest: i32, tz_dsttime: i32) -> Self {
        Self {
            tz_minuteswest,
            tz_dsttime,
        }
    }
}

/// Codes for the `arch_prctl` syscall.
#[repr(u32)]
#[non_exhaustive]
#[derive(Debug, IntEnum)]
pub enum ArchPrctlCode {
    /// Set the 64-bit base for the FS register
    #[cfg(target_arch = "x86_64")]
    SetFs = 0x1002,
    /// Return the 64-bit base value for the FS register of the calling thread
    #[cfg(target_arch = "x86_64")]
    GetFs = 0x1003,

    /* CET (Control-flow Enforcement Technology) ralated operations; each of these simply will return EINVAL */
    CETStatus = 0x3001,
    CETDisable = 0x3002,
    CETLock = 0x3003,
}

/// Argument for the `arch_prctl` syscall, corresponding to the [`ArchPrctlCode`] enum.
#[non_exhaustive]
#[derive(Debug)]
pub enum ArchPrctlArg {
    #[cfg(target_arch = "x86_64")]
    SetFs(usize),
    #[cfg(target_arch = "x86_64")]
    GetFs(UserPtrMut<usize>),

    CETStatus,
    CETDisable,
    CETLock,
}

/// Reads the FS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, calling this instruction from user land will throw an `#UD`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rdfsbase() -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) ret,
            options(nostack, nomem, preserves_flags)
        );
    }
    ret
}

/// Writes the FS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, calling this instruction from user land will throw an `#UD`.
///
/// The caller must ensure that this write operation has no unsafe side
/// effects, as the FS segment base address is often used for thread
/// local storage.
#[cfg(target_arch = "x86_64")]
pub unsafe fn wrfsbase(fs_base: usize) {
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) fs_base,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Reads the GS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, this instruction will throw an `#UD`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rdgsbase() -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "rdgsbase {}",
            out(reg) ret,
            options(nostack, nomem, preserves_flags)
        );
    }
    ret
}

/// Writes the GS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, this instruction will throw an `#UD`.
///
/// The caller must ensure that this write operation has no unsafe side
/// effects, as the GS segment base address might be in use.
#[cfg(target_arch = "x86_64")]
pub unsafe fn wrgsbase(gs_base: usize) {
    unsafe {
        core::arch::asm!(
            "wrgsbase {}",
            in(reg) gs_base,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Flags for the clone3 system call as defined in `/usr/include/linux/sched.h`.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct CloneFlags(u64);

bitflags::bitflags! {
    impl CloneFlags: u64 {
        /// Set if VM shared between processes
        const VM      = 0x00000100;
        /// Set if fs info shared between processes
        const FS      = 0x00000200;
        /// Set if open files shared between processes
        const FILES   = 0x00000400;
        /// Set if signal handlers and blocked signals shared
        const SIGHAND = 0x00000800;
        /// Set if a pidfd should be placed in parent
        const PIDFD   = 0x00001000;
        /// Set if we want to let tracing continue on the child too
        const PTRACE  = 0x00002000;
        /// Set if the parent wants the child to wake it up on mm_release
        const VFORK   = 0x00004000;
        /// Set if we want to have the same parent as the cloner
        const PARENT  = 0x00008000;
        /// Same thread group
        const THREAD  = 0x00010000;
        /// New mount namespace group
        const NEWNS   = 0x00020000;
        /// Share system V SEM_UNDO semantics
        const SYSVSEM = 0x00040000;
        /// Create a new TLS for the child
        const SETTLS  = 0x00080000;

        /// Set the TID in the parent
        const PARENT_SETTID  = 0x00100000;
        /// Clear the TID in the child
        const CHILD_CLEARTID = 0x00200000;
        /// Ignored.
        const DETACHED      = 0x00400000;
        /// Set if the tracing process can't force CLONE_PTRACE on this clone
        const UNTRACED       = 0x00800000;
        /// Set the TID in the child
        const CHILD_SETTID   = 0x01000000;
        /// New cgroup namespace
        const NEWCGROUP      = 0x02000000;
        /// New uts namespace
        const NEWUTS         = 0x04000000;
        /// New ipc namespace
        const NEWIPC         = 0x08000000;
        /// New user namespace
        const NEWUSER        = 0x10000000;
        /// New pid namespace
        const NEWPID         = 0x20000000;
        /// New network namespace
        const NEWNET         = 0x40000000;
        /// Clone io context
        const IO             = 0x80000000;

        /// Clear any signal handler and reset to SIG_DFL.
        const CLEAR_SIGHAND = 0x100000000;
        /// Clone into a specific cgroup given the right permissions.
        const INTO_CGROUP   = 0x200000000;

        /// New time namespace
        const NEWTIME = 0x00000080;

        const _ = !0; // Externally defined flags
    }
}

/// Arguments for the `clone3` syscall.
#[repr(C, align(8))]
#[derive(Clone, Debug, FromBytes, IntoBytes)]
pub struct CloneArgs {
    pub flags: CloneFlags,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// Task command name length
pub const TASK_COMM_LEN: usize = 16;

pub struct TaskParams {
    /// Process ID
    pub pid: i32,
    /// Parent Process ID
    pub ppid: i32,
    /// The initial uid.
    pub uid: u32,
    /// The initial effective uid.
    pub euid: u32,
    /// The initial gid.
    pub gid: u32,
    /// The initial effective gid.
    pub egid: u32,
}

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// Flags for the `getrandom` syscall.
    pub struct RngFlags: i32 {
        /// When reading from the random source, getrandom() blocks if no random bytes are available,
        /// and when reading from the urandom source, it blocks if the entropy pool has not yet been initialized.
        const NONBLOCK = 1;
        /// Random bytes are drawn from the random source (i.e., same as `/dev/random`)
        /// instead of the urandom source.
        const RANDOM = 2;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[cfg(not(target_arch = "riscv32"))]
pub type rlim_t = usize;

/// Used by getrlimit and setrlimit syscalls
#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes)]
pub struct Rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}

/// Used by prlimit64 syscall
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct Rlimit64 {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

pub fn rlimit_to_rlimit64(rlim: Rlimit) -> Rlimit64 {
    Rlimit64 {
        rlim_cur: if rlim.rlim_cur == rlim_t::MAX {
            u64::MAX
        } else {
            rlim.rlim_cur as u64
        },
        rlim_max: if rlim.rlim_max == rlim_t::MAX {
            u64::MAX
        } else {
            rlim.rlim_max as u64
        },
    }
}

pub fn rlimit64_to_rlimit(rlim: Rlimit64) -> Rlimit {
    Rlimit {
        rlim_cur: if rlim.rlim_cur >= rlim_t::MAX as u64 {
            rlim_t::MAX
        } else {
            rlim.rlim_cur.trunc()
        },
        rlim_max: if rlim.rlim_max >= rlim_t::MAX as u64 {
            rlim_t::MAX
        } else {
            rlim.rlim_max.trunc()
        },
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, IntEnum)]
pub enum RlimitResource {
    /// CPU time in sec
    CPU = 0,
    /// Max filesize
    FSIZE = 1,
    /// Max data size
    DATA = 2,
    /// Max stack size
    STACK = 3,
    /// Max core file size
    CORE = 4,
    /// Max resident set size
    RSS = 5,
    /// Max number of processes
    NPROC = 6,
    /// Max number of open files
    NOFILE = 7,
    /// Max number of locked memory
    MEMLOCK = 8,
    /// Max address space
    AS = 9,
    /// Max number of file locks held
    LOCKS = 10,
    /// Max number of pending signals
    SIGPENDING = 11,
    /// Max bytes in POSIX mqueues
    MSGQUEUE = 12,
    /// max nice prio allowed to raise to 0-39 for nice level 19 .. -20
    NICE = 13,
    /// Max realtime priority
    RTPRIO = 14,
    /// timeout for RT tasks in us
    RTTIME = 15,
}
impl RlimitResource {
    /// Maximum value for RlimitResource
    pub const RLIM_NLIMITS: usize = RlimitResource::RTTIME as usize + 1;
}

// FUTURE: The rust compiler is currently confused (in the shim, where a pointer
// to this is taken) by the overly recursive nature of the trait bounds if we
// actually set the types up for this the way they are in the comments, rather
// than the `usize`s (Note: the separate issue of `Unaligned` when using that
// variant is fixed simply by using `zerocopy::Usize`, and is not the issue
// being referred to here).  Using the RobustList based types here causes a
// E0275 (see `rustc --explain E0275`) on `Sized` and `FromBytes`. There is some
// belief that minor restructuring should allow rustc to properly discover that
// all the requirements are satisfied, but currently, that is considered beyond
// the scope of the changes in the PR that introduced the
// `FromBytes`/`IntoBytes` implementation here.
/// XXX: The types in this struct might be changed to stronger types in the
/// future.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct RobustList {
    pub next: usize, // Platform::RawConstPointer<RobustList<Platform>>,
}

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
// FUTURE: The rust compiler is currently confused (in the shim, where a pointer
// to this is taken) by the overly recursive nature of the trait bounds if we
// actually set the types up for this the way they are in the comments, rather
// than the `usize`s (Note: the separate issue of `Unaligned` when using that
// variant is fixed simply by using `zerocopy::Usize`, and is not the issue
// being referred to here).  Using the RobustList based types here causes a
// E0275 (see `rustc --explain E0275`) on `Sized` and `FromBytes`. There is some
// belief that minor restructuring should allow rustc to properly discover that
// all the requirements are satisfied, but currently, that is considered beyond
// the scope of the changes in the PR that introduced the
// `FromBytes`/`IntoBytes` implementation here.
/// XXX: The types in this struct might be changed to stronger types in the
/// future.
pub struct RobustListHead {
    /// The head of the list. Points back to itself if empty.
    pub list: RobustList, // RobustList<Platform>,
    /// This relative offset is set by user-space, it gives the kernel
    /// the relative position of the futex field to examine. This way
    /// we keep userspace flexible, to freely shape its data-structure,
    /// without hardcoding any particular offset into the kernel.
    pub futex_offset: isize,
    /// The death of the thread may race with userspace setting
    /// up a lock's links. So to handle this race, userspace first
    /// sets this field to the address of the to-be-taken lock,
    /// then does the lock acquire, and then adds itself to the
    /// list, and then clears this field. Hence the kernel will
    /// always have full knowledge of all locks that the thread
    /// _might_ have taken. We check the owner TID in any case,
    /// so only truly owned locks will be handled.
    pub list_op_pending: usize, // Platform::RawConstPointer<RobustList<Platform>>,
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct EpollCreateFlags: core::ffi::c_uint {
        const EPOLL_CLOEXEC = litebox::fs::OFlags::CLOEXEC.bits();
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[repr(i32)]
#[derive(Debug, IntEnum, PartialEq, Eq)]
pub enum EpollOp {
    EpollCtlAdd = 1,
    EpollCtlDel = 2,
    EpollCtlMod = 3,
}

/// The kernel's `struct epoll_event`.
///
/// x86-64 Linux declares it `__attribute__((packed))` (12 bytes, `data` at
/// offset 4); every other architecture -- aarch64 included -- uses natural
/// alignment (16 bytes, 4 padding bytes after `events`, `data` at offset 8).
/// Handing a packed layout to an aarch64 guest made it misparse every event
/// array `epoll_wait` returned: single events happened to read a `data` of
/// ~0 and misdispatched harmlessly, but a multi-event wakeup straddled the
/// 12-vs-16-byte stride into garbage fds -- observed live as libuv's
/// `uv__io_poll` aborting on `Assertion failed: fd >= 0` the first time a
/// spawned child's stdio produced three simultaneous events.
///
/// Construct via [`EpollEvent::new`]; the aarch64 variant carries the padding
/// as an explicit field so `IntoBytes` stays derivable (zerocopy rejects
/// implicit padding).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// See the x86-64 variant's doc comment for why the layout is per-arch.
#[cfg(not(target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(C)]
pub struct EpollEvent {
    pub events: u32,
    _pad: u32,
    pub data: u64,
}

impl EpollEvent {
    #[must_use]
    pub fn new(events: u32, data: u64) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self { events, data }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self {
                events,
                _pad: 0,
                data,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(C)]
pub struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[repr(i32)]
#[derive(Debug, IntEnum)]
pub enum MadviseBehavior {
    /// Normal behavior, no special treatment
    Normal = 0,
    /// Expect random page references
    Random = 1,
    /// Expect sequential page references
    Sequential = 2,
    /// Will need these pages
    WillNeed = 3,
    /// Do not expect access in the near future
    DontNeed = 4,

    /* common parameters: try to keep these consistent across architectures */
    /// Free pages only if memory pressure
    Free = 8,
    /// Remove these pages & resources
    Remove = 9,
    /// Don't inherit across fork
    DontFork = 10,
    /// Do inherit across fork
    DoFork = 11,
    /// Poison a page for testing
    HWPoison = 100,
    /// Soft offline page for testing
    SoftOffline = 101,

    /// KSM may merge identical pages
    Mergeable = 12,
    /// KSM may not merge identical pages
    Unmergeable = 13,
    /// Worth backing with hugepages
    HugePage = 14,
    /// Not worth backing with hugepages
    NoHugePage = 15,

    /// Explicitly exclude from core dumps,
    /// overrides the coredump filter bits
    DontDump = 16,
    /// Clear the MADV_DONTDUMP flag
    DoDump = 17,

    /// Zero memory on fork, child only
    WipeOnFork = 18,
    /// Undo MADV_WIPEONFORK
    KeepOnFork = 19,

    // Deactivate these pages
    Cold = 20,
    /// reclaim these pages
    Pageout = 21,

    /// populate (prefault) page tables readable
    PopulateRead = 22,
    /// populate (prefault) page tables writable
    PopulateWrite = 23,

    /// like DONTNEED, but drop locked pages too
    DontNeedLocked = 24,
}

// `#[repr(C)]` is load-bearing, not decoration: this struct is written into guest memory as raw
// bytes (`write_at_offset`) for the guest's libc to read back as the real Linux ABI `struct
// sysinfo`. Without it, `repr(Rust)`'s free field-reordering silently scrambled the layout --
// `busybox free`, which reads `totalram`/`freeram` straight out of this syscall, printed
// nonsensical multi-exabyte figures on real hardware (previously unobserved, since `free` always
// died at the missing `/proc/meminfo` open before reaching the `printf` that would have shown it).
#[repr(C)]
#[derive(Clone, Debug, Default, FromBytes, IntoBytes)]
pub struct Sysinfo {
    /// Seconds since boot
    pub uptime: usize,
    /// 1, 5, and 15 minute load averages
    pub loads: [usize; 3],
    /// Total usable main memory size
    pub totalram: usize,
    /// Available memory size
    pub freeram: usize,
    /// Amount of shared memory
    pub sharedram: usize,
    /// Memory used by buffers
    pub bufferram: usize,
    /// Total swap space size
    pub totalswap: usize,
    /// swap space still available
    pub freeswap: usize,
    /// Number of current processes
    pub procs: u16,
    /// Explicit padding for m68k
    pub pad: u16,
    /// Explicit padding so `totalhigh` lands on its natural 8-byte alignment, matching the real
    /// ABI's implicit compiler-inserted padding here. `IntoBytes` refuses a type with implicit
    /// padding (it would write uninitialized bytes into guest memory), so this has to be a real,
    /// zeroed field rather than a gap.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad2: u32,
    /// Total high memory size
    pub totalhigh: usize,
    /// Available high memory size
    pub freehigh: usize,
    /// Memory unit size in bytes
    pub mem_unit: u32,
    /// Padding: libc5 uses this..
    #[allow(clippy::pub_underscore_fields)]
    pub _f: [u8; 20 - 2 * core::mem::size_of::<usize>() - core::mem::size_of::<u32>()],
    /// Trailing padding rounding the struct up to `usize`'s alignment (the real ABI struct gets
    /// this from the compiler implicitly; see `_pad2` above on why it must be explicit here).
    #[allow(clippy::pub_underscore_fields)]
    pub _pad3: u32,
}

/// Linux's `statfs` struct (the generic `<asm-generic/statfs.h>` layout `statfs`/`fstatfs` use on
/// both x86-64 and aarch64 -- unlike `stat`, the 64-bit `statfs` ABI does not diverge per-arch).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes)]
pub struct Statfs {
    /// Filesystem magic number (e.g. a `*_MAGIC` constant from `<linux/magic.h>`).
    pub f_type: i64,
    /// Optimal transfer block size.
    pub f_bsize: i64,
    /// Total data blocks in the filesystem.
    pub f_blocks: u64,
    /// Free blocks.
    pub f_bfree: u64,
    /// Free blocks available to unprivileged users.
    pub f_bavail: u64,
    /// Total file nodes.
    pub f_files: u64,
    /// Free file nodes.
    pub f_ffree: u64,
    /// Filesystem ID.
    pub f_fsid: [i32; 2],
    /// Maximum length of filenames.
    pub f_namelen: i64,
    /// Fragment size.
    pub f_frsize: i64,
    /// Mount flags (`ST_*`).
    pub f_flags: i64,
    /// Reserved for future use.
    pub f_spare: [i64; 4],
}

bitflags::bitflags! {
    /// Represents a set of Linux capabilities.
    pub struct CapSet: u64 {
        const CHOWN = 1 << 0;
        const DAC_OVERRIDE = 1 << 1;
        const DAC_READ_SEARCH = 1 << 2;
        const FOWNER = 1 << 3;
        const FSETID = 1 << 4;
        const KILL = 1 << 5;
        const SETGID = 1 << 6;
        const SETUID = 1 << 7;
        const SETPCAP = 1 << 8;
        const LINUX_IMMUTABLE = 1 << 9;
        const NET_BIND_SERVICE = 1 << 10;
        const NET_BROADCAST = 1 << 11;
        const NET_ADMIN = 1 << 12;
        const NET_RAW = 1 << 13;
        const IPC_LOCK = 1 << 14;
        const IPC_OWNER = 1 << 15;
        const SYS_MODULE = 1 << 16;
        const SYS_RAWIO = 1 << 17;
        const SYS_CHROOT = 1 << 18;
        const SYS_PTRACE = 1 << 19;
        const SYS_PACCT = 1 << 20;
        const SYS_ADMIN = 1 << 21;
        const SYS_BOOT = 1 << 22;
        const SYS_NICE = 1 << 23;
        const SYS_RESOURCE = 1 << 24;
        const SYS_TIME = 1 << 25;
        const SYS_TTY_CONFIG = 1 << 26;
        const MKNOD = 1 << 27;
        const LEASE = 1 << 28;
        const AUDIT_WRITE = 1 << 29;
        const AUDIT_CONTROL = 1 << 30;
        const SETFCAP = 1 << 31;
        const MAC_OVERRIDE = 1 << 32;
        const MAC_ADMIN = 1 << 33;
        const SYSLOG = 1 << 34;
        const WAKE_ALARM = 1 << 35;
        const BLOCK_SUSPEND = 1 << 36;
        const AUDIT_READ = 1 << 37;
        const PERFMON = 1 << 38;
        const BPF = 1 << 39;
        const CHECKPOINT_RESTORE = 1u64 << 40;

        const LAST_CAP = Self::CHECKPOINT_RESTORE.bits();
        const _ = !0; // Externally defined flags
    }
}

/// Header structure used for the `capget` and `capset` syscalls.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes)]
pub struct CapHeader {
    pub version: u32,
    pub pid: u32,
}

/// Data structure used for the `capget` and `capset` syscalls.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes)]
pub struct CapData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[repr(C, packed)]
#[derive(Clone, FromBytes, IntoBytes)]
pub struct LinuxDirent64 {
    /// Inode number
    pub ino: u64,
    /// Filesystem-specific value with no specific meaning to user space.
    /// We use it to locate a directory entry
    pub off: u64,
    /// Length of this dirent (including the following name and padding)
    pub len: u16,
    /// File type
    pub typ: u8,
    /// File name (null-terminated)
    ///
    /// This is a flexible array member (FAM) with variable length. The actual name data
    /// follows immediately after this struct in memory.
    #[allow(clippy::pub_underscore_fields)]
    pub __name: [u8; 0],
}

#[non_exhaustive]
#[repr(i32)]
#[derive(Debug, Clone, Copy, IntEnum)]
pub enum ClockId {
    RealTime = 0,
    Monotonic = 1,
    /// `CLOCK_PROCESS_CPUTIME_ID`: CPU time consumed so far by all threads of the calling
    /// process. Unlike the other clocks here, this is *not* wall-clock time -- it only
    /// advances while the process is actually running on a CPU.
    ProcessCpuTime = 2,
    /// `CLOCK_THREAD_CPUTIME_ID`: CPU time consumed so far by the calling thread only. Also not
    /// wall-clock time.
    ThreadCpuTime = 3,
    /// `CLOCK_MONOTONIC_RAW`: like `CLOCK_MONOTONIC`, but on real Linux specifically excludes any
    /// NTP frequency slewing, giving raw hardware-derived elapsed time.
    ///
    /// Simplification: LiteBox maps this onto the same value as [`ClockId::Monotonic`]. This is
    /// legitimate for macOS, whose `Monotonic` is already sourced from the host's
    /// `CLOCK_MONOTONIC_RAW`; on other hosts it means we don't distinguish NTP-slewed monotonic
    /// time from raw monotonic time, which is a real (if minor) semantic difference from Linux.
    MonotonicRaw = 4,
    /// `CLOCK_REALTIME_COARSE`: a faster, lower-resolution version of `CLOCK_REALTIME`, intended
    /// to trade precision for speed.
    ///
    /// Simplification: LiteBox maps this onto the same (full-precision) value as
    /// [`ClockId::RealTime`]. We have no separate, cheaper-to-read coarse clock source, so callers
    /// get a more precise answer than real Linux would give, never a less precise one.
    RealTimeCoarse = 5,
    /// `CLOCK_MONOTONIC_COARSE`: a faster, lower-resolution version of `CLOCK_MONOTONIC`.
    ///
    /// Simplification: as with [`ClockId::RealTimeCoarse`], LiteBox maps this onto the full
    /// precision [`ClockId::Monotonic`] value.
    MonotonicCoarse = 6,
    /// `CLOCK_BOOTTIME`: like `CLOCK_MONOTONIC`, but on real Linux also includes time the system
    /// spent suspended.
    ///
    /// Simplification: LiteBox has no notion of the guest (or host) being suspended -- there is
    /// no way for wall-clock time to elapse without [`ClockId::Monotonic`] also elapsing -- so
    /// this is mapped onto the exact same value as [`ClockId::Monotonic`].
    Boottime = 7,
}

/// The `struct sched_param` argument of `sched_setparam`/`sched_getparam`/`sched_setscheduler`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes)]
pub struct SchedParam {
    pub sched_priority: i32,
}

/// Scheduling policy values accepted by `sched_setscheduler`, and reported by
/// `sched_getscheduler`.
///
/// LiteBox's process model has no real scheduling-class enforcement to expose (there is a single
/// cooperative/host-scheduled pool of threads, not a configurable in-guest scheduler), so these
/// are recognized only so `sched_setscheduler`/`sched_getscheduler`/`sched_setparam`/
/// `sched_getparam` can give believable, inert answers: the non-real-time policies are accepted
/// as no-ops (matching what an unprivileged real Linux process seeing a plain `SCHED_OTHER`
/// system would experience), while the real-time policies are recognized only so they can be
/// correctly rejected with `EPERM` -- matching real Linux's behavior for a process without
/// `CAP_SYS_NICE`, which is a real, accurate constraint on LiteBox guests (they never have that
/// capability), not a shortcut.
pub mod sched_policy {
    pub const SCHED_OTHER: i32 = 0;
    pub const SCHED_FIFO: i32 = 1;
    pub const SCHED_RR: i32 = 2;
    pub const SCHED_BATCH: i32 = 3;
    pub const SCHED_IDLE: i32 = 5;
    pub const SCHED_DEADLINE: i32 = 6;
    /// May be OR'd into the `policy` argument of `sched_setscheduler` to request that the
    /// policy revert to `SCHED_OTHER` across `fork()`. LiteBox has no `fork()` (see
    /// `litebox_shim_linux`'s `do_clone`), so this bit is accepted, to avoid spuriously
    /// rejecting an otherwise well-formed call, but has no effect.
    pub const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct TimerFlags: i32 {
        const ABSTIME = 0x1; // TIMER_ABSTIME
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[non_exhaustive]
#[repr(i32)]
#[derive(Debug, IntEnum, PartialEq)]
pub enum FutexOperation {
    Wait = 0,
    Wake = 1,
    Requeue = 3,
    CmpRequeue = 4,
    WaitBitset = 9,
    WakeBitset = 10,
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct FutexFlags: i32 {
        const PRIVATE = 0x80; // FUTEX_PRIVATE_FLAG
        const CLOCK_REALTIME = 0x100; // FUTEX_CLOCK_REALTIME
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;

        const FUTEX_CMD_MASK = !(FutexFlags::PRIVATE.bits() | FutexFlags::CLOCK_REALTIME.bits());
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum FutexArgs {
    Wait {
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        val: u32,
        /// Note: for FUTEX_WAIT, timeout is interpreted as a relative
        /// value. This differs from other futex operations, where
        /// timeout is interpreted as an absolute value.
        timeout: TimeParam,
    },
    WaitBitset {
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        val: u32,
        timeout: TimeParam,
        bitmask: u32,
    },
    Wake {
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        count: u32,
    },
    WakeBitset {
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        count: u32,
        bitmask: u32,
    },
    /// `FUTEX_REQUEUE`: wake up to `num_to_wake` waiters on `addr`, then move up to
    /// `num_to_requeue` of the *remaining* waiters on `addr` onto `addr2`'s wait queue, without
    /// waking them.
    ///
    /// Note the raw syscall ABI quirk this is parsed from: for this operation, the argument slot
    /// normally used for `WAIT`'s `timeout` pointer is instead a plain integer (`num_to_requeue`),
    /// not a `timespec*` -- see `man 2 futex`.
    Requeue {
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        num_to_wake: u32,
        num_to_requeue: u32,
        addr2: UserPtrMut<u32>,
    },
    /// `FUTEX_CMP_REQUEUE`: identical to `Requeue`, but first atomically checks that the word at
    /// `addr` still equals `expected_value`, failing with `EAGAIN` otherwise (closes the race
    /// where the value changed between userspace's check and this syscall).
    CmpRequeue {
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        num_to_wake: u32,
        num_to_requeue: u32,
        addr2: UserPtrMut<u32>,
        expected_value: u32,
    },
}

#[repr(u32)]
#[derive(Debug, IntEnum)]
pub enum PrctlOption {
    SetPDeathSig = 1,
    GetPDeathSig = 2,
    GetDumpable = 3,
    SetDumpable = 4,
    GetUnalign = 5,
    SetUnalign = 6,
    GetKeepCaps = 7,
    SetKeepCaps = 8,
    GetFpEmu = 9,
    SetFpEmu = 10,
    GetFpExc = 11,
    SetFpExc = 12,
    GetTiming = 13,
    SetTiming = 14,
    /// PR_SET_NAME: set process name
    SetName = 15,
    /// PR_GET_NAME: Get process name
    GetName = 16,
    GetEndian = 19,
    SetEndian = 20,
    GetSeccomp = 21,
    SetSeccomp = 22,
    /// PR_CAPBSET_READ: read the calling thread's capability bounding set
    CapBSetRead = 23,
    CapBSetDrop = 24,
    GetTSC = 25,
    SetTSC = 26,
    GetSecureBits = 27,
    SetSecureBits = 28,
    SetTimerSlack = 29,
    GetTimerSlack = 30,
    TaskPerfEventsDisable = 31,
    TaskPerfEventsEnable = 32,
    MCEKill = 33,
    MCEKillGet = 34,
    SetMM = 35,
    SetChildSubreaper = 36,
    GetChildSubreaper = 37,
    SetNoNewPrivs = 38,
    GetNoNewPrivs = 39,
    GetTidAddress = 40,
    SetTHPDisable = 41,
    GetTHPDisable = 42,
    // No longer implemented, but left here to ensure the numbers stay reserved:
    // MpxEnableManagement = 43,
    // MpxDisableManagement = 44,
    SetFpMode = 45,
    GetFpMode = 46,
    CapAmbient = 47,
    /// `PR_SET_VMA` (`0x53564d41`, the ASCII "SVMA"): name an anonymous
    /// mapping (`PR_SET_VMA_ANON_NAME`). Emitted by PartitionAlloc for every
    /// large allocation, so it must decode (and be visible in a syscall
    /// trace) even though the shim answers it with `EINVAL` like a kernel
    /// built without `CONFIG_ANON_VMA_NAME`.
    SetVma = 0x5356_4d41,
}

#[non_exhaustive]
#[derive(Debug)]
pub enum PrctlArg {
    SetPDeathSig(Option<signal::Signal>),
    GetPDeathSig(UserPtrMut<i32>),
    SetName(UserPtr<u8>),
    GetName(UserPtrMut<u8>),
    GetDumpable,
    /// `PR_SET_DUMPABLE`: the decoder has already checked the value is
    /// `SUID_DUMP_DISABLE` (0) or `SUID_DUMP_USER` (1), as Linux does.
    SetDumpable(u64),
    /// `PR_SET_VMA`: `opcode` is `PR_SET_VMA_ANON_NAME` (0) on every kernel
    /// so far; `addr`/`len` bound the mapping and `arg` is the name pointer.
    SetVma {
        opcode: u64,
        addr: usize,
        len: usize,
        arg: usize,
    },
    CapBSetRead(usize),
    SetNoNewPrivs,
    GetNoNewPrivs,
    /// `PR_SET_KEEPCAPS`: whether the permitted capability set is cleared on
    /// a UID switch away from 0. LiteBox does not model capabilities at all
    /// (`CapBSetRead` above always reports none held), so this is accepted
    /// as a no-op rather than rejected -- real callers (e.g. `setpriv
    /// --reuid`/`--regid`, which sets this before dropping privileges so
    /// the subsequent explicit `capset` isn't undone by the kernel's
    /// default clear-on-UID-change behavior) only need the call to
    /// succeed, not to observe any actual capability state change.
    SetKeepCaps(bool),
    /// `PR_GET_KEEPCAPS`: see `SetKeepCaps`.
    GetKeepCaps,
}

#[repr(i32)]
#[derive(Debug, IntEnum)]
pub enum IntervalTimer {
    /// This timer counts down in real (i.e., wall clock) time.  At each expiration, a SIGALRM signal is generated.
    Real = 0,
    /// This timer counts down against the user-mode CPU time consumed by the process. The measurement includes CPU time
    /// consumed by all threads in the process. At each expiration, a SIGVTALRM signal is generated.
    Virtual = 1,
    /// This timer counts down against the total (i.e., both user and system) CPU time consumed by the process.
    /// The measurement includes CPU time consumed by all threads in the process. At each expiration, a SIGPROF signal is generated.
    Prof = 2,
}

/// Flags for the `receive` function.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct ReceiveFlags(u32);

bitflags::bitflags! {
    impl ReceiveFlags: u32 {
        /// `MSG_CTRUNC`: ancillary data was truncated
        const CTRUNC = 0x8;
        /// `MSG_CMSG_CLOEXEC`: close-on-exec for the associated file descriptor
        const CMSG_CLOEXEC = 0x40000000;
        /// `MSG_DONTWAIT`: non-blocking operation
        const DONTWAIT = 0x40;
        /// `MSG_ERRQUEUE`: destination for error messages
        const ERRQUEUE = 0x2000;
        /// `MSG_OOB`: requests receipt of out-of-band data
        const OOB = 0x1;
        /// `MSG_PEEK`: requests to peek at incoming messages
        const PEEK = 0x2;
        /// `MSG_TRUNC`: truncate the message
        const TRUNC = 0x20;
        /// `MSG_WAITALL`: wait for the full amount of data
        const WAITALL = 0x100;
        /// `MSG_WAITFORONE`: `recvmmsg` only — turn on `MSG_DONTWAIT` after the
        /// first message has been received.
        const WAITFORONE = 0x10000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// Flags for the `send` function.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(C)]
pub struct SendFlags(u32);

bitflags::bitflags! {
    impl SendFlags: u32 {
        /// `MSG_CONFIRM`: requests confirmation of the message delivery.
        const CONFIRM = 0x800;
        /// `MSG_DONTROUTE`: send the message directly to the interface, bypassing routing.
        const DONTROUTE = 0x4;
        /// `MSG_DONTWAIT`: non-blocking operation, do not wait for buffer space to become available.
        const DONTWAIT = 0x40;
        /// `MSG_EOR`: indicates the end of a record for message-oriented sockets.
        const EOR = 0x80;
        /// `MSG_MORE`: indicates that more data will follow.
        const MORE = 0x8000;
        /// `MSG_NOSIGNAL`: prevents the sending of SIGPIPE signals when writing to a socket that is closed.
        const NOSIGNAL = 0x4000;
        /// `MSG_OOB`: sends out-of-band data.
        const OOB = 0x1;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// Packaged sigset pointer with its size, used by `pselect6` syscall.
#[derive(Clone, Copy, FromBytes)]
#[repr(C)]
pub struct SigSetPack {
    pub sigset: UserPtr<SigSet>,
    pub size: usize,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct UserMsgHdr {
    /// ptr to socket address structure
    pub msg_name: UserPtrMut<u8>,
    /// size of socket address structure
    pub msg_namelen: u32,
    /// Explicit padding to match the 4-byte gap that Linux's naturally-aligned
    /// `struct user_msghdr` has between `msg_namelen` and `msg_iov` on 64-bit.
    #[cfg(target_pointer_width = "64")]
    _pad: u32,
    /// ptr to an array of `iovec` structures
    pub msg_iov: UserPtr<IoVec>,
    /// number of elements in msg_iov
    pub msg_iovlen: usize,
    /// ptr to ancillary data
    pub msg_control: UserPtr<u8>,
    /// number of bytes of ancillary data
    pub msg_controllen: usize,
    /// flags on received message
    pub msg_flags: ReceiveFlags,
    /// Explicit trailing padding to match the 4-byte gap after `msg_flags` in
    /// Linux's naturally-aligned `struct user_msghdr` on 64-bit (total size 56).
    #[cfg(target_pointer_width = "64")]
    _pad2: u32,
}

/// Linux's `struct mmsghdr`: a `msghdr` paired with the number of bytes
/// transmitted, used by `sendmmsg`/`recvmmsg`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct UserMmsgHdr {
    /// the per-message `msghdr`
    pub msg_hdr: UserMsgHdr,
    /// bytes transmitted for this entry, written back by the kernel
    pub msg_len: u32,
    #[cfg(target_pointer_width = "64")]
    _pad: u32,
}

#[repr(i32)]
#[derive(Debug, IntEnum)]
pub enum SocketcallType {
    Socket = 1,
    Bind = 2,
    Connect = 3,
    Listen = 4,
    Accept = 5,
    GetSockname = 6,
    GetPeername = 7,
    Socketpair = 8,
    Send = 9,
    Recv = 10,
    Sendto = 11,
    Recvfrom = 12,
    Shutdown = 13,
    Setsockopt = 14,
    Getsockopt = 15,
    Sendmsg = 16,
    Recvmsg = 17,
    Accept4 = 18,
    Recvmmsg = 19,
    Sendmmsg = 20,
}

/// `how` argument to the `shutdown(2)` syscall.
#[repr(i32)]
#[derive(Debug, Clone, Copy, IntEnum)]
pub enum ShutdownHow {
    /// `SHUT_RD`.
    Read = 0,
    /// `SHUT_WR`.
    Write = 1,
    /// `SHUT_RDWR`.
    Both = 2,
}

impl ShutdownHow {
    /// Returns `true` when this `how` disables the receive side (`SHUT_RD` or `SHUT_RDWR`).
    #[must_use]
    pub fn is_shutdown_read(self) -> bool {
        matches!(self, Self::Read | Self::Both)
    }
    /// Returns `true` when this `how` disables the send side (`SHUT_WR` or `SHUT_RDWR`).
    #[must_use]
    pub fn is_shutdown_write(self) -> bool {
        matches!(self, Self::Write | Self::Both)
    }
}

/// Flags accepted by `inotify_init1(2)`.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct InotifyInitFlags(u32);

bitflags::bitflags! {
    impl InotifyInitFlags: u32 {
        const NONBLOCK = 0x0000_0800;
        const CLOEXEC = 0x0008_0000;
    }
}

/// Event-selection and behavior flags accepted by `inotify_add_watch(2)`.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct InotifyMask(u32);

bitflags::bitflags! {
    impl InotifyMask: u32 {
        const ACCESS = 0x0000_0001;
        const MODIFY = 0x0000_0002;
        const ATTRIB = 0x0000_0004;
        const CLOSE_WRITE = 0x0000_0008;
        const CLOSE_NOWRITE = 0x0000_0010;
        const OPEN = 0x0000_0020;
        const MOVED_FROM = 0x0000_0040;
        const MOVED_TO = 0x0000_0080;
        const CREATE = 0x0000_0100;
        const DELETE = 0x0000_0200;
        const DELETE_SELF = 0x0000_0400;
        const MOVE_SELF = 0x0000_0800;
        const UNMOUNT = 0x0000_2000;
        const Q_OVERFLOW = 0x0000_4000;
        const IGNORED = 0x0000_8000;
        const ONLYDIR = 0x0100_0000;
        const DONT_FOLLOW = 0x0200_0000;
        const EXCL_UNLINK = 0x0400_0000;
        const MASK_CREATE = 0x1000_0000;
        const MASK_ADD = 0x2000_0000;
        const ISDIR = 0x4000_0000;
        const ONESHOT = 0x8000_0000;
    }
}

impl InotifyMask {
    pub const CLOSE: Self = Self::CLOSE_WRITE.union(Self::CLOSE_NOWRITE);
    pub const MOVE: Self = Self::MOVED_FROM.union(Self::MOVED_TO);
    pub const ALL_EVENTS: Self = Self::from_bits_retain(0x0000_0fff);
}

/// Fixed header of one variable-length inotify queue record.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct InotifyEvent {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub len: u32,
}

/// Request to syscall handler
#[non_exhaustive]
#[derive(Debug)]
pub enum SyscallRequest {
    Exit {
        status: i32,
    },
    ExitGroup {
        status: i32,
    },
    Read {
        fd: i32,
        buf: UserPtrMut<u8>,
        count: usize,
    },
    Write {
        fd: i32,
        buf: UserPtr<u8>,
        count: usize,
    },
    Lseek {
        fd: i32,
        offset: isize,
        whence: i32,
    },
    Close {
        fd: i32,
    },
    Stat {
        pathname: UserPtr<c_char>,
        buf: UserPtrMut<FileStat>,
    },
    Fstat {
        fd: i32,
        buf: UserPtrMut<FileStat>,
    },
    Lstat {
        pathname: UserPtr<c_char>,
        buf: UserPtrMut<FileStat>,
    },
    Mkdirat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        mode: u32,
    },
    Chdir {
        pathname: UserPtr<c_char>,
    },
    Fchdir {
        fd: i32,
    },
    /// `chroot(2)`: make `path` the calling process's root directory.
    Chroot {
        path: UserPtr<c_char>,
    },
    /// `seccomp(2)`: `operation` is one of `SECCOMP_SET_MODE_STRICT` (0),
    /// `SECCOMP_SET_MODE_FILTER` (1), `SECCOMP_GET_ACTION_AVAIL` (2) or
    /// `SECCOMP_GET_NOTIF_SIZES` (3); `args` points at an operation-specific
    /// structure (a `struct sock_fprog` for `SET_MODE_FILTER`).
    /// `prctl(PR_SET_SECCOMP, mode, filter)` decodes to the equivalent
    /// request (`flags == 0`), exactly as Linux's `prctl_set_seccomp` does.
    Seccomp {
        operation: u32,
        flags: u32,
        args: UserPtr<u8>,
    },
    /// `mseal(2)` (Linux 6.10+, syscall 462 on every architecture): seal the
    /// mappings in `[addr, addr + len)` against further changes. Decoded so
    /// that it appears in the syscall trace even though nothing implements
    /// sealing yet (the shim answers `ENOSYS`, like an older kernel).
    Mseal {
        addr: usize,
        len: usize,
        flags: usize,
    },
    Mmap {
        addr: usize,
        length: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    },
    Mprotect {
        addr: UserPtrMut<u8>,
        length: usize,
        prot: ProtFlags,
    },
    Munmap {
        addr: UserPtrMut<u8>,
        length: usize,
    },
    Mremap {
        old_addr: UserPtrMut<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    },
    Brk {
        addr: UserPtrMut<u8>,
    },
    RtSigprocmask {
        how: signal::SigmaskHow,
        set: Option<UserPtr<SigSet>>,
        oldset: Option<UserPtrMut<SigSet>>,
        sigsetsize: usize,
    },
    RtSigaction {
        signum: signal::Signal,
        act: Option<UserPtr<signal::SigAction>>,
        oldact: Option<UserPtrMut<signal::SigAction>>,
        sigsetsize: usize,
    },
    RtSigreturn,
    RtSigsuspend {
        mask: Option<UserPtr<SigSet>>,
        sigsetsize: usize,
    },
    Kill {
        pid: i32,
        sig: i32,
    },
    Tkill {
        tid: i32,
        sig: i32,
    },
    Tgkill {
        tgid: i32,
        tid: i32,
        sig: i32,
    },
    Sigaltstack {
        ss: Option<UserPtr<signal::SigAltStack>>,
        old_ss: Option<UserPtrMut<signal::SigAltStack>>,
    },
    Ioctl {
        fd: i32,
        arg: IoctlArg,
    },
    Pread64 {
        fd: i32,
        buf: UserPtrMut<u8>,
        count: usize,
        offset: i64,
    },
    Pwrite64 {
        fd: i32,
        buf: UserPtr<u8>,
        count: usize,
        offset: i64,
    },
    Sendfile {
        out_fd: i32,
        in_fd: i32,
        offset: Option<UserPtrMut<i64>>,
        count: usize,
    },
    Readv {
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
    },
    Writev {
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
    },
    Preadv {
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
        pos_l: usize,
        pos_h: usize,
    },
    Pwritev {
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
        pos_l: usize,
        pos_h: usize,
    },
    Faccessat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        mode: AccessFlags,
        flags: AtFlags,
    },
    Madvise {
        addr: UserPtrMut<u8>,
        length: usize,
        behavior: MadviseBehavior,
    },
    Dup {
        oldfd: i32,
        newfd: Option<i32>,
        flags: Option<litebox::fs::OFlags>,
    },
    Socket {
        domain: u32,
        type_and_flags: u32,
        protocol: u8,
    },
    Socketpair {
        domain: u32,
        type_and_flags: u32,
        protocol: u8,
        sockvec: UserPtrMut<u32>,
    },
    Connect {
        sockfd: i32,
        sockaddr: UserPtr<u8>,
        addrlen: usize,
    },
    Accept {
        sockfd: i32,
        addr: Option<UserPtrMut<u8>>,
        addrlen: Option<UserPtrMut<u32>>,
        flags: SockFlags,
    },
    Sendto {
        sockfd: i32,
        buf: UserPtr<u8>,
        len: usize,
        flags: SendFlags,
        addr: Option<UserPtr<u8>>,
        addrlen: u32,
    },
    Sendmsg {
        sockfd: i32,
        msg: UserPtr<UserMsgHdr>,
        flags: SendFlags,
    },
    Sendmmsg {
        sockfd: i32,
        msgvec: UserPtrMut<UserMmsgHdr>,
        vlen: u32,
        flags: SendFlags,
    },
    Recvfrom {
        sockfd: i32,
        buf: UserPtrMut<u8>,
        len: usize,
        flags: ReceiveFlags,
        addr: Option<UserPtrMut<u8>>,
        addrlen: UserPtrMut<u32>,
    },
    Recvmsg {
        sockfd: i32,
        msg: UserPtrMut<UserMsgHdr>,
        flags: ReceiveFlags,
    },
    Recvmmsg {
        sockfd: i32,
        msgvec: UserPtrMut<UserMmsgHdr>,
        vlen: u32,
        flags: ReceiveFlags,
        timeout: TimeParam,
    },
    Shutdown {
        sockfd: i32,
        how: i32,
    },
    Bind {
        sockfd: i32,
        sockaddr: UserPtr<u8>,
        addrlen: usize,
    },
    Listen {
        sockfd: i32,
        backlog: u16,
    },
    Setsockopt {
        sockfd: i32,
        level: u32,
        optname: u32,
        optval: UserPtr<u8>,
        optlen: usize,
    },
    Getsockopt {
        sockfd: i32,
        level: u32,
        optname: u32,
        optval: UserPtrMut<u8>,
        optlen: UserPtrMut<u32>,
    },
    Getsockname {
        sockfd: i32,
        addr: UserPtrMut<u8>,
        addrlen: UserPtrMut<u32>,
    },
    Getpeername {
        sockfd: i32,
        addr: UserPtrMut<u8>,
        addrlen: UserPtrMut<u32>,
    },
    Uname {
        buf: UserPtrMut<Utsname>,
    },
    Fcntl {
        fd: i32,
        arg: FcntlArg,
    },
    Flock {
        fd: i32,
        operation: FlockOperation,
    },
    Getcwd {
        buf: UserPtrMut<u8>,
        size: usize,
    },
    EpollCtl {
        epfd: i32,
        op: EpollOp,
        fd: i32,
        event: UserPtr<EpollEvent>,
    },
    EpollPwait {
        epfd: i32,
        events: UserPtrMut<EpollEvent>,
        maxevents: u32,
        timeout: i32,
        sigmask: Option<UserPtr<SigSet>>,
        sigsetsize: usize,
    },
    EpollCreate {
        size: i32,
        flags: EpollCreateFlags,
    },
    Ppoll {
        fds: UserPtrMut<Pollfd>,
        nfds: usize,
        timeout: TimeParam,
        sigmask: Option<UserPtr<SigSet>>,
        sigsetsize: usize,
    },
    Pselect {
        nfds: u32,
        readfds: Option<UserPtrMut<usize>>,
        writefds: Option<UserPtrMut<usize>>,
        exceptfds: Option<UserPtrMut<usize>>,
        timeout: TimeParam,
        sigsetpack: Option<UserPtr<SigSetPack>>,
    },
    ArchPrctl {
        arg: ArchPrctlArg,
    },
    Readlink {
        pathname: UserPtr<c_char>,
        buf: UserPtrMut<u8>,
        bufsiz: usize,
    },
    Readlinkat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        buf: UserPtrMut<u8>,
        bufsiz: usize,
    },
    Openat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        flags: litebox::fs::OFlags,
        mode: litebox::fs::Mode,
    },
    Ftruncate {
        fd: i32,
        length: usize,
    },
    /// `fadvise64(2)` (`posix_fadvise`): `advice` is one of the `POSIX_FADV_*` values.
    Fadvise64 {
        fd: i32,
        offset: usize,
        len: usize,
        advice: i32,
    },
    /// `fallocate(2)`: `mode` is the `FALLOC_FL_*` bit set; `offset`/`len` are the raw
    /// (sign-bearing) `off_t` arguments, range-checked by the handler.
    Fallocate {
        fd: i32,
        mode: i32,
        offset: usize,
        len: usize,
    },
    /// `preadv2(2)`: `preadv` plus the `RWF_*` flag word; `pos_l`/`pos_h` of `-1` means
    /// "the file offset" (`readv` semantics).
    Preadv2 {
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
        pos_l: usize,
        pos_h: usize,
        flags: u32,
    },
    /// `pwritev2(2)`: `pwritev` plus the `RWF_*` flag word (see [`Self::Preadv2`]).
    Pwritev2 {
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
        pos_l: usize,
        pos_h: usize,
        flags: u32,
    },
    /// `rt_sigtimedwait(2)`: dequeue one signal from `set`, waiting up to `timeout`.
    RtSigtimedwait {
        set: Option<UserPtr<SigSet>>,
        info: Option<UserPtrMut<signal::Siginfo>>,
        timeout: TimeParam,
        sigsetsize: usize,
    },
    /// `rt_sigqueueinfo(2)`: send `sig` with a caller-supplied `siginfo` to process `pid`.
    RtSigqueueinfo {
        pid: i32,
        sig: i32,
        info: Option<UserPtr<signal::Siginfo>>,
    },
    /// `rt_tgsigqueueinfo(2)`: send `sig` with a caller-supplied `siginfo` to thread `tid` of
    /// thread group `tgid`.
    RtTgsigqueueinfo {
        tgid: i32,
        tid: i32,
        sig: i32,
        info: Option<UserPtr<signal::Siginfo>>,
    },
    /// `getpriority(2)`: `which` is `PRIO_PROCESS`/`PRIO_PGRP`/`PRIO_USER`.
    Getpriority {
        which: i32,
        who: i32,
    },
    /// `setpriority(2)`: `niceval` is the requested nice value, clamped by the handler.
    Setpriority {
        which: i32,
        who: i32,
        niceval: i32,
    },
    /// `membarrier(2)`.
    Membarrier {
        cmd: i32,
        flags: u32,
        cpu_id: i32,
    },
    MemfdCreate {
        name: UserPtr<c_char>,
        flags: u32,
    },
    Mknodat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        mode_and_type: u32,
        dev: u32,
    },
    Unlinkat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        flags: AtFlags,
    },
    /// Reached through both `symlink` (with `newdirfd` forced to `AT_FDCWD`) and
    /// `symlinkat`. `target` is the link's verbatim contents, `linkpath` is where
    /// the link is created (resolved against `newdirfd`).
    Symlinkat {
        target: UserPtr<c_char>,
        newdirfd: i32,
        linkpath: UserPtr<c_char>,
    },
    /// Reached through both `link` (both dirfds forced to `AT_FDCWD`, `flags` 0)
    /// and `linkat`. `flags` carries the raw `AT_*` bits (`AT_SYMLINK_FOLLOW`,
    /// `AT_EMPTY_PATH`); the shim interprets them.
    Linkat {
        olddirfd: i32,
        oldpath: UserPtr<c_char>,
        newdirfd: i32,
        newpath: UserPtr<c_char>,
        flags: u32,
    },
    /// Reached through `rename` (both dirfds forced to `AT_FDCWD`, `flags` 0),
    /// `renameat` (both dirfds real, `flags` 0), and `renameat2` (all fields as
    /// passed). `flags` carries the raw `RENAME_*` bits (`NOREPLACE`/`EXCHANGE`/
    /// `WHITEOUT`); the shim interprets them.
    Renameat2 {
        olddirfd: i32,
        oldpath: UserPtr<c_char>,
        newdirfd: i32,
        newpath: UserPtr<c_char>,
        flags: u32,
    },
    /// Reached through `chmod`, `fchmodat`, and `fchmodat2`.
    ///
    /// `flags` is empty for `chmod`/`fchmodat`, since the raw `fchmodat(2)` syscall (unlike
    /// `fchmodat2(2)`) takes no `flags` argument.
    Fchmodat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        mode: u32,
        flags: AtFlags,
    },
    Fchmod {
        fd: i32,
        mode: u32,
    },
    /// Reached through `fsync`, `fdatasync`, and `syncfs`: every LiteBox filesystem is
    /// memory-resident, so the three collapse into one "is this fd open" request.
    Fsync {
        fd: i32,
    },
    /// Reached through `fchown`. `owner`/`group` carry the raw `uid_t`/`gid_t`; a value of
    /// `(uid_t)-1` (`u32::MAX`) means "leave unchanged", which the shim maps to `None`.
    Fchown {
        fd: i32,
        owner: u32,
        group: u32,
    },
    /// Reached through `chown` (dirfd `AT_FDCWD`, flags empty), `lchown` (dirfd
    /// `AT_FDCWD`, flags `AT_SYMLINK_NOFOLLOW`), and `fchownat`. `owner`/`group`
    /// carry the raw `uid_t`/`gid_t`; a value of `(uid_t)-1` (`u32::MAX`) means
    /// "leave unchanged", which the shim maps to `None`.
    Fchownat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        owner: u32,
        group: u32,
        flags: AtFlags,
    },
    /// Reached through `utimensat`. Also covers `futimens`, which has no syscall of its own:
    /// glibc implements it as `utimensat(fd, NULL, times, 0)`, signaled here by `pathname` being
    /// `None`.
    Utimensat {
        dirfd: i32,
        pathname: Option<UserPtr<c_char>>,
        times: Option<UserPtr<Timespec>>,
        flags: AtFlags,
    },
    Newfstatat {
        dirfd: i32,
        pathname: UserPtr<c_char>,
        buf: UserPtrMut<FileStat>,
        flags: AtFlags,
    },
    Eventfd2 {
        initval: u32,
        flags: EfdFlags,
    },
    InotifyInit1 {
        flags: InotifyInitFlags,
    },
    InotifyAddWatch {
        fd: i32,
        pathname: UserPtr<c_char>,
        mask: InotifyMask,
    },
    InotifyRmWatch {
        fd: i32,
        wd: i32,
    },
    Pipe2 {
        pipefd: UserPtrMut<u32>,
        flags: litebox::fs::OFlags,
    },
    Clone {
        args: CloneArgs,
    },
    Clone3 {
        args: UserPtr<CloneArgs>,
    },
    Unshare {
        flags: CloneFlags,
    },
    /// Manipulate thread-local storage information.
    /// Returns `ENOSYS` on x86_64.
    SetThreadArea {
        user_desc: UserPtrMut<u8>,
    },
    ClockGettime {
        clockid: i32,
        tp: TimeParam,
    },
    ClockGetres {
        clockid: i32,
        res: TimeParam,
    },
    ClockNanosleep {
        clockid: i32,
        flags: TimerFlags,
        request: TimeParam,
        remain: TimeParam,
    },
    Gettimeofday {
        tv: Option<UserPtrMut<TimeVal>>,
        tz: Option<UserPtrMut<TimeZone>>,
    },
    Time {
        tloc: Option<UserPtrMut<time_t>>,
    },
    Getrlimit {
        resource: RlimitResource,
        rlim: UserPtrMut<Rlimit>,
    },
    Setrlimit {
        resource: RlimitResource,
        rlim: UserPtr<Rlimit>,
    },
    Prlimit {
        pid: i32,
        /// The resource for which the limit is being queried.
        resource: RlimitResource,
        /// If the new_limit argument is not a None, then the rlimit structure to which it points
        /// is used to set new values for the soft and hard limits for resource.
        new_limit: Option<UserPtr<Rlimit64>>,
        /// If the old_limit argument is not a None, then a successful call to prlimit() places the
        /// previous soft and hard limits for resource in the rlimit structure pointed to by old_limit.
        old_limit: Option<UserPtrMut<Rlimit64>>,
    },
    SetTidAddress {
        tidptr: UserPtrMut<i32>,
    },
    Gettid,
    SetRobustList {
        head: usize,
    },
    GetRobustList {
        pid: Option<i32>,
        head: UserPtrMut<usize>,
        len: UserPtrMut<usize>,
    },
    GetRandom {
        buf: UserPtrMut<u8>,
        count: usize,
        flags: RngFlags,
    },
    Getpid,
    Getppid,
    /// `getpgid(pid)`. `pid == 0` means "the calling process".
    Getpgid {
        pid: i32,
    },
    /// `setpgid(pid, pgid)`. `pid == 0` means "the calling process"; `pgid == 0` means "use
    /// `pid`'s own value as the new group id".
    Setpgid {
        pid: i32,
        pgid: i32,
    },
    /// `setsid()`: create a new session with the caller as its leader.
    Setsid,
    /// `wait4(pid, wstatus, options, rusage)`.
    ///
    /// This is the only wait syscall aarch64 offers besides `waitid`; libc's
    /// `wait`/`waitpid`/`wait3` all funnel into it. `rusage` is carried as a raw
    /// address rather than a typed pointer because the shim has no `struct
    /// rusage` accounting to report -- see `Task::sys_wait4`.
    Wait4 {
        pid: i32,
        wstatus: Option<UserPtrMut<i32>>,
        options: i32,
        rusage: usize,
    },
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    Getgroups {
        size: i32,
        list: UserPtrMut<u32>,
    },
    Setgroups {
        size: usize,
        list: UserPtr<u32>,
    },
    Setuid {
        uid: u32,
    },
    Setgid {
        gid: u32,
    },
    /// Reached through `setresuid`; also the syscall libc's `seteuid(2)` wrapper
    /// makes (`setresuid(-1, euid, -1)`). `u32::MAX` (-1) leaves a field unchanged.
    Setresuid {
        ruid: u32,
        euid: u32,
        suid: u32,
    },
    /// See [`Self::Setresuid`]; `setresgid` / libc `setegid`.
    Setresgid {
        rgid: u32,
        egid: u32,
        sgid: u32,
    },
    /// `getresuid`: read back the real/effective/saved uid set by `Setresuid`.
    Getresuid {
        ruid: UserPtrMut<u32>,
        euid: UserPtrMut<u32>,
        suid: UserPtrMut<u32>,
    },
    /// See [`Self::Getresuid`]; `getresgid`, with group IDs.
    Getresgid {
        rgid: UserPtrMut<u32>,
        egid: UserPtrMut<u32>,
        sgid: UserPtrMut<u32>,
    },
    Sysinfo {
        buf: UserPtrMut<Sysinfo>,
    },
    Getrusage {
        who: i32,
        usage: UserPtrMut<Rusage>,
    },
    CapGet {
        header: UserPtrMut<CapHeader>,
        data: Option<UserPtrMut<CapData>>,
    },
    CapSet {
        header: UserPtr<CapHeader>,
        data: Option<UserPtr<CapData>>,
    },
    GetDirent64 {
        fd: i32,
        dirp: UserPtrMut<u8>,
        count: usize,
    },
    SchedGetAffinity {
        pid: Option<i32>,
        len: usize,
        mask: UserPtrMut<u8>,
    },
    SchedYield,
    SchedGetParam {
        pid: Option<i32>,
        param: UserPtrMut<SchedParam>,
    },
    SchedSetParam {
        pid: Option<i32>,
        param: UserPtr<SchedParam>,
    },
    SchedGetScheduler {
        pid: Option<i32>,
    },
    SchedSetScheduler {
        pid: Option<i32>,
        policy: i32,
        param: UserPtr<SchedParam>,
    },
    Futex {
        args: FutexArgs,
    },
    Execve {
        pathname: UserPtr<c_char>,
        argv: UserPtr<UserPtr<c_char>>,
        envp: UserPtr<UserPtr<c_char>>,
    },
    Umask {
        mask: u32,
    },
    Prctl {
        args: PrctlArg,
    },
    Alarm {
        seconds: u32,
    },
    Pause,
    SetITimer {
        which: IntervalTimer,
        new_value: Option<UserPtr<ItimerVal>>,
        old_value: Option<UserPtrMut<ItimerVal>>,
    },
    GetITimer {
        which: IntervalTimer,
        curr_value: UserPtrMut<ItimerVal>,
    },
    Statx {
        dirfd: i32,
        pathname: Option<UserPtr<c_char>>,
        flags: AtFlags,
        mask: StatxMask,
        statxbuf: UserPtrMut<Statx>,
    },
    Statfs {
        pathname: UserPtr<c_char>,
        buf: UserPtrMut<Statfs>,
    },
    Fstatfs {
        fd: i32,
        buf: UserPtrMut<Statfs>,
    },
    /// `ptrace(request, pid, addr, data)`. `addr`/`data` are decoded generically here (as a raw
    /// address and a raw machine word, matching the real syscall's `void *`/`long` signature) --
    /// `request` determines how they are actually used (e.g. `PTRACE_GETREGSET`'s `data` is a
    /// `struct iovec *`), so that per-request interpretation happens in
    /// `syscalls::ptrace::Task::sys_ptrace`, not here.
    Ptrace {
        request: i64,
        pid: i32,
        addr: usize,
        data: usize,
    },
}

impl SyscallRequest {
    /// Take the raw syscall number and arguments, and provide a stronger-typed `SyscallRequest`.
    ///
    /// Returns `Ok` if a valid translation exists, if no such translation exists, returns the [`Errno`](errno::Errno) for it.
    ///
    /// # Panics
    ///
    /// Ideally, this function would not panic. However, since it is currently under development, it
    /// is allowed to panic upon receiving a syscall number (or arguments) that it does not know how
    /// to handle.
    // NOTE: This function is intended to be mostly trivial (in the future, we intend to replace
    // this entire function with a simple type-driven macro), thus any non-trivial parsing should
    // happen outside of this. Roughly speaking, if it is a simple integer, pointer, or a flag
    // field, it is fine; anything more complex should not attempt to do more, and must instead
    // perform the actual "parsing" outside. It is ok to introduce new `impl`s for
    // `ReinterpretTruncatedFromUsize` in order to support stronger types (especially if one desires
    // a fail-free parse), but also quite helpful is to define a `TryFrom<i32>` and use the `:?`
    // combinator (which will return `EINVAL` upon parse failure).
    /// `mseal` (Linux 6.10) is number 462 on every architecture but is absent from the
    /// `syscalls` 0.6.18 table, so `Sysno::new` cannot name it; `try_from_raw` decodes it by
    /// raw number so it is a visible request rather than an anonymous "unknown syscall".
    const SYS_MSEAL: usize = 462;

    pub fn try_from_raw(
        syscall_number: usize,
        ctx: &PtRegs,
        log_unsupported: impl Fn(core::fmt::Arguments<'_>),
    ) -> Result<Self, errno::Errno> {
        let unsupported_einval = |args: core::fmt::Arguments<'_>| {
            log_unsupported(args);
            errno::Errno::EINVAL
        };
        // sys_req! is a convenience macro that automatically takes the correct numbered arguments
        // (in the order of field specification); due to some Rust restrictions, we need to manually
        // specify pointers by adding the `:*` to that field, but otherwise everything else about
        // conversion to the type is automatically inferred.
        //
        // See below for example usage, but generally speaking, you just need to specify the fields
        // in order; if something needs to be a pointer and you forget (or accidentally mark
        // something as a pointer) the type checker will complain and remind you (due to the nice
        // attributes on the relevant traits), so you shouldn't need to worry about that.
        //
        // NOTE: This macro should seldom (if ever) be updated. Usually if you think you need to
        // update this, you probably need to introduce an `impl` instead.
        macro_rules! sys_req {
            ($id:ident { $( $field:ident $(:$star:tt)?),* $(,)? }) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ 0, 1, 2, 3, 4, 5 ] [ ]
                )
            };
            (@[$id:ident] [ $f:ident $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: ctx.sys_req_arg($n), ]
                )
            };
            (@[$id:ident] [ $f:ident : * $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: ctx.sys_req_ptr($n), ]
                )
            };
            (@[$id:ident] [ $f:ident : ? $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: ctx.sys_req_arg::<i32>($n).try_into().or(Err(errno::Errno::EINVAL))?, ]
                )
            };
            (@[$id:ident] [ $f:ident : { =*> $e:expr } $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                // `{ =*> e }`: temporary syntax to support removing some hard-coded bits
                // NOTE: Please do NOT use this for any new syscalls added
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: { $e ( ctx.sys_req_ptr($n) ) }, ]
                )
            };
            (@[$id:ident] [ $f:ident : { => $e:expr } $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                // `{ => e }`: temporary syntax to support removing some hard-coded bits
                // NOTE: Please do NOT use this for any new syscalls added
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: { $e ( ctx.sys_req_arg($n) ) }, ]
                )
            };
            (@[$id:ident] [ $f:ident : { $e:expr } $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: $e, ]
                )
            };
            (@[$id:ident] [ ] [ $($ns:literal),* ] [ $($tail:tt)* ]) => {
                SyscallRequest::$id { $($tail)* }
            };
        }

        if syscall_number == Self::SYS_MSEAL {
            return Ok(sys_req!(Mseal { addr, len, flags }));
        }
        let sysno = Sysno::new(syscall_number).ok_or_else(|| {
            log_unsupported(format_args!("unknown syscall {syscall_number}"));
            errno::Errno::ENOSYS
        })?;
        let dispatcher = match sysno {
            Sysno::read => sys_req!(Read { fd, buf:*, count }),
            Sysno::write => sys_req!(Write { fd, buf:*, count }),
            Sysno::close => sys_req!(Close { fd }),
            Sysno::lseek => sys_req!(Lseek { fd, offset, whence }),
            #[cfg(target_arch = "x86_64")]
            Sysno::stat => sys_req!(Stat { pathname:*, buf:* }),
            Sysno::fstat => sys_req!(Fstat { fd, buf:* }),
            #[cfg(target_arch = "x86_64")]
            Sysno::lstat => sys_req!(Lstat { pathname:*, buf:* }),
            #[cfg(target_arch = "x86_64")]
            Sysno::mkdir => SyscallRequest::Mkdirat {
                dirfd: AT_FDCWD,
                pathname: ctx.sys_req_ptr(0),
                mode: ctx.sys_req_arg(1),
            },
            Sysno::mkdirat => sys_req!(Mkdirat { dirfd, pathname:*, mode }),
            #[cfg(target_arch = "x86_64")]
            Sysno::chmod => SyscallRequest::Fchmodat {
                dirfd: AT_FDCWD,
                pathname: ctx.sys_req_ptr(0),
                mode: ctx.sys_req_arg(1),
                flags: AtFlags::empty(),
            },
            Sysno::fchmod => sys_req!(Fchmod { fd, mode }),
            Sysno::fchown => sys_req!(Fchown { fd, owner, group }),
            Sysno::fchmodat => sys_req!(Fchmodat {
                dirfd,
                pathname:*,
                mode,
                flags: { AtFlags::empty() },
            }),
            Sysno::fchmodat2 => sys_req!(Fchmodat { dirfd, pathname:*, mode, flags }),
            Sysno::fsync | Sysno::fdatasync | Sysno::syncfs => sys_req!(Fsync { fd }),
            Sysno::fchownat => sys_req!(Fchownat { dirfd, pathname:*, owner, group, flags }),
            #[cfg(target_arch = "x86_64")]
            Sysno::chown => SyscallRequest::Fchownat {
                dirfd: AT_FDCWD,
                pathname: ctx.sys_req_ptr(0),
                owner: ctx.sys_req_arg(1),
                group: ctx.sys_req_arg(2),
                flags: AtFlags::empty(),
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::lchown => SyscallRequest::Fchownat {
                // `lchown` acts on the link itself, i.e. `fchownat(.., AT_SYMLINK_NOFOLLOW)`.
                dirfd: AT_FDCWD,
                pathname: ctx.sys_req_ptr(0),
                owner: ctx.sys_req_arg(1),
                group: ctx.sys_req_arg(2),
                flags: AtFlags::AT_SYMLINK_NOFOLLOW,
            },
            Sysno::utimensat => sys_req!(Utimensat { dirfd, pathname:*, times:*, flags }),
            Sysno::chdir => sys_req!(Chdir { pathname:* }),
            Sysno::chroot => sys_req!(Chroot { path:* }),
            Sysno::seccomp => sys_req!(Seccomp {
                operation,
                flags,
                args:*
            }),
            Sysno::fchdir => sys_req!(Fchdir { fd }),
            Sysno::mmap => sys_req!(Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            }),
            Sysno::mprotect => sys_req!(Mprotect { addr:*, length, prot }),
            Sysno::munmap => sys_req!(Munmap { addr:*, length }),
            Sysno::brk => sys_req!(Brk { addr:* }),
            Sysno::mremap => sys_req!(Mremap { old_addr:*, old_size, new_size, flags, new_addr }),
            Sysno::rt_sigprocmask => sys_req!(RtSigprocmask {
                how:?,
                set:*,
                oldset:*,
                sigsetsize,
            }),
            Sysno::rt_sigaction => sys_req!(RtSigaction {
                signum:?,
                act:*,
                oldact:*,
                sigsetsize,
            }),
            Sysno::rt_sigreturn => SyscallRequest::RtSigreturn,
            Sysno::rt_sigsuspend => sys_req!(RtSigsuspend { mask:*, sigsetsize }),
            Sysno::kill => sys_req!(Kill { pid, sig }),
            Sysno::tkill => sys_req!(Tkill { tid, sig }),
            Sysno::tgkill => sys_req!(Tgkill { tgid, tid, sig }),
            Sysno::rt_sigtimedwait => {
                sys_req!(RtSigtimedwait { set:*, info:*, timeout: { =*> TimeParam::timespec_old }, sigsetsize })
            }
            Sysno::rt_sigqueueinfo => sys_req!(RtSigqueueinfo { pid, sig, info:* }),
            Sysno::rt_tgsigqueueinfo => sys_req!(RtTgsigqueueinfo { tgid, tid, sig, info:* }),
            Sysno::getpriority => sys_req!(Getpriority { which, who }),
            Sysno::setpriority => sys_req!(Setpriority {
                which,
                who,
                niceval
            }),
            Sysno::membarrier => sys_req!(Membarrier { cmd, flags, cpu_id }),
            Sysno::sigaltstack => sys_req!(Sigaltstack { ss:*, old_ss:* }),
            Sysno::ioctl => SyscallRequest::Ioctl {
                fd: ctx.sys_req_arg(0),
                arg: {
                    let cmd = ctx.sys_req_arg(1);
                    match cmd {
                        TCGETS => IoctlArg::TCGETS(ctx.sys_req_ptr(2)),
                        TCSETS => IoctlArg::TCSETS(ctx.sys_req_ptr(2), TerminalSetAction::Now),
                        TCSETSW => IoctlArg::TCSETS(ctx.sys_req_ptr(2), TerminalSetAction::Drain),
                        TCSETSF => IoctlArg::TCSETS(ctx.sys_req_ptr(2), TerminalSetAction::Flush),
                        TIOCSCTTY => IoctlArg::TIOCSCTTY(ctx.sys_req_arg(2)),
                        TIOCGPGRP => IoctlArg::TIOCGPGRP(ctx.sys_req_ptr(2)),
                        TIOCSPGRP => IoctlArg::TIOCSPGRP(ctx.sys_req_ptr(2)),
                        TIOCGWINSZ => IoctlArg::TIOCGWINSZ(ctx.sys_req_ptr(2)),
                        TIOCSWINSZ => IoctlArg::TIOCSWINSZ(ctx.sys_req_ptr(2)),
                        TIOCGPTN => IoctlArg::TIOCGPTN(ctx.sys_req_ptr(2)),
                        TIOCSPTLCK => IoctlArg::TIOCSPTLCK(ctx.sys_req_ptr(2)),
                        FIONBIO => IoctlArg::FIONBIO(ctx.sys_req_ptr(2)),
                        FIOCLEX => IoctlArg::FIOCLEX,
                        FBIOGET_VSCREENINFO => IoctlArg::FBIOGET_VSCREENINFO(ctx.sys_req_ptr(2)),
                        FBIOPUT_VSCREENINFO => IoctlArg::FBIOPUT_VSCREENINFO(ctx.sys_req_ptr(2)),
                        FBIOGET_FSCREENINFO => IoctlArg::FBIOGET_FSCREENINFO(ctx.sys_req_ptr(2)),
                        FBIOPAN_DISPLAY => IoctlArg::FBIOPAN_DISPLAY(ctx.sys_req_ptr(2)),
                        FBIOBLANK => IoctlArg::FBIOBLANK,
                        _ => IoctlArg::Raw {
                            cmd,
                            arg: ctx.sys_req_ptr(2),
                        },
                    }
                },
            },
            Sysno::pread64 => sys_req!(Pread64 {
                fd,
                buf:*,
                count,
                offset
            }),
            Sysno::pwrite64 => sys_req!(Pwrite64 {
                fd,
                buf:*,
                count,
                offset
            }),
            Sysno::sendfile => sys_req!(Sendfile { out_fd, in_fd, offset:*, count }),
            Sysno::readv => sys_req!(Readv { fd, iovec:*, iovcnt }),
            Sysno::writev => sys_req!(Writev { fd, iovec:*, iovcnt }),
            Sysno::preadv => sys_req!(Preadv { fd, iovec:*, iovcnt, pos_l, pos_h }),
            Sysno::pwritev => sys_req!(Pwritev { fd, iovec:*, iovcnt, pos_l, pos_h }),
            Sysno::preadv2 => sys_req!(Preadv2 { fd, iovec:*, iovcnt, pos_l, pos_h, flags }),
            Sysno::pwritev2 => sys_req!(Pwritev2 { fd, iovec:*, iovcnt, pos_l, pos_h, flags }),
            #[cfg(target_arch = "x86_64")]
            Sysno::access => SyscallRequest::Faccessat {
                dirfd: AT_FDCWD,
                pathname: ctx.sys_req_ptr(0),
                mode: ctx.sys_req_arg(1),
                flags: AtFlags::empty(),
            },
            Sysno::faccessat => SyscallRequest::Faccessat {
                dirfd: ctx.sys_req_arg(0),
                pathname: ctx.sys_req_ptr(1),
                mode: ctx.sys_req_arg(2),
                flags: AtFlags::empty(),
            },
            Sysno::faccessat2 => sys_req!(Faccessat { dirfd, pathname:*, mode, flags }),
            #[cfg(target_arch = "x86_64")]
            Sysno::pipe => sys_req!(Pipe2 { pipefd:*, flags: { litebox::fs::OFlags::empty() } }),
            Sysno::pipe2 => sys_req!(Pipe2 { pipefd:* ,flags }),
            Sysno::madvise => sys_req!(Madvise { addr:*, length, behavior:? }),
            Sysno::dup => SyscallRequest::Dup {
                oldfd: ctx.sys_req_arg(0),
                newfd: None,
                flags: None,
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::dup2 => SyscallRequest::Dup {
                oldfd: ctx.sys_req_arg(0),
                newfd: Some(ctx.sys_req_arg(1)),
                flags: None,
            },
            Sysno::dup3 => SyscallRequest::Dup {
                oldfd: ctx.sys_req_arg(0),
                newfd: Some(ctx.sys_req_arg(1)),
                flags: Some(ctx.sys_req_arg(2)),
            },
            Sysno::socket => sys_req!(Socket {
                domain,
                type_and_flags,
                protocol,
            }),
            Sysno::socketpair => sys_req!(Socketpair {
                domain,
                type_and_flags,
                protocol,
                sockvec: *,
            }),
            Sysno::connect => sys_req!(Connect { sockfd, sockaddr:*, addrlen }),
            Sysno::accept => sys_req!(Accept {
                sockfd,
                addr:*,
                addrlen:*,
                flags: { SockFlags::empty() }
            }),
            Sysno::accept4 => sys_req!(Accept { sockfd, addr:*, addrlen:*, flags }),
            Sysno::sendto => sys_req!(Sendto { sockfd, buf:*, len, flags, addr:*, addrlen }),
            Sysno::sendmsg => sys_req!(Sendmsg { sockfd, msg:*, flags }),
            Sysno::sendmmsg => sys_req!(Sendmmsg { sockfd, msgvec:*, vlen, flags }),
            Sysno::recvfrom => sys_req!(Recvfrom { sockfd, buf:*, len, flags, addr:*, addrlen:*, }),
            Sysno::recvmsg => sys_req!(Recvmsg { sockfd, msg:*, flags }),
            Sysno::recvmmsg => sys_req!(Recvmmsg {
                sockfd,
                msgvec:*,
                vlen,
                flags,
                timeout: { =*> TimeParam::timespec_old }
            }),
            Sysno::shutdown => sys_req!(Shutdown { sockfd, how }),
            Sysno::bind => sys_req!(Bind { sockfd, sockaddr:*, addrlen }),
            Sysno::listen => sys_req!(Listen { sockfd, backlog }),
            Sysno::setsockopt => sys_req!(Setsockopt {
                sockfd,
                level,
                optname,
                optval:*,
                optlen,
            }),
            Sysno::getsockopt => sys_req!(Getsockopt {
                sockfd,
                level,
                optname,
                optval:*,
                optlen:*,
            }),
            Sysno::getsockname => sys_req!(Getsockname { sockfd, addr:*, addrlen:* }),
            Sysno::getpeername => sys_req!(Getpeername { sockfd, addr:*, addrlen:* }),
            Sysno::exit => sys_req!(Exit { status }),
            Sysno::exit_group => sys_req!(ExitGroup { status }),
            Sysno::uname => sys_req!(Uname { buf:* }),
            Sysno::fcntl => {
                let cmd: i32 = ctx.sys_req_arg(1);
                let arg = ctx.sys_req_arg(2);
                SyscallRequest::Fcntl {
                    fd: ctx.sys_req_arg(0),
                    arg: FcntlArg::try_from(cmd, arg).ok_or_else(|| {
                        unsupported_einval(format_args!("fcntl(cmd = {cmd}, arg = {arg})"))
                    })?,
                }
            }
            Sysno::flock => {
                let operation: i32 = ctx.sys_req_arg(1);
                SyscallRequest::Flock {
                    fd: ctx.sys_req_arg(0),
                    operation: FlockOperation::from_bits(operation).ok_or_else(|| {
                        unsupported_einval(format_args!("flock(operation = {operation})"))
                    })?,
                }
            }
            Sysno::gettimeofday => sys_req!(Gettimeofday { tv:*, tz:* }),
            Sysno::clock_gettime => {
                sys_req!(ClockGettime { clockid, tp: { =*> TimeParam::timespec_old } })
            }
            Sysno::clock_getres => {
                sys_req!(ClockGetres { clockid, res: { =*> TimeParam::timespec_old } })
            }
            Sysno::clock_nanosleep => {
                sys_req!(ClockNanosleep {
                    clockid,
                    flags,
                    request: { =*> TimeParam::timespec_old },
                    remain: { =*> TimeParam::timespec_old },
                })
            }
            Sysno::nanosleep => sys_req!(ClockNanosleep {
                request: { =*> TimeParam::timespec_old },
                remain: { =*> TimeParam::timespec_old },
                clockid: { ClockId::Monotonic.into() },
                flags: { TimerFlags::empty() },
            }),
            #[cfg(target_arch = "x86_64")]
            Sysno::time => sys_req!(Time { tloc:* }),
            Sysno::getcwd => sys_req!(Getcwd { buf:*, size }),
            #[cfg(target_arch = "x86_64")]
            Sysno::readlink => sys_req!(Readlink { pathname:*, buf:* ,bufsiz }),
            Sysno::readlinkat => sys_req!(Readlinkat { dirfd, pathname:*, buf:*, bufsiz }),
            Sysno::getrlimit => sys_req!(Getrlimit { resource:?, rlim:* }),
            Sysno::setrlimit => sys_req!(Setrlimit { resource:?, rlim:* }),
            Sysno::prlimit64 => sys_req!(Prlimit { pid, resource:?, new_limit:*, old_limit:* }),
            Sysno::getpid => SyscallRequest::Getpid,
            Sysno::getppid => SyscallRequest::Getppid,
            Sysno::getpgid => sys_req!(Getpgid { pid }),
            Sysno::setpgid => sys_req!(Setpgid { pid, pgid }),
            Sysno::setsid => SyscallRequest::Setsid,
            Sysno::wait4 => sys_req!(Wait4 {
                pid,
                wstatus:*,
                options,
                rusage
            }),
            Sysno::getuid => SyscallRequest::Getuid,
            Sysno::getgid => SyscallRequest::Getgid,
            Sysno::geteuid => SyscallRequest::Geteuid,
            Sysno::getegid => SyscallRequest::Getegid,
            Sysno::getgroups => sys_req!(Getgroups { size, list:* }),
            Sysno::setgroups => sys_req!(Setgroups { size, list:* }),
            Sysno::setuid => sys_req!(Setuid { uid }),
            Sysno::setgid => sys_req!(Setgid { gid }),
            Sysno::setresuid => sys_req!(Setresuid { ruid, euid, suid }),
            Sysno::setresgid => sys_req!(Setresgid { rgid, egid, sgid }),
            Sysno::getresuid => sys_req!(Getresuid { ruid:*, euid:*, suid:* }),
            Sysno::getresgid => sys_req!(Getresgid { rgid:*, egid:*, sgid:* }),
            Sysno::epoll_ctl => sys_req!(EpollCtl { epfd, op:?, fd, event:* }),
            #[cfg(target_arch = "x86_64")]
            Sysno::epoll_wait => {
                sys_req!(EpollPwait { epfd, events:*, maxevents, timeout, sigmask: { None }, sigsetsize: { 0 }, })
            }
            Sysno::epoll_pwait => {
                sys_req!(EpollPwait { epfd, events:*, maxevents, timeout, sigmask:*, sigsetsize })
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::epoll_create => sys_req!(EpollCreate {
                size,
                flags: { EpollCreateFlags::empty() }
            }),
            Sysno::epoll_create1 => sys_req!(EpollCreate { flags, size: { 1 } }),
            Sysno::ppoll => {
                sys_req!(Ppoll { fds:*, nfds, timeout: { =*> TimeParam::timespec_old }, sigmask:*, sigsetsize })
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::poll => {
                sys_req!(Ppoll { fds:*, nfds, timeout: { => TimeParam::Milliseconds }, sigmask: { None }, sigsetsize: { 0 } })
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::select => {
                sys_req!(Pselect {
                    nfds,
                    readfds:*,
                    writefds:*,
                    exceptfds:*,
                    timeout: { =*> TimeParam::timeval },
                    sigsetpack: { None },
                })
            }
            Sysno::pselect6 => {
                sys_req!(Pselect {
                    nfds,
                    readfds:*,
                    writefds:*,
                    exceptfds:*,
                    timeout: { =*> TimeParam::timespec_old },
                    sigsetpack:*,
                })
            }
            Sysno::prctl => {
                let op: u32 = ctx.sys_req_arg(0);
                if let Ok(op) = PrctlOption::try_from(op) {
                    match op {
                        PrctlOption::SetPDeathSig => {
                            let signal: i32 = ctx.sys_req_arg(1);
                            let signal = if signal == 0 {
                                None
                            } else {
                                Some(signal::Signal::try_from(signal)?)
                            };
                            SyscallRequest::Prctl {
                                args: PrctlArg::SetPDeathSig(signal),
                            }
                        }
                        PrctlOption::GetPDeathSig => SyscallRequest::Prctl {
                            args: PrctlArg::GetPDeathSig(ctx.sys_req_ptr(1)),
                        },
                        PrctlOption::SetName => SyscallRequest::Prctl {
                            args: PrctlArg::SetName(ctx.sys_req_ptr(1)),
                        },
                        PrctlOption::GetName => SyscallRequest::Prctl {
                            args: PrctlArg::GetName(ctx.sys_req_ptr(1)),
                        },
                        // Linux (`kernel/sys.c`) does not check the trailing arguments for
                        // `PR_GET_DUMPABLE`; callers (Chromium's sandbox) pass whatever is
                        // left in the registers, and an `EINVAL` here reads as "no dumpable
                        // support" and trips their CHECK.
                        PrctlOption::GetDumpable => SyscallRequest::Prctl {
                            args: PrctlArg::GetDumpable,
                        },
                        // Linux (`kernel/sys.c`): only `SUID_DUMP_DISABLE` (0) and
                        // `SUID_DUMP_USER` (1) may be set through prctl; anything else is
                        // `EINVAL`. The trailing arguments are not checked by the kernel.
                        PrctlOption::SetDumpable => {
                            let value: usize = ctx.sys_req_arg(1);
                            if value > 1 {
                                return Err(unsupported_einval(format_args!(
                                    "prctl(PR_SET_DUMPABLE, {value})"
                                )));
                            }
                            SyscallRequest::Prctl {
                                args: PrctlArg::SetDumpable(value as u64),
                            }
                        }
                        // `prctl(PR_SET_SECCOMP, mode, filter)` is `seccomp(op, 0, filter)`
                        // with `SECCOMP_MODE_STRICT` (1) -> `SECCOMP_SET_MODE_STRICT` (0) and
                        // `SECCOMP_MODE_FILTER` (2) -> `SECCOMP_SET_MODE_FILTER` (1), exactly
                        // as the kernel's `prctl_set_seccomp` maps it; other modes are
                        // `EINVAL`.
                        PrctlOption::SetSeccomp => {
                            let mode: usize = ctx.sys_req_arg(1);
                            let operation = match mode {
                                1 => 0,
                                2 => 1,
                                _ => {
                                    return Err(unsupported_einval(format_args!(
                                        "prctl(PR_SET_SECCOMP, mode = {mode})"
                                    )));
                                }
                            };
                            SyscallRequest::Seccomp {
                                operation,
                                flags: 0,
                                args: ctx.sys_req_ptr(2),
                            }
                        }
                        PrctlOption::SetVma => SyscallRequest::Prctl {
                            args: PrctlArg::SetVma {
                                opcode: ctx.sys_req_arg::<usize>(1) as u64,
                                addr: ctx.sys_req_arg(2),
                                len: ctx.sys_req_arg(3),
                                arg: ctx.sys_req_arg(4),
                            },
                        },
                        PrctlOption::CapBSetRead => SyscallRequest::Prctl {
                            args: PrctlArg::CapBSetRead(ctx.sys_req_arg(1)),
                        },
                        PrctlOption::SetNoNewPrivs
                            if ctx.sys_req_arg::<usize>(1) == 1
                                && (2..5).all(|index| ctx.sys_req_arg::<usize>(index) == 0) =>
                        {
                            SyscallRequest::Prctl {
                                args: PrctlArg::SetNoNewPrivs,
                            }
                        }
                        PrctlOption::GetNoNewPrivs
                            if (1..5).all(|index| ctx.sys_req_arg::<usize>(index) == 0) =>
                        {
                            SyscallRequest::Prctl {
                                args: PrctlArg::GetNoNewPrivs,
                            }
                        }
                        PrctlOption::SetKeepCaps
                            if (2..5).all(|index| ctx.sys_req_arg::<usize>(index) == 0) =>
                        {
                            let keep: usize = ctx.sys_req_arg(1);
                            if keep > 1 {
                                return Err(unsupported_einval(format_args!(
                                    "prctl(PR_SET_KEEPCAPS, {keep})"
                                )));
                            }
                            SyscallRequest::Prctl {
                                args: PrctlArg::SetKeepCaps(keep == 1),
                            }
                        }
                        PrctlOption::GetKeepCaps
                            if (1..5).all(|index| ctx.sys_req_arg::<usize>(index) == 0) =>
                        {
                            SyscallRequest::Prctl {
                                args: PrctlArg::GetKeepCaps,
                            }
                        }
                        _ => {
                            return Err(unsupported_einval(format_args!("prctl({op:?})")));
                        }
                    }
                } else {
                    return Err(unsupported_einval(format_args!("prctl(option = {op:#x})")));
                }
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::arch_prctl => {
                let code: u32 = ctx.sys_req_arg(0);
                let code = ArchPrctlCode::try_from(code)
                    .map_err(|_| unsupported_einval(format_args!("arch_prctl(code = {code})")))?;
                let arg = match code {
                    #[cfg(target_arch = "x86_64")]
                    ArchPrctlCode::SetFs => ArchPrctlArg::SetFs(ctx.sys_req_arg(1)),
                    #[cfg(target_arch = "x86_64")]
                    ArchPrctlCode::GetFs => ArchPrctlArg::GetFs(ctx.sys_req_ptr(1)),
                    ArchPrctlCode::CETStatus => ArchPrctlArg::CETStatus,
                    ArchPrctlCode::CETDisable => ArchPrctlArg::CETDisable,
                    ArchPrctlCode::CETLock => ArchPrctlArg::CETLock,
                };
                SyscallRequest::ArchPrctl { arg }
            }
            Sysno::gettid => SyscallRequest::Gettid,
            #[cfg(target_arch = "x86_64")]
            Sysno::set_thread_area => sys_req!(SetThreadArea { user_desc:* }),
            Sysno::set_tid_address => sys_req!(SetTidAddress { tidptr:* }),
            Sysno::openat => sys_req!(Openat { dirfd,pathname:*,flags,mode }),
            #[cfg(target_arch = "x86_64")]
            Sysno::open => {
                // open is equivalent to openat with dirfd AT_FDCWD
                SyscallRequest::Openat {
                    dirfd: AT_FDCWD,
                    pathname: ctx.sys_req_ptr(0),
                    flags: ctx.sys_req_arg(1),
                    mode: ctx.sys_req_arg(2),
                }
            }
            Sysno::mknodat => sys_req!(Mknodat { dirfd,pathname:*,mode_and_type,dev }),
            #[cfg(target_arch = "x86_64")]
            Sysno::mknod => SyscallRequest::Mknodat {
                dirfd: AT_FDCWD,
                pathname: ctx.sys_req_ptr(0),
                mode_and_type: ctx.sys_req_arg(1),
                dev: ctx.sys_req_arg(2),
            },
            Sysno::symlinkat => sys_req!(Symlinkat { target:*, newdirfd, linkpath:* }),
            Sysno::linkat => {
                sys_req!(Linkat { olddirfd, oldpath:*, newdirfd, newpath:*, flags })
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::symlink => {
                // symlink is symlinkat with newdirfd AT_FDCWD
                SyscallRequest::Symlinkat {
                    target: ctx.sys_req_ptr(0),
                    newdirfd: AT_FDCWD,
                    linkpath: ctx.sys_req_ptr(1),
                }
            }
            Sysno::renameat2 => {
                sys_req!(Renameat2 { olddirfd, oldpath:*, newdirfd, newpath:*, flags })
            }
            Sysno::renameat => SyscallRequest::Renameat2 {
                // `renameat` has no flags argument; it is `renameat2` with flags 0.
                olddirfd: ctx.sys_req_arg(0),
                oldpath: ctx.sys_req_ptr(1),
                newdirfd: ctx.sys_req_arg(2),
                newpath: ctx.sys_req_ptr(3),
                flags: 0,
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::rename => SyscallRequest::Renameat2 {
                // `rename` is `renameat2` with both dirfds AT_FDCWD and flags 0.
                olddirfd: AT_FDCWD,
                oldpath: ctx.sys_req_ptr(0),
                newdirfd: AT_FDCWD,
                newpath: ctx.sys_req_ptr(1),
                flags: 0,
            },
            Sysno::unlinkat => sys_req!(Unlinkat { dirfd,pathname:*,flags }),
            #[cfg(target_arch = "x86_64")]
            Sysno::unlink => {
                // unlink is equivalent to unlinkat with dirfd AT_FDCWD and flags 0
                SyscallRequest::Unlinkat {
                    dirfd: AT_FDCWD,
                    pathname: ctx.sys_req_ptr(0),
                    flags: AtFlags::empty(),
                }
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::rmdir => {
                // rmdir is equivalent to unlinkat with dirfd AT_FDCWD and AT_REMOVEDIR
                SyscallRequest::Unlinkat {
                    dirfd: AT_FDCWD,
                    pathname: ctx.sys_req_ptr(0),
                    flags: AtFlags::AT_REMOVEDIR,
                }
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::creat => {
                // creat is equivalent to open with flags O_CREAT|O_WRONLY|O_TRUNC
                SyscallRequest::Openat {
                    dirfd: AT_FDCWD,
                    pathname: ctx.sys_req_ptr(0),
                    flags: litebox::fs::OFlags::CREAT
                        | litebox::fs::OFlags::WRONLY
                        | litebox::fs::OFlags::TRUNC,
                    mode: ctx.sys_req_arg(1),
                }
            }
            Sysno::ftruncate => sys_req!(Ftruncate { fd, length }),
            Sysno::fallocate => sys_req!(Fallocate {
                fd,
                mode,
                offset,
                len
            }),
            Sysno::fadvise64 => sys_req!(Fadvise64 {
                fd,
                offset,
                len,
                advice
            }),
            Sysno::memfd_create => sys_req!(MemfdCreate { name:*, flags }),
            #[cfg(target_arch = "x86_64")]
            Sysno::newfstatat => sys_req!(Newfstatat { dirfd,pathname:*,buf:*,flags }),
            #[cfg(target_arch = "aarch64")]
            Sysno::fstatat => sys_req!(Newfstatat { dirfd,pathname:*,buf:*,flags }),
            #[cfg(target_arch = "x86_64")]
            Sysno::eventfd => SyscallRequest::Eventfd2 {
                initval: ctx.sys_req_arg(0),
                flags: EfdFlags::empty(),
            },
            Sysno::eventfd2 => sys_req!(Eventfd2 { initval, flags }),
            #[cfg(target_arch = "x86_64")]
            Sysno::inotify_init => SyscallRequest::InotifyInit1 {
                flags: InotifyInitFlags::empty(),
            },
            Sysno::inotify_init1 => sys_req!(InotifyInit1 { flags }),
            Sysno::inotify_add_watch => sys_req!(InotifyAddWatch { fd, pathname:*, mask }),
            Sysno::inotify_rm_watch => sys_req!(InotifyRmWatch { fd, wd }),
            Sysno::getrandom => sys_req!(GetRandom { buf:*,count,flags }),
            Sysno::clone => {
                let args = CloneArgs {
                    // The upper 32 bits are clone3-specific. The low 8 bits are the exit signal.
                    flags: CloneFlags::from_bits_retain(ctx.syscall_arg(0) as u64 & 0xffffff00),
                    stack: ctx.sys_req_arg(1),
                    parent_tid: ctx.sys_req_arg(2),
                    // The order of the `child_tid` and `tls` arguments depends on
                    // CONFIG_CLONE_BACKWARDS (see kernel/fork.c): when set, the layout
                    // is (..., tls=arg3, child_tid=arg4); otherwise it is
                    // (..., child_tid=arg3, tls=arg4). arm64 selects CLONE_BACKWARDS
                    // (arch/arm64/Kconfig), whereas x86_64 does not (only X86_32 does,
                    // arch/x86/Kconfig), so the indices are swapped between the arches.
                    child_tid: ctx.sys_req_arg(if cfg!(target_arch = "x86_64") { 3 } else { 4 }),
                    tls: ctx.sys_req_arg(if cfg!(target_arch = "x86_64") { 4 } else { 3 }),
                    pidfd: ctx.sys_req_arg(2), // aliases parent_tid
                    exit_signal: ctx.syscall_arg(0) as u64 & 0xff,
                    stack_size: 0,
                    set_tid: 0,
                    set_tid_size: 0,
                    cgroup: 0,
                };
                SyscallRequest::Clone { args }
            }
            Sysno::clone3 => {
                debug_assert_eq!(
                    ctx.sys_req_arg::<usize>(1),
                    size_of::<CloneArgs>(),
                    "legacy clone3 struct"
                );
                SyscallRequest::Clone3 {
                    args: ctx.sys_req_ptr(0),
                }
            }
            Sysno::unshare => SyscallRequest::Unshare {
                flags: CloneFlags::from_bits_retain(ctx.sys_req_arg(0)),
            },
            Sysno::set_robust_list => {
                if ctx.sys_req_arg::<usize>(1) == size_of::<RobustListHead>() {
                    sys_req!(SetRobustList { head })
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::get_robust_list => {
                let pid = ctx.sys_req_arg(0);
                SyscallRequest::GetRobustList {
                    pid: if pid == 0 { None } else { Some(pid) },
                    head: ctx.sys_req_ptr(1),
                    len: ctx.sys_req_ptr(2),
                }
            }
            Sysno::sysinfo => sys_req!(Sysinfo { buf:* }),
            Sysno::getrusage => sys_req!(Getrusage { who, usage:* }),
            Sysno::capget => sys_req!(CapGet { header:*,data:* }),
            Sysno::capset => sys_req!(CapSet { header:*,data:* }),
            Sysno::getdents64 => sys_req!(GetDirent64 { fd,dirp:*,count }),
            Sysno::sched_getaffinity => {
                let pid = ctx.sys_req_arg(0);
                SyscallRequest::SchedGetAffinity {
                    pid: if pid == 0 { None } else { Some(pid) },
                    len: ctx.sys_req_arg(1),
                    mask: ctx.sys_req_ptr(2),
                }
            }
            Sysno::sched_yield => SyscallRequest::SchedYield,
            Sysno::sched_getparam => {
                let pid = ctx.sys_req_arg(0);
                SyscallRequest::SchedGetParam {
                    pid: if pid == 0 { None } else { Some(pid) },
                    param: ctx.sys_req_ptr(1),
                }
            }
            Sysno::sched_setparam => {
                let pid = ctx.sys_req_arg(0);
                SyscallRequest::SchedSetParam {
                    pid: if pid == 0 { None } else { Some(pid) },
                    param: ctx.sys_req_ptr(1),
                }
            }
            Sysno::sched_getscheduler => {
                let pid = ctx.sys_req_arg(0);
                SyscallRequest::SchedGetScheduler {
                    pid: if pid == 0 { None } else { Some(pid) },
                }
            }
            Sysno::sched_setscheduler => {
                let pid = ctx.sys_req_arg(0);
                SyscallRequest::SchedSetScheduler {
                    pid: if pid == 0 { None } else { Some(pid) },
                    policy: ctx.sys_req_arg(1),
                    param: ctx.sys_req_ptr(2),
                }
            }
            Sysno::futex => Self::parse_futex(ctx, TimeParam::timespec_old, unsupported_einval)?,
            Sysno::execve => sys_req!(Execve { pathname:*, argv:*, envp:* }),
            Sysno::umask => sys_req!(Umask { mask }),
            #[cfg(target_arch = "x86_64")]
            Sysno::alarm => sys_req!(Alarm { seconds }),
            #[cfg(target_arch = "x86_64")]
            Sysno::pause => SyscallRequest::Pause,
            Sysno::setitimer => sys_req!(SetITimer { which:?, new_value:*, old_value:* }),
            Sysno::getitimer => sys_req!(GetITimer { which:?, curr_value:* }),
            Sysno::statx => sys_req!(Statx {
                dirfd,
                pathname:*,
                flags,
                mask,
                statxbuf:*,
            }),
            Sysno::statfs => sys_req!(Statfs { pathname:*, buf:* }),
            Sysno::fstatfs => sys_req!(Fstatfs { fd, buf:* }),
            Sysno::ptrace => sys_req!(Ptrace {
                request,
                pid,
                addr,
                data
            }),
            // Noisy unsupported syscalls.
            Sysno::io_uring_setup | Sysno::rseq => {
                return Err(errno::Errno::ENOSYS);
            }
            sysno => {
                log_unsupported(format_args!("unsupported syscall {sysno:?}"));
                return Err(errno::Errno::ENOSYS);
            }
        };
        Ok(dispatcher)
    }

    fn parse_futex<T: FromBytes + IntoBytes>(
        ctx: &PtRegs,
        time_param: impl FnOnce(Option<UserPtrMut<T>>) -> TimeParam,
        unsupported_einval: impl Fn(core::fmt::Arguments<'_>) -> errno::Errno,
    ) -> Result<SyscallRequest, errno::Errno> {
        let addr = ctx.sys_req_ptr(0);
        let op_and_flags: i32 = ctx.sys_req_arg(1);
        let op = op_and_flags & FutexFlags::FUTEX_CMD_MASK.bits();
        let flags = op_and_flags & !FutexFlags::FUTEX_CMD_MASK.bits();
        let cmd = FutexOperation::try_from(op)
            .map_err(|_| unsupported_einval(format_args!("futex(op = {op})")))?;
        let flags = FutexFlags::from_bits(flags)
            .ok_or_else(|| unsupported_einval(format_args!("futex(flags = {flags})")))?;
        let val = ctx.sys_req_arg(2);
        let timeout = time_param(ctx.sys_req_ptr(3));
        let args = match cmd {
            FutexOperation::Wait => FutexArgs::Wait {
                addr,
                flags,
                val,
                timeout,
            },
            FutexOperation::WaitBitset => FutexArgs::WaitBitset {
                addr,
                flags,
                val,
                timeout,
                bitmask: ctx.sys_req_arg(5),
            },
            FutexOperation::Wake => FutexArgs::Wake {
                addr,
                flags,
                count: val,
            },
            FutexOperation::WakeBitset => FutexArgs::WakeBitset {
                addr,
                flags,
                count: val,
                bitmask: ctx.sys_req_arg(5),
            },
            FutexOperation::Requeue => {
                let num_to_requeue: u32 = ctx.sys_req_arg(3);
                // Linux's requeue quotas are `int`, despite occupying raw register-sized syscall
                // slots. Negative values are rejected before comparing or mutating either queue.
                if val > i32::MAX as u32 || num_to_requeue > i32::MAX as u32 {
                    return Err(errno::Errno::EINVAL);
                }
                FutexArgs::Requeue {
                    addr,
                    flags,
                    num_to_wake: val,
                    // ABI quirk: for `FUTEX_REQUEUE`, argument slot 3 (`WAIT`'s `timeout` pointer)
                    // is instead a plain integer, `num_to_requeue` -- not read via `time_param`/
                    // `sys_req_ptr` at all. See `man 2 futex`.
                    num_to_requeue,
                    addr2: ctx.sys_req_ptr(4),
                }
            }
            FutexOperation::CmpRequeue => {
                let num_to_requeue: u32 = ctx.sys_req_arg(3);
                if val > i32::MAX as u32 || num_to_requeue > i32::MAX as u32 {
                    return Err(errno::Errno::EINVAL);
                }
                FutexArgs::CmpRequeue {
                    addr,
                    flags,
                    num_to_wake: val,
                    // Same ABI quirk as `FUTEX_REQUEUE`: argument slot 3 is the plain integer
                    // `num_to_requeue`, not a `timeout` pointer. See `man 2 futex`.
                    num_to_requeue,
                    addr2: ctx.sys_req_ptr(4),
                    expected_value: ctx.sys_req_arg(5),
                }
            }
        };
        Ok(SyscallRequest::Futex { args })
    }
}

#[derive(Debug)]
pub enum TimeParam {
    None,
    Milliseconds(i32),
    TimeVal(UserPtrMut<TimeVal>),
    Timespec32(UserPtrMut<Timespec32>),
    Timespec64(UserPtrMut<Timespec>),
}

impl TimeParam {
    /// Return a `TimeParam` for a 64-bit timespec pointer.
    pub fn timespec64(tp: Option<UserPtrMut<Timespec>>) -> Self {
        tp.map_or(TimeParam::None, TimeParam::Timespec64)
    }

    /// Return a `TimeParam` for a 32-bit timespec pointer.
    pub fn timespec32(tp: Option<UserPtrMut<Timespec32>>) -> Self {
        tp.map_or(TimeParam::None, TimeParam::Timespec32)
    }

    /// Return a `TimeParam` for the old timespec pointer type, which is
    /// architecture dependent.
    pub fn timespec_old(tp: Option<UserPtrMut<Timespec>>) -> Self {
        Self::timespec64(tp)
    }

    /// Return a `TimeParam` for a timeval pointer.
    pub fn timeval(tp: Option<UserPtrMut<TimeVal>>) -> Self {
        tp.map_or(TimeParam::None, TimeParam::TimeVal)
    }

    /// Convert a generic timeout argument into a `Timeout` enum.
    pub fn read<P: litebox::platform::RawPointerProvider>(
        &self,
    ) -> Result<Option<Duration>, errno::Errno> {
        let v = match *self {
            TimeParam::None => return Ok(None),
            TimeParam::Milliseconds(s) => {
                // Negative values indicate an infinite timeout.
                let Ok(s) = s.try_into() else {
                    return Ok(None);
                };
                Duration::from_millis(s)
            }
            TimeParam::TimeVal(tv) => {
                let tv = tv.read_at_offset::<P>(0).ok_or(errno::Errno::EFAULT)?;
                Duration::try_from(tv).map_err(|_| errno::Errno::EINVAL)?
            }
            TimeParam::Timespec32(ts) => {
                let ts = ts.read_at_offset::<P>(0).ok_or(errno::Errno::EFAULT)?;
                Duration::try_from(ts).map_err(|_| errno::Errno::EINVAL)?
            }
            TimeParam::Timespec64(ts) => {
                let ts = ts.read_at_offset::<P>(0).ok_or(errno::Errno::EFAULT)?;
                Duration::try_from(ts).map_err(|_| errno::Errno::EINVAL)?
            }
        };
        Ok(Some(v))
    }

    /// Write a value to the time parameter.
    pub fn write<P: litebox::platform::RawPointerProvider>(
        &self,
        duration: Duration,
    ) -> Result<(), errno::Errno> {
        match *self {
            TimeParam::None | TimeParam::Milliseconds(_) => Ok(()),
            TimeParam::TimeVal(tv_ptr) => {
                tv_ptr
                    .write_at_offset::<P>(0, duration.into())
                    .ok_or(errno::Errno::EFAULT)?;
                Ok(())
            }
            TimeParam::Timespec32(ts_ptr) => {
                ts_ptr
                    .write_at_offset::<P>(0, duration.into())
                    .ok_or(errno::Errno::EFAULT)?;
                Ok(())
            }
            TimeParam::Timespec64(ts_ptr) => {
                ts_ptr
                    .write_at_offset::<P>(0, duration.into())
                    .ok_or(errno::Errno::EFAULT)?;
                Ok(())
            }
        }
    }
}

/// Context saved when entering the kernel
///
/// pt_regs from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/include/asm/ptrace.h#L59)
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct PtRegs {
    /*
     * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
     * unless syscall needs a complete, fully filled "struct pt_regs".
     */
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub rbp: usize,
    pub rbx: usize,
    /* These regs are callee-clobbered. Always saved on kernel entry. */
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rax: usize,
    pub rcx: usize,
    pub rdx: usize,
    pub rsi: usize,
    pub rdi: usize,

    /*
     * On syscall entry, this is syscall#. On CPU exception, this is error code.
     * On hw interrupt, it's IRQ number:
     */
    pub orig_rax: usize,
    /* Return frame for iretq */
    pub rip: usize,
    pub cs: usize,
    pub eflags: usize,
    pub rsp: usize,
    pub ss: usize,
    /* top of stack page */
}

/// Context saved when entering the kernel.
///
/// pt_regs from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/include/asm/ptrace.h#L178)
#[cfg(target_arch = "aarch64")]
#[repr(C, align(16))]
#[derive(Clone, Debug, Default)]
pub struct PtRegs {
    /// General-purpose registers x0-x30.
    pub regs: [usize; AARCH64_GENERAL_REGISTER_COUNT],
    /// Stack pointer.
    pub sp: usize,
    /// Program counter.
    pub pc: usize,
    /// Saved processor state (PSTATE/SPSR).
    pub pstate: u64,

    pub orig_x0: usize,

    // little endian
    pub syscallno: i32,
    pub unused2: u32,
    /* add remaining fields if needed */
}

/// AArch64 `ptrace(2)` request numbers, `NT_*` regset identifiers, and the
/// on-the-wire register layouts a `PTRACE_GETREGSET`/`PTRACE_SETREGSET`
/// exchanges for each supported `NT_*` type.
///
/// Only [`NT_PRSTATUS`](ptrace::NT_PRSTATUS) (general-purpose registers) and
/// [`NT_ARM_TLS`](ptrace::NT_ARM_TLS)
/// (`TPIDR_EL0`) are supported. Any other regset is a distinct, real Linux
/// type this shim does not populate (`NT_PRFPREG`/`NT_ARM_VFP` for FPSIMD
/// state, `NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH` for hardware debug state, and
/// so on) -- callers must reject those explicitly (`ENODEV`), never return
/// zeroed or partially-populated data for them.
#[cfg(target_arch = "aarch64")]
pub mod ptrace {
    use zerocopy::{FromBytes, Immutable, IntoBytes};

    /// Attach to a running process, stopping it and delivering the usual
    /// synthetic `SIGSTOP` a tracer waits for.
    pub const PTRACE_ATTACH: i64 = 16;
    /// Detach, resuming the tracee.
    pub const PTRACE_DETACH: i64 = 17;
    /// Resume a stopped tracee, optionally delivering `data` as a pending
    /// signal.
    pub const PTRACE_CONT: i64 = 7;
    /// Attach without an implicit stop; the tracee keeps running until an
    /// explicit `PTRACE_INTERRUPT` (unsupported here) or its own trap.
    pub const PTRACE_SEIZE: i64 = 0x4206;
    /// Read a register set (`data` is a `struct iovec *`).
    pub const PTRACE_GETREGSET: i64 = 0x4204;
    /// Write a register set (`data` is a `struct iovec *`).
    pub const PTRACE_SETREGSET: i64 = 0x4205;

    /// General-purpose registers: `x0`-`x30`, `sp`, `pc`, `pstate` -- Linux's
    /// `struct user_pt_regs`, 34 64-bit words / 272 bytes. Field-for-field
    /// identical to the leading portion of [`super::PtRegs`], so marshaling is
    /// a direct copy, never a reinterpretation of unrelated bytes.
    pub const NT_PRSTATUS: i32 = 1;
    /// A single `u64`: the thread pointer, `TPIDR_EL0`.
    pub const NT_ARM_TLS: i32 = 0x401;

    /// The `NT_PRSTATUS` wire layout: Linux's `struct user_pt_regs`.
    #[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    pub struct UserPtRegs {
        pub regs: [u64; super::AARCH64_GENERAL_REGISTER_COUNT],
        pub sp: u64,
        pub pc: u64,
        pub pstate: u64,
    }

    impl UserPtRegs {
        pub const SIZE: usize = core::mem::size_of::<Self>();
    }

    impl From<&super::PtRegs> for UserPtRegs {
        fn from(ctx: &super::PtRegs) -> Self {
            let mut regs = [0u64; super::AARCH64_GENERAL_REGISTER_COUNT];
            for (dst, src) in regs.iter_mut().zip(ctx.regs.iter()) {
                *dst = *src as u64;
            }
            Self {
                regs,
                sp: ctx.sp as u64,
                pc: ctx.pc as u64,
                pstate: ctx.pstate,
            }
        }
    }

    impl UserPtRegs {
        /// Applies this register set onto `ctx`, leaving every field `ctx`
        /// owns that is not part of `NT_PRSTATUS` (`orig_x0`, `syscallno`)
        /// untouched.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "this module is aarch64-only, where `u64` and `usize` have the same width"
        )]
        pub fn write_into(&self, ctx: &mut super::PtRegs) {
            for (dst, src) in ctx.regs.iter_mut().zip(self.regs.iter()) {
                *dst = *src as usize;
            }
            ctx.sp = self.sp as usize;
            ctx.pc = self.pc as usize;
            ctx.pstate = self.pstate;
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub mod arch {
    // User returns must not target the null-guard region.
    pub const USER_ADDR_MIN: usize = 0x0000_0000_0001_0000;
    // Exclusive upper bound; the final low-canonical page is reserved as a guard page.
    pub const USER_ADDR_END: usize = 0x0000_7fff_ffff_f000;
    pub const USER_CS: usize = 0x33;
    pub const USER_DS: usize = 0x2b;
    pub const EFLAGS_CF: usize = 1 << 0;
    pub const EFLAGS_FIXED: usize = 1 << 1;
    pub const EFLAGS_PF: usize = 1 << 2;
    pub const EFLAGS_AF: usize = 1 << 4;
    pub const EFLAGS_ZF: usize = 1 << 6;
    pub const EFLAGS_SF: usize = 1 << 7;
    pub const EFLAGS_IF: usize = 1 << 9;
    pub const EFLAGS_DF: usize = 1 << 10;
    pub const EFLAGS_OF: usize = 1 << 11;
    pub const EFLAGS_RF: usize = 1 << 16;
    pub const EFLAGS_ID: usize = 1 << 21;
    pub const SAFE_USER_EFLAGS: usize = EFLAGS_CF
        | EFLAGS_FIXED
        | EFLAGS_PF
        | EFLAGS_AF
        | EFLAGS_ZF
        | EFLAGS_SF
        | EFLAGS_IF
        | EFLAGS_DF
        | EFLAGS_OF
        | EFLAGS_RF
        | EFLAGS_ID;

    /// Returns whether `base` is a valid x86_64 Linux user FS-segment base.
    ///
    /// A user FS base is valid iff it is below the top of the user address
    /// space. Especially, if a given address is non-canonical, `wrfsbase`
    /// can result in a #GP fault. This check is based on Linux kernel's
    /// `do_arch_prctl_64`.
    #[must_use]
    pub fn is_valid_user_fs_base(base: usize) -> bool {
        base < USER_ADDR_END
    }
}

#[cfg(target_arch = "aarch64")]
pub mod arch {
    // User returns must not target the null-guard region.
    pub const USER_ADDR_MIN: usize = 0x0000_0000_0001_0000;
    // Exclusive upper bound; keep the final low-userspace page reserved as a guard page.
    pub const USER_ADDR_END: usize = 0x0000_ffff_ffff_f000;
    /// PSTATE condition flags (N, Z, C, V) — guest-controllable arithmetic state.
    pub const PSR_NZCV_MASK: u64 = 0b1111 << 28;
    /// Speculative Store Bypass Safe bit — a benign, user-settable mitigation bit.
    pub const PSR_SSBS_BIT: u64 = 1 << 12;
    /// Data Independent Timing bit — a benign, user-settable mitigation bit.
    pub const PSR_DIT_BIT: u64 = 1 << 24;
    /// PSTATE bits a guest may keep when returning to EL0.
    pub const SAFE_USER_PSTATE: u64 = PSR_NZCV_MASK | PSR_SSBS_BIT | PSR_DIT_BIT;
}

impl PtRegs {
    /// Returns whether `rip` and `rsp` are in the x86_64 Linux user address range.
    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn has_user_return_addresses(&self) -> bool {
        (arch::USER_ADDR_MIN..arch::USER_ADDR_END).contains(&self.rip)
            && (arch::USER_ADDR_MIN..arch::USER_ADDR_END).contains(&self.rsp)
    }

    /// Sanitizes CPU state and normalizes the context to the x86_64 Linux user ABI.
    ///
    /// Returns `false` if `rip` or `rsp` are outside the x86_64 Linux user address range.
    /// On success, privileged or unsafe RFLAGS bits are cleared, the fixed
    /// RFLAGS bit is set, interrupts are enabled, and the user CS/SS selectors
    /// are set to the x86_64 Linux ABI values.
    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn sanitize_for_user_return(&mut self) -> bool {
        if !self.has_user_return_addresses() {
            return false;
        }
        self.eflags = (self.eflags & arch::SAFE_USER_EFLAGS) | arch::EFLAGS_FIXED | arch::EFLAGS_IF;
        self.cs = arch::USER_CS;
        self.ss = arch::USER_DS;
        true
    }

    /// Returns whether `pc` and `sp` are in the aarch64 Linux user address range.
    #[cfg(target_arch = "aarch64")]
    #[must_use]
    pub fn has_user_return_addresses(&self) -> bool {
        (arch::USER_ADDR_MIN..arch::USER_ADDR_END).contains(&self.pc)
            && (arch::USER_ADDR_MIN..arch::USER_ADDR_END).contains(&self.sp)
    }

    /// Sanitizes CPU state and normalizes the context to the aarch64 Linux user ABI.
    ///
    /// Returns `false` if `pc` or `sp` are outside the aarch64 Linux user address
    /// range. On success, `pstate` is coerced to a clean AArch64 EL0t state: the
    /// guest keeps only the condition flags and benign mitigation bits. Every
    /// other bit is cleared, forcing EL0t, AArch64 execution state, unmasked
    /// exceptions, and no illegal-state or single-step.
    #[cfg(target_arch = "aarch64")]
    #[must_use]
    pub fn sanitize_for_user_return(&mut self) -> bool {
        if !self.has_user_return_addresses() {
            return false;
        }
        self.pstate &= arch::SAFE_USER_PSTATE;
        true
    }

    /// Get the `idx`th syscall argument.
    ///
    /// # Panics
    ///
    /// If `idx` is greater than 5, this function will panic.
    #[cfg(target_arch = "x86_64")]
    pub fn syscall_arg(&self, idx: usize) -> usize {
        match idx {
            0 => self.rdi,
            1 => self.rsi,
            2 => self.rdx,
            3 => self.r10,
            4 => self.r8,
            5 => self.r9,
            _ => panic!("Invalid syscall argument index: {idx}"),
        }
    }

    /// Get the `idx`th syscall argument.
    ///
    /// # Panics
    ///
    /// If `idx` is greater than 5, this function will panic.
    #[cfg(target_arch = "aarch64")]
    pub fn syscall_arg(&self, idx: usize) -> usize {
        if idx < 6 {
            self.regs[idx]
        } else {
            panic!("Invalid syscall argument index: {idx}")
        }
    }

    // (Private-only, only to be used via `SyscallRequest::try_from_raw`), get the `idx`th syscall
    // argument, reinterpret-truncated to the necessary type.
    fn sys_req_arg<T: ReinterpretTruncatedFromUsize>(&self, idx: usize) -> T {
        T::reinterpret_truncated_from_usize(self.syscall_arg(idx))
    }
    // (Private-only, only to be used via `SyscallRequest::try_from_raw`), get the `idx`th syscall
    // argument, reinterpreted to the necessary pointer type.
    fn sys_req_ptr<T: Clone, P: ReinterpretUsizeAsPtr<T>>(&self, idx: usize) -> P {
        P::reinterpret_usize_as_ptr(self.syscall_arg(idx))
    }

    /// Get the instruction pointer (IP)
    #[cfg(target_arch = "x86_64")]
    pub fn get_ip(&self) -> usize {
        self.rip
    }

    /// Get the instruction pointer (IP)
    #[cfg(target_arch = "aarch64")]
    pub fn get_ip(&self) -> usize {
        self.pc
    }
}

// This trait is to be used _only_ be `PtRegs`, and exists to simplify
// `SyscallRequest::try_from_raw`. It reinterprets `usize` values (via truncation and
// sign-reinterpretation and such) to a variety of values useful for `SyscallRequest`.
//
// IMPORTANT: this always silently performs truncation. This is why it should not be used for
// anything other than for `SyscallReuqest::try_from_raw`.
#[diagnostic::on_unimplemented(
    message = "If you are trying to use a pointer for the sys_req macro, you might want to `:*` it. Alternatively, you might be looking for `sys_req_ptr` rather than `sys_req_arg`."
)]
pub trait ReinterpretTruncatedFromUsize: Sized {
    fn reinterpret_truncated_from_usize(v: usize) -> Self;
}
impl ReinterpretTruncatedFromUsize for u64 {
    fn reinterpret_truncated_from_usize(v: usize) -> Self {
        v as u64
    }
}
impl ReinterpretTruncatedFromUsize for i64 {
    fn reinterpret_truncated_from_usize(v: usize) -> Self {
        v.reinterpret_as_signed() as i64
    }
}
impl ReinterpretTruncatedFromUsize for isize {
    fn reinterpret_truncated_from_usize(v: usize) -> Self {
        v.reinterpret_as_signed()
    }
}
macro_rules! reinterpret_truncated_from_usize_for {
    (
        unsigned [$($uty:ty),* $(,)?],
        signed [$($sty:ty),* $(,)?],
        flags [$($fty:ty),* $(,)?],
    ) => {
        $(
            impl ReinterpretTruncatedFromUsize for $uty {
                fn reinterpret_truncated_from_usize(v: usize) -> Self {
                    v.trunc()
                }
            }
        )*
        $(
            impl ReinterpretTruncatedFromUsize for $sty {
                fn reinterpret_truncated_from_usize(v: usize) -> Self {
                    v.reinterpret_as_signed().trunc()
                }
            }
        )*
        $(
            impl ReinterpretTruncatedFromUsize for $fty {
                fn reinterpret_truncated_from_usize(v: usize) -> Self {
                    <$fty>::from_bits_truncate(
                        <_ as ReinterpretTruncatedFromUsize>::reinterpret_truncated_from_usize(v),
                    )
                }
            }
        )*
    };
}
reinterpret_truncated_from_usize_for! {
    unsigned [usize, u8, u16, u32],
    signed [i8, i16, i32],
    flags [
        ProtFlags,
        MapFlags,
        MRemapFlags,
        AccessFlags,
        litebox::fs::Mode,
        litebox::fs::OFlags,
        AtFlags,
        SockFlags,
        SendFlags,
        ReceiveFlags,
        EpollCreateFlags,
        EfdFlags,
        RngFlags,
        TimerFlags,
        StatxMask,
        InotifyInitFlags,
        InotifyMask,
    ],
}

// See similar usage constraints as `ReinterpretTruncatedFromUsize`. It is somewhat unfortunate that
// we cannot just merge this nicely with the `ReinterpretTruncatedFromUsize` trait due to some
// details of Rust's trait restrictions, but thankfully we only need two traits---one for the base
// types, and one for the platform-generic ones.
//
// Note that the `T` here is fully unused, it exists only to get past a
// non-conflicting-implementations constraint that exists in Rust; it helps us make the two
// implementations below disjoint.
//
// Also, note how it is only implemented on `RawConstPointer` but will also work with
// `RawMutPointer` because `RawMutPointer` declares `RawConstPointer` as a super-trait.
#[diagnostic::on_unimplemented(
    message = "If you are trying to use a non-pointer for the sys_req macro, you might want remove the `:*` for it. Alternatively, you might be looking for `sys_req_arg` rather than `sys_req_ptr`."
)]
pub trait ReinterpretUsizeAsPtr<T>: Sized {
    fn reinterpret_usize_as_ptr(v: usize) -> Self;
}
impl<T> ReinterpretUsizeAsPtr<core::marker::PhantomData<((), T)>> for UserPtr<T> {
    fn reinterpret_usize_as_ptr(v: usize) -> Self {
        UserPtr::from_usize(v)
    }
}
impl<T> ReinterpretUsizeAsPtr<core::marker::PhantomData<((), T)>> for UserPtrMut<T> {
    fn reinterpret_usize_as_ptr(v: usize) -> Self {
        UserPtrMut::from_usize(v)
    }
}
impl<T> ReinterpretUsizeAsPtr<core::marker::PhantomData<(bool, T)>> for Option<UserPtr<T>> {
    fn reinterpret_usize_as_ptr(v: usize) -> Self {
        if v == 0 {
            None
        } else {
            Some(UserPtr::from_usize(v))
        }
    }
}
impl<T> ReinterpretUsizeAsPtr<core::marker::PhantomData<(bool, T)>> for Option<UserPtrMut<T>> {
    fn reinterpret_usize_as_ptr(v: usize) -> Self {
        if v == 0 {
            None
        } else {
            Some(UserPtrMut::from_usize(v))
        }
    }
}

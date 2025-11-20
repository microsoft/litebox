//! Common Linux-y items suitable for LiteBox

#![no_std]
#![allow(non_camel_case_types)]

use core::time::Duration;
use int_enum::IntEnum;
use litebox::{
    fs::OFlags,
    platform::{RawConstPointer, RawMutPointer},
    utils::{ReinterpretSignedExt as _, TruncateExt},
};
use syscalls::Sysno;

pub mod errno;
pub mod mm;

extern crate alloc;

// TODO(jayb): Should errno::Errno be publicly re-exported?

pub const STDIN_FILENO: i32 = 0;
pub const STDOUT_FILENO: i32 = 1;
pub const STDERR_FILENO: i32 = 2;

// linux/futex.h
pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
pub const FUTEX_REQUEUE: i32 = 3;

// linux/time.h
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_REALTIME_COARSE: i32 = 5;
pub const CLOCK_MONOTONIC_COARSE: i32 = 6;

/// Special value `libc::AT_FDCWD` used to indicate openat should use
/// the current working directory.
pub const AT_FDCWD: i32 = -100;

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
            _ => unimplemented!(),
        }
    }
}

/// Linux's `stat` struct
#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Clone, Default, PartialEq, Debug)]
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

/// Linux's `stat` struct
#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Clone, Default, PartialEq, Debug)]
pub struct FileStat {
    pub st_dev: u32,
    pub st_ino: u32,
    pub st_nlink: u16,
    pub st_mode: u16,
    pub st_uid: u16,
    pub st_gid: u16,
    pub st_rdev: u32,
    pub st_size: usize,
    pub st_blksize: usize,
    pub st_blocks: u32,
    pub st_atime: u32,
    pub st_atime_nsec: u32,
    pub st_mtime: u32,
    pub st_mtime_nsec: u32,
    pub st_ctime: u32,
    pub st_ctime_nsec: u32,
    #[expect(clippy::pub_underscore_fields)]
    pub __unused: [u32; 2],
}

/// Linux's `stat64` struct
#[cfg(target_arch = "x86")]
#[repr(C, packed)]
#[derive(Clone)]
pub struct FileStat64 {
    pub st_dev: u64,
    #[expect(clippy::pub_underscore_fields)]
    pub __pad1: core::ffi::c_uint,
    #[expect(clippy::pub_underscore_fields)]
    pub __st_ino: u32,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    #[expect(clippy::pub_underscore_fields)]
    pub __pad2: core::ffi::c_uint,
    pub st_size: u64,
    pub st_blksize: usize,
    pub st_blocks: u64,
    pub st_atime: u32,
    pub st_atime_nsec: u32,
    pub st_mtime: u32,
    pub st_mtime_nsec: u32,
    pub st_ctime: u32,
    pub st_ctime_nsec: u32,
    pub st_ino: u64,
}

#[cfg(target_arch = "x86")]
impl From<FileStat> for FileStat64 {
    fn from(stat: FileStat) -> Self {
        FileStat64 {
            st_dev: u64::from(stat.st_dev),
            __pad1: 0,
            __st_ino: stat.st_ino,
            st_mode: u32::from(stat.st_mode),
            st_nlink: u32::from(stat.st_nlink),
            st_uid: u32::from(stat.st_uid),
            st_gid: u32::from(stat.st_gid),
            st_rdev: u64::from(stat.st_rdev),
            __pad2: 0,
            st_size: stat.st_size as u64,
            st_blksize: stat.st_blksize,
            st_blocks: u64::from(stat.st_blocks),
            st_atime: stat.st_atime,
            st_atime_nsec: stat.st_atime_nsec,
            st_mtime: stat.st_mtime,
            st_mtime_nsec: stat.st_mtime_nsec,
            st_ctime: stat.st_ctime,
            st_ctime_nsec: stat.st_ctime_nsec,
            st_ino: u64::from(stat.st_ino),
        }
    }
}

/// Linux's `iovec` struct for `writev`
#[repr(C)]
pub struct IoWriteVec<P: RawConstPointer<u8>> {
    pub iov_base: P,
    pub iov_len: usize,
}

/// Linux's `iovec` struct for `readv`
#[repr(C)]
pub struct IoReadVec<P: RawMutPointer<u8>> {
    pub iov_base: P,
    pub iov_len: usize,
}

/// `iovec` struct for both read and write
pub type IoVec<P> = IoReadVec<P>;

impl<P: RawConstPointer<u8>> Clone for IoWriteVec<P> {
    fn clone(&self) -> Self {
        Self {
            iov_base: self.iov_base,
            iov_len: self.iov_len,
        }
    }
}

impl<P: RawMutPointer<u8>> Clone for IoReadVec<P> {
    fn clone(&self) -> Self {
        Self {
            iov_base: self.iov_base,
            iov_len: self.iov_len,
        }
    }
}

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
            ..
        } = value;
        Self {
            st_dev: <_>::try_from(dev).unwrap(),
            st_ino: <_>::try_from(ino).unwrap(),
            st_nlink: 1,
            st_mode: (mode.bits() | InodeType::from(file_type) as u32).truncate(),
            #[cfg_attr(target_arch = "x86", expect(clippy::useless_conversion))]
            st_uid: <_>::from(user),
            #[cfg_attr(target_arch = "x86", expect(clippy::useless_conversion))]
            st_gid: <_>::from(group),
            st_rdev: rdev
                .map(|r| <_>::try_from(r.get()).unwrap())
                .unwrap_or_default(),
            #[allow(clippy::cast_possible_wrap)]
            st_size: size,
            st_blksize: blksize,
            st_blocks: 0,
            ..Default::default()
        }
    }
}

/// Commands for use with `fcntl`.
#[derive(Debug)]
#[non_exhaustive]
pub enum FcntlArg<Platform: litebox::platform::RawPointerProvider> {
    /// Get the file descriptor flags
    GETFD,
    /// Set the file descriptor flags
    SETFD(FileDescriptorFlags),
    /// Get descriptor status flags
    GETFL,
    /// Set descriptor status flags
    SETFL(OFlags),
    /// Get a file lock
    GETLK(Platform::RawMutPointer<Flock>),
    /// Set a file lock
    SETLK(Platform::RawConstPointer<Flock>),
    /// Set a file lock and wait if blocked
    SETLKW(Platform::RawConstPointer<Flock>),
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
#[derive(Clone, Debug)]
pub struct Flock {
    /// Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK
    pub type_: i16,
    /// Where `start' is relative to
    pub whence: i16,
    /// Offset where the lock begins
    pub start: usize,
    /// Size of the locked area, 0 means until EOF
    pub len: isize,
    /// Process holding the lock
    pub pid: i32,
}

const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const F_GETLK: i32 = 5;
const F_SETLK: i32 = 6;
const F_SETLKW: i32 = 7;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FileDescriptorFlags: u32 {
        /// Close-on-exec flag
        const FD_CLOEXEC = 0x1;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

impl<Platform: litebox::platform::RawPointerProvider> FcntlArg<Platform> {
    pub fn try_from(cmd: i32, arg: usize) -> Option<Self> {
        Some(match cmd {
            F_GETFD => Self::GETFD,
            F_SETFD => Self::SETFD(FileDescriptorFlags::from_bits_truncate(arg.truncate())),
            F_GETFL => Self::GETFL,
            F_SETFL => Self::SETFL(OFlags::from_bits_truncate(arg.truncate())),
            F_GETLK => Self::GETLK(Platform::RawMutPointer::from_usize(arg)),
            F_SETLK => Self::SETLK(Platform::RawConstPointer::from_usize(arg)),
            F_SETLKW => Self::SETLKW(Platform::RawConstPointer::from_usize(arg)),
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
#[derive(Debug, Clone)]
pub struct Termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 19usize],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Winsize {
    pub row: u16,
    pub col: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const FIONBIO: u32 = 0x5421;
pub const FIOCLEX: u32 = 0x5451;
pub const TIOCGPTN: u32 = 0x80045430;

/// Commands for use with `ioctl`.
#[non_exhaustive]
#[derive(Debug)]
pub enum IoctlArg<Platform: litebox::platform::RawPointerProvider> {
    /// Get the current serial port settings.
    TCGETS(Platform::RawMutPointer<Termios>),
    /// Set the current serial port settings.
    TCSETS(Platform::RawConstPointer<Termios>),
    /// Get window size.
    TIOCGWINSZ(Platform::RawMutPointer<Winsize>),
    /// Obtain device unit number, which can be used to generate
    /// the filename of the pseudo-terminal slave device.
    TIOCGPTN(Platform::RawMutPointer<u32>),
    /// Enables or disables non-blocking mode
    FIONBIO(Platform::RawConstPointer<i32>),
    /// Set close on exec
    FIOCLEX,
    Raw {
        cmd: u32,
        arg: Platform::RawMutPointer<u8>,
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
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct SockFlags: core::ffi::c_uint {
        const NONBLOCK = OFlags::NONBLOCK.bits();
        const CLOEXEC = OFlags::CLOEXEC.bits();
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// struct for SO_LINGER option
#[repr(C)]
#[derive(Clone)]
pub struct Linger {
    pub onoff: i32,  /* Linger active		*/
    pub linger: i32, /* How long to linger for	*/
}

#[repr(u8)]
#[non_exhaustive]
#[derive(IntEnum, PartialEq, Debug)]
pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    RAW = 255,
}

#[repr(u32)]
#[derive(Debug, IntEnum)]
pub enum IpOption {
    TOS = 1,
}

#[repr(u32)]
#[derive(Debug, IntEnum)]
pub enum SocketOption {
    REUSEADDR = 2,
    TYPE = 3,
    BROADCAST = 6,
    SNDBUF = 7,
    RCVBUF = 8,
    KEEPALIVE = 9,
    /// This option controls the action taken when unsent messages queue on
    /// a socket and close() is performed. If SO_LINGER is set, the system
    /// shall block the process during close() until it can transmit the data
    /// or until the time expires.
    LINGER = 13,
    PEERCRED = 17,
    RCVTIMEO = 20,
    SNDTIMEO = 21,
}

#[repr(u32)]
#[derive(Debug, IntEnum)]
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

#[derive(Debug)]
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

// Following libc's definition of time_t and suseconds_t.
// They are not same as isize on all architectures, e.g.,
// `suseconds_t` is i64 on riscv32:
// https://github.com/rust-lang/libc/blob/151c3a971e423c76e7acb54aa2d21a6e2706c4e6/src/unix/linux_like/linux/gnu/b32/mod.rs#L22
cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "x86"))] {
        pub type time_t = i32;
        pub type suseconds_t = u32;
    } else if #[cfg(all(target_arch = "x86_64"))] {
        pub type time_t = i64;
        pub type suseconds_t = u64;
    } else {
        compile_error!("Unsupported architecture");
    }
}

/// timespec from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/time_types.h#L7)
#[derive(Debug, Clone, Copy, PartialOrd, PartialEq, Eq)]
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
        let nsec: usize = value.tv_nsec.truncate();
        if nsec >= 1_000_000_000 {
            return Err(errno::Errno::EINVAL);
        }
        Ok(Duration::new(
            u64::try_from(value.tv_sec).map_err(|_| errno::Errno::EINVAL)?,
            nsec.truncate(),
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
#[derive(Debug, Clone, Copy)]
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
            tv_sec: value.as_secs().reinterpret_as_signed().truncate(),
            tv_nsec: value.subsec_nanos(),
        }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct TimeVal {
    tv_sec: time_t,
    tv_usec: suseconds_t,
}
#[repr(C)]
#[derive(Clone)]
pub struct ItimerVal {
    /// Timer interval
    interval: TimeVal,
    /// Current value
    value: TimeVal,
}

impl TryFrom<TimeVal> for Duration {
    type Error = errno::Errno;

    fn try_from(value: TimeVal) -> Result<Self, Self::Error> {
        let usec: u32 = value.tv_usec.truncate();
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
            tv_sec: value.as_secs().reinterpret_as_signed().truncate(),
            #[cfg_attr(target_pointer_width = "32", expect(clippy::useless_conversion))]
            tv_usec: value.subsec_micros().into(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(i32)]
#[derive(Debug, IntEnum, PartialEq)]
/// Signal numbers used in Linux.
pub enum Signal {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    // SIGIOT = 6, // Alias for SIGABRT
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    SIGIO = 29,
    // SIGPOLL = 29, // Alias for SIGIO
    SIGPWR = 30,
    SIGSYS = 31,
}

impl Signal {
    pub const SIGIOT: Signal = Signal::SIGABRT;
    pub const SIGPOLL: Signal = Signal::SIGIO;
    pub const SIGUNUSED: Signal = Signal::SIGSYS;
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct SigSet(u64);

impl SigSet {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn add(&mut self, signum: Signal) {
        self.0 |= 1 << (signum as u64 - 1);
    }

    pub fn remove(&mut self, signum: Signal) {
        self.0 &= !(1 << (signum as u64 - 1));
    }

    pub fn contains(&self, signum: Signal) -> bool {
        (self.0 & (1 << (signum as u64 - 1))) != 0
    }
}

bitflags::bitflags! {
    #[derive(Clone)]
    pub struct SaFlags: u32 {
        const NOCLDSTOP = 1;
        const NOCLDWAIT = 2;
        const SIGINFO = 4;
        const ONSTACK   = 0x08000000;
        const RESTART   = 0x10000000;
        const NODEFER   = 0x40000000;
        const RESETHAND = 0x80000000;
    }
}

/// Linux's `sigaction` struct used by the `rt_sigaction` syscall.
#[repr(C)]
#[derive(Clone)]
pub struct SigAction {
    pub sigaction: usize,
    pub flags: SaFlags,
    pub restorer: Option<extern "C" fn()>,
    pub mask: SigSet,
}

#[repr(i32)]
#[derive(Debug, IntEnum)]
pub enum SigmaskHow {
    SIG_BLOCK = 0,
    SIG_UNBLOCK = 1,
    SIG_SETMASK = 2,
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
pub enum ArchPrctlArg<Platform: litebox::platform::RawPointerProvider> {
    #[cfg(target_arch = "x86_64")]
    SetFs(usize),
    #[cfg(target_arch = "x86_64")]
    GetFs(Platform::RawMutPointer<usize>),

    CETStatus,
    CETDisable,
    CETLock,

    #[doc(hidden)]
    #[allow(non_camel_case_types)]
    __Phantom(core::marker::PhantomData<Platform>),
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

/// Reads the current FS segment selector
#[cfg(target_arch = "x86")]
pub fn rdfss() -> u16 {
    let mut fs_selector: u16;
    unsafe {
        core::arch::asm!(
            "mov {0:x}, fs",
            out(reg) fs_selector,
            options(nostack, nomem, preserves_flags)
        );
    }
    fs_selector
}

/// Writes the FS segment selector
///
/// ## Safety
///
/// If a wrong value is written to the FS segment selector, it may lead to
/// undefined behavior or crashes.
#[cfg(target_arch = "x86")]
pub unsafe fn wrfss(fs_selector: u16) {
    unsafe {
        core::arch::asm!(
            "mov fs, {0:x}",
            in(reg) fs_selector,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Linux's `user_desc` struct used by the `set_thread_area` syscall.
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct UserDesc {
    pub entry_number: u32,
    pub base_addr: u32,
    pub limit: u32,
    pub flags: UserDescFlags,
}

bitfield::bitfield! {
    /// Flags for the `user_desc` struct.
    #[derive(Clone, Copy)]
    pub struct UserDescFlags(u32);
    impl Debug;
    /// 1 if the segment is 32-bit
    pub seg_32bit, set_seg_32bit: 0;
    /// Contents of the segment
    pub contents, set_contents: 1, 2;
    /// Read-exec only
    pub read_exec_only, set_read_exec_only: 3;
    /// Limit in pages
    pub limit_in_pages, set_limit_in_pages: 4;
    /// Segment not present
    pub seg_not_present, set_seg_not_present: 5;
    /// Usable by userland
    pub useable, set_useable: 6;
    /// 1 if the segment is 64-bit (x86_64 only)
    pub lm, set_lm: 7;
}

bitflags::bitflags! {
    /// Flags for the clone3 system call as defined in `/usr/include/linux/sched.h`.
    #[derive(Clone, Copy, Debug)]
    pub struct CloneFlags: u64 {
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
#[derive(Clone, Debug)]
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
#[derive(Clone)]
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
#[derive(Clone, Debug)]
pub struct Rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}

/// Used by prlimit64 syscall
#[repr(C)]
#[derive(Clone)]
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
            rlim.rlim_cur.truncate()
        },
        rlim_max: if rlim.rlim_max >= rlim_t::MAX as u64 {
            rlim_t::MAX
        } else {
            rlim.rlim_max.truncate()
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

#[repr(C)]
pub struct RobustList<Platform: litebox::platform::RawPointerProvider> {
    pub next: Platform::RawConstPointer<RobustList<Platform>>,
}

impl<Platform: litebox::platform::RawPointerProvider> Clone for RobustList<Platform> {
    fn clone(&self) -> Self {
        Self { next: self.next }
    }
}

#[repr(C)]
pub struct RobustListHead<Platform: litebox::platform::RawPointerProvider> {
    /// The head of the list. Points back to itself if empty.
    pub list: RobustList<Platform>,
    /// This relative offset is set by user-space, it gives the kernel
    /// the relative position of the futex field to examine. This way
    /// we keep userspace flexible, to freely shape its data-structure,
    /// without hardcoding any particular offset into the kernel.
    pub futex_offset: usize,
    /// The death of the thread may race with userspace setting
    /// up a lock's links. So to handle this race, userspace first
    /// sets this field to the address of the to-be-taken lock,
    /// then does the lock acquire, and then adds itself to the
    /// list, and then clears this field. Hence the kernel will
    /// always have full knowledge of all locks that the thread
    /// _might_ have taken. We check the owner TID in any case,
    /// so only truly owned locks will be handled.
    pub list_op_pending: Platform::RawConstPointer<RobustList<Platform>>,
}

impl<Platform: litebox::platform::RawPointerProvider> Clone for RobustListHead<Platform> {
    fn clone(&self) -> Self {
        Self {
            list: self.list.clone(),
            futex_offset: self.futex_offset,
            list_op_pending: self.list_op_pending,
        }
    }
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

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, Debug, Default)]
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
    /// Total high memory size
    pub totalhigh: usize,
    /// Available high memory size
    pub freehigh: usize,
    /// Memory unit size in bytes
    pub mem_unit: u32,
    /// Padding: libc5 uses this..
    #[allow(clippy::pub_underscore_fields)]
    pub _f: [u8; 20 - 2 * core::mem::size_of::<usize>() - core::mem::size_of::<u32>()],
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
#[derive(Clone, Debug)]
pub struct CapHeader {
    pub version: u32,
    pub pid: u32,
}

/// Data structure used for the `capget` and `capset` syscalls.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CapData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[repr(C)]
#[derive(Clone)]
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
#[derive(Debug, IntEnum)]
pub enum ClockId {
    RealTime = 0,
    Monotonic = 1,
    MonotonicCoarse = 6,
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
    WaitBitset = 9,
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
pub enum FutexArgs<Platform: litebox::platform::RawPointerProvider> {
    Wait {
        addr: Platform::RawMutPointer<u32>,
        flags: FutexFlags,
        val: u32,
        /// Note: for FUTEX_WAIT, timeout is interpreted as a relative
        /// value. This differs from other futex operations, where
        /// timeout is interpreted as an absolute value.
        timeout: TimeParam<Platform>,
    },
    WaitBitset {
        addr: Platform::RawMutPointer<u32>,
        flags: FutexFlags,
        val: u32,
        timeout: TimeParam<Platform>,
        bitmask: u32,
    },
    Wake {
        addr: Platform::RawMutPointer<u32>,
        flags: FutexFlags,
        count: u32,
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
}

#[non_exhaustive]
#[derive(Debug)]
pub enum PrctlArg<Platform: litebox::platform::RawPointerProvider> {
    SetName(Platform::RawConstPointer<u8>),
    GetName(Platform::RawMutPointer<u8>),
    CapBSetRead(usize),
}

#[repr(u32)]
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

bitflags::bitflags! {
    /// Flags for the `receive` function.
    #[derive(Clone, Copy, Debug)]
    pub struct ReceiveFlags: u32 {
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
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// Flags for the `send` function.
    #[derive(Clone, Copy, Debug)]
    pub struct SendFlags: u32 {
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

/// Packaged sigset with its size, used by `pselect` syscall
#[derive(Clone, Copy)]
pub struct SigSetPack {
    pub sigset: SigSet,
    pub size: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct UserMsgHdr<Platform: litebox::platform::RawPointerProvider> {
    /// ptr to socket address structure
    pub msg_name: Platform::RawConstPointer<u8>,
    /// size of socket address structure
    pub msg_namelen: u32,
    /// ptr to an array of `iovec` structures
    pub msg_iov: Platform::RawConstPointer<IoVec<Platform::RawMutPointer<u8>>>,
    /// number of elements in msg_iov
    pub msg_iovlen: usize,
    /// ptr to ancillary data
    pub msg_control: Platform::RawConstPointer<u8>,
    /// number of bytes of ancillary data
    pub msg_controllen: usize,
    /// flags on received message
    pub msg_flags: SendFlags,
}

impl<Platform: litebox::platform::RawPointerProvider> Clone for UserMsgHdr<Platform> {
    fn clone(&self) -> Self {
        Self {
            msg_name: self.msg_name,
            msg_namelen: self.msg_namelen,
            msg_iov: self.msg_iov,
            msg_iovlen: self.msg_iovlen,
            msg_control: self.msg_control,
            msg_controllen: self.msg_controllen,
            msg_flags: self.msg_flags,
        }
    }
}

/// Request to syscall handler
#[non_exhaustive]
#[derive(Debug)]
pub enum SyscallRequest<Platform: litebox::platform::RawPointerProvider> {
    Exit {
        status: i32,
    },
    ExitGroup {
        status: i32,
    },
    Read {
        fd: i32,
        buf: Platform::RawMutPointer<u8>,
        count: usize,
    },
    Write {
        fd: i32,
        buf: Platform::RawConstPointer<u8>,
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
        pathname: Platform::RawConstPointer<i8>,
        buf: Platform::RawMutPointer<FileStat>,
    },
    Fstat {
        fd: i32,
        buf: Platform::RawMutPointer<FileStat>,
    },
    Lstat {
        pathname: Platform::RawConstPointer<i8>,
        buf: Platform::RawMutPointer<FileStat>,
    },
    Mkdir {
        pathname: Platform::RawConstPointer<i8>,
        mode: u32,
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
        addr: Platform::RawMutPointer<u8>,
        length: usize,
        prot: ProtFlags,
    },
    Munmap {
        addr: Platform::RawMutPointer<u8>,
        length: usize,
    },
    Mremap {
        old_addr: Platform::RawMutPointer<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    },
    Brk {
        addr: Platform::RawMutPointer<u8>,
    },
    RtSigprocmask {
        how: SigmaskHow,
        set: Option<Platform::RawConstPointer<SigSet>>,
        oldset: Option<Platform::RawMutPointer<SigSet>>,
        sigsetsize: usize,
    },
    RtSigaction {
        signum: Signal,
        act: Option<Platform::RawConstPointer<SigAction>>,
        oldact: Option<Platform::RawMutPointer<SigAction>>,
        sigsetsize: usize,
    },
    RtSigreturn,
    Ioctl {
        fd: i32,
        arg: IoctlArg<Platform>,
    },
    Pread64 {
        fd: i32,
        buf: Platform::RawMutPointer<u8>,
        count: usize,
        offset: i64,
    },
    Pwrite64 {
        fd: i32,
        buf: Platform::RawConstPointer<u8>,
        count: usize,
        offset: i64,
    },
    Readv {
        fd: i32,
        iovec: Platform::RawConstPointer<IoReadVec<Platform::RawMutPointer<u8>>>,
        iovcnt: usize,
    },
    Writev {
        fd: i32,
        iovec: Platform::RawConstPointer<IoWriteVec<Platform::RawConstPointer<u8>>>,
        iovcnt: usize,
    },
    Access {
        pathname: Platform::RawConstPointer<i8>,
        mode: AccessFlags,
    },
    Madvise {
        addr: Platform::RawMutPointer<u8>,
        length: usize,
        behavior: MadviseBehavior,
    },
    Dup {
        oldfd: i32,
        newfd: Option<i32>,
        flags: Option<litebox::fs::OFlags>,
    },
    Socket {
        domain: AddressFamily,
        ty: SockType,
        flags: SockFlags,
        /// The `protocol` specifies a particular protocol to be used with the
        /// socket.  Normally only a single protocol exists to support a
        /// particular socket type within a given protocol family, in which case
        /// protocol can be specified as `None`.
        protocol: Option<Protocol>,
    },
    Connect {
        sockfd: i32,
        sockaddr: Platform::RawConstPointer<u8>,
        addrlen: usize,
    },
    Accept {
        sockfd: i32,
        addr: Option<Platform::RawMutPointer<u8>>,
        addrlen: Option<Platform::RawMutPointer<u32>>,
        flags: SockFlags,
    },
    Sendto {
        sockfd: i32,
        buf: Platform::RawConstPointer<u8>,
        len: usize,
        flags: SendFlags,
        addr: Option<Platform::RawConstPointer<u8>>,
        addrlen: u32,
    },
    Sendmsg {
        sockfd: i32,
        msg: Platform::RawConstPointer<UserMsgHdr<Platform>>,
        flags: SendFlags,
    },
    Recvfrom {
        sockfd: i32,
        buf: Platform::RawMutPointer<u8>,
        len: usize,
        flags: ReceiveFlags,
        addr: Option<Platform::RawMutPointer<u8>>,
        addrlen: Platform::RawMutPointer<u32>,
    },
    Bind {
        sockfd: i32,
        sockaddr: Platform::RawConstPointer<u8>,
        addrlen: usize,
    },
    Listen {
        sockfd: i32,
        backlog: u16,
    },
    Setsockopt {
        sockfd: i32,
        optname: SocketOptionName,
        optval: Platform::RawConstPointer<u8>,
        optlen: usize,
    },
    Getsockopt {
        sockfd: i32,
        optname: SocketOptionName,
        optval: Platform::RawMutPointer<u8>,
        optlen: Platform::RawMutPointer<u32>,
    },
    Getsockname {
        sockfd: i32,
        addr: Platform::RawMutPointer<u8>,
        addrlen: Platform::RawMutPointer<u32>,
    },
    Getpeername {
        sockfd: i32,
        addr: Platform::RawMutPointer<u8>,
        addrlen: Platform::RawMutPointer<u32>,
    },
    Uname {
        buf: Platform::RawMutPointer<Utsname>,
    },
    Fcntl {
        fd: i32,
        arg: FcntlArg<Platform>,
    },
    Getcwd {
        buf: Platform::RawMutPointer<u8>,
        size: usize,
    },
    EpollCtl {
        epfd: i32,
        op: EpollOp,
        fd: i32,
        event: Platform::RawConstPointer<EpollEvent>,
    },
    EpollPwait {
        epfd: i32,
        events: Platform::RawMutPointer<EpollEvent>,
        maxevents: u32,
        timeout: i32,
        sigmask: Option<Platform::RawConstPointer<SigSet>>,
        sigsetsize: usize,
    },
    EpollCreate {
        flags: EpollCreateFlags,
    },
    Ppoll {
        fds: Platform::RawMutPointer<Pollfd>,
        nfds: usize,
        timeout: TimeParam<Platform>,
        sigmask: Option<Platform::RawConstPointer<SigSet>>,
        sigsetsize: usize,
    },
    Pselect {
        nfds: u32,
        readfds: Option<Platform::RawMutPointer<usize>>,
        writefds: Option<Platform::RawMutPointer<usize>>,
        exceptfds: Option<Platform::RawMutPointer<usize>>,
        timeout: TimeParam<Platform>,
        sigsetpack: Option<Platform::RawConstPointer<SigSetPack>>,
    },
    ArchPrctl {
        arg: ArchPrctlArg<Platform>,
    },
    Readlink {
        pathname: Platform::RawConstPointer<i8>,
        buf: Platform::RawMutPointer<u8>,
        bufsiz: usize,
    },
    Readlinkat {
        dirfd: i32,
        pathname: Platform::RawConstPointer<i8>,
        buf: Platform::RawMutPointer<u8>,
        bufsiz: usize,
    },
    Openat {
        dirfd: i32,
        pathname: Platform::RawConstPointer<i8>,
        flags: litebox::fs::OFlags,
        mode: litebox::fs::Mode,
    },
    Ftruncate {
        fd: i32,
        length: usize,
    },
    Unlinkat {
        dirfd: i32,
        pathname: Platform::RawConstPointer<i8>,
        flags: AtFlags,
    },
    #[cfg(target_arch = "x86_64")]
    Newfstatat {
        dirfd: i32,
        pathname: Platform::RawConstPointer<i8>,
        buf: Platform::RawMutPointer<FileStat>,
        flags: AtFlags,
    },
    #[cfg(target_arch = "x86")]
    Fstatat64 {
        dirfd: i32,
        pathname: Platform::RawConstPointer<i8>,
        buf: Platform::RawMutPointer<FileStat64>,
        flags: AtFlags,
    },
    Eventfd2 {
        initval: u32,
        flags: EfdFlags,
    },
    Pipe2 {
        pipefd: Platform::RawMutPointer<u32>,
        flags: litebox::fs::OFlags,
    },
    Clone {
        args: CloneArgs,
    },
    Clone3 {
        args: Platform::RawConstPointer<CloneArgs>,
    },
    /// Manipulate thread-local storage information.
    /// Returns `ENOSYS` on 64-bit.
    SetThreadArea {
        user_desc: Platform::RawMutPointer<UserDesc>,
    },
    ClockGettime {
        clockid: i32,
        tp: TimeParam<Platform>,
    },
    ClockGetres {
        clockid: i32,
        res: TimeParam<Platform>,
    },
    ClockNanosleep {
        clockid: i32,
        flags: TimerFlags,
        request: TimeParam<Platform>,
        remain: TimeParam<Platform>,
    },
    Gettimeofday {
        tv: Option<Platform::RawMutPointer<TimeVal>>,
        tz: Option<Platform::RawMutPointer<TimeZone>>,
    },
    Time {
        tloc: Option<Platform::RawMutPointer<time_t>>,
    },
    Getrlimit {
        resource: RlimitResource,
        rlim: Platform::RawMutPointer<Rlimit>,
    },
    Setrlimit {
        resource: RlimitResource,
        rlim: Platform::RawConstPointer<Rlimit>,
    },
    Prlimit {
        pid: Option<i32>,
        /// The resource for which the limit is being queried.
        resource: RlimitResource,
        /// If the new_limit argument is not a None, then the rlimit structure to which it points
        /// is used to set new values for the soft and hard limits for resource.
        new_limit: Option<Platform::RawConstPointer<Rlimit64>>,
        /// If the old_limit argument is not a None, then a successful call to prlimit() places the
        /// previous soft and hard limits for resource in the rlimit structure pointed to by old_limit.
        old_limit: Option<Platform::RawMutPointer<Rlimit64>>,
    },
    SetTidAddress {
        tidptr: Platform::RawMutPointer<i32>,
    },
    Gettid,
    SetRobustList {
        head: usize,
    },
    GetRobustList {
        pid: Option<i32>,
        head: Platform::RawMutPointer<usize>,
        len: Platform::RawMutPointer<usize>,
    },
    GetRandom {
        buf: Platform::RawMutPointer<u8>,
        count: usize,
        flags: RngFlags,
    },
    Getpid,
    Getppid,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    Sysinfo {
        buf: Platform::RawMutPointer<Sysinfo>,
    },
    CapGet {
        header: Platform::RawMutPointer<CapHeader>,
        data: Option<Platform::RawMutPointer<CapData>>,
    },
    GetDirent64 {
        fd: i32,
        dirp: Platform::RawMutPointer<u8>,
        count: usize,
    },
    SchedGetAffinity {
        pid: Option<i32>,
        len: usize,
        mask: Platform::RawMutPointer<u8>,
    },
    SchedYield,
    Futex {
        args: FutexArgs<Platform>,
    },
    Execve {
        pathname: Platform::RawConstPointer<i8>,
        argv: Platform::RawConstPointer<Platform::RawConstPointer<i8>>,
        envp: Platform::RawConstPointer<Platform::RawConstPointer<i8>>,
    },
    Umask {
        mask: u32,
    },
    Prctl {
        args: PrctlArg<Platform>,
    },
    Alarm {
        seconds: u32,
    },
    ThreadKill {
        tgid: i32,
        tid: i32,
        sig: i32,
    },
    SetITimer {
        which: IntervalTimer,
        new_value: Platform::RawConstPointer<ItimerVal>,
        old_value: Option<Platform::RawMutPointer<ItimerVal>>,
    },
}

impl<Platform: litebox::platform::RawPointerProvider> SyscallRequest<Platform> {
    /// Take the raw syscall number and arguments, and provide a stronger-typed `SyscallRequest`.
    ///
    /// Returns `Ok` if a valid translation exists, if no such translation exists, returns the [`Errno`](errno::Errno) for it.
    ///
    /// # Panics
    ///
    /// Ideally, this function would not panic. However, since it is currently under development, it
    /// is allowed to panic upon receiving a syscall number (or arguments) that it does not know how
    /// to handle.
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
            (@[$id:ident] [ $f:ident : ts64 $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: TimeParam::timespec64(ctx.sys_req_ptr($n)), ]
                )
            };
            (@[$id:ident] [ $f:ident : tv $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: TimeParam::timeval(ctx.sys_req_ptr($n)), ]
                )
            };
            (@[$id:ident] [ $f:ident : ts $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: TimeParam::timespec_old(ctx.sys_req_ptr($n)), ]
                )
            };
            (@[$id:ident] [ $f:ident : millis $(,)? $($field:ident $(:$star:tt)?),* ] [ $n:literal $(,)? $($ns:literal),* ] [ $($tail:tt)* ]) => {
                sys_req!(
                    @[$id] [ $( $field $(:$star)? ),* ] [ $($ns),* ] [ $($tail)* $f: TimeParam::Milliseconds(ctx.sys_req_arg($n)), ]
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

        let sysno = Sysno::new(syscall_number).ok_or_else(|| {
            log_unsupported(format_args!("unknown syscall {syscall_number}"));
            errno::Errno::ENOSYS
        })?;
        let dispatcher = match sysno {
            Sysno::read => sys_req!(Read { fd, buf:*, count }),
            Sysno::write => sys_req!(Write { fd, buf:*, count }),
            Sysno::close => sys_req!(Close { fd }),
            Sysno::lseek => sys_req!(Lseek { fd, offset, whence }),
            Sysno::stat => sys_req!(Stat { pathname:*, buf:* }),
            Sysno::fstat => sys_req!(Fstat { fd, buf:* }),
            Sysno::lstat => sys_req!(Lstat { pathname:*, buf:* }),
            Sysno::mkdir => sys_req!(Mkdir { pathname:*, mode }),
            #[cfg(target_arch = "x86_64")]
            Sysno::mmap => sys_req!(Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            }),
            #[cfg(target_arch = "x86")]
            Sysno::mmap2 => sys_req!(Mmap {
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
            Sysno::rt_sigprocmask => {
                let how: i32 = ctx.sys_req_arg(0);
                if let Ok(how) = SigmaskHow::try_from(how) {
                    sys_req!(RtSigprocmask {
                        how: { how },
                        set:*,
                        oldset:*,
                        sigsetsize,
                    })
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::rt_sigaction => {
                let signum: i32 = ctx.sys_req_arg(0);
                if let Ok(signum) = Signal::try_from(signum) {
                    sys_req!(RtSigaction {
                        signum: { signum },
                        act:*,
                        oldact:*,
                        sigsetsize,
                    })
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::rt_sigreturn => SyscallRequest::RtSigreturn,
            Sysno::ioctl => SyscallRequest::Ioctl {
                fd: ctx.sys_req_arg(0),
                arg: {
                    let cmd = ctx.sys_req_arg(1);
                    match cmd {
                        TCGETS => IoctlArg::TCGETS(ctx.sys_req_ptr(2)),
                        TCSETS => IoctlArg::TCSETS(ctx.sys_req_ptr(2)),
                        TIOCGWINSZ => IoctlArg::TIOCGWINSZ(ctx.sys_req_ptr(2)),
                        TIOCGPTN => IoctlArg::TIOCGPTN(ctx.sys_req_ptr(2)),
                        FIONBIO => IoctlArg::FIONBIO(ctx.sys_req_ptr(2)),
                        FIOCLEX => IoctlArg::FIOCLEX,
                        _ => IoctlArg::Raw {
                            cmd,
                            arg: ctx.sys_req_ptr(2),
                        },
                    }
                },
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::pread64 => sys_req!(Pread64 {
                fd,
                buf:*,
                count,
                offset
            }),
            #[cfg(target_arch = "x86")]
            Sysno::pread64 => sys_req!(Pread64 {
                fd,
                buf:*,
                count,
                offset: { ctx.sys_req_arg::<i64>(3) | ((ctx.sys_req_arg::<i64>(4)) << 32) },
            }),
            #[cfg(target_arch = "x86_64")]
            Sysno::pwrite64 => sys_req!(Pwrite64 {
                fd,
                buf:*,
                count,
                offset
            }),
            #[cfg(target_arch = "x86")]
            Sysno::pwrite64 => sys_req!(Pwrite64 {
                fd,
                buf:*,
                count,
                offset: { ctx.sys_req_arg::<i64>(3) | ((ctx.sys_req_arg::<i64>(4)) << 32) },
            }),
            Sysno::readv => sys_req!(Readv { fd, iovec:*, iovcnt }),
            Sysno::writev => sys_req!(Writev { fd, iovec:*, iovcnt }),
            Sysno::access => sys_req!(Access { pathname:*, mode }),
            Sysno::pipe => sys_req!(Pipe2 { pipefd:*, flags: { litebox::fs::OFlags::empty() } }),
            Sysno::pipe2 => sys_req!(Pipe2 { pipefd:* ,flags }),
            Sysno::madvise => {
                let behavior: i32 = ctx.sys_req_arg(2);
                if let Ok(behavior) = MadviseBehavior::try_from(behavior) {
                    sys_req!(Madvise { addr:*, length, behavior: { behavior } })
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::dup => SyscallRequest::Dup {
                oldfd: ctx.sys_req_arg(0),
                newfd: None,
                flags: None,
            },
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
            Sysno::socket => {
                let domain: u32 = ctx.sys_req_arg(0);
                let type_and_flags: u32 = ctx.sys_req_arg(1);
                let ty = type_and_flags & 0x0f;
                let flags = type_and_flags & !0x0f;
                SyscallRequest::Socket {
                    domain: AddressFamily::try_from(domain).map_err(|_| {
                        unsupported_einval(format_args!("socket(domain = {domain})"))
                    })?,
                    ty: SockType::try_from(ty)
                        .map_err(|_| unsupported_einval(format_args!("socket(type = {ty})")))?,
                    flags: SockFlags::from_bits_truncate(flags),
                    protocol: if ctx.sys_req_arg::<u8>(2) == 0 {
                        None
                    } else {
                        let protocol: u8 = ctx.sys_req_arg(2);
                        Some(Protocol::try_from(protocol).map_err(|_| {
                            unsupported_einval(format_args!("socket(protocol = {protocol})"))
                        })?)
                    },
                }
            }
            Sysno::connect => sys_req!(Connect { sockfd, sockaddr:*, addrlen }),
            #[cfg(target_arch = "x86_64")]
            Sysno::accept => sys_req!(Accept {
                sockfd,
                addr:*,
                addrlen:*,
                flags: { SockFlags::empty() }
            }),
            Sysno::accept4 => sys_req!(Accept { sockfd, addr:*, addrlen:*, flags }),
            Sysno::sendto => sys_req!(Sendto { sockfd, buf:*, len, flags, addr:*, addrlen }),
            Sysno::sendmsg => sys_req!(Sendmsg { sockfd, msg:*, flags }),
            Sysno::recvfrom => sys_req!(Recvfrom { sockfd, buf:*, len, flags, addr:*, addrlen:*, }),
            Sysno::bind => sys_req!(Bind { sockfd, sockaddr:*, addrlen }),
            Sysno::listen => sys_req!(Listen { sockfd, backlog }),
            Sysno::setsockopt | Sysno::getsockopt => {
                let level: u32 = ctx.sys_req_arg(1);
                let name: u32 = ctx.sys_req_arg(2);
                let optname = SocketOptionName::try_from(level, name).ok_or_else(|| {
                    unsupported_einval(format_args!(
                        "setsockopt(level = {level}, optname = {name})",
                    ))
                })?;
                let sockfd = ctx.sys_req_arg(0);
                match sysno {
                    Sysno::setsockopt => SyscallRequest::Setsockopt {
                        sockfd,
                        optname,
                        optval: ctx.sys_req_ptr(3),
                        optlen: ctx.sys_req_arg(4),
                    },
                    Sysno::getsockopt => SyscallRequest::Getsockopt {
                        sockfd,
                        optname,
                        optval: ctx.sys_req_ptr(3),
                        optlen: ctx.sys_req_ptr(4),
                    },
                    _ => unreachable!(),
                }
            }
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
            // TODO: fcntl64 is identical to fcntl except certain commands (e.g., `F_OFD_SETLK`)
            // that we don't support yet.
            #[cfg(target_arch = "x86")]
            Sysno::fcntl64 => {
                let cmd: i32 = ctx.sys_req_arg(1);
                let arg = ctx.sys_req_arg(2);
                SyscallRequest::Fcntl {
                    fd: ctx.sys_req_arg(0),
                    arg: FcntlArg::try_from(cmd, arg).ok_or_else(|| {
                        unsupported_einval(format_args!("fcntl(cmd = {cmd}, arg = {arg})"))
                    })?,
                }
            }
            Sysno::gettimeofday => sys_req!(Gettimeofday { tv:*, tz:* }),
            Sysno::clock_gettime => sys_req!(ClockGettime { clockid, tp: ts }),
            #[cfg(target_arch = "x86")]
            Sysno::clock_gettime64 => sys_req!(ClockGettime { clockid, tp: ts64 }),
            Sysno::clock_getres => sys_req!(ClockGetres { clockid, res: ts }),
            #[cfg(target_arch = "x86")]
            Sysno::clock_getres_time64 => sys_req!(ClockGetres { clockid, res: ts64 }),
            Sysno::clock_nanosleep => {
                sys_req!(ClockNanosleep {
                    clockid,
                    flags,
                    request: ts,
                    remain: ts,
                })
            }
            #[cfg(target_arch = "x86")]
            Sysno::clock_nanosleep_time64 => {
                sys_req!(ClockNanosleep {
                    clockid,
                    flags,
                    request: ts64,
                    remain: ts64,
                })
            }
            Sysno::nanosleep => sys_req!(ClockNanosleep {
                request: ts,
                remain: ts,
                clockid: { ClockId::Monotonic.into() },
                flags: { TimerFlags::empty() },
            }),
            Sysno::time => sys_req!(Time { tloc:* }),
            Sysno::getcwd => sys_req!(Getcwd { buf:*, size }),
            Sysno::readlink => sys_req!(Readlink { pathname:*, buf:* ,bufsiz }),
            Sysno::readlinkat => sys_req!(Readlinkat { dirfd, pathname:*, buf:*, bufsiz }),
            #[cfg(target_arch = "x86_64")]
            Sysno::getrlimit => {
                let resource: i32 = ctx.sys_req_arg(0);
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Getrlimit {
                        resource,
                        rlim: ctx.sys_req_ptr(1),
                    }
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            #[cfg(target_arch = "x86")]
            Sysno::ugetrlimit => {
                let resource: i32 = ctx.sys_req_arg(0);
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Getrlimit {
                        resource,
                        rlim: ctx.sys_req_ptr(1),
                    }
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::setrlimit => {
                let resource: i32 = ctx.sys_req_arg(0);
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Setrlimit {
                        resource,
                        rlim: ctx.sys_req_ptr(1),
                    }
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::prlimit64 => {
                let pid: i32 = ctx.sys_req_arg(0);
                let resource: i32 = ctx.sys_req_arg(1);
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Prlimit {
                        pid: if pid == 0 { None } else { Some(pid) },
                        resource,
                        new_limit: ctx.sys_req_ptr(2),
                        old_limit: ctx.sys_req_ptr(3),
                    }
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::getpid => SyscallRequest::Getpid,
            Sysno::getppid => SyscallRequest::Getppid,
            Sysno::getuid => SyscallRequest::Getuid,
            Sysno::getgid => SyscallRequest::Getgid,
            Sysno::geteuid => SyscallRequest::Geteuid,
            Sysno::getegid => SyscallRequest::Getegid,
            Sysno::epoll_ctl => {
                let op: i32 = ctx.sys_req_arg(1);
                if let Ok(op) = EpollOp::try_from(op) {
                    sys_req!(EpollCtl { epfd, op: {op}, fd, event:*, })
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::epoll_wait => {
                sys_req!(EpollPwait { epfd, events:*, maxevents, timeout, sigmask: { None }, sigsetsize: { 0 }, })
            }
            Sysno::epoll_pwait => {
                sys_req!(EpollPwait { epfd, events:*, maxevents, timeout, sigmask:*, sigsetsize })
            }
            Sysno::epoll_create => {
                // the `size` argument is ignored, but must be greater than zero;
                let size: i32 = ctx.sys_req_arg(0);
                if size > 0 {
                    SyscallRequest::EpollCreate {
                        flags: EpollCreateFlags::empty(),
                    }
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            Sysno::epoll_create1 => sys_req!(EpollCreate { flags }),
            Sysno::ppoll => {
                sys_req!(Ppoll { fds:*, nfds, timeout:ts, sigmask:*, sigsetsize })
            }
            #[cfg(target_arch = "x86")]
            Sysno::ppoll_time64 => {
                sys_req!(Ppoll { fds:*, nfds, timeout:ts64, sigmask:*, sigsetsize })
            }
            Sysno::poll => {
                sys_req!(Ppoll { fds:*, nfds, timeout:millis, sigmask: { None }, sigsetsize: { 0 } })
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::select => {
                sys_req!(Pselect {
                    nfds,
                    readfds:*,
                    writefds:*,
                    exceptfds:*,
                    timeout:tv,
                    sigsetpack: { None },
                })
            }
            #[cfg(target_arch = "x86")]
            Sysno::_newselect => {
                sys_req!(Pselect {
                    nfds,
                    readfds:*,
                    writefds:*,
                    exceptfds:*,
                    timeout:tv,
                    sigsetpack: { None },
                })
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::pselect6 => {
                sys_req!(Pselect {
                    nfds,
                    readfds:*,
                    writefds:*,
                    exceptfds:*,
                    timeout:ts,
                    sigsetpack:*,
                })
            }
            #[cfg(target_arch = "x86")]
            Sysno::pselect6_time64 => {
                sys_req!(Pselect {
                    nfds,
                    readfds:*,
                    writefds:*,
                    exceptfds:*,
                    timeout:ts64,
                    sigsetpack:*,
                })
            }
            Sysno::prctl => {
                let op: u32 = ctx.sys_req_arg(0);
                if let Ok(op) = PrctlOption::try_from(op) {
                    match op {
                        PrctlOption::SetName => SyscallRequest::Prctl {
                            args: PrctlArg::SetName(ctx.sys_req_ptr(1)),
                        },
                        PrctlOption::GetName => SyscallRequest::Prctl {
                            args: PrctlArg::GetName(ctx.sys_req_ptr(1)),
                        },
                        PrctlOption::CapBSetRead => SyscallRequest::Prctl {
                            args: PrctlArg::CapBSetRead(ctx.sys_req_arg(1)),
                        },
                        _ => {
                            return Err(unsupported_einval(format_args!("prctl({op:?})")));
                        }
                    }
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
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
            Sysno::set_thread_area => sys_req!(SetThreadArea { user_desc:* }),
            Sysno::set_tid_address => sys_req!(SetTidAddress { tidptr:* }),
            Sysno::openat => sys_req!(Openat { dirfd,pathname:*,flags,mode }),
            Sysno::open => {
                // open is equivalent to openat with dirfd AT_FDCWD
                SyscallRequest::Openat {
                    dirfd: AT_FDCWD,
                    pathname: ctx.sys_req_ptr(0),
                    flags: ctx.sys_req_arg(1),
                    mode: ctx.sys_req_arg(2),
                }
            }
            Sysno::unlinkat => sys_req!(Unlinkat { dirfd,pathname:*,flags }),
            Sysno::unlink => {
                // unlink is equivalent to unlinkat with dirfd AT_FDCWD and flags 0
                SyscallRequest::Unlinkat {
                    dirfd: AT_FDCWD,
                    pathname: ctx.sys_req_ptr(0),
                    flags: AtFlags::empty(),
                }
            }
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
            #[cfg(target_arch = "x86_64")]
            Sysno::newfstatat => sys_req!(Newfstatat { dirfd,pathname:*,buf:*,flags }),
            #[cfg(target_arch = "x86")]
            Sysno::fstatat64 => sys_req!(Fstatat64 { dirfd,pathname:*,buf:*,flags }),
            Sysno::eventfd => SyscallRequest::Eventfd2 {
                initval: ctx.sys_req_arg(0),
                flags: EfdFlags::empty(),
            },
            Sysno::eventfd2 => sys_req!(Eventfd2 { initval, flags }),
            Sysno::getrandom => sys_req!(GetRandom { buf:*,count,flags }),
            Sysno::clone => {
                let args = CloneArgs {
                    // The upper 32 bits are clone3-specific. The low 8 bits are the exit signal.
                    flags: CloneFlags::from_bits_retain(ctx.syscall_arg(0) as u64 & 0xffffff00),
                    stack: ctx.sys_req_arg(1),
                    parent_tid: ctx.sys_req_arg(2),
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
            Sysno::set_robust_list => {
                if ctx.sys_req_arg::<usize>(1) == size_of::<RobustListHead<Platform>>() {
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
            Sysno::capget => sys_req!(CapGet { header:*,data:* }),
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
            Sysno::futex => Self::parse_futex(ctx, TimeParam::timespec_old, unsupported_einval)?,
            #[cfg(target_arch = "x86")]
            Sysno::futex_time64 => {
                Self::parse_futex(ctx, TimeParam::timespec64, unsupported_einval)?
            }
            Sysno::execve => sys_req!(Execve { pathname:*, argv:*, envp:* }),
            Sysno::umask => sys_req!(Umask { mask }),
            Sysno::alarm => sys_req!(Alarm { seconds }),
            Sysno::tgkill => sys_req!(ThreadKill { tgid, tid, sig }),
            Sysno::setitimer => {
                let which: u32 = ctx.sys_req_arg(0);
                if let Ok(which) = IntervalTimer::try_from(which) {
                    sys_req!(SetITimer { which: {which}, new_value:*, old_value:* })
                } else {
                    return Err(errno::Errno::EINVAL);
                }
            }
            // Noisy unsupported syscalls.
            Sysno::statx | Sysno::io_uring_setup | Sysno::rseq | Sysno::statfs => {
                return Err(errno::Errno::ENOSYS);
            }
            sysno => {
                log_unsupported(format_args!("unsupported syscall {sysno:?}"));
                return Err(errno::Errno::ENOSYS);
            }
        };
        Ok(dispatcher)
    }

    fn parse_futex<T: Clone>(
        ctx: &PtRegs,
        time_param: impl FnOnce(Option<Platform::RawMutPointer<T>>) -> TimeParam<Platform>,
        unsupported_einval: impl Fn(core::fmt::Arguments<'_>) -> errno::Errno,
    ) -> Result<SyscallRequest<Platform>, errno::Errno> {
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
        };
        Ok(SyscallRequest::Futex { args })
    }
}

/// A set of syscalls that are allowed to be punched through to platforms that work with the Linux
/// shim.
///
/// NOTE: It is assumed that all punchthroughs here are non-blocking.
#[derive(Debug)]
pub enum PunchthroughSyscall<Platform: litebox::platform::RawPointerProvider> {
    /// Examine and change blocked signals
    RtSigprocmask {
        /// The behavior of the call is dependent on the value of how
        ///
        /// * `SIG_BLOCK` (0): The set of blocked signals is the union of the current set and the `set`
        ///   argument.
        ///
        /// * `SIG_UNBLOCK` (1): The signals in `set` are removed from the current set of blocked
        ///   signals. It is permissible to attempt to unblock a signal which is not blocked.
        ///
        /// * `SIG_SETMASK` (2): The set of blocked signals is set to the argument `set`.
        how: SigmaskHow,
        /// If `set` is None, then the signal mask is unchanged (i.e., `how` is ignored), but the
        /// current value of the signal mask is nevertheless returned in `oldset` (if it is not None).
        set: Option<Platform::RawConstPointer<SigSet>>,
        /// If `oldset` is not None, the previous value of the signal mask is stored in `oldset`.
        oldset: Option<Platform::RawMutPointer<SigSet>>,
    },
    /// Change the action taken by a process on receipt of a specific signal
    RtSigaction {
        /// The signal number to change the action for.
        signum: Signal,
        /// If `act` is not None, the new action for signal `signum` is installed from `act`.
        act: Option<Platform::RawConstPointer<SigAction>>,
        /// If `oldact` is not None, the previous action for the signal is stored in `oldact`.
        oldact: Option<Platform::RawMutPointer<SigAction>>,
    },
    /// Return from signal handler and cleanup stack
    RtSigreturn {
        /// The user stack pointer at the time of the signal.
        stack: usize,
    },
    /// Arrange for a SIGALRM signal to be delivered to the calling process in `seconds` seconds.
    /// If `seconds` is zero, any pending alarm is canceled.
    /// In any event, any previously set alarm() is canceled.
    Alarm { seconds: u32 },
    /// Sends the signal `sig` to the thread with the thread ID `tid` in the thread group `tgid`.
    ThreadKill {
        thread_group_id: i32,
        thread_id: i32,
        sig: Signal,
    },
    SetITimer {
        which: IntervalTimer,
        new_value: Platform::RawConstPointer<ItimerVal>,
        old_value: Option<Platform::RawMutPointer<ItimerVal>>,
    },
    /// Set the FS base register to the value in `addr`.
    #[cfg(target_arch = "x86_64")]
    SetFsBase { addr: usize },
    /// Get the current value of the FS base register and store it in `addr`.
    #[cfg(target_arch = "x86_64")]
    GetFsBase {
        addr: Platform::RawMutPointer<usize>,
    },
    #[cfg(target_arch = "x86")]
    SetThreadArea { user_desc: *mut UserDesc },
}

#[derive(Debug)]
pub enum TimeParam<Platform: litebox::platform::RawPointerProvider> {
    None,
    Milliseconds(i32),
    TimeVal(Platform::RawMutPointer<TimeVal>),
    Timespec32(Platform::RawMutPointer<Timespec32>),
    Timespec64(Platform::RawMutPointer<Timespec>),
}

impl<Platform: litebox::platform::RawPointerProvider> TimeParam<Platform> {
    /// Return a `TimeParam` for a 64-bit timespec pointer.
    pub fn timespec64(tp: Option<Platform::RawMutPointer<Timespec>>) -> Self {
        tp.map_or(TimeParam::None, TimeParam::Timespec64)
    }

    /// Return a `TimeParam` for a 32-bit timespec pointer.
    pub fn timespec32(tp: Option<Platform::RawMutPointer<Timespec32>>) -> Self {
        tp.map_or(TimeParam::None, TimeParam::Timespec32)
    }

    /// Return a `TimeParam` for the old timespec pointer type, which is
    /// architecture dependent.
    #[cfg(target_arch = "x86_64")]
    pub fn timespec_old(tp: Option<Platform::RawMutPointer<Timespec>>) -> Self {
        Self::timespec64(tp)
    }

    /// Return a `TimeParam` for the old timespec pointer type, which is
    /// architecture dependent.
    #[cfg(target_arch = "x86")]
    pub fn timespec_old(tp: Option<Platform::RawMutPointer<Timespec32>>) -> Self {
        Self::timespec32(tp)
    }

    /// Return a `TimeParam` for a timeval pointer.
    pub fn timeval(tp: Option<Platform::RawMutPointer<TimeVal>>) -> Self {
        tp.map_or(TimeParam::None, TimeParam::TimeVal)
    }

    /// Convert a generic timeout argument into a `Timeout` enum.
    pub fn read(&self) -> Result<Option<Duration>, errno::Errno> {
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
                let tv = unsafe { tv.read_at_offset(0) }
                    .ok_or(errno::Errno::EFAULT)?
                    .into_owned();
                Duration::try_from(tv).map_err(|_| errno::Errno::EINVAL)?
            }
            TimeParam::Timespec32(ts) => {
                let ts = unsafe { ts.read_at_offset(0) }
                    .ok_or(errno::Errno::EFAULT)?
                    .into_owned();
                Duration::try_from(ts).map_err(|_| errno::Errno::EINVAL)?
            }
            TimeParam::Timespec64(ts) => {
                let ts = unsafe { ts.read_at_offset(0) }
                    .ok_or(errno::Errno::EFAULT)?
                    .into_owned();
                Duration::try_from(ts).map_err(|_| errno::Errno::EINVAL)?
            }
        };
        Ok(Some(v))
    }

    /// Write a value to the time parameter.
    pub fn write(&self, duration: Duration) -> Result<(), errno::Errno> {
        match *self {
            TimeParam::None | TimeParam::Milliseconds(_) => Ok(()),
            TimeParam::TimeVal(tv_ptr) => {
                unsafe { tv_ptr.write_at_offset(0, duration.into()) }
                    .ok_or(errno::Errno::EFAULT)?;
                Ok(())
            }
            TimeParam::Timespec32(ts_ptr) => {
                unsafe { ts_ptr.write_at_offset(0, duration.into()) }
                    .ok_or(errno::Errno::EFAULT)?;
                Ok(())
            }
            TimeParam::Timespec64(ts_ptr) => {
                unsafe { ts_ptr.write_at_offset(0, duration.into()) }
                    .ok_or(errno::Errno::EFAULT)?;
                Ok(())
            }
        }
    }
}

impl<Platform: litebox::platform::RawPointerProvider> litebox::platform::Punchthrough
    for PunchthroughSyscall<Platform>
{
    type ReturnSuccess = usize;
    type ReturnFailure = errno::Errno;
}

/// Context saved when entering the kernel
///
/// pt_regs from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/include/asm/ptrace.h#L59)
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
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

/// Context saved when entering the kernel
///
/// pt_regs from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/include/asm/ptrace.h#L12)
#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PtRegs {
    pub ebx: usize,
    pub ecx: usize,
    pub edx: usize,
    pub esi: usize,
    pub edi: usize,
    pub ebp: usize,
    pub eax: usize,
    pub xds: usize,
    pub xes: usize,
    pub xfs: usize,
    pub xgs: usize,
    pub orig_eax: usize,
    pub eip: usize,
    pub xcs: usize,
    pub eflags: usize,
    pub esp: usize,
    pub xss: usize,
}

impl PtRegs {
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
            _ => panic!("Invalid syscall argument index: {}", idx),
        }
    }

    /// Get the `idx`th syscall argument.
    ///
    /// # Panics
    ///
    /// If `idx` is greater than 5, this function will panic.
    #[cfg(target_arch = "x86")]
    pub fn syscall_arg(&self, idx: usize) -> usize {
        match idx {
            0 => self.ebx,
            1 => self.ecx,
            2 => self.edx,
            3 => self.esi,
            4 => self.edi,
            5 => self.ebp,
            _ => panic!("Invalid syscall argument index: {}", idx),
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
    #[cfg(target_arch = "x86")]
    pub fn get_ip(&self) -> usize {
        self.eip
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
trait ReinterpretTruncatedFromUsize: Sized {
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
                    v.truncate()
                }
            }
        )*
        $(
            impl ReinterpretTruncatedFromUsize for $sty {
                fn reinterpret_truncated_from_usize(v: usize) -> Self {
                    v.reinterpret_as_signed().truncate()
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
trait ReinterpretUsizeAsPtr<T>: Sized {
    fn reinterpret_usize_as_ptr(v: usize) -> Self;
}
impl<T: Clone, P: RawConstPointer<T>> ReinterpretUsizeAsPtr<core::marker::PhantomData<((), T)>>
    for P
{
    fn reinterpret_usize_as_ptr(v: usize) -> Self {
        P::from_usize(v)
    }
}
impl<T: Clone, P: RawConstPointer<T>> ReinterpretUsizeAsPtr<core::marker::PhantomData<(bool, T)>>
    for Option<P>
{
    fn reinterpret_usize_as_ptr(v: usize) -> Self {
        if v == 0 { None } else { Some(P::from_usize(v)) }
    }
}

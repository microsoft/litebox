//! Common Linux-y items suitable for LiteBox

#![no_std]
#![allow(non_camel_case_types)]

use int_enum::IntEnum;
use litebox::{
    fs::OFlags,
    net::{ReceiveFlags, SendFlags},
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
pub enum FcntlArg {
    /// Get the file descriptor flags
    GETFD,
    /// Set the file descriptor flags
    SETFD(FileDescriptorFlags),
    /// Get descriptor status flags
    GETFL,
    /// Set descriptor status flags
    SETFL(OFlags),
}

const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;

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
    pub fn from(cmd: i32, arg: usize) -> Self {
        match cmd {
            F_GETFD => Self::GETFD,
            F_SETFD => Self::SETFD(FileDescriptorFlags::from_bits_truncate(arg.truncate())),
            F_GETFL => Self::GETFL,
            F_SETFL => Self::SETFL(OFlags::from_bits_truncate(arg.truncate())),
            _ => unimplemented!(),
        }
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
pub const TIOCGPTN: u32 = 0x80045430;

/// Commands for use with `ioctl`.
#[non_exhaustive]
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
#[derive(Debug, IntEnum)]
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

#[repr(u8)]
#[non_exhaustive]
#[derive(IntEnum, PartialEq)]
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
    PEERCRED = 17,
    RCVTIMEO = 20,
    SNDTIMEO = 21,
}

#[repr(u32)]
#[derive(Debug, IntEnum)]
pub enum TcpOption {
    NODELAY = 1,
    CORK = 3,
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
    pub fn from(level: u32, optname: u32) -> Option<Self> {
        let level = SocketOptionLevel::try_from(level).ok()?;
        match level {
            SocketOptionLevel::IP => Some(Self::IP(IpOption::try_from(optname).ok()?)),
            SocketOptionLevel::SOCKET => Some(Self::Socket(SocketOption::try_from(optname).ok()?)),
            SocketOptionLevel::TCP => Some(Self::TCP(TcpOption::try_from(optname).ok()?)),
            _ => todo!(),
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
        pub type suseconds_t = i32;
    } else if #[cfg(all(target_arch = "x86_64"))] {
        pub type time_t = i64;
        pub type suseconds_t = i64;
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

impl Timespec {
    /// Subtract another `Timespec` from self
    pub fn sub_timespec(&self, other: &Timespec) -> Result<core::time::Duration, errno::Errno> {
        if self >= other {
            let (secs, nsec) = if self.tv_nsec >= other.tv_nsec {
                (
                    self.tv_sec
                        .checked_sub(other.tv_sec)
                        .ok_or(errno::Errno::EDOM)?,
                    self.tv_nsec - other.tv_nsec,
                )
            } else {
                (
                    self.tv_sec
                        .checked_sub(other.tv_sec + 1)
                        .ok_or(errno::Errno::EDOM)?,
                    self.tv_nsec + 1_000_000_000 - other.tv_nsec,
                )
            };

            Ok(core::time::Duration::new(
                u64::try_from(secs).map_err(|_| errno::Errno::EDOM)?,
                nsec.truncate(),
            ))
        } else {
            Err(errno::Errno::EINVAL)
        }
    }
}

impl From<Timespec> for core::time::Duration {
    fn from(timespec: Timespec) -> Self {
        core::time::Duration::new(
            u64::try_from(timespec.tv_sec).unwrap(),
            timespec.tv_nsec.truncate(),
        )
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TimeVal {
    tv_sec: time_t,
    tv_usec: suseconds_t,
}

const MICROS_PER_SEC: i32 = 1_000_000;
impl TryFrom<TimeVal> for core::time::Duration {
    type Error = errno::Errno;

    fn try_from(value: TimeVal) -> Result<Self, Self::Error> {
        let usec: i32 = value.tv_usec.truncate();
        if usec >= MICROS_PER_SEC {
            Err(errno::Errno::EDOM)
        } else {
            Ok(core::time::Duration::new(
                u64::try_from(value.tv_sec).map_err(|_| errno::Errno::EDOM)?,
                u32::try_from(value.tv_usec * 1000).map_err(|_| errno::Errno::EDOM)?,
            ))
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
pub struct SigSet(usize);

impl SigSet {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn add(&mut self, signum: Signal) {
        self.0 |= 1 << (signum as usize - 1);
    }

    pub fn remove(&mut self, signum: Signal) {
        self.0 &= !(1 << (signum as usize - 1));
    }

    pub fn contains(&self, signum: Signal) -> bool {
        (self.0 & (1 << (signum as usize - 1))) != 0
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
            options(nostack, nomem)
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
            options(nostack, nomem)
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
            options(nostack, nomem)
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
            options(nostack, nomem)
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

/// A descriptor for thread-local storage (TLS).
///
/// On `x86_64`, this is represented as a `u8`. The TLS pointer can point to
/// an arbitrary-sized memory region.
#[cfg(target_arch = "x86_64")]
pub type ThreadLocalDescriptor = u8;
/// A descriptor for thread-local storage (TLS).
///
/// On `x86`, this is represented as a `UserDesc`, which provides a more
/// structured descriptor (e.g., base address, limit, flags).
#[cfg(target_arch = "x86")]
pub type ThreadLocalDescriptor = UserDesc;

pub struct NewThreadArgs<Platform: litebox::platform::RawPointerProvider> {
    pub tls: Option<Platform::RawMutPointer<ThreadLocalDescriptor>>,
    pub set_child_tid: Option<Platform::RawMutPointer<i32>>,
    pub task: alloc::boxed::Box<Task<Platform>>,
    pub callback: fn(Self),
}

/// Struct for thread-local storage.
pub struct ThreadLocalStorage<Platform: litebox::platform::RawPointerProvider> {
    /// Indicates whether the TLS is being borrowed.
    pub borrowed: bool,

    #[cfg(target_arch = "x86")]
    pub self_ptr: *mut ThreadLocalStorage<Platform>,
    pub current_task: alloc::boxed::Box<Task<Platform>>,
}

/// Credentials of a process
#[derive(Clone)]
pub struct Credentials {
    pub uid: usize,
    pub euid: usize,
    pub gid: usize,
    pub egid: usize,
}

impl<Platform: litebox::platform::RawPointerProvider> ThreadLocalStorage<Platform> {
    pub const fn new(task: alloc::boxed::Box<Task<Platform>>) -> Self {
        Self {
            borrowed: false,
            #[cfg(target_arch = "x86")]
            self_ptr: core::ptr::null_mut(),
            current_task: task,
        }
    }
}

pub struct Task<Platform: litebox::platform::RawPointerProvider> {
    /// Process ID
    pub pid: i32,
    /// Parent Process ID
    pub ppid: i32,
    /// Thread ID
    pub tid: i32,
    /// When a thread whose `clear_child_tid` is not `None` terminates, and it shares memory with other threads,
    /// the kernel writes 0 to the address specified by `clear_child_tid` and then executes:
    ///
    /// futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
    ///
    /// This operation wakes a single thread waiting on the specified memory location via futex.
    /// Any errors from the futex wake operation are ignored.
    pub clear_child_tid: Option<Platform::RawMutPointer<i32>>,
    /// The purpose of the robust futex list is to ensure that if a thread accidentally fails to unlock a futex before
    /// terminating or calling execve(2), another thread that is waiting on that futex is notified that the former owner
    /// of the futex has died. This notification consists of two pieces: the FUTEX_OWNER_DIED bit is set in the futex word,
    /// and the kernel performs a futex(2) FUTEX_WAKE operation on one of the threads waiting on the futex.
    pub robust_list: Option<Platform::RawConstPointer<RobustListHead<Platform>>>,
    /// Shared process credentials.
    pub credentials: alloc::sync::Arc<Credentials>,
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
#[derive(Clone)]
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
#[derive(Debug, IntEnum)]
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

#[non_exhaustive]
#[repr(i32)]
#[derive(Debug, IntEnum)]
pub enum MadviseBehavior {
    /// Normal behavior, no special treatment
    Normal = 0,
    /// Do not expect access in the near future
    DontNeed = 4,
    /// Don't inherit across fork
    DontFork = 10,
    /// Do inherit across fork
    DoFork = 11,
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

/// Request to syscall handler
#[non_exhaustive]
pub enum SyscallRequest<'a, Platform: litebox::platform::RawPointerProvider> {
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
        offset: usize,
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
    Recvfrom {
        sockfd: i32,
        buf: Platform::RawMutPointer<u8>,
        len: usize,
        flags: ReceiveFlags,
        addr: Option<Platform::RawMutPointer<u8>>,
        addrlen: Option<Platform::RawMutPointer<u32>>,
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
    Uname {
        buf: Platform::RawMutPointer<Utsname>,
    },
    Fcntl {
        fd: i32,
        arg: FcntlArg,
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
        args: Platform::RawConstPointer<CloneArgs>,
        ctx: &'a PtRegs,
    },
    /// Manipulate thread-local storage information.
    /// Returns `ENOSYS` on 64-bit.
    SetThreadArea {
        user_desc: Platform::RawMutPointer<UserDesc>,
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
    /// A sentinel that is expected to be "handled" by trivially returning its value.
    Ret(errno::Errno),
}

impl<'a, Platform: litebox::platform::RawPointerProvider> SyscallRequest<'a, Platform> {
    /// Take the raw syscall number and arguments, and provide a stronger-typed `SyscallRequest`.
    ///
    /// Returns `Ok` if a valid translation exists, if no such translation exists, returns the [`Errno`](errno::Errno) for it.
    ///
    /// # Panics
    ///
    /// Ideally, this function would not panic. However, since it is currently under development, it
    /// is allowed to panic upon receiving a syscall number (or arguments) that it does not know how
    /// to handle.
    #[expect(clippy::too_many_lines)]
    pub fn try_from_raw(syscall_number: usize, ctx: &'a PtRegs) -> Result<Self, errno::Errno> {
        let sysno = Sysno::from(u32::try_from(syscall_number).map_err(|_| errno::Errno::ENOSYS)?);
        let dispatcher = match sysno {
            Sysno::read => SyscallRequest::Read {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                count: ctx.syscall_arg(2),
            },
            Sysno::write => SyscallRequest::Write {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                buf: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                count: ctx.syscall_arg(2),
            },
            Sysno::close => SyscallRequest::Close {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
            },
            Sysno::stat => SyscallRequest::Stat {
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
            },
            Sysno::fstat => SyscallRequest::Fstat {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
            },
            Sysno::lstat => SyscallRequest::Lstat {
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::mmap => SyscallRequest::Mmap {
                addr: ctx.syscall_arg(0),
                length: ctx.syscall_arg(1),
                prot: ProtFlags::from_bits_truncate(
                    ctx.syscall_arg(2).reinterpret_as_signed().truncate(),
                ),
                flags: MapFlags::from_bits_truncate(
                    ctx.syscall_arg(3).reinterpret_as_signed().truncate(),
                ),
                fd: ctx.syscall_arg(4).reinterpret_as_signed().truncate(),
                offset: ctx.syscall_arg(5),
            },
            #[cfg(target_arch = "x86")]
            Sysno::mmap2 => SyscallRequest::Mmap {
                addr: ctx.syscall_arg(0),
                length: ctx.syscall_arg(1),
                prot: ProtFlags::from_bits_truncate(
                    ctx.syscall_arg(2).reinterpret_as_signed().truncate(),
                ),
                flags: MapFlags::from_bits_truncate(
                    ctx.syscall_arg(3).reinterpret_as_signed().truncate(),
                ),
                fd: ctx.syscall_arg(4).reinterpret_as_signed().truncate(),
                offset: ctx.syscall_arg(5),
            },
            Sysno::mprotect => SyscallRequest::Mprotect {
                addr: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                length: ctx.syscall_arg(1),
                prot: ProtFlags::from_bits_truncate(
                    ctx.syscall_arg(2).reinterpret_as_signed().truncate(),
                ),
            },
            Sysno::munmap => SyscallRequest::Munmap {
                addr: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                length: ctx.syscall_arg(1),
            },
            Sysno::brk => SyscallRequest::Brk {
                addr: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
            },
            Sysno::mremap => SyscallRequest::Mremap {
                old_addr: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                old_size: ctx.syscall_arg(1),
                new_size: ctx.syscall_arg(2),
                flags: MRemapFlags::from_bits_truncate(ctx.syscall_arg(3).truncate()),
                new_addr: ctx.syscall_arg(4),
            },
            Sysno::rt_sigprocmask => {
                let how: i32 = ctx.syscall_arg(0).reinterpret_as_signed().truncate();
                if let Ok(how) = SigmaskHow::try_from(how) {
                    SyscallRequest::RtSigprocmask {
                        how,
                        set: if ctx.syscall_arg(1) == 0 {
                            None
                        } else {
                            Some(Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)))
                        },
                        oldset: if ctx.syscall_arg(2) == 0 {
                            None
                        } else {
                            Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)))
                        },
                        sigsetsize: ctx.syscall_arg(3),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::rt_sigaction => {
                let signum: i32 = ctx.syscall_arg(0).reinterpret_as_signed().truncate();
                if let Ok(signum) = Signal::try_from(signum) {
                    SyscallRequest::RtSigaction {
                        signum,
                        act: if ctx.syscall_arg(1) == 0 {
                            None
                        } else {
                            Some(Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)))
                        },
                        oldact: if ctx.syscall_arg(2) == 0 {
                            None
                        } else {
                            Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)))
                        },
                        sigsetsize: ctx.syscall_arg(3),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::ioctl => SyscallRequest::Ioctl {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                arg: {
                    let cmd = ctx.syscall_arg(1).truncate();
                    let arg = ctx.syscall_arg(2);
                    match cmd {
                        TCGETS => IoctlArg::TCGETS(Platform::RawMutPointer::from_usize(arg)),
                        TCSETS => IoctlArg::TCSETS(Platform::RawConstPointer::from_usize(arg)),
                        TIOCGWINSZ => {
                            IoctlArg::TIOCGWINSZ(Platform::RawMutPointer::from_usize(arg))
                        }
                        TIOCGPTN => IoctlArg::TIOCGPTN(Platform::RawMutPointer::from_usize(arg)),
                        FIONBIO => IoctlArg::FIONBIO(Platform::RawConstPointer::from_usize(arg)),
                        _ => IoctlArg::Raw {
                            cmd,
                            arg: Platform::RawMutPointer::from_usize(arg),
                        },
                    }
                },
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::pread64 => SyscallRequest::Pread64 {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                count: ctx.syscall_arg(2),
                offset: ctx.syscall_arg(3).reinterpret_as_signed() as i64,
            },
            #[cfg(target_arch = "x86")]
            Sysno::pread64 => SyscallRequest::Pread64 {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                count: ctx.syscall_arg(2),
                offset: ctx.syscall_arg(3).reinterpret_as_signed() as i64
                    | ((ctx.syscall_arg(4).reinterpret_as_signed() as i64) << 32),
            },
            Sysno::readv => SyscallRequest::Readv {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                iovec: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                iovcnt: ctx.syscall_arg(2),
            },
            Sysno::writev => SyscallRequest::Writev {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                iovec: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                iovcnt: ctx.syscall_arg(2),
            },
            Sysno::access => SyscallRequest::Access {
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                mode: AccessFlags::from_bits_truncate(
                    ctx.syscall_arg(1).reinterpret_as_signed().truncate(),
                ),
            },
            Sysno::pipe => SyscallRequest::Pipe2 {
                pipefd: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                flags: litebox::fs::OFlags::empty(),
            },
            Sysno::pipe2 => SyscallRequest::Pipe2 {
                pipefd: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                flags: litebox::fs::OFlags::from_bits_truncate(ctx.syscall_arg(1).truncate()),
            },
            Sysno::madvise => {
                let behavior: i32 = ctx.syscall_arg(2).reinterpret_as_signed().truncate();
                let behavior =
                    MadviseBehavior::try_from(behavior).expect("unsupported madvise behavior");
                SyscallRequest::Madvise {
                    addr: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                    length: ctx.syscall_arg(1),
                    behavior,
                }
            }
            Sysno::dup => SyscallRequest::Dup {
                oldfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                newfd: None,
                flags: None,
            },
            Sysno::dup2 => SyscallRequest::Dup {
                oldfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                newfd: Some(ctx.syscall_arg(1).reinterpret_as_signed().truncate()),
                flags: None,
            },
            Sysno::dup3 => SyscallRequest::Dup {
                oldfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                newfd: Some(ctx.syscall_arg(1).reinterpret_as_signed().truncate()),
                flags: Some(litebox::fs::OFlags::from_bits_truncate(
                    ctx.syscall_arg(2).truncate(),
                )),
            },
            Sysno::socket => {
                let domain: u32 = ctx.syscall_arg(0).truncate();
                let type_and_flags: u32 = ctx.syscall_arg(1).truncate();
                SyscallRequest::Socket {
                    domain: AddressFamily::try_from(domain).expect("Invalid domain"),
                    ty: SockType::try_from(type_and_flags & 0x0f).expect("Invalid sock type"),
                    flags: SockFlags::from_bits_truncate(type_and_flags & !0x0f),
                    protocol: if ctx.syscall_arg(2) == 0 {
                        None
                    } else {
                        let protocol: u8 = ctx.syscall_arg(2).truncate();
                        Some(Protocol::try_from(protocol).expect("Invalid protocol"))
                    },
                }
            }
            Sysno::connect => SyscallRequest::Connect {
                sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                sockaddr: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                addrlen: ctx.syscall_arg(2),
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::accept => SyscallRequest::Accept {
                sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                addr: if ctx.syscall_arg(1) == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)))
                },
                addrlen: if ctx.syscall_arg(2) == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)))
                },
                flags: SockFlags::empty(),
            },
            Sysno::accept4 => SyscallRequest::Accept {
                sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                addr: if ctx.syscall_arg(1) == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)))
                },
                addrlen: if ctx.syscall_arg(2) == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)))
                },
                flags: SockFlags::from_bits_truncate(ctx.syscall_arg(3).truncate()),
            },
            Sysno::sendto => SyscallRequest::Sendto {
                sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                buf: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                len: ctx.syscall_arg(2),
                flags: litebox::net::SendFlags::from_bits_truncate(ctx.syscall_arg(3).truncate()),
                addr: if ctx.syscall_arg(4) == 0 {
                    None
                } else {
                    Some(Platform::RawConstPointer::from_usize(ctx.syscall_arg(4)))
                },
                addrlen: ctx.syscall_arg(5).truncate(),
            },
            Sysno::recvfrom => SyscallRequest::Recvfrom {
                sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                len: ctx.syscall_arg(2),
                flags: litebox::net::ReceiveFlags::from_bits_truncate(
                    ctx.syscall_arg(3).truncate(),
                ),
                addr: if ctx.syscall_arg(4) == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(4)))
                },
                addrlen: if ctx.syscall_arg(5) == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(ctx.syscall_arg(5)))
                },
            },
            Sysno::bind => SyscallRequest::Bind {
                sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                sockaddr: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                addrlen: ctx.syscall_arg(2),
            },
            Sysno::listen => SyscallRequest::Listen {
                sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                backlog: ctx.syscall_arg(1).truncate(),
            },
            Sysno::setsockopt => {
                let optname = SocketOptionName::from(
                    ctx.syscall_arg(1).truncate(),
                    ctx.syscall_arg(2).truncate(),
                );
                if let Some(optname) = optname {
                    SyscallRequest::Setsockopt {
                        sockfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                        optname,
                        optval: Platform::RawConstPointer::from_usize(ctx.syscall_arg(3)),
                        optlen: ctx.syscall_arg(4),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::exit => SyscallRequest::Exit {
                status: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
            },
            Sysno::exit_group => SyscallRequest::ExitGroup {
                status: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
            },
            ::syscalls::Sysno::uname => SyscallRequest::Uname {
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
            },
            Sysno::fcntl => SyscallRequest::Fcntl {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                arg: FcntlArg::from(
                    ctx.syscall_arg(1).reinterpret_as_signed().truncate(),
                    ctx.syscall_arg(2),
                ),
            },
            Sysno::getcwd => SyscallRequest::Getcwd {
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                size: ctx.syscall_arg(1),
            },
            Sysno::readlink => SyscallRequest::Readlink {
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                bufsiz: ctx.syscall_arg(2),
            },
            Sysno::readlinkat => SyscallRequest::Readlinkat {
                dirfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)),
                bufsiz: ctx.syscall_arg(3),
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::getrlimit => {
                let resource: i32 = ctx.syscall_arg(0).reinterpret_as_signed().truncate();
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Getrlimit {
                        resource,
                        rlim: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            #[cfg(target_arch = "x86")]
            Sysno::ugetrlimit => {
                let resource: i32 = ctx.syscall_arg(0).reinterpret_as_signed().truncate();
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Getrlimit {
                        resource,
                        rlim: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            ::syscalls::Sysno::setrlimit => {
                let resource: i32 = ctx.syscall_arg(0).reinterpret_as_signed().truncate();
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Setrlimit {
                        resource,
                        rlim: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::prlimit64 => {
                let pid: i32 = ctx.syscall_arg(0).reinterpret_as_signed().truncate();
                let resource: i32 = ctx.syscall_arg(1).reinterpret_as_signed().truncate();
                let new_limit = ctx.syscall_arg(2);
                let old_limit = ctx.syscall_arg(3);
                if let Ok(resource) = RlimitResource::try_from(resource) {
                    SyscallRequest::Prlimit {
                        pid: if pid == 0 { None } else { Some(pid) },
                        resource,
                        new_limit: if new_limit == 0 {
                            None
                        } else {
                            Some(Platform::RawConstPointer::from_usize(new_limit))
                        },
                        old_limit: if old_limit == 0 {
                            None
                        } else {
                            Some(Platform::RawMutPointer::from_usize(old_limit))
                        },
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::getpid => SyscallRequest::Getpid,
            Sysno::getppid => SyscallRequest::Getppid,
            Sysno::getuid => SyscallRequest::Getuid,
            Sysno::getgid => SyscallRequest::Getgid,
            Sysno::geteuid => SyscallRequest::Geteuid,
            Sysno::getegid => SyscallRequest::Getegid,
            Sysno::epoll_ctl => {
                let op: i32 = ctx.syscall_arg(1).reinterpret_as_signed().truncate();
                if let Ok(op) = EpollOp::try_from(op) {
                    SyscallRequest::EpollCtl {
                        epfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                        op,
                        fd: ctx.syscall_arg(2).reinterpret_as_signed().truncate(),
                        event: Platform::RawConstPointer::from_usize(ctx.syscall_arg(3)),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::epoll_wait => SyscallRequest::EpollPwait {
                epfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                events: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                maxevents: ctx.syscall_arg(2).truncate(),
                timeout: ctx.syscall_arg(3).reinterpret_as_signed().truncate(),
                sigmask: None,
                sigsetsize: 0,
            },
            Sysno::epoll_pwait => SyscallRequest::EpollPwait {
                epfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                events: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                maxevents: ctx.syscall_arg(2).truncate(),
                timeout: ctx.syscall_arg(3).reinterpret_as_signed().truncate(),
                sigmask: if ctx.syscall_arg(4) == 0 {
                    None
                } else {
                    Some(Platform::RawConstPointer::from_usize(ctx.syscall_arg(4)))
                },
                sigsetsize: ctx.syscall_arg(5),
            },
            Sysno::epoll_create => {
                // the `size` argument is ignored, but must be greater than zero;
                let size: i32 = ctx.syscall_arg(0).reinterpret_as_signed().truncate();
                if size > 0 {
                    SyscallRequest::EpollCreate {
                        flags: EpollCreateFlags::empty(),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::epoll_create1 => SyscallRequest::EpollCreate {
                flags: EpollCreateFlags::from_bits_truncate(ctx.syscall_arg(0).truncate()),
            },
            Sysno::arch_prctl => {
                let code: u32 = ctx.syscall_arg(0).truncate();
                if let Ok(code) = ArchPrctlCode::try_from(code) {
                    let arg = match code {
                        #[cfg(target_arch = "x86_64")]
                        ArchPrctlCode::SetFs => ArchPrctlArg::SetFs(ctx.syscall_arg(1)),
                        #[cfg(target_arch = "x86_64")]
                        ArchPrctlCode::GetFs => ArchPrctlArg::GetFs(
                            Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                        ),
                        ArchPrctlCode::CETStatus => ArchPrctlArg::CETStatus,
                        ArchPrctlCode::CETDisable => ArchPrctlArg::CETDisable,
                        ArchPrctlCode::CETLock => ArchPrctlArg::CETLock,
                    };
                    SyscallRequest::ArchPrctl { arg }
                } else {
                    todo!("Unsupported arch_prctl syscall: {code:?}")
                }
            }
            Sysno::gettid => SyscallRequest::Gettid,
            Sysno::set_thread_area => SyscallRequest::SetThreadArea {
                user_desc: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
            },
            Sysno::set_tid_address => SyscallRequest::SetTidAddress {
                tidptr: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
            },
            Sysno::openat => SyscallRequest::Openat {
                dirfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                flags: litebox::fs::OFlags::from_bits_truncate(ctx.syscall_arg(2).truncate()),
                mode: litebox::fs::Mode::from_bits_truncate(ctx.syscall_arg(3).truncate()),
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::newfstatat => SyscallRequest::Newfstatat {
                dirfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)),
                flags: AtFlags::from_bits_truncate(
                    ctx.syscall_arg(3).reinterpret_as_signed().truncate(),
                ),
            },
            #[cfg(target_arch = "x86")]
            Sysno::fstatat64 => SyscallRequest::Fstatat64 {
                dirfd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                pathname: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)),
                flags: AtFlags::from_bits_truncate(
                    ctx.syscall_arg(3).reinterpret_as_signed().truncate(),
                ),
            },
            Sysno::eventfd => SyscallRequest::Eventfd2 {
                initval: ctx.syscall_arg(0).truncate(),
                flags: EfdFlags::empty(),
            },
            Sysno::eventfd2 => SyscallRequest::Eventfd2 {
                initval: ctx.syscall_arg(0).truncate(),
                flags: EfdFlags::from_bits_truncate(ctx.syscall_arg(1).truncate()),
            },
            Sysno::getrandom => SyscallRequest::GetRandom {
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                count: ctx.syscall_arg(1),
                flags: RngFlags::from_bits_truncate(
                    ctx.syscall_arg(2).reinterpret_as_signed().truncate(),
                ),
            },
            Sysno::clone3 => {
                debug_assert_eq!(
                    ctx.syscall_arg(1),
                    size_of::<CloneArgs>(),
                    "legacy clone3 struct"
                );
                SyscallRequest::Clone {
                    args: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                    ctx,
                }
            }
            Sysno::set_robust_list => {
                if ctx.syscall_arg(1) == size_of::<RobustListHead<Platform>>() {
                    SyscallRequest::SetRobustList {
                        head: ctx.syscall_arg(0),
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::get_robust_list => {
                let pid = ctx.syscall_arg(0);
                SyscallRequest::GetRobustList {
                    pid: if pid == 0 {
                        None
                    } else {
                        Some(pid.reinterpret_as_signed().truncate())
                    },
                    head: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                    len: Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)),
                }
            }
            Sysno::sysinfo => SyscallRequest::Sysinfo {
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
            },
            Sysno::capget => {
                let data_ptr = ctx.syscall_arg(1);
                SyscallRequest::CapGet {
                    header: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                    data: if data_ptr == 0 {
                        None
                    } else {
                        Some(Platform::RawMutPointer::from_usize(data_ptr))
                    },
                }
            }
            Sysno::getdents64 => SyscallRequest::GetDirent64 {
                fd: ctx.syscall_arg(0).reinterpret_as_signed().truncate(),
                dirp: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                count: ctx.syscall_arg(2),
            },
            // TODO: support syscall `statfs`
            Sysno::statx | Sysno::io_uring_setup | Sysno::rseq | Sysno::statfs => {
                SyscallRequest::Ret(errno::Errno::ENOSYS)
            }
            _ => unimplemented!("Translation for {sysno} is not (yet) currently supported"),
        };
        Ok(dispatcher)
    }
}

/// A set of syscalls that are allowed to be punched through to platforms that work with the Linux
/// shim.
///
/// NOTE: It is assumed that all punchthroughs here are non-blocking.
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
    /// Set the FS base register to the value in `addr`.
    #[cfg(target_arch = "x86_64")]
    SetFsBase {
        addr: usize,
    },
    /// Get the current value of the FS base register and store it in `addr`.
    #[cfg(target_arch = "x86_64")]
    GetFsBase {
        addr: Platform::RawMutPointer<usize>,
    },
    #[cfg(target_arch = "x86")]
    SetThreadArea {
        user_desc: Platform::RawMutPointer<UserDesc>,
    },
    WakeByAddress {
        addr: Platform::RawMutPointer<i32>,
    },
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

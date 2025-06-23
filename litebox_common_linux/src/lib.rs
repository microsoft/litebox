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

extern crate alloc;

// TODO(jayb): Should errno::Errno be publicly re-exported?

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

/// Linux's `stat` struct
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
    pub st_size: i64,
    pub st_blksize: i64,
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
        static mut INO: u64 = 0x1245;
        // TODO: add more fields
        let litebox::fs::FileStatus {
            file_type,
            mode,
            size,
            ..
        } = value;
        unsafe {
            INO += 1;
        }
        Self {
            // TODO: st_dev and st_ino are used by ld.so to unique identify
            // shared libraries. Give a random value for now.
            st_dev: 0,
            st_ino: unsafe { INO },
            st_nlink: 1,
            st_mode: mode.bits() | InodeType::from(file_type) as u32,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            #[allow(clippy::cast_possible_wrap)]
            st_size: size as i64,
            st_blksize: 0,
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
        if value.tv_usec >= MICROS_PER_SEC.into() {
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
    SetFs(Platform::RawConstPointer<u8>),
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

/// Struct for thread-local storage.
pub struct ThreadLocalStorage<Platform: litebox::platform::RawPointerProvider> {
    /// Indicates whether the TLS is being borrowed.
    pub borrowed: bool,

    #[cfg(target_arch = "x86")]
    pub self_ptr: *mut ThreadLocalStorage<Platform>,
    pub current_task: alloc::boxed::Box<Task>,

    pub __phantom: core::marker::PhantomData<Platform>,
}

impl<Platform: litebox::platform::RawPointerProvider> ThreadLocalStorage<Platform> {
    pub const fn new(task: alloc::boxed::Box<Task>) -> Self {
        Self {
            borrowed: false,
            #[cfg(target_arch = "x86")]
            self_ptr: core::ptr::null_mut(),
            current_task: task,
            __phantom: core::marker::PhantomData,
        }
    }
}

/// A task associated with a thread in LiteBox.
pub struct Task {
    /// Thread identifier
    pub tid: u32,
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

/// Request to syscall handler
#[non_exhaustive]
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
    Newfstatat {
        dirfd: i32,
        pathname: Platform::RawConstPointer<i8>,
        buf: Platform::RawMutPointer<FileStat>,
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
    /// Manipulate thread-local storage information.
    /// Returns `ENOSYS` on 64-bit.
    SetThreadArea {
        user_desc: Platform::RawMutPointer<UserDesc>,
    },
    GetRandom {
        buf: Platform::RawMutPointer<u8>,
        count: usize,
        flags: RngFlags,
    },
    /// A sentinel that is expected to be "handled" by trivially returning its value.
    Ret(errno::Errno),
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
    #[expect(clippy::too_many_lines)]
    pub fn try_from_raw(syscall_number: usize, args: &[usize; 6]) -> Result<Self, errno::Errno> {
        let sysno = Sysno::from(u32::try_from(syscall_number).map_err(|_| errno::Errno::ENOSYS)?);
        let dispatcher = match sysno {
            Sysno::read => SyscallRequest::Read {
                fd: args[0].reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(args[1]),
                count: args[2],
            },
            Sysno::write => SyscallRequest::Write {
                fd: args[0].reinterpret_as_signed().truncate(),
                buf: Platform::RawConstPointer::from_usize(args[1]),
                count: args[2],
            },
            Sysno::close => SyscallRequest::Close {
                fd: args[0].reinterpret_as_signed().truncate(),
            },
            Sysno::stat => SyscallRequest::Stat {
                pathname: Platform::RawConstPointer::from_usize(args[0]),
                buf: Platform::RawMutPointer::from_usize(args[1]),
            },
            Sysno::fstat => SyscallRequest::Fstat {
                fd: args[0].reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(args[1]),
            },
            Sysno::lstat => SyscallRequest::Lstat {
                pathname: Platform::RawConstPointer::from_usize(args[0]),
                buf: Platform::RawMutPointer::from_usize(args[1]),
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::mmap => SyscallRequest::Mmap {
                addr: args[0],
                length: args[1],
                prot: ProtFlags::from_bits_truncate(args[2].reinterpret_as_signed().truncate()),
                flags: MapFlags::from_bits_truncate(args[3].reinterpret_as_signed().truncate()),
                fd: args[4].reinterpret_as_signed().truncate(),
                offset: args[5],
            },
            #[cfg(target_arch = "x86")]
            Sysno::mmap2 => SyscallRequest::Mmap {
                addr: args[0],
                length: args[1],
                prot: ProtFlags::from_bits_truncate(args[2].reinterpret_as_signed().truncate()),
                flags: MapFlags::from_bits_truncate(args[3].reinterpret_as_signed().truncate()),
                fd: args[4].reinterpret_as_signed().truncate(),
                offset: args[5],
            },
            Sysno::mprotect => SyscallRequest::Mprotect {
                addr: Platform::RawMutPointer::from_usize(args[0]),
                length: args[1],
                prot: ProtFlags::from_bits_truncate(args[2].reinterpret_as_signed().truncate()),
            },
            Sysno::munmap => SyscallRequest::Munmap {
                addr: Platform::RawMutPointer::from_usize(args[0]),
                length: args[1],
            },
            Sysno::brk => SyscallRequest::Brk {
                addr: Platform::RawMutPointer::from_usize(args[0]),
            },
            Sysno::mremap => SyscallRequest::Mremap {
                old_addr: Platform::RawMutPointer::from_usize(args[0]),
                old_size: args[1],
                new_size: args[2],
                flags: MRemapFlags::from_bits_truncate(args[3].truncate()),
                new_addr: args[4],
            },
            Sysno::rt_sigprocmask => {
                let how: i32 = args[0].reinterpret_as_signed().truncate();
                if let Ok(how) = SigmaskHow::try_from(how) {
                    SyscallRequest::RtSigprocmask {
                        how,
                        set: if args[1] == 0 {
                            None
                        } else {
                            Some(Platform::RawConstPointer::from_usize(args[1]))
                        },
                        oldset: if args[2] == 0 {
                            None
                        } else {
                            Some(Platform::RawMutPointer::from_usize(args[2]))
                        },
                        sigsetsize: args[3],
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::rt_sigaction => {
                let signum: i32 = args[0].reinterpret_as_signed().truncate();
                if let Ok(signum) = Signal::try_from(signum) {
                    SyscallRequest::RtSigaction {
                        signum,
                        act: if args[1] == 0 {
                            None
                        } else {
                            Some(Platform::RawConstPointer::from_usize(args[1]))
                        },
                        oldact: if args[2] == 0 {
                            None
                        } else {
                            Some(Platform::RawMutPointer::from_usize(args[2]))
                        },
                        sigsetsize: args[3],
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::ioctl => SyscallRequest::Ioctl {
                fd: args[0].reinterpret_as_signed().truncate(),
                arg: {
                    let cmd = args[1].truncate();
                    let arg = args[2];
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
                fd: args[0].reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(args[1]),
                count: args[2],
                offset: args[3].reinterpret_as_signed() as i64,
            },
            #[cfg(target_arch = "x86")]
            Sysno::pread64 => SyscallRequest::Pread64 {
                fd: args[0].reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(args[1]),
                count: args[2],
                offset: args[3].reinterpret_as_signed() as i64
                    | ((args[4].reinterpret_as_signed() as i64) << 32),
            },
            Sysno::readv => SyscallRequest::Readv {
                fd: args[0].reinterpret_as_signed().truncate(),
                iovec: Platform::RawConstPointer::from_usize(args[1]),
                iovcnt: args[2],
            },
            Sysno::writev => SyscallRequest::Writev {
                fd: args[0].reinterpret_as_signed().truncate(),
                iovec: Platform::RawConstPointer::from_usize(args[1]),
                iovcnt: args[2],
            },
            Sysno::access => SyscallRequest::Access {
                pathname: Platform::RawConstPointer::from_usize(args[0]),
                mode: AccessFlags::from_bits_truncate(args[1].reinterpret_as_signed().truncate()),
            },
            Sysno::pipe => SyscallRequest::Pipe2 {
                pipefd: Platform::RawMutPointer::from_usize(args[0]),
                flags: litebox::fs::OFlags::empty(),
            },
            Sysno::pipe2 => SyscallRequest::Pipe2 {
                pipefd: Platform::RawMutPointer::from_usize(args[0]),
                flags: litebox::fs::OFlags::from_bits_truncate(args[1].truncate()),
            },
            Sysno::dup => SyscallRequest::Dup {
                oldfd: args[0].reinterpret_as_signed().truncate(),
                newfd: None,
                flags: None,
            },
            Sysno::dup2 => SyscallRequest::Dup {
                oldfd: args[0].reinterpret_as_signed().truncate(),
                newfd: Some(args[1].reinterpret_as_signed().truncate()),
                flags: None,
            },
            Sysno::dup3 => SyscallRequest::Dup {
                oldfd: args[0].reinterpret_as_signed().truncate(),
                newfd: Some(args[1].reinterpret_as_signed().truncate()),
                flags: Some(litebox::fs::OFlags::from_bits_truncate(args[2].truncate())),
            },
            Sysno::socket => {
                let domain: u32 = args[0].truncate();
                let type_and_flags: u32 = args[1].truncate();
                SyscallRequest::Socket {
                    domain: AddressFamily::try_from(domain).expect("Invalid domain"),
                    ty: SockType::try_from(type_and_flags & 0x0f).expect("Invalid sock type"),
                    flags: SockFlags::from_bits_truncate(type_and_flags & !0x0f),
                    protocol: if args[2] == 0 {
                        None
                    } else {
                        let protocol: u8 = args[2].truncate();
                        Some(Protocol::try_from(protocol).expect("Invalid protocol"))
                    },
                }
            }
            Sysno::connect => SyscallRequest::Connect {
                sockfd: args[0].reinterpret_as_signed().truncate(),
                sockaddr: Platform::RawConstPointer::from_usize(args[1]),
                addrlen: args[2],
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::accept => SyscallRequest::Accept {
                sockfd: args[0].reinterpret_as_signed().truncate(),
                addr: if args[1] == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(args[1]))
                },
                addrlen: if args[2] == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(args[2]))
                },
                flags: SockFlags::empty(),
            },
            Sysno::accept4 => SyscallRequest::Accept {
                sockfd: args[0].reinterpret_as_signed().truncate(),
                addr: if args[1] == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(args[1]))
                },
                addrlen: if args[2] == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(args[2]))
                },
                flags: SockFlags::from_bits_truncate(args[3].truncate()),
            },
            Sysno::sendto => SyscallRequest::Sendto {
                sockfd: args[0].reinterpret_as_signed().truncate(),
                buf: Platform::RawConstPointer::from_usize(args[1]),
                len: args[2],
                flags: litebox::net::SendFlags::from_bits_truncate(args[3].truncate()),
                addr: if args[4] == 0 {
                    None
                } else {
                    Some(Platform::RawConstPointer::from_usize(args[4]))
                },
                addrlen: args[5].truncate(),
            },
            Sysno::recvfrom => SyscallRequest::Recvfrom {
                sockfd: args[0].reinterpret_as_signed().truncate(),
                buf: Platform::RawMutPointer::from_usize(args[1]),
                len: args[2],
                flags: litebox::net::ReceiveFlags::from_bits_truncate(args[3].truncate()),
                addr: if args[4] == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(args[4]))
                },
                addrlen: if args[5] == 0 {
                    None
                } else {
                    Some(Platform::RawMutPointer::from_usize(args[5]))
                },
            },
            Sysno::bind => SyscallRequest::Bind {
                sockfd: args[0].reinterpret_as_signed().truncate(),
                sockaddr: Platform::RawConstPointer::from_usize(args[1]),
                addrlen: args[2],
            },
            Sysno::listen => SyscallRequest::Listen {
                sockfd: args[0].reinterpret_as_signed().truncate(),
                backlog: args[1].truncate(),
            },
            Sysno::setsockopt => {
                let optname = SocketOptionName::from(args[1].truncate(), args[2].truncate());
                if let Some(optname) = optname {
                    SyscallRequest::Setsockopt {
                        sockfd: args[0].reinterpret_as_signed().truncate(),
                        optname,
                        optval: Platform::RawConstPointer::from_usize(args[3]),
                        optlen: args[4],
                    }
                } else {
                    SyscallRequest::Ret(errno::Errno::EINVAL)
                }
            }
            Sysno::exit => SyscallRequest::Exit {
                status: args[0].reinterpret_as_signed().truncate(),
            },
            Sysno::exit_group => SyscallRequest::ExitGroup {
                status: args[0].reinterpret_as_signed().truncate(),
            },
            ::syscalls::Sysno::uname => SyscallRequest::Uname {
                buf: Platform::RawMutPointer::from_usize(args[0]),
            },
            Sysno::fcntl => SyscallRequest::Fcntl {
                fd: args[0].reinterpret_as_signed().truncate(),
                arg: FcntlArg::from(args[1].reinterpret_as_signed().truncate(), args[2]),
            },
            Sysno::getcwd => SyscallRequest::Getcwd {
                buf: Platform::RawMutPointer::from_usize(args[0]),
                size: args[1],
            },
            Sysno::readlink => SyscallRequest::Readlink {
                pathname: Platform::RawConstPointer::from_usize(args[0]),
                buf: Platform::RawMutPointer::from_usize(args[1]),
                bufsiz: args[2],
            },
            Sysno::readlinkat => SyscallRequest::Readlinkat {
                dirfd: args[0].reinterpret_as_signed().truncate(),
                pathname: Platform::RawConstPointer::from_usize(args[1]),
                buf: Platform::RawMutPointer::from_usize(args[2]),
                bufsiz: args[3],
            },
            Sysno::arch_prctl => {
                let code: u32 = args[0].truncate();
                if let Ok(code) = ArchPrctlCode::try_from(code) {
                    let arg = match code {
                        #[cfg(target_arch = "x86_64")]
                        ArchPrctlCode::SetFs => {
                            ArchPrctlArg::SetFs(Platform::RawConstPointer::from_usize(args[1]))
                        }
                        #[cfg(target_arch = "x86_64")]
                        ArchPrctlCode::GetFs => {
                            ArchPrctlArg::GetFs(Platform::RawMutPointer::from_usize(args[1]))
                        }
                        ArchPrctlCode::CETStatus => ArchPrctlArg::CETStatus,
                        ArchPrctlCode::CETDisable => ArchPrctlArg::CETDisable,
                        ArchPrctlCode::CETLock => ArchPrctlArg::CETLock,
                    };
                    SyscallRequest::ArchPrctl { arg }
                } else {
                    todo!("Unsupported arch_prctl syscall: {args:?}")
                }
            }
            Sysno::set_thread_area => SyscallRequest::SetThreadArea {
                user_desc: Platform::RawMutPointer::from_usize(args[0]),
            },
            Sysno::openat => SyscallRequest::Openat {
                dirfd: args[0].reinterpret_as_signed().truncate(),
                pathname: Platform::RawConstPointer::from_usize(args[1]),
                flags: litebox::fs::OFlags::from_bits_truncate(args[2].truncate()),
                mode: litebox::fs::Mode::from_bits_truncate(args[3].truncate()),
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::newfstatat => SyscallRequest::Newfstatat {
                dirfd: args[0].reinterpret_as_signed().truncate(),
                pathname: Platform::RawConstPointer::from_usize(args[1]),
                buf: Platform::RawMutPointer::from_usize(args[2]),
                flags: AtFlags::from_bits_truncate(args[3].reinterpret_as_signed().truncate()),
            },
            Sysno::eventfd => SyscallRequest::Eventfd2 {
                initval: args[0].truncate(),
                flags: EfdFlags::empty(),
            },
            Sysno::eventfd2 => SyscallRequest::Eventfd2 {
                initval: args[0].truncate(),
                flags: EfdFlags::from_bits_truncate(args[1].truncate()),
            },
            Sysno::getrandom => SyscallRequest::GetRandom {
                buf: Platform::RawMutPointer::from_usize(args[0]),
                count: args[1],
                flags: RngFlags::from_bits_truncate(args[2].reinterpret_as_signed().truncate()),
            },
            Sysno::statx | Sysno::io_uring_setup | Sysno::rseq => {
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
    SetFsBase { addr: Platform::RawConstPointer<u8> },
    /// Get the current value of the FS base register and store it in `addr`.
    #[cfg(target_arch = "x86_64")]
    GetFsBase {
        addr: Platform::RawMutPointer<usize>,
    },
    #[cfg(target_arch = "x86")]
    SetThreadArea {
        user_desc: Platform::RawMutPointer<UserDesc>,
    },
}

impl<Platform: litebox::platform::RawPointerProvider> litebox::platform::Punchthrough
    for PunchthroughSyscall<Platform>
{
    type ReturnSuccess = usize;
    type ReturnFailure = errno::Errno;
}

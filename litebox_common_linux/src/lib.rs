//! Common Linux-y items suitable for LiteBox

#![no_std]

use litebox::platform::{RawConstPointer, RawMutPointer};

pub mod errno;

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
            _ => unimplemented!(),
        }
    }
}

/// Linux's `stat` struct
#[repr(C, packed)]
#[derive(Clone, Default)]
pub struct FileStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    __pad0: core::ffi::c_int,
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
    __unused: [i64; 3],
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
            __pad0: 0,
            st_rdev: 0,
            #[allow(clippy::cast_possible_wrap)]
            st_size: size as i64,
            st_blksize: 0,
            st_blocks: 0,
            st_atime: 0,
            st_atime_nsec: 0,
            st_mtime: 0,
            st_mtime_nsec: 0,
            st_ctime: 0,
            st_ctime_nsec: 0,
            __unused: [0; 3],
        }
    }
}

/// Request to syscall handler
#[non_exhaustive]
pub enum SyscallRequest<Platform: litebox::platform::RawPointerProvider> {
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
    Fstat {
        fd: i32,
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
    Pread64 {
        fd: i32,
        buf: Platform::RawMutPointer<u8>,
        count: usize,
        offset: usize,
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
    Getcwd {
        buf: Platform::RawMutPointer<u8>,
        size: usize,
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
}

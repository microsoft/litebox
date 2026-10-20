// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin ABI definitions, independent of the host platform.

#![no_std]

extern crate alloc;

pub mod errno;
pub mod loader;
pub mod mach;
pub mod shared_cache;
pub mod syscall;

pub use litebox::user_pointers;
pub use syscall::SyscallRequest;

/// Return value used by Mach kernel APIs and traps.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernReturn(i32);

impl KernReturn {
    pub const SUCCESS: Self = Self(0);
    pub const INVALID_ADDRESS: Self = Self(1);
    pub const PROTECTION_FAILURE: Self = Self(2);
    pub const NO_SPACE: Self = Self(3);
    pub const INVALID_ARGUMENT: Self = Self(4);
    pub const FAILURE: Self = Self(5);
    pub const RESOURCE_SHORTAGE: Self = Self(6);
    /// `copyin`/`copyout` of a trap argument faulted (`mach_copyin`).
    pub const NO_ACCESS: Self = Self(8);
    pub const MEMORY_ERROR: Self = Self(10);
    pub const NAME_EXISTS: Self = Self(13);
    pub const ABORTED: Self = Self(14);
    pub const INVALID_NAME: Self = Self(15);
    pub const INVALID_TASK: Self = Self(16);
    pub const INVALID_RIGHT: Self = Self(17);
    pub const INVALID_VALUE: Self = Self(18);
    pub const UREFS_OVERFLOW: Self = Self(19);
    pub const INVALID_CAPABILITY: Self = Self(20);
    pub const RIGHT_EXISTS: Self = Self(21);
    pub const INVALID_HOST: Self = Self(22);
    pub const NOT_SUPPORTED: Self = Self(46);
    pub const OPERATION_TIMED_OUT: Self = Self(49);
    pub const DENIED: Self = Self(53);

    pub const fn from_raw(value: i32) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> i32 {
        self.0
    }
}

impl From<KernReturn> for usize {
    fn from(result: KernReturn) -> Self {
        result.raw().cast_unsigned() as Self
    }
}

/// Darwin's sleep-adjusted absolute clock interface.
pub trait MachClock {
    fn mach_absolute_time(&self) -> u64;
    fn mach_timebase_info(&self) -> syscall::MachTimebaseInfo;
    fn mach_wait_until(&self, deadline: u64) -> KernReturn;
}

impl From<KernReturn> for litebox::platform::page_mgmt::AllocationError {
    fn from(result: KernReturn) -> Self {
        match result {
            KernReturn::PROTECTION_FAILURE => Self::PermissionDenied,
            KernReturn::RESOURCE_SHORTAGE => Self::OutOfMemory,
            _ => Self::AddressInUseByPlatform,
        }
    }
}

bitflags::bitflags! {
    /// Mach virtual-memory protections.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmProtection: core::ffi::c_int {
        const READ = object::macho::VM_PROT_READ.cast_signed();
        const WRITE = object::macho::VM_PROT_WRITE.cast_signed();
        const EXECUTE = object::macho::VM_PROT_EXECUTE.cast_signed();
    }
}

bitflags::bitflags! {
    /// Supported Darwin `open` flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenFlags: core::ffi::c_int {
        // This is the absence of WRONLY/RDWR bits; do not test it with `contains`.
        const RDONLY = 0;
        const WRONLY = 0x0001;
        const RDWR = 0x0002;
        const NONBLOCK = 0x0004;
        const APPEND = 0x0008;
        const NOFOLLOW = 0x0100;
        const CREAT = 0x0200;
        const TRUNC = 0x0400;
        const EXCL = 0x0800;
        const NOCTTY = 0x0002_0000;
        const DIRECTORY = 0x0010_0000;
        const CLOEXEC = 0x0100_0000;
        const NOFOLLOW_ANY = 0x2000_0000;
    }
}

bitflags::bitflags! {
    /// Darwin descriptor-local flags.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct FileDescriptorFlags: u32 {
        const FD_CLOEXEC = 1;
    }
}

/// Darwin `struct stat64` (`struct stat` with 64-bit inodes).
#[derive(Clone, Copy, Debug, Default, zerocopy::FromBytes, zerocopy::IntoBytes)]
#[repr(C)]
pub struct Stat64 {
    pub dev: i32,
    pub mode: u16,
    pub nlink: u16,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub rdev: i32,
    pub pad0: u32,
    /// Access, modification, change and birth times (`timespec`).
    pub times: [[i64; 2]; 4],
    pub size: i64,
    pub blocks: i64,
    pub blksize: i32,
    pub flags: u32,
    pub gen_number: u32,
    pub lspare: i32,
    pub qspare: [i64; 2],
}

// The ABI dyld and libSystem read: `struct stat64` from <sys/stat.h>.
const _: () = {
    assert!(size_of::<Stat64>() == 144);
    assert!(core::mem::offset_of!(Stat64, ino) == 8);
    assert!(core::mem::offset_of!(Stat64, uid) == 16);
    assert!(core::mem::offset_of!(Stat64, rdev) == 24);
    assert!(core::mem::offset_of!(Stat64, times) == 32);
    assert!(core::mem::offset_of!(Stat64, size) == 96);
    assert!(core::mem::offset_of!(Stat64, blocks) == 104);
    assert!(core::mem::offset_of!(Stat64, blksize) == 112);
    assert!(core::mem::offset_of!(Stat64, flags) == 116);
    assert!(core::mem::offset_of!(Stat64, qspare) == 128);
};

/// Darwin `S_IF*` file types.
mod file_type {
    pub const CHARACTER_DEVICE: u16 = 0o020_000;
    pub const DIRECTORY: u16 = 0o040_000;
    pub const REGULAR: u16 = 0o100_000;
}

impl TryFrom<&litebox_broker_protocol::fs::FileStatus> for Stat64 {
    type Error = errno::Errno;

    /// LiteBox files have no timestamps, link counts or flags: those read
    /// as zero (one link).
    fn try_from(status: &litebox_broker_protocol::fs::FileStatus) -> Result<Self, Self::Error> {
        use litebox_broker_protocol::fs::FileType;
        let kind = match status.file_type {
            FileType::RegularFile => file_type::REGULAR,
            FileType::Directory => file_type::DIRECTORY,
            FileType::CharacterDevice => file_type::CHARACTER_DEVICE,
            _ => return Err(errno::Errno::EIO),
        };
        let size = i64::try_from(status.size).map_err(|_| errno::Errno::EOVERFLOW)?;
        let blksize = i32::try_from(status.blksize).map_err(|_| errno::Errno::EOVERFLOW)?;
        Ok(Self {
            // dev_t and the 32-bit rdev are truncated like XNU's `stat`.
            dev: litebox::utils::TruncateExt::<u32>::trunc(status.node_info.dev).cast_signed(),
            mode: kind | (status.mode.bits() & 0o7777),
            nlink: 1,
            ino: status.node_info.ino,
            uid: u32::from(status.owner.user),
            gid: u32::from(status.owner.group),
            rdev: status.node_info.rdev.map_or(0, |rdev| {
                litebox::utils::TruncateExt::<u32>::trunc(rdev.get()).cast_signed()
            }),
            size,
            blocks: size.saturating_add(511) / 512,
            blksize,
            ..Self::default()
        })
    }
}

/// Darwin pathname limit, including the terminating NUL.
pub const PATH_MAX: usize = 1024;

bitflags::bitflags! {
    /// Supported Darwin `mmap` flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MmapFlags: core::ffi::c_int {
        const SHARED = 0x0001;
        const PRIVATE = 0x0002;
        const FIXED = 0x0010;
        const ANONYMOUS = 0x1000;
    }
}

/// libSystem's UNIX03 mmap conformance flag. The shim already enforces its
/// nonzero-length, aligned-offset and mapping-kind checks.
pub const MAP_UNIX03: core::ffi::c_int = 0x40000;

/// Native Apple Silicon page size.
pub const PAGE_SIZE: usize = 16384;

/// AArch64 user-stack alignment in bytes.
pub const STACK_ALIGNMENT: usize = 16;

/// Darwin interrupt signal.
pub const SIGINT: i32 = 2;
/// Darwin abort signal.
pub const SIGABRT: i32 = 6;
/// Darwin kill signal.
pub const SIGKILL: i32 = 9;
/// Darwin invalid-memory-reference signal.
pub const SIGSEGV: i32 = 11;

/// Virtual process credentials, not the runner's host identity.
#[derive(Clone, Copy, Debug)]
pub struct TaskParams {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

impl Default for TaskParams {
    fn default() -> Self {
        Self {
            pid: 1,
            ppid: 0,
            uid: 1000,
            euid: 1000,
            gid: 1000,
            egid: 1000,
        }
    }
}

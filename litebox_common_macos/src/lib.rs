// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin ABI definitions, independent of the host platform.

#![no_std]

extern crate alloc;

pub mod errno;
pub mod loader;
pub mod syscall;

// Register storage and user-pointer types are shared; syscall decoding and
// return-value conventions are Darwin-specific.
pub use litebox_common_linux::{PtRegs, user_pointers};
pub use syscall::SyscallRequest;

/// Return value used by Mach kernel APIs and traps.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernReturn(i32);

impl KernReturn {
    pub const SUCCESS: Self = Self(0);
    pub const INVALID_ADDRESS: Self = Self(1);
    pub const PROTECTION_FAILURE: Self = Self(2);
    pub const RESOURCE_SHORTAGE: Self = Self(6);

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
    }
}

bitflags::bitflags! {
    /// Darwin descriptor-local flags.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct FileDescriptorFlags: u32 {
        const FD_CLOEXEC = 1;
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

/// Native Apple Silicon page size.
pub const PAGE_SIZE: usize = 16384;

/// AArch64 user-stack alignment in bytes.
pub const STACK_ALIGNMENT: usize = 16;

/// Darwin interrupt signal.
pub const SIGINT: i32 = 2;
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

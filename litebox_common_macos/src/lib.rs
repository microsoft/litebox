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

/// Native Apple Silicon page size.
pub const PAGE_SIZE: usize = 16384;

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

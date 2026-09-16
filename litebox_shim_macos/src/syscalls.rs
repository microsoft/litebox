// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed BSD process syscall implementations.

use crate::{ShimPlatform, Task};

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_exit(&self, status: i32) {
        self.process.exit(status & 0xff);
    }

    pub(crate) fn sys_getpid(&self) -> i32 {
        self.params.pid
    }
    pub(crate) fn sys_getppid(&self) -> i32 {
        self.params.ppid
    }
    pub(crate) fn sys_getuid(&self) -> u32 {
        self.params.uid
    }
    pub(crate) fn sys_geteuid(&self) -> u32 {
        self.params.euid
    }
    pub(crate) fn sys_getgid(&self) -> u32 {
        self.params.gid
    }
    pub(crate) fn sys_getegid(&self) -> u32 {
        self.params.egid
    }
}

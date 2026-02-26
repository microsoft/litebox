// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS syscall numbers for x86_64
//!
//! On macOS x86_64, syscall numbers are encoded with a class in the upper bits:
//! - UNIX syscalls have class 0x2000000

/// The UNIX syscall class identifier
pub const SYSCALL_CLASS_UNIX: u64 = 0x2000000;

/// exit(int rval)
pub const SYS_EXIT: u64 = SYSCALL_CLASS_UNIX | 1;

/// fork()
pub const SYS_FORK: u64 = SYSCALL_CLASS_UNIX | 2;

/// read(int fd, void *buf, size_t count)
pub const SYS_READ: u64 = SYSCALL_CLASS_UNIX | 3;

/// write(int fd, const void *buf, size_t count)
pub const SYS_WRITE: u64 = SYSCALL_CLASS_UNIX | 4;

/// open(const char *path, int flags, mode_t mode)
pub const SYS_OPEN: u64 = SYSCALL_CLASS_UNIX | 5;

/// close(int fd)
pub const SYS_CLOSE: u64 = SYSCALL_CLASS_UNIX | 6;

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

/// getpid(void)
pub const SYS_GETPID: u64 = SYSCALL_CLASS_UNIX | 20;

/// ioctl(int fd, unsigned long request, ...)
pub const SYS_IOCTL: u64 = SYSCALL_CLASS_UNIX | 54;

/// munmap(void *addr, size_t len)
pub const SYS_MUNMAP: u64 = SYSCALL_CLASS_UNIX | 73;

/// mprotect(void *addr, size_t len, int prot)
pub const SYS_MPROTECT: u64 = SYSCALL_CLASS_UNIX | 74;

/// fcntl(int fd, int cmd, ...)
pub const SYS_FCNTL: u64 = SYSCALL_CLASS_UNIX | 92;

/// gettimeofday(struct timeval *tp, void *tzp)
pub const SYS_GETTIMEOFDAY: u64 = SYSCALL_CLASS_UNIX | 116;

/// mmap(void *addr, size_t len, int prot, int flags, int fd, off_t pos)
pub const SYS_MMAP: u64 = SYSCALL_CLASS_UNIX | 197;

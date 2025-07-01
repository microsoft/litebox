//! The systrap platform relies on seccomp’s `SECCOMP_RET_TRAP` feature to intercept system calls.

/// Certain syscalls with this magic argument are allowed.
/// This is useful for syscall interception where we need to invoke the original syscall.
pub(crate) const SYSCALL_ARG_MAGIC: usize = usize::from_le_bytes(*b"LITE BOX");
pub(crate) const MMAP_FLAG_MAGIC: u32 = 1 << 31;
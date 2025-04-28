//! Implementation of syscall interception for Linux userland.

mod systrap;

pub(crate) use systrap::SYSCALL_ARG_MAGIC;
pub(crate) use systrap::init_sys_intercept;

//! Implementation of syscall interception for Linux userland.

#[cfg(target_arch = "x86_64")]
pub(crate) mod systrap;

#[cfg(target_arch = "x86")]
pub(crate) mod systrap {
    use litebox_common_linux::SyscallRequest;

    pub(crate) const SYSCALL_ARG_MAGIC: u32 = u32::from_le_bytes(*b"LtBx");

    pub(crate) fn init_sys_intercept(
        _handler: impl Fn(SyscallRequest<crate::LinuxUserland>) -> i64 + Send + Sync + 'static,
    ) {
        // TODO: Actually start intercepting syscalls on 32-bit Linux.
        //
        // Temporarily, we are not setting anything up, while getting things compiling onto 32-bit Linux.
    }
}

pub(crate) use systrap::init_sys_intercept;

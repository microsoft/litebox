//! Types and traits implemented by shims, for calling from platforms.

/// An object to initialize a newly spawned platform thread for use with the
/// shim that spawned it.
///
/// This is implemented by the shim for passing to
/// [`ThreadProvider::spawn_thread`](crate::platform::ThreadProvider::spawn_thread).
pub trait InitThread: Send {
    /// Initializes the thread.
    ///
    /// After calling this, the caller must run the thread in the shim until it
    /// exits, or there may be hangs or leaks.
    fn init(self: alloc::boxed::Box<Self>);
}

/// An interface for entering the shim from the platform.
pub trait EnterShim: Send + Sync {
    /// The execution context type passed to the shim.
    ///
    /// FUTURE: use a single per-architecture type for all shims and platforms.
    type ExecutionContext;
    /// The operation the platform should take after returning from the shim.
    ///
    /// FUTURE: use a single per-LiteBox type for all shims and platforms.
    type ContinueOperation;

    /// Handle a syscall.
    ///
    /// The platform should call this in response to `syscall` on x86_64 and
    /// `int 0x80` on x86.
    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> Self::ContinueOperation;

    /// Handle a hardware exception.
    ///
    /// The type of exception information passed depends on the architecture.
    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> Self::ContinueOperation;
}

/// Information about a hardware exception.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Copy, Clone, Debug)]
pub struct ExceptionInfo {
    /// The x86 exception type.
    pub exception: Exception,
    /// The hardware error code associated with the exception.
    pub error_code: u32,
    /// The value of the CR2 register at the time of the exception, if
    /// applicable (e.g., for page faults).
    pub cr2: usize,
}

/// An x86 exception type.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Exception(pub u8);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Exception {
    /// #DE
    pub const DIVIDE_ERROR: Self = Self(0);
    /// #BP
    pub const BREAKPOINT: Self = Self(3);
    /// #UD
    pub const INVALID_OPCODE: Self = Self(6);
    /// #GP
    pub const GENERAL_PROTECTION_FAULT: Self = Self(13);
    /// #PF
    pub const PAGE_FAULT: Self = Self(14);
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Types and traits implemented by shims, for calling from platforms.

/// An object to initialize a newly spawned platform thread for use with the
/// shim that spawned it.
///
/// This is implemented by the shim for passing to
/// [`ThreadProvider::spawn_thread`](crate::platform::ThreadProvider::spawn_thread).
pub trait InitThread: Send {
    /// The execution context type passed to the shim.
    ///
    /// FUTURE: use a single per-architecture type for all shims and platforms.
    type ExecutionContext;

    /// Initializes the thread, returning the shim interface for the new thread.
    #[must_use]
    fn init(
        self: alloc::boxed::Box<Self>,
    ) -> alloc::boxed::Box<dyn crate::shim::EnterShim<ExecutionContext = Self::ExecutionContext>>;
}

/// An interface for entering the shim from the platform.
pub trait EnterShim {
    /// The execution context type passed to the shim.
    ///
    /// FUTURE: use a single per-architecture type for all shims and platforms.
    type ExecutionContext;

    /// Initialize a new thread. Must be called by the platform exactly once
    /// before running the thread in the guest for the first time.
    ///
    /// Shims might use this to capture the thread handle via
    /// [`ThreadProvider::current_thread`] and to validate that the thread is
    /// still needed now that it has had a chance to run.
    ///
    /// This is called both for the initial thread and for any threads created
    /// via [`ThreadProvider::spawn_thread`]. In the latter case, the platform
    /// must first call [`InitThread::init`] on the object provided by the shim
    /// to set up thread local storage. (FUTURE: [`InitThread::init`] should
    /// return `Box<dyn EnterShim>` rather than rely on TLS.)
    ///
    /// [`ThreadProvider::spawn_thread`]:
    ///     crate::platform::ThreadProvider::spawn_thread
    /// [`ThreadProvider::current_thread`]:
    ///     crate::platform::ThreadProvider::current_thread
    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation;

    /// Handle a syscall.
    ///
    /// The platform should call this in response to `syscall` on x86_64 and
    /// `int 0x80` on x86.
    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation;

    /// Handle a hardware exception.
    ///
    /// The type of exception information passed depends on the architecture.
    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation;

    /// Handle an interrupt signaled by
    /// [`ThreadProvider::interrupt_thread`](crate::platform::ThreadProvider::interrupt_thread).
    ///
    /// Note that if another event occurs (e.g., a syscall or exception) while
    /// the thread is interrupted, the platform may just call the corresponding
    /// handler instead of this one.
    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation;

    /// Re-enter a thread of a guest program or library that is already loaded
    /// in memory.
    ///
    /// Unlike [`init`](Self::init), which must be called exactly once before
    /// running the thread in the guest for the first time, `reenter` allows
    /// the platform to enter the loaded program or library repeatedly until
    /// it is torn down.
    ///
    /// This is useful for scenarios such as OP-TEE trusted applications where
    /// the same TA may be invoked multiple times during its lifetime or dynamically
    /// loaded libraries like cryptographic libraries.
    ///
    /// By default, this implementation just exits the thread because `reenter` is
    /// not supported by all shims.
    fn reenter(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        ContinueOperation::Terminate
    }
}

/// The operation to perform after returning from a shim handler
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ContinueOperation {
    /// Resume the interrupted execution.
    Resume,
    /// Terminate the interrupted execution.
    Terminate,
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
    /// Whether the exception occurred in kernel mode (e.g., a demand page
    /// fault during a kernel-mode access to a user-space address).
    pub kernel_mode: bool,
}

/// An x86 exception type.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

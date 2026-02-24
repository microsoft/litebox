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

/// A signal number.
///
/// Signal numbers are 1-based and must be in the range 1–63.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Signal(u32);

impl Signal {
    /// SIGINT (signal 2) — interrupt from keyboard (Ctrl+C).
    pub const SIGINT: Self = Self(2);
    /// SIGALRM (signal 14) — timer signal from `alarm`.
    pub const SIGALRM: Self = Self(14);

    /// Create a `Signal` from a raw signal number.
    ///
    /// Returns `None` if `signum` is outside the valid range 1–63.
    pub const fn from_raw(signum: u32) -> Option<Self> {
        if signum >= 1 && signum <= 63 {
            Some(Self(signum))
        } else {
            None
        }
    }

    /// Returns the raw signal number.
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

/// A set of [`Signal`]s, stored as a 64-bit bitmask.
///
/// Bit `(signum - 1)` is set when signal `signum` is present in the set.
/// Because signal numbers are 1-based and capped at 63, all 63 possible
/// signals fit in a single `u64`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigSet(u64);

impl SigSet {
    /// An empty signal set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns `true` if the set contains no signals.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Adds `signal` to the set.
    pub const fn add(&mut self, signal: Signal) {
        self.0 |= 1 << (signal.0 - 1);
    }

    /// Returns a new set that is `self` with `signal` added.
    #[must_use]
    pub const fn with(self, signal: Signal) -> Self {
        Self(self.0 | (1 << (signal.0 - 1)))
    }

    /// Removes `signal` from the set.
    pub const fn remove(&mut self, signal: Signal) {
        self.0 &= !(1 << (signal.0 - 1));
    }

    /// Returns `true` if the set contains `signal`.
    pub const fn contains(&self, signal: Signal) -> bool {
        (self.0 & (1 << (signal.0 - 1))) != 0
    }

    /// Removes and returns the lowest-numbered signal in the set, or `None`
    /// if empty.
    pub fn pop_lowest(&mut self) -> Option<Signal> {
        if self.0 == 0 {
            return None;
        }
        let bit = self.0.trailing_zeros();
        self.0 &= !(1u64 << bit);
        // bit is 0–62, so bit + 1 is 1–63 — always valid.
        Some(Signal(bit + 1))
    }

    /// Creates a `SigSet` from a raw `u64` bitmask.
    pub const fn from_u64(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns the underlying `u64` bitmask.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Iterator for SigSet {
    type Item = Signal;

    fn next(&mut self) -> Option<Signal> {
        self.pop_lowest()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.0.count_ones() as usize;
        (count, Some(count))
    }
}

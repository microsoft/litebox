// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The underlying platform upon which LiteBox resides.
//!
//! The top-level trait that denotes something is a valid LiteBox platform is [`Provider`]. This
//! trait is merely a collection of subtraits that could be composed independently from various
//! other crates that implement them upon various types.

pub mod common_providers;
pub mod page_mgmt;
pub mod trivial_providers;

#[cfg(test)]
pub(crate) mod mock;

use either::Either;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

pub use page_mgmt::PageManagementProvider;

#[macro_export]
macro_rules! log_println {
    ($platform:expr, $s:expr) => {{
        use $crate::platform::DebugLogProvider as _;
        $platform.debug_log_print($s);
    }};
    ($platform:expr, $($tt:tt)*) => {{
        use core::fmt::Write as _;
        use $crate::platform::DebugLogProvider as _;
        let mut t: arrayvec::ArrayString<8192> = arrayvec::ArrayString::new();
        writeln!(t, $($tt)*).unwrap();
        $platform.debug_log_print(&t);
    }};
}

/// A provider of a platform upon which LiteBox can execute.
///
/// Ideally, a [`Provider`] is zero-sized, and only exists to provide access to functionality
/// provided by it. _However_, most of the provided APIs within the provider act upon an `&self` to
/// allow storage of any useful "globals" within it necessary.
pub trait Provider:
    RawMutexProvider
    + IPInterfaceProvider
    + TimeProvider
    + PunchthroughProvider
    + DebugLogProvider
    + RawPointerProvider
{
}

/// Provider for consuming platform-originating signals.
///
/// Platforms can record signals (e.g., `SIGALRM` from an interval timer) in
/// per-thread storage. The shim should call [`SignalProvider::take_pending_signals`]
/// to consume and forward them before re-entering the guest.
pub trait SignalProvider {
    /// Atomically take all pending platform signals for the current thread,
    /// passing each one to `f`.
    ///
    /// After this call returns, the platform will have no pending signals for
    /// the calling thread (until new signals arrive).
    ///
    /// The default implementation does nothing (no signals).
    fn take_pending_signals(&self, _f: impl FnMut(crate::shim::Signal)) {}
}

/// Thread management provider.
pub trait ThreadProvider: RawPointerProvider {
    /// Execution context for the current thread of the guest program.
    type ExecutionContext;
    /// Error type for [`ThreadProvider::spawn_thread`].
    type ThreadSpawnError: core::error::Error;
    type ThreadHandle: 'static + Send + Sync;

    /// Spawn a new thread with the given entry point.
    ///
    /// `ctx` contains the initial register state, including the entry point and stack pointer.
    ///
    /// `init_thread` provides an object used to initialize the shim on the new thread.
    ///
    /// # Safety
    ///
    /// The context must be valid.
    unsafe fn spawn_thread(
        &self,
        ctx: &Self::ExecutionContext,
        init_thread: alloc::boxed::Box<
            dyn crate::shim::InitThread<ExecutionContext = Self::ExecutionContext>,
        >,
    ) -> Result<(), Self::ThreadSpawnError>;

    /// Returns a handle to the current thread, which can be used to interrupt
    /// it later.
    ///
    /// # Panics
    /// May panic if called outside the platform's call to one of the
    /// [`EnterShim`] methods.
    ///
    /// [`EnterShim`]: crate::shim::EnterShim
    fn current_thread(&self) -> Self::ThreadHandle;

    /// Interrupt the given thread from running guest code.
    ///
    /// Ensures that one of the [`EnterShim`] methods ([`EnterShim::interrupt`]
    /// if no other guest exit is concurrently in progress) is called on the
    /// thread as soon as possible, interrupting currently running guest code if
    /// needed.
    ///
    /// [`EnterShim`]: crate::shim::EnterShim
    /// [`EnterShim::interrupt`]: crate::shim::EnterShim::interrupt
    fn interrupt_thread(&self, thread: &Self::ThreadHandle);

    /// Schedule a process-wide interrupt after `delay`.
    ///
    /// After `delay` has elapsed, [`EnterShim::interrupt`] should be called on an
    /// arbitrary guest thread so that pending signals such as SIGALRM can be processed.
    ///
    /// A zero `delay` is a no-op.
    ///
    /// This is a best-effort operation. The default implementation does
    /// nothing, meaning the signal will only be delivered when a thread next
    /// enters the shim via a syscall or exception. Platforms that support
    /// timer-based interruption should override this method.
    ///
    /// [`EnterShim::interrupt`]: crate::shim::EnterShim::interrupt
    fn schedule_interrupt(&self, _delay: core::time::Duration) {
        // Default: no-op. The alarm will be checked on the next syscall entry.
    }
}

/// Punch through any functionality for a particular platform that is not explicitly part of the
/// common _shared_ platform interface.
///
/// The punchthrough primarily exists to improve auditability, rather than preventing arbitrary
/// calls outside of the common interface, since it is impossible in Rust to prevent arbitrary
/// external calls. Thus, it should not be thought of as a security boundary. However, this should
/// be treated closer to "if someone is invoking things from the host without passing through a
/// punchthrough, their code is suspicious; if all host invocations pass through the punchthrough,
/// then it is sufficient to audit the punchthrough interface".
pub trait PunchthroughProvider {
    type PunchthroughToken<'a>: PunchthroughToken;
    /// Give permission token to invoke `punchthrough`, possibly after checking that it is ok.
    ///
    /// Even though `&self` is taken shared, the intention with the tokens is to use them
    /// _immediately_ before invoking other platform interactions. Ideally, we would ensure this via
    /// an `&mut self` to guarantee exclusivity, but this would limit us from supporting the ability
    /// for other threads being blocked when a punchthrough is done. Thus, this is kept as a
    /// `&self`. Morally this should be viewed as a `&mut self`.
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>>;
}

/// A token that demonstrates that the platform is allowing access for a particular [`Punchthrough`]
/// to occur (at that point, or at some indeterminate point in the future).
pub trait PunchthroughToken {
    type Punchthrough: Punchthrough;
    /// Consume the token, and invoke the underlying punchthrough that it represented.
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    >;
}

/// Punchthrough support allowing access to functionality not captured by [`Provider`].
///
/// Ideally, this is implemented by a (possibly `#[non_exhaustive]`) enum where a platform
/// provider can mark any unsupported/unimplemented punchthrough functionality with a
/// [`PunchthroughError::Unsupported`] or [`PunchthroughError::Unimplemented`].
///
/// The `Token` allows for obtaining permission from (and possibly, mutable access to) the platform
pub trait Punchthrough {
    type ReturnSuccess;
    type ReturnFailure: core::error::Error;
}

/// Possible errors for a [`Punchthrough`]
#[derive(Error, Debug)]
pub enum PunchthroughError<E: core::error::Error> {
    #[error("attempted to execute unsupported punchthrough")]
    Unsupported,
    #[error("punchthrough for `{0}` is not implemented")]
    Unimplemented(&'static str),
    #[error(transparent)]
    Failure(#[from] E),
}

/// An error-implementing [`Either`]-style type.
#[derive(Error, Debug)]
pub enum EitherError<L: core::error::Error, R: core::error::Error> {
    #[error(transparent)]
    Left(L),
    #[error(transparent)]
    Right(R),
}

// To support easily composing punchthroughs, it is implemented on the `Either` type on
// punchthroughs. An implementation of punchthrough could follow a similar implementation to
// obtain easy internal composability, but composing across crates providing punchthroughs is
// likely best provided using this `Either` based composition.
impl<L, R> PunchthroughToken for Either<L, R>
where
    L: PunchthroughToken,
    R: PunchthroughToken,
{
    type Punchthrough = Either<L::Punchthrough, R::Punchthrough>;

    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        match self {
            Either::Left(l) => match l.execute() {
                Ok(res) => Ok(Either::Left(res)),
                Err(PunchthroughError::Unsupported) => Err(PunchthroughError::Unsupported),
                Err(PunchthroughError::Unimplemented(e)) => {
                    Err(PunchthroughError::Unimplemented(e))
                }
                Err(PunchthroughError::Failure(e)) => {
                    Err(PunchthroughError::Failure(EitherError::Left(e)))
                }
            },
            Either::Right(r) => match r.execute() {
                Ok(res) => Ok(Either::Right(res)),
                Err(PunchthroughError::Unsupported) => Err(PunchthroughError::Unsupported),
                Err(PunchthroughError::Unimplemented(e)) => {
                    Err(PunchthroughError::Unimplemented(e))
                }
                Err(PunchthroughError::Failure(e)) => {
                    Err(PunchthroughError::Failure(EitherError::Right(e)))
                }
            },
        }
    }
}

impl<L, R> Punchthrough for Either<L, R>
where
    L: Punchthrough,
    R: Punchthrough,
{
    type ReturnSuccess = Either<L::ReturnSuccess, R::ReturnSuccess>;
    type ReturnFailure = EitherError<L::ReturnFailure, R::ReturnFailure>;
}

/// A provider of raw mutexes
pub trait RawMutexProvider {
    type RawMutex: RawMutex;
}

/// A raw mutex/lock API; expected to roughly match (or even be implemented using) a Linux futex.
pub trait RawMutex: Send + Sync + 'static {
    /// The initial value for a raw mutex, with an underlying atomic with a
    /// value of zero.
    const INIT: Self;

    /// Returns a reference to the underlying atomic value
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32;

    /// Wake up `n` threads blocked on on this raw mutex.
    ///
    /// Returns the number of waiters that were woken up.
    fn wake_many(&self, n: usize) -> usize;

    /// Wake up one thread blocked on this raw mutex.
    ///
    /// Returns true if this actually woke up such a thread, or false if no thread was waiting on this raw mutex.
    fn wake_one(&self) -> bool {
        self.wake_many(1) > 0
    }

    /// Wake up all threads that are blocked on this raw mutex.
    ///
    /// Returns the number of waiters that were woken up.
    fn wake_all(&self) -> usize {
        self.wake_many(i32::MAX as usize)
    }

    /// If the underlying value is `val`, block until a wake operation wakes us up.
    ///
    /// Importantly, a wake operation does NOT guarantee that the underlying value has changed; it
    /// only means that a wake operation has occurred. However, an [`ImmediatelyWokenUp`] means that
    /// the value had changed _before_ it went to sleep.
    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp>;

    /// If the underlying value is `val`, block until a wake operation wakes us up, or some `time`
    /// has passed without a wake operation having occurred.
    ///
    /// See comment on [`Self::block`] for more details on underlying value.
    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp>;
}

/// A zero-sized struct indicating that the block was immediately unblocked (due to non-matching
/// value).
pub struct ImmediatelyWokenUp;

/// Named-boolean to indicate whether [`RawMutex::block_or_timeout`] was woken up or timed out.
#[must_use]
pub enum UnblockedOrTimedOut {
    /// Unblocked by a wake call
    Unblocked,
    /// Sufficient time elapsed without a wake call
    TimedOut,
}

/// An IP packet interface to the outside world.
///
/// This could be implemented via a `read`/`write` to a TUN device.
pub trait IPInterfaceProvider {
    /// Send the IP packet.
    ///
    /// Returns `Ok(())` when entire packet is sent, or a [`SendError`] if it is unable to send the
    /// entire packet.
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), SendError>;

    /// Receive an IP packet into `packet`.
    ///
    /// Returns size of packet received, or a [`ReceiveError`] if unable to receive an entire
    /// packet.
    fn receive_ip_packet(&self, packet: &mut [u8]) -> Result<usize, ReceiveError>;
}

/// A non-exhaustive list of errors that can be thrown by [`IPInterfaceProvider::send_ip_packet`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SendError {}

/// A non-exhaustive list of errors that can be thrown by [`IPInterfaceProvider::receive_ip_packet`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ReceiveError {
    #[error("Receive operation would block")]
    WouldBlock,
}

/// An interface to understanding time.
pub trait TimeProvider {
    type Instant: Instant;
    type SystemTime: SystemTime;
    /// Returns an instant corresponding to "now".
    fn now(&self) -> Self::Instant;
    /// Returns the current system time.
    fn current_time(&self) -> Self::SystemTime;
}

/// An opaque measurement of a monotonically nondecreasing clock.
///
/// Notable, the `Instant` is distinct from [`SystemTime`], in that the `Instant` is monotonic, and
/// need not have any relation with "real" time. It does not matter if the world takes a step
/// backwards in time, the `Instant` continues marching forward.
pub trait Instant: Copy + Clone + PartialEq + Eq + PartialOrd + Ord + Send + Sync {
    /// Returns the amount of time elapsed from another instant to this one, or `None` if that
    /// instant is later than this one.
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration>;
    /// Returns the amount of time elapsed from another instant to this one, or zero duration if
    /// that instant is later than this one.
    fn duration_since(&self, earlier: &Self) -> core::time::Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(core::time::Duration::from_secs(0))
    }
    /// Returns a new `Instant` that is the sum of this instant and the provided
    /// duration, or `None` if the resulting instant would overflow.
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self>;
}

/// A measurement of the system clock.
///
/// Notably, the `SystemTime` is distinct from [`Instant`], in that the `SystemTime` need not be
/// monotonic, but instead is the best guess of "real" or "wall clock" time.
pub trait SystemTime: Send + Sync {
    /// An anchor in time corresponding to "1970-01-01 00:00:00 UTC".
    const UNIX_EPOCH: Self;
    /// Returns the amount of time elapsed from an `earlier` point in time to this one. This is
    /// fallible since the clock might have been adjusted backwards in time to before the earlier
    /// point in time was measured; in such a case, it returns an `Err(_)` with the absolute
    /// duration.
    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration>;
}

/// An interface to dumping debug output for tracing purposes.
pub trait DebugLogProvider {
    /// Print `msg` to the debug log
    ///
    /// Newlines are *not* automatically appended to `msg`, thus the caller must make sure to
    /// include newlines if necessary.
    ///
    /// One some platforms, this might be a slow/expensive operation, thus ideally callers of this
    /// should prefer not making a large number of small prints to print a single logical message,
    /// but instead should combine all strings part of a single logical message into a single
    /// `debug_log_print` call.
    fn debug_log_print(&self, msg: &str);
}

/// A common interface for raw pointers, aimed at usage in shims _above_ LiteBox.
///
/// Essentially, these types indicate "user" pointers (which are allowed to be null). Platforms with
/// no meaningful user-kernel separation can use [`trivial_providers::TransparentConstPtr`] and
/// [`trivial_providers::TransparentMutPtr`]. Platforms with meaningful user-kernel separation
/// should define their own `repr(C)` newtype wrappers that perform relevant copying between user
/// and kernel.
pub trait RawPointerProvider {
    type RawConstPointer<T: FromBytes>: RawConstPointer<T>;
    type RawMutPointer<T: FromBytes + IntoBytes>: RawMutPointer<T>;
}

/// A read-only raw pointer, morally equivalent to `*const T`.
///
/// See [`RawPointerProvider`] for details.
pub trait RawConstPointer<T>: Copy + core::fmt::Debug + FromBytes + IntoBytes
where
    T: FromBytes,
{
    /// Get the address of the pointer as a `usize`.
    fn as_usize(&self) -> usize;

    /// Convert a `usize` to a pointer with that address.
    ///
    /// Note: this can have tricky implications on exotic hardware. Implementors of this trait are
    /// encouraged to read about [Exposed
    /// Provenance](https://doc.rust-lang.org/std/ptr/index.html#exposed-provenance).
    fn from_usize(addr: usize) -> Self;

    /// Read the value of the pointer at signed offset from it.
    ///
    /// Returns `None` if the provided pointer is invalid, or such an offset is known (in advance)
    /// to be invalid.
    ///
    /// If `T` is of size 1, 2, 4, or (on 64-bit platforms) 8 bytes, and the pointer is aligned,
    /// then this function will perform a relaxed atomic load of the value. Otherwise, the
    /// access pattern is unspecified.
    fn read_at_offset(self, count: isize) -> Option<T>;

    /// Read the pointer as an owned slice of memory.
    ///
    /// Returns `None` if the provided pointer is invalid, or such a slice is known (in advance) to
    /// be invalid.
    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>>;

    /// Read the pointer as an owned C string.
    ///
    /// Returns `None` if the provided pointer is invalid, or such a string is known (in advance) to
    /// be invalid.
    fn to_cstring(self) -> Option<alloc::ffi::CString>
    where
        T: core::cmp::PartialEq<core::ffi::c_char>,
        Self: RawConstPointer<core::ffi::c_char>,
    {
        use alloc::boxed::Box;
        use alloc::vec::Vec;
        use core::ffi::c_char;
        let nul_position = {
            let mut i = 0isize;
            while <Self as RawConstPointer<c_char>>::read_at_offset(self, i)? != 0 {
                i = i.checked_add(1)?;
            }
            i
        };
        let len = nul_position.checked_add(1)?.try_into().ok()?;
        let bytes: Box<[c_char]> = self.to_owned_slice(len)?;
        // Doing a direct transmute of `Box<[c_char]>` to `Box<[u8]>` may not be guaranteed to be
        // safe (it probably is fine, but the following sequence of steps ensures we are
        // staying in a very safe subset).
        let bytes: *mut [c_char] = Box::into_raw(bytes);
        let bytes: *mut [u8] = bytes as *mut [u8];
        let bytes: Box<[u8]> = unsafe { Box::from_raw(bytes) };
        let bytes: Vec<u8> = Vec::from(bytes);
        alloc::ffi::CString::from_vec_with_nul(bytes).ok()
    }
}

/// A writable raw pointer, morally equivalent to `*mut T`.
///
/// See [`RawPointerProvider`] for details.
///
/// This is a sub-trait of [`RawConstPointer`] in order to support the reading-related functionality
/// on the pointer in addition to the writing-related functionality defined by this trait.
pub trait RawMutPointer<T>: Copy + RawConstPointer<T>
where
    T: FromBytes + IntoBytes,
{
    /// Write the value of the pointer at signed offset from it.
    ///
    /// Returns `None` if the provided pointer is invalid, or such an offset is known (in advance)
    /// to be invalid.
    #[must_use]
    fn write_at_offset(self, count: isize, value: T) -> Option<()>;

    /// Write a slice of values at the given offset.
    ///
    /// Returns `None` if the provided pointer is invalid, or if the specified offset is known (in
    /// advance) to be invalid; in that case there are no guarantees about how many values — if any —
    /// have been written.
    #[must_use]
    fn write_slice_at_offset(self, count: isize, values: &[T]) -> Option<()>
    where
        T: Clone,
    {
        for (offset, v) in (count..).zip(values) {
            self.write_at_offset(offset, v.clone())?;
        }
        Some(())
    }

    /// Obtain a mutable (sub)slice of memory at the pointer, and run `f` upon it.
    ///
    /// Returns `None` (and does not invoke `f`) if the provided pointer is invalid, or such a slice
    /// is known (in advance) to be invalid.
    ///
    /// This function may be a direct access to the underlying slice, or may be a newly allocated
    /// slice that is "flushed" at the end of the execution, depending on the platform. Thus, for
    /// performance reasons, a user of this function ideally invokes with the shortest subslice that
    /// they wish to mutate.
    ///
    /// Note: if `f` panics, there is no guarantee that the memory is left unchanged.
    #[must_use]
    #[deprecated = "will be removed in the future, do not use this"]
    fn mutate_subslice_with<R>(
        self,
        range: impl core::ops::RangeBounds<isize>,
        f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R>;

    /// Copy in a slice at the pointer offset.
    ///
    /// Returns `None` without copying if the provided pointer is invalid, or such a slice is known
    /// (in advance) to be invalid.
    ///
    /// This is essentially just a convenience wrapper around [`Self::mutate_subslice_with`], that
    /// makes it easier to notice and prevent some hazards that can come from
    /// `mutate_subslice_with`, by making sure kernel buffers are used before copying things in.
    #[must_use]
    fn copy_from_slice(self, start_offset: usize, buf: &[T]) -> Option<()>
    where
        T: Copy,
    {
        let start: isize = start_offset.try_into().ok()?;
        let end = start.checked_add_unsigned(buf.len())?;
        #[allow(deprecated)]
        self.mutate_subslice_with(start..end, |x| {
            debug_assert_eq!(x.len(), buf.len());
            x.copy_from_slice(buf);
        })
    }
}

/// A non-exhaustive list of errors that can be thrown by [`StdioProvider::read_from_stdin`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StdioReadError {
    #[error("input stream has been closed")]
    Closed,
}

/// A non-exhaustive list of errors that can be thrown by [`StdioProvider::write_to`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StdioWriteError {
    #[error("output stream has been closed")]
    Closed,
}

/// Possible standard output/error streams
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StdioOutStream {
    /// Standard output
    Stdout,
    /// Standard error
    Stderr,
}

/// Possible standard input/output streams
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StdioStream {
    /// Standard input
    Stdin = 0,
    /// Standard output
    Stdout = 1,
    /// Standard error
    Stderr = 2,
}

/// A provider of standard input/output functionality.
pub trait StdioProvider {
    /// Read from standard input. Returns number of bytes read.
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, StdioReadError>;

    /// Write to stdout/stderr. Returns number of bytes written.
    fn write_to(&self, stream: StdioOutStream, buf: &[u8]) -> Result<usize, StdioWriteError>;

    /// Check if a stream is connected to a TTY.
    fn is_a_tty(&self, stream: StdioStream) -> bool;
}

/// A provider for system information.
pub trait SystemInfoProvider {
    /// Returns the address of the syscall entry point for the platform.
    ///
    /// The entry point address is typically used by the runtime or kernel to save/restore
    /// execution context and transfer control to the syscall handler.
    fn get_syscall_entry_point(&self) -> usize;

    /// Get the address of the VDSO (Virtual Dynamic Shared Object).
    ///
    /// Return `Some(address)` if the VDSO is available on the platform, or `None`
    /// if the platform does not support or provide a VDSO.
    fn get_vdso_address(&self) -> Option<usize>;
}

/// A provider for thread-local storage.
///
/// Currently, this provides just a single thread-local storage pointer. Shims
/// should use [`shim_thread_local!`](crate::shim_thread_local) macro for a safe
/// and ergonomic interface to TLS.
///
/// # Safety
/// The implementation must ensure that the TLS pointer that is set for the
/// thread (via `replace_thread_local_storage`) is the one that is returned, and
/// that [`null_mut()`](core::ptr::null_mut) is returned if no TLS pointer has
/// been set.
pub unsafe trait ThreadLocalStorageProvider {
    /// Gets the current thread-local storage pointer that was set with the most
    /// recent call to `replace_thread_local_storage`. If
    /// `replace_thread_local_storage` was never called, this function must
    /// return [`null_mut()`](core::ptr::null_mut).
    ///
    // DEVNOTE: note that this does not take `&self`. So far, this has not been
    // a problem for platform implementations, and allowing this does improve
    // performance by avoiding a platform lookup on every TLS access. But we
    // could consider changing this in the future if needed.
    fn get_thread_local_storage() -> *mut ();

    /// Replaces the current thread-local storage pointer with `value`,
    /// returning the previous value.
    ///
    /// The initial value for a thread is [`null_mut()`](core::ptr::null_mut).
    ///
    /// # Safety
    /// The caller must cooperate with other users of this function to ensure
    /// that the TLS pointer is not replaced with an invalid pointer.
    ///
    /// This can be achieved by using
    /// [`shim_thread_local!`](crate::shim_thread_local).
    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut ();

    /// Clear any guest thread-local storage state for the current thread.
    ///
    /// This is used to help emulate certain syscalls (e.g., `execve`) that clear TLS.
    ///
    /// TODO: move this to a separate trait or eliminate.
    fn clear_guest_thread_local_storage(#[cfg(target_arch = "x86")] _selector: u16) {
        unimplemented!()
    }
}

/// A provider of cryptographically-secure random data.
///
/// The purpose of this provider is to allow LiteBox code to efficiently
/// generate cryptographically-secure random bytes. This must be an infallible
/// operation, with no possibility of failure, blocking, or returning
/// low-quality randomness. The implementation must ensure that the CRNG is
/// appropriately initialized and seeded by the time this method can be called.
///
/// Beyond that, the precise behavior and implementation is platform specific,
/// and in general these methods should pass through to the platform's native
/// cryptographic RNG API when one exists.
///
/// **Caution**: it may be tempting to write an non-passthrough implementation
/// of this method, perhaps for efficiency reasons, seeding a CRNG algorithm's
/// state from the platform's kernel CRNG or other trusted sources. Don't do
/// this! Implementing this correctly as anything other than a direct
/// passthrough is highly non-trivial, especially in the presence of `fork()`
/// and VM snapshots. Only the native platform has enough visibility to get this
/// right.
///
/// If you _are_ implementing a native platform, without an available CRNG to
/// leverage, then be sure to take such details into account.
///
/// See [this Linux kernel patch series][1] for more details of the kinds of
/// issues involved.
///
/// [1]: https://lore.kernel.org/all/20240703183115.1075219-1-Jason@zx2c4.com/
pub trait CrngProvider {
    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// This may take a long time for large buffers. Consider calling this
    /// multiple times, checking for interrupts between calls, if you need to
    /// fill a very large buffer.
    ///
    /// # Panics
    /// Panics if unable to fill the buffer with random bytes. This is
    /// considered a fatal error--LiteBox code is not expected to handle such
    /// failures.
    fn fill_bytes_crng(&self, buf: &mut [u8]);
}

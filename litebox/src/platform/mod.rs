// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The underlying platform upon which LiteBox resides.
//!
//! The top-level trait that denotes something is a valid LiteBox platform is [`Provider`]. This
//! trait is merely a collection of subtraits that could be composed independently from various
//! other crates that implement them upon various types.

pub mod address_space;
pub mod common_providers;
pub mod page_mgmt;
pub mod trivial_providers;

#[cfg(test)]
pub(crate) mod mock;

use either::Either;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

pub use address_space::AddressSpaceProvider;
pub use page_mgmt::PageManagementProvider;

#[macro_export]
macro_rules! log_println {
    ($platform:expr, $s:expr) => {{
        #[allow(unused_imports)]
        use $crate::platform::DebugLogProvider as _;
        $platform.debug_log_print($s);
    }};
    ($platform:expr, $($tt:tt)*) => {{
        use core::fmt::Write as _;
        #[allow(unused_imports)]
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
    + RawMessageProvider
    + TimeProvider
    + PunchthroughProvider
    + DebugLogProvider
    + ThreadIdentityProvider
    + RawPointerProvider
    + AddressSpaceProvider
{
}

/// Provides a cheap identity for the current host thread.
pub trait ThreadIdentityProvider {
    /// Returns an identifier that is stable for the calling thread while it is
    /// running and distinct from other concurrently-running threads.
    fn current_thread_id(&self) -> usize;
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

    /// Runs `f` on the current thread after performing any platform-specific
    /// thread registration needed for [`current_thread`](Self::current_thread)
    /// and related functionality to work.
    ///
    /// This is intended for test threads that do not go through the normal
    /// [`spawn_thread`](Self::spawn_thread) / guest entry path. The platform
    /// sets up thread state before calling `f` and tears it down afterward.
    ///
    /// The default implementation simply calls `f()` with no additional setup.
    /// Platforms that require explicit thread registration should override this.
    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
}

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum TimerCreationError {
    #[error("The platform does not support timers at all.")]
    Unsupported,
}

/// Timer support for proactive signal delivery.
pub trait TimerProvider {
    /// The timer handle type.
    type TimerHandle: TimerHandle;
    /// The signal type delivered by timers.
    type Signal;

    /// Create a new one-shot timer that delivers `signal` when it fires.
    ///
    /// By default, this returns an error indicating that timers are not supported.
    /// Platforms that support it should overwrite this.
    #[expect(unused_variables, reason = "returns an error by default")]
    fn create_timer(&self, signal: Self::Signal) -> Result<Self::TimerHandle, TimerCreationError> {
        Err(TimerCreationError::Unsupported)
    }
}

/// A handle to a platform timer created by [`TimerProvider::create_timer`].
pub trait TimerHandle: Sized {
    /// Arm (or re-arm) the timer to fire after `duration` elapses.
    ///
    /// If the timer is already armed, the previous deadline is replaced.
    /// A zero duration cancels the timer without firing.
    fn set_timer(&self, duration: core::time::Duration);

    /// Delete the timer.
    fn delete_timer(self) {}
}

/// Provider for consuming platform-originating signals.
///
/// Platforms can record signals (e.g., `SIGINT`) and the shim should call
/// [`SignalProvider::take_pending_signals`] to consume them.
pub trait SignalProvider {
    /// The signal type produced by this platform.
    type Signal;

    /// Atomically take all pending asynchronous signals (e.g., SIGINT and SIGALRM)
    /// for the current thread, passing each one to `f`.
    ///
    /// Platforms that support asynchronous signals should override this method.
    #[expect(unused_variables, reason = "no-op by default")]
    fn take_pending_signals(&self, f: impl FnMut(Self::Signal)) {}
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

    /// Updates the waker for the current thread's interruptible wait.
    ///
    /// Called by `WaitContext::start_wait` with `Some(waker)` when the current thread
    /// enters an interruptible wait, and by `WaitContext::end_wait` with
    /// `None` when it leaves. The thread in an interruptible wait can be unblocked
    /// by [`Waker::wake`].
    ///
    /// This is a no-op by default.
    ///
    /// [`Waker::wake`]: crate::event::wait::Waker::wake
    #[expect(unused_variables)]
    fn update_waker(&self, waker: Option<crate::event::wait::Waker<Self>>)
    where
        Self: crate::sync::RawSyncPrimitivesProvider + Sized,
    {
    }
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

    /// Send a port-listen control message (LBPL) to the broker to register
    /// or unregister interest in a TCP port for inbound connections.
    ///
    /// The message format is: `[0x00, b'P', b'L', port_hi, port_lo, action]`
    /// where action is 1 for listen and 0 for unlisten.
    ///
    /// The default implementation is a no-op (platforms without a broker).
    fn send_port_listen_notification(&self, _port: u16, _listen: bool) -> Result<(), SendError> {
        Ok(())
    }

    /// Send a port-listen transfer control message (LBPL action 2) to the broker.
    /// The default implementation is a no-op (platforms without a broker).
    fn send_port_listen_transfer(&self, _port: u16) -> Result<(), SendError> {
        Ok(())
    }

    /// Diagnostic callback: smoltcp generated a RST packet.
    /// Called from TxToken with the pre-poll TCP socket state.
    /// Default is no-op; overridden by platforms that can log.
    fn on_rst_transmitted(
        &self,
        _src_port: u16,
        _dst_port: u16,
        _tcp_count: u16,
        _listen_count: u16,
        _listen_ports: &[u16],
        _listen_addrs: &[u8],
    ) {
    }

    /// Diagnostic callback: a TCP listen socket was added or removed.
    /// `caller` is a short tag identifying which code path triggered this.
    /// Default is no-op.
    fn on_listen_socket_change(&self, _port: u16, _added: bool, _total_tcp: u16, _caller: &str) {}

    /// Diagnostic: called when close_handle destroys a listen socket.
    /// Platforms can panic or trigger a debugger break to get a backtrace.
    fn on_listen_socket_destroyed(&self, _port: u16) {}
}

/// A non-exhaustive list of errors that can be thrown by [`IPInterfaceProvider::send_ip_packet`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SendError {
    /// The underlying device returned an I/O error. The packet was not sent.
    #[error("I/O error on send: errno {0}")]
    Io(i32),
}

/// A non-exhaustive list of errors that can be thrown by [`IPInterfaceProvider::receive_ip_packet`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ReceiveError {
    #[error("Receive operation would block")]
    WouldBlock,
    #[error("IPC protocol error: oversized frame")]
    ProtocolError,
    #[error("Channel closed (EOF)")]
    Eof,
}

/// A raw byte-stream channel for direct message passing between the guest and
/// the broker (bypassing the IP network stack).
///
/// When available, this provides a fast path for protocols like 9P that would
/// otherwise pay the overhead of traversing two smoltcp stacks.
///
/// The default implementation returns [`ReceiveError::WouldBlock`] /
/// [`SendError::Io`], indicating the channel is not available.  Platforms that
/// support direct messaging override these methods.
pub trait RawMessageProvider {
    /// Send bytes to the broker over the raw channel.
    ///
    /// Returns `Ok(n)` with the number of bytes sent, or an error.
    fn send_raw_message(&self, _data: &[u8]) -> Result<usize, SendError> {
        Err(SendError::Io(0))
    }

    /// Receive bytes from the broker over the raw channel.
    ///
    /// Returns `Ok(n)` with the number of bytes read into `buf`, or
    /// [`ReceiveError::WouldBlock`] if no data is available yet.
    fn recv_raw_message(&self, _buf: &mut [u8]) -> Result<usize, ReceiveError> {
        Err(ReceiveError::WouldBlock)
    }
}

/// An interface to understanding time.
pub trait TimeProvider {
    type Instant: Instant;
    type SystemTime: SystemTime;
    /// Returns an instant corresponding to "now".
    fn now(&self) -> Self::Instant;
    /// Returns the current system time.
    fn current_time(&self) -> Self::SystemTime;

    /// Returns a process-independent monotonic timestamp when the platform can
    /// expose one. The epoch is unspecified; callers may only compare values
    /// from the same host clock to measure elapsed time.
    fn monotonic_timestamp(&self) -> Option<core::time::Duration> {
        let _ = self;
        None
    }
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
    /// Print `msg` to the debug log (typically stderr).
    ///
    /// Newlines are *not* automatically appended to `msg`, thus the caller must make sure to
    /// include newlines if necessary.
    ///
    /// One some platforms, this might be a slow/expensive operation, thus ideally callers of this
    /// should prefer not making a large number of small prints to print a single logical message,
    /// but instead should combine all strings part of a single logical message into a single
    /// `debug_log_print` call.
    fn debug_log_print(&self, msg: &str);

    /// Write `msg` to an arbitrary host file descriptor.
    ///
    /// Used by the audit log to write events directly to a log file without
    /// going through stderr. Returns `false` if the platform doesn't support
    /// fd-targeted writes (default).
    fn debug_log_write_to_fd(&self, _fd: i32, _msg: &str) -> bool {
        false
    }
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
    #[error("input would block")]
    WouldBlock,
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

/// A non-exhaustive list of errors from terminal operations on [`StdioProvider`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StdioIoctlError {
    /// The fd is not a terminal (ENOTTY).
    #[error("not a terminal")]
    NotATerminal,
    /// The operation failed with an OS error code (errno on Linux, mapped
    /// equivalent on other platforms).
    #[error("ioctl failed: {0}")]
    OsError(i32),
}

/// Platform-agnostic terminal attributes, mirroring the fields of Linux
/// `struct termios`.
///
/// The guest always runs Linux binaries and speaks the Linux terminal ABI.
/// Platform implementations fill this struct using their native APIs (e.g.,
/// direct ioctl forwarding on Linux, `GetConsoleMode`/`SetConsoleMode` on
/// Windows).
#[derive(Debug, Clone)]
pub struct TerminalAttributes {
    /// Input mode flags.
    pub c_iflag: u32,
    /// Output mode flags.
    pub c_oflag: u32,
    /// Control mode flags.
    pub c_cflag: u32,
    /// Local mode flags.
    pub c_lflag: u32,
    /// Line discipline (typically `0` for `N_TTY`).
    pub c_line: u8,
    /// Control characters.
    pub c_cc: [u8; 19],
}

// Terminal attribute flag constants.
const TERMATTR_ECHO: u32 = 0x0008;
const TERMATTR_ICRNL: u32 = 0x0100;
const TERMATTR_OPOST: u32 = 0x0001;
const TERMATTR_ONLCR: u32 = 0x0004;

impl TerminalAttributes {
    /// Default terminal attributes matching a freshly opened Linux PTY.
    ///
    /// These are realistic values that satisfy terminal detection in programs
    /// such as Node.js Ink. **All-zero termios causes such programs to reject
    /// the terminal silently.**
    pub fn new_default() -> Self {
        Self {
            c_iflag: 0x6d02, // ICRNL | IXON | IXANY | IMAXBEL | IUTF8
            c_oflag: 0x0005, // OPOST | ONLCR
            c_cflag: 0x04bf, // CS8 | CREAD | CLOCAL | B38400
            c_lflag: 0x8a3b, // ECHO | ECHOE | ECHOK | ISIG | ICANON | IEXTEN | ECHOCTL | ECHOKE
            c_line: 0,       // N_TTY
            c_cc: [
                0x03, 0x1c, 0x7f, 0x15, 0x04, 0x00, 0x01, 0x00, 0x11, 0x13, 0x1a, 0xff, 0x12, 0x0f,
                0x17, 0x16, 0xff, 0x00, 0x00,
            ],
        }
    }

    /// Returns `true` if the `ECHO` local flag is set.
    pub fn echo_enabled(&self) -> bool {
        self.c_lflag & TERMATTR_ECHO != 0
    }

    /// Returns `true` if the `ICRNL` input flag is set.
    pub fn icrnl_enabled(&self) -> bool {
        self.c_iflag & TERMATTR_ICRNL != 0
    }

    /// Returns `true` if output post-processing with newline translation
    /// (`OPOST | ONLCR`) is enabled.
    pub fn onlcr_enabled(&self) -> bool {
        (self.c_oflag & TERMATTR_OPOST != 0) && (self.c_oflag & TERMATTR_ONLCR != 0)
    }
}

/// Platform-agnostic terminal window size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSize {
    /// Number of rows (height in characters).
    pub rows: u16,
    /// Number of columns (width in characters).
    pub cols: u16,
    /// Horizontal size in pixels (informational, often zero).
    pub xpixel: u16,
    /// Vertical size in pixels (informational, often zero).
    pub ypixel: u16,
}

/// When to apply terminal attribute changes, corresponding to POSIX
/// `tcsetattr()` actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTermiosWhen {
    /// Apply immediately (Linux `TCSETS`).
    Now,
    /// Drain output first, then apply (Linux `TCSETSW`).
    AfterDrain,
    /// Drain output first, flush pending input, then apply (Linux `TCSETSF`).
    AfterDrainFlushInput,
}

/// A provider of standard input/output functionality.
pub trait StdioProvider {
    /// Read from standard input. Returns number of bytes read.
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, StdioReadError>;

    /// Read from standard input without blocking.
    ///
    /// Platforms with exact nonblocking stdin support should override this
    /// instead of emulating it with a separate readiness probe.
    fn read_from_stdin_nonblocking(&self, buf: &mut [u8]) -> Result<usize, StdioReadError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.poll_stdin_readable() {
            return Err(StdioReadError::WouldBlock);
        }
        self.read_from_stdin(buf)
    }

    /// Write to stdout/stderr. Returns number of bytes written.
    fn write_to(&self, stream: StdioOutStream, buf: &[u8]) -> Result<usize, StdioWriteError>;

    /// Check if a stream is connected to a TTY.
    fn is_a_tty(&self, stream: StdioStream) -> bool;

    /// Get the terminal attributes for a stdio stream.
    ///
    /// On Linux, this forwards `TCGETS` to the host kernel. On Windows, this
    /// returns stored attributes (initialized with realistic defaults).
    ///
    /// The default implementation returns [`StdioIoctlError::NotATerminal`].
    fn get_terminal_attributes(
        &self,
        _stream: StdioStream,
    ) -> Result<TerminalAttributes, StdioIoctlError> {
        Err(StdioIoctlError::NotATerminal)
    }

    /// Set the terminal attributes for a stdio stream.
    ///
    /// On Linux, this forwards `TCSETS`/`TCSETSW`/`TCSETSF` to the host
    /// kernel. On Windows, this stores the attributes and translates key flags
    /// (e.g., `ECHO`, `ICANON`) to `SetConsoleMode` calls.
    ///
    /// The default implementation returns [`StdioIoctlError::NotATerminal`].
    fn set_terminal_attributes(
        &self,
        _stream: StdioStream,
        _attrs: &TerminalAttributes,
        _when: SetTermiosWhen,
    ) -> Result<(), StdioIoctlError> {
        Err(StdioIoctlError::NotATerminal)
    }

    /// Get the terminal window size for a stdio stream.
    ///
    /// On Linux, this forwards `TIOCGWINSZ` to the host kernel. On Windows,
    /// this queries `GetConsoleScreenBufferInfo` or returns a stored override.
    ///
    /// The default implementation returns [`StdioIoctlError::NotATerminal`].
    fn get_window_size(&self, _stream: StdioStream) -> Result<WindowSize, StdioIoctlError> {
        Err(StdioIoctlError::NotATerminal)
    }

    /// Get the number of input bytes currently readable from a terminal stream.
    ///
    /// On Linux, this forwards `FIONREAD` to the host kernel. Platforms that
    /// do not support terminal input-queue queries may return
    /// [`StdioIoctlError::NotATerminal`].
    fn get_terminal_input_bytes(&self, _stream: StdioStream) -> Result<u32, StdioIoctlError> {
        Err(StdioIoctlError::NotATerminal)
    }

    /// Set the terminal window size for a stdio stream.
    ///
    /// On Linux, this forwards `TIOCSWINSZ` to the host kernel. On other
    /// platforms, this stores the size so that subsequent `get_window_size`
    /// calls return the stored value (the actual console is not resized).
    ///
    /// The default implementation returns [`StdioIoctlError::NotATerminal`].
    fn set_window_size(
        &self,
        _stream: StdioStream,
        _size: &WindowSize,
    ) -> Result<(), StdioIoctlError> {
        Err(StdioIoctlError::NotATerminal)
    }

    /// Check if stdin has data available for reading without blocking.
    ///
    /// Returns `true` if a `read()` on stdin would return data immediately.
    /// Used by epoll/poll to report stdin readability. The default returns
    /// `false`.
    fn poll_stdin_readable(&self) -> bool {
        false
    }

    /// Cancel any pending `read_from_stdin()` call, causing it to return
    /// [`StdioReadError::Closed`]. Used during process exit to unblock
    /// threads waiting on stdin. The default is a no-op.
    fn cancel_stdin(&self) {}

    /// Returns the host terminal device identity for stdin, if it is
    /// connected to a real terminal (e.g., a PTY slave like `/dev/pts/156`).
    ///
    /// Used to report correct device info in guest-visible `fstat()` and
    /// `readlink("/proc/self/fd/0")`, so that runtimes like Bun/libuv can
    /// discover and reopen the controlling terminal by its actual device path.
    ///
    /// The returned `st_dev`, `st_ino`, and `st_rdev` must match what the
    /// host kernel returns for `stat(path)` on the device path, because
    /// glibc `ttyname_r` verifies all three fields via `is_mytty()`.
    ///
    /// Returns `None` when stdin is not a terminal (pipes, files) or on
    /// platforms that do not expose PTY device paths (Windows).
    fn host_stdin_tty_device_info(&self) -> Option<HostTtyDeviceInfo> {
        None
    }
}

/// Host terminal device identity, returned by
/// [`StdioProvider::host_stdin_tty_device_info`].
#[derive(Debug, Clone)]
pub struct HostTtyDeviceInfo {
    /// Device path on the host, e.g., `/dev/pts/156`.
    pub path: alloc::string::String,
    /// `st_rdev` from `fstat()` on the host stdin fd, encoding the
    /// major/minor device numbers (e.g., `0x889c` for major 136, minor 156).
    pub rdev: u64,
    /// `st_dev` from `fstat()` on the host stdin fd (devpts superblock
    /// device number).
    pub dev: u64,
    /// `st_ino` from `fstat()` on the host stdin fd (inode within devpts).
    pub ino: u64,
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

    /// Returns the current processor number exposed to guest compatibility features.
    ///
    /// Platforms that do not expose a stable processor identifier, or that
    /// virtualize CPU topology, may return `0`.
    fn current_processor_number(&self) -> u32 {
        0
    }
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

    /// Arm a fork-child guest TLS handoff for the provided execution context.
    ///
    /// This is called only while initializing the process leader created by
    /// `fork`/fork-like `clone`. Platforms that defer hardware TLS restore until
    /// guest entry must consume the handoff from
    /// [`apply_fork_child_guest_thread_local_storage`] at the final pre-entry
    /// boundary for this exact context.
    fn prepare_fork_child_guest_thread_local_storage(
        _ctx: *const (),
        #[cfg(target_arch = "x86_64")] _fsbase: usize,
    ) {
    }

    /// Consume any fork-child guest TLS handoff for the provided context.
    fn apply_fork_child_guest_thread_local_storage(_ctx: *const ()) {}
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

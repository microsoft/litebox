//! The underlying platform upon which LiteBox resides.
//!
//! The top-level trait that denotes something is a valid LiteBox platform is [`Provider`]. This
//! trait is merely a collection of subtraits that could be composed independently from various
//! other crates that implement them upon various types.

pub mod trivial_providers;

#[cfg(test)]
pub(crate) mod mock;

use either::Either;
use thiserror::Error;

/// A provider of a platform upon which LiteBox can execute.
///
/// Ideally, a [`Provider`] is zero-sized, and only exists to provide access to functionality
/// provided by it. _However_, most of the provided APIs within the provider act upon an `&self` to
/// allow storage of any useful "globals" within it necessary.
pub trait Provider:
    RawMutexProvider + IPInterfaceProvider + TimeProvider + PunchthroughProvider + DebugLogProvider
{
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
    type PunchthroughToken<'a>: PunchthroughToken
    where
        Self: 'a;
    /// Give permission token to invoke `punchthrough`, possibly after checking that it is ok.
    ///
    /// The reason `&mut self` is taken mutably is to ensure that tokens aren't being held around
    /// for too long (i.e., all other platform interaction is disallowed between the creation and
    /// consumption of a token), as well as allowing the token to (possibly) get mutable access to
    /// the underlying platform storage.
    fn get_punchthrough_token_for<'a>(
        &'a mut self,
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
    /// Allocate a new [`RawMutex`].
    fn new_raw_mutex(&self) -> Self::RawMutex;
}

/// A raw mutex/lock API; expected to roughly match (or even be implemented using) a Linux futex.
pub trait RawMutex: Send + Sync {
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
        self.wake_many(usize::MAX)
    }

    /// If the underlying value is `val`, block until a wake operation wakes us up.
    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp>;

    /// If the underlying value is `val`, block until a wake operation wakes us up, or some `time`
    /// has passed without a wake operation having occured.
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
    /// Returns an instant coresponding to "now".
    fn now(&self) -> Self::Instant;
}

/// An opaque measurement of a monotonically nondecreasing clock.
pub trait Instant {
    /// Returns the amount of time elapsed from another instant to this one, or `None` if that
    /// instant is later than this one.
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration>;
    /// Returns the amount of time elapsed from another instant to this one, or zero duration if
    /// that instant is later than this one.
    fn duration_since(&self, earlier: &Self) -> core::time::Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(core::time::Duration::from_secs(0))
    }
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

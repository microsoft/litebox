//! The underlying platform upon which LiteBox resides.
//!
//! The top-level trait that denotes something is a valid LiteBox platform is [`Provider`]. This
//! trait is merely a collection of subtraits that could be composed independently from various
//! other crates that implement them upon various types.

use either::Either;
use thiserror::Error;

/// A provider of a platform upon which LiteBox can execute.
///
/// Ideally, a [`Provider`] is zero-sized, and only exists to provide access to functionality
/// provided by it. _However_, most of the provided APIs within the provider act upon an `&self` to
/// allow storage of any useful "globals" within it necessary.
pub trait Provider:
    RawMutexProvider + IPInterfaceProvider + TimeProvider + PunchthroughProvider
{
}

/// Punch through any functionality for a particular platform that is not explicitly part of the
/// common _shared_ platform interface.
pub trait PunchthroughProvider {
    type Punchthrough: Punchthrough;
}

/// Punchthrough support allowing access to functionality not captured by [`Provider`].
///
/// Ideally, this is implemented by a (possibly `#[non_exhaustive]`) enum where a platform
/// provider can mark any unsupported/unimplemented punchthrough functionality with a
/// [`PunchthroughError::Unsupported`] or [`PunchthroughError::Unimplemented`].
pub trait Punchthrough {
    type ReturnSuccess;
    type ReturnFailure: core::error::Error;
    fn execute(self) -> Result<Self::ReturnSuccess, PunchthroughError<Self::ReturnFailure>>;
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
impl<L, R> Punchthrough for Either<L, R>
where
    L: Punchthrough,
    R: Punchthrough,
{
    type ReturnSuccess = Either<L::ReturnSuccess, R::ReturnSuccess>;
    type ReturnFailure = EitherError<L::ReturnFailure, R::ReturnFailure>;

    fn execute(self) -> Result<Self::ReturnSuccess, PunchthroughError<Self::ReturnFailure>> {
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

/// A provider of raw mutexes
pub trait RawMutexProvider {
    type RawMutex;
    /// Allocate a new [`RawMutex`].
    fn new_raw_mutex(&self) -> Self::RawMutex;
}

/// A raw mutex/lock API; expected to roughly match (or even be implemented using) a Linux futex.
pub trait RawMutex: Send + Sync {
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

    /// Block until a wake operation wakes us up.
    fn block(&self);

    /// Block until a wake operation wakes us up, or some `time` has passed without a wake operation
    /// having occured.
    fn block_or_timeout(&self, time: core::time::Duration) -> UnblockedOrTimedOut;
}

/// Named-boolean to indicate whether [`RawMutex::block_or_timeout`] was woken up or timed out.
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
    fn send_ip_packet(&self, packet: &[u8]) -> Result<usize, SendError>;

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
pub enum ReceiveError {}

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

/// Implementations of trivial providers.
///
/// Most users of LiteBox may possibly need more featureful providers, provided by other crates;
/// however, some users might find these sufficient for their use case.
pub mod trivial_providers {
    use super::{Punchthrough, PunchthroughError, PunchthroughProvider};

    /// A trivial provider, useful when no punchthrough is necessary.
    pub struct ImpossiblePunchthroughProvider {}
    impl PunchthroughProvider for ImpossiblePunchthroughProvider {
        type Punchthrough = ImpossiblePunchthrough;
    }
    /// A [`Punchthrough`] for [`ImpossiblePunchthroughProvider`]
    pub enum ImpossiblePunchthrough {}
    impl Punchthrough for ImpossiblePunchthrough {
        // Infallible has the same role as the never type (`!`) which will _eventually_ be stabilized in
        // Rust. Since `Infallible` has no variant, a value of this type can never actually exist.
        type ReturnSuccess = core::convert::Infallible;
        type ReturnFailure = core::convert::Infallible;
        fn execute(self) -> Result<Self::ReturnSuccess, PunchthroughError<Self::ReturnFailure>> {
            // Since `ImpossiblePunchthrough` is an empty enum, it is impossible to actually invoke
            // `execute` upon it, meaning that the implementation here is irrelevant, since anything
            // within it is provably unreachable.
            unreachable!()
        }
    }

    /// A trivial provider, useful when punchthroughs are be necessary, but might prefer to be
    /// simply caught as "unimplemented" temporarily, while more infrastructure is set up.
    pub struct IgnoredPunchthroughProvider {}
    impl PunchthroughProvider for IgnoredPunchthroughProvider {
        type Punchthrough = IgnoredPunchthrough;
    }
    /// A [`Punchthrough`] for [`IgnoredPunchthroughProvider`]
    pub struct IgnoredPunchthrough {
        data: &'static str,
    }
    impl Punchthrough for IgnoredPunchthrough {
        type ReturnSuccess = Underspecified;
        type ReturnFailure = Underspecified;
        fn execute(self) -> Result<Self::ReturnSuccess, PunchthroughError<Self::ReturnFailure>> {
            Err(PunchthroughError::Unimplemented(self.data))
        }
    }

    /// An under-specified type that cannot be "inspected" or created; used for [`IgnoredPunchthrough`]
    #[doc(hidden)]
    pub struct Underspecified {
        // Explicitly private field, to prevent destructuring or creation outside this module.
        __private: (),
    }
    impl core::fmt::Debug for Underspecified {
        fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            unreachable!("Underspecified is never constructed")
        }
    }
    impl core::fmt::Display for Underspecified {
        fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            unreachable!("Underspecified is never constructed")
        }
    }
    impl core::error::Error for Underspecified {}
}

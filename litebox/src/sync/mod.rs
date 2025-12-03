//! Higher-level synchronization primitives
//!
//! The implementation for some of the components in this module (namely, [`Mutex`] and [`RwLock`])
//! is derived from related source files in Rust's `std`, taken from
//! `6fd7e9010db6be7605241c39eab7c5078ee2d5bd`/`98815742cf2e914ee0d7142a02322cf939c47834`. The files
//! have been modified significantly to support invoking through the [`platform`], rather than
//! through regular system interfaces. Additionally, support is added tracing locks through the
//! `lock_tracing` conditional-compilation feature that can aid in debugging.

use core::marker::PhantomData;

use crate::platform;

mod condvar;
pub mod futex;
mod mutex;
mod rwlock;

#[cfg(feature = "lock_tracing")]
mod lock_tracing;

pub use condvar::Condvar;
pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

#[cfg(not(feature = "lock_tracing"))]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider: platform::RawMutexProvider + Sync + 'static {}
#[cfg(not(feature = "lock_tracing"))]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: platform::RawMutexProvider + Sync + 'static
{
}

#[cfg(feature = "lock_tracing")]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider:
    platform::RawMutexProvider + platform::TimeProvider + platform::DebugLogProvider + Sync + 'static
{
}
#[cfg(feature = "lock_tracing")]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: platform::RawMutexProvider
        + platform::TimeProvider
        + platform::DebugLogProvider
        + Sync
        + 'static
{
}

/// The `Synchronization` provides access to all synchronization-related functionality provided by
/// [`crate::LiteBox`].
///
/// A LiteBox `Synchronization` is parametric in the platform it runs on.
pub struct Synchronization<Platform: RawSyncPrimitivesProvider>(
    PhantomData<fn(Platform) -> Platform>,
);

impl<Platform: RawSyncPrimitivesProvider> Synchronization<Platform> {
    /// Construct a new `Synchronization` instance. This is expected to be invoked only by
    /// [`crate::LiteBox`]'s creation method, and should not be invoked anywhere else in the codebase.
    pub(crate) fn new_from_platform(platform: &'static Platform) -> Self {
        // Enable lock tracing using this platform for time keeping and debug
        // prints, if the feature is enabled.
        #[cfg(feature = "lock_tracing")]
        lock_tracing::LockTracker::init(platform);
        let _ = platform;
        Self(PhantomData)
    }
}

impl<Platform: RawSyncPrimitivesProvider> Synchronization<Platform> {
    /// Create a new [`Condvar`]
    #[must_use]
    pub fn new_condvar(&self) -> Condvar<Platform> {
        Condvar::new()
    }

    /// Create a new [`Mutex`]
    #[must_use]
    pub fn new_mutex<T>(&self, val: T) -> Mutex<Platform, T> {
        Mutex::new(val)
    }

    /// Create a new [`Mutex`]
    #[must_use]
    pub fn new_rwlock<T>(&self, val: T) -> RwLock<Platform, T> {
        RwLock::new(val)
    }
}

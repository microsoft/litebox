//! Higher-level synchronization primitives
//!
//! The implementation for some of the components in this module (namely, [`Mutex`] and [`RwLock`])
//! is derived from related source files in Rust's `std`, taken from
//! `6fd7e9010db6be7605241c39eab7c5078ee2d5bd`/`98815742cf2e914ee0d7142a02322cf939c47834`. The files
//! have been modified significantly to support invoking through the [`platform`], rather than
//! through regular system interfaces. Additionally, support is added tracing locks through the
//! `lock_tracing` conditional-compilation feature that can aid in debugging.

use crate::platform;

mod condvar;
pub mod futex;
mod mutex;
mod rwlock;

#[cfg(feature = "lock_tracing")]
pub(crate) mod lock_tracing;

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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Higher-level synchronization primitives
//!
//! The implementation for some of the components in this module (specifically, [`Mutex`] and
//! [`RwLock`]) is derived from related source files in Rust's `std`. See `./cgmanifest.json` for a
//! declaration of the specific commit hashes. The files have been modified significantly to support
//! invoking through the [`crate::platform`], rather than through regular system interfaces.
//! Additionally,
//! support is added tracing locks through the `lock_tracing` conditional-compilation feature that
//! can aid in debugging.

use litebox_platform::sync::{RawMutexProvider, WaitWakerProvider};

#[cfg(feature = "lock_tracing")]
use crate::platform::TimeProvider;

mod condvar;
pub mod futex;
mod mutex;
mod rwlock;

#[cfg(feature = "lock_tracing")]
pub(crate) mod lock_tracing;

#[cfg(feature = "lock_tracing")]
pub use lock_tracing::{RecordingSummary, flush_to_jsonl, start_recording, stop_recording};

pub use condvar::Condvar;
pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

#[cfg(not(feature = "lock_tracing"))]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider: RawMutexProvider + WaitWakerProvider + Sync + 'static {}
#[cfg(not(feature = "lock_tracing"))]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: RawMutexProvider + WaitWakerProvider + Sync + 'static
{
}

#[cfg(feature = "lock_tracing")]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider:
    RawMutexProvider + WaitWakerProvider + TimeProvider + Sync + 'static
{
}
#[cfg(feature = "lock_tracing")]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: RawMutexProvider + WaitWakerProvider + TimeProvider + Sync + 'static
{
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Synchronization primitives used by LiteBox.
//!
//! Portable locks are implemented by [`litebox_platform::sync`] and re-exported
//! here. This module also provides LiteBox-specific futex support and the
//! platform capability bound used by interruptible waits.

pub mod futex;

pub use litebox_platform::sync::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, Mutex, MutexGuard, RwLock, RwLockReadGuard,
    RwLockWriteGuard,
};
#[cfg(feature = "lock_tracing")]
pub use litebox_platform::sync::{
    RecordingSummary, flush_to_jsonl, start_recording, stop_recording,
};

#[cfg(not(feature = "lock_tracing"))]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider:
    litebox_platform::sync::RawSyncPrimitivesProvider + litebox_platform::sync::WaitWakerProvider
{
}

#[cfg(not(feature = "lock_tracing"))]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: litebox_platform::sync::RawSyncPrimitivesProvider
        + litebox_platform::sync::WaitWakerProvider
{
}

#[cfg(feature = "lock_tracing")]
/// A convenience name for specific requirements from the platform
pub trait RawSyncPrimitivesProvider:
    litebox_platform::sync::RawSyncPrimitivesProvider
    + litebox_platform::sync::WaitWakerProvider
    + litebox_platform::time::TimeProvider
{
}

#[cfg(feature = "lock_tracing")]
impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: litebox_platform::sync::RawSyncPrimitivesProvider
        + litebox_platform::sync::WaitWakerProvider
        + litebox_platform::time::TimeProvider
{
}

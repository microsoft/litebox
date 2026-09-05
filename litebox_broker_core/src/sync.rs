// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker synchronization primitives supplied by the deployment platform.

mod mutex;
mod rwlock;

use litebox_platform::sync::RawMutexProvider;

pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

/// Convenience bound for broker platforms that provide synchronization.
pub trait RawSyncPrimitivesProvider: RawMutexProvider + Sync + 'static {}

impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: RawMutexProvider + Sync + 'static
{
}

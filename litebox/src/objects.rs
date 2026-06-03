// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local-core object factory namespaces.

use crate::{
    broker::BrokerState,
    event::counter::{EventCounter, EventCounterError},
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// Factories for local-core objects that may be backed by local or broker authority.
pub struct Objects<'a, Platform: RawSyncPrimitivesProvider> {
    broker: &'a BrokerState<Platform>,
}

impl<'a, Platform: RawSyncPrimitivesProvider> Objects<'a, Platform> {
    pub(crate) fn new(broker: &'a BrokerState<Platform>) -> Self {
        Self { broker }
    }

    /// Returns factories for local-core event objects.
    pub fn events(&self) -> EventObjects<'a, Platform> {
        EventObjects {
            broker: self.broker,
        }
    }
}

/// Factories for local-core event objects.
pub struct EventObjects<'a, Platform: RawSyncPrimitivesProvider> {
    broker: &'a BrokerState<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> EventObjects<'_, Platform> {
    /// Creates a local-core event counter.
    pub fn create_counter(
        &self,
        initial_count: u64,
    ) -> Result<EventCounter<Platform>, EventCounterError>
    where
        Platform: TimeProvider,
    {
        self.broker.create_event_counter(initial_count)
    }
}

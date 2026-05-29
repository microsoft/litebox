// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::object::ObjectKind;
use crate::{
    BrokerConnection, BrokerCore, BrokerError, ObjectHandle, ObjectRights, ObjectType,
    PolicyEngine, Result,
};

/// Event readiness snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessState {
    /// Whether the event is currently ready.
    pub ready: bool,
    /// Monotonic generation incremented on readiness changes.
    pub generation: u64,
}

impl ReadinessState {
    /// Creates a readiness snapshot.
    pub const fn new(ready: bool, generation: u64) -> Self {
        Self { ready, generation }
    }
}

/// Result of checking an event wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The event was ready and a nonblocking wait would complete.
    Ready(ReadinessState),
    /// The event was not ready and a blocking wait would sleep.
    WouldBlock(ReadinessState),
}

impl<P: PolicyEngine> BrokerCore<P> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self, connection: &BrokerConnection) -> Result<ObjectHandle> {
        let association = connection.association();
        self.authorize_create_object(association, ObjectType::Event)?;

        self.insert_object_with_reference(
            association,
            ObjectKind::Event(EventObject::new()),
            ObjectType::Event,
            ObjectRights::WAIT | ObjectRights::WRITE,
        )
    }

    /// Checks whether an event wait would complete now.
    ///
    /// Blocking is intentionally outside BrokerCore for the first proof of
    /// concept. Userland or kernel deployments can block on transport-specific
    /// wait primitives after BrokerCore authorizes and reports readiness state.
    pub fn wait_event(
        &mut self,
        connection: &BrokerConnection,
        handle: ObjectHandle,
    ) -> Result<WaitOutcome> {
        let association = connection.association();
        self.authorize_object_use(association, handle, ObjectType::Event, ObjectRights::WAIT)?;
        let state = self.event_state(handle)?;
        Ok(if state.ready {
            WaitOutcome::Ready(state)
        } else {
            WaitOutcome::WouldBlock(state)
        })
    }

    /// Signals a broker-owned event object.
    pub fn signal_event(
        &mut self,
        connection: &BrokerConnection,
        handle: ObjectHandle,
    ) -> Result<ReadinessState> {
        let association = connection.association();
        self.authorize_object_use(association, handle, ObjectType::Event, ObjectRights::WRITE)?;
        match &mut self.object_mut(handle.object_id)?.kind {
            ObjectKind::Event(event) => event.signal(),
        }
    }

    fn event_state(&self, handle: ObjectHandle) -> Result<ReadinessState> {
        match &self.object(handle.object_id)?.kind {
            ObjectKind::Event(event) => Ok(event.readiness_state()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventObject {
    ready: bool,
    readiness_generation: u64,
}

impl EventObject {
    pub(crate) const fn new() -> Self {
        Self {
            ready: false,
            readiness_generation: 0,
        }
    }

    pub(crate) const fn readiness_state(self) -> ReadinessState {
        ReadinessState::new(self.ready, self.readiness_generation)
    }

    fn signal(&mut self) -> Result<ReadinessState> {
        self.ready = true;
        self.readiness_generation = self
            .readiness_generation
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(self.readiness_state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerCore, CallerCredential, EventOnlyPolicy, ObjectGeneration};

    #[test]
    fn wait_rejects_reference_without_wait_right() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let connection = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core
            .insert_object_with_reference(
                connection.association(),
                ObjectKind::Event(EventObject::new()),
                ObjectType::Event,
                ObjectRights::WRITE,
            )
            .unwrap();

        assert_eq!(
            core.wait_event(&connection, handle),
            Err(BrokerError::InvalidRights)
        );
    }

    #[test]
    fn wait_rejects_stale_object_generation() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let connection = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();
        let mut handle = core.create_event(&connection).unwrap();
        handle.object_generation = ObjectGeneration::new(handle.object_generation.get() + 1);

        assert_eq!(
            core.wait_event(&connection, handle),
            Err(BrokerError::StaleHandle)
        );
    }

    #[test]
    fn wait_hides_handle_owned_by_another_association() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let owner = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();
        let other = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core.create_event(&owner).unwrap();

        assert_eq!(
            core.wait_event(&other, handle),
            Err(BrokerError::UnknownObject)
        );
    }
}

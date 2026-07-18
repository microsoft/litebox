// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use crate::event::EventObject;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use spin::rwlock::RwLock;

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same session-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    Unauthenticated,
}

/// Broker-assigned session identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SessionId(pub u64);

bitflags::bitflags! {
    /// Broker rights attached to an object reference.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ObjectRights: u32 {
        /// Right to wait for readiness.
        const WAIT = 1 << 0;
        /// Right to mutate object state, such as adding event readiness credits.
        const WRITE = 1 << 1;
    }
}

pub(crate) struct ObjectReference {
    pub(crate) object: Arc<RwLock<ObjectEntry>>,
    pub(crate) session_id: SessionId,
    pub(crate) rights: ObjectRights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectEntry {
    Event(EventObject),
}

/// Broker-owned authority token for one authenticated caller session.
///
/// User mode does not choose this value. The broker entry layer authenticates
/// the caller, then BrokerCore assigns this identity for all operations received
/// on that session. Dropping the session releases all object references it owns.
pub struct BrokerSession {
    pub(crate) core: BrokerCore,
    /// Broker-assigned session identity.
    pub(crate) session_id: SessionId,
    /// Broker-entry-authenticated caller credential for this session.
    pub(crate) caller_credential: CallerCredential,
}

impl BrokerSession {
    /// Creates an authenticated session identity.
    pub(crate) fn new(
        core: BrokerCore,
        session_id: SessionId,
        caller_credential: CallerCredential,
    ) -> Self {
        Self {
            core,
            session_id,
            caller_credential,
        }
    }

    pub(crate) fn create_object_reference(&self, object: ObjectEntry) -> Result<ObjectHandle> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let mut references = self.core.references.write();
        if references.len() >= self.core.limits.max_references {
            return Err(BrokerError::ResourceExhausted);
        }
        let handle = self.core.allocate_reference_handle()?;
        references.insert(
            handle,
            ObjectReference {
                object: Arc::new(RwLock::new(object)),
                session_id: self.session_id,
                rights,
            },
        );

        Ok(handle)
    }

    pub(crate) fn with_authorized_object<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(&ObjectEntry) -> Result<T>,
    ) -> Result<T> {
        let object = {
            let references = self.core.references.read();
            self.authorize_use_object(&references, handle, required_rights)?
        };
        let object = object.read();
        f(&object)
    }

    pub(crate) fn with_authorized_object_mut<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(&mut ObjectEntry) -> Result<T>,
    ) -> Result<T> {
        let object = {
            let references = self.core.references.read();
            self.authorize_use_object(&references, handle, required_rights)?
        };
        let mut object = object.write();
        f(&mut object)
    }

    fn authorize_use_object(
        &self,
        references: &HashMap<ObjectHandle, ObjectReference>,
        handle: ObjectHandle,
        required_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.session_id != self.session_id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.contains(required_rights) {
            return Err(BrokerError::InvalidRights);
        }
        let object = Arc::clone(&reference.object);
        Ok(object)
    }

    /// Closes one object reference owned by this session.
    ///
    /// The underlying object is released when this was the last live reference.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let mut references = self.core.references.write();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.session_id != self.session_id {
            return Err(BrokerError::UnknownObject);
        }
        references.remove(&handle);
        Ok(())
    }
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        self.core.close_session(self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
    use litebox_broker_protocol::readiness::ReadinessFlags;

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            BrokerCoreLimits::new(1),
        )
        .unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = crate::event::create(&session, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0 + 1);

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            crate::event::wait(&session, unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            crate::event::wait(&session, handle),
            Ok(ReadinessFlags::WRITE)
        );
        assert_eq!(
            crate::event::add(&session, handle, 1),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            crate::event::consume(&session, handle, EventConsumeMode::One),
            Ok(EventConsumption {
                value: 1,
                readiness: ReadinessFlags::WRITE,
            })
        );
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );

        assert_eq!(session.close_object_reference(handle), Ok(()));
        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _handle = crate::event::create(&session, 0).unwrap();
        {
            let references = broker.references.read();
            assert_eq!(references.len(), 1);
        }

        drop(session);

        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }

        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX;
        }
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
        let references = broker.references.read();
        assert!(references.is_empty());
    }
}

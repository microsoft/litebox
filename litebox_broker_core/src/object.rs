// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use crate::event::EventObject;
use crate::identity::{BrokerSession, CallerCredential, SessionId};
use crate::{BrokerCore, BrokerCoreState, BrokerError, Result, allocate_id};
use litebox_broker_protocol::ObjectHandle;
use spin::rwlock::RwLock;

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

slotmap::new_key_type! {
    /// Broker-owned object identifier.
    pub(crate) struct ObjectId;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectReference {
    pub(crate) object_id: ObjectId,
    pub(crate) session_id: SessionId,
    pub(crate) rights: ObjectRights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectEntry {
    Event(EventObject),
}

pub(super) fn create_object_with_reference(
    session: &BrokerSession,
    object: ObjectEntry,
) -> Result<ObjectHandle> {
    let mut state = session.core.state.write();
    let rights = match &object {
        ObjectEntry::Event(_) => state
            .policy
            .authorize_create_event(session.caller_credential)?,
    };

    if state.objects.len() >= state.limits.max_objects
        || state.references.len() >= state.limits.max_references
    {
        return Err(BrokerError::ResourceExhausted);
    }
    if state.objects.len() == state.objects.capacity() {
        state
            .objects
            .try_reserve(1)
            .map_err(|_| BrokerError::ResourceExhausted)?;
    }

    let handle = ObjectHandle(allocate_id(&mut state.next_reference_handle)?);
    let object_id = state.objects.insert(Arc::new(RwLock::new(object)));
    let old_reference = state.references.insert(
        handle,
        ObjectReference {
            object_id,
            session_id: session.session_id,
            rights,
        },
    );
    debug_assert!(old_reference.is_none());

    Ok(handle)
}

pub(super) fn with_authorized_object<T>(
    session: &BrokerSession,
    handle: ObjectHandle,
    rights: ObjectRights,
    f: impl FnOnce(&ObjectEntry, ObjectRights) -> Result<T>,
) -> Result<T> {
    let authorized = {
        let state = session.core.state.read();
        authorize_use_object(
            &state,
            session.session_id,
            session.caller_credential,
            handle,
            rights,
        )?
    };
    let object = authorized.object.read();
    f(&object, authorized.rights)
}

pub(super) fn with_authorized_object_mut<T>(
    session: &BrokerSession,
    handle: ObjectHandle,
    rights: ObjectRights,
    f: impl FnOnce(&mut ObjectEntry, ObjectRights) -> Result<T>,
) -> Result<T> {
    let authorized = {
        let state = session.core.state.read();
        authorize_use_object(
            &state,
            session.session_id,
            session.caller_credential,
            handle,
            rights,
        )?
    };
    let mut object = authorized.object.write();
    f(&mut object, authorized.rights)
}

fn authorize_use_object(
    state: &BrokerCoreState,
    session_id: SessionId,
    caller_credential: CallerCredential,
    handle: ObjectHandle,
    rights: ObjectRights,
) -> Result<AuthorizedObject> {
    let reference = validate_handle(state, session_id, handle, rights)?;
    let reference_rights = reference.rights;
    let object = state
        .objects
        .get(reference.object_id)
        .ok_or(BrokerError::UnknownObject)?;
    state
        .policy
        .authorize_use_event(caller_credential, rights)?;
    Ok(AuthorizedObject {
        object: Arc::clone(object),
        rights: reference_rights,
    })
}

pub(super) fn close_object_reference(session: &BrokerSession, handle: ObjectHandle) -> Result<()> {
    let mut state = session.core.state.write();
    let object_id = reference_for_handle(&state, session.session_id, handle)?.object_id;
    if !state.objects.contains_key(object_id) {
        return Err(BrokerError::UnknownObject);
    }

    state.references.remove(&handle);
    drop_object_if_unreferenced(&mut state, object_id);
    Ok(())
}

pub(super) fn drop_references_for_session(core: &BrokerCore, session_id: SessionId) {
    let mut state = core.state.write();
    let BrokerCoreState {
        objects,
        references,
        ..
    } = &mut *state;
    references.retain(|_, reference| reference.session_id != session_id);
    objects.retain(|object_id, _| {
        references
            .values()
            .any(|reference| reference.object_id == object_id)
    });
}

fn validate_handle(
    state: &BrokerCoreState,
    session_id: SessionId,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<ObjectReference> {
    let reference = reference_for_handle(state, session_id, handle)?;
    if !reference.rights.contains(required_rights) {
        return Err(BrokerError::InvalidRights);
    }

    state
        .objects
        .get(reference.object_id)
        .ok_or(BrokerError::UnknownObject)?;

    Ok(*reference)
}

fn reference_for_handle(
    state: &BrokerCoreState,
    session_id: SessionId,
    handle: ObjectHandle,
) -> Result<&ObjectReference> {
    let reference = state
        .references
        .get(&handle)
        .ok_or(BrokerError::UnknownObject)?;
    if reference.session_id != session_id {
        return Err(BrokerError::UnknownObject);
    }
    Ok(reference)
}

fn drop_object_if_unreferenced(state: &mut BrokerCoreState, object_id: ObjectId) {
    if !state
        .references
        .values()
        .any(|reference| reference.object_id == object_id)
    {
        state.objects.remove(object_id);
    }
}

struct AuthorizedObject {
    object: Arc<RwLock<ObjectEntry>>,
    rights: ObjectRights,
}

#[cfg(test)]
mod tests {
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, PolicyEngine, allocate_id,
        event,
    };
    use litebox_broker_protocol::{ObjectHandle, WaitOutcome};

    #[test]
    fn allocator_exhausts_before_id_overflow() {
        let mut next_id = u64::MAX;

        assert_eq!(
            allocate_id(&mut next_id),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            allocate_id(&mut next_id),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn oversized_object_slotmap_limits_are_rejected_before_core_construction() {
        let too_many_entries = u32::MAX as usize;

        assert!(matches!(
            BrokerCore::new_with_limits(
                PolicyEngine::event_only(),
                BrokerCoreLimits::new(too_many_entries, 1)
            ),
            Err(BrokerError::ResourceExhausted)
        ));
    }

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let broker = BrokerCore::new(PolicyEngine::event_only()).unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = event::create(&session, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0 + 1);

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            event::wait(&session, unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert!(matches!(
            event::wait(&session, handle),
            Ok(WaitOutcome::WouldBlock(_))
        ));

        assert_eq!(session.close_object_reference(handle), Ok(()));
        {
            let state = broker.state.read();
            assert!(state.references.is_empty());
            assert!(state.objects.is_empty());
        }
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _handle = event::create(&session, 0).unwrap();
        {
            let state = broker.state.read();
            assert_eq!(state.references.len(), 1);
            assert_eq!(state.objects.len(), 1);
        }

        drop(session);

        {
            let state = broker.state.read();
            assert!(state.references.is_empty());
            assert!(state.objects.is_empty());
        }

        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        {
            let mut state = broker.state.write();
            state.next_reference_handle = u64::MAX;
        }
        assert_eq!(
            event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
        let state = broker.state.read();
        assert!(state.references.is_empty());
        assert!(state.objects.is_empty());
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::AtomicUsize;

use crate::event::EventObject;
use crate::pipe::PipeObject;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::{Mutex, rwlock::RwLock};

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same session-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
    /// The trusted broker entry layer authenticated and bound the caller.
    HostGuaranteed,
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
    session_reference_index: usize,
}

pub(crate) enum ObjectEntry {
    Event(EventObject),
    Pipe(PipeObject),
}

/// Broker-owned authority token for one authenticated caller session.
///
/// User mode does not choose this value. The broker entry layer authenticates
/// the caller, then BrokerCore assigns this identity for all operations received
/// on that session. Dropping the session releases all object references it owns,
/// and with them the share of the core-wide budgets they held.
pub struct BrokerSession {
    pub(crate) core: BrokerCore,
    /// Broker-assigned session identity.
    pub(crate) session_id: SessionId,
    /// Broker-entry-authenticated caller credential for this session.
    pub(crate) caller_credential: CallerCredential,
    /// Handles of the live object references owned by this session.
    ///
    /// The length of this vector is the session's live reference count, so the
    /// per-session reference quota is enforced against the very state that
    /// releases it and the two cannot drift apart.
    reference_handles: Mutex<Vec<ObjectHandle>>,
    /// Capacity in bytes reserved by this session's live pipes.
    ///
    /// Reservations share ownership of this counter because a pipe object may
    /// outlive the session that created it: another worker can hold the
    /// object's `Arc` across session teardown, and the release must still find
    /// a live counter to credit.
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
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
            reference_handles: Mutex::new(Vec::new()),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn create_object_reference(&self, object: ObjectEntry) -> Result<ObjectHandle> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let mut reference_handles = self.reference_handles.lock();
        // Charge the session before the core-wide table is locked, so a session
        // that is already at its quota cannot make every other session contend
        // for the shared lock to be told the core is full.
        if reference_handles.len() >= self.core.limits.max_session_references {
            return Err(BrokerError::ResourceExhausted);
        }
        reference_handles
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let mut references = self.core.references.write();
        if references.len() >= self.core.limits.max_references {
            return Err(BrokerError::ResourceExhausted);
        }
        let handle = self.core.allocate_reference_handle()?;
        if references.contains_key(&handle) {
            return Err(BrokerError::Internal);
        }
        self.insert_object_reference(
            &mut references,
            &mut reference_handles,
            handle,
            object,
            rights,
        );

        Ok(handle)
    }

    pub(crate) fn create_object_reference_pair(
        &self,
        first: ObjectEntry,
        second: ObjectEntry,
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        // `first` and `second` are parameters, so they are dropped after every
        // lock guard declared in this body. That is what makes each failure
        // return below destroy the pipe endpoints, which take the pipe-state
        // lock, only once both reference-index locks are released. Do not
        // rebind them to locals declared after either guard.
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let mut reference_handles = self.reference_handles.lock();
        if reference_handles
            .len()
            .checked_add(2)
            .is_none_or(|count| count > self.core.limits.max_session_references)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        reference_handles
            .try_reserve(2)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let mut references = self.core.references.write();
        if references
            .len()
            .checked_add(2)
            .is_none_or(|count| count > self.core.limits.max_references)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let (first_handle, second_handle) = self.core.allocate_reference_handle_pair()?;
        if first_handle == second_handle
            || references.contains_key(&first_handle)
            || references.contains_key(&second_handle)
        {
            return Err(BrokerError::Internal);
        }
        for (handle, object) in [(first_handle, first), (second_handle, second)] {
            self.insert_object_reference(
                &mut references,
                &mut reference_handles,
                handle,
                object,
                rights,
            );
        }
        Ok((first_handle, second_handle))
    }

    fn insert_object_reference(
        &self,
        references: &mut HashMap<ObjectHandle, ObjectReference>,
        reference_handles: &mut Vec<ObjectHandle>,
        handle: ObjectHandle,
        object: ObjectEntry,
        rights: ObjectRights,
    ) {
        let session_reference_index = reference_handles.len();
        // Both callers check `contains_key` first, so this always replaces
        // nothing. Anything dropped here would be destroyed while both the
        // session's reference-handle lock and the core-wide reference lock are
        // held, so `ObjectReference` must never gain a destructor that takes
        // either. Keeping this insert infallible is also what lets the caller's
        // pair loop run without a rollback path.
        references.insert(
            handle,
            ObjectReference {
                object: Arc::new(RwLock::new(object)),
                session_id: self.session_id,
                rights,
                session_reference_index,
            },
        );
        reference_handles.push(handle);
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

    /// Returns the current readiness of a broker-owned object.
    pub fn check_readiness(&self, handle: ObjectHandle) -> Result<ReadinessFlags> {
        self.with_authorized_object(handle, ObjectRights::WAIT, |object| {
            Ok(match object {
                ObjectEntry::Event(event) => event.readiness(),
                ObjectEntry::Pipe(pipe) => pipe.readiness(),
            })
        })
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
    /// Destruction happens after releasing the process-wide reference-table
    /// lock, so an object may safely release platform resources.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let reference = self.remove_object_reference(handle)?;
        drop(reference);
        Ok(())
    }

    fn remove_object_reference(&self, handle: ObjectHandle) -> Result<ObjectReference> {
        let mut reference_handles = self.reference_handles.lock();
        let mut references = self.core.references.write();
        let reference = references
            .remove(&handle)
            .ok_or(BrokerError::UnknownObject)?;
        let index = reference.session_reference_index;
        // Keep fallible validation in a nested scope so `?` and early returns
        // reach the shared rollback below instead of dropping the removed
        // reference while either reference-index lock is held.
        let removal_result = (|| {
            if reference.session_id != self.session_id {
                return Err(BrokerError::UnknownObject);
            }
            if reference_handles.get(index) != Some(&handle) {
                return Err(BrokerError::Internal);
            }
            let last_index = reference_handles
                .len()
                .checked_sub(1)
                .ok_or(BrokerError::Internal)?;
            if index != last_index {
                let moved_handle = *reference_handles
                    .get(last_index)
                    .ok_or(BrokerError::Internal)?;
                let moved_reference = references
                    .get_mut(&moved_handle)
                    .ok_or(BrokerError::Internal)?;
                if moved_reference.session_id != self.session_id
                    || moved_reference.session_reference_index != last_index
                {
                    return Err(BrokerError::Internal);
                }
                moved_reference.session_reference_index = index;
            }
            reference_handles.swap_remove(index);
            Ok(())
        })();

        if let Err(error) = removal_result {
            let replaced_reference = references.insert(handle, reference);
            drop(references);
            drop(reference_handles);
            if replaced_reference.is_some() {
                return Err(BrokerError::Internal);
            }
            return Err(error);
        }
        Ok(reference)
    }
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        loop {
            let Some(handle) = self.reference_handles.lock().pop() else {
                break;
            };
            // Do not restore an inconsistent handle: retrying it forever would
            // prevent later valid references from being released.
            let reference = {
                let mut references = self.core.references.write();
                let Some(reference) = references.get(&handle) else {
                    continue;
                };
                if reference.session_id != self.session_id {
                    continue;
                }
                let Some(reference) = references.remove(&handle) else {
                    continue;
                };
                reference
            };
            // Object destruction may release platform resources and must never
            // run while either reference index lock is held.
            drop(reference);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use hashbrown::HashMap;
    use spin::rwlock::RwLock;

    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
    use litebox_broker_protocol::readiness::ReadinessFlags;

    /// Core-wide ceilings used by every check below.
    ///
    /// They are exactly twice the per-session quotas, so two sessions spending
    /// their full quota reach the ceilings and a third session is refused by
    /// the backstop rather than by its own quota.
    const TEST_MAX_REFERENCES: usize = 4;
    const TEST_MAX_TOTAL_PIPE_CAPACITY: usize = 8;
    /// Per-session quotas used by every check below.
    ///
    /// Two references is the smallest quota that still admits a pipe, whose two
    /// endpoints are created together.
    const TEST_MAX_SESSION_REFERENCES: usize = 2;
    const TEST_MAX_SESSION_PIPE_CAPACITY: usize = 4;
    /// `TEST_MAX_SESSION_PIPE_CAPACITY` in the width `pipe::create` accepts.
    const TEST_SESSION_PIPE_CAPACITY_REQUEST: u64 = 4;

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            BrokerCoreLimits::new(TEST_MAX_REFERENCES, TEST_MAX_TOTAL_PIPE_CAPACITY)
                .with_session_quotas(TEST_MAX_SESSION_REFERENCES, TEST_MAX_SESSION_PIPE_CAPACITY),
        )
        .unwrap();

        check_event_reference_lifecycle(&broker);
        check_session_drop_releases_references(&broker);
        check_pipe_lifecycle(&broker);
        check_pipe_reader_closure(&broker);
        check_corrupt_index_fails_without_mutation(&broker);
        check_corrupt_index_does_not_break_teardown(&broker);
        check_reference_quota_is_per_session(&broker);
        check_pipe_capacity_quota_is_per_session(&broker);
        check_session_drop_releases_quotas(&broker);
        check_pipe_capacity_is_released_when_endpoints_are_refused(&broker);
        // Handle allocation is exhausted for the rest of the process once this
        // check runs, so it must stay last.
        check_pair_handle_exhaustion(&broker);

        assert!(broker.references.read().is_empty());
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_event_reference_lifecycle(broker: &BrokerCore) {
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
            session.check_readiness(unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(session.check_readiness(handle), Ok(ReadinessFlags::WRITE));
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
        let second_handle = crate::event::create(&session, 0).unwrap();
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            crate::pipe::create(&session, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        // Closing the older handle exercises swap-removing a non-last entry.
        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(session.close_object_reference(second_handle), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    fn check_session_drop_releases_references(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let first = crate::event::create(&session, 0).unwrap();
        let second = crate::event::create(&session, 0).unwrap();
        assert_ne!(first, second);
        {
            let references = broker.references.read();
            assert_eq!(references.len(), 2);
        }

        drop(session);

        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
    }

    fn check_pipe_lifecycle(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&session, 5, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let (reader, writer) = crate::pipe::create(&session, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            session.check_readiness(reader),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 1),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(crate::pipe::write(&session, writer, &[1, 2]), Ok(2));
        assert_eq!(crate::pipe::write(&session, writer, &[3, 4, 5]), Ok(2));
        assert_eq!(
            crate::pipe::write(&session, writer, &[5]),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 3),
            Ok(std::vec::Vec::from([1, 2, 3]))
        );
        assert_eq!(crate::pipe::write(&session, writer, &[5, 6]), Ok(2));
        assert_eq!(session.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            session.check_readiness(reader),
            Ok(ReadinessFlags::READ | ReadinessFlags::HANGUP)
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 4),
            Ok(std::vec::Vec::from([4, 5, 6]))
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 1),
            Ok(std::vec::Vec::new())
        );
        assert_eq!(session.close_object_reference(reader), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_reader_closure(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = crate::pipe::create(&session, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(session.close_object_reference(reader), Ok(()));
        assert_eq!(crate::pipe::write(&session, writer, &[]), Ok(0));
        assert_eq!(
            crate::pipe::write(&session, writer, &[1]),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(
            session.check_readiness(writer),
            Ok(ReadinessFlags::WRITE | ReadinessFlags::ERROR)
        );
        assert_eq!(session.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_corrupt_index_fails_without_mutation(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let older = crate::event::create(&session, 0).unwrap();
        let newer = crate::event::create(&session, 0).unwrap();
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().session_reference_index = usize::MAX;
        }

        assert_eq!(
            session.close_object_reference(older),
            Err(BrokerError::Internal)
        );
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().session_reference_index = 0;
        }
        assert_eq!(session.close_object_reference(older), Ok(()));
        assert_eq!(session.close_object_reference(newer), Ok(()));
    }

    fn check_corrupt_index_does_not_break_teardown(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _older = crate::event::create(&session, 0).unwrap();
        let newer = crate::event::create(&session, 0).unwrap();
        broker
            .references
            .write()
            .get_mut(&newer)
            .unwrap()
            .session_reference_index = usize::MAX;

        drop(session);

        assert!(broker.references.read().is_empty());
    }

    /// One session spending its whole reference quota must not stop another
    /// session from creating objects. This is the regression test for the
    /// core-wide budgets being reachable by a single session.
    fn check_reference_quota_is_per_session(broker: &BrokerCore) {
        let greedy = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();

        let greedy_first = crate::event::create(&greedy, 0).unwrap();
        let greedy_second = crate::event::create(&greedy, 0).unwrap();
        // The greedy session stops at its own quota while the core-wide
        // ceiling still has room for every other session's share.
        assert_eq!(
            crate::event::create(&greedy, 0),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.references.read().len(), TEST_MAX_SESSION_REFERENCES);

        let neighbor_first = crate::event::create(&neighbor, 0).unwrap();
        let neighbor_second = crate::event::create(&neighbor, 0).unwrap();
        assert_eq!(broker.references.read().len(), TEST_MAX_REFERENCES);

        // With every quota spent, the core-wide ceiling is the backstop.
        let latecomer = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::event::create(&latecomer, 0),
            Err(BrokerError::ResourceExhausted)
        );
        // Same backstop on the pair path, which admits two references at once.
        // No pipe is alive here, so the capacity ceiling cannot short-circuit
        // it, and the latecomer is well inside its own quota.
        assert_eq!(
            crate::pipe::create(&latecomer, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(latecomer.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);

        // Closing a reference returns quota to the session that held it.
        assert_eq!(greedy.close_object_reference(greedy_first), Ok(()));
        let greedy_third = crate::event::create(&greedy, 0).unwrap();

        assert_eq!(greedy.close_object_reference(greedy_second), Ok(()));
        assert_eq!(greedy.close_object_reference(greedy_third), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_first), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_second), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    /// The same isolation must hold for reserved pipe capacity, which is
    /// tracked in a counter rather than in the reference table.
    fn check_pipe_capacity_quota_is_per_session(broker: &BrokerCore) {
        let greedy = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();

        let (greedy_reader, greedy_writer) =
            crate::pipe::create(&greedy, TEST_SESSION_PIPE_CAPACITY_REQUEST, 2).unwrap();
        assert_eq!(
            greedy.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_SESSION_PIPE_CAPACITY
        );
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_SESSION_PIPE_CAPACITY
        );
        // The greedy session is refused by its own quota, without charging the
        // core-wide counter it would otherwise have consumed.
        assert_eq!(
            crate::pipe::create(&greedy, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_SESSION_PIPE_CAPACITY
        );

        let (neighbor_reader, neighbor_writer) =
            crate::pipe::create(&neighbor, TEST_SESSION_PIPE_CAPACITY_REQUEST, 2).unwrap();
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_TOTAL_PIPE_CAPACITY
        );

        // The core-wide ceiling backstops a session that is within its quota,
        // and the refused reservation leaves no charge behind on either counter.
        let latecomer = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&latecomer, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(latecomer.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_TOTAL_PIPE_CAPACITY
        );

        // Capacity is held until both endpoints are gone, then credited back to
        // the session and to the core together.
        assert_eq!(greedy.close_object_reference(greedy_reader), Ok(()));
        assert_eq!(
            greedy.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_SESSION_PIPE_CAPACITY
        );
        assert_eq!(greedy.close_object_reference(greedy_writer), Ok(()));
        assert_eq!(greedy.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_SESSION_PIPE_CAPACITY
        );

        assert_eq!(neighbor.close_object_reference(neighbor_reader), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_writer), Ok(()));
        assert_eq!(neighbor.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert!(broker.references.read().is_empty());
    }

    /// Tearing a session down must return everything it held, so a session that
    /// stops making progress cannot pin a share of the core-wide budgets past
    /// its own lifetime.
    fn check_session_drop_releases_quotas(broker: &BrokerCore) {
        // Twice, so the second session proves the first really gave the
        // core-wide budgets back rather than merely stopping using them.
        for _ in 0..2 {
            let session = broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap();
            let (reader, writer) =
                crate::pipe::create(&session, TEST_SESSION_PIPE_CAPACITY_REQUEST, 2).unwrap();
            assert_ne!(reader, writer);
            assert_eq!(broker.references.read().len(), 2);
            assert_eq!(
                broker.reserved_pipe_capacity.load(Ordering::Relaxed),
                TEST_MAX_SESSION_PIPE_CAPACITY
            );
            // Outlives the session, so the per-session charge stays observable
            // across teardown.
            let session_capacity = Arc::clone(&session.reserved_pipe_capacity);
            assert_eq!(
                session_capacity.load(Ordering::Relaxed),
                TEST_MAX_SESSION_PIPE_CAPACITY
            );

            drop(session);

            assert!(broker.references.read().is_empty());
            assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
            assert_eq!(session_capacity.load(Ordering::Relaxed), 0);
        }
    }

    /// Pipe capacity is reserved before the endpoint references exist, so a
    /// session that is at its reference quota must get the reservation back.
    fn check_pipe_capacity_is_released_when_endpoints_are_refused(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let first = crate::event::create(&session, 0).unwrap();
        let second = crate::event::create(&session, 0).unwrap();

        assert_eq!(
            crate::pipe::create(&session, TEST_SESSION_PIPE_CAPACITY_REQUEST, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(session.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);

        assert_eq!(session.close_object_reference(first), Ok(()));
        assert_eq!(session.close_object_reference(second), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    fn check_pair_handle_exhaustion(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX - 1;
        }
        assert_eq!(
            crate::pipe::create(&session, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(*broker.next_reference_handle.read(), u64::MAX - 1);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let handle = crate::event::create(&session, 0).unwrap();
        assert_eq!(handle, ObjectHandle(u64::MAX - 1));
        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn unauthenticated_caller_gets_no_rights_under_the_deployed_broker_policy() {
        // `BrokerCore::new` enforces one core per process, and the lifecycle
        // group above already claims that slot for this test binary, so this
        // builds a core's fields directly to get an independent instance
        // configured the way `litebox_broker_userland`'s production entry
        // point configures it: host-guaranteed rights only, nothing granted
        // to an unauthenticated caller.
        let broker = BrokerCore {
            policy: PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()),
            limits: BrokerCoreLimits::DEFAULT,
            next_session_id: Arc::new(RwLock::new(1)),
            next_reference_handle: Arc::new(RwLock::new(1)),
            references: Arc::new(RwLock::new(HashMap::new())),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
        };

        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();

        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::PolicyDenied)
        );
        assert!(broker.references.read().is_empty());
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::authority::{Scope, Subject, Term};
use litebox_broker_protocol::{ObjectHandle, ProcessId};

use super::{Authority, AuthorityError};
use crate::object::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerProcess, Result};

/// A process-private subject. The weak pointer identifies the last authority
/// that admitted it without keeping that authority's terms alive.
pub(crate) struct SubjectObject {
    subject: Arc<Subject>,
    admitted_under: Weak<Authority>,
}

impl BrokerProcess {
    /// Returns an immutable snapshot of this process's credential authority.
    #[must_use]
    pub fn authority(&self) -> Arc<Authority> {
        Arc::clone(&self.authority.read())
    }

    /// Replaces this process's authority if the whole proposal is a restriction.
    /// A rejected proposal changes neither the authority nor registered subjects.
    pub fn restrict_authority(&self, terms: Vec<Term>) -> Result<()> {
        let proposed = Authority::new(terms).map_err(authority_error)?;
        self.install_restriction(proposed)
    }

    /// Restricts the selected child's own authority while it is still pending
    /// for this creator. The creator's authority does not change.
    pub fn restrict_child_authority(&self, child_id: ProcessId, terms: Vec<Term>) -> Result<()> {
        let proposed = Authority::new(terms).map_err(authority_error)?;
        self.with_pending_child(child_id, |child| child.install_restriction(proposed))?
    }

    fn install_restriction(&self, proposed: Authority) -> Result<()> {
        let mut current = self.authority.write();
        if !proposed.is_restriction_of(&current) {
            return Err(BrokerError::PolicyDenied);
        }
        *current = Arc::new(proposed);
        Ok(())
    }

    /// Registers an admissible subject. Its handle has no I/O rights, cannot be
    /// transferred and is released on close or process teardown.
    pub fn create_subject(&self, subject: Subject) -> Result<ObjectHandle> {
        if !subject.within_size_limits() {
            return Err(BrokerError::ResourceExhausted);
        }
        self.with_live_owner(|| {
            let authority = self.authority();
            if !authority.admits(&subject) {
                return Err(BrokerError::PolicyDenied);
            }
            self.reserve_object_reference(ObjectRights::empty())?
                .commit(ObjectEntry::Subject(SubjectObject {
                    subject: Arc::new(subject),
                    admitted_under: Arc::downgrade(&authority),
                }))
        })?
    }

    /// Uses an owned subject for one request, checking its scope and the
    /// authority in effect when the request resolves it. `None` accepts either
    /// scope. No broker lock is held while `operation` runs.
    ///
    /// Returns [`BrokerError::StaleSubject`] if a restriction revoked the
    /// subject; the caller must register an admissible replacement.
    pub fn with_subject<R>(
        &self,
        handle: ObjectHandle,
        scope: Option<Scope>,
        operation: impl FnOnce(&Subject) -> R,
    ) -> Result<R> {
        self.with_subject_authority(handle, scope, |subject, _| operation(subject))
    }

    /// Supplies the same authority snapshot that admitted the subject for
    /// this request. A descriptor mutation checks delegation against that
    /// snapshot, not against a separately sampled process authority.
    pub(crate) fn with_subject_authority<R>(
        &self,
        handle: ObjectHandle,
        scope: Option<Scope>,
        operation: impl FnOnce(&Subject, &Authority) -> R,
    ) -> Result<R> {
        let object = self.authorized_object(handle, ObjectRights::empty())?;
        let (subject, authority) = {
            let mut object = object.write();
            let ObjectEntry::Subject(registered) = &mut *object else {
                return Err(BrokerError::InvalidRights);
            };
            if scope.is_some_and(|scope| scope != registered.subject.scope) {
                return Err(BrokerError::InvalidRights);
            }
            let current = self.authority();
            if registered.admitted_under.as_ptr() != Arc::as_ptr(&current) {
                if !current.admits(&registered.subject) {
                    return Err(BrokerError::StaleSubject);
                }
                registered.admitted_under = Arc::downgrade(&current);
            }
            (Arc::clone(&registered.subject), current)
        };
        Ok(operation(&subject, &authority))
    }
}

fn authority_error(error: AuthorityError) -> BrokerError {
    match error {
        AuthorityError::TooManyTerms | AuthorityError::SetTooLarge => {
            BrokerError::ResourceExhausted
        }
        AuthorityError::OutOfMemory => BrokerError::OutOfMemory,
        AuthorityError::NotRestriction
        | AuthorityError::UnmappedPrincipal
        | AuthorityError::DenyOnlyOverlap
        | AuthorityError::InvalidPrivileges => BrokerError::PolicyDenied,
    }
}

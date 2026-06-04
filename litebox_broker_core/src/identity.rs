// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::{BrokerCore, Result, allocate_id};

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same association-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    Unauthenticated,
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) struct $name(u64);

        impl $name {
            pub(crate) const fn new(raw: u64) -> Self {
                Self(raw)
            }
        }
    };
}

id_type! {
    /// Process-local broker core identity.
    BrokerCoreId
}

static NEXT_CORE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn allocate_core_id() -> BrokerCoreId {
    BrokerCoreId::new(NEXT_CORE_ID.fetch_add(1, Ordering::Relaxed))
}

id_type! {
    /// Broker-assigned sandbox session identity.
    SessionId
}

impl SessionId {
    pub(crate) const FIRST: Self = Self::new(1);
}

id_type! {
    /// Broker-assigned guest process identity.
    ProcessId
}

/// Broker-assigned identity for one caller association.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AssociationIdentity {
    core: BrokerCoreId,
    session: SessionId,
    process: ProcessId,
}

impl AssociationIdentity {
    const fn new(core_id: BrokerCoreId, session_id: SessionId, process_id: ProcessId) -> Self {
        Self {
            core: core_id,
            session: session_id,
            process: process_id,
        }
    }
}

/// Broker-owned authority token for one authenticated caller association.
///
/// User mode does not choose this value. The broker entry layer authenticates
/// the caller, then BrokerCore assigns this identity for all operations received
/// on that association. The token is scoped by a process-local BrokerCore
/// identity so handles cannot be replayed across distinct core instances.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerAssociation {
    /// Broker-assigned sandbox session and guest process identity.
    identity: AssociationIdentity,
    /// Broker-entry-authenticated caller credential for this association.
    caller_credential: CallerCredential,
}

impl BrokerAssociation {
    /// Creates an authenticated association identity.
    pub(crate) const fn new(
        core_id: BrokerCoreId,
        session_id: SessionId,
        process_id: ProcessId,
        caller_credential: CallerCredential,
    ) -> Self {
        Self {
            identity: AssociationIdentity::new(core_id, session_id, process_id),
            caller_credential,
        }
    }

    pub(crate) const fn identity(&self) -> AssociationIdentity {
        self.identity
    }

    /// Returns the broker-entry-authenticated caller credential for this association.
    pub const fn caller_credential(&self) -> CallerCredential {
        self.caller_credential
    }
}

impl<P> BrokerCore<P> {
    /// Allocates broker authority state for one authenticated caller association.
    pub fn create_association(
        &mut self,
        caller_credential: CallerCredential,
    ) -> Result<BrokerAssociation> {
        let process_id = allocate_id(&mut self.next_process_id)?;
        // The POC models one sandbox session per BrokerCore; multi-session
        // allocation belongs with the future deployment/session manager.
        let association = BrokerAssociation::new(
            self.core_id,
            SessionId::FIRST,
            ProcessId::new(process_id),
            caller_credential,
        );
        Ok(association)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultDenyPolicy;

    #[test]
    fn create_association_assigns_distinct_identities_and_preserves_credential() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);

        let first = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let second = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();

        assert_ne!(first.identity(), second.identity());
        assert_eq!(first.caller_credential(), CallerCredential::Unauthenticated);
        assert_eq!(
            second.caller_credential(),
            CallerCredential::Unauthenticated
        );
    }

    #[test]
    fn create_association_scopes_identity_to_core_instance() {
        let mut first_core = BrokerCore::new(DefaultDenyPolicy);
        let mut second_core = BrokerCore::new(DefaultDenyPolicy);

        let first = first_core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let second = second_core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();

        assert_ne!(first.identity(), second.identity());
    }
}

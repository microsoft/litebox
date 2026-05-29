// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{BrokerCore, Result, allocate_id};

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same connection-creation seam.
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

/// Broker-assigned identity bound to one authenticated caller association.
///
/// User mode does not choose this value. The broker entry layer authenticates
/// the caller, then BrokerCore assigns this identity for all operations received
/// on that association.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Association {
    /// Broker-assigned sandbox session identity.
    session_id: SessionId,
    /// Broker-assigned guest process identity.
    process_id: ProcessId,
    /// Broker-entry-authenticated caller credential for this association.
    caller_credential: CallerCredential,
}

impl Association {
    /// Creates an authenticated association identity.
    pub(crate) const fn new(
        session_id: SessionId,
        process_id: ProcessId,
        caller_credential: CallerCredential,
    ) -> Self {
        Self {
            session_id,
            process_id,
            caller_credential,
        }
    }

    pub(crate) const fn caller_credential(self) -> CallerCredential {
        self.caller_credential
    }
}

impl<P> BrokerCore<P> {
    /// Allocates a broker association for one process connection.
    pub(crate) fn create_association(
        &mut self,
        caller_credential: CallerCredential,
    ) -> Result<Association> {
        let process_id = allocate_id(&mut self.next_process_id)?;
        // The POC models one sandbox session per BrokerCore; multi-session
        // allocation belongs with the future deployment/session manager.
        let association = Association::new(
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
    use crate::{BrokerError, DefaultDenyPolicy};

    #[test]
    fn create_association_uses_one_session_and_distinct_processes() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);

        let first = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let second = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();

        assert_eq!(first.session_id, SessionId::FIRST);
        assert_eq!(second.session_id, SessionId::FIRST);
        assert_eq!(first.process_id, ProcessId::new(1));
        assert_eq!(second.process_id, ProcessId::new(2));
        assert_eq!(first.caller_credential(), CallerCredential::Unauthenticated);
        assert_eq!(
            second.caller_credential(),
            CallerCredential::Unauthenticated
        );
    }

    #[test]
    fn create_association_issues_max_process_id_then_exhausts() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);
        core.next_process_id = u64::MAX;

        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(association.process_id, ProcessId::new(u64::MAX));
        assert_eq!(association.session_id, SessionId::FIRST);
        assert_eq!(core.next_process_id, 0);
        assert_eq!(
            core.create_association(CallerCredential::Unauthenticated),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(core.next_process_id, 0);
    }
}

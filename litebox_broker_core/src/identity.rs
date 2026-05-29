// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{BrokerCore, Result, allocate_id};
use litebox_broker_transport::PeerCredential;

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

/// Broker-assigned identity bound to one authenticated transport association.
///
/// User mode does not choose this value. The userland broker transport or a
/// future BrokerHost authenticates the peer, then BrokerCore assigns this
/// identity for all requests received on that association.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Association {
    /// Broker-assigned sandbox session identity.
    session_id: SessionId,
    /// Broker-assigned guest process identity.
    process_id: ProcessId,
    /// Transport-authenticated peer credential for this association.
    peer_credential: PeerCredential,
}

impl Association {
    /// Creates an authenticated association identity.
    pub(crate) const fn new(
        session_id: SessionId,
        process_id: ProcessId,
        peer_credential: PeerCredential,
    ) -> Self {
        Self {
            session_id,
            process_id,
            peer_credential,
        }
    }

    pub(crate) const fn peer_credential(self) -> PeerCredential {
        self.peer_credential
    }
}

impl<P> BrokerCore<P> {
    /// Allocates a transport-bound broker association for one process connection.
    pub(crate) fn create_association(
        &mut self,
        peer_credential: PeerCredential,
    ) -> Result<Association> {
        let process_id = allocate_id(&mut self.next_process_id)?;
        // The POC models one sandbox session per BrokerCore; multi-session
        // allocation belongs with the future deployment/session manager.
        let association = Association::new(
            SessionId::FIRST,
            ProcessId::new(process_id),
            peer_credential,
        );
        Ok(association)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultDenyPolicy;
    use litebox_broker_protocol::ErrorCode;

    #[test]
    fn create_association_uses_one_session_and_distinct_processes() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);

        let first = core
            .create_association(PeerCredential::Unauthenticated)
            .unwrap();
        let second = core
            .create_association(PeerCredential::Unauthenticated)
            .unwrap();

        assert_eq!(first.session_id, SessionId::FIRST);
        assert_eq!(second.session_id, SessionId::FIRST);
        assert_eq!(first.process_id, ProcessId::new(1));
        assert_eq!(second.process_id, ProcessId::new(2));
        assert_eq!(first.peer_credential(), PeerCredential::Unauthenticated);
        assert_eq!(second.peer_credential(), PeerCredential::Unauthenticated);
    }

    #[test]
    fn create_association_issues_max_process_id_then_exhausts() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);
        core.next_process_id = u64::MAX;

        let association = core
            .create_association(PeerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(association.process_id, ProcessId::new(u64::MAX));
        assert_eq!(association.session_id, SessionId::FIRST);
        assert_eq!(core.next_process_id, 0);
        assert_eq!(
            core.create_association(PeerCredential::Unauthenticated),
            Err(ErrorCode::ResourceExhausted)
        );
        assert_eq!(core.next_process_id, 0);
    }
}

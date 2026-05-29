// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::identity::Association;
use crate::{BrokerCore, CallerCredential, Result};

/// Broker-side authority state for one caller connection.
///
/// This type intentionally carries only BrokerCore association identity. Protocol
/// negotiation, request sequencing, and transport state live in the server layer.
pub struct BrokerConnection {
    association: Association,
}

impl BrokerConnection {
    pub(crate) const fn new(association: Association) -> Self {
        Self { association }
    }

    pub(crate) const fn association(&self) -> Association {
        self.association
    }

    /// Returns the broker-entry-authenticated caller credential for this connection.
    pub const fn caller_credential(&self) -> CallerCredential {
        self.association.caller_credential()
    }
}

impl<P> BrokerCore<P> {
    /// Allocates broker authority state for one caller connection.
    pub fn create_connection(
        &mut self,
        caller_credential: CallerCredential,
    ) -> Result<BrokerConnection> {
        self.create_association(caller_credential)
            .map(BrokerConnection::new)
    }

    /// Closes a broker connection and releases state owned by its association.
    pub fn close_connection(&mut self, connection: BrokerConnection) {
        self.close_association(connection.association);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerCore, EventOnlyPolicy};

    #[test]
    fn close_connection_releases_owned_references_and_orphaned_objects() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let connection = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();

        let _handle = core.create_event(&connection).unwrap();
        assert_eq!(core.references.len(), 1);
        assert_eq!(core.objects.len(), 1);

        core.close_connection(connection);

        assert!(core.references.is_empty());
        assert!(core.objects.is_empty());
    }
}

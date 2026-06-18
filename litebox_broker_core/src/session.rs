// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::BrokerCore;

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
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        self.core.close_session(self.session_id);
    }
}

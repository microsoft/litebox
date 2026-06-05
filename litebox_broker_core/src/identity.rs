// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

/// Broker-assigned guest process identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProcessId(u64);

impl ProcessId {
    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }
}

/// Broker-owned authority token for one authenticated caller association.
///
/// User mode does not choose this value. The broker entry layer authenticates
/// the caller, then BrokerCore assigns this identity for all operations received
/// on that association.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerAssociation {
    /// Broker-assigned guest process identity.
    process_id: ProcessId,
    /// Broker-entry-authenticated caller credential for this association.
    caller_credential: CallerCredential,
}

impl BrokerAssociation {
    /// Creates an authenticated association identity.
    pub(crate) const fn new(process_id: ProcessId, caller_credential: CallerCredential) -> Self {
        Self {
            process_id,
            caller_credential,
        }
    }

    pub(crate) const fn process_id(&self) -> ProcessId {
        self.process_id
    }

    /// Returns the broker-entry-authenticated caller credential for this association.
    pub const fn caller_credential(&self) -> CallerCredential {
        self.caller_credential
    }
}

impl BrokerCore {
    /// Allocates broker authority state for one authenticated caller association.
    pub fn create_association(
        &mut self,
        caller_credential: CallerCredential,
    ) -> Result<BrokerAssociation> {
        let process_id = allocate_id(&mut self.next_process_id)?;
        let association = BrokerAssociation::new(ProcessId::new(process_id), caller_credential);
        Ok(association)
    }
}

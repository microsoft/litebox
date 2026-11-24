// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original signals-kind projection, not send, delivery, or ownership policy.

use super::SignalsObject;
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub(crate) open spec fn signals_projection(entry: &ObjectEntry, result: Result<&SignalsObject>) -> bool {
    match entry {
        ObjectEntry::Signals(signals) => result == Ok(signals),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub closed spec fn signals_projection_policy() -> bool {
    forall|entry: &ObjectEntry, result: Result<&SignalsObject>|
        #[trigger] ObjectEntry::as_signals.ensures((entry,), result)
            ==> signals_projection(entry, result)
}

pub proof fn prove_signals_projection()
    ensures signals_projection_policy(),
{
}

}

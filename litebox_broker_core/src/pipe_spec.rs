// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Contract for the original private `ObjectEntry::as_pipe` implementation.
//! This checks kind and borrowed payload value, not caller rights or raw
//! pointer identity. Pipe contents and synchronization remain in progress.

use super::PipeObject;
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub(crate) open spec fn pipe_projection(entry: &ObjectEntry, result: Result<&PipeObject>) -> bool {
    match entry {
        ObjectEntry::Pipe(pipe) => result == Ok(pipe),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub closed spec fn pipe_projection_policy() -> bool {
    forall|entry: &ObjectEntry, result: Result<&PipeObject>|
        #[trigger] ObjectEntry::as_pipe.ensures((entry,), result) ==> pipe_projection(entry, result)
}

pub proof fn prove_pipe_projection()
    ensures pipe_projection_policy(),
{
}

}

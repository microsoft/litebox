// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original file-kind projection, not file-system policy or native authority.
//! The file payload remains opaque and explicitly in progress in object_spec.

use super::File;
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub(crate) open spec fn file_projection(entry: &ObjectEntry, result: Result<&File>) -> bool {
    match entry {
        ObjectEntry::File(file) => result == Ok(file),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub closed spec fn file_projection_policy() -> bool {
    forall|entry: &ObjectEntry, result: Result<&File>|
        #[trigger] ObjectEntry::as_file.ensures((entry,), result) ==> file_projection(entry, result)
}

pub proof fn prove_file_projection()
    ensures file_projection_policy(),
{
}

}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kind-level duplication policy for the original `ObjectEntry::is_duplicable`.
//! This proves neither caller rights nor policy/provenance checks at transfer.
//! Payloads are in progress and opaque: only the original enum's kind is used.

use super::ObjectEntry;
use vstd::prelude::*;

verus! {

pub(crate) open spec fn permitted_by_kind(entry: &ObjectEntry) -> bool {
    ||| entry is Event
    ||| entry is File
    ||| entry is UnixSocket
    ||| entry is Pipe
    ||| entry is Socket
    ||| entry is VsockSocket
    ||| entry is Timer
    ||| entry is ReadinessQueue
    ||| entry is Process
}

pub closed spec fn duplication_policy() -> bool {
    forall|entry: &ObjectEntry, result: bool|
        ObjectEntry::is_duplicable.ensures((entry,), result)
            ==> result == permitted_by_kind(entry)
}

pub proof fn prove_duplication_policy()
    ensures duplication_policy(),
{
}

}

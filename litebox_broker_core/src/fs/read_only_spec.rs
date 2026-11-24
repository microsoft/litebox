// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read semantics of the original read-only permission marker only.
//! Mode is an opaque native value: no bit, access or backend contract is assumed.
//! Ownership/mode values are preserved; ByBackend remains ByBackend.
//! This does not prove that any backend checks or enforces the marker.

use super::super::backend::{PermissionCheck, PermissionInfo};
use vstd::prelude::*;

verus! {

pub open spec fn readonly_metadata(before: PermissionCheck) -> PermissionCheck {
    match before {
        PermissionCheck::ByBackend => PermissionCheck::ByBackend,
        PermissionCheck::ByResolver(info) => PermissionCheck::ByResolver(PermissionInfo {
            mode: info.mode,
            owner: info.owner,
            on_read_only_fs: true,
        }),
    }
}

pub closed spec fn readonly_metadata_policy() -> bool {
    &&& (forall|prev: PermissionCheck|
        #[trigger] apply_readonly_transition.requires((prev,)))
    &&& (forall|prev: PermissionCheck, cur: PermissionCheck|
        #[trigger] readonly_transition(prev, cur)
            ==> cur == readonly_metadata(prev))
}

pub proof fn prove_readonly_metadata()
    ensures readonly_metadata_policy(),
{
}

// Two real calls establish idempotence as well as exact ownership/mode framing.
pub fn check_readonly_twice(before: PermissionCheck) -> (after: PermissionCheck)
    ensures after == readonly_metadata(before),
{
    let mut after = before;
    super::mark_read_only(&mut after);

    super::mark_read_only(&mut after);
    after
}


fn apply_readonly_transition(prev: PermissionCheck) -> (cur: PermissionCheck)
    ensures cur == readonly_metadata(prev),
{
    let mut cur = prev;

    super::mark_read_only(&mut cur);

    cur
}


closed spec fn readonly_transition(prev: PermissionCheck, cur: PermissionCheck) -> bool {
    apply_readonly_transition.ensures((prev,), cur)
}

}

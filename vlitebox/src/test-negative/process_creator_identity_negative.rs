// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately replaces a nonzero creator number with zero.

use vlitebox::spec::process_identity_spec::{ProcessGroupId, ProcessId, SessionId};
use vstd::prelude::*;

verus! {

pub fn reject_changed_creator_identity(creator: ProcessId)
    -> (result: (ProcessGroupId, SessionId))
    requires creator.0 != 0,
    ensures {
        &&& result.0.0 == 0
        &&& result.1.0 == 0
    },
{
    vlitebox::process_identity_proof::check_creator_group_and_session(creator)
}

}

fn main() {}

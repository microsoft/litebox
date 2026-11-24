// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Actual Into calls consume the checked original creator conversions.

use crate::process_identity_spec::{ProcessGroupId, ProcessId, SessionId, process_identity_policy};
use vstd::prelude::*;

verus! {

pub proof fn original_creator_identity_conversions_preserve_numbers()
    ensures process_identity_policy(),
{
    litebox_broker_protocol::process_identity_spec::prove_process_identity_conversions();
}

pub fn check_creator_group_and_session(creator: ProcessId)
    -> (result: (ProcessGroupId, SessionId))
    ensures {
        &&& result.0.0 == creator.0
        &&& result.1.0 == creator.0
    },
{
    let group: ProcessGroupId = creator.into();

    let session: SessionId = creator.into();

    (group, session)
}

}

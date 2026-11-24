// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original executable crate as well as this composition target.
//! No custom assumptions are used.

use crate::event_spec::event_kind_projection_policy;
use vstd::prelude::*;

verus! {

pub proof fn event_projection_preserves_kind_and_borrowed_state()
    ensures event_kind_projection_policy(),
{
    litebox_broker_core::event::verification::prove_event_projection();
}

}

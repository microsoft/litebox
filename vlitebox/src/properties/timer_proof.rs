// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original executable crate as well as this composition target.
//! No custom assumptions are used.

use crate::timer_spec::timer_kind_projection_policy;
use vstd::prelude::*;

verus! {

pub proof fn timer_projections_preserve_kind_value_and_borrowed_state()
    ensures timer_kind_projection_policy(),
{
    litebox_broker_core::verification::prove_timer_projection();
}

}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read together with the original timer accessor annotations and
//! `litebox_broker_core/src/timer_spec.rs`. This specifies both projections,
//! not timer scheduling or access control.

use vstd::prelude::*;

verus! {

pub open spec fn timer_kind_projection_policy() -> bool {
    litebox_broker_core::timer::verification::timer_projection_policy()
}

}

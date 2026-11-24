// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false regression: verification must fail.
//! Run with `cargo verus focus -p vlitebox --example timer_projection_negative`.

use vstd::prelude::*;

verus! {

proof fn reject_negated_timer_projection()
    ensures !vlitebox::timer_spec::timer_kind_projection_policy(),
{
    vlitebox::timer_proof::timer_projections_preserve_kind_value_and_borrowed_state();
}

}

fn main() {}

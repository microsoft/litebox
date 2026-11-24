// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false regression: verification must fail.
//! Run with `cargo verus focus -p vlitebox --example event_projection_negative`.

use vstd::prelude::*;

verus! {

proof fn reject_negated_event_projection()
    ensures !vlitebox::spec::event_spec::event_kind_projection_policy(),
{
    vlitebox::event_proof::event_projection_preserves_kind_and_borrowed_state();
}

}

fn main() {}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false regression: verification must fail.
//! Run with `cargo verus focus -p vlitebox --example pipe_projection_negative`.

use vstd::prelude::*;

verus! {

proof fn reject_negated_pipe_projection()
    ensures !vlitebox::spec::pipe_spec::pipe_kind_projection_policy(),
{
    vlitebox::pipe_proof::pipe_projection_checks_kind_and_value();
}

}

fn main() {}

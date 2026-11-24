// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false regression: verification must fail.
//! Run with `cargo verus focus -p vlitebox --example object_policy_negative`.

use vstd::prelude::*;

verus! {

proof fn reject_negated_object_policy()
    ensures !vlitebox::object_spec::object_kind_duplication_policy(),
{
    vlitebox::object_proof::object_kind_duplication_is_enforced();
}

}

fn main() {}

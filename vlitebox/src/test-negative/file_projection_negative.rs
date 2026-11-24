// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false regression: verification must fail.

use vstd::prelude::*;

verus! {

proof fn reject_negated_file_projection()
    ensures !vlitebox::file_projection_spec::file_kind_projection_policy(),
{
    vlitebox::file_projection_proof::file_projection_checks_kind_and_value();
}

}

fn main() {}

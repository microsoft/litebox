// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false regression: verification must fail.

use vstd::prelude::*;

verus! {

proof fn reject_negated_ipc_projections()
    ensures !vlitebox::spec::ipc_projection_spec::unix_socket_and_signals_projection_policy(),
{
    vlitebox::ipc_projection_proof::unix_socket_and_signals_projections_are_exact();
}

}

fn main() {}

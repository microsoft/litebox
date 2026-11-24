// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original executable crate as well as this composition target.
//! No custom assumptions are used.

use crate::spec::pipe_spec::pipe_kind_projection_policy;
use vstd::prelude::*;

verus! {

pub proof fn pipe_projection_checks_kind_and_value()
    ensures pipe_kind_projection_policy(),
{
    litebox_broker_core::pipe::verification::prove_pipe_projection();
}

}

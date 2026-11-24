// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read together with `litebox_broker_core/src/pipe_spec.rs` and the
//! original `as_pipe` annotation. This is not a pipe access-control theorem.

use vstd::prelude::*;

verus! {

pub open spec fn pipe_kind_projection_policy() -> bool {
    litebox_broker_core::pipe::verification::pipe_projection_policy()
}

}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked marker/frame proof, not read-only backend enforcement.
//! Independently check the original protocol and core; no custom behavioral
//! assumption is added by this slice.

use crate::spec::readonly_metadata_spec::readonly_metadata_policy;
use vstd::prelude::*;

verus! {

pub proof fn readonly_marker_sets_only_the_resolver_flag()
    ensures readonly_metadata_policy(),
{
    litebox_broker_core::fs::read_only::verification::prove_readonly_metadata();
}

}

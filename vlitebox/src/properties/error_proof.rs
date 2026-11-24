// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original platform, protocol, and broker crates as well as this target.
//! No custom assumptions are used.

use crate::spec::error_spec::error_category_policy;
use vstd::prelude::*;

verus! {

pub proof fn blocking_and_protocol_error_categories_are_exact()
    ensures error_category_policy(),
{
    litebox_broker_core::error::verification::prove_error_categories();
}

}

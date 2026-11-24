// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original executable crate as well as this composition target.
//! Uses existing vstd vector/allocation, Result/closure, and `?` identity
//! conversion contracts, not custom assumptions.

use crate::spec::transfer_spec::staging_buffer_policy;
use vstd::prelude::*;

verus! {

pub proof fn transfer_staging_is_zero_initialized()
    ensures staging_buffer_policy(),
{
}

}

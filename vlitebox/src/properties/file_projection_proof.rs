// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original executable crate as well as this composition target.
//! No custom assumptions are used.

use crate::file_projection_spec::file_kind_projection_policy;
use vstd::prelude::*;

verus! {

pub proof fn file_projection_checks_kind_and_value()
    ensures file_kind_projection_policy(),
{
    litebox_broker_core::verification::prove_file_projection();
}

}

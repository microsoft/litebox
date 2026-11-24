// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked property; requires the original core body to be
//! verified as well as this composition target. No custom assumptions used.

use crate::object_spec::object_kind_duplication_policy;
use vstd::prelude::*;

verus! {

pub proof fn object_kind_duplication_is_enforced()
    ensures object_kind_duplication_policy(),
{
    litebox_broker_core::object::verification::prove_duplication_policy();
}

}

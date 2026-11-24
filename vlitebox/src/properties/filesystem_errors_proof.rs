// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked; independently check the original platform and core.
//! The filesystem-error slice uses no custom behavioral assumptions.

use crate::filesystem_errors_spec::filesystem_error_policy;
use vstd::prelude::*;

verus! {

pub proof fn filesystem_fault_and_storage_error_conversions_are_exact()
    ensures filesystem_error_policy(),
{
    litebox_broker_core::fs::errors::verification::prove_filesystem_error_conversions();
}

}

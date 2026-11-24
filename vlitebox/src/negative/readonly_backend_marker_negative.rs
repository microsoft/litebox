// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately turns a self-enforcing backend into resolver-owned permissions.

use litebox_broker_core::fs::{
    backend::PermissionCheck, read_only::verification::check_readonly_twice,
};
use vstd::prelude::*;

verus! {

pub fn reject_reclassifying_backend_permissions() -> (after: PermissionCheck)
    ensures matches!(after, PermissionCheck::ByResolver(_)),
{
    check_readonly_twice(PermissionCheck::ByBackend)
}

}

fn main() {}

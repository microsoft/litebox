// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately leaves the resolver's read-only marker unset.

use litebox_broker_core::fs::{
    backend::{PermissionCheck, PermissionInfo},
    read_only::verification::check_readonly_twice,
};
use vstd::prelude::*;

verus! {

pub fn reject_leaving_resolver_permissions_writable(
    before: PermissionInfo,
) -> (after: PermissionCheck)
    requires !before.on_read_only_fs,
    ensures after == PermissionCheck::ByResolver(before),
{
    check_readonly_twice(PermissionCheck::ByResolver(before))
}

}

fn main() {}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the original mark_read_only annotation, read_only_spec.rs,
//! native PermissionCheck/PermissionInfo, and protocol FileUser/FileMode.
//! Native FileMode is explicitly opaque/in progress; no generated bit-operation
//! contract or backend enforcement behavior is assumed. The marker preserves
//! mode/owner values, sets the resolver flag, and leaves ByBackend unchanged.
//! This is not a read-only filesystem, access-decision or noninterference proof.

use vstd::prelude::*;

verus! {

pub open spec fn readonly_metadata_policy() -> bool {
    litebox_broker_core::fs::read_only::verification::readonly_metadata_policy()
}

}

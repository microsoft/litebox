// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the original `as_file` annotation and
//! `litebox_broker_core/src/fs/service_spec.rs`. This asserts kind and borrowed
//! payload value, not pointer identity, rights, path confinement, or file I/O.

use vstd::prelude::*;

verus! {

pub open spec fn file_kind_projection_policy() -> bool {
    litebox_broker_core::verification::file_projection_policy()
}

}

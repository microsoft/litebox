// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read together with `litebox_broker_core/src/object_spec.rs` and the
//! original enum/method annotations in `litebox_broker_core/src/object.rs`.
//! Only object-kind eligibility is covered, not transfer authorization.

use vstd::prelude::*;

verus! {

pub open spec fn object_kind_duplication_policy() -> bool {
    litebox_broker_core::object::verification::duplication_policy()
}

}

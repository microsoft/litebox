// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the original helper annotations, native protocol key/word
//! size, and `litebox_broker_core/src/shared_futex_spec.rs`. Shape validation
//! and waiter projection do not establish ID authentication or access control.

use litebox_broker_protocol::shared_futex::SharedFutexKey;
use vstd::prelude::*;

verus! {

pub open spec fn shared_futex_input_shape(key: SharedFutexKey, bitset: u32) -> bool {
    litebox_broker_core::shared_futex::verification::well_formed_futex_request(key, bitset)
}

pub open spec fn shared_futex_leaf_policy() -> bool {
    litebox_broker_core::shared_futex::verification::shared_futex_leaf_policy()
}

}

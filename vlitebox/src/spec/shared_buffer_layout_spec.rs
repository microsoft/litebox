// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the original five SharedBufferLayout methods and the exact
//! semantics/views in litebox_broker_protocol/src/shared_buffer_spec.rs.
//! Construction succeeds exactly for nonzero dimensions whose mathematical
//! product fits isize::MAX; successful layouts store that product.
//! Range checks cover arbitrary layout values, with explicit error precedence.
//! Containment additionally requires the explicitly defined well-formedness
//! established by construction: it is not an assumed datatype invariant.
//! Successful ranges in distinct slots are separated without assuming even
//! well-formedness. This is geometric separation, not peer ownership or isolation.
//! No custom assumptions. Derived methods, slot sequences, peer ownership,
//! memory attachment, concurrent snapshots and transport remain unverified.

use vstd::prelude::*;

pub use litebox_broker_protocol::shared_buffer::ranges_separated;

verus! {

pub open spec fn shared_buffer_layout_policy() -> bool {
    litebox_broker_protocol::shared_buffer::shared_buffer_layout_policy()
}

}

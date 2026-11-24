// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read together with the original `as_event_mut` annotation and
//! `litebox_broker_core/src/event_spec.rs`. This specifies kind, borrowed
//! payload value, and mutable-loan framing, not event counter authorization.

use vstd::prelude::*;

verus! {

pub open spec fn event_kind_projection_policy() -> bool {
    litebox_broker_core::event::verification::event_projection_policy()
}

}

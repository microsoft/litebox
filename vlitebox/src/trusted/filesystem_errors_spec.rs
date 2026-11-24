// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the seven original conversion annotations and semantic/From
//! definitions in litebox_broker_core/src/fs/{errors,errors_spec}.rs, plus the
//! native Fault and BrokerError conversion. No custom assumptions are added.
//! This proves error translation, not I/O, authorization, or correct failure.

use vstd::prelude::*;

verus! {

pub open spec fn filesystem_error_policy() -> bool {
    litebox_broker_core::fs::errors::verification::filesystem_error_policy()
}

}

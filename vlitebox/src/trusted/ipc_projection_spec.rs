// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Only the original Unix-socket and signals kind/payload projections.
//! Review both original annotations and their crate-local specification files.
//! No pointer identity, connection, delivery, or caller rights are asserted.

use vstd::prelude::*;

verus! {

pub open spec fn unix_socket_and_signals_projection_policy() -> bool {
    &&& litebox_broker_core::unix_socket::verification::unix_socket_projection_policy()
    &&& litebox_broker_core::signal::verification::signals_projection_policy()
}

}

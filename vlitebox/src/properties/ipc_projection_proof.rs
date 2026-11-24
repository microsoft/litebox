// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original executable crate as well as this composition target.
//! No custom assumptions are used.

use crate::spec::ipc_projection_spec::unix_socket_and_signals_projection_policy;
use vstd::prelude::*;

verus! {

pub proof fn unix_socket_and_signals_projections_are_exact()
    ensures unix_socket_and_signals_projection_policy(),
{
    litebox_broker_core::unix_socket::verification::prove_unix_socket_projection();
    litebox_broker_core::signal::verification::prove_signals_projection();
}

}

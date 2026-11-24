// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub fn wrongly_clamps_constructor_socket_quota(sockets: usize, per_process: usize)
    -> (cur: BrokerCoreLimits)
    requires per_process > sockets,
    ensures cur.max_sockets_per_process <= cur.max_sockets,
{
    BrokerCoreLimits::new_with_all_limits(0, 0, sockets, per_process)
}

}

fn main() {}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::signal::verification;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::signal::MAX_SIGNAL;
use vstd::prelude::*;

verus! {

pub fn wrongly_flips_the_cloned_sender_query(senders: [Option<ProcessId>; MAX_SIGNAL as usize])
    -> (result: ([Option<ProcessId>; MAX_SIGNAL as usize], bool, bool))
    ensures result.1 != result.2,
{
    verification::check_cloned_pending_sender_array(senders)
}

}

fn main() {}

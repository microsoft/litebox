// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::verification;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::signal::MAX_SIGNAL;
use vstd::prelude::*;

verus! {

pub fn wrongly_reports_no_pending_sender(
    senders: [Option<ProcessId>; MAX_SIGNAL as usize],
    index: usize,
) -> (result: bool)
    requires {
        &&& index < MAX_SIGNAL as usize
        &&& senders[index as int].is_some()
    },
    ensures result,
{
    verification::check_pending_sender_array(senders)
}

}

fn main() {}

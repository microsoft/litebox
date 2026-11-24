// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub fn wrongly_changes_thread_ceiling(prev: BrokerCoreLimits, files: usize)
    -> (cur: BrokerCoreLimits)
    requires files != prev.max_threads,
    ensures cur.max_threads == files,
{
    prev.with_shared_file_limit(files)
}

}

fn main() {}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub fn wrongly_changes_the_cloned_shared_file_limit(prev: BrokerCoreLimits)
    -> (cur: BrokerCoreLimits)
    ensures cur.max_shared_files != prev.max_shared_files,
{
    prev.clone()
}

}

fn main() {}

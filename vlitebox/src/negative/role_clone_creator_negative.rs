// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{ProcessGroupId, ProcessId};
use vstd::prelude::*;

verus! {

pub fn wrongly_changes_the_cloned_group_creator(creator: ProcessId) -> (cur: ProcessGroupId)
    ensures cur.0 != creator.0,
{
    let group: ProcessGroupId = creator.into();

    group.clone()
}

}

fn main() {}

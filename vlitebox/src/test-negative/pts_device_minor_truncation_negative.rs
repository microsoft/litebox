// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::fs::devices::verification;
use vstd::prelude::*;

verus! {

pub fn wrongly_truncates_the_native_device_minor(index: u32) -> (bits: u64)
    requires index >= 256,
    ensures (bits & 0xff) == index as u64,
{
    let number = verification::check_pts_device_number(index);

    number.get()
}

}

fn main() {}

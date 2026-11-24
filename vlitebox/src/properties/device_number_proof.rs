// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Actual encoder/getter calls preserve full indices, not terminal authority.

use litebox_broker_core::fs::devices::verification;
use vstd::prelude::*;

verus! {

pub proof fn original_pts_encoder_has_the_exact_numeric_policy()
    ensures verification::pts_device_number_policy(),
{
    verification::prove_pts_device_number_policy();
}

pub fn check_native_pts_device_number(index: u32) -> (bits: u64)
    ensures {
        &&& bits == verification::pts_device_bits(index)
        &&& bits != 0
        &&& verification::pts_device_minor(bits) == index
        &&& verification::pts_device_major(bits) == 136
    },
{
    let number = verification::check_pts_device_number(index);

    number.get()
}

pub fn check_distinct_native_pts_device_numbers(left: u32, right: u32)
    -> (result: (u64, u64))
    requires left != right,
    ensures {
        &&& result.0 == verification::pts_device_bits(left)
        &&& result.1 == verification::pts_device_bits(right)
        &&& verification::pts_device_minor(result.0) == left
        &&& verification::pts_device_minor(result.1) == right
        &&& result.0 != result.1
    },
{
    let left_number = verification::check_pts_device_number(left);

    let right_number = verification::check_pts_device_number(right);

    (left_number.get(), right_number.get())
}

}

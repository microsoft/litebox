// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Actual numeric device encoding, not path validation, allocation or authority.

use super::{PTS_MAJOR, pts_rdev};
use core::num::NonZeroU64;
use vstd::prelude::*;

verus! {

pub closed spec fn pts_device_bits(index: u32) -> u64 {
    ((index as u64) & 0xff) | (PTS_MAJOR << 8) | (((index as u64) & !0xffu64) << 12)
}

pub open spec fn pts_device_minor(bits: u64) -> u32 {
    ((bits & 0xff) | ((bits >> 12) & 0xffffff00)) as u32
}

pub open spec fn pts_device_major(bits: u64) -> u64 {
    (bits >> 8) & 0xff
}

pub closed spec fn pts_device_number_policy() -> bool {
    forall|index: u32, result: NonZeroU64|
        #[trigger] pts_rdev.ensures((index,), result) ==> {
            &&& result.get() == pts_device_bits(index)
            &&& result.get() != 0
        }
}

pub proof fn prove_pts_device_layout(index: u32)
    ensures {
        &&& pts_device_minor(pts_device_bits(index)) == index
        &&& pts_device_major(pts_device_bits(index)) == 136
    },
{
    reveal(pts_device_bits);

    assert(PTS_MAJOR == 136);

    assert(pts_device_minor(pts_device_bits(index)) == index) by(bit_vector);

    assert(pts_device_major(pts_device_bits(index)) == 136) by(bit_vector);
}

pub proof fn prove_pts_device_number_policy()
    ensures pts_device_number_policy(),
{
    reveal(pts_device_bits);
}

// Erased consumer of the original encoder; no replacement runtime encoder.
pub fn check_pts_device_number(index: u32) -> (result: NonZeroU64)
    ensures {
        &&& result.get() == pts_device_bits(index)
        &&& result.get() != 0
        &&& pts_device_minor(result.get()) == index
        &&& pts_device_major(result.get()) == 136
    },
{
    let result = pts_rdev(index);

    proof {
        reveal(pts_device_bits);

        prove_pts_device_layout(index);
    }

    result
}

}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Must-read semantics, included in the original module to preserve private fields.
// No invariant is assumed for arbitrary SharedBufferLayout values. Construction
// establishes well-formedness; range's contract covers even malformed layouts.
// Derived operations, slot sequences, peer ownership and transport are unverified.

use vstd::arithmetic::mul::{
    lemma_mul_inequality, lemma_mul_is_commutative, lemma_mul_is_distributive_add_other_way,
};
use vstd::prelude::*;

verus! {

pub closed spec fn layout_slot_size(layout: SharedBufferLayout) -> u32 {
    layout.slot_size
}

pub closed spec fn layout_slot_count(layout: SharedBufferLayout) -> u32 {
    layout.slot_count
}

pub closed spec fn layout_length(layout: SharedBufferLayout) -> usize {
    layout.total_len
}

pub open spec fn layout_well_formed(layout: SharedBufferLayout) -> bool {
    &&& layout_slot_size(layout) > 0
    &&& layout_slot_count(layout) > 0
    &&& layout_length(layout)
            == (layout_slot_size(layout) as int) * (layout_slot_count(layout) as int)
    &&& layout_length(layout) <= isize::MAX
}

pub open spec fn layout_creation(
    slot_size: u32,
    slot_count: u32,
    result: Result<SharedBufferLayout, SharedBufferLayoutError>,
) -> bool {
    if slot_size > 0 && slot_count > 0
        && (slot_size as int) * (slot_count as int) <= isize::MAX
    {
        match result {
            Ok(layout) => layout_slot_size(layout) == slot_size
                && layout_slot_count(layout) == slot_count
                && layout_well_formed(layout),
            Err(_) => false,
        }
    } else {
        result == Err(SharedBufferLayoutError::InvalidLayout)
    }
}

pub open spec fn slot_range(
    layout: SharedBufferLayout,
    slot: SharedBufferSlotIndex,
    length: usize,
    result: Result<Range<usize>, SharedBufferLayoutError>,
) -> bool {
    let offset = (slot.0 as int) * (layout_slot_size(layout) as int);
    if slot.0 >= layout_slot_count(layout) {
        result == Err(SharedBufferLayoutError::InvalidSlot)
    } else if length > layout_slot_size(layout) {
        result == Err(SharedBufferLayoutError::RangeExceedsSlot)
    } else if offset > usize::MAX {
        result == Err(SharedBufferLayoutError::InvalidLayout)
    } else if offset + length > usize::MAX {
        result == Err(SharedBufferLayoutError::RangeExceedsSlot)
    } else {
        match result {
            Ok(range) => range.start == offset && range.end == offset + length,
            Err(_) => false,
        }
    }
}

pub proof fn prove_slot_range_bounded(
    layout: SharedBufferLayout,
    slot: SharedBufferSlotIndex,
    length: usize,
    range: Range<usize>,
)
    requires layout_well_formed(layout), slot_range(layout, slot, length, Ok(range)),
    ensures range.start <= range.end, range.end <= layout_length(layout),
{
    lemma_mul_inequality(slot.0 as int + 1, layout.slot_count as int, layout.slot_size as int);
    lemma_mul_is_distributive_add_other_way(layout.slot_size as int, slot.0 as int, 1);
    lemma_mul_is_commutative(layout.slot_count as int, layout.slot_size as int);
}

pub open spec fn shared_buffer_layout_policy() -> bool {
    &&& (forall|size: u32, count: u32, result: Result<SharedBufferLayout, SharedBufferLayoutError>|
        #[trigger] SharedBufferLayout::new.ensures((size, count), result)
            ==> layout_creation(size, count, result))
    &&& (forall|layout: SharedBufferLayout, result: u32|
        #[trigger] SharedBufferLayout::slot_size.ensures((layout,), result)
            ==> result == layout_slot_size(layout))
    &&& (forall|layout: SharedBufferLayout, result: u32|
        #[trigger] SharedBufferLayout::slot_count.ensures((layout,), result)
            ==> result == layout_slot_count(layout))
    &&& (forall|layout: SharedBufferLayout, result: usize|
        #[trigger] SharedBufferLayout::total_len.ensures((layout,), result)
            ==> result == layout_length(layout))
    &&& (forall|layout: SharedBufferLayout, slot: SharedBufferSlotIndex, length: usize,
        result: Result<Range<usize>, SharedBufferLayoutError>|
        #[trigger] SharedBufferLayout::range.ensures((layout, slot, length), result)
            ==> slot_range(layout, slot, length, result))
    &&& (forall|layout: SharedBufferLayout, slot: SharedBufferSlotIndex, length: usize,
        range: Range<usize>|
        layout_well_formed(layout) && #[trigger] slot_range(layout, slot, length, Ok(range))
            ==> range.start <= range.end && range.end <= layout_length(layout))
}

pub proof fn prove_shared_buffer_layout()
    ensures shared_buffer_layout_policy(),
{
    assert forall|layout: SharedBufferLayout, slot: SharedBufferSlotIndex, length: usize,
        range: Range<usize>|
        layout_well_formed(layout) && #[trigger] slot_range(layout, slot, length, Ok(range))
            implies range.start <= range.end && range.end <= layout_length(layout) by {
        prove_slot_range_bounded(layout, slot, length, range);
    }
}

// Actual constructor/range composition, with no assumed well-formedness invariant.
pub fn check_layout_range(
    slot_size: u32,
    slot_count: u32,
    slot: SharedBufferSlotIndex,
    length: usize,
) -> (result: Result<Range<usize>, SharedBufferLayoutError>)
    ensures match result {
        Ok(range) => range.start <= range.end
            && range.end <= isize::MAX
            && range.end <= (slot_size as int) * (slot_count as int),
        Err(_) => true,
    },
{
    let layout = SharedBufferLayout::new(slot_size, slot_count)?;
    let range = layout.range(slot, length)?;

    proof {
        prove_slot_range_bounded(layout, slot, length, range);
    }
    Ok(range)
}

}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(verus_only)]
use vstd::layout::valid_layout;
use vstd::prelude::*;
#[cfg(verus_only)]
use vstd::raw_ptr::DeallocData;
use vstd::raw_ptr::{Dealloc, PointsToRaw};

verus! {

// Remove this vendored function once Verus PR 2786 is merged.
/// Allocate with the global allocator. The precondition should be consistent
/// with the [documented safety conditions on
/// `alloc`](https://doc.rust-lang.org/alloc/alloc/trait.GlobalAlloc.html#tymethod.alloc).
/// Returns a pointer with corresponding [`PointsToRaw`] and [`Dealloc`]
/// permissions.
///
/// # Panics
///
/// This function invokes [`alloc::alloc::handle_alloc_error`] when the
/// allocation request cannot be served. Depending on the platform, this
/// function may abort the process or unwind. It does so before minting any
/// capability to access the failed allocation.
#[verifier::external_body]
pub(super) fn allocate(size: usize, align: usize) -> (pt: (
    *mut u8,
    Tracked<PointsToRaw>,
    Tracked<Dealloc>,
))
    requires
        valid_layout(size, align),
        size != 0,
    ensures
        pt.1@.is_range(pt.0.addr() as int, size as int),
        pt.0.addr() + size <= usize::MAX + 1,
        pt.2@@ == (DeallocData {
            addr: pt.0.addr(),
            size: size as nat,
            align: align as nat,
            provenance: pt.1@.provenance(),
        }),
        pt.0.addr() as int % align as int == 0,
        pt.0@.provenance == pt.1@.provenance(),
    opens_invariants none
{
    // SAFETY: valid_layout is a precondition
    let layout = unsafe { alloc::alloc::Layout::from_size_align_unchecked(size, align) };
    // SAFETY: size != 0
    let p = unsafe { ::alloc::alloc::alloc(layout) };
    if p.is_null() {
        alloc::alloc::handle_alloc_error(layout);
    }
    (p, Tracked::assume_new(), Tracked::assume_new())
}

} // verus!

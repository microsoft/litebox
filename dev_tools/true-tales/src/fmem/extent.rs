// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use vstd::prelude::*;

verus! {

/// A pointer's current index and its domain region's stable half-open address range.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AddressExtent {
    pub start: usize,
    pub end: usize,
    pub index: usize,
}

impl AddressExtent {
    pub open spec fn spec_is_well_formed(self) -> bool {
        self.start <= self.end
    }

    #[verifier::when_used_as_spec(spec_is_well_formed)]
    pub fn is_well_formed(self) -> (result: bool)
        ensures
            result == self.spec_is_well_formed(),
    {
        self.start <= self.end
    }

    pub open spec fn spec_contains_range(self, len: usize) -> bool {
        self.spec_is_well_formed() && self.start <= self.index && self.index <= self.end && len
            <= self.end - self.index
    }

    #[verifier::when_used_as_spec(spec_contains_range)]
    pub fn contains_range(self, len: usize) -> (result: bool)
        ensures
            result == self.spec_contains_range(len),
    {
        self.start <= self.end && self.start <= self.index && self.index <= self.end && len
            <= self.end - self.index
    }
}

/// The requested region is not represented by a domain session.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WrongRegion;

} // verus!

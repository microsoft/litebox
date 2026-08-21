// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::erasure::ErasedArc;
use crate::fmem::ids::*;
use vstd::prelude::*;

verus! {

/// Typed pointer into a foreign-memory domain.
pub struct ForeignPtr {
    domain: ForeignDomainId,
    region: ForeignRegionId,
    // Cursor is a raw pointer, such that "real" (non-model) implementations can
    // use this field to store provenance-carrying pointers.
    //
    // Models may interpret this arbitrarily: cursor can be used to store an
    // absolute address, an offset in the domain's region, ...
    cursor: *mut u8,
    cap: Ghost<ErasedArc>,
}

impl Clone for ForeignPtr {
    fn clone(&self) -> (res: Self)
        ensures
            res == *self,
    {
        *self
    }
}

impl Copy for ForeignPtr {

}

impl ForeignPtr {
    pub closed spec fn spec_domain(self) -> ForeignDomainId {
        self.domain
    }

    pub closed spec fn spec_region(self) -> ForeignRegionId {
        self.region
    }

    pub closed spec fn spec_cursor(self) -> *mut u8 {
        self.cursor
    }

    #[verifier::when_used_as_spec(spec_domain)]
    pub fn domain(self) -> (d: ForeignDomainId)
        ensures
            d == self.domain(),
    {
        self.domain
    }

    #[verifier::when_used_as_spec(spec_region)]
    pub fn region(self) -> (r: ForeignRegionId)
        ensures
            r == self.region(),
    {
        self.region
    }

    #[verifier::when_used_as_spec(spec_cursor)]
    pub fn cursor(self) -> (c: *mut u8)
        ensures
            c == self.cursor(),
    {
        self.cursor
    }

    pub closed spec fn cap(self) -> ErasedArc {
        self.cap@
    }

    #[allow(unused_variables)]
    pub(crate) fn from_handle(
        domain: ForeignDomainId,
        region: ForeignRegionId,
        cursor: *mut u8,
        h: &ErasedArc,
    ) -> (ptr: Self)
        ensures
            ptr.domain() == domain,
            ptr.region() == region,
            ptr.cursor() == cursor,
            ptr.cap() == *h,
    {
        ForeignPtr { domain, region, cursor, cap: Ghost(*h) }
    }

    pub closed spec fn spec_advance(self, delta: usize) -> Self
        recommends
            self.cursor().addr() + delta <= usize::MAX,
    {
        ForeignPtr {
            domain: self.domain,
            region: self.region,
            cursor: self.cursor.with_addr((self.cursor.addr() + delta) as usize),
            cap: self.cap,
        }
    }

    #[verifier::when_used_as_spec(spec_advance)]
    pub fn advance(self, delta: usize) -> (ptr: Self)
        requires
            self.cursor().addr() + delta <= usize::MAX,
        ensures
            ptr == self.advance(delta),
            ptr.domain() == self.domain(),
            ptr.region() == self.region(),
            ptr.cap() == self.cap(),
            ptr.cursor() == self.cursor().with_addr((self.cursor().addr() + delta) as usize),
            ptr.cursor().addr() == self.cursor().addr() + delta,
    {
        ForeignPtr {
            domain: self.domain,
            region: self.region,
            cursor: self.cursor.with_addr(self.cursor.addr() + delta),
            cap: self.cap,
        }
    }

    pub proof fn lemma_advance_add(self, first: usize, second: usize)
        requires
            first + second <= usize::MAX,
            self.cursor().addr() + first + second <= usize::MAX,
        ensures
            self.advance(first).advance(second) == self.advance((first + second) as usize),
    {
    }

    pub proof fn lemma_advance_zero(self)
        ensures
            self.advance(0) == self,
    {
    }

    pub proof fn lemma_advance_fields(self, delta: usize)
        requires
            self.cursor().addr() + delta <= usize::MAX,
        ensures
            self.advance(delta).domain() == self.domain(),
            self.advance(delta).region() == self.region(),
            self.advance(delta).cap() == self.cap(),
            self.advance(delta).cursor() == self.cursor().with_addr(
                (self.cursor().addr() + delta) as usize,
            ),
            self.advance(delta).cursor().addr() == self.cursor().addr() + delta,
    {
    }
}

} // verus!

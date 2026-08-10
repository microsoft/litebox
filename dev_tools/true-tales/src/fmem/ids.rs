// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Identity types for the foreign-memory subsystem.
//!
//! This module holds nothing but names: the opaque identities that the rest of
//! the subsystem routes on. It deliberately contains no behaviour, no trait, no
//! map and no state — every type here is a plain wrapper whose only job is to
//! be distinguishable from the others at the type level.
use crate::fmem::erasure::ErasedArc;
use crate::helpers::erased_map::ErasedId;
use vstd::prelude::*;

verus! {

/// Opaque routing identity for a region within a foreign memory domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ForeignRegionId {
    pub raw: usize,
}

impl ForeignRegionId {
    pub open spec fn raw(self) -> usize {
        self.raw
    }

    pub fn new(raw: usize) -> (id: Self)
        ensures
            id == (ForeignRegionId { raw }),
    {
        ForeignRegionId { raw }
    }
}

/// Runtime generation tag paired with exported foreign pointers to reject stale
/// pointers when an allocator reuses a reclaimed domain allocation address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DomainCookie {
    pub raw: u64,
}

impl DomainCookie {
    /// Runtime generation comparison, linked to specification equality.
    pub fn same(self, other: Self) -> (same: bool)
        ensures
            same == (self == other),
    {
        self.raw == other.raw
    }
}

/// Internal address-derived key used by the routing map.
pub(crate) type DomainRouteKey = ErasedId<ErasedArc>;

/// Identifies one generation of a routed foreign domain. The routing key is a
/// provenance-carrying allocation pointer, but map routing is address-based, so
/// a stale key may select a later allocation that reuses the same address; the
/// generation cookie rejects that replacement. Fields are private so only the
/// domain map can mint a valid key-generation pair.
///
/// This value conveys no capability. Access additionally requires an owned
/// erased handle and a matching live session.
pub struct ForeignDomainId {
    route: DomainRouteKey,
    generation: DomainCookie,
}

impl ForeignDomainId {
    pub(crate) fn from_route(route: DomainRouteKey, generation: DomainCookie) -> (id: Self)
        ensures
            id.route() == route,
            id.generation() == generation,
            id.addr() == route.addr(),
            id.spec_addr() == route.spec_addr(),
    {
        ForeignDomainId { route, generation }
    }

    pub(crate) closed spec fn spec_route(self) -> DomainRouteKey {
        self.route
    }

    #[verifier::when_used_as_spec(spec_route)]
    pub(crate) fn route(self) -> (route: DomainRouteKey)
        ensures
            route == self.route(),
            route.addr() == self.addr(),
            route.spec_addr() == self.spec_addr(),
    {
        self.route
    }

    pub closed spec fn spec_generation(self) -> DomainCookie {
        self.generation
    }

    #[verifier::when_used_as_spec(spec_generation)]
    pub fn generation(self) -> (generation: DomainCookie)
        ensures
            generation == self.generation(),
    {
        self.generation
    }

    pub closed spec fn spec_addr(self) -> usize {
        self.route.spec_addr()
    }

    #[verifier::when_used_as_spec(spec_addr)]
    pub fn addr(self) -> (addr: usize)
        ensures
            addr == self.addr(),
    {
        self.route.addr()
    }

    /// Compare complete public identities: routing address and generation.
    pub fn same(self, other: Self) -> (same: bool)
        ensures
            same == (self.addr() == other.addr() && self.generation() == other.generation()),
    {
        self.route.same(other.route) && self.generation.same(other.generation)
    }

    pub(crate) proof fn lemma_route_addr(self)
        ensures
            self.route().addr() == self.addr(),
            self.route().spec_addr() == self.spec_addr(),
    {
    }
}

impl Clone for ForeignDomainId {
    fn clone(&self) -> (res: Self)
        ensures
            res == *self,
    {
        *self
    }
}

impl Copy for ForeignDomainId {

}

} // verus!

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::capability::{BoundSession, handle_obj, open_bound};
use crate::fmem::erasure::DynState;
#[cfg(verus_only)]
use crate::fmem::erasure::UnsizeShim;
use crate::fmem::erasure::{ErasedArc, RetiredDomain};
use crate::fmem::ids::{DomainCookie, ForeignDomainId, ForeignRegionId};
use crate::fmem::ptr::ForeignPtr;
#[cfg(verus_only)]
use crate::fmem::session::DomainSession;
use crate::fmem::session::ForeignDomain;
use crate::helpers::erased_map::ErasedMap;
#[cfg(verus_only)]
use crate::helpers::{owned_pptr::PointsTo, rust_any::type_tag};
use vstd::pervasive::unreached;
use vstd::prelude::*;

verus! {

/// Runtime map from a pptr-backed identity to a live erased
/// [`crate::fmem::erasure::DynState`] object.
///
/// Uses [`crate::helpers::erased_map::ErasedMap`]'s `Vec` of
/// provenance-carrying identities (pointers) for executable routing.
// The field is private because [`Self::wf`], which relates the two halves, is
// only maintainable if every mutation goes through this type's methods.
pub struct DomainMap {
    map: ErasedMap<ErasedArc>,
}

/// Why a generation-checked [`DomainMap::remove_domain`] did not remove an
/// object.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RemoveDomainError {
    /// No live domain is routed at the supplied address.
    NotFound,
    /// The address is live, but it belongs to a different generation.
    GenerationMismatch,
}

/// Why a typed, generation-checked domain resolution failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResolveDomainError {
    /// No live domain is routed at the supplied address.
    NotFound,
    /// The address is live, but it belongs to a different generation.
    GenerationMismatch,
    /// The generation is live, but it has a different domain type.
    TypeMismatch,
}

/// An owned handle minted by [`DomainMap`] after checking route, generation,
/// and domain type together.
pub struct RoutedDomainHandle<D: ForeignDomain> {
    id: ForeignDomainId,
    handle: ErasedArc,
    _domain: core::marker::PhantomData<D>,
}

impl<D: ForeignDomain> RoutedDomainHandle<D> {
    pub closed spec fn spec_id(&self) -> ForeignDomainId {
        self.id
    }

    pub closed spec fn spec_handle(&self) -> ErasedArc {
        self.handle
    }

    pub closed spec fn wf(&self) -> bool {
        &&& self.handle.wf()
        &&& self.handle.spec_cookie() == self.id.generation()
        &&& self.handle.spec_tag() == type_tag::<UnsizeShim<D::Obj>>()
    }

    pub fn id(&self) -> (id: ForeignDomainId)
        ensures
            id == self.spec_id(),
    {
        self.id
    }

    /// Mint a pointer whose routing identity and ghost capability come from
    /// this one checked handle.
    pub fn foreign_ptr(&self, region: ForeignRegionId, cursor: *mut u8) -> (ptr: ForeignPtr)
        requires
            self.wf(),
        ensures
            ptr.domain() == self.spec_id(),
            ptr.region() == region,
            ptr.cursor() == cursor,
            ptr.cap() == self.spec_handle(),
    {
        ForeignPtr::from_handle(self.id, region, cursor, &self.handle)
    }

    /// Open a session over the checked domain type.
    pub fn open<'a>(&'a self) -> (session: BoundSession<D::Session<'a>>)
        requires
            self.wf(),
        ensures
            session.cap() == self.spec_handle(),
            <D::Session<'a> as DomainSession>::wf(session.st()),
    {
        match open_bound::<D>(&self.handle) {
            Option::Some(session) => session,
            Option::None => unreached(),
        }
    }
}

impl DomainMap {
    /// Number of live objects.
    pub closed spec fn len(self) -> nat {
        self.map.len()
    }

    /// Whether the route address in `id` is live, without checking generation.
    pub closed spec fn has_route(self, id: ForeignDomainId) -> bool {
        self.map.contains(id.route())
    }

    /// Whether this complete route-generation identity is live in the map.
    pub closed spec fn contains(self, id: ForeignDomainId) -> bool {
        self.has_route(id) && self.obj_cookie(id) == id.generation()
    }

    /// The ownership permission for `id` (well-defined when `id` is present).
    pub closed spec fn perm_of(self, id: ForeignDomainId) -> PointsTo<Box<ErasedArc>> {
        self.map.perm_of(id.route())
    }

    /// Well-formedness of the object routed to by `id`.
    pub closed spec fn obj_wf(self, id: ForeignDomainId) -> bool {
        self.perm_of(id).value().wf()
    }

    /// The routing tag of the object at `id`.
    ///
    /// Verus loses specification links across unsizing coercions with generic
    /// parameters. Therefore, we wrap every object in this map in an
    /// [`crate::fmem::erasure::UnsizeShim`]. This is the tag of that wrapped
    /// type; see [`Self::domain_at`].
    pub closed spec fn obj_tag(self, id: ForeignDomainId) -> int {
        self.perm_of(id).value().spec_tag()
    }

    /// The generation cookie of the object at `id`. Runtime staleness policy
    /// only; no proof here depends on it. See [`DomainCookie`].
    pub closed spec fn obj_cookie(self, id: ForeignDomainId) -> DomainCookie {
        self.perm_of(id).value().spec_cookie()
    }

    /// The handle value stored at `id` ([`crate::fmem::erasure::ErasedArc`]).
    ///
    /// The cell itself, not an attribute of it: unlike [`Self::obj_wf`],
    /// [`Self::obj_tag`] and [`Self::obj_cookie`], which two distinct domains
    /// routinely agree on. This is the term the capability discipline is built
    /// on; see [`crate::fmem::capability`].
    pub closed spec fn obj_handle(self, id: ForeignDomainId) -> ErasedArc {
        *self.perm_of(id).value()
    }

    /// Map invariant: the [`crate::helpers::erased_map::ErasedMap`] substrate is structurally well-formed,
    /// and every live object is itself well-formed.
    ///
    pub closed spec fn wf(self) -> bool {
        &&& self.map.base_wf()
        &&& self.map.all_boxes(|b: Box<ErasedArc>| b.wf())
    }

    /// `id` routes to a live object of domain `D`.
    pub open spec fn domain_at<D: ForeignDomain>(self, id: ForeignDomainId) -> bool {
        &&& self.contains(id)
        &&& self.obj_tag(id) == type_tag::<UnsizeShim<D::Obj>>()
    }

    pub fn new() -> (m: DomainMap)
        ensures
            m.wf(),
            m.len() == 0,
    {
        let map = ErasedMap::<ErasedArc>::new();
        proof {
            map.lemma_all_boxes_empty(|b: Box<ErasedArc>| b.wf());
        }
        DomainMap { map }
    }

    /// Inject a live domain object, allocating its erased cell and returning
    /// the fresh routing token.
    pub fn inject_domain<D: ForeignDomain>(&mut self, obj: D::Obj) -> (id: ForeignDomainId)
        requires
            old(self).wf(),
            obj.wf(),
        ensures
            final(self).wf(),
            !old(self).contains(id),
            final(self).contains(id),
            final(self).domain_at::<D>(id),
            final(self).obj_tag(id) == type_tag::<UnsizeShim<D::Obj>>(),
            final(self).obj_cookie(id) == obj.spec_cookie(),
            final(self).obj_wf(id),
            forall|other: ForeignDomainId|
                #![auto]
                other.addr() != id.addr() ==> {
                    &&& final(self).contains(other) == old(self).contains(other)
                    &&& old(self).contains(other) ==> final(self).perm_of(other) == old(
                        self,
                    ).perm_of(other)
                },
    {
        let generation = obj.get_cookie();
        let bx: Box<ErasedArc> = Box::new(ErasedArc::new_shim(obj));
        let ghost pre = self.map;
        let route = self.map.insert_box(bx);
        let id = ForeignDomainId::from_route(route, generation);
        proof {
            ErasedMap::lemma_all_boxes_insert(
                pre,
                self.map,
                route.addr(),
                |b: Box<ErasedArc>| b.wf(),
            );
            assert forall|other: ForeignDomainId| #![auto] other.addr() != id.addr() implies {
                &&& self.contains(other) == old(self).contains(other)
                &&& old(self).contains(other) ==> self.perm_of(other) == old(self).perm_of(other)
            } by {
                other.lemma_route_addr();
                id.lemma_route_addr();
                let other_route = other.route();
                assert(other_route.spec_addr() == other.spec_addr());
                assert(route.spec_addr() == id.spec_addr());
            }
        }
        id
    }

    /// Inject, and hand back a routing token, a pointer over the injected
    /// object, and an owned handle on it.
    pub fn inject_domain_ptr<D: ForeignDomain>(
        &mut self,
        region: ForeignRegionId,
        obj: D::Obj,
    ) -> (res: (ForeignDomainId, ForeignPtr, ErasedArc))
        requires
            old(self).wf(),
            obj.wf(),
        ensures
            final(self).wf(),
            !old(self).contains(res.0),
            final(self).domain_at::<D>(res.0),
            final(self).obj_cookie(res.0) == obj.spec_cookie(),
            final(self).obj_wf(res.0),
            res.1.domain() == res.0,
            res.1.region() == region,
            res.1.cursor() == core::ptr::null_mut::<u8>(),
            res.2 == res.1.cap(),
            res.2.wf(),
            res.2.spec_tag() == type_tag::<UnsizeShim<D::Obj>>(),
            res.2.spec_cookie() == obj.spec_cookie(),
            res.2 == final(self).obj_handle(res.0),
            forall|other: ForeignDomainId|
                #![auto]
                other.addr() != res.0.addr() ==> {
                    &&& final(self).contains(other) == old(self).contains(other)
                    &&& old(self).contains(other) ==> final(self).perm_of(other) == old(
                        self,
                    ).perm_of(other)
                },
    {
        let id = self.inject_domain::<D>(obj);
        // `inject` publishes `domain_at::<D>(id)`, whose `contains` half is
        // `take_handle`'s completeness hypothesis, so this arm is dead.
        let h = match self.take_handle(id) {
            Option::Some(x) => x,
            Option::None => unreached(),
        };
        let ptr = ForeignPtr::from_handle(id, region, core::ptr::null_mut(), &h);
        (id, ptr, h)
    }

    /// Take an owned, refcounted handle on the object routed to by `id`.
    pub(crate) fn take_handle(&self, id: ForeignDomainId) -> (o: Option<ErasedArc>)
        requires
            self.wf(),
        ensures
            self.contains(id) ==> o is Some,
            o is Some ==> o->Some_0.wf(),
            o is Some ==> self.has_route(id),
            o is Some ==> o->Some_0.spec_tag() == self.obj_tag(id),
            o is Some ==> o->Some_0.spec_cookie() == self.obj_cookie(id),
            o is Some ==> o->Some_0 == self.obj_handle(id),
    {
        proof {
            if self.map.has_addr(id.addr()) {
                self.map.lemma_all_boxes(|b: Box<ErasedArc>| b.wf(), id.addr());
            }
        }
        // `share` copies a refcount, so objects can outlive the map.
        #[allow(clippy::manual_map)]
        match self.map.try_borrow(id.route()) {
            Option::Some(bx) => Option::Some(bx.share()),
            Option::None => Option::None,
        }
    }

    /// Resolve one complete identity and type, minting an owned handle only
    /// after all runtime checks have succeeded.
    pub fn resolve_domain<D: ForeignDomain>(&self, id: ForeignDomainId) -> (out: Result<
        RoutedDomainHandle<D>,
        ResolveDomainError,
    >)
        requires
            self.wf(),
        ensures
            out is Ok <==> self.contains(id) && self.domain_at::<D>(id),
            out is Ok ==> {
                &&& out->Ok_0.wf()
                &&& out->Ok_0.spec_id() == id
                &&& out->Ok_0.spec_handle() == self.obj_handle(id)
            },
            !self.has_route(id) ==> out == Result::Err(ResolveDomainError::NotFound),
            self.has_route(id) && self.obj_cookie(id) != id.generation() ==> out == Result::Err(
                ResolveDomainError::GenerationMismatch,
            ),
            self.contains(id) && !self.domain_at::<D>(id) ==> out == Result::Err(
                ResolveDomainError::TypeMismatch,
            ),
    {
        proof {
            if self.map.has_addr(id.addr()) {
                self.map.lemma_all_boxes(|b: Box<ErasedArc>| b.wf(), id.addr());
            }
        }
        let routed = match self.map.try_borrow(id.route()) {
            Option::Some(routed) => routed,
            Option::None => return Result::Err(ResolveDomainError::NotFound),
        };
        let routed_cookie = routed.get_cookie();
        if !routed_cookie.same(id.generation()) {
            return Result::Err(ResolveDomainError::GenerationMismatch);
        }
        let handle = routed.share();
        let _object = match handle_obj::<D>(&handle) {
            Option::Some(object) => object,
            Option::None => return Result::Err(ResolveDomainError::TypeMismatch),
        };
        proof {
            assert(handle == self.obj_handle(id));
            assert(handle.wf());
            assert(handle.spec_cookie() == id.generation());
            assert(handle.spec_tag() == type_tag::<UnsizeShim<D::Obj>>());
        }
        Result::Ok(RoutedDomainHandle { id, handle, _domain: core::marker::PhantomData })
    }

    fn cookie_at(&self, id: ForeignDomainId) -> (o: Option<DomainCookie>)
        requires
            self.wf(),
        ensures
            self.has_route(id) <==> o is Some,
            o is Some ==> o->Some_0 == self.obj_cookie(id),
    {
        proof {
            if self.map.has_addr(id.addr()) {
                self.map.lemma_all_boxes(|b: Box<ErasedArc>| b.wf(), id.addr());
            }
        }
        #[allow(clippy::manual_map)]
        match self.map.try_borrow(id.route()) {
            Option::Some(bx) => Option::Some(bx.get_cookie()),
            Option::None => Option::None,
        }
    }

    /// Atomically validate a domain generation and remove its route.
    pub fn remove_domain(&mut self, id: ForeignDomainId) -> (out: Result<
        RetiredDomain,
        RemoveDomainError,
    >)
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            out is Ok <==> old(self).contains(id),
            out is Ok ==> {
                &&& out->Ok_0.wf()
                &&& out->Ok_0.spec_tag() == old(self).obj_tag(id)
                &&& out->Ok_0.spec_cookie() == id.generation()
                &&& !final(self).contains(id)
            },
            out is Err ==> *final(self) == *old(self),
            !old(self).has_route(id) ==> out == Result::Err(RemoveDomainError::NotFound),
            old(self).has_route(id) && old(self).obj_cookie(id) != id.generation() ==> out
                == Result::Err(RemoveDomainError::GenerationMismatch),
            forall|other: ForeignDomainId|
                #![auto]
                other.addr() != id.addr() ==> {
                    &&& final(self).contains(other) == old(self).contains(other)
                    &&& old(self).contains(other) ==> final(self).perm_of(other) == old(
                        self,
                    ).perm_of(other)
                },
    {
        let routed_cookie = match self.cookie_at(id) {
            Option::Some(found_cookie) => found_cookie,
            Option::None => return Result::Err(RemoveDomainError::NotFound),
        };
        assert(self.has_route(id));
        assert(routed_cookie == self.obj_cookie(id));
        if !routed_cookie.same(id.generation()) {
            assert(self.obj_cookie(id) != id.generation());
            return Result::Err(RemoveDomainError::GenerationMismatch);
        }
        assert(self.obj_cookie(id) == id.generation());
        assert(self.contains(id));
        let route = id.route();
        let ghost pre = self.map;
        let bx = self.map.remove(route);
        proof {
            id.lemma_route_addr();
            pre.lemma_all_boxes(|b: Box<ErasedArc>| b.wf(), route.addr());
            ErasedMap::lemma_all_boxes_remove(
                pre,
                self.map,
                route.addr(),
                |b: Box<ErasedArc>| b.wf(),
            );
            assert forall|other: ForeignDomainId| #![auto] other.addr() != id.addr() implies {
                &&& self.contains(other) == old(self).contains(other)
                &&& old(self).contains(other) ==> self.perm_of(other) == old(self).perm_of(other)
            } by {
                other.lemma_route_addr();
                let other_route = other.route();
                assert(other_route.spec_addr() == other.spec_addr());
                assert(route.spec_addr() == id.spec_addr());
            }
        }
        assert(bx == pre.perm_of(route).value());
        assert(bx.wf());
        assert(bx.spec_cookie() == id.generation());
        Result::Ok((*bx).retire())
    }
}

impl Default for DomainMap {
    fn default() -> (m: DomainMap) {
        DomainMap::new()
    }
}

} // verus!

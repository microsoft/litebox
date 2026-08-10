// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::helpers::owned_pptr::{OwnedPPtr, PointsTo};
#[cfg(verus_only)]
use crate::helpers::owned_pptr::{lemma_box_unsized_nonzero, lemma_owned_pptr_addr};
use vstd::map::*;
use vstd::prelude::*;

verus! {

/// Routing identity for a live erased object.
///
/// The identity is the heap allocation that holds the erased-state box, a
/// provenance-carrying [`OwnedPPtr`] to `Box<T>`. Two distinct live objects
/// occupy disjoint allocations, so their identities have distinct addresses by
/// [`PointsTo::is_disjoint`].
pub struct ErasedId<T: ?Sized> {
    ptr: OwnedPPtr<Box<T>>,
}

impl<T: ?Sized> ErasedId<T> {
    pub fn from_owned(ptr: OwnedPPtr<Box<T>>) -> (id: Self)
        ensures
            id.owned() == ptr,
            id.addr() == ptr.spec_addr(),
    {
        ErasedId { ptr }
    }

    /// The underlying provenance-carrying pointer to the erased object box.
    pub closed spec fn owned(self) -> OwnedPPtr<Box<T>> {
        self.ptr
    }

    pub closed spec fn spec_addr(self) -> usize {
        self.ptr.spec_addr()
    }

    /// The routing key: the address of the erased object box.
    #[verifier::when_used_as_spec(spec_addr)]
    pub fn addr(self) -> (a: usize)
        ensures
            a == self.addr(),
    {
        self.ptr.addr()
    }

    /// Executable access to the provenance-carrying pointer, for borrowing the
    /// erased object box through its permission.
    pub fn owned_exec(self) -> (p: OwnedPPtr<Box<T>>)
        ensures
            p == self.owned(),
    {
        self.ptr
    }

    /// Compare two identities by their routing address.
    pub fn same(self, other: Self) -> (same: bool)
        ensures
            same == (self.addr() == other.addr()),
    {
        self.ptr.addr() == other.ptr.addr()
    }
}

impl<T: ?Sized> Clone for ErasedId<T> {
    fn clone(&self) -> (res: Self)
        ensures
            res == *self,
    {
        *self
    }
}

impl<T: ?Sized> Copy for ErasedId<T> {

}

pub struct ErasedMapEntry<T: ?Sized> {
    id: ErasedId<T>,
}

impl<T: ?Sized> ErasedMapEntry<T> {
    pub closed spec fn spec_id(self) -> ErasedId<T> {
        self.id
    }

    #[verifier::when_used_as_spec(spec_id)]
    pub fn id(self) -> (i: ErasedId<T>)
        ensures
            i == self.id(),
    {
        self.id
    }
}

pub proof fn lemma_entries_remove<T: ?Sized>(entries: Seq<ErasedMapEntry<T>>, idx: int)
    requires
        ErasedMap::<T>::entries_unique(entries),
        0 <= idx < entries.len(),
    ensures
        ErasedMap::<T>::entries_unique(entries.remove(idx)),
        forall|addr: usize|
            #![auto]
            ErasedMap::<T>::entries_contain_addr(entries.remove(idx), addr) <==> (ErasedMap::<
                T,
            >::entries_contain_addr(entries, addr) && addr != entries[idx].id().addr()),
{
    assert forall|addr: usize|
        #![auto]
        ErasedMap::<T>::entries_contain_addr(entries.remove(idx), addr) <==> (ErasedMap::<
            T,
        >::entries_contain_addr(entries, addr) && addr != entries[idx].id.addr()) by {
        if ErasedMap::<T>::entries_contain_addr(entries, addr) && addr != entries[idx].id.addr() {
            let oi = choose|oi: int|
                #![auto]
                0 <= oi < entries.len() && entries[oi].id.addr() == addr;
            let i = if oi < idx {
                oi
            } else {
                oi - 1
            };
            assert(entries.remove(idx)[i] == entries[oi]);
        }
    }
}

/// Runtime map from pptr-backed identities to erased object state.
pub struct ErasedMap<T: ?Sized> {
    entries: Vec<ErasedMapEntry<T>>,
    _perms: Tracked<Map<usize, PointsTo<Box<T>>>>,
}

impl<T: ?Sized> ErasedMap<T> {
    // --- structural projections over entries ---
    pub open spec fn entries_contain_addr(entries: Seq<ErasedMapEntry<T>>, addr: usize) -> bool {
        exists|i: int| #![auto] 0 <= i < entries.len() && entries[i].id().addr() == addr
    }

    pub open spec fn entries_unique(entries: Seq<ErasedMapEntry<T>>) -> bool {
        forall|i: int, j: int|
            #![auto]
            0 <= i < entries.len() && 0 <= j < entries.len() && entries[i].id().addr()
                == entries[j].id().addr() ==> i == j
    }

    pub closed spec fn spec_entries(self) -> Seq<ErasedMapEntry<T>> {
        self.entries@
    }

    pub closed spec fn len(self) -> nat {
        self.entries@.len()
    }

    // --- spec projections over the perm map ---
    /// Whether an allocation address is live.
    pub closed spec fn has_addr(self, addr: usize) -> bool {
        self._perms@.dom().contains(addr)
    }

    /// The sized ownership permission stored at a live address.
    pub closed spec fn perm_at(self, addr: usize) -> PointsTo<Box<T>> {
        self._perms@[addr]
    }

    pub open spec fn contains(self, id: ErasedId<T>) -> bool {
        self.has_addr(id.addr())
    }

    /// The sized ownership permission for `id` (well-defined when `id` is present).
    pub open spec fn perm_of(self, id: ErasedId<T>) -> PointsTo<Box<T>> {
        self.perm_at(id.addr())
    }

    /// The erased box for `id` (well-defined when `id` is present).
    pub open spec fn box_of(self, id: ErasedId<T>) -> Box<T> {
        self.perm_of(id).value()
    }

    /// Structural well-formedness of the map and its ownership permissions.
    ///
    /// Object-specific invariants belong to wrappers around this map.
    pub closed spec fn base_wf(self) -> bool {
        &&& ErasedMap::entries_unique(self.entries@)
        &&& forall|addr: usize| #[trigger]
            self._perms@.dom().contains(addr) <==> ErasedMap::entries_contain_addr(
                self.entries@,
                addr,
            )
        &&& forall|addr: usize| #[trigger]
            self._perms@.dom().contains(addr) ==> {
                &&& self._perms@[addr].wf()
                &&& self._perms@[addr].ptr().addr() == addr
                &&& self._perms@[addr].is_init()
            }
        &&& forall|i: int|
            #![trigger self.entries@[i]]
            0 <= i < self.entries@.len() ==> {
                &&& self._perms@.dom().contains(self.entries@[i].id.addr())
                &&& self._perms@[self.entries@[i].id.addr()].ptr()
                    == self.entries@[i].id.owned().ptr()
            }
    }

    /// Every live box is well-formed under `p`.
    ///
    /// Stated here rather than in a wrapper's own `wf` so that the quantifier's
    /// trigger fires on this type's own terms.
    pub closed spec fn all_boxes(self, p: spec_fn(Box<T>) -> bool) -> bool {
        forall|addr: usize| #[trigger]
            self._perms@.dom().contains(addr) ==> p(self._perms@[addr].value())
    }

    pub proof fn lemma_all_boxes(self, p: spec_fn(Box<T>) -> bool, addr: usize)
        requires
            self.all_boxes(p),
            self.has_addr(addr),
        ensures
            p(self.perm_at(addr).value()),
    {
    }

    pub proof fn lemma_all_boxes_empty(self, p: spec_fn(Box<T>) -> bool)
        requires
            self.base_wf(),
            self.len() == 0,
        ensures
            self.all_boxes(p),
    {
    }

    /// `all_boxes` survives an insertion that touches one address and frames
    /// every other, provided the new box satisfies `p`.
    pub proof fn lemma_all_boxes_insert(
        pre: ErasedMap<T>,
        post: ErasedMap<T>,
        addr: usize,
        p: spec_fn(Box<T>) -> bool,
    )
        requires
            pre.all_boxes(p),
            post.has_addr(addr),
            p(post.perm_at(addr).value()),
            forall|a: usize|
                #![auto]
                a != addr ==> {
                    &&& post.has_addr(a) == pre.has_addr(a)
                    &&& pre.has_addr(a) ==> post.perm_at(a) == pre.perm_at(a)
                },
        ensures
            post.all_boxes(p),
    {
        assert forall|a: usize| #[trigger] post._perms@.dom().contains(a) implies p(
            post._perms@[a].value(),
        ) by {
            if a != addr {
                assert(pre.has_addr(a));
                assert(post.perm_at(a) == pre.perm_at(a));
            }
        }
    }

    /// `all_boxes` survives removing one address when every other box is
    /// framed by the removal.
    pub proof fn lemma_all_boxes_remove(
        pre: ErasedMap<T>,
        post: ErasedMap<T>,
        addr: usize,
        p: spec_fn(Box<T>) -> bool,
    )
        requires
            pre.all_boxes(p),
            !post.has_addr(addr),
            forall|a: usize|
                #![trigger post.has_addr(a)]
                #![trigger post.perm_at(a)]
                a != addr ==> {
                    &&& post.has_addr(a) == pre.has_addr(a)
                    &&& pre.has_addr(a) ==> post.perm_at(a) == pre.perm_at(a)
                },
        ensures
            post.all_boxes(p),
    {
        assert forall|a: usize| #[trigger] post._perms@.dom().contains(a) implies p(
            post._perms@[a].value(),
        ) by {
            assert(post.has_addr(a));
            assert(a != addr) by {
                if a == addr {
                    assert(!post.has_addr(addr));
                }
            }
            assert(pre.has_addr(a));
            assert(post.perm_at(a) == pre.perm_at(a));
            pre.lemma_all_boxes(p, a);
        }
    }

    pub fn new() -> (map: ErasedMap<T>)
        ensures
            map.base_wf(),
            map.len() == 0,
    {
        let entries = Vec::new();
        let tracked perms = Map::<usize, PointsTo<Box<T>>>::tracked_empty();
        ErasedMap { entries, _perms: Tracked(perms) }
    }

    /// A freshly allocated, live, non-zero-sized object box is absent from the
    /// perm map: its address differs from every stored box's address by
    /// [`PointsTo::is_disjoint`], and every stored box's address is its key.
    pub proof fn lemma_fresh_not_in(
        tracked perms: &Map<usize, PointsTo<Box<T>>>,
        tracked perm: &mut PointsTo<Box<T>>,
        addr: usize,
    )
        requires
            forall|a: usize| #[trigger]
                perms.dom().contains(a) ==> {
                    &&& perms[a].wf()
                    &&& perms[a].ptr().addr() == a
                },
            old(perm).ptr().addr() == addr,
        ensures
            *old(perm) == *final(perm),
            !perms.dom().contains(addr),
    {
        broadcast use lemma_box_unsized_nonzero;

        if perms.dom().contains(addr) {
            let tracked existing = perms.tracked_borrow(addr);
            perm.is_disjoint(existing);
        }
    }

    /// Insert a newly allocated erased object box and return its fresh routing
    /// token.
    ///
    /// The provenance-carrying [`ErasedId`] stays inside [`Self::entries`];
    /// only the erased [`ErasedId<T>`] is handed back.
    pub fn insert_box(&mut self, bx: Box<T>) -> (id: ErasedId<T>)
        requires
            old(self).base_wf(),
        ensures
            final(self).base_wf(),
            !old(self).contains(id),
            final(self).contains(id),
            final(self).box_of(id) == bx,
            final(self).perm_of(id).value() == bx,
            forall|other: ErasedId<T>|
                #![auto]
                other.addr() != id.addr() ==> {
                    &&& final(self).contains(other) == old(self).contains(other)
                    &&& old(self).contains(other) ==> final(self).perm_of(other) == old(
                        self,
                    ).perm_of(other)
                },
            forall|a: usize|
                #![trigger final(self).has_addr(a)]
                #![trigger final(self).perm_at(a)]
                a != id.addr() ==> {
                    &&& final(self).has_addr(a) == old(self).has_addr(a)
                    &&& old(self).has_addr(a) ==> final(self).perm_at(a) == old(self).perm_at(a)
                },
    {
        broadcast use lemma_owned_pptr_addr;

        let ghost pre = *self;
        let (pptr, Tracked(mut perm)) = OwnedPPtr::new(bx);
        let eid = ErasedId { ptr: pptr };
        let ghost addr = pptr.spec_addr();
        proof {
            ErasedMap::lemma_fresh_not_in(self._perms.borrow(), &mut perm, addr);
        }
        self.entries.push(ErasedMapEntry { id: eid });
        proof {
            self._perms.borrow_mut().tracked_insert(addr, perm);
            assert forall|a: usize| #[trigger]
                self._perms@.dom().contains(a) <==> ErasedMap::entries_contain_addr(
                    self.entries@,
                    a,
                ) by {
                if a == addr {
                    assert(self.entries@[pre.entries@.len() as int].id.addr() == addr);
                } else if ErasedMap::entries_contain_addr(pre.entries@, a) {
                    let i = choose|i: int|
                        #![auto]
                        0 <= i < pre.entries@.len() && pre.entries@[i].id.addr() == a;
                    assert(self.entries@[i] == pre.entries@[i]);
                }
            }
        }
        eid
    }

    /// Executable lookup of the entry index for `id`.
    pub fn find_index(&self, id: ErasedId<T>) -> (idx: usize)
        requires
            self.base_wf(),
            self.contains(id),
        ensures
            idx < self.len(),
            self.spec_entries()[idx as int].id().addr() == id.addr(),
    {
        let mut i: usize = 0;
        while i < self.entries.len()
            invariant
                i <= self.entries.len(),
                forall|k: int| #![auto] 0 <= k < i ==> self.entries@[k].id.addr() != id.addr(),
            decreases self.entries.len() - i,
        {
            if self.entries[i].id.addr() == id.addr() {
                return i;
            }
            i += 1;
        }
        0
    }

    /// Remove a live erased object, deallocate its owning box allocation, and
    /// return the erased box value.
    pub fn remove(&mut self, id: ErasedId<T>) -> (bx: Box<T>)
        requires
            old(self).base_wf(),
            old(self).contains(id),
        ensures
            final(self).base_wf(),
            !final(self).contains(id),
            bx == old(self).perm_of(id).value(),
            forall|other: ErasedId<T>|
                #![auto]
                other.addr() != id.addr() ==> {
                    &&& final(self).contains(other) == old(self).contains(other)
                    &&& old(self).contains(other) ==> final(self).perm_of(other) == old(
                        self,
                    ).perm_of(other)
                },
            // Address-indexed twin; see the note on [`Self::insert_box`].
            forall|a: usize|
                #![trigger final(self).has_addr(a)]
                #![trigger final(self).perm_at(a)]
                a != id.addr() ==> {
                    &&& final(self).has_addr(a) == old(self).has_addr(a)
                    &&& old(self).has_addr(a) ==> final(self).perm_at(a) == old(self).perm_at(a)
                },
    {
        let ghost pre = *self;
        let idx = self.find_index(id);
        proof {
            lemma_entries_remove(pre.entries@, idx as int);
        }
        let entry = self.entries.remove(idx);
        let tracked perm = self._perms.borrow_mut().tracked_remove(id.addr());
        entry.id.owned_exec().into_inner(Tracked(perm))
    }

    /// Borrow the box routed to by `id`, if it is live here.
    #[allow(clippy::borrowed_box)]
    pub fn try_borrow(&self, id: ErasedId<T>) -> (o: Option<&Box<T>>)
        requires
            self.base_wf(),
        ensures
            self.contains(id) ==> o is Some,
            o is Some ==> self.contains(id),
            o is Some ==> *o->Some_0 == self.box_of(id),
    {
        let mut i: usize = 0;
        while i < self.entries.len()
            invariant
                self.base_wf(),
                i <= self.entries.len(),
                forall|k: int| #![auto] 0 <= k < i ==> self.entries@[k].id.addr() != id.addr(),
            decreases self.entries.len() - i,
        {
            let entry_id = self.entries[i].id;
            if entry_id.same(id) {
                let tracked perm = self._perms.borrow().tracked_borrow(id.addr());
                return Option::Some(entry_id.owned_exec().borrow(Tracked(perm)));
            }
            i += 1;
        }
        Option::None
    }
}

impl<T: ?Sized> Default for ErasedMap<T> {
    fn default() -> (map: ErasedMap<T>) {
        ErasedMap::new()
    }
}

} // verus!

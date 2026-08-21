// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::helpers::erased_pptr::*;

use super::rmem_perm::*;
#[cfg(verus_only)]
use vstd::{layout::size_of, modes::tracked_swap};
use vstd::{pervasive::unreached, prelude::*};

verus! {

/// Empty rmem stack tail.
#[derive(Copy, Clone)]
pub struct RmemNil;

/// One rmem permission layer plus an older backing stack.
///
/// The single permission is wrapped in an `Option` so the write path can swap
/// it out (leaving a freely-constructible `None` sentinel), mutate the owned
/// permission directly, and swap it back. A well-formed layer (`wf`) always has
/// `perm is Some`.
pub struct RmemCons<'a, Tail> {
    pub perm: Tracked<Option<RmemPerm<'a>>>,
    pub addr: usize,
    pub tail: Tail,
}

impl RmemNil {
    pub fn new() -> (nil: Self) {
        RmemNil
    }
}

impl Default for RmemNil {
    fn default() -> (nil: Self) {
        RmemNil::new()
    }
}

/// Rust-slice permission stack operations independent of stack depth.
pub trait RmemStack: Sized {
    /// Well-formedness (in particular, routes):
    spec fn wf(self) -> bool;

    spec fn contains_addr_any(self, addr: usize) -> bool;

    spec fn has_read_any(self, cell: ErasedPPtr) -> bool;

    spec fn has_mut_any(self, cell: ErasedPPtr) -> bool;

    spec fn is_mut_any(self, cell: ErasedPPtr) -> bool;

    spec fn view_any(self, cell: ErasedPPtr) -> Seq<u8>;

    spec fn matches_pptr_any(self, cell: ErasedPPtr) -> bool;

    proof fn lemma_not_contains_no_any(tracked &self, cell: ErasedPPtr)
        requires
            !self.contains_addr_any(cell.addr()),
        ensures
            !self.has_read_any(cell),
            !self.has_mut_any(cell),
            !self.matches_pptr_any(cell),
    ;

    proof fn lemma_matches_contains_any(self, cell: ErasedPPtr)
        ensures
            self.matches_pptr_any(cell) ==> self.contains_addr_any(cell.addr()),
    ;

    proof fn lemma_has_mut_matches_any(self, cell: ErasedPPtr)
        ensures
            self.has_mut_any(cell) ==> self.matches_pptr_any(cell),
    ;

    /// Sweep the stack and prove a fresh cell's address is absent from every
    /// layer. The probe must point at live, non-zero-sized memory; that lets
    /// each layer's [`PointsTo::is_disjoint`] conclude a distinct address.
    proof fn lemma_fresh_disjoint<W>(tracked &self, tracked probe: &mut PointsTo<W>)
        requires
            size_of::<W>() != 0,
        ensures
            *old(probe) == *final(probe),
            !self.contains_addr_any(old(probe).ptr().addr()),
    ;

    #[verifier::prophetic]
    spec fn mut_preserved_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool;

    spec fn unchanged_except_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool;

    fn copy_to_slice(&self, cell: ErasedPPtr, offset: usize, is_mut: bool, dst: &mut [u8])
        requires
            self.wf(),
            self.has_read_any(cell),
            self.matches_pptr_any(cell),
            self.is_mut_any(cell) == is_mut,
            offset + dst.len() <= self.view_any(cell).len(),
        ensures
            final(dst)@ == final(old(dst))@,
            final(dst).len() == old(dst).len(),
            final(dst)@ =~= self.view_any(cell).subrange(
                offset as int,
                (offset + final(dst).len()) as int,
            ),
    ;

    fn copy_from_slice(&mut self, cell: ErasedPPtr, offset: usize, src: &[u8])
        requires
            old(self).wf(),
            old(self).has_mut_any(cell),
            old(self).matches_pptr_any(cell),
            offset + src.len() <= old(self).view_any(cell).len(),
        ensures
            final(self).wf(),
            final(self).has_mut_any(cell),
            final(self).matches_pptr_any(cell),
            final(self).is_mut_any(cell) == old(self).is_mut_any(cell),
            final(self).view_any(cell).len() == old(self).view_any(cell).len(),
            forall|a: usize| final(self).contains_addr_any(a) == old(self).contains_addr_any(a),
            forall|i: int|
                0 <= i < final(self).view_any(cell).len() ==> if offset <= i < offset + src.len() {
                    final(self).view_any(cell)[i] == src[i - (offset as int)]
                } else {
                    final(self).view_any(cell)[i] == old(self).view_any(cell)[i]
                },
            Self::mut_preserved_any(*final(self), *old(self), cell),
            Self::unchanged_except_any(*final(self), *old(self), cell),
    ;
}

/// Proof-only permission lookup independent of stack depth.
pub trait RmemStackRead<'m>: RmemStack {
    proof fn borrow_read_mut_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m mut [u8]>)
        requires
            self.has_read_any(cell),
            self.is_mut_any(cell),
        ensures
            perm.wf(),
            perm.ptr() == cell.ptr() as *mut &'m mut [u8],
            perm.is_init(),
            perm.value()@ == self.view_any(cell),
    ;

    proof fn borrow_read_shared_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m [u8]>)
        requires
            self.has_read_any(cell),
            !self.is_mut_any(cell),
        ensures
            perm.wf(),
            perm.ptr() == cell.ptr() as *mut &'m [u8],
            perm.is_init(),
            perm.value()@ == self.view_any(cell),
    ;
}

impl RmemStack for RmemNil {
    open spec fn wf(self) -> bool {
        true
    }

    open spec fn contains_addr_any(self, addr: usize) -> bool {
        false
    }

    open spec fn has_read_any(self, cell: ErasedPPtr) -> bool {
        false
    }

    open spec fn has_mut_any(self, cell: ErasedPPtr) -> bool {
        false
    }

    open spec fn is_mut_any(self, cell: ErasedPPtr) -> bool {
        false
    }

    open spec fn view_any(self, cell: ErasedPPtr) -> Seq<u8> {
        Seq::empty()
    }

    open spec fn matches_pptr_any(self, cell: ErasedPPtr) -> bool {
        false
    }

    proof fn lemma_not_contains_no_any(tracked &self, cell: ErasedPPtr) {
    }

    proof fn lemma_matches_contains_any(self, cell: ErasedPPtr) {
    }

    proof fn lemma_has_mut_matches_any(self, cell: ErasedPPtr) {
    }

    proof fn lemma_fresh_disjoint<W>(tracked &self, tracked probe: &mut PointsTo<W>) {
    }

    #[verifier::prophetic]
    open spec fn mut_preserved_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool {
        true
    }

    open spec fn unchanged_except_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool {
        true
    }

    fn copy_to_slice(&self, _cell: ErasedPPtr, _offset: usize, _is_mut: bool, _dst: &mut [u8]) {
    }

    fn copy_from_slice(&mut self, _cell: ErasedPPtr, _offset: usize, _src: &[u8]) {
    }
}

impl<T: RmemStack> RmemStack for Option<T> {
    open spec fn wf(self) -> bool {
        self is Some && self->Some_0.wf()
    }

    open spec fn contains_addr_any(self, addr: usize) -> bool {
        if self is Some {
            self->Some_0.contains_addr_any(addr)
        } else {
            false
        }
    }

    open spec fn has_read_any(self, cell: ErasedPPtr) -> bool {
        if self is Some {
            self->Some_0.has_read_any(cell)
        } else {
            false
        }
    }

    open spec fn has_mut_any(self, cell: ErasedPPtr) -> bool {
        if self is Some {
            self->Some_0.has_mut_any(cell)
        } else {
            false
        }
    }

    open spec fn is_mut_any(self, cell: ErasedPPtr) -> bool {
        if self is Some {
            self->Some_0.is_mut_any(cell)
        } else {
            false
        }
    }

    open spec fn view_any(self, cell: ErasedPPtr) -> Seq<u8> {
        if self is Some {
            self->Some_0.view_any(cell)
        } else {
            Seq::empty()
        }
    }

    open spec fn matches_pptr_any(self, cell: ErasedPPtr) -> bool {
        if self is Some {
            self->Some_0.matches_pptr_any(cell)
        } else {
            false
        }
    }

    proof fn lemma_not_contains_no_any(tracked &self, cell: ErasedPPtr) {
        match self {
            Option::Some(inner) => inner.lemma_not_contains_no_any(cell),
            Option::None => {},
        }
    }

    proof fn lemma_matches_contains_any(self, cell: ErasedPPtr) {
        match self {
            Option::Some(inner) => inner.lemma_matches_contains_any(cell),
            Option::None => {},
        }
    }

    proof fn lemma_has_mut_matches_any(self, cell: ErasedPPtr) {
        match self {
            Option::Some(inner) => inner.lemma_has_mut_matches_any(cell),
            Option::None => {},
        }
    }

    proof fn lemma_fresh_disjoint<W>(tracked &self, tracked probe: &mut PointsTo<W>) {
        match self {
            Option::Some(inner) => inner.lemma_fresh_disjoint(probe),
            Option::None => {},
        }
    }

    #[verifier::prophetic]
    open spec fn mut_preserved_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool {
        if cur is Some && prev is Some {
            T::mut_preserved_any(cur->Some_0, prev->Some_0, cell)
        } else {
            cur == prev
        }
    }

    open spec fn unchanged_except_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool {
        if cur is Some && prev is Some {
            T::unchanged_except_any(cur->Some_0, prev->Some_0, cell)
        } else {
            cur == prev
        }
    }

    fn copy_to_slice(&self, cell: ErasedPPtr, offset: usize, is_mut: bool, dst: &mut [u8]) {
        match self {
            Option::Some(inner) => inner.copy_to_slice(cell, offset, is_mut, dst),
            Option::None => unreached(),
        }
    }

    fn copy_from_slice(&mut self, cell: ErasedPPtr, offset: usize, src: &[u8]) {
        match self {
            Option::Some(inner) => inner.copy_from_slice(cell, offset, src),
            Option::None => unreached(),
        }
    }
}

impl<'m> RmemStackRead<'m> for RmemNil {
    proof fn borrow_read_mut_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m mut [u8]>) {
        proof_from_false()
    }

    proof fn borrow_read_shared_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m [u8]>) {
        proof_from_false()
    }
}

impl<'m, T: RmemStack + RmemStackRead<'m>> RmemStackRead<'m> for Option<T> {
    proof fn borrow_read_mut_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m mut [u8]>) {
        match self {
            Option::Some(inner) => inner.borrow_read_mut_any(cell),
            Option::None => proof_from_false(),
        }
    }

    proof fn borrow_read_shared_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m [u8]>) {
        match self {
            Option::Some(inner) => inner.borrow_read_shared_any(cell),
            Option::None => proof_from_false(),
        }
    }
}

impl<'a, Tail: RmemStack> RmemCons<'a, Tail> {
    /// The permission held by this (well-formed) layer.
    pub open spec fn rp(self) -> RmemPerm<'a> {
        self.perm@->Some_0
    }

    /// Push a fresh mutable Rust slice onto the stack as a new top layer.
    pub fn push_mut(tail: Tail, s: &'a mut [u8]) -> (res: (Self, ErasedPPtr))
        requires
            tail.wf(),
        ensures
            res.0.wf(),
            res.0.addr == res.1.addr(),
            res.0.tail == tail,
            res.0.rp().matches_pptr(res.1),
            res.0.rp().is_init(),
            res.0.rp().is_mut(),
            res.0.has_read_any(res.1),
            res.0.is_mut_any(res.1),
            res.0.view_any(res.1) == old(s)@,
            final(res.0.rp().mut_value())@ =~= final(s)@,
    {
        broadcast use lemma_ref_slice_nonzero;

        let (cell, Tracked(mut perm)) = ErasedPPtr::new(s);
        let addr = cell.addr();
        proof {
            tail.lemma_fresh_disjoint(&mut perm);
        }
        let tracked rp = RmemPerm::Mut(perm);
        let res = RmemCons { perm: Tracked(Some(rp)), addr, tail };
        (res, cell)
    }

    /// Push a fresh shared Rust slice onto the stack as a new top layer.
    pub fn push_shared(tail: Tail, s: &'a [u8]) -> (res: (Self, ErasedPPtr))
        requires
            tail.wf(),
        ensures
            res.0.wf(),
            res.0.addr == res.1.addr(),
            res.0.tail == tail,
            res.0.rp().matches_pptr(res.1),
            res.0.rp().is_init(),
            !res.0.rp().is_mut(),
            res.0.has_read_any(res.1),
            !res.0.is_mut_any(res.1),
            res.0.view_any(res.1) == s@,
    {
        let (cell, Tracked(mut perm)) = ErasedPPtr::new(s);
        let addr = cell.addr();
        proof {
            tail.lemma_fresh_disjoint(&mut perm);
        }
        let tracked rp = RmemPerm::Shared(perm);
        let res = RmemCons { perm: Tracked(Some(rp)), addr, tail };
        (res, cell)
    }

    /// Pop the top mutable layer, reclaiming the owned `&mut [u8]`.
    pub fn reclaim_mut(self, cell: ErasedPPtr) -> (res: (Tail, &'a mut [u8]))
        requires
            self.wf(),
            self.addr == cell.addr(),
            self.rp().matches_pptr(cell),
            self.rp().is_init(),
            self.rp().is_mut(),
        ensures
            res.0 == self.tail,
            res.1@ == self.rp().view(),
            final(res.1)@ =~= final(self.rp().mut_value())@,
    {
        #[allow(unused_mut)]
        let mut this = self;
        let tracked mut taken: Option<RmemPerm<'a>> = None;
        proof {
            tracked_swap(this.perm.borrow_mut(), &mut taken);
        }
        let tracked p = match taken {
            Option::Some(rp) => match rp {
                RmemPerm::Mut(p) => p,
                RmemPerm::Shared(_) => proof_from_false(),
            },
            Option::None => proof_from_false(),
        };
        let s = cell.into_inner(Tracked(p));
        (this.tail, s)
    }

    /// Pop the top shared layer, reclaiming the owned `&[u8]`.
    pub fn reclaim_shared(self, cell: ErasedPPtr) -> (res: (Tail, &'a [u8]))
        requires
            self.wf(),
            self.addr == cell.addr(),
            self.rp().matches_pptr(cell),
            self.rp().is_init(),
            !self.rp().is_mut(),
        ensures
            res.0 == self.tail,
            res.1@ == self.rp().view(),
    {
        #[allow(unused_mut)]
        let mut this = self;
        let tracked mut taken: Option<RmemPerm<'a>> = None;
        proof {
            tracked_swap(this.perm.borrow_mut(), &mut taken);
        }
        let tracked p = match taken {
            Option::Some(rp) => match rp {
                RmemPerm::Shared(p) => p,
                RmemPerm::Mut(_) => proof_from_false(),
            },
            Option::None => proof_from_false(),
        };
        let s = cell.into_inner(Tracked(p));
        (this.tail, s)
    }
}

impl<'a, Tail: RmemStack> RmemStack for RmemCons<'a, Tail> {
    open spec fn wf(self) -> bool {
        &&& self.perm@ is Some
        &&& self.addr == self.rp().addr()
        &&& !self.tail.contains_addr_any(self.addr)
        &&& self.tail.wf()
    }

    open spec fn contains_addr_any(self, addr: usize) -> bool {
        (self.perm@ is Some && self.rp().addr() == addr) || self.tail.contains_addr_any(addr)
    }

    open spec fn has_read_any(self, cell: ErasedPPtr) -> bool {
        let local = self.perm@ is Some && self.rp().matches_pptr(cell) && self.rp().is_init();
        if local {
            true
        } else {
            self.tail.has_read_any(cell)
        }
    }

    open spec fn has_mut_any(self, cell: ErasedPPtr) -> bool {
        let local = self.perm@ is Some && self.rp().matches_pptr(cell) && self.rp().is_init();
        if local {
            self.rp().is_mut()
        } else {
            self.tail.has_mut_any(cell)
        }
    }

    open spec fn is_mut_any(self, cell: ErasedPPtr) -> bool {
        let local = self.perm@ is Some && self.rp().matches_pptr(cell) && self.rp().is_init();
        if local {
            self.rp().is_mut()
        } else {
            self.tail.is_mut_any(cell)
        }
    }

    open spec fn view_any(self, cell: ErasedPPtr) -> Seq<u8> {
        let local = self.perm@ is Some && self.rp().matches_pptr(cell) && self.rp().is_init();
        if local {
            self.rp().view()
        } else {
            self.tail.view_any(cell)
        }
    }

    open spec fn matches_pptr_any(self, cell: ErasedPPtr) -> bool {
        if self.perm@ is Some && self.rp().matches_pptr(cell) {
            true
        } else {
            self.tail.matches_pptr_any(cell)
        }
    }

    proof fn lemma_not_contains_no_any(tracked &self, cell: ErasedPPtr) {
        assert(!(self.perm@ is Some && self.rp().matches_pptr(cell))) by {
            if self.perm@ is Some && self.rp().matches_pptr(cell) {
                match self.rp() {
                    RmemPerm::Mut(p) => {
                        cell.lemma_cast_addr::<&'a mut [u8]>();
                        assert(p.ptr().addr() == cell.addr());
                    },
                    RmemPerm::Shared(p) => {
                        cell.lemma_cast_addr::<&'a [u8]>();
                        assert(p.ptr().addr() == cell.addr());
                    },
                }
            }
        };
        self.tail.lemma_not_contains_no_any(cell);
    }

    proof fn lemma_matches_contains_any(self, cell: ErasedPPtr) {
        if self.perm@ is Some && self.rp().matches_pptr(cell) {
            match self.rp() {
                RmemPerm::Mut(p) => {
                    cell.lemma_cast_addr::<&'a mut [u8]>();
                },
                RmemPerm::Shared(p) => {
                    cell.lemma_cast_addr::<&'a [u8]>();
                },
            }
        } else {
            self.tail.lemma_matches_contains_any(cell);
        }
    }

    proof fn lemma_has_mut_matches_any(self, cell: ErasedPPtr) {
        let local = self.perm@ is Some && self.rp().matches_pptr(cell) && self.rp().is_init();
        if local {
        } else {
            self.tail.lemma_has_mut_matches_any(cell);
        }
    }

    proof fn lemma_fresh_disjoint<W>(tracked &self, tracked probe: &mut PointsTo<W>) {
        broadcast use lemma_ref_slice_nonzero;

        match self.perm.borrow() {
            Option::Some(rp) => match rp {
                RmemPerm::Mut(p) => {
                    probe.is_disjoint(p);
                },
                RmemPerm::Shared(p) => {
                    probe.is_disjoint(p);
                },
            },
            Option::None => {},
        }
        self.tail.lemma_fresh_disjoint(probe);
    }

    #[verifier::prophetic]
    open spec fn mut_preserved_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool {
        let prev_local_mut = prev.perm@ is Some && prev.rp().matches_pptr(cell)
            && prev.rp().is_init() && prev.rp().is_mut();
        if prev_local_mut {
            final(cur.rp().mut_value())@ =~= final(prev.rp().mut_value())@
        } else {
            Tail::mut_preserved_any(cur.tail, prev.tail, cell)
        }
    }

    open spec fn unchanged_except_any(cur: Self, prev: Self, cell: ErasedPPtr) -> bool {
        let prev_local_mut = prev.perm@ is Some && prev.rp().matches_pptr(cell)
            && prev.rp().is_init() && prev.rp().is_mut();
        if prev_local_mut {
            &&& cur.tail == prev.tail
            &&& cur.addr == prev.addr
        } else {
            &&& cur.perm@ == prev.perm@
            &&& cur.addr == prev.addr
            &&& Tail::unchanged_except_any(cur.tail, prev.tail, cell)
        }
    }

    fn copy_to_slice(&self, cell: ErasedPPtr, offset: usize, is_mut: bool, dst: &mut [u8]) {
        let addr = cell.addr();
        if self.addr == addr {
            proof {
                self.tail.lemma_not_contains_no_any(cell);
            }
            if is_mut {
                let tracked p = match self.perm.borrow() {
                    Option::Some(rp) => match rp {
                        RmemPerm::Mut(p) => p,
                        RmemPerm::Shared(_) => proof_from_false(),
                    },
                    Option::None => proof_from_false(),
                };
                cell.copy_to_slice_mut(Tracked(p), offset, dst);
            } else {
                let tracked p = match self.perm.borrow() {
                    Option::Some(rp) => match rp {
                        RmemPerm::Shared(p) => p,
                        RmemPerm::Mut(_) => proof_from_false(),
                    },
                    Option::None => proof_from_false(),
                };
                cell.copy_to_slice_shared(Tracked(p), offset, dst);
            }
        } else {
            assert(!(self.perm@ is Some && self.rp().matches_pptr(cell))) by {
                if self.perm@ is Some && self.rp().matches_pptr(cell) {
                    match self.rp() {
                        RmemPerm::Mut(p) => {
                            cell.lemma_cast_addr::<&'a mut [u8]>();
                            assert(p.ptr().addr() == cell.addr());
                        },
                        RmemPerm::Shared(p) => {
                            cell.lemma_cast_addr::<&'a [u8]>();
                            assert(p.ptr().addr() == cell.addr());
                        },
                    }
                }
            };
            self.tail.copy_to_slice(cell, offset, is_mut, dst);
        }
    }

    fn copy_from_slice(&mut self, cell: ErasedPPtr, offset: usize, src: &[u8]) {
        let addr = cell.addr();
        if self.addr == addr {
            proof {
                self.tail.lemma_not_contains_no_any(cell);
            }
            // Swap the permission out, write through it, and swap it back.
            let tracked mut taken: Option<RmemPerm<'a>> = None;
            proof {
                tracked_swap(self.perm.borrow_mut(), &mut taken);
            }
            let tracked mut p = match taken {
                Option::Some(rp) => match rp {
                    RmemPerm::Mut(p) => p,
                    RmemPerm::Shared(_) => proof_from_false(),
                },
                Option::None => proof_from_false(),
            };
            cell.copy_from_slice(Tracked(&mut p), offset, src);
            let tracked mut back: Option<RmemPerm<'a>> = Some(RmemPerm::Mut(p));
            proof {
                tracked_swap(self.perm.borrow_mut(), &mut back);
            }
        } else {
            assert(!(self.perm@ is Some && self.rp().matches_pptr(cell))) by {
                if self.perm@ is Some && self.rp().matches_pptr(cell) {
                    match self.rp() {
                        RmemPerm::Mut(p) => {
                            cell.lemma_cast_addr::<&'a mut [u8]>();
                            assert(p.ptr().addr() == cell.addr());
                        },
                        RmemPerm::Shared(p) => {
                            cell.lemma_cast_addr::<&'a [u8]>();
                            assert(p.ptr().addr() == cell.addr());
                        },
                    }
                }
            };
            self.tail.copy_from_slice(cell, offset, src);
        }
    }
}

impl<'m, 'a, Tail: RmemStack + RmemStackRead<'m>> RmemStackRead<'m> for RmemCons<'a, Tail> where
    'a: 'm,
 {
    proof fn borrow_read_mut_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m mut [u8]>) {
        let local = self.perm@ is Some && self.rp().matches_pptr(cell) && self.rp().is_init();
        if local {
            match self.perm.borrow() {
                Option::Some(rp) => match rp {
                    RmemPerm::Mut(p) => p,
                    RmemPerm::Shared(_) => proof_from_false(),
                },
                Option::None => proof_from_false(),
            }
        } else {
            self.tail.borrow_read_mut_any(cell)
        }
    }

    proof fn borrow_read_shared_any<'b>(tracked &'b self, cell: ErasedPPtr) -> (tracked perm:
        &'b PointsTo<&'m [u8]>) {
        let local = self.perm@ is Some && self.rp().matches_pptr(cell) && self.rp().is_init();
        if local {
            match self.perm.borrow() {
                Option::Some(rp) => match rp {
                    RmemPerm::Shared(p) => p,
                    RmemPerm::Mut(_) => proof_from_false(),
                },
                Option::None => proof_from_false(),
            }
        } else {
            self.tail.borrow_read_shared_any(cell)
        }
    }
}

} // verus!

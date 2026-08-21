// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Type-erased privileged pointer helper backed by strict-provenance raw
//! pointers.
use crate::helpers::raw_ptr_alloc::allocate;
use vstd::layout::*;
use vstd::prelude::*;
use vstd::raw_ptr::{self, Dealloc, PointsTo as RawPointsTo};
#[cfg(verus_only)]
use vstd::raw_ptr::{MemContents, PointsToRaw, Provenance};

verus! {

pub assume_specification<T: Sized>[ core::ptr::without_provenance_mut::<T> ](addr: usize) -> (p:
    *mut T)
    ensures
        p == raw_ptr::ptr_mut_from_data::<T>(
            raw_ptr::PtrData::<T> { addr, provenance: Provenance::null(), metadata: () },
        ),
    opens_invariants none
    no_unwind
;

pub struct ErasedPPtr {
    ptr: *mut (),
}

/// `vstd` axiomatizes the layout of `&T` and `*mut T`, but not `&mut T`.
///
/// This axiom bridges that gap so that `size_of::<&mut [u8]>()` is known to
/// match `size_of::<*mut [u8]>()`, which in turn lets us prove that a `&mut
/// [u8]` capability is non-zero-sized (required by [`PointsTo::is_disjoint`]).
#[verifier::external_body]
pub broadcast axiom fn layout_of_mut_references<T: ?Sized>()
    ensures
        #![trigger size_of::<&mut T>()]
        size_of::<&mut T>() == size_of::<*mut T>(),
        align_of::<&mut T>() == align_of::<*mut T>(),
;

/// Slice references are fat pointers, hence non-zero-sized.
pub broadcast proof fn lemma_ref_slice_nonzero()
    ensures
        #![trigger size_of::<&[u8]>()]
        #![trigger size_of::<&mut [u8]>()]
        size_of::<&[u8]>() != 0,
        size_of::<&mut [u8]>() != 0,
{
    broadcast use {
        layout_of_mut_references,
        vstd::layout::layout_of_references_and_pointers,
        vstd::layout::layout_of_references_and_pointers_for_unsized_types,
        vstd::layout::layout_of_primitives,
    };

}

pub proof fn lemma_mut_slice_points_to_nonzero<'a>(tracked _perm: &PointsTo<&'a mut [u8]>)
    ensures
        size_of::<&'a mut [u8]>() != 0,
{
    broadcast use lemma_ref_slice_nonzero;

}

pub proof fn lemma_shared_slice_points_to_nonzero<'a>(tracked _perm: &PointsTo<&'a [u8]>)
    ensures
        size_of::<&'a [u8]>() != 0,
{
}

#[allow(dead_code)]
pub tracked struct PointsTo<V> {
    points_to: RawPointsTo<V>,
    dealloc: Option<Dealloc>,
}

impl<V> PointsTo<V> {
    pub closed spec fn wf(self) -> bool {
        &&& size_of::<V>() == 0 ==> self.dealloc is None
        &&& size_of::<V>() != 0 ==> {
            &&& self.dealloc is Some
            &&& self.dealloc->Some_0.addr() == self.points_to.ptr().addr()
            &&& self.dealloc->Some_0.size() == size_of::<V>()
            &&& self.dealloc->Some_0.align() == align_of::<V>()
            &&& self.dealloc->Some_0.provenance() == self.points_to.ptr()@.provenance
        }
    }

    pub closed spec fn ptr(self) -> *mut V {
        self.points_to.ptr()
    }

    pub closed spec fn opt_value(self) -> MemContents<V> {
        self.points_to.opt_value()
    }

    pub closed spec fn is_init(self) -> bool {
        self.points_to.is_init()
    }

    pub closed spec fn is_uninit(self) -> bool {
        self.points_to.is_uninit()
    }

    pub closed spec fn value(self) -> V
        recommends
            self.is_init(),
    {
        self.points_to.value()
    }

    /// Two live, non-zero-sized capabilities occupy disjoint memory, so their
    /// pointers have distinct addresses.
    pub proof fn is_disjoint<W>(tracked &mut self, tracked other: &PointsTo<W>)
        requires
            size_of::<V>() != 0,
            size_of::<W>() != 0,
        ensures
            *old(self) == *final(self),
            old(self).ptr().addr() != other.ptr().addr(),
    {
        self.points_to.is_disjoint(&other.points_to);
    }
}

impl ErasedPPtr {
    pub closed spec fn ptr(self) -> *mut () {
        self.ptr
    }

    pub closed spec fn spec_addr(self) -> usize {
        self.ptr@.addr
    }

    #[verifier::when_used_as_spec(spec_addr)]
    pub fn addr(self) -> (addr: usize)
        ensures
            addr == self.addr(),
    {
        self.ptr.addr()
    }

    #[verifier::external_body]
    pub fn same(self, other: Self) -> (same: bool)
        ensures
            same == (self == other),
    {
        self.ptr == other.ptr
    }

    pub broadcast proof fn lemma_cast_addr<V>(self)
        ensures
            #![trigger (self.ptr() as *mut V).addr()]
            (self.ptr() as *mut V).addr() == self.addr(),
    {
    }

    pub fn new<V>(v: V) -> (res: (Self, Tracked<PointsTo<V>>))
        ensures
            res.1@.wf(),
            res.1@.ptr() == res.0.ptr() as *mut V,
            res.1@.ptr().addr() == res.0.addr(),
            res.1@.value() == v,
            res.1@.opt_value() == MemContents::Init(v),
            res.1@.is_init(),
    {
        layout_for_type_is_valid::<V>();

        if core::mem::size_of::<V>() != 0 {
            let (raw, Tracked(raw_perm), Tracked(dealloc)) = allocate(
                core::mem::size_of::<V>(),
                core::mem::align_of::<V>(),
            );

            let tracked mut points_to = raw_perm.into_typed::<V>(raw.addr());

            raw_ptr::ptr_mut_write(raw as *mut V, Tracked(&mut points_to), v);

            let tracked perm = PointsTo { points_to, dealloc: Some(dealloc) };

            (ErasedPPtr { ptr: raw as *mut () }, Tracked(perm))
        } else {
            let addr = core::mem::align_of::<V>();

            let ptr: *mut V = core::ptr::without_provenance_mut::<V>(addr);

            let tracked emp = PointsToRaw::empty(Provenance::null());
            let tracked points_to = emp.into_typed(addr);

            raw_ptr::ptr_mut_write(ptr, Tracked(&mut points_to), v);

            let tracked perm = PointsTo { points_to, dealloc: None };

            (ErasedPPtr { ptr: ptr as *mut () }, Tracked(perm))
        }
    }

    pub fn borrow<V>(self, Tracked(perm): Tracked<&PointsTo<V>>) -> (v: &V)
        requires
            perm.wf(),
            perm.ptr() == self.ptr() as *mut V,
            perm.is_init(),
        ensures
            *v == perm.value(),
    {
        raw_ptr::ptr_ref(self.ptr as *mut V, Tracked(&perm.points_to))
    }

    pub fn borrow_mut<V>(self, Tracked(perm): Tracked<&mut PointsTo<V>>) -> (v: &mut V)
        requires
            old(perm).wf(),
            old(perm).ptr() == self.ptr() as *mut V,
            old(perm).is_init(),
        ensures
            final(perm).wf(),
            final(perm).ptr() == self.ptr() as *mut V,
            final(perm).is_init(),
            *v == old(perm).value(),
            final(perm).value() == *final(v),
    {
        raw_ptr::ptr_mut_ref(self.ptr as *mut V, Tracked(&mut perm.points_to))
    }

    pub fn into_inner<V>(self, Tracked(perm): Tracked<PointsTo<V>>) -> (v: V)
        requires
            perm.wf(),
            perm.ptr() == self.ptr() as *mut V,
            perm.is_init(),
        ensures
            v == perm.value(),
    {
        let tracked PointsTo { mut points_to, dealloc } = perm;
        let v = raw_ptr::ptr_mut_read(self.ptr as *mut V, Tracked(&mut points_to));
        let tracked raw_perm = points_to.into_raw();
        let raw = self.ptr as *mut u8;
        if core::mem::size_of::<V>() != 0 {
            let tracked d = match dealloc {
                Option::Some(d) => d,
                Option::None => { proof_from_false() },
            };
            raw_ptr::deallocate(
                raw,
                core::mem::size_of::<V>(),
                core::mem::align_of::<V>(),
                Tracked(raw_perm),
                Tracked(d),
            );
        }
        v
    }

    pub fn copy_from_slice<'a>(
        self,
        Tracked(perm): Tracked<&mut PointsTo<&'a mut [u8]>>,
        offset: usize,
        src: &[u8],
    )
        requires
            old(perm).wf(),
            old(perm).ptr() == self.ptr() as *mut &'a mut [u8],
            old(perm).is_init(),
            (offset + src.len()) <= old(perm).value()@.len(),
        ensures
            final(perm).wf(),
            final(perm).ptr() == self.ptr() as *mut &'a mut [u8],
            final(perm).is_init(),
            final(perm).value()@.len() == old(perm).value()@.len(),
            final(final(perm).value())@ =~= final(old(perm).value())@,
            forall|i: int|
                0 <= i < final(perm).value().len() ==> if offset <= i < offset + src.len() {
                    final(perm).value()@[i] == src@[i - offset]
                } else {
                    final(perm).value()@[i] == old(perm).value()@[i]
                },
    {
        let ghost orig = perm.value();

        let slice: &mut &'a mut [u8] = self.borrow_mut(Tracked(perm));
        let ghost slice_len = slice.len();

        for i in 0..src.len()
            invariant
                0 <= i <= src.len(),
                slice_len == orig.len(),
                slice_len == orig@.len(),
                slice.len() == slice_len,
                offset + src.len() <= slice_len,
                // the inner mutable slice reference has not been swapped out.
                final(*slice)@ =~= final(orig)@,
                forall|j: int|
                    #![trigger slice@[j]]
                    0 <= j < slice_len ==> if offset <= j < offset + i {
                        slice@[j] == src@[j - offset]
                    } else {
                        slice@[j] == orig@[j]
                    },
        {
            let idx = offset + i;
            slice[idx] = src[i];

        }

    }

    pub fn copy_to_slice_mut<'a>(
        self,
        Tracked(perm): Tracked<&PointsTo<&'a mut [u8]>>,
        offset: usize,
        dst: &mut [u8],
    )
        requires
            perm.wf(),
            perm.ptr() == self.ptr() as *mut &'a mut [u8],
            perm.is_init(),
            (offset + dst.len()) <= perm.value()@.len(),
        ensures
            final(dst)@ == final(old(dst))@,
            final(dst).len() == old(dst).len(),
            final(dst)@ =~= perm.value()@.subrange(
                offset as int,
                (offset + final(dst)@.len()) as int,
            ),
    {
        let slice: &&'a mut [u8] = self.borrow(Tracked(perm));
        let ghost slice_len = slice.len();

        let dst_len = dst.len();

        for i in 0..dst_len
            invariant
                0 <= i <= dst_len,
                dst_len == dst.len(),
                slice.len() == slice_len,
                offset + dst_len <= slice_len,
                forall|j: int|
                    #![trigger dst@[j as int]]
                    0 <= j < i ==> dst@[j as int] == slice@[offset + j],
        {
            let idx = offset + i;
            dst[i] = slice[idx];
        }

    }

    pub fn copy_to_slice_shared<'a>(
        self,
        Tracked(perm): Tracked<&PointsTo<&'a [u8]>>,
        offset: usize,
        dst: &mut [u8],
    )
        requires
            perm.wf(),
            perm.ptr() == self.ptr() as *mut &'a [u8],
            perm.is_init(),
            (offset + dst.len()) <= perm.value()@.len(),
        ensures
            final(dst).len() == old(dst).len(),
            forall|i: int|
                0 <= i < final(dst).len() ==> final(dst)@[i] == perm.value()@[offset + i],
    {
        let slice: &&'a [u8] = self.borrow(Tracked(perm));
        let ghost slice_len = slice.len();

        let dst_len = dst.len();

        for i in 0..dst_len
            invariant
                0 <= i <= dst_len,
                dst_len == dst.len(),
                slice.len() == slice_len,
                offset + dst_len <= slice_len,
                forall|j: int|
                    #![trigger dst@[j as int]]
                    0 <= j < i ==> dst@[j as int] == slice@[offset + j],
        {
            let idx = offset + i;
            dst[i] = slice[idx];
        }
    }
}

impl Clone for ErasedPPtr {
    fn clone(&self) -> (res: Self)
        ensures
            res == *self,
    {
        *self
    }
}

impl Copy for ErasedPPtr {

}

} // verus!
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(verus_only)]
    use vstd::prelude::*;

    verus! {

fn write_first_byte<'a>(dst: &'a mut [u8]) -> (recovered: &'a mut [u8])
    requires
        old(dst)@.len() > 0,
    ensures
        recovered@ == old(dst)@.update(0, 7u8),
{
    let (pptr, Tracked(mut perm)) = ErasedPPtr::new(dst);
    {
        let slice: &mut &'a mut [u8] = pptr.borrow_mut(Tracked(&mut perm));
        slice[0] = 7;
    }
    pptr.into_inner(Tracked(perm))
}

} // verus!
    #[test]
    fn erased_pptr_roundtrip_runs() {
        let mut dst = [0x11u8, 0x22, 0x33];
        let recovered = write_first_byte(&mut dst);
        assert_eq!(recovered, &mut [0x07, 0x22, 0x33]);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed privileged pointers backed by strict-provenance raw pointers.
use crate::helpers::raw_ptr_alloc::allocate;
use vstd::layout::*;
use vstd::prelude::*;
use vstd::raw_ptr::{self, Dealloc, PointsTo as RawPointsTo};
#[cfg(verus_only)]
use vstd::raw_ptr::{MemContents, PointsToRaw, Provenance};

verus! {

pub struct OwnedPPtr<V> {
    ptr: *mut V,
}

#[verifier::external]
unsafe impl<V: Send> Send for OwnedPPtr<V> {

}

#[verifier::external]
unsafe impl<V: Sync> Sync for OwnedPPtr<V> {

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

    pub closed spec fn pptr(self) -> OwnedPPtr<V> {
        OwnedPPtr { ptr: self.ptr() }
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

impl<V> OwnedPPtr<V> {
    pub closed spec fn ptr(self) -> *mut V {
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

    pub fn new(v: V) -> (res: (Self, Tracked<PointsTo<V>>))
        ensures
            res.1@.wf(),
            res.1@.ptr() == res.0.ptr(),
            res.1@.pptr() == res.0,
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

            (OwnedPPtr { ptr: raw as *mut V }, Tracked(perm))
        } else {
            let addr = core::mem::align_of::<V>();

            let ptr: *mut V = core::ptr::without_provenance_mut::<V>(addr);

            let tracked emp = PointsToRaw::empty(Provenance::null());
            let tracked points_to = emp.into_typed(addr);

            raw_ptr::ptr_mut_write(ptr, Tracked(&mut points_to), v);

            let tracked perm = PointsTo { points_to, dealloc: None };

            (OwnedPPtr { ptr }, Tracked(perm))
        }
    }

    pub fn borrow(self, Tracked(perm): Tracked<&PointsTo<V>>) -> (v: &V)
        requires
            perm.wf(),
            perm.ptr() == self.ptr(),
            perm.is_init(),
        ensures
            *v == perm.value(),
    {
        raw_ptr::ptr_ref(self.ptr, Tracked(&perm.points_to))
    }

    pub fn borrow_mut(self, Tracked(perm): Tracked<&mut PointsTo<V>>) -> (v: &mut V)
        requires
            old(perm).wf(),
            old(perm).ptr() == self.ptr(),
            old(perm).is_init(),
        ensures
            final(perm).wf(),
            final(perm).ptr() == self.ptr(),
            final(perm).is_init(),
            *v == old(perm).value(),
            final(perm).value() == *final(v),
    {
        raw_ptr::ptr_mut_ref(self.ptr, Tracked(&mut perm.points_to))
    }

    pub fn into_inner(self, Tracked(perm): Tracked<PointsTo<V>>) -> (v: V)
        requires
            perm.wf(),
            perm.ptr() == self.ptr(),
            perm.is_init(),
        ensures
            v == perm.value(),
    {
        let tracked PointsTo { mut points_to, dealloc } = perm;
        let v = raw_ptr::ptr_mut_read(self.ptr, Tracked(&mut points_to));
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
}

/// `Box<T>` has the same layout as `*mut T` for any (possibly unsized) `T`:
/// both are thin/fat pointers. `vstd` axiomatizes pointer/reference layout but
/// not `Box`, so this bridges the gap.
pub broadcast axiom fn layout_of_box<T: ?Sized>()
    ensures
        #![trigger size_of::<Box<T>>()]
        size_of::<Box<T>>() == size_of::<*mut T>(),
        align_of::<Box<T>>() == align_of::<*mut T>(),
;

/// A `Box` of a (possibly) unsized value is a thin or fat pointer, hence
/// non-zero-sized.
pub broadcast proof fn lemma_box_unsized_nonzero<T: ?Sized>()
    ensures
        #![trigger size_of::<Box<T>>()]
        size_of::<Box<T>>() != 0,
{
    broadcast use {
        layout_of_box,
        vstd::layout::layout_of_references_and_pointers_for_unsized_types,
        vstd::layout::layout_of_primitives,
    };

}

pub broadcast proof fn lemma_owned_pptr_addr<V>(p: OwnedPPtr<V>)
    ensures
        #[trigger] p.spec_addr() == p.ptr().addr(),
{
}

impl<V> Clone for OwnedPPtr<V> {
    fn clone(&self) -> (res: Self)
        ensures
            res == *self,
    {
        *self
    }
}

impl<V> Copy for OwnedPPtr<V> {

}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    verus! {

fn write_first_byte(v: Vec<u8>) -> (recovered: Vec<u8>)
    requires
        v@.len() > 0,
    ensures
        recovered@ == v@.update(0, 7u8),
{
    let (pptr, Tracked(mut perm)) = OwnedPPtr::new(v);
    {
        let bytes = pptr.borrow_mut(Tracked(&mut perm));
        bytes.set(0, 7);
    }
    pptr.into_inner(Tracked(perm))
}

} // verus!

    #[test]
    fn owned_pptr_roundtrip_runs() {
        assert_send_sync::<OwnedPPtr<u8>>();
        assert_send_sync::<PointsTo<u8>>();
        assert_send_sync::<Tracked<PointsTo<u8>>>();

        let recovered = write_first_byte(vec![0x11u8, 0x22, 0x33]);
        assert_eq!(recovered, vec![0x07, 0x22, 0x33]);
    }

    fn assert_send_sync<T: Send + Sync>() {}
}

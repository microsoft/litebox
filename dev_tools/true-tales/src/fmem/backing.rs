// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::helpers::owned_pptr::{OwnedPPtr, PointsTo};
use vstd::prelude::*;
use vstd::rwlock::{RwLock, RwLockPredicate};

verus! {

pub ghost struct TransactionalVecPred {
    pub pptr: OwnedPPtr<Vec<u8>>,
    pub base: usize,
    pub len: nat,
}

impl RwLockPredicate<Tracked<PointsTo<Vec<u8>>>> for TransactionalVecPred {
    open spec fn inv(self, p: Tracked<PointsTo<Vec<u8>>>) -> bool {
        &&& p@.wf()
        &&& p@.ptr() == self.pptr.ptr()
        &&& p@.is_init()
        &&& p@.value().len() == self.len
    }
}

/// Executable byte-vector backing for a foreign-memory region.
///
/// The lock predicate pins the backing allocation and its length. The
/// `read_atomic` and `write_atomic` methods use that lock to model one
/// indivisible foreign-memory transaction over an absolute address window
/// `[base, base + len)`.
pub struct TransactionalVec {
    pptr: OwnedPPtr<Vec<u8>>,
    base: usize,
    len: usize,
    lock: RwLock<Tracked<PointsTo<Vec<u8>>>, TransactionalVecPred>,
}

impl TransactionalVec {
    pub open spec fn wf(&self) -> bool {
        &&& self.spec_lock().pred().pptr == self.spec_pptr()
        &&& self.spec_lock().pred().base == self.spec_base()
        &&& self.spec_lock().pred().len == self.spec_len()
        &&& self.spec_base() as nat + self.spec_len() as nat <= usize::MAX as nat
    }

    pub closed spec fn spec_pptr(&self) -> OwnedPPtr<Vec<u8>> {
        self.pptr
    }

    pub closed spec fn spec_base(&self) -> usize {
        self.base
    }

    pub closed spec fn spec_len(&self) -> usize {
        self.len
    }

    pub open spec fn base(&self) -> nat {
        self.spec_base() as nat
    }

    pub open spec fn len(&self) -> nat {
        self.spec_len() as nat
    }

    #[verifier::when_used_as_spec(spec_pptr)]
    pub fn pptr(&self) -> (p: OwnedPPtr<Vec<u8>>)
        ensures
            p == self.pptr(),
    {
        self.pptr
    }

    #[verifier::when_used_as_spec(spec_base)]
    pub fn base_addr(&self) -> (b: usize)
        ensures
            b == self.base_addr(),
    {
        self.base
    }

    #[verifier::when_used_as_spec(spec_len)]
    pub fn size(&self) -> (l: usize)
        ensures
            l == self.size(),
    {
        self.len
    }

    #[allow(clippy::type_complexity)]
    pub fn acquire_write(&self) -> (r: (
        Tracked<PointsTo<Vec<u8>>>,
        vstd::rwlock::WriteHandle<'_, Tracked<PointsTo<Vec<u8>>>, TransactionalVecPred>,
    ))
        ensures
            r.1.rwlock() == self.spec_lock(),
            self.spec_lock().pred().inv(r.0),
    {
        self.lock.acquire_write()
    }

    pub closed spec fn spec_lock(&self) -> RwLock<
        Tracked<PointsTo<Vec<u8>>>,
        TransactionalVecPred,
    > {
        self.lock
    }

    pub fn from_backing(base: usize, backing: Vec<u8>) -> (backing_vec: Self)
        requires
            base as nat + backing@.len() <= usize::MAX as nat,
        ensures
            backing_vec.wf(),
            backing_vec.base() == base,
            backing_vec.len() == backing@.len(),
    {
        let len = backing.len();
        let (pptr, points_to) = OwnedPPtr::new(backing);
        let ghost pred = TransactionalVecPred { pptr, base, len: len as nat };
        let lock = RwLock::new(points_to, Ghost(pred));
        TransactionalVec { pptr, base, len, lock }
    }

    pub fn zeroed(base: usize, len: usize) -> (backing_vec: Self)
        requires
            base as nat + len as nat <= usize::MAX as nat,
        ensures
            backing_vec.wf(),
            backing_vec.base() == base,
            backing_vec.len() == len,
    {
        TransactionalVec::from_backing(base, vec![0; len])
    }

    pub fn into_backing(self) -> (backing: Vec<u8>)
        requires
            self.wf(),
        ensures
            backing@.len() == self.len(),
    {
        let pptr = self.pptr;
        let lock = self.lock;
        let points_to = lock.into_inner();
        pptr.into_inner(points_to)
    }

    pub fn read_atomic(&self, dst: &mut [u8], absolute_offset: usize) -> (observed: Ghost<Seq<u8>>)
        requires
            self.wf(),
            absolute_offset >= self.base_addr(),
            old(dst).len() <= self.len(),
            absolute_offset - self.base_addr() <= self.len() - old(dst).len(),
        ensures
            final(dst).len() == old(dst).len(),
            final(dst).len() == observed@.len(),
            final(dst)@ == observed@,
    {
        let read_handle = self.lock.acquire_read();
        let _points_to = read_handle.borrow();
        let mem = self.pptr.borrow(Tracked(_points_to.borrow()));
        let ghost observed = Seq::empty();

        let n = dst.len();
        let backing_offset = absolute_offset - self.base;
        for i in 0..n
            invariant
                0 <= i <= n,
                n == dst.len(),
                backing_offset + n <= mem.len(),
                observed.len() == i,
                forall|j: int| 0 <= j < i ==> #[trigger] dst[j] == observed[j],
        {
            let read_byte = mem[backing_offset + i];
            dst[i] = read_byte;
            proof {
                observed = observed.push(read_byte);
            }
        }

        read_handle.release_read();

        assert(dst@ =~= observed);
        Ghost(observed)
    }

    pub fn write_atomic(&self, src: &[u8], absolute_offset: usize)
        requires
            self.wf(),
            absolute_offset >= self.base_addr(),
            src.len() <= self.len(),
            absolute_offset - self.base_addr() <= self.len() - src.len(),
        ensures
            self.wf(),
    {
        #[allow(unused_mut)]
        let (mut points_to, write_handle) = self.lock.acquire_write();
        let mem = self.pptr.borrow_mut(Tracked(points_to.borrow_mut()));

        let n = src.len();
        let backing_offset = absolute_offset - self.base;
        for i in 0..n
            invariant
                0 <= i <= n,
                n == src.len(),
                backing_offset + n <= mem.len(),
                mem.len() == self.len(),
        {
            mem[backing_offset + i] = src[i];
        }

        write_handle.release_write(points_to);
    }
}

} // verus!
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn transactional_vec_miri_smoke() {
        let backing = TransactionalVec::from_backing(0x1000, vec![1u8, 2, 3, 4]);

        let mut out = vec![0u8; 2];
        let _observed = backing.read_atomic(&mut out, 0x1001);
        assert_eq!(out, vec![2u8, 3u8]);

        backing.write_atomic(&[9u8, 8u8], 0x1002);

        let mut out_after = vec![0u8; 4];
        let _observed_after = backing.read_atomic(&mut out_after, 0x1000);
        assert_eq!(out_after, vec![1u8, 2u8, 9u8, 8u8]);

        assert_eq!(backing.into_backing(), vec![1u8, 2u8, 9u8, 8u8]);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::backing::{TransactionalVec, TransactionalVecPred};
use crate::fmem::erasure::DynState;
use crate::fmem::extent::{AddressExtent, WrongRegion};
use crate::fmem::ids::{DomainCookie, ForeignRegionId};
use crate::fmem::session::{AccessDisposition, DomainSession, ForeignDomain};
use crate::helpers::owned_pptr::{OwnedPPtr, PointsTo};
use crate::helpers::rust_any::{RuntimeAnyRef, RuntimeTypeTag};

#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
use vstd::prelude::*;
use vstd::rwlock::{RwLock, WriteHandle};

#[cfg(verus_only)]
use vstd::rwlock::RwLockPredicate;

verus! {

pub ghost struct UncoopFaultSessionView {
    pub region: ForeignRegionId,
    pub pptr: OwnedPPtr<Vec<u8>>,
    pub base: usize,
    pub len: usize,
    pub lock: RwLock<Tracked<PointsTo<Vec<u8>>>, TransactionalVecPred>,
    pub perm: Tracked<PointsTo<Vec<u8>>>,
}

pub struct UncoopFaultDomainState {
    region: ForeignRegionId,
    backing: TransactionalVec,
    cookie: DomainCookie,
}

pub struct UncoopFaultSession<'a> {
    obj: &'a UncoopFaultDomainState,
    perm: Tracked<PointsTo<Vec<u8>>>,
    handle: WriteHandle<'a, Tracked<PointsTo<Vec<u8>>>, TransactionalVecPred>,
}

pub struct UncoopFaultDomain(());

impl UncoopFaultDomainState {
    pub closed spec fn spec_region(&self) -> ForeignRegionId {
        self.region
    }

    pub closed spec fn backing(&self) -> TransactionalVec {
        self.backing
    }

    pub fn backing_ref(&self) -> (b: &TransactionalVec)
        ensures
            *b == self.backing(),
    {
        &self.backing
    }

    #[verifier::when_used_as_spec(spec_region)]
    pub fn region(&self) -> (r: ForeignRegionId)
        ensures
            r == self.region(),
    {
        self.region
    }
}

impl<'a> UncoopFaultSession<'a> {
    pub closed spec fn spec_obj(&self) -> UncoopFaultDomainState {
        *self.obj
    }

    pub closed spec fn spec_perm(&self) -> Tracked<PointsTo<Vec<u8>>> {
        self.perm
    }

    pub closed spec fn spec_handle_rwlock(&self) -> RwLock<
        Tracked<PointsTo<Vec<u8>>>,
        TransactionalVecPred,
    > {
        self.handle.rwlock()
    }
}

impl DynState for UncoopFaultDomainState {
    open spec fn wf(&self) -> bool {
        self.backing().wf()
    }

    open spec fn spec_tag(&self) -> int {
        type_tag::<UncoopFaultDomainState>()
    }

    closed spec fn spec_cookie(&self) -> DomainCookie {
        self.cookie
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<UncoopFaultDomainState>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.cookie
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

impl<'a> DomainSession for UncoopFaultSession<'a> {
    type State = UncoopFaultSessionView;

    open spec fn st(&self) -> UncoopFaultSessionView {
        UncoopFaultSessionView {
            region: self.spec_obj().region(),
            pptr: self.spec_obj().backing().pptr(),
            base: self.spec_obj().backing().base_addr(),
            len: self.spec_obj().backing().size(),
            lock: self.spec_handle_rwlock(),
            perm: self.spec_perm(),
        }
    }

    open spec fn wf(st: UncoopFaultSessionView) -> bool {
        &&& st.lock.pred().pptr == st.pptr
        &&& st.lock.pred().base == st.base
        &&& st.lock.pred().len == st.len
        &&& st.base + st.len <= usize::MAX
        &&& st.lock.pred().inv(st.perm)
    }

    open spec fn interfere(pre: UncoopFaultSessionView, post: UncoopFaultSessionView) -> bool {
        &&& post.region == pre.region
        &&& post.pptr == pre.pptr
        &&& post.base == pre.base
        &&& post.len == pre.len
        &&& post.lock == pre.lock
        &&& post.perm@.wf() == pre.perm@.wf()
        &&& post.perm@.ptr() == pre.perm@.ptr()
        &&& post.perm@.is_init() == pre.perm@.is_init()
        &&& post.perm@.value().len() == pre.perm@.value().len()
    }

    proof fn lemma_interfere_refl(_s: UncoopFaultSessionView) {
    }

    proof fn lemma_interfere_trans(
        _a: UncoopFaultSessionView,
        _b: UncoopFaultSessionView,
        _c: UncoopFaultSessionView,
    ) {
    }

    proof fn lemma_interfere_wf(_pre: UncoopFaultSessionView, _post: UncoopFaultSessionView) {
    }

    open spec fn address_extent(
        st: UncoopFaultSessionView,
        region: ForeignRegionId,
        index: usize,
    ) -> Option<AddressExtent> {
        if st.region == region {
            Some(AddressExtent { start: st.base, end: (st.base + st.len) as usize, index })
        } else {
            None
        }
    }

    proof fn lemma_address_extent_interfere(
        _pre: UncoopFaultSessionView,
        _post: UncoopFaultSessionView,
        _region: ForeignRegionId,
        _index: usize,
    ) {
    }

    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >) {
        if self.obj.region().raw == region.raw {
            let start = self.obj.backing_ref().base_addr();
            Ok(AddressExtent { start, end: start + self.obj.backing_ref().size(), index })
        } else {
            Err(WrongRegion)
        }
    }

    open spec fn load_disposition(
        st: UncoopFaultSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region != region {
            AccessDisposition::Invalid
        } else if offset >= st.base && size <= st.len && offset - st.base <= st.len - size {
            AccessDisposition::MayFault
        } else {
            AccessDisposition::AlwaysFaults
        }
    }

    fn check_load_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition) {
        let base = self.obj.backing_ref().base_addr();
        let len = self.obj.backing_ref().size();
        if self.obj.region().raw != region.raw {
            AccessDisposition::Invalid
        } else if offset >= base && size <= len && offset - base <= len - size {
            AccessDisposition::MayFault
        } else {
            AccessDisposition::AlwaysFaults
        }
    }

    open spec fn load_post(
        pre: UncoopFaultSessionView,
        post: UncoopFaultSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool {
        &&& post == pre
        &&& pre.region == region
        &&& offset >= pre.base
        &&& size <= pre.len
        &&& offset - pre.base <= pre.len - size
        &&& observed.len() == size
    }

    open spec fn store_disposition(
        st: UncoopFaultSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region != region {
            AccessDisposition::Invalid
        } else if offset >= st.base && size <= st.len && offset - st.base <= st.len - size {
            AccessDisposition::MayFault
        } else {
            AccessDisposition::AlwaysFaults
        }
    }

    fn check_store_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition) {
        let base = self.obj.backing_ref().base_addr();
        let len = self.obj.backing_ref().size();
        if self.obj.region().raw != region.raw {
            AccessDisposition::Invalid
        } else if offset >= base && size <= len && offset - base <= len - size {
            AccessDisposition::MayFault
        } else {
            AccessDisposition::AlwaysFaults
        }
    }

    open spec fn store_post(
        pre: UncoopFaultSessionView,
        post: UncoopFaultSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        written: Seq<u8>,
    ) -> bool {
        &&& post.region == pre.region
        &&& post.pptr == pre.pptr
        &&& post.base == pre.base
        &&& post.len == pre.len
        &&& post.lock == pre.lock
        &&& post.perm@.wf()
        &&& post.perm@.ptr() == pre.perm@.ptr()
        &&& post.perm@.is_init()
        &&& post.perm@.value().len() == pre.perm@.value().len()
        &&& pre.region == region
        &&& offset >= pre.base
        &&& size <= pre.len
        &&& offset - pre.base <= pre.len - size
        &&& written.len() == size
    }

    proof fn lemma_load_post_wf(
        _pre: UncoopFaultSessionView,
        _post: UncoopFaultSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _observed: Seq<u8>,
    ) {
    }

    proof fn lemma_store_post_wf(
        _pre: UncoopFaultSessionView,
        _post: UncoopFaultSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _written: Seq<u8>,
    ) {
    }

    fn load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (bytes: Vec<
        u8,
    >) {
        proof {
            Self::lemma_interfere_refl(old(self).st());
        }
        let _ = region;
        let pptr = self.obj.backing_ref().pptr();
        let base = self.obj.backing_ref().base_addr();
        let backing_offset = offset - base;
        let mem: &Vec<u8> = pptr.borrow(Tracked(self.perm.borrow()));

        let mut out: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < size
            invariant
                i <= size,
                out@.len() == i,
                backing_offset + size <= mem.len(),
            decreases size - i,
        {
            out.push(mem[backing_offset + i]);
            i += 1;
        }
        out
    }

    fn try_load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (res: (
        bool,
        Vec<u8>,
    )) {
        proof {
            Self::lemma_interfere_refl(old(self).st());
        }
        let ghost pre = old(self).st();
        let base = self.obj.backing_ref().base_addr();
        let len = self.obj.backing_ref().size();
        if offset >= base && size <= len && offset - base <= len - size {
            assert forall|env: UncoopFaultSessionView| #[trigger]
                Self::interfere(pre, env) implies Self::load_disposition(
                env,
                region,
                offset,
                size,
            ).permits_success() by {
                Self::lemma_interfere_refl(pre);
            }
            let bytes = self.load_atomic(region, offset, size);
            (false, bytes)
        } else {
            (true, Vec::new())
        }
    }

    fn store_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize, data: &[u8]) {
        proof {
            Self::lemma_interfere_refl(old(self).st());
        }
        let _ = region;
        let pptr = self.obj.backing_ref().pptr();
        let base = self.obj.backing_ref().base_addr();
        let ghost blen = self.obj.backing().spec_len();
        let backing_offset = offset - base;
        let mem: &mut Vec<u8> = pptr.borrow_mut(Tracked(self.perm.borrow_mut()));

        let mut i: usize = 0;
        while i < size
            invariant
                i <= size,
                data@.len() == size,
                mem.len() == blen,
                backing_offset + size <= blen,
            decreases size - i,
        {
            mem[backing_offset + i] = data[i];
            i += 1;
        }
    }

    fn try_store_atomic(
        &mut self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> (faulted: bool) {
        proof {
            Self::lemma_interfere_refl(old(self).st());
        }
        let ghost pre = old(self).st();
        let base = self.obj.backing_ref().base_addr();
        let len = self.obj.backing_ref().size();
        if offset >= base && size <= len && offset - base <= len - size {
            assert forall|env: UncoopFaultSessionView| #[trigger]
                Self::interfere(pre, env) implies Self::store_disposition(
                env,
                region,
                offset,
                size,
            ).permits_success() by {
                Self::lemma_interfere_refl(pre);
            }
            self.store_atomic(region, offset, size, data);
            false
        } else {
            true
        }
    }

    fn close(self) {
        let perm = self.perm;
        let handle = self.handle;
        handle.release_write(perm);
    }
}

impl ForeignDomain for UncoopFaultDomain {
    type Obj = UncoopFaultDomainState;

    type Session<'a> = UncoopFaultSession<'a>;

    fn open<'a>(obj: &'a UncoopFaultDomainState) -> (s: UncoopFaultSession<'a>) {
        let (perm, handle) = obj.backing_ref().acquire_write();
        UncoopFaultSession { obj, perm, handle }
    }
}

impl UncoopFaultDomain {
    pub fn open_strong<'a>(obj: &'a UncoopFaultDomainState) -> (s: UncoopFaultSession<'a>)
        requires
            obj.wf(),
        ensures
            <UncoopFaultSession<'a> as DomainSession>::wf(s.st()),
            s.st().region == obj.region(),
            s.st().base == obj.backing().spec_base(),
            s.st().len == obj.backing().spec_len(),
    {
        let (perm, handle) = obj.backing_ref().acquire_write();
        UncoopFaultSession { obj, perm, handle }
    }
}

impl UncoopFaultDomainState {
    pub fn zeroed(region: ForeignRegionId, base: usize, len: usize, cookie: DomainCookie) -> (obj:
        Self)
        requires
            base as nat + len as nat <= usize::MAX as nat,
        ensures
            obj.wf(),
            obj.region() == region,
            obj.backing().spec_base() == base,
            obj.backing().spec_len() == len,
            obj.spec_cookie() == cookie,
    {
        UncoopFaultDomainState { region, backing: TransactionalVec::zeroed(base, len), cookie }
    }
}

pub fn drive_uncoop_fault_session(obj: &UncoopFaultDomainState)
    requires
        obj.wf(),
        obj.backing().spec_len() >= 4,
{
    let mut sess = UncoopFaultDomain::open_strong(obj);
    let ghost s0 = sess.st();
    let base = obj.backing_ref().base_addr();
    let hi = base + 2;
    let region = obj.region();

    assert forall|env: UncoopFaultSessionView| #[trigger]
        UncoopFaultSession::interfere(s0, env) implies {
        &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_success()
        &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_fault()
        &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_success()
        &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_fault()
    } by {}

    let _b1 = sess.load_atomic(region, base, 2);
    let ghost s1 = sess.st();
    assert(_b1@.len() == 2);
    let ghost e1 = choose|env: UncoopFaultSessionView|
        #![trigger UncoopFaultSession::interfere(s0, env)]
        UncoopFaultSession::interfere(s0, env) && UncoopFaultSession::load_post(
            env,
            s1,
            region,
            base,
            2,
            _b1@,
        );
    assert(UncoopFaultSession::interfere(s0, s1));

    proof {
        lemma_drift_admits(s0, s1, region, base, hi);
    }
    let (_f2, _b2) = sess.try_load_atomic(region, base, 2);
    let ghost s2 = sess.st();
    proof {
        if _f2 {
            UncoopFaultSession::lemma_interfere_trans(s0, s1, s2);
        } else {
            let e2 = choose|env: UncoopFaultSessionView|
                #![trigger UncoopFaultSession::interfere(s1, env)]
                UncoopFaultSession::interfere(s1, env) && UncoopFaultSession::load_post(
                    env,
                    s2,
                    region,
                    base,
                    2,
                    _b2@,
                );
            UncoopFaultSession::lemma_interfere_trans(s0, s1, s2);
        }
    }
    assert(UncoopFaultSession::interfere(s0, s2));

    let data: Vec<u8> = vec![7u8, 9u8];
    proof {
        lemma_drift_admits(s0, s2, region, base, hi);
    }
    sess.store_atomic(region, hi, 2, data.as_slice());
    let ghost s3 = sess.st();
    proof {
        let e3 = choose|env: UncoopFaultSessionView|
            #![trigger UncoopFaultSession::interfere(s2, env)]
            UncoopFaultSession::interfere(s2, env) && UncoopFaultSession::store_post(
                env,
                s3,
                region,
                hi,
                2,
                data@,
            );
        UncoopFaultSession::lemma_interfere_trans(s0, s2, s3);
    }
    assert(UncoopFaultSession::interfere(s0, s3));

    proof {
        lemma_drift_admits(s0, s3, region, base, hi);
    }
    let _f4 = sess.try_store_atomic(region, hi, 2, data.as_slice());
    let ghost s4 = sess.st();
    proof {
        if !_f4 {
            let e4 = choose|env: UncoopFaultSessionView|
                #![trigger UncoopFaultSession::interfere(s3, env)]
                UncoopFaultSession::interfere(s3, env) && UncoopFaultSession::store_post(
                    env,
                    s4,
                    region,
                    hi,
                    2,
                    data@,
                );
        }
        UncoopFaultSession::lemma_interfere_trans(s0, s3, s4);
    }

    assert(s4.region == obj.region());
    assert(s4.base == obj.backing().spec_base());
    assert(s4.len == obj.backing().spec_len());
    assert(s4.perm@.value().len() == obj.backing().spec_len());

    sess.close();
}

proof fn lemma_drift_admits(
    s0: UncoopFaultSessionView,
    sk: UncoopFaultSessionView,
    region: ForeignRegionId,
    base: usize,
    hi: usize,
)
    requires
        UncoopFaultSession::interfere(s0, sk),
        forall|env: UncoopFaultSessionView| #[trigger]
            UncoopFaultSession::interfere(s0, env) ==> {
                &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_success()
                &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_fault()
                &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_success()
                &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_fault()
            },
    ensures
        forall|env: UncoopFaultSessionView| #[trigger]
            UncoopFaultSession::interfere(sk, env) ==> {
                &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_success()
                &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_fault()
                &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_success()
                &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_fault()
            },
{
    assert forall|env: UncoopFaultSessionView| #[trigger]
        UncoopFaultSession::interfere(sk, env) implies {
        &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_success()
        &&& UncoopFaultSession::load_disposition(env, region, base, 2).permits_fault()
        &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_success()
        &&& UncoopFaultSession::store_disposition(env, region, hi, 2).permits_fault()
    } by {
        UncoopFaultSession::lemma_interfere_trans(s0, sk, env);
    }
}

} // verus!

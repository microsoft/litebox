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

pub ghost struct StableUserSessionView {
    pub region: ForeignRegionId,
    pub pptr: OwnedPPtr<Vec<u8>>,
    pub base: usize,
    pub len: usize,
    pub lock: RwLock<Tracked<PointsTo<Vec<u8>>>, TransactionalVecPred>,
    pub perm: Tracked<PointsTo<Vec<u8>>>,
}

impl StableUserSessionView {
    pub open spec fn bytes(self) -> Seq<u8> {
        self.perm@.value()@
    }
}

pub struct StableUserDomainState {
    region: ForeignRegionId,
    backing: TransactionalVec,
    cookie: DomainCookie,
}

pub struct StableUserSession<'a> {
    obj: &'a StableUserDomainState,
    perm: Tracked<PointsTo<Vec<u8>>>,
    handle: WriteHandle<'a, Tracked<PointsTo<Vec<u8>>>, TransactionalVecPred>,
}

pub struct StableUserDomain(());

impl StableUserDomainState {
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

impl<'a> StableUserSession<'a> {
    pub closed spec fn spec_obj(&self) -> StableUserDomainState {
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

impl DynState for StableUserDomainState {
    open spec fn wf(&self) -> bool {
        self.backing().wf()
    }

    open spec fn spec_tag(&self) -> int {
        type_tag::<StableUserDomainState>()
    }

    closed spec fn spec_cookie(&self) -> DomainCookie {
        self.cookie
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<StableUserDomainState>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.cookie
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

impl<'a> DomainSession for StableUserSession<'a> {
    type State = StableUserSessionView;

    open spec fn st(&self) -> StableUserSessionView {
        StableUserSessionView {
            region: self.spec_obj().region(),
            pptr: self.spec_obj().backing().pptr(),
            base: self.spec_obj().backing().base_addr(),
            len: self.spec_obj().backing().size(),
            lock: self.spec_handle_rwlock(),
            perm: self.spec_perm(),
        }
    }

    open spec fn wf(st: StableUserSessionView) -> bool {
        &&& st.lock.pred().pptr == st.pptr
        &&& st.lock.pred().base == st.base
        &&& st.lock.pred().len == st.len
        &&& st.base + st.len <= usize::MAX
        &&& st.lock.pred().inv(st.perm)
    }

    open spec fn interfere(pre: StableUserSessionView, post: StableUserSessionView) -> bool {
        post == pre
    }

    proof fn lemma_interfere_refl(_s: StableUserSessionView) {
    }

    proof fn lemma_interfere_trans(
        _a: StableUserSessionView,
        _b: StableUserSessionView,
        _c: StableUserSessionView,
    ) {
    }

    proof fn lemma_interfere_wf(_pre: StableUserSessionView, _post: StableUserSessionView) {
    }

    open spec fn address_extent(
        st: StableUserSessionView,
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
        _pre: StableUserSessionView,
        _post: StableUserSessionView,
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
        st: StableUserSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region == region && offset >= st.base && size <= st.len && offset - st.base <= st.len
            - size {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::Invalid
        }
    }

    fn check_load_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition) {
        if self.obj.region().raw == region.raw && offset >= self.obj.backing_ref().base_addr()
            && size <= self.obj.backing_ref().size() && offset - self.obj.backing_ref().base_addr()
            <= self.obj.backing_ref().size() - size {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::Invalid
        }
    }

    open spec fn load_post(
        pre: StableUserSessionView,
        post: StableUserSessionView,
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
        &&& observed == pre.bytes().subrange(offset - pre.base, offset - pre.base + size)
    }

    open spec fn store_disposition(
        st: StableUserSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region == region && offset >= st.base && size <= st.len && offset - st.base <= st.len
            - size {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::Invalid
        }
    }

    fn check_store_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition) {
        if self.obj.region().raw == region.raw && offset >= self.obj.backing_ref().base_addr()
            && size <= self.obj.backing_ref().size() && offset - self.obj.backing_ref().base_addr()
            <= self.obj.backing_ref().size() - size {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::Invalid
        }
    }

    open spec fn store_post(
        pre: StableUserSessionView,
        post: StableUserSessionView,
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
        &&& post.bytes().len() == pre.bytes().len()
        &&& pre.region == region
        &&& offset >= pre.base
        &&& size <= pre.len
        &&& offset - pre.base <= pre.len - size
        &&& written.len() == size
        &&& post.bytes() == pre.bytes().subrange(0, offset - pre.base).add(written).add(
            pre.bytes().subrange(offset - pre.base + size, pre.bytes().len() as int),
        )
    }

    proof fn lemma_load_post_wf(
        _pre: StableUserSessionView,
        _post: StableUserSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _observed: Seq<u8>,
    ) {
    }

    proof fn lemma_store_post_wf(
        _pre: StableUserSessionView,
        _post: StableUserSessionView,
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
                backing_offset + size <= mem.len(),
                out@ == mem@.subrange(backing_offset as int, backing_offset + i),
            decreases size - i,
        {
            out.push(mem[backing_offset + i]);
            proof {
                assert(out@ =~= mem@.subrange(backing_offset as int, backing_offset + i + 1));
            }
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
        let bytes = self.load_atomic(region, offset, size);
        (false, bytes)
    }

    fn store_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize, data: &[u8]) {
        proof {
            Self::lemma_interfere_refl(old(self).st());
        }
        let _ = region;
        let pptr = self.obj.backing_ref().pptr();
        let base = self.obj.backing_ref().base_addr();
        let ghost blen = self.obj.backing().spec_len();
        let ghost orig = old(self).st().bytes();
        let backing_offset = offset - base;
        let mem: &mut Vec<u8> = pptr.borrow_mut(Tracked(self.perm.borrow_mut()));

        let mut i: usize = 0;
        while i < size
            invariant
                i <= size,
                data@.len() == size,
                mem.len() == blen,
                mem@.len() == orig.len(),
                backing_offset + size <= blen,
                forall|j: int| #![trigger mem@[j]] 0 <= j < backing_offset ==> mem@[j] == orig[j],
                forall|j: int|
                    backing_offset <= j < backing_offset + i ==> mem@[j] == data@[j
                        - backing_offset],
                forall|j: int|
                    #![trigger mem@[j]]
                    backing_offset + i <= j < mem@.len() ==> mem@[j] == orig[j],
            decreases size - i,
        {
            mem.set(backing_offset + i, data[i]);
            i += 1;
        }
        assert(mem@ =~= orig.subrange(0, backing_offset as int).add(data@).add(
            orig.subrange(backing_offset + size, orig.len() as int),
        ));
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
        self.store_atomic(region, offset, size, data);
        false
    }

    fn close(self) {
        let perm = self.perm;
        let handle = self.handle;
        handle.release_write(perm);
    }
}

impl ForeignDomain for StableUserDomain {
    type Obj = StableUserDomainState;

    type Session<'a> = StableUserSession<'a>;

    fn open<'a>(obj: &'a StableUserDomainState) -> (s: StableUserSession<'a>) {
        let (perm, handle) = obj.backing_ref().acquire_write();
        StableUserSession { obj, perm, handle }
    }
}

impl StableUserDomain {
    pub fn open_strong<'a>(obj: &'a StableUserDomainState) -> (s: StableUserSession<'a>)
        requires
            obj.wf(),
        ensures
            <StableUserSession<'a> as DomainSession>::wf(s.st()),
            s.st().region == obj.region(),
            s.st().base == obj.backing().spec_base(),
            s.st().len == obj.backing().spec_len(),
    {
        let (perm, handle) = obj.backing_ref().acquire_write();
        StableUserSession { obj, perm, handle }
    }
}

impl StableUserDomainState {
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
        StableUserDomainState { region, backing: TransactionalVec::zeroed(base, len), cookie }
    }

    pub fn from_backing(
        region: ForeignRegionId,
        base: usize,
        backing: Vec<u8>,
        cookie: DomainCookie,
    ) -> (obj: Self)
        requires
            base as nat + backing@.len() <= usize::MAX as nat,
        ensures
            obj.wf(),
            obj.region() == region,
            obj.backing().spec_base() == base,
            obj.backing().spec_len() == backing@.len(),
            obj.spec_cookie() == cookie,
    {
        StableUserDomainState {
            region,
            backing: TransactionalVec::from_backing(base, backing),
            cookie,
        }
    }
}

pub fn drive_stable_user_session(obj: &StableUserDomainState)
    requires
        obj.wf(),
        obj.backing().spec_len() >= 4,
{
    let mut sess = StableUserDomain::open_strong(obj);
    let ghost s0 = sess.st();
    let ghost pre_bytes = s0.bytes();
    let base = obj.backing_ref().base_addr();
    let region = obj.region();

    assert(pre_bytes.len() == obj.backing().spec_len());

    assert forall|env: StableUserSessionView| #[trigger]
        StableUserSession::interfere(s0, env) implies {
        &&& StableUserSession::load_disposition(env, region, base, 1).permits_success()
        &&& StableUserSession::load_disposition(env, region, base, 2).permits_success()
        &&& StableUserSession::store_disposition(env, region, base, 2).permits_success()
    } by {}

    let _b1 = sess.load_atomic(region, base, 1);
    let ghost s1 = sess.st();
    let ghost e1 = choose|env: StableUserSessionView|
        #![trigger StableUserSession::interfere(s0, env)]
        StableUserSession::interfere(s0, env) && StableUserSession::load_post(
            env,
            s1,
            region,
            base,
            1,
            _b1@,
        );

    assert(_b1@ == pre_bytes.subrange(0, 1));
    assert(s1 == s0);

    let data: Vec<u8> = vec![7u8, 9u8];
    assert forall|env: StableUserSessionView| #[trigger]
        StableUserSession::interfere(s1, env) implies StableUserSession::store_disposition(
        env,
        region,
        base,
        2,
    ).permits_success() by {
        StableUserSession::lemma_interfere_trans(s0, s1, env);
    }
    sess.store_atomic(region, base, 2, data.as_slice());
    let ghost s2 = sess.st();
    let ghost e2 = choose|env: StableUserSessionView|
        #![trigger StableUserSession::interfere(s1, env)]
        StableUserSession::interfere(s1, env) && StableUserSession::store_post(
            env,
            s2,
            region,
            base,
            2,
            data@,
        );
    assert(e2 == s0);
    assert(s2.region == region);
    assert(s2.base == base);
    assert(s2.len == s0.len);

    assert(s2.bytes() == pre_bytes.subrange(0, 0).add(data@).add(
        pre_bytes.subrange(2, pre_bytes.len() as int),
    ));
    assert(s2.bytes().len() == pre_bytes.len());

    assert forall|env: StableUserSessionView| #[trigger]
        StableUserSession::interfere(s2, env) implies StableUserSession::load_disposition(
        env,
        region,
        base,
        2,
    ).permits_success() by {}
    let _b2 = sess.load_atomic(region, base, 2);
    let ghost s3 = sess.st();
    let ghost e3 = choose|env: StableUserSessionView|
        #![trigger StableUserSession::interfere(s2, env)]
        StableUserSession::interfere(s2, env) && StableUserSession::load_post(
            env,
            s3,
            region,
            base,
            2,
            _b2@,
        );

    assert(_b2@ =~= data@);
    assert(_b2@ == data@);

    assert(s3.region == obj.region());
    assert(s3.base == obj.backing().spec_base());
    assert(s3.len == obj.backing().spec_len());
    assert(s3.bytes().len() == obj.backing().spec_len());

    sess.close();
}

} // verus!

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::erasure::DynState;
use crate::fmem::extent::{AddressExtent, WrongRegion};
use crate::fmem::ids::{DomainCookie, ForeignRegionId};
use crate::fmem::session::{AccessDisposition, DomainSession, ForeignDomain};
use crate::helpers::rust_any::{RuntimeAnyRef, RuntimeTypeTag};

#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
use vstd::prelude::*;

verus! {

#[derive(Copy, Clone)]
pub struct FallibleCopySessionView {
    #[allow(dead_code)]
    pub region: ForeignRegionId,
    #[allow(dead_code)]
    pub len: usize,
    #[allow(dead_code)]
    pub fault_at: usize,
}

pub struct FallibleCopyDomainState {
    pub region: ForeignRegionId,
    #[allow(dead_code)]
    pub len: usize,
    pub fault_at: usize,
    pub cookie: DomainCookie,
}

pub struct FallibleCopySession<'a> {
    pub obj: &'a FallibleCopyDomainState,
}

pub struct FallibleCopyDomain(());

impl DynState for FallibleCopyDomainState {
    open spec fn wf(&self) -> bool {
        self.fault_at <= self.len
    }

    open spec fn spec_tag(&self) -> int {
        type_tag::<FallibleCopyDomainState>()
    }

    open spec fn spec_cookie(&self) -> DomainCookie {
        self.cookie
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<FallibleCopyDomainState>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.cookie
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

impl<'a> DomainSession for FallibleCopySession<'a> {
    type State = FallibleCopySessionView;

    open spec fn st(&self) -> FallibleCopySessionView {
        FallibleCopySessionView {
            region: self.obj.region,
            len: self.obj.len,
            fault_at: self.obj.fault_at,
        }
    }

    open spec fn wf(st: FallibleCopySessionView) -> bool {
        st.fault_at <= st.len
    }

    open spec fn interfere(pre: FallibleCopySessionView, post: FallibleCopySessionView) -> bool {
        post == pre
    }

    proof fn lemma_interfere_refl(_s: FallibleCopySessionView) {
    }

    proof fn lemma_interfere_trans(
        _a: FallibleCopySessionView,
        _b: FallibleCopySessionView,
        _c: FallibleCopySessionView,
    ) {
    }

    proof fn lemma_interfere_wf(_pre: FallibleCopySessionView, _post: FallibleCopySessionView) {
    }

    open spec fn address_extent(
        st: FallibleCopySessionView,
        region: ForeignRegionId,
        index: usize,
    ) -> Option<AddressExtent> {
        if st.region == region {
            Some(AddressExtent { start: 0, end: st.len, index })
        } else {
            None
        }
    }

    proof fn lemma_address_extent_interfere(
        _pre: FallibleCopySessionView,
        _post: FallibleCopySessionView,
        _region: ForeignRegionId,
        _index: usize,
    ) {
    }

    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >) {
        if self.obj.region.raw == region.raw {
            Ok(AddressExtent { start: 0, end: self.obj.len, index })
        } else {
            Err(WrongRegion)
        }
    }

    open spec fn load_disposition(
        st: FallibleCopySessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region != region || size != 1 || offset >= st.len {
            AccessDisposition::Invalid
        } else if offset < st.fault_at {
            AccessDisposition::Infallible
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
        if self.obj.region.raw != region.raw || size != 1 || offset >= self.obj.len {
            AccessDisposition::Invalid
        } else if offset < self.obj.fault_at {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::AlwaysFaults
        }
    }

    open spec fn load_post(
        pre: FallibleCopySessionView,
        post: FallibleCopySessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool {
        &&& post == pre
        &&& Self::load_disposition(pre, region, offset, size).permits_success()
        &&& observed == seq![0u8]
    }

    open spec fn store_disposition(
        _st: FallibleCopySessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> AccessDisposition {
        AccessDisposition::Invalid
    }

    open spec fn store_post(
        _pre: FallibleCopySessionView,
        _post: FallibleCopySessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _written: Seq<u8>,
    ) -> bool {
        false
    }

    proof fn lemma_load_post_wf(
        _pre: FallibleCopySessionView,
        _post: FallibleCopySessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _observed: Seq<u8>,
    ) {
    }

    proof fn lemma_store_post_wf(
        _pre: FallibleCopySessionView,
        _post: FallibleCopySessionView,
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
        let _ = (region, offset, size);
        let mut out: Vec<u8> = Vec::new();
        out.push(0);
        assert(out@ =~= seq![0u8]);
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
        let fault_at = self.obj.fault_at;
        if offset < fault_at {
            assert forall|env: FallibleCopySessionView| #[trigger]
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
        let _ = (region, offset, size, data);
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
        let _ = (region, offset, size, data);
        true
    }

    fn close(self) {
    }
}

impl ForeignDomain for FallibleCopyDomain {
    type Obj = FallibleCopyDomainState;

    type Session<'a> = FallibleCopySession<'a>;

    fn open<'a>(obj: &'a FallibleCopyDomainState) -> (s: FallibleCopySession<'a>) {
        FallibleCopySession { obj }
    }
}

impl FallibleCopyDomain {
    pub fn open_strong<'a>(obj: &'a FallibleCopyDomainState) -> (s: FallibleCopySession<'a>)
        requires
            obj.wf(),
        ensures
            s.st() == (FallibleCopySessionView {
                region: obj.region,
                len: obj.len,
                fault_at: obj.fault_at,
            }),
            <FallibleCopySession<'a> as DomainSession>::wf(s.st()),
    {
        FallibleCopySession { obj }
    }
}

impl FallibleCopyDomainState {
    pub fn new(region: ForeignRegionId, len: usize, fault_at: usize, cookie: DomainCookie) -> (obj:
        Self)
        requires
            fault_at <= len,
        ensures
            obj.region == region,
            obj.len == len,
            obj.fault_at == fault_at,
            obj.spec_cookie() == cookie,
            obj.wf(),
    {
        FallibleCopyDomainState { region, len, fault_at, cookie }
    }
}

pub fn drive_fallible_copy_session(obj: &FallibleCopyDomainState)
    requires
        obj.wf(),
        obj.len >= 4,
        obj.fault_at == 2,
{
    let mut sess = FallibleCopyDomain::open_strong(obj);
    let ghost s0 = sess.st();
    let region = obj.region;

    assert forall|env: FallibleCopySessionView| #[trigger]
        FallibleCopySession::interfere(s0, env) implies {
        &&& FallibleCopySession::load_disposition(env, region, 0, 1).permits_success()
        &&& !FallibleCopySession::load_disposition(env, region, 0, 1).permits_fault()
    } by {}
    let (_f1, _b1) = sess.try_load_atomic(region, 0, 1);
    let ghost s1 = sess.st();
    proof {
        if !_f1 {
            let e1 = choose|env: FallibleCopySessionView|
                #![trigger FallibleCopySession::interfere(s0, env)]
                FallibleCopySession::interfere(s0, env) && FallibleCopySession::load_post(
                    env,
                    s1,
                    region,
                    0,
                    1,
                    _b1@,
                );
        }
    }

    assert(!_f1);
    assert(_b1@ == seq![0u8]);
    assert(s1 == s0);

    assert forall|env: FallibleCopySessionView| #[trigger]
        FallibleCopySession::interfere(s1, env) implies {
        &&& FallibleCopySession::load_disposition(env, region, 3, 1).permits_fault()
        &&& !FallibleCopySession::load_disposition(env, region, 3, 1).permits_success()
    } by {
        FallibleCopySession::lemma_interfere_trans(s0, s1, env);
    }
    let (_f2, _b2) = sess.try_load_atomic(region, 3, 1);
    let ghost s2 = sess.st();
    proof {
        if !_f2 {
            let e2 = choose|env: FallibleCopySessionView|
                #![trigger FallibleCopySession::interfere(s1, env)]
                FallibleCopySession::interfere(s1, env) && FallibleCopySession::load_post(
                    env,
                    s2,
                    region,
                    3,
                    1,
                    _b2@,
                );
        }
        FallibleCopySession::lemma_interfere_trans(s0, s1, s2);
    }

    assert(_f2);
    assert(FallibleCopySession::load_disposition(s2, region, 3, 1).permits_fault());

    assert(s2 == s0);
    assert(s2.region == obj.region);
    assert(s2.len == obj.len);
    assert(s2.fault_at == obj.fault_at);

    sess.close();
}

} // verus!
#[test]
fn fallible_copy_session_drives() {
    let region = ForeignRegionId { raw: 0 };
    let cookie = DomainCookie { raw: 1 };
    let obj = FallibleCopyDomainState::new(region, 4, 2, cookie);

    drive_fallible_copy_session(&obj);
}

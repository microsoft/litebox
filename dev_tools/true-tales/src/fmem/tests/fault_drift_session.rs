// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::erasure::DynState;
use crate::fmem::extent::{AddressExtent, WrongRegion};
use crate::fmem::ids::{DomainCookie, ForeignRegionId};
use crate::fmem::session::AccessDisposition;
use crate::fmem::session::{DomainSession, ForeignDomain};
use crate::helpers::rust_any::{RuntimeAnyRef, RuntimeTypeTag};

#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
use vstd::prelude::*;

verus! {

#[derive(Copy, Clone)]
pub struct RegionOnlySessionView {
    #[allow(dead_code)]
    pub region: ForeignRegionId,
}

pub struct RegionOnlyDomainState {
    pub region: ForeignRegionId,
    pub cookie: DomainCookie,
}

pub struct RegionOnlySession<'a> {
    #[allow(dead_code)]
    pub obj: &'a RegionOnlyDomainState,
}

pub struct RegionOnlyDomain(());

impl DynState for RegionOnlyDomainState {
    open spec fn wf(&self) -> bool {
        true
    }

    open spec fn spec_tag(&self) -> int {
        type_tag::<RegionOnlyDomainState>()
    }

    open spec fn spec_cookie(&self) -> DomainCookie {
        self.cookie
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<RegionOnlyDomainState>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.cookie
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

impl<'a> DomainSession for RegionOnlySession<'a> {
    type State = RegionOnlySessionView;

    open spec fn st(&self) -> RegionOnlySessionView {
        RegionOnlySessionView { region: self.obj.region }
    }

    open spec fn wf(_st: RegionOnlySessionView) -> bool {
        true
    }

    open spec fn interfere(pre: RegionOnlySessionView, post: RegionOnlySessionView) -> bool {
        post.region == pre.region
    }

    proof fn lemma_interfere_refl(_s: RegionOnlySessionView) {
    }

    proof fn lemma_interfere_trans(
        _a: RegionOnlySessionView,
        _b: RegionOnlySessionView,
        _c: RegionOnlySessionView,
    ) {
    }

    proof fn lemma_interfere_wf(_pre: RegionOnlySessionView, _post: RegionOnlySessionView) {
    }

    open spec fn address_extent(
        st: RegionOnlySessionView,
        region: ForeignRegionId,
        index: usize,
    ) -> Option<AddressExtent> {
        if st.region == region {
            Some(AddressExtent { start: 0, end: usize::MAX, index })
        } else {
            None
        }
    }

    proof fn lemma_address_extent_interfere(
        _pre: RegionOnlySessionView,
        _post: RegionOnlySessionView,
        _region: ForeignRegionId,
        _index: usize,
    ) {
    }

    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >) {
        if self.obj.region.raw == region.raw {
            Ok(AddressExtent { start: 0, end: usize::MAX, index })
        } else {
            Err(WrongRegion)
        }
    }

    open spec fn load_disposition(
        st: RegionOnlySessionView,
        region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> AccessDisposition {
        if st.region == region {
            AccessDisposition::AlwaysFaults
        } else {
            AccessDisposition::Invalid
        }
    }

    open spec fn load_post(
        pre: RegionOnlySessionView,
        post: RegionOnlySessionView,
        region: ForeignRegionId,
        _offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool {
        &&& post.region == pre.region
        &&& pre.region == region
        &&& observed.len() == size
    }

    open spec fn store_disposition(
        st: RegionOnlySessionView,
        region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> AccessDisposition {
        if st.region == region {
            AccessDisposition::AlwaysFaults
        } else {
            AccessDisposition::Invalid
        }
    }

    fn check_store_disposition(
        &self,
        region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> (disposition: AccessDisposition) {
        if self.obj.region.raw == region.raw {
            AccessDisposition::AlwaysFaults
        } else {
            AccessDisposition::Invalid
        }
    }

    open spec fn store_post(
        pre: RegionOnlySessionView,
        post: RegionOnlySessionView,
        region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _written: Seq<u8>,
    ) -> bool {
        &&& post.region == pre.region
        &&& pre.region == region
    }

    proof fn lemma_load_post_wf(
        _pre: RegionOnlySessionView,
        _post: RegionOnlySessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _observed: Seq<u8>,
    ) {
    }

    proof fn lemma_store_post_wf(
        _pre: RegionOnlySessionView,
        _post: RegionOnlySessionView,
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
        let _ = (region, offset);
        let mut out: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < size
            invariant
                i <= size,
                out@.len() == i,
            decreases size - i,
        {
            out.push(0);
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
        let _ = (region, offset, size);
        (true, Vec::new())
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

impl ForeignDomain for RegionOnlyDomain {
    type Obj = RegionOnlyDomainState;

    type Session<'a> = RegionOnlySession<'a>;

    fn open<'a>(obj: &'a RegionOnlyDomainState) -> (s: RegionOnlySession<'a>) {
        RegionOnlySession { obj }
    }
}

impl RegionOnlyDomain {
    pub fn open_strong<'a>(obj: &'a RegionOnlyDomainState) -> (s: RegionOnlySession<'a>)
        requires
            obj.wf(),
        ensures
            s.st() == (RegionOnlySessionView { region: obj.region }),
            <RegionOnlySession<'a> as DomainSession>::wf(s.st()),
    {
        RegionOnlySession { obj }
    }
}

impl RegionOnlyDomainState {
    pub fn new(region: ForeignRegionId, cookie: DomainCookie) -> (obj: Self)
        ensures
            obj.region == region,
            obj.spec_cookie() == cookie,
            obj.wf(),
    {
        RegionOnlyDomainState { region, cookie }
    }
}

pub fn drive_region_only_session(obj: &RegionOnlyDomainState)
    requires
        obj.wf(),
{
    let mut sess = RegionOnlyDomain::open_strong(obj);
    let ghost s0 = sess.st();
    let region = obj.region;

    assert forall|env: RegionOnlySessionView| #[trigger]
        RegionOnlySession::interfere(s0, env) implies {
        &&& RegionOnlySession::load_disposition(env, region, 0, 1).permits_fault()
        &&& RegionOnlySession::store_disposition(env, region, 0, 1).permits_fault()
    } by {}

    let (_f1, _b1) = sess.try_load_atomic(region, 0, 1);
    let ghost s1 = sess.st();
    proof {
        if !_f1 {
            let e1 = choose|env: RegionOnlySessionView|
                #![trigger RegionOnlySession::interfere(s0, env)]
                RegionOnlySession::interfere(s0, env) && RegionOnlySession::load_post(
                    env,
                    s1,
                    region,
                    0,
                    1,
                    _b1@,
                );
        }
    }

    assert(RegionOnlySession::interfere(s0, s1));
    assert(RegionOnlySession::load_disposition(s1, region, 0, 1).permits_fault());

    let data: Vec<u8> = vec![7u8];
    assert forall|env: RegionOnlySessionView| #[trigger]
        RegionOnlySession::interfere(s1, env) implies RegionOnlySession::store_disposition(
        env,
        region,
        0,
        1,
    ).permits_fault() by {
        RegionOnlySession::lemma_interfere_trans(s0, s1, env);
    }
    let _f2 = sess.try_store_atomic(region, 0, 1, data.as_slice());
    let ghost s2 = sess.st();
    proof {
        if !_f2 {
            let e2 = choose|env: RegionOnlySessionView|
                #![trigger RegionOnlySession::interfere(s1, env)]
                RegionOnlySession::interfere(s1, env) && RegionOnlySession::store_post(
                    env,
                    s2,
                    region,
                    0,
                    1,
                    data@,
                );
        }
        RegionOnlySession::lemma_interfere_trans(s0, s1, s2);
    }

    assert(s2.region == obj.region);
    assert(RegionOnlySession::load_disposition(s2, region, 0, 1).permits_fault());
    assert(RegionOnlySession::store_disposition(s2, region, 0, 1).permits_fault());

    sess.close();
}

pub open spec fn session_atomic_load_post(
    pre: RegionOnlySessionView,
    post: RegionOnlySessionView,
    region: ForeignRegionId,
    offset: usize,
    size: usize,
    observed: Seq<u8>,
) -> bool {
    exists|env: RegionOnlySessionView|
        #![trigger RegionOnlySession::interfere(pre, env)]
        RegionOnlySession::interfere(pre, env) && RegionOnlySession::load_post(
            env,
            post,
            region,
            offset,
            size,
            observed,
        )
}

pub open spec fn session_atomic_store_post(
    pre: RegionOnlySessionView,
    post: RegionOnlySessionView,
    region: ForeignRegionId,
    offset: usize,
    size: usize,
    written: Seq<u8>,
) -> bool {
    exists|env: RegionOnlySessionView|
        #![trigger RegionOnlySession::interfere(pre, env)]
        RegionOnlySession::interfere(pre, env) && RegionOnlySession::store_post(
            env,
            post,
            region,
            offset,
            size,
            written,
        )
}

proof fn lemma_drift_hypotheses_are_satisfiable(
    region: ForeignRegionId,
    offset: usize,
    size: usize,
    bytes: Seq<u8>,
)
    requires
        bytes.len() == size,
    ensures
        session_atomic_load_post(
            RegionOnlySessionView { region },
            RegionOnlySessionView { region },
            region,
            offset,
            size,
            bytes,
        ),
        session_atomic_store_post(
            RegionOnlySessionView { region },
            RegionOnlySessionView { region },
            region,
            offset,
            size,
            bytes,
        ),
{
    let s = RegionOnlySessionView { region };
    assert(RegionOnlySession::interfere(s, s) && RegionOnlySession::load_post(
        s,
        s,
        region,
        offset,
        size,
        bytes,
    ));
    assert(RegionOnlySession::interfere(s, s) && RegionOnlySession::store_post(
        s,
        s,
        region,
        offset,
        size,
        bytes,
    ));
}

proof fn fault_witness_survives_load(
    pre: RegionOnlySessionView,
    post: RegionOnlySessionView,
    region: ForeignRegionId,
    offset: usize,
    size: usize,
    observed: Seq<u8>,
)
    requires
        session_atomic_load_post(pre, post, region, offset, size, observed),
    ensures
        RegionOnlySession::load_disposition(post, region, offset, size).permits_fault()
            == RegionOnlySession::load_disposition(pre, region, offset, size).permits_fault(),
{
}

proof fn store_fault_witness_survives_load(
    pre: RegionOnlySessionView,
    post: RegionOnlySessionView,
    region: ForeignRegionId,
    offset: usize,
    size: usize,
    observed: Seq<u8>,
)
    requires
        session_atomic_load_post(pre, post, region, offset, size, observed),
    ensures
        RegionOnlySession::store_disposition(post, region, offset, size)
            == RegionOnlySession::store_disposition(pre, region, offset, size),
{
}

proof fn load_fault_witness_survives_store(
    pre: RegionOnlySessionView,
    post: RegionOnlySessionView,
    region: ForeignRegionId,
    offset: usize,
    size: usize,
    written: Seq<u8>,
)
    requires
        session_atomic_store_post(pre, post, region, offset, size, written),
    ensures
        RegionOnlySession::load_disposition(post, region, offset, size).permits_fault()
            == RegionOnlySession::load_disposition(pre, region, offset, size).permits_fault(),
{
}

proof fn store_fault_witness_survives_store(
    pre: RegionOnlySessionView,
    post: RegionOnlySessionView,
    region: ForeignRegionId,
    offset: usize,
    size: usize,
    written: Seq<u8>,
)
    requires
        session_atomic_store_post(pre, post, region, offset, size, written),
    ensures
        RegionOnlySession::store_disposition(post, region, offset, size)
            == RegionOnlySession::store_disposition(pre, region, offset, size),
{
}

} // verus!
#[test]
fn region_only_session_drives() {
    let region = ForeignRegionId { raw: 0 };
    let cookie = DomainCookie { raw: 1 };
    let obj = RegionOnlyDomainState::new(region, cookie);

    drive_region_only_session(&obj);
}

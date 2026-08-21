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
use vstd::rwlock::{RwLock, RwLockPredicate, WriteHandle};

verus! {

#[derive(Copy, Clone)]
pub struct OnlyOnceCellState {
    #[allow(dead_code)]
    pub region: ForeignRegionId,
    pub byte: u8,
    pub loadable: bool,
}

pub ghost struct OnlyOnceCellStatePred {
    #[allow(dead_code)]
    pub region: ForeignRegionId,
}

impl RwLockPredicate<OnlyOnceCellState> for OnlyOnceCellStatePred {
    open spec fn inv(self, v: OnlyOnceCellState) -> bool {
        v.region == self.region
    }
}

pub ghost struct OnlyOnceSessionView {
    #[allow(dead_code)]
    pub region: ForeignRegionId,
    #[allow(dead_code)]
    pub byte: u8,
    #[allow(dead_code)]
    pub loadable: bool,
    #[allow(dead_code)]
    pub lock: RwLock<OnlyOnceCellState, OnlyOnceCellStatePred>,
}

impl OnlyOnceSessionView {
    pub open spec fn inner(self) -> OnlyOnceCellState {
        OnlyOnceCellState { region: self.region, byte: self.byte, loadable: self.loadable }
    }
}

pub struct OnlyOnceDomainState {
    pub region: ForeignRegionId,
    pub lock: RwLock<OnlyOnceCellState, OnlyOnceCellStatePred>,
    pub cookie: DomainCookie,
}

pub struct OnlyOnceSession<'a> {
    #[allow(dead_code)]
    pub obj: &'a OnlyOnceDomainState,
    pub val: OnlyOnceCellState,
    pub handle: WriteHandle<'a, OnlyOnceCellState, OnlyOnceCellStatePred>,
}

pub struct OnlyOnceDomain(());

impl DynState for OnlyOnceDomainState {
    open spec fn wf(&self) -> bool {
        self.lock.pred() == (OnlyOnceCellStatePred { region: self.region })
    }

    open spec fn spec_tag(&self) -> int {
        type_tag::<OnlyOnceDomainState>()
    }

    open spec fn spec_cookie(&self) -> DomainCookie {
        self.cookie
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<OnlyOnceDomainState>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.cookie
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

impl<'a> DomainSession for OnlyOnceSession<'a> {
    type State = OnlyOnceSessionView;

    open spec fn st(&self) -> OnlyOnceSessionView {
        OnlyOnceSessionView {
            region: self.val.region,
            byte: self.val.byte,
            loadable: self.val.loadable,
            lock: self.handle.rwlock(),
        }
    }

    open spec fn wf(st: OnlyOnceSessionView) -> bool {
        st.lock.pred().inv(st.inner())
    }

    open spec fn interfere(pre: OnlyOnceSessionView, post: OnlyOnceSessionView) -> bool {
        post == pre
    }

    proof fn lemma_interfere_refl(_s: OnlyOnceSessionView) {
    }

    proof fn lemma_interfere_trans(
        _a: OnlyOnceSessionView,
        _b: OnlyOnceSessionView,
        _c: OnlyOnceSessionView,
    ) {
    }

    proof fn lemma_interfere_wf(_pre: OnlyOnceSessionView, _post: OnlyOnceSessionView) {
    }

    open spec fn address_extent(
        st: OnlyOnceSessionView,
        region: ForeignRegionId,
        index: usize,
    ) -> Option<AddressExtent> {
        if st.region == region {
            Some(AddressExtent { start: 0, end: 1, index })
        } else {
            None
        }
    }

    proof fn lemma_address_extent_interfere(
        _pre: OnlyOnceSessionView,
        _post: OnlyOnceSessionView,
        _region: ForeignRegionId,
        _index: usize,
    ) {
    }

    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >) {
        if self.val.region.raw == region.raw {
            Ok(AddressExtent { start: 0, end: 1, index })
        } else {
            Err(WrongRegion)
        }
    }

    open spec fn load_disposition(
        st: OnlyOnceSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region != region || offset != 0 || size != 1 {
            AccessDisposition::Invalid
        } else if st.loadable {
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
    ) -> (disposition: AccessDisposition)
        ensures
            disposition == Self::load_disposition(self.st(), region, offset, size),
    {
        if self.val.region.raw != region.raw || offset != 0 || size != 1 {
            AccessDisposition::Invalid
        } else if self.val.loadable {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::AlwaysFaults
        }
    }

    open spec fn load_post(
        pre: OnlyOnceSessionView,
        post: OnlyOnceSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool {
        &&& Self::load_disposition(pre, region, offset, size).permits_success()
        &&& post.region == pre.region
        &&& post.byte == pre.byte
        &&& post.loadable == false
        &&& post.lock == pre.lock
        &&& observed == seq![pre.byte]
    }

    open spec fn store_disposition(
        _st: OnlyOnceSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> AccessDisposition {
        AccessDisposition::Invalid
    }

    fn check_store_disposition(
        &self,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> (disposition: AccessDisposition)
        ensures
            disposition == Self::store_disposition(self.st(), _region, _offset, _size),
    {
        AccessDisposition::Invalid
    }

    open spec fn store_post(
        _pre: OnlyOnceSessionView,
        _post: OnlyOnceSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _written: Seq<u8>,
    ) -> bool {
        false
    }

    proof fn lemma_load_post_wf(
        _pre: OnlyOnceSessionView,
        _post: OnlyOnceSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _observed: Seq<u8>,
    ) {
    }

    proof fn lemma_store_post_wf(
        _pre: OnlyOnceSessionView,
        _post: OnlyOnceSessionView,
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
        out.push(self.val.byte);

        self.val.loadable = false;
        assert(out@ =~= seq![old(self).st().byte]);
        out
    }

    fn try_load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (res: (
        bool,
        Vec<u8>,
    )) {
        let ghost pre = old(self).st();
        proof {
            Self::lemma_interfere_refl(pre);
        }
        if self.val.loadable {
            assert forall|env: OnlyOnceSessionView| #[trigger]
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
            proof {
                assert(Self::interfere(pre, pre));
                assert(Self::load_disposition(pre, region, offset, size).permits_fault());
            }
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
        let val = self.val;
        let handle = self.handle;
        handle.release_write(val);
    }
}

impl<'a> OnlyOnceSession<'a> {
    pub fn is_loadable(&self) -> (b: bool)
        ensures
            b == self.st().loadable,
    {
        self.val.loadable
    }
}

impl ForeignDomain for OnlyOnceDomain {
    type Obj = OnlyOnceDomainState;

    type Session<'a> = OnlyOnceSession<'a>;

    fn open<'a>(obj: &'a OnlyOnceDomainState) -> (s: OnlyOnceSession<'a>) {
        let (val, handle) = obj.lock.acquire_write();
        OnlyOnceSession { obj, val, handle }
    }
}

impl OnlyOnceDomain {
    pub fn open_strong<'a>(obj: &'a OnlyOnceDomainState) -> (s: OnlyOnceSession<'a>)
        requires
            obj.wf(),
        ensures
            <OnlyOnceSession<'a> as DomainSession>::wf(s.st()),
            s.st().region == obj.region,
            s.st().lock == obj.lock,
    {
        let (val, handle) = obj.lock.acquire_write();
        OnlyOnceSession { obj, val, handle }
    }
}

impl OnlyOnceDomainState {
    pub fn new(region: ForeignRegionId, byte: u8, cookie: DomainCookie) -> (obj: Self)
        ensures
            obj.wf(),
            obj.region == region,
            obj.spec_cookie() == cookie,
    {
        let ghost pred = OnlyOnceCellStatePred { region };
        let lock = RwLock::new(OnlyOnceCellState { region, byte, loadable: true }, Ghost(pred));
        OnlyOnceDomainState { region, lock, cookie }
    }
}

pub fn drive_only_once_session(obj: &OnlyOnceDomainState)
    requires
        obj.wf(),
{
    let mut sess = OnlyOnceDomain::open_strong(obj);
    let ghost s0 = sess.st();
    let region = obj.region;
    assert(s0.region == region);

    if sess.is_loadable() {
        let _wrong_region = if region.raw == 0 {
            ForeignRegionId { raw: 1 }
        } else {
            ForeignRegionId { raw: 0 }
        };
        let _wrong_disposition = sess.check_load_disposition(_wrong_region, 0, 1);
        assert(_wrong_disposition.is_invalid());
        let _unsupported_disposition = sess.check_load_disposition(region, 0, 0);
        assert(_unsupported_disposition.is_invalid());
        let _store_disposition = sess.check_store_disposition(region, 0, 1);
        assert(_store_disposition.is_invalid());
        let _initial_disposition = sess.check_load_disposition(region, 0, 1);
        assert(_initial_disposition.is_infallible());

        assert forall|env: OnlyOnceSessionView| #[trigger]
            OnlyOnceSession::interfere(s0, env) implies OnlyOnceSession::load_disposition(
            env,
            region,
            0,
            1,
        ).permits_success() by {}

        let _b = sess.load_atomic(region, 0, 1);
        let ghost s1 = sess.st();
        let ghost e1 = choose|env: OnlyOnceSessionView|
            #![trigger OnlyOnceSession::interfere(s0, env)]
            OnlyOnceSession::interfere(s0, env) && OnlyOnceSession::load_post(
                env,
                s1,
                region,
                0,
                1,
                _b@,
            );

        assert(_b@ == seq![s0.byte]);
        assert(s1.byte == s0.byte);
        assert(s1.region == s0.region);

        assert(s1.loadable == false);
        assert(!OnlyOnceSession::load_disposition(sess.st(), region, 0, 1).permits_success());
        let _consumed_disposition = sess.check_load_disposition(region, 0, 1);
        assert(_consumed_disposition.is_always_faulting());
        let (_faulted, _bytes) = sess.try_load_atomic(region, 0, 1);
        assert(_faulted);

        assert forall|env: OnlyOnceSessionView, offset: usize, size: usize|
            #![trigger OnlyOnceSession::load_disposition(env, region, offset, size)]
            OnlyOnceSession::interfere(s1, env) implies !OnlyOnceSession::load_disposition(
            env,
            region,
            offset,
            size,
        ).permits_success() by {}

        let _again = sess.is_loadable();
        assert(!_again);

        assert(s1.lock == s0.lock);
        assert(s1.lock == obj.lock);
    }
    sess.close();
}

pub open spec fn only_once_consumed(pre: OnlyOnceSessionView) -> OnlyOnceSessionView {
    OnlyOnceSessionView { region: pre.region, byte: pre.byte, loadable: false, lock: pre.lock }
}

fn only_once_load<'a>(
    sess: &mut OnlyOnceSession<'a>,
    region: ForeignRegionId,
    offset: usize,
    size: usize,
) -> (byte: u8)
    requires
        <OnlyOnceSession<'a> as DomainSession>::wf(old(sess).st()),
        forall|env: OnlyOnceSessionView| #[trigger]
            OnlyOnceSession::interfere(old(sess).st(), env) ==> OnlyOnceSession::load_disposition(
                env,
                region,
                offset,
                size,
            ).permits_success(),
    ensures
        !OnlyOnceSession::load_disposition(
            final(sess).st(),
            region,
            offset,
            size,
        ).permits_success(),
        final(sess).st() == only_once_consumed(old(sess).st()),
        byte == old(sess).st().byte,
{
    let bytes = sess.load_atomic(region, offset, size);
    bytes[0]
}

pub fn drive_only_once_load(obj: &OnlyOnceDomainState)
    requires
        obj.wf(),
{
    let mut sess = OnlyOnceDomain::open_strong(obj);
    let region = obj.region;
    if sess.is_loadable() {
        let ghost s0 = sess.st();

        assert forall|env: OnlyOnceSessionView| #[trigger]
            OnlyOnceSession::interfere(s0, env) implies OnlyOnceSession::load_disposition(
            env,
            region,
            0,
            1,
        ).permits_success() by {}

        let _b = only_once_load(&mut sess, region, 0, 1);

        assert(_b == s0.byte);
        assert forall|env: OnlyOnceSessionView| #[trigger]
            OnlyOnceSession::interfere(sess.st(), env) implies !OnlyOnceSession::load_disposition(
            env,
            region,
            0,
            1,
        ).permits_success() by {}
        let _again = sess.is_loadable();
        assert(!_again);
        assert(sess.st().lock == obj.lock);
    }
    sess.close();
}

} // verus!
#[test]
fn only_once_session_drives() {
    let region = ForeignRegionId { raw: 0 };
    let cookie = DomainCookie { raw: 1 };
    let obj = OnlyOnceDomainState::new(region, 0x42, cookie);

    drive_only_once_session(&obj);
}

#[test]
fn only_once_load_runs() {
    let region = ForeignRegionId { raw: 0 };
    let cookie = DomainCookie { raw: 1 };
    let obj = OnlyOnceDomainState::new(region, 0x42, cookie);
    drive_only_once_load(&obj);
}

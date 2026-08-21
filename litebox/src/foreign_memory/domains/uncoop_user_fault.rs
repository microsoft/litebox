// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![allow(clippy::elidable_lifetime_names)]

use alloc::sync::Arc;
use alloc::vec::Vec;

use vstd::prelude::*;

use true_tales::fmem::backing::TransactionalVec;
use true_tales::fmem::erasure::DynState;
use true_tales::fmem::extent::{AddressExtent, WrongRegion};
use true_tales::fmem::ids::{DomainCookie, ForeignRegionId};
use true_tales::fmem::session::{AccessDisposition, DomainSession, ForeignDomain};
#[cfg(verus_only)]
use true_tales::helpers::rust_any::type_tag;
use true_tales::helpers::rust_any::{RuntimeAnyRef, RuntimeTypeTag};

use super::{
    DomainRegistration, ExportedPointer, ForeignMemoryRuntime, RetireError, RetiredDomain,
    fresh_cookie,
};

verus! {

// In our model, a process has exactly one single contiguous memory region.
pub const UNCOOP_FAULT_REGION: ForeignRegionId = ForeignRegionId { raw: 0 };

pub ghost struct UncoopFaultSessionView {
    pub region: ForeignRegionId,
    pub base: usize,
    pub len: usize,
}

pub struct UncoopFaultDomainState {
    region: ForeignRegionId,
    backing: Arc<TransactionalVec>,
    cookie: DomainCookie,
}

pub struct UncoopFaultSession<'a> {
    obj: &'a UncoopFaultDomainState,
}

pub struct UncoopFaultDomain(());

/// Registration and exported base pointer for one uncooperative userspace domain.
pub struct UncoopUserFaultRegistration {
    registration: DomainRegistration<UncoopFaultDomain>,
    pointer: ExportedPointer<UncoopFaultDomain>,
}

impl UncoopFaultDomainState {
    #[verifier::type_invariant]
    closed spec fn inv(&self) -> bool {
        self.backing().wf()
    }

    pub closed spec fn spec_region(&self) -> ForeignRegionId {
        self.region
    }

    pub closed spec fn backing(&self) -> TransactionalVec {
        *self.backing
    }

    pub fn backing_ref(&self) -> (b: &TransactionalVec)
        ensures
            *b == self.backing(),
            self.wf() ==> b.wf(),
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

impl ForeignMemoryRuntime {
    fn route_uncoop_user_fault(
        &self,
        obj: UncoopFaultDomainState,
        cursor: *mut u8,
    ) -> (registered: UncoopUserFaultRegistration)
        requires
            self.wf(),
            obj.wf(),
    {
        let registration = self.register::<UncoopFaultDomain>(obj);
        let pointer = registration.export_pointer(UNCOOP_FAULT_REGION.raw, cursor);
        UncoopUserFaultRegistration { registration, pointer }
    }

    pub fn inject_uncoop_user_fault(
        &self,
        cursor: *mut u8,
    ) -> (registered: UncoopUserFaultRegistration)
        requires
            self.wf(),
    {
        let obj = UncoopFaultDomainState::dead(UNCOOP_FAULT_REGION, fresh_cookie());
        self.route_uncoop_user_fault(obj, cursor)
    }

    pub fn inject_uncoop_user_fault_modeled(
        &self,
        base: usize,
        backing: Vec<u8>,
    ) -> (result: (UncoopUserFaultRegistration, Arc<TransactionalVec>))
        requires
            self.wf(),
            base as nat + backing@.len() <= usize::MAX as nat,
    {
        let shared_backing = Arc::new(TransactionalVec::from_backing(base, backing));
        let obj = UncoopFaultDomainState::from_shared_backing(
            UNCOOP_FAULT_REGION,
            shared_backing.clone(),
            fresh_cookie(),
        );
        let registered =
            self.route_uncoop_user_fault(obj, core::ptr::null_mut::<u8>().with_addr(base));
        (registered, shared_backing)
    }
}

impl UncoopUserFaultRegistration {
    pub closed spec fn wf(&self) -> bool {
        self.registration.wf()
    }

    pub fn pointer(&self) -> (pointer: ExportedPointer<UncoopFaultDomain>) {
        self.pointer
    }

    #[cfg(all(test, feature = "modeled_backend"))]
    pub(crate) fn pointer_at(
        &self,
        region: usize,
        address: usize,
    ) -> ExportedPointer<UncoopFaultDomain> {
        self.registration
            .export_pointer(region, core::ptr::null_mut::<u8>().with_addr(address))
    }

    pub fn retire(self) -> (result: Result<RetiredDomain, RetireError>)
        requires
            self.wf(),
    {
        self.registration.retire()
    }
}

impl<'a> UncoopFaultSession<'a> {
    pub closed spec fn spec_obj(&self) -> UncoopFaultDomainState {
        *self.obj
    }

}

impl DynState for UncoopFaultDomainState {
    open spec fn wf(&self) -> bool {
        self.backing().wf()
    }

    // SOUNDNESS: must be `type_tag::<Self>()` literally, never delegated.
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

    fn as_any<'b>(&'b self) -> (r: RuntimeAnyRef<'b>) {
        RuntimeAnyRef::new(self)
    }
}

impl<'a> DomainSession for UncoopFaultSession<'a> {
    type State = UncoopFaultSessionView;

    open spec fn st(&self) -> UncoopFaultSessionView {
        UncoopFaultSessionView {
            region: self.spec_obj().region(),
            base: self.spec_obj().backing().base_addr(),
            len: self.spec_obj().backing().size(),
        }
    }

    open spec fn wf(st: UncoopFaultSessionView) -> bool {
        st.base + st.len <= usize::MAX
    }

    open spec fn interfere(pre: UncoopFaultSessionView, post: UncoopFaultSessionView) -> bool {
        &&& post.region == pre.region
        &&& post.base == pre.base
        &&& post.len == pre.len
    }

    proof fn lemma_interfere_refl(_s: UncoopFaultSessionView) {
    }

    proof fn lemma_interfere_trans(_a: UncoopFaultSessionView, _b: UncoopFaultSessionView, _c: UncoopFaultSessionView) {
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

    fn check_address_extent(
        &self,
        region: ForeignRegionId,
        index: usize,
    ) -> (result: Result<AddressExtent, WrongRegion>) {
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
        &&& post.base == pre.base
        &&& post.len == pre.len
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
            use_type_invariant(self.obj);
            Self::lemma_interfere_refl(old(self).st());
        }
        let _ = region;
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
        let _ = self.obj.backing_ref().read_atomic(&mut out, offset);
        out
    }

    fn try_load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (res: (
        bool,
        Vec<u8>,
    )) {
        proof {
            use_type_invariant(self.obj);
            Self::lemma_interfere_refl(old(self).st());
        }
        let ghost pre = old(self).st();
        let base = self.obj.backing_ref().base_addr();
        let len = self.obj.backing_ref().size();
        if offset >= base && size <= len && offset - base <= len - size {
            assert forall|env: UncoopFaultSessionView| #[trigger]
                Self::interfere(pre, env) implies Self::load_disposition(env, region, offset, size).permits_success() by {
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
            use_type_invariant(self.obj);
            Self::lemma_interfere_refl(old(self).st());
        }
        let _ = region;
        let _ = size;
        self.obj.backing_ref().write_atomic(data, offset);
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
                Self::interfere(pre, env) implies Self::store_disposition(env, region, offset, size).permits_success() by {
                Self::lemma_interfere_refl(pre);
            }
            self.store_atomic(region, offset, size, data);
            false
        } else {
            true
        }
    }

    fn close(self) {}
}

impl UncoopFaultDomain {
    fn open_strong<'a>(obj: &'a UncoopFaultDomainState) -> (s: UncoopFaultSession<'a>)
        requires
            obj.wf(),
        ensures
            UncoopFaultSession::wf(s.st()),
            s.st().region == obj.region(),
            s.st().base == obj.backing().spec_base(),
            s.st().len == obj.backing().spec_len(),
    {
        UncoopFaultSession { obj }
    }
}

impl ForeignDomain for UncoopFaultDomain {
    type Obj = UncoopFaultDomainState;

    type Session<'a> = UncoopFaultSession<'a>;

    fn open<'a>(obj: &'a UncoopFaultDomainState) -> (s: UncoopFaultSession<'a>) {
        UncoopFaultDomain::open_strong(obj)
    }
}

impl UncoopFaultDomainState {
    /// Mount a real `Vec<u8>` as the window `[base, base + backing.len())`,
    /// used for testing under Miri / Loom etc.
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
        UncoopFaultDomainState {
            region,
            backing: Arc::new(TransactionalVec::from_backing(base, backing)),
            cookie,
        }
    }

    pub fn from_shared_backing(
        region: ForeignRegionId,
        backing: Arc<TransactionalVec>,
        cookie: DomainCookie,
    ) -> (obj: Self)
        requires
            backing.wf(),
        ensures
            obj.wf(),
            obj.region() == region,
            obj.backing() == *backing,
            obj.spec_cookie() == cookie,
    {
        UncoopFaultDomainState { region, backing, cookie }
    }

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
        UncoopFaultDomainState {
            region,
            backing: Arc::new(TransactionalVec::zeroed(base, len)),
            cookie,
        }
    }

    pub fn dead(region: ForeignRegionId, cookie: DomainCookie) -> (obj: Self)
        ensures
            obj.wf(),
            obj.region() == region,
            obj.backing().spec_len() == 0,
            obj.spec_cookie() == cookie,
    {
        UncoopFaultDomainState::zeroed(region, 0, 0, cookie)
    }
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn backing_can_change_while_session_is_open() {
        let base = 0x1000;
        let backing = Arc::new(TransactionalVec::from_backing(base, vec![1, 2]));
        let object = UncoopFaultDomainState::from_shared_backing(
            UNCOOP_FAULT_REGION,
            backing.clone(),
            DomainCookie { raw: 1 },
        );
        let mut session = UncoopFaultDomain::open(&object);

        assert_eq!(session.load_atomic(UNCOOP_FAULT_REGION, base, 1), vec![1]);
        backing.write_atomic(&[9], base);
        assert_eq!(session.load_atomic(UNCOOP_FAULT_REGION, base, 1), vec![9]);

        session.close();
    }
}

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
pub struct UncoopUserSessionView {
    pub region: ForeignRegionId,
    pub len: usize,
}

pub struct UncoopUserDomainState {
    region: ForeignRegionId,
    len: usize,
    cookie: DomainCookie,
}

pub struct UncoopUserSession<'a> {
    _obj: &'a UncoopUserDomainState,
}

pub struct UncoopUserDomain(());

impl DynState for UncoopUserDomainState {
    open spec fn wf(&self) -> bool {
        true
    }

    open spec fn spec_tag(&self) -> int {
        type_tag::<UncoopUserDomainState>()
    }

    closed spec fn spec_cookie(&self) -> DomainCookie {
        self.cookie
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<UncoopUserDomainState>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.cookie
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

impl UncoopUserDomainState {
    pub closed spec fn spec_region(&self) -> ForeignRegionId {
        self.region
    }

    pub closed spec fn spec_len(&self) -> usize {
        self.len
    }

    #[verifier::when_used_as_spec(spec_region)]
    pub fn region(&self) -> (r: ForeignRegionId)
        ensures
            r == self.region(),
    {
        self.region
    }

    #[allow(clippy::len_without_is_empty)]
    #[verifier::when_used_as_spec(spec_len)]
    pub fn len(&self) -> (l: usize)
        ensures
            l == self.len(),
    {
        self.len
    }
}

impl<'a> UncoopUserSession<'a> {
    pub closed spec fn spec_obj(&self) -> UncoopUserDomainState {
        *self._obj
    }
}

impl<'a> DomainSession for UncoopUserSession<'a> {
    type State = UncoopUserSessionView;

    open spec fn st(&self) -> UncoopUserSessionView {
        UncoopUserSessionView { region: self.spec_obj().region(), len: self.spec_obj().len() }
    }

    open spec fn wf(_st: UncoopUserSessionView) -> bool {
        true
    }

    open spec fn interfere(pre: UncoopUserSessionView, post: UncoopUserSessionView) -> bool {
        &&& post.region == pre.region
        &&& post.len == pre.len
    }

    proof fn lemma_interfere_refl(_s: UncoopUserSessionView) {
    }

    proof fn lemma_interfere_trans(
        _a: UncoopUserSessionView,
        _b: UncoopUserSessionView,
        _c: UncoopUserSessionView,
    ) {
    }

    proof fn lemma_interfere_wf(_pre: UncoopUserSessionView, _post: UncoopUserSessionView) {
    }

    open spec fn address_extent(
        st: UncoopUserSessionView,
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
        _pre: UncoopUserSessionView,
        _post: UncoopUserSessionView,
        _region: ForeignRegionId,
        _index: usize,
    ) {
    }

    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >) {
        if self._obj.region.raw == region.raw {
            Ok(AddressExtent { start: 0, end: self._obj.len, index })
        } else {
            Err(WrongRegion)
        }
    }

    open spec fn load_disposition(
        st: UncoopUserSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region == region && offset <= st.len && size <= st.len - offset {
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
        if self._obj.region.raw == region.raw && offset <= self._obj.len && size <= self._obj.len
            - offset {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::Invalid
        }
    }

    open spec fn load_post(
        pre: UncoopUserSessionView,
        post: UncoopUserSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool {
        &&& post == pre
        &&& pre.region == region
        &&& offset <= pre.len
        &&& size <= pre.len - offset
        &&& observed.len() == size
    }

    open spec fn store_disposition(
        st: UncoopUserSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if st.region == region && offset <= st.len && size <= st.len - offset {
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
        if self._obj.region.raw == region.raw && offset <= self._obj.len && size <= self._obj.len
            - offset {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::Invalid
        }
    }

    open spec fn store_post(
        pre: UncoopUserSessionView,
        post: UncoopUserSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        written: Seq<u8>,
    ) -> bool {
        &&& post.region == pre.region
        &&& post.len == pre.len
        &&& pre.region == region
        &&& offset <= pre.len
        &&& size <= pre.len - offset
        &&& written.len() == size
    }

    proof fn lemma_load_post_wf(
        _pre: UncoopUserSessionView,
        _post: UncoopUserSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _observed: Seq<u8>,
    ) {
    }

    proof fn lemma_store_post_wf(
        _pre: UncoopUserSessionView,
        _post: UncoopUserSessionView,
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
        let bytes = self.load_atomic(region, offset, size);
        (false, bytes)
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
        self.store_atomic(region, offset, size, data);
        false
    }

    fn close(self) {
    }
}

impl ForeignDomain for UncoopUserDomain {
    type Obj = UncoopUserDomainState;

    type Session<'a> = UncoopUserSession<'a>;

    fn open<'a>(obj: &'a UncoopUserDomainState) -> (s: UncoopUserSession<'a>) {
        UncoopUserSession { _obj: obj }
    }
}

impl UncoopUserDomainState {
    pub fn new(region: ForeignRegionId, len: usize, cookie: DomainCookie) -> (obj: Self)
        ensures
            obj.region() == region,
            obj.len() == len,
            obj.spec_cookie() == cookie,
            obj.wf(),
    {
        UncoopUserDomainState { region, len, cookie }
    }
}

} // verus!

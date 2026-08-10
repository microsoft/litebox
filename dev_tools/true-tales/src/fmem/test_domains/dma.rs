// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::erasure::DynState;
use crate::fmem::extent::{AddressExtent, WrongRegion};
use crate::fmem::ids::{DomainCookie, ForeignRegionId};
use crate::fmem::session::{AccessDisposition, DomainSession, ForeignDomain};
#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
use crate::helpers::rust_any::{RuntimeAnyRef, RuntimeTypeTag};
use vstd::prelude::*;
use vstd::rwlock::{RwLock, RwLockPredicate, WriteHandle};

verus! {

pub const DMA_MMIO_REGION: ForeignRegionId = ForeignRegionId { raw: 0 };

pub const DMA_MEMORY_REGION: ForeignRegionId = ForeignRegionId { raw: 1 };

pub struct DmaDeviceState {
    pub enabled: bool,
    pub bytes: Vec<u8>,
}

pub ghost struct DmaDeviceStatePred {
    pub len: nat,
}

impl RwLockPredicate<DmaDeviceState> for DmaDeviceStatePred {
    open spec fn inv(self, v: DmaDeviceState) -> bool {
        v.bytes@.len() == self.len
    }
}

pub ghost struct DmaSessionView {
    pub enabled: bool,
    pub bytes: Seq<u8>,
    pub lock: RwLock<DmaDeviceState, DmaDeviceStatePred>,
}

pub struct DmaDomainState {
    lock: RwLock<DmaDeviceState, DmaDeviceStatePred>,
    cookie: DomainCookie,
}

pub struct DmaSession<'a> {
    _obj: &'a DmaDomainState,
    val: DmaDeviceState,
    handle: WriteHandle<'a, DmaDeviceState, DmaDeviceStatePred>,
}

pub struct DmaDomain(());

impl DmaDomainState {
    pub closed spec fn spec_lock(&self) -> RwLock<DmaDeviceState, DmaDeviceStatePred> {
        self.lock
    }

    pub fn acquire_write(&self) -> (r: (
        DmaDeviceState,
        WriteHandle<'_, DmaDeviceState, DmaDeviceStatePred>,
    ))
        ensures
            r.1.rwlock() == self.spec_lock(),
            self.spec_lock().pred().inv(r.0),
    {
        self.lock.acquire_write()
    }
}

impl<'a> DmaSession<'a> {
    pub closed spec fn spec_val(&self) -> DmaDeviceState {
        self.val
    }

    pub closed spec fn spec_handle_rwlock(&self) -> RwLock<DmaDeviceState, DmaDeviceStatePred> {
        self.handle.rwlock()
    }
}

impl DynState for DmaDomainState {
    open spec fn wf(&self) -> bool {
        true
    }

    open spec fn spec_tag(&self) -> int {
        type_tag::<DmaDomainState>()
    }

    closed spec fn spec_cookie(&self) -> DomainCookie {
        self.cookie
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<DmaDomainState>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.cookie
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

impl<'a> DomainSession for DmaSession<'a> {
    type State = DmaSessionView;

    open spec fn st(&self) -> DmaSessionView {
        DmaSessionView {
            enabled: self.spec_val().enabled,
            bytes: self.spec_val().bytes@,
            lock: self.spec_handle_rwlock(),
        }
    }

    open spec fn wf(st: DmaSessionView) -> bool {
        st.bytes.len() == st.lock.pred().len
    }

    open spec fn interfere(pre: DmaSessionView, post: DmaSessionView) -> bool {
        &&& post.enabled == pre.enabled
        &&& post.bytes.len() == pre.bytes.len()
        &&& post.lock == pre.lock
        &&& (!pre.enabled ==> post.bytes == pre.bytes)
    }

    proof fn lemma_interfere_refl(_s: DmaSessionView) {
    }

    proof fn lemma_interfere_trans(_a: DmaSessionView, _b: DmaSessionView, _c: DmaSessionView) {
    }

    proof fn lemma_interfere_wf(_pre: DmaSessionView, _post: DmaSessionView) {
    }

    open spec fn address_extent(
        st: DmaSessionView,
        region: ForeignRegionId,
        index: usize,
    ) -> Option<AddressExtent> {
        if region == DMA_MMIO_REGION {
            Some(AddressExtent { start: 0, end: 1, index })
        } else if region == DMA_MEMORY_REGION {
            Some(AddressExtent { start: 0, end: st.bytes.len() as usize, index })
        } else {
            None
        }
    }

    proof fn lemma_address_extent_interfere(
        _pre: DmaSessionView,
        _post: DmaSessionView,
        _region: ForeignRegionId,
        _index: usize,
    ) {
    }

    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >) {
        if DMA_MMIO_REGION.raw == region.raw {
            Ok(AddressExtent { start: 0, end: 1, index })
        } else if DMA_MEMORY_REGION.raw == region.raw {
            Ok(AddressExtent { start: 0, end: self.val.bytes.len(), index })
        } else {
            Err(WrongRegion)
        }
    }

    open spec fn load_disposition(
        st: DmaSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        if (region == DMA_MMIO_REGION && offset == 0 && size == 1) || (region == DMA_MEMORY_REGION
            && size <= st.bytes.len() && offset <= st.bytes.len() - size) {
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
        if (DMA_MMIO_REGION.raw == region.raw && offset == 0 && size == 1) || (DMA_MEMORY_REGION.raw
            == region.raw && size <= self.val.bytes.len() && offset <= self.val.bytes.len()
            - size) {
            AccessDisposition::Infallible
        } else {
            AccessDisposition::Invalid
        }
    }

    open spec fn load_post(
        pre: DmaSessionView,
        post: DmaSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool {
        &&& post.enabled == pre.enabled
        &&& post.bytes == pre.bytes
        &&& post.lock == pre.lock
        &&& observed.len() == size
        &&& if region == DMA_MMIO_REGION {
            &&& offset == 0
            &&& size == 1
            &&& observed[0] == if pre.enabled {
                1u8
            } else {
                0u8
            }
        } else {
            &&& region == DMA_MEMORY_REGION
            &&& size <= pre.bytes.len()
            &&& offset <= pre.bytes.len() - size
            &&& observed == pre.bytes.subrange(offset as int, offset + size)
        }
    }

    open spec fn store_disposition(
        st: DmaSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        Self::load_disposition(st, region, offset, size)
    }

    fn check_store_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition) {
        self.check_load_disposition(region, offset, size)
    }

    open spec fn store_post(
        pre: DmaSessionView,
        post: DmaSessionView,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        written: Seq<u8>,
    ) -> bool {
        &&& post.lock == pre.lock
        &&& written.len() == size
        &&& if region == DMA_MMIO_REGION {
            &&& offset == 0
            &&& size == 1
            &&& post.enabled == (written[0] != 0)
            &&& post.bytes == pre.bytes
        } else {
            &&& region == DMA_MEMORY_REGION
            &&& size <= pre.bytes.len()
            &&& offset <= pre.bytes.len() - size
            &&& post.enabled == pre.enabled
            &&& post.bytes == pre.bytes.subrange(0, offset as int).add(written).add(
                pre.bytes.subrange(offset + size, pre.bytes.len() as int),
            )
        }
    }

    proof fn lemma_load_post_wf(
        _pre: DmaSessionView,
        _post: DmaSessionView,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
        _observed: Seq<u8>,
    ) {
    }

    proof fn lemma_store_post_wf(
        _pre: DmaSessionView,
        _post: DmaSessionView,
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
        let mut out: Vec<u8> = Vec::new();
        if DMA_MMIO_REGION.raw == region.raw {
            out.push(
                if self.val.enabled {
                    1u8
                } else {
                    0u8
                },
            );
        } else {
            let mut i: usize = 0;
            while i < size
                invariant
                    i <= size,
                    offset + size <= self.val.bytes.len(),
                    out@ == self.val.bytes@.subrange(offset as int, offset + i),
                decreases size - i,
            {
                out.push(self.val.bytes[offset + i]);
                proof {
                    assert(out@ =~= self.val.bytes@.subrange(offset as int, offset + i + 1));
                }
                i += 1;
            }
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
        (false, self.load_atomic(region, offset, size))
    }

    fn store_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize, data: &[u8]) {
        proof {
            Self::lemma_interfere_refl(old(self).st());
        }
        if DMA_MMIO_REGION.raw == region.raw {
            self.val.enabled = data[0] != 0;
        } else {
            let ghost orig = old(self).st().bytes;
            let mut i: usize = 0;
            while i < size
                invariant
                    i <= size,
                    data@.len() == size,
                    self.val.bytes@.len() == orig.len(),
                    offset + size <= self.val.bytes.len(),
                    forall|j: int|
                        #![trigger self.val.bytes@[j]]
                        0 <= j < offset ==> self.val.bytes@[j] == orig[j],
                    forall|j: int|
                        offset <= j < offset + i ==> self.val.bytes@[j] == data@[j - offset],
                    forall|j: int|
                        #![trigger self.val.bytes@[j]]
                        offset + i <= j < self.val.bytes@.len() ==> self.val.bytes@[j] == orig[j],
                decreases size - i,
            {
                self.val.bytes.set(offset + i, data[i]);
                i += 1;
            }
            assert(self.val.bytes@ =~= orig.subrange(0, offset as int).add(data@).add(
                orig.subrange(offset + size, orig.len() as int),
            ));
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
        self.store_atomic(region, offset, size, data);
        false
    }

    fn close(self) {
        let val = self.val;
        let handle = self.handle;
        handle.release_write(val);
    }
}

impl ForeignDomain for DmaDomain {
    type Obj = DmaDomainState;

    type Session<'a> = DmaSession<'a>;

    fn open<'a>(obj: &'a DmaDomainState) -> (s: DmaSession<'a>) {
        let (val, handle) = obj.lock.acquire_write();
        DmaSession { _obj: obj, val, handle }
    }
}

impl DmaDomain {
    pub fn open_strong<'a>(obj: &'a DmaDomainState) -> (s: DmaSession<'a>)
        requires
            obj.wf(),
        ensures
            <DmaSession<'a> as DomainSession>::wf(s.st()),
    {
        let (val, handle) = obj.acquire_write();
        DmaSession { _obj: obj, val, handle }
    }
}

impl DmaDomainState {
    pub fn new(len: usize, cookie: DomainCookie) -> (obj: Self)
        ensures
            obj.wf(),
            obj.spec_cookie() == cookie,
    {
        let bytes = vec![0u8; len];
        let ghost pred = DmaDeviceStatePred { len: len as nat };
        let state = DmaDeviceState { enabled: false, bytes };
        let lock = RwLock::new(state, Ghost(pred));
        DmaDomainState { lock, cookie }
    }
}

pub fn drive_dma_disabled_round_trip(obj: &DmaDomainState)
    requires
        obj.wf(),
{
    let mut sess = DmaDomain::open_strong(obj);
    if sess.val.bytes.len() < 2 {
        sess.close();
        return;
    }
    let disable: Vec<u8> = vec![0u8];
    sess.store_atomic(DMA_MMIO_REGION, 0, 1, disable.as_slice());
    let ghost disabled = sess.st();
    assert(!disabled.enabled);
    assert forall|env: DmaSessionView| #[trigger]
        DmaSession::interfere(disabled, env) implies env.bytes == disabled.bytes by {
        assert(!disabled.enabled);
    }

    let mut written: Vec<u8> = Vec::new();
    written.push(0x5a);
    written.push(0xa5);
    sess.store_atomic(DMA_MEMORY_REGION, 0, 2, written.as_slice());
    let ghost stored = sess.st();
    assert(!stored.enabled);
    assert forall|env: DmaSessionView| #[trigger] DmaSession::interfere(stored, env) implies {
        &&& DmaSession::load_disposition(env, DMA_MEMORY_REGION, 0, 2).permits_success()
        &&& env.bytes == stored.bytes
    } by {
        assert(!stored.enabled);
    }

    let _observed = sess.load_atomic(DMA_MEMORY_REGION, 0, 2);
    assert(_observed@ == written@);
    sess.close();
}

pub proof fn lemma_enabled_dma_may_overwrite(pre: DmaSessionView, replacement: Seq<u8>)
    requires
        pre.enabled,
        replacement.len() == pre.bytes.len(),
    ensures
        exists|post: DmaSessionView|
            {
                &&& #[trigger] DmaSession::interfere(pre, post)
                &&& post.bytes == replacement
            },
{
    let post = DmaSessionView { enabled: pre.enabled, bytes: replacement, lock: pre.lock };
    assert(DmaSession::interfere(pre, post));
}

} // verus!

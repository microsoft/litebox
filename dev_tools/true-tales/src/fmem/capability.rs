// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Binds foreign-memory sessions to pointer capabilities.
//!
//! [`BoundSession`] records the session handle used to open it. Foreign-memory
//! operations require this handle to match the pointer's handle, preventing
//! access through a session for another domain. Handles are not unique
//! identifiers, so unequal handles do not prove that objects differ.

#[cfg(verus_only)]
use crate::fmem::erasure::DynState;
use crate::fmem::erasure::{ErasedArc, UnsizeShim, downcast_state};
use crate::fmem::extent::{AddressExtent, WrongRegion};
use crate::fmem::ids::ForeignRegionId;
use crate::fmem::session::{AccessDisposition, DomainSession, ForeignDomain};
#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
use vstd::prelude::*;

verus! {

/// Recover a typed domain object from an erased handle.
///
/// The downcast is checked, and the returned borrow is tied to the handle.
/// `None` means that the handle contains another domain type.
pub fn handle_obj<D: ForeignDomain>(h: &ErasedArc) -> (o: Option<&D::Obj>)
    ensures
        h.spec_tag() == type_tag::<UnsizeShim<D::Obj>>() ==> o is Some,
        o is Some ==> o->Some_0.wf() == h.wf(),
        o is Some ==> h.spec_tag() == type_tag::<UnsizeShim<D::Obj>>(),
        o is Some ==> o->Some_0.spec_cookie() == h.spec_cookie(),
{
    match downcast_state::<UnsizeShim<D::Obj>>(h.borrow()) {
        Option::Some(live) => Option::Some(live.obj()),
        Option::None => Option::None,
    }
}

/// A [`DomainSession`] paired with the handle used to open it.
pub struct BoundSession<T: DomainSession> {
    inner: T,
    _cap: Ghost<ErasedArc>,
}

impl<T: DomainSession> BoundSession<T> {
    /// The handle used to open this session.
    ///
    /// This is closed because it reads a private field. [`open_bound`] provides
    /// the equality callers need.
    pub closed spec fn cap(&self) -> ErasedArc {
        self._cap@
    }

    pub fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >)
        requires
            T::wf(self.st()),
        ensures
            result is Ok ==> T::address_extent(self.st(), region, index) == Some(result->Ok_0),
            result is Err ==> T::address_extent(self.st(), region, index).is_none(),
    {
        self.inner.check_address_extent(region, index)
    }

    pub fn check_load_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition)
        requires
            T::wf(self.st()),
        ensures
            match disposition {
                AccessDisposition::Invalid => true,
                AccessDisposition::Infallible => forall|env: T::State| #[trigger]
                    T::interfere(self.st(), env) ==> T::load_disposition(
                        env,
                        region,
                        offset,
                        size,
                    ).is_infallible(),
                AccessDisposition::AlwaysFaults => forall|env: T::State| #[trigger]
                    T::interfere(self.st(), env) ==> T::load_disposition(
                        env,
                        region,
                        offset,
                        size,
                    ).is_always_faulting(),
                AccessDisposition::MayFault => forall|env: T::State| #[trigger]
                    T::interfere(self.st(), env) ==> T::load_disposition(
                        env,
                        region,
                        offset,
                        size,
                    ).is_invalid() == false,
            },
    {
        self.inner.check_load_disposition(region, offset, size)
    }

    pub fn check_store_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition)
        requires
            T::wf(self.st()),
        ensures
            match disposition {
                AccessDisposition::Invalid => true,
                AccessDisposition::Infallible => forall|env: T::State| #[trigger]
                    T::interfere(self.st(), env) ==> T::store_disposition(
                        env,
                        region,
                        offset,
                        size,
                    ).is_infallible(),
                AccessDisposition::AlwaysFaults => forall|env: T::State| #[trigger]
                    T::interfere(self.st(), env) ==> T::store_disposition(
                        env,
                        region,
                        offset,
                        size,
                    ).is_always_faulting(),
                AccessDisposition::MayFault => forall|env: T::State| #[trigger]
                    T::interfere(self.st(), env) ==> T::store_disposition(
                        env,
                        region,
                        offset,
                        size,
                    ).is_invalid() == false,
            },
    {
        self.inner.check_store_disposition(region, offset, size)
    }

    /// Perform an atomic load without changing the session capability.
    pub fn load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (bytes:
        Vec<u8>)
        requires
            T::wf(old(self).st()),
            forall|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) ==> T::load_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success(),
        ensures
            T::wf(final(self).st()),
            bytes@.len() == size,
            exists|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) && T::load_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    bytes@,
                ),
            final(self).cap() == old(self).cap(),
    {
        self.inner.load_atomic(region, offset, size)
    }

    /// Perform a fallible atomic load without changing the session capability.
    pub fn try_load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (res:
        (bool, Vec<u8>))
        requires
            T::wf(old(self).st()),
            forall|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) ==> (T::load_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success() || T::load_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_fault()),
        ensures
            T::wf(final(self).st()),
            final(self).cap() == old(self).cap(),
            res.0 ==> {
                &&& T::interfere(old(self).st(), final(self).st())
                &&& T::load_disposition(final(self).st(), region, offset, size).permits_fault()
            },
            !res.0 ==> res.1@.len() == size,
            !res.0 ==> exists|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) && T::load_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    res.1@,
                ),
    {
        self.inner.try_load_atomic(region, offset, size)
    }

    pub fn store_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize, data: &[u8])
        requires
            T::wf(old(self).st()),
            data@.len() == size,
            forall|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) ==> T::store_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success(),
        ensures
            T::wf(final(self).st()),
            exists|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) && T::store_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    data@,
                ),
            final(self).cap() == old(self).cap(),
    {
        self.inner.store_atomic(region, offset, size, data)
    }

    pub fn try_store_atomic(
        &mut self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> (faulted: bool)
        requires
            T::wf(old(self).st()),
            data@.len() == size,
            forall|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) ==> (T::store_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success() || T::store_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_fault()),
        ensures
            T::wf(final(self).st()),
            final(self).cap() == old(self).cap(),
            faulted ==> {
                &&& T::interfere(old(self).st(), final(self).st())
                &&& T::store_disposition(final(self).st(), region, offset, size).permits_fault()
            },
            !faulted ==> exists|env: T::State| #[trigger]
                T::interfere(old(self).st(), env) && T::store_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    data@,
                ),
    {
        self.inner.try_store_atomic(region, offset, size, data)
    }
}

/// Forwards [`DomainSession`] to the inner session.
impl<T: DomainSession> DomainSession for BoundSession<T> {
    type State = T::State;

    closed spec fn st(&self) -> T::State {
        self.inner.st()
    }

    open spec fn wf(st: T::State) -> bool {
        T::wf(st)
    }

    open spec fn interfere(pre: T::State, post: T::State) -> bool {
        T::interfere(pre, post)
    }

    proof fn lemma_interfere_refl(s: T::State) {
        T::lemma_interfere_refl(s);
    }

    proof fn lemma_interfere_trans(a: T::State, b: T::State, c: T::State) {
        T::lemma_interfere_trans(a, b, c);
    }

    proof fn lemma_interfere_wf(pre: T::State, post: T::State) {
        T::lemma_interfere_wf(pre, post);
    }

    open spec fn address_extent(st: T::State, region: ForeignRegionId, index: usize) -> Option<
        AddressExtent,
    > {
        T::address_extent(st, region, index)
    }

    proof fn lemma_address_extent_interfere(
        pre: T::State,
        post: T::State,
        region: ForeignRegionId,
        index: usize,
    ) {
        T::lemma_address_extent_interfere(pre, post, region, index);
    }

    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >) {
        self.inner.check_address_extent(region, index)
    }

    open spec fn load_disposition(
        st: T::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        T::load_disposition(st, region, offset, size)
    }

    fn check_load_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition) {
        self.inner.check_load_disposition(region, offset, size)
    }

    open spec fn load_post(
        pre: T::State,
        post: T::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool {
        T::load_post(pre, post, region, offset, size, observed)
    }

    open spec fn store_disposition(
        st: T::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition {
        T::store_disposition(st, region, offset, size)
    }

    fn check_store_disposition(
        &self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> (disposition: AccessDisposition) {
        self.inner.check_store_disposition(region, offset, size)
    }

    open spec fn store_post(
        pre: T::State,
        post: T::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        written: Seq<u8>,
    ) -> bool {
        T::store_post(pre, post, region, offset, size, written)
    }

    proof fn lemma_load_post_wf(
        pre: T::State,
        post: T::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) {
        T::lemma_load_post_wf(pre, post, region, offset, size, observed);
    }

    proof fn lemma_store_post_wf(
        pre: T::State,
        post: T::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        written: Seq<u8>,
    ) {
        T::lemma_store_post_wf(pre, post, region, offset, size, written);
    }

    fn load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (bytes: Vec<
        u8,
    >) {
        let ghost s0 = self.st();
        assert forall|env: T::State| #[trigger] T::interfere(s0, env) implies T::load_disposition(
            env,
            region,
            offset,
            size,
        ).permits_success() by {
            assert(Self::interfere(s0, env));
        }
        let bytes = BoundSession::load_atomic(self, region, offset, size);
        proof {
            let env = choose|env: T::State|
                #![trigger T::interfere(s0, env)]
                T::interfere(s0, env) && T::load_post(env, self.st(), region, offset, size, bytes@);
            assert(Self::interfere(s0, env));
            assert(Self::load_post(env, self.st(), region, offset, size, bytes@));
        }
        bytes
    }

    fn try_load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (res: (
        bool,
        Vec<u8>,
    )) {
        let ghost s0 = self.st();
        assert forall|env: T::State| #[trigger] T::interfere(s0, env) implies (T::load_disposition(
            env,
            region,
            offset,
            size,
        ).permits_success() || T::load_disposition(env, region, offset, size).permits_fault()) by {
            assert(Self::interfere(s0, env));
        }
        let res = BoundSession::try_load_atomic(self, region, offset, size);
        proof {
            if !res.0 {
                let env = choose|env: T::State|
                    #![trigger T::interfere(s0, env)]
                    T::interfere(s0, env) && T::load_post(
                        env,
                        self.st(),
                        region,
                        offset,
                        size,
                        res.1@,
                    );
                assert(Self::interfere(s0, env));
                assert(Self::load_post(env, self.st(), region, offset, size, res.1@));
            }
        }
        res
    }

    fn store_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize, data: &[u8]) {
        let ghost s0 = self.inner.st();
        assert forall|env: T::State| #[trigger] T::interfere(s0, env) implies T::store_disposition(
            env,
            region,
            offset,
            size,
        ).permits_success() by {
            assert(Self::interfere(s0, env));
        }
        self.inner.store_atomic(region, offset, size, data);
        proof {
            let env = choose|env: T::State|
                #![trigger T::interfere(s0, env)]
                T::interfere(s0, env) && T::store_post(
                    env,
                    self.inner.st(),
                    region,
                    offset,
                    size,
                    data@,
                );
            assert(Self::interfere(s0, env));
            assert(Self::store_post(env, self.st(), region, offset, size, data@));
        }
    }

    fn try_store_atomic(
        &mut self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> (faulted: bool) {
        let ghost s0 = self.inner.st();
        assert forall|env: T::State| #[trigger] T::interfere(s0, env) implies (T::store_disposition(
            env,
            region,
            offset,
            size,
        ).permits_success() || T::store_disposition(env, region, offset, size).permits_fault()) by {
            assert(Self::interfere(s0, env));
        }
        let faulted = self.inner.try_store_atomic(region, offset, size, data);
        proof {
            if !faulted {
                let env = choose|env: T::State|
                    #![trigger T::interfere(s0, env)]
                    T::interfere(s0, env) && T::store_post(
                        env,
                        self.inner.st(),
                        region,
                        offset,
                        size,
                        data@,
                    );
                assert(Self::interfere(s0, env));
                assert(Self::store_post(env, self.st(), region, offset, size, data@));
            }
        }
        faulted
    }

    fn close(self) {
        // A struct pattern expands into a form rejected by the lint.
        let inner = self.inner;
        inner.close();
    }
}

/// Open a typed session and bind it to the supplied handle.
pub fn open_bound<'a, D: ForeignDomain>(cap: &'a ErasedArc) -> (result: Option<
    BoundSession<D::Session<'a>>,
>)
    requires
        cap.wf(),
    ensures
        cap.spec_tag() == type_tag::<UnsizeShim<D::Obj>>() ==> result is Some,
        result is Some ==> result->Some_0.cap() == *cap,
        result is Some ==> <BoundSession<D::Session<'a>> as DomainSession>::wf(result->Some_0.st()),
{
    match handle_obj::<D>(cap) {
        Option::Some(obj) => {
            let s = D::open(obj);
            Option::Some(BoundSession { inner: s, _cap: Ghost(*cap) })
        },
        Option::None => Option::None,
    }
}

} // verus!

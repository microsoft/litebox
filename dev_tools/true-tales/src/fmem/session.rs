// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Defines foreign-memory domain and session behavior.
use crate::fmem::erasure::DynState;
use crate::fmem::extent::{AddressExtent, WrongRegion};
use crate::fmem::ids::ForeignRegionId;
use vstd::prelude::*;

verus! {

/// Classifies permitted outcomes for one atomic memory transaction.
///
/// `Invalid` admits no transaction, `Infallible` admits only success,
/// `AlwaysFaults` admits only a fault, and `MayFault` admits either outcome.
/// Partial completion belongs to operations made from multiple transactions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AccessDisposition {
    Invalid,
    Infallible,
    AlwaysFaults,
    MayFault,
}

#[allow(clippy::match_like_matches_macro)]
impl AccessDisposition {
    pub open spec fn spec_is_invalid(self) -> bool {
        self == AccessDisposition::Invalid
    }

    #[verifier::when_used_as_spec(spec_is_invalid)]
    pub fn is_invalid(self) -> (result: bool)
        ensures
            result == self.spec_is_invalid(),
    {
        match self {
            AccessDisposition::Invalid => true,
            _ => false,
        }
    }

    pub open spec fn spec_is_infallible(self) -> bool {
        self == AccessDisposition::Infallible
    }

    #[verifier::when_used_as_spec(spec_is_infallible)]
    pub fn is_infallible(self) -> (result: bool)
        ensures
            result == self.spec_is_infallible(),
    {
        match self {
            AccessDisposition::Infallible => true,
            _ => false,
        }
    }

    pub open spec fn spec_is_always_faulting(self) -> bool {
        self == AccessDisposition::AlwaysFaults
    }

    #[verifier::when_used_as_spec(spec_is_always_faulting)]
    pub fn is_always_faulting(self) -> (result: bool)
        ensures
            result == self.spec_is_always_faulting(),
    {
        match self {
            AccessDisposition::AlwaysFaults => true,
            _ => false,
        }
    }

    pub open spec fn spec_is_may_fault(self) -> bool {
        self == AccessDisposition::MayFault
    }

    #[verifier::when_used_as_spec(spec_is_may_fault)]
    pub fn is_may_fault(self) -> (result: bool)
        ensures
            result == self.spec_is_may_fault(),
    {
        match self {
            AccessDisposition::MayFault => true,
            _ => false,
        }
    }

    pub open spec fn permits_success(self) -> bool {
        self.is_infallible() || self.is_may_fault()
    }

    pub open spec fn permits_fault(self) -> bool {
        self.is_always_faulting() || self.is_may_fault()
    }
}

/// Behavior of an open session over a live foreign-memory domain.
///
/// A session may hold a borrow or state taken from a lock. [`Self::close`] is
/// explicit because `vstd` locks cannot be released from `Drop`.
///
/// [`Self::interfere`] models environment changes between atomic transactions.
/// Preconditions cover every permitted state. Postconditions expose one
/// permitted state.
pub trait DomainSession: Sized {
    /// Abstract state observed through this session.
    type State;

    /// The session's current abstract state. The only `&self` specification
    /// function in this trait.
    spec fn st(&self) -> Self::State;

    spec fn wf(st: Self::State) -> bool;

    /// Environment transitions allowed between atomic operations.
    spec fn interfere(pre: Self::State, post: Self::State) -> bool;

    proof fn lemma_interfere_refl(s: Self::State)
        ensures
            Self::interfere(s, s),
    ;

    proof fn lemma_interfere_trans(a: Self::State, b: Self::State, c: Self::State)
        requires
            Self::interfere(a, b),
            Self::interfere(b, c),
        ensures
            Self::interfere(a, c),
    ;

    proof fn lemma_interfere_wf(pre: Self::State, post: Self::State)
        requires
            Self::interfere(pre, post),
        ensures
            Self::wf(pre) == Self::wf(post),
    ;

    /// Returns the stable address extent for `index` in `region`.
    spec fn address_extent(st: Self::State, region: ForeignRegionId, index: usize) -> Option<
        AddressExtent,
    >;

    /// Interference does not change the address extent.
    proof fn lemma_address_extent_interfere(
        pre: Self::State,
        post: Self::State,
        region: ForeignRegionId,
        index: usize,
    )
        requires
            Self::interfere(pre, post),
        ensures
            Self::address_extent(pre, region, index) == Self::address_extent(post, region, index),
    ;

    /// Returns the executable address extent for `index` in `region`.
    fn check_address_extent(&self, region: ForeignRegionId, index: usize) -> (result: Result<
        AddressExtent,
        WrongRegion,
    >)
        requires
            Self::wf(self.st()),
        ensures
            result is Ok ==> Self::address_extent(self.st(), region, index) == Some(result->Ok_0),
            result is Err ==> Self::address_extent(self.st(), region, index).is_none(),
    ;

    /// Returns the exact disposition in one abstract state.
    spec fn load_disposition(
        st: Self::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition;

    /// Returns a conservative disposition covering every permitted interference state.
    fn check_load_disposition(
        &self,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> (disposition: AccessDisposition)
        requires
            Self::wf(self.st()),
        ensures
            match disposition {
                AccessDisposition::Invalid => true,
                AccessDisposition::Infallible => forall|env: Self::State| #[trigger]
                    Self::interfere(self.st(), env) ==> Self::load_disposition(
                        env,
                        _region,
                        _offset,
                        _size,
                    ).is_infallible(),
                AccessDisposition::AlwaysFaults => forall|env: Self::State| #[trigger]
                    Self::interfere(self.st(), env) ==> Self::load_disposition(
                        env,
                        _region,
                        _offset,
                        _size,
                    ).is_always_faulting(),
                AccessDisposition::MayFault => forall|env: Self::State| #[trigger]
                    Self::interfere(self.st(), env) ==> Self::load_disposition(
                        env,
                        _region,
                        _offset,
                        _size,
                    ).is_invalid() == false,
            },
    {
        AccessDisposition::Invalid
    }

    spec fn load_post(
        pre: Self::State,
        post: Self::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    ) -> bool;

    spec fn store_disposition(
        st: Self::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
    ) -> AccessDisposition;

    /// Returns a conservative disposition covering every permitted interference
    /// state.
    fn check_store_disposition(
        &self,
        _region: ForeignRegionId,
        _offset: usize,
        _size: usize,
    ) -> (disposition: AccessDisposition)
        requires
            Self::wf(self.st()),
        ensures
            match disposition {
                AccessDisposition::Invalid => true,
                AccessDisposition::Infallible => forall|env: Self::State| #[trigger]
                    Self::interfere(self.st(), env) ==> Self::store_disposition(
                        env,
                        _region,
                        _offset,
                        _size,
                    ).is_infallible(),
                AccessDisposition::AlwaysFaults => forall|env: Self::State| #[trigger]
                    Self::interfere(self.st(), env) ==> Self::store_disposition(
                        env,
                        _region,
                        _offset,
                        _size,
                    ).is_always_faulting(),
                AccessDisposition::MayFault => forall|env: Self::State| #[trigger]
                    Self::interfere(self.st(), env) ==> Self::store_disposition(
                        env,
                        _region,
                        _offset,
                        _size,
                    ).is_invalid() == false,
            },
    {
        AccessDisposition::Invalid
    }

    spec fn store_post(
        pre: Self::State,
        post: Self::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        written: Seq<u8>,
    ) -> bool;

    proof fn lemma_load_post_wf(
        pre: Self::State,
        post: Self::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        observed: Seq<u8>,
    )
        requires
            Self::wf(pre),
            Self::load_post(pre, post, region, offset, size, observed),
        ensures
            Self::wf(post),
    ;

    proof fn lemma_store_post_wf(
        pre: Self::State,
        post: Self::State,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        written: Seq<u8>,
    )
        requires
            Self::wf(pre),
            Self::store_post(pre, post, region, offset, size, written),
        ensures
            Self::wf(post),
    ;

    /// Perform one atomic load after any permitted interference.
    fn load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (bytes: Vec<
        u8,
    >)
        requires
            Self::wf(old(self).st()),
            forall|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) ==> Self::load_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success(),
        ensures
            Self::wf(final(self).st()),
            bytes@.len() == size,
            exists|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) && Self::load_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    bytes@,
                ),
    ;

    /// Try one atomic load after any permitted interference.
    ///
    /// On fault, the state changes only through interference and the returned
    /// buffer is unconstrained.
    fn try_load_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize) -> (res: (
        bool,
        Vec<u8>,
    ))
        requires
            Self::wf(old(self).st()),
            forall|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) ==> (Self::load_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success() || Self::load_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_fault()),
        ensures
            Self::wf(final(self).st()),
            res.0 ==> {
                &&& Self::interfere(old(self).st(), final(self).st())
                &&& Self::load_disposition(final(self).st(), region, offset, size).permits_fault()
            },
            !res.0 ==> res.1@.len() == size,
            !res.0 ==> exists|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) && Self::load_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    res.1@,
                ),
    ;

    /// Perform one atomic store after any permitted interference.
    fn store_atomic(&mut self, region: ForeignRegionId, offset: usize, size: usize, data: &[u8])
        requires
            Self::wf(old(self).st()),
            data@.len() == size,
            forall|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) ==> Self::store_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success(),
        ensures
            Self::wf(final(self).st()),
            exists|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) && Self::store_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    data@,
                ),
    ;

    /// Try one atomic store after any permitted interference.
    ///
    /// On fault, the state changes only through interference.
    fn try_store_atomic(
        &mut self,
        region: ForeignRegionId,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> (faulted: bool)
        requires
            Self::wf(old(self).st()),
            data@.len() == size,
            forall|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) ==> (Self::store_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_success() || Self::store_disposition(
                    env,
                    region,
                    offset,
                    size,
                ).permits_fault()),
        ensures
            Self::wf(final(self).st()),
            faulted ==> {
                &&& Self::interfere(old(self).st(), final(self).st())
                &&& Self::store_disposition(final(self).st(), region, offset, size).permits_fault()
            },
            !faulted ==> exists|env: Self::State| #[trigger]
                Self::interfere(old(self).st(), env) && Self::store_post(
                    env,
                    final(self).st(),
                    region,
                    offset,
                    size,
                    data@,
                ),
    ;

    /// Explicit session teardown: `vstd` locks cannot be released from `Drop`.
    fn close(self)
        requires
            Self::wf(self.st()),
    ;
}

/// Links an erasable domain object to its session type.
///
/// The trait is used statically. Live objects are erased through [`DynState`].
pub trait ForeignDomain: 'static {
    /// The live, erasable domain object.
    type Obj: DynState + 'static;

    /// The session opened by borrowing a [`Self::Obj`] for `'a`.
    type Session<'a>: DomainSession where Self::Obj: 'a;

    /// Open a session over a well-formed domain object.
    fn open<'a>(obj: &'a Self::Obj) -> (s: Self::Session<'a>)
        requires
            obj.wf(),
        ensures
            <Self::Session<'a> as DomainSession>::wf(s.st()),
    ;
}

} // verus!

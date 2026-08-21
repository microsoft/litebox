// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::ids::DomainCookie;
#[cfg(verus_only)]
use crate::helpers::rust_any::type_tag;
use crate::helpers::rust_any::{RuntimeAnyRef, RuntimeTypeTag};
use std::sync::{Arc, Weak};
use vstd::prelude::*;

verus! {

#[cfg(verus_only)]
#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::reject_recursive_types(T)]
#[verifier::reject_recursive_types(A)]
pub struct ExWeak<T: ?Sized, A: std::alloc::Allocator>(Weak<T, A>);

/// Type-erased state for one live foreign-memory domain.
///
/// `Send + Sync` allows handles to be shared across hardware threads.
pub trait DynState: Send + Sync {
    /// Rely-stable well-formedness of the erased object.
    ///
    /// For a lock-bearing domain this is the fact that the lock carries the
    /// expected predicate.
    spec fn wf(&self) -> bool;

    /// Identifies the concrete object type in specifications.
    ///
    /// Implementors must return `type_tag::<Self>()`, and `tag` must return
    /// `RuntimeTypeTag::of::<Self>()`. Verus does not enforce this rule.
    /// [`downcast_state`] relies on it, so forwarding another type's tag is
    /// unsound.
    spec fn spec_tag(&self) -> int;

    /// The OS-supplied generation tag. No uniqueness proof depends on it.
    spec fn spec_cookie(&self) -> DomainCookie;

    fn tag(&self) -> (t: RuntimeTypeTag)
        ensures
            t.spec_tag() == self.spec_tag(),
    ;

    fn get_cookie(&self) -> (c: DomainCookie)
        ensures
            c == self.spec_cookie(),
    ;

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>);
}

/// Recover a typed `&'a S` from an erased `&'a dyn DynState`.
///
/// The trusted body uses Rust's checked `Any::downcast_ref` and preserves the
/// input lifetime. Its contracts rely on the `DynState::spec_tag` rule to link
/// Rust's type check with specification equality. A typed and erased reference
/// to the same object have the same `wf`, tag, and cookie.
///
/// `None` only means that the concrete type is not `S`.
#[verifier::external_body]
pub fn downcast_state<S: DynState + 'static>(e: &dyn DynState) -> (out: Option<&S>)
    ensures
        out is Some <==> e.spec_tag() == type_tag::<S>(),
        out is Some ==> out->Some_0.wf() == e.wf(),
        out is Some ==> out->Some_0.spec_tag() == e.spec_tag(),
        out is Some ==> out->Some_0.spec_cookie() == e.spec_cookie(),
{
    e.as_any().downcast::<S>()
}

/// Concrete wrapper used when storing a generic object in an [`ErasedArc`].
///
/// Verus loses specification links when a generic value is unsized to
/// `dyn DynState`. This wrapper keeps those links available to proofs.
///
/// Its type tag must identify `UnsizeShim<O>`. Its `wf` and cookie come from
/// the wrapped object.
pub struct UnsizeShim<O: DynState + 'static> {
    obj: O,
}

impl<O: DynState + 'static> UnsizeShim<O> {
    pub fn new(obj: O) -> (s: Self)
        ensures
            s.wf() == obj.wf(),
            s.spec_tag() == type_tag::<UnsizeShim<O>>(),
            s.spec_cookie() == obj.spec_cookie(),
    {
        UnsizeShim { obj }
    }

    pub fn obj(&self) -> (o: &O)
        ensures
            o.wf() == self.wf(),
            o.spec_cookie() == self.spec_cookie(),
    {
        &self.obj
    }
}

impl<O: DynState + 'static> DynState for UnsizeShim<O> {
    closed spec fn wf(&self) -> bool {
        self.obj.wf()
    }

    closed spec fn spec_tag(&self) -> int {
        type_tag::<UnsizeShim<O>>()
    }

    closed spec fn spec_cookie(&self) -> DomainCookie {
        self.obj.spec_cookie()
    }

    fn tag(&self) -> (t: RuntimeTypeTag) {
        RuntimeTypeTag::of::<UnsizeShim<O>>()
    }

    fn get_cookie(&self) -> (c: DomainCookie) {
        self.obj.get_cookie()
    }

    fn as_any<'a>(&'a self) -> (r: RuntimeAnyRef<'a>) {
        RuntimeAnyRef::new(self)
    }
}

/// Sized, refcounted handle to an erased [`DynState`] object.
///
/// Sessions can own a handle without borrowing the domain map. After a route is
/// removed, a `Weak` reference can wait for remaining handles to be dropped.
///
/// Verus treats `Arc::clone` as the same logical value and gives `Arc<T>` the
/// logical value of `T`. [`Self::share`] relies on these rules.
pub struct ErasedArc {
    inner: Arc<dyn DynState>,
}

#[must_use]
pub struct RetiredDomain {
    inner: Weak<dyn DynState>,
    #[allow(dead_code)]
    identity: Ghost<ErasedArc>,
}

impl Clone for RetiredDomain {
    #[verifier::external_body]
    fn clone(&self) -> (retired: Self)
        ensures
            retired.wf() == self.wf(),
            retired.spec_tag() == self.spec_tag(),
            retired.spec_cookie() == self.spec_cookie(),
    {
        RetiredDomain { inner: self.inner.clone(), identity: self.identity }
    }
}

impl RetiredDomain {
    pub closed spec fn wf(&self) -> bool {
        self.identity@.wf()
    }

    pub closed spec fn spec_tag(&self) -> int {
        self.identity@.spec_tag()
    }

    pub closed spec fn spec_cookie(&self) -> DomainCookie {
        self.identity@.spec_cookie()
    }

    #[verifier::external_body]
    pub fn is_dead(&self) -> bool {
        self.inner.strong_count() == 0
    }
}

impl ErasedArc {
    pub fn new_shim<O: DynState + 'static>(obj: O) -> (e: ErasedArc)
        ensures
            e.wf() == obj.wf(),
            e.spec_tag() == type_tag::<UnsizeShim<O>>(),
            e.spec_cookie() == obj.spec_cookie(),
    {
        ErasedArc { inner: Arc::new(UnsizeShim::new(obj)) }
    }

    pub closed spec fn wf(&self) -> bool {
        self.inner.wf()
    }

    pub closed spec fn spec_tag(&self) -> int {
        self.inner.spec_tag()
    }

    pub closed spec fn spec_cookie(&self) -> DomainCookie {
        self.inner.spec_cookie()
    }

    /// Increment the runtime refcount without changing logical identity.
    pub fn share(&self) -> (h: Self)
        ensures
            h == *self,
            h.wf() == self.wf(),
            h.spec_tag() == self.spec_tag(),
            h.spec_cookie() == self.spec_cookie(),
    {
        ErasedArc { inner: self.inner.clone() }
    }

    /// Borrow the erased object for the lifetime of this handle.
    ///
    /// This remains an inherent method because its Verus postconditions are
    /// required.
    #[allow(clippy::should_implement_trait)]
    pub fn borrow(&self) -> (e: &dyn DynState)
        ensures
            e.wf() == self.wf(),
            e.spec_tag() == self.spec_tag(),
            e.spec_cookie() == self.spec_cookie(),
    {
        &*self.inner
    }

    /// Read the generation cookie without downcasting. Staleness policy is the
    /// caller's (see [`crate::fmem::map::DomainMap::take_handle`]), and
    /// applying it does not require knowing the object's type.
    pub fn get_cookie(&self) -> (c: DomainCookie)
        ensures
            c == self.spec_cookie(),
    {
        self.inner.get_cookie()
    }

    #[verifier::external_body]
    pub(crate) fn retire(self) -> (retired: RetiredDomain)
        ensures
            retired.wf() == self.wf(),
            retired.spec_tag() == self.spec_tag(),
            retired.spec_cookie() == self.spec_cookie(),
    {
        let inner = Arc::downgrade(&self.inner);
        RetiredDomain { inner, identity: Ghost(self) }
    }
}

} // verus!

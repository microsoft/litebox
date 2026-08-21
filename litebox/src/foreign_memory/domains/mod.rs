// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod uncoop_user_fault;

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use true_tales::fmem::capability::BoundSession;
#[cfg(verus_only)]
use true_tales::fmem::erasure::DynState;
use true_tales::fmem::erasure::RetiredDomain as TrueTalesRetiredDomain;
use true_tales::fmem::ids::{DomainCookie, ForeignDomainId, ForeignRegionId};
use true_tales::fmem::map::{DomainMap, RemoveDomainError, ResolveDomainError, RoutedDomainHandle};
use true_tales::fmem::ptr::ForeignPtr;
use true_tales::fmem::session::{DomainSession, ForeignDomain};
use vstd::pervasive::unreached;
use vstd::prelude::*;
use vstd::rwlock::{RwLock, RwLockPredicate};

verus! {

#[verifier::external_body]
fn cookie_exhausted() -> ! {
    unreachable!("domain cookie exhausted")
}

exec static NEXT_COOKIE: AtomicU64
    ensures
        true,
{
    AtomicU64::new(1)
}

pub struct DomainMapInv;

impl RwLockPredicate<DomainMap> for DomainMapInv {
    open spec fn inv(self, map: DomainMap) -> bool {
        map.wf()
    }
}

type SharedRegistry = Arc<RwLock<DomainMap, DomainMapInv>>;

/// Shared routing and liveness state for one platform instance.
pub struct ForeignMemoryRuntime {
    registry: Option<SharedRegistry>,
}

/// Exclusive registration and retirement authority for one foreign domain.
#[must_use = "a registration must be retained until its backing resource is retired"]
pub struct DomainRegistration<D: ForeignDomain> {
    runtime: ForeignMemoryRuntime,
    id: ForeignDomainId,
    _domain: PhantomData<D>,
}

/// A pointer exported by a registered domain.
pub struct ExportedPointer<D: ForeignDomain> {
    id: ForeignDomainId,
    region: ForeignRegionId,
    cursor: *mut u8,
    _domain: PhantomData<D>,
}

/// Diagnostic identity for one routed generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DomainIdentity {
    pub address: usize,
    pub generation: u64,
}

/// Nonblocking quiescence token returned after a domain is unrouted.
#[must_use = "the backing resource must remain live until the retired domain is dead"]
pub struct RetiredDomain {
    inner: TrueTalesRetiredDomain,
}

impl<D: ForeignDomain> Clone for ExportedPointer<D> {
    fn clone(&self) -> (pointer: Self)
        ensures
            pointer == *self,
    {
        *self
    }
}

impl<D: ForeignDomain> Copy for ExportedPointer<D> {}

// SAFETY: the raw cursor is never dereferenced by ExportedPointer. Operations
// resolve and pin the registered domain before passing it to a backend, and a
// stale pointer is rejected after retirement.
#[verifier::external]
unsafe impl<D: ForeignDomain> Send for ExportedPointer<D> {}

// SAFETY: sharing the routing value does not grant memory access. Every access
// independently acquires the domain's session and enforces its synchronization.
#[verifier::external]
unsafe impl<D: ForeignDomain> Sync for ExportedPointer<D> {}

/// Why retirement could not remove the registration's route.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RetireError {
    NotFound,
    GenerationMismatch,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OperationError {
    NotFound,
    GenerationMismatch,
    TypeMismatch,
}

/// Validation failures before a fallible load operation starts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FallibleLoadError {
    OffsetOverflow,
    AccessDenied,
    InvalidPointer(OperationError),
}

impl ForeignMemoryRuntime {
    /// Create an empty platform-wide foreign-memory runtime.
    pub fn new() -> (runtime: Self)
        ensures
            runtime.wf(),
    {
        ForeignMemoryRuntime {
            registry: Some(Arc::new(RwLock::new(DomainMap::new(), Ghost(DomainMapInv)))),
        }
    }

    pub closed spec fn wf(&self) -> bool {
        self.registry is Some && (*self.registry->Some_0).pred() == DomainMapInv
    }

    /// Register one lifetime-owned foreign domain.
    pub fn register<D: ForeignDomain>(&self, object: D::Obj) -> (registration:
        DomainRegistration<D>)
        requires
            self.wf(),
            object.wf(),
        ensures
            registration.wf(),
    {
        let registry = match &self.registry {
            Some(registry) => registry,
            None => unreached(),
        };
        let (mut map, write_handle) = (**registry).acquire_write();
        let id = map.inject_domain::<D>(object);
        write_handle.release_write(map);
        DomainRegistration {
            runtime: self.clone(),
            id,
            _domain: PhantomData,
        }
    }

    pub(crate) fn resolve<D: ForeignDomain>(
        &self,
        pointer: ExportedPointer<D>,
    ) -> (result: Result<RoutedDomainHandle<D>, OperationError>)
        requires
            self.wf(),
        ensures
            result is Ok ==> {
                &&& result->Ok_0.wf()
                &&& result->Ok_0.spec_id() == pointer.spec_id()
            },
    {
        let registry = match &self.registry {
            Some(registry) => registry,
            None => unreached(),
        };
        let read_handle = (**registry).acquire_read();
        let resolved = read_handle.borrow().resolve_domain::<D>(pointer.id);
        read_handle.release_read();
        match resolved {
            Result::Ok(routed) => Result::Ok(routed),
            Result::Err(ResolveDomainError::NotFound) => Result::Err(OperationError::NotFound),
            Result::Err(ResolveDomainError::GenerationMismatch) => {
                Result::Err(OperationError::GenerationMismatch)
            }
            Result::Err(ResolveDomainError::TypeMismatch) => {
                Result::Err(OperationError::TypeMismatch)
            }
        }
    }

    /// Resolve, validate, and run one potentially faulting load operation.
    pub fn with_fallible_load<D: ForeignDomain, C, R>(
        &self,
        pointer: ExportedPointer<D>,
        size: usize,
        context: C,
        operation: impl FnOnce(C, ForeignPtr, &mut BoundSession<D::Session<'_>>) -> R,
    ) -> Result<R, FallibleLoadError>
        requires
            self.wf(),
            forall|pointer: ForeignPtr, session: &mut BoundSession<D::Session<'_>>|
                #![trigger operation.requires((context, pointer, session))]
                <D::Session<'_> as DomainSession>::wf(session.st())
                    ==> operation.requires((context, pointer, session)),
            forall|pointer: ForeignPtr, session: &mut BoundSession<D::Session<'_>>, result: R|
                #![trigger operation.ensures((context, pointer, session), result)]
                <D::Session<'_> as DomainSession>::wf(session.st())
                    && operation.ensures((context, pointer, session), result)
                    ==> <D::Session<'_> as DomainSession>::wf(final(session).st()),
    {
        if pointer.cursor.addr().checked_add(size).is_none() {
            return Result::Err(FallibleLoadError::OffsetOverflow);
        }
        let routed = match self.resolve(pointer) {
            Result::Ok(routed) => routed,
            Result::Err(error) => {
                return Result::Err(FallibleLoadError::InvalidPointer(error));
            }
        };
        let foreign_pointer = routed.foreign_ptr(pointer.region, pointer.cursor);
        let mut session = routed.open();
        let disposition =
            session.check_load_disposition(pointer.region, pointer.cursor.addr(), size);
        if disposition.is_invalid() {
            session.close();
            return Result::Err(FallibleLoadError::AccessDenied);
        }
        let result = operation(context, foreign_pointer, &mut session);
        session.close();
        Result::Ok(result)
    }

}

impl Clone for ForeignMemoryRuntime {
    fn clone(&self) -> (runtime: Self)
        ensures
            runtime.wf() == self.wf(),
    {
        let registry = self.registry.clone();
        ForeignMemoryRuntime { registry }
    }
}

impl Default for ForeignMemoryRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: ForeignDomain> DomainRegistration<D> {
    pub closed spec fn wf(&self) -> bool {
        self.runtime.wf()
    }

    /// Export a copyable pointer without creating another routing entry.
    pub fn export_pointer(
        &self,
        region: usize,
        cursor: *mut u8,
    ) -> (pointer: ExportedPointer<D>)
        requires
            self.wf(),
    {
        ExportedPointer {
            id: self.id,
            region: ForeignRegionId { raw: region },
            cursor,
            _domain: PhantomData,
        }
    }

    /// Atomically unroute this generation and return its quiescence token.
    pub fn retire(self) -> (result: Result<RetiredDomain, RetireError>)
        requires
            self.wf(),
    {
        let registry = match &self.runtime.registry {
            Some(registry) => registry,
            None => unreached(),
        };
        let (mut map, write_handle) = (**registry).acquire_write();
        let removed = map.remove_domain(self.id);
        write_handle.release_write(map);
        match removed {
            Result::Ok(retired) => Result::Ok(RetiredDomain { inner: retired }),
            Result::Err(RemoveDomainError::NotFound) => Result::Err(RetireError::NotFound),
            Result::Err(RemoveDomainError::GenerationMismatch) => {
                Result::Err(RetireError::GenerationMismatch)
            }
        }
    }
}

impl<D: ForeignDomain> ExportedPointer<D> {
    pub closed spec fn spec_id(&self) -> ForeignDomainId {
        self.id
    }

    pub closed spec fn spec_region(&self) -> ForeignRegionId {
        self.region
    }

    pub closed spec fn spec_cursor(&self) -> *mut u8 {
        self.cursor
    }

    pub(crate) fn foreign_pointer(
        self,
        routed: &RoutedDomainHandle<D>,
    ) -> (pointer: ForeignPtr)
        requires
            routed.wf(),
            routed.spec_id() == self.spec_id(),
        ensures
            pointer.domain() == self.spec_id(),
            pointer.region() == self.spec_region(),
            pointer.cursor() == self.spec_cursor(),
            pointer.cap() == routed.spec_handle(),
    {
        routed.foreign_ptr(self.region, self.cursor)
    }

    pub(crate) fn raw_region(&self) -> (region: ForeignRegionId)
        ensures
            region == self.spec_region(),
    {
        self.region
    }

    /// Domain identity, including its generation.
    pub fn domain(&self) -> DomainIdentity {
        DomainIdentity {
            address: self.id.addr(),
            generation: self.id.generation().raw,
        }
    }

    /// Region selected within the domain.
    pub fn region(&self) -> usize {
        self.region.raw
    }

    /// Current provenance-carrying address.
    pub fn cursor(&self) -> (cursor: *mut u8)
        ensures
            cursor == self.spec_cursor(),
    {
        self.cursor
    }

    /// Return a pointer advanced by `delta`, or `None` on address overflow.
    pub fn checked_advance(self, delta: usize) -> Option<Self> {
        let address = self.cursor.addr().checked_add(delta)?;
        Some(ExportedPointer {
            id: self.id,
            region: self.region,
            cursor: self.cursor.with_addr(address),
            _domain: PhantomData,
        })
    }
}

impl RetiredDomain {
    /// Whether every operation that resolved the domain before retirement has
    /// released its strong handle.
    pub fn is_dead(&self) -> bool {
        self.inner.is_dead()
    }
}

pub(super) fn fresh_cookie() -> (cookie: DomainCookie) {
    let raw = NEXT_COOKIE.fetch_add(1, Ordering::Relaxed);
    if raw == u64::MAX {
        cookie_exhausted();
    }
    DomainCookie { raw }
}

} // verus!

impl Drop for ForeignMemoryRuntime {
    fn drop(&mut self) {
        let Some(registry) = self.registry.take() else {
            return;
        };
        let Some(registry) = Arc::into_inner(registry) else {
            return;
        };
        drop(registry.into_inner());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use true_tales::fmem::ids::{DomainCookie, ForeignRegionId};
    use true_tales::fmem::test_domains::stable::{StableUserDomain, StableUserDomainState};

    const REGION: usize = 7;

    fn object(cookie: u64) -> StableUserDomainState {
        StableUserDomainState::zeroed(
            ForeignRegionId { raw: REGION },
            0,
            8,
            DomainCookie { raw: cookie },
        )
    }

    #[test]
    fn retirement_rejects_exported_pointer() {
        let runtime = ForeignMemoryRuntime::new();
        let registration = runtime.register::<StableUserDomain>(object(1));
        let pointer = registration.export_pointer(REGION, core::ptr::null_mut());

        let retired = registration.retire().unwrap();
        assert!(retired.is_dead());
        assert!(matches!(
            runtime.with_fallible_load(pointer, 1, (), |(), _, _| ()),
            Err(FallibleLoadError::InvalidPointer(OperationError::NotFound))
        ));
    }

    #[test]
    fn in_flight_operation_pins_retired_domain() {
        let runtime = ForeignMemoryRuntime::new();
        let registration = runtime.register::<StableUserDomain>(object(2));
        let pointer = registration.export_pointer(REGION, core::ptr::null_mut());
        let value = runtime
            .with_fallible_load(pointer, 1, registration, |registration, _, _| {
                let token = registration.retire().unwrap();
                assert!(!token.is_dead());
                (42, token)
            })
            .unwrap();

        assert_eq!(value.0, 42);
        assert!(value.1.is_dead());
    }

    #[test]
    fn exported_pointer_supports_checked_cursor_advance() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ExportedPointer<StableUserDomain>>();

        let runtime = ForeignMemoryRuntime::new();
        let registration = runtime.register::<StableUserDomain>(object(3));
        let pointer = registration.export_pointer(REGION, core::ptr::null_mut());
        let advanced = pointer.checked_advance(4).unwrap();

        assert_eq!(advanced.domain(), pointer.domain());
        assert_eq!(advanced.region(), REGION);
        assert_eq!(advanced.cursor().addr(), 4);
        assert!(pointer.checked_advance(usize::MAX).is_some());
        assert!(advanced.checked_advance(usize::MAX).is_none());
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(verus_only)]
use crate::fmem::erasure::DynState;
use crate::fmem::ids::{DomainCookie, ForeignDomainId, ForeignRegionId};
use crate::fmem::map::{DomainMap, ResolveDomainError, RoutedDomainHandle};
use crate::fmem::session::DomainSession;
use crate::fmem::test_domains::stable::{StableUserDomain, StableUserDomainState};
use crate::fmem::test_domains::uncoop::{UncoopUserDomain, UncoopUserDomainState};
use vstd::pervasive::unreached;
use vstd::prelude::*;

verus! {

#[allow(dead_code)]
pub fn verified_resolve_success(map: &DomainMap, id: ForeignDomainId) -> (routed:
    RoutedDomainHandle<StableUserDomain>)
    requires
        map.wf(),
        map.domain_at::<StableUserDomain>(id),
    ensures
        routed.wf(),
        routed.spec_id() == id,
        routed.spec_handle() == map.obj_handle(id),
{
    match map.resolve_domain::<StableUserDomain>(id) {
        Result::Ok(routed) => routed,
        Result::Err(_) => unreached(),
    }
}

#[allow(dead_code)]
pub fn verified_failed_resolution_frames_map(map: &DomainMap, stale_id: ForeignDomainId) -> (error:
    ResolveDomainError)
    requires
        map.wf(),
        map.has_route(stale_id),
        map.obj_cookie(stale_id) != stale_id.generation(),
    ensures
        error == ResolveDomainError::GenerationMismatch,
{
    match map.resolve_domain::<StableUserDomain>(stale_id) {
        Result::Err(error) => error,
        Result::Ok(_) => unreached(),
    }
}

#[allow(dead_code)]
pub fn verified_pointer_and_session_binding(
    routed: &RoutedDomainHandle<StableUserDomain>,
    region: ForeignRegionId,
    cursor: *mut u8,
)
    requires
        routed.wf(),
{
    let _ptr = routed.foreign_ptr(region, cursor);
    assert(_ptr.domain() == routed.spec_id());
    assert(_ptr.cap() == routed.spec_handle());
    let session = routed.open();
    assert(session.cap() == _ptr.cap());
    session.close();
}

} // verus!
fn stable(cookie: u64) -> StableUserDomainState {
    StableUserDomainState::zeroed(
        ForeignRegionId { raw: 1 },
        0,
        1,
        DomainCookie { raw: cookie },
    )
}

#[test]
fn typed_resolution_mints_pointer_and_session() {
    let mut map = DomainMap::new();
    let id = map.inject_domain::<StableUserDomain>(stable(1));
    assert_eq!(id.generation().raw, 1);

    let routed = map.resolve_domain::<StableUserDomain>(id).unwrap();
    assert_eq!(routed.id().generation().raw, 1);
    let ptr = routed.foreign_ptr(ForeignRegionId { raw: 1 }, core::ptr::null_mut());
    assert_eq!(ptr.domain().generation().raw, 1);
    let session = routed.open();
    session.close();
}

#[test]
fn resolution_errors_have_stable_precedence() {
    let mut map = DomainMap::new();
    let missing = map.inject_domain::<StableUserDomain>(stable(1));
    let _retired = map.remove_domain(missing).unwrap();
    assert!(matches!(
        map.resolve_domain::<UncoopUserDomain>(missing),
        Err(ResolveDomainError::NotFound)
    ));

    let replacement = map.inject_domain::<StableUserDomain>(stable(2));
    let stale = ForeignDomainId::from_route(replacement.route(), DomainCookie { raw: 1 });
    assert!(matches!(
        map.resolve_domain::<UncoopUserDomain>(stale),
        Err(ResolveDomainError::GenerationMismatch)
    ));
    assert!(matches!(
        map.resolve_domain::<UncoopUserDomain>(replacement),
        Err(ResolveDomainError::TypeMismatch)
    ));
}

#[test]
fn routed_handle_outlives_route() {
    let mut map = DomainMap::new();
    let id = map.inject_domain::<StableUserDomain>(stable(3));
    let routed = map.resolve_domain::<StableUserDomain>(id).unwrap();
    let retired = map.remove_domain(id).unwrap();

    assert!(matches!(
        map.resolve_domain::<StableUserDomain>(id),
        Err(ResolveDomainError::NotFound)
    ));
    assert!(!retired.is_dead());
    let session = routed.open();
    session.close();
    drop(routed);
    assert!(retired.is_dead());
}

#[test]
fn failed_resolution_preserves_other_routes() {
    let mut map = DomainMap::new();
    let first = map.inject_domain::<StableUserDomain>(stable(4));
    let other = map.inject_domain::<UncoopUserDomain>(UncoopUserDomainState::new(
        ForeignRegionId { raw: 2 },
        1,
        DomainCookie { raw: 5 },
    ));
    let stale = ForeignDomainId::from_route(first.route(), DomainCookie { raw: 99 });

    assert!(matches!(
        map.resolve_domain::<StableUserDomain>(stale),
        Err(ResolveDomainError::GenerationMismatch)
    ));
    assert!(map.resolve_domain::<StableUserDomain>(first).is_ok());
    assert!(map.resolve_domain::<UncoopUserDomain>(other).is_ok());
}

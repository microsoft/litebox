// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::erasure::RetiredDomain;
use crate::fmem::ids::{DomainCookie, ForeignDomainId, ForeignRegionId};
use crate::fmem::map::{DomainMap, RemoveDomainError};
use crate::fmem::test_domains::stable::{StableUserDomain, StableUserDomainState};
use vstd::pervasive::unreached;
use vstd::prelude::*;

verus! {

#[allow(dead_code)]
pub fn verified_remove_success(
    map: &mut DomainMap,
    id: ForeignDomainId,
    _other: ForeignDomainId,
) -> (retired: RetiredDomain)
    requires
        old(map).wf(),
        old(map).contains(id),
        old(map).contains(_other),
        id.addr() != _other.addr(),
        old(map).obj_cookie(id) == id.generation(),
    ensures
        final(map).wf(),
        !final(map).contains(id),
        final(map).contains(_other),
        final(map).perm_of(_other) == old(map).perm_of(_other),
        retired.wf(),
        retired.spec_tag() == old(map).obj_tag(id),
        retired.spec_cookie() == id.generation(),
{
    match map.remove_domain(id) {
        Result::Ok(retired) => retired,
        Result::Err(_) => unreached(),
    }
}

#[allow(dead_code)]
pub fn verified_stale_generation_rejected(map: &mut DomainMap, stale_id: ForeignDomainId) -> (error:
    RemoveDomainError)
    requires
        old(map).wf(),
        old(map).has_route(stale_id),
        old(map).obj_cookie(stale_id) != stale_id.generation(),
    ensures
        *final(map) == *old(map),
        error == RemoveDomainError::GenerationMismatch,
{
    match map.remove_domain(stale_id) {
        Result::Err(error) => error,
        Result::Ok(_) => unreached(),
    }
}

} // verus!
fn object(cookie: u64) -> StableUserDomainState {
    StableUserDomainState::zeroed(
        ForeignRegionId {
            raw: cookie as usize,
        },
        0,
        1,
        DomainCookie { raw: cookie },
    )
}

#[test]
fn retired_domain_is_static_and_clone() {
    fn check<T: 'static + Clone>() {}
    check::<RetiredDomain>();
}

#[test]
fn removed_domain_without_handles_is_dead() {
    let mut map = DomainMap::new();
    let id = map.inject_domain::<StableUserDomain>(object(1));
    let retired = map.remove_domain(id).unwrap();
    assert!(retired.is_dead());
}

#[test]
fn removed_domain_dies_after_outstanding_handles_are_dropped() {
    let mut map = DomainMap::new();
    let first_id = map.inject_domain::<StableUserDomain>(object(1));
    let other_id = map.inject_domain::<StableUserDomain>(object(2));
    let in_flight = map.take_handle(first_id).unwrap();

    let retired = map.remove_domain(first_id).unwrap();

    assert!(map.take_handle(first_id).is_none());
    assert_eq!(map.take_handle(other_id).unwrap().get_cookie().raw, 2);
    assert_eq!(in_flight.get_cookie().raw, 1);
    assert!(!retired.is_dead());
    let also_retired = retired.clone();
    assert!(!also_retired.is_dead());
    drop(in_flight);
    assert!(retired.is_dead());
    assert!(also_retired.is_dead());
}

#[test]
fn stale_generation_cannot_remove_replacement() {
    let mut map = DomainMap::new();
    let retired_id = map.inject_domain::<StableUserDomain>(object(10));
    let _retired = map.remove_domain(retired_id).unwrap();
    let replacement_id = map.inject_domain::<StableUserDomain>(object(11));
    let stale_id = ForeignDomainId::from_route(replacement_id.route(), DomainCookie { raw: 10 });

    assert!(matches!(
        map.remove_domain(stale_id),
        Err(RemoveDomainError::GenerationMismatch)
    ));
    assert_eq!(
        map.take_handle(replacement_id).unwrap().get_cookie().raw,
        11,
    );
}

#[test]
fn missing_id_is_rejected_without_disturbing_live_routes() {
    let mut map = DomainMap::new();
    let live_id = map.inject_domain::<StableUserDomain>(object(21));
    let missing_id = map.inject_domain::<StableUserDomain>(object(20));
    let _retired = map.remove_domain(missing_id).unwrap();

    assert!(matches!(
        map.remove_domain(missing_id),
        Err(RemoveDomainError::NotFound)
    ));
    assert_eq!(map.take_handle(live_id).unwrap().get_cookie().raw, 21);
}

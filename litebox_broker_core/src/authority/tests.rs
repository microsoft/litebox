// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;

const fn user(id: u32) -> Principal {
    Principal {
        domain: DomainId::POSIX_USER,
        id,
    }
}

const fn group(id: u32) -> Principal {
    Principal {
        domain: DomainId::POSIX_GROUP,
        id,
    }
}

fn exact(p: Principal) -> PrincipalSet {
    PrincipalSet {
        exact: [p].into(),
        ..PrincipalSet::default()
    }
}

fn term(owner: Principal) -> Term {
    let slots = Slots {
        owners: exact(owner),
        groups: exact(group(1)),
    };
    Term {
        access: slots.clone(),
        identity: slots,
        ..Term::default()
    }
}

fn subject(owner: Principal) -> Subject {
    Subject {
        scope: Scope::Access,
        owner,
        group: group(1),
        identities: BTreeSet::new(),
        deny_only: BTreeSet::new(),
        privileges: Privileges::empty(),
    }
}

#[test]
fn scopes_and_alternative_terms_do_not_combine() {
    let mut first = term(user(1));
    first.access.owners = exact(user(2));
    let second = Term {
        privileges: Privileges::SIGNAL_ANY,
        ..term(user(3))
    };
    let authority = Authority::new([first.clone(), second]).unwrap();
    let mut s = subject(user(2));
    assert!(authority.admits(&s));
    s.scope = Scope::Identity;
    assert!(!authority.admits(&s));
    s.owner = user(1);
    assert!(authority.admits(&s));
    s.privileges = Privileges::SIGNAL_ANY;
    assert!(!authority.admits(&s));
    s.owner = user(3);
    assert!(authority.admits(&s));

    first.privileges = Privileges::SIGNAL_ANY;
    assert!(
        !Authority::new([first])
            .unwrap()
            .is_restriction_of(&authority)
    );
}

#[test]
fn restriction_requires_both_scopes_to_fit_one_parent_term() {
    let a = term(user(1));
    let b = term(user(2));
    let mut authority = Authority::new([a.clone(), b.clone()]).unwrap();
    let mixed = Term {
        access: a.access,
        identity: b.identity,
        ..Term::default()
    };
    assert_eq!(
        authority.restrict([mixed]),
        Err(AuthorityError::NotRestriction)
    );
}

#[test]
fn unmapped_deny_only_principal_does_not_confer_membership() {
    let authority = Authority::new([term(user(1))]).unwrap();
    let mut s = subject(user(1));
    s.deny_only.insert(Principal::UNMAPPED);
    assert!(authority.admits(&s));
    s.identities.insert(Principal::UNMAPPED);
    assert!(!authority.admits(&s));
}

#[test]
fn slot_is_not_a_membership_and_deny_only_is_not_optional() {
    let membership = group(1); // Also the primary group.
    let original = Term {
        required: [membership].into(),
        optional: exact(group(9)),
        ..term(user(1))
    };
    let mut authority = Authority::new([original.clone()]).unwrap();
    let mut s = subject(user(1));
    assert!(!authority.admits(&s));
    s.identities.insert(membership);
    assert!(authority.admits(&s));
    s.group = group(9);
    s.identities.insert(group(9));
    assert!(!authority.admits(&s));

    // Narrow the group slot before moving the mandatory membership to deny-only.
    let mut initial = original;
    initial.access.groups.exact.insert(group(2));
    initial.identity.groups.exact.insert(group(2));
    authority = Authority::new([initial.clone()]).unwrap();
    let mut filtered = Term {
        access: Slots {
            groups: exact(group(2)),
            ..initial.access.clone()
        },
        identity: Slots {
            groups: exact(group(2)),
            ..initial.identity.clone()
        },
        ..initial.clone()
    };
    filtered.required.clear();
    filtered.deny_only.insert(membership);
    authority.restrict([filtered.clone()]).unwrap();
    let mut filtered_subject = Subject {
        group: group(2),
        ..subject(user(1))
    };
    assert!(!authority.admits(&filtered_subject));
    filtered_subject.deny_only.insert(membership);
    assert!(authority.admits(&filtered_subject));
    filtered_subject.identities.insert(membership);
    assert!(!authority.admits(&filtered_subject));

    filtered.deny_only.clear();
    assert_eq!(
        authority.restrict([filtered]),
        Err(AuthorityError::NotRestriction)
    );
    assert_eq!(
        authority.restrict([initial]),
        Err(AuthorityError::NotRestriction)
    );
}

#[test]
fn restriction_respects_domains_and_preserves_required_identities() {
    let mut parent = term(user(1));
    parent.access.owners.domains.insert(DomainId::POSIX_USER);
    parent.optional.domains.insert(DomainId::POSIX_GROUP);
    let mut authority = Authority::new([parent]).unwrap();
    let mut child = term(user(u32::MAX));
    child.identity.owners = exact(user(1));
    child.required.insert(group(8));

    let mut wrong_domain = child.clone();
    wrong_domain.access.owners = exact(group(u32::MAX));
    assert_eq!(
        authority.restrict([wrong_domain]),
        Err(AuthorityError::NotRestriction)
    );
    authority.restrict([child.clone()]).unwrap();
    child.required.clear();
    child.optional.exact.insert(group(8));
    let before = authority.clone();
    assert_eq!(
        authority.restrict([child]),
        Err(AuthorityError::NotRestriction)
    );
    assert_eq!(authority, before);
}

#[test]
fn invalid_terms_are_rejected_even_on_initial_assignment() {
    let mut t = term(user(1));
    t.identity.owners.domains.insert(DomainId::POSIX_GROUP);
    t.deny_only.insert(group(77));
    assert_eq!(Authority::new([t]), Err(AuthorityError::DenyOnlyOverlap));

    let mut t = term(user(1));
    t.optional.domains.insert(DomainId::UNMAPPED);
    assert_eq!(Authority::new([t]), Err(AuthorityError::UnmappedPrincipal));

    for privileges in [
        Privileges::EXECUTE_ANY,
        Privileges::from_bits_retain(1 << 31),
    ] {
        let t = Term {
            privileges,
            ..term(user(1))
        };
        assert_eq!(Authority::new([t]), Err(AuthorityError::InvalidPrivileges));
    }
}

#[test]
fn narrower_directory_search_survives_restriction() {
    let mut t = Term {
        privileges: Privileges::TRAVERSE_ANY,
        ..term(user(1))
    };
    let mut authority = Authority::new([t.clone()]).unwrap();
    t.privileges = Privileges::LOOKUP_ANY;
    authority.restrict([t.clone()]).unwrap();
    assert!(authority.admits(&Subject {
        privileges: Privileges::LOOKUP_ANY,
        ..subject(user(1))
    }));
    t.privileges = Privileges::TRAVERSE_ANY;
    assert_eq!(authority.restrict([t]), Err(AuthorityError::NotRestriction));
}

#[test]
fn bound_counts_distinct_terms_not_threads_and_never_partially_commits() {
    let mut broad = term(user(1));
    broad.access.owners.domains.insert(DomainId::POSIX_USER);
    let mut equivalent = broad.clone();
    equivalent.access.owners.exact.insert(user(2));
    let mut authority =
        Authority::new(core::iter::repeat_n(broad.clone(), MAX_TERMS + 1).chain([equivalent]))
            .unwrap();
    assert_eq!(authority.terms().len(), 1);
    let before = authority.clone();
    let narrower = (0..u32::try_from(MAX_TERMS).unwrap()).map(|id| {
        let mut t = broad.clone();
        t.access.owners = exact(user(id));
        t
    });
    // Keep distinct terms even if another thread's broad term subsumes them.
    assert_eq!(
        authority.restrict(narrower.clone().chain([broad.clone()])),
        Err(AuthorityError::TooManyTerms)
    );
    assert_eq!(authority, before);
    authority.restrict(narrower).unwrap();
    assert_eq!(authority.terms().len(), MAX_TERMS);
    authority.restrict([]).unwrap();
    assert!(!authority.admits(&subject(user(1))));
    assert_eq!(
        authority.restrict([broad]),
        Err(AuthorityError::NotRestriction)
    );
}

mod lifecycle {
    use super::*;
    use crate::test_support::{TestBroker, TestBrokerBuilder};
    use crate::{
        BrokerCoreLimits, BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
    };
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    fn broker(limits: BrokerCoreLimits) -> TestBroker {
        TestBrokerBuilder::new(PolicyEngine::default_deny().with_process_duplication_enabled(true))
            .with_limits(limits)
            .build()
            .unwrap()
    }

    fn root(broker: &TestBroker, terms: impl IntoIterator<Item = Term>) -> Arc<BrokerProcess> {
        let process = broker
            .core
            .create_process(
                CallerCredential::HostGuaranteed,
                Arc::new(Authority::new(terms).unwrap()),
                &broker.pid_namespace,
                &broker.fs,
                &broker.job,
                broker.host_names.clone(),
                None,
            )
            .unwrap();
        process.complete_start().unwrap();
        process
    }

    #[test]
    fn subjects_are_private_scoped_and_rechecked_after_restriction() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let a = term(user(7));
        let b = term(user(8));
        let process = root(&broker, [a.clone(), b.clone()]);
        let other = root(&broker, [b.clone()]);
        let kept = process.create_subject(subject(user(7))).unwrap();
        let lost = process.create_subject(subject(user(8))).unwrap();
        assert_eq!(
            other.with_subject(lost, Some(Scope::Access), |_| ()),
            Err(BrokerError::UnknownObject)
        );
        assert!(
            process
                .duplicate_object_references_to(&[kept], &other)
                .is_err()
        );
        assert_eq!(
            process.with_subject(kept, Some(Scope::Identity), |_| ()),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            process.restrict_authority(vec![a.clone(), term(user(9))]),
            Err(BrokerError::PolicyDenied)
        );
        assert!(process.with_subject(lost, None, |_| ()).is_ok());
        process.restrict_authority(vec![a]).unwrap();
        assert_eq!(
            process.with_subject(kept, Some(Scope::Access), |s| s.owner),
            Ok(user(7))
        );
        assert_eq!(
            process.with_subject(lost, None, |_| ()),
            Err(BrokerError::StaleSubject)
        );
        assert_eq!(
            process.create_subject(subject(user(8))),
            Err(BrokerError::PolicyDenied)
        );
        assert!(other.create_subject(subject(user(8))).is_ok());
        process.close_object_reference(lost).unwrap();
        assert_eq!(
            process.with_subject(lost, None, |_| ()),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn pending_sibling_inherits_creator_not_tree_parent() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let a = term(user(1));
        let ancestor = root(&broker, [a.clone(), term(user(2))]);
        let id = ancestor.allocate_child_process(None, false).unwrap();
        let creator = ancestor.take_child_process(id.process_id).unwrap();
        creator.complete_start().unwrap();
        creator.restrict_authority(vec![a.clone()]).unwrap();
        let sibling_id = creator
            .allocate_child_process(None, true)
            .unwrap()
            .process_id;
        assert_eq!(
            ancestor.restrict_child_authority(sibling_id, Vec::new()),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            creator.restrict_child_authority(sibling_id, vec![term(user(2))]),
            Err(BrokerError::PolicyDenied)
        );
        creator
            .restrict_child_authority(sibling_id, Vec::new())
            .unwrap();
        let sibling = creator.take_child_process(sibling_id).unwrap();
        assert_eq!(sibling.authority().terms().len(), 0);
        assert!(creator.authority().terms().eq([&a]));
        assert_eq!(
            creator.restrict_child_authority(sibling_id, Vec::new()),
            Err(BrokerError::UnknownObject)
        );
        assert!(ancestor.authority().admits(&subject(user(2))));
    }

    #[test]
    fn subject_quota_is_released_on_close_and_cleanup() {
        let broker = broker(BrokerCoreLimits {
            max_references: 1,
            max_references_per_process: 1,
            ..BrokerCoreLimits::DEFAULT
        });
        let first = root(&broker, [term(user(1))]);
        let second = root(&broker, [term(user(2))]);
        let handle = first.create_subject(subject(user(1))).unwrap();
        assert_eq!(
            second.create_subject(subject(user(2))),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            first.check_readiness(handle),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            first.duplicate_object_reference_to(handle, &second, ObjectRights::WAIT),
            Err(BrokerError::InvalidRights)
        );
        first.close_object_reference(handle).unwrap();
        first.create_subject(subject(user(1))).unwrap();
        first.cleanup(true);
        assert_eq!(
            first.create_subject(subject(user(1))),
            Err(BrokerError::PeerClosed)
        );
        assert!(second.create_subject(subject(user(2))).is_ok());
    }

    #[test]
    fn concurrent_restrictions_cannot_restore_an_alternative() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let a = term(user(1));
        let b = term(user(2));
        let process = root(&broker, [a.clone(), b.clone()]);
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| process.restrict_authority(vec![a]));
            let second = scope.spawn(|| process.restrict_authority(vec![b]));
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert!(results.contains(&Ok(())));
        assert!(results.contains(&Err(BrokerError::PolicyDenied)));
        assert_eq!(process.authority().terms().len(), 1);
    }

    #[test]
    fn oversized_principal_sets_are_rejected_without_changing_authority() {
        use litebox_broker_protocol::authority::MAX_SET_PRINCIPALS;

        let broker = broker(BrokerCoreLimits::DEFAULT);
        let mut broad = term(user(7));
        broad.optional.domains.insert(DomainId::POSIX_GROUP);
        let process = root(&broker, [broad.clone()]);
        let oversized: BTreeSet<_> = (0..=u32::try_from(MAX_SET_PRINCIPALS).unwrap())
            .map(group)
            .collect();
        let mut proposal = broad.clone();
        proposal.required.clone_from(&oversized);
        assert_eq!(
            Authority::new([proposal.clone()]),
            Err(AuthorityError::SetTooLarge)
        );
        assert_eq!(
            process.restrict_authority(vec![proposal]),
            Err(BrokerError::ResourceExhausted)
        );
        assert!(process.authority().terms().eq([&broad]));
        assert_eq!(
            process.create_subject(Subject {
                identities: oversized,
                ..subject(user(7))
            }),
            Err(BrokerError::ResourceExhausted)
        );
    }
}

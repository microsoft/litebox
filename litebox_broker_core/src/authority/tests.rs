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

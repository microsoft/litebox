// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::authority::{PrincipalSet, Slots, Term};

use super::*;
use crate::authority::Authority;
use crate::descriptor::mutation::{MutationContext, MutationError};

fn slots(owner: Principal, group: Principal) -> Slots {
    let exact = |p| PrincipalSet {
        exact: [p].into(),
        ..PrincipalSet::default()
    };
    Slots {
        owners: exact(owner),
        groups: exact(group),
    }
}

fn authority(s: &Subject, pairs: &[(Principal, Principal)]) -> Authority {
    Authority::new(pairs.iter().map(|&(owner, group)| Term {
        access: slots(s.owner, s.group),
        identity: slots(owner, group),
        optional: PrincipalSet {
            exact: s.identities.clone(),
            ..PrincipalSet::default()
        },
        privileges: s.privileges,
        ..Term::default()
    }))
    .unwrap()
}

fn context<'a>(subject: &'a Subject, authority: &'a Authority) -> MutationContext<'a> {
    MutationContext {
        subject,
        authority,
        profile: FileSystemProfile::new(StorableForms::MODE).unwrap(),
    }
}

#[test]
fn create_uses_the_parent_and_checks_the_file_service_profile() {
    let creator = with_privileges(subject(user(70_000), group(80_000)), Privileges::LOOKUP_ANY);
    let authority = authority(&creator, &[(creator.owner, creator.group)]);
    let ctx = context(&creator, &authority);
    let parent = dir(0o2777);
    let (owner, group) = ctx.creation_ownership(&parent);
    assert_eq!((owner, group), (creator.owner, parent.group()));
    let child = mode_of(FileKind::Directory, owner, group, 0o750);
    assert_eq!(
        ctx.create(&parent, child).unwrap().mode().unwrap().bits(),
        0o2750
    );

    let file = mode_of(FileKind::File, owner, group, 0o640);
    assert_eq!(
        ctx.create(&dir(0o2776), file.clone()),
        Err(MutationError::Denied)
    );
    assert_eq!(ctx.create(&dir(0o777), file), Err(MutationError::Denied));
    assert_eq!(
        ctx.create(&parent, file_acl(vec![])),
        Err(MutationError::UnsupportedForm)
    );
}

#[test]
fn owner_group_and_access_changes_need_independent_authorization() {
    let actor = with_privileges(
        with_identities(subject(user(7), group(8)), &[group(9)]),
        Privileges::TAKE_OWNERSHIP | Privileges::ACT_AS_OWNER,
    );
    let authority = authority(&actor, &[(actor.owner, actor.group)]);
    let ctx = context(&actor, &authority);
    let original = file(0o6750);
    let proposed = |owner, group| mode_of(FileKind::File, owner, group, 0o6750);
    assert_eq!(
        ctx.set_security(&original, proposed(actor.owner, original.group()))
            .unwrap()
            .mode()
            .unwrap()
            .bits(),
        0o750
    );
    // Taking ownership in the same request cannot supply authority to change the group.
    assert_eq!(
        ctx.set_security(&original, proposed(actor.owner, group(9))),
        Err(MutationError::Denied)
    );
    assert_eq!(
        ctx.set_security(&original, proposed(user(2), original.group())),
        Err(MutationError::Denied)
    );

    let owned = proposed(actor.owner, actor.group);
    assert_eq!(
        ctx.set_security(&owned, proposed(actor.owner, group(9)))
            .unwrap()
            .group(),
        group(9)
    );
    assert_eq!(
        ctx.set_security(&owned, proposed(actor.owner, group(3))),
        Err(MutationError::Denied)
    );
}

#[test]
fn both_elevation_grants_require_one_identity_term_even_with_manage_elevation() {
    let writer = with_privileges(subject(user(1), group(1)), Privileges::MANAGE_ELEVATION);
    let split = authority(&writer, &[(user(1), group(2)), (user(2), group(1))]);
    let together = authority(&writer, &[(user(1), group(1))]);
    let proposal = file(0o6710);
    for (authority, expected) in [
        (&split, ElevationGrants::empty()),
        (&together, ElevationGrants::all()),
    ] {
        let ctx = context(&writer, authority);
        assert_eq!(
            ctx.create(&dir(0o777), proposal.clone())
                .unwrap()
                .elevation_grants(),
            expected
        );
        assert_eq!(
            ctx.set_security(&file(0o710), proposal.clone())
                .unwrap()
                .elevation_grants(),
            expected
        );
        let mut written = proposal.clone();
        ctx.content_change(&mut written);
        assert_eq!(written.elevation_grants(), expected);
        assert!(written.allows_file(&writer, Rights::EXECUTE));
    }

    let ordinary = subject(user(1), group(1));
    let ctx = context(&ordinary, &together);
    let mut written = proposal;
    ctx.content_change(&mut written);
    assert!(written.elevation_grants().is_empty());
}

#[test]
fn group_standing_for_delegation_is_not_a_deny_only_membership() {
    let actor = with_deny_only(subject(user(1), group(2)), &[group(1)]);
    let authority = authority(&actor, &[(user(1), group(1))]);
    let ctx = context(&actor, &authority);
    assert_eq!(
        ctx.set_security(&file(0o710), file(0o6710))
            .unwrap()
            .elevation_grants(),
        ElevationGrants::AS_OWNER
    );
    assert_eq!(
        ctx.set_security(&dir(0o750), dir(0o2750))
            .unwrap()
            .mode()
            .unwrap()
            .bits(),
        0o750
    );
}

#[test]
fn replacement_acl_cannot_authorize_itself() {
    let actor = subject(user(3), group(3));
    let authority = authority(&actor, &[(actor.owner, actor.group)]);
    let ctx = MutationContext {
        profile: FileSystemProfile::new(StorableForms::ACL).unwrap(),
        ..context(&actor, &authority)
    };
    let descriptor = |owner, rights| {
        SecurityDescriptor::from_acl(
            FileKind::File,
            owner,
            group(1),
            DirectoryFlags::empty(),
            ElevationGrants::all(),
            vec![Ace::allow(Trustee::Everyone, rights)],
        )
        .unwrap()
    };
    let current = descriptor(user(1), Rights::WRITE_OWNER);
    let changed = ctx
        .set_security(&current, descriptor(actor.owner, Rights::WRITE_OWNER))
        .unwrap();
    assert_eq!(changed.owner(), actor.owner);
    assert!(changed.elevation_grants().is_empty());
    assert_eq!(
        ctx.set_security(&current, descriptor(actor.owner, Rights::WRITE_SECURITY)),
        Err(MutationError::Denied)
    );
}

#[test]
fn guest_mutations_cannot_confer_trusted_provenance() {
    let actor = subject(user(1), group(1));
    let authority = authority(&actor, &[(actor.owner, actor.group)]);
    let ctx = context(&actor, &authority);
    let foreign = FileSystemProfile::new(StorableForms::ACL).unwrap();
    let initial = file(0o600).from_trusted_configuration();
    let replacement = file(0o640).from_trusted_configuration();
    assert!(foreign.honors(&initial));
    let created = ctx.create(&dir(0o777), initial.clone()).unwrap();
    assert!(!foreign.honors(&created));
    let changed = ctx.set_security(&initial, replacement).unwrap();
    assert!(!foreign.honors(&changed));
    let same = ctx.set_security(&initial, file(0o600)).unwrap();
    assert!(foreign.honors(&same));
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::descriptor::{FileKind, Rights, SecurityDescriptor};
use litebox_broker_protocol::authority::{
    DomainId, Principal, Privileges, Scope, Subject, sorted_set::SortedSet,
};
use litebox_broker_protocol::fs::FileMode;

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

fn subject(owner: Principal, primary_group: Principal) -> Subject {
    Subject {
        scope: Scope::Access,
        owner,
        group: primary_group,
        identities: SortedSet::new(),
        deny_only: SortedSet::new(),
        privileges: Privileges::empty(),
    }
}

#[test]
fn all_modes_obey_class_precedence_for_whole_requests() {
    let owner = subject(user(1), group(2));
    let primary = subject(user(2), group(2));
    let other = subject(user(2), group(1));
    let supplementary = Subject {
        identities: [group(2)].into(),
        ..other.clone()
    };
    let deny_only = Subject {
        deny_only: [group(2)].into(),
        ..other.clone()
    };

    for (kind, read, write, execute) in [
        (FileKind::File, Rights::READ, Rights::WRITE, Rights::EXECUTE),
        (
            FileKind::Directory,
            Rights::LIST,
            Rights::ADD_ENTRY,
            Rights::TRAVERSE,
        ),
    ] {
        for bits in 0u16..=0o777 {
            let descriptor = SecurityDescriptor::from_mode(
                kind,
                user(1),
                group(2),
                FileMode::from_bits_retain(bits),
            )
            .unwrap();
            let (u, g, o) = (bits >> 6, (bits >> 3) & 7, bits & 7);
            for (who, class) in [
                (&owner, u),
                (&primary, g),
                (&supplementary, g),
                (&other, o),
                // A deny-only group cannot grant its own bits; it can still
                // veto an other-class bit that the group lacks.
                (&deny_only, g & o),
            ] {
                for (mask, rights) in [
                    (4, read),
                    (2, write),
                    (1, execute),
                    (6, read | write),
                    (5, read | execute),
                    (3, write | execute),
                    (7, read | write | execute),
                ] {
                    assert_eq!(
                        descriptor.allows_file(who, rights),
                        class & mask == mask,
                        "mode {bits:03o}, class {class:o}, request {mask:o}, subject {who:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn directory_search_depends_on_the_entire_request() {
    let outsider = Subject {
        privileges: Privileges::LOOKUP_ANY | Privileges::WRITE_ANY,
        ..subject(user(0), group(0))
    };
    let sticky =
        SecurityDescriptor::from_mode(FileKind::Directory, user(1), group(2), FileMode::SVTX)
            .unwrap();
    assert!(sticky.allows_file(&outsider, Rights::TRAVERSE));
    for write in [Rights::ADD_ENTRY, Rights::REPARENT] {
        assert!(sticky.allows_file(&outsider, write));
        assert!(!sticky.allows_file(&outsider, Rights::TRAVERSE | write));
    }
    let modifier = Subject {
        privileges: Privileges::TRAVERSE_ANY | Privileges::WRITE_ANY,
        ..outsider
    };
    assert!(sticky.allows_file(&modifier, Rights::TRAVERSE | Rights::ADD_ENTRY));
    assert!(!sticky.allows_file(&modifier, Rights::TRAVERSE | Rights::DELETE_CHILD));
}

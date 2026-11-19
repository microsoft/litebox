// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec;
use alloc::vec::Vec;

use litebox_broker_protocol::authority::{DomainId, sorted_set::SortedSet};
use litebox_broker_protocol::signal::MAX_SIGNAL;

use super::acl::{AceKind, AllOf, MAX_ALL_OF};
use super::handle::{HandleGrants, HandleUse};
use super::process::{ProcessAce, ProcessDescriptor, ProcessRights, SignalMask, SignalRequest};
use super::profile::{FileSystemProfile, HandleRules, StorableForms};
use super::*;

mod mutation;

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

const UNMAPPED: Principal = Principal::UNMAPPED;

fn set(principals: &[Principal]) -> SortedSet<Principal> {
    SortedSet::try_from_iter(principals.iter().copied()).unwrap()
}

fn subject(owner: Principal, group: Principal) -> Subject {
    Subject {
        scope: Scope::Access,
        owner,
        group,
        identities: SortedSet::new(),
        deny_only: SortedSet::new(),
        privileges: Privileges::empty(),
    }
}

fn with_identities(mut subject: Subject, identities: &[Principal]) -> Subject {
    subject.identities = set(identities);
    subject
}

fn with_deny_only(mut subject: Subject, deny_only: &[Principal]) -> Subject {
    subject.deny_only = set(deny_only);
    subject
}

fn with_privileges(mut subject: Subject, privileges: Privileges) -> Subject {
    subject.privileges = privileges;
    subject
}

fn identity(subject: Subject) -> Subject {
    Subject {
        scope: Scope::Identity,
        ..subject
    }
}

fn mode_of(kind: FileKind, owner: Principal, group: Principal, bits: u16) -> SecurityDescriptor {
    SecurityDescriptor::from_mode(kind, owner, group, FileMode::from_bits_retain(bits)).unwrap()
}

fn file(bits: u16) -> SecurityDescriptor {
    mode_of(FileKind::File, user(1), group(1), bits)
}

fn dir(bits: u16) -> SecurityDescriptor {
    mode_of(FileKind::Directory, user(1), group(1), bits)
}

fn file_acl(entries: Vec<Ace>) -> SecurityDescriptor {
    SecurityDescriptor::from_acl(
        FileKind::File,
        user(1),
        group(1),
        DirectoryFlags::empty(),
        ElevationGrants::empty(),
        entries,
    )
    .unwrap()
}

fn all_of(parts: &[Trustee]) -> AllOf {
    AllOf::new(parts).unwrap()
}

fn single_rights(kind: FileKind) -> impl Iterator<Item = Rights> {
    kind.rights().iter()
}

/// Deterministic xorshift generator for property tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn subset<T: Copy>(&mut self, items: &[T]) -> Vec<T> {
        items
            .iter()
            .copied()
            .filter(|_| self.next() & 1 == 0)
            .collect()
    }
}

const UNIVERSE: [Principal; 5] = [user(1), user(2), group(1), group(2), UNMAPPED];

fn random_trustee(rng: &mut Rng) -> Trustee {
    let principal = rng.pick(&UNIVERSE);
    match rng.below(6) {
        0 => Trustee::Principal(principal),
        1 => Trustee::Owner,
        2 => Trustee::Group,
        3 => Trustee::Everyone,
        4 => Trustee::SubjectOwner(principal),
        _ => Trustee::SubjectGroup(principal),
    }
}

fn random_entries(rng: &mut Rng, kind: FileKind, rights: &[Rights]) -> Vec<Ace> {
    (0..=rng.below(5))
        .map(|_| {
            let parts: Vec<Trustee> = (0..=rng.below(2)).map(|_| random_trustee(rng)).collect();
            let trustee = all_of(&parts);
            let rights = rng.pick(rights) & kind.rights();
            if rng.next() & 1 == 0 {
                Ace::allow(trustee, rights)
            } else {
                Ace::deny(trustee, rights)
            }
        })
        .collect()
}

#[test]
fn mode_selects_the_first_matching_class() {
    // Owner rw-, group ---, other rwx.
    let descriptor = file(0o607);
    let owner = subject(user(1), group(9));
    assert!(descriptor.allows_file(&owner, Rights::READ | Rights::WRITE | Rights::TOUCH));
    assert!(!descriptor.allows_file(&owner, Rights::EXECUTE));
    assert!(!descriptor.allows_file(&subject(user(2), group(1)), Rights::READ));
    let member = with_identities(subject(user(2), group(9)), &[group(1)]);
    assert!(!descriptor.allows_file(&member, Rights::READ));
    // A subject that drops the group gains the other class, as on POSIX, but
    // keeping the group as deny-only still refuses the other-class rights.
    let dropped = subject(user(2), group(9));
    assert!(descriptor.allows_file(&dropped, Rights::READ | Rights::WRITE | Rights::EXECUTE));
    let deny_only = with_deny_only(dropped, &[group(1)]);
    assert_eq!(
        descriptor.granted_file_rights(&deny_only, FileKind::File.rights()),
        Rights::empty()
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Owner,
    Group,
    Other,
}

/// POSIX permission of one class, written per right as in the spec.
fn posix_allows(kind: FileKind, mode: u16, class: Class, right: Rights) -> bool {
    let shift = match class {
        Class::Owner => 6,
        Class::Group => 3,
        Class::Other => 0,
    };
    let bits = (mode >> shift) & 0o7;
    let (r, w, x) = (bits & 0o4 != 0, bits & 0o2 != 0, bits & 0o1 != 0);
    let sticky = kind == FileKind::Directory && mode & 0o1000 != 0;
    if right == Rights::READ || right == Rights::LIST {
        r
    } else if right == Rights::DELETE_CHILD {
        w && (class == Class::Owner || !sticky)
    } else if [
        Rights::WRITE,
        Rights::TOUCH,
        Rights::ADD_ENTRY,
        Rights::REPARENT,
    ]
    .contains(&right)
    {
        w
    } else if right == Rights::EXECUTE || right == Rights::TRAVERSE {
        x
    } else if right == Rights::WRITE_SECURITY || right == Rights::WRITE_ATTRIBUTES {
        class == Class::Owner
    } else {
        false
    }
}

#[test]
fn mode_matches_posix_class_selection() {
    for kind in [FileKind::File, FileKind::Directory] {
        for mode in 0..0o2000 {
            let descriptor = mode_of(kind, user(1), group(1), mode);
            let cases: [(Subject, &[Class]); 7] = [
                (subject(user(1), group(9)), &[Class::Owner]),
                (subject(user(1), group(1)), &[Class::Owner]),
                (subject(user(2), group(1)), &[Class::Group]),
                (
                    with_identities(subject(user(2), group(9)), &[group(1)]),
                    &[Class::Group],
                ),
                (subject(user(2), group(9)), &[Class::Other]),
                // A deny-only class refuses what it lacks.
                (
                    with_deny_only(subject(user(2), group(9)), &[group(1)]),
                    &[Class::Group, Class::Other],
                ),
                (
                    with_deny_only(subject(user(2), group(9)), &[user(1)]),
                    &[Class::Owner, Class::Other],
                ),
            ];
            for (subject, classes) in &cases {
                for right in single_rights(kind) {
                    let expected = classes
                        .iter()
                        .all(|&class| posix_allows(kind, mode, class, right));
                    assert_eq!(
                        descriptor.allows_file(subject, right),
                        expected,
                        "{kind:?} {mode:o} {right:?} {subject:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn clearing_a_mode_bit_never_adds_access() {
    let subjects = [
        subject(user(1), group(9)),
        subject(user(2), group(1)),
        subject(user(2), group(9)),
        subject(UNMAPPED, group(9)),
        with_deny_only(subject(user(2), group(9)), &[user(1), group(1)]),
        with_deny_only(subject(user(2), group(1)), &[user(1)]),
        with_identities(subject(user(2), group(9)), &[user(1)]),
    ];
    let privileges = [
        Privileges::empty(),
        Privileges::READ_ANY | Privileges::EXECUTE_ANY,
        Privileges::WRITE_ANY | Privileges::LOOKUP_ANY,
    ];
    for kind in [FileKind::File, FileKind::Directory] {
        // With and without a modifying search.
        let requests = [kind.rights(), kind.rights() - Rights::MODIFYING];
        for owner in [user(1), UNMAPPED] {
            for mode in 0..0o2000 {
                let descriptor = mode_of(kind, owner, group(1), mode);
                for bit in (0..9).map(|bit| 1 << bit).filter(|bit| mode & bit != 0) {
                    let cleared = mode_of(kind, owner, group(1), mode & !bit);
                    for subject in &subjects {
                        for &privileges in &privileges {
                            let subject = with_privileges(subject.clone(), privileges);
                            for requested in requests {
                                let before = descriptor.granted_file_rights(&subject, requested);
                                let after = cleared.granted_file_rights(&subject, requested);
                                assert!(
                                    before.contains(after),
                                    "{kind:?} {mode:o} -{bit:o} {subject:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn acl_decides_each_bit_at_its_first_matching_entry() {
    let two = subject(user(2), group(9));
    let three = subject(user(3), group(9));
    let descriptor = file_acl(vec![
        Ace::deny(Trustee::Principal(user(2)), Rights::WRITE),
        Ace::allow(Trustee::Everyone, Rights::READ | Rights::WRITE),
    ]);
    assert!(descriptor.allows_file(&two, Rights::READ));
    assert!(!descriptor.allows_file(&two, Rights::READ | Rights::WRITE));
    assert!(descriptor.allows_file(&three, Rights::READ | Rights::WRITE));
    // Undecided rights are denied.
    assert!(!descriptor.allows_file(&three, Rights::EXECUTE));

    // Reversed, the allow decides first.
    let reversed = file_acl(vec![
        Ace::allow(Trustee::Everyone, Rights::READ | Rights::WRITE),
        Ace::deny(Trustee::Principal(user(2)), Rights::WRITE),
    ]);
    assert!(reversed.allows_file(&two, Rights::READ | Rights::WRITE));

    // An entry decides only the rights it names; later entries decide the rest.
    let split = file_acl(vec![
        Ace::allow(Trustee::Principal(user(2)), Rights::READ),
        Ace::deny(Trustee::Everyone, Rights::READ | Rights::WRITE),
        Ace::allow(Trustee::Principal(user(2)), Rights::WRITE | Rights::EXECUTE),
    ]);
    assert_eq!(
        split.granted_file_rights(&two, FileKind::File.rights()),
        Rights::READ | Rights::EXECUTE
    );
}

#[test]
fn trustees_match_their_slots() {
    let descriptor = file_acl(vec![
        Ace::allow(Trustee::SubjectOwner(user(2)), Rights::READ),
        Ace::allow(Trustee::SubjectGroup(group(5)), Rights::WRITE),
        Ace::allow(
            all_of(&[Trustee::Principal(group(6)), Trustee::Group]),
            Rights::EXECUTE,
        ),
        Ace::allow(Trustee::Owner, Rights::TOUCH),
    ]);
    // Slot trustees match the slot, not an identity.
    assert!(descriptor.allows_file(&subject(user(2), group(9)), Rights::READ));
    let named = with_identities(subject(user(3), group(9)), &[user(2), group(5)]);
    assert!(!descriptor.allows_file(&named, Rights::READ));
    assert!(descriptor.allows_file(&subject(user(3), group(5)), Rights::WRITE));
    assert!(!descriptor.allows_file(&named, Rights::WRITE));
    // A conjunction needs every part; Owner@ and Group@ match identities too.
    let both = with_identities(subject(user(3), group(6)), &[group(1)]);
    assert!(descriptor.allows_file(&both, Rights::EXECUTE));
    assert!(!descriptor.allows_file(&subject(user(3), group(6)), Rights::EXECUTE));
    assert!(!descriptor.allows_file(&subject(user(3), group(1)), Rights::EXECUTE));
    let owner = with_identities(subject(user(3), group(9)), &[user(1)]);
    assert!(descriptor.allows_file(&owner, Rights::TOUCH));

    // A deny conjunction matches deny-only principals in any part.
    let denied = file_acl(vec![
        Ace::deny(
            all_of(&[Trustee::Principal(group(5)), Trustee::Principal(group(6))]),
            Rights::READ,
        ),
        Ace::allow(Trustee::Everyone, Rights::READ),
    ]);
    let five = with_identities(subject(user(3), group(9)), &[group(5)]);
    assert!(denied.allows_file(&five, Rights::READ));
    assert!(!denied.allows_file(&with_deny_only(five.clone(), &[group(6)]), Rights::READ));
    // Deny-only principals never match an allow entry.
    let allowed = file_acl(vec![Ace::allow(Trustee::Principal(group(5)), Rights::READ)]);
    assert!(allowed.allows_file(&five, Rights::READ));
    let deny_five = with_deny_only(subject(user(3), group(9)), &[group(5)]);
    assert!(!allowed.allows_file(&deny_five, Rights::READ));
}

#[test]
fn unmapped_principals_never_grant() {
    let unmapped = subject(UNMAPPED, UNMAPPED);
    let other = subject(user(2), group(2));
    // Owner@ and Group@ of an unmapped object never allow, but still deny.
    let descriptor = mode_of(FileKind::File, UNMAPPED, UNMAPPED, 0o707);
    assert!(!descriptor.allows_file(&unmapped, Rights::READ));
    assert!(!descriptor.allows_file(&unmapped, Rights::WRITE_SECURITY));
    assert!(!descriptor.is_owned_by(&unmapped));
    assert!(descriptor.allows_file(&other, Rights::READ));
    let denying = mode_of(FileKind::File, UNMAPPED, group(1), 0o007);
    assert!(!denying.allows_file(&unmapped, Rights::READ));
    assert!(denying.allows_file(&other, Rights::READ));

    for trustee in [
        Trustee::Principal(UNMAPPED),
        Trustee::SubjectOwner(UNMAPPED),
        Trustee::SubjectGroup(UNMAPPED),
    ] {
        let allow = file_acl(vec![Ace::allow(trustee, Rights::READ)]);
        assert!(!allow.allows_file(&unmapped, Rights::READ), "{trustee:?}");
        let deny = file_acl(vec![
            Ace::deny(trustee, Rights::READ),
            Ace::allow(Trustee::Everyone, Rights::READ),
        ]);
        assert!(!deny.allows_file(&unmapped, Rights::READ), "{trustee:?}");
    }
}

#[test]
fn file_requests_fail_closed() {
    let descriptor = file(0o777);
    let anyone = with_privileges(subject(user(2), group(2)), Privileges::all());
    assert!(descriptor.allows_file(&anyone, Rights::READ));
    // Wrong scope, empty, other-kind or unknown requests grant nothing.
    assert!(!descriptor.allows_file(&identity(anyone.clone()), Rights::READ));
    assert!(!descriptor.allows_file(&anyone, Rights::empty()));
    assert!(!descriptor.allows_file(&anyone, Rights::LIST));
    let unknown = Rights::from_bits_retain(1 << 20);
    assert!(!descriptor.allows_file(&anyone, unknown));
    assert_eq!(
        descriptor.granted_file_rights(&anyone, Rights::READ | Rights::TRAVERSE),
        Rights::empty()
    );
    assert_eq!(
        descriptor.granted_file_rights(&anyone, Rights::READ | unknown),
        Rights::empty()
    );
    // Neither Mode nor any privilege grants DELETE or WRITE_OWNER.
    assert!(!descriptor.allows_file(&anyone, Rights::DELETE));
    assert!(!descriptor.allows_file(&anyone, Rights::WRITE_OWNER));
}

#[test]
fn construction_rejects_invalid_descriptors() {
    let mode = |bits| {
        SecurityDescriptor::from_mode(
            FileKind::File,
            user(1),
            group(1),
            FileMode::from_bits_retain(bits),
        )
    };
    assert_eq!(mode(0o100_644), Err(DescriptorError::InvalidMode));
    assert!(mode(0o7777).is_ok());

    let acl = |kind, flags, grants, entries| {
        SecurityDescriptor::from_acl(kind, user(1), group(1), flags, grants, entries)
    };
    let entries = |entries| {
        acl(
            FileKind::File,
            DirectoryFlags::empty(),
            ElevationGrants::empty(),
            entries,
        )
    };
    let entry = Ace::allow(Trustee::Everyone, Rights::READ);
    assert!(entries(vec![entry; MAX_ACL_ENTRIES]).is_ok());
    assert_eq!(
        entries(vec![entry; MAX_ACL_ENTRIES + 1]),
        Err(DescriptorError::TooManyEntries)
    );
    for rights in [Rights::LIST, Rights::from_bits_retain(1 << 20)] {
        assert_eq!(
            entries(vec![Ace::allow(Trustee::Everyone, rights)]),
            Err(DescriptorError::InvalidRights)
        );
    }
    assert_eq!(
        acl(
            FileKind::Directory,
            DirectoryFlags::empty(),
            ElevationGrants::empty(),
            vec![entry],
        ),
        Err(DescriptorError::InvalidRights)
    );
    assert_eq!(
        entries(vec![Ace::allow(
            all_of(&[Trustee::Everyone, Trustee::SameSession]),
            Rights::READ,
        )]),
        Err(DescriptorError::InvalidTrustee)
    );
    for (kind, flags, grants) in [
        (
            FileKind::File,
            DirectoryFlags::INHERIT_GROUP,
            ElevationGrants::empty(),
        ),
        (
            FileKind::Directory,
            DirectoryFlags::empty(),
            ElevationGrants::AS_OWNER,
        ),
        (
            FileKind::Directory,
            DirectoryFlags::from_bits_retain(1 << 7),
            ElevationGrants::empty(),
        ),
        (
            FileKind::File,
            DirectoryFlags::empty(),
            ElevationGrants::from_bits_retain(1 << 7),
        ),
    ] {
        assert_eq!(
            acl(kind, flags, grants, Vec::new()),
            Err(DescriptorError::InvalidFlags)
        );
    }

    assert_eq!(AllOf::new(&[]), Err(DescriptorError::InvalidConjunction));
    assert_eq!(
        AllOf::new(&[Trustee::Everyone; MAX_ALL_OF + 1]),
        Err(DescriptorError::InvalidConjunction)
    );
    assert_eq!(
        all_of(&[Trustee::Owner; MAX_ALL_OF]).parts(),
        &[Trustee::Owner; MAX_ALL_OF]
    );
}

#[test]
fn special_mode_bits_supply_flags_and_grants() {
    let directory = dir(0o3777);
    assert_eq!(directory.directory_flags(), DirectoryFlags::all());
    assert_eq!(directory.elevation_grants(), ElevationGrants::empty());
    assert_eq!(dir(0o4777).directory_flags(), DirectoryFlags::empty());

    assert_eq!(file(0o6755).elevation_grants(), ElevationGrants::all());
    // Set-group-ID without group execute is not an elevation.
    assert_eq!(file(0o6745).elevation_grants(), ElevationGrants::AS_OWNER);
    let sticky = file(0o1777);
    assert_eq!(sticky.elevation_grants(), ElevationGrants::empty());
    assert_eq!(sticky.directory_flags(), DirectoryFlags::empty());
    assert_eq!(sticky.mode(), Some(FileMode::from_bits_retain(0o1777)));
    assert_eq!(sticky.form(), DescriptorForm::Mode);
    assert_eq!(sticky.acl(), None);
}

#[test]
fn profile_bounds_guest_descriptor_forms() {
    let mode = file(0o644);
    let acl = file_acl(Vec::new());
    assert_eq!(acl.form(), DescriptorForm::Acl);
    assert_eq!(acl.acl(), Some(&[][..]));

    let linux = FileSystemProfile::new(StorableForms::MODE).unwrap();
    assert!(linux.admits_guest_descriptor(&mode));
    assert!(!linux.admits_guest_descriptor(&acl));
    let windows = FileSystemProfile::new(StorableForms::ACL).unwrap();
    assert!(!windows.admits_guest_descriptor(&mode));
    assert!(windows.admits_guest_descriptor(&acl));
    let none = FileSystemProfile::new(StorableForms::empty()).unwrap();
    assert!(!none.admits_guest_descriptor(&mode));
    assert_eq!(
        FileSystemProfile::new(StorableForms::from_bits_retain(1 << 5)),
        Err(DescriptorError::InvalidForms)
    );
}

const fn rules(open_gated: Rights, cacheable: Rights) -> HandleRules {
    HandleRules {
        open_gated,
        cacheable,
    }
}

#[test]
fn profiles_accept_only_valid_handle_rules() {
    let linux = FileSystemProfile::new(StorableForms::MODE).unwrap();
    assert_eq!(linux.handle_rules(FileKind::File), HandleRules::LINUX_FILE);
    assert_eq!(
        linux.handle_rules(FileKind::Directory),
        HandleRules::LINUX_DIRECTORY
    );
    let with = |file, directory| {
        FileSystemProfile::with_handle_rules(StorableForms::MODE, file, directory)
    };
    assert_eq!(
        with(HandleRules::LINUX_FILE, HandleRules::LINUX_DIRECTORY),
        Ok(linux)
    );

    let checked = rules(Rights::READ | Rights::WRITE, Rights::empty());
    let profile = with(
        checked,
        rules(Rights::LIST | Rights::TRAVERSE, Rights::TRAVERSE),
    )
    .unwrap();
    assert_eq!(profile.handle_rules(FileKind::File), checked);
    assert_ne!(profile, linux);

    let invalid = [
        // Caching a right that the open does not admit.
        (
            rules(Rights::READ, Rights::READ | Rights::WRITE),
            HandleRules::LINUX_DIRECTORY,
        ),
        // Caching a decision about who may access the object.
        (
            rules(Rights::WRITE_SECURITY, Rights::WRITE_SECURITY),
            HandleRules::LINUX_DIRECTORY,
        ),
        (
            HandleRules::LINUX_FILE,
            rules(Rights::LIST | Rights::WRITE_OWNER, Rights::WRITE_OWNER),
        ),
        // Rights of the other kind.
        (
            rules(Rights::LIST, Rights::empty()),
            HandleRules::LINUX_DIRECTORY,
        ),
        (HandleRules::LINUX_FILE, rules(Rights::READ, Rights::READ)),
        (HandleRules::LINUX_DIRECTORY, HandleRules::LINUX_FILE),
    ];
    for (file, directory) in invalid {
        assert_eq!(
            with(file, directory),
            Err(DescriptorError::InvalidHandleRules),
            "{file:?} {directory:?}"
        );
    }
    // A gated right need not be cached.
    with(
        rules(Rights::WRITE_SECURITY, Rights::empty()),
        HandleRules::LINUX_DIRECTORY,
    )
    .unwrap();
}

#[test]
fn handle_grants_separate_the_mask_admission_and_cache() {
    let opener = subject(user(1), group(1));
    let reader = subject(user(2), group(1));
    let gated = rules(Rights::READ | Rights::WRITE, Rights::READ);
    let all = FileKind::File.rights();
    let read_only = all - Rights::WRITE;

    // A read-write open by the owner caches only the cacheable grant.
    let grants = HandleGrants::admit(
        gated,
        FileKind::File,
        all,
        Rights::READ | Rights::WRITE,
        &file(0o640),
        &opener,
    )
    .unwrap();
    assert_eq!(grants.kind(), FileKind::File);
    assert_eq!(grants.mask(), all);
    assert_eq!(grants.admitted(), Rights::READ | Rights::WRITE);
    assert_eq!(grants.cached(), Rights::READ);
    assert_eq!(grants.decide(Rights::READ), HandleUse::Cached);
    assert_eq!(grants.decide(Rights::WRITE), HandleUse::CheckAtUse);
    assert_eq!(
        grants.decide(Rights::READ | Rights::WRITE),
        HandleUse::CheckAtUse
    );
    assert_eq!(grants.decide(Rights::TOUCH), HandleUse::CheckAtUse);
    assert_eq!(grants.decide(Rights::empty()), HandleUse::Denied);
    assert_eq!(grants.decide(Rights::LIST), HandleUse::Denied);

    // Gated rights that the open does not request leave the mask, ungated ones do not.
    let grants = HandleGrants::admit(
        gated,
        FileKind::File,
        read_only,
        Rights::READ,
        &file(0o640),
        &reader,
    )
    .unwrap();
    assert_eq!(grants.mask(), read_only);
    assert_eq!(grants.decide(Rights::WRITE), HandleUse::Denied);
    assert_eq!(grants.decide(Rights::EXECUTE), HandleUse::CheckAtUse);
    let ungated = HandleGrants::admit(
        rules(Rights::WRITE, Rights::WRITE),
        FileKind::File,
        read_only,
        Rights::READ,
        &file(0o600),
        &reader,
    )
    .unwrap();
    assert_eq!(ungated.admitted(), Rights::empty());
    assert_eq!(ungated.decide(Rights::READ), HandleUse::CheckAtUse);

    // The open needs every requested gated right, of a descriptor of its kind.
    assert!(
        HandleGrants::admit(
            gated,
            FileKind::File,
            all,
            Rights::READ | Rights::WRITE,
            &file(0o640),
            &reader,
        )
        .is_none()
    );
    assert!(
        HandleGrants::admit(
            gated,
            FileKind::File,
            all,
            Rights::READ,
            &dir(0o777),
            &opener
        )
        .is_none()
    );
    assert!(
        HandleGrants::admit(
            HandleRules::LINUX_DIRECTORY,
            FileKind::Directory,
            FileKind::Directory.rights(),
            Rights::LIST,
            &file(0o777),
            &opener,
        )
        .is_none()
    );
}

#[test]
fn handles_use_only_masked_rights_that_are_cached_or_granted_now() {
    let opener = subject(user(1), group(1));
    let other = subject(user(2), group(2));
    let writer = with_privileges(other.clone(), Privileges::WRITE_ANY | Privileges::READ_ANY);
    let all = FileKind::File.rights();
    let grants = HandleGrants::admit(
        rules(Rights::READ | Rights::WRITE, Rights::READ),
        FileKind::File,
        all,
        Rights::READ | Rights::WRITE,
        &file(0o600),
        &opener,
    )
    .unwrap();
    let data = Rights::READ | Rights::WRITE;
    // A cached grant outlives revocation; others follow the current descriptor and subject.
    assert_eq!(
        grants.granted_at_use(&file(0o000), &opener, data),
        Rights::READ
    );
    assert_eq!(grants.granted_at_use(&file(0o600), &opener, data), data);
    assert_eq!(
        grants.granted_at_use(&file(0o600), &other, data),
        Rights::READ
    );
    assert_eq!(grants.granted_at_use(&file(0o606), &other, data), data);
    assert_eq!(
        grants.granted_at_use(&file(0o777), &other, data | Rights::EXECUTE),
        data | Rights::EXECUTE
    );
    // A descriptor of another kind grants nothing uncached.
    assert_eq!(
        grants.granted_at_use(&dir(0o777), &opener, data),
        Rights::READ
    );

    // Nothing outside the mask, whatever the descriptor grants.
    let reader = grants.restrict(all - Rights::WRITE);
    assert_eq!(
        reader.granted_at_use(&file(0o777), &writer, data),
        Rights::READ
    );
    assert_eq!(
        reader.granted_at_use(&file(0o777), &writer, Rights::WRITE),
        Rights::empty()
    );

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let privileges = [
        Privileges::empty(),
        Privileges::READ_ANY | Privileges::WRITE_ANY,
        Privileges::ACT_AS_OWNER,
    ];
    let rights: Vec<Rights> = single_rights(FileKind::File).collect();
    for _ in 0..500 {
        let at_open = file_acl(random_entries(&mut rng, FileKind::File, &rights));
        let at_use = file_acl(random_entries(&mut rng, FileKind::File, &rights));
        let actor = |rng: &mut Rng| {
            with_privileges(
                subject(rng.pick(&UNIVERSE), rng.pick(&UNIVERSE)),
                rng.pick(&privileges),
            )
        };
        let (opener, user) = (actor(&mut rng), actor(&mut rng));
        let pick = |rng: &mut Rng| {
            Rights::from_bits_truncate(u32::try_from(rng.next() >> 32).unwrap()) & all
        };
        let open_gated = pick(&mut rng);
        let handle_rules = rules(
            open_gated,
            open_gated & pick(&mut rng) & !Rights::NEVER_CACHEABLE,
        );
        let (eligible, requested) = (pick(&mut rng), pick(&mut rng));
        let Some(grants) = HandleGrants::admit(
            handle_rules,
            FileKind::File,
            eligible,
            requested,
            &at_open,
            &opener,
        ) else {
            continue;
        };
        let grants = grants.restrict(pick(&mut rng));
        assert!(grants.mask().contains(grants.admitted()));
        assert!(grants.admitted().contains(grants.cached()));
        let asked = pick(&mut rng);
        let granted = grants.granted_at_use(&at_use, &user, asked);
        assert!((asked & grants.mask()).contains(granted));
        assert!(granted.contains(asked & grants.cached()));
        assert!(
            (granted & !grants.cached())
                .difference(at_use.granted_file_rights(&user, asked & !grants.cached()))
                .is_empty()
        );
    }
}

#[test]
fn restricting_handle_grants_only_removes_rights() {
    let all = FileKind::File.rights();
    let grants = HandleGrants::admit(
        HandleRules::LINUX_FILE,
        FileKind::File,
        all,
        Rights::READ | Rights::WRITE,
        &file(0o600),
        &subject(user(1), group(1)),
    )
    .unwrap();
    assert_eq!(grants.cached(), Rights::READ | Rights::WRITE);

    let reader = grants.restrict(Rights::READ | Rights::TOUCH);
    assert_eq!(reader.mask(), Rights::READ | Rights::TOUCH);
    assert_eq!(reader.admitted(), Rights::READ);
    assert_eq!(reader.cached(), Rights::READ);
    assert_eq!(reader.decide(Rights::WRITE), HandleUse::Denied);
    // Restricting again cannot restore a right.
    assert_eq!(reader.restrict(all), reader);
    assert_eq!(reader.restrict(Rights::WRITE).mask(), Rights::empty());

    // Under rules that cache less, cached grants are checked at use; under rules gating more,
    // rights that the open did not admit leave the mask.
    let stricter = grants.restrict_to_rules(rules(
        Rights::READ | Rights::WRITE | Rights::TOUCH,
        Rights::READ,
    ));
    assert_eq!(stricter.mask(), all - Rights::TOUCH);
    assert_eq!(stricter.admitted(), Rights::READ | Rights::WRITE);
    assert_eq!(stricter.cached(), Rights::READ);
    assert_eq!(stricter.decide(Rights::WRITE), HandleUse::CheckAtUse);
    assert_eq!(stricter.decide(Rights::TOUCH), HandleUse::Denied);
    let unchecked = grants.restrict_to_rules(rules(Rights::empty(), Rights::empty()));
    assert_eq!(unchecked.mask(), all);
    assert_eq!(unchecked.cached(), Rights::empty());
    assert_eq!(
        unchecked.restrict_to_rules(HandleRules::LINUX_FILE),
        unchecked
    );
}

#[test]
fn handles_never_cache_a_search_only_lookup_any_granted() {
    let directory_rules = rules(
        Rights::LIST | Rights::TRAVERSE,
        Rights::LIST | Rights::TRAVERSE,
    );
    let private = dir(0o700);
    let admit = |subject: &Subject| {
        HandleGrants::admit(
            directory_rules,
            FileKind::Directory,
            FileKind::Directory.rights(),
            Rights::TRAVERSE,
            &private,
            subject,
        )
    };
    let lookup = with_privileges(subject(user(3), group(3)), Privileges::LOOKUP_ANY);
    let grants = admit(&lookup).unwrap();
    assert_eq!(grants.admitted(), Rights::TRAVERSE);
    assert_eq!(grants.cached(), Rights::empty());
    assert_eq!(grants.decide(Rights::TRAVERSE), HandleUse::CheckAtUse);
    assert_eq!(grants.decide(Rights::LIST), HandleUse::Denied);

    let traverse = with_privileges(lookup, Privileges::TRAVERSE_ANY);
    assert_eq!(admit(&traverse).unwrap().cached(), Rights::TRAVERSE);
    assert_eq!(
        admit(&subject(user(1), group(1))).unwrap().cached(),
        Rights::TRAVERSE
    );
}

#[test]
fn cached_directory_modification_still_requires_a_modifying_search() {
    let subject_at_open = subject(user(1), group(1));
    let lookup = with_privileges(subject(user(3), group(3)), Privileges::LOOKUP_ANY);
    let private = dir(0o700);
    let requested = Rights::ADD_ENTRY | Rights::TRAVERSE;
    let grants = HandleGrants::admit(
        rules(Rights::ADD_ENTRY, Rights::ADD_ENTRY),
        FileKind::Directory,
        FileKind::Directory.rights(),
        requested,
        &private,
        &subject_at_open,
    )
    .unwrap();
    assert_eq!(grants.admitted(), requested);
    assert_eq!(grants.cached(), Rights::ADD_ENTRY);
    assert_eq!(
        grants.granted_at_use(&private, &lookup, Rights::TRAVERSE),
        Rights::TRAVERSE
    );
    assert_eq!(
        grants.granted_at_use(&private, &lookup, requested),
        Rights::ADD_ENTRY
    );
    // A receiving profile can require admission for previously ungated traversal, but cannot cache it.
    let recipient = grants.restrict_to_rules(rules(requested, requested));
    assert_eq!(recipient.decide(Rights::TRAVERSE), HandleUse::CheckAtUse);
}

#[test]
fn created_handles_gain_only_the_gated_rights_they_request() {
    let all = FileKind::File.rights();
    let gated = rules(Rights::READ | Rights::WRITE | Rights::TOUCH, Rights::WRITE);
    let writer = HandleGrants::created(gated, FileKind::File, all - Rights::READ, Rights::WRITE);
    assert_eq!(writer.mask(), all - Rights::READ - Rights::TOUCH);
    assert_eq!(writer.admitted(), Rights::WRITE);
    assert_eq!(writer.cached(), Rights::WRITE);
    let both = HandleGrants::created(gated, FileKind::File, all, Rights::READ | Rights::WRITE);
    assert_eq!(both.admitted(), Rights::READ | Rights::WRITE);
    assert_eq!(both.cached(), Rights::WRITE);
    assert_eq!(both.decide(Rights::READ), HandleUse::CheckAtUse);
    let path = HandleGrants::created(gated, FileKind::File, all, Rights::empty());
    assert_eq!(path.admitted(), Rights::empty());
    assert_eq!(
        path.mask(),
        all - Rights::READ - Rights::WRITE - Rights::TOUCH
    );
}

#[test]
fn lookup_any_never_supplies_a_modifying_search() {
    // Other may write but not search.
    let directory = dir(0o766);
    let child = file(0o644);
    let lookup = with_privileges(subject(user(3), group(3)), Privileges::LOOKUP_ANY);
    assert!(directory.allows_file(&lookup, Rights::TRAVERSE));
    assert!(directory.allows_file(&lookup, Rights::TRAVERSE | Rights::LIST));
    for modifying in [Rights::ADD_ENTRY, Rights::DELETE_CHILD, Rights::REPARENT] {
        assert!(directory.allows_file(&lookup, modifying));
        // The entries grant the modifying right, yet the search is refused.
        assert_eq!(
            directory.granted_file_rights(&lookup, Rights::TRAVERSE | modifying),
            modifying
        );
    }
    assert!(!directory.allows_remove(&child, &lookup));

    let traverse = with_privileges(lookup, Privileges::TRAVERSE_ANY);
    assert!(directory.allows_file(&traverse, Rights::TRAVERSE | Rights::ADD_ENTRY));
    assert!(directory.allows_remove(&child, &traverse));
}

#[test]
fn restricted_deletion_needs_ownership_even_with_write_any() {
    let writer = with_privileges(subject(user(3), group(3)), Privileges::WRITE_ANY);
    let own_child = mode_of(FileKind::File, user(3), group(3), 0o600);
    let other_child = mode_of(FileKind::File, user(4), group(4), 0o600);
    for bits in [0o1777, 0o1755] {
        let sticky = dir(bits);
        assert!(sticky.allows_file(&writer, Rights::TRAVERSE | Rights::ADD_ENTRY));
        assert!(
            !sticky.allows_file(&writer, Rights::DELETE_CHILD),
            "{bits:o}"
        );
        assert!(sticky.allows_remove(&own_child, &writer));
        assert!(!sticky.allows_remove(&other_child, &writer));
        let owner = with_privileges(
            writer.clone(),
            Privileges::WRITE_ANY | Privileges::ACT_AS_OWNER,
        );
        assert!(sticky.allows_remove(&other_child, &owner));
    }
    // Without restricted deletion, WRITE_ANY removes any entry.
    let plain = dir(0o755);
    assert!(plain.allows_file(&writer, Rights::DELETE_CHILD));
    assert!(plain.allows_remove(&other_child, &writer));
    // A directory owner qualifies even when its write comes from WRITE_ANY.
    let owner = subject(user(1), group(9));
    let owner_writer = with_privileges(owner.clone(), Privileges::WRITE_ANY);
    assert!(dir(0o1500).allows_remove(&other_child, &owner_writer));
    assert!(!dir(0o1500).allows_remove(&other_child, &owner));
    // The owner class's w grants DELETE_CHILD despite restricted deletion.
    assert!(dir(0o1700).allows_file(&owner, Rights::DELETE_CHILD));
    assert!(!dir(0o1777).allows_file(&subject(user(3), group(3)), Rights::DELETE_CHILD));
    // An owner held only as deny-only does not count as owning.
    let deny_owner = with_deny_only(subject(user(5), group(3)), &[user(3)]);
    assert!(!dir(0o1777).allows_remove(&own_child, &deny_owner));
}

#[test]
fn remove_accepts_delete_on_the_entry() {
    let deletable = file_acl(vec![Ace::allow(Trustee::Everyone, Rights::DELETE)]);
    let other = subject(user(3), group(3));
    assert!(dir(0o755).allows_remove(&deletable, &other));
    assert!(!dir(0o754).allows_remove(&deletable, &other));
    assert!(!dir(0o755).allows_remove(&file(0o777), &other));
    assert!(!file(0o777).allows_remove(&deletable, &other));
}

/// Whether any unprivileged subject over the test universe executes
/// `descriptor`. Principals outside the universe stand for fresh ones.
fn some_subject_executes(descriptor: &SecurityDescriptor) -> bool {
    let owners = [user(1), user(2), group(1), group(2), UNMAPPED, user(9)];
    let groups = [user(1), user(2), group(1), group(2), UNMAPPED, group(9)];
    owners.iter().any(|&owner| {
        groups.iter().any(|&group| {
            (0..1u32 << UNIVERSE.len()).any(|bits| {
                let identities: Vec<Principal> = UNIVERSE
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| bits & (1 << index) != 0)
                    .map(|(_, &principal)| principal)
                    .collect();
                descriptor.allows_file(
                    &with_identities(subject(owner, group), &identities),
                    Rights::EXECUTE,
                )
            })
        })
    })
}

fn execute_any(descriptor: &SecurityDescriptor) -> bool {
    let privileged = with_privileges(
        subject(user(8), group(8)),
        Privileges::READ_ANY | Privileges::EXECUTE_ANY,
    );
    descriptor.allows_file(&privileged, Rights::EXECUTE)
}

#[test]
fn execute_any_needs_execute_reachable_through_the_walk() {
    assert!(!execute_any(&file(0o644)));
    for bits in [0o100, 0o010] {
        assert!(execute_any(&file(bits)), "{bits:o}");
    }
    let other_execute = file(0o001);
    let owner = subject(other_execute.owner(), group(8));
    assert!(!other_execute.allows_file(&owner, Rights::EXECUTE));
    let privileged_owner = with_privileges(owner, Privileges::READ_ANY | Privileges::EXECUTE_ANY);
    assert!(other_execute.allows_file(&privileged_owner, Rights::EXECUTE));
    // Owner and group are one principal, so the owner class shadows group x.
    assert!(!execute_any(&mode_of(
        FileKind::File,
        user(1),
        user(1),
        0o010
    )));
    assert!(!execute_any(&mode_of(
        FileKind::File,
        UNMAPPED,
        group(1),
        0o100
    )));

    let execute = |entries| execute_any(&file_acl(entries));
    let allow = |trustee: AllOf| Ace::allow(trustee, Rights::EXECUTE);
    let deny = |trustee: AllOf| Ace::deny(trustee, Rights::EXECUTE);
    let everyone = AllOf::from(Trustee::Everyone);
    let named = |principal| AllOf::from(Trustee::Principal(principal));
    // Shadowed by an earlier deny that matches every subject the allow does.
    assert!(!execute(vec![deny(everyone), allow(everyone)]));
    assert!(!execute(vec![
        deny(named(user(2))),
        allow(Trustee::SubjectOwner(user(2)).into()),
    ]));
    assert!(!execute(vec![
        deny(Trustee::Owner.into()),
        allow(named(user(1)))
    ]));
    assert!(!execute(vec![
        deny(Trustee::SubjectOwner(user(2)).into()),
        allow(all_of(&[
            Trustee::SubjectOwner(user(2)),
            Trustee::Principal(group(1)),
        ])),
    ]));
    // Impossible allows.
    assert!(!execute(vec![allow(named(UNMAPPED))]));
    assert!(!execute(vec![allow(all_of(&[
        Trustee::SubjectOwner(user(2)),
        Trustee::SubjectOwner(user(3)),
    ]))]));
    assert!(!execute(vec![Ace::allow(Trustee::Everyone, Rights::READ)]));
    // Reachable by some subject the earlier denies miss.
    assert!(execute(vec![deny(named(user(2))), allow(everyone)]));
    assert!(execute(vec![
        deny(all_of(&[
            Trustee::Principal(group(1)),
            Trustee::Principal(group(2)),
        ])),
        allow(named(group(1))),
    ]));
    assert!(execute(vec![
        allow(named(user(2))),
        deny(everyone),
        allow(everyone),
    ]));

    // EXECUTE_ANY never supplies a directory search.
    let searcher = with_privileges(
        subject(user(8), group(8)),
        Privileges::READ_ANY | Privileges::EXECUTE_ANY,
    );
    assert!(!dir(0o700).allows_file(&searcher, Rights::TRAVERSE));
}

#[test]
fn cached_execute_reachability_matches_exhaustive_search() {
    for (owner, group) in [
        (user(1), group(1)),
        (user(1), user(1)),
        (UNMAPPED, group(1)),
        (user(1), UNMAPPED),
    ] {
        for x in 0..8 {
            let bits = 0o644 | ((x & 4) << 4) | ((x & 2) << 2) | (x & 1);
            let descriptor = mode_of(FileKind::File, owner, group, bits);
            assert_eq!(
                descriptor.executable,
                some_subject_executes(&descriptor),
                "{owner:?} {group:?} {bits:o}"
            );
        }
    }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let rights = [
        Rights::EXECUTE,
        Rights::READ | Rights::EXECUTE,
        Rights::READ,
    ];
    for _ in 0..300 {
        let owner = rng.pick(&UNIVERSE);
        let group = rng.pick(&UNIVERSE);
        let entries = random_entries(&mut rng, FileKind::File, &rights);
        let descriptor = SecurityDescriptor::from_acl(
            FileKind::File,
            owner,
            group,
            DirectoryFlags::empty(),
            ElevationGrants::empty(),
            entries,
        )
        .unwrap();
        assert_eq!(
            descriptor.executable,
            some_subject_executes(&descriptor),
            "{descriptor:?}"
        );
    }
}

#[test]
fn restricting_an_acl_or_subject_never_adds_access() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let privileges = [
        Privileges::empty(),
        Privileges::LOOKUP_ANY,
        Privileges::WRITE_ANY | Privileges::READ_ANY | Privileges::EXECUTE_ANY,
        Privileges::ACT_AS_OWNER | Privileges::TRAVERSE_ANY,
    ];
    let principals = [
        user(1),
        user(2),
        user(3),
        group(1),
        group(2),
        group(3),
        UNMAPPED,
    ];
    for _ in 0..500 {
        let kind = rng.pick(&[FileKind::File, FileKind::Directory]);
        let rights: Vec<Rights> = (0..4)
            .map(|_| Rights::from_bits_truncate(u32::try_from(rng.next() >> 32).unwrap()))
            .collect();
        let entries = random_entries(&mut rng, kind, &rights);
        let flags = if kind == FileKind::Directory && rng.next() & 1 == 0 {
            DirectoryFlags::RESTRICTED_DELETION
        } else {
            DirectoryFlags::empty()
        };
        let build = |entries: Vec<Ace>| {
            SecurityDescriptor::from_acl(
                kind,
                user(1),
                group(1),
                flags,
                ElevationGrants::empty(),
                entries,
            )
            .unwrap()
        };
        let descriptor = build(entries.clone());
        let mut actor = with_deny_only(
            with_identities(
                subject(rng.pick(&principals), rng.pick(&principals)),
                &rng.subset(&principals),
            ),
            &rng.subset(&principals),
        );
        actor.privileges = rng.pick(&privileges);
        let requests: Vec<Rights> = single_rights(kind).chain([kind.rights()]).collect();
        let granted = |descriptor: &SecurityDescriptor, actor: &Subject| {
            requests
                .iter()
                .map(|&requested| descriptor.granted_file_rights(actor, requested))
                .collect::<Vec<_>>()
        };
        let before = granted(&descriptor, &actor);
        let within_before = |after: Vec<Rights>| {
            before
                .iter()
                .zip(after)
                .all(|(before, after)| before.contains(after))
        };

        for (index, _) in entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.kind == AceKind::Allow)
        {
            let mut fewer = entries.clone();
            fewer.remove(index);
            assert!(
                within_before(granted(&build(fewer), &actor)),
                "{entries:?} -{index} {actor:?}"
            );
        }
        for &moved in &actor.identities {
            let mut restricted = actor.clone();
            restricted.identities.remove(&moved);
            restricted.deny_only.try_insert(moved).unwrap();
            assert!(
                within_before(granted(&descriptor, &restricted)),
                "{entries:?} {moved:?} {actor:?}"
            );
        }
    }
}

#[test]
fn privileges_add_only_their_rights() {
    let other = subject(user(3), group(3));
    let locked = file(0o000);
    let owner_like = with_privileges(other.clone(), Privileges::ACT_AS_OWNER);
    assert_eq!(
        locked.granted_file_rights(&owner_like, FileKind::File.rights()),
        Rights::WRITE_SECURITY | Rights::WRITE_ATTRIBUTES
    );
    assert!(locked.is_owned_by(&owner_like));
    assert!(!locked.is_owned_by(&identity(owner_like)));
    let reader = with_privileges(other.clone(), Privileges::READ_ANY);
    assert_eq!(
        locked.granted_file_rights(&reader, FileKind::File.rights()),
        Rights::READ
    );
    assert_eq!(
        dir(0o000).granted_file_rights(&reader, FileKind::Directory.rights()),
        Rights::LIST
    );
    let writer = with_privileges(other.clone(), Privileges::WRITE_ANY);
    assert_eq!(
        locked.granted_file_rights(&writer, FileKind::File.rights()),
        Rights::WRITE | Rights::TOUCH
    );
    let inert = with_privileges(
        other,
        Privileges::TAKE_OWNERSHIP | Privileges::SET_ANY_OWNER | Privileges::MANAGE_ELEVATION,
    );
    assert_eq!(
        locked.granted_file_rights(&inert, FileKind::File.rights()),
        Rights::empty()
    );
    // The owner class may always change security and attributes.
    let owner = subject(user(1), group(9));
    assert_eq!(
        locked.granted_file_rights(&owner, FileKind::File.rights()),
        Rights::WRITE_SECURITY | Rights::WRITE_ATTRIBUTES
    );
    assert!(locked.is_owned_by(&owner));
}

#[test]
fn signal_masks_distinguish_signals_and_the_probe() {
    assert_eq!(SignalMask::signal(0), None);
    assert_eq!(SignalMask::signal(MAX_SIGNAL + 1), None);
    let last = SignalMask::signal(MAX_SIGNAL).unwrap();
    assert!(last.contains(SignalRequest::Deliver(MAX_SIGNAL)));
    let nine = SignalMask::signal(9).unwrap();
    assert_eq!(SignalMask::from_signal_bits(1 << 8), Some(nine));
    assert!(nine.contains(SignalRequest::Deliver(9)));
    assert!(!nine.contains(SignalRequest::Deliver(10)));
    assert!(!nine.contains(SignalRequest::Probe));
    assert!(SignalMask::PROBE.contains(SignalRequest::Probe));
    assert!(!SignalMask::PROBE.contains(SignalRequest::Deliver(9)));
    assert!(nine.union(SignalMask::PROBE).contains(SignalRequest::Probe));
    for invalid in [0, MAX_SIGNAL + 1, u32::MAX] {
        assert!(!SignalMask::ALL.contains(SignalRequest::Deliver(invalid)));
    }
}

/// A descriptor with separate signal and inspection criteria.
fn sample_process() -> ProcessDescriptor {
    let sigcont = SignalMask::signal(18).unwrap();
    let signal_all = |principal| {
        ProcessAce::allow(
            Trustee::Principal(principal),
            ProcessRights::empty(),
            SignalMask::ALL,
        )
    };
    ProcessDescriptor::new(
        user(1),
        group(1),
        vec![
            signal_all(user(1)),
            signal_all(user(2)),
            ProcessAce::allow(Trustee::SameSession, ProcessRights::empty(), sigcont),
            ProcessAce::allow(
                all_of(&[
                    Trustee::SubjectOwner(user(1)),
                    Trustee::SubjectGroup(group(1)),
                ]),
                ProcessRights::all(),
                SignalMask::EMPTY,
            ),
        ],
    )
    .unwrap()
}

#[test]
fn process_descriptor_checks_signals() {
    let process = sample_process();
    let ruid = identity(subject(user(1), group(9)));
    assert!(process.allows_signal(&ruid, SignalRequest::Deliver(9), false));
    assert!(process.allows_signal(&ruid, SignalRequest::Probe, false));
    // Signals need the Identity scope.
    let access = subject(user(1), group(9));
    assert!(!process.allows_signal(&access, SignalRequest::Probe, false));

    let stranger = identity(subject(user(3), group(3)));
    assert!(!process.allows_signal(&stranger, SignalRequest::Deliver(18), false));
    assert!(process.allows_signal(&stranger, SignalRequest::Deliver(18), true));
    assert!(!process.allows_signal(&stranger, SignalRequest::Deliver(9), true));
    assert!(!process.allows_signal(&stranger, SignalRequest::Probe, true));

    let any = with_privileges(stranger.clone(), Privileges::SIGNAL_ANY);
    assert!(process.allows_signal(&any, SignalRequest::Deliver(5), false));
    assert!(!process.allows_signal(&any, SignalRequest::Deliver(0), false));
    let any_access = with_privileges(access, Privileges::SIGNAL_ANY);
    assert!(!process.allows_signal(&any_access, SignalRequest::Probe, false));

    // A deny entry decides only the signals in its mask.
    let denying = ProcessDescriptor::new(
        user(1),
        group(1),
        vec![
            ProcessAce::deny(
                Trustee::Principal(group(5)),
                ProcessRights::empty(),
                SignalMask::signal(9).unwrap(),
            ),
            ProcessAce::allow(Trustee::Everyone, ProcessRights::empty(), SignalMask::ALL),
        ],
    )
    .unwrap();
    let restricted = with_deny_only(stranger, &[group(5)]);
    assert!(!denying.allows_signal(&restricted, SignalRequest::Deliver(9), false));
    assert!(denying.allows_signal(&restricted, SignalRequest::Deliver(15), false));
    assert!(denying.allows_signal(&restricted, SignalRequest::Probe, false));
}

#[test]
fn process_descriptor_checks_inspect_and_control() {
    let process = sample_process();
    let all = ProcessRights::all();
    // Either scope works; the group must be the slot, not an identity.
    assert!(process.allows_process(&subject(user(1), group(1)), all, false));
    assert!(process.allows_process(&identity(subject(user(1), group(1))), all, false));
    let member = with_identities(subject(user(1), group(2)), &[group(1)]);
    assert!(!process.allows_process(&member, all, false));
    assert!(!process.allows_process(&subject(user(2), group(1)), ProcessRights::INSPECT, false));

    let tracer = with_privileges(subject(user(3), group(3)), Privileges::TRACE_ANY);
    assert!(process.allows_process(&tracer, all, false));
    assert!(!process.allows_process(&tracer, ProcessRights::empty(), false));
    assert!(!process.allows_process(&tracer, ProcessRights::from_bits_retain(1 << 5), false));
    let empty = ProcessDescriptor::new(user(1), group(1), vec![]).unwrap();
    assert!(!empty.allows_process(&subject(user(1), group(1)), all, false));
}

#[test]
fn process_owner_and_group_match_memberships_and_deny_only() {
    let descriptor = ProcessDescriptor::new(
        user(1),
        group(1),
        vec![
            ProcessAce::deny(Trustee::Group, ProcessRights::CONTROL, SignalMask::EMPTY),
            ProcessAce::allow(Trustee::Owner, ProcessRights::all(), SignalMask::ALL),
        ],
    )
    .unwrap();
    let member = identity(with_identities(subject(user(2), group(2)), &[user(1)]));
    assert!(descriptor.allows_process(&member, ProcessRights::all(), false));
    let restricted = with_deny_only(member, &[group(1)]);
    assert!(!descriptor.allows_process(&restricted, ProcessRights::CONTROL, false));
    assert!(descriptor.allows_process(&restricted, ProcessRights::INSPECT, false));
    let deny_only_owner = identity(with_deny_only(subject(user(2), group(2)), &[user(1)]));
    assert!(!descriptor.allows_signal(&deny_only_owner, SignalRequest::Probe, false));
}

#[test]
fn process_descriptor_rejects_invalid_entries() {
    let allow = |trustee: AllOf, rights| ProcessAce::allow(trustee, rights, SignalMask::EMPTY);
    assert_eq!(
        ProcessDescriptor::new(
            user(1),
            group(1),
            vec![allow(
                Trustee::Everyone.into(),
                ProcessRights::from_bits_retain(1 << 5)
            )]
        ),
        Err(DescriptorError::InvalidRights)
    );
    let entry = allow(Trustee::SameSession.into(), ProcessRights::INSPECT);
    assert!(ProcessDescriptor::new(user(1), group(1), vec![entry; MAX_ACL_ENTRIES]).is_ok());
    assert_eq!(
        ProcessDescriptor::new(user(1), group(1), vec![entry; MAX_ACL_ENTRIES + 1]),
        Err(DescriptorError::TooManyEntries)
    );
}

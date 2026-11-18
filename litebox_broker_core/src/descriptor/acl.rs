// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Entries, trustees and the first-match walk shared by every descriptor.

use core::fmt;

use litebox_broker_protocol::authority::{DomainId, Principal, Subject};

use super::{DescriptorError, Rights};

/// Maximum number of entries in one ACL.
pub const MAX_ACL_ENTRIES: usize = 128;

/// Maximum number of trustees in one [`AllOf`].
pub const MAX_ALL_OF: usize = 4;

/// Whether an entry grants or refuses the rights it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AceKind {
    /// Grant the named rights that are still undecided.
    Allow,
    /// Refuse the named rights that are still undecided.
    Deny,
}

/// One condition on the subject.
///
/// "Holds" means the principal is the subject's owner, its group or one of its
/// identities. An allow entry never matches a principal of
/// [`DomainId::UNMAPPED`]. A deny entry also matches the subject's deny-only
/// principals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Trustee {
    /// The subject holds this principal.
    Principal(Principal),
    /// The subject holds the object's owner.
    Owner,
    /// The subject holds the object's group.
    Group,
    /// Any subject.
    Everyone,
    /// The subject's owner slot is this principal; identities do not count.
    SubjectOwner(Principal),
    /// The subject's group slot is this principal; identities do not count.
    SubjectGroup(Principal),
    /// The caller is in the target process's session. Process objects only.
    SameSession,
}

/// A conjunction of one to [`MAX_ALL_OF`] trustees: it matches only when each
/// trustee matches under the entry's allow or deny rule.
///
/// Trustees are not nested, so matching never recurses.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllOf {
    len: u8,
    /// Slots past `len` are [`Trustee::Everyone`].
    parts: [Trustee; MAX_ALL_OF],
}

impl AllOf {
    /// The conjunction of `parts`, which must have one to [`MAX_ALL_OF`]
    /// trustees.
    pub fn new(parts: &[Trustee]) -> Result<Self, DescriptorError> {
        if parts.is_empty() || parts.len() > MAX_ALL_OF {
            return Err(DescriptorError::InvalidConjunction);
        }
        let len = u8::try_from(parts.len()).map_err(|_| DescriptorError::InvalidConjunction)?;
        let mut all = Self {
            len,
            parts: [Trustee::Everyone; MAX_ALL_OF],
        };
        all.parts[..parts.len()].copy_from_slice(parts);
        Ok(all)
    }

    /// The trustees, in order.
    #[must_use]
    pub fn parts(&self) -> &[Trustee] {
        &self.parts[..usize::from(self.len)]
    }
}

impl From<Trustee> for AllOf {
    fn from(trustee: Trustee) -> Self {
        let mut parts = [Trustee::Everyone; MAX_ALL_OF];
        parts[0] = trustee;
        Self { len: 1, parts }
    }
}

impl fmt::Debug for AllOf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AllOf").field(&self.parts()).finish()
    }
}

/// An entry of a file-system ACL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ace {
    /// Whether the entry grants or refuses.
    pub kind: AceKind,
    /// Which subjects the entry applies to.
    pub trustee: AllOf,
    /// The rights the entry decides.
    pub rights: Rights,
}

impl Ace {
    /// An entry granting `rights` to `trustee`.
    pub fn allow(trustee: impl Into<AllOf>, rights: Rights) -> Self {
        Self {
            kind: AceKind::Allow,
            trustee: trustee.into(),
            rights,
        }
    }

    /// An entry refusing `rights` to `trustee`.
    pub fn deny(trustee: impl Into<AllOf>, rights: Rights) -> Self {
        Self {
            kind: AceKind::Deny,
            trustee: trustee.into(),
            rights,
        }
    }
}

pub(super) fn mapped(principal: Principal) -> bool {
    principal.domain != DomainId::UNMAPPED
}

/// Whether `subject` holds `principal` as its owner, group or an identity.
pub(super) fn held(subject: &Subject, principal: Principal) -> bool {
    subject.owner == principal
        || subject.group == principal
        || subject.identities.contains(&principal)
}

/// What trustees are matched against.
pub(super) struct Context<'a> {
    pub(super) subject: &'a Subject,
    pub(super) owner: Principal,
    pub(super) group: Principal,
    pub(super) same_session: bool,
}

impl Context<'_> {
    fn holds(&self, principal: Principal, kind: AceKind) -> bool {
        match kind {
            AceKind::Allow => mapped(principal) && held(self.subject, principal),
            AceKind::Deny => {
                held(self.subject, principal) || self.subject.deny_only.contains(&principal)
            }
        }
    }

    fn matches_one(&self, trustee: Trustee, kind: AceKind) -> bool {
        let slot_is = |slot: Principal, principal: Principal| {
            slot == principal && (kind == AceKind::Deny || mapped(principal))
        };
        match trustee {
            Trustee::Principal(principal) => self.holds(principal, kind),
            Trustee::Owner => self.holds(self.owner, kind),
            Trustee::Group => self.holds(self.group, kind),
            Trustee::Everyone => true,
            Trustee::SubjectOwner(principal) => slot_is(self.subject.owner, principal),
            Trustee::SubjectGroup(principal) => slot_is(self.subject.group, principal),
            Trustee::SameSession => self.same_session,
        }
    }

    fn matches(&self, trustee: &AllOf, kind: AceKind) -> bool {
        trustee
            .parts()
            .iter()
            .all(|&part| self.matches_one(part, kind))
    }
}

/// Walks `entries` once, each given as its kind, trustee and the bits it
/// names. Returns the bits of `requested` whose first matching entry naming
/// them is an allow entry.
pub(super) fn walk<'e>(
    entries: impl IntoIterator<Item = (AceKind, &'e AllOf, u32)>,
    context: &Context<'_>,
    requested: u32,
) -> u32 {
    let mut undecided = requested;
    let mut granted = 0;
    for (kind, trustee, named) in entries {
        if undecided == 0 {
            break;
        }
        let deciding = named & undecided;
        if deciding == 0 || !context.matches(trustee, kind) {
            continue;
        }
        if kind == AceKind::Allow {
            granted |= deciding;
        }
        undecided &= !deciding;
    }
    granted
}

/// Whether the walk of some subject over the file-system `entries` grants
/// `right`, a single right.
///
/// For each allow entry naming `right`, this builds the subject that entry
/// matches with the fewest principals: exactly the principals and slots its
/// trustees require, with no deny-only principals and fresh principals in
/// unconstrained slots. Every other subject the entry matches also matches
/// each deny entry this one matches, so `right` is reachable through the
/// entry if and only if no earlier deny entry naming `right` matches it.
pub(super) fn is_reachable(
    entries: &[Ace],
    owner_group: (Principal, Principal),
    right: Rights,
) -> bool {
    entries.iter().enumerate().any(|(index, entry)| {
        entry.kind == AceKind::Allow
            && entry.rights.contains(right)
            && Witness::new(&entry.trustee, owner_group).is_some_and(|witness| {
                !entries[..index].iter().any(|earlier| {
                    earlier.kind == AceKind::Deny
                        && earlier.rights.contains(right)
                        && witness.matches(&earlier.trustee, owner_group)
                })
            })
    })
}

/// The least subject an allow trustee matches. Unconstrained slots hold
/// principals that appear nowhere in the descriptor.
struct Witness {
    owner: Option<Principal>,
    group: Option<Principal>,
    len: usize,
    required: [Principal; MAX_ALL_OF],
}

impl Witness {
    /// Returns `None` if no subject matches `trustee` in an allow entry.
    fn new(trustee: &AllOf, (owner, group): (Principal, Principal)) -> Option<Self> {
        let mut witness = Self {
            owner: None,
            group: None,
            len: 0,
            required: [Principal::UNMAPPED; MAX_ALL_OF],
        };
        for &part in trustee.parts() {
            match part {
                Trustee::Everyone => {}
                Trustee::Principal(principal) => witness.require(principal)?,
                Trustee::Owner => witness.require(owner)?,
                Trustee::Group => witness.require(group)?,
                Trustee::SubjectOwner(principal) => fix(&mut witness.owner, principal)?,
                Trustee::SubjectGroup(principal) => fix(&mut witness.group, principal)?,
                // Never stored on a file-system object.
                Trustee::SameSession => return None,
            }
        }
        Some(witness)
    }

    fn require(&mut self, principal: Principal) -> Option<()> {
        if !mapped(principal) {
            return None;
        }
        self.required[self.len] = principal;
        self.len += 1;
        Some(())
    }

    fn holds(&self, principal: Principal) -> bool {
        self.owner == Some(principal)
            || self.group == Some(principal)
            || self.required[..self.len].contains(&principal)
    }

    /// Whether a deny entry with `trustee` matches this subject.
    fn matches(&self, trustee: &AllOf, (owner, group): (Principal, Principal)) -> bool {
        trustee.parts().iter().all(|&part| match part {
            Trustee::Everyone => true,
            Trustee::Principal(principal) => self.holds(principal),
            Trustee::Owner => self.holds(owner),
            Trustee::Group => self.holds(group),
            Trustee::SubjectOwner(principal) => self.owner == Some(principal),
            Trustee::SubjectGroup(principal) => self.group == Some(principal),
            Trustee::SameSession => false,
        })
    }
}

/// Fixes a slot to `principal`, failing if it is unmapped or already differs.
fn fix(slot: &mut Option<Principal>, principal: Principal) -> Option<()> {
    if !mapped(principal) || slot.is_some_and(|fixed| fixed != principal) {
        return None;
    }
    *slot = Some(principal);
    Some(())
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-neutral credential values shared by LiteBox and the broker.
//! A term describes proposed authority; possession of these values grants nothing.

use alloc::collections::BTreeSet;
use bitflags::bitflags;

/// A principal namespace. Non-reserved numbers are local to a broker instance,
/// not stable identifiers for persistent storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(pub u32);

impl DomainId {
    /// Reserved for unmapped object identities; never a source of authority.
    pub const UNMAPPED: Self = Self(0);
    /// The namespace for POSIX user IDs.
    pub const POSIX_USER: Self = Self(1);
    /// The namespace for POSIX group IDs.
    pub const POSIX_GROUP: Self = Self(2);
}

/// An opaque identity; equality includes the domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal {
    /// Namespace that gives `id` its meaning.
    pub domain: DomainId,
    /// Identifier within that namespace.
    pub id: u32,
}

impl Principal {
    /// Placeholder used on an object when its owner or group cannot be mapped.
    pub const UNMAPPED: Self = Self {
        domain: DomainId::UNMAPPED,
        id: 0,
    };
}

/// Exact principals plus wildcards for entire domains. There is no wildcard
/// across domains, so a newly registered domain cannot enter an existing set.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrincipalSet {
    /// Individually named principals.
    pub exact: BTreeSet<Principal>,
    /// Domains whose every principal is included.
    pub domains: BTreeSet<DomainId>,
}

impl PrincipalSet {
    /// Whether this set names `principal` exactly or via its domain.
    pub fn contains(&self, principal: &Principal) -> bool {
        self.domains.contains(&principal.domain) || self.exact.contains(principal)
    }
}

bitflags! {
    /// Operation-specific privileges. No bit implies general administrative access.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Privileges: u32 {
        /// Read files or list directories.
        const READ_ANY         = 1 << 0;
        /// Search a directory except as part of a change to its entries.
        const LOOKUP_ANY       = 1 << 1;
        /// Search a directory, including for an entry change. Implies LOOKUP_ANY.
        const TRAVERSE_ANY     = 1 << 2;
        /// Override file or directory write permissions, not ownership checks.
        const WRITE_ANY        = 1 << 3;
        /// Execute when the descriptor grants execute to someone. Requires READ_ANY in a term.
        const EXECUTE_ANY      = 1 << 4;
        /// Override owner checks on security, attributes and restricted deletion, not group changes.
        const ACT_AS_OWNER     = 1 << 5;
        /// Set an object's owner to the subject's owner.
        const TAKE_OWNERSHIP   = 1 << 6;
        /// Assign an arbitrary owner or group.
        const SET_ANY_OWNER    = 1 << 7;
        /// Manage group inheritance and elevation grants; not permission to exercise a grant.
        const MANAGE_ELEVATION = 1 << 8;
        /// Override the signal descriptor check, not target visibility or confinement.
        const SIGNAL_ANY       = 1 << 9;
        /// Override private-process descriptor checks, not confinement or credential dominance.
        const TRACE_ANY        = 1 << 10;
        /// Create a namespace.
        const CREATE_NAMESPACE = 1 << 11;
        /// Change the host name.
        const SET_HOST_NAME    = 1 << 12;
        /// Raise hard resource limits within the sandbox ceiling.
        const RAISE_LIMITS     = 1 << 13;
        /// Bind a reserved port, subject to sandbox policy.
        const BIND_RESERVED_PORT = 1 << 14;
    }
}

/// Which owner and group choices apply. The operation, not just the caller,
/// determines which scopes it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Accessing a file-system object.
    Access,
    /// Acting as an identity toward another process.
    Identity,
}

/// The subject a process proposes to use for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    /// Selects one pair of slots in each candidate term.
    pub scope: Scope,
    /// Selected owner, always held.
    pub owner: Principal,
    /// Selected primary group, always held.
    pub group: Principal,
    /// Enabled memberships, distinct from the owner and group slots.
    pub identities: BTreeSet<Principal>,
    /// Additional principals to match for deny entries, never a membership claim.
    pub deny_only: BTreeSet<Principal>,
    /// Privileges used for this request.
    pub privileges: Privileges,
}

/// Principals selectable for each slot, not interchangeable with memberships.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slots {
    /// Choices for the subject's owner.
    pub owners: PrincipalSet,
    /// Choices for the subject's primary group.
    pub groups: PrincipalSet,
}

/// One set of jointly reachable subject choices. Different terms are
/// alternatives; taking a privilege from one and an identity from another is invalid.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Term {
    /// Slots available to access-scoped requests.
    pub access: Slots,
    /// Slots available to identity-scoped requests.
    pub identity: Slots,
    /// Memberships that must be present, either enabled or deny-only.
    pub required: BTreeSet<Principal>,
    /// Memberships that may be enabled in addition to the required ones.
    pub optional: PrincipalSet,
    /// Principals that must always be deny-only.
    pub deny_only: BTreeSet<Principal>,
    /// Privileges reachable together with this term's identity choices.
    pub privileges: Privileges,
}

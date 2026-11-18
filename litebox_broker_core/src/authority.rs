// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The credential boundary is a union of terms, not a bag of principals.
//! Dropping a membership can gain access (e.g. by selecting a different mode
//! class), so a restriction must preserve identities the caller cannot drop.
//! Each new term must fit in one old term, in both scopes. This also makes
//! restriction transitive without depending on any particular object descriptor.

use alloc::collections::BTreeSet;
use litebox_broker_protocol::authority::{
    DomainId, Principal, PrincipalSet, Privileges, Scope, Slots, Subject, Term,
};
use thiserror::Error;

/// Maximum number of distinct terms, including subsumed but nonidentical
/// terms. Allows old and new pairs to coexist during a multithreaded change.
pub const MAX_TERMS: usize = 16;

/// Reason a proposed authority was rejected.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AuthorityError {
    #[error("unmapped principals cannot appear in authority")]
    UnmappedPrincipal,
    #[error("a mandatory deny-only principal can also be enabled")]
    DenyOnlyOverlap,
    #[error("invalid privilege set")]
    InvalidPrivileges,
    #[error("too many distinct authority terms")]
    TooManyTerms,
    #[error("proposed authority is not a restriction")]
    NotRestriction,
}

/// Validated credential authority. Only the broker decides which authority
/// to assign initially; changing it in place can only narrow it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Authority {
    terms: BTreeSet<Term>,
}

impl Authority {
    /// Validate and deduplicate terms. An empty authority admits no subjects.
    pub fn new(terms: impl IntoIterator<Item = Term>) -> Result<Self, AuthorityError> {
        let mut distinct = BTreeSet::new();
        for mut term in terms {
            validate_and_normalize(&mut term)?;
            distinct.insert(term);
            if distinct.len() > MAX_TERMS {
                return Err(AuthorityError::TooManyTerms);
            }
        }
        Ok(Self { terms: distinct })
    }

    /// The validated terms; no cross-term subsumption or merging is performed.
    pub fn terms(&self) -> impl ExactSizeIterator<Item = &Term> {
        self.terms.iter()
    }

    /// Whether one term admits this whole subject. Callers must also require
    /// the appropriate scope and check the operation against its object.
    pub fn admits(&self, subject: &Subject) -> bool {
        // All enabled identities and both slots are already bounded by terms.
        // Extra deny-only identities are not, but even they must be mapped.
        subject.deny_only.iter().copied().all(mapped)
            && self.terms.iter().any(|term| admits(term, subject))
    }

    /// Whether every term fits in one term of `other`. This compares
    /// credentials, not confinement contexts or file services.
    pub fn is_restriction_of(&self, other: &Self) -> bool {
        self.terms
            .iter()
            .all(|new| other.terms.iter().any(|old| restricts(new, old)))
    }

    /// Replace this authority only if the entire proposal is a valid restriction.
    pub fn restrict(
        &mut self,
        terms: impl IntoIterator<Item = Term>,
    ) -> Result<(), AuthorityError> {
        let proposed = Self::new(terms)?;
        if !proposed.is_restriction_of(self) {
            return Err(AuthorityError::NotRestriction);
        }
        *self = proposed;
        Ok(())
    }
}

fn mapped(p: Principal) -> bool {
    p.domain != DomainId::UNMAPPED
}

fn validate_and_normalize(term: &mut Term) -> Result<(), AuthorityError> {
    if !Privileges::all().contains(term.privileges)
        || (term.privileges.contains(Privileges::EXECUTE_ANY)
            && !term.privileges.contains(Privileges::READ_ANY))
    {
        return Err(AuthorityError::InvalidPrivileges);
    }
    if term.privileges.contains(Privileges::TRAVERSE_ANY) {
        term.privileges.insert(Privileges::LOOKUP_ANY);
    }
    if !term
        .required
        .iter()
        .chain(&term.deny_only)
        .copied()
        .all(mapped)
    {
        return Err(AuthorityError::UnmappedPrincipal);
    }
    if !term.required.is_disjoint(&term.deny_only) {
        return Err(AuthorityError::DenyOnlyOverlap);
    }
    for set in [
        &mut term.access.owners,
        &mut term.access.groups,
        &mut term.identity.owners,
        &mut term.identity.groups,
        &mut term.optional,
    ] {
        if set.domains.contains(&DomainId::UNMAPPED) || !set.exact.iter().copied().all(mapped) {
            return Err(AuthorityError::UnmappedPrincipal);
        }
        if term.deny_only.iter().any(|p| set.contains(p)) {
            return Err(AuthorityError::DenyOnlyOverlap);
        }
        set.exact.retain(|p| !set.domains.contains(&p.domain));
    }
    term.optional.exact.retain(|p| !term.required.contains(p));
    Ok(())
}

fn may_enable(term: &Term, p: Principal) -> bool {
    term.required.contains(&p) || term.optional.contains(&p)
}

fn admits(term: &Term, subject: &Subject) -> bool {
    let slots = match subject.scope {
        Scope::Access => &term.access,
        Scope::Identity => &term.identity,
    };
    slots.owners.contains(&subject.owner)
        && slots.groups.contains(&subject.group)
        && subject.identities.iter().all(|&p| may_enable(term, p))
        && term
            .required
            .iter()
            .all(|p| subject.identities.contains(p) || subject.deny_only.contains(p))
        && term.deny_only.is_subset(&subject.deny_only)
        && term.privileges.contains(subject.privileges)
}

fn set_within(new: &PrincipalSet, old: &PrincipalSet) -> bool {
    new.domains.is_subset(&old.domains) && new.exact.iter().all(|p| old.contains(p))
}

fn slots_within(new: &Slots, old: &Slots) -> bool {
    set_within(&new.owners, &old.owners) && set_within(&new.groups, &old.groups)
}

fn restricts(new: &Term, old: &Term) -> bool {
    slots_within(&new.access, &old.access)
        && slots_within(&new.identity, &old.identity)
        && new.optional.domains.is_subset(&old.optional.domains)
        && new
            .required
            .iter()
            .chain(&new.optional.exact)
            .all(|&p| may_enable(old, p))
        && old
            .required
            .iter()
            .all(|p| new.required.contains(p) || new.deny_only.contains(p))
        && old.deny_only.is_subset(&new.deny_only)
        && old.privileges.contains(new.privileges)
}

#[cfg(test)]
mod tests;

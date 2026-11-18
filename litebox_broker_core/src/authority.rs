// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The credential boundary is a union of terms, not a bag of principals.
//! Dropping a membership can gain access (e.g. by selecting a different mode
//! class), so a restriction must preserve identities the caller cannot drop.
//! Each new term must fit in one old term, in both scopes. This also makes
//! restriction transitive without depending on any particular object descriptor.

use alloc::vec::Vec;
use litebox_broker_protocol::authority::{
    Principal, PrincipalSet, Scope, Slots, Subject, Term, TermsError, canonical_terms,
};
use thiserror::Error;

mod process;
pub(crate) use process::SubjectObject;

/// Maximum number of distinct canonical terms in an authority.
pub const MAX_TERMS: usize = litebox_broker_protocol::authority::MAX_AUTHORITY_TERMS;

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
    #[error("authority principal set exceeds the size limit")]
    SetTooLarge,
    #[error("proposed authority is not a restriction")]
    NotRestriction,
    #[error("authority allocation failed")]
    OutOfMemory,
}

impl From<TermsError> for AuthorityError {
    fn from(error: TermsError) -> Self {
        match error {
            TermsError::UnmappedPrincipal => Self::UnmappedPrincipal,
            TermsError::DenyOnlyOverlap => Self::DenyOnlyOverlap,
            TermsError::InvalidPrivileges => Self::InvalidPrivileges,
            TermsError::TooManyTerms => Self::TooManyTerms,
            TermsError::SetTooLarge => Self::SetTooLarge,
            TermsError::OutOfMemory => Self::OutOfMemory,
        }
    }
}

/// Validated credential authority. Only the broker decides which authority
/// to assign initially; changing it in place can only narrow it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Authority {
    /// Distinct canonical terms in ascending order.
    terms: Vec<Term>,
}

impl Authority {
    /// Validate terms and keep their distinct [`canonical_terms`]. An empty
    /// authority admits no subjects.
    pub fn new(terms: impl IntoIterator<Item = Term>) -> Result<Self, AuthorityError> {
        Ok(Self {
            terms: canonical_terms(terms)?,
        })
    }

    /// The validated terms; no cross-term subsumption or merging is performed.
    pub fn terms(&self) -> impl ExactSizeIterator<Item = &Term> {
        self.terms.iter()
    }

    /// Whether one term admits this whole subject. Callers must also require
    /// the appropriate scope and check the operation against its object.
    pub fn admits(&self, subject: &Subject) -> bool {
        self.terms.iter().any(|term| admits(term, subject))
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

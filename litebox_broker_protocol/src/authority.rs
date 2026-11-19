// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-neutral credential values shared by LiteBox and the broker.
//! A term describes proposed authority; possession of these values grants nothing.
//!
//! Term lists and subjects travel in shared buffers, encoded by [`EncodedTerms`]
//! and [`EncodedSubject`]. Every set has a protocol ceiling, so any authority of
//! at most [`MAX_AUTHORITY_TERMS`] terms that are [`Term::within_size_limits`]
//! fits in [`MAX_ENCODED_TERMS_SIZE`] bytes. Sets are [`SortedSet`]s, so a
//! peer-sized set never allocates infallibly.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use bitflags::bitflags;
use thiserror::Error;

use crate::ProcessId;
use crate::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence,
};
use crate::wire::{Decoder, Encoder, Wire, WireError};

pub mod sorted_set;
use sorted_set::SortedSet;

/// Maximum number of distinct canonical terms in an authority or a proposed
/// restriction, including subsumed but nonidentical terms. Old and new terms
/// may coexist during a multithreaded change. See [`canonical_terms`].
pub const MAX_AUTHORITY_TERMS: usize = 16;

/// Maximum number of exact principals in one set: [`PrincipalSet::exact`],
/// [`Term::required`], [`Term::deny_only`], [`Subject::identities`] or
/// [`Subject::deny_only`].
pub const MAX_SET_PRINCIPALS: usize = 1024;

/// Maximum number of domain wildcards in one [`PrincipalSet::domains`].
pub const MAX_SET_DOMAINS: usize = 16;

const COUNT_SIZE: usize = u16::MAX_SIZE;
const MAX_PRINCIPAL_LIST_SIZE: usize = COUNT_SIZE + MAX_SET_PRINCIPALS * Principal::MAX_SIZE;
const MAX_PRINCIPAL_SET_SIZE: usize =
    MAX_PRINCIPAL_LIST_SIZE + COUNT_SIZE + MAX_SET_DOMAINS * DomainId::MAX_SIZE;
const MAX_TERM_SIZE: usize = 4 * MAX_PRINCIPAL_SET_SIZE // access and identity slots
    + 2 * MAX_PRINCIPAL_LIST_SIZE // required and deny-only
    + MAX_PRINCIPAL_SET_SIZE // optional
    + Privileges::MAX_SIZE;
/// Smallest encoding of a term: every set empty.
const MIN_TERM_SIZE: usize = 5 * 2 * COUNT_SIZE + 2 * COUNT_SIZE + Privileges::MAX_SIZE;

/// Maximum byte length of [`EncodedTerms`]: [`MAX_AUTHORITY_TERMS`] terms with
/// every set at its ceiling. It spans several shared-buffer slots.
#[allow(clippy::cast_possible_truncation, reason = "checked below")]
pub const MAX_ENCODED_TERMS_SIZE: u32 = (COUNT_SIZE + MAX_AUTHORITY_TERMS * MAX_TERM_SIZE) as u32;

/// Maximum byte length of an [`EncodedSubject`], which fits in one slot.
#[allow(clippy::cast_possible_truncation, reason = "checked below")]
pub const MAX_ENCODED_SUBJECT_SIZE: u32 = (Scope::MAX_SIZE
    + 2 * Principal::MAX_SIZE
    + 2 * MAX_PRINCIPAL_LIST_SIZE
    + Privileges::MAX_SIZE) as u32;

const _: () = {
    assert!(MAX_AUTHORITY_TERMS <= u16::MAX as usize);
    assert!(MAX_SET_PRINCIPALS <= u16::MAX as usize);
    assert!(MAX_SET_DOMAINS <= u16::MAX as usize);
    assert!(
        COUNT_SIZE + MAX_AUTHORITY_TERMS * MAX_TERM_SIZE
            <= MAX_SHARED_BUFFER_SEQUENCE_SLOTS * SHARED_BUFFER_SLOT_SIZE as usize
    );
    assert!(MAX_ENCODED_SUBJECT_SIZE <= SHARED_BUFFER_SLOT_SIZE);
};

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

    /// The POSIX user `id`.
    pub const fn posix_user(id: u32) -> Self {
        Self {
            domain: DomainId::POSIX_USER,
            id,
        }
    }

    /// The POSIX group `id`.
    pub const fn posix_group(id: u32) -> Self {
        Self {
            domain: DomainId::POSIX_GROUP,
            id,
        }
    }

    /// The identifier this principal has in `domain`, or `None` if it is in another domain.
    pub fn id_in(self, domain: DomainId) -> Option<u32> {
        (self.domain == domain).then_some(self.id)
    }
}

/// Exact principals plus wildcards for entire domains. There is no wildcard
/// across domains, so a newly registered domain cannot enter an existing set.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrincipalSet {
    /// Individually named principals.
    pub exact: SortedSet<Principal>,
    /// Domains whose every principal is included.
    pub domains: SortedSet<DomainId>,
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
    pub identities: SortedSet<Principal>,
    /// Additional principals to match for deny entries, never a membership claim.
    pub deny_only: SortedSet<Principal>,
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
    pub required: SortedSet<Principal>,
    /// Memberships that may be enabled in addition to the required ones.
    pub optional: PrincipalSet,
    /// Principals that must always be deny-only.
    pub deny_only: SortedSet<Principal>,
    /// Privileges reachable together with this term's identity choices.
    pub privileges: Privileges,
}

impl PrincipalSet {
    fn within_size_limits(&self) -> bool {
        self.exact.len() <= MAX_SET_PRINCIPALS && self.domains.len() <= MAX_SET_DOMAINS
    }

    fn try_clone(&self) -> Result<Self, TryReserveError> {
        Ok(Self {
            exact: self.exact.try_clone()?,
            domains: self.domains.try_clone()?,
        })
    }

    fn encoded_len(&self) -> usize {
        2 * COUNT_SIZE
            + self.exact.len() * Principal::MAX_SIZE
            + self.domains.len() * DomainId::MAX_SIZE
    }

    fn encode(&self, encoder: &mut Encoder) {
        encode_set(&self.exact, encoder);
        encode_set(&self.domains, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, AuthorityCodecError> {
        Ok(Self {
            exact: decode_set(decoder, MAX_SET_PRINCIPALS)?,
            domains: decode_set(decoder, MAX_SET_DOMAINS)?,
        })
    }
}

impl Slots {
    fn within_size_limits(&self) -> bool {
        self.owners.within_size_limits() && self.groups.within_size_limits()
    }

    fn try_clone(&self) -> Result<Self, TryReserveError> {
        Ok(Self {
            owners: self.owners.try_clone()?,
            groups: self.groups.try_clone()?,
        })
    }

    fn encoded_len(&self) -> usize {
        self.owners.encoded_len() + self.groups.encoded_len()
    }

    fn encode(&self, encoder: &mut Encoder) {
        self.owners.encode(encoder);
        self.groups.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, AuthorityCodecError> {
        Ok(Self {
            owners: PrincipalSet::decode(decoder)?,
            groups: PrincipalSet::decode(decoder)?,
        })
    }
}

impl Term {
    /// Whether every set in this term is within [`MAX_SET_PRINCIPALS`] and
    /// [`MAX_SET_DOMAINS`]. Only such terms can be exchanged with the broker.
    #[must_use]
    pub fn within_size_limits(&self) -> bool {
        self.access.within_size_limits()
            && self.identity.within_size_limits()
            && self.required.len() <= MAX_SET_PRINCIPALS
            && self.optional.within_size_limits()
            && self.deny_only.len() <= MAX_SET_PRINCIPALS
    }

    fn encoded_len(&self) -> usize {
        self.access.encoded_len()
            + self.identity.encoded_len()
            + principal_list_len(&self.required)
            + self.optional.encoded_len()
            + principal_list_len(&self.deny_only)
            + Privileges::MAX_SIZE
    }

    fn encode(&self, encoder: &mut Encoder) {
        self.access.encode(encoder);
        self.identity.encode(encoder);
        encode_set(&self.required, encoder);
        self.optional.encode(encoder);
        encode_set(&self.deny_only, encoder);
        self.privileges.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, AuthorityCodecError> {
        Ok(Self {
            access: Slots::decode(decoder)?,
            identity: Slots::decode(decoder)?,
            required: decode_set(decoder, MAX_SET_PRINCIPALS)?,
            optional: PrincipalSet::decode(decoder)?,
            deny_only: decode_set(decoder, MAX_SET_PRINCIPALS)?,
            privileges: Privileges::decode(decoder)?,
        })
    }

    fn enabled_sets(&self) -> [&PrincipalSet; 5] {
        [
            &self.access.owners,
            &self.access.groups,
            &self.identity.owners,
            &self.identity.groups,
            &self.optional,
        ]
    }

    /// Checks the term as given, before anything is normalized away.
    fn validate(&self) -> Result<(), TermsError> {
        if !self.within_size_limits() {
            return Err(TermsError::SetTooLarge);
        }
        if !Privileges::all().contains(self.privileges)
            || (self.privileges.contains(Privileges::EXECUTE_ANY)
                && !self.privileges.contains(Privileges::READ_ANY))
        {
            return Err(TermsError::InvalidPrivileges);
        }
        if !self
            .required
            .iter()
            .chain(&self.deny_only)
            .copied()
            .all(mapped)
        {
            return Err(TermsError::UnmappedPrincipal);
        }
        if !self.required.is_disjoint(&self.deny_only) {
            return Err(TermsError::DenyOnlyOverlap);
        }
        for set in self.enabled_sets() {
            if set.domains.contains(&DomainId::UNMAPPED) || !set.exact.iter().copied().all(mapped) {
                return Err(TermsError::UnmappedPrincipal);
            }
            if self.deny_only.iter().any(|p| set.contains(p)) {
                return Err(TermsError::DenyOnlyOverlap);
            }
        }
        Ok(())
    }

    /// Drops what the rest of a valid term already implies. This neither
    /// allocates nor changes which subjects the term admits.
    fn normalize(&mut self) {
        if self.privileges.contains(Privileges::TRAVERSE_ANY) {
            self.privileges.insert(Privileges::LOOKUP_ANY);
        }
        for set in [
            &mut self.access.owners,
            &mut self.access.groups,
            &mut self.identity.owners,
            &mut self.identity.groups,
            &mut self.optional,
        ] {
            set.exact.retain(|p| !set.domains.contains(&p.domain));
        }
        self.optional.exact.retain(|p| !self.required.contains(p));
    }

    fn try_clone(&self) -> Result<Self, TryReserveError> {
        Ok(Self {
            access: self.access.try_clone()?,
            identity: self.identity.try_clone()?,
            required: self.required.try_clone()?,
            optional: self.optional.try_clone()?,
            deny_only: self.deny_only.try_clone()?,
            privileges: self.privileges,
        })
    }
}

fn mapped(p: Principal) -> bool {
    p.domain != DomainId::UNMAPPED
}

/// Reason terms cannot form an authority.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TermsError {
    /// A term names [`DomainId::UNMAPPED`] or one of its principals.
    #[error("unmapped principals cannot appear in authority")]
    UnmappedPrincipal,
    /// A deny-only principal of a term can also be enabled or selected.
    #[error("a mandatory deny-only principal can also be enabled")]
    DenyOnlyOverlap,
    /// A term has unknown privileges, or [`Privileges::EXECUTE_ANY`] without
    /// [`Privileges::READ_ANY`].
    #[error("invalid privilege set")]
    InvalidPrivileges,
    /// There are more than [`MAX_AUTHORITY_TERMS`] distinct canonical terms.
    #[error("too many distinct authority terms")]
    TooManyTerms,
    /// A set exceeds [`MAX_SET_PRINCIPALS`] or [`MAX_SET_DOMAINS`].
    #[error("an authority set exceeds its protocol ceiling")]
    SetTooLarge,
    /// The canonical terms could not be allocated.
    #[error("authority allocation failed")]
    OutOfMemory,
}

impl From<TryReserveError> for TermsError {
    fn from(_: TryReserveError) -> Self {
        Self::OutOfMemory
    }
}

/// Validates `terms`, which may repeat and come in any order, and returns
/// their distinct canonical forms in ascending order.
///
/// Each term is validated as given, so an invalid term is rejected even if
/// its canonical form would be valid or equal to another term's. A canonical
/// term admits the same subjects: [`Privileges::TRAVERSE_ANY`] includes
/// [`Privileges::LOOKUP_ANY`], no exact principal repeats its set's domain
/// wildcard and no optional principal is also required. At most
/// [`MAX_AUTHORITY_TERMS`] distinct canonical terms are accepted.
///
/// Both LiteBox and the broker apply this; the broker's result is authoritative.
pub fn canonical_terms(terms: impl IntoIterator<Item = Term>) -> Result<Vec<Term>, TermsError> {
    let mut distinct = Vec::new();
    for mut term in terms {
        term.validate()?;
        term.normalize();
        insert_distinct(&mut distinct, term)?;
    }
    Ok(distinct)
}

fn insert_distinct(distinct: &mut Vec<Term>, term: Term) -> Result<(), TermsError> {
    if let Err(index) = distinct.binary_search(&term) {
        if distinct.len() == MAX_AUTHORITY_TERMS {
            return Err(TermsError::TooManyTerms);
        }
        distinct.try_reserve(1)?;
        distinct.insert(index, term);
    }
    Ok(())
}

impl Subject {
    /// Whether [`Self::identities`] and [`Self::deny_only`] are within
    /// [`MAX_SET_PRINCIPALS`]. Only such subjects can be exchanged with the
    /// broker.
    #[must_use]
    pub fn within_size_limits(&self) -> bool {
        self.identities.len() <= MAX_SET_PRINCIPALS && self.deny_only.len() <= MAX_SET_PRINCIPALS
    }
}

/// Error while encoding or decoding credential values for a shared buffer.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityCodecError {
    /// The payload has more than [`MAX_AUTHORITY_TERMS`] terms.
    #[error("too many distinct authority terms")]
    TooManyTerms,
    /// A set exceeds [`MAX_SET_PRINCIPALS`] or [`MAX_SET_DOMAINS`].
    #[error("an authority set exceeds its protocol ceiling")]
    SetTooLarge,
    /// The payload is truncated, has trailing bytes or unknown values, or is
    /// not in canonical order.
    #[error("malformed authority payload")]
    Malformed,
    /// The payload could not be allocated.
    #[error("authority payload allocation failed")]
    OutOfMemory,
}

impl From<WireError> for AuthorityCodecError {
    fn from(_: WireError) -> Self {
        Self::Malformed
    }
}

/// A list of terms encoded for a shared buffer: a little-endian `u16` count,
/// then each distinct canonical term in ascending [`Ord`] order.
///
/// Each term holds its access and identity slots (owners, then groups),
/// `required`, `optional`, `deny_only` and `privileges`. A principal set holds
/// its exact principals and then its domains. Every set is a `u16` count
/// followed by its elements in strictly ascending order. A principal is its
/// `u32` domain and `u32` ID, and privileges are their `u32` bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedTerms(Vec<u8>);

impl EncodedTerms {
    /// Encodes the [`canonical_terms`] of `terms`, which may repeat and come
    /// in any order. The recipient must still validate the decoded terms.
    pub fn new<'a>(terms: impl IntoIterator<Item = &'a Term>) -> Result<Self, TermsError> {
        let mut distinct = Vec::new();
        for term in terms {
            // Validating first also bounds the copy.
            term.validate()?;
            let mut term = term.try_clone()?;
            term.normalize();
            insert_distinct(&mut distinct, term)?;
        }
        let length = COUNT_SIZE + distinct.iter().map(Term::encoded_len).sum::<usize>();
        let mut encoder = Encoder::try_with_capacity(length).ok_or(TermsError::OutOfMemory)?;
        encode_count(distinct.len(), &mut encoder);
        for term in &distinct {
            term.encode(&mut encoder);
        }
        let bytes = encoder.finish();
        debug_assert_eq!(bytes.len(), length);
        Ok(Self(bytes))
    }

    /// Returns the encoded bytes, at most [`MAX_ENCODED_TERMS_SIZE`] long.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Decodes terms encoded by [`EncodedTerms::new`], accepting only strictly
/// ascending terms and sets. It does not validate the terms; see
/// [`canonical_terms`].
pub fn decode_terms(payload: &[u8]) -> Result<Vec<Term>, AuthorityCodecError> {
    if payload.len() > MAX_ENCODED_TERMS_SIZE as usize {
        return Err(AuthorityCodecError::Malformed);
    }
    let mut decoder = Decoder::new(payload);
    let count = usize::from(u16::decode(&mut decoder)?);
    if count > MAX_AUTHORITY_TERMS {
        return Err(AuthorityCodecError::TooManyTerms);
    }
    if count > decoder.remaining() / MIN_TERM_SIZE {
        return Err(AuthorityCodecError::Malformed);
    }
    let mut terms: Vec<Term> = Vec::new();
    terms
        .try_reserve_exact(count)
        .map_err(|_| AuthorityCodecError::OutOfMemory)?;
    for _ in 0..count {
        let term = Term::decode(&mut decoder)?;
        if terms.last().is_some_and(|last| *last >= term) {
            return Err(AuthorityCodecError::Malformed);
        }
        terms.push(term);
    }
    decoder.finish()?;
    Ok(terms)
}

/// A subject encoded for a shared buffer: its scope (`0` for access, `1` for
/// identity), owner, group, identities, deny-only principals and privileges,
/// each as [`EncodedTerms`] encodes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedSubject(Vec<u8>);

impl EncodedSubject {
    /// Encodes `subject`.
    pub fn new(subject: &Subject) -> Result<Self, AuthorityCodecError> {
        if !Privileges::all().contains(subject.privileges) {
            return Err(AuthorityCodecError::Malformed);
        }
        if !subject.within_size_limits() {
            return Err(AuthorityCodecError::SetTooLarge);
        }
        let length = Scope::MAX_SIZE
            + 2 * Principal::MAX_SIZE
            + principal_list_len(&subject.identities)
            + principal_list_len(&subject.deny_only)
            + Privileges::MAX_SIZE;
        let mut encoder =
            Encoder::try_with_capacity(length).ok_or(AuthorityCodecError::OutOfMemory)?;
        subject.scope.encode(&mut encoder);
        subject.owner.encode(&mut encoder);
        subject.group.encode(&mut encoder);
        encode_set(&subject.identities, &mut encoder);
        encode_set(&subject.deny_only, &mut encoder);
        subject.privileges.encode(&mut encoder);
        let bytes = encoder.finish();
        debug_assert_eq!(bytes.len(), length);
        Ok(Self(bytes))
    }

    /// Returns the encoded bytes, at most [`MAX_ENCODED_SUBJECT_SIZE`] long.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Decodes a subject encoded by [`EncodedSubject::new`], accepting only its
/// canonical form.
pub fn decode_subject(payload: &[u8]) -> Result<Subject, AuthorityCodecError> {
    if payload.len() > MAX_ENCODED_SUBJECT_SIZE as usize {
        return Err(AuthorityCodecError::Malformed);
    }
    let mut decoder = Decoder::new(payload);
    let subject = Subject {
        scope: Scope::decode(&mut decoder)?,
        owner: Principal::decode(&mut decoder)?,
        group: Principal::decode(&mut decoder)?,
        identities: decode_set(&mut decoder, MAX_SET_PRINCIPALS)?,
        deny_only: decode_set(&mut decoder, MAX_SET_PRINCIPALS)?,
        privileges: Privileges::decode(&mut decoder)?,
    };
    decoder.finish()?;
    Ok(subject)
}

wire_struct! {
    /// Restricts the authority of the caller's pending child.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RestrictChildAuthorityRequest {
        /// The caller's pending child.
        pub child_process_id: ProcessId,
        /// The child's new terms, as [`EncodedTerms`].
        pub terms: SharedBufferSequence,
    }
}

fn principal_list_len(set: &SortedSet<Principal>) -> usize {
    COUNT_SIZE + set.len() * Principal::MAX_SIZE
}

fn encode_count(count: usize, encoder: &mut Encoder) {
    u16::try_from(count)
        .expect("counts are checked against the protocol ceilings")
        .encode(encoder);
}

fn encode_set<T: Wire>(set: &SortedSet<T>, encoder: &mut Encoder) {
    encode_count(set.len(), encoder);
    for item in set {
        item.encode(encoder);
    }
}

fn decode_set<T: Wire + Ord>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<SortedSet<T>, AuthorityCodecError> {
    let count = usize::from(u16::decode(decoder)?);
    if count > maximum {
        return Err(AuthorityCodecError::SetTooLarge);
    }
    if count > decoder.remaining() / T::MAX_SIZE {
        return Err(AuthorityCodecError::Malformed);
    }
    let mut items: Vec<T> = Vec::new();
    items
        .try_reserve_exact(count)
        .map_err(|_| AuthorityCodecError::OutOfMemory)?;
    for _ in 0..count {
        let item = T::decode(decoder)?;
        if items.last().is_some_and(|last| *last >= item) {
            return Err(AuthorityCodecError::Malformed);
        }
        items.push(item);
    }
    Ok(SortedSet::from_ascending(items))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn principal(domain: u32, id: u32) -> Principal {
        Principal {
            domain: DomainId(domain),
            id,
        }
    }

    fn term_bytes(term: &Term) -> Vec<u8> {
        EncodedTerms::new([term]).unwrap().as_bytes()[COUNT_SIZE..].to_vec()
    }

    fn full_principals(domain: u32) -> SortedSet<Principal> {
        SortedSet::try_from_iter(
            (0..MAX_SET_PRINCIPALS).map(|id| principal(domain, u32::try_from(id).unwrap())),
        )
        .unwrap()
    }

    /// Wildcards that cover none of the domains [`full_term`] names exactly.
    fn full_set(domain: u32) -> PrincipalSet {
        PrincipalSet {
            exact: full_principals(domain),
            domains: SortedSet::try_from_iter((100..).take(MAX_SET_DOMAINS).map(DomainId)).unwrap(),
        }
    }

    /// A valid canonical term with every set at its ceiling.
    fn full_term(variant: u32) -> Term {
        let slots = Slots {
            owners: full_set(1),
            groups: full_set(2),
        };
        Term {
            access: slots.clone(),
            identity: slots,
            required: full_principals(3),
            optional: full_set(4),
            deny_only: full_principals(5),
            privileges: Privileges::from_bits(variant << 5).unwrap(),
        }
    }

    /// Distinct valid canonical terms.
    fn small_term(variant: u32) -> Term {
        Term {
            privileges: Privileges::from_bits(variant << 5).unwrap(),
            ..Term::default()
        }
    }

    fn full_subject() -> Subject {
        Subject {
            scope: Scope::Identity,
            owner: principal(1, 0),
            group: principal(2, 0),
            identities: full_principals(2),
            deny_only: full_principals(3),
            privileges: Privileges::all(),
        }
    }

    #[test]
    fn terms_encoding_is_pinned() {
        let term = Term {
            access: Slots {
                owners: PrincipalSet {
                    exact: SortedSet::new(),
                    domains: SortedSet::from([DomainId::POSIX_USER]),
                },
                groups: PrincipalSet::default(),
            },
            required: SortedSet::from([principal(2, 5)]),
            privileges: Privileges::READ_ANY | Privileges::SIGNAL_ANY,
            ..Term::default()
        };
        assert_eq!(
            EncodedTerms::new([&term]).unwrap().as_bytes(),
            [
                1, 0, // term count
                0, 0, 1, 0, 1, 0, 0, 0, // access owners
                0, 0, 0, 0, // access groups
                0, 0, 0, 0, 0, 0, 0, 0, // identity slots
                1, 0, 2, 0, 0, 0, 5, 0, 0, 0, // required
                0, 0, 0, 0, // optional
                0, 0, // deny-only
                1, 2, 0, 0, // privileges
            ]
        );
        assert_eq!(term_bytes(&Term::default()).len(), MIN_TERM_SIZE);
    }

    #[test]
    fn subject_encoding_is_pinned() {
        let subject = Subject {
            scope: Scope::Identity,
            owner: principal(1, 1000),
            group: principal(2, 100),
            identities: SortedSet::from([principal(2, 5)]),
            deny_only: SortedSet::new(),
            privileges: Privileges::SIGNAL_ANY,
        };
        let encoded = EncodedSubject::new(&subject).unwrap();
        assert_eq!(
            encoded.as_bytes(),
            [
                1, // scope
                1, 0, 0, 0, 232, 3, 0, 0, // owner
                2, 0, 0, 0, 100, 0, 0, 0, // group
                1, 0, 2, 0, 0, 0, 5, 0, 0, 0, // identities
                0, 0, // deny-only
                0, 2, 0, 0, // privileges
            ]
        );
        assert_eq!(decode_subject(encoded.as_bytes()), Ok(subject));
    }

    #[test]
    fn terms_round_trip_in_canonical_order() {
        let narrow = Term {
            required: SortedSet::from([principal(2, 5)]),
            ..Term::default()
        };
        let broad = Term {
            optional: PrincipalSet {
                exact: SortedSet::from([principal(3, 6), principal(3, 7)]),
                domains: SortedSet::from([DomainId::POSIX_GROUP]),
            },
            deny_only: SortedSet::from([principal(4, 8)]),
            privileges: Privileges::all(),
            ..Term::default()
        };
        let encoded = EncodedTerms::new([&broad, &narrow, &broad]).unwrap();
        let mut expected = vec![broad, narrow];
        expected.sort();
        assert_eq!(decode_terms(encoded.as_bytes()), Ok(expected));
        let empty = EncodedTerms::new([]).unwrap();
        assert_eq!(empty.as_bytes(), [0, 0]);
        assert_eq!(decode_terms(empty.as_bytes()), Ok(Vec::new()));
    }

    #[test]
    fn ceilings_bound_the_encoded_sizes() {
        let terms: Vec<Term> = (0..MAX_AUTHORITY_TERMS)
            .map(|index| full_term(u32::try_from(index).unwrap()))
            .collect();
        assert_eq!(canonical_terms(terms.clone()).as_ref(), Ok(&terms));
        let encoded = EncodedTerms::new(&terms).unwrap();
        assert_eq!(encoded.as_bytes().len(), MAX_ENCODED_TERMS_SIZE as usize);
        assert_eq!(decode_terms(encoded.as_bytes()), Ok(terms));

        let subject = full_subject();
        let encoded = EncodedSubject::new(&subject).unwrap();
        assert_eq!(encoded.as_bytes().len(), MAX_ENCODED_SUBJECT_SIZE as usize);
        assert_eq!(decode_subject(encoded.as_bytes()), Ok(subject));
    }

    #[test]
    fn encoding_rejects_values_over_the_ceilings() {
        let terms: Vec<Term> = (0..=MAX_AUTHORITY_TERMS)
            .map(|index| small_term(u32::try_from(index).unwrap()))
            .collect();
        assert_eq!(EncodedTerms::new(&terms), Err(TermsError::TooManyTerms));
        assert_eq!(canonical_terms(terms), Err(TermsError::TooManyTerms));
        // Repeats do not count against the ceiling.
        let repeated = vec![Term::default(); MAX_AUTHORITY_TERMS + 1];
        assert!(EncodedTerms::new(&repeated).is_ok());

        let mut term = Term::default();
        term.identity.groups.domains =
            SortedSet::try_from_iter((1..).take(MAX_SET_DOMAINS + 1).map(DomainId)).unwrap();
        assert!(!term.within_size_limits());
        assert_eq!(EncodedTerms::new([&term]), Err(TermsError::SetTooLarge));
        assert_eq!(canonical_terms([term]), Err(TermsError::SetTooLarge));

        let mut subject = full_subject();
        subject.deny_only.try_insert(principal(4, 0)).unwrap();
        assert!(!subject.within_size_limits());
        assert_eq!(
            EncodedSubject::new(&subject),
            Err(AuthorityCodecError::SetTooLarge)
        );
    }

    #[test]
    fn terms_count_once_canonical() {
        let canonical = Term {
            access: Slots {
                owners: PrincipalSet {
                    exact: SortedSet::new(),
                    domains: SortedSet::from([DomainId::POSIX_USER]),
                },
                groups: PrincipalSet::default(),
            },
            required: SortedSet::from([principal(2, 5)]),
            optional: PrincipalSet {
                exact: SortedSet::from([principal(2, 6)]),
                domains: SortedSet::new(),
            },
            privileges: Privileges::LOOKUP_ANY | Privileges::TRAVERSE_ANY,
            ..Term::default()
        };
        // Each differs only in what the rest of the term already implies.
        let redundant: Vec<Term> = (0..=u32::try_from(MAX_AUTHORITY_TERMS).unwrap())
            .map(|id| {
                let mut term = canonical.clone();
                term.access.owners.exact = SortedSet::from([principal(1, id)]);
                term.optional.exact.try_insert(principal(2, 5)).unwrap();
                term.privileges = Privileges::TRAVERSE_ANY;
                term
            })
            .collect();
        assert_eq!(
            canonical_terms(redundant.clone()),
            Ok(vec![canonical.clone()])
        );
        let encoded = EncodedTerms::new(&redundant).unwrap();
        assert_eq!(encoded, EncodedTerms::new([&canonical]).unwrap());
        assert_eq!(decode_terms(encoded.as_bytes()), Ok(vec![canonical]));
    }

    #[test]
    fn invalid_terms_are_not_normalized_away() {
        let valid = Term {
            access: Slots {
                owners: PrincipalSet {
                    exact: SortedSet::new(),
                    domains: SortedSet::from([DomainId::POSIX_USER]),
                },
                groups: PrincipalSet::default(),
            },
            ..Term::default()
        };
        let mut overlap = valid.clone();
        overlap.access.owners.exact = SortedSet::from([principal(1, 7)]);
        overlap.deny_only = SortedSet::from([principal(1, 7)]);
        let mut required_overlap = valid.clone();
        required_overlap.required = SortedSet::from([principal(2, 7)]);
        required_overlap.optional.exact = SortedSet::from([principal(2, 7)]);
        required_overlap.deny_only = SortedSet::from([principal(2, 7)]);
        let mut unmapped = valid.clone();
        unmapped.optional.exact = SortedSet::from([Principal::UNMAPPED]);
        let mut unmapped_domain = valid.clone();
        unmapped_domain.identity.groups.domains = SortedSet::from([DomainId::UNMAPPED]);
        let mut execute = valid.clone();
        execute.privileges = Privileges::EXECUTE_ANY | Privileges::TRAVERSE_ANY;
        for (invalid, error) in [
            (overlap, TermsError::DenyOnlyOverlap),
            (required_overlap, TermsError::DenyOnlyOverlap),
            (unmapped, TermsError::UnmappedPrincipal),
            (unmapped_domain, TermsError::UnmappedPrincipal),
            (execute, TermsError::InvalidPrivileges),
        ] {
            // Valid repeats fill the ceiling, then the invalid term follows.
            let mut terms = vec![valid.clone(); MAX_AUTHORITY_TERMS];
            terms.push(invalid);
            assert_eq!(EncodedTerms::new(&terms), Err(error));
            assert_eq!(canonical_terms(terms), Err(error));
        }
    }

    #[test]
    fn encoding_refuses_unknown_privilege_bits() {
        let unknown = Privileges::from_bits_retain(1 << 31);
        let term = Term {
            privileges: unknown,
            ..Term::default()
        };
        assert_eq!(
            EncodedTerms::new([&term]),
            Err(TermsError::InvalidPrivileges)
        );
        let mut subject = full_subject();
        subject.privileges = unknown;
        assert_eq!(
            EncodedSubject::new(&subject),
            Err(AuthorityCodecError::Malformed)
        );
    }

    #[test]
    fn terms_decoding_rejects_noncanonical_payloads() {
        let low = Term::default();
        let high = Term {
            privileges: Privileges::READ_ANY,
            ..Term::default()
        };
        let pair = |first: &Term, second: &Term| {
            [&[2, 0][..], &term_bytes(first), &term_bytes(second)].concat()
        };
        assert!(decode_terms(&pair(&low, &high)).is_ok());
        assert_eq!(
            decode_terms(&pair(&high, &low)),
            Err(AuthorityCodecError::Malformed)
        );
        assert_eq!(
            decode_terms(&pair(&low, &low)),
            Err(AuthorityCodecError::Malformed)
        );

        let encoded = EncodedTerms::new([&Term {
            required: SortedSet::from([principal(2, 5), principal(2, 6)]),
            ..Term::default()
        }])
        .unwrap();
        // The required set starts after the count and the empty slots.
        let required = COUNT_SIZE + 8 * COUNT_SIZE;
        let mut descending = encoded.as_bytes().to_vec();
        descending[required + 2..required + 10].copy_from_slice(&[2, 0, 0, 0, 6, 0, 0, 0]);
        descending[required + 10..required + 18].copy_from_slice(&[2, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(
            decode_terms(&descending),
            Err(AuthorityCodecError::Malformed)
        );
        let mut duplicate = encoded.as_bytes().to_vec();
        duplicate[required + 14] = 5;
        assert_eq!(
            decode_terms(&duplicate),
            Err(AuthorityCodecError::Malformed)
        );
    }

    #[test]
    fn terms_decoding_rejects_malformed_payloads() {
        let valid = EncodedTerms::new([&Term::default()]).unwrap();
        let bytes = valid.as_bytes();
        assert_eq!(decode_terms(&[]), Err(AuthorityCodecError::Malformed));
        assert_eq!(
            decode_terms(&bytes[..bytes.len() - 1]),
            Err(AuthorityCodecError::Malformed)
        );
        assert_eq!(
            decode_terms(&[bytes, &[0]].concat()),
            Err(AuthorityCodecError::Malformed)
        );

        let mut unknown_privilege = bytes.to_vec();
        *unknown_privilege.last_mut().unwrap() = 0x80;
        assert_eq!(
            decode_terms(&unknown_privilege),
            Err(AuthorityCodecError::Malformed)
        );

        // A count larger than the remaining bytes could hold is rejected
        // before anything is allocated for it.
        let mut overcounted = bytes.to_vec();
        overcounted[0] = 2;
        assert_eq!(
            decode_terms(&overcounted),
            Err(AuthorityCodecError::Malformed)
        );
        let mut overcounted_set = bytes.to_vec();
        overcounted_set[COUNT_SIZE..2 * COUNT_SIZE].copy_from_slice(&1000u16.to_le_bytes());
        assert_eq!(
            decode_terms(&overcounted_set),
            Err(AuthorityCodecError::Malformed)
        );

        let too_many = u16::try_from(MAX_AUTHORITY_TERMS + 1).unwrap();
        assert_eq!(
            decode_terms(&too_many.to_le_bytes()),
            Err(AuthorityCodecError::TooManyTerms)
        );
        let mut oversized_set = bytes.to_vec();
        oversized_set[COUNT_SIZE..2 * COUNT_SIZE]
            .copy_from_slice(&u16::try_from(MAX_SET_PRINCIPALS + 1).unwrap().to_le_bytes());
        assert_eq!(
            decode_terms(&oversized_set),
            Err(AuthorityCodecError::SetTooLarge)
        );
        assert_eq!(
            decode_terms(&vec![0; MAX_ENCODED_TERMS_SIZE as usize + 1]),
            Err(AuthorityCodecError::Malformed)
        );
    }

    #[test]
    fn subject_decoding_rejects_malformed_payloads() {
        let subject = Subject {
            scope: Scope::Access,
            owner: principal(1, 1),
            group: principal(2, 2),
            identities: SortedSet::from([principal(2, 3)]),
            deny_only: SortedSet::new(),
            privileges: Privileges::empty(),
        };
        let encoded = EncodedSubject::new(&subject).unwrap();
        let bytes = encoded.as_bytes();
        assert_eq!(decode_subject(bytes), Ok(subject));
        assert_eq!(
            decode_subject(&bytes[..bytes.len() - 1]),
            Err(AuthorityCodecError::Malformed)
        );
        assert_eq!(
            decode_subject(&[bytes, &[0]].concat()),
            Err(AuthorityCodecError::Malformed)
        );
        let mut unknown_scope = bytes.to_vec();
        unknown_scope[0] = 2;
        assert_eq!(
            decode_subject(&unknown_scope),
            Err(AuthorityCodecError::Malformed)
        );
        let mut oversized_set = bytes.to_vec();
        oversized_set[17..19]
            .copy_from_slice(&u16::try_from(MAX_SET_PRINCIPALS + 1).unwrap().to_le_bytes());
        assert_eq!(
            decode_subject(&oversized_set),
            Err(AuthorityCodecError::SetTooLarge)
        );
        assert_eq!(
            decode_subject(&vec![0; MAX_ENCODED_SUBJECT_SIZE as usize + 1]),
            Err(AuthorityCodecError::Malformed)
        );
    }
}

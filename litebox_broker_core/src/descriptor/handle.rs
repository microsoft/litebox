// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! What a file-system handle may do with its object's descriptor rights.
//!
//! A handle keeps three sets of rights, each within the one before:
//! - its *operation mask*, the rights it may attempt at all. Its kind and open
//!   mode decide which rights are eligible, and an open-gated right (see
//!   [`HandleRules`]) stays only if the open requested it and was granted it;
//! - its *admitted* rights, the rights that its open actually requested and
//!   was granted, whether or not its first holder required admission;
//! - its *cached* grants, the admitted rights whose grant authorizes later
//!   uses without another check.
//!
//! A use of a right outside the mask is denied, even if the current subject
//! now holds it. A use of a cached right is allowed. Any other use is checked
//! against the current subject and the object's current descriptor. Restricting
//! a handle only ever removes rights from each set.

use litebox_broker_protocol::authority::{Scope, Subject};

use super::profile::HandleRules;
use super::{FileKind, Rights, SecurityDescriptor};

/// How a handle may use one right; see [`HandleGrants::decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleUse {
    /// The handle may not attempt it, whoever uses it and whatever the
    /// object's descriptor now grants.
    Denied,
    /// A grant cached at open authorizes it, without a subject.
    Cached,
    /// The current subject must be granted it by the object's current
    /// descriptor, checked when and where it is used.
    CheckAtUse,
}

/// The descriptor rights of one file-system handle: its operation mask, the
/// rights its open admitted, and the grants it caches. See the
/// [module documentation](self).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HandleGrants {
    kind: FileKind,
    mask: Rights,
    admitted: Rights,
    cached: Rights,
}

impl HandleGrants {
    /// The grants of a handle to an object of `kind`, opened by `subject` while
    /// the object had `descriptor`, under `rules`.
    ///
    /// `eligible` are the rights the handle's kind and open mode let it attempt,
    /// and `requested` those its open asks for. Returns `None`, refusing the
    /// open, unless `descriptor` grants `subject` every open-gated right that
    /// is both eligible and requested. Open-gated rights not requested leave
    /// the mask. Of those admitted, the handle caches the cacheable ones, but
    /// never a [`Rights::TRAVERSE`] that only
    /// [`Privileges::LOOKUP_ANY`](litebox_broker_protocol::authority::Privileges::LOOKUP_ANY)
    /// granted (see [`SecurityDescriptor::cacheable_file_rights`]).
    ///
    /// Callers must check separately that their profile honors `descriptor`.
    #[must_use]
    pub fn admit(
        rules: HandleRules,
        kind: FileKind,
        eligible: Rights,
        requested: Rights,
        descriptor: &SecurityDescriptor,
        subject: &Subject,
    ) -> Option<Self> {
        if subject.scope != Scope::Access || descriptor.kind != kind || !rules.is_valid_for(kind) {
            return None;
        }
        let requested = requested & eligible & kind.rights();
        let admitted = descriptor.granted_file_rights(subject, requested);
        if !admitted.contains(requested & rules.open_gated) {
            return None;
        }
        let cached = descriptor.cacheable_file_rights(subject, requested) & rules.cacheable;
        Some(Self::with(rules, kind, eligible, admitted, cached))
    }

    /// The grants of a handle whose open created its object of `kind`.
    ///
    /// As Linux opens a file that the open creates whatever access its new mode
    /// grants, the creator is admitted the open-gated rights that it requests
    /// and the handle may attempt, without consulting the new descriptor. It
    /// gains nothing else: the cacheable ones of these are cached, and other
    /// rights are checked at use as for any other handle.
    #[must_use]
    pub(crate) fn created(
        rules: HandleRules,
        kind: FileKind,
        eligible: Rights,
        requested: Rights,
    ) -> Self {
        let gated = requested & eligible & rules.open_gated & kind.rights();
        Self::with(rules, kind, eligible, gated, gated & rules.cacheable)
    }

    fn with(
        rules: HandleRules,
        kind: FileKind,
        eligible: Rights,
        admitted: Rights,
        cached: Rights,
    ) -> Self {
        let mask = eligible & kind.rights() & !(rules.open_gated & !admitted);
        let admitted = admitted & mask;
        Self {
            kind,
            mask,
            admitted,
            cached: cached & rules.cacheable & admitted,
        }
    }

    /// The kind of object the handle refers to.
    #[must_use]
    pub fn kind(&self) -> FileKind {
        self.kind
    }

    /// The rights the handle may attempt.
    #[must_use]
    pub fn mask(&self) -> Rights {
        self.mask
    }

    /// The rights that the handle's open requested and was granted,
    /// and that it may still attempt.
    #[must_use]
    pub fn admitted(&self) -> Rights {
        self.admitted
    }

    /// The rights whose grant at open authorizes later uses.
    #[must_use]
    pub fn cached(&self) -> Rights {
        self.cached
    }

    /// How the handle may use `right`, which names one or more rights that
    /// must all be authorized; none is never authorized.
    #[must_use]
    pub fn decide(&self, right: Rights) -> HandleUse {
        if right.is_empty() || !self.mask.contains(right) {
            HandleUse::Denied
        } else if self.cached.contains(right) {
            HandleUse::Cached
        } else {
            HandleUse::CheckAtUse
        }
    }

    /// The subset of `requested` that the handle may use now for `subject`,
    /// given the object's current `descriptor`: cached rights, and the other
    /// rights in the mask that `descriptor` grants `subject`. Never a right
    /// outside the mask.
    ///
    /// Callers must check separately that their profile honors `descriptor`,
    /// and use the result under the lock that keeps `descriptor` current.
    #[must_use]
    pub fn granted_at_use(
        &self,
        descriptor: &SecurityDescriptor,
        subject: &Subject,
        requested: Rights,
    ) -> Rights {
        let cached = requested & self.cached;
        let uncached = requested & self.mask & !cached;
        if uncached.is_empty() || descriptor.kind != self.kind {
            return cached;
        }
        // Even a cached modifying right makes a simultaneous TRAVERSE a modifying search.
        // Masking it out before evaluating the request would let LOOKUP_ANY supply traversal.
        cached | (descriptor.granted_file_rights(subject, requested) & uncached)
    }

    /// These grants without any right outside `operations`.
    #[must_use]
    pub fn restrict(self, operations: Rights) -> Self {
        let mask = self.mask & operations;
        let admitted = self.admitted & mask;
        Self {
            kind: self.kind,
            mask,
            admitted,
            cached: self.cached & admitted,
        }
    }

    /// These grants as a holder under `rules` may use them: cached grants that
    /// `rules` do not let it cache become checked at use, and rights that
    /// `rules` gate at open leave the mask unless the open admitted them.
    #[must_use]
    pub fn restrict_to_rules(self, rules: HandleRules) -> Self {
        let mask = self.mask & !(rules.open_gated & !self.admitted);
        let admitted = self.admitted & mask;
        Self {
            kind: self.kind,
            mask,
            admitted,
            cached: self.cached & rules.cacheable & admitted,
        }
    }
}

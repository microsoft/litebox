// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Computes the descriptor to store after a guest-initiated mutation.

use litebox_broker_protocol::authority::{Principal, Privileges, Scope, Subject};
use litebox_broker_protocol::fs::FileMode;
use thiserror::Error;

use super::acl::{held, mapped};
use super::profile::FileSystemProfile;
use super::{Access, DirectoryFlags, ElevationGrants, FileKind, Rights, SecurityDescriptor};
use crate::authority::Authority;

/// Why a requested descriptor cannot be stored.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MutationError {
    /// The subject or its authority does not authorize the mutation.
    #[error("descriptor change is not permitted")]
    Denied,
    /// A guest cannot store this descriptor form in this file service.
    #[error("descriptor form is not supported by this file service")]
    UnsupportedForm,
    /// A creation parent is not a directory or a replacement changes the object's kind.
    #[error("incompatible object kind")]
    WrongKind,
}

/// Inputs for one filesystem operation. The authority is the snapshot under
/// which the broker admitted the subject, and the profile is the object's
/// file service's, not one chosen by the guest.
#[derive(Clone, Copy)]
pub struct MutationContext<'a> {
    /// The acting subject.
    pub subject: &'a Subject,
    /// Determines which identity slots the caller can confer together.
    pub authority: &'a Authority,
    /// Bounds guest-stored descriptors.
    pub profile: FileSystemProfile,
}

impl MutationContext<'_> {
    /// Owner and group to use when a creation request doesn't specify them.
    #[must_use]
    pub fn creation_ownership(&self, parent: &SecurityDescriptor) -> (Principal, Principal) {
        let group = if parent
            .directory_flags()
            .contains(DirectoryFlags::INHERIT_GROUP)
        {
            parent.group()
        } else {
            self.subject.group
        };
        (self.subject.owner, group)
    }

    fn check_store(&self, requested: &SecurityDescriptor) -> Result<(), MutationError> {
        if self.subject.scope != Scope::Access || !self.authority.admits(self.subject) {
            return Err(MutationError::Denied);
        }
        if !self.profile.admits_guest_descriptor(requested) {
            return Err(MutationError::UnsupportedForm);
        }
        Ok(())
    }

    /// Computes a new entry's descriptor. `requested` contains the explicit
    /// owner and group, or the defaults from [`Self::creation_ownership`].
    /// Callers must still respect mount restrictions and install the new
    /// entry in the same checked parent without replacing an existing entry.
    pub fn create(
        &self,
        parent: &SecurityDescriptor,
        mut requested: SecurityDescriptor,
    ) -> Result<SecurityDescriptor, MutationError> {
        self.check_store(&requested)?;
        if !self.profile.honors(parent) {
            return Err(MutationError::UnsupportedForm);
        }
        if parent.kind() != FileKind::Directory {
            return Err(MutationError::WrongKind);
        }
        if !parent.allows_file(self.subject, Rights::TRAVERSE | Rights::ADD_ENTRY)
            || ((requested.owner(), requested.group()) != self.creation_ownership(parent)
                && !self.subject.privileges.contains(Privileges::SET_ANY_OWNER))
        {
            return Err(MutationError::Denied);
        }
        if requested.kind() == FileKind::Directory
            && parent
                .directory_flags()
                .contains(DirectoryFlags::INHERIT_GROUP)
        {
            // Inheritance is mandatory, including for a creator that does not hold the group.
            requested.set_group_inheritance(true);
        } else {
            self.filter_requested_bits(&mut requested);
        }
        requested.trusted_initial = false;
        Ok(requested)
    }

    /// Authorizes a replacement against the **old** descriptor, then removes
    /// any grants the change cannot preserve. The caller must commit it to
    /// that same object only if the checked descriptor is still current.
    pub fn set_security(
        &self,
        current: &SecurityDescriptor,
        mut requested: SecurityDescriptor,
    ) -> Result<SecurityDescriptor, MutationError> {
        self.check_store(&requested)?;
        if !self.profile.honors(current) {
            return Err(MutationError::UnsupportedForm);
        }
        if current.kind() != requested.kind() {
            return Err(MutationError::WrongKind);
        }
        let access_changed = current.access != requested.access;
        if access_changed && !current.allows_file(self.subject, Rights::WRITE_SECURITY) {
            return Err(MutationError::Denied);
        }
        let owner_changed = current.owner() != requested.owner();
        let group_changed = current.group() != requested.group();
        let privileges = self.subject.privileges;
        if (owner_changed || group_changed) && !privileges.contains(Privileges::SET_ANY_OWNER) {
            let write_owner = current.allows_file(self.subject, Rights::WRITE_OWNER);
            if owner_changed
                && !(requested.owner() == self.subject.owner
                    && (write_owner || privileges.contains(Privileges::TAKE_OWNERSHIP)))
            {
                return Err(MutationError::Denied);
            }
            if group_changed
                && !((write_owner || self.holds(current.owner())) && self.holds(requested.group()))
            {
                return Err(MutationError::Denied);
            }
        }
        if access_changed {
            self.filter_requested_bits(&mut requested);
        }
        if owner_changed || group_changed {
            requested.remove_grants(requested.elevation_grants());
        }
        // A no-op cannot change the provenance of someone else's descriptor.
        requested.trusted_initial =
            current.trusted_initial && !owner_changed && !group_changed && !access_changed;
        Ok(requested)
    }

    /// Updates the descriptor as part of an already authorized content change.
    /// The backend must make clearing effective no later than changing the
    /// contents; this does not itself authorize a write.
    pub fn content_change(&self, descriptor: &mut SecurityDescriptor) {
        let grants = descriptor.elevation_grants();
        if grants.is_empty() {
            return;
        }
        let may_preserve = self.profile.honors(descriptor)
            && self.subject.scope == Scope::Access
            && self
                .subject
                .privileges
                .contains(Privileges::MANAGE_ELEVATION)
            && self.authority.admits(self.subject)
            && self.may_confer(descriptor, grants);
        if !may_preserve {
            descriptor.remove_grants(grants);
        }
    }

    fn holds(&self, principal: Principal) -> bool {
        mapped(principal) && held(self.subject, principal)
    }

    fn may_confer(&self, descriptor: &SecurityDescriptor, grants: ElevationGrants) -> bool {
        self.authority.terms().any(|term| {
            (!grants.contains(ElevationGrants::AS_OWNER)
                || term.identity.owners.contains(&descriptor.owner()))
                && (!grants.contains(ElevationGrants::AS_GROUP)
                    || term.identity.groups.contains(&descriptor.group()))
        })
    }

    fn filter_requested_bits(&self, descriptor: &mut SecurityDescriptor) {
        let may_set_group = self.holds(descriptor.group())
            || self
                .subject
                .privileges
                .contains(Privileges::MANAGE_ELEVATION);
        let grants = descriptor.elevation_grants();
        if !grants.is_empty() && !self.may_confer(descriptor, grants) {
            descriptor.remove_grants(grants);
        } else if !may_set_group {
            descriptor.remove_grants(grants & ElevationGrants::AS_GROUP);
        }
        if !may_set_group && descriptor.kind() == FileKind::Directory {
            descriptor.set_group_inheritance(false);
        }
    }
}

impl SecurityDescriptor {
    fn set_group_inheritance(&mut self, inherit: bool) {
        debug_assert_eq!(self.kind(), FileKind::Directory);
        match &mut self.access {
            Access::Mode(mode) => mode.set(FileMode::SGID, inherit),
            Access::Acl { flags, .. } => flags.set(DirectoryFlags::INHERIT_GROUP, inherit),
        }
    }

    // Neither inheritance nor elevation affects the cached execute walk.
    fn remove_grants(&mut self, remove: ElevationGrants) {
        match &mut self.access {
            Access::Mode(mode) => {
                if remove.contains(ElevationGrants::AS_OWNER) {
                    mode.remove(FileMode::SUID);
                }
                if remove.contains(ElevationGrants::AS_GROUP) {
                    mode.remove(FileMode::SGID);
                }
            }
            Access::Acl { grants, .. } => grants.remove(remove),
        }
    }
}

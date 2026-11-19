// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Security descriptors and the single evaluator that judges them.
//!
//! A descriptor says which subjects may act on one object. A file-system
//! object has a [`SecurityDescriptor`], whose access is either a Mode or an
//! explicit ACL. A Mode is only an encoding of a canonical five-entry ACL, so
//! one walk decides both. A process has a [`ProcessDescriptor`](process::ProcessDescriptor).
//!
//! The walk visits entries in order. Each entry whose trustee matches decides
//! the requested rights it names that are still undecided, and rights that stay
//! undecided are denied. An allow entry matches only principals the subject
//! holds (its owner, its group and its identities), never an unmapped
//! principal. A deny entry also matches the subject's deny-only principals.
//! Privileges then add operation-specific rights. Removing allow entries, or
//! moving an identity to deny-only, therefore never adds access.
//!
//! Each check judges one subject alone. Callers must:
//! - admit the subject under the process's current authority (see
//!   [`Authority::admits`](crate::authority::Authority::admits)), and choose a
//!   scope the operation accepts: Access for files, Identity for signals, and
//!   either for inspection and control;
//! - check a request that names several subjects one subject at a time, never
//!   combining what different subjects are granted;
//! - enforce L0 sandbox policy (for example read-only mounts) before or after
//!   this check, since no descriptor or privilege overrides it;
//! - for processes, require the same confinement context and file service, and
//!   credential dominance for inspection and control.
//!
//! The [`FileSystemProfile`](profile::FileSystemProfile) of a file service bounds which descriptor forms
//! guests may store there. Elevation grants are recorded but never honored.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use bitflags::bitflags;
use litebox_broker_protocol::authority::{Principal, Privileges, Scope, Subject};
use litebox_broker_protocol::fs::FileMode;
use thiserror::Error;

pub mod acl;
pub mod handle;
mod mode;
pub mod mutation;
pub mod process;
pub mod profile;

use acl::{Ace, Context, MAX_ACL_ENTRIES, Trustee, held, mapped};

bitflags! {
    /// Rights on a file-system object. Which apply depends on its
    /// [`FileKind`]; see [`FileKind::rights`].
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct Rights: u32 {
        /// Read a file's data.
        const READ             = 1 << 0;
        /// Write a file's data.
        const WRITE            = 1 << 1;
        /// Execute a file.
        const EXECUTE          = 1 << 2;
        /// List a directory's entries.
        const LIST             = 1 << 3;
        /// Add an entry to a directory.
        const ADD_ENTRY        = 1 << 4;
        /// Remove any entry from a directory.
        const DELETE_CHILD     = 1 << 5;
        /// Search a directory: look up a name in it.
        const TRAVERSE         = 1 << 6;
        /// Move a directory to a new parent, which changes its `..` entry.
        const REPARENT         = 1 << 7;
        /// Set both of an object's times to now.
        const TOUCH            = 1 << 8;
        /// Set an object's times and other attributes to any value.
        const WRITE_ATTRIBUTES = 1 << 9;
        /// Change an object's access, flags and elevation grants.
        const WRITE_SECURITY   = 1 << 10;
        /// Remove the object's own entry from a directory.
        const DELETE           = 1 << 11;
        /// Give the object to a new owner.
        const WRITE_OWNER      = 1 << 12;
    }
}

impl Rights {
    /// Rights that make a [`Self::TRAVERSE`] in the same request a
    /// *modifying search*, which [`Privileges::LOOKUP_ANY`] does not supply.
    pub const MODIFYING: Self = Self::ADD_ENTRY
        .union(Self::DELETE_CHILD)
        .union(Self::REPARENT);

    /// Rights that decide who may access the object, which a handle never
    /// caches: a cached copy would outlive a change of owner.
    pub const NEVER_CACHEABLE: Self = Self::WRITE_SECURITY.union(Self::WRITE_OWNER);

    const COMMON: Self = Self::TOUCH
        .union(Self::WRITE_ATTRIBUTES)
        .union(Self::WRITE_SECURITY)
        .union(Self::DELETE)
        .union(Self::WRITE_OWNER);
}

/// Kind of file-system object a [`SecurityDescriptor`] protects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// Any object that is not a directory, such as a regular file, a device,
    /// a socket or a symbolic link.
    File,
    /// A directory.
    Directory,
}

/// Which part of the entry removal check refused the subject.
#[derive(Clone, Copy)]
pub(crate) enum RemovalDenied {
    Access,
    NotOwner,
}

impl FileKind {
    /// The rights that apply to this kind. Requests and entries naming any
    /// other right fail closed.
    #[must_use]
    pub const fn rights(self) -> Rights {
        match self {
            Self::File => Rights::READ
                .union(Rights::WRITE)
                .union(Rights::EXECUTE)
                .union(Rights::COMMON),
            Self::Directory => Rights::LIST
                .union(Rights::ADD_ENTRY)
                .union(Rights::DELETE_CHILD)
                .union(Rights::TRAVERSE)
                .union(Rights::REPARENT)
                .union(Rights::COMMON),
        }
    }
}

bitflags! {
    /// Flags of a directory's descriptor.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct DirectoryFlags: u8 {
        /// New entries take the directory's group, and new subdirectories
        /// inherit this flag.
        const INHERIT_GROUP       = 1 << 0;
        /// Only subjects that own the directory or the entry may remove an
        /// entry using [`Rights::ADD_ENTRY`]; see
        /// [`SecurityDescriptor::allows_remove`]. Privileges never grant
        /// [`Rights::DELETE_CHILD`] here.
        const RESTRICTED_DELETION = 1 << 1;
    }
}

bitflags! {
    /// Elevation grants of a non-directory's descriptor.
    ///
    /// A grant would let a fresh process act as the object's owner or group.
    /// Grants are only recorded, so that guest-visible state stays consistent;
    /// nothing honors them.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ElevationGrants: u8 {
        /// Run as the object's owner.
        const AS_OWNER = 1 << 0;
        /// Run as the object's group.
        const AS_GROUP = 1 << 1;
    }
}

/// How a [`SecurityDescriptor`] stores its access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DescriptorForm {
    /// A [`FileMode`], an encoding of a canonical ACL.
    Mode,
    /// An explicit list of [`Ace`]s.
    Acl,
}

/// Reason a descriptor or profile was rejected.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DescriptorError {
    /// A mode has bits other than [`FileMode::SUPPORTED`].
    #[error("mode has unsupported bits")]
    InvalidMode,
    /// An entry names unknown rights or rights of another kind of object.
    #[error("entry rights are unknown or do not apply to the object")]
    InvalidRights,
    /// An entry names a trustee that cannot apply to the object.
    #[error("entry trustee does not apply to the object")]
    InvalidTrustee,
    /// Flags or grants are unknown or do not apply to the object.
    #[error("flags or grants are unknown or do not apply to the object")]
    InvalidFlags,
    /// An ACL has more than [`MAX_ACL_ENTRIES`] entries.
    #[error("too many entries")]
    TooManyEntries,
    /// A conjunction has no trustee or more than [`acl::MAX_ALL_OF`].
    #[error("conjunction is empty or too long")]
    InvalidConjunction,
    /// A profile names unknown descriptor forms.
    #[error("unknown descriptor forms")]
    InvalidForms,
    /// A profile's handle rules name rights of another kind of object, cache
    /// a right that is not open-gated, or cache a never-cacheable right.
    #[error("invalid handle rules")]
    InvalidHandleRules,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Access {
    Mode(FileMode),
    Acl {
        entries: Vec<Ace>,
        flags: DirectoryFlags,
        grants: ElevationGrants,
    },
}

/// Validated, immutable descriptor of a file-system object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityDescriptor {
    kind: FileKind,
    owner: Principal,
    group: Principal,
    access: Access,
    /// Only broker configuration can opt out of the guest storage profile.
    trusted_initial: bool,
    /// Whether some subject's walk grants [`Rights::EXECUTE`], which
    /// [`Privileges::EXECUTE_ANY`] requires. Computed once from the rest.
    executable: bool,
}

impl SecurityDescriptor {
    /// A descriptor whose access is `mode`.
    ///
    /// The mode's special bits supply the flags and grants: on a directory,
    /// sticky is [`DirectoryFlags::RESTRICTED_DELETION`] and set-group-ID is
    /// [`DirectoryFlags::INHERIT_GROUP`]; on a file, set-user-ID is
    /// [`ElevationGrants::AS_OWNER`], and set-group-ID with group execute is
    /// [`ElevationGrants::AS_GROUP`]. Other special bits are kept but have no
    /// effect.
    pub fn from_mode(
        kind: FileKind,
        owner: Principal,
        group: Principal,
        mode: FileMode,
    ) -> Result<Self, DescriptorError> {
        if !FileMode::SUPPORTED.contains(mode) {
            return Err(DescriptorError::InvalidMode);
        }
        let executable = kind == FileKind::File
            && acl::is_reachable(
                &mode::canonical_entries(kind, mode),
                (owner, group),
                Rights::EXECUTE,
            );
        Ok(Self {
            kind,
            owner,
            group,
            access: Access::Mode(mode),
            trusted_initial: false,
            executable,
        })
    }

    /// A descriptor whose access is the explicit ACL `entries`, in order.
    ///
    /// Only directories may have `flags` and only files `grants`. Entries
    /// must name only rights of `kind`, and no [`Trustee::SameSession`].
    pub fn from_acl(
        kind: FileKind,
        owner: Principal,
        group: Principal,
        flags: DirectoryFlags,
        grants: ElevationGrants,
        entries: Vec<Ace>,
    ) -> Result<Self, DescriptorError> {
        if entries.len() > MAX_ACL_ENTRIES {
            return Err(DescriptorError::TooManyEntries);
        }
        let special_valid = match kind {
            FileKind::File => flags.is_empty() && ElevationGrants::all().contains(grants),
            FileKind::Directory => grants.is_empty() && DirectoryFlags::all().contains(flags),
        };
        if !special_valid {
            return Err(DescriptorError::InvalidFlags);
        }
        for entry in &entries {
            if !kind.rights().contains(entry.rights) {
                return Err(DescriptorError::InvalidRights);
            }
            if entry.trustee.parts().contains(&Trustee::SameSession) {
                return Err(DescriptorError::InvalidTrustee);
            }
        }
        let executable =
            kind == FileKind::File && acl::is_reachable(&entries, (owner, group), Rights::EXECUTE);
        Ok(Self {
            kind,
            owner,
            group,
            access: Access::Acl {
                entries,
                flags,
                grants,
            },
            trusted_initial: false,
            executable,
        })
    }

    /// Marks a descriptor taken directly from trusted configuration, not from a guest store.
    /// Copy-up preserves this origin; guest creation and replacement never do.
    #[must_use]
    pub fn from_trusted_configuration(mut self) -> Self {
        self.trusted_initial = true;
        self
    }

    /// Clones the descriptor, reporting allocation failure.
    pub fn try_clone(&self) -> Result<Self, TryReserveError> {
        let access = match &self.access {
            Access::Mode(mode) => Access::Mode(*mode),
            Access::Acl {
                entries,
                flags,
                grants,
            } => {
                let mut copy = Vec::new();
                copy.try_reserve_exact(entries.len())?;
                copy.extend_from_slice(entries);
                Access::Acl {
                    entries: copy,
                    flags: *flags,
                    grants: *grants,
                }
            }
        };
        Ok(Self { access, ..*self })
    }

    /// The kind of object this descriptor protects.
    #[must_use]
    pub fn kind(&self) -> FileKind {
        self.kind
    }

    /// The object's owner, which [`Trustee::Owner`] names.
    #[must_use]
    pub fn owner(&self) -> Principal {
        self.owner
    }

    /// The object's group, which [`Trustee::Group`] names.
    #[must_use]
    pub fn group(&self) -> Principal {
        self.group
    }

    /// How the access is stored.
    #[must_use]
    pub fn form(&self) -> DescriptorForm {
        match self.access {
            Access::Mode(_) => DescriptorForm::Mode,
            Access::Acl { .. } => DescriptorForm::Acl,
        }
    }

    /// The mode, for a Mode descriptor.
    #[must_use]
    pub fn mode(&self) -> Option<FileMode> {
        match self.access {
            Access::Mode(mode) => Some(mode),
            Access::Acl { .. } => None,
        }
    }

    /// The explicit entries, for an ACL descriptor.
    #[must_use]
    pub fn acl(&self) -> Option<&[Ace]> {
        match &self.access {
            Access::Mode(_) => None,
            Access::Acl { entries, .. } => Some(entries),
        }
    }

    /// The directory flags; always empty for a file.
    #[must_use]
    pub fn directory_flags(&self) -> DirectoryFlags {
        match self.access {
            Access::Mode(mode) => mode::directory_flags(self.kind, mode),
            Access::Acl { flags, .. } => flags,
        }
    }

    /// The recorded elevation grants; always empty for a directory. They are
    /// never honored.
    #[must_use]
    pub fn elevation_grants(&self) -> ElevationGrants {
        match self.access {
            Access::Mode(mode) => mode::elevation_grants(self.kind, mode),
            Access::Acl { grants, .. } => grants,
        }
    }

    /// The subset of `requested` that `subject` is granted.
    ///
    /// Grants nothing unless `subject` has the Access scope and `requested`
    /// names only rights of this object's kind. Each right is decided as if
    /// requested alone, except that a [`Rights::TRAVERSE`] requested with any
    /// of [`Rights::MODIFYING`] is a modifying search, which
    /// [`Privileges::LOOKUP_ANY`] does not supply even when the entries already
    /// grant the other rights.
    #[must_use]
    pub fn granted_file_rights(&self, subject: &Subject, requested: Rights) -> Rights {
        self.granted_with_privileges(subject, subject.privileges, requested)
    }

    /// The subset of `requested` that `subject` is granted and that a handle
    /// may cache (see [`handle::HandleGrants`]): as
    /// [`Self::granted_file_rights`], but without a [`Rights::TRAVERSE`] that
    /// only [`Privileges::LOOKUP_ANY`] supplies, since a cached search could
    /// later serve as a modifying search.
    #[must_use]
    pub fn cacheable_file_rights(&self, subject: &Subject, requested: Rights) -> Rights {
        self.granted_with_privileges(
            subject,
            subject.privileges.difference(Privileges::LOOKUP_ANY),
            requested,
        ) & !Rights::NEVER_CACHEABLE
    }

    fn granted_with_privileges(
        &self,
        subject: &Subject,
        privileges: Privileges,
        requested: Rights,
    ) -> Rights {
        if subject.scope != Scope::Access || !self.kind.rights().contains(requested) {
            return Rights::empty();
        }
        let context = Context {
            subject,
            owner: self.owner,
            group: self.group,
            same_session: false,
        };
        let walked = match &self.access {
            Access::Mode(mode) => walk(
                &mode::canonical_entries(self.kind, *mode),
                &context,
                requested,
            ),
            Access::Acl { entries, .. } => walk(entries, &context, requested),
        };
        walked | (self.privileged_rights(privileges, requested) & requested)
    }

    /// Whether `subject` is granted every right in `requested`, which must be
    /// non-empty. See [`Self::granted_file_rights`].
    #[must_use]
    pub fn allows_file(&self, subject: &Subject, requested: Rights) -> bool {
        !requested.is_empty() && self.granted_file_rights(subject, requested) == requested
    }

    /// Whether `subject` counts as this object's owner: it holds the owner,
    /// as an allow entry would match it, or [`Privileges::ACT_AS_OWNER`].
    /// An Identity subject never does.
    #[must_use]
    pub fn is_owned_by(&self, subject: &Subject) -> bool {
        subject.scope == Scope::Access
            && (subject.privileges.contains(Privileges::ACT_AS_OWNER)
                || (mapped(self.owner) && held(subject, self.owner)))
    }

    /// Whether `subject` may remove the entry for an object with descriptor
    /// `entry` from this directory.
    ///
    /// The directory search is always a modifying search. Then
    /// [`Rights::DELETE_CHILD`] here, or [`Rights::DELETE`] on the entry,
    /// suffices. On a [`DirectoryFlags::RESTRICTED_DELETION`] directory,
    /// [`Rights::ADD_ENTRY`] also suffices if `subject` owns this directory or
    /// the entry (see [`Self::is_owned_by`]).
    #[must_use]
    pub fn allows_remove(&self, entry: &SecurityDescriptor, subject: &Subject) -> bool {
        self.check_remove(entry, subject).is_ok()
    }

    pub(crate) fn check_remove(
        &self,
        entry: &SecurityDescriptor,
        subject: &Subject,
    ) -> Result<(), RemovalDenied> {
        if self.kind != FileKind::Directory {
            return Err(RemovalDenied::Access);
        }
        let parent = self.granted_file_rights(
            subject,
            Rights::TRAVERSE | Rights::ADD_ENTRY | Rights::DELETE_CHILD,
        );
        if !parent.contains(Rights::TRAVERSE) {
            return Err(RemovalDenied::Access);
        }
        if parent.contains(Rights::DELETE_CHILD) || entry.allows_file(subject, Rights::DELETE) {
            return Ok(());
        }
        if self
            .directory_flags()
            .contains(DirectoryFlags::RESTRICTED_DELETION)
            && parent.contains(Rights::ADD_ENTRY)
        {
            if self.is_owned_by(subject) || entry.is_owned_by(subject) {
                return Ok(());
            }
            return Err(RemovalDenied::NotOwner);
        }
        Err(RemovalDenied::Access)
    }

    /// Rights `privileges` add after the walk, for a request of `requested`.
    fn privileged_rights(&self, privileges: Privileges, requested: Rights) -> Rights {
        let mut rights = Rights::empty();
        if privileges.contains(Privileges::READ_ANY) {
            rights |= Rights::READ | Rights::LIST;
        }
        if privileges.contains(Privileges::TRAVERSE_ANY)
            || (privileges.contains(Privileges::LOOKUP_ANY)
                && !requested.intersects(Rights::MODIFYING))
        {
            rights |= Rights::TRAVERSE;
        }
        if privileges.contains(Privileges::WRITE_ANY) {
            rights |= Rights::WRITE | Rights::TOUCH | Rights::ADD_ENTRY | Rights::REPARENT;
            if !self
                .directory_flags()
                .contains(DirectoryFlags::RESTRICTED_DELETION)
            {
                rights |= Rights::DELETE_CHILD;
            }
        }
        if privileges.contains(Privileges::EXECUTE_ANY) && self.executable {
            rights |= Rights::EXECUTE;
        }
        if privileges.contains(Privileges::ACT_AS_OWNER) {
            rights |= Rights::WRITE_SECURITY | Rights::WRITE_ATTRIBUTES;
        }
        rights & self.kind.rights()
    }
}

fn walk(entries: &[Ace], context: &Context<'_>, requested: Rights) -> Rights {
    let granted = acl::walk(
        entries
            .iter()
            .map(|entry| (entry.kind, &entry.trustee, entry.rights.bits())),
        context,
        requested.bits(),
    );
    Rights::from_bits_retain(granted)
}

#[cfg(test)]
mod tests;

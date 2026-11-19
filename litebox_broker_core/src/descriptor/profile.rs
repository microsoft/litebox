// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The trusted file-system profile that bounds guest-stored descriptors.

use bitflags::bitflags;

use super::{DescriptorError, DescriptorForm, FileKind, Rights, SecurityDescriptor};

bitflags! {
    /// Set of [`DescriptorForm`]s.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct StorableForms: u8 {
        /// [`DescriptorForm::Mode`].
        const MODE = 1 << 0;
        /// [`DescriptorForm::Acl`].
        const ACL  = 1 << 1;
    }
}

impl From<DescriptorForm> for StorableForms {
    fn from(form: DescriptorForm) -> Self {
        match form {
            DescriptorForm::Mode => Self::MODE,
            DescriptorForm::Acl => Self::ACL,
        }
    }
}

/// How handles of one [`FileKind`] take descriptor rights from their open,
/// as trusted configuration of a [`FileSystemProfile`].
///
/// Outside [`Self::open_gated`], a handle's kind and open mode alone decide
/// which operations it may attempt, and each attempt is checked against the
/// current subject and descriptor when it is made. See
/// [`HandleGrants`](super::handle::HandleGrants).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HandleRules {
    /// Rights that a handle may exercise only if its open requested them and
    /// the opener was granted them then.
    pub open_gated: Rights,
    /// Open-gated rights whose grant at open the handle keeps, so that using
    /// them is not checked again. Must be a subset of [`Self::open_gated`]
    /// without any of [`Rights::NEVER_CACHEABLE`].
    pub cacheable: Rights,
}

impl HandleRules {
    /// Linux file handles: reads and writes are admitted at open and kept.
    pub const LINUX_FILE: Self = Self {
        open_gated: Rights::READ.union(Rights::WRITE),
        cacheable: Rights::READ.union(Rights::WRITE),
    };
    /// Linux directory handles: listing is admitted at open and kept.
    pub const LINUX_DIRECTORY: Self = Self {
        open_gated: Rights::LIST,
        cacheable: Rights::LIST,
    };

    /// Whether these rules are valid for handles of `kind`.
    pub(super) fn is_valid_for(self, kind: FileKind) -> bool {
        kind.rights().contains(self.open_gated)
            && self.open_gated.contains(self.cacheable)
            && !self.cacheable.intersects(Rights::NEVER_CACHEABLE)
    }
}

/// Descriptor rules of one file service, taken from trusted broker
/// configuration. Every process the file service serves has its profile.
///
/// The profile names the descriptor forms guests may store in the file
/// service; for example, a Linux profile stores only Mode, because an ACL
/// could grant [`Rights::DELETE`](super::Rights::DELETE) or
/// [`Rights::WRITE_OWNER`](super::Rights::WRITE_OWNER), which act beyond the
/// object and which Linux lacks. Use [`Self::admits_guest_descriptor`]:
/// - for every guest request that stores a file-system descriptor (create and
///   set-security), judged by the profile of the file service that holds the
///   object, not the requester's;
/// - when reading a guest-stored descriptor from a store that outlives the
///   broker or that another file service can reach, before honoring it.
///
/// Descriptors from trusted sources are not bound by it: the root image, nodes
/// the broker builds itself, host mounts through their identity map, and
/// devices. Nor are [`ProcessDescriptor`](super::process::ProcessDescriptor)s.
///
/// The profile also holds the [`HandleRules`] of the service's file and
/// directory handles. It has no rules for process handles: a process handle
/// with a profile at either end keeps only operations that need no descriptor,
/// and so cannot signal (see `ProcessObject`). Two profiles are the same
/// exactly when they compare equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileSystemProfile {
    forms: StorableForms,
    file_handles: HandleRules,
    directory_handles: HandleRules,
}

impl FileSystemProfile {
    /// A profile whose guests may store descriptors of `forms`, with Linux
    /// handle rules ([`HandleRules::LINUX_FILE`] and
    /// [`HandleRules::LINUX_DIRECTORY`]).
    pub fn new(forms: StorableForms) -> Result<Self, DescriptorError> {
        Self::with_handle_rules(forms, HandleRules::LINUX_FILE, HandleRules::LINUX_DIRECTORY)
    }

    /// A profile whose guests may store descriptors of `forms`, and whose file
    /// and directory handles follow `file_handles` and `directory_handles`.
    ///
    /// Fails with [`DescriptorError::InvalidHandleRules`] unless each rule
    /// names only rights of its kind and caches only open-gated rights other
    /// than [`Rights::NEVER_CACHEABLE`] ones.
    pub fn with_handle_rules(
        forms: StorableForms,
        file_handles: HandleRules,
        directory_handles: HandleRules,
    ) -> Result<Self, DescriptorError> {
        if !StorableForms::all().contains(forms) {
            return Err(DescriptorError::InvalidForms);
        }
        if !file_handles.is_valid_for(FileKind::File)
            || !directory_handles.is_valid_for(FileKind::Directory)
        {
            return Err(DescriptorError::InvalidHandleRules);
        }
        Ok(Self {
            forms,
            file_handles,
            directory_handles,
        })
    }

    /// The forms guests may store.
    #[must_use]
    pub fn storable_forms(&self) -> StorableForms {
        self.forms
    }

    /// The rules of this service's handles to objects of `kind`.
    #[must_use]
    pub fn handle_rules(&self, kind: FileKind) -> HandleRules {
        match kind {
            FileKind::File => self.file_handles,
            FileKind::Directory => self.directory_handles,
        }
    }

    /// Whether this file service may store, or honor once stored, `descriptor`
    /// from a guest.
    #[must_use]
    pub fn admits_guest_descriptor(&self, descriptor: &SecurityDescriptor) -> bool {
        self.forms.contains(descriptor.form().into())
    }

    /// Whether this service may use the descriptor already stored on an object.
    #[must_use]
    pub fn honors(&self, descriptor: &SecurityDescriptor) -> bool {
        descriptor.trusted_initial || self.admits_guest_descriptor(descriptor)
    }
}

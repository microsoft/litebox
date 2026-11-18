// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The trusted file-system profile that bounds guest-stored descriptors.

use bitflags::bitflags;

use super::{DescriptorError, DescriptorForm, SecurityDescriptor};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileSystemProfile {
    forms: StorableForms,
}

impl FileSystemProfile {
    /// A profile whose guests may store descriptors of `forms`.
    pub fn new(forms: StorableForms) -> Result<Self, DescriptorError> {
        if !StorableForms::all().contains(forms) {
            return Err(DescriptorError::InvalidForms);
        }
        Ok(Self { forms })
    }

    /// The forms guests may store.
    #[must_use]
    pub fn storable_forms(&self) -> StorableForms {
        self.forms
    }

    /// Whether this file service may store, or honor once stored, `descriptor`
    /// from a guest.
    #[must_use]
    pub fn admits_guest_descriptor(&self, descriptor: &SecurityDescriptor) -> bool {
        self.forms.contains(descriptor.form().into())
    }
}

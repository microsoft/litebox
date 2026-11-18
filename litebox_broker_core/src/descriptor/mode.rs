// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Mode form: a POSIX mode encoded as a canonical five-entry ACL.

use litebox_broker_protocol::fs::FileMode;

use super::{Ace, DirectoryFlags, ElevationGrants, FileKind, Rights, Trustee};

/// Rights the r, w and x bits of one class grant.
fn class_rights(kind: FileKind, bits: u16, owner_class: bool, sticky: bool) -> Rights {
    let mut rights = Rights::empty();
    if bits & 0o4 != 0 {
        rights |= match kind {
            FileKind::File => Rights::READ,
            FileKind::Directory => Rights::LIST,
        };
    }
    if bits & 0o2 != 0 {
        rights |= Rights::TOUCH;
        rights |= match kind {
            FileKind::File => Rights::WRITE,
            FileKind::Directory => Rights::ADD_ENTRY | Rights::REPARENT,
        };
        if kind == FileKind::Directory && (owner_class || !sticky) {
            rights |= Rights::DELETE_CHILD;
        }
    }
    if bits & 0o1 != 0 {
        rights |= match kind {
            FileKind::File => Rights::EXECUTE,
            FileKind::Directory => Rights::TRAVERSE,
        };
    }
    if owner_class {
        rights |= Rights::WRITE_SECURITY | Rights::WRITE_ATTRIBUTES;
    }
    rights
}

/// The canonical ACL `mode` encodes on an object of `kind`.
pub(super) fn canonical_entries(kind: FileKind, mode: FileMode) -> [Ace; 5] {
    let bits = mode.bits();
    let sticky = kind == FileKind::Directory && mode.contains(FileMode::SVTX);
    let user = class_rights(kind, (bits >> 6) & 0o7, true, sticky);
    let group = class_rights(kind, (bits >> 3) & 0o7, false, sticky);
    let other = class_rights(kind, bits & 0o7, false, sticky);
    [
        Ace::allow(Trustee::Owner, user),
        Ace::deny(Trustee::Owner, (group | other) - user),
        Ace::allow(Trustee::Group, group),
        Ace::deny(Trustee::Group, other - group),
        Ace::allow(Trustee::Everyone, other),
    ]
}

/// The flags `mode` encodes on an object of `kind`.
pub(super) fn directory_flags(kind: FileKind, mode: FileMode) -> DirectoryFlags {
    let mut flags = DirectoryFlags::empty();
    if kind == FileKind::Directory {
        flags.set(
            DirectoryFlags::RESTRICTED_DELETION,
            mode.contains(FileMode::SVTX),
        );
        flags.set(DirectoryFlags::INHERIT_GROUP, mode.contains(FileMode::SGID));
    }
    flags
}

/// The elevation grants `mode` encodes on an object of `kind`.
pub(super) fn elevation_grants(kind: FileKind, mode: FileMode) -> ElevationGrants {
    let mut grants = ElevationGrants::empty();
    if kind == FileKind::File {
        grants.set(ElevationGrants::AS_OWNER, mode.contains(FileMode::SUID));
        grants.set(
            ElevationGrants::AS_GROUP,
            mode.contains(FileMode::SGID | FileMode::XGRP),
        );
    }
    grants
}

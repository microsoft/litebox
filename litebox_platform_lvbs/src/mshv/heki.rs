// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-coupled HEKI helpers.
//!
//! The wire types, enums, and constants have been hoisted into
//! [`litebox_common_lvbs`]. What remains here are helpers that depend on
//! platform-specific types (e.g. [`HvPageProtFlags`]).

use crate::mshv::HvPageProtFlags;
use litebox_common_lvbs::MemAttr;

pub(crate) fn mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();

    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }

    flags
}

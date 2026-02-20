// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Different host implementations of [`super::HostInterface`]
pub mod bootparam;
pub mod linux;
pub mod lvbs_impl;
pub mod per_cpu_variables;

pub use lvbs_impl::LvbsLinuxKernel;

#[cfg(test)]
pub mod mock;

use crate::mshv::vtl1_mem_layout::PAGE_SIZE;

#[repr(align(4096))]
pub(crate) struct HypercallPage(pub(crate) [u8; PAGE_SIZE]);

/// Get the address of a Hyper-V hypercall page. A `call` instruction to this address
/// results in a trap-based Hyper-V hypercall. We must ensure that each
/// Virtual Processor (VP)'s hypercall page is neither overlapped with nor reused
/// for other code and data. Different VPs can share the same address for
/// their hypercall pages because Hyper-V will figure out which VP makes this hypercall.
/// To this end, we reserve a static memory page for the hypercall page which will
/// never be deallocated and be read-only shared among all VPs.
/// # Panics
/// Panics if the address of the hypercall page is not page-aligned or zero
pub fn hv_hypercall_page_address() -> u64 {
    crate::PLATFORM_STATE.hypercall_page_address()
}

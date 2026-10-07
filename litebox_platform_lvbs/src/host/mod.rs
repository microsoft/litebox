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

/// Anchor byte that ensures the `.hvcall_page` linker section is emitted.
#[used]
#[unsafe(link_section = ".hvcall_page")]
static HVCALL_PAGE_ANCHOR: u8 = 0;

/// Get the address of the Hyper-V hypercall code page.
///
/// The page is defined in the linker script (`.hvcall_page` section) so that it
/// has a well-known, page-aligned location. The hypervisor writes executable
/// code into it at runtime via wrmsr(`HV_X64_MSR_HYPERCALL`).
/// A `call` instruction to this address performs a trap-based hypercall.
///
/// Different Virtual Processors (VPs) can share the same address because
/// Hyper-V identifies the calling VP internally.
#[inline]
pub fn hv_hypercall_page_address() -> u64 {
    crate::mshv::vtl1_mem_layout::get_hvcall_page_start_address()
}

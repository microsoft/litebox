//! Different host implementations of [`super::HostInterface`]
pub mod bootparam;
pub mod linux;
pub mod lvbs_impl;
pub mod per_cpu_variables;

pub use lvbs_impl::LvbsLinuxKernel;

#[cfg(test)]
pub mod mock;

use crate::mshv::vtl1_mem_layout::PAGE_SIZE;
use core::num::NonZeroUsize;

#[repr(align(4096))]
struct HypercallPage([u8; PAGE_SIZE]);

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
    static HYPERCALL_PAGE: HypercallPage = HypercallPage([0; PAGE_SIZE]);
    static HYPERCALL_PAGE_ADDR_ONCE: once_cell::race::OnceNonZeroUsize =
        once_cell::race::OnceNonZeroUsize::new();
    let hypercall_page_addr = HYPERCALL_PAGE_ADDR_ONCE.get_or_init(|| {
        let addr = HYPERCALL_PAGE.0.as_ptr() as usize;
        assert!(
            addr.is_multiple_of(PAGE_SIZE),
            "Hypercall page address is not page-aligned"
        );
        NonZeroUsize::new(addr).expect("Failed to get non-zero hypercall page address")
    });
    u64::try_from(hypercall_page_addr.get()).unwrap()
}

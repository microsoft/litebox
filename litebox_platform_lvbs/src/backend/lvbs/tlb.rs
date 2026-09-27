// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS TLB policy: early-boot local invalidation, then VTL1 VP shootdowns.

use litebox_common_lvbs::HypervCallError;
use x86_64::structures::paging::{Page, Size4KiB};

/// Preserve the existing range-versus-address-space hypercall threshold.
const SINGLE_PAGE_FLUSH_CEILING: usize = 33;

/// Production invalidator for LVBS page tables.
#[cfg(not(test))]
pub struct LvbsTlb;

// SAFETY: before hypercalls are ready the boot path has no remote users of
// these mappings. Afterwards the Hyper-V helpers synchronously invalidate
// VPs currently in VTL1. Excluded VPs reload CR3 before using VTL1 mappings
// again (PCID is disabled). Hypercall failure never returns to frame reuse.
#[cfg(not(test))]
unsafe impl crate::mm::tlb::TlbInvalidation for LvbsTlb {
    fn invalidate(start: Page<Size4KiB>, page_count: usize) {
        use crate::mshv::{hvcall_mm, is_hvcall_ready};
        invalidate_with(
            start,
            page_count,
            is_hvcall_ready,
            |start, count| {
                // SAFETY: this branch is only used during early boot, before
                // remote VPs can use the modified mappings; LVBS disables PCID.
                unsafe { crate::arch::mm::tlb::invalidate_local(start, count) };
            },
            |start, count| {
                hvcall_mm::hv_flush_virtual_address_list(start.start_address().as_u64(), count)
            },
            hvcall_mm::hv_flush_virtual_address_space,
        );
    }
}

/// Keep policy testable without executing privileged instructions. The real
/// backend supplies concrete function items/closures, resolved statically.
fn invalidate_with(
    start: Page<Size4KiB>,
    page_count: usize,
    hypercalls_ready: impl FnOnce() -> bool,
    local: impl FnOnce(Page<Size4KiB>, usize),
    list: impl FnOnce(Page<Size4KiB>, usize) -> Result<(), HypervCallError>,
    space: impl FnOnce() -> Result<(), HypervCallError>,
) {
    if page_count == 0 {
        return;
    }
    if !hypercalls_ready() {
        local(start, page_count);
        return;
    }
    let result = if page_count <= SINGLE_PAGE_FLUSH_CEILING {
        list(start, page_count)
    } else {
        space()
    };
    // A failed shootdown cannot be repaired by flushing just this VP: callers
    // may free frames immediately after this function returns. Fail in release
    // builds too, rather than report completion with stale remote translations.
    result.unwrap_or_else(|e| panic!("TLB shootdown failed: {e:?}"));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use x86_64::VirtAddr;

    #[derive(Debug, PartialEq)]
    enum Event {
        Ready,
        Local(Page<Size4KiB>, usize),
        List(Page<Size4KiB>, usize),
        Space,
    }

    fn start() -> Page<Size4KiB> {
        Page::from_start_address(VirtAddr::new(0x10000)).unwrap()
    }

    fn run(count: usize, ready: bool, fail: bool, events: &RefCell<Vec<Event>>) {
        let result = || {
            if fail {
                Err(HypervCallError::InvalidParameter)
            } else {
                Ok(())
            }
        };
        invalidate_with(
            start(),
            count,
            || {
                events.borrow_mut().push(Event::Ready);
                ready
            },
            |page, n| events.borrow_mut().push(Event::Local(page, n)),
            |page, n| {
                events.borrow_mut().push(Event::List(page, n));
                result()
            },
            || {
                events.borrow_mut().push(Event::Space);
                result()
            },
        );
    }

    #[test]
    fn empty_range_does_not_even_query_readiness() {
        for ready in [false, true] {
            let events = RefCell::new(Vec::new());
            run(0, ready, false, &events);
            assert!(events.borrow().is_empty());
        }
    }

    #[test]
    fn early_boot_uses_local_invalidation() {
        for count in [1, 33, 34] {
            let events = RefCell::new(Vec::new());
            run(count, false, false, &events);
            assert_eq!(
                *events.borrow(),
                [Event::Ready, Event::Local(start(), count)]
            );
        }
    }

    #[test]
    fn ready_backend_preserves_hypercall_threshold() {
        for count in [1, 33, 34] {
            let events = RefCell::new(Vec::new());
            run(count, true, false, &events);
            let expected = if count <= 33 {
                Event::List(start(), count)
            } else {
                Event::Space
            };
            assert_eq!(*events.borrow(), [Event::Ready, expected]);
        }
    }

    #[test]
    fn failed_shootdown_never_falls_back_to_local_or_returns() {
        for count in [1, 34] {
            let events = RefCell::new(Vec::new());
            assert!(catch_unwind(AssertUnwindSafe(|| run(count, true, true, &events))).is_err());
            let expected = if count <= 33 {
                Event::List(start(), count)
            } else {
                Event::Space
            };
            assert_eq!(*events.borrow(), [Event::Ready, expected]);
        }
    }
}

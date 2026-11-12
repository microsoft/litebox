// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! What the running broker work is doing, for the console, behind broker core,
//! to look up: whose requests it serves, and whether it publishes the
//! console's `WRITE` to its waiters alone (see `stdio::OutputWaiters`). In the
//! CPU's word: broker work runs on its CPU without interruption, and a
//! suspended worker serves nothing else, and resumes on its own CPU.

use crate::readiness::KernelReadiness;
use alloc::sync::Arc;
#[cfg(not(test))]
use litebox_platform_vm_kernel::cpu::{local as word, set_local as set_word};

/// Bit 0 of the word: publishing the console's `WRITE` to its waiters alone.
/// The rest: the address of the served association's readiness `Arc`, or zero.
const PUBLISHING: usize = 1;

/// Runs `f`, which serves the requests of the association with readiness
/// `association`.
pub(crate) fn serve<T>(association: &Arc<KernelReadiness>, f: impl FnOnce() -> T) -> T {
    let outer = word();
    let address = core::ptr::from_ref(association).expose_provenance();
    debug_assert_eq!(address & PUBLISHING, 0, "an `Arc` is aligned");
    // Safety: `association`'s address, which outlives `f`, after which the
    // word is restored.
    unsafe { set_word(address) };
    let result = f();
    // Safety: the word's value before.
    unsafe { set_word(outer) };
    result
}

/// The readiness of the association whose requests the running broker work
/// serves, if any.
pub(crate) fn served() -> Option<Arc<KernelReadiness>> {
    let address = word() & !PUBLISHING;
    if address == 0 {
        return None;
    }
    // Safety: only this module sets the word (`set_local`'s contract), so a
    // nonzero address is that of the one `serve` on this CPU (its worker's,
    // perhaps suspended), whose `association` outlives it: the work holds its
    // process, and so the association.
    let association =
        unsafe { &*core::ptr::with_exposed_provenance::<Arc<KernelReadiness>>(address) };
    Some(association.clone())
}

/// Runs `f`, which publishes the console's `WRITE` to its waiters alone (see
/// [`publishing_console`]).
pub(crate) fn publish_console<T>(f: impl FnOnce() -> T) -> T {
    let outer = word();
    // Safety: the word's value with the publishing bit, which `served` masks.
    unsafe { set_word(outer | PUBLISHING) };
    let result = f();
    // Safety: the word's value before.
    unsafe { set_word(outer) };
    result
}

/// Whether the running broker work publishes the console's `WRITE` to its
/// waiters alone.
pub(crate) fn publishing_console() -> bool {
    word() & PUBLISHING != 0
}

/// Host tests: no broker work runs, so none does any of the above.
#[cfg(test)]
fn word() -> usize {
    0
}

#[cfg(test)]
unsafe fn set_word(_word: usize) {}

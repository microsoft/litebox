// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Completion contract between page-table mutation and platform TLB invalidation.

use x86_64::structures::paging::{Page, Size4KiB};

/// Synchronous invalidation for the page tables using a memory provider.
///
/// The backend owns CPU targeting and the mechanism (local instructions,
/// hypercalls, or IPIs). Paging must not know how the backend achieves completion.
///
/// # Safety
///
/// After `invalidate` returns, preceding page-table writes must be visible and
/// no CPU may use a stale translation for the requested range in any address
/// space managed by this provider. A CPU excluded from an immediate shootdown
/// must invalidate before it can use those address spaces again.
///
/// Callers may immediately reuse unmapped frames or virtual addresses after
/// return. Failure must therefore not return normally: a local flush cannot
/// substitute for a failed remote shootdown. Implementations must also work
/// while the caller holds the page-table lock (including their remote handlers).
///
/// The current kernel uses non-global mappings without PCID. Backends must be
/// revisited before enabling global mappings or retaining translations across
/// address-space switches.
pub unsafe trait TlbInvalidation {
    /// Invalidate `page_count` consecutive 4 KiB pages starting at `start`.
    /// Zero pages is a no-op. Flushing a larger range or all address spaces is
    /// permitted. Paging supplies a valid, non-wrapping canonical range.
    fn invalidate(start: Page<Size4KiB>, page_count: usize);
}

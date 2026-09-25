// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management module for x86 architecture.

/// Base page size used by the guest kernel.
pub const PAGE_SIZE: usize = litebox::mm::vmem::PAGE_SIZE;
/// Shift for x86-64 4 KiB pages.
pub const PAGE_SHIFT: usize = 12;
/// Entries in an x86-64 page-table page.
pub const PTES_PER_PAGE: usize = 512;

const _: () = assert!(PAGE_SIZE == 1 << PAGE_SHIFT);
const _: () = assert!(PAGE_SIZE == PTES_PER_PAGE * core::mem::size_of::<u64>());

pub(crate) mod paging;

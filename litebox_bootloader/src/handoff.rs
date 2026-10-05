// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The front-end handoff. Before calling `kernel_start` with its [`BootInfo`]
//! parser, a front end establishes: long mode, interrupts off, one CPU, a
//! boot stack, relocations applied, and the mapping of
//! [`BootInfo::mapped_limit`].
//! `kernel_start` sets up the console and logging before running the parser.
//!
//! The heap gets all usable RAM above `_heap_start` (`x86_64_kernel.ld`)
//! except [`BootInfo::reserved`], while the boot stack and page tables are
//! still in use: a front end keeps them, and anything else it still needs,
//! below `_heap_start` or lists them in `reserved`.

use arrayvec::{ArrayString, ArrayVec};
use core::ops::Range;
use x86_64::PhysAddr;

// Boot fails rather than dropping entries beyond these limits.
pub const MAX_RAM_REGIONS: usize = 32;
pub const MAX_RESERVED: usize = 16;
pub const MAX_MODULES: usize = 8;
pub const MAX_CMDLINE: usize = 1024;

pub struct BootInfo {
    /// Usable RAM from the memory map, not clamped to `mapped_limit`.
    pub usable: ArrayVec<Range<PhysAddr>, MAX_RAM_REGIONS>,
    /// Boot structures and modules inside `usable` that must not reach the heap.
    pub reserved: ArrayVec<Range<PhysAddr>, MAX_RESERVED>,
    /// Boot modules, in order.
    pub modules: ArrayVec<Range<PhysAddr>, MAX_MODULES>,
    pub cmdline: ArrayString<MAX_CMDLINE>,
    /// Physical memory below this is mapped read/write at `PA + KERNEL_OFFSET`
    /// on entry.
    pub mapped_limit: PhysAddr,
}

impl BootInfo {
    pub fn cmdline_value(&self, key: &str) -> Option<&str> {
        self.cmdline.split_ascii_whitespace().find_map(|arg| {
            arg.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
        })
    }
}

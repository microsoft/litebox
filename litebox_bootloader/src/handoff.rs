// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The front-end handoff. Before calling `kernel_start`, a front end
//! establishes: long mode, interrupts off, one CPU, a boot stack, relocations
//! applied, and physical memory below [`BootInfo::mapped_limit`] mapped
//! read/write at `PA + KERNEL_OFFSET`.

use arrayvec::{ArrayString, ArrayVec};

/// A half-open physical range `[start, end)`.
#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}

// Boot fails rather than dropping entries beyond these limits.
pub const MAX_RAM_REGIONS: usize = 32;
pub const MAX_RESERVED: usize = 16;
pub const MAX_MODULES: usize = 8;
pub const MAX_CMDLINE: usize = 1024;

pub struct BootInfo {
    /// Usable RAM from the memory map, not clamped to `mapped_limit`.
    pub usable: ArrayVec<Range, MAX_RAM_REGIONS>,
    /// Boot structures and modules inside `usable` that must not reach the heap.
    pub reserved: ArrayVec<Range, MAX_RESERVED>,
    /// Boot modules (`-initrd`), in order.
    pub modules: ArrayVec<Range, MAX_MODULES>,
    pub cmdline: ArrayString<MAX_CMDLINE>,
    /// Physical memory below this is mapped at `PA + KERNEL_OFFSET` on entry.
    pub mapped_limit: u64,
}

impl BootInfo {
    pub fn cmdline_value(&self, key: &str) -> Option<&str> {
        self.cmdline.split_ascii_whitespace().find_map(|arg| {
            arg.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
        })
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The front-end handoff. Before calling `kernel_start` with its [`BootInfo`]
//! parser, a front end establishes: long mode, interrupts off, one CPU, a
//! boot stack, the image running at `KERNEL_IMAGE_OFFSET` with relocations
//! applied, and the mapping of [`BootInfo::mapped_limit`].
//! `kernel_start` sets up the console and logging before running the parser.
//!
//! The heap gets all usable RAM above the kernel image (`_image_end` in
//! `x86_64_kernel.ld`) except [`BootInfo::reserved`], while the boot stack
//! and page tables are still in use: a front end keeps them, and anything
//! else it still needs, below the image's end or lists them in `reserved`.
//! What it keeps below the image unlisted must be dead once the kernel runs
//! (e.g., the CPU trampoline may reuse it).

use arrayvec::{ArrayString, ArrayVec};
use core::ops::Range;
use litebox_platform_vm_kernel::cpu::MAX_CPUS;
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
    /// The ACPI RSDP, if the front end knows where; otherwise it is searched
    /// for where the BIOS leaves it.
    pub rsdp: Option<PhysAddr>,
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

/// The page size of the ranges below.
pub(crate) const PAGE_SIZE: u64 = 4096;

impl BootInfo {
    /// The usable RAM in `window`, but the reserved ranges.
    pub(crate) fn free_ranges(
        &self,
        window: Range<PhysAddr>,
    ) -> ArrayVec<Range<PhysAddr>, { MAX_RAM_REGIONS + MAX_RESERVED }> {
        // Each reserved range splits at most one free range in two.
        let mut free = ArrayVec::new();
        for r in &self.usable {
            let start = r.start.max(window.start);
            let end = r.end.min(window.end);
            if start < end {
                free.push(start..end);
            }
        }
        for hole in &self.reserved {
            subtract(&mut free, hole);
        }
        free
    }

    /// A page for the CPU trampoline: free RAM ([`Self::free_ranges`]) below
    /// VGA memory (as startup IPIs' pages are: see
    /// [`litebox_hal::interrupt::VGA_MEMORY`]) and below `image`, the kernel
    /// image's start (so the heap, above it, never gets it), but page 0 (the
    /// real-mode IVT and BIOS data); the highest.
    pub(crate) fn trampoline_page(&self, image: PhysAddr) -> Option<PhysAddr> {
        let end = image.min(PhysAddr::new(litebox_hal::interrupt::VGA_MEMORY.start));
        self.free_ranges(PhysAddr::new(PAGE_SIZE)..end)
            .iter()
            .filter_map(|r| {
                let end = r.end.align_down(PAGE_SIZE);
                (r.start.align_up(PAGE_SIZE) < end).then(|| end - PAGE_SIZE)
            })
            .max()
    }

    /// How many CPUs to use at most: [`MAX_CPUS`], or `litebox.cpus` if
    /// lower; `Err` with its value if that is not a positive number.
    pub(crate) fn cpu_limit(&self) -> Result<usize, &str> {
        let Some(value) = self.cmdline_value("litebox.cpus") else {
            return Ok(MAX_CPUS);
        };
        match value.parse::<usize>() {
            Ok(limit) if limit != 0 => Ok(limit.min(MAX_CPUS)),
            _ => Err(value),
        }
    }
}

fn subtract<const N: usize>(ranges: &mut ArrayVec<Range<PhysAddr>, N>, hole: &Range<PhysAddr>) {
    let mut out = ArrayVec::<Range<PhysAddr>, N>::new();
    let mut keep = |r: Range<PhysAddr>| {
        assert!(
            out.try_push(r).is_ok(),
            "free-memory list overflowed ({N} ranges)"
        );
    };
    for r in ranges.iter() {
        if hole.end <= r.start || hole.start >= r.end {
            keep(r.clone());
            continue;
        }
        if r.start < hole.start {
            keep(r.start..hole.start);
        }
        if hole.end < r.end {
            keep(hole.end..r.end);
        }
    }
    *ranges = out;
}

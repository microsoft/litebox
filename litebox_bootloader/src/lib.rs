// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boots a LiteBox kernel-mode runner: takes the handoff from a boot front
//! end, brings up a `VmKernel` (heap, interrupts, TSC, and the PIT as its
//! deadline timer), and runs the runner's `entry!` function.
//!
//! Front ends: PVH.
//!
//! The runner provides the panic handler and, through `entry!`, the logger.
//!
//! Requirements: link with this crate's `x86_64_kernel.ld` (its path is in
//! `DEP_LITEBOX_BOOTLOADER_LINKER_SCRIPT` for build scripts). Hardware is
//! reached through `litebox_hal`.

// Bare-metal only: defines `_start` and the global allocator, and needs the
// kernel's `entry!` symbols. Elsewhere (host builds of the workspace) the crate
// is empty.
#![cfg(all(target_arch = "x86_64", target_os = "none"))]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

pub mod handoff;
mod heap;
mod layout;
mod pvh;

use core::ops::Range;
use handoff::BootInfo;
use layout::{
    heap_start_address, rodata_end_address, rodata_start_address, text_end_address,
    text_start_address,
};
use litebox_platform_vm_kernel::clock::{ClockSource as _, DeadlineTimer, TscClock};
use litebox_platform_vm_kernel::{BootConfig, KERNEL_OFFSET, VmKernel};
use x86_64::PhysAddr;

const PAGE_SIZE: u64 = 4096;

pub struct Kernel {
    pub platform: &'static VmKernel,
    /// Boot modules stay mapped at `PA + KERNEL_OFFSET`, in kernel-managed
    /// RAM, for the kernel's lifetime.
    pub boot_info: &'static BootInfo,
    pub tsc_khz: u64,
}

/// Declares the kernel's `fn(Kernel) -> !`, run on the kernel stack once the
/// platform is up, and its `&'static dyn log::Log`, installed before the
/// bootloader logs anything. Exactly one per kernel; the kernel must depend
/// on `log`.
#[macro_export]
macro_rules! entry {
    ($main:path, $logger:expr) => {
        #[unsafe(no_mangle)]
        fn __litebox_kernel_main(kernel: $crate::Kernel) -> ! {
            $main(kernel)
        }

        #[unsafe(no_mangle)]
        fn __litebox_kernel_logger() -> &'static dyn ::log::Log {
            $logger
        }
    };
}

unsafe extern "Rust" {
    safe fn __litebox_kernel_main(kernel: Kernel) -> !;
    safe fn __litebox_kernel_logger() -> &'static dyn log::Log;
}

static BOOT: spin::Once<(BootInfo, u64)> = spin::Once::new();

fn early_console_init() {
    let _ = log::set_logger(__litebox_kernel_logger());
    log::set_max_level(log::LevelFilter::Info);

    litebox_hal::console_println!("=====================");
    litebox_hal::console_println!(" Hello from LiteBox! ");
    litebox_hal::console_println!("=====================");
}

/// The front ends' entry; see [`handoff`].
fn kernel_start(boot_info: impl FnOnce() -> BootInfo) -> ! {
    early_console_init();
    let info = boot_info();
    if let Some(level) = info.cmdline_value("litebox.log") {
        log::set_max_level(level.parse().unwrap_or(log::LevelFilter::Info));
    }
    litebox_util_log::info!(cmdline:% = info.cmdline.as_str(); "boot");

    seed_heap(&info);
    let ram_end = ram_end(&info);
    report_unused_ram(&info, ram_end);
    let ram: arrayvec::ArrayVec<_, { handoff::MAX_RAM_REGIONS }> = info
        .usable
        .iter()
        .filter(|r| r.start < ram_end)
        .map(|r| r.start..r.end.min(ram_end))
        .collect();
    let to_pa = |va: u64| VmKernel::va_to_pa(x86_64::VirtAddr::new(va));
    litebox_hal::interrupt::init_legacy_pics();
    let tsc_khz = litebox_hal::clock::calibrate_tsc_khz();
    litebox_util_log::info!(mhz:% = tsc_khz / 1000; "TSC calibrated against the PIT");
    BOOT.call_once(|| (info, tsc_khz));
    let clock: &'static TscClock =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(TscClock::new(tsc_khz)));
    let timer: &'static PitDeadline =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(PitDeadline {
            // Safety: the only one, after `init_legacy_pics`.
            pit: unsafe { litebox_hal::timer::PitTimer::init() },
            clock,
        }));
    // Safety: the front end established the direct mapping with IRQs off on one
    // CPU. The heap contains only `ram`, text bounds come from the linker, and
    // no live resource needs the boot stack after the handoff.
    unsafe {
        VmKernel::boot(
            BootConfig {
                page_allocator: &heap::KernelPages,
                clock,
                timer: Some(timer),
                ram: &ram,
                text: to_pa(text_start_address())..to_pa(text_end_address()),
                read_only: to_pa(rodata_start_address())..to_pa(rodata_end_address()),
                ignored_vectors: &litebox_hal::interrupt::SPURIOUS_VECTORS,
            },
            kernel_main,
        )
    }
}

/// The PIT as a deadline timer on the TSC clock.
struct PitDeadline {
    pit: litebox_hal::timer::PitTimer,
    clock: &'static TscClock,
}

impl DeadlineTimer for PitDeadline {
    fn vector(&self) -> u8 {
        litebox_hal::timer::VECTOR
    }

    fn arm(&self, deadline: u64) {
        let delay = deadline.saturating_sub(self.clock.monotonic_nanos());
        self.pit.arm(core::time::Duration::from_nanos(delay));
    }

    fn disarm(&self) {
        self.pit.disarm();
    }

    fn end_of_interrupt(&self) {
        self.pit.end_of_interrupt();
    }
}

fn kernel_main(platform: &'static VmKernel) -> ! {
    let (boot_info, tsc_khz) = BOOT.get().expect("boot info captured");
    for m in &boot_info.modules {
        assert!(
            platform.contains_ram(m.clone()),
            "boot module {:#x}..{:#x} lies outside kernel-managed RAM",
            m.start.as_u64(),
            m.end.as_u64()
        );
    }
    __litebox_kernel_main(Kernel {
        platform,
        boot_info,
        tsc_khz: *tsc_khz,
    })
}

/// Heap seeding precedes the permanent mapping, so RAM must fit the boot mapping.
fn ram_end(info: &BootInfo) -> PhysAddr {
    info.usable
        .iter()
        .filter(|r| r.start < info.mapped_limit)
        .map(|r| r.end.min(info.mapped_limit))
        .max()
        .expect("no usable RAM")
        .align_down(PAGE_SIZE)
}

fn report_unused_ram(info: &BootInfo, ram_end: PhysAddr) {
    let unused: u64 = info
        .usable
        .iter()
        .map(|r| r.end.as_u64().saturating_sub(r.start.max(ram_end).as_u64()))
        .sum();
    if unused != 0 {
        litebox_util_log::warn!(
            unused_mib:% = unused >> 20,
            limit:% = format_args!("{:#x}", ram_end.as_u64());
            "RAM above the kernel-managed limit is unused"
        );
    }
}

fn seed_heap(info: &BootInfo) {
    let heap_floor = PhysAddr::new(heap_start_address() - KERNEL_OFFSET);
    let ram_end = ram_end(info);
    // Each reserved range splits at most one free range in two.
    let mut free = arrayvec::ArrayVec::<
        Range<PhysAddr>,
        { handoff::MAX_RAM_REGIONS + handoff::MAX_RESERVED },
    >::new();
    for r in &info.usable {
        let start = r.start.max(heap_floor);
        let end = r.end.min(ram_end);
        if start < end {
            free.push(start..end);
        }
    }
    for hole in &info.reserved {
        subtract(&mut free, hole);
    }
    let mut total = 0;
    for r in &free {
        let start = r.start.align_up(PAGE_SIZE);
        let end = r.end.align_down(PAGE_SIZE);
        if start >= end {
            continue;
        }
        let va = usize::try_from(start.as_u64() + KERNEL_OFFSET).unwrap();
        let len = usize::try_from(end - start).unwrap();
        // Safety: usable, unreserved RAM above the image, mapped at
        // `KERNEL_OFFSET` by the front end.
        unsafe { heap::add_memory(va, len) };
        total += end - start;
        litebox_util_log::debug!(
            start:% = format_args!("{:#x}", start.as_u64()),
            end:% = format_args!("{:#x}", end.as_u64());
            "heap"
        );
    }
    litebox_util_log::info!(mib:% = total >> 20; "heap seeded");
}

fn subtract<const N: usize>(
    ranges: &mut arrayvec::ArrayVec<Range<PhysAddr>, N>,
    hole: &Range<PhysAddr>,
) {
    let mut out = arrayvec::ArrayVec::<Range<PhysAddr>, N>::new();
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

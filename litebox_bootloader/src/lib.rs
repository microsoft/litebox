// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boots a LiteBox kernel-mode runner: takes the handoff from a boot front
//! end, brings up a `VmKernel` (heap, interrupts, TSC), and runs the runner's
//! `entry!` function.
//!
//! Front ends: PVH (direct kernel boot, e.g. `qemu -kernel`).
//!
//! The runner provides the panic handler and, through `entry!`, the logger.
//!
//! Requirements: link with this crate's `x86_64_kernel.ld` (its path is in
//! `DEP_LITEBOX_BOOTLOADER_LINKER_SCRIPT` for build scripts). Assumes PC
//! hardware: COM1, legacy PICs, and the PIT (to calibrate the TSC).

// Owns the global allocator: empty on hosted targets.
#![cfg(all(target_arch = "x86_64", target_os = "none"))]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

pub mod handoff;
mod heap;
mod layout;
pub mod machine;
mod pvh;
pub mod serial;

use handoff::{BootInfo, Range};
use layout::{
    heap_start_address, rodata_end_address, rodata_start_address, text_end_address,
    text_start_address,
};
use litebox_platform_vm_kernel::{BootConfig, KERNEL_OFFSET, VmKernel, clock::TscClock};

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

    serial_println!("=====================");
    serial_println!(" Hello from LiteBox! ");
    serial_println!("=====================");
}

fn kernel_start(info: BootInfo) -> ! {
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
        .map(|r| x86_64::PhysAddr::new(r.start)..x86_64::PhysAddr::new(r.end.min(ram_end)))
        .collect();
    let to_pa = |va: u64| VmKernel::va_to_pa(x86_64::VirtAddr::new(va));
    machine::init_legacy_pics();
    let tsc_khz = machine::calibrate_tsc_khz();
    litebox_util_log::info!(mhz:% = tsc_khz / 1000; "TSC calibrated against the PIT");
    BOOT.call_once(|| (info, tsc_khz));
    let clock = alloc::boxed::Box::leak(alloc::boxed::Box::new(TscClock::new(tsc_khz)));
    // Safety: the front end established the direct mapping with IRQs off on one
    // CPU. The heap contains only `ram`, text bounds come from the linker, and
    // no live resource needs the boot stack after the handoff.
    unsafe {
        VmKernel::boot(
            BootConfig {
                page_allocator: &heap::KernelPages,
                clock,
                ram: &ram,
                text: to_pa(text_start_address())..to_pa(text_end_address()),
                read_only: to_pa(rodata_start_address())..to_pa(rodata_end_address()),
                ignored_vectors: &machine::SPURIOUS_VECTORS,
            },
            kernel_main,
        )
    }
}

fn kernel_main(platform: &'static VmKernel) -> ! {
    let (boot_info, tsc_khz) = BOOT.get().expect("boot info captured");
    // Modules are read through the kernel mapping, which covers only managed RAM.
    for m in &boot_info.modules {
        assert!(
            platform.contains_ram(x86_64::PhysAddr::new(m.start)..x86_64::PhysAddr::new(m.end)),
            "boot module {:#x}..{:#x} lies outside kernel-managed RAM",
            m.start,
            m.end
        );
    }
    __litebox_kernel_main(Kernel {
        platform,
        boot_info,
        tsc_khz: *tsc_khz,
    })
}

/// Heap seeding precedes the permanent mapping, so RAM must fit the boot mapping.
fn ram_end(info: &BootInfo) -> u64 {
    info.usable
        .iter()
        .filter(|r| r.start < info.mapped_limit)
        .map(|r| r.end.min(info.mapped_limit))
        .max()
        .expect("no usable RAM")
        & !(PAGE_SIZE - 1)
}

fn report_unused_ram(info: &BootInfo, ram_end: u64) {
    let unused: u64 = info
        .usable
        .iter()
        .map(|r| r.end.saturating_sub(r.start.max(ram_end)))
        .sum();
    if unused != 0 {
        litebox_util_log::warn!(
            unused_mib:% = unused >> 20,
            limit:% = format_args!("{ram_end:#x}");
            "RAM above the kernel-managed limit is unused"
        );
    }
}

/// The image, boot scratch, and boot modules must stay out of the heap.
fn seed_heap(info: &BootInfo) {
    let heap_floor = heap_start_address() - KERNEL_OFFSET;
    let ram_end = ram_end(info);
    // Each reserved range splits at most one free range in two.
    let mut free =
        arrayvec::ArrayVec::<Range, { handoff::MAX_RAM_REGIONS + handoff::MAX_RESERVED }>::new();
    for r in &info.usable {
        let start = r.start.max(heap_floor);
        let end = r.end.min(ram_end);
        if start < end {
            free.push(Range { start, end });
        }
    }
    for hole in &info.reserved {
        subtract(&mut free, *hole);
    }
    let mut total = 0;
    for r in &free {
        let start = r.start.next_multiple_of(PAGE_SIZE);
        let end = r.end & !(PAGE_SIZE - 1);
        if start >= end {
            continue;
        }
        let va = usize::try_from(start + KERNEL_OFFSET).unwrap();
        let len = usize::try_from(end - start).unwrap();
        // Safety: usable, unreserved RAM above the image, mapped at
        // `KERNEL_OFFSET` by the front end.
        unsafe { heap::add_memory(va, len) };
        total += end - start;
        litebox_util_log::debug!(start:% = format_args!("{start:#x}"), end:% = format_args!("{end:#x}"); "heap");
    }
    litebox_util_log::info!(mib:% = total >> 20; "heap seeded");
}

fn subtract<const N: usize>(ranges: &mut arrayvec::ArrayVec<Range, N>, hole: Range) {
    let mut out = arrayvec::ArrayVec::<Range, N>::new();
    let mut keep = |r: Range| {
        assert!(
            out.try_push(r).is_ok(),
            "free-memory list overflowed ({N} ranges)"
        );
    };
    for r in ranges.iter() {
        if hole.end <= r.start || hole.start >= r.end {
            keep(*r);
            continue;
        }
        if r.start < hole.start {
            keep(Range {
                start: r.start,
                end: hole.start,
            });
        }
        if hole.end < r.end {
            keep(Range {
                start: hole.end,
                end: r.end,
            });
        }
    }
    *ranges = out;
}

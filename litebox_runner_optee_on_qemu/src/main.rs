// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs OP-TEE TAs with LiteBox as the guest kernel of a QEMU VM. Exits QEMU
//! with status 33 if all tests pass and 65 otherwise (see [`machine::exit`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod boot;
mod broker;
mod heap;
mod layout;
mod machine;
mod optee;
mod serial;
mod tests;

use boot::{BootInfo, Range};
use core::panic::PanicInfo;
use layout::{
    heap_start_address, rodata_end_address, rodata_start_address, text_end_address,
    text_start_address,
};
use litebox_platform_vm_kernel::{
    BootConfig, KERNEL_OFFSET, VmKernel,
    clock::TscClock,
    providers::{PRK_LEN, set_platform_root_key},
};
use serial::serial_println;

const PAGE_SIZE: u64 = 4096;

struct SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if is_spurious_tar_error(record) {
            return;
        }
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        serial::print_str(&buf);
    }

    fn flush(&self) {}
}

/// `tar-no-std` logs this error for the end-of-archive block of every valid
/// archive.
fn is_spurious_tar_error(record: &log::Record) -> bool {
    use core::fmt::Write as _;
    const SPURIOUS: &str = "Unparsable size (ParseIntError { kind: Empty })";
    if record.level() != log::Level::Error || !record.target().starts_with("tar_no_std") {
        return false;
    }
    // Only the prefix is needed; truncation is expected.
    let mut msg = arrayvec::ArrayString::<64>::new();
    let _ = write!(msg, "{}", record.args());
    msg.starts_with(SPURIOUS)
}

static SERIAL_LOGGER: SerialLogger = SerialLogger;

pub(crate) static BOOT_INFO: spin::Once<BootInfo> = spin::Once::new();

pub(crate) fn early_console_init() {
    let _ = log::set_logger(&SERIAL_LOGGER);
    log::set_max_level(log::LevelFilter::Info);

    serial_println!("=============================");
    serial_println!(" Hello from LiteBox on QEMU! ");
    serial_println!("=============================");
}

pub(crate) fn kernel_start(info: BootInfo) -> ! {
    if let Some(level) = info.cmdline_value("litebox.log") {
        log::set_max_level(level.parse().unwrap_or(log::LevelFilter::Info));
    }
    litebox_util_log::info!(cmdline:% = info.cmdline.as_str(); "boot");

    seed_heap(&info);
    let info = BOOT_INFO.call_once(|| info);
    let ram_end = ram_end(info);
    report_unused_ram(info, ram_end);
    let ram: arrayvec::ArrayVec<_, { boot::MAX_RAM_REGIONS }> = info
        .usable
        .iter()
        .filter(|r| r.start < ram_end)
        .map(|r| x86_64::PhysAddr::new(r.start)..x86_64::PhysAddr::new(r.end.min(ram_end)))
        .collect();
    let to_pa = |va: u64| VmKernel::va_to_pa(x86_64::VirtAddr::new(va));
    machine::init_legacy_pics();
    let tsc_khz = machine::calibrate_tsc_khz();
    litebox_util_log::info!(mhz:% = tsc_khz / 1000; "TSC calibrated against the PIT");
    let clock = alloc::boxed::Box::leak(alloc::boxed::Box::new(TscClock::new(tsc_khz)));
    // Safety: PVH boot established the direct mapping with IRQs off on one CPU.
    // The heap contains only `ram`, text bounds come from the linker, and no
    // live resource needs the boot stack after the handoff.
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
    let info = BOOT_INFO.get().expect("boot info captured");
    // Modules are read through the kernel mapping, which covers only managed RAM.
    for m in &info.modules {
        assert!(
            platform.contains_ram(x86_64::PhysAddr::new(m.start)..x86_64::PhysAddr::new(m.end)),
            "boot module {:#x}..{:#x} lies outside kernel-managed RAM",
            m.start,
            m.end
        );
    }

    install_development_platform_root_key();
    tests::check_user_memory_protection(platform);

    optee::run(platform, info);
    serial_println!("[litebox] ALL TESTS PASSED");
    machine::exit(true)
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
        arrayvec::ArrayVec::<Range, { boot::MAX_RAM_REGIONS + boot::MAX_RESERVED }>::new();
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
        // `KERNEL_OFFSET` by the boot stub.
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

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::panic_print(format_args!(
        "[litebox] PANIC: {info}\n[litebox] TESTS FAILED\n"
    ));
    machine::exit(false)
}

/// SHA-256 of "litebox-vm development platform root key v1 -- NOT A SECRET".
const DEV_PRK: [u8; PRK_LEN] = [
    0xb3, 0x09, 0x9d, 0xf9, 0x38, 0x4f, 0xc7, 0x67, 0xb7, 0x38, 0x1c, 0x49, 0xc1, 0x67, 0x13, 0x82,
    0xeb, 0x25, 0x85, 0xaf, 0x85, 0xf0, 0x39, 0xc9, 0xe8, 0x30, 0x4e, 0x4e, 0x04, 0xe1, 0xc8, 0x11,
];

/// No confidentiality: this development PRK is public and identical on every boot.
/// TODO: provision a TPM-backed PRK.
fn install_development_platform_root_key() {
    litebox_util_log::warn!(
        "installing a DEVELOPMENT platform root key with NO SECURITY VALUE; \
         anything sealed with keys derived from it is sealed against nobody"
    );
    set_platform_root_key(&DEV_PRK);
}

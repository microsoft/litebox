#![no_std]
#![no_main]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use x86_64::structures::paging::PhysFrame;

entry_point!(kernel_main);

/// Entry point for the kernel
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    // Initialize memory
    let phys_mem_offset = boot_info.physical_memory_offset;
    unsafe {
        // Initialize heap - use 10MB heap starting at a fixed location
        let heap_start = 0x_4444_4444_0000;
        let heap_size = 10 * 1024 * 1024; // 10 MB
        litebox_platform_baremetal::memory::init_heap(heap_start, heap_size);

        // Initialize page allocator - use memory from the bootloader
        // We'll use memory starting at 16MB physical
        let page_alloc_start = 16 * 1024 * 1024;
        let page_alloc_size = 32 * 1024 * 1024; // 32 MB for page allocation
        litebox_platform_baremetal::memory::init_page_allocator(page_alloc_start, page_alloc_size);
    }

    // Get the page table root from CR3
    let page_table_root = PhysFrame::containing_address(x86_64::PhysAddr::new(
        litebox_platform_baremetal::arch::read_cr3() as u64,
    ));

    // Create and initialize the platform
    let platform = litebox_platform_baremetal::BaremetalPlatform::new(page_table_root);
    platform.init();

    litebox::log_println!(platform, "Baremetal LiteBox runner starting...");
    litebox::log_println!(platform, "Physical memory offset: {:#x}", phys_mem_offset);

    // Initialize system time
    litebox_platform_baremetal::time::SystemTime::init_boot_time();

    litebox::log_println!(platform, "System time initialized");

    litebox::log_println!(
        platform,
        "Baremetal platform initialized successfully!"
    );
    litebox::log_println!(
        platform,
        "System ready - waiting for guest programs (not yet implemented)"
    );

    // Note: Linux shim and filesystem initialization would go here
    // For now, this is a minimal runner that just boots and halts
    litebox::log_println!(platform, "Entering halt loop...");

    // Halt loop
    loop {
        litebox_platform_baremetal::arch::hlt();
    }
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    litebox_platform_baremetal::serial::write_str("KERNEL PANIC: ");
    if let Some(location) = info.location() {
        litebox_platform_baremetal::serial::write_str("at ");
        litebox_platform_baremetal::serial::write_str(location.file());
        litebox_platform_baremetal::serial::write_str(":");
        // Can't easily format numbers without std, so just print the message
    }

    use core::fmt::Write;
    struct SerialWriter;
    impl Write for SerialWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            litebox_platform_baremetal::serial::write_str(s);
            Ok(())
        }
    }
    let _ = core::write!(SerialWriter, " - {}\n", info.message());

    loop {
        litebox_platform_baremetal::arch::hlt();
    }
}

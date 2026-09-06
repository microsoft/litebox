// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std] // don't link the Rust standard library
#![no_main] // disable all Rust-level entry points

core::arch::global_asm!(include_str!("entry.S"));

mod globals;

extern crate alloc;

use alloc::boxed::Box;
use litebox::utils::TruncateExt as _;
use litebox_platform_linux_kernel::{HostInterface, host::snp::ghcb::ghcb_prints};

/// `log` backend that forwards to the GHCB serial console.
struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        ghcb_prints(&buf);
    }

    fn flush(&self) {}
}

static HOST_LOGGER: HostLogger = HostLogger;

type Platform = litebox_platform_linux_kernel::host::snp::snp_impl::SnpLinuxKernel;
type Shim = litebox_shim_linux::LinuxShim<Platform>;

// FUTURE: eliminate this entirely (ideal).
static SHIM: once_cell::race::OnceBox<Shim> = once_cell::race::OnceBox::new();

#[unsafe(no_mangle)]
pub extern "C" fn floating_point_handler(_pt_regs: &mut litebox_common_linux::PtRegs) {
    todo!()
}

/// # Panics
///
/// Panics if the shim has not been initialized.
#[unsafe(no_mangle)]
pub extern "C" fn page_fault_handler(pt_regs: &mut litebox_common_linux::PtRegs) {
    let addr: u64 = litebox_platform_linux_kernel::arch::instructions::cr2();
    let code = pt_regs.orig_rax;

    let shim = SHIM.get().expect("initialized");

    match unsafe {
        shim.page_manager()
            .handle_page_fault(addr.trunc(), code as u64)
    } {
        Ok(()) => (),
        Err(e) => {
            if let litebox::mm::linux::PageFaultError::AccessError(_) = e {
                // Try to recover from page faults in kernel mode using the exception table.
                // This handles fallible memory operations like memcpy_fallible.
                // Only check the exception table for kernel-space addresses (high canonical addresses).
                if pt_regs.rip >= <litebox_platform_linux_kernel::host::snp::snp_impl::SnpLinuxKernel as litebox::platform::PageManagementProvider<4096>>::TASK_ADDR_MAX
                    && let Some(fixup_addr) =
                        litebox::mm::exception_table::search_exception_tables(pt_regs.rip.trunc())
                    {
                        pt_regs.rip = fixup_addr;
                        return;
                    }
            }

            litebox_util_log::error!(
                rip:% = pt_regs.rip,
                addr:% = addr,
                code:% = code,
                err:% = e;
                "page fault failed"
            );
            let platform = shim.platform();
            platform.terminate(globals::SM_SEV_TERM_SET, globals::SM_TERM_EXCEPTION);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn int_handler(pt_regs: &mut litebox_common_linux::PtRegs, vector: u64) {
    litebox_platform_linux_kernel::print_str_and_int!("Unhandled interrupt: ", vector, 10);
    litebox_platform_linux_kernel::print_str_and_int!("RIP: ", pt_regs.rip as u64, 16);
    #[cfg(debug_assertions)]
    litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::dump_stack(
        pt_regs.rsp,
        512,
    );
    litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
        globals::SM_SEV_TERM_SET,
        globals::SM_TERM_EXCEPTION,
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn sandbox_kernel_init(
    _pt_regs: &mut litebox_common_linux::PtRegs,
    boot_params: &'static litebox_platform_linux_kernel::host::snp::snp_impl::vmpl2_boot_params,
) {
    ghcb_prints("sandbox_kernel_init called\n");

    let _ = log::set_logger(&HOST_LOGGER);
    log::set_max_level(log::LevelFilter::Trace);

    let ghcb_page = litebox_platform_linux_kernel::arch::PhysAddr::new(boot_params.ghcb_page);
    let ghcb_page_va = litebox_platform_linux_kernel::arch::VirtAddr::new(boot_params.ghcb_page_va);
    if litebox_platform_linux_kernel::host::snp::ghcb::GhcbProtocol::setup_ghcb_page(
        ghcb_page,
        ghcb_page_va,
    )
    .is_none()
    {
        ghcb_prints("GHCB page setup failed\n");
        litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
            globals::SM_SEV_TERM_SET,
            globals::SM_TERM_NO_GHCB,
        );
    } else {
        ghcb_prints("GHCB page setup done\n");
    }

    litebox_platform_linux_kernel::update_cpu_mhz(boot_params.cpu_khz / 1000);

    ghcb_prints("sandbox_kernel_init done\n");
    litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::return_to_host();
}

/// Initializes the sandbox process.
///
/// # Panics
///
/// Panics if the shim has already been initialized.
#[unsafe(no_mangle)]
pub extern "C" fn sandbox_process_init(
    pt_regs: &mut litebox_common_linux::PtRegs,
    boot_params: &'static litebox_platform_linux_kernel::host::snp::snp_impl::vmpl2_boot_params,
) -> ! {
    let pgd = litebox_platform_linux_kernel::arch::PhysAddr::new_truncate(
        litebox_platform_linux_kernel::arch::instructions::cr3()
            & !(litebox::mm::linux::PAGE_SIZE as u64 - 1),
    );
    let platform = litebox_platform_linux_kernel::host::snp::snp_impl::SnpLinuxKernel::new(pgd);
    #[cfg(debug_assertions)]
    litebox_util_log::debug!("sandbox_process_init called");

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let shim = shim_builder.build();
    let initialized = SHIM.set(Box::new(shim)).is_ok();
    assert!(initialized, "shim initialized more than once");

    let _ = (boot_params, pt_regs);
    ghcb_prints("filesystem startup requires a kernel broker platform");
    litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
        globals::SM_SEV_TERM_SET,
        globals::SM_TERM_GENERAL,
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn sandbox_panic(_rsp: u64) {
    todo!()
}

#[unsafe(no_mangle)]
pub extern "C" fn sandbox_task_exit() {
    todo!()
}

#[unsafe(no_mangle)]
pub extern "C" fn do_syscall_64(pt_regs: &mut litebox_common_linux::PtRegs) -> ! {
    litebox_platform_linux_kernel::host::snp::snp_impl::handle_syscall(pt_regs);
}

/// This function is called on panic.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let msg = info.message();
    ghcb_prints(msg.as_str().unwrap_or("empty panic message"));

    if let Some(location) = info.location() {
        ghcb_prints("panic occurred at ");
        ghcb_prints(location.file());
        litebox_platform_linux_kernel::print_str_and_int!(":", u64::from(location.line()), 10);
    } else {
        ghcb_prints("panic occurred but can't get location information...");
    }
    litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
        globals::SM_SEV_TERM_SET,
        globals::SM_TERM_GENERAL,
    );
}

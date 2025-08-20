#![no_std] // don't link the Rust standard library
#![no_main] // disable all Rust-level entry points

core::arch::global_asm!(include_str!("entry.S"));

mod globals;

extern crate alloc;

use litebox::utils::TruncateExt as _;
use litebox_platform_linux_kernel::{HostInterface, host::snp::ghcb::ghcb_prints};

#[unsafe(no_mangle)]
pub extern "C" fn floating_point_handler(_pt_regs: &mut litebox_common_linux::PtRegs) {
    todo!()
}

#[unsafe(no_mangle)]
pub extern "C" fn page_fault_handler(pt_regs: &mut litebox_common_linux::PtRegs) {
    let addr = litebox_platform_linux_kernel::arch::instructions::cr2();
    let code = pt_regs.orig_rax;

    match unsafe {
        litebox_shim_linux::litebox_page_manager().handle_page_fault(addr.truncate(), code as u64)
    } {
        Ok(()) => (),
        Err(e) => {
            litebox::log_println!(
                litebox_platform_multiplex::platform(),
                "page fault at {} for {} with code {} failed: {}",
                pt_regs.rip,
                addr,
                code,
                e
            );
            litebox_platform_multiplex::platform()
                .terminate(globals::SM_SEV_TERM_SET, globals::SM_TERM_EXCEPTION);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn int_handler(_pt_regs: &mut litebox_common_linux::PtRegs, _vector: u64) {
    todo!()
}

#[unsafe(no_mangle)]
pub extern "C" fn sandbox_kernel_init(
    _pt_regs: &mut litebox_common_linux::PtRegs,
    _boot_params: &'static litebox_platform_linux_kernel::host::snp::snp_impl::vmpl2_boot_params,
) {
    ghcb_prints("sandbox_kernel_init called\n");
    todo!()
}

/// Initializes the sandbox process.
#[unsafe(no_mangle)]
pub extern "C" fn sandbox_process_init(
    _pt_regs: &mut litebox_common_linux::PtRegs,
    _boot_params: &'static litebox_platform_linux_kernel::host::snp::snp_impl::vmpl2_boot_params,
) {
    todo!()
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
pub extern "C" fn do_syscall_64(_nr: u64, _pt_regs: &mut litebox_common_linux::PtRegs) {
    todo!()
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

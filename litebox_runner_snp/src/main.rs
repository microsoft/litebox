#![no_std] // don't link the Rust standard library
#![no_main] // disable all Rust-level entry points

core::arch::global_asm!(include_str!("entry.S"));

mod globals;

extern crate alloc;

use alloc::borrow::ToOwned;
use litebox::shim::EnterShim as _;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::ContinueOperation;
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
pub extern "C" fn int_handler(pt_regs: &mut litebox_common_linux::PtRegs, vector: u64) {
    litebox_platform_linux_kernel::print_str_and_int!("Unhandled interrupt: ", vector, 10);
    litebox_platform_linux_kernel::print_str_and_int!("RIP: ", pt_regs.rip as u64, 16);
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

const ROOTFS: &[u8] = include_bytes!("./test.tar");

/// Initializes the sandbox process.
#[unsafe(no_mangle)]
pub extern "C" fn sandbox_process_init(
    pt_regs: &mut litebox_common_linux::PtRegs,
    boot_params: &'static litebox_platform_linux_kernel::host::snp::snp_impl::vmpl2_boot_params,
) {
    let pgd = litebox_platform_linux_kernel::arch::PhysAddr::new_truncate(
        litebox_platform_linux_kernel::arch::instructions::cr3()
            & !(litebox::mm::linux::PAGE_SIZE as u64 - 1),
    );
    let platform = litebox_platform_linux_kernel::host::snp::snp_impl::SnpLinuxKernel::new(pgd);
    litebox::log_println!(platform, "sandbox_process_init called");

    litebox_platform_multiplex::set_platform(platform);
    let litebox = litebox_shim_linux::init_process(platform.init_task(boot_params));
    let in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, ROOTFS.into());
    litebox_shim_linux::set_fs(litebox_shim_linux::default_fs(in_mem_fs, tar_ro));

    let parse_args =
        |params: &litebox_platform_linux_kernel::host::snp::snp_impl::vmpl2_boot_params| -> Option<(
            alloc::string::String,
            alloc::vec::Vec<alloc::ffi::CString>,
            alloc::vec::Vec<alloc::ffi::CString>,
        )> {
            let mut argv = alloc::vec::Vec::new();
            let mut envp = alloc::vec::Vec::new();

            let argv_len = params.argv_len.reinterpret_as_unsigned() as usize;
            let env_len = params.env_len.reinterpret_as_unsigned() as usize;
            let total = argv_len + env_len;

            let mut idx = 0;
            while idx < total {
                let arg = core::ffi::CStr::from_bytes_until_nul(&params.argv_and_env[idx..])
                    .ok()?
                    .to_owned();
                let this_len = arg.count_bytes() + 1;

                if idx < argv_len {
                    argv.push(arg);
                } else {
                    envp.push(arg);
                }
                idx += this_len;
            }
            let program = argv.first().cloned()?;
            Some((program.to_str().ok()?.to_owned(), argv, envp))
        };
    let Some((program, argv, envp)) = parse_args(boot_params) else {
        litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
            globals::SM_SEV_TERM_SET,
            globals::SM_TERM_INVALID_PARAM,
        );
    };
    *pt_regs = match litebox_shim_linux::load_program(&program, argv, envp) {
        Ok(regs) => regs,
        Err(err) => {
            litebox::log_println!(platform, "failed to load program: {}", err);
            litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
                globals::SM_SEV_TERM_SET,
                globals::SM_TERM_GENERAL,
            );
        }
    };
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
pub extern "C" fn do_syscall_64(pt_regs: &mut litebox_common_linux::PtRegs) {
    match litebox_shim_linux::LinuxShim.syscall(pt_regs) {
        ContinueOperation::ResumeGuest => {}
        ContinueOperation::ExitThread(status) | ContinueOperation::ExitProcess(status) => {
            pt_regs.rax = status.cast_unsigned() as usize;
        }
    }
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

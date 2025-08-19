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
    litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::exit();
}

const ROOTFS: &[u8] = include_bytes!("./test.tar");

#[unsafe(no_mangle)]
pub extern "C" fn sandbox_process_init(
    pt_regs: &mut litebox_common_linux::PtRegs,
    // boot_params: &'static litebox_platform_linux_kernel::host::snp::snp_impl::vmpl2_boot_params,
) {
    let pgd = litebox_platform_linux_kernel::arch::PhysAddr::new_truncate(
        litebox_platform_linux_kernel::arch::instructions::cr3()
            & !(litebox::mm::linux::PAGE_SIZE as u64 - 1),
    );
    let platform = litebox_platform_linux_kernel::host::snp::snp_impl::SnpLinuxKernel::new(pgd);
    litebox::log_println!(platform, "sandbox_process_init called");

    let litebox = litebox::LiteBox::new(platform);
    let in_mem_fs = litebox::fs::in_mem::FileSystem::new(&litebox);
    let tar_ro = litebox::fs::tar_ro::FileSystem::new(&litebox, ROOTFS.into());
    let dev_stdio = litebox::fs::devices::stdio::FileSystem::new(&litebox);
    let fs = litebox::fs::layered::FileSystem::new(
        &litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            &litebox,
            dev_stdio,
            tar_ro,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    );
    litebox_shim_linux::set_fs(fs);
    litebox_platform_multiplex::set_platform(platform);

    let aux = litebox_shim_linux::loader::auxv::init_auxv();
    let loaded_program = match litebox_shim_linux::loader::load_program("/test", alloc::vec![], alloc::vec![], aux) {
        Ok(program) => program,
        Err(err) => {
            litebox::log_println!(platform, "failed to load program: {}", err);
            litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
                globals::SM_SEV_TERM_SET,
                globals::SM_TERM_GENERAL,
            );
        }
    };

    pt_regs.rip = loaded_program.entry_point;
    pt_regs.rsp = loaded_program.user_stack_top;
    pt_regs.rdx = 0;
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
    litebox_platform_multiplex::platform()
        .terminate(globals::SM_SEV_TERM_SET, globals::SM_TERM_GENERAL);
}

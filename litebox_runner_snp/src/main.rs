// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std] // don't link the Rust standard library
#![no_main] // disable all Rust-level entry points

core::arch::global_asm!(include_str!("entry.S"));

mod globals;

extern crate alloc;

use alloc::{borrow::ToOwned, string::ToString};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_platform_linux_kernel::{HostInterface, host::snp::ghcb::ghcb_prints};

// FUTURE: replace this with some kind of OnceLock, or just eliminate this
// entirely (ideal).
static mut SHIM: Option<litebox_shim_linux::LinuxShim> = None;

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

    let shim = &raw const SHIM;

    match unsafe {
        (*shim)
            .as_ref()
            .unwrap()
            .page_manager()
            .handle_page_fault(addr.truncate(), code as u64)
    } {
        Ok(()) => (),
        Err(e) => {
            if let litebox::mm::linux::PageFaultError::AccessError(_) = e {
                // Try to recover from page faults in kernel mode using the exception table.
                // This handles fallible memory operations like memcpy_fallible.
                // Only check the exception table for kernel-space addresses (high canonical addresses).
                if pt_regs.rip >= <litebox_platform_linux_kernel::host::snp::snp_impl::SnpLinuxKernel as litebox::platform::PageManagementProvider<4096>>::TASK_ADDR_MAX
                    && let Some(fixup_addr) =
                        litebox::mm::exception_table::search_exception_tables(pt_regs.rip.truncate())
                    {
                        pt_regs.rip = fixup_addr;
                        return;
                    }
            }

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

/// Pre-defined file paths to load from host for testing purposes.
/// Will remove this after we migrate 9p fs from VSBox to LiteBox, as we can directly access host files then.
#[cfg(debug_assertions)]
const HOST_FILE_PATHS: &[&str] = &[
    "/out/hello",
    "/out/efault",
    "/out/thread_exit",
    "/out/tcp_server",
    // Add more paths as needed
];

/// Load pre-set files from host into the in-memory filesystem
///
/// This is a temporary solution before we migrate 9p fs from VSBox to LiteBox.
#[cfg(debug_assertions)]
fn load_host_files_into_fs<Platform: litebox::sync::RawSyncPrimitivesProvider>(
    in_mem_fs: &mut litebox::fs::in_mem::FileSystem<Platform>,
) {
    use litebox::fs::FileSystem;

    in_mem_fs.with_root_privileges(|fs| {
        // Create /out directory if needed
        let _ = fs.mkdir(
            "/out",
            litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
        );

        for path in HOST_FILE_PATHS {
            match litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::load_file_from_host(path) {
                Ok(data) if !data.is_empty() => {
                    // Create parent directories if needed
                    if let Some(parent) = path.rsplit_once('/').map(|(p, _)| p)
                        && !parent.is_empty() {
                            let _ = fs.mkdir(
                                parent,
                                litebox::fs::Mode::RWXU
                                    | litebox::fs::Mode::RWXG
                                    | litebox::fs::Mode::RWXO,
                            );
                        }

                    // Create and initialize the file
                    let mode =
                        litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO; // executable
                    let flags = litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY;
                    if let Ok(fd) = fs.open(path, flags, mode) {
                        fs.initialize_primarily_read_heavy_file(&fd, data.into());
                        let _ = fs.close(&fd);
                    }
                }
                Ok(_) => {
                    // Empty file, skip
                    litebox::log_println!(
                        litebox_platform_multiplex::platform(),
                        "File is empty, skipping\n"
                    );
                }
                Err(e) => {
                    let s = format_args!("Failed to load file {path}: {e}\n").to_string();
                    // File not available from host or too large, skip
                    litebox::log_println!(litebox_platform_multiplex::platform(), &s);
                }
            }
        }
    });
}

/// Initializes the sandbox process.
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
    litebox::log_println!(platform, "sandbox_process_init called\n");

    litebox_platform_multiplex::set_platform(platform);
    let mut shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let litebox = shim_builder.litebox();
    let in_mem_fs = {
        #[cfg(debug_assertions)]
        {
            let mut fs = litebox::fs::in_mem::FileSystem::new(litebox);
            load_host_files_into_fs(&mut fs);
            fs
        }
        #[cfg(not(debug_assertions))]
        {
            litebox::fs::in_mem::FileSystem::new(litebox)
        }
    };
    let tar_ro =
        litebox::fs::tar_ro::FileSystem::new(litebox, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    shim_builder.set_fs(shim_builder.default_fs(in_mem_fs, tar_ro));

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
    let shim = shim_builder.build();
    unsafe { SHIM = Some(shim) };

    // Loading a program may trigger page faults, so we need to set SHIM before this.
    let shim = &raw const SHIM;
    #[allow(clippy::missing_panics_doc)]
    let program = match unsafe { (*shim).as_ref().expect("initialized") }.load_program(
        platform.init_task(boot_params),
        &program,
        argv,
        envp,
    ) {
        Ok(program) => program,
        Err(err) => {
            litebox::log_println!(platform, "failed to load program: {}", err);
            litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::terminate(
                globals::SM_SEV_TERM_SET,
                globals::SM_TERM_GENERAL,
            );
        }
    };
    unsafe {
        litebox_platform_linux_kernel::host::snp::snp_impl::run_thread(
            alloc::boxed::Box::new(program.entrypoints),
            pt_regs,
        )
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
pub extern "C" fn do_syscall_64(pt_regs: &mut litebox_common_linux::PtRegs) -> ! {
    litebox_platform_linux_kernel::host::snp::snp_impl::handle_syscall(pt_regs);
}

#[unsafe(no_mangle)]
pub extern "C" fn sandbox_tun_read_write() {
    let shim = &raw const SHIM;
    // wait until shim is initialized
    let shim = loop {
        if let Some(shim) = unsafe { (*shim).as_ref() } {
            break shim;
        }
    };
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sandbox_tun_read_write started\n"
    );
    while !litebox_platform_linux_kernel::host::snp::snp_impl::all_threads_exited() {
        let _timeout = loop {
            match shim
                .perform_network_interaction() {
                    litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {},
                    litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => break timeout,
                }
        };
        // TODO: use timeout to wait on host events
    }

    litebox_platform_linux_kernel::host::snp::snp_impl::HostSnpInterface::return_to_host();
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

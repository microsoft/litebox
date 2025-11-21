#![no_std]
#![feature(let_chains)]

extern crate alloc;

use alloc::vec::Vec;
use litebox::fs::FileSystem as _;
use litebox::shim::EnterShim as _;
use ostd::arch::cpu::context::UserContext;
use ostd::prelude::println;
use ostd::task::TaskOptions;
use ostd::user::{ReturnReason, UserMode};
use platform::OstdPlatform;

#[ostd::main]
pub fn main() {
    let program_binary = include_bytes!("../../test-bins/hello_world_static");

    let platform = alloc::boxed::Box::leak(alloc::boxed::Box::new(OstdPlatform::new()));

    // Activate the VmSpace immediately so allocations during load_program can be accessed
    println!("Activating VmSpace...");
    platform.activate_vm_space();

    litebox_platform_multiplex::set_platform(platform);

    let mut shim = litebox_shim_linux::LinuxShim::new();
    let litebox = shim.litebox();

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);

        in_mem.with_root_privileges(|fs| {
            fs.mkdir(
                "/bin",
                litebox::fs::Mode::RWXU
                    | litebox::fs::Mode::RGRP
                    | litebox::fs::Mode::XGRP
                    | litebox::fs::Mode::ROTH
                    | litebox::fs::Mode::XOTH,
            )
            .unwrap();
        });

        in_mem.with_root_privileges(|fs| {
            let fd = fs
                .open(
                    "/bin/hello_world_static",
                    litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                    litebox::fs::Mode::RWXU
                        | litebox::fs::Mode::RGRP
                        | litebox::fs::Mode::XGRP
                        | litebox::fs::Mode::ROTH
                        | litebox::fs::Mode::XOTH,
                )
                .unwrap();
            let mut data = program_binary.as_slice();
            while !data.is_empty() {
                let len = fs.write(&fd, data, None).unwrap();
                data = &data[len..];
            }
            fs.close(&fd).unwrap();
        });

        let tar_ro = litebox::fs::tar_ro::FileSystem::new(
            litebox,
            litebox::fs::tar_ro::EMPTY_TAR_FILE.into(),
        );
        shim.default_fs(in_mem, tar_ro)
    };

    shim.set_fs(initial_file_system);

    let argv: Vec<alloc::ffi::CString> =
        alloc::vec![alloc::ffi::CString::new("/bin/hello_world_static").unwrap(),];
    let envp: Vec<alloc::ffi::CString> = alloc::vec![];

    println!(r#"   _     _ _       ____              "#);
    println!(r#"  | |   (_) |_ ___| __ )  _____  __  "#);
    println!(r#"  | |   | | __/ _ \  _ \ / _ \ \/ /  "#);
    println!(r#"  | |___| | ||  __/ |_) | (_) >  <   "#);
    println!(r#"  |_____|_|\__\___|____/ \___/_/\_\  "#);
    println!(r#"                                     "#);
    println!("Runner initialized with binary at /bin/hello_world_static");
    println!("Loading and executing program...");

    let task_params = litebox_common_linux::TaskParams {
        pid: 1,
        ppid: 0,
        uid: 1000,
        euid: 1000,
        gid: 1000,
        egid: 1000,
    };

    let entrypoints = shim.entrypoints();

    let mut pt_regs = shim
        .load_program(task_params, "/bin/hello_world_static", argv, envp)
        .expect("Failed to load program");

    let user_task = move || {
        let mut user_context = UserContext::default();

        #[cfg(target_arch = "x86_64")]
        {
            user_context.set_rip(pt_regs.rip as usize);
            user_context.set_rsp(pt_regs.rsp as usize);
        }

        let mut user_mode = UserMode::new(user_context);

        loop {
            let return_reason = user_mode.execute(|| false);

            match return_reason {
                ReturnReason::UserSyscall => {
                    let user_context = user_mode.context_mut();
                    copy_uc_to_pt(&user_context, &mut pt_regs);
                    match entrypoints.syscall(&mut pt_regs) {
                        litebox::shim::ContinueOperation::ResumeGuest => {
                            copy_pt_to_uc(user_context, &pt_regs);
                        }
                        litebox::shim::ContinueOperation::ExitThread => {
                            println!("Program exited");
                            break;
                        }
                    }
                }
                ReturnReason::KernelEvent | ReturnReason::UserException => {
                    println!("TODO: Unhandled return reason: {:?}", return_reason);
                    break;
                }
            }
        }
    };

    // Create and run the task
    let task = alloc::sync::Arc::new(TaskOptions::new(user_task).build().unwrap());
    task.run();

    println!("oO0OoO0OoO0OooO0OoO0OoO0OooO0OoO0OoO0Oo");
    ostd::arch::qemu::exit_qemu(ostd::arch::qemu::QemuExitCode::Success);
}

fn copy_uc_to_pt(user_context: &UserContext, pt_regs: &mut litebox_common_linux::PtRegs) {
    // Convert UserContext to PtRegs for the shim
    macro_rules! cp {
        ($($r:ident),*) => { $(pt_regs.$r = user_context.$r();)* };
    }
    #[cfg(target_arch = "x86_64")]
    cp!(
        rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10, r11, r12, r13, r14, r15, rip
    );
}

fn copy_pt_to_uc(user_context: &mut UserContext, pt_regs: &litebox_common_linux::PtRegs) {
    // Copy results back to user context
    macro_rules! cp {
        ($($r:ident),*) => { $(user_context.general_regs_mut().$r = pt_regs.$r;)* };
    }
    #[cfg(target_arch = "x86_64")]
    cp!(
        rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10, r11, r12, r13, r14, r15, rip
    );
}

#![no_std]
#![feature(let_chains)]

extern crate alloc;

use alloc::vec::Vec;
use litebox::fs::FileSystem as _;
use ostd::prelude::println;
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
    platform.register_shim(shim.entrypoints());

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

    platform::run_thread(&mut pt_regs);

    println!("oO0OoO0OoO0OooO0OoO0OoO0OooO0OoO0OoO0Oo");
    ostd::arch::qemu::exit_qemu(ostd::arch::qemu::QemuExitCode::Success);
}

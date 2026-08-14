// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::CString;

use litebox::fs::{FileSystem as _, Mode, OFlags};
use litebox_platform_linux_userland::LinuxUserland as Platform;

#[test]
fn runtime_trampoline_reserve_does_not_skip_brk_heap() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("hello_exec_runtime_trampoline_brk_static_loader");
    let output = std::process::Command::new("gcc")
        .args(["-static", "-o"])
        .arg(&path)
        .arg("./tests/hello.c")
        .output()
        .expect("failed to compile static loader fixture");
    assert!(
        output.status.success(),
        "failed to compile static loader fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let executable_path = "/hello_exec_runtime_trampoline_brk";
    let platform = Platform::new();
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let litebox = shim_builder.litebox();
    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("failed to set permissions on root");
    });
    let fs = shim_builder.default_fs(in_mem_fs, litebox::fs::tar_ro::EMPTY_TAR_FILE.into());
    let fd = fs
        .open(
            executable_path,
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXU | Mode::RWXG | Mode::RWXO,
        )
        .unwrap();
    fs.write(&fd, &std::fs::read(path).unwrap(), None).unwrap();
    fs.close(&fd).unwrap();

    let argv = vec![CString::new(executable_path).unwrap()];
    let envp = vec![CString::new("PATH=/bin").unwrap()];
    let program = shim_builder
        .build()
        .load_program(
            std::sync::Arc::new(fs),
            platform.init_task(),
            executable_path,
            argv,
            envp,
        )
        .unwrap();
    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    assert_eq!(program.process.wait(), 0);
}

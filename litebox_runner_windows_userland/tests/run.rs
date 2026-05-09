// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::ffi::c_void;

unsafe extern "system" {
    fn GetModuleHandleA(module_name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, proc_name: *const u8) -> *const c_void;
}

#[test]
fn loads_minimal_pe_without_imports() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no_import");
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path = build_no_import_pe(&test_dir);
    println!("Built no-import PE fixture at `{}`", pe_path.display());

    let tar_path = test_dir.join("no_import.tar");
    create_tar_with_exe(&test_dir, &tar_path, "no_import.exe");

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    command.args([
        "--initial-files",
        tar_path.to_str().unwrap(),
        "/no_import.exe",
    ]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");

    assert!(
        output.status.success(),
        "runner failed to load no-import PE; status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_no_import_pe(test_dir: &std::path::Path) -> std::path::PathBuf {
    let source_path = test_dir.join("no_import.rs");
    let exe_path = test_dir.join("no_import.exe");
    let syscall_number = nt_terminate_process_syscall_number();
    println!("Using NtTerminateProcess syscall number `{syscall_number:#x}`");
    std::fs::write(
        &source_path,
        minimal_pe_with_nt_terminate_process_syscall_source(syscall_number),
    )
    .unwrap();

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = std::process::Command::new(rustc)
        .args([
            "--edition=2024",
            source_path.to_str().unwrap(),
            "-C",
            "panic=abort",
            "-C",
            "link-arg=/ENTRY:mainCRTStartup",
            "-C",
            "link-arg=/SUBSYSTEM:CONSOLE",
            "-C",
            "link-arg=/NODEFAULTLIB",
            "-o",
            exe_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run rustc for the no-import Windows PE fixture");

    assert!(
        output.status.success(),
        "failed to build no-import Windows PE fixture\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    exe_path
}

fn minimal_pe_with_nt_terminate_process_syscall_source(syscall_number: u32) -> String {
    format!(
        r#"
#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub unsafe extern "system" fn mainCRTStartup() -> ! {{
    unsafe {{
        core::arch::asm!(
            "mov rcx, -1",
            "xor edx, edx",
            "mov r10, rcx",
            "mov eax, {syscall_number:#x}",
            "syscall",
            options(noreturn),
        );
    }}
}}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {{
    loop {{
        core::hint::spin_loop();
    }}
}}
"#
    )
}

fn nt_terminate_process_syscall_number() -> u32 {
    // SAFETY: These are static NUL-terminated strings, and GetModuleHandleA does not retain them.
    let ntdll = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) };
    assert!(
        !ntdll.is_null(),
        "ntdll.dll is not loaded in the test process"
    );

    // SAFETY: These are static NUL-terminated strings, and GetProcAddress does not retain them.
    let nt_terminate_process =
        unsafe { GetProcAddress(ntdll, c"NtTerminateProcess".as_ptr().cast()) };
    assert!(
        !nt_terminate_process.is_null(),
        "NtTerminateProcess is not exported by ntdll.dll"
    );

    // SAFETY: `nt_terminate_process` points to executable code in the loaded ntdll image. Reading
    // a small prefix of the function stub is sufficient to decode the `mov eax, imm32` syscall ID.
    let stub = unsafe { std::slice::from_raw_parts(nt_terminate_process.cast::<u8>(), 32) };
    let syscall_offset = stub
        .windows(2)
        .position(|bytes| bytes == [0x0f, 0x05])
        .expect("NtTerminateProcess stub does not contain syscall instruction");
    let mov_eax_offset = stub[..syscall_offset]
        .iter()
        .position(|byte| *byte == 0xb8)
        .expect("NtTerminateProcess stub does not load a syscall number into eax");

    u32::from_le_bytes(
        stub[mov_eax_offset + 1..mov_eax_offset + 5]
            .try_into()
            .unwrap(),
    )
}

fn create_tar_with_exe(test_dir: &std::path::Path, tar_path: &std::path::Path, exe_name: &str) {
    let output = std::process::Command::new("tar.exe")
        .args([
            "-cf",
            tar_path.to_str().unwrap(),
            "-C",
            test_dir.to_str().unwrap(),
            exe_name,
        ])
        .output()
        .expect("failed to run tar.exe for the no-import Windows PE fixture");

    assert!(
        output.status.success(),
        "failed to create tar for no-import Windows PE fixture\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

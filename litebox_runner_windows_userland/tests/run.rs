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
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path = build_no_import_pe(&test_dir);
    println!(
        "Built rewritten no-import PE fixture at `{}`",
        pe_path.display()
    );
    for dll_name in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
        let dll_path = build_rewritten_system_dll(&test_dir, dll_name);
        println!(
            "Built rewritten {dll_name} fixture at `{}`",
            dll_path.display()
        );
    }
    // ntdll's NLS init opens these locale tables before reaching the test's
    // `NtTerminateProcess` syscall; copy them verbatim from the host.
    for nls_name in ["c_1252.nls", "c_437.nls", "c_10000.nls", "locale.nls"] {
        let nls_path = copy_host_system32_file(&test_dir, nls_name);
        println!("Copied {nls_name} fixture at `{}`", nls_path.display());
    }
    let tar_path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no_import.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    // Verbose log for failure triage; not load-bearing for any assertion.
    command.env("LITEBOX_LOG", "debug");
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
    let raw_exe_path = test_dir.join("no_import.raw.exe");
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
            raw_exe_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run rustc for the no-import Windows PE fixture");

    assert!(
        output.status.success(),
        "failed to build no-import Windows PE fixture\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let rewritten =
        litebox_syscall_rewriter::rewrite_binary(&std::fs::read(raw_exe_path).unwrap(), None)
            .expect("failed to rewrite no-import Windows PE fixture");
    std::fs::write(&exe_path, rewritten).unwrap();
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

fn build_rewritten_system_dll(test_dir: &std::path::Path, dll_name: &str) -> std::path::PathBuf {
    let dll_path = fixture_system32_path(test_dir, dll_name);
    let host_dll = std::fs::read(host_system32_file_path(dll_name))
        .unwrap_or_else(|error| panic!("failed to read host {dll_name}: {error}"));
    let rewritten = match litebox_syscall_rewriter::rewrite_binary(&host_dll, None) {
        Ok(rewritten) => rewritten,
        Err(litebox_syscall_rewriter::Error::UnpatchableSyscalls(_)) => panic!(
            "failed to rewrite host {dll_name}; required support: patch dense ntdll syscall stubs or provide a pre-rewritten guest DLL"
        ),
        Err(error) => panic!("failed to rewrite host {dll_name}: {error}"),
    };
    std::fs::write(&dll_path, rewritten).unwrap();
    dll_path
}

fn copy_host_system32_file(test_dir: &std::path::Path, file_name: &str) -> std::path::PathBuf {
    let fixture_path = fixture_system32_path(test_dir, file_name);
    std::fs::copy(host_system32_file_path(file_name), &fixture_path)
        .unwrap_or_else(|error| panic!("failed to copy host {file_name}: {error}"));
    fixture_path
}

fn fixture_system32_path(test_dir: &std::path::Path, file_name: &str) -> std::path::PathBuf {
    let system32_dir = test_dir.join("Windows").join("System32");
    std::fs::create_dir_all(&system32_dir).unwrap();
    system32_dir.join(file_name)
}

fn host_system32_file_path(file_name: &str) -> std::path::PathBuf {
    std::env::var_os("SystemRoot")
        .map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        )
        .join("System32")
        .join(file_name)
}

fn create_tar_with_dir(test_dir: &std::path::Path, tar_path: &std::path::Path) {
    let output_file = std::fs::File::create(tar_path)
        .expect("failed to create tar for the no-import Windows PE fixture");
    let mut builder = tar::Builder::new(output_file);
    append_regular_files_to_ustar(&mut builder, test_dir, test_dir);
    builder
        .finish()
        .expect("failed to finalize tar for the no-import Windows PE fixture");
}

fn append_regular_files_to_ustar(
    builder: &mut tar::Builder<std::fs::File>,
    root: &std::path::Path,
    dir: &std::path::Path,
) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            append_regular_files_to_ustar(builder, root, &path);
            continue;
        }

        // Avoid nesting tar files from previous runs into the fixture archive.
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"))
        {
            continue;
        }

        let data = std::fs::read(&path).unwrap_or_else(|error| {
            panic!("failed to read fixture file {}: {error}", path.display())
        });
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        let relative = path.strip_prefix(root).unwrap();
        let relative = relative.to_string_lossy().replace('\\', "/");
        builder
            .append_data(&mut header, relative, data.as_slice())
            .unwrap_or_else(|error| {
                panic!(
                    "failed to append fixture file {} to tar: {error}",
                    path.display()
                )
            });
    }
}

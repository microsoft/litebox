// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

/// Runs a hello-world guest PE end to end.
#[test]
fn run_hello_world_pe() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kernel32_import");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path = build_kernel32_import_pe(&test_dir);
    println!(
        "Built rewritten kernel32-import PE fixture at `{}`",
        pe_path.display()
    );
    stage_system_fixtures(&test_dir);
    let tar_path =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kernel32_import.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    // Verbose log for failure triage; not load-bearing for any assertion.
    command.env("LITEBOX_LOG", "debug");
    command.args([
        "--initial-files",
        tar_path.to_str().unwrap(),
        "/kernel32_import.exe",
    ]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "runner failed to run kernel32-import PE; status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.contains("hello world\n"),
        "guest output was not captured\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Stages the guest system DLLs and locale tables the PE fixture needs.
fn stage_system_fixtures(test_dir: &std::path::Path) {
    for dll_name in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
        let dll_path = build_rewritten_system_dll(test_dir, dll_name);
        println!(
            "Built rewritten {dll_name} fixture at `{}`",
            dll_path.display()
        );
    }
    for nls_name in ["c_1252.nls", "c_437.nls", "c_10000.nls", "locale.nls"] {
        let nls_path = copy_host_system32_file(test_dir, nls_name);
        println!("Copied {nls_name} fixture at `{}`", nls_path.display());
    }
}

fn build_kernel32_import_pe(test_dir: &std::path::Path) -> std::path::PathBuf {
    let source_path = test_dir.join("kernel32_import.rs");
    let raw_exe_path = test_dir.join("kernel32_import.raw.exe");
    let exe_path = test_dir.join("kernel32_import.exe");
    std::fs::write(&source_path, KERNEL32_IMPORT_PE_SOURCE).unwrap();

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = std::process::Command::new(rustc)
        .args([
            "--edition=2024",
            source_path.to_str().unwrap(),
            "-C",
            "panic=abort",
            "-C",
            "opt-level=1",
            "-l",
            "dylib=kernel32",
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
        .expect("failed to run rustc for the kernel32-import Windows PE fixture");

    assert!(
        output.status.success(),
        "failed to build kernel32-import Windows PE fixture\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let rewritten =
        litebox_syscall_rewriter::rewrite_binary(&std::fs::read(&raw_exe_path).unwrap(), None)
            .expect("failed to rewrite kernel32-import Windows PE fixture");
    std::fs::write(&exe_path, rewritten).unwrap();
    // Keep the unrewritten build out of the fixture tar.
    std::fs::remove_file(&raw_exe_path).unwrap();
    exe_path
}

/// `STD_OUTPUT_HANDLE` is `(DWORD)-11`.
const KERNEL32_IMPORT_PE_SOURCE: &str = r#"
#![no_std]
#![no_main]

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(std_handle: u32) -> usize;
    fn WriteFile(
        file: usize,
        buffer: *const u8,
        length: u32,
        written: *mut u32,
        overlapped: usize,
    ) -> i32;
    fn ExitProcess(exit_code: u32) -> !;
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn mainCRTStartup() -> ! {
    unsafe {
        let MESSAGE: &[u8] = b"hello world\n";
        let stdout = GetStdHandle(0xffff_fff5);
        let mut written = 0u32;
        let ok = WriteFile(
            stdout,
            MESSAGE.as_ptr(),
            MESSAGE.len() as u32,
            &raw mut written,
            0,
        );
        ExitProcess(u32::from(ok == 0 || written as usize != MESSAGE.len()));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
"#;

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
    let output_file =
        std::fs::File::create(tar_path).expect("failed to create tar for the Windows PE fixture");
    let mut builder = tar::Builder::new(output_file);
    append_regular_files_to_ustar(&mut builder, test_dir, test_dir);
    builder
        .finish()
        .expect("failed to finalize tar for the Windows PE fixture");
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

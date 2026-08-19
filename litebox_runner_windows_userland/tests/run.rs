// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

/// Runs a hello-world guest PE end to end.
#[test]
fn run_hello_world_pe() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kernel32_import");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path =
        build_kernel32_import_pe(&test_dir, "kernel32_import", KERNEL32_IMPORT_PE_SOURCE, &[]);
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

/// Runs a hello-world guest PE through the Windows userland broker.
#[test]
fn run_hello_world_pe_with_broker() {
    let test_dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kernel32_import_broker");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path =
        build_kernel32_import_pe(&test_dir, "kernel32_import", KERNEL32_IMPORT_PE_SOURCE, &[]);
    println!(
        "Built rewritten kernel32-import PE fixture at `{}`",
        pe_path.display()
    );
    stage_system_fixtures(&test_dir);
    let tar_path =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kernel32_import_broker.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let (broker, runner) = build_windows_broker();
    let mut command = std::process::Command::new(broker);
    command
        .env("LITEBOX_LOG", "debug")
        .arg("--runner")
        .arg(runner)
        .args([
            "--initial-files",
            tar_path.to_str().unwrap(),
            "/kernel32_import.exe",
        ]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland through the broker");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "broker failed to run kernel32-import PE; status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.contains("hello world\n"),
        "guest output was not captured\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Runs a guest PE that creates and joins a child thread.
#[test]
fn run_multithreaded_pe() {
    let test_dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kernel32_multithread");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path = build_kernel32_import_pe(
        &test_dir,
        "kernel32_multithread",
        KERNEL32_MULTITHREAD_PE_SOURCE,
        &[],
    );
    println!(
        "Built rewritten multithreaded PE fixture at `{}`",
        pe_path.display()
    );
    stage_system_fixtures(&test_dir);
    let tar_path =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kernel32_multithread.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    command.env("LITEBOX_LOG", "debug");
    command.args([
        "--initial-files",
        tar_path.to_str().unwrap(),
        "/kernel32_multithread.exe",
    ]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "runner failed to run multithreaded PE; status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    let child_one_position = stdout.find("child one\n");
    let child_two_position = stdout.find("child two\n");
    let joined_position = stdout.find("main joined\n");
    assert!(
        child_one_position.is_some() && child_two_position.is_some() && joined_position.is_some(),
        "guest thread output was not captured\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        child_one_position < joined_position && child_two_position < joined_position,
        "main reported joining before both children ran\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Runs a guest PE that imports the C runtime (ucrtbase via the CRT api-set
/// contracts), forcing ucrtbase to load and initialize.
#[test]
fn run_crt_locale_pe() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("crt_locale");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();
    let pe_path =
        build_kernel32_import_pe(&test_dir, "crt_locale", CRT_LOCALE_PE_SOURCE, &["ucrt"]);
    println!(
        "Built rewritten crt-locale PE fixture at `{}`",
        pe_path.display()
    );
    stage_system_fixtures(&test_dir);
    let tar_path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("crt_locale.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    command.env("LITEBOX_LOG", "debug");
    command.args([
        "--initial-files",
        tar_path.to_str().unwrap(),
        "/crt_locale.exe",
    ]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "runner failed to run crt-locale PE; status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.contains("crt ok\n"),
        "guest crt output was not captured\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn build_windows_broker() -> (std::path::PathBuf, std::path::PathBuf) {
    let runner = std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_windows_userland").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_BIN_EXE_litebox_runner_windows_userland")),
        std::path::PathBuf::from,
    );
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = std::process::Command::new(cargo)
        .args([
            "build",
            "-p",
            "litebox_broker_userland",
            "--bin",
            "litebox-broker-userland",
        ])
        .status()
        .expect("failed to build litebox-broker-userland");
    assert!(status.success(), "failed to build litebox-broker-userland");

    let broker = runner.with_file_name("litebox-broker-userland.exe");
    assert!(
        broker.is_file(),
        "broker executable not found at {}",
        broker.display()
    );
    (broker, runner)
}

/// Drives the real `7za b` CPU benchmark through the runner using the
/// transitive-import-closure staging helper. `7za` is a large third-party
/// binary that must not be committed. `LITEBOX_7ZA_PATH` can point at a locally
/// provided x64 `7za.exe`; otherwise the test downloads and verifies a pinned
/// official x64 7-Zip installer, then extracts its console executable into
/// `CARGO_TARGET_TMPDIR`.
///
/// This drives the frontier forward while asserting the deliverable: staging
/// must reach transitive depth the old hardcoded list missed (`cryptbase.dll`),
/// and the closure walk plus run must complete without panicking. The guest
/// reaching a not-yet-implemented syscall or runtime limit is expected while
/// the CRT/registry/mm frontier is still being built out, so the guest's own
/// exit status is reported rather than asserted.
///
/// Marked `#[ignore]` so it never reports a misleading `PASS` on the default
/// gate (it downloads an external binary); run it explicitly with
/// `--run-ignored all`. The hermetic tests below exercise the helper on every
/// default run.
#[test]
#[ignore = "downloads an official x64 7-Zip binary unless LITEBOX_7ZA_PATH is set"]
fn run_7za_benchmark_pe() {
    let source = seven_zip_source();

    let test_dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("seven_zip_benchmark");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();

    let host_exe = std::fs::read(&source).expect("failed to read LITEBOX_7ZA_PATH binary");
    let rewritten = litebox_syscall_rewriter::rewrite_binary(&host_exe, None)
        .expect("failed to rewrite 7za.exe");
    std::fs::write(test_dir.join("7za.exe"), &rewritten).unwrap();
    // Import parsing walks the original host image; rewriting does not change
    // the import tables.
    stage_transitive_import_closure(&test_dir, &host_exe);

    // Oracle for the deliverable: the transitive walk must reach depth the old
    // hardcoded 7-DLL list missed. `cryptbase.dll` is only reachable through
    // 7za's transitive closure (crypt32 -> ... -> cryptbase), so its presence
    // proves the closure walk — not a fixed list — did the staging.
    assert!(
        fixture_system32_path(&test_dir, "cryptbase.dll").exists(),
        "transitive closure did not stage cryptbase.dll"
    );

    let tar_path =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("seven_zip_benchmark.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_litebox_runner_windows_userland"));
    command.env("LITEBOX_LOG", "debug");
    command.args([
        "--initial-files",
        tar_path.to_str().unwrap(),
        "/7za.exe",
        "b",
    ]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");
    println!(
        "7za exit: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn seven_zip_source() -> std::path::PathBuf {
    const INSTALLER_URL: &str =
        "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-x64.msi";
    const INSTALLER_SHA256: &str =
        "db407a4f6d4999e5c7bc00ce8a882be94717b56e7fa68140fe3f12605d91643e";

    if let Some(source) = std::env::var_os("LITEBOX_7ZA_PATH") {
        return source.into();
    }

    let download_dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("seven_zip_26.02_x64_msi");
    std::fs::create_dir_all(&download_dir).expect("failed to create 7-Zip download directory");
    let installer = download_dir.join("7z2602-x64.msi");

    if installer.exists() && sha256_file(&installer) != INSTALLER_SHA256 {
        println!(
            "Removing cached 7-Zip installer with an unexpected SHA-256: `{}`",
            installer.display()
        );
        std::fs::remove_file(&installer).expect("failed to remove invalid cached 7-Zip installer");
    }

    if !installer.exists() {
        let temporary_installer =
            download_dir.join(format!("7z2602-x64.msi.{}.tmp", std::process::id()));
        println!("Downloading 7-Zip from `{INSTALLER_URL}`");
        let status = std::process::Command::new("curl.exe")
            .args([
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--output",
            ])
            .arg(&temporary_installer)
            .arg(INSTALLER_URL)
            .status()
            .expect("failed to start curl.exe to download 7-Zip");
        assert!(status.success(), "curl.exe failed to download 7-Zip");

        let actual_sha256 = sha256_file(&temporary_installer);
        assert_eq!(
            actual_sha256, INSTALLER_SHA256,
            "downloaded 7-Zip installer has an unexpected SHA-256"
        );
        std::fs::rename(&temporary_installer, &installer)
            .expect("failed to cache verified 7-Zip installer");
    }

    let install_dir = download_dir.join("installed");
    let source = install_dir.join("Files").join("7-Zip").join("7z.exe");
    if !source.exists() {
        std::fs::create_dir_all(&install_dir).expect("failed to create 7-Zip extraction directory");
        println!("Extracting verified 7-Zip MSI");
        let status = std::process::Command::new("msiexec.exe")
            .arg("/a")
            .arg(&installer)
            .arg("/qn")
            .arg(format!("TARGETDIR={}", install_dir.display()))
            .status()
            .expect("failed to start msiexec.exe");
        assert!(
            status.success(),
            "msiexec.exe failed to extract 7-Zip with status {status}"
        );
        assert!(
            source.is_file(),
            "7-Zip installer did not extract `{}`",
            source.display()
        );
    }

    source
}

fn sha256_file(path: &std::path::Path) -> String {
    use sha2::Digest;

    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("failed to read `{}` for SHA-256: {error}", path.display()));
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Stages the minimal guest system DLLs and locale tables the lightweight PE
/// fixtures need. These fixtures import only a tiny surface, so a fixed minimal
/// set is deliberately used rather than the full transitive closure: walking
/// `kernel32`'s real closure would stage hundreds of DLLs and exhaust the guest
/// allocator. The transitive-closure helper (`stage_transitive_import_closure`)
/// is used instead for real third-party applications such as `7za`.
fn stage_system_fixtures(test_dir: &std::path::Path) {
    for dll_name in [
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "ucrtbase.dll",
        "advapi32.dll",
        "gdi32full.dll",
        "sechost.dll",
    ] {
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

fn build_kernel32_import_pe(
    test_dir: &std::path::Path,
    fixture_name: &str,
    source: &str,
    extra_libs: &[&str],
) -> std::path::PathBuf {
    let source_path = test_dir.join(format!("{fixture_name}.rs"));
    let raw_exe_path = test_dir.join(format!("{fixture_name}.raw.exe"));
    let exe_path = test_dir.join(format!("{fixture_name}.exe"));
    std::fs::write(&source_path, source).unwrap();

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let mut command = std::process::Command::new(rustc);
    command.args([
        "--edition=2024",
        source_path.to_str().unwrap(),
        "-C",
        "panic=abort",
        "-C",
        "opt-level=1",
        "-l",
        "dylib=kernel32",
        "-l",
        "dylib=ntdll",
    ]);
    for lib in extra_libs {
        command.args(["-l", &format!("dylib={lib}")]);
    }
    command.args([
        "-C",
        "link-arg=/ENTRY:mainCRTStartup",
        "-C",
        "link-arg=/SUBSYSTEM:CONSOLE",
        "-C",
        "link-arg=/NODEFAULTLIB",
        "-o",
        raw_exe_path.to_str().unwrap(),
    ]);
    let output = command
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

/// A minimal PE that imports a single `ntdll` symbol and nothing else. `ntdll`
/// is a true leaf (it has no regular or delay imports of its own), so staging
/// this fixture's closure resolves and stages exactly one DLL — `ntdll.dll` —
/// keeping the hermetic closure-walk test fast and deterministic without any
/// external binary.
const NTDLL_ONLY_PE_SOURCE: &str = r#"
#![no_std]
#![no_main]

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlExitUserProcess(exit_code: u32) -> !;
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn mainCRTStartup() -> ! {
    unsafe { RtlExitUserProcess(0) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
"#;

const CRT_LOCALE_PE_SOURCE: &str = r#"
#![no_std]
#![no_main]

// Imported from the C runtime; these resolve through the `api-ms-win-crt-*`
// api-set contracts to `ucrtbase.dll`, forcing it to load and initialize.
unsafe extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
    fn setlocale(category: i32, locale: *const u8) -> *mut u8;
}

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
        let block = malloc(16);
        if block.is_null() {
            ExitProcess(2);
        }
        free(block);
        let _ = setlocale(0, b"C\0".as_ptr());

        let MESSAGE: &[u8] = b"crt ok\n";
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

const KERNEL32_MULTITHREAD_PE_SOURCE: &str = r#"
#![no_std]
#![no_main]

use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static CHILDREN_STARTED: AtomicU32 = AtomicU32::new(0);
static CHILDREN_MAY_EXIT: AtomicBool = AtomicBool::new(false);

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
    fn CreateThread(
        thread_attributes: *const u8,
        stack_size: usize,
        start_routine: unsafe extern "system" fn(*mut u8) -> u32,
        parameter: *mut u8,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> usize;
    fn WaitForSingleObject(handle: usize, milliseconds: u32) -> u32;
    fn ExitProcess(exit_code: u32) -> !;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationThread(
        thread_handle: usize,
        thread_information_class: u32,
        thread_information: *mut u32,
        thread_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

unsafe fn write_stdout(message: &[u8]) -> bool {
    unsafe {
        let stdout = GetStdHandle(0xffff_fff5);
        let mut written = 0u32;
        WriteFile(
            stdout,
            message.as_ptr(),
            message.len() as u32,
            &raw mut written,
            0,
        ) != 0
            && written as usize == message.len()
    }
}

unsafe extern "system" fn child_thread(parameter: *mut u8) -> u32 {
    CHILDREN_STARTED.fetch_add(1, Ordering::Release);
    while !CHILDREN_MAY_EXIT.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let message: &[u8] = if parameter as usize == 1 {
        b"child one\n"
    } else {
        b"child two\n"
    };
    u32::from(!unsafe { write_stdout(message) })
}

unsafe fn am_i_last_thread() -> Option<bool> {
    let mut is_last_thread = u32::MAX;
    let mut return_length = 0;
    let status = unsafe {
        NtQueryInformationThread(
            usize::MAX - 1,
            12,
            &raw mut is_last_thread,
            size_of::<u32>() as u32,
            &raw mut return_length,
        )
    };
    (status == 0 && return_length as usize == size_of::<u32>())
        .then_some(is_last_thread != 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn mainCRTStartup() -> ! {
    unsafe {
        let thread_one = CreateThread(
            core::ptr::null(),
            0,
            child_thread,
            1usize as *mut u8,
            0,
            core::ptr::null_mut(),
        );
        let thread_two = CreateThread(
            core::ptr::null(),
            0,
            child_thread,
            2usize as *mut u8,
            0,
            core::ptr::null_mut(),
        );
        if thread_one == 0 || thread_two == 0 {
            ExitProcess(1);
        }
        while CHILDREN_STARTED.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
        if am_i_last_thread() != Some(false)
            || WaitForSingleObject(thread_one, 0) != 258
            || WaitForSingleObject(thread_two, 0) != 258
        {
            ExitProcess(1);
        }
        CHILDREN_MAY_EXIT.store(true, Ordering::Release);
        if WaitForSingleObject(thread_one, u32::MAX) != 0
            || WaitForSingleObject(thread_two, u32::MAX) != 0
            || am_i_last_thread() != Some(true)
        {
            ExitProcess(1);
        }
        ExitProcess(u32::from(!write_stdout(b"main joined\n")));
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

// Resolves an api-set contract to the host module that implements it, by asking
// the host loader directly (`api-ms-*`/`ext-ms-*` names are not physical files).
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(
        name: *const u16,
        file: *mut core::ffi::c_void,
        flags: u32,
    ) -> *mut core::ffi::c_void;
    fn FreeLibrary(module: *mut core::ffi::c_void) -> i32;
    fn GetModuleFileNameW(module: *mut core::ffi::c_void, filename: *mut u16, size: u32) -> u32;
}

/// `LOAD_LIBRARY_SEARCH_SYSTEM32` — restrict DLL resolution to System32.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

/// A directory of a PE's imports: the regular import directory or the
/// delay-load import directory. Carried by [`ClosureDiagnostic`] so a diagnostic
/// pins down *which* table was malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportDirectory {
    Regular,
    DelayLoad,
}

impl core::fmt::Display for ImportDirectory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ImportDirectory::Regular => f.write_str("import"),
            ImportDirectory::DelayLoad => f.write_str("delay-load"),
        }
    }
}

/// A structured diagnostic for a specific malformed-input case encountered while
/// scanning a PE's import directories. Returned (not merely printed) so callers
/// and tests can assert *by variant* that malformed input was surfaced rather
/// than silently collapsed into an empty closure — a silent parse failure is
/// otherwise indistinguishable from a legitimately import-free binary.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClosureDiagnostic {
    /// The PE image itself could not be parsed.
    UnparsablePe(String),
    /// A directory's import table header was malformed.
    MalformedTable(ImportDirectory, String),
    /// The descriptor list of a directory could not be produced.
    MalformedDescriptors(ImportDirectory, String),
    /// Iterating the descriptor list yielded a corrupt descriptor entry.
    MalformedDescriptor(ImportDirectory, String),
    /// A descriptor's DLL-name RVA could not be resolved to a name.
    MalformedName(ImportDirectory, String),
}

impl core::fmt::Display for ClosureDiagnostic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClosureDiagnostic::UnparsablePe(error) => {
                write!(f, "unparsable PE image ({error})")
            }
            ClosureDiagnostic::MalformedTable(dir, error) => {
                write!(f, "malformed {dir} table ({error})")
            }
            ClosureDiagnostic::MalformedDescriptors(dir, error) => {
                write!(f, "malformed {dir} descriptors ({error})")
            }
            ClosureDiagnostic::MalformedDescriptor(dir, error) => {
                write!(f, "malformed {dir} descriptor ({error})")
            }
            ClosureDiagnostic::MalformedName(dir, error) => {
                write!(f, "malformed {dir} name ({error})")
            }
        }
    }
}

/// Structured result of scanning a PE's import directories: the imported DLL /
/// api-set names, plus [`ClosureDiagnostic`]s for any malformed table,
/// descriptor, or name encountered.
///
/// Diagnostics are *returned* (not merely printed) so callers and tests can
/// assert that malformed input was reported rather than silently collapsed into
/// an empty closure — a silent parse failure is otherwise indistinguishable from
/// a legitimately import-free binary.
#[derive(Default)]
struct ImportScan {
    names: Vec<String>,
    diagnostics: Vec<ClosureDiagnostic>,
}

/// Parses the regular and delay-load import directories of a PE image.
///
/// Uses the vendored `object` crate rather than hand-rolled offset math, and
/// deliberately parses the delay-import directory too — forwarder / delay
/// chains (e.g. `version`, `cryptbase`) are invisible to a regular-imports-only
/// walk.
///
/// `Ok(None)` from a directory is the legitimate absent case and stays silent.
/// Every `Err` — an unparsable image, a malformed directory, a malformed
/// descriptor *iteration*, or a malformed *name* lookup — is recorded as a
/// [`ClosureDiagnostic`]. In particular the descriptor `next()` and `name()`
/// results are matched exhaustively rather than filtered with
/// `while let Ok(Some(..))` / `if let Ok(..)`, so a corrupt descriptor or name
/// RVA is surfaced instead of silently terminating the walk.
fn scan_imports(image: &[u8]) -> ImportScan {
    use object::LittleEndian as LE;
    use object::read::pe::PeFile64;

    let mut scan = ImportScan::default();
    let file = match PeFile64::parse(image) {
        Ok(file) => file,
        Err(error) => {
            scan.diagnostics
                .push(ClosureDiagnostic::UnparsablePe(error.to_string()));
            return scan;
        }
    };
    let sections = file.section_table();

    match file.import_table() {
        Ok(Some(table)) => match table.descriptors() {
            Ok(mut descriptors) => loop {
                match descriptors.next() {
                    Ok(Some(descriptor)) => match table.name(descriptor.name.get(LE)) {
                        Ok(name) => scan.names.push(String::from_utf8_lossy(name).into_owned()),
                        Err(error) => scan.diagnostics.push(ClosureDiagnostic::MalformedName(
                            ImportDirectory::Regular,
                            error.to_string(),
                        )),
                    },
                    Ok(None) => break,
                    Err(error) => {
                        scan.diagnostics
                            .push(ClosureDiagnostic::MalformedDescriptor(
                                ImportDirectory::Regular,
                                error.to_string(),
                            ));
                        break;
                    }
                }
            },
            Err(error) => scan
                .diagnostics
                .push(ClosureDiagnostic::MalformedDescriptors(
                    ImportDirectory::Regular,
                    error.to_string(),
                )),
        },
        Ok(None) => {}
        Err(error) => scan.diagnostics.push(ClosureDiagnostic::MalformedTable(
            ImportDirectory::Regular,
            error.to_string(),
        )),
    }

    match file
        .data_directories()
        .delay_load_import_table(image, &sections)
    {
        Ok(Some(table)) => match table.descriptors() {
            Ok(mut descriptors) => loop {
                match descriptors.next() {
                    Ok(Some(descriptor)) => match table.name(descriptor.dll_name_rva.get(LE)) {
                        Ok(name) => scan.names.push(String::from_utf8_lossy(name).into_owned()),
                        Err(error) => scan.diagnostics.push(ClosureDiagnostic::MalformedName(
                            ImportDirectory::DelayLoad,
                            error.to_string(),
                        )),
                    },
                    Ok(None) => break,
                    Err(error) => {
                        scan.diagnostics
                            .push(ClosureDiagnostic::MalformedDescriptor(
                                ImportDirectory::DelayLoad,
                                error.to_string(),
                            ));
                        break;
                    }
                }
            },
            Err(error) => scan
                .diagnostics
                .push(ClosureDiagnostic::MalformedDescriptors(
                    ImportDirectory::DelayLoad,
                    error.to_string(),
                )),
        },
        Ok(None) => {}
        Err(error) => scan.diagnostics.push(ClosureDiagnostic::MalformedTable(
            ImportDirectory::DelayLoad,
            error.to_string(),
        )),
    }

    scan
}

/// Convenience wrapper over [`scan_imports`] for callers that only need the
/// imported names: it prints any diagnostics (so malformed tables stay visible
/// in run output) and returns the names.
fn imported_dll_names(image: &[u8]) -> Vec<String> {
    let scan = scan_imports(image);
    for diagnostic in &scan.diagnostics {
        println!("closure: {diagnostic}");
    }
    scan.names
}

/// Validates that an imported name is a single normal filename component and
/// returns it lowercased. Import names come from an untrusted guest PE, so an
/// absolute path or one containing `..` (which would escape the fixture
/// System32 directory when joined) is rejected, returning `None`.
fn staged_file_name(name: &str) -> Option<String> {
    let lowered = name.to_ascii_lowercase();
    let mut components = std::path::Path::new(&lowered).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(component)), None) => {
            Some(component.to_string_lossy().into_owned())
        }
        _ => None,
    }
}

/// Resolves an imported name to the host System32 file that must be staged.
///
/// Real DLL imports map to themselves. Api-set contracts are resolved through
/// the host loader to their implementing module. Contracts with no host
/// implementation (empty-target api-sets such as `ext-ms-win-core-winrt-remote`)
/// resolve to `None` and are skipped by the caller.
fn resolve_to_host_dll(import_name: &str) -> Option<String> {
    let lowercased = import_name.to_ascii_lowercase();
    if !(lowercased.starts_with("api-ms-") || lowercased.starts_with("ext-ms-")) {
        // A real DLL import maps to itself, but only if it is a bare filename;
        // a path-bearing name from an untrusted PE is rejected.
        return staged_file_name(import_name);
    }

    let wide: Vec<u16> = import_name
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    // Restrict the search to System32 so resolution cannot be redirected by the
    // test process's working directory or PATH.
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string; the module handle,
    // if non-null, is released with `FreeLibrary` before returning.
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            core::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return None;
    }
    let mut buffer = [0u16; 260];
    let capacity = u32::try_from(buffer.len()).expect("buffer length fits in u32");
    // SAFETY: `module` is a live handle from `LoadLibraryExW`; `buffer` is a
    // writable array of `buffer.len()` `u16`s.
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), capacity) } as usize;
    // SAFETY: `module` is a live handle previously returned by `LoadLibraryExW`.
    unsafe {
        FreeLibrary(module);
    }
    if length == 0 || length >= buffer.len() {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..length]);
    let file_name = std::path::Path::new(&path).file_name()?.to_string_lossy();
    staged_file_name(&file_name)
}

/// Stages the transitive import closure of a guest PE: walks its imports,
/// resolves api-set contracts to host modules, rewrites and stages each real
/// DLL, and recurses into every staged DLL's own imports.
///
/// Returns a [`StagingReport`] recording which DLLs were staged, which were
/// skipped (with a reason), and any malformed-import diagnostics. The report is
/// returned — not only printed — so tests can deterministically assert that the
/// skip-with-report and malformed-parse paths fire, rather than merely
/// observing `println!` output.
///
/// This is a *floor* for harness DLL staging only — it does NOT touch the
/// shim's `API_SET_MAPPINGS` table. A contract it resolves and stages here can
/// still fail to load in the guest if that contract is absent from the shim
/// table; surfacing those api-set-table gaps stays with runtime iteration, not
/// this helper. Likewise, export forwarders (`kernel32.f -> kernelbase.f`) are
/// not followed here — the import-table walk under-approximates the true
/// closure, and any forwarder target it misses is expected to be staged by the
/// runtime iteration pass rather than by this static floor. Missing or
/// unrewritable host DLLs are skipped with a report rather than panicking,
/// since an open closure walk legitimately encounters modules that cannot be
/// staged.
#[derive(Default)]
struct StagingReport {
    staged: Vec<String>,
    skipped: Vec<String>,
    diagnostics: Vec<ClosureDiagnostic>,
}

fn stage_transitive_import_closure(
    test_dir: &std::path::Path,
    guest_image: &[u8],
) -> StagingReport {
    let mut report = StagingReport::default();
    let mut staged = std::collections::BTreeSet::new();

    let scan = scan_imports(guest_image);
    for diagnostic in &scan.diagnostics {
        println!("closure: {diagnostic}");
    }
    report.diagnostics.extend(scan.diagnostics);
    let mut worklist = scan.names;

    while let Some(import_name) = worklist.pop() {
        let Some(host_dll) = resolve_to_host_dll(&import_name) else {
            let reason = format!("unresolved import `{import_name}`");
            println!("closure: skipping {reason}");
            report.skipped.push(reason);
            continue;
        };
        // Visited-set keyed by the resolved real DLL breaks ntdll/kernelbase/
        // kernel32 import cycles.
        if !staged.insert(host_dll.clone()) {
            continue;
        }

        let host_path = host_system32_file_path(&host_dll);
        let host_bytes = match std::fs::read(&host_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let reason = format!("`{host_dll}` (unreadable host DLL: {error})");
                println!("closure: skipping {reason}");
                report.skipped.push(reason);
                continue;
            }
        };

        // Recurse into the DLL's own imports regardless of whether the DLL
        // itself is rewritable, so the closure stays complete.
        let scan = scan_imports(&host_bytes);
        for diagnostic in &scan.diagnostics {
            println!("closure: {diagnostic}");
        }
        report.diagnostics.extend(scan.diagnostics);
        worklist.extend(scan.names);

        match litebox_syscall_rewriter::rewrite_binary(&host_bytes, None) {
            Ok(rewritten) => {
                let dll_path = fixture_system32_path(test_dir, &host_dll);
                std::fs::write(&dll_path, rewritten).unwrap();
                println!("closure: staged `{host_dll}`");
                report.staged.push(host_dll);
            }
            // Narrow skip: only DLLs whose dense syscall stubs cannot be patched
            // are skipped-with-report. Any other rewrite error is a real defect
            // and panics loudly rather than silently under-staging a DLL the
            // guest genuinely needs.
            Err(litebox_syscall_rewriter::Error::UnpatchableSyscalls(reason)) => {
                let reason = format!("`{host_dll}` (unpatchable syscalls: {reason})");
                println!("closure: skipping {reason}");
                report.skipped.push(reason);
            }
            Err(error) => {
                panic!("closure: failed to rewrite `{host_dll}`: {error}");
            }
        }
    }

    for nls_name in ["c_1252.nls", "c_437.nls", "c_10000.nls", "locale.nls"] {
        copy_host_system32_file(test_dir, nls_name);
    }

    report
}

/// `staged_file_name` must reject path-bearing import names (traversal defense)
/// and accept bare filenames.
#[test]
fn staged_file_name_rejects_path_traversal() {
    assert_eq!(
        staged_file_name("kernel32.dll").as_deref(),
        Some("kernel32.dll")
    );
    assert_eq!(
        staged_file_name("KERNEL32.DLL").as_deref(),
        Some("kernel32.dll")
    );
    assert_eq!(staged_file_name(r"..\..\evil.dll"), None);
    assert_eq!(staged_file_name(r"C:\Windows\evil.dll"), None);
    assert_eq!(staged_file_name("sub/dir.dll"), None);
    assert_eq!(staged_file_name(".."), None);
}

/// `resolve_to_host_dll` maps a real DLL to itself and an api-set contract to
/// its host implementer via the host loader. Uses a contract known to be absent
/// from the shim's `API_SET_MAPPINGS`, proving host-loader resolution (not the
/// shim table) is the staging authority.
#[test]
fn resolve_to_host_dll_maps_real_dll_and_absent_contract() {
    assert_eq!(
        resolve_to_host_dll("ntdll.dll").as_deref(),
        Some("ntdll.dll")
    );
    assert_eq!(
        resolve_to_host_dll("api-ms-win-core-libraryloader-l1-1-0").as_deref(),
        Some("kernelbase.dll"),
    );
    // An empty-target / nonexistent contract has no host implementation.
    assert_eq!(
        resolve_to_host_dll("api-ms-win-does-not-exist-l1-1-0"),
        None
    );
}

/// `imported_dll_names` parses a real host DLL and surfaces its api-set imports.
#[test]
fn imported_dll_names_parses_host_dll() {
    let ucrtbase = std::fs::read(host_system32_file_path("ucrtbase.dll")).unwrap();
    let names = imported_dll_names(&ucrtbase);
    assert!(!names.is_empty(), "ucrtbase.dll should have imports");
    assert!(
        names
            .iter()
            .any(|name| name.to_ascii_lowercase().starts_with("api-ms-win-")),
        "expected api-set imports, got {names:?}"
    );
}

/// A malformed PE image must be *reported* as a diagnostic, never silently
/// collapsed into an empty (import-free) closure — otherwise a parse failure is
/// indistinguishable from a binary that genuinely has no imports.
#[test]
fn scan_imports_reports_unparsable_pe() {
    let scan = scan_imports(b"this is not a PE image");
    assert!(
        scan.names.is_empty(),
        "unparsable image should yield no names, got {:?}",
        scan.names
    );
    assert!(
        scan.diagnostics
            .iter()
            .any(|d| matches!(d, ClosureDiagnostic::UnparsablePe(_))),
        "unparsable image was not reported, diagnostics: {:?}",
        scan.diagnostics
    );
}

/// File offset of the RVA of the first regular import descriptor's DLL-name.
///
/// Locates the import data directory in the PE32+ optional header, maps its RVA
/// to a file offset via the section table, and returns the offset of the first
/// descriptor's `Name` field (`IMAGE_IMPORT_DESCRIPTOR` byte offset 12). Used
/// only by the malformed-name test to deterministically corrupt a single name
/// RVA out of range.
fn first_import_name_rva_offset(image: &[u8]) -> usize {
    let read_u16 = |off: usize| u16::from_le_bytes(image[off..off + 2].try_into().unwrap());
    let read_u32 = |off: usize| u32::from_le_bytes(image[off..off + 4].try_into().unwrap());

    let pe = read_u32(0x3C) as usize;
    assert_eq!(&image[pe..pe + 4], b"PE\0\0", "not a PE image");
    let coff = pe + 4;
    let num_sections = read_u16(coff + 2) as usize;
    let size_optional = read_u16(coff + 16) as usize;
    let optional = coff + 20;
    // PE32+ data directories begin at optional-header offset 112; index 1 is the
    // import directory.
    let import_dir_rva = read_u32(optional + 112 + 8);
    assert_ne!(import_dir_rva, 0, "image has no import directory");

    let section_table = optional + size_optional;
    let rva_to_offset = |rva: u32| -> usize {
        for i in 0..num_sections {
            let entry = section_table + i * 40;
            let virtual_size = read_u32(entry + 8);
            let virtual_address = read_u32(entry + 12);
            let raw_size = read_u32(entry + 16);
            let raw_pointer = read_u32(entry + 20);
            let span = virtual_size.max(raw_size);
            if rva >= virtual_address && rva < virtual_address + span {
                return (raw_pointer + (rva - virtual_address)) as usize;
            }
        }
        panic!("RVA {rva:#x} is not within any section");
    };

    // First descriptor at the directory; its `Name` field is at byte offset 12.
    rva_to_offset(import_dir_rva) + 12
}

/// A malformed *import name* (a descriptor whose name RVA points out of range)
/// must be reported by `scan_imports`, exercising the previously-silent
/// `table.name(..)` error branch. Corrupts a single name RVA in a real host DLL
/// so the failure path is hit deterministically without a hand-built PE.
#[test]
fn scan_imports_reports_malformed_import_name() {
    let mut bytes = std::fs::read(host_system32_file_path("ucrtbase.dll")).unwrap();

    // Baseline diagnostics from the pristine image (expected empty, but compared
    // rather than assumed so the test is robust to benign parser notes).
    let clean = scan_imports(&bytes);

    // Point the first descriptor's name RVA far past the image so the loader's
    // name lookup fails.
    let name_rva_offset = first_import_name_rva_offset(&bytes);
    bytes[name_rva_offset..name_rva_offset + 4].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());

    let scan = scan_imports(&bytes);
    assert!(
        scan.diagnostics.len() > clean.diagnostics.len(),
        "corrupting an import name RVA produced no new diagnostic (clean: {:?}, corrupt: {:?})",
        clean.diagnostics,
        scan.diagnostics
    );
    assert!(
        scan.diagnostics.iter().any(|d| matches!(
            d,
            ClosureDiagnostic::MalformedName(ImportDirectory::Regular, _)
        )),
        "corrupt import name RVA was not reported via the name branch, diagnostics: {:?}",
        scan.diagnostics
    );
}

/// Returns the file offset of the import data-directory's virtual-address field
/// (so the test can overwrite it) together with the virtual address and
/// effective on-disk length (`min(virtual_size, size_of_raw_data)`, matching
/// `object`'s `pe_file_range`) of the section that currently contains the import
/// directory. Used by the malformed-descriptor test to redirect the import
/// directory to the tail of that section.
fn import_dir_va_field_and_section(image: &[u8]) -> (usize, u32, u32) {
    let read_u16 = |off: usize| u16::from_le_bytes(image[off..off + 2].try_into().unwrap());
    let read_u32 = |off: usize| u32::from_le_bytes(image[off..off + 4].try_into().unwrap());

    let pe = read_u32(0x3C) as usize;
    assert_eq!(&image[pe..pe + 4], b"PE\0\0", "not a PE image");
    let coff = pe + 4;
    let num_sections = read_u16(coff + 2) as usize;
    let size_optional = read_u16(coff + 16) as usize;
    let optional = coff + 20;
    // PE32+ data directories begin at optional-header offset 112; index 1 is the
    // import directory, whose virtual-address field is the first u32.
    let import_va_field = optional + 112 + 8;
    let import_rva = read_u32(import_va_field);
    assert_ne!(import_rva, 0, "image has no import directory");

    let section_table = optional + size_optional;
    for i in 0..num_sections {
        let entry = section_table + i * 40;
        let virtual_size = read_u32(entry + 8);
        let virtual_address = read_u32(entry + 12);
        let raw_size = read_u32(entry + 16);
        let effective = virtual_size.min(raw_size);
        if import_rva >= virtual_address && import_rva - virtual_address < effective {
            return (import_va_field, virtual_address, effective);
        }
    }
    panic!("no section contains the import directory");
}

/// A malformed *import descriptor* — a descriptor array that runs off the end of
/// its containing section without a null terminator — must be reported by
/// `scan_imports`, exercising the previously-silent `descriptors.next()` error
/// branch. Redirects the import data directory to eight bytes before the section
/// data ends, so the first 20-byte descriptor read is truncated and fails
/// deterministically, without any external binary.
#[test]
fn scan_imports_reports_malformed_import_descriptor() {
    let mut bytes = std::fs::read(host_system32_file_path("ucrtbase.dll")).unwrap();

    // Baseline diagnostics from the pristine image, compared rather than assumed.
    let clean = scan_imports(&bytes);

    let (import_va_field, section_va, effective_len) = import_dir_va_field_and_section(&bytes);
    assert!(effective_len >= 8, "section too small to truncate");
    // Point the import directory 8 bytes before the section's data ends: the
    // descriptor list is then non-terminated and a full descriptor cannot be
    // read, so `descriptors().next()` returns Err.
    let truncated_va = section_va + effective_len - 8;
    bytes[import_va_field..import_va_field + 4].copy_from_slice(&truncated_va.to_le_bytes());

    let scan = scan_imports(&bytes);
    assert!(
        scan.diagnostics.len() > clean.diagnostics.len(),
        "truncating the import descriptor produced no new diagnostic (clean: {:?}, corrupt: {:?})",
        clean.diagnostics,
        scan.diagnostics
    );
    assert!(
        scan.diagnostics.iter().any(|d| matches!(
            d,
            ClosureDiagnostic::MalformedDescriptor(ImportDirectory::Regular, _)
        )),
        "truncated import descriptor was not reported via the descriptor branch, diagnostics: {:?}",
        scan.diagnostics
    );
}

/// The closure walk must record a *skip with reason* — not silently drop — when
/// an import resolves to a host DLL that cannot be read. Builds the ntdll-only
/// fixture, rewrites its single import name in place to a bogus (nonexistent)
/// DLL, and asserts the returned report skips it and stages nothing.
#[test]
fn stage_transitive_import_closure_reports_skipped_unresolvable() {
    let test_dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("closure_skip_report");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();

    let pe_path = build_kernel32_import_pe(&test_dir, "ntdll_skip", NTDLL_ONLY_PE_SOURCE, &[]);
    let mut guest_image = std::fs::read(&pe_path).unwrap();

    // Replace the import name string in place with a same-length bogus name so
    // it resolves to a bare (nonexistent) filename that cannot be read from
    // System32. Same length keeps every RVA/offset valid.
    let original = b"ntdll.dll";
    let bogus = b"zzdll.zzz";
    assert_eq!(original.len(), bogus.len());
    let mut replaced = false;
    let mut cursor = 0;
    while let Some(pos) = guest_image[cursor..]
        .windows(original.len())
        .position(|window| window.eq_ignore_ascii_case(original))
    {
        let start = cursor + pos;
        guest_image[start..start + original.len()].copy_from_slice(bogus);
        replaced = true;
        cursor = start + original.len();
    }
    assert!(
        replaced,
        "did not find the ntdll.dll import name to corrupt"
    );

    let report = stage_transitive_import_closure(&test_dir, &guest_image);

    assert!(
        report.staged.is_empty(),
        "nothing should have been staged for a bogus import, got {:?}",
        report.staged
    );
    assert!(
        report.skipped.iter().any(|reason| reason.contains("zzdll")),
        "the unreadable bogus import was not reported as skipped: {:?}",
        report.skipped
    );
    assert!(
        !fixture_system32_path(&test_dir, "zzdll.zzz").exists(),
        "a bogus import must not be staged"
    );
}

/// Hermetic, always-on exercise of the closure-walk orchestration itself
/// (`stage_transitive_import_closure`) — not just its sub-functions — on every
/// default gate, with no external binary. It builds a fixture PE that imports a
/// single `ntdll` symbol; because `ntdll` is a leaf (no imports of its own), the
/// walk resolves the import, reads the host module, recurses (into an empty
/// import set), rewrites it, and stages exactly `ntdll.dll`. This proves the
/// worklist loop, real-DLL resolution, host read, recursion, cycle-insert, and
/// the successful rewrite-and-stage branch run deterministically and cheaply.
///
/// The skip-with-report decision (`resolve_to_host_dll` returning `None`, and
/// path-traversal rejection) is covered on every run by the unit tests above
/// (`resolve_to_host_dll_maps_real_dll_and_absent_contract`,
/// `staged_file_name_rejects_path_traversal`); the deep multi-level walk over a
/// real third-party closure is covered by the two gated tests below.
#[test]
fn stage_transitive_import_closure_walks_and_stages_leaf() {
    let test_dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("closure_walk_hermetic");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();

    let pe_path = build_kernel32_import_pe(&test_dir, "ntdll_only", NTDLL_ONLY_PE_SOURCE, &[]);
    let guest_image = std::fs::read(&pe_path).unwrap();

    // Confirm the fixture really imports the leaf we rely on, so the walk below
    // is exercising the intended (single-DLL) closure.
    let imports = imported_dll_names(&guest_image);
    assert!(
        imports
            .iter()
            .any(|name| name.eq_ignore_ascii_case("ntdll.dll")),
        "ntdll-only fixture did not import ntdll.dll, got {imports:?}"
    );

    let report = stage_transitive_import_closure(&test_dir, &guest_image);

    assert!(
        fixture_system32_path(&test_dir, "ntdll.dll").exists(),
        "closure walk did not stage the ntdll.dll leaf"
    );
    assert!(
        report.staged.iter().any(|dll| dll == "ntdll.dll"),
        "staging report did not record ntdll.dll as staged: {report:?}",
        report = report.staged
    );
}

/// End-to-end hermetic exercise of the staging helper without the external 7za
/// binary: staging the closure of host `ucrtbase.dll` must resolve its api-set
/// imports through the host loader and transitively stage `kernelbase.dll`.
///
/// Rewriting ucrtbase's full transitive closure is expensive (100+ DLLs, ~60s),
/// so this deep end-to-end test is gated behind `LITEBOX_RUN_SLOW_TESTS` and
/// skips cleanly by default. The fast unit tests above cover resolution,
/// parsing, and traversal rejection on every run, and
/// `stage_transitive_import_closure_walks_and_stages_leaf` exercises the walk
/// orchestration on every run; this adds the deep multi-level proof on demand.
#[test]
fn stage_transitive_import_closure_stages_transitive_dependency() {
    if std::env::var_os("LITEBOX_RUN_SLOW_TESTS").is_none() {
        println!(
            "skipping stage_transitive_import_closure_stages_transitive_dependency: \
             LITEBOX_RUN_SLOW_TESTS is not set"
        );
        return;
    }

    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("closure_hermetic");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();

    let ucrtbase = std::fs::read(host_system32_file_path("ucrtbase.dll")).unwrap();
    stage_transitive_import_closure(&test_dir, &ucrtbase);

    assert!(
        fixture_system32_path(&test_dir, "kernelbase.dll").exists(),
        "closure did not transitively stage kernelbase.dll from ucrtbase's api-set imports"
    );
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

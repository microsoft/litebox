// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

// Import-closure tests require dumpbin.exe, either on PATH or installed with
// Visual Studio's x64 C++ tools (located through vswhere.exe).

/// Runs a hello-world guest PE end to end through the userland broker.
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

    let (broker, runner) = build_windows_broker();
    let mut separate_process = std::process::Command::new(&broker);
    separate_process
        .arg("--fs-initial-files")
        .arg(&tar_path)
        .arg("--runner")
        .arg(runner);
    let mut in_process = std::process::Command::new(broker);
    in_process
        .arg("--fs-initial-files")
        .arg(&tar_path)
        .args(["--unstable", "--in-process-runner"]);

    for (mode, mut command) in [
        ("separate-process", separate_process),
        ("in-process", in_process),
    ] {
        // Verbose log for failure triage; not load-bearing for any assertion.
        command.env("LITEBOX_LOG", "debug");
        command.arg("/kernel32_import.exe");
        println!("Running {mode} `{command:?}`");
        let output = command
            .output()
            .expect("failed to run litebox_runner_windows_userland");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "{mode} runner failed to run kernel32-import PE; status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
        assert!(
            stdout.contains("hello world\n"),
            "{mode} guest output was not captured\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

/// Runs a guest PE through the broker that creates and joins a child thread.
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

    let mut command = brokered_windows_runner_command(&tar_path);
    command.env("LITEBOX_LOG", "debug");
    command.arg("/kernel32_multithread.exe");
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

/// Runs a guest PE through the broker that imports the C runtime (ucrtbase via
/// the CRT api-set contracts), forcing ucrtbase to load and initialize.
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

    let mut command = brokered_windows_runner_command(&tar_path);
    command.env("LITEBOX_LOG", "debug");
    command.arg("/crt_locale.exe");
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

fn brokered_windows_runner_command(initial_files: &std::path::Path) -> std::process::Command {
    let (broker, runner) = build_windows_broker();
    let mut command = std::process::Command::new(broker);
    command
        .arg("--fs-initial-files")
        .arg(initial_files)
        .arg("--runner")
        .arg(runner);
    command
}

/// Runs a locally installed x64 Python through the runner. Uses
/// `LITEBOX_PYTHON_PATH` when set, otherwise locates `python.exe` on `PATH`.
/// Supports embeddable distributions and regular installations; the latter's
/// standard library is mounted through the broker. Bytecode writes and site
/// initialization are disabled to avoid modifying the host or loading its packages.
///
/// Python is run with deterministic hash seeding because the Windows entropy
/// path it normally uses is not implemented by the shim yet.
#[test]
fn run_python_pe() {
    let source = python_source();
    println!("Using local Python at `{}`", source.display());
    let source_dir = source
        .parent()
        .expect("LITEBOX_PYTHON_PATH must have a parent directory");
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("python");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();

    let mut host_images = Vec::new();
    for entry in std::fs::read_dir(source_dir)
        .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", source_dir.display()))
    {
        let entry = entry.expect("failed to read Python distribution entry");
        let file_type = entry
            .file_type()
            .expect("failed to read Python distribution entry type");
        if !file_type.is_file() {
            continue;
        }

        let source_path = entry.path();
        let destination = test_dir.join(entry.file_name());
        let bytes = std::fs::read(&source_path)
            .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", source_path.display()));
        let file_name = entry.file_name();
        let file_name = file_name.to_str();
        if file_name.is_some_and(|name| {
            let name = name.to_ascii_lowercase();
            name == "python.exe"
                || (name.starts_with("python")
                    && source_path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("dll")))
        }) {
            let rewritten =
                litebox_syscall_rewriter::rewrite_binary(&bytes, None).unwrap_or_else(|error| {
                    panic!("failed to rewrite `{}`: {error}", source_path.display())
                });
            std::fs::write(&destination, rewritten).unwrap();
            host_images.push(source_path);
        } else {
            std::fs::write(&destination, bytes).unwrap();
        }
    }

    assert!(
        test_dir.join("python.exe").is_file(),
        "Python distribution did not contain python.exe"
    );
    build_rewritten_system_dll(&test_dir, "kernel.appcore.dll");
    host_images.push(host_system32_file_path("kernel.appcore.dll"));
    stage_startup_import_closures(
        &test_dir,
        host_images.iter().map(std::path::PathBuf::as_path),
    );

    let tar_path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("python.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let mut command = brokered_windows_runner_command(&tar_path);
    let stdlib = source_dir.join("Lib");
    if stdlib.is_dir() {
        let mut mount = stdlib.into_os_string();
        mount.push("::/Lib");
        command.arg("--mount").arg(mount);
    }
    // command.env("LITEBOX_LOG", "debug");
    command.args([
        "--env",
        "PYTHONHASHSEED=0",
        "/python.exe",
        "-B",
        "-S",
        "-c",
        "import colorsys, sys; assert sys.dont_write_bytecode and sys.flags.no_site; \
         assert colorsys.rgb_to_hsv(1, 0, 0) == (0, 1, 1); print('hello world')",
    ]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!(
        "Python exit: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );

    assert!(
        output.status.success(),
        "Python failed; status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.lines().any(|line| line == "hello world"),
        "Python output was not captured\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn python_source() -> std::path::PathBuf {
    if let Some(source) = std::env::var_os("LITEBOX_PYTHON_PATH") {
        let source = std::path::PathBuf::from(source);
        assert!(
            source.is_file(),
            "LITEBOX_PYTHON_PATH does not point to a file: `{}`",
            source.display()
        );
        return source;
    }

    std::env::var_os("PATH")
        .and_then(|paths| find_executable_on_path("python.exe", &paths))
        .expect("python.exe not found on PATH; install x64 Python or set LITEBOX_PYTHON_PATH")
}

/// Runs a locally installed x64 Node.js through the runner. Uses
/// `LITEBOX_NODE_PATH` when set, otherwise locates `node.exe` on `PATH`.
#[test]
fn run_node_pe() {
    let source = node_source();
    println!("Using local Node.js at `{}`", source.display());
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("node");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).unwrap();

    let host_exe = std::fs::read(&source)
        .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", source.display()));
    let rewritten = litebox_syscall_rewriter::rewrite_binary(&host_exe, None)
        .expect("failed to rewrite node.exe");
    std::fs::write(test_dir.join("node.exe"), rewritten).unwrap();

    let mut host_images = vec![source];
    // Startup-only scans omit dbghelp's dbgcore export forwarders and the
    // delay-load dependencies and provider DLLs used by BCrypt and legacy CryptoAPI.
    for dll_name in [
        "dbgcore.dll",
        "bcryptprimitives.dll",
        "cryptbase.dll",
        "cryptsp.dll",
        "rsaenh.dll",
    ] {
        build_rewritten_system_dll(&test_dir, dll_name);
        host_images.push(host_system32_file_path(dll_name));
    }
    stage_startup_import_closures(
        &test_dir,
        host_images.iter().map(std::path::PathBuf::as_path),
    );
    stage_node_cryptoapi_registry(&test_dir);

    let tar_path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("node.tar");
    create_tar_with_dir(&test_dir, &tar_path);

    let mut command = brokered_windows_runner_command(&tar_path);
    // command.env("LITEBOX_LOG", "debug");
    command.args(["/node.exe", "-e", "console.log('hello world')"]);
    println!("Running `{command:?}`");
    let output = command
        .output()
        .expect("failed to run litebox_runner_windows_userland");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!(
        "Node.js exit: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );

    assert!(
        output.status.success(),
        "Node.js failed; status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.lines().any(|line| line == "hello world"),
        "Node.js output was not captured\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Provisions the legacy CryptoAPI RSA provider used by some local Node builds.
fn stage_node_cryptoapi_registry(test_dir: &std::path::Path) {
    let defaults = test_dir.join(r"registry\machine\software\microsoft\cryptography\defaults");
    for (key, name, value) in [
        (
            r"provider types\type 001",
            "name",
            "Microsoft Strong Cryptographic Provider",
        ),
        (
            r"provider\microsoft strong cryptographic provider",
            "image path",
            r"C:\Windows\System32\rsaenh.dll",
        ),
    ] {
        let values_dir = defaults.join(key).join(".values");
        std::fs::create_dir_all(&values_dir).unwrap();
        // Registry value files begin with a little-endian REG_SZ type tag.
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend(
            value
                .encode_utf16()
                .chain(core::iter::once(0))
                .flat_map(u16::to_le_bytes),
        );
        std::fs::write(values_dir.join(name), bytes).unwrap();
    }
    let mut bytes = 4u32.to_le_bytes().to_vec(); // REG_DWORD
    bytes.extend(1u32.to_le_bytes()); // PROV_RSA_FULL
    std::fs::write(
        defaults.join(r"provider\microsoft strong cryptographic provider\.values\type"),
        bytes,
    )
    .unwrap();
}

fn node_source() -> std::path::PathBuf {
    if let Some(source) = std::env::var_os("LITEBOX_NODE_PATH") {
        let source = std::path::PathBuf::from(source);
        assert!(
            source.is_file(),
            "LITEBOX_NODE_PATH does not point to a file: `{}`",
            source.display()
        );
        return source;
    }

    std::env::var_os("PATH")
        .and_then(|paths| find_executable_on_path("node.exe", &paths))
        .expect("node.exe not found on PATH; install x64 Node.js or set LITEBOX_NODE_PATH")
}

/// Stages the minimal guest system DLLs and locale tables the lightweight PE
/// fixtures need. These fixtures import only a tiny surface, so a fixed minimal
/// set is deliberately used rather than the full transitive closure: walking
/// `kernel32`'s real closure would stage hundreds of DLLs and exhaust the guest
/// allocator. The transitive-closure helpers are used instead for real
/// third-party applications.
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

fn find_executable_on_path(name: &str, paths: &std::ffi::OsStr) -> Option<std::path::PathBuf> {
    std::env::split_paths(paths)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join(name))
        .find(|path| path.is_file())
}

#[test]
fn find_executable_on_path_respects_order_and_skips_directories() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("executable_lookup");
    let directory = test_dir.join("directory");
    let first = test_dir.join("first with spaces");
    let second = test_dir.join("second");
    std::fs::create_dir_all(directory.join("node.exe")).unwrap();
    for dir in [&first, &second] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("node.exe"), b"fixture").unwrap();
    }
    let paths = std::env::join_paths([&directory, &first, &second]).unwrap();
    assert_eq!(
        find_executable_on_path("node.exe", &paths),
        Some(first.join("node.exe"))
    );
    let paths = std::env::join_paths([&second, &first]).unwrap();
    assert_eq!(
        find_executable_on_path("node.exe", &paths),
        Some(second.join("node.exe"))
    );
    assert_eq!(find_executable_on_path("missing.exe", &paths), None);
    assert_eq!(
        find_executable_on_path("node.exe", std::ffi::OsStr::new("")),
        None
    );
}

fn dumpbin_path() -> &'static std::path::Path {
    static DUMPBIN: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        if let Some(path) = std::env::var_os("PATH")
            .and_then(|paths| find_executable_on_path("dumpbin.exe", &paths))
        {
            return path;
        }

        let vswhere = std::path::PathBuf::from(
            std::env::var_os("ProgramFiles(x86)")
                .expect("ProgramFiles(x86) is not set; put dumpbin.exe on PATH"),
        )
        .join(r"Microsoft Visual Studio\Installer\vswhere.exe");
        let output = std::process::Command::new(&vswhere)
            .args([
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-find",
                r"VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe",
            ])
            .output()
            .unwrap_or_else(|error| {
                panic!("failed to run `{}`: {error}; install Visual Studio's x64 C++ tools or put dumpbin.exe on PATH", vswhere.display())
            });
        assert!(
            output.status.success(),
            "vswhere failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("vswhere output is not UTF-8")
            .lines()
            .map(|line| std::path::PathBuf::from(line.trim()))
            .find(|path| path.is_file())
            .expect(
                "dumpbin.exe not found; install Visual Studio's x64 C++ tools or put it on PATH",
            )
    });
    &DUMPBIN
}

#[derive(Debug, Default)]
struct ImportScan {
    names: Vec<String>,
    regular_names: Vec<String>,
}

/// Parses dumpbin's regular and delay-load dependency sections, ignoring the
/// input filename and section summary. Diagnostics are errors even when
/// dumpbin exits successfully (for example, warning LNK4048 for invalid input).
fn parse_dumpbin_dependents(output: &str) -> Result<ImportScan, String> {
    let mut scan = ImportScan::default();
    let mut regular = None;
    let mut is_pe = false;
    let mut has_summary = false;
    for line in output.lines().map(str::trim) {
        if line.contains(": warning ")
            || line.contains(": error ")
            || line.contains(": fatal error ")
        {
            return Err(line.to_owned());
        }
        match line {
            "File Type: DLL" | "File Type: EXECUTABLE IMAGE" => is_pe = true,
            "Image has the following dependencies:" => regular = Some(true),
            "Image has the following delay load dependencies:" => regular = Some(false),
            "Summary" => {
                regular = None;
                has_summary = true;
            }
            "" => {}
            name => {
                if let Some(regular) = regular {
                    let name = staged_file_name(name)
                        .ok_or_else(|| format!("invalid dumpbin dependency name `{name}`"))?;
                    if regular {
                        scan.regular_names.push(name.clone());
                    }
                    scan.names.push(name);
                }
            }
        }
    }
    if !is_pe || !has_summary {
        return Err(format!(
            "unrecognized or incomplete dumpbin output:\n{output}"
        ));
    }
    Ok(scan)
}

fn scan_imports(image: &std::path::Path) -> Result<ImportScan, String> {
    let output = std::process::Command::new(dumpbin_path())
        .args(["/NOLOGO", "/DEPENDENTS"])
        .arg(image)
        .output()
        .map_err(|error| format!("failed to start dumpbin: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "dumpbin failed for `{}`: {}\nstdout:\n{}\nstderr:\n{}",
            image.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("dumpbin output is not UTF-8: {error}"))?;
    parse_dumpbin_dependents(&stdout)
        .map_err(|error| format!("dumpbin could not inspect `{}`: {error}", image.display()))
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
/// skipped (with a reason). Failed import scans abort staging instead of
/// silently treating an unreadable import table as an empty closure.
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
}

fn stage_transitive_import_closure(
    test_dir: &std::path::Path,
    guest_image: &std::path::Path,
) -> StagingReport {
    stage_import_closure(test_dir, [guest_image], true)
}

fn stage_startup_import_closures<'a>(
    test_dir: &std::path::Path,
    guest_images: impl IntoIterator<Item = &'a std::path::Path>,
) -> StagingReport {
    stage_import_closure(test_dir, guest_images, false)
}

fn stage_import_closure<'a>(
    test_dir: &std::path::Path,
    guest_images: impl IntoIterator<Item = &'a std::path::Path>,
    include_delay_imports: bool,
) -> StagingReport {
    let mut report = StagingReport::default();
    let mut staged = std::collections::BTreeSet::new();
    let mut worklist = Vec::new();

    for guest_image in guest_images {
        let scan = scan_imports(guest_image).unwrap_or_else(|error| panic!("closure: {error}"));
        worklist.extend(if include_delay_imports {
            scan.names
        } else {
            scan.regular_names
        });
    }

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
        let scan = scan_imports(&host_path).unwrap_or_else(|error| panic!("closure: {error}"));
        worklist.extend(if include_delay_imports {
            scan.names
        } else {
            scan.regular_names
        });

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

#[test]
fn scan_imports_parses_host_dll() {
    let names = scan_imports(&host_system32_file_path("ucrtbase.dll"))
        .unwrap()
        .names;
    assert!(!names.is_empty(), "ucrtbase.dll should have imports");
    assert!(
        names
            .iter()
            .any(|name| name.to_ascii_lowercase().starts_with("api-ms-win-")),
        "expected api-set imports, got {names:?}"
    );
}

#[test]
fn scan_imports_reports_unparsable_pe() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dumpbin_invalid");
    std::fs::create_dir_all(&test_dir).unwrap();
    let path = test_dir.join("invalid image.dll");
    std::fs::write(&path, b"this is not a PE image").unwrap();
    let error = scan_imports(&path).unwrap_err();
    assert!(
        error.contains("LNK"),
        "expected a dumpbin diagnostic: {error}"
    );
}

#[test]
fn scan_imports_reports_missing_file() {
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("dumpbin_missing")
        .join("missing.dll");
    assert!(!path.exists());
    let error = scan_imports(&path).unwrap_err();
    assert!(
        error.contains("LNK"),
        "expected a dumpbin diagnostic: {error}"
    );
}

#[test]
fn parse_dumpbin_dependents_separates_startup_and_delay_imports() {
    let scan = parse_dumpbin_dependents(
        "Dump of file C:\\a directory\\input.dll\r\n\
         File Type: DLL\r\n\
           Image has the following dependencies:\r\n\
         \r\n\
             KERNEL32.dll\r\n\
             api-ms-win-crt-runtime-l1-1-0.dll\r\n\
           Image has the following delay load dependencies:\r\n\
         \r\n\
             VERSION.dll\r\n\
             plugin.without_dll_extension\r\n\
           Summary\r\n\
                 1000 .data\r\n",
    )
    .unwrap();
    assert_eq!(
        scan.regular_names,
        ["kernel32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"]
    );
    assert_eq!(
        scan.names,
        [
            "kernel32.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "version.dll",
            "plugin.without_dll_extension",
        ]
    );
}

#[test]
fn parse_dumpbin_dependents_accepts_import_free_and_delay_only_images() {
    let scan = parse_dumpbin_dependents(
        "Dump of file leaf.dll\nFile Type: DLL\n  Summary\n  1000 .text\n",
    )
    .unwrap();
    assert_eq!(scan.names, Vec::<String>::new());
    let scan = parse_dumpbin_dependents(
        "File Type: EXECUTABLE IMAGE\n\
         Image has the following delay load dependencies:\n\
             VERSION.dll\n\
         Summary\n",
    )
    .unwrap();
    assert_eq!(scan.regular_names, Vec::<String>::new());
    assert_eq!(scan.names, ["version.dll"]);
}

#[test]
fn parse_dumpbin_dependents_rejects_diagnostics_and_unrecognized_output() {
    for output in [
        "",
        "Dump of file invalid.dll\n  Summary\n",
        "File Type: DLL\n",
        "File Type: DLL\ninvalid.dll : warning LNK4048: Invalid format file; ignored\nSummary\n",
        "invalid.dll : fatal error LNK1107: invalid or corrupt file\n",
        "invalid.dll : error LNK1107: invalid or corrupt file\n",
        "File Type: DLL\nImage has the following dependencies:\n..\\evil.dll\nSummary\n",
    ] {
        assert!(
            parse_dumpbin_dependents(output).is_err(),
            "accepted invalid output: {output}"
        );
    }
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

    std::fs::write(&pe_path, guest_image).unwrap();
    let report = stage_transitive_import_closure(&test_dir, &pe_path);

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
    // Confirm the fixture really imports the leaf we rely on, so the walk below
    // is exercising the intended (single-DLL) closure.
    let imports = scan_imports(&pe_path).unwrap().names;
    assert!(
        imports
            .iter()
            .any(|name| name.eq_ignore_ascii_case("ntdll.dll")),
        "ntdll-only fixture did not import ntdll.dll, got {imports:?}"
    );

    let report = stage_transitive_import_closure(&test_dir, &pe_path);

    assert!(
        fixture_system32_path(&test_dir, "ntdll.dll").exists(),
        "closure walk did not stage the ntdll.dll leaf"
    );
    assert!(
        report.staged.iter().any(|dll| dll == "ntdll.dll"),
        "staging report did not record ntdll.dll as staged: {report:?}",
        report = report.staged
    );

    let ntdll = host_system32_file_path("ntdll.dll");
    let startup_report =
        stage_startup_import_closures(&test_dir, [pe_path.as_path(), ntdll.as_path()]);
    assert_eq!(startup_report.staged, ["ntdll.dll"]);
    assert_eq!(startup_report.skipped, Vec::<String>::new());
}

/// End-to-end hermetic exercise of the staging helper without an external
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

    stage_transitive_import_closure(&test_dir, &host_system32_file_path("ucrtbase.dll"));

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

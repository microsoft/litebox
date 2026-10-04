// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests for the Windows userland runner.
//!
//! **NOTE:** These tests depend on pre-built Linux ELF binaries in `tests/test-bins/`,
//! including shared libraries (`libc.so.6`, `ld-linux-x86-64.so.2`)
//! and test executables.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_exec_nolibc` test."
)]
const HELLO_WORLD_NOLIBC: &str = r#"
// gcc tests/test.c -o test -static -nostdlib (-m32)
#if defined(__x86_64__)
int write(int fd, const char *buf, int length)
{
    int ret;

    asm("mov %1, %%eax\n\t"
        "mov %2, %%edi\n\t"
        "mov %3, %%rsi\n\t"
        "mov %4, %%edx\n\t"
        "syscall\n\t"
        "mov %%eax, %0"
        : "=r" (ret)
        : "i" (1), // #define SYS_write 1
          "r" (fd),
          "r" (buf),
          "r" (length)
        : "%eax", "%edi", "%rsi", "%edx");

    return ret;
}

_Noreturn void exit_group(int code)
{
    /* Infinite for-loop since this function can't return */
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%edi\n\t"
            "syscall\n\t"
            :
            : "i" (231), // #define SYS_exit_group 231
              "r" (code)
            : "%eax", "%edi");
    }
}
#elif defined(__i386__)
int write(int fd, const char *buf, int length)
{
    int ret;

    asm("mov %1, %%eax\n\t"
        "mov %2, %%ebx\n\t"
        "mov %3, %%ecx\n\t"
        "mov %4, %%edx\n\t"
        "int $0x80\n\t"
        "mov %%eax, %0"
        : "=r" (ret)
        : "i" (4), // #define SYS_write 4
          "g" (fd),
          "g" (buf),
          "g" (length)
        : "%eax", "%ebx", "%ecx", "%edx");

    return ret;
}
_Noreturn void exit_group(int code)
{
    /* Infinite for-loop since this function can't return */
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%ebx\n\t"
            "int $0x80\n\t"
            :
            : "i" (252), // #define SYS_exit_group 252
              "r" (code)
            : "%eax", "%ebx");
    }
}
#else
#error "Unsupported architecture"
#endif

int main() {
    // use write to print a string
    write(1, "Hello, World!\n", 14);
    return 0;
}

void _start() {
    exit_group(main());
}
"#;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_thread_static/dynamic` test."
)]
const HELLO_WORLD: &str = r#"
// gcc -o hello_world_static hello_world_static.c -static
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
"#;

#[expect(
    unused,
    reason = "This code snippet is just used to illustrate the source code of the `hello_thread_static/dynamic` test."
)]
const HELLO_THREAD: &str = r#"
// gcc hello_thread.c -o hello_thread_static -static
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void* child_thread_func(void* arg) {
    (void)arg;
    printf("Hello from child thread.\n");
    return NULL;
}

int main(void) {
    pthread_t tid;

    if (pthread_create(&tid, NULL, child_thread_func, NULL) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    printf("Hello from main thread.\n");

    if (pthread_join(tid, NULL) != 0) {
        perror("pthread_join");
        exit(EXIT_FAILURE);
    }

    return 0;
}
"#;

#[test]
fn test_static_linked_prog_with_rewriter() {
    println!("Running statically linked binary + rewriter test...");
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests/test-bins");

    let prog_name = "hello_world_static";
    let path = test_dir.join(prog_name);
    let executable_data =
        litebox_syscall_rewriter::rewrite_binary(&std::fs::read(path).unwrap(), None).unwrap();

    let (broker, runner) = build_windows_broker();
    run_prog_with_windows_broker(&broker, &runner, prog_name, &[], Some(&executable_data));
}

#[test]
fn test_programs_with_windows_broker() {
    let (broker, runner) = build_windows_broker();
    run_prog_with_windows_broker(&broker, &runner, "hello_world_static", &[], None);
    run_prog_with_windows_broker(&broker, &runner, "pipe_broker", &[], None);
    run_prog_with_windows_broker(&broker, &runner, "hello_world_dyn", &DYNAMIC_LIBS, None);
    run_prog_with_windows_broker(&broker, &runner, "hello_thread", &DYNAMIC_LIBS, None);
}

/// Runs `fork_parent`, whose children resume from snapshots of their parents' memory.
///
/// Built with `gcc -static -m64` from `litebox_runner_linux_userland/tests/fork_parent.c`.
#[test]
fn test_fork_with_windows_broker() {
    let (broker, runner) = build_windows_broker();
    let output = run_progs_with_process_duplication(&broker, &runner, &["fork_parent"], &[]);

    let parent = output_line(&output, "parent ");
    assert_eq!(numeric_field(parent, "global="), 2);
    assert_eq!(numeric_field(parent, "intact="), 1);
    assert_eq!(numeric_field(parent, "echild="), 1);
    let fork = output_line(&output, "fork ");
    let child = numeric_field(fork, "child=");
    assert_ne!(child, numeric_field(parent, "pid="));
    assert_eq!(numeric_field(fork, "waited="), child);
    // The child and its own forked child passed every check.
    assert_eq!(numeric_field(fork, "code="), 7);
    assert_eq!(numeric_field(output_line(&output, "pipe "), "failures="), 0);
    assert_eq!(numeric_field(output_line(&output, "raw-fork "), "code="), 9);
}

/// Runs `vfork_exec_parent`, whose child execs `vfork_exec_child` in a new runner.
///
/// Built with `gcc -static -m64` from `litebox_runner_linux_userland/tests/vfork_exec_*.c`.
#[test]
fn test_vfork_exec_with_windows_broker() {
    let (broker, runner) = build_windows_broker();
    let output = run_progs_with_process_duplication(
        &broker,
        &runner,
        &["vfork_exec_parent", "vfork_exec_child"],
        &["/bin/vfork_exec_child.hooked"],
    );

    let parent = output_line(&output, "parent ");
    let child = numeric_field(parent, "child=");
    assert_eq!(numeric_field(parent, "waited="), child);
    assert_eq!(numeric_field(parent, "code="), 42);
    let child_line = output_line(&output, "child ");
    assert_eq!(numeric_field(child_line, "pid="), child);
    assert_eq!(
        numeric_field(child_line, "ppid="),
        numeric_field(parent, "before=")
    );
    assert!(child_line.contains("marker=from-vfork env=1"));
}

const DYNAMIC_LIBS: [(&str, &str); 2] = [
    ("libc.so.6", "/lib/x86_64-linux-gnu"),
    ("ld-linux-x86-64.so.2", "/lib64"),
];

fn build_windows_broker() -> (std::path::PathBuf, std::path::PathBuf) {
    let runner = std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_linux_on_windows_userland")
        .map_or_else(
            || {
                std::path::PathBuf::from(env!(
                    "CARGO_BIN_EXE_litebox_runner_linux_on_windows_userland"
                ))
            },
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

fn run_prog_with_windows_broker(
    broker: &std::path::Path,
    runner: &std::path::Path,
    exec_name: &str,
    libs: &[(&str, &str)],
    pre_rewritten_exec: Option<&[u8]>,
) {
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test-bins");
    let variant = if pre_rewritten_exec.is_some() {
        "_pre_rewritten"
    } else {
        ""
    };
    let tar_path = std::path::Path::new(env!("OUT_DIR"))
        .join(format!("broker_{exec_name}{variant}_rootfs.tar"));
    let mut tar = tar::Builder::new(std::fs::File::create(&tar_path).unwrap());
    let exec_path = format!("bin/{exec_name}.hooked");
    if let Some(executable) = pre_rewritten_exec {
        append_file(&mut tar, executable, &exec_path);
    } else {
        append_rewritten_file(&mut tar, &test_dir.join(exec_name), &exec_path);
    }
    for (file, prefix) in libs {
        append_rewritten_file(
            &mut tar,
            &test_dir.join(file),
            &format!("{}/{file}", prefix.trim_start_matches('/')),
        );
    }
    tar.finish().unwrap();
    drop(tar);

    let mut arguments: Vec<std::ffi::OsString> = Vec::new();
    if !libs.is_empty() {
        arguments.extend(["--env".into(), "LD_LIBRARY_PATH=/lib64:/lib32:/lib".into()]);
    }
    arguments.push(format!("/{exec_path}").into());
    let status = std::process::Command::new(broker)
        .arg("--fs-initial-files")
        .arg(&tar_path)
        .arg("--runner")
        .arg(runner)
        .args(arguments)
        .status()
        .expect("failed to run litebox-broker-userland");
    assert!(status.success(), "litebox-broker-userland failed: {status}");
}

/// Runs the first of `programs` with `arguments` and process duplication allowed, and returns its
/// standard output. Each program is at `/bin/<program>.hooked`.
fn run_progs_with_process_duplication(
    broker: &std::path::Path,
    runner: &std::path::Path,
    programs: &[&str],
    arguments: &[&str],
) -> String {
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test-bins");
    let tar_path =
        std::path::Path::new(env!("OUT_DIR")).join(format!("broker_{}_rootfs.tar", programs[0]));
    let mut tar = tar::Builder::new(std::fs::File::create(&tar_path).unwrap());
    for program in programs {
        append_rewritten_file(
            &mut tar,
            &test_dir.join(program),
            &format!("bin/{program}.hooked"),
        );
    }
    tar.finish().unwrap();
    drop(tar);

    let output = std::process::Command::new(broker)
        .args([
            "--unstable",
            "--allow-process-duplication",
            "--fs-initial-files",
        ])
        .arg(&tar_path)
        .arg("--runner")
        .arg(runner)
        .arg(format!("/bin/{}.hooked", programs[0]))
        .args(arguments)
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("failed to run litebox-broker-userland");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "litebox-broker-userland failed: {}\n{stdout}",
        output.status
    );
    stdout
}

fn output_line<'a>(output: &'a str, prefix: &str) -> &'a str {
    output
        .lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing {prefix:?} output in {output:?}"))
}

fn numeric_field(line: &str, name: &str) -> i32 {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(name)?.parse().ok())
        .unwrap_or_else(|| panic!("missing {name} in {line:?}"))
}

fn append_rewritten_file(
    tar: &mut tar::Builder<std::fs::File>,
    source: &std::path::Path,
    archive_path: &str,
) {
    let rewritten =
        litebox_syscall_rewriter::rewrite_binary(&std::fs::read(source).unwrap(), None).unwrap();
    append_file(tar, &rewritten, archive_path);
}

fn append_file(tar: &mut tar::Builder<std::fs::File>, contents: &[u8], archive_path: &str) {
    let mut header = tar::Header::new_ustar();
    header.set_size(contents.len() as u64);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    tar.append_data(&mut header, archive_path, contents)
        .unwrap();
}

fn run_dynamic_linked_prog_with_rewriter(
    libs_to_rewrite: &[(&str, &str)],
    exec_name: &str,
    cmd_args: &[&str],
    install_files: fn(std::path::PathBuf),
) {
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests/test-bins");

    let prog_name = exec_name;
    let prog_name_hooked = format!("{prog_name}.hooked");

    let out_path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("dynamic_rewriter_{prog_name}"));
    std::fs::create_dir_all(&out_path).unwrap();
    let path = test_dir.join(prog_name);
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    // Create tar file containing all dependencies
    let tar_src_path = out_path.join("test_program_tar");
    println!(
        "Creating tar source directory path: {}",
        tar_src_path.to_str().unwrap()
    );

    std::fs::create_dir_all(tar_src_path.join("out")).unwrap();

    // Rewrite all libraries that are required for initialization
    for (file, prefix) in libs_to_rewrite {
        let src = test_dir.join(file);
        let dst_dir = tar_src_path.join(prefix.trim_start_matches('/'));
        let dst = dst_dir.join(file);
        std::fs::create_dir_all(&dst_dir).unwrap();
        let _ = std::fs::remove_file(&dst);
        println!(
            "Running `cargo run -p litebox_syscall_rewriter -- {} -o {}`",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        );
        let output = std::process::Command::new(&cargo)
            .args([
                "run",
                "-p",
                "litebox_syscall_rewriter",
                "--",
                src.to_str().unwrap(),
                "-o",
                dst.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run syscall rewriter");
        assert!(
            output.status.success(),
            "failed to run syscall rewriter {:?}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap()
        );
    }

    // Install the required files (e.g., scripts) to tar directory's /out
    install_files(tar_src_path.join("out"));

    let tar_target_file = out_path.join("rootfs_rewriter.tar");
    let mut tar = tar::Builder::new(std::fs::File::create(&tar_target_file).unwrap());
    for directory in ["lib", "lib64", "out"] {
        tar.append_dir_all(directory, tar_src_path.join(directory))
            .unwrap();
    }
    append_rewritten_file(&mut tar, &path, &format!("bin/{prog_name_hooked}"));
    tar.finish().unwrap();
    println!("Tar file created at: {}", tar_target_file.to_str().unwrap());

    // The program path refers to the tar-internal path.
    let prog_tar_path = format!("/bin/{prog_name_hooked}");

    // Run litebox_runner_linux_on_windows_userland with the broker-owned file system.
    let mut args = vec![
        // Tell ld where to find the libraries.
        // See https://man7.org/linux/man-pages/man8/ld.so.8.html for how ld works.
        // Alternatively, we could add a `/etc/ld.so.cache` file to the rootfs.
        "--env",
        "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
    ];
    args.push(&prog_tar_path);
    args.extend_from_slice(cmd_args);
    let (broker, runner) = build_windows_broker();
    let mut command = std::process::Command::new(broker);
    command
        .arg("--fs-initial-files")
        .arg(&tar_target_file)
        .arg("--runner")
        .arg(runner)
        .args(&args);
    println!("Running `{command:?}`");
    let status = command
        .status()
        .expect("Failed to run litebox_runner_linux_on_windows_userland");
    assert!(
        status.success(),
        "failed to run litebox_runner_linux_on_windows_userland: {status}",
    );
}

#[test]
fn test_testcase_dynamic_with_rewriter() {
    let exec_name = "hello_world_dyn";
    let libs_to_rewrite = [
        ("libc.so.6", "/lib/x86_64-linux-gnu"),
        ("ld-linux-x86-64.so.2", "/lib64"),
    ];
    // Run
    run_dynamic_linked_prog_with_rewriter(&libs_to_rewrite, exec_name, &[], |_| {});
}

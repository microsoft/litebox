#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

mod common;

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
    let prog_name_hooked = format!("{prog_name}.hooked");

    let path = test_dir.join(prog_name);
    let hooked_path = test_dir.join(&prog_name_hooked);

    // rewrite the target ELF executable file
    let _ = std::fs::remove_file(hooked_path.clone());
    println!(
        "Running `cargo run -p litebox_syscall_rewriter -- -o {} {}`",
        hooked_path.to_str().unwrap(),
        path.to_str().unwrap()
    );
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_syscall_rewriter",
            "--",
            path.to_str().unwrap(),
            "-o",
            hooked_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run syscall rewriter");
    assert!(
        output.status.success(),
        "failed to run syscall rewriter {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    let executable_path = format!("/{prog_name_hooked}");
    let executable_data = std::fs::read(hooked_path).unwrap();

    common::init_platform(&[], &[], &[]);
    common::install_file(executable_data, &executable_path);
    common::test_load_exec_common(&executable_path);
}

// #[test]
#[expect(clippy::too_many_lines)]
fn run_dynamic_linked_prog_with_rewriter(
    libs_to_rewrite: &[(&str, &str)],
    libs_without_rewrite: &[(&str, &str)],
    exec_name: &str,
    cmd_args: &[&str],
    install_files: fn(std::path::PathBuf),
) {
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests/test-bins");

    let prog_name = exec_name;
    let prog_name_hooked = format!("{prog_name}.hooked");

    let path = test_dir.join(prog_name);
    let hooked_path = test_dir.join(&prog_name_hooked);

    let out_path = std::env::var("OUT_DIR").unwrap();

    // Rewrite the target ELF executable file
    let _ = std::fs::remove_file(hooked_path.clone());
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_syscall_rewriter",
            "--",
            path.to_str().unwrap(),
            "-o",
            hooked_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run syscall rewriter");
    assert!(
        output.status.success(),
        "failed to run syscall rewriter {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    // Create tar file containing all dependencies
    let tar_src_path = std::path::Path::new(&out_path).join("test_program_tar");
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
        let output = std::process::Command::new("cargo")
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

    // Copy libraries that are not needed to be rewritten (`litebox_rtld_audit.so`)
    // to the tar directory
    for (file, prefix) in libs_without_rewrite {
        let src = test_dir.join(file);
        let dst_dir = tar_src_path.join(prefix.trim_start_matches('/'));
        let dst = dst_dir.join(file);
        std::fs::create_dir_all(&dst_dir).unwrap();
        let _ = std::fs::remove_file(&dst);
        println!(
            "Copying {} to {}",
            src.to_str().unwrap(),
            dst.to_str().unwrap()
        );
        std::fs::copy(&src, &dst).unwrap();
    }

    // Install the required files (e.g., scripts) to tar directory's /out
    install_files(tar_src_path.join("out"));

    // tar
    let tar_target_file = std::path::Path::new(&out_path).join("rootfs_rewriter.tar");
    let tar_data = std::process::Command::new("tar")
        .args([
            "-cvf",
            tar_target_file.to_str().unwrap(),
            "lib",
            "lib64",
            "out",
        ])
        .current_dir(&tar_src_path)
        .output()
        .expect("Failed to create tar file");
    assert!(
        tar_data.status.success(),
        "failed to create tar file {:?}",
        std::str::from_utf8(tar_data.stderr.as_slice()).unwrap()
    );
    println!("Tar file created at: {}", tar_target_file.to_str().unwrap());

    // Run litebox_runner_linux_on_windows_userland with the tar file and the compiled executable
    let mut args = vec![
        "run",
        "-p",
        "litebox_runner_linux_on_windows_userland",
        "--",
        "--unstable",
        // Tell ld where to find the libraries.
        // See https://man7.org/linux/man-pages/man8/ld.so.8.html for how ld works.
        // Alternatively, we could add a `/etc/ld.so.cache` file to the rootfs.
        "--env",
        "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
        "--initial-files",
        tar_target_file.to_str().unwrap(),
        "--env",
        "LD_AUDIT=/lib64/litebox_rtld_audit.so",
    ];
    args.push(hooked_path.to_str().unwrap());
    args.extend_from_slice(cmd_args);

    println!("Running `cargo {}`", args.join(" "));
    let output = std::process::Command::new("cargo")
        .args(args)
        .output()
        .expect("Failed to run litebox_runner_linux_on_windows_userland");
    assert!(
        output.status.success(),
        "failed to run litebox_runner_linux_on_windows_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
}

#[test]
fn test_testcase_dynamic_with_rewriter() {
    let exec_name = "hello_world_dyn";
    let libs_to_rewrite = [
        ("libc.so.6", "/lib/x86_64-linux-gnu"),
        ("ld-linux-x86-64.so.2", "/lib64"),
    ];
    let libs_without_rewrite = [("litebox_rtld_audit.so", "/lib64")];

    // Run
    run_dynamic_linked_prog_with_rewriter(
        &libs_to_rewrite,
        &libs_without_rewrite,
        exec_name,
        &[],
        |_| {},
    );
}

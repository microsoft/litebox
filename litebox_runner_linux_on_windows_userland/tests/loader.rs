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
    reason = "This code snippet is just used to illustrate the source code of the `hello_thread_static` test."
)]
const HELLO_THREAD_STATIC: &str = r#"
// gcc hello_thread.c -o hello_thread_static -static                                                                                                     7,36          Top
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
fn test_syscall_rewriter() {
    println!("Running syscall rewriter test...");
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests");
    let path = test_dir.join("hello_exec_nolibc");
    let hooked_path = test_dir.join("hello_exec_nolibc.hooked");

    // rewrite the hello_exec_nolibc
    let _ = std::fs::remove_file(hooked_path.clone());
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_syscall_rewriter",
            "--",
            "--trampoline-addr",
            litebox_shim_linux::loader::REWRITER_MAGIC_NUMBER
                .to_string()
                .as_str(),
            "-o",
            hooked_path.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run syscall rewriter");
    assert!(
        output.status.success(),
        "failed to run syscall rewriter {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    let executable_path = "/hello_exec_nolibc.hooked";
    let executable_data = std::fs::read(hooked_path).unwrap();

    common::init_platform(&[], &[], &[]);
    common::install_file(executable_data, executable_path);
    common::test_load_exec_common(executable_path);
}

#[test]
fn test_hello_thread_static_rewriter() {
    println!("Running hello_thread static + rewriter test...");
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests");
    let path = test_dir.join("hello_thread_static");
    let hooked_path = test_dir.join("hello_thread_static.hooked");

    // rewrite the hello_thread_static
    let _ = std::fs::remove_file(hooked_path.clone());
    println!("Running `cargo run -p litebox_syscall_rewriter -- -o {} {}`",
                hooked_path.to_str().unwrap(),
                path.to_str().unwrap());
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

    let executable_path = "/hello_thread_static.hooked";
    let executable_data = std::fs::read(hooked_path).unwrap();

    common::init_platform(&[], &[], &[]);
    common::install_file(executable_data, executable_path);
    common::test_load_exec_common(executable_path);
}

const HELLO_THREAD_INIT_FILES: [(&str, &str); 2] = [
    ("libc.so.6", "/lib/x86_64-linux-gnu"),
    ("ld-linux-x86-64.so.2", "/lib64"),
];

#[test]
fn test_dynamic_lib_rewriter() {
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests");
    let path = test_dir.join("hello_thread");
    let hooked_path = test_dir.join("hello_thread.hooked");

    // rewrite the hello_thread
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

    let executable_path = "/hello_exec_nolibc.hooked";
    let executable_data = std::fs::read(hooked_path).unwrap();

    // create tar file containing all dependencies
    let tar_dir = test_dir.join("hello_thread_tar");
    std::fs::create_dir_all(tar_dir.join("out")).unwrap();

    for (file, prefix) in HELLO_THREAD_INIT_FILES {
        let src = test_dir.join(file);
        let dst_dir = tar_dir.join(prefix.trim_start_matches('/'));
        let dst = dst_dir.join(file);
        std::fs::create_dir_all(&dst_dir).unwrap();
        std::fs::copy(&src, &dst).unwrap();
    }
}
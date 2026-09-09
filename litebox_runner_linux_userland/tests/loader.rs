// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod cache;
mod common;

use common::runner::Runner;

#[test]
fn test_load_exec_dynamic() {
    let path = common::compile("./tests/hello.c", "hello_dylib", false, false);
    Runner::new(&path, "loader_dynamic")
        .env("PATH=/bin")
        .arg("hello")
        .run();
}

#[test]
fn test_load_exec_static() {
    let path = common::compile("./tests/hello.c", "hello_exec", true, false);
    Runner::new(&path, "loader_static")
        .env("PATH=/bin")
        .arg("hello")
        .run();
}

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
        : "i" (1), // x86-64 SYS_write
          "r" (fd),
          "r" (buf),
          "r" (length)
        : "%eax", "%edi", "%rsi", "%edx");

    return ret;
}

_Noreturn void exit_group(int code)
{
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%edi\n\t"
            "syscall\n\t"
            :
            : "i" (231), // x86-64 SYS_exit_group
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
        : "i" (4), // i386 SYS_write
          "g" (fd),
          "g" (buf),
          "g" (length)
        : "%eax", "%ebx", "%ecx", "%edx");

    return ret;
}
_Noreturn void exit_group(int code)
{
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%ebx\n\t"
            "int $0x80\n\t"
            :
            : "i" (252), // i386 SYS_exit_group
              "r" (code)
            : "%eax", "%ebx");
    }
}
#elif defined(__aarch64__)
int write(int fd, const char *buf, int length)
{
    register long x8 asm("x8") = 64; // AArch64 SYS_write
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = length;

    asm volatile("svc #0"
        : "+r" (x0)
        : "r" (x8), "r" (x1), "r" (x2)
        : "memory");

    return (int)x0;
}

_Noreturn void exit_group(int code)
{
    for (;;) {
        register long x8 asm("x8") = 94; // AArch64 SYS_exit_group
        register long x0 asm("x0") = code;

        asm volatile("svc #0"
            :
            : "r" (x8), "r" (x0)
            : "memory");
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

#[test]
fn test_syscall_rewriter() {
    let dir_path = env!("CARGO_TARGET_TMPDIR").to_string();
    let src_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.c");
    std::fs::write(src_path.clone(), HELLO_WORLD_NOLIBC).unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc");
    common::compile(
        src_path.to_str().unwrap(),
        path.to_str().unwrap(),
        true,
        true,
    );

    // rewrite the hello_exec_nolibc
    let hooked_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.hooked");
    let _ = std::fs::remove_file(hooked_path.clone());
    let rewrite_success = common::rewrite_with_cache(&path, &hooked_path, &[]);
    assert!(rewrite_success, "failed to run syscall rewriter");

    Runner::new_pre_rewritten(&hooked_path, "loader_pre_rewritten")
        .env("PATH=/bin")
        .arg("hello")
        .run();
}

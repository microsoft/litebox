mod common;

#[test]
fn test_load_exec_static() {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_exec");
    common::compile("./tests/hello.c", &path, true, false);

    let executable_path = "/hello_exec";
    let executable_data = std::fs::read(path).unwrap();

    common::init_platform(true);

    common::install_file(executable_data, executable_path);

    common::test_load_exec_common(executable_path);
}

const HELLO_WORLD_NOLIBC: &str = r#"
// gcc tests/test.c -o test -static -nostdlib
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
        : "r" (1), // #define SYS_write 1
          "r" (fd),
          "r" (buf),
          "r" (length)
        : "%rax", "%rdi", "%rsi", "%rdx");

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
            : "r" (231),
              "r" (code)
            : "%rax", "%rdi");
    }
}

int main() {
    // use write to print a string
    write(1, "Hello, World!\n", 14);
    return 0;
}

void _start() {
    exit_group(main());
}"#;

#[test]
fn test_syscall_rewriter() {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let src_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.c");
    std::fs::write(src_path.clone(), HELLO_WORLD_NOLIBC).unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc");
    common::compile(src_path.to_str().unwrap(), &path, true, true);

    // rewrite the hello_exec_nolibc
    let hooked_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.hooked");
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

    common::init_platform(false);
    common::install_file(executable_data, executable_path);
    common::test_load_exec_common(executable_path);
}

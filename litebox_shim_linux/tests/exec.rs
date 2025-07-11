mod common;

#[test]
fn test_load_exec_static() {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_exec");
    common::compile("./tests/hello.c", path.to_str().unwrap(), true, false);

    let executable_path = "/hello_exec";
    let executable_data = std::fs::read(path).unwrap();

    common::init_platform(&[], &[], &[], None, true);

    common::install_file(executable_data, executable_path);

    common::test_load_exec_common(executable_path);
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

#[test]
fn test_syscall_rewriter() {
    let (path, hooked_path) = {
        #[cfg(target_os = "freebsd")]
        {
            // Use the already compiled executable from the tests folder (same dir as this file)
            let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            test_dir.push("tests");
            let path = test_dir.join("hello_exec_nolibc");
            let hooked_path = test_dir.join("hello_exec_nolibc.hooked");
            (path, hooked_path)
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            let dir_path = std::env::var("OUT_DIR").unwrap();
            let src_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.c");
            std::fs::write(src_path.clone(), HELLO_WORLD_NOLIBC).unwrap();
            let path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc");
            common::compile(
                src_path.to_str().unwrap(),
                path.to_str().unwrap(),
                true,
                true,
            );
            let hooked_path =
                std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.hooked");
            (path, hooked_path)
        }
    };

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

    common::init_platform(&[], &[], &[], None, false);
    common::install_file(executable_data, executable_path);
    common::test_load_exec_common(executable_path);
}

#[test]
#[cfg(all(target_arch = "x86_64", target_os = "freebsd"))]
fn test_syscall_rewriter_curdir() {
    // Use the already compiled executable from the tests folder (same dir as this file)
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests");
    let path = test_dir.join("hello_exec_nolibc");

    // print path
    println!("Using hello_exec_nolibc from: {}", path.display());
    // Verify the executable exists
    assert!(
        path.exists(),
        "hello_exec_nolibc executable not found in tests directory"
    );

    // rewrite the hello_exec_nolibc
    let hooked_path = test_dir.join("hello_exec_nolibc.hooked");
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

    common::init_platform(&[], &[], &[], None, false);
    common::install_file(executable_data, executable_path);
    common::test_load_exec_common(executable_path);
}

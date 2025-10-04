mod cache;
mod common;

use std::ffi::CString;

use litebox::{
    fs::{FileSystem as _, Mode, OFlags},
    platform::SystemInfoProvider as _,
};
use litebox_platform_multiplex::{Platform, set_platform};
use litebox_shim_linux::{litebox_fs, loader::load_program, set_fs};

fn init_platform(
    tar_data: &'static [u8],
    initial_dirs: &[&str],
    initial_files: &[&str],
    tun_device_name: Option<&str>,
    enable_syscall_interception: bool,
) {
    let platform = Platform::new(tun_device_name);
    set_platform(platform);
    let platform = litebox_platform_multiplex::platform();
    let litebox = litebox_shim_linux::litebox();

    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
    in_mem_fs.with_root_privileges(|fs| {
        fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to set permissions on root");
    });
    let tar_ro_fs = litebox::fs::tar_ro::FileSystem::new(
        litebox,
        if tar_data.is_empty() {
            litebox::fs::tar_ro::EMPTY_TAR_FILE.into()
        } else {
            tar_data.into()
        },
    );
    set_fs(litebox_shim_linux::default_fs(in_mem_fs, tar_ro_fs));

    for each in initial_dirs {
        install_dir(each);
    }
    for each in initial_files {
        let data = std::fs::read(each).unwrap();
        install_file(data, each);
    }

    platform.register_syscall_handler(litebox_shim_linux::handle_syscall_request);

    if enable_syscall_interception {
        platform.enable_seccomp_based_syscall_interception();
    }
}

fn install_dir(path: &str) {
    litebox_fs()
        .mkdir(path, Mode::RWXU | Mode::RWXG | Mode::RWXO)
        .expect("Failed to create directory");
}

fn install_file(contents: Vec<u8>, out: &str) {
    let fd = litebox_fs()
        .open(
            out,
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXG | Mode::RWXO | Mode::RWXU,
        )
        .unwrap();
    litebox_fs().write(&fd, &contents, None).unwrap();
    litebox_fs().close(fd).unwrap();
}

fn test_load_exec_common(executable_path: &str) {
    let argv = vec![
        CString::new(executable_path).unwrap(),
        CString::new("hello").unwrap(),
    ];
    let envp = vec![
        CString::new("PATH=/bin").unwrap(),
        CString::new("HOME=/").unwrap(),
    ];
    let mut aux = litebox_shim_linux::loader::auxv::init_auxv();
    if litebox_platform_multiplex::platform()
        .get_vdso_address()
        .is_none()
    {
        // Due to restrict permissions in CI, we cannot read `/proc/self/maps`.
        // To pass CI, we rely on `getauxval` (which we should avoid #142) to get the VDSO
        // address when failing to read `/proc/self/maps`.
        #[cfg(target_arch = "x86_64")]
        {
            let vdso_address = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) };
            aux.insert(
                litebox_shim_linux::loader::auxv::AuxKey::AT_SYSINFO_EHDR,
                usize::try_from(vdso_address).unwrap(),
            );
        }
        #[cfg(target_arch = "x86")]
        {
            // AT_SYSINFO = 32
            let vdso_address = unsafe { libc::getauxval(32) };
            aux.insert(
                litebox_shim_linux::loader::auxv::AuxKey::AT_SYSINFO,
                usize::try_from(vdso_address).unwrap(),
            );
        }
    }
    let info = load_program(executable_path, argv, envp, aux).unwrap();
    #[cfg(target_arch = "x86_64")]
    let pt_regs = litebox_common_linux::PtRegs {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: info.user_stack_top,
        r10: info.entry_point,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: 0,
        rip: 0,
        cs: 0x33, // __USER_CS
        eflags: 0,
        rsp: 0,
        ss: 0x2b, // __USER_DS
    };
    #[cfg(target_arch = "x86")]
    let pt_regs = litebox_common_linux::PtRegs {
        ebx: info.entry_point,
        ecx: info.user_stack_top,
        edx: 0,
        esi: 0,
        edi: 0,
        ebp: 0,
        eax: 0,
        xds: 0,
        xes: 0,
        xfs: 0,
        xgs: 0,
        orig_eax: 0,
        eip: 0,
        xcs: 0x23, // __USER_CS
        eflags: 0,
        esp: 0,
        xss: 0x2b, // __USER_DS
    };
    unsafe { litebox_platform_linux_userland::thread_start_asm(&pt_regs) };
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_load_exec_dynamic() {
    let path = common::compile("./tests/hello.c", "hello_dylib", false, false);

    let files_to_install = common::find_dependencies(path.to_str().unwrap());

    let executable_path = "/hello_dylib";
    let executable_data = std::fs::read(path).unwrap();

    init_platform(
        &[],
        &["lib64", "lib32", "lib", "lib/x86_64-linux-gnu"],
        &files_to_install
            .iter()
            .map(std::string::String::as_str)
            .collect::<Vec<_>>(),
        None,
        false,
    );
    install_file(executable_data, executable_path);
    test_load_exec_common(executable_path);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_load_exec_static() {
    let path = common::compile("./tests/hello.c", "hello_exec", true, false);

    let executable_path = "/hello_exec";
    let executable_data = std::fs::read(path).unwrap();

    init_platform(&[], &[], &[], None, false);

    install_file(executable_data, executable_path);

    test_load_exec_common(executable_path);
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

    // rewrite the hello_exec_nolibc
    let hooked_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.hooked");
    let _ = std::fs::remove_file(hooked_path.clone());
    let rewrite_success = common::rewrite_with_cache(
        &path,
        &hooked_path,
        &[
            "--trampoline-addr",
            litebox_shim_linux::loader::REWRITER_MAGIC_NUMBER
                .to_string()
                .as_str(),
        ],
    );
    assert!(rewrite_success, "failed to run syscall rewriter");

    let executable_path = "/hello_exec_nolibc.hooked";
    let executable_data = std::fs::read(hooked_path).unwrap();

    init_platform(&[], &[], &[], None, false);
    install_file(executable_data, executable_path);
    test_load_exec_common(executable_path);
}

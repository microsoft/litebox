#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::{arch::global_asm, ffi::CString};

use litebox::{
    fs::{FileSystem as _, Mode, OFlags},
    platform::SystemInfoProvider as _,
};
use litebox_platform_multiplex::{Platform, set_platform};
use litebox_shim_linux::{litebox_fs, loader::load_program, set_fs};

// According to glibc's ABI (https://github.com/lattera/glibc/blob/master/sysdeps/x86_64/start.S#L79),
// when entering the _start function, %rdx will move to %r9, which is the 6th argument of the function
// __libc_start_main. This argument `rtld_fini` is used to register a cleanup function (`atexit`).
// However, today's Linux kernel by default does not set it. So we will need to clear %rdx before jumping
// to the _start function.
global_asm!(
    "
    .text
    .align	4
    .globl	trampoline
trampoline:
    xor r8, r8
    mov	rsp, rdx
    /* Clear rdx (will move to r9 according to glibc's ABI) */
    xor rdx, rdx
    /* Jump to glibc's _start */
    jmp	rcx
    /* Should not reach. */
    hlt"
);

unsafe extern "C" {
    fn trampoline(entry: usize, sp: usize) -> !;
}

pub fn init_platform(tar_data: &'static [u8], initial_dirs: &[&str], initial_files: &[&str]) {
    let platform = Platform::new();
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
}

pub fn install_dir(path: &str) {
    litebox_fs()
        .mkdir(path, Mode::RWXU | Mode::RWXG | Mode::RWXO)
        .expect("Failed to create directory");
}

pub fn install_file(contents: Vec<u8>, out: &str) {
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

pub fn test_load_exec_common(executable_path: &str) {
    let argv = vec![
        CString::new(executable_path).unwrap(),
        CString::new("hello").unwrap(),
    ];
    let envp = vec![CString::new("PATH=/bin").unwrap()];
    let aux = litebox_shim_linux::loader::auxv::init_auxv();
    if litebox_platform_multiplex::platform()
        .get_vdso_address()
        .is_none()
    {
        // do nothing about aux for now
    }
    let info = load_program(executable_path, argv, envp, aux).unwrap();

    unsafe { trampoline(info.entry_point, info.user_stack_top) };
}

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::{arch::global_asm, ffi::CString};

use litebox::{
    LiteBox,
    fs::{FileSystem as _, Mode, OFlags},
    platform::SystemInfoProvider as _,
};
use litebox_platform_multiplex::{Platform, set_platform};
use litebox_shim_linux::{litebox_fs, loader::load_program, set_fs};

// global_asm!(
//     "
//     .text
//     .align	4
//     .globl	trampoline
// trampoline:
//     xor rdx, rdx
//     mov	rsp, rsi
//     jmp	rdi
//     /* Should not reach. */
//     hlt"
// );

global_asm!(
    "
    .text
    .align	4
    .globl	trampoline
trampoline:
    xor r8, r8
    mov	rsp, rdx
    jmp	rcx
    /* Should not reach. */
    hlt"
);


unsafe extern "C" {
    fn trampoline(entry: usize, sp: usize) -> !;
}

pub fn init_platform(tar_data: &[u8], initial_dirs: &[&str], initial_files: &[&str]) {
    let platform = Platform::new();
    set_platform(platform);
    let platform = litebox_platform_multiplex::platform();
    let litebox = LiteBox::new(platform);

    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(&litebox);
    in_mem_fs.with_root_privileges(|fs| {
        fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to set permissions on root");
    });
    let dev_stdio = litebox::fs::devices::stdio::FileSystem::new(&litebox);
    let tar_ro_fs = litebox::fs::tar_ro::FileSystem::new(
        &litebox,
        if tar_data.is_empty() {
            litebox::fs::tar_ro::empty_tar_file()
        } else {
            tar_data.into()
        },
    );
    set_fs(litebox::fs::layered::FileSystem::new(
        &litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            &litebox,
            dev_stdio,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    ));

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

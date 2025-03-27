use std::{arch::global_asm, ffi::CString};

use litebox::{
    fs::{FileSystem as _, Mode, OFlags},
    platform::trivial_providers::ImpossiblePunchthroughProvider,
};
use litebox_platform_multiplex::{Platform, set_platform};
use litebox_shim_linux::{litebox_fs, loader::load_program, set_fs, syscall_entry};

global_asm!(
    "
    .text
    .align	4
    .globl	trampoline
    .type	trampoline,@function
trampoline:
    xor rdx, rdx
    mov	rsp, rsi
    jmp	rdi
    /* Should not reach. */
    hlt"
);

unsafe extern "C" {
    fn trampoline(entry: usize, sp: usize) -> !;
}

pub fn init_platform() {
    let platform = Platform::new(None, ImpossiblePunchthroughProvider {}, syscall_entry);
    set_platform(platform);

    let mut in_mem_fs =
        litebox::fs::in_mem::FileSystem::new(litebox_platform_multiplex::platform());
    in_mem_fs.with_root_privileges(|fs| {
        fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to set permissions on root");
    });
    set_fs(in_mem_fs);

    install_dir("/lib64");
}

pub fn compile(output: &std::path::Path, exec_or_lib: bool) {
    // Compile the hello.c file to an executable
    let mut args = vec!["-o", output.to_str().unwrap(), "./tests/hello.c"];
    if exec_or_lib {
        args.push("-static");
    }
    let output = std::process::Command::new("gcc")
        .args(args)
        .output()
        .expect("Failed to compile hello.c");
    assert!(
        output.status.success(),
        "failed to compile hello.c {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
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
    let info = load_program(executable_path, argv, envp).unwrap();

    unsafe { trampoline(info.entry_point, info.user_stack_top) };
}

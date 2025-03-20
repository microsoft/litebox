use std::{arch::global_asm, ffi::CString};

use litebox::{
    fs::{FileSystem, Mode, OFlags},
    platform::trivial_providers::ImpossiblePunchthroughProvider,
};
use litebox_platform_multiplex::{Platform, set_platform};
use litebox_shim_linux::{litebox_fs, loader::load_program, set_fs};

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

fn compile(output: &std::path::Path, exec_or_lib: bool) {
    // Compile the hello.c file to an executable
    let mut args = vec![
        "-o",
        output.to_str().unwrap(),
        "litebox_shim_linux/tests/hello.c",
    ];
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

fn init_platform() {
    let platform = unsafe { Platform::new_for_test(ImpossiblePunchthroughProvider {}) };
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

fn main() {
    // let dir = std::env::var("OUT_DIR").unwrap();
    let dir = "./target/debug".to_string();
    let path = std::path::Path::new(dir.as_str()).join("hello_exec");
    compile(&path, true);

    let executable_path = "/hello_exec";
    let contents = std::fs::read(path).unwrap();

    init_platform();

    install_file(contents, executable_path);

    let argv = vec![
        CString::new(executable_path).unwrap(),
        CString::new("hello").unwrap(),
    ];
    let envp = vec![CString::new("PATH=/bin").unwrap()];
    let info = load_program(executable_path, argv, envp).unwrap();

    unsafe { trampoline(info.entry_point, info.user_stack_top) };
}

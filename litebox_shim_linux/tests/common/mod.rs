use core::arch::global_asm;

use alloc::{ffi::CString, vec};
use litebox::{
    fs::{FileSystem as _, Mode, OFlags},
    platform::trivial_providers::ImpossiblePunchthroughProvider,
};
use litebox_platform_multiplex::{Platform, set_platform};

use litebox_shim_linux::{litebox_fs, set_fs};

use litebox_shim_linux::loader::elf::ElfLoader;

extern crate alloc;
extern crate std;

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

pub fn init_platform() {
    static ONCE: spin::Once = spin::Once::new();
    ONCE.call_once(|| {
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
    });
}

pub fn compile(path: &std::path::Path, exec_or_lib: bool) {
    // Compile the hello.c file to an executable
    let mut args = vec!["-o", path.to_str().unwrap(), "./tests/hello.c"];
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
        output.stderr
    );
}

pub fn install_dir(path: &str) {
    litebox_fs()
        .mkdir(path, Mode::RWXU | Mode::RWXG | Mode::RWXO)
        .expect("Failed to create directory");
}

pub fn install_file(path: &std::path::PathBuf, out: &str) {
    let fd = litebox_fs()
        .open(
            out,
            OFlags::CREAT | OFlags::WRONLY,
            Mode::RWXG | Mode::RWXO | Mode::RWXU,
        )
        .unwrap();
    let contents = std::fs::read(path).unwrap();
    litebox_fs().write(&fd, &contents, None).unwrap();
    litebox_fs().close(fd).unwrap();
}

pub fn test_load_exec_common(executable_path: &str) {
    let argv = vec![
        CString::new(executable_path).unwrap(),
        CString::new("hello").unwrap(),
    ];
    let envp = vec![CString::new("PATH=/bin").unwrap()];
    let info = ElfLoader::load(executable_path, argv, envp).unwrap();

    unsafe { trampoline(info.entry_point, info.user_stack_top) };
}

unsafe extern "C" {
    fn trampoline(entry: usize, sp: usize) -> !;
}

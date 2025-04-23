use std::{arch::global_asm, ffi::CString};

use litebox::{
    LiteBox,
    fs::{FileSystem as _, Mode, OFlags},
    platform::trivial_providers::ImpossiblePunchthroughProvider,
};
use litebox_platform_multiplex::{Platform, set_platform};
use litebox_shim_linux::{litebox_fs, loader::load_program, set_fs};

#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86")]
global_asm!(
    "
    .text
    .align  4
    .globl  trampoline
    .type   trampoline,@function
trampoline:
    xor     edx, edx
    mov     ebx, [esp + 4]
    mov     eax, [esp + 8]
    mov     esp, eax
    jmp     ebx
    /* Should not reach. */
    hlt"
);

unsafe extern "C" {
    fn trampoline(entry: usize, sp: usize) -> !;
}

pub fn init_platform() {
    let platform = Platform::new(None, ImpossiblePunchthroughProvider {});
    set_platform(platform);
    let platform = litebox_platform_multiplex::platform();
    let litebox = LiteBox::new(platform);

    let mut in_mem_fs = litebox::fs::in_mem::FileSystem::new(&litebox);
    in_mem_fs.with_root_privileges(|fs| {
        fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to set permissions on root");
    });
    let dev_stdio = litebox::fs::devices::stdio::FileSystem::new(&litebox);
    let tar_ro_fs =
        litebox::fs::tar_ro::FileSystem::new(&litebox, litebox::fs::tar_ro::empty_tar_file());
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
    platform.enable_syscall_interception_with(litebox_shim_linux::syscall_entry);

    install_dir("/lib64");
    install_dir("/lib32");
    install_dir("/lib");
    install_dir("/lib/x86_64-linux-gnu");
}

pub fn compile(output: &std::path::Path, exec_or_lib: bool) {
    // Compile the hello.c file to an executable
    let mut args = vec!["-o", output.to_str().unwrap(), "./tests/hello.c"];
    if exec_or_lib {
        args.push("-static");
    }
    args.push(match std::env::consts::ARCH {
        "x86_64" => "-m64",
        "x86" => "-m32",
        _ => unimplemented!(),
    });
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

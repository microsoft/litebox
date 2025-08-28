use std::{arch::global_asm, ffi::CString};

use litebox::{
    LiteBox,
    fs::{FileSystem as _, Mode, OFlags},
    platform::SystemInfoProvider as _,
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

pub fn init_platform(
    tar_data: &'static [u8],
    initial_dirs: &[&str],
    initial_files: &[&str],
    tun_device_name: Option<&str>,
    enable_syscall_interception: bool,
) {
    let platform = Platform::new(tun_device_name);
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
            litebox::fs::tar_ro::empty_tar_file().into()
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

    if enable_syscall_interception {
        platform.enable_seccomp_based_syscall_interception();
    }
}

/// Compile C code into an executable
pub fn compile(input: &str, output: &str, exec_or_lib: bool, nolibc: bool) {
    let mut args = vec!["-o", output, input];
    if exec_or_lib {
        args.push("-static");
    }
    if nolibc {
        args.push("-nostdlib");
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

    unsafe { trampoline(info.entry_point, info.user_stack_top) };
}

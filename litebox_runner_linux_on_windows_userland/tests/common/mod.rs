#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::ffi::CString;

use litebox::fs::{FileSystem as _, Mode, OFlags};
use litebox_platform_multiplex::{Platform, set_platform};
use litebox_shim_linux::{litebox_fs, load_program, set_fs};

pub fn init_platform(tar_data: &'static [u8], initial_dirs: &[&str], initial_files: &[&str]) {
    let platform = Platform::new();
    set_platform(platform);
    let platform = litebox_platform_multiplex::platform();
    let litebox = litebox_shim_linux::init_process(platform.init_task());

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

    platform.register_shim(&litebox_shim_linux::LinuxShim);
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
    litebox_fs().close(&fd).unwrap();
}

pub fn test_load_exec_common(executable_path: &str) {
    let argv = vec![
        CString::new(executable_path).unwrap(),
        CString::new("hello").unwrap(),
    ];
    let envp = vec![CString::new("PATH=/bin").unwrap()];
    let mut pt_regs = load_program(executable_path, argv, envp).unwrap();
    unsafe { litebox_platform_windows_userland::run_thread(&mut pt_regs) };
}

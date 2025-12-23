// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::ffi::CString;

use litebox::fs::{FileSystem as _, Mode, OFlags};
use litebox_platform_multiplex::Platform;

pub struct TestLauncher {
    platform: &'static Platform,
    shim_builder: litebox_shim_linux::LinuxShimBuilder,
    fs: litebox_shim_linux::DefaultFS,
}

impl TestLauncher {
    pub fn init_platform(
        tar_data: &'static [u8],
        initial_dirs: &[&str],
        initial_files: &[&str],
    ) -> Self {
        let platform = Platform::new();
        litebox_platform_multiplex::set_platform(platform);
        let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
        let litebox = shim_builder.litebox();

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
        let fs = shim_builder.default_fs(in_mem_fs, tar_ro_fs);
        let mut this = Self {
            platform,
            shim_builder,
            fs,
        };

        for each in initial_dirs {
            this.install_dir(each);
        }
        for each in initial_files {
            let data = std::fs::read(each).unwrap();
            this.install_file(data, each);
        }

        this
    }

    pub fn install_dir(&mut self, path: &str) {
        self.fs
            .mkdir(path, Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");
    }

    pub fn install_file(&mut self, contents: Vec<u8>, out: &str) {
        let fd = self
            .fs
            .open(
                out,
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXG | Mode::RWXO | Mode::RWXU,
            )
            .unwrap();
        self.fs.write(&fd, &contents, None).unwrap();
        self.fs.close(&fd).unwrap();
    }

    pub fn test_load_exec_common(mut self, executable_path: &str) {
        self.shim_builder.set_fs(self.fs);
        let argv = vec![
            CString::new(executable_path).unwrap(),
            CString::new("hello").unwrap(),
        ];
        let envp = vec![CString::new("PATH=/bin").unwrap()];
        let shim = self.shim_builder.build();
        let program = shim
            .load_program(self.platform.init_task(), executable_path, argv, envp)
            .unwrap();
        unsafe {
            litebox_platform_windows_userland::run_thread(
                program.entrypoints,
                &mut litebox_common_linux::PtRegs::default(),
            );
        }
        assert_eq!(program.process.wait(), 0);
    }
}

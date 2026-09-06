// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::ffi::CString;

use litebox::fs::{Mode, OFlags};
use litebox_broker_core::fs::{
    Mode as BackendMode, UserInfo as BackendUserInfo, composer::Composer, devices::Devices,
    in_mem::InMem, in_mem::InitialNode, overlay::Overlay, tar_ro::TarRo,
};
use litebox_platform_windows_userland::WindowsUserland as Platform;

pub struct TestLauncher {
    platform: &'static Platform,
    shim_builder: litebox_shim_linux::LinuxShimBuilder<Platform>,
    fs: litebox_shim_linux::DefaultFS<Platform>,
    context: litebox::fs::resolver::Context,
}

impl TestLauncher {
    pub fn init_platform(
        tar_data: &'static [u8],
        initial_dirs: &[&str],
        initial_files: &[&str],
    ) -> Self {
        let platform = Platform::new();
        let in_mem = InMem::<Platform>::new_initialized([(
            "/",
            InitialNode::Directory {
                mode: BackendMode::RWXU | BackendMode::RWXG | BackendMode::RWXO,
                owner: BackendUserInfo::ROOT,
            },
        )]);
        let tar_data = if tar_data.is_empty() {
            litebox_broker_core::fs::tar_ro::EMPTY_TAR_FILE.into()
        } else {
            tar_data.into()
        };
        let backend = Composer::builder()
            .mount_nestable("/", |allocators| {
                Overlay::<Platform>::new(
                    in_mem,
                    TarRo::new(tar_data, allocators.next()),
                    allocators.next(),
                )
            })
            .mount("/dev", Devices::new)
            .build()
            .unwrap();
        let broker_local =
            litebox_broker_test_support::connect_with_filesystem::<Platform, _>(backend);
        let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
        let shim_builder =
            litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox);
        let fs = shim_builder.brokered_fs();
        let mut this = Self {
            platform,
            shim_builder,
            fs,
            context: litebox::fs::resolver::Context::new(),
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
            .mkdir(&self.context, path, Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");
    }

    pub fn install_file(&mut self, contents: Vec<u8>, out: &str) {
        let fd = self
            .fs
            .open(
                &self.context,
                out,
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXG | Mode::RWXO | Mode::RWXU,
            )
            .unwrap();
        let mut written = 0;
        while written < contents.len() {
            let count = self.fs.write(&fd, &contents[written..], None).unwrap();
            assert!(count > 0, "filesystem write made no progress");
            written += count;
        }
        self.fs.close(&fd).unwrap();
    }

    pub fn test_load_exec_common(self, executable_path: &str) {
        let fs = std::sync::Arc::new(self.fs);
        let argv = vec![
            CString::new(executable_path).unwrap(),
            CString::new("hello").unwrap(),
        ];
        let envp = vec![CString::new("PATH=/bin").unwrap()];
        let shim = self.shim_builder.build();
        let program = shim
            .load_program(fs, self.platform.init_task(), executable_path, argv, envp)
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

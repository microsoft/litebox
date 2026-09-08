// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::ffi::CString;

use litebox::fs::{Mode, OFlags};
use litebox_platform_windows_userland::WindowsUserland as Platform;

mod broker;

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
        let core_mode = litebox_broker_core::fs::Mode::RWXU
            | litebox_broker_core::fs::Mode::RWXG
            | litebox_broker_core::fs::Mode::RWXO;
        let mut entries = vec![(
            "/".to_string(),
            litebox_broker_core::fs::in_mem::InitialNode::Directory {
                mode: core_mode,
                owner: litebox_broker_core::fs::UserInfo::ROOT,
            },
        )];
        entries.extend(initial_dirs.iter().map(|path| {
            (
                (*path).to_string(),
                litebox_broker_core::fs::in_mem::InitialNode::Directory {
                    mode: core_mode,
                    owner: litebox_broker_core::fs::UserInfo::ROOT,
                },
            )
        }));
        entries.extend(initial_files.iter().map(|path| {
            (
                (*path).to_string(),
                litebox_broker_core::fs::in_mem::InitialNode::File {
                    mode: core_mode,
                    owner: litebox_broker_core::fs::UserInfo::ROOT,
                    data: std::fs::read(path).unwrap().into(),
                },
            )
        }));
        let in_mem = litebox_broker_core::fs::in_mem::InMem::<Platform>::new_initialized(entries);
        let tar_data = if tar_data.is_empty() {
            litebox_broker_core::fs::tar_ro::EMPTY_TAR_FILE.into()
        } else {
            tar_data.into()
        };
        let backend = litebox_broker_core::fs::composer::Composer::builder()
            .mount_nestable("/", |allocators| {
                litebox_broker_core::fs::overlay::Overlay::<Platform>::new(
                    in_mem,
                    litebox_broker_core::fs::tar_ro::TarRo::new(tar_data, allocators.next()),
                    allocators.next(),
                )
            })
            .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
            .build()
            .unwrap();
        let litebox = broker::litebox(platform, backend);
        let shim_builder =
            litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox);
        let fs = shim_builder.brokered_fs();
        Self {
            platform,
            shim_builder,
            fs,
            context: litebox::fs::resolver::Context::new(),
        }
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
        self.fs.write(&fd, &contents, None).unwrap();
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

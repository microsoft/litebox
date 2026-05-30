// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::AtomicI32;
use litebox::LiteBox;
use litebox::fd::RawDescriptorStorage;

use crate::{DefaultFS, GlobalState, Process, Task, WindowsHandleStore, WindowsPageManager};

#[cfg(target_os = "linux")]
pub(crate) type TestPlatform = litebox_platform_linux_userland::LinuxUserland;
#[cfg(target_os = "windows")]
pub(crate) type TestPlatform = litebox_platform_windows_userland::WindowsUserland;
pub(crate) type TestFS = DefaultFS<TestPlatform>;

pub(crate) fn test_platform() -> &'static TestPlatform {
    static PLATFORM: std::sync::OnceLock<&'static TestPlatform> = std::sync::OnceLock::new();
    PLATFORM.get_or_init(|| {
        #[cfg(target_os = "linux")]
        let platform = TestPlatform::new(None);

        #[cfg(target_os = "windows")]
        let platform = TestPlatform::new();

        platform
    })
}

pub(crate) fn test_task() -> Task<TestPlatform, TestFS> {
    let platform = test_platform();
    let litebox = LiteBox::new(platform);
    let page_manager = WindowsPageManager::<TestPlatform>::new(&litebox);
    Task {
        global: Arc::new(GlobalState {
            platform,
            registry: crate::syscalls::registry::RegistryStore::new(&litebox),
            litebox,
            page_manager,
            _fs: PhantomData,
        }),
        process: Arc::new(Process {
            ntdll_mapping: None,
            handles: WindowsHandleStore::<TestPlatform>::new(RawDescriptorStorage::new()),
            exit_code: AtomicI32::new(0),
        }),
        entry_point: 0,
        stack_top: 0,
        _phantom: PhantomData,
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::AtomicI32;
use litebox::LiteBox;
use litebox::fd::RawDescriptorStorage;

use crate::{DefaultFS, GlobalState, Process, Task, WindowsHandleStore, WindowsPageManager};

pub(crate) fn init_platform() {
    static PLATFORM_INIT: std::sync::Once = std::sync::Once::new();
    PLATFORM_INIT.call_once(|| {
        #[cfg(target_os = "linux")]
        let platform = crate::Platform::new(None);

        #[cfg(not(target_os = "linux"))]
        let platform = crate::Platform::new();

        litebox_platform_multiplex::set_platform(platform);
    });
}

pub(crate) fn test_task() -> Task<DefaultFS> {
    init_platform();
    let platform = litebox_platform_multiplex::platform();
    let litebox = LiteBox::new(platform);
    let page_manager = WindowsPageManager::new(&litebox);
    Task {
        global: Arc::new(GlobalState {
            registry: crate::syscalls::registry::RegistryStore::new(&litebox),
            litebox,
            page_manager,
            _fs: PhantomData,
        }),
        process: Arc::new(Process {
            ntdll_mapping: None,
            handles: WindowsHandleStore::new(RawDescriptorStorage::new()),
            exit_code: AtomicI32::new(0),
        }),
        entry_point: 0,
        stack_top: 0,
        _phantom: PhantomData,
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::mem::ManuallyDrop;

extern crate alloc;

use litebox::LiteBox;

use crate::context::{ExecutionContext, GuestApi};
use crate::kernel::HarnessKernel;
use crate::platform::{HarnessPlatform, spawn_guest_thread};
use crate::process_memory::ProcessMemory;
use crate::shim::HarnessInitThread;

pub struct HarnessRunner {
    platform: ManuallyDrop<Arc<HarnessPlatform>>,

    litebox: ManuallyDrop<LiteBox<HarnessPlatform>>,

    kernel: ManuallyDrop<Arc<HarnessKernel>>,
    process_memory: ManuallyDrop<Arc<ProcessMemory>>,
}

impl HarnessRunner {
    pub fn new() -> Self {
        Self::with_process_memory(Vec::new())
    }

    pub fn with_process_memory(backing: Vec<u8>) -> Self {
        let platform = HarnessPlatform::new_arc();

        let platform_static: &'static HarnessPlatform = unsafe { &*Arc::as_ptr(&platform) };

        let litebox = LiteBox::new(platform_static);
        let kernel = HarnessKernel::new(&litebox);
        let process_memory = ProcessMemory::new(platform.foreign_memory(), backing);

        Self {
            platform: ManuallyDrop::new(platform),
            litebox: ManuallyDrop::new(litebox),
            kernel: ManuallyDrop::new(kernel),
            process_memory: ManuallyDrop::new(process_memory),
        }
    }

    pub fn platform(&self) -> &HarnessPlatform {
        &self.platform
    }

    pub fn litebox(&self) -> &LiteBox<HarnessPlatform> {
        &self.litebox
    }

    pub fn run<F>(&self, guest: F)
    where
        F: for<'a> FnOnce(&GuestApi<'a>) + Send + 'static,
    {
        let ctx = ExecutionContext::start(guest);
        let init_thread = Box::new(HarnessInitThread {
            platform: Arc::clone(&self.platform),
            kernel: Arc::clone(&self.kernel),
            process_memory: Arc::clone(&self.process_memory),
        });
        spawn_guest_thread(Arc::clone(&self.platform), init_thread, ctx);
        self.platform.join_all_spawned();
    }
}

impl Default for HarnessRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HarnessRunner {
    fn drop(&mut self) {
        self.platform.join_all_spawned();

        unsafe { ManuallyDrop::drop(&mut self.litebox) };

        let kernel = unsafe { ManuallyDrop::take(&mut self.kernel) };
        assert!(
            Arc::into_inner(kernel).is_some(),
            "HarnessRunner shutdown: extra strong references to HarnessKernel survived; \
             a guest thread or GuestApi was leaked past shutdown."
        );

        let process_memory = unsafe { ManuallyDrop::take(&mut self.process_memory) };
        let Some(process_memory) = Arc::into_inner(process_memory) else {
            panic!("HarnessRunner shutdown: extra strong references to ProcessMemory survived");
        };
        drop(process_memory);

        let platform = unsafe { ManuallyDrop::take(&mut self.platform) };

        assert!(
            Arc::into_inner(platform).is_some(),
            "HarnessRunner shutdown: extra strong references to HarnessPlatform survived; \
             something is holding the platform past LiteBox::drop / thread join."
        );
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An end-to-end harness runner, wiring up [`shim`] and [`platform`] into a
//! LiteBox environment that runs entirely within the Rust Abstract Machine and
//! can be used for Miri tests.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::mem::ManuallyDrop;

extern crate alloc;

use litebox::LiteBox;

use crate::context::{ExecutionContext, GuestApi};
use crate::kernel::HarnessKernel;
use crate::platform::{HarnessPlatform, spawn_guest_thread};
use crate::shim::HarnessInitThread;

pub struct HarnessRunner {
    platform: ManuallyDrop<Arc<HarnessPlatform>>,

    litebox: ManuallyDrop<LiteBox<HarnessPlatform>>,

    kernel: ManuallyDrop<Arc<HarnessKernel>>,
}

impl HarnessRunner {
    pub fn new() -> Self {
        let platform = HarnessPlatform::new_arc();

        let platform_static: &'static HarnessPlatform = unsafe { &*Arc::as_ptr(&platform) };

        let litebox = LiteBox::new(platform_static);
        let kernel = HarnessKernel::new(&litebox);

        Self {
            platform: ManuallyDrop::new(platform),
            litebox: ManuallyDrop::new(litebox),
            kernel: ManuallyDrop::new(kernel),
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

        let platform = unsafe { ManuallyDrop::take(&mut self.platform) };

        assert!(
            Arc::into_inner(platform).is_some(),
            "HarnessRunner shutdown: extra strong references to HarnessPlatform survived; \
             something is holding the platform past LiteBox::drop / thread join."
        );
    }
}

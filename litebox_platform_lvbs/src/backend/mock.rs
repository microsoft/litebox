// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Software-only backend for page-table tests. No VM lifecycle or peer operations.

use crate::backend::KernelBackend;

mod clock;

pub struct MockBackend {}
pub type MockKernel = crate::LinuxKernel<MockBackend>;
pub struct MockMemory;
pub struct MockTlb;

// SAFETY: software-only tables are never installed in CR3.
unsafe impl crate::mm::tlb::TlbInvalidation for MockTlb {
    fn invalidate(
        _start: x86_64::structures::paging::Page<x86_64::structures::paging::Size4KiB>,
        _page_count: usize,
    ) {
    }
}
impl crate::console::DiagnosticOutput for MockBackend {
    fn print(args: core::fmt::Arguments<'_>) {
        Self::log(&alloc::format!("{args}"));
    }
}
impl KernelBackend for MockBackend {
    type Memory = MockMemory;
    type Timer = Self;
    fn execution_timer(&self) -> &Self {
        self
    }
}
impl litebox::platform::RawMutexProvider for MockBackend {
    type RawMutex = super::no_scheduler::NoSchedulerMutex;
}
impl crate::execution::ExecutionTimer for MockBackend {
    fn arm(&self) {
        panic!("software-only backend cannot enter user mode");
    }
    fn on_user_exception(&self, _exception: litebox::shim::Exception) {
        panic!("software-only backend cannot receive interrupts");
    }
}

impl MockBackend {
    // The old ignored memory tests still lack a boot-memory harness. These
    // fixture helpers are not part of the production KernelBackend contract.
    pub fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        todo!()
    }
    /// # Safety
    /// The address must have been allocated by this fixture's allocation hook.
    pub unsafe fn free(_addr: usize) {
        todo!()
    }
    pub fn log(msg: &str) {
        unsafe {
            libc::write(libc::STDOUT_FILENO, msg.as_ptr().cast(), msg.len());
        }
    }
}

#[macro_export]
macro_rules! mock_log_println {
    ($($tt:tt)*) => {{
        use core::fmt::Write;
        let mut t: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        writeln!(t, $($tt)*).unwrap();
        $crate::backend::mock::MockBackend::log(&t);
    }};
}

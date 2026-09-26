// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Software-only host for page-table tests. No VM lifecycle or peer operations.

use crate::host::Host;

mod clock;

pub struct MockHost {}
pub type MockKernel = crate::LinuxKernel<MockHost>;
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
impl crate::console::DiagnosticOutput for MockHost {
    fn print(args: core::fmt::Arguments<'_>) {
        Self::log(&alloc::format!("{args}"));
    }
}
impl Host for MockHost {
    type Memory = MockMemory;
    type Timer = Self;
    fn execution_timer(&self) -> &Self {
        self
    }
}
impl litebox::platform::RawMutexProvider for MockHost {
    type RawMutex = super::no_scheduler::NoSchedulerMutex;
}
impl crate::execution::ExecutionTimer for MockHost {
    fn arm(&self) {
        panic!("software-only host cannot enter user mode");
    }
    fn on_user_exception(&self, _exception: litebox::shim::Exception) {
        panic!("software-only host cannot receive interrupts");
    }
}

impl MockHost {
    // The old ignored memory tests still lack a boot-memory harness. These
    // fixture helpers are not part of the production Host contract.
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
        $crate::host::mock::MockHost::log(&t);
    }};
}

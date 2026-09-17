// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions as Permissions};
use litebox::platform::{
    PageManagementProvider as _, RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _,
    ThreadProvider as _,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo, InitThread};
use litebox_common_linux::PtRegs;
use litebox_platform_macos_userland::{
    GuestAbi, HOST_PAGE_SIZE, MacosUserland, run_thread, set_guest_abi,
};
use litebox_syscall_rewriter::{TargetHost, macho::Rewriter};
use std::cell::Cell;
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;

#[test]
#[expect(clippy::single_range_in_vec_init, reason = "one executable code range")]
fn spawned_threads_use_configured_darwin_gates() {
    struct Child {
        entry: usize,
        stack: usize,
        calls: Cell<usize>,
        completed: Sender<usize>,
    }
    impl InitThread for Child {
        type ExecutionContext = PtRegs;
        fn init(self: Box<Self>) -> Box<dyn EnterShim<ExecutionContext = PtRegs>> {
            self
        }
    }
    impl EnterShim for Child {
        type ExecutionContext = PtRegs;
        fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
            ctx.pc = self.entry;
            ctx.sp = self.stack;
            ctx.regs[0] = 77;
            ctx.regs[16] = 20;
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let calls = self.calls.get();
            assert_eq!(ctx.sp, self.stack);
            assert_eq!(ctx.pc, self.entry + (calls + 1) * 4);
            assert_eq!(ctx.regs[16], 20);
            assert_eq!(ctx.regs[0], if calls == 0 { 77 } else { 42 });
            ctx.regs[0] = 42;
            self.calls.set(calls + 1);
            if calls == 0 {
                ContinueOperation::Resume
            } else {
                ContinueOperation::Terminate
            }
        }
        fn exception(&self, _: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
            panic!("unexpected guest exception: {info:?}");
        }
        fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
    }
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.completed.send(self.calls.get());
        }
    }
    struct Parent {
        platform: &'static MacosUserland,
        child: std::cell::RefCell<Option<Child>>,
    }
    impl EnterShim for Parent {
        type ExecutionContext = PtRegs;
        fn init(&self, _: &mut PtRegs) -> ContinueOperation {
            let child = self.child.borrow_mut().take().unwrap();
            // SAFETY: Child::init installs the mapped entry and stack. The
            // test retains those mappings until the child has stopped.
            unsafe {
                self.platform
                    .spawn_thread(&PtRegs::default(), Box::new(child))
                    .unwrap();
            }
            ContinueOperation::Terminate
        }
        fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
            unreachable!()
        }
        fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
            unreachable!()
        }
        fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
            unreachable!()
        }
    }

    set_guest_abi(GuestAbi::Darwin);
    set_guest_abi(GuestAbi::Darwin);
    // Rejected reconfiguration must leave the selected convention unchanged.
    // Executing the child's Darwin gates below verifies that it is retained.
    assert!(std::panic::catch_unwind(|| set_guest_abi(GuestAbi::Linux)).is_err());
    let platform = MacosUserland::new();
    let memory = platform
        .allocate_pages(
            MacosUserland::TASK_ADDR_MIN..MacosUserland::TASK_ADDR_MIN + 3 * HOST_PAGE_SIZE,
            Permissions::READ | Permissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap();
    let base = memory.as_usize();
    let mut code = [0xd4001001u32.to_le_bytes(); 2].concat();
    let gate_offset = HOST_PAGE_SIZE / 2;
    let (gates, trapped) = Rewriter::new(TargetHost::MacOs)
        .unwrap()
        .patch_code_segment(
            &mut code,
            base as u64,
            &[0..8],
            (base + gate_offset) as u64,
            platform.get_syscall_entry_point() as u64,
            platform
                .guest_thread_pointer_offset()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
    assert!(trapped.is_empty());
    memory.copy_from_slice(0, &code).unwrap();
    memory.copy_from_slice(gate_offset, &gates).unwrap();
    // SAFETY: code and gates are initialized and have no active users.
    unsafe {
        platform
            .update_permissions(
                base..base + HOST_PAGE_SIZE,
                Permissions::READ | Permissions::EXEC,
            )
            .unwrap();
    }
    let (completed, receive) = channel();
    let parent = Parent {
        platform,
        child: Some(Child {
            entry: base,
            stack: base + 3 * HOST_PAGE_SIZE,
            calls: Cell::new(0),
            completed,
        })
        .into(),
    };
    // SAFETY: Parent::init runs host-side and terminates without guest entry.
    unsafe {
        run_thread(parent, &mut PtRegs::default());
    }
    let calls = receive.recv_timeout(Duration::from_secs(5)).unwrap();
    // SAFETY: receipt of Child::drop confirms guest execution has stopped.
    unsafe {
        platform
            .deallocate_pages(base..base + 3 * HOST_PAGE_SIZE)
            .unwrap();
    }
    assert_eq!(calls, 2);
}

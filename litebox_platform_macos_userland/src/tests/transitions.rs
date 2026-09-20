// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_syscall_rewriter::{
    RewriteOptions, TargetHost, macho::Rewriter, patch_code_segment_with_options,
};

// The first page contains code and gates; remaining pages are RW stack storage.
// Darwin gates are host-aware so the native-path test can call them directly.
fn prepare_code(platform: &MacosUserland, words: &[u32], pages: usize, abi: GuestAbi) -> usize {
    assert!(pages > 0);
    let memory = platform
        .allocate_pages(
            TASK_ADDR_MIN..TASK_ADDR_MIN + pages * HOST_PAGE_SIZE,
            RW,
            false,
            true,
            FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
        )
        .unwrap();
    let base = memory.as_usize();
    let mut code: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    assert!(code.len() <= HOST_PAGE_SIZE / 2);
    let gate_address = (base + HOST_PAGE_SIZE / 2) as u64;
    let callback = platform.get_syscall_entry_point() as u64;
    let (gates, trapped) = match abi {
        GuestAbi::Linux => patch_code_segment_with_options(
            &mut code,
            base as u64,
            gate_address,
            callback,
            RewriteOptions::new(TargetHost::MacOs, true),
        ),
        GuestAbi::Darwin => {
            let range = 0..code.len();
            Rewriter::new(TargetHost::MacOs)
                .unwrap()
                .patch_host_shared_cache_code(
                    &mut code,
                    base as u64,
                    core::slice::from_ref(&range),
                    gate_address,
                    callback,
                    u16::try_from(platform.guest_thread_pointer_offset().unwrap()).unwrap(),
                )
        }
    }
    .unwrap();
    assert_eq!(trapped, [] as [u64; 0]);
    assert!(gates.len() <= HOST_PAGE_SIZE / 2);
    assert_eq!(memory.write_slice_at_offset(0, &code), Some(()));
    assert_eq!(
        memory.write_slice_at_offset((HOST_PAGE_SIZE / 2).cast_signed(), &gates),
        Some(())
    );
    // SAFETY: code and gates are initialized and have no users before RX publication.
    unsafe {
        platform.update_permissions(
            base..base + HOST_PAGE_SIZE,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        )
    }
    .unwrap();
    base
}

#[test]
fn signal_return_guard_publishes_pending_native_return() {
    set_guest_abi(GuestAbi::Darwin);
    MacosUserland::new();
    let _cleanup = litebox::utils::defer(|| {
        write_tls(tls_offset::IN_GUEST, 0);
        write_tls(tls_offset::NATIVE_SIGRETURN_PENDING, 0);
    });
    for rewritten in [false, true] {
        if rewritten {
            enable_rewritten_host_sigreturn();
        }
        // Host-only signals never manufacture a guest return.
        drop(SignalReturnGuard::new());
        assert_eq!(read_tls(tls_offset::IN_GUEST), 0);
        assert_eq!(read_tls(tls_offset::NATIVE_SIGRETURN_PENDING), 0);

        write_tls(tls_offset::IN_GUEST, 1);
        let guard = SignalReturnGuard::new();
        assert_eq!(read_tls(tls_offset::IN_GUEST), 0);
        drop(guard);
        assert_eq!(read_tls(tls_offset::IN_GUEST), 1);
        assert_eq!(
            read_tls(tls_offset::NATIVE_SIGRETURN_PENDING),
            usize::from(rewritten)
        );

        write_tls(tls_offset::NATIVE_SIGRETURN_PENDING, 0);
        let mut guard = SignalReturnGuard::new();
        guard.disarm();
        drop(guard);
        assert_eq!(read_tls(tls_offset::IN_GUEST), 0);
        assert_eq!(read_tls(tls_offset::NATIVE_SIGRETURN_PENDING), 0);
    }
}

#[test]
fn native_syscall_gate_preserves_registers_and_carry() {
    // entry must point to a live RX copy of the test stub below.
    unsafe fn check(entry: usize) {
        for (syscall, argument, result, carry) in [
            (20usize, 0, std::process::id() as usize, 0),   // getpid
            (6, usize::MAX, libc::EBADF as usize, 1 << 29), // close(-1)
        ] {
            let mut observed = [0usize; 4];
            // SAFETY: the caller retains the RX stub, and observed is writable
            // for its four outputs. Arguments and clobbers follow the C ABI.
            unsafe {
                core::arch::asm!("blr {entry}", entry = in(reg) entry,
                    in("x0") syscall, in("x1") argument, in("x2") observed.as_mut_ptr(), clobber_abi("C"));
            }
            assert_eq!(&observed[..3], &[result, syscall, 0x1717]);
            assert_eq!(observed[3] & (1 << 29), carry);
        }
    }
    let platform = MacosUserland::new();
    let base = prepare_code(
        platform,
        &[
            0xaa00_03f0, // mov x16, x0
            0xaa01_03e0, // mov x0, x1
            0xd282_e2f1, // mov x17, #0x1717
            0xd400_1001, // svc #0x80
            0xa900_4040, // stp x0, x16, [x2]
            0xd53b_4200, // mrs x0, nzcv
            0xa901_0051, // stp x17, x0, [x2, #16]
            0xd65f_03c0, // ret
        ],
        1,
        GuestAbi::Darwin,
    );
    let _cleanup = litebox::utils::defer(|| {
        // SAFETY: both callers have finished before this test-owned code is released.
        unsafe { platform.release_pages(base..base + HOST_PAGE_SIZE) }.unwrap();
    });
    assert_ne!(tls_block_address(), 0);
    assert_eq!(read_tls(tls_offset::IN_GUEST), 0);
    // SAFETY: the initialized test stub remains RX until both callers finish.
    unsafe { check(base) };
    std::thread::spawn(move || {
        assert_eq!(tls_block_address(), 0);
        // SAFETY: the parent retains the RX stub until this thread is joined.
        unsafe { check(base) };
    })
    .join()
    .unwrap();
}

#[test]
fn child_inherits_vector_state_and_dispatches_on_host_stack() {
    use litebox::shim::InitThread;

    struct Probe {
        vector_state: GuestVectorState,
        passed: Cell<bool>,
        done: std::sync::mpsc::Sender<bool>,
    }
    fn assert_host_stack() {
        // SAFETY: stack_t is zero-valid writable output for this thread's query.
        let mut stack = unsafe { core::mem::zeroed::<libc::stack_t>() };
        // SAFETY: null requests a query; stack remains writable for the call.
        assert_eq!(
            unsafe { libc::sigaltstack(core::ptr::null(), &raw mut stack) },
            0
        );
        assert_eq!(stack.ss_flags & (libc::SS_ONSTACK | libc::SS_DISABLE), 0);
    }
    impl InitThread for Probe {
        type ExecutionContext = PtRegs;
        fn init(self: Box<Self>) -> Box<dyn EnterShim<ExecutionContext = PtRegs>> {
            assert_eq!(get_guest_vector_state(), self.vector_state);
            self
        }
    }
    impl EnterShim for Probe {
        type ExecutionContext = PtRegs;
        fn init(&self, _: &mut PtRegs) -> ContinueOperation {
            assert_host_stack();
            ContinueOperation::Resume
        }
        fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
            assert_host_stack();
            assert_eq!(get_guest_vector_state(), self.vector_state);
            self.passed.set(true);
            ContinueOperation::Terminate
        }
        fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
            panic!("unexpected guest exception");
        }
        fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
            panic!("unexpected interruption");
        }
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            let _ = self.done.send(self.passed.get());
        }
    }

    set_guest_abi(GuestAbi::Linux);
    let platform = MacosUserland::new();
    let base = prepare_code(platform, &[0xd400_0001], 3, GuestAbi::Linux); // svc #0
    let original = get_guest_vector_state();
    let _restore = litebox::utils::defer(|| set_guest_vector_state(&original));
    let mut vector_state = GuestVectorState::default();
    vector_state.registers[0] = 0x1234;
    vector_state.registers[31] = 0x5678;
    set_guest_vector_state(&vector_state);
    let mut ctx = PtRegs {
        pc: base,
        sp: base + 3 * HOST_PAGE_SIZE,
        ..PtRegs::default()
    };
    ctx.regs[8] = 172; // getpid
    let (done, receive) = std::sync::mpsc::channel();
    // SAFETY: the test retains the child's rewritten code and stack until Probe is dropped.
    unsafe {
        platform
            .spawn_thread(
                &ctx,
                Box::new(Probe {
                    vector_state,
                    passed: Cell::new(false),
                    done,
                }),
            )
            .unwrap();
    }
    assert!(receive.recv_timeout(Duration::from_secs(5)).unwrap());
    // SAFETY: Probe has stopped, so the guest mappings are idle.
    unsafe { platform.release_pages(base..base + 3 * HOST_PAGE_SIZE) }.unwrap();
}

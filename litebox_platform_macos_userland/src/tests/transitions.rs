// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_trampoline::{
    TargetHost,
    aarch64::{
        self, GateLayout, GateMetadata, Insn,
        gate::{self, GateInstance},
    },
};

// The first page contains code and gates; remaining pages are RW stack storage.
// Fixtures declare their SVC sites explicitly, without scanning instructions.
fn prepare_code(
    platform: &MacosUserland,
    words: &[u32],
    svc_offsets: &[usize],
    pages: usize,
) -> MacosUserlandReservation<HOST_PAGE_SIZE> {
    assert!(pages > 0);
    // SAFETY: The fixed test range is aligned, free, and retained by the returned reservation.
    let reservation = unsafe {
        platform.reserve_and_commit_pages(
            core::iter::empty,
            TASK_ADDR_MIN..TASK_ADDR_MIN + pages * HOST_PAGE_SIZE,
            RW,
            AllocationOptions::POPULATE,
            FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
        )
    }
    .unwrap();
    let base = reservation.range().start;
    let memory =
        <MacosUserland as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
            base,
        );
    let mut code: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    assert!(code.len() <= HOST_PAGE_SIZE / 2);
    let gate_address = (base + HOST_PAGE_SIZE / 2) as u64;
    let callback = platform.get_syscall_entry_point() as u64;
    let layout = GateLayout::linux(TargetHost::MacOs);
    let mut gates = Vec::new();
    aarch64::emit_shared_prologue(&mut gates, callback);
    for &offset in svc_offsets {
        let site = (base + offset) as u64;
        let slot_address = gate_address + gates.len() as u64;
        let instance = GateInstance::new(GateMetadata::Svc, site + aarch64::INSN_BYTES_U64);
        gate::build(&instance, layout, slot_address, gate_address)
            .unwrap()
            .append_to(&mut gates);
        let branch = Insn::B(slot_address.cast_signed() - site.cast_signed())
            .encode()
            .unwrap();
        code[offset..offset + aarch64::INSN_BYTES].copy_from_slice(&branch.to_le_bytes());
    }
    assert!(gates.len() <= HOST_PAGE_SIZE / 2);
    assert_eq!(memory.write_slice_at_offset(0, &code), Some(()));
    assert_eq!(
        memory.write_slice_at_offset((HOST_PAGE_SIZE / 2).cast_signed(), &gates),
        Some(())
    );
    // SAFETY: code and gates are initialized and have no users before RX publication.
    unsafe {
        platform.protect_pages(
            core::iter::empty,
            base..base + HOST_PAGE_SIZE,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        )
    }
    .unwrap();
    reservation
}

#[test]
fn signal_return_guard_restores_guest_mode_unless_disarmed() {
    set_guest_abi(GuestAbi::Darwin);
    MacosUserland::new();
    let _cleanup = litebox::utils::defer(|| write_tls(tls_offset::IN_GUEST, 0));
    // Host-only signals never manufacture a guest return.
    drop(SignalReturnGuard::new());
    assert_eq!(read_tls(tls_offset::IN_GUEST), 0);

    write_tls(tls_offset::IN_GUEST, 1);
    let guard = SignalReturnGuard::new();
    assert_eq!(read_tls(tls_offset::IN_GUEST), 0);
    drop(guard);
    assert_eq!(read_tls(tls_offset::IN_GUEST), 1);

    let mut guard = SignalReturnGuard::new();
    guard.disarm();
    drop(guard);
    assert_eq!(read_tls(tls_offset::IN_GUEST), 0);
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
    let reservation = prepare_code(platform, &[0xd400_0001], &[0], 3); // svc #0
    let base = reservation.range().start;
    let original = get_guest_vector_state();
    let _restore = litebox::utils::defer(|| set_guest_vector_state(&original));
    let mut vregs = [0; 32];
    vregs[0] = 0x1234;
    vregs[31] = 0x5678;
    let mut vector_state = GuestVectorState::default();
    vector_state.set_fpsimd(&vregs, 0, 0);
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
    unsafe { platform.release_pages(reservation.into()) }.unwrap();
}

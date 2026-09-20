// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_syscall_rewriter::{
    RewriteOptions, TargetHost, macho::Rewriter, patch_code_segment_with_options,
};

enum CodeKind {
    Linux,
    Darwin,
    SharedDarwin,
}

// The first page contains code and gates; any remaining pages are RW stack
// storage. Callers retain the allocation until all users have stopped.
fn prepare_code(platform: &MacosUserland, words: &[u32], pages: usize, kind: CodeKind) -> usize {
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
    let range = 0..code.len();
    let offset = u16::try_from(platform.guest_thread_pointer_offset().unwrap()).unwrap();
    let rewriter = Rewriter::new(TargetHost::MacOs).unwrap();
    let (gates, trapped) = match kind {
        CodeKind::Linux => patch_code_segment_with_options(
            &mut code,
            base as u64,
            gate_address,
            callback,
            RewriteOptions::new(TargetHost::MacOs, true),
        ),
        CodeKind::Darwin => rewriter.patch_code_segment(
            &mut code,
            base as u64,
            core::slice::from_ref(&range),
            gate_address,
            callback,
            offset,
        ),
        CodeKind::SharedDarwin => rewriter.patch_host_shared_cache_code(
            &mut code,
            base as u64,
            core::slice::from_ref(&range),
            gate_address,
            callback,
            offset,
        ),
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

// Kernel-facing __sigaction includes a trampoline pointer; libc::sigaction does not.
#[repr(C)]
struct KernelSigaction {
    handler: usize,
    trampoline: usize,
    mask: libc::sigset_t,
    flags: i32,
}
const _: () = assert!(size_of::<KernelSigaction>() == 24);

unsafe extern "C" {
    fn __sigaction(
        signal: i32,
        action: *const KernelSigaction,
        previous: *mut libc::sigaction,
    ) -> i32;
}

// XNU's AArch64 sendsig supplies the ucontext validation token in x5. The
// successful path forwards the real frame and token without disabling validation.
unsafe extern "C" fn signal_trampoline<const INVALID_CONTEXT: bool>(
    _handler: usize,
    style: i32,
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
    token: usize,
) -> ! {
    let active = read_tls(tls_offset::ACTIVE) as *const ThreadContext<'_>;
    if active.is_null() {
        fatal_signal(b"test signal without an active guest", 0);
    }
    // SAFETY: ACTIVE belongs to this test's suspended run_thread invocation.
    // Only the first syscall requests generic resume by changing saved x16.
    if unsafe { (*active).ctx.regs[16] } != 0x1616 {
        fatal_signal(b"unexpected signal outside generic resume", 0);
    }
    // SAFETY: these are XNU's live signal arguments. The installed handler is
    // the platform handler, which prepares the return context before returning.
    unsafe {
        exception_signal_handler(signal, info, context);
        // A null ucontext makes XNU return EFAULT before validating the token.
        // The failure test keeps the handler's signal mask, including SIGTRAP.
        let context = if INVALID_CONTEXT {
            core::ptr::null_mut()
        } else {
            context
        };
        sigreturn_through_callback(context, style, token);
    }
}

// Model the rewritten __sigreturn SVC without replacing any live libSystem code.
#[unsafe(naked)]
unsafe extern "C" fn sigreturn_through_callback(_: *mut libc::c_void, _: i32, _: usize) -> ! {
    core::arch::naked_asm!(
        "mov x16, #{sigreturn}",
        "sub sp, sp, #{frame_bytes}",
        "str x16, [sp, #{frame_x16}]",
        "adr x17, 2f",
        "str x17, [sp, #{frame_retaddr}]",
        "str x17, [sp, #{frame_stub}]",
        "b {callback}",
        "2:",
        "brk #1",
        sigreturn = const BSD_SYS_SIGRETURN,
        frame_bytes = const litebox_syscall_rewriter::aarch64::DARWIN_SVC_FRAME_BYTES,
        frame_x16 = const SVC_FRAME_OFF_X16,
        frame_retaddr = const SVC_FRAME_OFF_RETADDR,
        frame_stub = const SVC_FRAME_OFF_STUB,
        callback = sym syscall_callback,
    );
}

#[test]
fn direct_outbound_and_native_sigreturn_restore_guest_state() {
    struct Probe {
        calls: Cell<usize>,
        native_anchor: usize,
    }
    impl EnterShim for &Probe {
        type ExecutionContext = PtRegs;
        fn init(&self, _: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            assert_eq!(
                ctx.regs[16], 20,
                "native sigreturn was routed into the guest shim"
            );
            assert_eq!(ctx.regs[17], 0x1717);
            assert_eq!(ctx.regs[18], 0x1818);
            assert_eq!(anchor(), self.native_anchor);
            assert_eq!(read_tls(tls_offset::NATIVE_SIGRETURN_PENDING), 0);
            let call = self.calls.get();
            self.calls.set(call + 1);
            let mut vector = get_guest_vector_state();
            let expected = if call < 2 {
                (0x1111, 0x3131)
            } else {
                (0x2222, 0x3232)
            };
            assert_eq!((vector.registers[0], vector.registers[31]), expected);
            match call {
                0 => {
                    assert_eq!(ctx.regs[0], 0xabcd);
                    // Changing x16 forces generic resume through native sigreturn.
                    ctx.regs[16] = 0x1616;
                    ContinueOperation::Resume
                }
                1 => {
                    assert_eq!(ctx.regs[0], 0x1616);
                    // Leave PC/SP/x16 unchanged so this resume uses the outbound stub.
                    ctx.regs[0] = 0xbeef;
                    vector.registers[0] = 0x2222;
                    vector.registers[31] = 0x3232;
                    set_guest_vector_state(&vector);
                    ContinueOperation::Resume
                }
                2 => {
                    assert_eq!(ctx.regs[0], 0xbeef);
                    ContinueOperation::Terminate
                }
                _ => panic!("unexpected syscall"),
            }
        }
        fn exception(&self, _: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
            panic!("unexpected guest exception: {info:?}");
        }
        fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
            panic!("unexpected interruption");
        }
    }

    set_guest_abi(GuestAbi::Darwin);
    let platform = MacosUserland::new();
    enable_rewritten_host_sigreturn();
    // SAFETY: sigaction is zero-valid output storage for querying the existing handler.
    let mut original = unsafe { core::mem::zeroed::<libc::sigaction>() };
    // SAFETY: null queries the current action; original remains writable.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGTRAP, core::ptr::null(), &raw mut original) },
        0
    );
    let _restore = litebox::utils::defer(|| {
        // SAFETY: restore the saved action after guest execution has stopped.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTRAP, &raw const original, core::ptr::null_mut()) },
            0
        );
    });
    let action = KernelSigaction {
        handler: exception_signal_handler as *const () as usize,
        trampoline: if std::env::var_os("LITEBOX_TEST_INVALID_SIGRETURN").is_some() {
            signal_trampoline::<true> as *const () as usize
        } else {
            signal_trampoline::<false> as *const () as usize
        },
        mask: original.sa_mask,
        flags: original.sa_flags,
    };
    // SAFETY: this isolated test process runs only this guest; action matches
    // the SDK's kernel-facing structure and both callbacks stay live.
    assert_eq!(
        unsafe { __sigaction(libc::SIGTRAP, &raw const action, core::ptr::null_mut()) },
        0
    );
    let base = prepare_code(
        platform,
        &[
            0xd280_0290, // mov x16, #20
            0xd400_1001, // svc #0x80
            0xaa10_03e0, // mov x0, x16 -- observe the restored value
            0xd280_0290, // mov x16, #20
            0xd400_1001, // svc #0x80
            0xd400_1001, // svc #0x80 -- observe outbound restoration
            0xd420_0000, // brk #0 -- unreachable
        ],
        2,
        CodeKind::Darwin,
    );
    let _release = litebox::utils::defer(|| {
        // SAFETY: this test owns the code and stack; no guest uses them after run_thread.
        unsafe { platform.release_pages(base..base + 2 * HOST_PAGE_SIZE) }.unwrap();
    });
    let original_vector = get_guest_vector_state();
    let _restore_vector = litebox::utils::defer(|| set_guest_vector_state(&original_vector));
    let mut vector = GuestVectorState::default();
    vector.registers[0] = 0x1111;
    vector.registers[31] = 0x3131;
    set_guest_vector_state(&vector);
    let mut ctx = PtRegs {
        pc: base,
        sp: base + 2 * HOST_PAGE_SIZE,
        ..PtRegs::default()
    };
    ctx.regs[0] = 0xabcd;
    ctx.regs[17] = 0x1717;
    ctx.regs[18] = 0x1818;
    let probe = Probe {
        calls: Cell::new(0),
        native_anchor: anchor(),
    };
    // SAFETY: the test retains the rewritten code, stack and signal callbacks until termination.
    unsafe { run_thread(&probe, &mut ctx) };
    assert_eq!(probe.calls.get(), 3);
}

#[test]
fn native_sigreturn_failure_exits_with_sigtrap_blocked() {
    use std::process::{Command, Stdio};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::transitions::direct_outbound_and_native_sigreturn_restore_guest_state",
            "--nocapture",
        ])
        .env("LITEBOX_TEST_INVALID_SIGRETURN", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output().unwrap();
    assert!(!timed_out, "native sigreturn failure hung: {output:?}");
    assert_eq!(
        output.status.code(),
        Some(128 + libc::SIGABRT),
        "{output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fault in macOS syscall transition pc=0x"),
        "{output:?}"
    );
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
        CodeKind::SharedDarwin,
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

    #[derive(Debug, PartialEq)]
    enum Event {
        VectorStateInherited(bool),
        EnteredOnHostStack(bool),
        SyscallOnHostStackWithVectorState(bool),
        Done,
    }
    struct VectorStateProbe {
        entry: usize,
        stack: usize,
        vector_state: GuestVectorState,
        send: std::sync::mpsc::Sender<Event>,
    }
    fn altstack_is_installed_and_inactive() -> bool {
        // SAFETY: stack_t is zero-valid writable output for this thread's query.
        let mut stack = unsafe { core::mem::zeroed::<libc::stack_t>() };
        // SAFETY: null requests a query; stack remains writable for the call.
        let result = unsafe { libc::sigaltstack(core::ptr::null(), &raw mut stack) };
        result == 0 && stack.ss_flags & (libc::SS_ONSTACK | libc::SS_DISABLE) == 0
    }
    impl InitThread for VectorStateProbe {
        type ExecutionContext = PtRegs;
        fn init(self: Box<Self>) -> Box<dyn EnterShim<ExecutionContext = PtRegs>> {
            self.send
                .send(Event::VectorStateInherited(
                    get_guest_vector_state() == self.vector_state,
                ))
                .unwrap();
            self
        }
    }
    impl EnterShim for VectorStateProbe {
        type ExecutionContext = PtRegs;
        fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
            self.send
                .send(Event::EnteredOnHostStack(
                    altstack_is_installed_and_inactive(),
                ))
                .unwrap();
            ctx.pc = self.entry;
            ctx.sp = self.stack;
            ctx.regs[8] = 172; // getpid
            ContinueOperation::Resume
        }
        fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
            self.send
                .send(Event::SyscallOnHostStackWithVectorState(
                    altstack_is_installed_and_inactive()
                        && get_guest_vector_state() == self.vector_state,
                ))
                .unwrap();
            ContinueOperation::Terminate
        }
        fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
    }
    impl Drop for VectorStateProbe {
        fn drop(&mut self) {
            let _ = self.send.send(Event::Done);
        }
    }

    set_guest_abi(GuestAbi::Linux);
    let platform = MacosUserland::new();
    let base = prepare_code(platform, &[0xd400_0001], 3, CodeKind::Linux); // svc #0
    let original_vector_state = get_guest_vector_state();
    let _restore = litebox::utils::defer(|| set_guest_vector_state(&original_vector_state));
    let mut vector_state = GuestVectorState::default();
    vector_state.registers[0] = 0x1234;
    vector_state.registers[31] = 0x5678;
    set_guest_vector_state(&vector_state);
    let (send, receive) = std::sync::mpsc::channel();
    // SAFETY: the test retains the child's rewritten code and stack until
    // VectorStateProbe is dropped.
    unsafe {
        platform
            .spawn_thread(
                &PtRegs::default(),
                Box::new(VectorStateProbe {
                    entry: base,
                    stack: base + 3 * HOST_PAGE_SIZE,
                    vector_state,
                    send,
                }),
            )
            .unwrap();
    }
    let observed: Vec<_> = (0..4)
        .map(|_| receive.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect();
    assert_eq!(
        observed,
        [
            Event::VectorStateInherited(true),
            Event::EnteredOnHostStack(true),
            Event::SyscallOnHostStackWithVectorState(true),
            Event::Done,
        ]
    );
    // SAFETY: VectorStateProbe has stopped, so the guest mappings are idle.
    unsafe { platform.release_pages(base..base + 3 * HOST_PAGE_SIZE) }.unwrap();
}

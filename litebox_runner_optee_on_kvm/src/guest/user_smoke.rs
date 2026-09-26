// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Ring-3 debugging payloads, not an application ABI or an OP-TEE service.
//! The only supported syscalls are test checkpoints. No timer is installed;
//! all payloads are finite and the host smoke script enforces a process timeout.

use super::Platform;
use core::cell::Cell;
use litebox::{
    mm::exception_table::memcpy_fallible,
    platform::{
        PageManagementProvider, RawMutPointer,
        page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions as Perms},
    },
    shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo},
};
use litebox_common_linux::{
    PtRegs,
    arch::{EFLAGS_DF, EFLAGS_IF, USER_CS, USER_DS},
    errno::Errno,
};
use litebox_platform_lvbs::{KERNEL_OFFSET, execution::ExecutionTimer, serial_println};

const PAGE: usize = 4096;
const CODE: usize = 0x200000;
const DATA: usize = 0x400000;
const STACK: usize = 0x600000;
const STACK_TOP: usize = STACK + PAGE - 16;
const UNMAPPED: usize = 0x800000;
const INITIAL_RBX: usize = 0x1122334455667788;
const UPDATED_RBX: usize = 0x8877665544332211;
const BREAKPOINT_RAX: usize = 0x123456789abcdef0;
const SYSCALL_REPLY: usize = 0x1234;
const BREAKPOINT_REPLY: usize = 0x5678;
const DONE: usize = 0xfeed;

core::arch::global_asm!(
    include_str!("user_smoke.S"),
    data = const DATA,
    initial_rbx = const INITIAL_RBX,
    updated_rbx = const UPDATED_RBX,
    breakpoint_rax = const BREAKPOINT_RAX,
    syscall_reply = const SYSCALL_REPLY,
    breakpoint_reply = const BREAKPOINT_REPLY,
);

unsafe extern "C" {
    static user_smoke_start: u8;
    static user_smoke_end: u8;
    static user_smoke_after_syscall: u8;
    static user_smoke_after_breakpoint: u8;
    static user_smoke_ud: u8;
    static user_smoke_gp: u8;
    static user_smoke_write: u8;
    static user_smoke_read: u8;
    static user_smoke_nx: u8;
}

fn user_address(label: *const u8) -> usize {
    CODE + (label as usize - &raw const user_smoke_start as usize)
}

/// An explicit debugging choice, not an implicit platform default. It counts
/// the shared hooks but programs no device. Never use for untrusted workloads.
#[derive(Default)]
struct NoTimerForFiniteTests {
    arms: Cell<usize>,
    user_exceptions: Cell<usize>,
}
impl ExecutionTimer for NoTimerForFiniteTests {
    fn arm(&self) {
        self.arms.set(self.arms.get() + 1);
    }
    fn on_user_exception(&self, _exception: Exception) {
        self.user_exceptions.set(self.user_exceptions.get() + 1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Case {
    RoundTrip,
    InvalidOpcode,
    PrivilegedInstruction,
    WriteCode,
    ExecuteData,
    ReadKernel,
    ReadUnmapped,
    InvalidReturn,
}

struct TestShim {
    case: Case,
    kernel_address: usize,
    kernel_gs: usize,
    init_calls: Cell<usize>,
    reenter_calls: Cell<usize>,
    syscalls: Cell<usize>,
    user_faults: Cell<usize>,
    kernel_faults: Cell<usize>,
}

impl TestShim {
    fn new(case: Case, platform: &Platform) -> Self {
        Self {
            case,
            kernel_address: core::ptr::from_ref(platform) as usize,
            kernel_gs: unsafe { litebox_common_linux::rdgsbase() },
            init_calls: Cell::new(0),
            reenter_calls: Cell::new(0),
            syscalls: Cell::new(0),
            user_faults: Cell::new(0),
            kernel_faults: Cell::new(0),
        }
    }

    fn prepare(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.syscalls.set(0);
        self.user_faults.set(0);
        self.kernel_faults.set(0);
        let entry = match self.case {
            Case::RoundTrip | Case::InvalidReturn => &raw const user_smoke_start,
            Case::InvalidOpcode => &raw const user_smoke_ud,
            Case::PrivilegedInstruction => &raw const user_smoke_gp,
            Case::WriteCode => &raw const user_smoke_write,
            Case::ExecuteData => &raw const user_smoke_nx,
            Case::ReadKernel | Case::ReadUnmapped => &raw const user_smoke_read,
        };
        *ctx = PtRegs::default();
        ctx.rip = user_address(entry);
        ctx.rsp = STACK_TOP;
        ctx.rdi = match self.case {
            Case::WriteCode => CODE,
            Case::ReadKernel => self.kernel_address,
            Case::ReadUnmapped => UNMAPPED,
            _ => DATA,
        };
        // Deliberately unsafe flags/selectors: shared return sanitization must
        // normalize these before IRETQ instead of trusting the shim's inputs.
        ctx.cs = 0x08;
        ctx.ss = 0x10;
        ctx.eflags = (3 << 12) | (1 << 14) | (1 << 18);
        ContinueOperation::Resume
    }

    fn check_kernel_context(&self) {
        assert_eq!(unsafe { litebox_common_linux::rdgsbase() }, self.kernel_gs);
        let cs: u16;
        unsafe {
            core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nostack, nomem, preserves_flags));
        }
        assert_eq!(cs & 3, 0);
        let flags = x86_64::registers::rflags::read_raw();
        assert_eq!(
            flags & ((1 << 9) | (1 << 10) | (1 << 18)),
            0,
            "kernel IF/DF/AC must be clear"
        );
    }

    fn check_user_context(ctx: &PtRegs) {
        assert_eq!(ctx.cs, USER_CS);
        assert_eq!(ctx.ss, USER_DS);
        assert_eq!(ctx.rsp, STACK_TOP);
        assert_ne!(ctx.eflags & EFLAGS_IF, 0);
        assert_eq!(ctx.eflags & ((3 << 12) | (1 << 14) | (1 << 18)), 0);
    }

    fn check_registers(ctx: &PtRegs, rbx: usize) {
        assert_eq!(ctx.rbx, rbx);
        assert_eq!(
            [ctx.rbp, ctx.r12, ctx.r13, ctx.r14, ctx.r15],
            [0x55, 0x12, 0x13, 0x14, 0x15]
        );
        assert_eq!(
            [ctx.rdi, ctx.rsi, ctx.rdx, ctx.r8, ctx.r9, ctx.r10],
            [DATA, 0x22, 0x33, 0x88, 0x99, 0xaa]
        );
    }
}

impl EnterShim for TestShim {
    type ExecutionContext = PtRegs;
    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.init_calls.set(self.init_calls.get() + 1);
        self.prepare(ctx)
    }
    fn reenter(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.reenter_calls.set(self.reenter_calls.get() + 1);
        self.prepare(ctx)
    }
    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.check_kernel_context();
        Self::check_user_context(ctx);
        assert_ne!(
            ctx.orig_rax, 0xff,
            "ring-3 register/XSAVE self-check failed"
        );
        self.syscalls.set(self.syscalls.get() + 1);
        match ctx.orig_rax {
            1 => {
                assert_eq!(self.syscalls.get(), 1);
                assert_eq!(ctx.rip, user_address(&raw const user_smoke_after_syscall));
                assert_eq!(ctx.rcx, ctx.rip);
                assert_eq!(ctx.r11, ctx.eflags);
                assert_ne!(ctx.eflags & EFLAGS_DF, 0);
                Self::check_registers(ctx, INITIAL_RBX);
                // Exercise the in-user-context kernel #PF path, distinct from
                // the boot test's exception-table-only path. The nested shim
                // exception declines the fault; shared code performs the fixup.
                let mut byte = 0u8;
                assert!(
                    unsafe { memcpy_fallible(&raw mut byte, UNMAPPED as *const u8, 1) }.is_err()
                );
                Self::check_registers(ctx, INITIAL_RBX);
                ctx.rbx = UPDATED_RBX;
                ctx.rax = SYSCALL_REPLY;
                if self.case == Case::InvalidReturn {
                    // Must be rejected without IRET or any new user exception.
                    ctx.rip = usize::try_from(KERNEL_OFFSET).unwrap();
                }
                clobber_extended_state();
                ContinueOperation::Resume
            }
            2 => {
                assert_eq!(self.case, Case::RoundTrip);
                assert_eq!(self.syscalls.get(), 2);
                assert_eq!(self.user_faults.get(), 1);
                Self::check_registers(ctx, UPDATED_RBX);
                ctx.rax = DONE;
                clobber_extended_state();
                ContinueOperation::Terminate
            }
            number => panic!("unexpected test syscall {number:#x}"),
        }
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        self.check_kernel_context();
        if info.kernel_mode {
            assert_eq!(info.exception, Exception::PAGE_FAULT);
            assert_eq!(info.cr2, UNMAPPED);
            assert_eq!(info.error_code & 7, 0);
            self.kernel_faults.set(self.kernel_faults.get() + 1);
            return ContinueOperation::Terminate;
        }
        Self::check_user_context(ctx);
        self.user_faults.set(self.user_faults.get() + 1);
        assert_eq!(self.user_faults.get(), 1);
        let (exception, cr2, error, rip) = match self.case {
            Case::RoundTrip => {
                assert_eq!(
                    info.exception,
                    Exception::BREAKPOINT,
                    "unexpected user exception at {:#x}: error={:#x}, cr2={:#x}, syscalls={}",
                    ctx.rip,
                    info.error_code,
                    info.cr2,
                    self.syscalls.get()
                );
                assert_eq!(info.error_code, 0);
                assert_eq!(
                    ctx.rip,
                    user_address(&raw const user_smoke_after_breakpoint)
                );
                assert_eq!(ctx.rax, BREAKPOINT_RAX);
                Self::check_registers(ctx, UPDATED_RBX);
                ctx.rax = BREAKPOINT_REPLY;
                clobber_extended_state();
                return ContinueOperation::Resume;
            }
            Case::InvalidOpcode => (
                Exception::INVALID_OPCODE,
                0,
                0,
                user_address(&raw const user_smoke_ud),
            ),
            Case::PrivilegedInstruction => (
                Exception::GENERAL_PROTECTION_FAULT,
                0,
                0,
                user_address(&raw const user_smoke_gp),
            ),
            Case::WriteCode => (
                Exception::PAGE_FAULT,
                CODE,
                7,
                user_address(&raw const user_smoke_write),
            ),
            Case::ExecuteData => (Exception::PAGE_FAULT, DATA, 0x15, DATA),
            Case::ReadKernel => (
                Exception::PAGE_FAULT,
                self.kernel_address,
                5,
                user_address(&raw const user_smoke_read),
            ),
            Case::ReadUnmapped => (
                Exception::PAGE_FAULT,
                UNMAPPED,
                4,
                user_address(&raw const user_smoke_read),
            ),
            Case::InvalidReturn => panic!("invalid return context reached user mode"),
        };
        assert_eq!(info.exception, exception);
        assert_eq!(ctx.rip, rip);
        assert_eq!(info.error_code, error);
        if exception == Exception::PAGE_FAULT {
            assert_eq!(info.cr2, cr2);
        }
        clobber_extended_state();
        ContinueOperation::Terminate
    }
    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        panic!("no interrupt source is configured for the finite user tests");
    }
}

#[inline(never)]
fn clobber_extended_state() {
    let default_mxcsr = 0x1f80u32;
    // These registers/control words deliberately differ from the user payload.
    // Rust uses SSE, not the x87 stack, so FNINIT cannot clobber a Rust live value.
    unsafe {
        core::arch::asm!(
            "fninit", "ldmxcsr [{mxcsr}]", "pxor xmm0, xmm0", "pcmpeqd xmm15, xmm15",
            mxcsr = in(reg) &raw const default_mxcsr, out("xmm0") _, out("xmm15") _, options(nostack),
        );
    }
}

fn control_words() -> (u32, u16) {
    let mut mxcsr = 0u32;
    let mut fcw = 0u16;
    unsafe {
        core::arch::asm!("stmxcsr [{mxcsr}]", "fnstcw [{fcw}]",
            mxcsr = in(reg) &raw mut mxcsr, fcw = in(reg) &raw mut fcw,
            options(nostack, preserves_flags));
    }
    (mxcsr, fcw)
}

fn map_and_copy(platform: &Platform, address: usize, bytes: &[u8], permissions: Perms) {
    assert!(bytes.len() <= PAGE);
    let pointer = <Platform as PageManagementProvider<PAGE>>::allocate_pages(
        platform,
        address..address + PAGE,
        Perms::READ | Perms::WRITE,
        false,
        true,
        FixedAddressBehavior::NoReplace,
    )
    .unwrap();
    assert!(pointer.write_slice_at_offset(0, bytes).is_some());
    unsafe {
        <Platform as PageManagementProvider<PAGE>>::update_permissions(
            platform,
            address..address + PAGE,
            permissions,
        )
        .unwrap();
    }
}

pub(super) fn run(platform: &Platform) {
    assert!(platform.page_table_manager().is_base_page_table_active());
    let task = platform.create_task_page_table().unwrap();
    unsafe {
        platform.switch_page_table(task).unwrap();
    }
    let start = &raw const user_smoke_start;
    let length = &raw const user_smoke_end as usize - start as usize;
    assert!((1..=PAGE).contains(&length));
    // SAFETY: the linker keeps the assembly blob in mapped kernel rodata. It
    // contains only self-contained code; no compiler/runtime relocations.
    let code = unsafe { core::slice::from_raw_parts(start, length) };
    map_and_copy(platform, CODE, code, Perms::READ | Perms::EXEC);
    let mut data = [0u8; 64];
    data[..16].copy_from_slice(&[0xa5; 16]);
    data[16..32].copy_from_slice(&[0x3c; 16]);
    data[32..34].copy_from_slice(&0x077fu16.to_le_bytes());
    data[36..40].copy_from_slice(&0x3f80u32.to_le_bytes());
    map_and_copy(platform, DATA, &data, Perms::READ | Perms::WRITE);
    map_and_copy(platform, STACK, &[], Perms::READ | Perms::WRITE);
    let timer = NoTimerForFiniteTests::default();
    let mut regs = PtRegs::default();
    let roundtrip = TestShim::new(Case::RoundTrip, platform);
    // The primary test exercises first save/restore and subsequent XSAVEOPT
    // paths across syscalls, exceptions and repeated reentry on the same CPU.
    for entry in 0..3 {
        let before = control_words();
        unsafe {
            if entry == 0 {
                litebox_platform_lvbs::run_thread_ref(&roundtrip, &mut regs, &timer);
            } else {
                litebox_platform_lvbs::reenter_thread_ref(&roundtrip, &mut regs, &timer);
            }
        }
        assert_eq!(regs.rax, DONE);
        assert_eq!(roundtrip.syscalls.get(), 2);
        assert_eq!(roundtrip.user_faults.get(), 1);
        assert_eq!(roundtrip.kernel_faults.get(), 1);
        assert_eq!(
            control_words(),
            before,
            "kernel FP control state was not restored"
        );
        assert_eq!(
            unsafe { litebox_common_linux::rdgsbase() },
            roundtrip.kernel_gs
        );
        assert_eq!(platform.current_page_table_id(), task);
    }
    assert_eq!(roundtrip.init_calls.get(), 1);
    assert_eq!(roundtrip.reenter_calls.get(), 2);
    assert_eq!(timer.arms.get(), 3);
    assert_eq!(
        timer.user_exceptions.get(),
        3,
        "kernel faults must not notify user timer hook"
    );
    serial_println!("QEMU-USER: syscall reentry registers XSAVE OK");

    for case in [
        Case::InvalidOpcode,
        Case::PrivilegedInstruction,
        Case::WriteCode,
        Case::ExecuteData,
        Case::ReadKernel,
        Case::ReadUnmapped,
        Case::InvalidReturn,
    ] {
        let shim = TestShim::new(case, platform);
        let before = control_words();
        unsafe {
            litebox_platform_lvbs::run_thread_ref(&shim, &mut regs, &timer);
        }
        assert_eq!(control_words(), before);
        assert_eq!(shim.init_calls.get(), 1);
        assert_eq!(
            shim.syscalls.get(),
            usize::from(case == Case::InvalidReturn)
        );
        assert_eq!(
            shim.user_faults.get(),
            usize::from(case != Case::InvalidReturn)
        );
        assert_eq!(
            shim.kernel_faults.get(),
            usize::from(case == Case::InvalidReturn)
        );
        assert_eq!(unsafe { litebox_common_linux::rdgsbase() }, shim.kernel_gs);
        serial_println!("QEMU-USER: {case:?} OK");
    }
    assert_eq!(timer.arms.get(), 10);
    assert_eq!(timer.user_exceptions.get(), 9);
    assert_eq!(platform.current_page_table_id(), task);
    let handle = platform.page_table_manager().current_page_table();
    for base in [CODE, DATA, STACK] {
        unsafe {
            <Platform as PageManagementProvider<PAGE>>::deallocate_pages(
                platform,
                base..base + PAGE,
            )
            .unwrap();
        }
    }
    unsafe {
        platform
            .switch_page_table(litebox_platform_lvbs::BASE_PAGE_TABLE_ID)
            .unwrap();
    }
    assert_eq!(
        unsafe { platform.delete_task_page_table(task) },
        Err(Errno::EBUSY)
    );
    drop(handle);
    unsafe {
        platform.delete_task_page_table(task).unwrap();
    }
    // A subsequent kernel fault must use the no-user-context fixup path, not
    // dereference the old stack-local ThreadContext after user execution ended.
    let mut byte = 0;
    assert!(unsafe { memcpy_fallible(&raw mut byte, UNMAPPED as *const u8, 1) }.is_err());
    serial_println!("QEMU-USER: faults isolation teardown OK");
}

use crate::debug_serial_println;
use crate::{
    kernel_context::get_per_core_kernel_context, mshv::vtl_switch::jump_to_vtl_switch_loop,
    user_context::UserSpaceManagement,
};
use core::arch::{asm, naked_asm};
use x86_64::{
    VirtAddr,
    registers::{
        model_specific::{Efer, EferFlags, LStar, SFMask, Star},
        rflags::RFlags,
    },
};

// Generic x86_64 syscall support with a minor extension for realizing OP-TEE's
// up to 8 syscall arguments (r12 and r13 for the 6th and 7th arguments).
//
// rax: system call number
// rdi: arg0
// rsi: arg1
// rdx: arg2
// r10: arg3
// r8:  arg4
// r9:  arg5
// r12: arg6 (*)
// r13: arg7 (*)
//
// the `syscall` instruction automatically sets the following registers:
// rcx: userspace return address (note. arg3 for normal func call)
// r11: userspace rflags
//
// the `sysretq` instruction uses the following registers:
// rax: syscall return value
// rcx: userspace return address
// r11: userspace rflags
// Note. rsp should point to the userspace stack before calling `sysretq`

// placholder for the syscall handler function type
pub type SyscallHandler = fn() -> isize;
static SYSCALL_HANDLER: spin::Once<SyscallHandler> = spin::Once::new();

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SyscallContext {
    rdi: u64, // arg0
    rsi: u64, // arg1
    rdx: u64, // arg2
    r10: u64, // arg3
    r8: u64,  // arg4
    r9: u64,  // arg5
    r12: u64, // arg6
    r13: u64, // arg7
    rcx: u64, // userspace return address
    r11: u64, // userspace rflags
    rsp: u64, // userspace stack pointer
}

impl SyscallContext {
    /// # Panics
    /// Panics if the index is out of bounds (greater than 7).
    pub fn arg_index(&self, index: usize) -> u64 {
        match index {
            0 => self.rdi,
            1 => self.rsi,
            2 => self.rdx,
            3 => self.r10,
            4 => self.r8,
            5 => self.r9,
            6 => self.r12,
            7 => self.r13,
            _ => panic!("BUG: Invalid syscall argument index: {}", index),
        }
    }

    pub fn user_rip(&self) -> Option<VirtAddr> {
        VirtAddr::try_new(self.rcx).ok()
    }

    pub fn user_rflags(&self) -> RFlags {
        RFlags::from_bits_truncate(self.r11)
    }

    pub fn user_rsp(&self) -> Option<VirtAddr> {
        VirtAddr::try_new(self.rsp).ok()
    }
}

#[allow(clippy::similar_names)]
#[allow(unreachable_code)]
fn syscall_dispatcher(sysnr: u64, ctx: *const SyscallContext) -> isize {
    let syscall_handler: SyscallHandler = *SYSCALL_HANDLER
        .get()
        .expect("Syscall handler should be initialized");

    debug_serial_println!("sysnr = {:#x}, ctx = {:#x}", sysnr, ctx as usize);
    let ctx = unsafe { &*ctx };

    assert!(
        ctx.user_rip().is_some() && ctx.user_rsp().is_some(),
        "BUG: userspace RIP or RSP is invalid"
    );

    // placeholder for the syscall handler
    let sysret = syscall_handler();

    // TODO: We should determine whether we should place this function here, OP-TEE shim, or separate it into
    // multiple functions and place them in the appropriate places.
    // In OP-TEE TAs, a system call can have three different return paths:
    // 1. Return to the user space to resume its execution: This means a TA is in the middle of its execution.
    // It does not yet complete a request from a VTL0 client (e.g., sign a message) and makes several syscalls to do so.
    // 2. Switch to VTL0 with a final outcome: a TA completes a client's request and returns a final outcome to VTL0.
    // 3. Switch to VTL0 to interact with VTL0: a TA can initiate an RPC to VTL0 to interact with its client app or services.
    // OP-TEE Shim is expected to host a logic to decide a return path, Platform is expected to host a logic to change
    // address spaces, and LVBS Runner is expected to host a logic to switch to VTL0.

    // placeholder for returning to the user space
    if sysret == 0 {
        return sysret;
    }

    // save user context before switching to VTL0
    crate::platform_low()
        .save_user_context(
            ctx.user_rip().unwrap(),
            ctx.user_rsp().unwrap(),
            ctx.user_rflags(),
        )
        .expect("Failed to save user context");

    let kernel_context = get_per_core_kernel_context();
    kernel_context.set_vtl_return_value(0);
    let stack_top = kernel_context.kernel_stack_top();
    unsafe {
        asm!(
            "mov rsp, rax",
            "and rsp, -16",
            in("rax") stack_top
        );
    }

    crate::platform_low().page_table.change_address_space();
    unsafe { jump_to_vtl_switch_loop() }
    unreachable!()
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_dispatcher_wrapper() {
    naked_asm!(
        "push rsp",
        "push r11",
        "push rcx",
        "push r13",
        "push r12",
        "push r9",
        "push r8",
        "push r10",
        "push rdx",
        "push rsi",
        "push rdi",
        "mov rdi, rax",
        "mov rsi, rsp",
        "and rsp, {stack_alignment}",
        "call {syscall_dispatcher}",
        "add rsp, {register_space}",
        "pop rcx",
        "pop r11",
        "pop rbp",
        "sysretq",
        stack_alignment = const STACK_ALIGNMENT,
        syscall_dispatcher = sym syscall_dispatcher,
        register_space = const core::mem::size_of::<SyscallContext>() - core::mem::size_of::<u64>() * NUM_REGISTERS_TO_POP,
    );
}
const NUM_REGISTERS_TO_POP: usize = 3;
const STACK_ALIGNMENT: isize = -16;

/// This function enables 64-bit syscall extensions and sets up the necessary MSRs.
/// It must be called for each core.
/// # Panics
/// Panics if GDT is not initialized for the current core.
#[cfg(target_arch = "x86_64")]
pub(crate) fn init(syscall_handler: SyscallHandler) {
    SYSCALL_HANDLER.call_once(|| syscall_handler);

    // enable 64-bit syscall/sysret
    let mut efer = Efer::read();
    efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
    unsafe { Efer::write(efer) };

    let dispatcher_addr = syscall_dispatcher_wrapper as *const () as u64;
    LStar::write(VirtAddr::new(dispatcher_addr));

    let rflags = RFlags::INTERRUPT_FLAG;
    SFMask::write(rflags);

    // configure STAR MSR for CS/SS selectors
    let kernel_context = get_per_core_kernel_context();
    let (kernel_cs, user_cs, _) = kernel_context
        .get_segment_selectors()
        .expect("GDT not initialized for the current core");
    unsafe { Star::write_raw(user_cs, kernel_cs) };
}

#[cfg(target_arch = "x86")]
pub(crate) fn init(_syscall_handler: SyscallHandler) {
    todo!("we don't support 32-bit mode syscalls for now");
    // AMD and Intel CPUs have different syscall mechanisms in 32-bit mode.
}

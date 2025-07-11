use crate::debug_serial_println;
use crate::user_context::UserSpace;
use crate::{kernel_context::get_per_core_kernel_context, mshv::vtl_switch::jump_vtl_switch_loop};
use core::arch::{asm, naked_asm};
use x86_64::{
    VirtAddr,
    registers::{
        model_specific::{Efer, EferFlags, LStar, SFMask, Star},
        rflags::RFlags,
    },
};

// the maximum number of arguments of OP-TEE syscall is 8
const MAX_SYSCALL_ARGS: usize = 8;

// assume OP-TEE syscall
#[allow(clippy::too_many_arguments)]
fn handle_syscall(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    arg7: u64,
    sysnr: u64,
) -> ! {
    debug_serial_println!(
        "syscall {:#x} invoked with arguments:\n\t{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
        sysnr,
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6,
        arg7
    );

    // TODO: check syscall number and its handling result to determine whether we should
    // return to the user space or switch to VTL0
    let sysret = 0;

    let kernel_context = get_per_core_kernel_context();
    let stack_top = kernel_context.kernel_stack_top();
    unsafe {
        asm!(
            "mov rsp, rax",
            "and rsp, -16",
            in("rax") stack_top
        );
    }
    kernel_context.set_vtl_return_value(sysret);

    crate::platform_low().page_table.switch_address_space();
    unsafe { jump_vtl_switch_loop() }
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_dispatcher_wrapper() {
    naked_asm!(
        "push rax",
        "push r13",
        "push r12",
        "push r9",
        "push r8",
        "push r10",
        "push rdx",
        "push rsi",
        "push rdi",
        "mov rdi, rcx",
        "mov rsi, rsp",
        "mov rdx, r11",
        "call {save_user_state}",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop r8",
        "pop r9",
        "call {handle_syscall}",
        save_user_state = sym save_user_state,
        handle_syscall = sym handle_syscall,
    );
}

fn save_user_state(user_ret_addr: u64, user_stack_ptr: u64, user_rflags: u64) {
    if crate::platform_low()
        .save_user_context(
            VirtAddr::new(user_ret_addr),
            VirtAddr::new(
                user_stack_ptr
                    + u64::try_from(core::mem::size_of::<u64>() * (MAX_SYSCALL_ARGS + 1)).unwrap(),
            ),
            RFlags::from_bits_truncate(user_rflags),
        )
        .is_err()
    {
        debug_serial_println!("Failed to save user context in the syscall handler");
    }
}

/// This function enables 64-bit syscall extensions and sets up the necessary MSRs.
/// It must be called for each core.
/// # Panics
///
/// Panics if GDT is not initialized for the current core.
#[cfg(target_arch = "x86_64")]
pub fn init() {
    // enable 64-bit syscall/sysret
    let mut efer = Efer::read();
    efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
    unsafe { Efer::write(efer) };

    let handler_addr = syscall_dispatcher_wrapper as *const () as u64;
    LStar::write(VirtAddr::new(handler_addr));

    let rflags = RFlags::INTERRUPT_FLAG;
    SFMask::write(rflags);

    // configure STAR MSR for CS/SS selectors
    let kernel_context = get_per_core_kernel_context();
    let (kernel_cs, user_cs) = kernel_context
        .get_kernel_user_code_segments()
        .expect("GDT not initialized for the current core");
    unsafe { Star::write_raw(user_cs, kernel_cs) };
}

#[cfg(target_arch = "x86")]
pub fn init() {
    todo!("we don't support 32-bit mode syscalls for now");
    // AMD and Intel CPUs have different syscall mechanisms in 32-bit mode.
}

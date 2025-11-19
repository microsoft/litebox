use crate::debug_serial_println;
use crate::per_cpu_variables::with_per_cpu_variables;
use core::arch::naked_asm;
use litebox_common_linux::PtRegs;
use litebox_common_optee::SyscallContext;
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

cfg_if::cfg_if! {
    if #[cfg(feature = "linux_syscall")] {
        use litebox_common_linux::ContinueOperation;
        pub type SyscallReturnType = ContinueOperation;
    } else if #[cfg(feature = "optee_syscall")] {
        use litebox_common_optee::ContinueOperation;
        pub type SyscallReturnType = ContinueOperation;
    } else {
        compile_error!(r##"No syscall handler specified."##);
    }
}

static SHIM: spin::Once<
    &'static dyn litebox::shim::EnterShim<
        ExecutionContext = PtRegs,
        ContinueOperation = ContinueOperation,
    >,
> = spin::Once::new();

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SyscallContextRaw {
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

impl SyscallContextRaw {
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

    #[expect(clippy::cast_possible_truncation)]
    pub fn syscall_context(&self) -> SyscallContext {
        SyscallContext::new(&[
            self.rdi as usize,
            self.rsi as usize,
            self.rdx as usize,
            self.r10 as usize,
            self.r8 as usize,
            self.r9 as usize,
            self.r12 as usize,
            self.r13 as usize,
        ])
    }

    #[expect(clippy::cast_possible_truncation)]
    pub fn to_pt_regs(&self, rax: u64) -> PtRegs {
        PtRegs {
            r15: 0,
            r14: 0,
            r13: self.r13 as usize,
            r12: self.r12 as usize,
            rbp: 0,
            rbx: 0,
            r11: self.r11 as usize,
            r10: self.r10 as usize,
            r9: self.r9 as usize,
            r8: self.r8 as usize,
            rax: 0,
            rcx: self.rcx as usize,
            rdx: self.rdx as usize,
            rsi: self.rsi as usize,
            rdi: self.rdi as usize,
            orig_rax: rax as usize,
            rip: 0,
            cs: 0,
            eflags: 0,
            rsp: self.rsp as usize,
            ss: 0,
        }
    }
}

#[allow(clippy::similar_names)]
#[allow(unreachable_code)]
fn syscall_entry(sysnr: u64, ctx_raw: *const SyscallContextRaw) -> usize {
    let &shim = SHIM.get().expect("Shim should be initialized");

    debug_serial_println!("sysnr = {:#x}, ctx_raw = {:#x}", sysnr, ctx_raw as usize);
    let ctx_raw = unsafe { &*ctx_raw };

    assert!(
        ctx_raw.user_rip().is_some() && ctx_raw.user_rsp().is_some(),
        "BUG: userspace RIP or RSP is invalid"
    );

    let mut ctx = ctx_raw.to_pt_regs(sysnr);

    // call the syscall handler passed down from the shim
    match shim.syscall(&mut ctx) {
        ContinueOperation::ResumeGuest => ctx.rax,
        ContinueOperation::ExitThread(status) | ContinueOperation::ExitProcess(status) => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "linux_syscall")] {
                    let ret = status.cast_unsigned() as usize;
                } else if #[cfg(feature = "optee_syscall")] {
                    let ret = status;
                } else {
                    compile_error!(r##"No syscall handler specified."##);
                }
            };

            let host_bp = unsafe { crate::get_host_bp() };
            debug_serial_println!(
                "Exiting from run_thread: rbp={:#x}, ret={:#x}",
                host_bp,
                ret
            );

            unsafe {
                core::arch::asm!(
                    "mov rax, {ret}",
                    "mov rbp, {host_bp}",
                    "lea rsp, [rbp - 5*8]",
                    "pop r15",
                    "pop r14",
                    "pop r13",
                    "pop r12",
                    "pop rbx",
                    "pop rbp",
                    "ret",
                    ret = in(reg) ret,
                    host_bp = in(reg) host_bp,
                    options(nostack, noreturn, preserves_flags),
                );
            }
        }
        #[cfg(feature = "linux_syscall")]
        ContinueOperation::RtSigreturn(..) => unreachable!(),
    }
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_entry_wrapper() {
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
        "call {syscall_entry}",
        "add rsp, {register_space}",
        "pop rcx",
        "pop r11",
        "pop rbp",
        "sysretq",
        stack_alignment = const STACK_ALIGNMENT,
        syscall_entry = sym syscall_entry,
        register_space = const core::mem::size_of::<SyscallContextRaw>() - core::mem::size_of::<u64>() * NUM_REGISTERS_TO_POP,
    );
}
const NUM_REGISTERS_TO_POP: usize = 3;
const STACK_ALIGNMENT: isize = -16;

/// This function enables 64-bit syscall extensions and sets up the necessary MSRs.
/// It must be called for each core.
/// # Panics
/// Panics if GDT is not initialized for the current core.
#[cfg(target_arch = "x86_64")]
pub(crate) fn init(
    shim: &'static dyn litebox::shim::EnterShim<
        ExecutionContext = PtRegs,
        ContinueOperation = ContinueOperation,
    >,
) {
    SHIM.call_once(|| shim);

    // enable 64-bit syscall/sysret
    let mut efer = Efer::read();
    efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
    unsafe { Efer::write(efer) };

    let syscall_entry_addr = syscall_entry_wrapper as *const () as u64;
    LStar::write(VirtAddr::new(syscall_entry_addr));

    let rflags = RFlags::INTERRUPT_FLAG;
    SFMask::write(rflags);

    // configure STAR MSR for CS/SS selectors
    let (kernel_cs, user_cs, _) = with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables
            .get_segment_selectors()
            .expect("GDT not initialized for the current core")
    });
    unsafe { Star::write_raw(user_cs, kernel_cs) };
}

#[cfg(target_arch = "x86")]
pub(crate) fn init(_syscall_handler: SyscallHandler) {
    todo!("we don't support 32-bit mode syscalls for now");
    // AMD and Intel CPUs have different syscall mechanisms in 32-bit mode.
}

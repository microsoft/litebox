//! Linux Structs

/// Context saved when entering the kernel
///
/// pt_regs from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/include/asm/ptrace.h#L12)
#[allow(non_camel_case_types)]
#[repr(C, packed)]
pub struct pt_regs {
    /*
     * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
     * unless syscall needs a complete, fully filled "struct pt_regs".
     */
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    /* These regs are callee-clobbered. Always saved on kernel entry. */
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,

    /*
     * On syscall entry, this is syscall#. On CPU exception, this is error code.
     * On hw interrupt, it's IRQ number:
     */
    pub orig_rax: u64,
    /* Return frame for iretq */
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    /* top of stack page */
}

/// Registers used for syscall arguments
pub struct SyscallRegs {
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}

impl pt_regs {
    pub fn save_syscall_regs(&self) -> SyscallRegs {
        SyscallRegs {
            rdi: self.rdi,
            rsi: self.rsi,
            rdx: self.rdx,
            r10: self.r10,
            r8: self.r8,
            r9: self.r9,
        }
    }

    pub fn restore_syscall_regs(&mut self, regs: SyscallRegs) {
        self.rdi = regs.rdi;
        self.rsi = regs.rsi;
        self.rdx = regs.rdx;
        self.r10 = regs.r10;
        self.r8 = regs.r8;
        self.r9 = regs.r9;
    }
}

/// timespec from [Linux](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/time.h#L11)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,

    /// Nanoseconds. Must be less than 1_000_000_000.
    pub tv_nsec: i64,
}

//! This module contains the loader for the LiteBox shim.

pub(crate) mod elf;
pub(crate) mod ta_stack;

pub fn load_elf_buffer(elf_buf: &[u8]) -> Result<ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load_buffer(elf_buf)
}

#[cfg(target_arch = "x86_64")]
pub fn allocate_guest_tls(
    tls_size: Option<usize>,
) -> Result<(), litebox_common_linux::errno::Errno> {
    elf::allocate_guest_tls(tls_size)
}

/// Load the trampoline code based on the given base address.
/// This function might overwrite (i.e., unmap) `ldelf`'s memory region if there is overlap.
#[cfg(feature = "platform_linux_userland")]
pub fn load_ta_trampoline(elf_buf: &[u8], base: usize) -> Result<(), elf::ElfLoaderError> {
    elf::ElfLoader::load_trampoline(elf_buf, base)
}

/// Struct to hold the information needed to start the program (entry point and stack_base).
#[derive(Clone, Copy)]
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub stack_base: usize,
    pub params_address: usize,
    pub ldelf_arg_address: Option<usize>,
}

/// Initialize the TA stack with the given base address and parameters.
pub fn init_stack(
    stack_base: Option<usize>,
    params: &[litebox_common_optee::UteeParamOwned],
) -> Option<ta_stack::TaStack> {
    let mut stack = ta_stack::allocate_stack(stack_base)?;
    stack.init(params)?;
    Some(stack)
}

/// Initialize the ldelf stack with the given base address and argument.
pub fn init_ldelf_stack(
    stack_base: Option<usize>,
    ldelf_arg: &litebox_common_optee::LdelfArg,
) -> Option<ta_stack::TaStack> {
    let mut stack = ta_stack::allocate_stack(stack_base)?;
    stack.init_with_ldelf_arg(ldelf_arg)?;
    Some(stack)
}

/// Prepare the CPU registers for starting the TA.
#[allow(clippy::missing_panics_doc)]
pub fn prepare_registers(
    ta_info: &ElfLoadInfo,
    stack: &ta_stack::TaStack,
    session_id: u32,
    func_id: u32,
    cmd_id: Option<u32>,
) -> litebox_common_linux::PtRegs {
    litebox_common_linux::PtRegs {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: usize::try_from(cmd_id.unwrap_or(0)).unwrap(),
        rdx: stack.get_params_address(),
        rsi: usize::try_from(session_id).unwrap(),
        rdi: usize::try_from(func_id).unwrap(),
        orig_rax: 0,
        rip: ta_info.entry_point,
        cs: 0x33, // __USER_CS
        eflags: 0,
        rsp: stack.get_cur_stack_top(),
        ss: 0x2b, // __USER_DS
    }
}

/// Prepare the CPU registers for starting ldelf.
#[allow(clippy::missing_panics_doc)]
pub fn prepare_ldelf_registers(
    ta_info: &ElfLoadInfo,
    stack: &ta_stack::TaStack,
) -> litebox_common_linux::PtRegs {
    litebox_common_linux::PtRegs {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: stack.get_ldelf_arg_address(),
        orig_rax: 0,
        rip: ta_info.entry_point,
        cs: 0x33, // __USER_CS
        eflags: 0,
        rsp: stack.get_cur_stack_top(),
        ss: 0x2b, // __USER_DS
    }
}

/// The magic number used to identify the LiteBox rewriter and where we should
/// update the syscall callback pointer.
pub const REWRITER_MAGIC_NUMBER: u64 = u64::from_le_bytes(*b"LITE BOX");
pub const REWRITER_VERSION_NUMBER: u64 = u64::from_le_bytes(*b"LITEBOX0");

pub(crate) const DEFAULT_STACK_SIZE: usize = 1024 * 1024; // 1 MB

//! This module contains the loader for the LiteBox shim.

pub(crate) mod elf;
pub mod ta_stack;

pub fn load_elf_buffer(elf_buf: &[u8]) -> Result<ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load_buffer(elf_buf)
}

/// Struct to hold the information needed to start the program
/// (entry point and stack_base).
#[derive(Clone, Copy)]
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub stack_base: usize,
    pub params_address: usize,
}

pub fn init_stack(
    stack_base: Option<usize>,
    params: &[litebox_common_optee::UteeParamOwned],
) -> Option<ta_stack::TaStack> {
    let mut stack = ta_stack::allocate_stack(stack_base)?;
    stack.init(params)?;
    Some(stack)
}

/// The magic number used to identify the LiteBox rewriter and where we should
/// update the syscall callback pointer.
pub const REWRITER_MAGIC_NUMBER: u64 = u64::from_le_bytes(*b"LITE BOX");
pub const REWRITER_VERSION_NUMBER: u64 = u64::from_le_bytes(*b"LITEBOX0");

pub(crate) const DEFAULT_STACK_SIZE: usize = 1024 * 1024; // 1 MB

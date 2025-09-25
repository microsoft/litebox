//! This module contains the loader for the LiteBox shim.

pub(crate) mod elf;
pub(crate) mod ta_stack;

pub fn load_elf_buffer(elf_buf: &[u8]) -> Result<elf::ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load_buffer(elf_buf)
}

/// The magic number used to identify the LiteBox rewriter and where we should
/// update the syscall callback pointer.
pub const REWRITER_MAGIC_NUMBER: u64 = u64::from_le_bytes(*b"LITE BOX");
pub const REWRITER_VERSION_NUMBER: u64 = u64::from_le_bytes(*b"LITEBOX0");

pub(crate) const DEFAULT_STACK_SIZE: usize = 1024 * 1024; // 1 MB

pub const DEFAULT_FS_BASE: usize = (1 << 46) - 2 * 4096;

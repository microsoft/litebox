//! This module contains the loader for the LiteBox shim.

mod elf;
mod stack;

pub fn load_elf_buffer(elf_buf: &[u8]) -> Result<elf::ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load_buffer(elf_buf)
}

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

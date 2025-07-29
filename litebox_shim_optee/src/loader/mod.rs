//! This module contains the loader for the LiteBox shim.

mod elf;
mod stack;

// Load a program into the LiteBox shim.
// pub fn load_program(
//     path: &str,
//     argv: alloc::vec::Vec<alloc::ffi::CString>,
//     envp: alloc::vec::Vec<alloc::ffi::CString>,
// ) -> Result<elf::ElfLoadInfo, elf::ElfLoaderError> {
//     elf::ElfLoader::load(path, argv, envp, aux)
// }

pub fn load_elf_buffer(
    elf_buf: &[u8],
    argv: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<elf::ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load_buffer(elf_buf, argv)
}

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

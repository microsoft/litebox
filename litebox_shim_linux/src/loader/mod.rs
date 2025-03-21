//! This module contains the loader for the LiteBox shim.

#![cfg(target_arch = "x86_64")]
mod elf;
mod stack;

pub fn load_program(
    path: &str,
    argv: alloc::vec::Vec<alloc::ffi::CString>,
    envp: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<elf::ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load(path, argv, envp)
}

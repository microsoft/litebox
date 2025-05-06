//! This module contains the loader for the LiteBox shim.

#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod elf;
mod stack;

pub fn load_program(
    path: &str,
    argv: alloc::vec::Vec<alloc::ffi::CString>,
    envp: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<elf::ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load(path, argv, envp)
}

/// The magic number used to identify the LiteBox rewriter and where we should
/// update the syscall callback pointer.
pub const REWRITER_MAGIC_NUMBER: u64 = u64::from_le_bytes(*b"LITE BOX");

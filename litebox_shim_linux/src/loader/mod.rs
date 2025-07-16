//! This module contains the loader for the LiteBox shim.

#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod auxv;
mod elf;
mod stack;

/// Load a program into the LiteBox shim.
pub fn load_program(
    path: &str,
    argv: alloc::vec::Vec<alloc::ffi::CString>,
    envp: alloc::vec::Vec<alloc::ffi::CString>,
    aux: auxv::AuxVec,
) -> Result<elf::ElfLoadInfo, elf::ElfLoaderError> {
    elf::ElfLoader::load(path, argv, envp, aux)
}

/// The magic number used to identify the LiteBox rewriter and where we should
/// update the syscall callback pointer.
pub const REWRITER_MAGIC_NUMBER: u64 = u64::from_le_bytes(*b"LITE BOX");
pub const REWRITER_VERSION_NUMBER: u64 = u64::from_le_bytes(*b"LITEBOX0");

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// A default low address is used for the binary (which grows upwards) to avoid
/// conflicts with the kernel's memory mappings (which grows downwards).
pub(crate) const DEFAULT_LOW_ADDR: usize = 0x1000_0000;

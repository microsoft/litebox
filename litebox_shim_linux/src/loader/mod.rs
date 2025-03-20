//! This module contains the loader for the LiteBox shim.

#![cfg(target_arch = "x86_64")]
mod elf;
mod stack;

pub fn load_program(
    path: &str,
    argv: alloc::vec::Vec<alloc::ffi::CString>,
    envp: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<elf::ElfLoadInfo, litebox_common_linux::errno::Errno> {
    elf::ElfLoader::load(path, argv, envp).map_err(litebox_common_linux::errno::Errno::from)
}

//! Syscalls Handlers

pub(crate) mod cryp;
pub(crate) mod syscall_nr;
pub(crate) mod tee;

#[cfg(test)]
pub(crate) mod tests;

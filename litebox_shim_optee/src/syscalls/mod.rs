// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Syscalls Handlers

use crate::{Task, UserMutPtr};
use litebox::platform::RawConstPointer as _;

pub(crate) mod cryp;
pub(crate) mod ldelf;
pub(crate) mod mm;
pub(crate) mod pta;
pub(crate) mod tee;

#[cfg(test)]
pub(crate) mod tests;

/// Undo a syscall/command's side effects if dispatch fails after the command
/// succeeded (currently only when copying results back out to the guest fails).
#[derive(Default)]
#[must_use = "must be run when dispatch fails after the command, or the side effect leaks"]
pub(crate) enum Cleanup {
    #[default]
    None,
    /// Unmap a region. `addr` must be page-aligned; `len` is rounded up by `sys_munmap`.
    Unmap { addr: usize, len: usize },
}

impl Cleanup {
    /// Undo the side effect. Runs only on an error path, so failures are ignored.
    pub(crate) fn run(self, task: &Task) {
        match self {
            Self::None => {}
            Self::Unmap { addr, len } => {
                let _ = task.sys_munmap(UserMutPtr::<u8>::from_usize(addr), len);
            }
        }
    }
}

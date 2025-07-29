//! This module manages the stack layout for the user process.

use alloc::{ffi::CString, vec::Vec};
use litebox::platform::{RawConstPointer, RawMutPointer};

use crate::MutPtr;

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

/// the user stack for OP-TEE TAs. Unlike Linux/libc, OP-TEE TAs do not have
///  argc and argv. Also, they do not have a notion of environment variables.
/// They obtain four arguments through CPU registers:
/// - rdi: function ID
/// - rsi: session ID
/// - rdx: the address of parameters
/// - rcx: command ID
pub(super) struct UserStack {
    /// The top of the stack (base address)
    stack_top: MutPtr<u8>,
    /// The length of the stack
    len: usize,
    /// The current position of the stack pointer
    pos: usize,
}

impl UserStack {
    /// Stack alignment required by libc ABI
    const STACK_ALIGNMENT: usize = 16;

    /// Create a new stack for the user process.
    ///
    /// `stack_top` and `len` must be aligned to [`Self::STACK_ALIGNMENT`]
    pub(super) fn new(stack_top: MutPtr<u8>, len: usize) -> Option<Self> {
        if stack_top.as_usize() % Self::STACK_ALIGNMENT != 0 {
            return None;
        }
        if len % Self::STACK_ALIGNMENT != 0 {
            return None;
        }
        Some(Self {
            stack_top,
            len,
            pos: len,
        })
    }

    /// Get the current stack pointer.
    pub(super) fn get_cur_stack_top(&self) -> usize {
        self.stack_top.as_usize() + self.pos
    }

    /// Initialize the stack for the new process.
    pub(super) fn init(&mut self) -> Option<()> {
        // end markers
        self.pos = self.pos.checked_sub(size_of::<usize>())?;
        unsafe {
            self.stack_top
                .write_at_offset(isize::try_from(self.pos).ok()?, 0)?;
        }

        // ensure stack is aligned
        self.pos = align_down(self.pos, Self::STACK_ALIGNMENT);
        Some(())
    }
}

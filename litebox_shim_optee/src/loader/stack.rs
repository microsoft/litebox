//! This module manages the stack layout for the user process.

use litebox::platform::{RawConstPointer, RawMutPointer};
use litebox_common_optee::UteeParams;

use crate::MutPtr;

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

/// the user stack for OP-TEE TAs. Unlike Linux/libc, OP-TEE TAs do not have
///  argc and argv. Also, they do not have a notion of environment variables.
pub(super) struct UserStack {
    /// The top of the stack (base address)
    stack_top: MutPtr<u8>,
    /// The length of the stack
    _len: usize,
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
            _len: len,
            pos: len,
        })
    }

    /// Get the current stack pointer.
    pub(super) fn get_cur_stack_top(&self) -> usize {
        self.stack_top.as_usize() + self.pos
    }

    /// Push `bytes` to the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        self.pos = self.pos.checked_sub(bytes.len())?;
        self.stack_top.copy_from_slice(self.pos, bytes)?;
        Some(())
    }

    fn push_utee_params(&mut self, params: &UteeParams) -> Option<()> {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(params).cast::<u8>(),
                core::mem::size_of::<UteeParams>(),
            )
        };
        self.push_bytes(bytes)
    }

    /// Initialize the stack for the new process.
    pub(super) fn init(&mut self, params: &UteeParams) -> Option<()> {
        // end markers
        self.pos = self.pos.checked_sub(size_of::<usize>())?;
        unsafe {
            self.stack_top
                .write_at_offset(isize::try_from(self.pos).ok()?, 0)?;
        }

        // TODO: generate a random value
        self.push_bytes(&[
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
            0xBE, 0xEF,
        ])?;

        // ensure stack is aligned
        self.pos = align_down(self.pos, Self::STACK_ALIGNMENT);
        let size = core::mem::size_of::<UteeParams>();
        let final_pos = self.pos.checked_sub(size)?;
        self.pos -= final_pos - align_down(final_pos, Self::STACK_ALIGNMENT);

        self.push_utee_params(params)?;

        assert_eq!(self.pos, align_down(self.pos, Self::STACK_ALIGNMENT));
        Some(())
    }
}

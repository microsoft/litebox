//! This module manages the stack layout for the user process.

use alloc::{collections::btree_map::BTreeMap, ffi::CString, vec::Vec};
use litebox::platform::{RawConstPointer, RawMutPointer};

use crate::MutPtr;

/// The stack layout for the user process. This is used to set up the stack
/// for the new process.
///
/// The stack layout is as follows:
/// ```text
///                           STACK LAYOUT
/// position            content                     size (bytes) + comment
/// ------------------------------------------------------------------------
/// stack pointer ->  [ argc = number of args ]     8
///                   [ argv[0] (pointer) ]         8   (program name)
///                   [ argv[1] (pointer) ]         8
///                   [ argv[..] (pointer) ]        8 * x
///                   [ argv[n - 1] (pointer) ]     8
///                   [ argv[n] (pointer) ]         8   (= NULL)
///
///                   [ padding ]                   0 - 16
///
///                   [ argument ASCIIZ strings ]   >= 0
///
/// (0xbffffffc)      [ end marker ]                8   (= NULL)
///
/// (0xc0000000)      < bottom of stack >           0   (virtual)
/// ------------------------------------------------------------------------
/// ```
///
/// NOTE: The above layout diagram is for 64-bit processes. Similar (but updated to use 32-bit
/// values, rather than 64-bit values) is used for 32-bit processes.
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

    /// Push `bytes` to the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        let end = isize::try_from(self.pos).ok()?;
        self.pos = self.pos.checked_sub(bytes.len())?;
        self.stack_top.copy_from_slice(self.pos, bytes)?;
        Some(())
    }

    /// Push a value to the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_usize(&mut self, val: usize) -> Option<()> {
        self.push_bytes(&val.to_le_bytes())
    }

    /// Push a string with a null terminator to the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_cstring(&mut self, val: &CString) -> Option<()> {
        let bytes = val.as_bytes_with_nul();
        self.push_bytes(bytes)
    }

    /// Push a vector of strings with null terminators to the stack.
    ///
    /// Returns the offsets of the strings in the stack.
    /// Returns `None` if stack has no enough space.
    fn push_cstrings(&mut self, vals: &[CString]) -> Option<Vec<usize>> {
        let mut envp = Vec::with_capacity(vals.len());
        for val in vals {
            self.push_cstring(val)?;
            envp.push(self.pos);
        }
        Some(envp)
    }

    /// Push a vector of stack pointers to the stack.
    ///
    /// `offsets` are the offsets of the pointers in the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_pointers(&mut self, offsets: Vec<usize>) -> Option<()> {
        // write end marker
        self.push_usize(0)?;
        let size = offsets.len().checked_mul(size_of::<usize>())?;
        let end = isize::try_from(self.pos).ok()?;
        self.pos = self.pos.checked_sub(size)?;
        let begin = isize::try_from(self.pos).ok()?;
        self.stack_top
            .mutate_subslice_with(begin..end, |s| -> Option<()> {
                for (i, p) in offsets.iter().enumerate() {
                    let addr: usize = self.stack_top.as_usize() + *p;
                    s[i * core::mem::size_of::<usize>()..(i + 1) * core::mem::size_of::<usize>()]
                        .copy_from_slice(&addr.to_le_bytes());
                }
                Some(())
            })?;
        Some(())
    }

    /// Initialize the stack for the new process.
    pub(super) fn init(&mut self, argv: Vec<CString>) -> Option<()> {
        // end markers
        self.pos = self.pos.checked_sub(size_of::<usize>())?;
        unsafe {
            self.stack_top
                .write_at_offset(isize::try_from(self.pos).ok()?, 0)?;
        }

        let argvp = self.push_cstrings(&argv)?;

        let align_down = |pos: usize, alignment: usize| -> usize {
            debug_assert!(alignment.is_power_of_two());
            pos & !(alignment - 1)
        };

        // ensure stack is aligned
        self.pos = align_down(self.pos, size_of::<usize>());
        // to ensure the final pos is aligned, we need to add some padding
        let len = argvp.len() + 1 + /* argc */ 1;
        let size = len * size_of::<usize>();
        let final_pos = self.pos.checked_sub(size)?;
        self.pos -= final_pos - align_down(final_pos, Self::STACK_ALIGNMENT);

        self.push_pointers(argvp)?;

        self.push_usize(argv.len())?;
        assert_eq!(self.pos, align_down(self.pos, Self::STACK_ALIGNMENT));
        Some(())
    }
}

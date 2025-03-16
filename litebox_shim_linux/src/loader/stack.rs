//! This module contains the stack layout for the user process.

use alloc::{collections::btree_map::BTreeMap, ffi::CString, vec::Vec};
use litebox::platform::{RawConstPointer, RawMutPointer};

use crate::MutPtr;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum AuxKey {
    AT_NULL = 0,      /* end of vector */
    AT_IGNORE = 1,    /* entry should be ignored */
    AT_EXECFD = 2,    /* file descriptor of program */
    AT_PHDR = 3,      /* program headers for program */
    AT_PHENT = 4,     /* size of program header entry */
    AT_PHNUM = 5,     /* number of program headers */
    AT_PAGESZ = 6,    /* system page size */
    AT_BASE = 7,      /* base address of interpreter */
    AT_FLAGS = 8,     /* flags */
    AT_ENTRY = 9,     /* entry point of program */
    AT_NOTELF = 10,   /* program is not ELF */
    AT_UID = 11,      /* real uid */
    AT_EUID = 12,     /* effective uid */
    AT_GID = 13,      /* real gid */
    AT_EGID = 14,     /* effective gid */
    AT_PLATFORM = 15, /* string identifying CPU for optimizations */
    AT_HWCAP = 16,    /* arch dependent hints at CPU capabilities */
    AT_CLKTCK = 17,   /* frequency at which times() increments */

    /* 18...22 not used */
    AT_SECURE = 23, /* secure mode boolean */
    AT_BASE_PLATFORM = 24, /* string identifying real platform, may
                     * differ from AT_PLATFORM. */
    AT_RANDOM = 25, /* address of 16 random bytes */
    AT_HWCAP2 = 26, /* extension of AT_HWCAP */

    /* 28...30 not used */
    AT_EXECFN = 31, /* filename of program */
    AT_SYSINFO = 32,
    AT_SYSINFO_EHDR = 33, /* the start address of the page containing the VDSO */
}

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
///                   [ envp[0] (pointer) ]         8
///                   [ envp[1] (pointer) ]         8
///                   [ envp[..] (pointer) ]        8 * y
///                   [ envp[term] (pointer) ]      8   (= NULL)
///
///                   [ auxv[0] (Elf64_auxv_t) ]    8
///                   [ auxv[1] (Elf64_auxv_t) ]    8
///                   [ auxv[..] (Elf64_auxv_t) ]   8 * z
///                   [ auxv[term] (Elf64_auxv_t) ] 8   (= AT_NULL vector)
///
///                   [ padding ]                   0 - 16
///
///                   [ argument ASCIIZ strings ]   >= 0
///                   [ environment ASCIIZ str. ]   >= 0
///
/// (0xbffffffc)      [ end marker ]                8   (= NULL)
///
/// (0xc0000000)      < bottom of stack >           0   (virtual)
/// ------------------------------------------------------------------------
/// ```
pub(super) struct UserStack {
    /// The top of the stack (base address)
    stack_top: MutPtr<u8>,
    /// The length of the stack
    len: usize,
    /// The current position of the stack pointer
    pos: isize,
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
            pos: isize::try_from(len).ok()?,
        })
    }

    /// Get the current stack pointer.
    pub(super) fn get_cur_stack_top(&self) -> usize {
        debug_assert!(self.pos >= 0);
        self.stack_top.as_usize() + self.pos.unsigned_abs()
    }

    /// Push `bytes` to the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        let old_pos = self.pos;
        self.pos = self.pos.checked_sub_unsigned(bytes.len())?;
        self.stack_top
            .mutate_subslice_with(self.pos..old_pos, |s| s.copy_from_slice(bytes))?;
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
    fn push_cstrings(&mut self, vals: &[CString]) -> Option<Vec<isize>> {
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
    fn push_pointers(&mut self, offsets: Vec<isize>) -> Option<()> {
        // write end marker
        self.push_usize(0)?;
        let size = offsets.len().checked_mul(size_of::<isize>())?;
        let old_pos = self.pos;
        self.pos = self.pos.checked_sub_unsigned(size)?;
        self.stack_top
            .mutate_subslice_with(self.pos..old_pos, |s| -> Option<()> {
                for (i, p) in offsets.iter().enumerate() {
                    let addr = self.stack_top.as_usize().checked_add_signed(*p)?;
                    s[i * 8..(i + 1) * 8].copy_from_slice(&addr.to_le_bytes());
                }
                Some(())
            })?;
        Some(())
    }

    /// Push a auxiliary vector to the stack.
    ///
    /// Returns `None` if stack has no enough space.
    fn push_aux(&mut self, aux: BTreeMap<AuxKey, usize>) -> Option<()> {
        // write end marker
        self.push_usize(0)?;
        self.push_usize(AuxKey::AT_NULL as usize)?;
        for (key, val) in aux {
            self.push_usize(val)?;
            self.push_usize(key as usize)?;
        }
        Some(())
    }

    fn align_down(pos: isize, alignment: usize) -> isize {
        assert!(alignment.is_power_of_two());
        pos & !isize::try_from(alignment - 1).unwrap()
    }

    fn get_random_value() -> [u8; 16] {
        // TODO: generate a random value
        [
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
            0xBE, 0xEF,
        ]
    }

    /// Initialize the stack for the new process.
    pub(super) fn init(
        &mut self,
        argv: Vec<CString>,
        env: Vec<CString>,
        mut aux: BTreeMap<AuxKey, usize>,
    ) -> Option<()> {
        // end markers
        self.pos = self.pos.checked_sub_unsigned(size_of::<usize>())?;
        unsafe {
            self.stack_top.write_at_offset(self.pos, 0)?;
        }

        let envp = self.push_cstrings(&env)?;
        let argvp = self.push_cstrings(&argv)?;

        self.push_bytes(&Self::get_random_value())?;
        aux.insert(
            AuxKey::AT_RANDOM,
            self.stack_top.as_usize().checked_add_signed(self.pos)?,
        );

        // ensure stack is aligned
        self.pos = Self::align_down(self.pos, size_of::<usize>());
        // to ensure the final pos is aligned, we need to add some padding
        let len = (aux.len() + 1) * 2 + envp.len() + 1 + argvp.len() + 1 + /* argc */ 1;
        let size = len * size_of::<usize>();
        let final_pos = self.pos.checked_sub_unsigned(size)?;
        self.pos -= final_pos - Self::align_down(final_pos, Self::STACK_ALIGNMENT);

        self.push_aux(aux)?;
        self.push_pointers(envp)?;
        self.push_pointers(argvp)?;

        self.push_usize(argv.len())?;
        assert_eq!(self.pos, Self::align_down(self.pos, Self::STACK_ALIGNMENT));
        Some(())
    }
}

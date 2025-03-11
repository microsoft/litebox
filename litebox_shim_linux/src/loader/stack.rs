use alloc::{collections::btree_map::BTreeMap, ffi::CString, vec::Vec};
use litebox::platform::RawMutPointer;

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

pub(super) struct UserStack {
    stack_top_vaddr: usize,
}

impl UserStack {
    /// Stack alignment required by libc ABI
    const STACK_ALIGNMENT: usize = 16;

    /// stack_top must be aligned to [`Self::STACK_ALIGNMENT`] bytes
    pub fn new(stack_top_vaddr: usize) -> Self {
        Self { stack_top_vaddr }
    }

    fn write_bytes(&self, bytes: &[u8], pos: isize) -> Option<isize> {
        let len = bytes.len() as isize;
        let new_pos = pos - len;
        let stack_top = MutPtr::<u8>::from(self.stack_top_vaddr);
        stack_top.mutate_subslice_with(new_pos..pos, |s| s.copy_from_slice(bytes))?;
        Some(new_pos)
    }

    fn write_cstring(&self, val: &CString, pos: isize) -> Option<isize> {
        let bytes = val.as_bytes_with_nul();
        self.write_bytes(bytes, pos)
    }

    fn write_cstrings(&self, vals: &[CString], pos: isize) -> Option<(isize, Vec<isize>)> {
        let mut envp = Vec::with_capacity(vals.len());
        let mut new_pos = pos;
        for val in vals.iter() {
            new_pos = self.write_cstring(val, new_pos)?;
            envp.push(new_pos);
        }
        Some((new_pos, envp))
    }

    fn write_pointers(&self, offsets: Vec<isize>, pos: isize) -> Option<isize> {
        // write end marker
        let pos = self.write_bytes(&0isize.to_le_bytes(), pos)?;
        let len = offsets.len();
        let new_pos = pos - (len * size_of::<isize>()) as isize;
        let stack_top = MutPtr::<u8>::from(self.stack_top_vaddr);
        stack_top.mutate_subslice_with(new_pos..pos, |s| {
            for (i, p) in offsets.iter().enumerate() {
                let addr = self.stack_top_vaddr as isize + *p;
                s[i * 8..(i + 1) * 8].copy_from_slice(&addr.to_le_bytes());
            }
        })?;
        Some(new_pos)
    }

    fn write_aux(&self, aux: BTreeMap<AuxKey, usize>, pos: isize) -> Option<isize> {
        // write end marker
        let pos = self.write_bytes(&0usize.to_le_bytes(), pos)?;
        let pos = self.write_bytes(&(AuxKey::AT_NULL as usize).to_le_bytes(), pos)?;
        let mut new_pos = pos;
        for (key, val) in aux.iter() {
            new_pos = self.write_bytes(&val.to_le_bytes(), new_pos)?;
            new_pos = self.write_bytes(&(*key as usize).to_le_bytes(), new_pos)?;
        }
        Some(new_pos)
    }

    fn align_down(pos: isize, alignment: usize) -> isize {
        assert!(alignment.is_power_of_two());
        pos & !(alignment - 1) as isize
    }

    fn get_random_value(&self) -> [u8; 16] {
        [
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
            0xBE, 0xEF,
        ]
    }

    pub fn init(
        &self,
        argv: Vec<CString>,
        env: Vec<CString>,
        mut aux: BTreeMap<AuxKey, usize>,
    ) -> Option<isize> {
        let pos: isize = -8;
        // end markers
        let stack_top = MutPtr::<u8>::from(self.stack_top_vaddr);
        unsafe {
            stack_top.write_at_offset(pos, 0)?;
        }

        let (pos, envp) = self.write_cstrings(&env, pos)?;
        let (pos, argvp) = self.write_cstrings(&argv, pos)?;

        let pos = self.write_bytes(&self.get_random_value(), pos)?;
        aux.insert(
            AuxKey::AT_RANDOM,
            (self.stack_top_vaddr as isize + pos) as usize,
        );

        // ensure stack is aligned
        let pos = Self::align_down(pos, 8);
        // assert_eq!(pos, 0);
        let len = (aux.len() + 1) * 2 + envp.len() + 1 + argvp.len() + 1 + /* argc */ 1;
        let size = len * size_of::<usize>();
        let final_pos = pos - size as isize;
        let new_pos =
            pos - (final_pos - Self::align_down(final_pos, Self::STACK_ALIGNMENT)) as isize;

        let new_pos = self.write_aux(aux, new_pos)?;
        let new_pos = self.write_pointers(envp, new_pos)?;
        let new_pos = self.write_pointers(argvp, new_pos)?;

        let new_pos = self.write_bytes(&argv.len().to_le_bytes(), new_pos)?;
        assert_eq!(new_pos, Self::align_down(new_pos, Self::STACK_ALIGNMENT));
        Some(new_pos)
    }
}

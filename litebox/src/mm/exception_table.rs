use crate::utils::ReinterpretUnsignedExt;

core::arch::global_asm!(
    r#"
    .section .ex_table, "a"
    .align 8
    .global __ex_table_start
    __ex_table_start:
"#
);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("memcpy_fallible_64.S"));
#[cfg(target_arch = "x86")]
core::arch::global_asm!(include_str!("memcpy_fallible_32.S"));

// IMPORTANT: This __ex_table_end marker must be placed AFTER all assembly files
// that use `.pushsection .ex_table` to add exception table entries.
core::arch::global_asm!(
    r#"
    .section .ex_table, "a"
    .global __ex_table_end
    __ex_table_end:
"#
);

unsafe extern "C" {
    /// Copies `size` bytes from `src` to `dst`. This function works with exception handling
    /// and can recover from page fault.
    /// Returns number of bytes that failed to copy.
    pub fn __memcpy_fallible(dst: *mut u8, src: *const u8, size: usize) -> usize;

    static __ex_table_start: [ExceptionTableEntry; 0];
    static __ex_table_end: [ExceptionTableEntry; 0];
}

/// Exception table entry with relative offsets
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ExceptionTableEntry {
    /// Relative offset from this field to the faulting instruction
    insn_offset: i32,
    /// Relative offset from this field to the recovery instruction
    fixup_offset: i32,
}

impl ExceptionTableEntry {
    /// Get the absolute address of the faulting instruction
    fn insn_addr(&self) -> usize {
        let base_addr = core::ptr::addr_of!(self.insn_offset) as usize;
        base_addr
            .checked_add_signed(self.insn_offset as isize)
            .unwrap()
    }

    /// Get the absolute address of the recovery instruction
    fn fixup_addr(&self) -> usize {
        let base_addr = core::ptr::addr_of!(self.fixup_offset) as usize;
        base_addr
            .checked_add_signed(self.fixup_offset as isize)
            .unwrap()
    }
}

/// Search the exception table for a matching instruction address.
/// If found, returns the corresponding recovery address.
pub fn search_exception_tables(addr: usize) -> Option<usize> {
    unsafe {
        let start = (&raw const __ex_table_start).cast::<ExceptionTableEntry>();
        let end = (&raw const __ex_table_end).cast::<ExceptionTableEntry>();

        let entries = end.offset_from(start).reinterpret_as_unsigned();
        if entries == 0 {
            return None;
        }

        let table = core::slice::from_raw_parts(start, entries);

        for entry in table {
            let insn_addr = entry.insn_addr();

            if addr == insn_addr {
                return Some(entry.fixup_addr());
            }
        }

        None
    }
}

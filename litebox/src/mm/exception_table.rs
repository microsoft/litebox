//! Exception Table Infrastructure
//!
//! This module provides the core exception table mechanism used by fallible
//! memory operations.
//!
//! ## Architecture
//!
//! The exception table works by:
//! 1. Assembly code marks potentially faulting instructions with entries in `.ex_table`
//! 2. Each entry maps a faulting instruction address to a recovery address
//! 3. Signal/exception handlers use [`search_exception_tables`] to look up recovery points
//! 4. If found, execution is redirected to allow graceful failure handling
//!
//! New fallible functions should follow the pattern established by [`memcpy_fallible`].

use crate::utils::TruncateExt as _;

#[cfg(any(target_os = "linux", target_os = "none"))]
macro_rules! ex_table_section {
    () => {
        // a = allocate, R = retain: don't discard on linking.
        "ex_table,\"aR\""
    };
}

#[cfg(target_os = "windows")]
macro_rules! ex_table_section {
    () => {
        // d = data, r = read-only
        ".extable,\"dr\""
    };
}

macro_rules! ex_table_entry {
    ($start:tt, $stop:tt, $recover:tt) => {
        concat!(
            ".pushsection ",
            ex_table_section!(),
            "\n",
            ".balign 4\n",
            ".long ",
            $start,
            " - .\n",
            ".long ",
            $stop,
            " - .\n",
            ".long ",
            $recover,
            " - .\n",
            ".popsection"
        )
    };
}

/// Represents a fault during a fallible memory operation.
pub struct Fault;

/// Copies `size` bytes from `src` to `dst` in a fallible manner.
///
/// This function can recover from memory access exceptions (e.g., page faults,
/// SIGSEGV) when proper exception handling is set up by the platform.
///
/// For details on how fallible memory access works and platform requirements,
/// see [`crate::platform::common_providers::userspace_pointers`].
///
/// # Safety
/// `dst` and `src` must be valid for reads and writes of `size` bytes, or
/// pointers that are guaranteed to be in non-Rust memory.
pub unsafe fn memcpy_fallible(dst: *mut u8, src: *const u8, size: usize) -> Result<(), Fault> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm! {
            "2:",
            "rep movsb",
            "3:",
            ex_table_entry!("2b", "3b", "{fault}"),
            inout("di") dst => _,
            inout("si") src => _,
            inout("cx") size => _,
            fault = label { return Err(Fault) }
        }
    }
    // LLVM on x86 does not allow using `esi` as an asm operand register. Save
    // and restore it manually.
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm! {
            "2:",
            "xchg esi, eax",
            "rep movsb",
            "3:",
            "mov esi, eax",
            ex_table_entry!("2b", "3b", "{fault}"),
            inout("di") dst => _,
            inout("ax") src => _,
            inout("cx") size => _,
            fault = label { return Err(Fault) }
        }
    }
    Ok(())
}

macro_rules! read_fn {
    ($name:ident, $ty:ty, $mov_instr:expr) => {
        /// Reads a value from the given `src` pointer in a fallible manner.
        ///
        /// # Safety
        /// `src` must be valid for reads or a pointer that's guaranteed to be
        /// in non-Rust memory.
        pub unsafe fn $name(src: *const $ty) -> Result<$ty, Fault> {
            let value: usize;
            let failed: u32;
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            unsafe {
                core::arch::asm! {
                    "2:",
                    $mov_instr,
                    "xor {failed:e}, {failed:e}",
                    "3:",
                    ex_table_entry!("2b", "3b", "3b"),
                    src = in(reg) src,
                    dest = out(reg) value,
                    failed = inout(reg) 1 => failed,
                }
            }
            if failed == 0 {
                Ok((value as u64).truncate())
            } else {
                Err(Fault)
            }
        }
    };
}

read_fn!(read_u8_fallible, u8, "movzx {dest:e}, byte ptr [{src}]");
read_fn!(read_u16_fallible, u16, "movzx {dest:e}, word ptr [{src}]");
read_fn!(read_u32_fallible, u32, "mov {dest:e}, dword ptr [{src}]");
#[cfg(target_pointer_width = "64")]
read_fn!(read_u64_fallible, u64, "mov {dest:r}, qword ptr [{src}]");

macro_rules! write_fn {
    ($name:ident, $ty:ty, $mov_instr:expr) => {
        /// Writes a value to the given `dest` pointer in a fallible manner.
        ///
        /// # Safety
        /// `dest` must be valid for writes or a pointer that's guaranteed to be
        /// in non-Rust memory.
        pub unsafe fn $name(dest: *mut $ty, value: $ty) -> Result<(), Fault> {
            let value: usize = (u64::from(value)).truncate();
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            unsafe {
                core::arch::asm! {
                    "2:",
                    $mov_instr,
                    "3:",
                    ex_table_entry!("2b", "3b", "{fault}"),
                    src = in(reg) value,
                    dest = in(reg) dest,
                    fault = label { return Err(Fault) }
                }
            }
            Ok(())
        }
    };
}

#[cfg(target_arch = "x86_64")]
write_fn!(write_u8_fallible, u8, "mov byte ptr [{dest}], {src:l}");
write_fn!(write_u16_fallible, u16, "mov word ptr [{dest}], {src:x}");
write_fn!(write_u32_fallible, u32, "mov dword ptr [{dest}], {src:e}");
#[cfg(target_pointer_width = "64")]
write_fn!(write_u64_fallible, u64, "mov qword ptr [{dest}], {src:r}");

/// Writes a value to the given `dest` pointer in a fallible manner.
///
/// # Safety
/// `dest` must be valid for writes or a pointer that's guaranteed to be
/// in non-Rust memory.
//
// Special case instead of the macro since 32 bit cannot use `reg` for 8-bit
// values.
#[cfg(target_arch = "x86")]
pub unsafe fn write_u8_fallible(dest: *mut u8, value: u8) -> Result<(), Fault> {
    unsafe {
        core::arch::asm! {
            "2:",
            "mov byte ptr [{dest}], {src}",
            "3:",
            ex_table_entry!("2b", "3b", "{fault}"),
            src = in(reg_byte) value,
            dest = in(reg) dest,
            fault = label { return Err(Fault) }
        }
    }
    Ok(())
}

/// Exception table entry with relative offsets
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ExceptionTableEntry {
    start: i32,
    stop: i32,
    fixup: i32,
}

/// Returns the exception table, found by linker-defined symbols marking the
/// start and end of the section.
#[cfg(any(target_os = "linux", target_os = "none"))]
fn exception_table() -> &'static [ExceptionTableEntry] {
    // SAFETY: the linker automatically defines these symbols when the section
    // is non-empty.
    unsafe extern "C" {
        #[link_name = "__start_ex_table"]
        static START_EX_TABLE: [ExceptionTableEntry; 0];
        #[link_name = "__stop_ex_table"]
        static STOP_EX_TABLE: [ExceptionTableEntry; 0];
    }

    // Ensure the section exists even if there no recovery descriptors get
    // generated.
    //
    // SAFETY: just a no-op asm block to force the section to be created.
    unsafe {
        core::arch::asm!(concat!(
            ".pushsection ",
            ex_table_section!(),
            "\n",
            ".popsection"
        ));
    }

    // SAFETY: accessing the section as defined above.
    unsafe {
        core::slice::from_raw_parts(
            START_EX_TABLE.as_ptr(),
            STOP_EX_TABLE
                .as_ptr()
                .offset_from_unsigned(START_EX_TABLE.as_ptr()),
        )
    }
}

/// Returns the exception table, found by finding the .section via the PE
/// headers.
///
/// The more typical way to do this on Windows is to use the grouping feature of
/// the linker to create symbols marking the start and end of the section, via
/// something like `.ex_table$a` and `.ex_table$z`, with the elements in between
/// in `.ex_table$b`.
///
/// However, Rust/LLVM inline asm (but not global asm) seems to drop the '$', so
/// this doesn't work. So, we use a different technique.
#[cfg(windows)]
#[expect(clippy::cast_ptr_alignment)]
fn exception_table() -> &'static [ExceptionTableEntry] {
    use crate::utils::ReinterpretUnsignedExt as _;

    /// Find a PE section by name.
    fn find_section(name: [u8; 8]) -> Option<(*const u8, usize)> {
        use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
        use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
        use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

        unsafe extern "C" {
            safe static __ImageBase: IMAGE_DOS_HEADER;
        }

        let dos_header = &__ImageBase;
        let base_ptr = &raw const __ImageBase;
        // SAFETY: the current module must have valid PE headers.
        let pe = unsafe {
            &*base_ptr
                .byte_add(dos_header.e_lfanew.reinterpret_as_unsigned() as usize)
                .cast::<IMAGE_NT_HEADERS64>()
        };
        let number_of_sections: usize = pe.FileHeader.NumberOfSections.into();

        // SAFETY: the section table is laid out in memory according to the PE format.
        let sections = unsafe {
            let base = (&raw const pe.OptionalHeader)
                .byte_add(pe.FileHeader.SizeOfOptionalHeader.into())
                .cast::<IMAGE_SECTION_HEADER>();
            core::slice::from_raw_parts(base, number_of_sections)
        };

        sections.iter().find_map(|section| {
            (section.Name == name).then_some({
                // SAFETY: section data is valid according to the PE format.
                unsafe {
                    (
                        base_ptr.byte_add(section.VirtualAddress as usize).cast(),
                        section.Misc.VirtualSize as usize,
                    )
                }
            })
        })
    }

    let Some((start, len)) = find_section(*b".extable") else {
        // No recovery descriptors.
        return &[];
    };
    assert_eq!(len % size_of::<ExceptionTableEntry>(), 0);
    // SAFETY: this section is made up solely of ExceptionTableEntry entries.
    unsafe {
        core::slice::from_raw_parts(
            start.cast::<ExceptionTableEntry>(),
            len / size_of::<ExceptionTableEntry>(),
        )
    }
}

/// Search the exception table for a matching instruction address.
/// If found, returns the corresponding recovery address.
pub fn search_exception_tables(addr: usize) -> Option<usize> {
    let table = exception_table();
    let reloc = |addr: &i32| -> usize {
        let base = &raw const *addr as usize;
        base.wrapping_add_signed(*addr as isize)
    };
    for entry in table {
        let start = reloc(&entry.start);
        let stop = reloc(&entry.stop);
        if addr >= start && addr < stop {
            return Some(reloc(&entry.fixup));
        }
    }
    None
}

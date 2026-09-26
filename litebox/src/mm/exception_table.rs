// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

#[cfg(target_vendor = "apple")]
macro_rules! ex_table_section {
    () => {
        // Mach-O spells a section as `segment,section[,type[,attributes]]`.
        // `__TEXT` keeps the table read-only (the entries are link-time-resolved
        // relative offsets, so no runtime relocation is needed), matching where
        // the platform ABI already puts `__gcc_except_tab`. `no_dead_strip` is
        // the Mach-O counterpart of ELF's `R` (retain) flag: the entries carry
        // no symbol of their own, so without it the linker would drop them.
        "__TEXT,__ex_table,regular,no_dead_strip"
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
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // Bulk-copy 16 bytes at a time via ldp/stp, then a byte tail for the
        // remaining 0..15 bytes. aarch64 permits unaligned access on normal
        // memory, so no alignment prologue is needed.
        //
        // Every faulting load/store must be covered by the [2:, 3:) exception
        // table range; non-memory instructions (cmp/sub/branch) within the
        // range never fault. On fault, the partially-copied destination is
        // observable to the caller, matching the x86_64 `rep movsb` behavior.
        core::arch::asm! {
            "2:",
            "cmp {size}, #16",
            "b.lo 20f",
            // 16-byte chunk loop.
            "30:",
            "ldp {t1}, {t2}, [{src}], #16",
            "stp {t1}, {t2}, [{dst}], #16",
            "sub {size}, {size}, #16",
            "cmp {size}, #16",
            "b.hs 30b",
            // Byte tail (0..15 bytes remaining).
            "20:",
            "cbz {size}, 3f",
            "21:",
            "ldrb {t1:w}, [{src}], #1",
            "strb {t1:w}, [{dst}], #1",
            "subs {size}, {size}, #1",
            "b.ne 21b",
            "3:",
            ex_table_entry!("2b", "3b", "{fault}"),
            dst = inout(reg) dst => _,
            src = inout(reg) src => _,
            size = inout(reg) size => _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            fault = label { return Err(Fault) }
        }
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
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
            #[cfg(target_arch = "x86_64")]
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
            // FUTURE: use a `label` like with the write functions once Rust
            // supports them with `out` operands.
            if failed == 0 {
                Ok((value as u64).trunc())
            } else {
                Err(Fault)
            }
        }
    };
}

#[cfg(target_arch = "x86_64")]
read_fn!(read_u8_fallible, u8, "movzx {dest:e}, byte ptr [{src}]");
#[cfg(target_arch = "x86_64")]
read_fn!(read_u16_fallible, u16, "movzx {dest:e}, word ptr [{src}]");
#[cfg(target_arch = "x86_64")]
read_fn!(read_u32_fallible, u32, "mov {dest:e}, dword ptr [{src}]");
#[cfg(target_arch = "x86_64")]
read_fn!(read_u64_fallible, u64, "mov {dest:r}, qword ptr [{src}]");

#[cfg(target_arch = "aarch64")]
macro_rules! read_fn {
    ($name:ident, $ty:ty, $load_instr:expr) => {
        /// Reads a value from the given `src` pointer in a fallible manner.
        ///
        /// # Safety
        /// `src` must be valid for reads or a pointer that's guaranteed to be
        /// in non-Rust memory.
        pub unsafe fn $name(src: *const $ty) -> Result<$ty, Fault> {
            let value: usize;
            let failed: u32;
            unsafe {
                core::arch::asm! {
                    "2:",
                    $load_instr,
                    "mov {failed:w}, wzr",
                    "3:",
                    ex_table_entry!("2b", "3b", "3b"),
                    src = in(reg) src,
                    dest = out(reg) value,
                    failed = inout(reg) 1u32 => failed,
                }
            }
            if failed == 0 {
                Ok((value as u64).trunc())
            } else {
                Err(Fault)
            }
        }
    };
}

#[cfg(target_arch = "aarch64")]
read_fn!(read_u8_fallible, u8, "ldrb {dest:w}, [{src}]");
#[cfg(target_arch = "aarch64")]
read_fn!(read_u16_fallible, u16, "ldrh {dest:w}, [{src}]");
#[cfg(target_arch = "aarch64")]
read_fn!(read_u32_fallible, u32, "ldr {dest:w}, [{src}]");
#[cfg(target_arch = "aarch64")]
read_fn!(read_u64_fallible, u64, "ldr {dest}, [{src}]");

#[cfg(target_arch = "x86_64")]
macro_rules! write_fn {
    ($name:ident, $ty:ty, $mov_instr:expr) => {
        /// Writes a value to the given `dest` pointer in a fallible manner.
        ///
        /// # Safety
        /// `dest` must be valid for writes or a pointer that's guaranteed to be
        /// in non-Rust memory.
        pub unsafe fn $name(dest: *mut $ty, value: $ty) -> Result<(), Fault> {
            let value: usize = (u64::from(value)).trunc();
            #[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
write_fn!(write_u16_fallible, u16, "mov word ptr [{dest}], {src:x}");
#[cfg(target_arch = "x86_64")]
write_fn!(write_u32_fallible, u32, "mov dword ptr [{dest}], {src:e}");
#[cfg(target_arch = "x86_64")]
write_fn!(write_u64_fallible, u64, "mov qword ptr [{dest}], {src:r}");

#[cfg(target_arch = "aarch64")]
macro_rules! write_fn {
    ($name:ident, $ty:ty, $store_instr:expr, $convert:expr) => {
        /// Writes a value to the given `dest` pointer in a fallible manner.
        ///
        /// # Safety
        /// `dest` must be valid for writes or a pointer that's guaranteed to be
        /// in non-Rust memory.
        pub unsafe fn $name(dest: *mut $ty, value: $ty) -> Result<(), Fault> {
            unsafe {
                core::arch::asm! {
                    "2:",
                    $store_instr,
                    "3:",
                    ex_table_entry!("2b", "3b", "{fault}"),
                    src = in(reg) $convert(value),
                    dest = in(reg) dest,
                    fault = label { return Err(Fault) }
                }
            }
            Ok(())
        }
    };
}

#[cfg(target_arch = "aarch64")]
write_fn!(write_u8_fallible, u8, "strb {src:w}, [{dest}]", u32::from);
#[cfg(target_arch = "aarch64")]
write_fn!(write_u16_fallible, u16, "strh {src:w}, [{dest}]", u32::from);
#[cfg(target_arch = "aarch64")]
write_fn!(
    write_u32_fallible,
    u32,
    "str {src:w}, [{dest}]",
    core::convert::identity
);
#[cfg(target_arch = "aarch64")]
write_fn!(
    write_u64_fallible,
    u64,
    "str {src}, [{dest}]",
    core::convert::identity
);

/// Atomically compares and conditionally exchanges a `u32` in fallible guest memory.
///
/// The outer `Result` reports a memory fault. The inner result matches
/// [`core::sync::atomic::AtomicU32::compare_exchange`]: `Ok(previous)` on exchange and
/// `Err(actual)` on comparison failure.
///
/// # Safety
/// `dest` must be aligned and valid for a `u32` atomic access, or point into non-Rust memory whose
/// faults are handled through this module's exception table.
#[cfg(target_arch = "x86_64")]
pub unsafe fn compare_exchange_u32_fallible(
    dest: *mut u32,
    current: u32,
    new: u32,
) -> Result<Result<u32, u32>, Fault> {
    let mut observed = current;
    let mut exchanged = 0u8;
    let mut faulted = 0u8;
    unsafe {
        core::arch::asm! {
            "2:",
            "lock cmpxchg dword ptr [{dest}], {new:e}",
            "sete {exchanged}",
            "jmp 4f",
            "3:",
            "mov {faulted}, 1",
            "4:",
            ex_table_entry!("2b", "3b", "3b"),
            dest = in(reg) dest,
            new = in(reg) new,
            inout("eax") observed,
            exchanged = inout(reg_byte) exchanged,
            faulted = inout(reg_byte) faulted,
        }
    }
    if faulted != 0 {
        return Err(Fault);
    }
    Ok(if exchanged != 0 {
        Ok(observed)
    } else {
        Err(observed)
    })
}

/// Atomically compares and conditionally exchanges a `u32` in fallible guest memory.
///
/// See the x86-64 implementation for the contract.
///
/// # Safety
/// Same requirements as the x86-64 implementation.
#[cfg(target_arch = "aarch64")]
pub unsafe fn compare_exchange_u32_fallible(
    dest: *mut u32,
    current: u32,
    new: u32,
) -> Result<Result<u32, u32>, Fault> {
    let mut observed = current;
    let mut exchanged = 0u32;
    let mut status = 0u32;
    let mut faulted = 0u32;
    unsafe {
        core::arch::asm! {
            "2:",
            "ldaxr {observed:w}, [{dest}]",
            "cmp {observed:w}, {current:w}",
            "b.ne 4f",
            "stlxr {status:w}, {new:w}, [{dest}]",
            "cbnz {status:w}, 2b",
            "mov {exchanged:w}, #1",
            "b 3f",
            "4:",
            "clrex",
            "mov {exchanged:w}, wzr",
            "3:",
            "b 6f",
            "5:",
            "clrex",
            "mov {faulted:w}, #1",
            "6:",
            ex_table_entry!("2b", "3b", "5b"),
            dest = in(reg) dest,
            current = in(reg) current,
            new = in(reg) new,
            observed = inout(reg) observed,
            exchanged = inout(reg) exchanged,
            status = inout(reg) status,
            faulted = inout(reg) faulted,
        }
    }
    let _ = status;
    if faulted != 0 {
        return Err(Fault);
    }
    Ok(if exchanged != 0 {
        Ok(observed)
    } else {
        Err(observed)
    })
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

/// Returns the exception table, found by locating the Mach-O section through
/// the current image's load commands.
///
/// Mach-O has no linker-synthesized `__start_`/`__stop_` pair for an arbitrary
/// section, so the table is located the same way the Windows path locates its
/// PE section: from the image headers at runtime. `__dso_handle` is the Mach-O
/// header of the image this code was linked into, and `getsectiondata` walks
/// its load commands and applies the slide.
#[cfg(target_vendor = "apple")]
#[expect(clippy::cast_ptr_alignment)]
fn exception_table() -> &'static [ExceptionTableEntry] {
    unsafe extern "C" {
        /// This image's Mach-O header. Rust prefixes Mach-O symbols with `_`,
        /// so this resolves to `___dso_handle`, the symbol the linker
        /// synthesizes for every image.
        static __dso_handle: u8;

        /// `<mach-o/getsect.h>`: yields the in-memory address (slide applied)
        /// and size of `segname,sectname` within the image at `mhp`, or null
        /// when the image has no such section.
        ///
        /// The real signature takes `mhp: *const mach_header_64`; it is opaque
        /// here (never dereferenced, only its address is taken and passed
        /// through) since a pointer is a single machine word at the FFI
        /// boundary regardless of pointee type, and this crate has no need to
        /// otherwise model the Mach-O header layout.
        fn getsectiondata(
            mhp: *const core::ffi::c_void,
            segname: *const core::ffi::c_char,
            sectname: *const core::ffi::c_char,
            size: *mut core::ffi::c_ulong,
        ) -> *mut u8;
    }

    // Ensure the section exists even if no recovery descriptors get generated.
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

    let mut size: core::ffi::c_ulong = 0;
    // SAFETY: `__dso_handle` is this image's Mach-O header, both names are
    // NUL-terminated, and `getsectiondata` only reads the image's load
    // commands. It reports a null base for an absent section.
    let start = unsafe {
        getsectiondata(
            (&raw const __dso_handle).cast::<core::ffi::c_void>(),
            c"__TEXT".as_ptr(),
            c"__ex_table".as_ptr(),
            &raw mut size,
        )
    };
    if start.is_null() {
        // No recovery descriptors.
        return &[];
    }
    let size = usize::try_from(size).expect("a section is never larger than the address space");
    assert_eq!(size % size_of::<ExceptionTableEntry>(), 0);
    // SAFETY: this section is made up solely of `ExceptionTableEntry` entries,
    // each `.balign 4`-ed by `ex_table_entry!` to the type's alignment.
    unsafe {
        core::slice::from_raw_parts(
            start.cast::<ExceptionTableEntry>(),
            size / size_of::<ExceptionTableEntry>(),
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
    search_in(exception_table(), addr)
}

/// The pure relocation/interval-comparison logic behind
/// [`search_exception_tables`], parameterized on the table instead of reading
/// it from the linker-defined section.
///
/// Split out so it can be exercised against a synthetic table in tests: the
/// real [`exception_table`] involves an inline-asm section lookup that has no
/// meaning outside a real process image, but the relocation arithmetic here is
/// ordinary integer math with no such dependency.
fn search_in(table: &[ExceptionTableEntry], addr: usize) -> Option<usize> {
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

#[cfg(test)]
mod search_in_tests {
    use super::{ExceptionTableEntry, search_in};

    const ZERO_ENTRY: ExceptionTableEntry = ExceptionTableEntry {
        start: 0,
        stop: 0,
        fixup: 0,
    };

    /// Rewrites `table[index]` in place to cover `[fault_addr, fault_addr + 1)`
    /// with fixup `recovery_addr`, using the same self-relative encoding real
    /// entries use (an `i32` offset from each field's own address).
    ///
    /// Must be called on a table that has already settled into its final
    /// storage location and will not be moved again afterward -- the encoded
    /// offsets are only valid relative to where the entry actually lives when
    /// [`search_in`] later decodes them, exactly as for a real entry emitted by
    /// the assembly macro into a fixed section.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "test helper: callers keep fault_addr/recovery_addr within i32 range of the \
                  table's own address, exactly as the real PC-relative encoding requires"
    )]
    fn encode_entry(
        table: &mut [ExceptionTableEntry],
        index: usize,
        fault_addr: usize,
        recovery_addr: usize,
    ) {
        let start_addr = core::ptr::addr_of!(table[index].start) as usize;
        let stop_addr = core::ptr::addr_of!(table[index].stop) as usize;
        let fixup_addr = core::ptr::addr_of!(table[index].fixup) as usize;
        table[index].start = (fault_addr as isize - start_addr as isize) as i32;
        // A one-instruction-wide range: [fault_addr, fault_addr + 1).
        table[index].stop = (fault_addr as isize + 1 - stop_addr as isize) as i32;
        table[index].fixup = (recovery_addr as isize - fixup_addr as isize) as i32;
    }

    // The real encoding is PC-relative with an `i32` (roughly +-2 GiB) range,
    // which is always satisfied in a real binary (an entry and the code/data
    // it refers to live in the same image). Synthetic fault/recovery
    // addresses must respect the same constraint, so every test derives them
    // as small offsets from the table's own real address rather than
    // arbitrary constants -- an arbitrary constant like `0x1000` can be
    // billions of bytes away from a real stack address and silently overflow
    // the `i32` encoding.
    fn addr_of_table(table: &[ExceptionTableEntry]) -> usize {
        table.as_ptr() as usize
    }

    #[test]
    fn finds_recovery_address_inside_range() {
        let mut table = [ZERO_ENTRY];
        let base = addr_of_table(&table);
        encode_entry(&mut table, 0, base + 0x100, base + 0x200);
        assert_eq!(search_in(&table, base + 0x100), Some(base + 0x200));
    }

    #[test]
    fn misses_just_below_range() {
        let mut table = [ZERO_ENTRY];
        let base = addr_of_table(&table);
        encode_entry(&mut table, 0, base + 0x100, base + 0x200);
        assert_eq!(search_in(&table, base + 0x0ff), None);
    }

    #[test]
    fn misses_at_the_exclusive_upper_bound() {
        // The range is [start, stop), so stop itself (fault_addr + 1 here) is
        // not covered.
        let mut table = [ZERO_ENTRY];
        let base = addr_of_table(&table);
        encode_entry(&mut table, 0, base + 0x100, base + 0x200);
        assert_eq!(search_in(&table, base + 0x101), None);
    }

    #[test]
    fn empty_table_never_matches() {
        assert_eq!(search_in(&[], 0x1000), None);
    }

    #[test]
    fn later_entry_matches_when_earlier_entries_miss() {
        let mut table = [ZERO_ENTRY, ZERO_ENTRY];
        let base = addr_of_table(&table);
        encode_entry(&mut table, 0, base + 0x100, base + 0xa000);
        encode_entry(&mut table, 1, base + 0x200, base + 0xb000);
        assert_eq!(search_in(&table, base + 0x200), Some(base + 0xb000));
    }
}

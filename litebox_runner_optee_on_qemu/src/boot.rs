// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PVH boot (`qemu -kernel`).
//!
//! On entry to [`crate::kernel_start`]: long mode, interrupts off, running at
//! `PA + KERNEL_OFFSET` with the low 4 GiB mapped read/write there,
//! relocations applied, on the boot stack in the scratch region. The linker
//! script must define `_memory_base`, `_rela_start` and `_rela_end`.

use arrayvec::{ArrayString, ArrayVec};
use core::arch::global_asm;
use litebox_platform_vm_kernel::KERNEL_OFFSET;
use zerocopy::FromBytes;

/// A half-open physical range `[start, end)`.
#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}

// Boot fails rather than dropping entries beyond these limits.
pub const MAX_RAM_REGIONS: usize = 32;
pub const MAX_RESERVED: usize = 16;
pub const MAX_MODULES: usize = 8;
pub const MAX_CMDLINE: usize = 1024;

pub struct BootInfo {
    /// Usable RAM from the memory map, not clamped to `mapped_limit`.
    pub usable: ArrayVec<Range, MAX_RAM_REGIONS>,
    /// Boot structures and modules inside `usable` that must not reach the heap.
    pub reserved: ArrayVec<Range, MAX_RESERVED>,
    /// Boot modules (`-initrd`), in order.
    pub modules: ArrayVec<Range, MAX_MODULES>,
    pub cmdline: ArrayString<MAX_CMDLINE>,
    /// Physical memory below this is mapped at `PA + KERNEL_OFFSET` on entry.
    pub mapped_limit: u64,
}

impl BootInfo {
    pub fn cmdline_value(&self, key: &str) -> Option<&str> {
        self.cmdline.split_ascii_whitespace().find_map(|arg| {
            arg.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
        })
    }
}

/// Physical address of `_start`; must match the linker script.
const PVH_ENTRY_ADDR: u32 = 0x0020_0000;

/// ELF note type that makes QEMU boot the image via PVH.
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

/// `KERNEL_OFFSET` must be 512 GiB aligned so the identity map and the
/// alias can share one PDPT and its PDs.
const KERNEL_PML4_INDEX: u32 = ((KERNEL_OFFSET >> 39) & 0x1FF) as u32;
const _: () = assert!(KERNEL_OFFSET.trailing_zeros() >= 39);

/// Page directories (1 GiB of 2 MiB pages each) in the early page tables.
const PD_COUNT: u32 = 4;
const PD_ENTRIES: u32 = PD_COUNT * 512;
/// Covers every address PVH hands over (all are 32-bit).
pub const MAPPED_LIMIT: u64 = 1 << 32;

/// Must match `.boot_scratch` in the linker script. Everything below lives
/// there; the region is `NOLOAD`, so the stub initializes what it uses.
const BOOT_SCRATCH_BASE: u32 = 0x0100_0000;
const OFF_PML4: u32 = 0x0000;
const OFF_PDPT: u32 = 0x1000;
/// [`PD_COUNT`] contiguous page directories.
const OFF_PD: u32 = 0x2000;
const OFF_GDT: u32 = OFF_PD + PD_COUNT * 0x1000;
const OFF_GDTR: u32 = OFF_GDT + 0x20;
const OFF_HVM_START_INFO: u32 = OFF_GDT + 0x30;
/// Boot stack top; the stack grows down towards the page tables.
const OFF_STACK_TOP: u32 = 0x80000;

#[repr(C, align(4))]
struct PvhNote {
    namesz: u32,
    descsz: u32,
    ntype: u32,
    name: [u8; 4],
    desc: u32,
}

#[used]
#[unsafe(link_section = ".note.Xen")]
static PVH_NOTE: PvhNote = PvhNote {
    namesz: 4,
    descsz: 4,
    ntype: XEN_ELFNOTE_PHYS32_ENTRY,
    name: *b"Xen\0",
    desc: PVH_ENTRY_ADDR,
};

global_asm!(
    r#"
    .section .text._start,"ax",@progbits
    .globl _start
    .code32
_start:
    /* %ebx is the only pointer to hvm_start_info; save it first. */
    mov dword ptr [{scratch} + {off_sinfo}], ebx
    mov dword ptr [{scratch} + {off_sinfo} + 4], 0

    /* PVH does not define %esp; use our own stack before pushing anything. */
    mov esp, {scratch} + {off_stack_top}

    cld
    mov edi, {scratch} + {off_pml4}
    xor eax, eax
    mov ecx, ((2 + {pd_count}) * 4096) / 4
    rep stosd

    /* PML4[0] (identity) and PML4[KERNEL_OFFSET] (alias) -> PDPT. */
    mov eax, {scratch} + {off_pdpt}
    or eax, 0x03
    mov dword ptr [{scratch} + {off_pml4}], eax
    mov dword ptr [{scratch} + {off_pml4} + {kernel_pml4_index} * 8], eax

    xor ecx, ecx
    mov eax, {scratch} + {off_pd}
    or eax, 0x03
1:
    mov dword ptr [{scratch} + {off_pdpt} + ecx * 8], eax
    add eax, 0x1000
    inc ecx
    cmp ecx, {pd_count}
    jb 1b

    /* All physical addresses are below 4 GiB; high dwords stay zero. */
    xor ecx, ecx
    mov eax, 0x83
2:
    mov dword ptr [{scratch} + {off_pd} + ecx * 8], eax
    add eax, 0x200000
    inc ecx
    cmp ecx, {pd_entries}
    jb 2b

    /* 64-bit GDT: null, code64, data. */
    mov dword ptr [{scratch} + {off_gdt} + 0x00], 0x00000000
    mov dword ptr [{scratch} + {off_gdt} + 0x04], 0x00000000
    mov dword ptr [{scratch} + {off_gdt} + 0x08], 0x0000FFFF
    mov dword ptr [{scratch} + {off_gdt} + 0x0C], 0x00AF9A00
    mov dword ptr [{scratch} + {off_gdt} + 0x10], 0x0000FFFF
    mov dword ptr [{scratch} + {off_gdt} + 0x14], 0x00CF9200
    mov word ptr  [{scratch} + {off_gdtr}], 3 * 8 - 1
    mov dword ptr [{scratch} + {off_gdtr} + 2], {scratch} + {off_gdt}

    /* PAE, CR3, EFER.LME, CR0.PG. */
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    mov eax, {scratch} + {off_pml4}
    mov cr3, eax
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax

    /* Compatibility mode -> 64-bit via our GDT and a far return. */
    lgdt [{scratch} + {off_gdtr}]
    mov eax, offset .Lpa_compat
    push 0x08
    push eax
    retf

    .code64
.Lcompat_to_long:
    mov ax, 0x10
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    mov rax, offset .Lpa_high
    mov rcx, {kernel_offset}
    add rax, rcx
    jmp rax

.Lhigh_half:
    mov rsp, {scratch} + {off_stack_top}
    add rsp, rcx

    /* No Rust before relocation: generated code may use unrelocated GOT entries. */
    lea rdx, [rip + _memory_base]
    lea rsi, [rip + _rela_start]
    lea rdi, [rip + _rela_end]
4:
    cmp rsi, rdi
    jae 5f
    mov eax, [rsi + 8]                           /* ELF64_R_TYPE(r_info) */
    test eax, eax                               /* R_X86_64_NONE */
    jz 6f
    cmp eax, {r_x86_64_relative}
    jne 7f
    mov rax, [rsi + 16]                           /* r_addend */
    add rax, rdx
    mov rcx, [rsi]                                /* r_offset */
    mov [rdx + rcx], rax
6:
    add rsi, 24                                   /* sizeof(Elf64_Rela) */
    jmp 4b
5:
    xor rbp, rbp
    call {rust_entry}
7:
    /* No Rust diagnostics are available before relocation completes. */
    mov dx, {debug_exit_port}
    mov eax, {debug_exit_failure}
    out dx, eax
3:
    cli
    hlt
    jmp 3b

    .set .Lpa_compat, .Lcompat_to_long - _start + {entry}
    .set .Lpa_high,   .Lhigh_half - _start + {entry}
"#,
    entry = const PVH_ENTRY_ADDR,
    kernel_offset = const KERNEL_OFFSET,
    kernel_pml4_index = const KERNEL_PML4_INDEX,
    pd_entries = const PD_ENTRIES,
    pd_count = const PD_COUNT,
    scratch = const BOOT_SCRATCH_BASE,
    off_pml4 = const OFF_PML4,
    off_pdpt = const OFF_PDPT,
    off_pd = const OFF_PD,
    off_gdt = const OFF_GDT,
    off_gdtr = const OFF_GDTR,
    off_sinfo = const OFF_HVM_START_INFO,
    off_stack_top = const OFF_STACK_TOP,
    r_x86_64_relative = const 8,
    debug_exit_port = const crate::machine::DEBUG_EXIT_PORT,
    debug_exit_failure = const crate::machine::DEBUG_EXIT_FAILURE,
    rust_entry = sym pvh_entry,
);

// Layouts from xen/include/public/arch-x86/hvm/start_info.h.

const HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;
const HVM_MEMMAP_TYPE_RAM: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, FromBytes)]
struct HvmStartInfo {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    modlist_paddr: u64,
    cmdline_paddr: u64,
    rsdp_paddr: u64,
    memmap_paddr: u64,
    memmap_entries: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes)]
struct HvmMemmapTableEntry {
    addr: u64,
    size: u64,
    type_: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes)]
struct HvmModlistEntry {
    paddr: u64,
    size: u64,
    cmdline_paddr: u64,
    reserved: u64,
}

/// # Safety
///
/// `pa..pa + size_of::<T>()` must be RAM that nothing writes concurrently.
unsafe fn read_phys<T: FromBytes>(pa: u64) -> T {
    let end = pa
        .checked_add(size_of::<T>() as u64)
        .expect("physical address overflow");
    assert!(
        end <= MAPPED_LIMIT,
        "boot structure at {pa:#x} is outside the early mapping"
    );
    // Safety: in bounds of the early mapping (checked above), readable per the
    // caller, and valid for `T` (`FromBytes`); `read_unaligned` needs no alignment.
    unsafe { ((pa + KERNEL_OFFSET) as *const T).read_unaligned() }
}

fn range_end(start: u64, size: u64, what: &str) -> u64 {
    start.checked_add(size).unwrap_or_else(|| {
        panic!("{what} at {start:#x} with size {size:#x} overflows the address space")
    })
}

extern "C" fn pvh_entry() -> ! {
    crate::early_console_init();
    crate::kernel_start(boot_info())
}

/// # Panics
///
/// Panics on a malformed or unsupported `hvm_start_info`.
pub fn boot_info() -> BootInfo {
    let slot = u64::from(BOOT_SCRATCH_BASE + OFF_HVM_START_INFO) + KERNEL_OFFSET;
    // Safety: written by the entry stub before any Rust code ran.
    let start_info_pa = unsafe { (slot as *const u64).read() };
    assert!(start_info_pa != 0, "PVH passed a null hvm_start_info");
    // Safety: the pointer comes from the PVH ABI; the magic is checked below.
    let info: HvmStartInfo = unsafe { read_phys(start_info_pa) };
    assert_eq!(
        info.magic, HVM_START_MAGIC_VALUE,
        "bad hvm_start_info magic"
    );
    assert!(info.version >= 1, "hvm_start_info has no memory map");

    let mut reserved = ArrayVec::<Range, MAX_RESERVED>::new();
    let mut reserve = |start: u64, len: u64| {
        let range = Range {
            start,
            end: start.saturating_add(len),
        };
        assert!(
            reserved.try_push(range).is_ok(),
            "more than {MAX_RESERVED} firmware-reserved ranges (at {start:#x}); \
             raise MAX_RESERVED rather than let the heap overwrite them"
        );
    };
    reserve(start_info_pa, size_of::<HvmStartInfo>() as u64);
    reserve(
        info.memmap_paddr,
        u64::from(info.memmap_entries) * size_of::<HvmMemmapTableEntry>() as u64,
    );

    let mut cmdline = ArrayString::new();
    if info.cmdline_paddr != 0 {
        let mut len = 0u64;
        loop {
            // Safety: a NUL-terminated string per the PVH ABI; bounded below.
            let byte: u8 = unsafe { read_phys(info.cmdline_paddr + len) };
            len += 1;
            if byte == 0 {
                break;
            }
            assert!(
                cmdline.try_push(char::from(byte)).is_ok(),
                "kernel command line is too long"
            );
        }
        reserve(info.cmdline_paddr, len);
    }

    let nr_modules = usize::try_from(info.nr_modules).unwrap();
    assert!(
        nr_modules <= MAX_MODULES,
        "the VMM passed {nr_modules} boot modules; at most {MAX_MODULES} are supported"
    );
    let mut modules = ArrayVec::<Range, MAX_MODULES>::new();
    if nr_modules != 0 {
        let entry_size = size_of::<HvmModlistEntry>() as u64;
        reserve(info.modlist_paddr, u64::from(info.nr_modules) * entry_size);
        for i in 0..u64::from(info.nr_modules) {
            // Safety: `i`th element of the module list named by start_info.
            let module: HvmModlistEntry = unsafe { read_phys(info.modlist_paddr + i * entry_size) };
            let range = Range {
                start: module.paddr,
                end: range_end(module.paddr, module.size, "boot module"),
            };
            reserve(range.start, module.size);
            modules.push(range);
        }
    }

    let mut usable = ArrayVec::<Range, MAX_RAM_REGIONS>::new();
    for i in 0..u64::from(info.memmap_entries) {
        // Safety: `i`th element of the memory map named by start_info.
        let entry: HvmMemmapTableEntry =
            unsafe { read_phys(info.memmap_paddr + i * size_of::<HvmMemmapTableEntry>() as u64) };
        let end = range_end(entry.addr, entry.size, "memory map entry");
        log::debug!(
            "memmap {:#014x}..{:#014x} type {}",
            entry.addr,
            end,
            entry.type_
        );
        if entry.type_ == HVM_MEMMAP_TYPE_RAM {
            let range = Range {
                start: entry.addr,
                end,
            };
            assert!(
                usable.try_push(range).is_ok(),
                "the memory map has more than {MAX_RAM_REGIONS} RAM regions; \
                 raise MAX_RAM_REGIONS rather than silently drop memory"
            );
        }
    }

    BootInfo {
        usable,
        reserved,
        modules,
        cmdline,
        mapped_limit: MAPPED_LIMIT,
    }
}

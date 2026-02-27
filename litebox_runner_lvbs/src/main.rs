// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use litebox_platform_lvbs::{
    arch::{enable_extended_states, enable_fsgsbase, enable_smep_smap, instrs::hlt_loop},
    host::{
        bootparam::parse_boot_info,
        per_cpu_variables::{
            PerCpuVariablesAsm, allocate_own_per_cpu_variables, init_per_cpu_variables,
        },
    },
    mshv::vtl1_mem_layout::{self, VTL1_REMAP_PDE_PAGE, VTL1_REMAP_PDPT_PAGE},
    serial_println,
};
use x86_64::VirtAddr;
use x86_64::structures::paging::PageTableFlags;

/// ELF64 relocation entry
#[repr(C)]
struct Elf64Rela {
    offset: u64,
    info: u64,
    addend: i64,
}

const R_X86_64_RELATIVE: u64 = 8;

/// KERNEL_OFFSET: the offset added to PA to get the VTL1 kernel VA.
const KERNEL_OFFSET: u64 = litebox_platform_lvbs::KERNEL_OFFSET;

/// Page table entry flags for Phase 1 mappings (present + writable).
const PTE_TABLE_FLAGS: u64 = PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits();

/// x86-64 page table structure constants
const ENTRIES_PER_PT_PAGE: usize = 512;
const CR3_ADDR_MASK: u64 = !(vtl1_mem_layout::PAGE_SIZE as u64 - 1);

/// Apply ELF relocations to support position-independent execution.
/// This code has NO dependency on absolute addresses - uses only RIP-relative addressing.
///
/// # Safety
/// - Must be called before any absolute addresses are accessed
/// - Must be called exactly once at boot
/// - Requires valid relocation section in the binary
#[inline(never)]
unsafe fn apply_relocations() {
    unsafe extern "C" {
        static _rela_start: u8;
        static _rela_end: u8;
        static _memory_base: u8;
    }

    // Calculate load offset using ONLY position-independent code
    // This works regardless of where we're loaded

    // Get actual runtime address (where we ARE)
    let actual_base: u64;
    unsafe {
        asm!(
            "lea {}, [rip + _memory_base]",
            out(reg) actual_base,
            options(nostack, nomem, preserves_flags)
        );
    }

    // offset = actual_base - expected_base
    // The expected base is 0x0, so offset = actual_base
    let offset = actual_base;

    // Early return if already at expected location
    if offset == 0 {
        return;
    }

    // Get relocation table bounds using RIP-relative addressing
    let rela_start: u64;
    let rela_end: u64;
    unsafe {
        asm!(
            "lea {start}, [rip + _rela_start]",
            "lea {end}, [rip + _rela_end]",
            start = out(reg) rela_start,
            end = out(reg) rela_end,
            options(nostack, nomem, preserves_flags)
        );
    }

    let mut rela_ptr = rela_start as *const Elf64Rela;
    let rela_end_ptr = rela_end as *const Elf64Rela;

    // Process each relocation entry
    while rela_ptr < rela_end_ptr {
        // SAFETY: rela_ptr is within bounds of relocation section
        let rela = unsafe { &*rela_ptr };
        let r_type = rela.info & 0xffffffff;

        // Only handle R_X86_64_RELATIVE relocations
        if r_type == R_X86_64_RELATIVE {
            // Calculate target address: original offset + load offset
            // SAFETY: Target address is valid after offset adjustment
            let target = (offset.wrapping_add(rela.offset)) as *mut u64;
            // SAFETY: Target is within the .rela.dyn section and properly aligned
            unsafe {
                // Relocation calculation: addend + load_offset
                // The casts between signed/unsigned are intentional for ELF relocation math
                #[allow(clippy::cast_possible_wrap)]
                #[allow(clippy::cast_sign_loss)]
                let value = rela.addend.wrapping_add(offset as i64) as u64;
                target.write_volatile(value);
            }
        }

        // SAFETY: Moving to next entry within bounds
        rela_ptr = unsafe { rela_ptr.add(1) };
    }

    // NOTE: .rela.dyn section memory is reclaimed later in init() (lib.rs)
    // after the remap to high-canonical VA, so that the allocator receives
    // high-canonical addresses instead of low-canonical (PA-based) ones.
}

/// Remap VTL1 kernel pages from identity-mapped low-canonical addresses to
/// high-canonical addresses (VA = PA + KERNEL_OFFSET).
///
/// # Two-Phase Page Table Setup
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────┐
/// │ Phase 1 – Trampoline (remap_to_high_canonical)                      │
/// │                                                                     │
/// │ VTL0 left us with an identity map: VA == PA via PML4[0].            │
/// │ We add a HIGH-canonical mapping into the SAME PML4 so that          │
/// │ VA = PA + KERNEL_OFFSET also reaches the same frames.               │
/// │ Then jump to continue_boot at the high VA and fix RSP.              │
/// │                                                                     │
/// │ PML4 (page 2, from VTL0)                                            │
/// │ ┌──────────────────────────────────────────────┐                    │
/// │ │ [0]   → VTL0 PDPT (page 3)    ← identity     │ kept (harmless)    │
/// │ │ [256] → new  PDPT (page 16)   ← high-canon   │ Phase 1 adds       │
/// │ │  ...                                         │                    │
/// │ └──────────────────────────────────────────────┘                    │
/// │                                                                     │
/// │ New PDPT (page 16)                                                  │
/// │ ┌──────────────────────────────────────────────┐                    │
/// │ │ [pdpt_idx] → new PDE (page 17)               │                    │
/// │ └──────────────────────────────────────────────┘                    │
/// │                                                                     │
/// │ New PDE (page 17)                                                   │
/// │ ┌──────────────────────────────────────────────┐                    │
/// │ │ [pde+0] → VTL0 PTE page 5  (2 MiB, 4KB pgs)  │ reused as-is       │
/// │ │ [pde+1] → VTL0 PTE page 6                    │                    │
/// │ │   ...                                        │                    │
/// │ │ [pde+7] → VTL0 PTE page 12                   │ 8 pages = 16 MiB   │
/// │ └──────────────────────────────────────────────┘                    │
/// │                                                                     │
/// │ After CR3 flush, BOTH low and high VAs work. We jump high           │
/// │ and fix RSP. PML4[0] is left — removed naturally in Phase 2.        │
/// └─────────────────────────────────────────────────────────────────────┘
///
/// ┌─────────────────────────────────────────────────────────────────────┐
/// │ Phase 2 – Base page table with DEP (Platform::new, lib.rs)          │
/// │                                                                     │
/// │ Heap is now available (seeded from the 16 MiB Phase 1 window).      │
/// │ Allocate a fresh PML4 from the heap. Map ALL 128 MiB of VTL1        │
/// │ memory with NX (no-execute) by default; mark only .text and         │
/// │ .hvcall_page executable. Enable EFER.NXE, then load the new CR3.    │
/// │                                                                     │
/// │ The page table pages themselves are allocated from the heap         │
/// │ (within 16 MiB) — we never need to ACCESS memory beyond 16 MiB      │
/// │ to MAP it, so Phase 1's limited coverage is sufficient.             │
/// │                                                                     │
/// │ Key: PML4[0] is ABSENT → low-canonical identity map is gone.        │
/// │ The entire low half [0, 0x7FFF_FFFF_F000) is now available          │
/// │ for user-space (TAs / Linux apps).                                  │
/// │                                                                     │
/// │ Reclaim all Phase 1 pages (2–12, 16–17) back to the allocator.      │
/// └─────────────────────────────────────────────────────────────────────┘
/// ```
///
/// ## Strategy
///
/// VTL0 pre-populates 16 MiB of VTL1 memory with an identity-mapped page
/// table using 4KB pages:
///
///   PML4[0] → PDPT (page 3) → PDE (page 4) → PTE pages 5–12
///
/// Because `KERNEL_OFFSET` is 2 MiB-aligned, adding it to a PA does not change
/// the PDE or PTE indices — only the PML4 and PDPT indices differ. This
/// means the existing PTE pages can be **reused as-is** for the
/// high-canonical mapping; we only need a new PDPT page and a new PDE page.
///
/// The PDPT and PDE pages are allocated from unused memory after the
/// VTL0-reserved special pages (pages 16–17), preserving all 8 PTE pages
/// for the high-canonical mapping and covering the full 16 MiB.
///
/// ## Page table pages used
///
/// | page | constant              | purpose                                |
/// |------|-----------------------|----------------------------------------|
/// | 16   | `VTL1_REMAP_PDPT_PAGE`| PDPT for the high-canonical PML4 entry |
/// | 17   | `VTL1_REMAP_PDE_PAGE` | PDE pointing to PTE pages 5–12         |
///
/// ## Algorithm
///
/// 1. Compute PML4/PDPT/PDE indices from `memory_base + KERNEL_OFFSET`.
/// 2. Zero and populate a PDPT page (page 16).
/// 3. Zero and populate a PDE page (page 17) pointing to all 8 VTL0 PTE
///    pages 5–12 (4KB page mappings, no huge pages).
/// 4. Wire PML4 → PDPT → PDE.
/// 5. Flush TLB and jump to `continue_boot` at the high-canonical address.
///
/// # Safety
/// - Must be called exactly once on BSP in `_start()`, after `apply_relocations()`
/// - Must be called before any heap/allocator initialization
/// - Must be called before `enable_fsgsbase()` and `init_per_cpu_variables()`
/// - The VTL0-provided page table must be at the expected layout (pages 2-12)
#[inline(never)]
#[allow(clippy::similar_names)]
unsafe fn remap_to_high_canonical() -> ! {
    // Get _memory_base (relocated once, so it is still an identity-mapped address)
    let memory_base = vtl1_mem_layout::get_memory_base_address();

    // Compute the high-canonical VA of the start of VTL1 memory.
    let high_va_base = memory_base.wrapping_add(KERNEL_OFFSET);

    // Compute page table indices for high_va_base.
    let high_va = VirtAddr::new(high_va_base);
    let pml4_idx: usize = high_va.p4_index().into();
    let pdpt_idx: usize = high_va.p3_index().into();
    let pde_start_idx: usize = high_va.p2_index().into();

    let cr3: u64;
    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) cr3,
            options(nostack, nomem, preserves_flags)
        );
    }
    let pml4_pa = cr3 & CR3_ADDR_MASK;
    let pml4_ptr = pml4_pa as *mut u64;

    // Set up the PDPT page (page 16)
    let pdpt_page_pa = memory_base + (VTL1_REMAP_PDPT_PAGE * vtl1_mem_layout::PAGE_SIZE) as u64;
    let pdpt_ptr = pdpt_page_pa as *mut u64;
    unsafe { core::ptr::write_bytes(pdpt_ptr, 0, ENTRIES_PER_PT_PAGE) };

    // Set up the PDE page (page 17)
    let pde_page_pa = memory_base + (VTL1_REMAP_PDE_PAGE * vtl1_mem_layout::PAGE_SIZE) as u64;
    let pde_ptr = pde_page_pa as *mut u64;
    unsafe { core::ptr::write_bytes(pde_ptr, 0, ENTRIES_PER_PT_PAGE) };

    // Point PDE entries to the existing VTL0 PTE pages (pages 5–12).
    // Each PTE page covers 2 MiB = 512 × 4KB.
    for (i, pte_page_idx) in (vtl1_mem_layout::VTL1_PTE_0_PAGE..)
        .take(vtl1_mem_layout::VTL1_REMAP_PTE_COUNT)
        .enumerate()
    {
        let pte_page_pa = memory_base + (pte_page_idx * vtl1_mem_layout::PAGE_SIZE) as u64;
        let pde_entry = pte_page_pa | PTE_TABLE_FLAGS;
        unsafe {
            pde_ptr.add(pde_start_idx + i).write_volatile(pde_entry);
        }
    }

    unsafe {
        // PDPT[pdpt_idx] = PDE page
        pdpt_ptr
            .add(pdpt_idx)
            .write_volatile(pde_page_pa | PTE_TABLE_FLAGS);

        // PML4[pml4_idx] = PDPT page
        pml4_ptr
            .add(pml4_idx)
            .write_volatile(pdpt_page_pa | PTE_TABLE_FLAGS);
    }
    x86_64::instructions::tlb::flush_all();

    let trampoline_pa = high_canonical_trampoline as *const () as u64;
    let trampoline_high = trampoline_pa + KERNEL_OFFSET;

    unsafe {
        asm!(
            "jmp {target}",
            target = in(reg) trampoline_high,
            options(noreturn)
        );
    }
}

/// Trampoline executed at the high-canonical address after Phase 1 remap.
///
/// Adjusts RSP from low-canonical (PA-based) to high-canonical, re-applies
/// ELF relocations for the final link address, and tail-jumps to
/// `common_start` with `is_bsp = true`.
#[unsafe(naked)]
unsafe extern "C" fn high_canonical_trampoline() -> ! {
    // 1. Adjust RSP from low-canonical (PA-based) to high-canonical.
    // 2. Phase 1b: Re-apply ELF relocations so every GOT slot now points to
    //    high-canonical VAs (addend + memory_base + KERNEL_OFFSET).
    // 3. Set edi = 1 (is_bsp = true) and tail-jump to common_start.
    naked_asm!(
        "mov rax, {offset}",
        "add rsp, rax",
        "and rsp, -16",
        "call {apply_reloc}",
        "mov edi, 1",
        "jmp {common_start}",
        offset = const KERNEL_OFFSET,
        apply_reloc = sym apply_relocations,
        common_start = sym common_start,
    );
}

/// AP entry point — entered directly by Hyper-V via `hvcall_enable_vp_vtl`
/// (the VP context's RIP is set to this symbol).  APs inherit the BSP's CR3
/// (Phase 2 page table with full 128 MiB mapped), so they already run at
/// high-canonical VAs and need no remap.
#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _ap_start() -> ! {
    unsafe { common_start(false) }
}

/// Shared boot path for BSP and AP cores.
///
/// When `is_bsp` is `true`, seeds the initial heap first.  Then every core
/// heap-allocates its own per-CPU variables (APs can do this because the
/// heap is already available and they enter VTL1 one at a time on the
/// shared 4 KiB boot stack).
///
/// Common sequence: enable CPU features → allocate own PCV →
/// init per-CPU variables → switch to kernel stack → `kernel_main(is_bsp)`.
unsafe extern "C" fn common_start(is_bsp: bool) -> ! {
    enable_fsgsbase();
    enable_extended_states();

    if is_bsp {
        litebox_runner_lvbs::seed_initial_heap();
    }

    // Each core heap-allocates its own PerCpuVariables, RefCellWrapper, and
    // XSAVE areas, then sets GSBASE.
    allocate_own_per_cpu_variables();

    init_per_cpu_variables();

    // Switch to the kernel stack and tail-call kernel_main with is_bsp
    // in edi (x86_64 SysV ABI first argument).
    let is_bsp_u32 = u32::from(is_bsp);
    unsafe {
        asm!(
            "mov rsp, gs:[{kernel_sp_off}]",
            "call {kernel_main}",
            kernel_sp_off = const { PerCpuVariablesAsm::kernel_stack_ptr_offset() },
            in("edi") is_bsp_u32,
            kernel_main = sym kernel_main
        );
    }

    hlt_loop()
}

/// BSP-only entry point.
///
/// APs never enter here — they start directly at `_ap_start` via the VP
/// context set up by `hvcall_enable_vp_vtl`.
#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    unsafe {
        // Phase 1a: Fix GOT entries from link-time (base 0x0) to PA-based VAs.
        // The binary is linked at address 0x0 but loaded by VTL0 at an arbitrary
        // physical address (memory_base). This pass rewrites every GOT slot so
        // that globals and function pointers resolve correctly under the
        // identity map (VA == PA) that VTL0 left us with.
        apply_relocations();

        remap_to_high_canonical();
    }
}

unsafe extern "C" fn kernel_main(is_bsp: bool) -> ! {
    if is_bsp {
        serial_println!("==============================");
        serial_println!(" Hello from LiteBox for LVBS! ");
        serial_println!("==============================");

        parse_boot_info();
    }

    let platform = litebox_runner_lvbs::init(is_bsp);

    enable_smep_smap();

    litebox_runner_lvbs::run(platform)
}

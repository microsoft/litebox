// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-place ntdll.dll syscall rewriter.
//!
//! Scans the `.text` section of a loaded ntdll.dll for the standard Windows
//! syscall stub pattern and replaces each `syscall; ret` sequence with a
//! `jmp rel32` to a shared trampoline.  The trampoline then performs an
//! indirect jump to the litebox shim's syscall entry point.
//!
//! ## Stub pattern (24 active bytes, 32-byte aligned)
//!
//! ```text
//! +00: 4C 8B D1              mov  r10, rcx
//! +03: B8 xx xx xx xx        mov  eax, <syscall_nr>
//! +08: F6 04 25 08 03 FE 7F  test byte [0x7FFE0308], 1
//! +0F: 01                    (imm8)
//! +10: 75 03                 jne  +3           ← we overwrite from here
//! +12: 0F 05                 syscall           ← through here
//! +14: C3                    ret               ← and here (5 bytes total)
//! +15: CD 2E                 int  2Eh          (fallback)
//! +17: C3                    ret
//! ```
//!
//! We replace bytes [+10 .. +15) with a 5-byte `JMP rel32` to the
//! trampoline, which itself does `JMP [RIP+0]` using an 8-byte
//! absolute pointer to the shim entry.
//!
//! On entry to the shim:
//! - `eax`  = NT syscall number
//! - `r10`  = original `rcx` (first argument)
//! - `rdx`, `r8`, `r9`, stack args = remaining arguments
//! - return address on stack (from the caller of the ntdll stub)
//!
//! The shim must `ret` back to that return address when done.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::{NtSyscallId, NtSyscallMap, name_to_syscall_id};

/// Result of rewriting an ntdll image.
pub struct NtdllRewriteResult {
    /// The rewritten ntdll image bytes (PE file, modified in place).
    pub image: Vec<u8>,
    /// Trampoline code bytes (one page, to be mapped near the loaded ntdll).
    pub trampoline: Vec<u8>,
    /// Offset within the trampoline where the 8-byte shim entry pointer lives.
    /// The runner must write the actual shim syscall_entry address here
    /// after mapping the trampoline.
    pub entry_ptr_offset: usize,
    /// Offset within the trampoline where the 8-byte forward GS table pointer
    /// lives (guest_gs → host_gs). The runner must write the platform's
    /// forward GS lookup table address here.
    pub gs_table_ptr_offset: usize,
    /// Offset within the trampoline where the 8-byte reverse GS table pointer
    /// lives (host_gs → guest_gs). The runner must write the platform's
    /// reverse GS lookup table address here. This table is used to detect
    /// that GS is already the host TEB (e.g., after kernel exception dispatch)
    /// and skip the swap.
    pub reverse_gs_table_ptr_offset: usize,
    /// Number of syscall stubs that were rewritten (JMP-patched).
    pub stubs_rewritten: usize,
    /// Number of stubs whose export name matched a known `NtSyscallId`.
    pub stubs_identified: usize,
    /// Mapping from real Windows syscall numbers to `NtSyscallId`.
    /// Stubs keep their original numbers — no remapping is done.
    pub syscall_map: NtSyscallMap,
    /// Syscall number → export name for stubs NOT in `NtSyscallId`.
    /// Useful for debugging which unhandled syscalls are being called.
    pub unhandled_stubs: Vec<(u32, String)>,
    /// Number of `int 0x29` (__fastfail) instructions that were replaced
    /// with `int 3` (breakpoint) to keep them catchable by VEH.
    pub fastfail_patched: usize,
}

/// The 4-byte prefix of every ntdll syscall stub.
const STUB_PREFIX: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8]; // mov r10, rcx; mov eax, ...

/// The 8-byte CFG check that follows the mov eax.
const CFG_CHECK: [u8; 8] = [0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01];

/// Bytes at +16: jne +3; syscall; ret
const SYSCALL_TAIL: [u8; 5] = [0x75, 0x03, 0x0F, 0x05, 0xC3];

/// Size of one page (trampoline allocation unit).
const PAGE_SIZE: usize = 4096;

/// Rewrite an ntdll.dll PE image in memory.
///
/// `ntdll_data` is the raw PE file bytes (will be copied and modified).
/// `ntdll_load_va` is the virtual address where ntdll will be mapped.
/// `trampoline_va` is the virtual address where the trampoline page
/// will be mapped (must be within ±2GB of ntdll's .text section).
///
/// Returns the rewritten image + trampoline page.  The caller must:
/// 1. Map the rewritten image at `ntdll_load_va`
/// 2. Map the trampoline at `trampoline_va`
/// 3. Write the shim's `syscall_entry` address into the trampoline at
///    `result.entry_ptr_offset`
///
/// # Panics
///
/// Panics if the PE file is malformed or lacks required sections.
pub fn rewrite_ntdll(
    ntdll_data: &[u8],
    ntdll_load_va: u64,
    trampoline_va: u64,
) -> NtdllRewriteResult {
    let mut image = ntdll_data.to_vec();

    // Build the trampoline page.
    //
    // When guest code CALLs an ntdll function, the return address is pushed.
    // The ntdll stub does `mov r10, rcx; mov eax, NR; ...` then JMPs here.
    // The return address stays on the stack throughout the trampoline.
    //
    // The trampoline:
    //   1. Scans the GS table to swap GS from guest TEB to host TEB
    //      (needed because syscall_callback reads TLS via GS).
    //   2. Loads RCX with the address of a `ret` instruction at the end.
    //   3. JMPs to the platform's syscall_callback.
    //
    // When the shim finishes, the guest resumes at the `ret` instruction,
    // which pops the caller's actual return address from the stack.
    //
    // This matches the PE-builder stub convention: the return address is
    // on the stack, so the shim sees the standard x64 callee stack layout:
    //   [rsp+0x00] = return address
    //   [rsp+0x08] = shadow rcx
    //   ...
    //   [rsp+0x28] = 5th arg, etc.
    //
    // The trampoline must swap GS from guest TEB to host TEB before entering
    // the syscall callback, because `syscall_callback` reads TLS via
    // `gs:[TLS_INDEX * 8 + TEB_TLS_SLOTS_OFFSET]`.
    //
    // However, the Windows kernel may have already reset GS to the host TEB
    // (e.g., after exception dispatch or APC delivery). To handle both cases,
    // the trampoline does a two-phase scan:
    //
    //   Phase 1: Scan the forward table (guest_gs → host_gs). If the current
    //            GS matches a guest_gs entry, swap to the corresponding host_gs.
    //   Phase 2: If not found, scan the reverse table (host_gs → guest_gs).
    //            If the current GS matches a host_gs entry, it's already the
    //            host TEB — skip the swap and proceed directly to the shim.
    //   Miss:    If neither table matches, UD2 (unknown GS value).
    //
    // Layout:
    //   +0x00: 8-byte shim entry pointer (filled by runner)
    //   +0x08: 8-byte forward GS table pointer (guest→host, filled by runner)
    //   +0x10: 8-byte reverse GS table pointer (host→guest, filled by runner)
    //   +0x18: trampoline code

    let mut trampoline = vec![0xCCu8; PAGE_SIZE]; // fill with INT3 for safety

    let entry_ptr_offset = 0usize; // shim entry ptr at +0x00
    let gs_table_ptr_offset = 8usize; // forward GS table ptr at +0x08
    let reverse_gs_table_ptr_offset = 16usize; // reverse GS table ptr at +0x10
    let code_offset = 24usize; // code starts at +0x18
    let trampoline_code_va = trampoline_va + code_offset as u64;

    let mut off = code_offset;

    // The caller's `call NtFoo` pushed a return address.  The ntdll stub
    // does `mov r10, rcx; mov eax, NR; ... jmp trampoline`.  The return
    // address stays on the stack throughout — we leave it there so that
    // ctx.regs.rsp seen by the shim includes the return address, matching
    // the standard Windows x64 callee view:
    //   [rsp+0x00] = return address
    //   [rsp+0x08] = shadow rcx  ...  [rsp+0x28] = 5th stack arg, etc.
    //
    // At the end we load RCX with the address of a `ret` instruction
    // that follows the JMP.  The platform pushes RCX as pt_regs->ip.
    // When the guest resumes there, the `ret` pops the real return
    // address and control returns to the original caller.

    // rdgsbase r11  (F3 49 0F AE CB) — current GS → R11
    trampoline[off..off + 5].copy_from_slice(&[0xF3, 0x49, 0x0F, 0xAE, 0xCB]);
    off += 5;

    // === Phase 1: scan forward table (guest_gs → host_gs) ===
    //
    // mov rcx, [rip+disp32]  (48 8B 0D xx xx xx xx) — load forward GS table ptr
    let rip_after_fwd_mov = off + 7;
    let fwd_mov_disp = (gs_table_ptr_offset as i32) - (rip_after_fwd_mov as i32);
    trampoline[off..off + 3].copy_from_slice(&[0x48, 0x8B, 0x0D]);
    trampoline[off + 3..off + 7].copy_from_slice(&fwd_mov_disp.to_le_bytes());
    off += 7;

    // .probe_fwd:
    let probe_fwd_off = off;
    // cmp [rcx], r11  (4C 39 19)
    trampoline[off..off + 3].copy_from_slice(&[0x4C, 0x39, 0x19]);
    off += 3;

    // je .found_guest  (74 xx) — forward jump, will patch
    let je_found_guest_off = off;
    trampoline[off] = 0x74;
    off += 2;

    // add rcx, 16  (48 83 C1 10)
    trampoline[off..off + 4].copy_from_slice(&[0x48, 0x83, 0xC1, 0x10]);
    off += 4;

    // cmp qword [rcx], 0  (48 83 39 00) — sentinel?
    trampoline[off..off + 4].copy_from_slice(&[0x48, 0x83, 0x39, 0x00]);
    off += 4;

    // jne .probe_fwd  (75 xx)
    let back_disp = (probe_fwd_off as i32) - (off as i32 + 2);
    trampoline[off] = 0x75;
    trampoline[off + 1] = back_disp as u8;
    off += 2;

    // === Phase 2: scan reverse table (host_gs → guest_gs) ===
    // Not found in forward table. Check if GS is already the host TEB.
    //
    // mov rcx, [rip+disp32]  (48 8B 0D xx xx xx xx) — load reverse GS table ptr
    let rip_after_rev_mov = off + 7;
    let rev_mov_disp = (reverse_gs_table_ptr_offset as i32) - (rip_after_rev_mov as i32);
    trampoline[off..off + 3].copy_from_slice(&[0x48, 0x8B, 0x0D]);
    trampoline[off + 3..off + 7].copy_from_slice(&rev_mov_disp.to_le_bytes());
    off += 7;

    // .probe_rev:
    let probe_rev_off = off;
    // cmp [rcx], r11  (4C 39 19)
    trampoline[off..off + 3].copy_from_slice(&[0x4C, 0x39, 0x19]);
    off += 3;

    // je .already_host  (74 xx) — forward jump, will patch
    let je_already_host_off = off;
    trampoline[off] = 0x74;
    off += 2;

    // add rcx, 16  (48 83 C1 10)
    trampoline[off..off + 4].copy_from_slice(&[0x48, 0x83, 0xC1, 0x10]);
    off += 4;

    // cmp qword [rcx], 0  (48 83 39 00) — sentinel?
    trampoline[off..off + 4].copy_from_slice(&[0x48, 0x83, 0x39, 0x00]);
    off += 4;

    // jne .probe_rev  (75 xx)
    let back_disp_rev = (probe_rev_off as i32) - (off as i32 + 2);
    trampoline[off] = 0x75;
    trampoline[off + 1] = back_disp_rev as u8;
    off += 2;

    // ud2 (0F 0B) — not in either table
    trampoline[off..off + 2].copy_from_slice(&[0x0F, 0x0B]);
    off += 2;

    // .found_guest: swap GS from guest to host
    let found_guest_off = off;
    trampoline[je_found_guest_off + 1] = (found_guest_off - (je_found_guest_off + 2)) as u8;

    // mov rcx, [rcx+8]  (48 8B 49 08) — host GS from forward table
    trampoline[off..off + 4].copy_from_slice(&[0x48, 0x8B, 0x49, 0x08]);
    off += 4;

    // wrgsbase rcx  (F3 48 0F AE D9) — swap to host GS
    trampoline[off..off + 5].copy_from_slice(&[0xF3, 0x48, 0x0F, 0xAE, 0xD9]);
    off += 5;

    // .already_host: GS is already host TEB, skip swap
    let already_host_off = off;
    trampoline[je_already_host_off + 1] = (already_host_off - (je_already_host_off + 2)) as u8;

    // lea rcx, [rip+6]  (48 8D 0D 06 00 00 00) — rcx = addr of `ret` below
    trampoline[off..off + 7].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x06, 0x00, 0x00, 0x00]);
    off += 7;

    // jmp [rip+disp32]  (FF 25 xx xx xx xx) — jump to shim entry
    let rip_after_jmp = (off + 6) as i32;
    let jmp_disp = (entry_ptr_offset as i32) - rip_after_jmp;
    trampoline[off] = 0xFF;
    trampoline[off + 1] = 0x25;
    trampoline[off + 2..off + 6].copy_from_slice(&jmp_disp.to_le_bytes());
    off += 6;

    // ret  (C3) — resume point: pops the caller's actual return address
    trampoline[off] = 0xC3;

    // Now scan the image for syscall stubs and rewrite them.

    // Build an RVA→export name map from the PE export table so we can
    // identify which syscall each stub implements.
    let export_rva_to_name = build_export_rva_map(&image);

    // We need to find file offsets of .text section code.
    // Parse PE headers minimally to locate .text.
    let text_range = find_text_section(&image);
    let (text_file_start, text_file_end, text_rva) = match text_range {
        Some(r) => r,
        None => {
            return NtdllRewriteResult {
                image,
                trampoline,
                entry_ptr_offset,
                gs_table_ptr_offset,
                reverse_gs_table_ptr_offset,
                stubs_rewritten: 0,
                stubs_identified: 0,
                syscall_map: NtSyscallMap::from_pairs(&[]),
                unhandled_stubs: Vec::new(),
                fastfail_patched: 0,
            };
        }
    };

    // Scan for syscall stubs: patch each to JMP trampoline and collect
    // the real_nr → NtSyscallId mapping from export names.
    let mut stubs_rewritten = 0usize;
    let mut stubs_identified = 0usize;
    let mut syscall_pairs: Vec<(u32, NtSyscallId)> = Vec::new();
    let mut unhandled_stubs: Vec<(u32, String)> = Vec::new();

    let mut i = text_file_start;
    while i + 24 <= text_file_end {
        if image[i..i + 4] == STUB_PREFIX
            && image[i + 8..i + 16] == CFG_CHECK
            && image[i + 16..i + 21] == SYSCALL_TAIL
        {
            // Patch the stub tail to JMP rel32 → trampoline.
            let stub_rva = (i - text_file_start) as u64 + u64::from(text_rva);
            let jmp_site_va = ntdll_load_va + stub_rva + 16;
            let jmp_rip = jmp_site_va + 5;
            let rel32 = (trampoline_code_va as i64 - jmp_rip as i64) as i32;
            image[i + 16] = 0xE9;
            image[i + 17..i + 21].copy_from_slice(&rel32.to_le_bytes());

            // If the stub has an export name we recognise, record the mapping.
            // The syscall number in the stub is NOT modified — it stays as the
            // real Windows number.
            let real_nr = u32::from_le_bytes(image[i + 4..i + 8].try_into().unwrap());
            let stub_rva_u32 = stub_rva as u32;
            let export_name = export_rva_to_name
                .iter()
                .find(|(rva, _)| *rva == stub_rva_u32)
                .map(|(_, name)| name.as_str());
            if let Some(id) = export_name.and_then(name_to_syscall_id) {
                syscall_pairs.push((real_nr, id));
                stubs_identified += 1;
            } else if let Some(name) = export_name {
                unhandled_stubs.push((real_nr, String::from(name)));
            }

            stubs_rewritten += 1;
        }
        i += 1;
    }

    // ── Neutralize `int 0x29` (__fastfail) instructions ──
    //
    // `int 0x29` triggers the Windows __fastfail mechanism, which
    // terminates the process WITHOUT delivering the exception to VEH
    // handlers.  Since the guest runs in the same host process, an
    // uncaught __fastfail kills the sandbox.
    //
    // We replace every `CD 29` in ntdll's .text section with `EB 00`
    // (JMP +0, i.e. jump to next instruction = NOP).  This is safer
    // than `90 90` (two NOPs) because `90 90` could interfere with
    // instruction alignment if the scanner hits a false-positive
    // `CD 29` that is actually operand bytes.  `EB 00` is a 2-byte
    // no-op that preserves the instruction boundary.
    //
    // When __fastfail is neutralized, the code after it (typically a
    // `ret`) executes normally.  If the stack cookie WAS corrupted,
    // the guest will likely crash at a subsequent access, which the
    // sandbox CAN catch via VEH.
    let mut fastfail_patched = 0usize;
    let mut j = text_file_start;
    while j + 1 < text_file_end {
        if image[j] == 0xCD && image[j + 1] == 0x29 {
            image[j] = 0xEB; // JMP rel8
            image[j + 1] = 0x00; // offset 0 → fall through
            fastfail_patched += 1;
        }
        j += 1;
    }

    let syscall_map = NtSyscallMap::from_pairs(&syscall_pairs);

    NtdllRewriteResult {
        image,
        trampoline,
        entry_ptr_offset,
        gs_table_ptr_offset,
        reverse_gs_table_ptr_offset,
        stubs_rewritten,
        stubs_identified,
        syscall_map,
        unhandled_stubs,
        fastfail_patched,
    }
}

/// Find the .text section's file offset range and RVA.
fn find_text_section(pe_data: &[u8]) -> Option<(usize, usize, u32)> {
    if pe_data.len() < 0x40 {
        return None;
    }
    let pe_offset = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().ok()?) as usize;
    if pe_offset + 24 > pe_data.len() {
        return None;
    }
    // COFF header starts at pe_offset + 4.
    let num_sections =
        u16::from_le_bytes(pe_data[pe_offset + 6..pe_offset + 8].try_into().ok()?) as usize;
    let opt_size =
        u16::from_le_bytes(pe_data[pe_offset + 20..pe_offset + 22].try_into().ok()?) as usize;
    let section_table = pe_offset + 24 + opt_size;

    for s in 0..num_sections {
        let off = section_table + s * 40;
        if off + 40 > pe_data.len() {
            break;
        }
        let name = &pe_data[off..off + 8];
        if name.starts_with(b".text\0") || name.starts_with(b".text\x00\x00\x00") {
            let virtual_size =
                u32::from_le_bytes(pe_data[off + 8..off + 12].try_into().ok()?) as usize;
            let virtual_address = u32::from_le_bytes(pe_data[off + 12..off + 16].try_into().ok()?);
            let raw_size =
                u32::from_le_bytes(pe_data[off + 16..off + 20].try_into().ok()?) as usize;
            let raw_ptr = u32::from_le_bytes(pe_data[off + 20..off + 24].try_into().ok()?) as usize;
            let size = raw_size.min(virtual_size);
            return Some((raw_ptr, raw_ptr + size, virtual_address));
        }
    }
    None
}

/// Parse the PE export table and return a list of (RVA, name) pairs.
///
/// This allows the rewriter to determine which ntdll export each syscall
/// stub belongs to, enabling syscall number remapping.
fn build_export_rva_map(pe_data: &[u8]) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    if pe_data.len() < 0x40 {
        return result;
    }
    let pe_offset = match pe_data[0x3C..0x40].try_into().ok().map(u32::from_le_bytes) {
        Some(o) => o as usize,
        None => return result,
    };
    if pe_offset + 24 > pe_data.len() {
        return result;
    }
    // Optional header starts at pe_offset + 24.
    let opt = pe_offset + 24;
    let magic = u16::from_le_bytes(pe_data[opt..opt + 2].try_into().unwrap_or([0; 2]));
    let export_dd_offset = if magic == 0x20B {
        // PE32+: export dir is at optional_header + 112
        opt + 112
    } else {
        // PE32: export dir is at optional_header + 96
        opt + 96
    };
    if export_dd_offset + 8 > pe_data.len() {
        return result;
    }
    let export_rva = u32::from_le_bytes(
        pe_data[export_dd_offset..export_dd_offset + 4]
            .try_into()
            .unwrap(),
    );
    let export_size = u32::from_le_bytes(
        pe_data[export_dd_offset + 4..export_dd_offset + 8]
            .try_into()
            .unwrap(),
    );
    if export_rva == 0 || export_size == 0 {
        return result;
    }
    // Convert RVA to file offset using the section table.
    let rva_to_file = |rva: u32| -> Option<usize> {
        let num_sections =
            u16::from_le_bytes(pe_data[pe_offset + 6..pe_offset + 8].try_into().ok()?) as usize;
        let opt_size =
            u16::from_le_bytes(pe_data[pe_offset + 20..pe_offset + 22].try_into().ok()?) as usize;
        let sec_table = pe_offset + 24 + opt_size;
        for s in 0..num_sections {
            let off = sec_table + s * 40;
            if off + 40 > pe_data.len() {
                break;
            }
            let sec_va = u32::from_le_bytes(pe_data[off + 12..off + 16].try_into().ok()?);
            let sec_raw_size = u32::from_le_bytes(pe_data[off + 16..off + 20].try_into().ok()?);
            let sec_raw_ptr = u32::from_le_bytes(pe_data[off + 20..off + 24].try_into().ok()?);
            let sec_vsize = u32::from_le_bytes(pe_data[off + 8..off + 12].try_into().ok()?);
            let range = sec_raw_size.max(sec_vsize);
            if rva >= sec_va && rva < sec_va + range {
                return Some((sec_raw_ptr + (rva - sec_va)) as usize);
            }
        }
        None
    };

    let dir_off = match rva_to_file(export_rva) {
        Some(o) => o,
        None => return result,
    };
    if dir_off + 40 > pe_data.len() {
        return result;
    }
    // IMAGE_EXPORT_DIRECTORY fields:
    let num_functions =
        u32::from_le_bytes(pe_data[dir_off + 20..dir_off + 24].try_into().unwrap()) as usize;
    let num_names =
        u32::from_le_bytes(pe_data[dir_off + 24..dir_off + 28].try_into().unwrap()) as usize;
    let addr_table_rva =
        u32::from_le_bytes(pe_data[dir_off + 28..dir_off + 32].try_into().unwrap());
    let name_table_rva =
        u32::from_le_bytes(pe_data[dir_off + 32..dir_off + 36].try_into().unwrap());
    let ordinal_table_rva =
        u32::from_le_bytes(pe_data[dir_off + 36..dir_off + 40].try_into().unwrap());

    let addr_off = match rva_to_file(addr_table_rva) {
        Some(o) => o,
        None => return result,
    };
    let name_off = match rva_to_file(name_table_rva) {
        Some(o) => o,
        None => return result,
    };
    let ord_off = match rva_to_file(ordinal_table_rva) {
        Some(o) => o,
        None => return result,
    };

    for i in 0..num_names {
        // Each name pointer is a 4-byte RVA.
        let np_off = name_off + i * 4;
        if np_off + 4 > pe_data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes(pe_data[np_off..np_off + 4].try_into().unwrap());
        let name_file = match rva_to_file(name_rva) {
            Some(o) => o,
            None => continue,
        };
        // Read NUL-terminated name.
        let name_end = pe_data[name_file..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(256);
        let name = match core::str::from_utf8(&pe_data[name_file..name_file + name_end]) {
            Ok(s) => String::from(s),
            Err(_) => continue,
        };
        // Get the ordinal index for this name.
        let o_off = ord_off + i * 2;
        if o_off + 2 > pe_data.len() {
            break;
        }
        let ordinal = u16::from_le_bytes(pe_data[o_off..o_off + 2].try_into().unwrap()) as usize;
        if ordinal >= num_functions {
            continue;
        }
        // Look up the function RVA.
        let a_off = addr_off + ordinal * 4;
        if a_off + 4 > pe_data.len() {
            continue;
        }
        let func_rva = u32::from_le_bytes(pe_data[a_off..a_off + 4].try_into().unwrap());
        result.push((func_rva, name));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_finds_stubs_in_synthetic_image() {
        // Build a minimal PE-like buffer with a .text section containing one stub.
        let mut pe = vec![0u8; 4096];

        // DOS header: e_lfanew at offset 0x3C
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature at 0x80
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");

        // COFF header
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader

        // Section table starts at 0x80 + 24 + 0xF0 = 0x188
        let sec = 0x188;
        pe[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        // VirtualSize = 256
        pe[sec + 8..sec + 12].copy_from_slice(&256u32.to_le_bytes());
        // VirtualAddress = 0x1000
        pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfRawData = 256
        pe[sec + 16..sec + 20].copy_from_slice(&256u32.to_le_bytes());
        // PointerToRawData = 0x400
        pe[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());

        // Extend buffer to include the .text section data
        pe.resize(0x400 + 256, 0xCC);

        // Place a syscall stub at .text offset 0 (file offset 0x400)
        let stub_off = 0x400;
        pe[stub_off..stub_off + 4].copy_from_slice(&STUB_PREFIX);
        pe[stub_off + 4..stub_off + 8].copy_from_slice(&42u32.to_le_bytes()); // syscall 42
        pe[stub_off + 8..stub_off + 16].copy_from_slice(&CFG_CHECK);
        pe[stub_off + 16..stub_off + 21].copy_from_slice(&SYSCALL_TAIL);

        let result = rewrite_ntdll(&pe, 0x1_0000_0000, 0x1_0001_0000);
        assert_eq!(result.stubs_rewritten, 1);
        // The byte at stub_off + 16 should now be 0xE9 (JMP rel32).
        assert_eq!(result.image[stub_off + 16], 0xE9);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration tests for the AArch64 (Linux) rewriter, exercised through the
//! public [`hook_syscalls_in_elf`] entry point.
//!
//! These assert byte-level invariants rather than an objdump snapshot: an
//! aarch64 objdump is not reliably available on the (x86) test host, and the
//! emitted trampoline is a clean reimplementation whose exact bytes differ from
//! the reference implementation.

// Deliberate, range-checked casts on a 64-bit host throughout this test.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use litebox_syscall_rewriter::aarch64::GATE_ALIGNMENT;
use litebox_syscall_rewriter::{
    AARCH64_X18_TRAMPOLINE_MAGIC, Error, RewriteOptions, TRAMPOLINE_MAGIC, TargetHost,
    hook_syscalls_in_elf, hook_syscalls_in_elf_with_options,
};
use std::process::Command;

const HELLO_AARCH64: &[u8] = include_bytes!("hello-aarch64");

/// `SVC #0`.
const SVC_0: u32 = 0xD400_0001;

/// `MSR TPIDR_EL0, Xt` / `MRS Xd, TPIDR_EL0`: the low 5 bits select the register,
/// so mask them off to match the opcode.
const TPIDR_REG_MASK: u32 = 0xFFFF_FFE0;
const MSR_TPIDR_BITS: u32 = 0xD51B_D040;
const MRS_TPIDR_BITS: u32 = 0xD53B_D040;

#[test]
fn big_endian_aarch64_is_rejected() {
    let mut elf = HELLO_AARCH64.to_vec();
    elf[5] = object::elf::ELFDATA2MSB;
    elf[18..20].copy_from_slice(&object::elf::EM_AARCH64.to_be_bytes());

    assert!(matches!(
        hook_syscalls_in_elf(&elf, Some(0)),
        Err(Error::UnsupportedExecutable(reason)) if reason.contains("big-endian AArch64")
    ));
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}
fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

/// Minimal ELF64 section-header walk: returns `(file_offset, vaddr, size)` for
/// every executable (`SHF_EXECINSTR`) `PROGBITS` section.
fn exec_sections(data: &[u8]) -> Vec<(usize, u64, usize)> {
    let e_shoff = read_u64(data, 40) as usize;
    let e_shentsize = read_u16(data, 58) as usize;
    let e_shnum = read_u16(data, 60) as usize;
    let mut out = Vec::new();
    for i in 0..e_shnum {
        let base = e_shoff + i * e_shentsize;
        let sh_type = read_u32(data, base + 4);
        let sh_flags = read_u64(data, base + 8);
        let sh_addr = read_u64(data, base + 16);
        let sh_offset = read_u64(data, base + 24) as usize;
        let sh_size = read_u64(data, base + 32) as usize;
        // SHT_PROGBITS = 1, SHF_EXECINSTR = 0x4.
        if sh_type == 1 && (sh_flags & 0x4) != 0 {
            out.push((sh_offset, sh_addr, sh_size));
        }
    }
    out
}

/// File offsets and virtual addresses of every `SVC #0` in the executable
/// sections of `data`.
fn svc_sites(data: &[u8]) -> Vec<(usize, u64)> {
    let mut sites = Vec::new();
    for (file_off, vaddr, size) in exec_sections(data) {
        let mut i = 0;
        while i + 4 <= size {
            if read_u32(data, file_off + i) == SVC_0 {
                sites.push((file_off + i, vaddr + i as u64));
            }
            i += 4;
        }
    }
    sites
}

/// File offset of the first instruction in `data`'s executable sections whose
/// bits satisfy `(insn & mask) == bits`, if any.
fn first_site(data: &[u8], mask: u32, bits: u32) -> Option<usize> {
    for (file_off, _vaddr, size) in exec_sections(data) {
        let mut i = 0;
        while i + 4 <= size {
            if read_u32(data, file_off + i) & mask == bits {
                return Some(file_off + i);
            }
            i += 4;
        }
    }
    None
}

/// File offset of the first exact word in an executable section.
fn first_exact_site(data: &[u8], expected: u32) -> Option<usize> {
    first_site(data, u32::MAX, expected)
}

fn separate_code_elf() -> Vec<u8> {
    const TEXT_OFFSET: u64 = 0x100;
    const TEXT_VADDR: u64 = 0x400100;
    const TEXT_SIZE: u64 = 0x40;
    let mut elf = HELLO_AARCH64.to_vec();
    elf[56..58].copy_from_slice(&2u16.to_le_bytes());
    elf[68..72].copy_from_slice(&object::elf::PF_R.to_le_bytes());
    elf[96..104].copy_from_slice(&TEXT_OFFSET.to_le_bytes());
    elf[104..112].copy_from_slice(&TEXT_OFFSET.to_le_bytes());
    let ph = 64 + 56;
    elf[ph..ph + 4].copy_from_slice(&object::elf::PT_LOAD.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&(object::elf::PF_R | object::elf::PF_X).to_le_bytes());
    elf[ph + 8..ph + 16].copy_from_slice(&TEXT_OFFSET.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&TEXT_VADDR.to_le_bytes());
    elf[ph + 24..ph + 32].copy_from_slice(&TEXT_VADDR.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&TEXT_SIZE.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&TEXT_SIZE.to_le_bytes());
    elf[ph + 48..ph + 56].copy_from_slice(&0x10000u64.to_le_bytes());
    elf
}

fn executable_data_outside_text_elf(word: u32) -> (Vec<u8>, usize) {
    let mut elf = separate_code_elf();
    let offset = 0x100;
    assert!(
        exec_sections(&elf)
            .iter()
            .all(|(start, _, size)| !(*start..*start + *size).contains(&offset))
    );
    elf[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    (elf, offset)
}

fn executable_alias_elf(first_size: u64, second_vaddr: u64) -> Vec<u8> {
    const TEXT_OFFSET: usize = 0x100;
    const TEXT_VADDR: u64 = 0x400100;
    const SECOND_OFFSET: u64 = 0x120;
    const SECOND_SIZE: u64 = 0x20;
    const NOP: u32 = 0xD503_201F;
    let mut elf = separate_code_elf();
    elf[40..48].copy_from_slice(&0u64.to_le_bytes());
    elf[58..64].fill(0);
    elf[68..72].copy_from_slice(&(object::elf::PF_R | object::elf::PF_X).to_le_bytes());
    elf[72..80].copy_from_slice(&(TEXT_OFFSET as u64).to_le_bytes());
    elf[80..88].copy_from_slice(&TEXT_VADDR.to_le_bytes());
    elf[88..96].copy_from_slice(&TEXT_VADDR.to_le_bytes());
    elf[96..104].copy_from_slice(&first_size.to_le_bytes());
    elf[104..112].copy_from_slice(&first_size.to_le_bytes());
    let second = 64 + 56;
    elf[second + 8..second + 16].copy_from_slice(&SECOND_OFFSET.to_le_bytes());
    elf[second + 16..second + 24].copy_from_slice(&second_vaddr.to_le_bytes());
    elf[second + 24..second + 32].copy_from_slice(&second_vaddr.to_le_bytes());
    elf[second + 32..second + 40].copy_from_slice(&SECOND_SIZE.to_le_bytes());
    elf[second + 40..second + 48].copy_from_slice(&SECOND_SIZE.to_le_bytes());
    for bytes in elf[TEXT_OFFSET..TEXT_OFFSET + 0x40].chunks_exact_mut(4) {
        bytes.copy_from_slice(&NOP.to_le_bytes());
    }
    elf[0x120..0x124].copy_from_slice(&SVC_0.to_le_bytes());
    elf
}

fn executable_section_alias_elf(word: u32, alias_vaddr: u64) -> (Vec<u8>, usize) {
    let mut elf = HELLO_AARCH64.to_vec();
    let section_table = read_u64(&elf, 40) as usize;
    let section_size = read_u16(&elf, 58) as usize;
    let section_count = read_u16(&elf, 60) as usize;
    let text = section_table + section_size;
    let alias = section_table + section_count * section_size;
    let text_offset = read_u64(&elf, text + 24) as usize;

    elf.resize(alias + section_size, 0);
    elf.copy_within(text..text + section_size, alias);
    elf[alias + 16..alias + 24].copy_from_slice(&alias_vaddr.to_le_bytes());
    elf[alias + 24..alias + 32]
        .copy_from_slice(&u64::try_from(text_offset + 4).unwrap().to_le_bytes());
    let alias_size = read_u64(&elf, alias + 32) - 4;
    elf[alias + 32..alias + 40].copy_from_slice(&alias_size.to_le_bytes());
    elf[60..62].copy_from_slice(&u16::try_from(section_count + 1).unwrap().to_le_bytes());
    elf[text_offset + 4..text_offset + 8].copy_from_slice(&word.to_le_bytes());
    (elf, text_offset + 4)
}

fn x18_only_elf() -> (Vec<u8>, usize) {
    const MOV_X8_64: u32 = 0xD280_0808;
    const MOV_X18_X0: u32 = 0xAA00_03F2;
    let mut elf = separate_code_elf();
    for (offset, _, size) in exec_sections(&elf) {
        for at in (offset..offset + size).step_by(4) {
            let word = read_u32(&elf, at);
            if word == SVC_0
                || word & TPIDR_REG_MASK == MSR_TPIDR_BITS
                || word & TPIDR_REG_MASK == MRS_TPIDR_BITS
            {
                elf[at..at + 4].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
            }
        }
    }
    let x18_offset = first_exact_site(&elf, MOV_X8_64).unwrap();
    elf[x18_offset..x18_offset + 4].copy_from_slice(&MOV_X18_X0.to_le_bytes());
    (elf, x18_offset)
}

fn no_patch_sites_elf() -> Vec<u8> {
    let (mut elf, _) = x18_only_elf();
    for (offset, _, size) in exec_sections(&elf) {
        for at in (offset..offset + size).step_by(4) {
            elf[at..at + 4].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
        }
    }
    elf
}

/// Decode the trailing [`TrampolineHeader64`]: `(file_offset, vaddr, size)`.
fn trampoline_header(out: &[u8]) -> (u64, u64, u64) {
    let header = &out[out.len() - 32..];
    (
        read_u64(header, 8),
        read_u64(header, 16),
        read_u64(header, 24),
    )
}

#[test]
fn aarch64_hello_world_is_hooked() {
    let original_sites = svc_sites(HELLO_AARCH64);
    assert_eq!(original_sites.len(), 3, "expected 3 SVC sites in fixture");

    let callback = 0xDEAD_0000u64;
    let out = hook_syscalls_in_elf(HELLO_AARCH64, Some(callback)).unwrap();

    // Output grew: original (patched, same length) + padding + trampoline + header.
    assert!(out.len() > HELLO_AARCH64.len());
    assert_eq!(&out[out.len() - 32..out.len() - 24], TRAMPOLINE_MAGIC);

    // --- Trailing header invariants ---
    let (file_offset, vaddr, size) = trampoline_header(&out);
    assert!(
        size != 0,
        "fixture has SVC sites, so a trampoline is emitted"
    );
    assert_eq!(
        file_offset % 0x1000,
        0,
        "trampoline file offset page-aligned"
    );
    assert_eq!(vaddr % 0x1000, 0, "trampoline vaddr page-aligned");
    assert_eq!(
        file_offset + size,
        (out.len() - 32) as u64,
        "trampoline must end right before the 32-byte header"
    );

    // --- Trampoline prologue invariants ---
    let tramp = &out[file_offset as usize..(file_offset + size) as usize];
    // Offset 0: callback slot holds the value we passed in.
    assert_eq!(read_u64(tramp, 0), callback, "callback slot");
    // Offset 8: deterministic NOP padding; each SVC slot dispatches through
    // the single callback pointer directly.
    assert_eq!(read_u32(tramp, 8), 0xD503_201F, "header NOP padding");
    assert_eq!(read_u32(tramp, 12), 0xD503_201F, "header NOP padding");

    // --- Every SVC became a branch into the trampoline region ---
    let tramp_range = vaddr..(vaddr + size);
    for (file_off, site_vaddr) in &original_sites {
        let word = read_u32(&out, *file_off);
        assert_eq!(
            word & 0xFC00_0000,
            0x1400_0000,
            "SVC at {site_vaddr:#x} should be rewritten to B"
        );
        // Reconstruct the branch target and confirm it lands in the trampoline.
        let imm26 = i64::from(word & 0x03FF_FFFF);
        // Sign-extend the 26-bit immediate, then scale by 4.
        let disp = (imm26 << 38) >> 38 << 2;
        let target = site_vaddr.wrapping_add(disp as u64);
        assert!(
            tramp_range.contains(&target),
            "branch target {target:#x} not in trampoline range {tramp_range:?}"
        );
    }

    // --- Thread-pointer handling ---
    // The `MSR TPIDR_EL0` write is virtualized: rewritten to a branch into the
    // trampoline's MSR gate.
    let msr_off = first_site(HELLO_AARCH64, TPIDR_REG_MASK, MSR_TPIDR_BITS)
        .expect("fixture has an MSR TPIDR_EL0 write");
    assert_eq!(
        read_u32(&out, msr_off) & 0xFC00_0000,
        0x1400_0000,
        "MSR TPIDR_EL0 should be rewritten to B"
    );

    // The `MRS TPIDR_EL0` read is virtualized: rewritten to a branch into the
    // MRS gate.
    let mrs_off = first_site(HELLO_AARCH64, TPIDR_REG_MASK, MRS_TPIDR_BITS)
        .expect("fixture has an MRS TPIDR_EL0 read");
    assert_eq!(
        read_u32(&out, mrs_off) & 0xFC00_0000,
        0x1400_0000,
        "MRS TPIDR_EL0 should be rewritten to B"
    );
}

#[test]
fn default_aarch64_rewrite_ignores_instruction_shaped_data_outside_text() {
    let (elf, offset) = executable_data_outside_text_elf(SVC_0);

    let baseline = hook_syscalls_in_elf(HELLO_AARCH64, Some(0)).unwrap();
    let rewritten = hook_syscalls_in_elf(&elf, Some(0)).unwrap();

    assert_eq!(read_u32(&rewritten, offset), SVC_0);
    assert_eq!(&rewritten[0x110..0x140], &baseline[0x110..0x140]);
    assert_eq!(trampoline_header(&rewritten), trampoline_header(&baseline));
    let (trampoline_offset, _, trampoline_size) = trampoline_header(&rewritten);
    assert_eq!(
        &rewritten[trampoline_offset as usize..(trampoline_offset + trampoline_size) as usize],
        &baseline[trampoline_offset as usize..(trampoline_offset + trampoline_size) as usize]
    );
}

#[test]
fn x18_enabled_aarch64_rewrite_ignores_executable_metadata_outside_code_ranges() {
    let (elf, offset) = executable_data_outside_text_elf(0xAA00_03F2); // mov x18, x0

    let rewritten = hook_syscalls_in_elf_with_options(
        &elf,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap();

    assert_eq!(read_u32(&rewritten, offset), 0xAA00_03F2);
}

#[test]
fn default_aarch64_rewrite_without_executable_text_is_unchanged() {
    let elf = executable_alias_elf(0x20, 0x400120);

    assert_eq!(hook_syscalls_in_elf(&elf, Some(0)).unwrap(), elf);
}

#[test]
fn x18_enabled_aarch64_rewrite_without_identifiable_code_is_rejected() {
    let elf = executable_alias_elf(0x20, 0x400120);

    let error = hook_syscalls_in_elf_with_options(
        &elf,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap_err();

    assert!(
        matches!(error, Error::UnsupportedExecutable(ref reason)
            if reason.contains("identifiable code ranges")),
        "{error:?}"
    );
}

#[test]
fn default_aarch64_rewrite_rejects_conflicting_executable_aliases() {
    let (elf, site) = executable_section_alias_elf(SVC_0, 0x500114);
    let before = elf.clone();

    let error = hook_syscalls_in_elf(&elf, Some(0)).unwrap_err();

    assert!(
        matches!(error, Error::UnsupportedExecutable(ref reason)
            if reason.contains("conflicting executable aliases")),
        "{error:?}"
    );
    assert_eq!(elf, before);
    assert_eq!(read_u32(&elf, site), SVC_0);
}

#[test]
fn x18_aarch64_rewrite_rejects_conflicting_conditional_aliases() {
    const CBZ_X18_NEXT: u32 = 0xB400_0032;
    let (elf, site) = executable_section_alias_elf(CBZ_X18_NEXT, 0x500114);
    let before = elf.clone();

    let error = hook_syscalls_in_elf_with_options(
        &elf,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap_err();

    assert!(
        matches!(error, Error::UnsupportedExecutable(ref reason)
            if reason.contains("conflicting executable aliases")),
        "{error:?}"
    );
    assert_eq!(elf, before);
    assert_eq!(read_u32(&elf, site), CBZ_X18_NEXT);
}

#[test]
fn compatible_executable_aliases_patch_each_file_word_once() {
    let (elf, site) = executable_section_alias_elf(SVC_0, 0x400114);
    let mut baseline = elf.clone();
    baseline[60..62].copy_from_slice(&5u16.to_le_bytes());

    let rewritten = hook_syscalls_in_elf(&elf, Some(0)).unwrap();
    let baseline = hook_syscalls_in_elf(&baseline, Some(0)).unwrap();

    assert_eq!(read_u32(&rewritten, site) & 0xFC00_0000, 0x1400_0000);
    assert_eq!(
        trampoline_header(&rewritten).2,
        trampoline_header(&baseline).2
    );
}

#[test]
fn aarch64_mapping_symbols_skip_data_and_resume_code() {
    const MOV_X18_X0: u32 = 0xAA00_03F2;
    let mut elf = HELLO_AARCH64.to_vec();
    let text_offset = exec_sections(&elf)[0].0;
    let symbol_table = read_u64(&elf, 40) as usize - 0x190;
    let string_table = symbol_table + 0x120;

    let data_name = elf[string_table..]
        .windows(7)
        .position(|name| name == b"_edata\0")
        .unwrap();
    let code_name = elf[string_table..]
        .windows(6)
        .position(|name| name == b"_end__")
        .unwrap();
    elf[string_table + data_name..string_table + data_name + 3].copy_from_slice(b"$d\0");
    elf[string_table + code_name..string_table + code_name + 3].copy_from_slice(b"$x\0");

    for (symbol_index, name, address) in [
        (10, data_name as u32, 0x400118u64),
        (11, code_name as u32, 0x40011cu64),
    ] {
        let symbol = symbol_table + symbol_index * 24;
        elf[symbol..symbol + 4].copy_from_slice(&name.to_le_bytes());
        elf[symbol + 8..symbol + 16].copy_from_slice(&address.to_le_bytes());
    }
    let function = symbol_table + 7 * 24;
    elf[function + 4] = 0x12; // STB_GLOBAL | STT_FUNC
    elf[function + 16..function + 24].copy_from_slice(&0x30u64.to_le_bytes());
    elf[text_offset + 8..text_offset + 12].copy_from_slice(&MOV_X18_X0.to_le_bytes());
    elf[text_offset + 12..text_offset + 16].copy_from_slice(&MOV_X18_X0.to_le_bytes());

    let rewritten = hook_syscalls_in_elf_with_options(
        &elf,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap();

    assert_eq!(read_u32(&rewritten, text_offset + 8), MOV_X18_X0);
    assert_eq!(
        read_u32(&rewritten, text_offset + 12) & 0xFC00_0000,
        0x1400_0000
    );
}

#[test]
fn aarch64_rehooking_is_idempotent() {
    let out = hook_syscalls_in_elf(HELLO_AARCH64, Some(0)).unwrap();
    // Running the rewriter on an already-hooked binary returns it unchanged.
    let again = hook_syscalls_in_elf(&out, Some(0)).unwrap();
    assert_eq!(
        again, out,
        "already-hooked binary must be returned unchanged"
    );
}

#[test]
fn aarch64_x18_rewrite_uses_distinct_policy_magic() {
    let (elf, _) = x18_only_elf();
    let out = hook_syscalls_in_elf_with_options(
        &elf,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap();

    assert_eq!(
        &out[out.len() - 32..out.len() - 24],
        AARCH64_X18_TRAMPOLINE_MAGIC
    );
    assert_ne!(AARCH64_X18_TRAMPOLINE_MAGIC, TRAMPOLINE_MAGIC);
}

#[test]
fn aarch64_x18_no_site_sentinel_uses_x18_policy_magic() {
    let out = hook_syscalls_in_elf_with_options(
        &no_patch_sites_elf(),
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap();

    assert_eq!(
        &out[out.len() - 32..out.len() - 24],
        AARCH64_X18_TRAMPOLINE_MAGIC
    );
    assert_eq!(trampoline_header(&out), (0, 0, 0));
}

#[test]
fn default_sentinel_then_x18_rewrite_reports_policy_mismatch() {
    let default = hook_syscalls_in_elf(&no_patch_sites_elf(), Some(0)).unwrap();
    let error = hook_syscalls_in_elf_with_options(
        &default,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap_err();

    assert!(matches!(error, Error::UnsupportedExecutable(reason)
        if reason.contains("rewrite policy mismatch") && reason.contains("x18")));
}

#[test]
fn x18_sentinel_then_default_rewrite_reports_policy_mismatch() {
    let x18 = hook_syscalls_in_elf_with_options(
        &no_patch_sites_elf(),
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap();
    let error = hook_syscalls_in_elf(&x18, Some(0)).unwrap_err();

    assert!(matches!(error, Error::UnsupportedExecutable(reason)
        if reason.contains("rewrite policy mismatch") && reason.contains("default")));
}

#[test]
fn nonempty_aarch64_rewrites_reject_opposite_policy() {
    let default = hook_syscalls_in_elf(HELLO_AARCH64, Some(0)).unwrap();
    let default_error = hook_syscalls_in_elf_with_options(
        &default,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap_err();
    assert!(matches!(default_error, Error::UnsupportedExecutable(reason)
        if reason.contains("rewrite policy mismatch")));

    let (elf, _) = x18_only_elf();
    let x18 = hook_syscalls_in_elf_with_options(
        &elf,
        Some(0),
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap();
    let x18_error = hook_syscalls_in_elf(&x18, Some(0)).unwrap_err();
    assert!(matches!(x18_error, Error::UnsupportedExecutable(reason)
        if reason.contains("rewrite policy mismatch")));
}

#[test]
fn each_target_host_emits_its_exact_x18_anchor_instruction() {
    let (elf, _) = x18_only_elf();

    for (host, expected_anchor) in [
        (TargetHost::Linux, 0xD53B_D050),   // mrs x16, tpidr_el0
        (TargetHost::MacOs, 0xD53B_D070),   // mrs x16, tpidrro_el0
        (TargetHost::Windows, 0xAA12_03F0), // mov x16, x18
    ] {
        let out = hook_syscalls_in_elf_with_options(&elf, Some(0), RewriteOptions::new(host, true))
            .unwrap();
        let (offset, _, size) = trampoline_header(&out);
        let trampoline = &out[offset as usize..(offset + size) as usize];
        assert_eq!(
            read_u32(trampoline, GATE_ALIGNMENT),
            expected_anchor,
            "{host:?}"
        );
    }
}

#[test]
fn non_linux_x18_only_elf_rewrites_but_host_specific_tp_sites_are_rejected() {
    let (x18_only, x18_offset) = x18_only_elf();

    for host in [TargetHost::MacOs, TargetHost::Windows] {
        let rewritten =
            hook_syscalls_in_elf_with_options(&x18_only, Some(0), RewriteOptions::new(host, false))
                .unwrap();
        assert_eq!(read_u32(&rewritten, x18_offset) & 0xFC00_0000, 0x1400_0000);

        let error = hook_syscalls_in_elf_with_options(
            HELLO_AARCH64,
            Some(0),
            RewriteOptions::new(host, false),
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::UnsupportedExecutable(ref reason)
                if reason.contains("host") && reason.contains("site")),
            "{host:?}: {error:?}"
        );
    }
}

#[test]
fn cli_rewrites_x18_only_elf_for_each_target_host() {
    let (elf, x18_offset) = x18_only_elf();
    let directory =
        std::env::temp_dir().join(format!("litebox-aarch64-hosts-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("input");
    std::fs::write(&input, elf).unwrap();

    for host in ["linux", "macos", "windows"] {
        let output = directory.join(host);
        let mut command = Command::new(env!("CARGO_BIN_EXE_litebox_syscall_rewriter"));
        command
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .args(["--target-host", host]);
        if host == "linux" {
            command.arg("--virtualize-x18");
        }
        let status = command.status().unwrap();
        assert!(status.success(), "CLI rewrite failed for {host}");
        let rewritten = std::fs::read(output).unwrap();
        assert_eq!(read_u32(&rewritten, x18_offset) & 0xFC00_0000, 0x1400_0000);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn each_host_structurally_finalizes_only_its_own_x18_topology() {
    for host in [TargetHost::Linux, TargetHost::MacOs, TargetHost::Windows] {
        let (elf, _) = x18_only_elf();
        let rewritten =
            hook_syscalls_in_elf_with_options(&elf, Some(0), RewriteOptions::new(host, true))
                .unwrap();
        let (offset, _, size) = trampoline_header(&rewritten);
        let mut trampoline = rewritten[offset as usize..(offset + size) as usize].to_vec();
        let offsets =
            litebox_syscall_rewriter::aarch64::Aarch64GateOffsets::new(96, 104, 112, 120).unwrap();

        litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_for_host(
            &mut trampoline,
            offsets,
            host,
        )
        .unwrap();
        assert_eq!(
            litebox_syscall_rewriter::aarch64::classify_x18_topology_for_host(&trampoline, host),
            litebox_syscall_rewriter::aarch64::X18Topology::Valid
        );
        for wrong in [TargetHost::Linux, TargetHost::MacOs, TargetHost::Windows] {
            if wrong != host {
                assert_ne!(
                    litebox_syscall_rewriter::aarch64::classify_x18_topology_for_host(
                        &trampoline,
                        wrong,
                    ),
                    litebox_syscall_rewriter::aarch64::X18Topology::Valid
                );
                let mut mismatched = rewritten[offset as usize..(offset + size) as usize].to_vec();
                let before = mismatched.clone();
                assert!(
                    litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_for_host(
                        &mut mismatched,
                        offsets,
                        wrong,
                    )
                    .is_err()
                );
                assert_eq!(
                    mismatched, before,
                    "wrong-host finalization must be transactional"
                );
            }
        }
    }
}

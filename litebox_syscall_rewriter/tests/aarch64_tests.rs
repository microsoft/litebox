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

use litebox_syscall_rewriter::{TRAMPOLINE_MAGIC, hook_syscalls_in_elf};

const HELLO_AARCH64: &[u8] = include_bytes!("hello-aarch64");

/// `SVC #0`.
const SVC_0: u32 = 0xD400_0001;

/// `MSR TPIDR_EL0, Xt` / `MRS Xd, TPIDR_EL0`: the low 5 bits select the register,
/// so mask them off to match the opcode.
const TPIDR_REG_MASK: u32 = 0xFFFF_FFE0;
const MSR_TPIDR_BITS: u32 = 0xD51B_D040;
const MRS_TPIDR_BITS: u32 = 0xD53B_D040;

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

/// Decode the trailing [`TrampolineHeader64`]: `(file_offset, vaddr, size)`.
fn trampoline_header(out: &[u8]) -> (u64, u64, u64) {
    let header = &out[out.len() - 32..];
    assert_eq!(&header[..8], TRAMPOLINE_MAGIC, "trampoline magic mismatch");
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
    // Offset 8: the shared SVC handler — LDR X16,<callback@0>; BR X16.
    assert_eq!(
        read_u32(tramp, 8),
        0x58FF_FFD0,
        "LDR X16, <callback> (pcrel -8)"
    );
    assert_eq!(read_u32(tramp, 12), 0xD61F_0200, "BR X16");

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
fn aarch64_rehooking_is_idempotent() {
    let out = hook_syscalls_in_elf(HELLO_AARCH64, Some(0)).unwrap();
    // Running the rewriter on an already-hooked binary returns it unchanged.
    let again = hook_syscalls_in_elf(&out, Some(0)).unwrap();
    assert_eq!(
        again, out,
        "already-hooked binary must be returned unchanged"
    );
}

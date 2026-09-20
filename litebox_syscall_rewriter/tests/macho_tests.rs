// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 Mach-O rewriter integration tests.
#![allow(clippy::cast_possible_truncation)]

use litebox_syscall_rewriter::{
    Error, TRAMPOLINE_MAGIC, TargetHost,
    aarch64::{self, GateMetadata},
    hook_syscalls_in_macho,
    macho::{CodeMetadata, Rewriter},
    rewrite_binary,
};
use object::macho;

const BASE: u64 = 0x1_0000_0000;
const TEXT: usize = 0x400;
const SECTION: usize = 32 + 72;
const SVC: u32 = 0xd400_1001;
const MRS: u32 = 0xd53b_d063; // mrs x3, tpidrro_el0
const NOP: u32 = 0xd503_201f;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn image(words: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0; 0x4000];
    put32(&mut bytes, 0, macho::MH_MAGIC_64);
    put32(&mut bytes, 4, macho::CPU_TYPE_ARM64);
    put32(&mut bytes, 12, macho::MH_EXECUTE);
    put32(&mut bytes, 16, 1);
    put32(&mut bytes, 20, 72 + 80 * 2);
    put32(&mut bytes, 24, macho::MH_PIE);
    put32(&mut bytes, 32, macho::LC_SEGMENT_64);
    put32(&mut bytes, 36, 72 + 80 * 2);
    bytes[40..46].copy_from_slice(b"__TEXT");
    put64(&mut bytes, 56, BASE);
    put64(&mut bytes, 64, 0x4000);
    put64(&mut bytes, 80, 0x4000);
    put32(&mut bytes, 88, 5);
    put32(&mut bytes, 92, 5);
    put32(&mut bytes, 96, 2);
    for (section, name, offset, size, flags) in [
        (
            SECTION,
            b"__text".as_slice(),
            TEXT,
            words.len() * 4,
            macho::S_ATTR_PURE_INSTRUCTIONS,
        ),
        (SECTION + 80, b"__const".as_slice(), 0x3000, 8, 0),
    ] {
        bytes[section..section + name.len()].copy_from_slice(name);
        bytes[section + 16..section + 22].copy_from_slice(b"__TEXT");
        put64(&mut bytes, section + 32, BASE + offset as u64);
        put64(&mut bytes, section + 40, size as u64);
        put32(&mut bytes, section + 48, offset as u32);
        put32(&mut bytes, section + 52, 2);
        put32(&mut bytes, section + 64, flags);
    }
    for (i, &word) in words.iter().enumerate() {
        put32(&mut bytes, TEXT + i * 4, word);
    }
    put32(&mut bytes, 0x3000, SVC);
    put32(&mut bytes, 0x3004, MRS);
    bytes
}

fn add_command(bytes: &mut [u8], command: u32, size: u32) -> usize {
    let count = u32_at(bytes, 16);
    let old_size = u32_at(bytes, 20);
    let offset = 32 + old_size as usize;
    assert!(offset + size as usize <= TEXT);
    put32(bytes, offset, command);
    put32(bytes, offset + 4, size);
    put32(bytes, 16, count + 1);
    put32(bytes, 20, old_size + size);
    offset
}

fn add_segment(bytes: &mut [u8], start: u64, size: u64) {
    let command = add_command(bytes, macho::LC_SEGMENT_64, 72);
    bytes[command + 8..command + 14].copy_from_slice(b"__DATA");
    put64(bytes, command + 24, start);
    put64(bytes, command + 32, size);
    put32(bytes, command + 56, 3);
    put32(bytes, command + 60, 3);
}

fn footer(bytes: &[u8]) -> (usize, u64, usize) {
    let header = &bytes[bytes.len() - 32..];
    assert_eq!(&header[..8], TRAMPOLINE_MAGIC);
    (
        u64_at(header, 8) as usize,
        u64_at(header, 16),
        u64_at(header, 24) as usize,
    )
}

#[test]
fn arm64e_images_and_capability_bits_are_supported() {
    for subtype in [
        macho::CPU_SUBTYPE_ARM64E,
        macho::CPU_SUBTYPE_ARM64E | macho::CPU_SUBTYPE_PTRAUTH_ABI,
    ] {
        let mut input = image(&[SVC]);
        put32(&mut input, 8, subtype);
        CodeMetadata::parse(&input).unwrap();
        hook_syscalls_in_macho(&input, None).unwrap();
    }
}

#[test]
fn load_time_rewriting_uses_mapping_addresses_and_finalizes_gates() {
    let rewriter = Rewriter::new(TargetHost::MacOs).unwrap();
    let mut input = image(&[SVC, MRS, SVC, NOP]);
    let command = add_command(&mut input, macho::LC_DATA_IN_CODE, 16);
    put32(&mut input, command + 8, 0x3100);
    put32(&mut input, command + 12, 8);
    put32(&mut input, 0x3100, (TEXT + 8) as u32);
    input[0x3104..0x3106].copy_from_slice(&4u16.to_le_bytes());
    input[0x3106..0x3108].copy_from_slice(&1u16.to_le_bytes());
    let metadata = CodeMetadata::parse(&input).unwrap();
    let ranges = metadata.ranges_for_mapping(TEXT as u64, 16).unwrap();
    assert_eq!(ranges, vec![0..8, 12..16]);
    assert!(metadata.ranges_for_mapping(0x3000, 8).unwrap().is_empty());

    let callback = 0x1234_5678;
    let aot = rewrite_binary(&input, Some(callback)).unwrap();
    let (offset, base, size) = footer(&aot);
    let slide = 0x4000_0000;
    let code_vaddr = BASE + TEXT as u64 + slide;
    let mut code = input[TEXT..TEXT + 16].to_vec();
    let (gates, trapped) = rewriter
        .patch_code_segment(&mut code, code_vaddr, &ranges, base + slide, callback, 96)
        .unwrap();
    assert!(trapped.is_empty());
    assert_eq!(code, aot[TEXT..TEXT + 16]);
    assert_eq!(u32_at(&code, 8), SVC); // data-in-code is untouched
    assert!(
        gates.len()
            <= metadata
                .trampoline_size_upper_bound(&input, rewriter)
                .unwrap()
    );
    let mut aot_gates = aot[offset..offset + size].to_vec();
    rewriter
        .finalize_trampoline_gates(&mut aot_gates, 96)
        .unwrap();
    assert_eq!(gates, aot_gates);
    let svc = rewriter
        .classify_gate_slot(&gates[16..80], base + slide + 16, base + slide + 16)
        .unwrap();
    assert_eq!(svc.metadata(), GateMetadata::Svc);
    assert_eq!(svc.original_site(), code_vaddr);
    let tp = rewriter
        .classify_gate_slot(&gates[80..], base + slide + 80, base + slide + 80)
        .unwrap();
    assert_eq!(tp.original_site(), code_vaddr + 4);
    assert_eq!(u32_at(&gates, 88), 0xf940_3063); // finalized runtime TSD slot
    assert_eq!(u32_at(&gates, 92), 0xf940_0063); // logical TP within the TLS block
}

#[test]
#[expect(
    clippy::single_range_in_vec_init,
    reason = "mapping metadata contains ranges, not offsets"
)]
fn load_time_rewriting_errors_leave_code_unchanged() {
    let rewriter = Rewriter::new(TargetHost::MacOs).unwrap();
    let original = [SVC.to_le_bytes(), MRS.to_le_bytes()].concat();
    let mut code = original.clone();
    // Finalization fails after emission; the mapping must remain untouched.
    assert!(
        rewriter
            .patch_code_segment(&mut code, 0x1000, &[0..8], 0x2000, 0x1234, 0)
            .is_err()
    );
    assert_eq!(code, original);
    let mut code = [SVC.to_le_bytes(), 0xd51b_d060u32.to_le_bytes()].concat();
    let before = code.clone();
    assert!(
        rewriter
            .patch_code_segment(&mut code, 0x1000, &[0..8], 0x2000, 0x1234, 96)
            .is_err()
    );
    assert_eq!(code, before);
    assert!(
        rewriter
            .trap_code_segment(&mut code, 0x1000, &[0..8])
            .is_err()
    );
    assert_eq!(code, before);
}

#[test]
#[expect(
    clippy::single_range_in_vec_init,
    reason = "mapping metadata contains ranges, not offsets"
)]
fn load_time_out_of_range_sites_match_trap_fallback() {
    let rewriter = Rewriter::new(TargetHost::MacOs).unwrap();
    let original = [SVC.to_le_bytes(), MRS.to_le_bytes()].concat();
    let mut code = original.clone();
    let (gates, trapped) = rewriter
        .patch_code_segment(&mut code, 0x1000, &[0..8], 0x900_0000, 0x1234, 96)
        .unwrap();
    assert_eq!(trapped, vec![0x1000, 0x1004]);
    assert_eq!(gates.len(), 16); // callback header only
    for offset in [0, 4] {
        assert_eq!(u32_at(&code, offset) & 0xffe0_001f, 0xd420_0000);
    }
    let mut fallback = original;
    assert_eq!(
        rewriter
            .trap_code_segment(&mut fallback, 0x1000, &[0..8])
            .unwrap(),
        2
    );
    assert_eq!(fallback, code);
}

#[test]
fn load_time_finalization_checks_the_configured_frame_transactionally() {
    let rewriter = Rewriter::new(TargetHost::MacOs).unwrap();
    let out = hook_syscalls_in_macho(&image(&[MRS, SVC]), None).unwrap();
    let (offset, _, size) = footer(&out);
    let mut gates = out[offset..offset + size].to_vec();
    // A wrong SVC frame after the TP gate must not leave a patched TLS offset.
    put32(&mut gates, 48, 0xd100_83ff);
    let before = gates.clone();
    assert!(rewriter.finalize_trampoline_gates(&mut gates, 96).is_err());
    assert_eq!(gates, before);
}

#[test]
fn svc_frame_layout_is_selected_by_the_runner() {
    let rewriter = Rewriter::new(TargetHost::MacOs).unwrap();
    let out = hook_syscalls_in_macho(&image(&[SVC]), None).unwrap();
    let (offset, base, _) = footer(&out);
    let mut slot = out[offset + 16..offset + 80].to_vec();
    assert_eq!(u32_at(&slot, 0), 0xd102_83ff); // sub sp, sp, #160
    assert_eq!(u32_at(&slot, 40), 0x9102_83ff); // add sp, sp, #160
    assert!(
        aarch64::classify_copied_gate_slot_for_host(&slot, base + 16, base + 16, TargetHost::MacOs)
            .is_none()
    );
    assert_eq!(
        rewriter
            .classify_gate_slot(&slot, base + 16, base + 16)
            .unwrap()
            .metadata(),
        GateMetadata::Svc
    );
    put32(&mut slot, 0, 0xd100_83ff); // sub sp, sp, #32
    put32(&mut slot, 40, 0x9100_83ff); // add sp, sp, #32
    assert!(
        rewriter
            .classify_gate_slot(&slot, base + 16, base + 16)
            .is_none()
    );
    assert_eq!(
        aarch64::classify_copied_gate_slot_for_host(&slot, base + 16, base + 16, TargetHost::MacOs)
            .unwrap()
            .metadata(),
        GateMetadata::Svc
    );
}

#[test]
fn placement_uses_native_page_holes_and_counts_zerofill() {
    let mut input = image(&[SVC]);
    add_segment(&mut input, BASE + 0x10000, 0x4000);
    let out = hook_syscalls_in_macho(&input, None).unwrap();
    assert_eq!(footer(&out).1, BASE + 0x4000);
    // A contiguous large zero-fill segment leaves no reachable trampoline.
    let mut far = image(&[SVC]);
    add_segment(&mut far, BASE + 0x4000, 0x900_0000);
    assert!(matches!(
        hook_syscalls_in_macho(&far, None),
        Err(Error::UnpatchableSyscalls(_))
    ));
}

#[test]
fn small_hole_retries_past_the_image_without_rewriting_patched_code() {
    let mut input = image(&vec![SVC; 300]); // > 16 KiB of gates
    add_segment(&mut input, BASE + 0x8000, 0x4000);
    let out = hook_syscalls_in_macho(&input, None).unwrap();
    let (_, base, size) = footer(&out);
    assert!(base >= BASE + 0xc000);
    assert_eq!(size, 16 + 300 * 64);
    assert_eq!(
        aarch64::decode_branch_target(u32_at(&out, TEXT), BASE + TEXT as u64),
        Some(base + 16)
    );
}

#[test]
fn high_virtual_addresses_do_not_overflow_file_range_projection() {
    let mut high = image(&[SVC]);
    let high_base = !0x3fffu64;
    put64(&mut high, 56, high_base);
    put64(&mut high, 64, 0x3ffc);
    put64(&mut high, 80, 0x3ffc);
    put64(&mut high, SECTION + 32, high_base + 0x3000);
    put32(&mut high, SECTION + 48, 0x3000);
    assert!(matches!(
        hook_syscalls_in_macho(&high, None),
        Err(Error::AddressOverflow(_))
    ));
}

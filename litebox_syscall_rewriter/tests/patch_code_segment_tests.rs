// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_syscall_rewriter::patch_code_segment;

/// Basic test: synthetic code with `nop; nop; nop; syscall; ret`
#[test]
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn patch_single_syscall() {
    //                     nop   nop   nop   syscall  ret
    let mut code = vec![0x90, 0x90, 0x90, 0x0F, 0x05, 0xC3];
    let code_vaddr: u64 = 0x40_1000;
    // Entry point at start of trampoline region, stubs follow after 8 bytes
    let syscall_entry_addr: u64 = 0x40_2000;
    let trampoline_write_vaddr: u64 = syscall_entry_addr + 8;

    let mut skipped = Vec::new();
    let stubs = patch_code_segment(
        &mut code,
        code_vaddr,
        trampoline_write_vaddr,
        syscall_entry_addr,
        &mut skipped,
    )
    .unwrap();

    // First 5 bytes should be a JMP rel32
    assert_eq!(code[0], 0xE9, "should be JMP rel32");
    let jmp_rel32 = i32::from_le_bytes(code[1..5].try_into().unwrap());
    let jmp_target = (code_vaddr as i64 + 5 + i64::from(jmp_rel32)) as u64;
    assert_eq!(
        jmp_target, trampoline_write_vaddr,
        "JMP should target start of stubs"
    );

    // Stubs must be non-empty
    assert!(!stubs.is_empty(), "should have trampoline stubs");

    // Stubs should contain a JMP [RIP+disp32] (FF 25) targeting syscall_entry_addr
    let jmp_indirect_pos = stubs
        .windows(2)
        .position(|w| w == [0xFF, 0x25])
        .expect("stubs should contain JMP [RIP+disp32]");
    let disp32 = i32::from_le_bytes(
        stubs[jmp_indirect_pos + 2..jmp_indirect_pos + 6]
            .try_into()
            .unwrap(),
    );
    // RIP after = trampoline_write_vaddr + position_after_disp32
    let rip_after = trampoline_write_vaddr as i64 + jmp_indirect_pos as i64 + 6;
    let target = (rip_after + i64::from(disp32)) as u64;
    assert_eq!(
        target, syscall_entry_addr,
        "indirect JMP should target entry point"
    );
}

/// Code with no syscalls should return empty stubs and leave code unchanged.
#[test]
fn no_syscalls_returns_empty() {
    //                     nop   nop   ret
    let original = vec![0x90, 0x90, 0xC3];
    let mut code = original.clone();

    let stubs =
        patch_code_segment(&mut code, 0x40_1000, 0x40_2008, 0x40_2000, &mut Vec::new()).unwrap();

    assert!(stubs.is_empty(), "no syscalls → no stubs");
    assert_eq!(code, original, "code should be unmodified");
}

/// Compare patch_code_segment against hook_syscalls_in_elf on the same binary:
/// the .text section patches and trampoline stubs should be byte-identical.
#[test]
#[allow(clippy::cast_possible_truncation)]
fn matches_hook_syscalls_in_elf() {
    use object::read::{Object as _, ObjectSection as _};

    let input = include_bytes!("hello");

    // --- Run the whole-file API ---
    let output = litebox_syscall_rewriter::hook_syscalls_in_elf(input, None, &mut Vec::new())
        .expect("hook_syscalls_in_elf");

    // Parse the trampoline header (last 32 bytes for 64-bit)
    let hdr_start = output.len() - 32;
    let trampoline_file_offset =
        u64::from_le_bytes(output[hdr_start + 8..hdr_start + 16].try_into().unwrap());
    let trampoline_vaddr =
        u64::from_le_bytes(output[hdr_start + 16..hdr_start + 24].try_into().unwrap());
    let trampoline_size =
        u64::from_le_bytes(output[hdr_start + 24..hdr_start + 32].try_into().unwrap()) as usize;

    // The first 8 bytes of the trampoline code are the entry-point placeholder (zeros).
    let trampoline_code_start = trampoline_file_offset as usize + 8;
    let trampoline_stubs_from_elf = &output[trampoline_code_start..][..trampoline_size - 8];

    // --- Run the per-segment API on each executable section ---
    // We need to reproduce the same setup: parse the ELF, find .text sections.
    // Align input for object::File::parse
    let mut backing = vec![0u64; input.len().div_ceil(8)];
    let buf: &mut [u8] = zerocopy::IntoBytes::as_mut_bytes(backing.as_mut_slice());
    buf[..input.len()].copy_from_slice(input);
    let buf = &mut buf[..input.len()];

    let file = object::File::parse(&*buf).unwrap();
    let text_sections: Vec<(u64, u64, u64)> = file
        .sections()
        .filter_map(|s| {
            let object::SectionFlags::Elf { sh_flags } = s.flags() else {
                return None;
            };
            if s.kind() != object::SectionKind::Text {
                return None;
            }
            if sh_flags & u64::from(object::elf::SHF_ALLOC) == 0 {
                return None;
            }
            if sh_flags & u64::from(object::elf::SHF_EXECINSTR) == 0 {
                return None;
            }
            let (file_offset, size) = s.file_range()?;
            Some((s.address(), file_offset, size))
        })
        .collect();
    drop(file);

    // The entry-point address for stubs (same as trampoline_vaddr for the
    // whole-file API since offset 0 of the trampoline holds the entry).
    let entry_point_addr = trampoline_vaddr;
    let stubs_base = trampoline_vaddr + 8; // stubs start after the 8-byte entry

    let mut all_stubs = Vec::new();
    for &(vaddr, file_offset, size) in &text_sections {
        let off = file_offset as usize;
        let sz = size as usize;
        let mut section_data = buf[off..off + sz].to_vec();
        let write_vaddr = stubs_base + all_stubs.len() as u64;
        let stubs = patch_code_segment(
            &mut section_data,
            vaddr,
            write_vaddr,
            entry_point_addr,
            &mut Vec::new(),
        )
        .expect("patch_code_segment");

        // The patched section bytes should match those in the whole-file output.
        assert_eq!(
            &section_data[..],
            &output[off..off + sz],
            "patched section at vaddr {vaddr:#x} should match hook_syscalls_in_elf output"
        );

        all_stubs.extend_from_slice(&stubs);
    }

    assert_eq!(
        all_stubs, trampoline_stubs_from_elf,
        "accumulated stubs should match hook_syscalls_in_elf trampoline (minus 8-byte header)"
    );
}

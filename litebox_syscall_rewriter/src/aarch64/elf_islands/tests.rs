// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::{hook_syscalls_in_elf, hook_syscalls_in_elf_with_options};

const HELLO: &[u8] = include_bytes!("../../../tests/hello-aarch64");

fn output() -> Vec<u8> {
    hook_syscalls_in_elf(HELLO, None).unwrap()
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn elf_islands_roundtrip_byte_aligned_and_arbitrary_far_finalization() {
    let out = output();
    let mut unaligned = vec![0];
    unaligned.extend_from_slice(&out);
    let payload = ElfIslands::parse(&unaligned[1..]).unwrap().unwrap();
    assert_eq!(payload.pairs.len(), 1);
    assert_eq!(payload.pairs[0].slots_used(), 5);
    assert_eq!(hook_syscalls_in_elf(&out, Some(123)).unwrap(), out);
    for far in [0x10_0000_0000, 0x7000_0000_0000] {
        let mut pair = payload.pairs[0].clone();
        pair.set_chunk_vaddr(far).unwrap();
        pair.set_callback(0x1234);
        let mut chunk = pair.chunk().to_vec();
        island::finalize_island_chunk(&mut chunk, 96, TargetHost::Linux).unwrap();
        assert_eq!(
            island::decode_island_header(pair.island()),
            Some(island::island_delta(pair.island_vaddr(), far))
        );
        IslandPair::from_images(
            pair.island_vaddr(),
            pair.island().to_vec(),
            chunk,
            TargetHost::Linux,
        )
        .unwrap();
    }
}

#[test]
fn elf_islands_reject_descriptor_footer_ranges_counts_and_truncation() {
    let out = output();
    let tail = out.len() - 32;
    let base = usize::try_from(u64_at(&out, tail + 8).unwrap()).unwrap();
    for (at, value) in [
        (tail + 8, u64::MAX),
        (tail + 16, 1),
        (tail + 24, u64::MAX),
        (base + 8, 2),
        (base + 16, 3),
        (base + 24, 8192),
        (base + 32, u64::MAX),
        (base + 32, 0),
        (base + 40, 39),
        (base + 48, u64::MAX),
        (base + 56, 1),
        (base + 64, 0),
        (base + 64, u64::MAX - 4095),
        (base + 72, 64),
        (base + 80, 4095),
        (base + 88, 64),
        (base + 96, u64::MAX),
    ] {
        let mut corrupt = out.clone();
        put64(&mut corrupt, at, value);
        assert!(
            ElfIslands::parse(&corrupt).is_err(),
            "field {at:#x} = {value:#x}"
        );
        assert!(hook_syscalls_in_elf(&corrupt, None).is_err());
    }
    for removed in 1..=24 {
        assert!(
            ElfIslands::parse(&out[..out.len() - removed])
                .unwrap()
                .is_none()
        );
    }
    for corruption in [b'1', b'?', 0] {
        let mut corrupt = out.clone();
        corrupt[tail + 7] = corruption;
        assert!(ElfIslands::parse(&corrupt).is_err());
    }
    let mut displaced = out.clone();
    displaced.push(0);
    assert!(ElfIslands::parse(&displaced).unwrap().is_none());
    // Retaining exact magic while truncating the payload still fails closed.
    let mut truncated = out[..tail - 4].to_vec();
    truncated.extend_from_slice(&out[tail..]);
    assert!(ElfIslands::parse(&truncated).is_err());
}

#[test]
fn elf_islands_sentinel_and_host_compatibility() {
    let mut no_sites = HELLO.to_vec();
    // Replace the fixture's entire .text with NOPs, retaining valid ELF metadata.
    for word in no_sites[0x110..0x148].as_chunks_mut::<4>().0 {
        word.copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    let out = hook_syscalls_in_elf(&no_sites, None).unwrap();
    assert_eq!(out.len(), no_sites.len() + 32);
    assert_eq!(ElfIslands::parse(&out).unwrap().unwrap().pairs, []);
    assert_eq!(hook_syscalls_in_elf(&out, None).unwrap(), out);
    let mut corrupt = out.clone();
    let at = corrupt.len() - 24;
    put64(&mut corrupt, at, 4096);
    assert!(ElfIslands::parse(&corrupt).is_err());
    let linux = ElfIslands::parse(&output()).unwrap().unwrap();
    assert!(
        linux
            .check_compatibility(RewriteOptions::new(TargetHost::MacOs, true), 16384)
            .is_err()
    );
    assert!(
        linux
            .check_compatibility(RewriteOptions::default(), 16384)
            .is_err()
    );
    let mac = hook_syscalls_in_elf_with_options(
        HELLO,
        None,
        RewriteOptions::new(TargetHost::MacOs, true),
    )
    .unwrap();
    let mac = ElfIslands::parse(&mac).unwrap().unwrap();
    assert_eq!(mac.granule, 16384);
    assert!(mac.pairs.iter().all(|p| p.island_vaddr() % 16384 == 0));
}

/// Sparse LOAD addresses, not an attacker-selected huge backing allocation.
fn sparse_image() -> Vec<u8> {
    let mut elf = vec![0; 4 * 4096];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, value) in [(16, 3u16), (18, 183), (52, 64), (54, 56), (56, 4)] {
        elf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    put64(&mut elf, 32, 64);
    // Deliberately out of order, with an overlapping LOAD and more than 169
    // sites in each separated code region. Auxiliary exits also consume slots.
    for (index, offset, address, size) in [
        (0, 8192, 0x3000_0000, 4096),
        (1, 0, 0x10000, 8192),
        (2, 0, 0x10000, 4096),
        (3, 12288, 0x3000_8000, 4096),
    ] {
        let at = 64 + index * 56;
        elf[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        elf[at + 4..at + 8].copy_from_slice(&5u32.to_le_bytes());
        for (field, value) in [
            (8, offset),
            (16, address),
            (32, size),
            (40, size),
            (48, 4096),
        ] {
            put64(&mut elf, at + field, value);
        }
    }
    for at in (4096..12288).step_by(4) {
        elf[at..at + 4].copy_from_slice(&0xd4000001u32.to_le_bytes());
    }
    elf
}

#[test]
fn elf_islands_multiple_gaps_capacity_sparse_distance_and_duplicate_extents() {
    let original = sparse_image();
    let out = hook_syscalls_in_elf(&original, None).unwrap();
    let payload = ElfIslands::parse(&out).unwrap().unwrap();
    assert!(payload.pairs.len() >= 14);
    assert_eq!(
        payload
            .pairs
            .iter()
            .map(IslandPair::slots_used)
            .sum::<usize>(),
        2048
    );
    assert!(
        payload
            .pairs
            .iter()
            .all(|p| p.slots_used() <= island::ISLAND_SLOTS)
    );
    assert_eq!(&original[64..64 + 4 * 56], &out[64..64 + 4 * 56]);
    let base = usize::try_from(u64_at(&out, out.len() - 24).unwrap()).unwrap();
    let mut corrupt = out.clone();
    put64(
        &mut corrupt,
        base + 64 + 40,
        payload.pairs[0].island_vaddr(),
    );
    assert!(ElfIslands::parse(&corrupt).is_err());
    // Move a future LOAD over the first island without touching the images.
    let mut corrupt = out;
    put64(
        &mut corrupt,
        64 + 3 * 56 + 16,
        payload.pairs[0].island_vaddr(),
    );
    assert!(ElfIslands::parse(&corrupt).is_err());
}

#[test]
fn elf_islands_conditional_auxiliary_ownership_and_transactional_tls() {
    let mut original = HELLO.to_vec();
    for word in original[0x110..0x148].as_chunks_mut::<4>().0 {
        word.copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    original[0x110..0x114].copy_from_slice(&0xb4000052u32.to_le_bytes()); // CBZ x18, +8
    let options = RewriteOptions::new(TargetHost::Linux, true);
    let out = hook_syscalls_in_elf_with_options(&original, None, options).unwrap();
    let payload = ElfIslands::parse(&out).unwrap().unwrap();
    let pair = &payload.pairs[0];
    assert_eq!(pair.slots_used(), 2);
    let primary = island::decode_island_slot(pair.island(), pair.island_vaddr(), 0).unwrap();
    let aux = island::decode_island_slot(pair.island(), pair.island_vaddr(), 1).unwrap();
    assert!(!primary.auxiliary && aux.auxiliary);
    assert_eq!(primary.site, aux.site);
    assert_eq!(aux.resume, primary.site + 8);
    let mut chunk = pair.chunk().to_vec();
    island::finalize_island_chunk(&mut chunk, 96, TargetHost::Linux).unwrap();
    let base = usize::try_from(u64_at(&out, out.len() - 24).unwrap()).unwrap();
    let chunk_at = base + usize::try_from(u64_at(&out, base + 88).unwrap()).unwrap();
    let mut corrupt = out;
    corrupt[chunk_at..chunk_at + chunk.len()].copy_from_slice(&chunk);
    assert!(
        ElfIslands::parse(&corrupt).is_err(),
        "on-disk TLS must be placeholders"
    );
}

#[test]
fn unrewritten_elf_with_incidental_trailing_litebox_text() {
    let mut elf = HELLO.to_vec();
    elf.extend_from_slice(b"arbitrary trailing LITEBOX text!!");
    assert!(ElfIslands::parse(&elf).unwrap().is_none());
    let rewritten = hook_syscalls_in_elf(&elf, None).unwrap();
    assert_ne!(ElfIslands::parse(&rewritten).unwrap().unwrap().pairs, []);
}

fn distant_hole_image(word: u32) -> Vec<u8> {
    let mut elf = sparse_image();
    elf.truncate(4096);
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    for (at, value) in [(72, 0), (80, 0), (96, 4096), (104, 0x6000000)] {
        put64(&mut elf, at, value);
    }
    elf[0x110..0x114].copy_from_slice(&word.to_le_bytes());
    elf
}

#[test]
fn distant_hole_intersects_conditional_taken_range() {
    // CBZ x18, -256: the inbound B reaches the page at 128MiB, but the
    // auxiliary return does not. Moving the LOAD end down one page admits it.
    let mut elf = distant_hole_image(0xb4fff812);
    put64(&mut elf, 104, 0x8000000);
    let options = RewriteOptions::new(TargetHost::Linux, true);
    assert!(hook_syscalls_in_elf_with_options(&elf, None, options).is_err());
    put64(&mut elf, 104, 0x7fff000);
    let out = hook_syscalls_in_elf_with_options(&elf, None, options).unwrap();
    let payload = ElfIslands::parse(&out).unwrap().unwrap();
    assert_eq!(payload.pairs[0].island_vaddr(), 0x7fff000);
    assert_eq!(payload.pairs[0].slots_used(), 2);
}

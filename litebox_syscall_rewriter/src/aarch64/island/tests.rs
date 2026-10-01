// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::TargetHost;
use alloc::vec;

const SVC: u32 = 0xD400_0001;
const fn mrs(rd: u32) -> u32 {
    0xD53B_D040 | rd
}
const fn msr(rt: u32) -> u32 {
    0xD51B_D040 | rt
}

pub(super) fn sections(vaddr: u64, len: usize) -> Vec<TextSectionInfo> {
    vec![TextSectionInfo {
        vaddr,
        file_offset: 0,
        size: len as u64,
    }]
}

pub(super) fn code(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub(super) fn rewrite(
    buf: &mut [u8],
    vaddr: u64,
    pairs: &mut [IslandPair],
    host: TargetHost,
    x18: bool,
) -> IslandRewrite {
    let sections = sections(vaddr, buf.len());
    rewrite_sections(
        buf,
        &sections,
        &sections,
        pairs,
        RewriteConfig::new(host, x18),
    )
    .unwrap()
}

fn word_at(buf: &[u8], offset: usize) -> u32 {
    get(buf, offset).unwrap()
}

#[test]
fn rewrites_every_supported_kind_through_one_island() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let vaddr = 0x40_0000;
        let words = [
            SVC,
            0xD503_201F,
            mrs(5),
            mrs(16),
            mrs(30),
            msr(7),
            msr(16),
            msr(30),
            msr(31),
        ];
        let mut buf = code(&words);
        let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
        let outcome = rewrite(&mut buf, vaddr, &mut pairs, host, false);
        assert_eq!(outcome.trapped_sites, Vec::<u64>::new());
        assert_eq!(outcome.patched_sites, 8);
        let pair = &pairs[0];
        assert_eq!(pair.slots_used(), 8);
        assert_eq!(word_at(&buf, 4), 0xD503_201F, "non-site left untouched");

        let gates = decode_island_chunk(pair.chunk(), host).unwrap();
        assert_eq!(gates.len(), 8);
        let mut slot = 0;
        for (index, original) in words.iter().enumerate() {
            if *original == 0xD503_201F {
                continue;
            }
            let site = vaddr + (index * INSN_BYTES) as u64;
            // Site branches to in_k; the slot names the site.
            let in_k = pair.slot_vaddr(slot);
            assert_eq!(
                b_target(word_at(&buf, index * INSN_BYTES), site),
                Some(in_k)
            );
            let decoded = decode_island_slot(pair.island(), pair.island_vaddr(), slot).unwrap();
            assert_eq!(
                decoded,
                IslandSlot {
                    index: slot,
                    site,
                    resume: site + 4,
                    auxiliary: false,
                    entry_depth: 16,
                    exit_depth: 16
                }
            );
            // Gate semantics follow the original instruction.
            let expected = match *original {
                SVC => GateMetadata::Svc,
                w if w & 0xFFFF_FFE0 == mrs(0) => GateMetadata::MrsTpidr {
                    destination: (w & 31) as u8,
                },
                w => GateMetadata::MsrTpidr {
                    source: (w & 31) as u8,
                },
            };
            assert_eq!(gates[slot].metadata, expected);
            if expected == GateMetadata::Svc {
                let out = island_out(pair.island_vaddr(), slot);
                assert_eq!(gates[slot].k, Some((site + 4).wrapping_sub(out)));
            }
            slot += 1;
        }
    }
}

#[test]
fn chunk_is_position_independent() {
    // Moving code and island together leaves the chunk byte-identical.
    let words = [SVC, mrs(3), msr(9)];
    let mut images = Vec::new();
    for shift in [0u64, 0x1234_5000, 0x7000_0000_0000] {
        let mut buf = code(&words);
        let mut pairs = vec![IslandPair::new(0x50_0000 + shift).unwrap()];
        rewrite(
            &mut buf,
            0x40_0000 + shift,
            &mut pairs,
            TargetHost::Linux,
            false,
        );
        images.push(pairs[0].chunk().to_vec());
    }
    assert!(images.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn delta_and_callback_are_the_only_placement_writes() {
    let mut buf = code(&[SVC]);
    let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
    rewrite(&mut buf, 0x40_0000, &mut pairs, TargetHost::Linux, false);
    let before = pairs[0].clone();
    pairs[0].set_chunk_vaddr(0x7000_0000_0000).unwrap();
    pairs[0].set_callback(0xdead_beef_0000);
    let pair = &pairs[0];
    let diff: Vec<usize> = (0..ISLAND_BYTES)
        .filter(|&i| before.island()[i] != pair.island()[i])
        .collect();
    assert!(
        diff.iter()
            .all(|&i| (ISLAND_DELTA_OFFSET..ISLAND_DELTA_OFFSET + 8).contains(&i))
    );
    assert_eq!(
        decode_island_header(pair.island()),
        Some(island_delta(0x50_0000, 0x7000_0000_0000))
    );
    assert_eq!(&pair.chunk()[..8], &0xdead_beef_0000u64.to_le_bytes());
    assert_eq!(&pair.chunk()[8..], &before.chunk()[8..]);
}

#[test]
fn capacity_overflow_spills_to_the_next_island_then_traps() {
    let n = ISLAND_SLOTS + 10;
    let mut buf = code(&vec![SVC; n]);
    let mut one = vec![IslandPair::new(0x50_0000).unwrap()];
    let outcome = rewrite(
        &mut buf.clone(),
        0x40_0000,
        &mut one,
        TargetHost::Linux,
        false,
    );
    assert_eq!(outcome.patched_sites, ISLAND_SLOTS);
    assert_eq!(outcome.trapped_sites.len(), 10);

    let mut two = vec![
        IslandPair::new(0x50_0000).unwrap(),
        IslandPair::new(0x60_0000).unwrap(),
    ];
    let outcome = rewrite(&mut buf, 0x40_0000, &mut two, TargetHost::Linux, false);
    assert_eq!(outcome.patched_sites, n);
    assert_eq!(two[0].slots_used() + two[1].slots_used(), n);
    for pair in &two {
        assert_eq!(
            decode_island_chunk(pair.chunk(), TargetHost::Linux)
                .unwrap()
                .len(),
            pair.slots_used()
        );
    }
}

#[test]
fn nearest_reachable_island_wins_and_far_sites_trap() {
    let mut buf = code(&[SVC]);
    let far = 0x40_0000 + (256 << 20);
    let near = 0x40_0000 + (64 << 20);
    let mut pairs = vec![
        IslandPair::new(far).unwrap(),
        IslandPair::new(near).unwrap(),
    ];
    let outcome = rewrite(&mut buf, 0x40_0000, &mut pairs, TargetHost::Linux, false);
    assert_eq!(outcome.patched_sites, 1);
    assert_eq!((pairs[0].slots_used(), pairs[1].slots_used()), (0, 1));

    let mut buf = code(&[SVC]);
    let mut pairs = vec![IslandPair::new(far).unwrap()];
    let outcome = rewrite(&mut buf, 0x40_0000, &mut pairs, TargetHost::Linux, false);
    assert_eq!(outcome.trapped_sites, vec![0x40_0000]);
    assert_eq!(pairs[0].slots_used(), 0);
    assert_eq!(word_at(&buf, 0) & 0xFFE0_001F, 0xD420_0000, "BRK");
}

#[test]
fn finalization_patches_only_tls_fields_and_is_transactional() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut buf = code(&[SVC, mrs(5), mrs(16), msr(30), msr(2)]);
        let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
        rewrite(&mut buf, 0x40_0000, &mut pairs, host, false);
        let original = pairs[0].chunk().to_vec();
        let mut chunk = original.clone();
        finalize_island_chunk(&mut chunk, 0x40, host).unwrap();
        let changed: Vec<usize> = (0..chunk.len() / 4)
            .filter(|&w| get(&chunk, w * 4) != get(&original, w * 4))
            .collect();
        // One TLS field per MRS/MSR gate on either host.
        assert_eq!(changed.len(), 4, "{host:?}");
        // Idempotent with the same offset; rejects a different one untouched.
        let finalized = chunk.clone();
        finalize_island_chunk(&mut chunk, 0x40, host).unwrap();
        assert_eq!(chunk, finalized);
        assert!(finalize_island_chunk(&mut chunk, 0x48, host).is_err());
        assert_eq!(chunk, finalized);
        // Rejects invalid offsets and corrupted gates without mutation.
        let mut copy = original.clone();
        assert!(finalize_island_chunk(&mut copy, 3, host).is_err());
        assert_eq!(copy, original);
        let last = copy.len() - 8;
        copy[last] ^= 1;
        assert!(finalize_island_chunk(&mut copy, 0x40, host).is_err());
        assert_eq!(copy[..last], original[..last]);
    }
}

#[test]
fn stages_mark_the_commit_point() {
    let host = TargetHost::Linux;
    let lookup = |metadata, offset| {
        let code = emit_gate(
            metadata,
            host.into(),
            0,
            0,
            GUEST_TPIDR_OFFSET_PLACEHOLDER,
            None,
        )
        .unwrap();
        let gate = decode_island_gate(&code, 0, host).unwrap();
        island_gate_stage(&gate, offset)
    };
    let stage = |metadata, offset| lookup(metadata, offset).unwrap();
    // SVC: always before the syscall; the frame grows after the first SUB.
    assert_eq!(stage(GateMetadata::Svc, 0), before(0));
    for offset in (4..28).step_by(4) {
        assert_eq!(
            stage(GateMetadata::Svc, offset),
            IslandStage {
                out_saved: if offset >= 8 { Some(-8) } else { None },
                ..before(16)
            }
        );
    }
    assert_eq!(lookup(GateMetadata::Svc, 28), None);
    // MRS: committed by the destination load.
    let mrs5 = GateMetadata::MrsTpidr { destination: 5 };
    assert_eq!(stage(mrs5, 4), before(0));
    assert_eq!(stage(mrs5, 8), after(0));
    // MRS x16: committed by the frame store.
    let mrs16 = GateMetadata::MrsTpidr { destination: 16 };
    assert_eq!(stage(mrs16, 8), before(0));
    assert_eq!(stage(mrs16, 12), after(0));
    // MSR x30: borrowed x30 spill sits below the island frame.
    let msr30 = GateMetadata::MsrTpidr { source: 30 };
    assert_eq!(stage(msr30, 0), before(0));
    assert_eq!(
        stage(msr30, 12),
        IslandStage {
            out_saved: Some(-16),
            ..before(16)
        }
    );
    assert_eq!(
        stage(msr30, 16),
        IslandStage {
            out_saved: Some(-16),
            ..after(16)
        }
    );
    assert_eq!(stage(msr30, 20), after(0));
}

#[test]
fn v1_and_v2_metadata_do_not_alias() {
    let v2 = encode_metadata(GateMetadata::Svc).unwrap();
    assert_eq!(decode_island_metadata(v2), Some(GateMetadata::Svc));
    assert_eq!(super::super::decode_gate_metadata_word(v2), None);
    let v1 = EncodedGateMetadata::encode(GateMetadata::Svc).unwrap().0;
    assert_eq!(decode_island_metadata(v1), None);
}

#[test]
fn relocation_changes_only_placement_fields_and_redirects_transactionally() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let site = 0x400000;
        // SVC, TP, ordinary x18, ADR x18, ADRP x18, CBZ x18 (two exits).
        let mut source = code(&[SVC, mrs(5), 0x91000652, 0x10000092, 0x90000012, 0xb4000052]);
        let mut pairs = vec![IslandPair::new(0x500000).unwrap()];
        assert_eq!(
            rewrite(&mut source, site, &mut pairs, host, true).trapped_sites,
            []
        );
        let serialized = &pairs[0];
        for bias in [0, 0x100000000] {
            let mut original = IslandPair::from_images(
                serialized.island_vaddr() + bias,
                serialized.island().to_vec(),
                serialized.chunk().to_vec(),
                host,
            )
            .unwrap();
            original.set_chunk_vaddr(0x5_0000_0000 + bias).unwrap();
            original.set_callback(0x1234);
            for address in [0x300000 + bias, 0x600000 + bias] {
                let moved = original.relocated(address, host).unwrap();
                assert_eq!(moved.slots_used(), original.slots_used());
                assert_eq!(decode_island_header(moved.island()), Some(0));
                let mut allowed_island = vec![false; ISLAND_BYTES];
                allowed_island[ISLAND_DELTA_OFFSET..ISLAND_DELTA_OFFSET + 8].fill(true);
                let mut allowed_chunk = vec![false; original.chunk().len()];
                let gates = walk_chunk(original.chunk(), host.into()).unwrap();
                let moved_gates = walk_chunk(moved.chunk(), host.into()).unwrap();
                for (i, gate) in gates.iter().enumerate() {
                    let old =
                        decode_island_slot(original.island(), original.island_vaddr(), i).unwrap();
                    let new = decode_island_slot(moved.island(), address, i).unwrap();
                    assert_eq!(
                        new, old,
                        "logical primary and auxiliary identity survives relocation"
                    );
                    let at = ISLAND_HEADER_BYTES + i * ISLAND_SLOT_BYTES + 20;
                    allowed_island[at..at + 4].fill(true);
                    if let Some(k) = gate.k {
                        assert_eq!(
                            island_out(original.island_vaddr(), i).wrapping_add(k),
                            island_out(address, i).wrapping_add(moved_gates[i].k.unwrap())
                        );
                        let spec = gate
                            .original
                            .and_then(|raw| x18::Spec::decode(raw, old.site));
                        let at = gate.offset
                            + program(gate.metadata, host.into(), spec)
                                .unwrap()
                                .k_literal
                                .unwrap();
                        allowed_chunk[at..at + 8].fill(true);
                    }
                }
                for ((a, b), allowed) in original
                    .island()
                    .iter()
                    .zip(moved.island())
                    .zip(allowed_island)
                {
                    assert!(allowed || a == b, "only return branches/delta may change");
                }
                for ((a, b), allowed) in original
                    .chunk()
                    .iter()
                    .zip(moved.chunk())
                    .zip(allowed_chunk)
                {
                    assert!(
                        allowed || a == b,
                        "operation bodies must be copied verbatim"
                    );
                }
                let mut redirected = source.clone();
                moved
                    .redirect_inbound_branches(
                        &mut redirected,
                        site + bias,
                        original.island_vaddr(),
                    )
                    .unwrap();
                for i in 0..moved.slots_used() {
                    let slot = decode_island_slot(moved.island(), address, i).unwrap();
                    if !slot.auxiliary {
                        assert_eq!(
                            b_target(
                                word_at(
                                    &redirected,
                                    usize::try_from(slot.site - site - bias).unwrap()
                                ),
                                slot.site
                            ),
                            Some(moved.slot_vaddr(i))
                        );
                    }
                }
                let replay = redirected.clone();
                moved
                    .redirect_inbound_branches(
                        &mut redirected,
                        site + bias,
                        original.island_vaddr(),
                    )
                    .unwrap();
                assert_eq!(redirected, replay);
                let mut changed = source.clone();
                put(&mut changed, 4, SVC);
                moved
                    .redirect_inbound_branches(&mut changed, site + bias, original.island_vaddr())
                    .unwrap();
                assert_eq!(
                    get(&changed, 4),
                    Some(SVC),
                    "modified sites must reach the current-byte scanner"
                );
                assert_eq!(get(&changed, 0), get(&redirected, 0));
                let mut truncated = source[..5].to_vec();
                let before = truncated.clone();
                assert!(
                    moved
                        .redirect_inbound_branches(
                            &mut truncated,
                            site + bias,
                            original.island_vaddr()
                        )
                        .is_err()
                );
                assert_eq!(
                    truncated, before,
                    "no partial source redirection on failure"
                );
            }
        }
    }
}

#[test]
fn relocation_whole_pair_reach_checks_exact_entry_and_auxiliary_return_pcs() {
    let host = TargetHost::Linux;
    let mut pair = IslandPair::new(0x10000000).unwrap();
    for site in [0x08001000, 0x17fff000] {
        let raw = 0xb4000052; // CBZ x18, site+8.
        let spec = x18::Spec::decode(raw, site).unwrap();
        assert!(
            pair.push(site, spec.metadata, host.into(), Some(spec))
                .unwrap()
                .is_some()
        );
    }
    let range = pair.placement_range().unwrap();
    let first = range.start().next_multiple_of(ISLAND_BYTES as u64);
    let last = range.end() & !(ISLAND_BYTES as u64 - 1);
    assert!(first <= last);
    assert!(pair.relocated(first, host).is_ok());
    assert!(pair.relocated(last, host).is_ok());
    assert!(pair.relocated(first - ISLAND_BYTES as u64, host).is_err());
    assert!(pair.relocated(last + ISLAND_BYTES as u64, host).is_err());
    assert!(pair.relocated(u64::MAX, host).is_err());
    assert!(pair.relocated(first + 4, host).is_err());
    // Individually valid return templates need not have a common entry/return
    // interval. Such a pair cannot pass serialized inbound-branch validation.
    put(
        &mut pair.island,
        ISLAND_HEADER_BYTES + 20,
        Insn::B((1 << 27) - 4).encode().unwrap(),
    );
    put(
        &mut pair.island,
        ISLAND_HEADER_BYTES + 2 * ISLAND_SLOT_BYTES + 20,
        Insn::B(-(1 << 27)).encode().unwrap(),
    );
    assert!(
        (0..pair.slots_used())
            .all(|i| decode_island_slot(pair.island(), pair.island_vaddr(), i).is_some())
    );
    assert!(pair.placement_range().is_err());
}

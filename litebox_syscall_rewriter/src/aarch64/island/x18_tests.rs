// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::signal::classify_island_signal_gate;
use super::tests::{code, rewrite, sections};
use super::*;
use crate::TargetHost;
use alloc::vec;

// Source-named instruction words for signal-classifier parity coverage.
const OPERATIONS: &[(&str, u32)] = &[
    ("adds_x18", 0xab01_0252),
    ("adds_destination_x16_source_x30", 0xab1e_0250),
    ("adds_destination_x30_source_x16", 0xab12_021e),
    ("ldr_x18", 0xf940_0012),
    ("str_x18", 0xf900_0012),
    ("ldp_x18_x16_post16", 0xa8c1_43f2),
    ("ldp_x30_x18_pre_negative32", 0xa9fe_4bfe),
    ("ldp_x18_x16_pre_negative16", 0xa9ff_43f2),
    ("ldp_x18_x16_pre_negative8", 0xa9ff_c3f2),
    ("ldp_w18_w30_pre_negative4", 0x29ff_fbf2),
    ("stp_x18_x30_pre_negative32", 0xa9be_7bf2),
    ("ldp_x18_x16_pre_negative512", 0xa9e0_43f2),
    ("ldp_x30_x18_post_negative512", 0xa8e0_4bfe),
    ("stp_x16_x18_post504", 0xa89f_cbf0),
    ("ldp_w18_w30_pre_negative256", 0x29e0_7bf2),
    ("stp_w16_w18_post252", 0x289f_cbf0),
    ("add_x18", 0x9100_0652),
    ("ldr_x16_base_x18", 0xf940_0250),
    ("ldr_x16_post_index_x18", 0xf840_8650),
    ("stp_x18_x16_post_negative16", 0xa8bf_43f2),
    ("ldp_w30_w18_post_negative256", 0x28e0_4bfe),
    ("str_x30_base_x18", 0xf900_025e),
    ("ldp_x18_x30_sp_offset16", 0xa941_7bf2),
    ("cbz_x18", 0xb400_0212),
    ("cbz_w18", 0x3400_0212),
    ("cbnz_x18", 0xb500_0212),
    ("tbz_x18_bit0", 0x3600_0212),
    ("tbnz_x18_bit63", 0xb7f8_0212),
    ("cbnz_w18", 0x3500_0212),
    ("tbz_x18_bit63", 0xb6f8_0212),
    ("tbnz_w18_bit5", 0x3728_0212),
    ("adr_x18", 0x1000_0072),
    ("adrp_x18", 0xb000_0012),
    ("adr_x18_min", 0x1080_0012),
    ("adr_x18_max", 0x707f_fff2),
    ("adrp_x18_min", 0x9080_0012),
    ("adrp_x18_max", 0xf07f_fff2),
    ("br_x18", 0xd61f_0240),
    ("blr_x18", 0xd63f_0240),
    ("ret_x18", 0xd65f_0240),
];

// Structural coverage, not an EL0 executability claim for arbitrary SYS words.
const SYSTEM_OPERATIONS: &[(&str, u32)] = &[
    ("mrs_x18_nzcv", 0xd53b_4212),
    ("mrs_x18_cntvct_el0", 0xd53b_e052),
    ("dc_cvau_x18", 0xd50b_7b32),
];

#[test]
fn pair_entry_spills_are_below_full_operands_and_exit_recovers_writeback() {
    // Exercise every immediate and both element widths/modes/directions, not
    // just the convenient aligned endpoints. Guest final SP may be unaligned.
    for width in [4i16, 8] {
        for mode in [1u32, 3] {
            for load in [0u32, 1] {
                for imm in -64i16..=63 {
                    let raw = 0x2800_0000
                        | (u32::from(width == 8) << 31)
                        | (mode << 23)
                        | (load << 22)
                        | ((u32::from(imm.cast_unsigned()) & 127) << 15)
                        | (30 << 10)
                        | (31 << 5)
                        | 0x12;
                    let spec = x18::Spec::decode(raw, 0x40_0000).unwrap();
                    let delta = imm * width;
                    let memory_start = if mode == 3 { delta } else { 0 };
                    let memory_end = memory_start + 2 * width;
                    let spill_start = -i32::from(spec.entry);
                    let spill_end = spill_start + 16;
                    assert!(
                        spill_end <= i32::from(memory_start)
                            || spill_start >= i32::from(memory_end)
                    );
                    assert_eq!(
                        -i32::from(spec.entry) + i32::from(spec.exit),
                        i32::from(delta)
                    );
                    let program = program(spec.metadata, Host::Linux, Some(spec)).unwrap();
                    let execute = program
                        .items
                        .iter()
                        .position(|(i, _)| matches!(i, Item::Raw(_)))
                        .unwrap();
                    let before = program.items[execute].1;
                    let after = program.items[execute + 1].1;
                    assert_eq!(before.frame_base, spec.anchor);
                    assert!(before.guest_pair_live && before.scratches_saved);
                    assert_eq!(before.phase, IslandPhase::Before);
                    assert_eq!(after.phase, IslandPhase::After);
                    assert_eq!(after.pending_x18, Some(spec.value));
                    assert_eq!(after.frame_base, spec.anchor);
                }
            }
        }
    }
}

#[test]
fn conditional_auxiliary_capacity_identity_and_reach_are_transactional() {
    let conditional = 0xb400_0212;
    let words = [vec![0xd400_0001; ISLAND_SLOTS - 1], vec![conditional]].concat();
    let mut buf = code(&words);
    let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
    let result = rewrite(&mut buf, 0x40_0000, &mut pairs, TargetHost::Linux, true);
    assert_eq!(result.patched_sites, ISLAND_SLOTS - 1);
    assert_eq!(pairs[0].slots_free(), 1);
    let ranges = sections(0x40_0000, words.len() * 4);
    assert_eq!(
        count_sites(
            &code(&words),
            &ranges,
            &ranges,
            RewriteConfig::new(TargetHost::Linux, true)
        )
        .unwrap(),
        ISLAND_SLOTS + 1
    );
    let mut buf = code(&[conditional]);
    let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
    rewrite(&mut buf, 0x40_0000, &mut pairs, TargetHost::Linux, true);
    let p = &pairs[0];
    let aux = decode_island_slot(p.island(), p.island_vaddr(), 1).unwrap();
    assert!(aux.auxiliary);
    assert_eq!(aux.site, 0x40_0000);
    assert_eq!(aux.resume, 0x40_0040);
    assert!(decode_island_chunk(p.chunk(), TargetHost::Linux).unwrap()[1].auxiliary);
    // Primary is reachable at the edge, but its taken target is not.
    let site = 0x1000_0030;
    let mut buf = code(&[0xb4ff_fff2]); // CBZ x18, site - 4
    let mut pairs = vec![IslandPair::new(0x1800_0000).unwrap()];
    assert!(pairs[0].inbound(site, 0).is_some());
    let result = rewrite(&mut buf, site, &mut pairs, TargetHost::Linux, true);
    assert_eq!(result.patched_sites, 0);
    assert_eq!(pairs[0].slots_used(), 0);
}

#[test]
fn taken_x30_adjustment_preserves_primary_identity_at_both_boundaries() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let site = 0x40_0000;
        let raw = 0xb400_0212; // CBZ x18, site + 64
        let mut buf = code(&[raw]);
        let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
        rewrite(&mut buf, site, &mut pairs, host, true);
        let pair = &pairs[0];
        let gates = decode_island_chunk(pair.chunk(), host).unwrap();
        let gate = &gates[0];
        let spec = x18::Spec::decode(raw, site).unwrap();
        let emitted = program(spec.metadata, host.into(), Some(spec)).unwrap();
        let adjust = emitted
            .items
            .iter()
            .position(|(item, _)| {
                matches!(
                    item,
                    Item::Fixed(Insn::AddImm {
                        rd: X30,
                        rn: X30,
                        imm12: 24
                    })
                )
            })
            .unwrap();
        let first_out = island_out(pair.island_vaddr(), 0);
        for (offset, live_x30, index) in [
            (adjust * 4, first_out, 0),
            ((adjust + 1) * 4, first_out + 24, 1),
        ] {
            let stage = island_gate_stage(gate, offset).unwrap();
            assert_eq!(stage.phase, IslandPhase::After);
            assert!(stage.taken);
            assert_eq!(stage.out_saved, None);
            let decoded_index =
                usize::try_from((live_x30 - first_out) / ISLAND_SLOT_BYTES as u64).unwrap();
            assert_eq!(decoded_index, index);
            let owner =
                decode_island_slot(pair.island(), pair.island_vaddr(), decoded_index).unwrap();
            assert_eq!(owner.site, site);
            assert_eq!(owner.auxiliary, index != 0);
            assert_eq!(
                b_target(get(&buf, 0).unwrap(), owner.site),
                Some(first_out - ISLAND_OUT_OFFSET as u64)
            );
        }
        let taken = decode_island_slot(pair.island(), pair.island_vaddr(), 1).unwrap();
        assert_eq!(taken.resume, site + 64);
        assert_ne!(taken.site, taken.resume - 4);
    }
}

#[test]
fn x18_literals_remain_relative_across_load_bias_and_far_chunk_placement() {
    for raw in [0x1000_0072, 0xb000_0012] {
        let mut chunks = Vec::new();
        for bias in [0, 0x7000_0000_0000] {
            let mut buf = code(&[raw]);
            let mut pairs = vec![IslandPair::new(0x50_0000 + bias).unwrap()];
            rewrite(
                &mut buf,
                0x40_0000 + bias,
                &mut pairs,
                TargetHost::Linux,
                true,
            );
            let pair = &mut pairs[0];
            pair.set_chunk_vaddr(if bias == 0 { 0x7000_0000_0000 } else { 0x1000 })
                .unwrap();
            let g = decode_island_chunk(pair.chunk(), TargetHost::Linux)
                .unwrap()
                .remove(0);
            let target = x18::Spec::decode(raw, 0x40_0000 + bias)
                .unwrap()
                .target
                .unwrap();
            assert_eq!(
                island_out(pair.island_vaddr(), 0).wrapping_add(g.k.unwrap()),
                target
            );
            chunks.push(pair.chunk().to_vec());
        }
        assert_eq!(chunks[0], chunks[1]);
    }
}

#[test]
fn corrupted_original_executable_word_aux_or_tls_never_half_finalizes() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut buf = code(&[0x9100_0652, 0xb400_0212]);
        let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
        rewrite(&mut buf, 0x40_0000, &mut pairs, host, true);
        let pair = &pairs[0];
        let gates = decode_island_chunk(pair.chunk(), host).unwrap();
        let first = &gates[0];
        let spec = x18::Spec::decode(first.original.unwrap(), 0x40_0000).unwrap();
        let p = program(first.metadata, host.into(), Some(spec)).unwrap();
        let execute = p
            .items
            .iter()
            .position(|(item, _)| matches!(item, Item::Raw(_)))
            .unwrap()
            * 4;
        for (at, bad) in [
            (first.offset + execute, NOP),
            (first.offset + first.size - 8, 0xd61f_0000),
            (CHUNK_TABLE_OFFSET + 2 * ISLAND_SLOT_BYTES, brk()),
            (CHUNK_TABLE_OFFSET + 4, NOP),
        ] {
            let mut bad_chunk = pair.chunk().to_vec();
            put(&mut bad_chunk, at, bad);
            let before = bad_chunk.clone();
            assert!(finalize_island_chunk(&mut bad_chunk, 64, host).is_err());
            assert_eq!(bad_chunk, before);
        }
        let mut chunk = pair.chunk().to_vec();
        let (_, fields) = walk_chunk_with_tls(&chunk, host.into()).unwrap();
        finalize_island_chunk(&mut chunk, 64, host).unwrap();
        for (at, addend) in fields {
            assert_eq!(
                (get(&chunk, at).unwrap() & LDST_UIMM12_IMM_MASK) >> LDST_UIMM12_IMM_SHIFT,
                u32::from((64 + addend) / 8)
            );
        }
        let finalized = chunk.clone();
        assert!(finalize_island_chunk(&mut chunk, 72, host).is_err());
        assert_eq!(chunk, finalized);
    }
}

#[test]
fn unsupported_and_exclusive_sequences_keep_the_old_rejection_policy() {
    for raw in [0xd51b_d052, 0xd53b_d052, 0x5800_0012, 0x9100_025f] {
        let mut buf = code(&[raw]);
        let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
        let outcome = rewrite(&mut buf, 0x40_0000, &mut pairs, TargetHost::Linux, true);
        assert_eq!(outcome.trapped_sites, vec![0x40_0000], "{raw:08x}");
    }
    let mut buf = code(&[0xc85f_7c00, 0x9100_0652, 0xc801_7c00]);
    let before = buf.clone();
    let ranges = sections(0x40_0000, buf.len());
    let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
    assert!(
        rewrite_sections(
            &mut buf,
            &ranges,
            &ranges,
            &mut pairs,
            RewriteConfig::new(TargetHost::Linux, true)
        )
        .is_err()
    );
    assert_eq!(buf, before);
    assert_eq!(pairs[0].slots_used(), 0);
    assert!(IslandPair::new(u64::MAX - 4095).is_err());
    assert!(decode_island_gate(&[], usize::MAX, TargetHost::Linux).is_none());
}

#[test]
fn host_tls_forms_keep_tp_and_x18_distinct() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut buf = code(&[0xd53b_d045, 0x9100_0652]); // MRS x5, TP; ADD x18,x18,#1
        let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
        rewrite(&mut buf, 0x40_0000, &mut pairs, host, true);
        let mut chunk = pairs[0].chunk().to_vec();
        finalize_island_chunk(&mut chunk, 64, host).unwrap();
        let gates = decode_island_chunk(&chunk, host).unwrap();
        let words: Vec<u32> = (0..gates[1].stages.len())
            .map(|i| get(&chunk, gates[1].offset + 4 * i).unwrap())
            .collect();
        let value = gates[1].scratches.unwrap().0;
        let offset = if host == TargetHost::Linux { 72 } else { 8 };
        assert!(words.contains(&word(Insn::LdrUimm {
            rt: value,
            rn: X16,
            imm_bytes: offset
        })));
        assert!(words.contains(&word(Insn::StrUimm {
            rt: value,
            rn: X16,
            imm_bytes: offset
        })));
        assert!(words.contains(&if host == TargetHost::Linux {
            0xd53b_d050
        } else {
            0xd53b_d070
        }));
        if host == TargetHost::MacOs {
            assert_eq!(
                words
                    .iter()
                    .filter(|&&w| w
                        == word(Insn::LdrUimm {
                            rt: X16,
                            rn: X16,
                            imm_bytes: 64
                        }))
                    .count(),
                2
            );
            assert_eq!(
                words
                    .iter()
                    .filter(|&&w| w == word(super::super::anchor_mask(X16)))
                    .count(),
                2
            );
        }
        let tp_offset = if host == TargetHost::Linux { 64 } else { 0 };
        assert!(
            (0..gates[0].stages.len()).any(|i| get(&chunk, gates[0].offset + 4 * i)
                == Some(word(Insn::LdrUimm {
                    rt: 5,
                    rn: X16,
                    imm_bytes: tp_offset
                })))
        );
    }
}

#[test]
fn persisted_pair_cross_checks_depth_literals_auxiliary_target_and_unused_bytes() {
    for raw in [0xa9e0_43f2, 0xb400_0212, 0x1000_0072] {
        let mut buf = code(&[raw]);
        let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
        rewrite(&mut buf, 0x40_0000, &mut pairs, TargetHost::Linux, true);
        let pair = &pairs[0];
        let mut bad = pair.island().to_vec();
        let at = match raw {
            0xa9e0_43f2 => ISLAND_HEADER_BYTES, // still a valid SUB, but wrong frame depth
            0xb400_0212 => ISLAND_HEADER_BYTES + ISLAND_SLOT_BYTES + 20, // valid B, wrong taken target
            _ => ISLAND_BYTES - 4,                                       // unused image space
        };
        let changed = get(&bad, at).unwrap() ^ if raw == 0xa9e0_43f2 { 16 << 10 } else { 1 };
        put(&mut bad, at, changed);
        assert!(
            IslandPair::from_images(
                pair.island_vaddr(),
                bad,
                pair.chunk().to_vec(),
                TargetHost::Linux
            )
            .is_err()
        );
        if raw == 0x1000_0072 {
            let spec = x18::Spec::decode(raw, 0x40_0000).unwrap();
            let literal = program(spec.metadata, Host::Linux, Some(spec))
                .unwrap()
                .k_literal
                .unwrap();
            let mut chunk = pair.chunk().to_vec();
            chunk[CHUNK_GATES_OFFSET + literal] ^= 1;
            assert!(
                IslandPair::from_images(
                    pair.island_vaddr(),
                    pair.island().to_vec(),
                    chunk,
                    TargetHost::Linux
                )
                .is_err()
            );
        }
    }
    let mut pair = IslandPair::new(0x50_0000).unwrap();
    let before = pair.clone();
    assert!(pair.set_chunk_vaddr(!15).is_err());
    assert!(pair.set_chunk_vaddr(1).is_err());
    assert_eq!(pair, before);
    let mut buf = code(&[0x9100_0652]);
    rewrite(
        &mut buf,
        0x40_0000,
        core::slice::from_mut(&mut pair),
        TargetHost::Linux,
        true,
    );
    let mut chunk = pair.chunk().to_vec();
    let before = chunk.clone();
    assert!(
        finalize_island_chunk(
            &mut chunk,
            super::super::GUEST_X18_OFFSET_PLACEHOLDER - 8,
            TargetHost::Linux
        )
        .is_err()
    );
    assert_eq!(chunk, before);
}

#[test]
fn signal_classifier_matches_offline_stages() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        for &(_, raw) in OPERATIONS.iter().chain(SYSTEM_OPERATIONS) {
            let mut buf = code(&[raw]);
            let mut pairs = vec![IslandPair::new(0x2_0050_0000).unwrap()];
            rewrite(&mut buf, 0x2_0040_0000, &mut pairs, host, true);
            let gates = decode_island_chunk(pairs[0].chunk(), host).unwrap();
            let gate = &gates[0];
            {
                for offset in (0..gate.size).step_by(4) {
                    let signal = classify_island_signal_gate(
                        &pairs[0].chunk()[gate.offset..gate.offset + gate.size],
                        (0x7000_0000_0000 + gate.offset) as u64,
                        offset,
                        host,
                    );
                    assert_eq!(signal.map(|g| g.stage), island_gate_stage(gate, offset));
                    if let Some(signal) = signal {
                        assert_eq!(signal.scratches, gate.scratches);
                        assert_eq!(signal.entry_depth, gate.entry_depth);
                        assert_eq!(signal.exit_depth, gate.exit_depth);
                    }
                }
            }
        }
    }
}

// Use a real ordinary emitted scaffold, then replace only its original and
// transformed words. This also tests rejection of forged unsupported classes.
fn ordinary_signal_template(host: TargetHost) -> (Vec<u8>, usize, u8) {
    let raw = 0x9100_0652; // ADD x18,x18,#1
    let mut buf = code(&[raw]);
    let mut pairs = vec![IslandPair::new(0x50_0000).unwrap()];
    rewrite(&mut buf, 0x40_0000, &mut pairs, host, true);
    let gate = &decode_island_chunk(pairs[0].chunk(), host).unwrap()[0];
    let spec = x18::Spec::decode(raw, 0x40_0000).unwrap();
    let execute = program(spec.metadata, host.into(), Some(spec))
        .unwrap()
        .items
        .iter()
        .position(|(item, _)| matches!(item, Item::Raw(_)))
        .unwrap()
        * 4;
    (
        pairs[0].chunk()[gate.offset..gate.offset + gate.size].to_vec(),
        execute,
        spec.value,
    )
}

#[test]
fn signal_classifier_system_classes_match_offline_admission_exhaustively() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let (mut slot, execute, scratch) = ordinary_signal_template(host);
        let original_at = slot.len() - 8;
        let mut counts = [0usize; 8];
        // Exhaust every system encoding's L:op0 and op1:CRn:CRm:op2 with
        // Rt=x18: 131,072 words per host, including MSR/SYSL and TPIDR_EL0.
        for l_op0 in 0u32..8 {
            for fields in 0..(1u32 << 14) {
                let raw = 0xd500_0012 | (l_op0 << 19) | (fields << 5);
                let transformed = (raw & !31) | u32::from(scratch);
                let admitted = x18::Spec::decode(raw, 0x40_0000);
                if let Some(spec) = admitted {
                    assert_eq!(spec.metadata, GateMetadata::X18 { scratch });
                    assert_eq!(spec.transformed, transformed);
                    counts[l_op0 as usize] += 1;
                }
                put(&mut slot, original_at, raw);
                put(&mut slot, execute, transformed);
                {
                    let signal = classify_island_signal_gate(&slot, 0x7000_0000, execute, host);
                    assert_eq!(signal.is_some(), admitted.is_some(), "{raw:08x} {host:?}");
                    if let Some(signal) = signal {
                        assert!(signal.guest_instruction);
                        assert_eq!(signal.stage.phase, IslandPhase::Before);
                        let pending =
                            classify_island_signal_gate(&slot, 0x7000_0000, execute + 4, host)
                                .unwrap();
                        assert_eq!(pending.stage.phase, IslandPhase::After);
                        assert_eq!(pending.stage.pending_x18, Some(scratch));
                    }
                }
            }
        }
        // SYS is already admitted; MRS excludes only TPIDR_EL0,x18. MSR and
        // SYSL remain unsupported. This is not an EL0 executability claim.
        assert_eq!(counts, [0, 16384, 0, 0, 0, 0, 16384, 16383]);
    }
}

#[test]
fn signal_classifier_rejects_forged_system_fields_and_control_flow() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let (mut slot, execute, scratch) = ordinary_signal_template(host);
        let original_at = slot.len() - 8;
        let mut reject = |raw, transformed| {
            put(&mut slot, original_at, raw);
            put(&mut slot, execute, transformed);
            {
                for offset in (0..slot.len()).step_by(4) {
                    assert!(
                        classify_island_signal_gate(&slot, 0x7000_0000, offset, host).is_none(),
                        "forged {raw:08x} -> {transformed:08x} {host:?} +{offset}"
                    );
                }
            }
        };
        for shift in [5, 10, 16] {
            // A system selector that happens to look like register 18 must
            // never authorize changing the system register/operation itself.
            let raw = (0xd530_0012 & !(31 << shift)) | (18 << shift);
            let transformed =
                ((raw & !31) | u32::from(scratch)) & !(31 << shift) | (u32::from(scratch) << shift);
            reject(raw, transformed);
            // Nor can a system field alone authorize a gate with Rt != x18.
            reject(raw & !31, transformed & !31);
        }
        for raw in [
            0xd51b_4212, // MSR NZCV,x18
            0xd528_0012, // SYSL x18,#0,C0,C0,#0
            0xd53b_d052, // MRS x18,TPIDR_EL0
            0xd420_0252, // exception-class forged immediate
            0x1400_0012, // B with immediate bits resembling Rt
            0x9400_0012, // BL
            0xb400_0212, // CBZ x18
            0x3600_0212, // TBZ x18
            0x1000_0072, // ADR x18
        ] {
            reject(raw, (raw & !31) | u32::from(scratch));
        }
        for raw in [0xd61f_0240, 0xd63f_0240, 0xd65f_0240, 0xd73f_0a40] {
            reject(raw, (raw & !(31 << 5)) | (u32::from(scratch) << 5));
        }
    }
}

#[test]
fn conditional_site_placement_range_matches_all_slot_edges_and_host_pages() {
    let site = 0x4000_0020u64;
    for &(name, original) in OPERATIONS {
        if !name.starts_with("cb") && !name.starts_with("tb") {
            continue;
        }
        let bits = if name.starts_with("cb") { 19 } else { 14 };
        let mask = (1u32 << bits) - 1;
        for immediate in [1u32 << (bits - 1), (1 << (bits - 1)) - 1] {
            let raw = (original & !(mask << 5)) | (immediate << 5);
            let spec = x18::Spec::decode(raw, site).unwrap();
            let target = spec.target.unwrap();
            let mut buf = code(&[raw]);
            let outcome = rewrite(&mut buf, site, &mut [], TargetHost::Linux, true);
            assert_eq!(outcome.unplaced_sites.len(), 1, "{name}");
            let descriptor = &outcome.unplaced_sites[0];
            assert_eq!(descriptor.site, site);
            assert_eq!(descriptor.slots, 2);
            let range = &descriptor.placement_range;
            let edges = |base: u64| {
                [
                    (base + ISLAND_HEADER_BYTES as u64, site),
                    (site + 4, base + (ISLAND_HEADER_BYTES + 20) as u64),
                    (
                        target,
                        base + (ISLAND_HEADER_BYTES + ISLAND_SLOT_BYTES + 20) as u64,
                    ),
                ]
            };
            let encodable = |base| {
                edges(base).into_iter().all(|(to, from)| {
                    branch_distance(to, from)
                        .and_then(|d| Insn::B(d).encode())
                        .is_some()
                })
            };
            for endpoint in [*range.start(), *range.end()] {
                assert!(encodable(endpoint), "{name} {immediate:#x} {endpoint:#x}");
                assert!(
                    edges(endpoint).into_iter().any(|(to, from)| {
                        matches!(
                            i128::from(to) - i128::from(from),
                            -134_217_728 | 134_217_724
                        )
                    }),
                    "an exact signed imm26 endpoint must bind"
                );
            }
            assert!(!encodable(range.start() - 4));
            assert!(!encodable(range.end() + 4));
            for page in [4096u64, 16384] {
                let low = range.start().checked_next_multiple_of(page).unwrap();
                let high = range.end() / page * page;
                for base in [low, high] {
                    let mut pair = IslandPair::new(base).unwrap();
                    assert!(
                        pair.push(site, spec.metadata, Host::Linux, Some(spec))
                            .unwrap()
                            .is_some()
                    );
                    // Relocation uses independently decoded slot PCs, including
                    // the taken exit, and must yield precisely the same range.
                    assert_eq!(pair.placement_range().unwrap(), *range);
                }
            }
        }
    }
}

#[test]
fn fresh_pair_range_checks_address_limits_without_constraining_data_targets() {
    assert_eq!(*site_placement_range(0, None).unwrap().start(), 0);
    assert_eq!(
        *site_placement_range(u64::MAX - 7, None).unwrap().end(),
        u64::MAX - ISLAND_BYTES as u64
    );
    assert!(site_placement_range(u64::MAX - 3, None).is_err());
    let site = 0x4_4000_0020;
    for &(name, raw) in OPERATIONS
        .iter()
        .filter(|(name, _)| name.starts_with("adr"))
    {
        let spec = x18::Spec::decode(raw, site).unwrap();
        assert_eq!(
            site_placement_range(site, Some(spec)).unwrap(),
            site_placement_range(site, None).unwrap(),
            "{name} is not a branch exit"
        );
    }
    let mut impossible = x18::Spec::decode(0xb400_0212, site).unwrap();
    impossible.target = Some(u64::MAX - 3);
    assert!(site_placement_range(site, Some(impossible)).is_err());
}

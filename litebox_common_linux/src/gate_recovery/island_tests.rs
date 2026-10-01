// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use alloc::{vec, vec::Vec};
use litebox_syscall_rewriter::aarch64::{
    ElfCodeMetadata, island::signal::classify_island_signal_gate, island::*,
};
use litebox_syscall_rewriter::{RewriteOptions, patch_aarch64_code_segment_with_islands};

const SITE: usize = 0x40_0000;
const ISLAND: usize = 0x50_0000;
const FAR: usize = 0x7000_0000_0000;
const FRAME: usize = 0x80_1000;
const TLS: usize = 0x90_0000;
const LOGICAL_BEFORE: usize = 0x1818;
const LOGICAL_AFTER: usize = 0x9191;

const OPERATIONS: &[u32] = &[
    0xd400_0001, // SVC
    0xd53b_d040,
    0xd53b_d045,
    0xd53b_d050,
    0xd53b_d05e, // MRS x0,x5,x16,x30
    0xd51b_d040,
    0xd51b_d047,
    0xd51b_d050,
    0xd51b_d05e,
    0xd51b_d05f, // MSR incl XZR
    0xd53b_4212, // MRS x18,NZCV (ordinary x18 gate, not TP virtualization)
    0xd53b_e052, // MRS x18,CNTVCT_EL0
    0xd50b_7b32, // SYS/DC CVAU,x18 (synthetic recovery, not executed here)
    0xab01_0252,
    0xab1e_0250,
    0xab12_021e, // ADDS, x16/x30 aliases
    0xf940_0012,
    0xf900_0012,
    0xf940_0250,
    0xf840_8650,
    0xf900_025e,
    0xa8c1_43f2,
    0xa9fe_4bfe,
    0xa9ff_c3f2,
    0x29ff_fbf2,
    0xa9be_7bf2,
    0xa9e0_43f2,
    0xa8e0_4bfe,
    0xa89f_cbf0,
    0x29e0_7bf2,
    0x289f_cbf0,
    0xa8bf_43f2,
    0x28e0_4bfe,
    0xa941_7bf2,
    0xb400_0212,
    0x3400_0212,
    0xb500_0212,
    0x3500_0212,
    0x3600_0212,
    0xb7f8_0212,
    0xb6f8_0212,
    0x3728_0212,
    0x1000_0072,
    0xb000_0012,
    0x707f_fff2,
    0xd61f_0240,
    0xd63f_0240,
    0xd65f_0240,
];

// Exercise the public offline admission API with a minimal stripped ELF's
// executable PT_LOAD, rather than exposing a test-only range constructor.
fn scan_ranges(len: usize) -> litebox_syscall_rewriter::aarch64::CodeScanRanges {
    use zerocopy::IntoBytes as _;
    let mut elf = [0u64; 128];
    let b = elf.as_mut_bytes();
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&183u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[72..80].copy_from_slice(&128u64.to_le_bytes());
    b[80..88].copy_from_slice(&(SITE as u64).to_le_bytes());
    b[96..104].copy_from_slice(&(len as u64).to_le_bytes());
    b[104..112].copy_from_slice(&(len as u64).to_le_bytes());
    ElfCodeMetadata::parse_aligned_in_place(&mut elf, 1024)
        .unwrap()
        .ranges_for_mapping(128, len)
        .unwrap()
}

struct Fixture {
    site: usize,
    island_address: usize,
    chunk_address: usize,
    out: usize,
    code: Vec<u8>,
    island: Vec<u8>,
    chunk: Vec<u8>,
    stack: [u8; 1024],
    tls: [u8; 16],
    gate: IslandGate,
    host: TargetHost,
}
impl Fixture {
    fn new(raw: u32, host: TargetHost, prefix: usize, reverse: bool) -> Self {
        let (site, island_address, chunk_address) = if reverse {
            (FAR, FAR + 0x10_0000, ISLAND)
        } else {
            (SITE, ISLAND, FAR)
        };
        Self::at(raw, host, prefix, site, island_address, chunk_address)
    }
    fn at(
        raw: u32,
        host: TargetHost,
        prefix: usize,
        site: usize,
        island_address: usize,
        chunk_address: usize,
    ) -> Self {
        let mut code = vec![0xd400_0001u32; prefix];
        code.push(raw);
        let mut code: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut pairs = [IslandPair::new(island_address as u64).unwrap()];
        let result = patch_aarch64_code_segment_with_islands(
            &mut code,
            site as u64,
            &scan_ranges((prefix + 1) * 4),
            &mut pairs,
            RewriteOptions::new(host, true),
        )
        .unwrap();
        assert!(result.trapped_sites.is_empty(), "{raw:x}");
        pairs[0].set_chunk_vaddr(chunk_address as u64).unwrap();
        pairs[0].set_callback(0x1234_0000);
        let island = pairs[0].island().to_vec();
        let mut chunk = pairs[0].chunk().to_vec();
        finalize_island_chunk(&mut chunk, 64, host).unwrap();
        let gate = decode_island_chunk(&chunk, host).unwrap()[prefix].clone();
        Self {
            site: site + prefix * 4,
            island_address,
            chunk_address,
            out: island_out(island_address as u64, prefix).trunc(),
            code,
            island,
            chunk,
            stack: [0; 1024],
            tls: [0; 16],
            gate,
            host,
        }
    }
    fn read(&self, address: usize, output: &mut [u8]) -> bool {
        for (base, bytes) in [
            (self.site - self.code.len() + 4, self.code.as_slice()),
            (self.island_address, self.island.as_slice()),
            (self.chunk_address, self.chunk.as_slice()),
            (FRAME - 512, self.stack.as_slice()),
            (TLS, self.tls.as_slice()),
        ] {
            if let Some(at) = address.checked_sub(base)
                && let Some(end) = at.checked_add(output.len())
                && let Some(bytes) = bytes.get(at..end)
            {
                output.copy_from_slice(bytes);
                return true;
            }
        }
        false
    }
    fn save(&mut self, address: usize, value: usize) {
        self.stack[address - (FRAME - 512)..address - (FRAME - 512) + 8]
            .copy_from_slice(&value.to_le_bytes());
    }
    fn runtime(&self) -> GateRuntimeState {
        GateRuntimeState {
            guest_thread_pointer_addr: TLS,
            expected_outbound_stub: self.out,
            expected_outbound_pc: self.site + 4,
        }
    }
    fn run(&self, context: &PtRegs, kind: GateInterruption) -> Aarch64GateSignalResult {
        let mut reads = 0;
        let result = canonicalize(context, self.runtime(), kind, self.host, true, |at, out| {
            reads += 1;
            assert!(out.len() <= MAX_ISLAND_GATE_BYTES);
            self.read(at, out)
        });
        assert!(reads <= 1200, "bounded reads: {reads}");
        result
    }
    fn boundary(&mut self, offset: usize) -> (PtRegs, PtRegs) {
        let stage = island_gate_stage(&self.gate, offset).unwrap();
        let post = stage.phase == IslandPhase::After;
        let mut expected = guest(post);
        expected.pc = if !post {
            self.site
        } else if stage.taken {
            self.site + 64
        } else {
            self.site + 4
        };
        expected.sp = FRAME
            + usize::from(if post {
                self.gate.exit_depth
            } else {
                self.gate.entry_depth
            });
        let mut ctx = expected.clone();
        ctx.pc = self.chunk_address + self.gate.offset + offset;
        ctx.regs[18] = 0xdead_1818;
        ctx.orig_x0 = 0xbad;
        self.save(FRAME, expected.regs[16]);
        self.save(FRAME + 8, expected.regs[30]);
        ctx.sp = FRAME - usize::from(stage.frame_offset);
        if !stage.guest_pair_live {
            ctx.regs[16] = 0xbad_1616;
            let word = u32::from_le_bytes(
                self.chunk[self.gate.offset + offset..self.gate.offset + offset + 4]
                    .try_into()
                    .unwrap(),
            );
            let adjusting = word == 0x9100_63de; // ADD x30,x30,#24
            ctx.regs[30] = self.out + if stage.taken && !adjusting { 24 } else { 0 };
        }
        if let Some(saved) = stage.out_saved {
            self.save(
                FRAME.checked_add_signed(isize::from(saved)).unwrap(),
                self.out,
            );
        }
        if let Some((value, anchor)) = self.gate.scratches {
            if stage.scratches_saved {
                self.save(FRAME - 32, expected.regs[usize::from(value)]);
                self.save(FRAME - 24, expected.regs[usize::from(anchor)]);
                ctx.regs[usize::from(value)] = 0xbaad;
                ctx.regs[usize::from(anchor)] = 0xbad;
            }
            if stage.frame_base != 31 {
                ctx.regs[usize::from(anchor)] = FRAME - usize::from(stage.frame_offset);
                ctx.sp = expected.sp;
            }
        }
        if let Some(value) = stage.pending_x18 {
            ctx.regs[usize::from(value)] = LOGICAL_AFTER;
        }
        self.tls[8..].copy_from_slice(
            &(if post && stage.pending_x18.is_none() {
                LOGICAL_AFTER
            } else {
                LOGICAL_BEFORE
            })
            .to_le_bytes(),
        );
        (ctx, expected)
    }
}
fn guest(post: bool) -> PtRegs {
    let mut regs = PtRegs::default();
    for (i, r) in regs.regs.iter_mut().enumerate() {
        *r = 0xa000 + i + if post { 0x1000 } else { 0 };
    }
    regs.regs[18] = if post { LOGICAL_AFTER } else { LOGICAL_BEFORE };
    regs.pstate = if post { 0x6000_0000 } else { 0x9000_0000 };
    regs.orig_x0 = regs.regs[0];
    regs
}
fn equal(actual: Aarch64GateSignalResult, expected: &PtRegs, note: &str) {
    let Aarch64GateSignalResult::Canonicalized(actual) = actual else {
        panic!("not canonicalized: {note}");
    };
    assert_eq!(actual.regs, expected.regs, "{note}");
    assert_eq!(
        (actual.sp, actual.pc, actual.pstate, actual.orig_x0),
        (expected.sp, expected.pc, expected.pstate, expected.orig_x0),
        "{note}"
    );
}

#[test]
fn production_island_every_emitted_boundary_both_hosts_and_far_directions() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        for &raw in OPERATIONS {
            for reverse in [false, true] {
                let mut f = Fixture::new(raw, host, 2, reverse);
                for offset in (0..f.gate.size).step_by(4) {
                    if island_gate_stage(&f.gate, offset).is_none() {
                        continue;
                    }
                    let (ctx, expected) = f.boundary(offset);
                    equal(
                        f.run(&ctx, GateInterruption::Asynchronous),
                        &expected,
                        &alloc::format!("{raw:x} {host:?} +{offset}"),
                    );
                }
            }
        }
    }
}

#[test]
fn production_island_populated_chunk_below_island() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut saw_1020 = false;
        // Extent/placement is separate from the exhaustive operation matrix:
        // SVC has the reported 0x1020 extent, MRS uses TLS, CBZ has both exits.
        for raw in [0xd400_0001, 0xd53b_d040, 0xb400_0212] {
            let len = Fixture::new(raw, host, 0, false).chunk.len();
            saw_1020 |= len == 0x1020;
            for chunk in [
                ISLAND - 0x3000,
                ISLAND - 0x5000,
                ISLAND - len,
                ISLAND + ISLAND_BYTES,
            ] {
                let mut f = Fixture::at(raw, host, 0, SITE, ISLAND, chunk);
                for offset in (0..f.gate.size).step_by(4) {
                    if island_gate_stage(&f.gate, offset).is_none() {
                        continue;
                    }
                    let (ctx, expected) = f.boundary(offset);
                    equal(
                        f.run(&ctx, GateInterruption::Asynchronous),
                        &expected,
                        &alloc::format!("{raw:x} {host:?} chunk={chunk:x} +{offset}"),
                    );
                }
                for pc in [
                    ISLAND,
                    ISLAND + 4,
                    ISLAND + 8,
                    chunk + CHUNK_TABLE_OFFSET,
                    f.out - 4,
                ] {
                    let (mut ctx, expected) = f.boundary(0);
                    ctx.pc = pc;
                    equal(
                        f.run(&ctx, GateInterruption::Asynchronous),
                        &expected,
                        "near-chunk transport",
                    );
                }
            }
        }
        assert!(saw_1020, "includes the reported populated extent");
    }
}

#[test]
fn production_island_actual_chunk_overlap_and_overflow_rejected() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        // Valid header/primary slot survive each overlap. In particular the
        // table case overlaps only unused entries, not the selected entry.
        for (chunk, gate_offset) in [
            (ISLAND + ISLAND_BYTES - 16, CHUNK_GATES_OFFSET), // header
            (ISLAND - 64, 0x3000),                            // fixed table prefix
            (ISLAND - CHUNK_GATES_OFFSET, CHUNK_GATES_OFFSET + 0x100), // actual gate
        ] {
            let mut f = Fixture::at(0xd53b_d040, host, 0, SITE, ISLAND, chunk);
            let bytes = f.chunk[f.gate.offset..f.gate.offset + f.gate.size].to_vec();
            f.chunk.resize(gate_offset + f.gate.size, 0);
            f.chunk[gate_offset..gate_offset + f.gate.size].copy_from_slice(&bytes);
            f.gate.offset = gate_offset;
            let branch =
                0x1400_0000 | u32::try_from((gate_offset - CHUNK_TABLE_OFFSET) / 4).unwrap();
            f.chunk[CHUNK_TABLE_OFFSET..CHUNK_TABLE_OFFSET + 4]
                .copy_from_slice(&branch.to_le_bytes());
            // Model consistent memory when the header or gate really occupies
            // otherwise unused island bytes. The table case already reads the
            // intact island header through the overlapping unused entries.
            for (start, bytes) in [
                (chunk, f.chunk[..16].to_vec()),
                (chunk + gate_offset, bytes),
            ] {
                if (ISLAND + 0x100..ISLAND + ISLAND_BYTES).contains(&start) {
                    let at = start - ISLAND;
                    f.island[at..at + bytes.len()].copy_from_slice(&bytes);
                }
            }
            let (ctx, _) = f.boundary(0);
            assert!(
                matches!(
                    f.run(&ctx, GateInterruption::Asynchronous),
                    Aarch64GateSignalResult::NotGate
                ),
                "overlap chunk={chunk:x} gate={gate_offset:x}"
            );
        }
        for chunk in [usize::MAX - CHUNK_GATES_OFFSET + 1, usize::MAX - 15] {
            let mut f = Fixture::new(0xd53b_d040, host, 0, false);
            f.chunk_address = chunk;
            let delta = chunk.wrapping_add(CHUNK_TABLE_OFFSET).wrapping_sub(f.out);
            f.island[ISLAND_DELTA_OFFSET..ISLAND_DELTA_OFFSET + 8]
                .copy_from_slice(&delta.to_le_bytes());
            let mut ctx = guest(false);
            ctx.pc = f.out - 12;
            ctx.sp = FRAME;
            assert!(matches!(
                f.run(&ctx, GateInterruption::Asynchronous),
                Aarch64GateSignalResult::NotGate
            ));
        }
    }
}

#[test]
fn production_island_entry_dispatch_table_and_both_exits() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        for &raw in OPERATIONS {
            let mut f = Fixture::new(raw, host, 0, false);
            for (pc, post, taken, live, allocated) in [
                (f.out - 12, false, false, true, false),
                (f.out - 8, false, false, true, true),
                (f.out - 4, false, false, false, true),
                (ISLAND, false, false, false, true),
                (ISLAND + 4, false, false, false, true),
                (ISLAND + 8, false, false, false, true),
                (FAR + CHUNK_TABLE_OFFSET, false, false, false, true),
                (f.out, true, false, false, true),
                (f.out + 4, true, false, true, true),
                (f.out + 8, true, false, true, false),
                (f.out + 24, true, true, false, true),
                (f.out + 28, true, true, true, true),
                (f.out + 32, true, true, true, false),
            ] {
                if taken && !matches!(f.gate.metadata, GateMetadata::X18CompareBranch { .. }) {
                    continue;
                }
                let mut expected = guest(post);
                expected.sp = FRAME
                    + usize::from(if post {
                        f.gate.exit_depth
                    } else {
                        f.gate.entry_depth
                    });
                expected.pc = f.site
                    + if !post {
                        0
                    } else if taken {
                        64
                    } else {
                        4
                    };
                let mut ctx = expected.clone();
                ctx.pc = pc;
                ctx.sp = if allocated { FRAME } else { expected.sp };
                ctx.regs[18] = 0xbad;
                if !live {
                    ctx.regs[16] = 0xdead;
                    ctx.regs[30] = f.out + if taken { 24 } else { 0 };
                }
                f.save(FRAME, expected.regs[16]);
                f.save(FRAME + 8, expected.regs[30]);
                f.tls[8..].copy_from_slice(&expected.regs[18].to_le_bytes());
                let result = f.run(&ctx, GateInterruption::Asynchronous);
                if post && matches!(f.gate.metadata, GateMetadata::Svc) {
                    assert!(matches!(
                        result,
                        Aarch64GateSignalResult::PreserveSavedContext
                    ));
                    for (stub, pc) in [(0, f.site + 4), (f.out, 0), (f.out + 24, f.site + 4)] {
                        let runtime = GateRuntimeState {
                            expected_outbound_stub: stub,
                            expected_outbound_pc: pc,
                            ..f.runtime()
                        };
                        assert!(matches!(
                            canonicalize(
                                &ctx,
                                runtime,
                                GateInterruption::Asynchronous,
                                host,
                                true,
                                |a, b| f.read(a, b)
                            ),
                            Aarch64GateSignalResult::NotGate
                        ));
                    }
                } else {
                    equal(
                        result,
                        &expected,
                        &alloc::format!("transport {raw:x} {host:?} {pc:x}"),
                    );
                }
                let synchronous = f.run(&ctx, GateInterruption::Synchronous);
                if pc == f.out - 8 {
                    equal(synchronous, &expected, "entry spill uses live pair");
                } else if pc == f.out && matches!(f.gate.metadata, GateMetadata::Svc) {
                    assert!(matches!(
                        synchronous,
                        Aarch64GateSignalResult::PreserveSavedContext
                    ));
                } else {
                    assert!(matches!(
                        synchronous,
                        Aarch64GateSignalResult::InvalidRuntimeState
                    ));
                }
            }
        }
    }
}

#[test]
fn production_island_stack_store_faults_never_read_partial_destinations() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        for &raw in OPERATIONS {
            let mut f = Fixture::new(raw, host, 2, false);
            let mut expected = guest(false);
            expected.pc = f.site;
            expected.sp = FRAME + usize::from(f.gate.entry_depth);
            f.tls[8..].copy_from_slice(&expected.regs[18].to_le_bytes());
            let mut ctx = expected.clone();
            ctx.pc = f.out - 8;
            ctx.sp = FRAME;
            equal(
                canonicalize(
                    &ctx,
                    f.runtime(),
                    GateInterruption::Synchronous,
                    host,
                    true,
                    |a, b| {
                        assert!(
                            a + b.len() <= FRAME || a >= FRAME + 16,
                            "entry STP is unreadable"
                        );
                        f.read(a, b)
                    },
                ),
                &expected,
                "partial entry STP",
            );
            for offset in (0..f.gate.size).step_by(4) {
                let Some(gate) = classify_island_signal_gate(
                    &f.chunk[f.gate.offset..f.gate.offset + f.gate.size],
                    (f.chunk_address + f.gate.offset) as u64,
                    offset,
                    host,
                ) else {
                    continue;
                };
                if !gate.stack_store {
                    continue;
                }
                let (ctx, mut expected) = f.boundary(offset);
                let at = f.gate.offset + offset;
                let word = u32::from_le_bytes(f.chunk[at..at + 4].try_into().unwrap());
                let (displacement, len) = if word & 0xffc0_0000 == 0xf900_0000 {
                    (isize::try_from(((word >> 10) & 4095) * 8).unwrap(), 8)
                } else {
                    (((word << 10).cast_signed() >> 25) as isize * 8, 16)
                };
                let fault = ctx.sp.checked_add_signed(displacement).unwrap();
                // Partial stores may corrupt any destination bytes; none are a
                // valid recovery source at this boundary.
                f.save(fault, usize::MAX);
                if len == 16 {
                    f.save(fault + 8, usize::MAX);
                }
                if let GateMetadata::MrsTpidr { destination } = f.gate.metadata {
                    expected.regs[usize::from(destination)] = ctx.regs[16];
                    expected.pc = f.site + 4;
                }
                let result = canonicalize(
                    &ctx,
                    f.runtime(),
                    GateInterruption::Synchronous,
                    host,
                    true,
                    |a, b| {
                        assert!(
                            a + b.len() <= fault || a >= fault + len,
                            "faulted spill {raw:x}+{offset}"
                        );
                        f.read(a, b)
                    },
                );
                equal(result, &expected, "partial gate store");
            }
        }
    }
}

#[test]
fn production_island_fault_attribution_pending_commits_and_brk_vs_async() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        for &raw in OPERATIONS {
            const FLAGS: usize = 0x9000_0000;
            let completed_system_x18 = match raw {
                0xd53b_4212 => Some(FLAGS),          // MRS x18,NZCV
                0xd53b_e052 => Some(0xabcd_1234),    // MRS x18,CNTVCT_EL0
                0xd50b_7b32 => Some(LOGICAL_BEFORE), // SYS leaves x18 unchanged
                _ => None,
            };
            let mut f = Fixture::new(raw, host, 0, false);
            let mut saw_system_instruction = false;
            let mut pending_boundaries = 0;
            for offset in (0..f.gate.size).step_by(4) {
                let Some(stage) = island_gate_stage(&f.gate, offset) else {
                    continue;
                };
                let (mut ctx, mut expected) = f.boundary(offset);
                if let Some(completed) = completed_system_x18 {
                    // These operations preserve flags; their result is independent
                    // of the generic fixture's synthetic LOGICAL_AFTER value.
                    ctx.pstate = FLAGS as u64;
                    expected.pstate = FLAGS as u64;
                    if stage.phase == IslandPhase::After {
                        expected.regs[18] = completed;
                        if let Some(scratch) = stage.pending_x18 {
                            ctx.regs[usize::from(scratch)] = completed;
                        } else {
                            f.tls[8..].copy_from_slice(&completed.to_le_bytes());
                        }
                    }
                }
                let descriptor = classify_island_signal_gate(
                    &f.chunk[f.gate.offset..f.gate.offset + f.gate.size],
                    (f.chunk_address + f.gate.offset) as u64,
                    offset,
                    host,
                )
                .unwrap();
                if completed_system_x18.is_some() && descriptor.guest_instruction {
                    let GateMetadata::X18 { scratch } = f.gate.metadata else {
                        panic!("system operation must use an ordinary x18 gate");
                    };
                    let at = f.gate.offset + offset;
                    assert_eq!(
                        &f.chunk[at..at + 4],
                        &((raw & !31) | u32::from(scratch)).to_le_bytes()
                    );
                    assert_eq!(expected.pc, f.site);
                    assert_eq!(expected.regs[18], LOGICAL_BEFORE);
                    saw_system_instruction = true;
                }
                let result = f.run(&ctx, GateInterruption::Synchronous);
                if descriptor.guest_instruction || descriptor.stack_store {
                    let mut expected = expected.clone();
                    if descriptor.stack_store
                        && let GateMetadata::MrsTpidr { destination } = f.gate.metadata
                    {
                        expected.regs[usize::from(destination)] = ctx.regs[16];
                        expected.pc = f.site + 4;
                    }
                    equal(result, &expected, "guest instruction/stack-store fault");
                } else {
                    assert!(matches!(
                        result,
                        Aarch64GateSignalResult::InvalidRuntimeState
                    ));
                }
                if let GateMetadata::X18Branch { kind } = f.gate.metadata {
                    let Aarch64GateSignalResult::ResumeGuest(r) =
                        f.run(&ctx, GateInterruption::Breakpoint)
                    else {
                        panic!("BRK not emulated");
                    };
                    assert_eq!(r.pc, LOGICAL_BEFORE);
                    assert_eq!(r.sp, expected.sp);
                    assert_eq!(
                        r.regs[30],
                        if kind.writes_link_register() {
                            f.site + 4
                        } else {
                            expected.regs[30]
                        }
                    );
                    equal(
                        f.run(&ctx, GateInterruption::Asynchronous),
                        &expected,
                        "async BRK boundary must not execute",
                    );
                }
                pending_boundaries += usize::from(stage.pending_x18.is_some());
                if stage.pending_x18.is_some()
                    || (completed_system_x18.is_some() && stage.phase == IslandPhase::After)
                {
                    // A completed operation is never replayed. Pending x18 must
                    // come from the scratch, not a stale/unreadable TLS slot.
                    let result = canonicalize(
                        &ctx,
                        f.runtime(),
                        GateInterruption::Asynchronous,
                        host,
                        true,
                        |a, b| (stage.pending_x18.is_none() || a != TLS + 8) && f.read(a, b),
                    );
                    equal(
                        result,
                        &expected,
                        "completed result, flags, and pending commit with unreadable TLS",
                    );
                    assert_eq!(expected.pc, f.site + 4);
                }
            }
            if completed_system_x18.is_some() {
                assert!(saw_system_instruction);
                assert!(
                    pending_boundaries > 0,
                    "MRS/SYS pending boundary must be exercised"
                );
            }
        }
    }
}

#[test]
fn production_island_svc_exact_callback_frame_and_unreadable_provenance() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut f = Fixture::new(0xd400_0001, host, 0, false);
        let (ctx, expected) = f.boundary(24); // BR callback
        f.save(FRAME - 16, f.site + 4);
        f.save(FRAME - 8, f.out);
        assert_eq!(ctx.sp, FRAME - 16);
        let mut frame = [0; 32];
        assert!(f.read(ctx.sp, &mut frame));
        let words: Vec<_> = frame
            .as_chunks::<8>()
            .0
            .iter()
            .map(|w| usize::from_le_bytes(*w))
            .collect();
        assert_eq!(
            words,
            [f.site + 4, f.out, expected.regs[16], expected.regs[30]]
        );
        equal(
            f.run(&ctx, GateInterruption::Asynchronous),
            &expected,
            "SVC callback frame",
        );
        for denied in [f.site, f.island_address, f.chunk_address, FRAME, FRAME - 8] {
            assert!(
                matches!(
                    canonicalize(
                        &ctx,
                        f.runtime(),
                        GateInterruption::Asynchronous,
                        host,
                        true,
                        |a, b| a != denied && f.read(a, b)
                    ),
                    Aarch64GateSignalResult::NotGate
                ),
                "{denied:x}"
            );
        }
        assert!(matches!(
            canonicalize(
                &ctx,
                f.runtime(),
                GateInterruption::Asynchronous,
                host,
                true,
                |a, b| a != TLS + 8 && f.read(a, b)
            ),
            Aarch64GateSignalResult::InvalidRuntimeState
        ));
    }
}

#[test]
fn production_island_rejects_malformed_unreadable_padding_and_unsupported_traps() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        for raw in [0xd63f_0240, 0xb400_0212, 0xa9e0_43f2, 0xd400_0001] {
            let mut f = Fixture::new(raw, host, 0, false);
            let (ctx, _) = f.boundary(0);
            for (region, at) in [
                (0, 0),
                (1, 0),
                (1, 8),
                (1, 16),
                (1, 32),
                (1, 40),
                (1, 52),
                (2, 8),
                (2, 16),
                (2, 20),
                (2, f.gate.offset),
            ] {
                let bytes = match region {
                    0 => &mut f.code,
                    1 => &mut f.island,
                    _ => &mut f.chunk,
                };
                bytes[at] ^= 0x80;
                assert!(
                    matches!(
                        f.run(&ctx, GateInterruption::Breakpoint),
                        Aarch64GateSignalResult::NotGate
                    ),
                    "forged {raw:x} region {region} offset {at}"
                );
                let bytes = match region {
                    0 => &mut f.code,
                    1 => &mut f.island,
                    _ => &mut f.chunk,
                };
                bytes[at] ^= 0x80;
            }
            for offset in (0..f.gate.size)
                .step_by(4)
                .filter(|off| island_gate_stage(&f.gate, *off).is_none())
            {
                let mut bad = ctx.clone();
                bad.pc += offset;
                assert!(matches!(
                    f.run(&bad, GateInterruption::Breakpoint),
                    Aarch64GateSignalResult::NotGate
                ));
            }
            for bad_pc in [
                ISLAND + 12,
                ISLAND + 16,
                ISLAND + 24,
                FAR + 20,
                usize::MAX - 3,
            ] {
                let mut bad = ctx.clone();
                bad.pc = bad_pc;
                assert!(matches!(
                    f.run(&bad, GateInterruption::Asynchronous),
                    Aarch64GateSignalResult::NotGate
                ));
            }
            assert!(matches!(
                canonicalize(
                    &ctx,
                    f.runtime(),
                    GateInterruption::Asynchronous,
                    host,
                    true,
                    |_, _| false
                ),
                Aarch64GateSignalResult::NotGate
            ));
            // A forged BLRAA-like footer may not authorize BRK emulation.
            if raw == 0xd63f_0240 {
                let at = f.gate.offset + f.gate.size - 8;
                f.chunk[at..at + 4].copy_from_slice(&0xd73f_0a40u32.to_le_bytes());
                assert!(matches!(
                    f.run(&ctx, GateInterruption::Breakpoint),
                    Aarch64GateSignalResult::NotGate
                ));
            }
        }
    }
}

#[test]
fn production_island_ambiguous_copied_candidates_fail_closed() {
    // A mapping changing between reads could present two individually valid
    // slot sizes at one address. Never accept the first or last such snapshot.
    let mut first = Fixture::new(0xd53b_d045, TargetHost::Linux, 0, false);
    let second = Fixture::new(0xd53b_d050, TargetHost::Linux, 0, false);
    assert_ne!(first.gate.size, second.gate.size);
    let (ctx, _) = first.boundary(0);
    let address = FAR + first.gate.offset;
    let result = canonicalize(
        &ctx,
        first.runtime(),
        GateInterruption::Asynchronous,
        TargetHost::Linux,
        true,
        |at, bytes| {
            if (at == address && bytes.len() == second.gate.size)
                || (at == address + second.gate.size - 4 && bytes.len() == 4)
            {
                second.read(at, bytes)
            } else {
                first.read(at, bytes)
            }
        },
    );
    assert!(matches!(result, Aarch64GateSignalResult::NotGate));
}

#[test]
fn production_island_respects_virtualization_guest_abi_and_overflow() {
    for raw in [0xd400_0001, 0xab01_0252] {
        let mut f = Fixture::new(raw, TargetHost::MacOs, 0, false);
        let (ctx, mut expected) = f.boundary(0);
        let result = canonicalize(
            &ctx,
            f.runtime(),
            GateInterruption::Asynchronous,
            f.host,
            false,
            |at, bytes| at != TLS + 8 && f.read(at, bytes),
        );
        if raw == 0xd400_0001 {
            expected.regs[18] = ctx.regs[18];
            equal(result, &expected, "nonvirtualized Linux guest");
        } else {
            assert!(matches!(result, Aarch64GateSignalResult::NotGate));
        }
        assert!(matches!(
            canonicalize_darwin(
                &ctx,
                f.runtime(),
                GateInterruption::Asynchronous,
                |at, bytes| f.read(at, bytes)
            ),
            Aarch64GateSignalResult::NotGate
        ));
        let bad_runtime = GateRuntimeState {
            guest_thread_pointer_addr: usize::MAX - 3,
            ..f.runtime()
        };
        assert!(matches!(
            canonicalize(
                &ctx,
                bad_runtime,
                GateInterruption::Asynchronous,
                f.host,
                true,
                |at, bytes| f.read(at, bytes)
            ),
            Aarch64GateSignalResult::InvalidRuntimeState
        ));
        let mut bad = ctx.clone();
        bad.sp = usize::MAX - 7;
        assert!(matches!(
            f.run(&bad, GateInterruption::Asynchronous),
            Aarch64GateSignalResult::NotGate
        ));
    }
}

#[test]
fn production_island_rejects_mismatched_tls_transport_fields_and_aux_target() {
    for host in [TargetHost::Linux, TargetHost::MacOs] {
        let mut f = Fixture::new(0xab01_0252, host, 0, false);
        let (ctx, _) = f.boundary(0);
        // Change only the second TLS offset, leaving both offsets individually
        // valid. Full transport must still reject the conflicting fields.
        let tls_words: Vec<_> = f.chunk[f.gate.offset..f.gate.offset + f.gate.size]
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, w)| {
                let raw = u32::from_le_bytes(*w);
                ((raw & 0xffc0_0000 == 0xf900_0000 || raw & 0xffc0_0000 == 0xf940_0000)
                    && ((raw >> 5) & 31) == 16
                    && ((raw >> 10) & 4095) >= 8)
                    .then_some(i * 4)
            })
            .collect();
        let at = f.gate.offset + *tls_words.last().unwrap();
        let raw = u32::from_le_bytes(f.chunk[at..at + 4].try_into().unwrap());
        f.chunk[at..at + 4].copy_from_slice(&(raw + (2 << 10)).to_le_bytes());
        assert!(matches!(
            f.run(&ctx, GateInterruption::Asynchronous),
            Aarch64GateSignalResult::NotGate
        ));
        let mut f = Fixture::new(0xb400_0212, host, 0, false);
        let (ctx, _) = f.boundary(0);
        // Still a valid auxiliary B, but no longer the original conditional's
        // taken target. Primary site identity must not be derived from it.
        f.island[76] ^= 1;
        assert!(matches!(
            f.run(&ctx, GateInterruption::Asynchronous),
            Aarch64GateSignalResult::NotGate
        ));
    }
}

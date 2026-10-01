// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Registry-free island recovery. All addresses are untrusted until the full
//! site -> entry -> dispatcher/table -> gate -> exit loop has been checked.

use super::{
    Aarch64GateSignalResult, GateInterruption, GateMetadata, GateRuntimeState, PtRegs, TargetHost,
};
use litebox::utils::TruncateExt as _;
use litebox_syscall_rewriter::aarch64::island::{
    CHUNK_CAPACITY_BYTES, CHUNK_GATES_OFFSET, CHUNK_TABLE_OFFSET, ISLAND_BYTES,
    ISLAND_HEADER_BYTES, ISLAND_OUT_OFFSET, ISLAND_SLOT_BYTES, ISLAND_SLOTS, IslandPhase,
    IslandSlot, IslandStage, MAX_ISLAND_GATE_BYTES, decode_island_header,
    signal::{IslandSignalGate, classify_island_signal_gate, classify_island_signal_slot},
};

// A hard bound in addition to the statically bounded loops. Reads never exceed
// 96 bytes, even on forged memory that makes every footer look plausible.
const READ_BUDGET: usize = 1024;
const TABLE_PADDING: u32 = 0xd420_2b40;
const AUX_MARKER: u32 = 0xd420_2b60;

struct Reader<F> {
    read: F,
    remaining: usize,
    exhausted: bool,
}
impl<F: FnMut(usize, &mut [u8]) -> bool> Reader<F> {
    fn bytes<const N: usize>(&mut self, address: usize) -> Option<[u8; N]> {
        address.checked_add(N)?;
        self.remaining = if let Some(n) = self.remaining.checked_sub(1) {
            n
        } else {
            self.exhausted = true;
            return None;
        };
        let mut bytes = [0; N];
        (self.read)(address, &mut bytes).then_some(bytes)
    }
    fn word(&mut self, address: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(address)?))
    }
    fn pointer(&mut self, address: usize) -> Option<usize> {
        Some(usize::from_le_bytes(self.bytes(address)?))
    }
    fn slot(
        &mut self,
        island: usize,
        index: usize,
        primary: Option<IslandSlot>,
    ) -> Option<IslandSlot> {
        if index >= ISLAND_SLOTS {
            return None;
        }
        classify_island_signal_slot(
            &self.bytes::<ISLAND_SLOT_BYTES>(
                island.checked_add(ISLAND_HEADER_BYTES + index * ISLAND_SLOT_BYTES)?,
            )?,
            island as u64,
            index,
            primary,
        )
    }
    fn table(&mut self, table: usize) -> Option<u32> {
        let bytes = self.bytes::<ISLAND_SLOT_BYTES>(table)?;
        for at in (4..ISLAND_SLOT_BYTES).step_by(4) {
            if u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) != TABLE_PADDING {
                return None;
            }
        }
        Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
    }
    fn gate(
        &mut self,
        address: usize,
        offset: usize,
        host: TargetHost,
    ) -> Option<IslandSignalGate> {
        let mut found = None;
        for size in (16..=MAX_ISLAND_GATE_BYTES).step_by(16) {
            let footer = self.word(address.checked_add(size - 4)?);
            if footer
                .and_then(litebox_syscall_rewriter::aarch64::island::decode_island_metadata)
                .is_none()
            {
                continue;
            }
            let mut bytes = [0; MAX_ISLAND_GATE_BYTES];
            // Only read the actual candidate, not the mapping after its end.
            address.checked_add(size)?;
            self.remaining = self.remaining.checked_sub(1).or_else(|| {
                self.exhausted = true;
                None
            })?;
            if !(self.read)(address, bytes.get_mut(..size)?) {
                continue;
            }
            let Some(gate) =
                classify_island_signal_gate(bytes.get(..size)?, address as u64, offset, host)
            else {
                continue;
            };
            if found.is_some() {
                return None;
            }
            found = Some(gate);
        }
        found
    }
}

#[derive(Clone, Copy)]
struct Link {
    primary: IslandSlot,
    auxiliary: Option<IslandSlot>,
    out: usize,
    table: usize,
    gate_address: usize,
    gate: IslandSignalGate,
}

/// out may name either exit; primary identity is *always* obtained from the
/// primary's fallthrough branch, never from the taken target.
fn link<F: FnMut(usize, &mut [u8]) -> bool>(
    out: usize,
    host: TargetHost,
    read: &mut Reader<F>,
) -> Option<Link> {
    let island = out & !(ISLAND_BYTES - 1);
    let within = out.checked_sub(island + ISLAND_HEADER_BYTES + ISLAND_OUT_OFFSET)?;
    if !within.is_multiple_of(ISLAND_SLOT_BYTES) {
        return None;
    }
    let index = within / ISLAND_SLOT_BYTES;
    if index >= ISLAND_SLOTS {
        return None;
    }
    let header = read.bytes::<ISLAND_HEADER_BYTES>(island)?;
    let delta: usize = decode_island_header(&header)?.trunc();
    let primary = read.slot(island, index, None).or_else(|| {
        let p = read.slot(island, index.checked_sub(1)?, None)?;
        let aux = read.slot(island, index, Some(p))?;
        aux.auxiliary.then_some(p)
    })?;
    let primary_out = island
        .checked_add(ISLAND_HEADER_BYTES + primary.index * ISLAND_SLOT_BYTES + ISLAND_OUT_OFFSET)?;
    // The delta is intentionally modular: chunks may lie arbitrarily far in
    // either direction. Every resulting mapping range is checked separately.
    let chunk = (island + ISLAND_HEADER_BYTES + ISLAND_OUT_OFFSET)
        .wrapping_add(delta)
        .checked_sub(CHUNK_TABLE_OFFSET)?;
    if !chunk.is_multiple_of(16) {
        return None;
    }
    // Capacity bounds offsets, not the mapped footprint. The fixed header/table
    // prefix and this fully validated gate must be disjoint from the island;
    // unused gate capacity need not even be mapped.
    let island_end = island.checked_add(ISLAND_BYTES)?;
    let gates_start = chunk.checked_add(CHUNK_GATES_OFFSET)?;
    if island < gates_start && chunk < island_end {
        return None;
    }
    let chunk_header = read.bytes::<16>(chunk)?;
    if chunk_header.get(8..)? != [0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5] {
        return None;
    }
    let table = chunk.checked_add(CHUNK_TABLE_OFFSET + primary.index * ISLAND_SLOT_BYTES)?;
    let gate_address = usize::try_from(litebox_syscall_rewriter::aarch64::decode_branch_target(
        read.table(table)?,
        table as u64,
    )?)
    .ok()?;
    let gate_offset = gate_address.checked_sub(chunk)?;
    if !(CHUNK_GATES_OFFSET..CHUNK_CAPACITY_BYTES).contains(&gate_offset) {
        return None;
    }
    let gate = read.gate(gate_address, 0, host)?;
    if gate_offset.checked_add(gate.size)? > CHUNK_CAPACITY_BYTES
        || (island < gate_address.checked_add(gate.size)? && chunk < island_end)
        || primary.entry_depth != gate.entry_depth
        || primary.exit_depth != gate.exit_depth
    {
        return None;
    }
    let site = usize::try_from(primary.site).ok()?;
    if !site.is_multiple_of(4)
        || litebox_syscall_rewriter::aarch64::decode_branch_target(read.word(site)?, primary.site)
            != Some((primary_out - ISLAND_OUT_OFFSET) as u64)
    {
        return None;
    }
    let auxiliary = if matches!(gate.metadata, GateMetadata::X18CompareBranch { .. }) {
        let aux = read.slot(island, primary.index.checked_add(1)?, Some(primary))?;
        if !aux.auxiliary
            || aux.entry_depth != gate.entry_depth
            || aux.exit_depth != gate.exit_depth
            || gate.target(primary.site) != Some(aux.resume)
            || read.table(table.checked_add(ISLAND_SLOT_BYTES)?)? != AUX_MARKER
        {
            return None;
        }
        Some(aux)
    } else {
        None
    };
    if out != primary_out
        && (auxiliary.is_none() || out != primary_out.checked_add(ISLAND_SLOT_BYTES)?)
    {
        return None;
    }
    if let Some(k) = gate.k {
        let target = if matches!(gate.metadata, GateMetadata::X18Adr { .. }) {
            gate.target(primary.site)?
        } else {
            primary.site.checked_add(4)?
        };
        if k != target.wrapping_sub(primary_out as u64) {
            return None;
        }
    }
    if gate.callback_literal.is_some_and(|at| at != chunk as u64) {
        return None;
    }
    Some(Link {
        primary,
        auxiliary,
        out: primary_out,
        table,
        gate_address,
        gate,
    })
}

#[derive(Clone, Copy)]
struct Candidate {
    link: Link,
    stage: IslandStage,
    frame: usize,
    guest_sp: usize,
    guest_fault: bool,
    pair_result: Option<u8>,
    branch_trap: bool,
    outbound: bool,
}

fn stage_frame(context: &PtRegs, stage: IslandStage) -> Option<usize> {
    let base = if stage.frame_base == 31 {
        context.sp
    } else {
        *context.regs.get(usize::from(stage.frame_base))?
    };
    base.checked_add(usize::from(stage.frame_offset))
}

fn gate_candidate<F: FnMut(usize, &mut [u8]) -> bool>(
    context: &PtRegs,
    gate: IslandSignalGate,
    address: usize,
    host: TargetHost,
    read: &mut Reader<F>,
) -> Option<Candidate> {
    let stage = gate.stage;
    let frame = stage_frame(context, stage)?;
    let out = if let Some(saved) = stage.out_saved {
        read.pointer(frame.checked_add_signed(isize::from(saved))?)?
    } else {
        context.regs[30]
    };
    let link = link(out, host, read)?;
    let expected_out = link.out.checked_add(if gate.live_auxiliary {
        ISLAND_SLOT_BYTES
    } else {
        0
    })?;
    // Saved out_k is always primary, even when guest x30 is live.
    if out != expected_out
        || link.gate_address != address
        || link.gate.size != gate.size
        || link.gate.metadata != gate.metadata
    {
        return None;
    }
    let guest_sp = frame.checked_add(usize::from(if stage.phase == IslandPhase::Before {
        gate.entry_depth
    } else {
        gate.exit_depth
    }))?;
    Some(Candidate {
        link,
        stage,
        frame,
        guest_sp,
        guest_fault: gate.guest_instruction || gate.stack_store,
        pair_result: if let GateMetadata::MrsTpidr { destination } = gate.metadata {
            gate.stack_store.then_some(destination)
        } else {
            None
        },
        branch_trap: matches!(gate.metadata, GateMetadata::X18Branch { .. }),
        outbound: false,
    })
}

fn transport_candidate(context: &PtRegs, link: Link) -> Option<Candidate> {
    let pc = context.pc;
    let island = link.out & !(ISLAND_BYTES - 1);
    let mut stage = link.gate.stage; // gate entry always has the basic Before stage
    let mut frame = context.sp;
    let mut outbound = false;
    if pc == link.table || [island, island + 4, island + 8].contains(&pc) {
        if context.regs[30] != link.out {
            return None;
        }
    } else {
        let (out, taken) = if (link.out - 12..=link.out + 8).contains(&pc) {
            (link.out, false)
        } else if link.auxiliary.is_some()
            && (link.out + ISLAND_SLOT_BYTES..=link.out + ISLAND_SLOT_BYTES + 8).contains(&pc)
        {
            (link.out + ISLAND_SLOT_BYTES, true)
        } else {
            return None;
        };
        match pc.checked_add(12)?.checked_sub(out)? {
            0 => {
                frame = context.sp.checked_sub(usize::from(link.gate.entry_depth))?;
                stage.guest_pair_live = true;
            }
            4 => {
                stage.guest_pair_live = true;
            }
            8 => {} // STP complete, BL has not yet overwritten x30
            12 | 16 | 20 => {
                stage.phase = IslandPhase::After;
                stage.taken = taken;
                stage.guest_pair_live = pc != out;
                if pc == out + 8 {
                    frame = context.sp.checked_sub(usize::from(link.gate.exit_depth))?;
                }
                outbound = matches!(link.gate.metadata, GateMetadata::Svc);
            }
            _ => return None,
        }
    }
    let guest_sp = frame.checked_add(usize::from(if stage.phase == IslandPhase::Before {
        link.gate.entry_depth
    } else {
        link.gate.exit_depth
    }))?;
    Some(Candidate {
        link,
        stage,
        frame,
        guest_sp,
        guest_fault: pc == link.out - 8,
        pair_result: None,
        branch_trap: false,
        outbound,
    })
}

pub(super) fn canonicalize(
    context: &PtRegs,
    runtime: GateRuntimeState,
    interruption: GateInterruption,
    host: TargetHost,
    virtualize_x18: bool,
    read: &mut impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    let mut read = Reader {
        read,
        remaining: READ_BUDGET,
        exhausted: false,
    };
    let mut found = None;
    let mut ambiguous = false;
    let mut accept = |candidate: Option<Candidate>| {
        if let Some(c) = candidate {
            if found.is_some() {
                ambiguous = true;
            } else {
                found = Some(c);
            }
        }
    };
    let island = context.pc & !(ISLAND_BYTES - 1);
    let within = context.pc - island;
    // Near PCs carry their own identity, including after LDP restores guest LR.
    if (ISLAND_HEADER_BYTES..ISLAND_HEADER_BYTES + ISLAND_SLOTS * ISLAND_SLOT_BYTES)
        .contains(&within)
    {
        let index = (within - ISLAND_HEADER_BYTES) / ISLAND_SLOT_BYTES;
        if let Some(out) =
            island.checked_add(ISLAND_HEADER_BYTES + index * ISLAND_SLOT_BYTES + ISLAND_OUT_OFFSET)
        {
            accept(link(out, host, &mut read).and_then(|l| transport_candidate(context, l)));
        }
    }
    // Dispatcher and table entry still have a live primary out_k in x30.
    if let Some(l) = link(context.regs[30], host, &mut read) {
        let base = l.out & !(ISLAND_BYTES - 1);
        if context.pc == l.table || [base, base + 4, base + 8].contains(&context.pc) {
            accept(transport_candidate(context, l));
        }
    }
    let aligned = context.pc & !15;
    for back in (0..MAX_ISLAND_GATE_BYTES).step_by(16) {
        let Some(address) = aligned.checked_sub(back) else {
            continue;
        };
        if let Some(gate) = read.gate(address, context.pc - address, host) {
            accept(gate_candidate(context, gate, address, host, &mut read));
        }
    }
    if ambiguous || read.exhausted {
        return Aarch64GateSignalResult::NotGate;
    }
    let Some(mut c) = found else {
        return Aarch64GateSignalResult::NotGate;
    };
    if interruption != GateInterruption::Synchronous {
        c.pair_result = None;
    }
    let is_x18 = c.link.gate.original.is_some();
    if is_x18 && !virtualize_x18 {
        return Aarch64GateSignalResult::NotGate;
    }
    // TLS/literals and scaffolding fetch faults indicate runtime corruption.
    // Guest-stack stores are different: all inputs still exist at the described
    // boundary, even if STP wrote only half its destination before faulting.
    // Stack loads cannot recover unavailable originals; SVC's outbound path is
    // the exception because the callback already saved the entire guest context.
    if interruption == GateInterruption::Synchronous
        && !(c.guest_fault || c.outbound && context.pc == c.link.out)
    {
        return Aarch64GateSignalResult::InvalidRuntimeState;
    }
    if c.outbound {
        return if runtime.expected_outbound_stub == c.link.out
            && runtime.expected_outbound_pc == c.link.primary.resume.trunc()
        {
            Aarch64GateSignalResult::PreserveSavedContext
        } else {
            Aarch64GateSignalResult::NotGate
        };
    }
    let mut canonical = context.clone();
    canonical.sp = c.guest_sp;
    canonical.pc = (if c.stage.phase == IslandPhase::Before && c.pair_result.is_none() {
        c.link.primary.site
    } else if c.stage.taken {
        match c.link.auxiliary {
            Some(aux) => aux.resume,
            None => return Aarch64GateSignalResult::NotGate,
        }
    } else {
        c.link.primary.resume
    })
    .trunc();
    if !c.stage.guest_pair_live {
        for (reg, offset) in [(16, 0), (30, 8)] {
            // MRS completed its TLS read before updating a saved x16/x30. Its
            // result is live in x16, and the faulting destination is untrusted.
            canonical.regs[reg] = if c.pair_result.map(usize::from) == Some(reg) {
                context.regs[16]
            } else if let Some(value) = read.pointer(c.frame + offset) {
                value
            } else {
                return if interruption == GateInterruption::Synchronous {
                    Aarch64GateSignalResult::InvalidRuntimeState
                } else {
                    Aarch64GateSignalResult::NotGate
                };
            };
        }
    }
    // Obtain pending x18 *before* restoring its borrowed register.
    if virtualize_x18 {
        canonical.regs[18] = if let Some(reg) = c.stage.pending_x18 {
            let Some(value) = context.regs.get(usize::from(reg)) else {
                return Aarch64GateSignalResult::NotGate;
            };
            *value
        } else {
            let Some(address) = runtime.guest_thread_pointer_addr.checked_add(8) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(value) = read.pointer(address) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            value
        };
    }
    if c.stage.scratches_saved {
        let Some((value, anchor)) = c.link.gate.scratches else {
            return Aarch64GateSignalResult::NotGate;
        };
        let Some(address) = c.frame.checked_sub(32) else {
            return Aarch64GateSignalResult::NotGate;
        };
        let Some(saved) = read.bytes::<16>(address) else {
            return Aarch64GateSignalResult::NotGate;
        };
        let (first, second) = saved.split_at(8);
        let (Ok(first), Ok(second)) = (first.try_into(), second.try_into()) else {
            return Aarch64GateSignalResult::NotGate;
        };
        canonical.regs[usize::from(value)] = usize::from_le_bytes(first);
        canonical.regs[usize::from(anchor)] = usize::from_le_bytes(second);
    }
    canonical.orig_x0 = canonical.regs[0];
    if c.branch_trap
        && interruption == GateInterruption::Breakpoint
        && let GateMetadata::X18Branch { kind } = c.link.gate.metadata
    {
        if kind.writes_link_register() {
            canonical.regs[30] = c.link.primary.resume.trunc();
        }
        canonical.pc = canonical.regs[18];
        return Aarch64GateSignalResult::ResumeGuest(canonical);
    }
    Aarch64GateSignalResult::Canonicalized(canonical)
}

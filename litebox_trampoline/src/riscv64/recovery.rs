// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent recovery of interrupted RV64 gates.
//!
//! Platforms keep their OS context types and supply the integer registers in
//! Linux `sc_regs` order: index 0 is the pc and index `i` is `x<i>`. Recovery
//! never touches index 3: physical gp is the runtime's, and the platform
//! substitutes [`GateTls::guest_gp`](super::GateTls::guest_gp).
//!
//! A gate changes no guest-visible state before its last [`GateTls`] write,
//! other than its scratch register (saved in `spill`) and, for `ecall`,
//! through the runtime. So a context interrupted before the reload restarts
//! the original instruction, and one at or after the reload completes it:
//!
//! | Interrupted at        | Scratch register | pc        |
//! | --------------------- | ---------------- | --------- |
//! | the first instruction | unchanged        | a restart |
//! | the body              | `spill`          | a restart |
//! | the reload            | `spill`          | `next`    |
//! | the return `jal`      | unchanged        | `next`    |
//!
//! Recovery decodes only the gate, which is in the readable trampoline. A
//! restart resumes at the site when it is known: for `ecall`, which has no
//! compressed form, the site is always `next - 4`; for other gates it is the
//! instruction before `next` that jumps to the gate, if that can be read.
//! Guest code may be execute-only, so otherwise a restart resumes at the
//! gate's first instruction, which is equivalent: a restarted context holds
//! the guest's scratch register and nothing else the gate has changed.
//!
//! An `ecall` gate is at its reload only after the runtime has completed the
//! syscall; [`canonicalize_syscall_entry`] handles a context interrupted when
//! entering the runtime, before the syscall. A restart re-executes at most a
//! relocated load or computation, which wrote only the scratch register: a
//! relocated store is followed directly by the reload.
//!
//! Gates are recognized by their exact form. Guest code never contains one,
//! as the rewriter replaces every instruction with a gp operand.
//!
//! [`GateTls`]: super::GateTls

use super::gate::{self, Form, MAX_GATE_WORDS, Template};

const T0: usize = 5;

/// Recovery outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateSignalResult {
    /// The pc is not inside a gate; the registers are unchanged.
    NotGate,
    /// The registers now hold the architectural guest context.
    Canonicalized,
    /// A gate's own access to the runtime's [`GateTls`](super::GateTls)
    /// faulted, so physical gp does not point at it. The registers are
    /// unchanged.
    InvalidRuntimeState,
}

/// How the signal being handled relates to the interrupted instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateInterruption {
    /// A memory fault raised by the interrupted instruction's own data
    /// access: inside a gate, its access to the runtime's
    /// [`GateTls`](super::GateTls) or a relocated guest load or store.
    Synchronous,
    /// Any other signal, even a trap raised by the interrupted instruction,
    /// such as an illegal instruction or a breakpoint.
    Asynchronous,
}

/// A gate, and the pc its return `jal` jumps to.
struct Located {
    template: Template,
    start: usize,
    words: [u32; MAX_GATE_WORDS],
    next: usize,
}

impl Located {
    /// Where a restart of the gate's instruction resumes; see the module docs.
    fn restart(&self, read: &mut impl FnMut(usize, &mut [u8]) -> bool) -> usize {
        if self.template.form == Form::Ecall {
            return self.next.wrapping_sub(4);
        }
        site_of(self.start, self.next, read).unwrap_or(self.start)
    }
}

fn read_word(read: &mut impl FnMut(usize, &mut [u8]) -> bool, addr: usize) -> Option<u32> {
    let mut bytes = [0; 4];
    read(addr, &mut bytes).then(|| u32::from_le_bytes(bytes))
}

/// Finds the gate containing `pc`.
fn locate(pc: usize, read: &mut impl FnMut(usize, &mut [u8]) -> bool) -> Option<Located> {
    if !pc.is_multiple_of(4) {
        return None;
    }
    // Gates are contiguous whole words, and none contains another's first
    // instruction, so at most one candidate decodes. Nor is a gate a prefix
    // of another, so a candidate is read only until it decodes: the words
    // after a gate may be unmapped.
    for back in 0..MAX_GATE_WORDS {
        let Some(start) = pc.checked_sub(back * 4) else {
            break;
        };
        let mut words = [0; MAX_GATE_WORDS];
        let mut template = None;
        for len in 1..=MAX_GATE_WORDS {
            let Some(word) = start
                .checked_add((len - 1) * 4)
                .and_then(|addr| read_word(read, addr))
            else {
                break;
            };
            words[len - 1] = word;
            // Reject most candidates after a single read.
            if len == 1 && !gate::is_spill(word) {
                break;
            }
            template = gate::decode(&words[..len]);
            if template.is_some() {
                break;
            }
        }
        let Some(template) = template else {
            continue;
        };
        let end = template.reload + 2;
        if back >= end {
            continue;
        }
        let jump = start + (template.reload + 1) * 4;
        let next =
            jump.wrapping_add_signed(gate::jal_x0_offset(words[template.reload + 1])? as isize);
        return Some(Located {
            template,
            start,
            words,
            next,
        });
    }
    None
}

/// The site before `next` that jumps to the gate at `start`, if it can be read.
fn site_of(
    start: usize,
    next: usize,
    read: &mut impl FnMut(usize, &mut [u8]) -> bool,
) -> Option<usize> {
    let targets = |site: usize, offset: i32| site.wrapping_add_signed(offset as isize) == start;
    let wide = next.checked_sub(4)?;
    if read_word(read, wide)
        .and_then(gate::jal_x0_offset)
        .is_some_and(|offset| targets(wide, offset))
    {
        return Some(wide);
    }
    let narrow = next.checked_sub(2)?;
    let mut half = [0; 2];
    (read(narrow, &mut half)
        && gate::compressed_jump_offset(u16::from_le_bytes(half))
            .is_some_and(|offset| targets(narrow, offset)))
    .then_some(narrow)
}

/// Maps a context interrupted inside a gate to the guest context it stands
/// for, given the interrupted thread's [`GateTls::spill`](super::GateTls::spill).
/// A [`GateInterruption::Synchronous`] fault of a gate's own [`GateTls`]
/// access is [`GateSignalResult::InvalidRuntimeState`]; any other
/// interruption is canonicalized alike.
///
/// `read(addr, buf)` must fill `buf` from guest memory at `addr`, returning
/// false instead of faulting. Recovery does not allocate. Platform-specific
/// bookkeeping such as Linux `orig_a0` is not handled here.
///
/// [`GateTls`]: super::GateTls
pub fn canonicalize(
    regs: &mut [usize; 32],
    spill: usize,
    interruption: GateInterruption,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> GateSignalResult {
    let Some(gate) = locate(regs[0], &mut read) else {
        return GateSignalResult::NotGate;
    };
    let index = (regs[0] - gate.start) / 4;
    if interruption == GateInterruption::Synchronous && gate::accesses_gate_tls(gate.words[index]) {
        return GateSignalResult::InvalidRuntimeState;
    }
    let scratch = gate.template.scratch as usize;
    let reload = gate.template.reload;
    if (1..=reload).contains(&index) {
        regs[scratch] = spill;
    }
    regs[0] = if index < reload {
        gate.restart(&mut read)
    } else {
        gate.next
    };
    GateSignalResult::Canonicalized
}

/// Maps a context interrupted at the runtime's syscall entry, before the
/// entry has saved or changed anything, to the guest context it stands for,
/// given the interrupted thread's [`GateTls::spill`](super::GateTls::spill).
///
/// The `ecall` gate's `jalr` has run, so `t0` holds the continuation and
/// `spill` the guest `t0`. The syscall has not run, so the context restarts
/// the `ecall`. If the continuation is not the reload of an `ecall` gate, the
/// guest entered the runtime itself; the context then resumes at the
/// continuation, as the runtime does after such a syscall.
pub fn canonicalize_syscall_entry(
    regs: &mut [usize; 32],
    spill: usize,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) {
    let continuation = regs[T0];
    regs[T0] = spill;
    regs[0] = syscall_return_pc(continuation, &mut read)
        .map_or(continuation, |next| next.wrapping_sub(4));
}

/// Returns the pc after the `ecall` site of the gate whose runtime entry
/// linked `continuation`, or `None` if `continuation` is not the reload of an
/// `ecall` gate. Reads only the gate: the site is the four bytes before the
/// result.
pub fn syscall_return_pc(
    continuation: usize,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Option<usize> {
    let gate = locate(continuation, &mut read)?;
    (gate.template.form == Form::Ecall && continuation == gate.start + gate.template.reload * 4)
        .then_some(gate.next)
}

#[cfg(test)]
mod tests {
    use super::super::gate::{GateKind, RD, RS1, RS2, emit, reg};
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    const CODE: usize = 0x1_0000;
    const BASE: usize = 0x1_0100;
    const BLOCK: usize = 0x2_0000;
    const ENTRY: usize = 0x3_0000;
    const STACK: usize = 0x4_0000;
    const DATA: usize = 0x5_0000;
    const SPILL: usize = BLOCK + 8;

    const A0: usize = 10;
    const A7: usize = 17;

    /// A guest instruction to rewrite: its bytes at the site, and its 32-bit
    /// expansion, which is what gp-operand gates relocate.
    struct Case {
        name: &'static str,
        bytes: Vec<u8>,
        word: u32,
        kind: GateKind,
    }

    const fn i_type(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (imm.cast_unsigned() & 0xfff) << 20 | rs1 << RS1 | funct3 << 12 | rd << RD | opcode
    }

    const fn s_type(imm: u32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
        (imm >> 5) << 25 | rs2 << RS2 | rs1 << RS1 | funct3 << 12 | (imm & 31) << RD | 0x23
    }

    const ADDI_A0_GP: u32 = i_type(16, 3, 0, 10, 0x13);
    const LD_GP_SP: u32 = i_type(8, 2, 3, 3, 0x03);
    const ADD_GP_GP_A1: u32 = 11 << RS2 | 3 << RS1 | 3 << RD | 0x33;
    const SD_GP_SP: u32 = s_type(8, 3, 2, 3);
    const SD_T0_GP: u32 = s_type(8, 5, 3, 3);
    const ADD_T0_T1_GP: u32 = 3 << RS2 | 6 << RS1 | 5 << RD | 0x33;
    const ADD_A0_ZERO_GP: u32 = 3 << RS2 | 10 << RD | 0x33;
    const ADDI_GP_GP: u32 = i_type(-1, 3, 0, 3, 0x13);
    const LUI_GP: u32 = 0x1000 | 3 << RD | 0x37;

    fn le(word: u32) -> Vec<u8> {
        word.to_le_bytes().into()
    }

    fn cases() -> Vec<Case> {
        let load_store = &[RD, RS1][..];
        let all = &[RD, RS1, RS2][..];
        Vec::from([
            Case {
                name: "ecall",
                bytes: le(0x73),
                word: 0x73,
                kind: GateKind::Ecall,
            },
            Case {
                name: "auipc gp, 0x12345",
                bytes: le(0x1234_5197),
                word: 0x1234_5197,
                kind: GateKind::AuipcGp(0x1234_5000),
            },
            Case {
                name: "auipc gp, -1",
                bytes: le(0xffff_f197),
                word: 0xffff_f197,
                kind: GateKind::AuipcGp(0xffff_f000),
            },
            Case {
                name: "addi a0, gp, 16",
                bytes: le(ADDI_A0_GP),
                word: ADDI_A0_GP,
                kind: GateKind::Gp {
                    word: ADDI_A0_GP,
                    fields: load_store,
                },
            },
            Case {
                name: "ld gp, 8(sp)",
                bytes: le(LD_GP_SP),
                word: LD_GP_SP,
                kind: GateKind::Gp {
                    word: LD_GP_SP,
                    fields: load_store,
                },
            },
            Case {
                name: "add gp, gp, a1",
                bytes: le(ADD_GP_GP_A1),
                word: ADD_GP_GP_A1,
                kind: GateKind::Gp {
                    word: ADD_GP_GP_A1,
                    fields: all,
                },
            },
            Case {
                name: "sd gp, 8(sp)",
                bytes: le(SD_GP_SP),
                word: SD_GP_SP,
                kind: GateKind::Gp {
                    word: SD_GP_SP,
                    fields: &[RS1, RS2],
                },
            },
            Case {
                name: "sd t0, 8(gp)",
                bytes: le(SD_T0_GP),
                word: SD_T0_GP,
                kind: GateKind::Gp {
                    word: SD_T0_GP,
                    fields: &[RS1, RS2],
                },
            },
            Case {
                name: "add t0, t1, gp",
                bytes: le(ADD_T0_T1_GP),
                word: ADD_T0_T1_GP,
                kind: GateKind::Gp {
                    word: ADD_T0_T1_GP,
                    fields: all,
                },
            },
            Case {
                name: "c.mv a0, gp",
                bytes: Vec::from([0x0e, 0x85]),
                word: ADD_A0_ZERO_GP,
                kind: GateKind::Gp {
                    word: ADD_A0_ZERO_GP,
                    fields: all,
                },
            },
            Case {
                name: "c.addi gp, -1",
                bytes: Vec::from([0xfd, 0x11]),
                word: ADDI_GP_GP,
                kind: GateKind::Gp {
                    word: ADDI_GP_GP,
                    fields: load_store,
                },
            },
            Case {
                name: "c.lui gp, 1",
                bytes: Vec::from([0x85, 0x61]),
                word: LUI_GP,
                kind: GateKind::Gp {
                    word: LUI_GP,
                    fields: &[RD],
                },
            },
        ])
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Machine {
        pc: usize,
        x: [usize; 32],
        mem: BTreeMap<usize, u8>,
        /// Whether the guest code, below the trampoline, is execute-only.
        execute_only: bool,
    }

    impl Machine {
        /// Reads memory as a load, or recovery, does.
        fn read(&self, addr: usize, buf: &mut [u8]) -> bool {
            let hidden = |a: &usize| self.execute_only && (CODE..BASE).contains(a);
            !(addr..addr + buf.len()).any(|a| hidden(&a)) && self.fetch(addr, buf)
        }

        /// Reads memory as instruction fetch does.
        fn fetch(&self, addr: usize, buf: &mut [u8]) -> bool {
            for (i, byte) in buf.iter_mut().enumerate() {
                let Some(&value) = self.mem.get(&(addr + i)) else {
                    return false;
                };
                *byte = value;
            }
            true
        }

        fn load(&self, addr: usize) -> usize {
            let mut bytes = [0; 8];
            assert!(self.read(addr, &mut bytes), "load from {addr:#x}");
            usize::from_le_bytes(bytes)
        }

        fn store(&mut self, addr: usize, value: usize) {
            for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
                *self
                    .mem
                    .get_mut(&(addr + i))
                    .expect("store to mapped memory") = byte;
            }
        }

        fn map(&mut self, addr: usize, bytes: &[u8]) {
            for (i, &byte) in bytes.iter().enumerate() {
                self.mem.insert(addr + i, byte);
            }
        }

        /// Executes `word` as the `len`-byte instruction at `pc`. Supports the
        /// instructions gates and test cases use; `ecall` is the fake syscall
        /// `a0 ^= a7`.
        fn exec(&mut self, word: u32, len: usize) {
            let rs1 = self.x[reg(word, RS1) as usize];
            let rs2 = self.x[reg(word, RS2) as usize];
            let i_imm = ((word.cast_signed() >> 20) as isize).cast_unsigned();
            let s_imm = (((word.cast_signed() >> 25) << 5) as isize).cast_unsigned()
                | reg(word, RD) as usize;
            let upper = ((word & 0xffff_f000).cast_signed() as isize).cast_unsigned();
            let mut next = self.pc + len;
            let value = match word & 0x7f {
                0x03 if word >> 12 & 7 == 3 => Some(self.load(rs1.wrapping_add(i_imm))),
                0x23 if word >> 12 & 7 == 3 => {
                    self.store(rs1.wrapping_add(s_imm), rs2);
                    None
                }
                0x13 if word & 0x7000 == 0 => Some(rs1.wrapping_add(i_imm)),
                0x33 if word & 0xfe00_7000 == 0 => Some(rs1.wrapping_add(rs2)),
                0x37 => Some(upper),
                0x17 => Some(self.pc.wrapping_add(upper)),
                0x6f => {
                    let offset = gate::jal_x0_offset(word & !0xf80).unwrap();
                    next = self.pc.wrapping_add_signed(offset as isize);
                    Some(self.pc + 4)
                }
                0x67 if word & 0x7000 == 0 => {
                    next = rs1.wrapping_add(i_imm) & !1;
                    Some(self.pc + 4)
                }
                0x73 if word == 0x73 => {
                    self.x[A0] ^= self.x[A7];
                    None
                }
                _ => panic!("unsupported instruction {word:#010x}"),
            };
            if let Some(value) = value
                && reg(word, RD) != 0
            {
                self.x[reg(word, RD) as usize] = value;
            }
            self.pc = next;
        }

        /// Executes the (rewritten) instruction at `pc`, or at the runtime's
        /// syscall entry, runs the syscall on the guest context and returns to
        /// the continuation in t0.
        fn step(&mut self) {
            if self.pc == ENTRY {
                self.x[A0] ^= self.x[A7];
                self.pc = self.x[T0];
                return;
            }
            let mut half = [0; 2];
            assert!(self.fetch(self.pc, &mut half));
            let half = u16::from_le_bytes(half);
            if half & 3 == 3 {
                let mut word = [0; 4];
                assert!(self.fetch(self.pc, &mut word));
                self.exec(u32::from_le_bytes(word), 4);
            } else {
                let offset = gate::compressed_jump_offset(half).expect("only c.j is rewritten");
                self.pc = self.pc.wrapping_add_signed(offset as isize);
            }
        }

        /// The guest context the physical state stands for when outside a gate.
        fn guest(&self) -> Self {
            let mut guest = self.clone();
            guest.x[3] = self.load(BLOCK);
            for addr in BLOCK..BLOCK + size_of::<super::super::GateTls>() {
                guest.mem.remove(&addr);
            }
            guest
        }

        /// Applies `recover` to the integer registers in `sc_regs` order.
        fn recover<R>(&self, recover: impl FnOnce(&mut [usize; 32]) -> R) -> (R, Self) {
            let mut regs = self.x;
            regs[0] = self.pc;
            let result = recover(&mut regs);
            let mut canonical = self.clone();
            canonical.pc = regs[0];
            canonical.x[1..].copy_from_slice(&regs[1..]);
            (result, canonical)
        }

        fn canonicalize(&self, interruption: GateInterruption) -> (GateSignalResult, Self) {
            self.recover(|regs| {
                canonicalize(regs, self.load(SPILL), interruption, |a, b| self.read(a, b))
            })
        }
    }

    /// Lays out every case's site at consecutive addresses and its gate in
    /// one trampoline, as the rewriter does. Returns the machine and each
    /// case's site and gate.
    fn rewrite(cases: &[Case]) -> (Machine, Vec<(usize, usize)>) {
        let mut code = Vec::new();
        let mut gates = Vec::new();
        let mut rewritten = Vec::new();
        for case in cases {
            let pc = CODE + code.len();
            let gate = BASE + gates.len();
            let mut site = case.bytes.clone();
            emit(&mut site, pc as u64, case.kind, BASE as u64, &mut gates).unwrap();
            code.extend_from_slice(&site);
            rewritten.push((pc, gate));
        }
        let mut m = Machine {
            pc: 0,
            x: core::array::from_fn(|i| if i == 0 { 0 } else { 0x0100_0000 + i * 0x1111 }),
            mem: BTreeMap::new(),
            execute_only: false,
        };
        m.map(CODE, &code);
        m.map(BASE, &gates);
        m.map(BLOCK, &[0; 24]);
        m.map(STACK, &[0x5a; 32]);
        m.map(DATA, &[0xa5; 32]);
        m.x[2] = STACK;
        m.x[3] = BLOCK;
        m.store(BLOCK, DATA);
        m.store(BLOCK + 16, ENTRY);
        (m, rewritten)
    }

    /// The guest context after the original instruction at `site` runs.
    fn reference(case: &Case, guest: &Machine) -> Machine {
        let mut m = guest.clone();
        m.exec(case.word, case.bytes.len());
        m
    }

    /// The guest context after resuming the context that `canonical`
    /// stands for, at the site with the original instruction, at the gate's
    /// start through the gate, or at `next`.
    fn resume(case: &Case, site: usize, next: usize, canonical: &Machine) -> Machine {
        if canonical.pc == site {
            return reference(case, &canonical.guest());
        }
        let mut m = canonical.clone();
        while m.pc != next {
            m.step();
        }
        m.guest()
    }

    /// Runs the rewritten site, checking the canonical context at every gate
    /// instruction and at the runtime's syscall entry: resuming it with the
    /// original instruction (at the site), the gate (at its start) or nothing
    /// (after it) must reach the same guest context as running the gate to
    /// completion. Execute-only guest code hides the sites from recovery.
    #[test]
    fn canonicalization_at_every_gate_instruction_resumes_equivalently() {
        let cases = cases();
        let (machine, rewritten) = rewrite(&cases);
        for execute_only in [false, true] {
            for (case, &(site, gate)) in cases.iter().zip(&rewritten) {
                let name = (case.name, execute_only);
                let next = site + case.bytes.len();
                let restart = if execute_only && !matches!(case.kind, GateKind::Ecall) {
                    gate
                } else {
                    site
                };
                let mut m = machine.clone();
                m.execute_only = execute_only;
                m.pc = site;
                let expected = reference(case, &m.guest());
                let mut visited = 0;
                while m.pc != next {
                    if m.pc == ENTRY {
                        let return_pc = syscall_return_pc(m.x[T0], |a, b| m.read(a, b));
                        assert_eq!(return_pc, Some(next), "{name:?}");
                        let ((), entered) = m.recover(|regs| {
                            canonicalize_syscall_entry(regs, m.load(SPILL), |a, b| m.read(a, b));
                        });
                        assert_eq!(entered.pc, site, "{name:?}");
                        assert_eq!(resume(case, site, next, &entered), expected, "{name:?}");
                    } else if m.pc >= BASE {
                        visited += 1;
                        let (result, canonical) = m.canonicalize(GateInterruption::Asynchronous);
                        assert_eq!(result, GateSignalResult::Canonicalized, "{name:?}");
                        if canonical.pc != next {
                            assert_eq!(canonical.pc, restart, "{name:?} at {:#x}", m.pc);
                        }
                        assert_eq!(
                            resume(case, site, next, &canonical),
                            expected,
                            "{name:?} interrupted at {:#x}",
                            m.pc
                        );

                        let mut word = [0; 4];
                        assert!(m.read(m.pc, &mut word));
                        let (result, synchronous) = m.canonicalize(GateInterruption::Synchronous);
                        if gate::accesses_gate_tls(u32::from_le_bytes(word)) {
                            assert_eq!(result, GateSignalResult::InvalidRuntimeState);
                            assert_eq!(synchronous, m, "{name:?}");
                        } else {
                            assert_eq!(synchronous, canonical, "{name:?}");
                        }
                    } else {
                        assert_eq!(m.pc, site, "{name:?}");
                        let (result, _) = m.canonicalize(GateInterruption::Asynchronous);
                        assert_eq!(result, GateSignalResult::NotGate, "{name:?}");
                    }
                    m.step();
                }
                assert_eq!(m.guest(), expected, "{name:?}");
                assert!(visited >= 5, "{name:?} visited {visited} gate instructions");
            }
        }
    }

    #[test]
    fn a_gate_whose_site_does_not_jump_to_it_restarts_at_its_start() {
        let cases = cases();
        let (mut m, rewritten) = rewrite(&cases[..2]);
        let interrupted = |m: &Machine, pc: usize| {
            let mut m = m.clone();
            m.pc = pc;
            let (result, canonical) = m.canonicalize(GateInterruption::Asynchronous);
            (result, canonical.pc)
        };
        for &(site, _) in &rewritten {
            m.map(site, &le(0x13)); // nop
        }
        let [(ecall_site, ecall_gate), (_, auipc_gate)] = rewritten[..] else {
            unreachable!()
        };
        // An `ecall` site needs no confirmation.
        assert_eq!(
            interrupted(&m, ecall_gate + 4),
            (GateSignalResult::Canonicalized, ecall_site)
        );
        assert_eq!(
            interrupted(&m, auipc_gate + 4),
            (GateSignalResult::Canonicalized, auipc_gate)
        );
        assert_eq!(interrupted(&m, auipc_gate + 2).0, GateSignalResult::NotGate);
    }

    #[test]
    fn a_syscall_entry_without_an_ecall_gate_resumes_at_the_continuation() {
        let cases = cases();
        let (mut m, rewritten) = rewrite(&cases[1..2]);
        // The `auipc gp` gate's reload.
        let continuation = rewritten[0].1 + 16;
        m.pc = ENTRY;
        m.x[T0] = continuation;
        m.store(SPILL, 0x7470);
        let ((), entered) = m.recover(|regs| {
            canonicalize_syscall_entry(regs, m.load(SPILL), |a, b| m.read(a, b));
        });
        assert_eq!((entered.pc, entered.x[T0]), (continuation, 0x7470));
    }

    /// Each gate ends its trampoline here, and reading past it would fault.
    #[test]
    fn a_final_gate_is_recovered_without_reading_past_it() {
        for case in cases() {
            let (m, rewritten) = rewrite(core::slice::from_ref(&case));
            let [(site, gate)] = rewritten[..] else {
                unreachable!()
            };
            // The trampoline is the last mapping below the block.
            let end = m.mem.range(..BLOCK).next_back().unwrap().0 + 1;
            let next = site + case.bytes.len();
            let reload = (end - gate) / 4 - 2;
            let mut past_end = false;
            let mut read = |addr: usize, buf: &mut [u8]| {
                past_end |= addr + buf.len() > end;
                m.read(addr, buf)
            };
            for index in 0..(end - gate) / 4 {
                let mut regs = m.x;
                regs[0] = gate + index * 4;
                let result = canonicalize(
                    &mut regs,
                    m.load(SPILL),
                    GateInterruption::Asynchronous,
                    &mut read,
                );
                assert_eq!(result, GateSignalResult::Canonicalized, "{}", case.name);
                let pc = if index < reload { site } else { next };
                assert_eq!(regs[0], pc, "{} at {index}", case.name);
            }
            if matches!(case.kind, GateKind::Ecall) {
                assert_eq!(syscall_return_pc(gate + reload * 4, &mut read), Some(next));
            }
            assert!(!past_end, "{}", case.name);
        }
    }

    #[test]
    fn an_ecall_site_must_be_four_bytes() {
        let mut gates = Vec::new();
        let result = emit(
            &mut [0; 2],
            CODE as u64,
            GateKind::Ecall,
            BASE as u64,
            &mut gates,
        );
        assert!(result.is_err() && gates.is_empty());
    }

    #[test]
    fn only_an_ecall_continuation_has_a_syscall_return_pc() {
        let cases = cases();
        let (m, rewritten) = rewrite(&cases[..2]);
        let read = |a: usize, b: &mut [u8]| m.read(a, b);
        assert_eq!(syscall_return_pc(BASE + 12, read), Some(rewritten[0].0 + 4));
        for pc in (BASE..BASE + 44).step_by(4).filter(|&pc| pc != BASE + 12) {
            assert_eq!(syscall_return_pc(pc, read), None, "{pc:#x}");
        }
    }
}

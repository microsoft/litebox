// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Ahead-of-time RV64 Linux rewriting for static, symbolized ELFs. Only scan
//! instruction ranges identified by RISC-V ELF mapping symbols. Refuse an
//! unsupported instruction or unreachable gate rather than leaving a native
//! syscall or a physical-gp access behind.
//! Register-selector hints stay in place. A cache-locality hint immediately
//! before a relocated access may therefore be ineffective, as on hardware
//! that implements the hint as a no-op.

use super::{Error, Result, TextSectionInfo, append_trampoline_footer, checked_add_u64};
use alloc::{format, vec::Vec};
use core::mem::offset_of;
use litebox_trampoline::riscv64::GateTls;
use object::{Object, ObjectSection, ObjectSymbol};

const GP: u32 = 3;
const T0: u32 = 5;
const RD: u32 = 7;
const RS1: u32 = 15;
const RS2: u32 = 20;
const fn tls_offset(offset: usize) -> u32 {
    assert!(offset < 2048);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "checked signed 12-bit offset"
    )]
    {
        offset as u32
    }
}
const GUEST_GP: u32 = tls_offset(offset_of!(GateTls, guest_gp));
const SPILL: u32 = tls_offset(offset_of!(GateTls, spill));
const ENTRY: u32 = tls_offset(offset_of!(GateTls, syscall_entry));

const fn ld(rd: u32, offset: u32) -> u32 {
    offset << 20 | GP << RS1 | 3 << 12 | rd << RD | 0x03
}

const fn sd(rs: u32, offset: u32) -> u32 {
    (offset >> 5) << 25 | rs << RS2 | GP << RS1 | 3 << 12 | (offset & 31) << RD | 0x23
}

const fn reg(insn: u32, shift: u32) -> u32 {
    (insn >> shift) & 31
}

fn unsupported(pc: u64, reason: &str) -> Error {
    Error::UnsupportedExecutable(format!("RV64 at {pc:#x}: {reason}"))
}

/// Signed even byte displacement for a JAL or C.J.
fn displacement(pc: u64, target: u64, bits: u32) -> Result<u32> {
    let delta = i128::from(target) - i128::from(pc);
    let limit = 1 << (bits - 1);
    if delta & 1 != 0 || !(-limit..limit).contains(&delta) {
        return Err(unsupported(pc, "trampoline branch out of range"));
    }
    Ok(i32::try_from(delta).unwrap().cast_unsigned())
}

fn jal(pc: u64, target: u64) -> Result<u32> {
    let d = displacement(pc, target, 21)?;
    Ok(((d >> 20) & 1) << 31 | (d & 0x7fe) << 20 | (d & 0x800) << 9 | d & 0xff000 | 0x6f)
}

fn compressed_jump(pc: u64, target: u64) -> Result<u16> {
    let d = displacement(pc, target, 12)?;
    let bits = ((d >> 11) & 1) << 12
        | ((d >> 4) & 1) << 11
        | ((d >> 8) & 3) << 9
        | ((d >> 10) & 1) << 8
        | ((d >> 6) & 1) << 7
        | ((d >> 7) & 1) << 6
        | ((d >> 1) & 7) << 3
        | ((d >> 5) & 1) << 2;
    Ok(0xa001 | u16::try_from(bits).unwrap())
}

enum Site {
    Native,
    Ecall,
    /// Execute at the gate after substituting only actual integer gp operands.
    Gp {
        word: u32,
        fields: &'static [u32],
    },
    AuipcGp(u32),
}

fn operands(word: u32, fields: &'static [u32]) -> Site {
    if fields.iter().any(|&field| reg(word, field) == GP) {
        Site::Gp { word, fields }
    } else {
        Site::Native
    }
}

fn word_site(word: u32, pc: u64) -> Result<Site> {
    let opcode = word & 0x7f;
    let site = match opcode {
        0x73 if word == 0x73 => Site::Ecall,
        0x73 if word == 0x0010_0073 => Site::Native, // ebreak
        0x03 | 0x13 | 0x1b => operands(word, &[RD, RS1]),
        0x23 => operands(word, &[RS1, RS2]),
        // ADD x0,x0,rs2 encodes hints such as NTL.PALL, not a read of gp.
        0x33 if word & !(31 << RS2) == 0x33 => Site::Native,
        0x33 | 0x3b => operands(word, &[RD, RS1, RS2]),
        0x37 => operands(word, &[RD]),
        0x17 if reg(word, RD) == GP => Site::AuipcGp(word & 0xffff_f000),
        0x17 => Site::Native,
        0x63 | 0x67 | 0x6f => {
            let fields: &[u32] = match opcode {
                0x63 => &[RS1, RS2],
                0x67 => &[RD, RS1],
                _ => &[RD],
            };
            if fields.iter().any(|&field| reg(word, field) == GP) {
                return Err(unsupported(pc, "control transfer using gp"));
            }
            Site::Native
        }
        0x0f if reg(word, RD) == 0 && reg(word, RS1) == 0 => Site::Native,
        // A spill in an otherwise valid LR/SC sequence could prevent progress.
        // Do not admit such images until the rewriter tracks reservations.
        _ => {
            return Err(unsupported(
                pc,
                &format!("unsupported instruction {word:#010x}"),
            ));
        }
    };
    Ok(site)
}

fn compressed_site(half: u16, pc: u64) -> Result<Site> {
    let h = u32::from(half);
    let rd = reg(h, RD);
    let rs = reg(h, 2);
    let group = (h & 3, h >> 13);
    // Prime-register forms use only x8..x15 (plus implicit sp/x0).
    match group {
        (0, 0..=3 | 5..=7) | (1, 4..=7) | (2, 1 | 5) => return Ok(Site::Native),
        (1, 0..=3) | (2, 0 | 2 | 3) if rd != GP => return Ok(Site::Native),
        (2, 6 | 7) if rs != GP => return Ok(Site::Native),
        (2, 4) if rd == 0 && rs != 0 => return Ok(Site::Native), // C.MV/C.ADD hints
        (2, 4) if rd != GP && rs != GP => return Ok(Site::Native),
        _ => (),
    }
    let imm6 = (h >> 12 & 1) << 5 | (h >> 2 & 31);
    let imm12 = if imm6 & 32 == 0 { imm6 } else { imm6 | 0xfc0 };
    let word = match group {
        (1, 0) => imm12 << 20 | rd << RS1 | rd << RD | 0x13, // c.addi
        (1, 1) => imm12 << 20 | rd << RS1 | rd << RD | 0x1b, // c.addiw
        (1, 2) => imm12 << 20 | rd << RD | 0x13,             // c.li
        // c.lui: sign-extend the six-bit upper immediate. Zero is reserved.
        (1, 3) if imm6 != 0 => ((imm12 << 20).cast_signed() >> 8).cast_unsigned() | rd << RD | 0x37,
        (2, 0) => imm6 << 20 | rd << RS1 | 1 << 12 | rd << RD | 0x13, // c.slli
        (2, 4) if rs != 0 => {
            // c.mv / c.add
            let lhs = if h & (1 << 12) == 0 { 0 } else { rd };
            rs << RS2 | lhs << RS1 | rd << RD | 0x33
        }
        _ => {
            return Err(unsupported(
                pc,
                &format!("unsupported compressed instruction {half:#06x}"),
            ));
        }
    };
    word_site(word, pc)
}

fn emit_site(bytes: &mut [u8], pc: u64, site: Site, base: u64, gates: &mut Vec<u8>) -> Result<()> {
    let start = checked_add_u64(base, gates.len() as u64, "RV64 gate")?;
    let mut emit = |word: u32| gates.extend_from_slice(&word.to_le_bytes());
    match site {
        Site::Native => return Ok(()),
        Site::Ecall => {
            emit(sd(T0, SPILL));
            emit(ld(T0, ENTRY));
            // jalr t0,0(t0): t0 links to the reload, preserving guest ra.
            emit(T0 << RS1 | T0 << RD | 0x67);
            emit(ld(T0, SPILL));
        }
        Site::AuipcGp(upper) => {
            emit(sd(T0, SPILL));
            let delta = i128::from(pc) + i128::from(upper.cast_signed()) - (i128::from(start) + 4);
            let hi = i32::try_from((delta + 0x800) >> 12)
                .ok()
                .filter(|n| (-0x80000..0x80000).contains(n))
                .ok_or_else(|| unsupported(pc, "relocated auipc out of range"))?;
            let lo = u32::try_from(delta & 0xfff).unwrap();
            emit(hi.cast_unsigned() << 12 | T0 << RD | 0x17);
            emit(lo << 20 | T0 << RS1 | T0 << RD | 0x13);
            emit(sd(T0, GUEST_GP));
            emit(ld(T0, SPILL));
        }
        Site::Gp { mut word, fields } => {
            // Never borrow a real source or destination; e.g., sd t0,8(gp)
            // must still store the guest t0. At most three registers are used.
            let tmp = [5, 6, 7, 28]
                .into_iter()
                .find(|&r| fields.iter().all(|&f| reg(word, f) != r))
                .unwrap();
            emit(sd(tmp, SPILL));
            let mut writes_gp = false;
            if fields.iter().any(|&f| f != RD && reg(word, f) == GP) {
                emit(ld(tmp, GUEST_GP));
            }
            for &f in fields {
                if reg(word, f) == GP {
                    writes_gp |= f == RD;
                    word = (word & !(31 << f)) | tmp << f;
                }
            }
            emit(word);
            if writes_gp {
                emit(sd(tmp, GUEST_GP));
            }
            emit(ld(tmp, SPILL));
        }
    }
    let next = checked_add_u64(pc, bytes.len() as u64, "RV64 resume PC")?;
    let at = checked_add_u64(base, gates.len() as u64, "RV64 return jump")?;
    gates.extend_from_slice(&jal(at, next)?.to_le_bytes());
    if bytes.len() == 2 {
        bytes.copy_from_slice(&compressed_jump(pc, start)?.to_le_bytes());
    } else {
        bytes.copy_from_slice(&jal(pc, start)?.to_le_bytes());
    }
    Ok(())
}

fn rewrite_range(mut bytes: &mut [u8], mut pc: u64, base: u64, gates: &mut Vec<u8>) -> Result<()> {
    if pc & 1 != 0 {
        return Err(unsupported(pc, "unaligned code range"));
    }
    while !bytes.is_empty() {
        let half = u16::from_le_bytes(
            *bytes
                .first_chunk()
                .ok_or_else(|| unsupported(pc, "truncated instruction"))?,
        );
        let (width, site) = if half & 3 == 3 {
            let word = u32::from_le_bytes(
                *bytes
                    .first_chunk()
                    .ok_or_else(|| unsupported(pc, "truncated instruction"))?,
            );
            (4, word_site(word, pc)?)
        } else {
            (2, compressed_site(half, pc)?)
        };
        let (instruction, tail) = bytes.split_at_mut(width);
        emit_site(instruction, pc, site, base, gates)?;
        pc = checked_add_u64(pc, width as u64, "RV64 code PC")?;
        bytes = tail;
    }
    Ok(())
}

/// Respect `$d` regions (literal pools); without `$x` we cannot establish
/// instruction boundaries, particularly for C instructions.
pub(super) fn code_ranges(file: &object::File<'_>) -> Result<Vec<TextSectionInfo>> {
    let object::File::Elf64(elf) = file else {
        unreachable!()
    };
    if file.kind() != object::ObjectKind::Executable
        || elf.elf_program_headers().iter().any(|s| {
            matches!(
                s.p_type.get(elf.endian()),
                object::elf::PT_INTERP | object::elf::PT_DYNAMIC
            )
        })
    {
        return Err(Error::UnsupportedExecutable(
            "RV64 bring-up requires a static ET_EXEC".into(),
        ));
    }
    let mut ranges = Vec::new();
    for section in file.sections() {
        let object::SectionFlags::Elf { sh_flags } = section.flags() else {
            continue;
        };
        let flags = u64::from(object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR);
        if sh_flags & flags != flags || section.size() == 0 {
            continue;
        }
        let (offset, size) = section
            .file_range()
            .ok_or_else(|| unsupported(section.address(), "missing section bytes"))?;
        let end = checked_add_u64(section.address(), size, "RV64 section end")?;
        let mut marks = Vec::new();
        for symbol in file
            .symbols()
            .filter(|s| s.section_index() == Some(section.index()))
        {
            let Ok(name) = symbol.name() else { continue };
            let stem = name.split('.').next().unwrap_or(name);
            let code = match stem {
                "$d" => false,
                "$x" => true,
                x if x.starts_with("$xrv64") => true,
                _ => continue,
            };
            marks.push((symbol.address(), code));
        }
        marks.sort_unstable();
        marks.dedup();
        if marks.first().map(|m| m.0) != Some(section.address()) {
            return Err(unsupported(
                section.address(),
                "missing initial RISC-V ELF mapping symbol",
            ));
        }
        marks.push((end, false));
        for pair in marks.windows(2) {
            let [(from, code), (to, _)] = *pair else {
                unreachable!()
            };
            if from >= to || to > end {
                return Err(unsupported(from, "invalid mapping symbols"));
            }
            if code {
                ranges.push(TextSectionInfo {
                    file_offset: checked_add_u64(
                        offset,
                        from - section.address(),
                        "RV64 code file offset",
                    )?,
                    vaddr: from,
                    size: to - from,
                });
            }
        }
    }
    if ranges.is_empty() {
        return Err(Error::UnsupportedExecutable(
            "missing RV64 code sections".into(),
        ));
    }
    Ok(ranges)
}

pub(super) fn rewrite_elf(
    input_binary: &[u8],
    buf: &mut [u8],
    ranges: &[TextSectionInfo],
    base: u64,
) -> Result<Vec<u8>> {
    let mut gates = Vec::new();
    for range in ranges {
        rewrite_range(
            super::section_slice_mut(buf, range)?,
            range.vaddr,
            base,
            &mut gates,
        )?;
    }
    if gates.is_empty() {
        return Ok(super::elf_with_empty_footer(input_binary));
    }
    let mut out = buf.to_vec();
    append_trampoline_footer(&mut out, &mut gates, base, false);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_temporal_hints_preserve_the_encoded_register_selector() {
        let hints = [0x33, 0x00, 0x30, 0x00, 0x0e, 0x90]; // ntl.pall; c.ntl.pall
        let mut code = hints;
        let mut gates = Vec::new();
        rewrite_range(&mut code, 0, 0x10_0000, &mut gates).unwrap();
        assert_eq!(code, hints);
        assert_eq!(gates, [] as [u8; 0]);
    }

    #[test]
    fn narrow_site_cannot_overwrite_the_next_instruction_to_reach_a_gate() {
        let mut code = [0x0e, 0x85, 0x82, 0x80]; // c.mv a0,gp; ret
        assert!(rewrite_range(&mut code, 0x1000, 0x1800, &mut Vec::new()).is_err());
        assert_eq!(code, [0x0e, 0x85, 0x82, 0x80]);
        assert!(rewrite_range(&mut code, 0x1000, 0x17fe, &mut Vec::new()).is_ok());
        assert_eq!(code[2..], [0x82, 0x80]);
    }

    #[test]
    fn rejects_truncated_code_and_unsupported_gp_control_transfers() {
        for bytes in [&[0x73, 0x00][..], &[0x82, 0x81], &[0xe7, 0x80, 0x01, 0x00]] {
            assert!(rewrite_range(&mut bytes.to_vec(), 0x1000, 0x1100, &mut Vec::new()).is_err());
        }
    }
}

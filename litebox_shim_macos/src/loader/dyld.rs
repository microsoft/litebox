// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boot-local patches for the standalone dyld used with the host shared cache.
//!
//! These signatures are intentionally fail-closed. A macOS update that changes
//! the relevant code produces `MachoLoaderError::Rewrite` instead of silently
//! executing a partially compatible dyld.

use crate::MachoLoaderError;
use alloc::{format, vec::Vec};
use litebox::utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _};

const AARCH64_NOP: u32 = 0xd503_201f;
const AARCH64_RET: u32 = 0xd65f_03c0;
const AARCH64_BL_OPCODE: u32 = 0b100101;
const AARCH64_BRANCH_IMMEDIATE_MASK: u32 = 0x03ff_ffff;

pub(super) fn patch(data: &mut [u8]) -> Result<(), MachoLoaderError> {
    disable_restart_into_cached_dyld(data)?;
    suppress_shared_cache_initializers(data)?;
    redirect_process_exit(data)?;
    Ok(())
}

/// `restartWithDyldInCache` normally switches SP and branches into cached dyld.
/// The cache belongs to this process's host runtime, so the guest must continue
/// in its fresh standalone dyld mapping instead.
fn disable_restart_into_cached_dyld(data: &mut [u8]) -> Result<(), MachoLoaderError> {
    const MOV_SP_X0: u32 = 0x9100_001f;
    const BR_X3: u32 = 0xd61f_0060;

    for offset in instruction_offsets(data.len(), 2) {
        if word(data, offset) == MOV_SP_X0 && word(data, offset + 4) == BR_X3 {
            write_word(data, offset, AARCH64_RET);
            write_word(data, offset + 4, AARCH64_NOP);
            return Ok(());
        }
    }
    Err(signature_failure(
        data,
        "disable_restart_into_cached_dyld",
        &[Some(MOV_SP_X0), Some(BR_X3)],
    ))
}

/// Host cache initializers have already run and are not safe to run again in
/// the forked guest runner. Keep dyld's state bookkeeping but skip the call to
/// `findAndRunAllInitializers`.
fn suppress_shared_cache_initializers(data: &mut [u8]) -> Result<(), MachoLoaderError> {
    const PREFIX: [u32; 4] = [0x7940_5808, 0x3600_0088, 0xaa14_03e0, 0xaa13_03e1];

    for offset in instruction_offsets(data.len(), 5) {
        let prefix_matches = PREFIX
            .iter()
            .enumerate()
            .all(|(index, expected)| word(data, offset + index * 4) == *expected);
        if prefix_matches && is_bl(word(data, offset + 16)) {
            write_word(data, offset + 16, AARCH64_NOP);
            return Ok(());
        }
    }
    Err(signature_failure(
        data,
        "suppress_shared_cache_initializers",
        &[
            Some(PREFIX[0]),
            Some(PREFIX[1]),
            Some(PREFIX[2]),
            Some(PREFIX[3]),
            None,
        ],
    ))
}

/// Redirect dyld's non-simulator `LibSystemHelpers::exit` call to dyld's own
/// rewritten `___exit` stub. This terminates the guest task through the shim
/// instead of terminating the host runner from an unrewritten cache function.
fn redirect_process_exit(data: &mut [u8]) -> Result<(), MachoLoaderError> {
    const CBZ_W0_PLUS_12: u32 = 0x3400_0060;
    const MOV_X0_X19: u32 = 0xaa13_03e0;
    const LDR_X8_SP_464: u32 = 0xf940_ebe8;
    const ADD_X0_X8_160: u32 = 0x9102_8100;
    const MOV_X1_X19: u32 = 0xaa13_03e1;

    for offset in instruction_offsets(data.len(), 7) {
        let simulator_exit = word(data, offset + 8);
        let helper_exit = word(data, offset + 24);
        if word(data, offset) == CBZ_W0_PLUS_12
            && word(data, offset + 4) == MOV_X0_X19
            && is_bl(simulator_exit)
            && word(data, offset + 12) == LDR_X8_SP_464
            && word(data, offset + 16) == ADD_X0_X8_160
            && word(data, offset + 20) == MOV_X1_X19
            && is_bl(helper_exit)
        {
            let immediate = sign_extend_branch(simulator_exit & AARCH64_BRANCH_IMMEDIATE_MASK);
            let redirected = (AARCH64_BL_OPCODE << 26)
                | ((immediate - 4).reinterpret_as_unsigned() & AARCH64_BRANCH_IMMEDIATE_MASK);
            write_word(data, offset + 12, MOV_X0_X19);
            write_word(data, offset + 16, AARCH64_NOP);
            write_word(data, offset + 20, AARCH64_NOP);
            write_word(data, offset + 24, redirected);
            return Ok(());
        }
    }
    Err(signature_failure(
        data,
        "redirect_process_exit",
        &[
            Some(CBZ_W0_PLUS_12),
            Some(MOV_X0_X19),
            None,
            Some(LDR_X8_SP_464),
            Some(ADD_X0_X8_160),
            Some(MOV_X1_X19),
            None,
        ],
    ))
}

fn signature_failure(data: &[u8], name: &str, signature: &[Option<u32>]) -> MachoLoaderError {
    let mut candidates: Vec<_> = instruction_offsets(data.len(), signature.len())
        .map(|offset| {
            let score = signature
                .iter()
                .enumerate()
                .filter(|(index, expected)| {
                    expected.is_some_and(|expected| word(data, offset + index * 4) == expected)
                })
                .count();
            (score, offset)
        })
        .collect();
    candidates.sort_unstable_by_key(|&(score, offset)| (core::cmp::Reverse(score), offset));
    candidates.truncate(8);

    let candidates = candidates
        .into_iter()
        .map(|(score, offset)| {
            let words = (0..signature.len())
                .map(|index| {
                    let instruction = word(data, offset + index * 4);
                    if is_bl(instruction) {
                        format!("{instruction:08x}(bl)")
                    } else {
                        format!("{instruction:08x}")
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!("offset=0x{offset:x} score={score}: {words}")
        })
        .collect::<Vec<_>>()
        .join("; ");
    MachoLoaderError::RewriteDiagnostic(format!(
        "{name} signature not found (image_bytes={}, exact_words={}): {candidates}",
        data.len(),
        signature.iter().flatten().count()
    ))
}

fn instruction_offsets(data_len: usize, words: usize) -> impl Iterator<Item = usize> {
    let bytes = words * size_of::<u32>();
    (0..=data_len.saturating_sub(bytes)).step_by(size_of::<u32>())
}

fn word(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("bounded signature"),
    )
}

fn write_word(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn is_bl(instruction: u32) -> bool {
    instruction >> 26 == AARCH64_BL_OPCODE
}

fn sign_extend_branch(immediate: u32) -> i32 {
    let immediate = immediate.reinterpret_as_signed();
    if immediate & (1 << 25) != 0 {
        immediate | !AARCH64_BRANCH_IMMEDIATE_MASK.reinterpret_as_signed()
    } else {
        immediate
    }
}

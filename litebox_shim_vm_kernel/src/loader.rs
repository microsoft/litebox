// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner image requirements: static-PIE x86-64 `ET_DYN` linked at 0, loaded
//! at `layout::RUNNER_IMAGE`'s start; `PT_LOAD` segments within that area,
//! not sharing pages, never writable and executable; relocations only
//! `R_X86_64_RELATIVE` in `DT_RELA`, which the kernel applies before setting
//! the segments' permissions; a nonempty [`GATE_SECTION`] inside an
//! executable segment.

use crate::layout::RUNNER_IMAGE;
use crate::memory::{Mappings, checked_range, copy_to_user};
use alloc::vec::Vec;
use core::ops::Range;
use elf::ElfBytes;
use elf::abi::{
    DT_JMPREL, DT_NEEDED, DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, EM_X86_64, ET_DYN, PF_R, PF_W,
    PF_X, PT_INTERP, PT_LOAD, R_X86_64_NONE, R_X86_64_RELATIVE,
};
use elf::endian::LittleEndian;
use litebox_common_vm_abi::{GATE_SECTION, PAGE_SIZE, Placement, Populate, Prot};

#[derive(Debug)]
pub enum LoadError {
    Parse(elf::ParseError),
    NotStaticPieX86_64,
    BadSegment,
    WritableAndExecutable,
    BadRelocation,
    NoGate,
    Map(litebox_common_vm_abi::Status),
}

pub(crate) struct LoadedRunner {
    pub(crate) entry: u64,
    /// Only `syscall`s here are kernel calls.
    pub(crate) gate: Range<u64>,
}

const BASE: u64 = RUNNER_IMAGE.start;

/// `Elf64_Rela`.
const RELA_SIZE: u64 = 24;

fn segment_prot(flags: u32) -> Result<Prot, LoadError> {
    let prot = Prot::from_rwx(flags & PF_R != 0, flags & PF_W != 0, flags & PF_X != 0);
    if prot.write() && prot.exec() {
        return Err(LoadError::WritableAndExecutable);
    }
    Ok(prot)
}

struct Segment {
    /// Link-time addresses.
    vaddr: Range<u64>,
    file_offset: u64,
    file_len: u64,
    pages: Range<usize>,
    prot: Prot,
}

/// Into the current address space.
pub(crate) fn load(image: &[u8], mappings: &Mappings) -> Result<LoadedRunner, LoadError> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(image).map_err(LoadError::Parse)?;
    if file.ehdr.e_type != ET_DYN || file.ehdr.e_machine != EM_X86_64 {
        return Err(LoadError::NotStaticPieX86_64);
    }
    let phdrs = file.segments().ok_or(LoadError::NotStaticPieX86_64)?;
    if phdrs.iter().any(|p| p.p_type == PT_INTERP) {
        return Err(LoadError::NotStaticPieX86_64);
    }
    let mut segments = Vec::new();
    for phdr in phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        if phdr.p_filesz > phdr.p_memsz {
            return Err(LoadError::BadSegment);
        }
        let end = phdr
            .p_vaddr
            .checked_add(phdr.p_memsz)
            .ok_or(LoadError::BadSegment)?;
        let start = BASE
            .checked_add(phdr.p_vaddr & !(PAGE_SIZE - 1))
            .ok_or(LoadError::BadSegment)?;
        let page_end = BASE
            .checked_add(end)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(LoadError::BadSegment)?;
        let pages = checked_range(
            start,
            page_end - start,
            RUNNER_IMAGE.start..RUNNER_IMAGE.end(),
        )
        .map_err(|_| LoadError::BadSegment)?;
        segments.push(Segment {
            vaddr: phdr.p_vaddr..end,
            file_offset: phdr.p_offset,
            file_len: phdr.p_filesz,
            pages,
            prot: segment_prot(phdr.p_flags)?,
        });
    }

    // Writable until relocated.
    for segment in &segments {
        let data = usize::try_from(segment.file_offset)
            .ok()
            .zip(usize::try_from(segment.file_len).ok())
            .and_then(|(offset, len)| image.get(offset..offset.checked_add(len)?))
            .ok_or(LoadError::BadSegment)?;
        mappings
            .map(
                segment.pages.clone(),
                Prot::ReadWrite,
                Placement::NoReplace,
                Populate::Now,
            )
            .map_err(|status| match status {
                litebox_common_vm_abi::Status::Exists => LoadError::BadSegment,
                status => LoadError::Map(status),
            })?;
        copy_to_user(BASE + segment.vaddr.start, data).map_err(LoadError::Map)?;
    }
    relocate(&file, image, &segments)?;
    for segment in &segments {
        mappings
            .protect(segment.pages.clone(), segment.prot)
            .map_err(LoadError::Map)?;
    }

    let (sections, strtab) = file
        .section_headers_with_strtab()
        .map_err(LoadError::Parse)?;
    let gate = sections
        .zip(strtab)
        .and_then(|(sections, strtab)| {
            sections.iter().find(|s| {
                strtab
                    .get(s.sh_name as usize)
                    .is_ok_and(|name| name == GATE_SECTION)
            })
        })
        .map(|s| s.sh_addr..s.sh_addr.saturating_add(s.sh_size))
        .filter(|gate| {
            !gate.is_empty()
                && segments.iter().any(|seg| {
                    seg.prot.exec() && seg.vaddr.start <= gate.start && gate.end <= seg.vaddr.end
                })
        })
        .ok_or(LoadError::NoGate)?;
    Ok(LoadedRunner {
        entry: BASE
            .checked_add(file.ehdr.e_entry)
            .ok_or(LoadError::NotStaticPieX86_64)?,
        gate: BASE + gate.start..BASE + gate.end,
    })
}

/// Applies `DT_RELA`, read from the file, to the loaded segments.
fn relocate(
    file: &ElfBytes<'_, LittleEndian>,
    image: &[u8],
    segments: &[Segment],
) -> Result<(), LoadError> {
    let Some(dynamic) = file.dynamic().map_err(LoadError::Parse)? else {
        return Ok(());
    };
    let (mut rela, mut rela_len, mut rela_entry) = (None, 0, RELA_SIZE);
    for entry in dynamic.iter() {
        match entry.d_tag {
            DT_RELA => rela = Some(entry.d_ptr()),
            DT_RELASZ => rela_len = entry.d_val(),
            DT_RELAENT => rela_entry = entry.d_val(),
            DT_REL | DT_JMPREL | DT_NEEDED => return Err(LoadError::BadRelocation),
            _ => {}
        }
    }
    let Some(rela) = rela else {
        return Ok(());
    };
    if rela_entry != RELA_SIZE || !rela_len.is_multiple_of(RELA_SIZE) {
        return Err(LoadError::BadRelocation);
    }
    // The table's file bytes, through the segment that loads it.
    let table = segments
        .iter()
        .find(|seg| {
            seg.vaddr.start <= rela
                && rela
                    .checked_add(rela_len)
                    .is_some_and(|end| end <= seg.vaddr.start + seg.file_len)
        })
        .and_then(|seg| {
            let offset = usize::try_from(seg.file_offset + (rela - seg.vaddr.start)).ok()?;
            image.get(offset..offset.checked_add(usize::try_from(rela_len).ok()?)?)
        })
        .ok_or(LoadError::BadRelocation)?;
    for entry in table.as_chunks::<24>().0 {
        let field = |i: usize| u64::from_le_bytes(entry[i * 8..i * 8 + 8].try_into().unwrap());
        let (offset, info, addend) = (field(0), field(1), field(2));
        #[allow(clippy::cast_possible_truncation)] // ELF64_R_TYPE
        match info as u32 {
            R_X86_64_NONE => {}
            R_X86_64_RELATIVE => {
                let in_segment = segments.iter().any(|seg| {
                    seg.vaddr.start <= offset
                        && offset
                            .checked_add(8)
                            .is_some_and(|end| end <= seg.vaddr.end)
                });
                if !in_segment {
                    return Err(LoadError::BadRelocation);
                }
                #[allow(clippy::cast_possible_wrap)] // r_addend is signed
                let value = BASE
                    .checked_add_signed(addend as i64)
                    .ok_or(LoadError::BadRelocation)?;
                copy_to_user(BASE + offset, &value.to_le_bytes()).map_err(LoadError::Map)?;
            }
            _ => return Err(LoadError::BadRelocation),
        }
    }
    Ok(())
}

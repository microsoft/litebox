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
    PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_INTERP, PT_LOAD, R_X86_64_NONE, R_X86_64_RELATIVE,
};
use elf::dynamic::DynamicTable;
use elf::endian::LittleEndian;
use elf::relocation::RelaIterator;
use litebox_common_vm_abi::{GATE_SECTION, PAGE_SIZE, Placement, Populate, Prot};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("malformed ELF: {0}")]
    Parse(elf::ParseError),
    #[error("not an x86-64 static PIE")]
    NotStaticPieX86_64,
    #[error("bad loadable segment")]
    BadSegment,
    #[error("writable and executable segment")]
    WritableAndExecutable,
    #[error("unsupported relocation")]
    BadRelocation,
    #[error("no kernel-call gate section")]
    NoGate,
    #[error("entry point outside the executable segments")]
    BadEntry,
    #[error("mapping failed: {0:?}")]
    Map(litebox_common_vm_abi::Status),
}

pub(crate) struct LoadedRunner {
    /// In [`Self::executable`].
    pub(crate) entry: u64,
    /// Only `syscall`s here are kernel calls.
    pub(crate) gate: Range<u64>,
    /// The executable segments, which the runner cannot remap or reprotect.
    pub(crate) executable: Vec<Range<u64>>,
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

struct Segment<'a> {
    /// Link-time addresses.
    vaddr: Range<u64>,
    data: &'a [u8],
    pages: Range<usize>,
    prot: Prot,
}

/// What [`load`] does, decided from the image alone.
struct Plan<'a> {
    segments: Vec<Segment<'a>>,
    /// Link-time address and value of each 8-byte relocation write.
    relocations: Vec<(u64, u64)>,
    /// Read-only once relocated.
    relro: Vec<Range<usize>>,
    runner: LoadedRunner,
}

/// Into the current address space.
pub(crate) fn load(image: &[u8], mappings: &Mappings) -> Result<LoadedRunner, LoadError> {
    let plan = plan(image)?;
    // Writable until relocated.
    for segment in &plan.segments {
        mappings
            .map(
                segment.pages.clone(),
                Prot::ReadWrite,
                Placement::NoReplace,
                Populate::Now,
            )
            .map_err(LoadError::Map)?;
        copy_to_user(BASE + segment.vaddr.start, segment.data).map_err(LoadError::Map)?;
    }
    for &(offset, value) in &plan.relocations {
        copy_to_user(BASE + offset, &value.to_le_bytes()).map_err(LoadError::Map)?;
    }
    for segment in &plan.segments {
        mappings
            .protect(segment.pages.clone(), segment.prot)
            .map_err(LoadError::Map)?;
    }
    for pages in plan.relro {
        mappings
            .protect(pages, Prot::Read)
            .map_err(LoadError::Map)?;
    }
    Ok(plan.runner)
}

fn plan(image: &[u8]) -> Result<Plan<'_>, LoadError> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(image).map_err(LoadError::Parse)?;
    if file.ehdr.e_type != ET_DYN || file.ehdr.e_machine != EM_X86_64 {
        return Err(LoadError::NotStaticPieX86_64);
    }
    let phdrs = file.segments().ok_or(LoadError::NotStaticPieX86_64)?;
    if phdrs.iter().any(|p| p.p_type == PT_INTERP) {
        return Err(LoadError::NotStaticPieX86_64);
    }
    let mut segments: Vec<Segment<'_>> = Vec::new();
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
        if segments
            .iter()
            .any(|seg| seg.pages.start < pages.end && pages.start < seg.pages.end)
        {
            return Err(LoadError::BadSegment);
        }
        let data = usize::try_from(phdr.p_offset)
            .ok()
            .zip(usize::try_from(phdr.p_filesz).ok())
            .and_then(|(offset, len)| image.get(offset..offset.checked_add(len)?))
            .ok_or(LoadError::BadSegment)?;
        segments.push(Segment {
            vaddr: phdr.p_vaddr..end,
            data,
            pages,
            prot: segment_prot(phdr.p_flags)?,
        });
    }
    let relocations = relocations(&file, image, &segments)?;

    // From a page boundary through the end's page, within one writable
    // segment.
    let mut relro = Vec::new();
    for phdr in phdrs.iter().filter(|p| p.p_type == PT_GNU_RELRO) {
        let start = phdr.p_vaddr;
        let end = start
            .checked_add(phdr.p_memsz)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .filter(|_| start.is_multiple_of(PAGE_SIZE))
            .ok_or(LoadError::BadSegment)?;
        let in_writable = segments.iter().any(|seg| {
            seg.prot.write()
                && seg.vaddr.start <= start
                && seg.vaddr.end.next_multiple_of(PAGE_SIZE) >= end
        });
        if !in_writable {
            return Err(LoadError::BadSegment);
        }
        relro.push(
            checked_range(
                BASE + start,
                end - start,
                RUNNER_IMAGE.start..RUNNER_IMAGE.end(),
            )
            .map_err(|_| LoadError::BadSegment)?,
        );
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
    let executable: Vec<Range<u64>> = segments
        .iter()
        .filter(|seg| seg.prot.exec())
        .map(|seg| BASE + seg.vaddr.start..BASE + seg.vaddr.end)
        .collect();
    let entry = BASE
        .checked_add(file.ehdr.e_entry)
        .filter(|entry| executable.iter().any(|seg| seg.contains(entry)))
        .ok_or(LoadError::BadEntry)?;
    Ok(Plan {
        segments,
        relocations,
        relro,
        runner: LoadedRunner {
            entry,
            gate: BASE + gate.start..BASE + gate.end,
            executable,
        },
    })
}

/// `DT_RELA`, read from the file through `PT_DYNAMIC`, as program loaders do
/// (section headers are not consulted).
fn relocations(
    file: &ElfBytes<'_, LittleEndian>,
    image: &[u8],
    segments: &[Segment<'_>],
) -> Result<Vec<(u64, u64)>, LoadError> {
    let Some(phdr) = file
        .segments()
        .and_then(|phdrs| phdrs.iter().find(|p| p.p_type == PT_DYNAMIC))
    else {
        return Ok(Vec::new());
    };
    let table = usize::try_from(phdr.p_offset)
        .ok()
        .zip(usize::try_from(phdr.p_filesz).ok())
        .and_then(|(offset, len)| image.get(offset..offset.checked_add(len)?))
        .ok_or(LoadError::BadRelocation)?;
    let dynamic = DynamicTable::new(LittleEndian, file.ehdr.class, table);
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
        return Ok(Vec::new());
    };
    if rela_entry != RELA_SIZE || !rela_len.is_multiple_of(RELA_SIZE) {
        return Err(LoadError::BadRelocation);
    }
    // The table's file bytes, through the segment that loads it.
    let table = segments
        .iter()
        .find_map(|seg| {
            let start = usize::try_from(rela.checked_sub(seg.vaddr.start)?).ok()?;
            seg.data
                .get(start..start.checked_add(usize::try_from(rela_len).ok()?)?)
        })
        .ok_or(LoadError::BadRelocation)?;
    let mut writes = Vec::new();
    for rela in RelaIterator::new(LittleEndian, file.ehdr.class, table) {
        match rela.r_type {
            R_X86_64_NONE => {}
            R_X86_64_RELATIVE => {
                let offset = rela.r_offset;
                let in_segment = segments.iter().any(|seg| {
                    seg.vaddr.start <= offset
                        && offset
                            .checked_add(8)
                            .is_some_and(|end| end <= seg.vaddr.end)
                });
                if !in_segment {
                    return Err(LoadError::BadRelocation);
                }
                let value = BASE
                    .checked_add_signed(rela.r_addend)
                    .ok_or(LoadError::BadRelocation)?;
                writes.push((offset, value));
            }
            _ => return Err(LoadError::BadRelocation),
        }
    }
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const PF_RX: u32 = 4 | 1;
    const PF_RW: u32 = 4 | 2;
    const DT_RELA_TAG: i64 = 7;
    const R_X86_64_64: u32 = 1;

    /// A minimal static PIE: text at 0x1000 holding the gate, data at 0x2000
    /// holding `PT_DYNAMIC` and, at 0x2100, the `DT_RELA` table.
    struct Elf {
        e_type: u16,
        machine: u16,
        entry: u64,
        /// `(p_type, p_flags, offset and vaddr, filesz, memsz)`.
        phdrs: Vec<(u32, u32, u64, u64, u64)>,
        gate: Option<(u64, u64)>,
        dynamic: Vec<(i64, u64)>,
        /// `(r_offset, r_type, r_addend)`.
        relas: Vec<(u64, u32, i64)>,
    }

    impl Elf {
        fn valid() -> Self {
            let relas = vec![(0x2800, R_X86_64_RELATIVE, 0x1000)];
            let dynamic = vec![
                (DT_RELA_TAG, 0x2100),
                (DT_RELASZ, 24 * relas.len() as u64),
                (DT_RELAENT, 24),
            ];
            let dynamic_len = 16 * (dynamic.len() as u64 + 1);
            Self {
                e_type: ET_DYN,
                machine: EM_X86_64,
                entry: 0x1000,
                phdrs: vec![
                    (PT_LOAD, PF_RX, 0x1000, 0x1000, 0x1000),
                    (PT_LOAD, PF_RW, 0x2000, 0x1000, 0x1000),
                    (PT_DYNAMIC, PF_RW, 0x2000, dynamic_len, dynamic_len),
                ],
                gate: Some((0x1000, 0x10)),
                dynamic,
                relas,
            }
        }

        fn build(&self) -> Vec<u8> {
            let put = |f: &mut Vec<u8>, at: usize, bytes: &[u8]| {
                f[at..at + bytes.len()].copy_from_slice(bytes);
            };
            let mut f = vec![0u8; 0x3100];
            for (i, &(tag, val)) in self.dynamic.iter().chain([&(0, 0)]).enumerate() {
                put(&mut f, 0x2000 + 16 * i, &tag.to_le_bytes());
                put(&mut f, 0x2008 + 16 * i, &val.to_le_bytes());
            }
            for (i, &(offset, kind, addend)) in self.relas.iter().enumerate() {
                put(&mut f, 0x2100 + 24 * i, &offset.to_le_bytes());
                put(&mut f, 0x2108 + 24 * i, &u64::from(kind).to_le_bytes());
                put(&mut f, 0x2110 + 24 * i, &addend.to_le_bytes());
            }
            let names = b"\0.kabi_gate\0.shstrtab\0";
            put(&mut f, 0x3000, names);
            // Null, the gate (if any), then the string table.
            let mut sections = vec![[0u8; 64]];
            let mut section = |name: u32, kind: u32, addr: u64, offset: u64, size: u64| {
                let mut s = [0u8; 64];
                s[0..4].copy_from_slice(&name.to_le_bytes());
                s[4..8].copy_from_slice(&kind.to_le_bytes());
                s[16..24].copy_from_slice(&addr.to_le_bytes());
                s[24..32].copy_from_slice(&offset.to_le_bytes());
                s[32..40].copy_from_slice(&size.to_le_bytes());
                sections.push(s);
            };
            if let Some((addr, size)) = self.gate {
                section(1, 1, addr, addr, size);
            }
            section(12, 3, 0, 0x3000, names.len() as u64);
            let shoff = 0x3040;
            f.resize(shoff + 64 * sections.len(), 0);
            for (i, s) in sections.iter().enumerate() {
                put(&mut f, shoff + 64 * i, s);
            }
            let mut ehdr = [0u8; 64];
            ehdr[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
            ehdr[16..18].copy_from_slice(&self.e_type.to_le_bytes());
            ehdr[18..20].copy_from_slice(&self.machine.to_le_bytes());
            ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
            ehdr[24..32].copy_from_slice(&self.entry.to_le_bytes());
            ehdr[32..40].copy_from_slice(&64u64.to_le_bytes());
            ehdr[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
            ehdr[52..54].copy_from_slice(&64u16.to_le_bytes());
            ehdr[54..56].copy_from_slice(&56u16.to_le_bytes());
            ehdr[56..58].copy_from_slice(&u16::try_from(self.phdrs.len()).unwrap().to_le_bytes());
            ehdr[58..60].copy_from_slice(&64u16.to_le_bytes());
            ehdr[60..62].copy_from_slice(&u16::try_from(sections.len()).unwrap().to_le_bytes());
            ehdr[62..64].copy_from_slice(&u16::try_from(sections.len() - 1).unwrap().to_le_bytes());
            put(&mut f, 0, &ehdr);
            for (i, &(kind, flags, at, filesz, memsz)) in self.phdrs.iter().enumerate() {
                let p = 64 + 56 * i;
                put(&mut f, p, &kind.to_le_bytes());
                put(&mut f, p + 4, &flags.to_le_bytes());
                put(&mut f, p + 8, &at.to_le_bytes());
                put(&mut f, p + 16, &at.to_le_bytes());
                put(&mut f, p + 24, &at.to_le_bytes());
                put(&mut f, p + 32, &filesz.to_le_bytes());
                put(&mut f, p + 40, &memsz.to_le_bytes());
            }
            f
        }

        fn plan(self) -> Result<(), LoadError> {
            plan(&self.build()).map(|_| ())
        }
    }

    #[test]
    fn a_valid_image_is_planned() {
        let image = Elf::valid().build();
        let plan = plan(&image).unwrap();
        assert_eq!(plan.runner.entry, BASE + 0x1000);
        assert_eq!(plan.runner.gate, BASE + 0x1000..BASE + 0x1010);
        assert_eq!(plan.runner.executable, vec![BASE + 0x1000..BASE + 0x2000]);
        assert_eq!(plan.relocations, [(0x2800, BASE + 0x1000)]);
        assert_eq!(plan.relro, []);
    }

    #[test]
    fn non_static_pies_are_refused() {
        let mut exec = Elf::valid();
        exec.e_type = 2; // ET_EXEC
        assert!(matches!(exec.plan(), Err(LoadError::NotStaticPieX86_64)));
        let mut arm = Elf::valid();
        arm.machine = 183; // EM_AARCH64
        assert!(matches!(arm.plan(), Err(LoadError::NotStaticPieX86_64)));
        let mut interp = Elf::valid();
        interp.phdrs.push((PT_INTERP, 4, 0x2000, 1, 1));
        assert!(matches!(interp.plan(), Err(LoadError::NotStaticPieX86_64)));
        assert!(matches!(plan(&[0; 16]), Err(LoadError::Parse(_))));
    }

    #[test]
    fn bad_segments_are_refused() {
        let segment = |phdr: (u32, u32, u64, u64, u64)| {
            let mut elf = Elf::valid();
            elf.phdrs[1] = phdr;
            elf.plan()
        };
        assert!(matches!(
            segment((PT_LOAD, 7, 0x2000, 0x1000, 0x1000)),
            Err(LoadError::WritableAndExecutable)
        ));
        assert!(matches!(
            segment((PT_LOAD, PF_RW, 0x2000, 0x2000, 0x1000)),
            Err(LoadError::BadSegment),
        ));
        assert!(
            matches!(
                segment((PT_LOAD, PF_RW, 0x1800, 0x100, 0x100)),
                Err(LoadError::BadSegment)
            ),
            "shares a page with the text"
        );
        assert!(
            matches!(
                segment((PT_LOAD, PF_RW, 0x2000, 0x1000, RUNNER_IMAGE.len)),
                Err(LoadError::BadSegment)
            ),
            "outside the runner-image area"
        );
        assert!(
            matches!(
                segment((PT_LOAD, PF_RW, 0x2000, 0x10_0000, 0x10_0000)),
                Err(LoadError::BadSegment)
            ),
            "past the end of the file"
        );
    }

    #[test]
    fn the_gate_and_entry_must_be_in_executable_segments() {
        let mut no_gate = Elf::valid();
        no_gate.gate = None;
        assert!(matches!(no_gate.plan(), Err(LoadError::NoGate)));
        let mut data_gate = Elf::valid();
        data_gate.gate = Some((0x2000, 0x10));
        assert!(matches!(data_gate.plan(), Err(LoadError::NoGate)));
        let mut empty_gate = Elf::valid();
        empty_gate.gate = Some((0x1000, 0));
        assert!(matches!(empty_gate.plan(), Err(LoadError::NoGate)));
        let mut data_entry = Elf::valid();
        data_entry.entry = 0x2000;
        assert!(matches!(data_entry.plan(), Err(LoadError::BadEntry)));
        let mut wild_entry = Elf::valid();
        wild_entry.entry = u64::MAX;
        assert!(matches!(wild_entry.plan(), Err(LoadError::BadEntry)));
    }

    #[test]
    fn only_relative_relocations_inside_segments_are_applied() {
        let rela = |relas: Vec<(u64, u32, i64)>| {
            let mut elf = Elf::valid();
            elf.relas = relas;
            elf.plan()
        };
        let relative = R_X86_64_RELATIVE;
        assert!(matches!(
            rela(vec![(0x2800, R_X86_64_64, 0)]),
            Err(LoadError::BadRelocation)
        ));
        assert!(matches!(
            rela(vec![(0x2ffc, relative, 0)]),
            Err(LoadError::BadRelocation)
        ));
        assert!(matches!(
            rela(vec![(0x10_0000, relative, 0)]),
            Err(LoadError::BadRelocation)
        ));
        assert!(matches!(
            rela(vec![(0x2800, relative, i64::MIN)]),
            Err(LoadError::BadRelocation)
        ));
        let dynamic = |dynamic: Vec<(i64, u64)>| {
            let mut elf = Elf::valid();
            elf.dynamic = dynamic;
            elf.plan()
        };
        assert!(matches!(
            dynamic(vec![
                (DT_RELA_TAG, 0x2100),
                (DT_RELASZ, 24),
                (DT_RELAENT, 16)
            ]),
            Err(LoadError::BadRelocation)
        ));
        assert!(matches!(
            dynamic(vec![(DT_RELA_TAG, 0x2100), (DT_RELASZ, 25)]),
            Err(LoadError::BadRelocation)
        ));
        assert!(matches!(
            dynamic(vec![(DT_RELA_TAG, 0x2ff0), (DT_RELASZ, 24)]),
            Err(LoadError::BadRelocation)
        ));
        assert!(matches!(
            dynamic(vec![(DT_REL, 0x2100)]),
            Err(LoadError::BadRelocation)
        ));
    }

    #[test]
    fn relro_must_start_a_page_in_a_writable_segment() {
        let relro = |vaddr: u64, len: u64| {
            let mut elf = Elf::valid();
            elf.phdrs.push((PT_GNU_RELRO, 4, vaddr, len, len));
            elf.build()
        };
        let image = relro(0x2000, 0x800);
        let plan = plan(&image).unwrap();
        let start = usize::try_from(BASE).unwrap() + 0x2000;
        assert_eq!(plan.relro, vec![start..start + 0x1000]);
        assert!(matches!(
            super::plan(&relro(0x2100, 0x100)),
            Err(LoadError::BadSegment)
        ));
        assert!(matches!(
            super::plan(&relro(0x1000, 0x100)),
            Err(LoadError::BadSegment)
        ));
    }
}

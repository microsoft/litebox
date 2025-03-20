/// The code below is copied from https://github.com/gimli-rs/object/blame/master/crates/rewrite/src/elf.rs.
use anyhow::Result;
use object::build;
use object::elf;

enum BlockKind {
    FileHeader,
    ProgramHeaders,
    Segment,
    Section(build::elf::SectionId),
}

struct Block<'a> {
    #[allow(dead_code)]
    name: build::ByteString<'a>,
    kind: BlockKind,
    address: u64,
    size: u64,
    // Higher means better to move. 0 means never move.
    move_priority: u8,
}

/// Move sections between segments if needed, and assign file offsets to segments and sections.
///
/// Does not change the size of existing `PT_LOAD` segments, but may add new segments.
// TODO: allow changing size of existing `PT_LOAD` segments
#[allow(clippy::too_many_lines)]
pub fn move_sections(builder: &mut build::elf::Builder) -> Result<()> {
    builder.delete_orphans();
    builder.delete_unused_versions();
    builder.set_section_sizes();

    let mut added_p_flags = Vec::new();
    let mut added_segments = 0;

    // Loop until we reach a fixed point for the number of additional segments needed.
    loop {
        let mut move_sections = find_move_sections(builder, added_segments)?;
        if move_sections.is_empty() {
            return Ok(());
        }

        // Calculate the number of additional PT_LOAD segments needed.
        added_p_flags.clear();
        for id in &move_sections {
            let section = builder.sections.get_mut(*id);
            // Flag the section as needing to move.
            section.sh_offset = 0;
            // We need one PT_LOAD segment for each unique combination of p_flags.
            let p_flags = section.p_flags();
            if !added_p_flags.contains(&p_flags) {
                added_p_flags.push(p_flags);
            }
        }

        // If moving a section that is part of a non-PT_LOAD segment, then we may need to
        // split the segment, which will require an additional segment.
        let mut split_segments = 0;
        for segment in &mut builder.segments {
            if segment.p_type == elf::PT_LOAD {
                continue;
            }
            let mut any = false;
            let mut all = true;
            for id in &segment.sections {
                if move_sections.contains(id) {
                    any = true;
                } else {
                    all = false;
                }
            }
            if !any || all {
                continue;
            }
            split_segments += 1;
        }

        // Check if we have reached a fixed point for the number of additional segments needed.
        if added_segments < split_segments + added_p_flags.len() {
            added_segments = split_segments + added_p_flags.len();
            continue;
        }

        println!(
            "Moving {} sections, adding {} PT_LOAD segments, splitting {} segments",
            move_sections.len(),
            added_p_flags.len(),
            split_segments,
        );

        // Add the PT_LOAD segments and append sections to them.
        // Try to keep the same order of sections in the new segments.
        move_sections.sort_by_key(|id| {
            let section = builder.sections.get(*id);
            (section.sh_addr, section.sh_size)
        });
        for p_flags in added_p_flags {
            // TODO: reuse segments that only contain movable sections
            let segment = builder
                .segments
                .add_load_segment(p_flags, builder.load_align);
            for id in &move_sections {
                let section = builder.sections.get_mut(*id);
                if p_flags == section.p_flags() {
                    segment.append_section(section);
                    println!(
                        "Moved {} to offset {:x}, addr {:x}",
                        section.name, section.sh_offset, section.sh_addr
                    );
                }
            }
            println!(
                "Added PT_LOAD segment with p_flags {:x}, offset {:x}, addr {:x}, size {:x}",
                p_flags, segment.p_offset, segment.p_vaddr, segment.p_memsz,
            );
        }

        // Split or move non-PT_LOAD segments that contain sections that have been moved.
        let sections = &builder.sections;
        let mut split_segments = Vec::new();
        for segment in &mut builder.segments {
            if segment.p_type == elf::PT_LOAD {
                continue;
            }

            let mut any = false;
            let mut all = true;
            for id in &segment.sections {
                if move_sections.contains(id) {
                    any = true;
                } else {
                    all = false;
                }
            }
            if !any {
                continue;
            }
            if !all {
                // Segment needs splitting.
                // Remove all the sections that have been moved, and store them so
                // that we can add the new segment later.
                let mut split_sections = Vec::new();
                segment.sections.retain(|id| {
                    if move_sections.contains(id) {
                        split_sections.push(*id);
                        false
                    } else {
                        true
                    }
                });
                split_segments.push((segment.id(), split_sections));
            }

            // The remaining sections have already been assigned an address.
            // Recalcuate the file and address ranges for the segment.
            // TODO: verify that the sections are contiguous. If not, try to slide the sections
            // down in memory.
            segment.recalculate_ranges(sections);
        }

        // Add new segments due to splitting.
        for (segment_id, split_sections) in split_segments {
            let segment = builder.segments.copy(segment_id);
            for id in split_sections {
                let section = builder.sections.get_mut(id);
                segment.append_section(section);
            }
            println!(
                "Split segment with type {:x}, offset {:x}, addr {:x}, size {:x}",
                segment.p_type, segment.p_offset, segment.p_vaddr, segment.p_memsz,
            );
        }

        // Update the PT_PHDR segment to include the new program headers.
        let size = builder.program_headers_size() as u64;
        for segment in &mut builder.segments {
            if segment.p_type != elf::PT_PHDR {
                continue;
            }
            segment.p_filesz = size;
            segment.p_memsz = size;
        }
        return Ok(());
    }
}

#[allow(clippy::too_many_lines)]
fn find_move_sections(
    builder: &build::elf::Builder,
    added_segments: usize,
) -> Result<Vec<build::elf::SectionId>> {
    use build::elf::SectionData;

    let mut move_sections = Vec::new();
    let mut blocks = Vec::new();
    let file_header_size = builder.file_header_size() as u64;
    let program_headers_size = (builder.program_headers_size()
        + added_segments * builder.class().program_header_size())
        as u64;
    let interp = builder.interp_section();

    if let Some(segment) = builder.segments.find_load_segment_from_offset(0) {
        let address = segment.address_from_offset(0);
        blocks.push(Block {
            name: "file header".into(),
            kind: BlockKind::FileHeader,
            address,
            size: file_header_size,
            move_priority: 0,
        });
    }
    if let Some(segment) = builder
        .segments
        .find_load_segment_from_offset(builder.header.e_phoff)
    {
        let address = segment.address_from_offset(builder.header.e_phoff);
        blocks.push(Block {
            name: "program headers".into(),
            kind: BlockKind::ProgramHeaders,
            address,
            size: program_headers_size,
            move_priority: 0,
        });
    }
    for segment in &builder.segments {
        if segment.p_type != elf::PT_LOAD {
            continue;
        }
        // Add zero-sized blocks at the start and end of the segment
        // to prevent changing the segment address or size.
        blocks.push(Block {
            name: "segment start".into(),
            kind: BlockKind::Segment,
            address: segment.p_vaddr,
            size: 0,
            move_priority: 0,
        });
        blocks.push(Block {
            name: "segment end".into(),
            kind: BlockKind::Segment,
            address: segment.p_vaddr + segment.p_memsz,
            size: 0,
            move_priority: 0,
        });
    }
    for section in &builder.sections {
        if !section.is_alloc() {
            continue;
        }
        if section.sh_offset == 0 {
            // Newly added section that needs to be assigned to a segment,
            // or a section that has already been flagged for moving.
            move_sections.push(section.id());
            continue;
        }
        if section.sh_type == elf::SHT_NOBITS && section.sh_flags & u64::from(elf::SHF_TLS) != 0 {
            // Uninitialized TLS sections are not part of the address space.
            continue;
        }
        let move_priority = match &section.data {
            // Can't move sections whose address may referenced from
            // a section that we can't rewrite.
            #[allow(clippy::bool_to_int_with_if)]
            SectionData::Data(_) => {
                if Some(section.id()) == interp {
                    1
                } else {
                    0
                }
            }
            #[allow(clippy::match_same_arms)]
            SectionData::UninitializedData(_) | SectionData::Dynamic(_) => 0,
            // TODO: Can be referenced by dynamic entries, but we don't support that yet.
            #[allow(clippy::match_same_arms)]
            SectionData::DynamicRelocation(_) => 0,
            // None of these can be referenced by address that I am aware of.
            SectionData::Relocation(_)
            | SectionData::Note(_)
            | SectionData::Attributes(_)
            | SectionData::SectionString
            | SectionData::Symbol
            | SectionData::SymbolSectionIndex
            | SectionData::String
            | SectionData::DynamicSymbol
            | SectionData::DynamicString
            | SectionData::Hash
            | SectionData::GnuHash
            | SectionData::GnuVersym
            | SectionData::GnuVerdef
            | SectionData::GnuVerneed => 2,
        };
        blocks.push(Block {
            name: (*section.name).into(),
            kind: BlockKind::Section(section.id()),
            address: section.sh_addr,
            size: section.sh_size,
            move_priority,
        });
    }
    blocks.sort_by_key(|block| (block.address, block.size));

    // For each pair of overlapping blocks, decide which one to move.
    let mut i = 0;
    while i + 1 < blocks.len() {
        let end_address = blocks[i].address + blocks[i].size;
        if end_address <= blocks[i + 1].address {
            i += 1;
            continue;
        }
        // Prefer moving the earlier block, since it is the reason for the overlap.
        if blocks[i].move_priority >= blocks[i + 1].move_priority {
            if blocks[i].move_priority == 0 {
                println!(
                    "Immovable {} (end address {:x}) overlaps immovable {} (start address {:x})",
                    blocks[i].name,
                    end_address,
                    blocks[i + 1].name,
                    blocks[i + 1].address,
                );
                return Err(anyhow::anyhow!("Overlapping immovable sections"));
            }
            println!(
                "Need to move {} (end address {:x}) because of {} (start address {:x})",
                blocks[i].name,
                end_address,
                blocks[i + 1].name,
                blocks[i + 1].address,
            );
            if let BlockKind::Section(section) = blocks[i].kind {
                move_sections.push(section);
                blocks.remove(i);
            } else {
                // Only sections can be moved.
                unreachable!();
            }
        } else {
            println!(
                "Need to move {} (start address {:x}) because of {} (end address {:x})",
                blocks[i + 1].name,
                blocks[i + 1].address,
                blocks[i].name,
                end_address,
            );
            if let BlockKind::Section(section) = blocks[i + 1].kind {
                move_sections.push(section);
                blocks.remove(i + 1);
            } else {
                // Only sections can be moved.
                unreachable!();
            }
        }
    }
    Ok(move_sections)
}

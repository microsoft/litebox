// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Versioned Linux-guest ELF island images under the unchanged `LITEBOX0`
//! footer. All integers are little endian; parsing never requires aligned input.

use alloc::{collections::BTreeSet, vec, vec::Vec};
use core::ops::Range;

use super::island::{self, IslandPair};
use crate::{Error, Result, RewriteOptions, TargetHost};

const MAGIC: &[u8; 8] = b"LBISLAND";
const HEADER: usize = 64;
const ENTRY: usize = 40;

fn bad() -> Error {
    Error::TrampolinePatchFailure("invalid ELF island payload".into())
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    ))
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    ))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(bad)
}
fn aligned(a: u64, page: u64) -> Result<u64> {
    a.checked_next_multiple_of(page).ok_or_else(bad)
}
fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Validated, immutable file images. Empty pairs denote the processed size-zero
/// sentinel, not an executable payload. Chunk runtime addresses are absent.
#[derive(Clone, Debug)]
pub struct ElfIslands {
    /// Host/options against which the gate images were validated.
    pub options: RewriteOptions,
    /// Fixed virtual allocation size of each island (populated bytes are 4096).
    pub granule: u64,
    /// Object-relative island and position-independent full-chunk images.
    pub pairs: Vec<IslandPair>,
}

impl ElfIslands {
    /// Parse and validate the entire footer, descriptor, images, LOAD exclusion,
    /// and every primary site's inbound branch before returning any images.
    /// Reads at most one bounded image at a time; untrusted counts never become
    /// allocation capacities. `None` means no recognized footer, not corruption.
    pub fn read(
        file_size: u64,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    ) -> Result<Option<Self>> {
        if file_size < 32 {
            return Ok(None);
        }
        let tail = file_size - 32;
        let mut footer = [0; 32];
        read(tail, &mut footer)?;
        if &footer[..8] != crate::TRAMPOLINE_MAGIC {
            return if &footer[..7] == b"LITEBOX" {
                Err(bad())
            } else {
                Ok(None)
            };
        }
        let base = u64_at(&footer, 8)?;
        let vaddr = u64_at(&footer, 16)?;
        let size = u64_at(&footer, 24)?;
        if size == 0 {
            if base != 0 || vaddr != 0 {
                return Err(bad());
            }
            return Ok(Some(Self {
                options: RewriteOptions::default(),
                granule: 4096,
                pairs: Vec::new(),
            }));
        }
        if base == 0 || base % 4096 != 0 || add(base, size)? != tail || size < HEADER as u64 {
            return Err(bad());
        }
        let mut header = [0; HEADER];
        read(base, &mut header)?;
        if &header[..8] != MAGIC
            || u32_at(&header, 8)? != 1
            || u32_at(&header, 12)? != u32::try_from(HEADER).map_err(|_| bad())?
            || u64_at(&header, 40)? != ENTRY as u64
            || u64_at(&header, 56)? != 0
        {
            return Err(bad());
        }
        let host = match u32_at(&header, 16)? {
            1 => TargetHost::Linux,
            2 => TargetHost::MacOs,
            _ => return Err(Error::UnsupportedExecutable("ELF island host".into())),
        };
        let flags = u32_at(&header, 20)?;
        if flags > 1 || (host == TargetHost::MacOs && flags != 1) {
            return Err(bad());
        }
        let options = RewriteOptions::new(host, flags != 0);
        let granule = u64_at(&header, 24)?;
        if granule
            != match host {
                TargetHost::MacOs => 16384,
                _ => 4096,
            }
        {
            return Err(bad());
        }
        let count = u64_at(&header, 32)?;
        let file_end = u64_at(&header, 48)?;
        if file_end < 64 || aligned(file_end, 4096)? != base || count == 0 {
            return Err(bad());
        }
        let mut cursor = aligned(
            add(
                HEADER as u64,
                count.checked_mul(ENTRY as u64).ok_or_else(bad)?,
            )?,
            16,
        )?;
        let minimum = (island::ISLAND_BYTES + island::CHUNK_GATES_OFFSET + 16) as u64;
        if count > file_end / 4 || count > size.saturating_sub(cursor) / minimum {
            return Err(bad());
        }
        // Padding has one canonical representation, including table alignment.
        let mut padding = [0; 4096];
        read(
            file_end,
            &mut padding[..usize::try_from(base - file_end).map_err(|_| bad())?],
        )?;
        if padding.iter().any(|b| *b != 0) {
            return Err(bad());
        }
        let table_end = add(HEADER as u64, count * ENTRY as u64)?;
        let padding_len = usize::try_from(cursor - table_end).map_err(|_| bad())?;
        read(add(base, table_end)?, &mut padding[..padding_len])?;
        if padding[..padding_len].iter().any(|b| *b != 0) {
            return Err(bad());
        }

        let mut ehdr = [0; 64];
        read(0, &mut ehdr)?;
        if &ehdr[..7] != b"\x7fELF\x02\x01\x01"
            || u32_at(&ehdr, 20)? != 1
            || u16_at(&ehdr, 52)? != 64
            || u16_at(&ehdr, 18)? != object::elf::EM_AARCH64
            || !matches!(u16_at(&ehdr, 16)?, 2 | 3)
        {
            return Err(bad());
        }
        let phoff = u64_at(&ehdr, 32)?;
        let phnum = u16_at(&ehdr, 56)?;
        if u16_at(&ehdr, 54)? != 56
            || phnum == 0
            || u64::from(phnum) * 56 > 65536
            || add(phoff, u64::from(phnum) * 56)? > file_end
        {
            return Err(bad());
        }
        // The descriptor's original-file boundary also excludes section tables
        // and file-backed sections from borrowing bytes in the appended images.
        let shoff = u64_at(&ehdr, 40)?;
        let shnum = u16_at(&ehdr, 60)?;
        if shoff != 0 || shnum != 0 {
            if shoff < 64
                || shnum == 0
                || u16_at(&ehdr, 58)? != 64
                || add(shoff, u64::from(shnum) * 64)? > file_end
            {
                return Err(bad());
            }
            for index in 0..shnum {
                let mut sh = [0; 64];
                read(add(shoff, u64::from(index) * 64)?, &mut sh)?;
                if u32_at(&sh, 4)? != object::elf::SHT_NOBITS
                    && add(u64_at(&sh, 24)?, u64_at(&sh, 32)?)? > file_end
                {
                    return Err(bad());
                }
            }
        }
        let mut loads = Vec::new();
        for i in 0..phnum {
            let mut ph = [0; 56];
            read(add(phoff, u64::from(i) * 56)?, &mut ph)?;
            if u32_at(&ph, 0)? != object::elf::PT_LOAD {
                continue;
            }
            let offset = u64_at(&ph, 8)?;
            let address = u64_at(&ph, 16)?;
            let filesz = u64_at(&ph, 32)?;
            let memsz = u64_at(&ph, 40)?;
            if add(offset, filesz)? > file_end {
                return Err(bad());
            }
            let end = add(address, filesz.max(memsz))?;
            loads.push((
                address..end,
                offset,
                filesz,
                u32_at(&ph, 4)? & object::elf::PF_X != 0,
            ));
        }
        if loads.is_empty() {
            return Err(bad());
        }
        let mut pairs = Vec::new();
        let mut extents = BTreeSet::new();
        let mut sites = BTreeSet::new();
        for index in 0..count {
            let mut entry = [0; ENTRY];
            read(
                add(base, add(HEADER as u64, index * ENTRY as u64)?)?,
                &mut entry,
            )?;
            let address = u64_at(&entry, 0)?;
            let island_offset = u64_at(&entry, 8)?;
            let island_len = u64_at(&entry, 16)?;
            let chunk_offset = u64_at(&entry, 24)?;
            let chunk_len = u64_at(&entry, 32)?;
            let extent = address..add(address, granule)?;
            if address % granule != 0
                || !extents.insert(address)
                || loads.iter().any(|(load, _, _, _)| {
                    let end = load
                        .end
                        .checked_next_multiple_of(granule)
                        .unwrap_or(u64::MAX);
                    overlaps(&extent, &(load.start / granule * granule..end))
                })
                || island_offset != cursor
                || island_len != island::ISLAND_BYTES as u64
                || chunk_offset != add(cursor, island_len)?
                || !(island::CHUNK_GATES_OFFSET as u64..=island::CHUNK_CAPACITY_BYTES as u64)
                    .contains(&chunk_len)
                || chunk_len % 16 != 0
            {
                return Err(bad());
            }
            cursor = add(chunk_offset, chunk_len)?;
            if cursor > size {
                return Err(bad());
            }
            let mut near = vec![0; island::ISLAND_BYTES];
            let mut far = vec![0; usize::try_from(chunk_len).map_err(|_| bad())?];
            read(add(base, island_offset)?, &mut near)?;
            read(add(base, chunk_offset)?, &mut far)?;
            if island::decode_island_header(&near) != Some(0) || u64_at(&far, 0)? != 0 {
                return Err(bad());
            }
            island::validate_serialized_chunk(&far, host, options.virtualizes_x18())?;
            let pair = IslandPair::from_images(address, near, far, host)?;
            if pair.slots_used() == 0 {
                return Err(bad());
            }
            for slot in 0..pair.slots_used() {
                let slot =
                    island::decode_island_slot(pair.island(), address, slot).ok_or_else(bad)?;
                if slot.auxiliary {
                    continue;
                }
                if !sites.insert(slot.site) {
                    return Err(bad());
                }
                let inbound = add(
                    address,
                    (island::ISLAND_HEADER_BYTES + slot.index * island::ISLAND_SLOT_BYTES) as u64,
                )?;
                let mut covered = false;
                for (load, offset, filesz, execute) in &loads {
                    if *execute
                        && load.start <= slot.site
                        && add(slot.site, 4)? <= add(load.start, *filesz)?
                    {
                        let mut word = [0; 4];
                        read(add(*offset, slot.site - load.start)?, &mut word)?;
                        if super::decode_branch_target(u32::from_le_bytes(word), slot.site)
                            != Some(inbound)
                        {
                            return Err(bad());
                        }
                        covered = true;
                    }
                }
                if !covered {
                    return Err(bad());
                }
            }
            pairs.push(pair);
        }
        if cursor != size || extents.first().copied() != Some(vaddr) {
            return Err(bad());
        }
        Ok(Some(Self {
            options,
            granule,
            pairs,
        }))
    }

    /// Parse a byte-aligned file buffer.
    pub fn parse(file: &[u8]) -> Result<Option<Self>> {
        Self::read(file.len() as u64, |offset, bytes| {
            let start = usize::try_from(offset).map_err(|_| bad())?;
            let end = start.checked_add(bytes.len()).ok_or_else(bad)?;
            bytes.copy_from_slice(file.get(start..end).ok_or_else(bad)?);
            Ok(())
        })
    }

    /// Reject host/options mismatches before executable publication. A sentinel
    /// has no host-dependent instructions and is compatible with either host.
    pub fn check_compatibility(&self, options: RewriteOptions, granule: usize) -> Result<()> {
        if !self.pairs.is_empty() && (self.options != options || self.granule != granule as u64) {
            return Err(Error::UnsupportedExecutable(
                "incompatible ELF island host/options/granule".into(),
            ));
        }
        Ok(())
    }

    /// Serialize already-built images; no runtime address is written to disk.
    pub(crate) fn append(&self, out: &mut Vec<u8>) -> Result<()> {
        let file_end = out.len() as u64;
        if self.pairs.is_empty() {
            out.extend_from_slice(crate::TRAMPOLINE_MAGIC);
            out.extend_from_slice(&[0; 24]);
            return Ok(());
        }
        let base = aligned(file_end, 4096)?;
        let table_end = add(
            HEADER as u64,
            (self.pairs.len() as u64)
                .checked_mul(ENTRY as u64)
                .ok_or_else(bad)?,
        )?;
        let mut payload = vec![0; usize::try_from(aligned(table_end, 16)?).map_err(|_| bad())?];
        payload[..8].copy_from_slice(MAGIC);
        payload[8..12].copy_from_slice(&1u32.to_le_bytes());
        payload[12..16].copy_from_slice(&(u32::try_from(HEADER).map_err(|_| bad())?).to_le_bytes());
        let host: u32 = match self.options.target_host() {
            TargetHost::Linux => 1,
            TargetHost::MacOs => 2,
            TargetHost::Windows => return Err(bad()),
        };
        payload[16..20].copy_from_slice(&host.to_le_bytes());
        payload[20..24].copy_from_slice(&u32::from(self.options.virtualizes_x18()).to_le_bytes());
        for (at, value) in [
            (24, self.granule),
            (32, self.pairs.len() as u64),
            (40, ENTRY as u64),
            (48, file_end),
        ] {
            payload[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (index, pair) in self.pairs.iter().enumerate() {
            let offset = payload.len() as u64;
            for (field, value) in [
                pair.island_vaddr(),
                offset,
                pair.island().len() as u64,
                add(offset, pair.island().len() as u64)?,
                pair.chunk().len() as u64,
            ]
            .into_iter()
            .enumerate()
            {
                let at = HEADER + index * ENTRY + field * 8;
                payload[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            payload.extend_from_slice(pair.island());
            payload.extend_from_slice(pair.chunk());
        }
        out.resize(usize::try_from(base).map_err(|_| bad())?, 0);
        out.extend_from_slice(&payload);
        out.extend_from_slice(crate::TRAMPOLINE_MAGIC);
        for value in [
            base,
            self.pairs
                .iter()
                .map(IslandPair::island_vaddr)
                .min()
                .ok_or_else(bad)?,
            payload.len() as u64,
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }
}

pub(crate) fn rewrite(
    original: &[u8],
    buf: &mut [u8],
    sections: super::ScanSections<'_>,
    options: RewriteOptions,
) -> Result<Vec<u8>> {
    use object::read::{Object as _, ObjectSegment as _};
    if options.target_host() == TargetHost::Windows {
        return Err(Error::UnsupportedExecutable("Windows ELF islands".into()));
    }
    let granule = if options.target_host() == TargetHost::MacOs {
        16384
    } else {
        4096
    };
    let file = object::File::parse(&*buf).map_err(|_| bad())?;
    let mut loads: Vec<Range<u64>> = file
        .segments()
        .map(|seg| {
            Ok(seg.address() / granule * granule
                ..aligned(
                    add(seg.address(), seg.size().max(seg.file_range().1))?,
                    granule,
                )?)
        })
        .collect::<Result<_>>()?;
    loads.sort_unstable_by_key(|r| r.start);
    let mut union: Vec<Range<u64>> = Vec::new();
    for load in loads {
        if let Some(last) = union.last_mut()
            && load.start <= last.end
        {
            last.end = last.end.max(load.end);
        } else {
            union.push(load);
        }
    }
    let span = union.first().ok_or_else(bad)?.start..union.last().ok_or_else(bad)?.end;
    let config = super::RewriteConfig::new(options.target_host(), options.virtualizes_x18());
    let mut probe = buf.to_vec();
    let pairs = island::rewrite_allocating_sections(
        &mut probe,
        sections.executable,
        sections.code,
        config,
        |site, reach, pairs| {
            let low = aligned((*reach.start()).max(granule), granule).ok()?;
            let high = *reach.end() / granule * granule;
            if low > high {
                return None;
            }
            let mut occupied = union.clone();
            occupied.extend(
                pairs
                    .iter()
                    .map(|p| p.island_vaddr()..p.island_vaddr() + granule),
            );
            occupied.sort_unstable_by_key(|r| r.start);
            let mut cursor = low;
            let mut best = None;
            // Each free interval contributes only its nearest page, split at
            // the LOAD span boundaries to preserve the internal-gap preference.
            // Every page in reach has identical admission; no per-page rescans.
            let mut consider = |start: u64, end: u64| {
                for r in [
                    start..end.min(span.start),
                    start.max(span.start)..end.min(span.end),
                    start.max(span.end)..end,
                ] {
                    if r.start >= r.end {
                        continue;
                    }
                    let at = (site / granule * granule).clamp(r.start, r.end - granule);
                    let key = (!span.contains(&at), at.abs_diff(site), at);
                    if best.is_none_or(|old| key < old) {
                        best = Some(key);
                    }
                }
            };
            let end = high.checked_add(granule)?;
            for load in occupied {
                if cursor < load.start.min(end) {
                    consider(cursor, load.start.min(end));
                }
                cursor = cursor.max(load.end);
                if cursor >= end {
                    break;
                }
            }
            if cursor < end {
                consider(cursor, end);
            }
            best.map(|(_, _, at)| at)
        },
    )?;
    let payload = ElfIslands {
        options,
        granule,
        pairs,
    };
    let mut out = if payload.pairs.is_empty() {
        original.to_vec()
    } else {
        probe.clone()
    };
    payload.append(&mut out)?;
    // Verify the exact serialized file before making any caller-visible edit.
    ElfIslands::parse(&out)?.ok_or_else(bad)?;
    buf.copy_from_slice(&probe);
    Ok(out)
}

#[cfg(test)]
mod tests;

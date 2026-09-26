// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded PVH v1 parsing and conservative heap selection. No allocation is
//! allowed until this policy has finished validating the entire description.
//! We support one contiguous RAM region containing the image and boot scratch;
//! low RAM is ignored, and modules/initrd are explicitly unsupported for now.

use arrayvec::ArrayVec;
use core::ops::Range;

pub const ENTRY_PA: u64 = 0x200000;
pub const SCRATCH_PA: u64 = 0x1000000;
pub const HEAP_FLOOR: u64 = SCRATCH_PA + 0x80000;
pub const MAPPED_LIMIT: u64 = 1 << 30;
const PAGE: u64 = 4096;
const MAX_ENTRIES: usize = 128;
const START_INFO_SIZE: usize = 56;
const ENTRY_SIZE: usize = 24;
const MAGIC: u32 = 0x336e_c578;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadPointer,
    BadMagic,
    OldVersion,
    ModulesUnsupported,
    BadEntryCount,
    Overflow,
    OverlappingEntries,
    UnsupportedRamLayout,
    UnterminatedCommandLine,
    NoHeap,
}

#[derive(Debug)]
pub struct BootMemory {
    /// RAM mapped by the final shared kernel page tables, including reserved
    /// boot storage. Being mapped does not make a page allocator-owned.
    pub ram: Range<u64>,
    /// Non-overlapping, page-aligned ranges safe to transfer to the heap.
    pub heap: ArrayVec<Range<u64>, 4>,
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn read<const N: usize>(
    source: &impl Fn(u64, &mut [u8]) -> Result<(), Error>,
    pa: u64,
) -> Result<[u8; N], Error> {
    if pa == 0 || pa.checked_add(N as u64).ok_or(Error::Overflow)? > MAPPED_LIMIT {
        return Err(Error::BadPointer);
    }
    let mut bytes = [0; N];
    source(pa, &mut bytes)?;
    Ok(bytes)
}

fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Parse using a reader supplied by the runner (mapped guest physical memory)
/// or a host unit test. Return all heap ranges before any may be transferred.
/// Reader errors and malformed/unsupported layouts are rejected, never guessed.
///
/// # Panics
/// Internal fixed-size integer decoding cannot fail for the supplied arrays.
pub fn parse(
    info_pa: u64,
    source: impl Fn(u64, &mut [u8]) -> Result<(), Error>,
) -> Result<BootMemory, Error> {
    // Check version before reading the v1-only fields.
    let header = read::<8>(&source, info_pa)?;
    if u32_at(&header, 0) != MAGIC {
        return Err(Error::BadMagic);
    }
    if u32_at(&header, 4) < 1 {
        return Err(Error::OldVersion);
    }
    let info = read::<START_INFO_SIZE>(&source, info_pa)?;
    if u32_at(&info, 12) != 0 {
        return Err(Error::ModulesUnsupported);
    }
    let table = u64_at(&info, 40);
    let count = u32_at(&info, 48) as usize;
    if count == 0 || count > MAX_ENTRIES {
        return Err(Error::BadEntryCount);
    }
    let table_end = table
        .checked_add((count * ENTRY_SIZE) as u64)
        .ok_or(Error::Overflow)?;
    if table == 0 || table_end > MAPPED_LIMIT {
        return Err(Error::BadPointer);
    }

    let mut entries = ArrayVec::<(Range<u64>, u32), MAX_ENTRIES>::new();
    for index in 0..count {
        let entry = read::<ENTRY_SIZE>(&source, table + (index * ENTRY_SIZE) as u64)?;
        let start = u64_at(&entry, 0);
        let end = start
            .checked_add(u64_at(&entry, 8))
            .ok_or(Error::Overflow)?;
        if start == end {
            continue;
        }
        let range = start..end;
        if entries.iter().any(|(other, _)| overlaps(&range, other)) {
            return Err(Error::OverlappingEntries);
        }
        entries.push((range, u32_at(&entry, 16)));
    }
    let ram = entries
        .iter()
        .find(|(range, kind)| *kind == 1 && range.start <= ENTRY_PA && range.end > HEAP_FLOOR)
        .map(|(range, _)| range.clone())
        .ok_or(Error::UnsupportedRamLayout)?;
    if ram.start < 0x100000 || ram.end > MAPPED_LIMIT || !ram.start.is_multiple_of(PAGE) {
        return Err(Error::UnsupportedRamLayout);
    }
    let ram = ram.start..(ram.end & !(PAGE - 1));
    let mut reserved = ArrayVec::<Range<u64>, 3>::new();
    reserved.push(info_pa..info_pa + START_INFO_SIZE as u64);
    reserved.push(table..table_end);
    let cmdline = u64_at(&info, 24);
    if cmdline != 0 {
        let mut end = None;
        for i in 0..4096u64 {
            let pa = cmdline.checked_add(i).ok_or(Error::Overflow)?;
            if read::<1>(&source, pa)?[0] == 0 {
                end = Some(pa + 1);
                break;
            }
        }
        reserved.push(cmdline..end.ok_or(Error::UnterminatedCommandLine)?);
    }
    // Firmware tables may overlap each other; subtract their union. All image,
    // scratch, boot stack, and low memory pages are excluded by HEAP_FLOOR.
    reserved.sort_unstable_by_key(|range| range.start);
    let mut heap = ArrayVec::new();
    let mut cursor = HEAP_FLOOR;
    for excluded in reserved {
        if excluded.end <= cursor {
            continue;
        }
        if excluded.start >= ram.end {
            break;
        }
        emit(&mut heap, cursor, excluded.start.min(ram.end));
        cursor = cursor.max(excluded.end);
    }
    emit(&mut heap, cursor, ram.end);
    if heap.is_empty() {
        return Err(Error::NoHeap);
    }
    Ok(BootMemory { ram, heap })
}

fn emit(heap: &mut ArrayVec<Range<u64>, 4>, start: u64, end: u64) {
    // All inputs are bounded by the 1 GiB mapping, except a reservation end
    // which may leave cursor beyond RAM. Do not round that cursor if empty.
    if start >= end {
        return;
    }
    let start = (start + PAGE - 1) & !(PAGE - 1);
    let end = end & !(PAGE - 1);
    if start < end {
        heap.push(start..end);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const INFO: usize = 0x1000;
    const TABLE: usize = 0x2000;
    fn put32(mem: &mut [u8], at: usize, value: u32) {
        mem[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(mem: &mut [u8], at: usize, value: u64) {
        mem[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture(entries: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut mem = vec![0; 0x10000];
        put32(&mut mem, INFO, MAGIC);
        put32(&mut mem, INFO + 4, 1);
        put64(&mut mem, INFO + 40, TABLE as u64);
        put32(&mut mem, INFO + 48, u32::try_from(entries.len()).unwrap());
        for (i, &(start, size, kind)) in entries.iter().enumerate() {
            let at = TABLE + i * ENTRY_SIZE;
            put64(&mut mem, at, start);
            put64(&mut mem, at + 8, size);
            put32(&mut mem, at + 16, kind);
        }
        mem
    }
    fn parse_mem(mem: &[u8]) -> Result<BootMemory, Error> {
        parse(INFO as u64, |pa, out| {
            let start = usize::try_from(pa).map_err(|_| Error::BadPointer)?;
            out.copy_from_slice(mem.get(start..start + out.len()).ok_or(Error::BadPointer)?);
            Ok(())
        })
    }
    fn normal() -> Vec<u8> {
        fixture(&[(0, 0x9fc00, 1), (0x100000, 0x3f00000, 1)])
    }

    #[test]
    fn excludes_low_memory_image_and_scratch() {
        let parsed = parse_mem(&normal()).unwrap();
        assert_eq!(parsed.ram, 0x100000..0x4000000);
        assert_eq!(parsed.heap.len(), 1);
        assert_eq!(parsed.heap[0], HEAP_FLOOR..0x4000000);
    }
    #[test]
    fn rejects_overlap_overflow_and_unmapped_ram() {
        assert_eq!(
            parse_mem(&fixture(&[(0x100000, 0x3f00000, 1), (0x300000, 4096, 2)])).unwrap_err(),
            Error::OverlappingEntries
        );
        assert_eq!(
            parse_mem(&fixture(&[(u64::MAX, 2, 1)])).unwrap_err(),
            Error::Overflow
        );
        assert_eq!(
            parse_mem(&fixture(&[(0x100000, 2 * MAPPED_LIMIT, 1)])).unwrap_err(),
            Error::UnsupportedRamLayout
        );
    }
    #[test]
    fn rejects_bad_header_modules_and_counts() {
        let mut mem = normal();
        put32(&mut mem, INFO, 0);
        assert_eq!(parse_mem(&mem).unwrap_err(), Error::BadMagic);
        let mut mem = normal();
        put32(&mut mem, INFO + 4, 0);
        assert_eq!(parse_mem(&mem).unwrap_err(), Error::OldVersion);
        let mut mem = normal();
        put32(&mut mem, INFO + 12, 1);
        assert_eq!(parse_mem(&mem).unwrap_err(), Error::ModulesUnsupported);
        let mut mem = normal();
        put32(&mut mem, INFO + 48, 129);
        assert_eq!(parse_mem(&mem).unwrap_err(), Error::BadEntryCount);
    }
    #[test]
    fn reserves_firmware_data_inside_heap_and_rounds_inward() {
        let mut mem = normal();
        let cmdline = HEAP_FLOOR + PAGE + 3;
        put64(&mut mem, INFO + 24, cmdline);
        let parsed = parse(INFO as u64, |pa, out| {
            if pa == cmdline {
                out.fill(0);
                return Ok(());
            }
            let start = usize::try_from(pa).unwrap();
            out.copy_from_slice(mem.get(start..start + out.len()).ok_or(Error::BadPointer)?);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            parsed.heap.as_slice(),
            &[
                HEAP_FLOOR..HEAP_FLOOR + PAGE,
                HEAP_FLOOR + 2 * PAGE..0x4000000
            ]
        );
    }
    #[test]
    fn reserves_start_info_and_memory_map_even_when_firmware_places_them_above_image() {
        let mut mem = normal();
        let info_pa = HEAP_FLOOR + 3;
        let table_pa = HEAP_FLOOR + 2 * PAGE + 5;
        put64(&mut mem, INFO + 40, table_pa);
        let parsed = parse(info_pa, |pa, out| {
            let start = if pa >= table_pa && pa < table_pa + 2 * ENTRY_SIZE as u64 {
                TABLE + usize::try_from(pa - table_pa).unwrap()
            } else if pa == info_pa {
                INFO
            } else {
                return Err(Error::BadPointer);
            };
            out.copy_from_slice(&mem[start..start + out.len()]);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            parsed.heap.as_slice(),
            &[
                HEAP_FLOOR + PAGE..HEAP_FLOOR + 2 * PAGE,
                HEAP_FLOOR + 3 * PAGE..0x4000000,
            ]
        );
    }

    #[test]
    fn no_allocatable_pages_is_an_error_not_an_empty_heap() {
        let mut mem = fixture(&[(0x100000, HEAP_FLOOR + PAGE - 0x100000, 1)]);
        put64(&mut mem, INFO + 24, HEAP_FLOOR);
        let result = parse(INFO as u64, |pa, out| {
            if (HEAP_FLOOR..HEAP_FLOOR + PAGE).contains(&pa) {
                out[0] = u8::from(pa != HEAP_FLOOR + PAGE - 1);
                return Ok(());
            }
            let start = usize::try_from(pa).unwrap();
            out.copy_from_slice(mem.get(start..start + out.len()).ok_or(Error::BadPointer)?);
            Ok(())
        });
        assert_eq!(result.unwrap_err(), Error::NoHeap);
    }

    #[test]
    fn rejects_null_or_out_of_bounds_reads_and_unterminated_strings() {
        assert_eq!(
            parse(0, |_, _| panic!("must not read null")).unwrap_err(),
            Error::BadPointer
        );
        let mut mem = normal();
        put64(&mut mem, INFO + 40, MAPPED_LIMIT - 1);
        assert_eq!(parse_mem(&mem).unwrap_err(), Error::BadPointer);
        let mut mem = normal();
        put64(&mut mem, INFO + 24, 0x3000);
        mem[0x3000..0x4000].fill(1);
        assert_eq!(parse_mem(&mem).unwrap_err(), Error::UnterminatedCommandLine);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ACPI tables, from an x86 PC's firmware: the local APIC IDs of the enabled
//! processors in the MADT ([`cpus`]), and how to power off from the FADT and
//! the DSDT ([`soft_off`]), found from the RSDP (which the BIOS leaves in its
//! areas below 1 MiB). Lengths and checksums are checked before anything is
//! read past a header: a bad table is an error, not a panic. As in Linux,
//! trailing bytes too few for another entry are ignored.

use crate::interrupt::{VGA_MEMORY, X2APIC_BROADCAST, XAPIC_BROADCAST};
use crate::power::SoftOff;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::ops::Range;
use zerocopy::FromBytes;

/// Tables longer than this are not believed.
const MAX_TABLE_LEN: usize = 1 << 20;
/// Nor RSDPs longer than this (ACPI 2.0 and on: 36 bytes).
const MAX_RSDP_LEN: usize = 0x100;

/// The BIOS data area, whose word at `EBDA_SEGMENT` is the EBDA's segment.
const BDA: u64 = 0x400;
const EBDA_SEGMENT: u64 = 0x40e;
/// The BIOS's area below 1 MiB, where it may leave the RSDP.
const BIOS_AREA: Range<u64> = 0xe_0000..0x10_0000;

/// Physical memory, which the tables are read from.
pub trait Memory {
    /// Physical `pa..pa + len`; an error if it cannot be read.
    fn bytes(&self, pa: u64, len: usize) -> Result<&[u8], &'static str>;
}

/// Physical memory below `limit`, mapped at `PA + offset`, e.g., a boot
/// mapping of the low 4 GiB, where the firmware's tables are, while it
/// lasts. They are read as `&[u8]`: the firmware is trusted to point only at
/// its own.
pub struct MappedMemory {
    offset: u64,
    limit: u64,
}

impl MappedMemory {
    /// # Safety
    ///
    /// While the result lives, physical `0..limit` is mapped readable at
    /// `PA + offset`, where that is an address (not 0, nor past the end of
    /// the address space, which [`Memory::bytes`] refuses), and nothing
    /// writes what is read through it: the firmware's tables and areas.
    pub unsafe fn new(offset: u64, limit: u64) -> Self {
        Self { offset, limit }
    }
}

impl Memory for MappedMemory {
    fn bytes(&self, pa: u64, len: usize) -> Result<&[u8], &'static str> {
        let end = u64::try_from(len).ok().and_then(|len| pa.checked_add(len));
        if end.is_none_or(|end| end > self.limit) {
            return Err("ACPI table outside the mapped memory");
        }
        if len == 0 {
            return Ok(&[]);
        }
        let va = pa
            .checked_add(self.offset)
            .and_then(|va| usize::try_from(va).ok())
            .filter(|&va| va != 0 && isize::try_from(len).is_ok() && va.checked_add(len).is_some())
            .ok_or("ACPI table outside the address space")?;
        // Safety: below `limit` (checked above), so mapped, and unchanged
        // while `self`, which the slice borrows, lives (`new`'s contract); not
        // null, and the `len` bytes neither wrap nor exceed `isize::MAX`.
        Ok(unsafe { core::slice::from_raw_parts(va as *const u8, len) })
    }
}

/// The Root System Description Pointer's ACPI 1.0 part, which its checksum
/// covers.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// The whole RSDP, from ACPI 2.0 (revision 2) on, which its extended
/// checksum covers.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes)]
struct Rsdp {
    v1: RsdpV1,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

const RSDP_V1_LEN: usize = size_of::<RsdpV1>();
const _: () = assert!(RSDP_V1_LEN == 20 && size_of::<Rsdp>() == 36);

/// System Description Table header.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// The MADT's entries follow the header, the local APIC address, and flags.
const MADT_ENTRIES: usize = size_of::<SdtHeader>() + 8;
/// MADT entry types, and their `flags` bit for an enabled processor.
const MADT_LOCAL_APIC: u8 = 0;
const MADT_LOCAL_X2APIC: u8 = 9;
const MADT_ENABLED: u32 = 1;

/// A MADT entry of type [`MADT_LOCAL_APIC`] (later versions' may be longer).
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes)]
struct MadtLocalApic {
    kind: u8,
    len: u8,
    processor_uid: u8,
    apic_id: u8,
    flags: u32,
}

/// A MADT entry of type [`MADT_LOCAL_X2APIC`] (later versions' may be
/// longer).
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes)]
struct MadtLocalX2apic {
    kind: u8,
    len: u8,
    reserved: u16,
    apic_id: u32,
    flags: u32,
    processor_uid: u32,
}

/// The local APIC IDs of the enabled processors in the MADT, the calling
/// (boot) CPU's (`boot_apic_id`) first, then in the MADT's order. `rsdp` is
/// the RSDP's address if the boot protocol gives one (PVH's 0 is `None`);
/// otherwise it is searched for where the BIOS leaves it. IDs from 0xff up
/// (x2APIC entries') are beyond an xAPIC's IPIs (see
/// [`LocalApic::send_startup_ipi`](crate::interrupt::LocalApic::send_startup_ipi)):
/// in xAPIC mode, those CPUs cannot be started.
pub fn cpus(
    memory: &impl Memory,
    rsdp: Option<u64>,
    boot_apic_id: u32,
) -> Result<Vec<u32>, &'static str> {
    let madt = find_table(memory, rsdp, *b"APIC", "no MADT")?;
    let mut apic_ids = madt_apic_ids(madt)?;
    let boot = apic_ids
        .iter()
        .position(|&id| id == boot_apic_id)
        .ok_or("the boot CPU is not in the MADT")?;
    apic_ids[..=boot].rotate_right(1);
    Ok(apic_ids)
}

/// The first good table with `signature` that the root table lists, else
/// the last one's error, or `missing` if it lists none. The root table is
/// the RSDP's at `rsdp` (if the boot protocol gives one: PVH's 0 is `None`),
/// else where the BIOS leaves it.
fn find_table<'m>(
    memory: &'m impl Memory,
    rsdp: Option<u64>,
    signature: [u8; 4],
    missing: &'static str,
) -> Result<&'m [u8], &'static str> {
    let rsdp = match rsdp {
        Some(rsdp) => rsdp,
        None => find_rsdp(memory)?,
    };
    let (root, entry_len, root_signature) = root_table(memory, rsdp)?;
    table(memory, root, root_signature)?[size_of::<SdtHeader>()..]
        .chunks_exact(entry_len)
        .map(|entry| {
            let mut address = [0; 8];
            address[..entry_len].copy_from_slice(entry);
            u64::from_le_bytes(address)
        })
        // Firmware may leave null entries (ACPICA skips them too).
        .filter(|&pa| pa != 0)
        .filter(|&pa| {
            read::<SdtHeader>(memory, pa).is_ok_and(|header| header.signature == signature)
        })
        .map(|pa| table(memory, pa, signature))
        .reduce(Result::or)
        .unwrap_or(Err(missing))
}

/// The enabled processors' local APIC IDs in `madt`, without repeats (one
/// may have both kinds of entry). As in Linux, with local APIC entries,
/// x2APIC ones count only from ID 0xff up: ACPI gives the IDs below local
/// APIC entries.
fn madt_apic_ids(madt: &[u8]) -> Result<Vec<u32>, &'static str> {
    // (from an x2APIC entry, flags, ID), in order.
    let mut processors = Vec::new();
    let mut rest = madt.get(MADT_ENTRIES..).ok_or("truncated MADT")?;
    // An entry is more than its 2-byte header.
    while let [kind, len, _, ..] = *rest {
        let len = usize::from(len);
        let entry = rest
            .get(..len)
            .filter(|_| len >= 2)
            .ok_or("bad MADT entry")?;
        rest = &rest[len..];
        let short = "short MADT processor entry";
        processors.push(match kind {
            MADT_LOCAL_APIC => {
                let (cpu, _) = MadtLocalApic::read_from_prefix(entry).map_err(|_| short)?;
                (false, cpu.flags, u32::from(cpu.apic_id))
            }
            MADT_LOCAL_X2APIC => {
                let (cpu, _) = MadtLocalX2apic::read_from_prefix(entry).map_err(|_| short)?;
                (true, cpu.flags, cpu.apic_id)
            }
            _ => continue,
        });
    }
    let local_apics = processors.iter().any(|&(x2apic, ..)| !x2apic);
    let mut seen = BTreeSet::new();
    Ok(processors
        .into_iter()
        .filter(|&(x2apic, flags, id)| {
            // The broadcast IDs are no processor's.
            let valid = if x2apic {
                id != X2APIC_BROADCAST && (id >= XAPIC_BROADCAST || !local_apics)
            } else {
                id != XAPIC_BROADCAST
            };
            valid && flags & MADT_ENABLED != 0
        })
        .map(|(.., id)| id)
        .filter(|&id| seen.insert(id))
        .collect())
}

/// FADT fields' offsets (ACPI 6.5, table 5.9), and its flag for
/// hardware-reduced ACPI. Earlier revisions' FADTs end sooner.
mod fadt {
    pub const DSDT: usize = 40;
    pub const PM1A_CNT_BLK: usize = 64;
    pub const PM1B_CNT_BLK: usize = 68;
    pub const FLAGS: usize = 112;
    pub const X_DSDT: usize = 140;
    pub const X_PM1A_CNT_BLK: usize = 172;
    pub const X_PM1B_CNT_BLK: usize = 184;
    pub const SLEEP_CONTROL_REG: usize = 244;

    pub const HW_REDUCED_ACPI: u32 = 1 << 20;
}

/// A Generic Address Structure: a register's address.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes)]
struct GenericAddress {
    space_id: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64,
}

/// [`GenericAddress::space_id`] of I/O ports.
const SYSTEM_IO: u8 = 1;

/// The sleep control register's sleep type field and enable bit.
const SLEEP_TYPE_SHIFT: u8 = 2;
const SLEEP_TYPE: u8 = 0b111 << SLEEP_TYPE_SHIFT;
const SLEEP_ENABLE: u8 = 1 << 5;

/// How to enter the S5 sleep state (soft off), as ACPICA does: with
/// hardware-reduced ACPI (e.g., Cloud Hypervisor), through the FADT's sleep
/// control register, else (e.g., QEMU) its PM1 control registers; with the
/// sleep types of the DSDT's `\_S5`. `rsdp` is the RSDP's address if the
/// boot protocol gives one (PVH's 0 is `None`); otherwise it is searched for
/// where the BIOS leaves it. Only I/O-port registers are supported.
pub fn soft_off(memory: &impl Memory, rsdp: Option<u64>) -> Result<SoftOff, &'static str> {
    let fadt = find_table(memory, rsdp, *b"FACP", "no FADT")?;
    // The 64-bit address where set, as ACPICA prefers it.
    let dsdt = field::<u64>(fadt, fadt::X_DSDT)
        .filter(|&pa| pa != 0)
        .or_else(|| field::<u32>(fadt, fadt::DSDT).map(u64::from))
        .filter(|&pa| pa != 0)
        .ok_or("no DSDT")?;
    let (type_a, type_b) = s5_sleep_types(table(memory, dsdt, *b"DSDT")?)?;
    let flags = field::<u32>(fadt, fadt::FLAGS).unwrap_or(0);
    if flags & fadt::HW_REDUCED_ACPI != 0 {
        let port = field::<GenericAddress>(fadt, fadt::SLEEP_CONTROL_REG)
            .and_then(io_port)
            .ok_or("no sleep control register at an I/O port")?;
        let value = ((type_a << SLEEP_TYPE_SHIFT) & SLEEP_TYPE) | SLEEP_ENABLE;
        return Ok(SoftOff::SleepControl { port, value });
    }
    let a = pm1_port(fadt, fadt::X_PM1A_CNT_BLK, fadt::PM1A_CNT_BLK)?
        .ok_or("no PM1a control register")?;
    let b = pm1_port(fadt, fadt::X_PM1B_CNT_BLK, fadt::PM1B_CNT_BLK)?;
    Ok(SoftOff::Pm1 {
        a: (a, type_a),
        b: b.map(|b| (b, type_b)),
    })
}

/// The I/O port of the PM1 control register at the FADT's `extended`
/// address, where set (as ACPICA prefers it), else at its `legacy` one;
/// `None` if neither is.
fn pm1_port(fadt: &[u8], extended: usize, legacy: usize) -> Result<Option<u16>, &'static str> {
    const NOT_IO: &str = "PM1 control register not at an I/O port";
    match field::<GenericAddress>(fadt, extended) {
        Some(register) if { register.address } != 0 => io_port(register).map(Some).ok_or(NOT_IO),
        _ => match field::<u32>(fadt, legacy).unwrap_or(0) {
            0 => Ok(None),
            port => u16::try_from(port).map(Some).map_err(|_| NOT_IO),
        },
    }
}

/// The I/O port that `register` names, if it names one, from its first bit.
fn io_port(register: GenericAddress) -> Option<u16> {
    let GenericAddress {
        space_id,
        bit_offset,
        address,
        ..
    } = register;
    if space_id != SYSTEM_IO || bit_offset != 0 {
        return None;
    }
    u16::try_from(address).ok().filter(|&port| port != 0)
}

/// The field at `offset` of `table`, if the table is long enough for it.
fn field<T: FromBytes>(table: &[u8], offset: usize) -> Option<T> {
    let (value, _) = T::read_from_prefix(table.get(offset..)?).ok()?;
    Some(value)
}

/// AML opcodes, for [`s5_sleep_types`].
mod aml {
    pub const NAME: u8 = 0x08;
    pub const ROOT: u8 = b'\\';
    pub const PACKAGE: u8 = 0x12;
    pub const ZERO: u8 = 0x00;
    pub const ONE: u8 = 0x01;
    pub const BYTE: u8 = 0x0a;
    pub const WORD: u8 = 0x0b;
    pub const DWORD: u8 = 0x0c;
    pub const QWORD: u8 = 0x0e;
}

/// The S5 sleep types (`SLP_TYPa`, `SLP_TYPb`, 3 bits each) of the `DSDT`,
/// without an AML interpreter, as small kernels find them: from the first
/// `Name (_S5, Package () {...})` (maybe with a root prefix) whose first
/// elements are integer constants. As in ACPICA, a package of one element
/// holds both types, `SLP_TYPa` in its low byte and `SLP_TYPb` in the next.
fn s5_sleep_types(dsdt: &[u8]) -> Result<(u8, u8), &'static str> {
    let aml = &dsdt[size_of::<SdtHeader>()..];
    (1..aml.len())
        .filter(|&at| {
            aml[at..].starts_with(b"_S5_")
                && (aml[at - 1] == aml::NAME
                    || at >= 2 && aml[at - 2..at] == [aml::NAME, aml::ROOT])
        })
        .find_map(|at| s5_package(&aml[at + 4..]))
        .ok_or("no \\_S5 package in the DSDT")
}

/// The sleep types of the package at the start of `aml`; see
/// [`s5_sleep_types`].
fn s5_package(aml: &[u8]) -> Option<(u8, u8)> {
    let (&aml::PACKAGE, rest) = aml.split_first()? else {
        return None;
    };
    // `PkgLength`: bits 7:6 of its first byte count the bytes that follow.
    let rest = rest.get(1 + usize::from(rest.first()? >> 6)..)?;
    let (&elements, mut rest) = rest.split_first()?;
    // As ACPICA, which rejects an empty package.
    if elements == 0 {
        return None;
    }
    let a = integer(&mut rest)?;
    let b = if elements >= 2 {
        integer(&mut rest)?
    } else {
        a >> 8
    };
    let sleep_type = |value: u64| value.to_le_bytes()[0] & 0b111;
    Some((sleep_type(a), sleep_type(b)))
}

/// The integer constant at the start of `aml`, which it then skips.
fn integer(aml: &mut &[u8]) -> Option<u64> {
    let (&opcode, rest) = aml.split_first()?;
    let len = match opcode {
        aml::ZERO | aml::ONE => 0,
        aml::BYTE => 1,
        aml::WORD => 2,
        aml::DWORD => 4,
        aml::QWORD => 8,
        _ => return None,
    };
    let mut bytes = [0; 8];
    bytes[..len].copy_from_slice(rest.get(..len)?);
    *aml = &rest[len..];
    Some(if opcode == aml::ONE {
        1
    } else {
        u64::from_le_bytes(bytes)
    })
}

/// The root table (RSDT or XSDT) of the RSDP at `rsdp`, checked as ACPICA
/// does (the ACPI 1.0 checksum, and the extended one from revision 2 on):
/// its address, entry length, and signature.
fn root_table(memory: &impl Memory, rsdp: u64) -> Result<(u64, usize, [u8; 4]), &'static str> {
    let v1: RsdpV1 = read(memory, rsdp)?;
    if v1.signature != *b"RSD PTR " || sum(memory.bytes(rsdp, RSDP_V1_LEN)?) != 0 {
        return Err("bad RSDP");
    }
    let mut root = (u64::from(v1.rsdt_address), size_of::<u32>(), *b"RSDT");
    if v1.revision >= 2 {
        let v2: Rsdp = read(memory, rsdp)?;
        // The ACPI 1.0 checksum covers neither the length nor the XSDT's
        // address.
        let len = usize::try_from(v2.length).unwrap_or(usize::MAX);
        if !(size_of::<Rsdp>()..=MAX_RSDP_LEN).contains(&len) || sum(memory.bytes(rsdp, len)?) != 0
        {
            return Err("bad RSDP");
        }
        if v2.xsdt_address != 0 {
            root = (v2.xsdt_address, size_of::<u64>(), *b"XSDT");
        }
    }
    if root.0 == 0 {
        return Err("no RSDT");
    }
    Ok(root)
}

/// Where the BIOS left the RSDP: in the EBDA's first KiB, or in
/// [`BIOS_AREA`], on a 16-byte boundary. As in ACPICA, only an EBDA between
/// the BIOS data area and VGA memory counts, cut short at VGA memory, and
/// only if it can be read; and only an RSDP that [`root_table`] takes.
fn find_rsdp(memory: &impl Memory) -> Result<u64, &'static str> {
    let ebda = u64::from(read::<u16>(memory, EBDA_SEGMENT)?) << 4;
    if (BDA + 1..VGA_MEMORY.start).contains(&ebda)
        && let Ok(Some(rsdp)) = rsdp_in(memory, ebda..(ebda + 0x400).min(VGA_MEMORY.start))
    {
        return Ok(rsdp);
    }
    rsdp_in(memory, BIOS_AREA)?.ok_or("no RSDP")
}

/// The first RSDP that [`root_table`] takes in physical `area` (below
/// 1 MiB), on a 16-byte boundary.
fn rsdp_in(memory: &impl Memory, area: Range<u64>) -> Result<Option<u64>, &'static str> {
    let len = usize::try_from(area.end - area.start).expect("below 1 MiB");
    let bytes = memory.bytes(area.start, len)?;
    Ok((0..len)
        .step_by(16)
        .filter(|&offset| bytes[offset..].starts_with(b"RSD PTR "))
        .map(|offset| area.start + offset as u64)
        .find(|&rsdp| root_table(memory, rsdp).is_ok()))
}

/// The table at `pa` with `signature`, its length and checksum checked.
fn table(memory: &impl Memory, pa: u64, signature: [u8; 4]) -> Result<&[u8], &'static str> {
    let header: SdtHeader = read(memory, pa)?;
    let len = usize::try_from(header.length).unwrap_or(usize::MAX);
    if header.signature != signature || !(size_of::<SdtHeader>()..=MAX_TABLE_LEN).contains(&len) {
        return Err("bad ACPI table header");
    }
    let table = memory.bytes(pa, len)?;
    if sum(table) != 0 {
        return Err("bad ACPI table checksum");
    }
    Ok(table)
}

fn sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |sum, &byte| sum.wrapping_add(byte))
}

fn read<T: FromBytes>(memory: &impl Memory, pa: u64) -> Result<T, &'static str> {
    T::read_from_bytes(memory.bytes(pa, size_of::<T>())?).map_err(|_| "unreachable: sized")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Memory from physical address 0, as long as `bytes`.
    struct Image(Vec<u8>);

    impl Memory for Image {
        fn bytes(&self, pa: u64, len: usize) -> Result<&[u8], &'static str> {
            usize::try_from(pa)
                .ok()
                .and_then(|start| self.0.get(start..start.checked_add(len)?))
                .ok_or("outside the image")
        }
    }

    impl Image {
        fn put(&mut self, pa: u64, bytes: &[u8]) {
            let pa = usize::try_from(pa).unwrap();
            self.0[pa..pa + bytes.len()].copy_from_slice(bytes);
        }
    }

    const RSDP: u64 = 0x100;
    const OTHER: u64 = 0x200;
    const ROOT: u64 = 0x300;
    const MADT: u64 = 0x400;

    /// Sets the byte at `at` so that `bytes` sum to 0.
    fn checksum(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        bytes[at] = 0u8.wrapping_sub(sum(bytes));
    }

    fn sdt(signature: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut table = vec![0; size_of::<SdtHeader>()];
        table[..4].copy_from_slice(&signature);
        table.extend_from_slice(body);
        let len = u32::try_from(table.len()).unwrap();
        table[4..8].copy_from_slice(&len.to_le_bytes());
        checksum(&mut table, 9);
        table
    }

    /// An ACPI 2.0 RSDP with an XSDT at `ROOT`, or with `revision` 0, one
    /// with an RSDT there.
    fn rsdp(revision: u8) -> Vec<u8> {
        let mut rsdp = vec![0; size_of::<Rsdp>()];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = revision;
        let root = u32::try_from(ROOT).unwrap();
        if revision < 2 {
            rsdp[16..20].copy_from_slice(&root.to_le_bytes());
        } else {
            rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
            rsdp[24..32].copy_from_slice(&ROOT.to_le_bytes());
        }
        checksum(&mut rsdp[..RSDP_V1_LEN], 8);
        checksum(&mut rsdp, 32);
        rsdp
    }

    fn local_apic(id: u8, flags: u32) -> Vec<u8> {
        let mut entry = vec![MADT_LOCAL_APIC, 8, 0, id];
        entry.extend_from_slice(&flags.to_le_bytes());
        entry
    }

    fn x2apic(id: u32, flags: u32) -> Vec<u8> {
        let mut entry = vec![MADT_LOCAL_X2APIC, 16, 0, 0];
        entry.extend_from_slice(&id.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry.extend_from_slice(&0u32.to_le_bytes());
        entry
    }

    fn madt(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![0; MADT_ENTRIES - size_of::<SdtHeader>()];
        for entry in entries {
            body.extend_from_slice(entry);
        }
        sdt(*b"APIC", &body)
    }

    /// The RSDP of `revision` (see [`rsdp`]), its root table listing another
    /// table, then `madt`.
    fn image(revision: u8, madt: &[u8]) -> Image {
        let mut image = Image(vec![0; 0x1000]);
        image.put(RSDP, &rsdp(revision));
        image.put(OTHER, &sdt(*b"FACP", &[]));
        let mut entries = Vec::new();
        for table in [OTHER, MADT] {
            if revision < 2 {
                entries.extend_from_slice(&u32::try_from(table).unwrap().to_le_bytes());
            } else {
                entries.extend_from_slice(&table.to_le_bytes());
            }
        }
        let signature = if revision < 2 { *b"RSDT" } else { *b"XSDT" };
        image.put(ROOT, &sdt(signature, &entries));
        image.put(MADT, madt);
        image
    }

    const ENABLED: u32 = MADT_ENABLED;

    #[test]
    fn enabled_processors_boot_cpu_first() {
        let madt = madt(&[
            local_apic(0, ENABLED),
            // An I/O APIC.
            vec![1, 12, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0],
            local_apic(1, ENABLED),
            local_apic(2, 0),
            // With local APIC entries, below 0xff: not taken (as by Linux).
            x2apic(2, ENABLED),
            x2apic(1, ENABLED),
            x2apic(0x100, ENABLED),
            x2apic(3, 0),
            // xAPIC's broadcast ID, but a valid x2APIC ID (which an xAPIC
            // cannot address alone).
            local_apic(0xff, ENABLED),
            x2apic(0xff, ENABLED),
            x2apic(u32::MAX, ENABLED),
        ]);
        for revision in [0, 2] {
            let image = image(revision, &madt);
            assert_eq!(cpus(&image, Some(RSDP), 0), Ok(vec![0, 1, 0x100, 0xff]));
            assert_eq!(cpus(&image, Some(RSDP), 1), Ok(vec![1, 0, 0x100, 0xff]));
            assert_eq!(cpus(&image, Some(RSDP), 0xff), Ok(vec![0xff, 0, 1, 0x100]));
            assert_eq!(
                cpus(&image, Some(RSDP), 2),
                Err("the boot CPU is not in the MADT"),
                "disabled"
            );
            assert_eq!(
                cpus(&image, Some(RSDP), u32::MAX),
                Err("the boot CPU is not in the MADT")
            );
        }
    }

    #[test]
    fn an_acpi_2_rsdp_without_xsdt_has_the_rsdt() {
        let madt = madt(&[local_apic(0, ENABLED), local_apic(1, ENABLED)]);
        let mut image = image(0, &madt);
        let mut rsdp = rsdp(2);
        rsdp[16..20].copy_from_slice(&u32::try_from(ROOT).unwrap().to_le_bytes());
        rsdp[24..32].fill(0);
        checksum(&mut rsdp[..RSDP_V1_LEN], 8);
        checksum(&mut rsdp, 32);
        image.put(RSDP, &rsdp);
        assert_eq!(cpus(&image, Some(RSDP), 1), Ok(vec![1, 0]));
        // Its extended checksum is still checked.
        image.0[usize::try_from(RSDP).unwrap() + 33] ^= 1;
        assert_eq!(cpus(&image, Some(RSDP), 1), Err("bad RSDP"));
    }

    #[test]
    fn an_rsdp_without_root_table() {
        let mut image = image(0, &madt(&[local_apic(0, ENABLED)]));
        let mut rsdp = rsdp(0);
        rsdp[16..20].fill(0);
        checksum(&mut rsdp[..RSDP_V1_LEN], 8);
        image.put(RSDP, &rsdp);
        assert_eq!(cpus(&image, Some(RSDP), 0), Err("no RSDT"));
    }

    #[test]
    fn an_acpi_1_rsdp_is_only_20_bytes() {
        let mut image = image(0, &madt(&[local_apic(0, ENABLED)]));
        // At the very end of the memory.
        let at = image.0.len() - RSDP_V1_LEN;
        image.0[at..].copy_from_slice(&rsdp(0)[..RSDP_V1_LEN]);
        assert_eq!(cpus(&image, Some(at as u64), 0), Ok(vec![0]));
    }

    #[test]
    fn root_tables_skip_null_partial_and_bad_entries() {
        const BAD_MADT: u64 = 0x600;
        let madt = madt(&[local_apic(0, ENABLED)]);
        let root = |tables: &[u64], tail: &[u8]| {
            let mut image = image(2, &madt);
            let mut bad = madt.clone();
            bad[9] ^= 1;
            image.put(BAD_MADT, &bad);
            let mut entries: Vec<u8> = tables.iter().flat_map(|pa| pa.to_le_bytes()).collect();
            entries.extend_from_slice(tail);
            image.put(ROOT, &sdt(*b"XSDT", &entries));
            cpus(&image, Some(RSDP), 0)
        };
        assert_eq!(root(&[0, OTHER, MADT], &[]), Ok(vec![0]));
        assert_eq!(root(&[OTHER, MADT], &[0; 4]), Ok(vec![0]));
        // The first good MADT, else the last one's error.
        assert_eq!(root(&[BAD_MADT, MADT], &[]), Ok(vec![0]));
        assert_eq!(root(&[BAD_MADT], &[]), Err("bad ACPI table checksum"));
    }

    #[test]
    fn mapped_memory_is_read_below_its_limit() {
        let ram: Vec<u8> = (0..16).collect();
        // Safety: `ram`, which nothing writes, is physical `0..16` here and
        // outlives `memory`.
        let memory = unsafe { MappedMemory::new(ram.as_ptr() as u64, 16) };
        assert_eq!(memory.bytes(0, 16), Ok(&ram[..]));
        assert_eq!(memory.bytes(15, 1), Ok(&ram[15..]));
        assert_eq!(memory.bytes(16, 0), Ok(&[][..]));
        let outside = Err("ACPI table outside the mapped memory");
        assert_eq!(memory.bytes(15, 2), outside);
        assert_eq!(memory.bytes(16, 1), outside);
        assert_eq!(memory.bytes(u64::MAX, 1), outside, "overflows");
        assert_eq!(memory.bytes(1, usize::MAX), outside, "overflows");
    }

    #[test]
    fn mapped_memory_refuses_null_and_wrapping_addresses() {
        let refused = Err("ACPI table outside the address space");
        // Safety: nothing is read: the only bytes asked for, but none, are at
        // address 0, which `bytes` refuses.
        let identity = unsafe { MappedMemory::new(0, 0x1000) };
        assert_eq!(identity.bytes(0, 0), Ok(&[][..]));
        assert_eq!(identity.bytes(0, 1), refused);
        // Safety: nothing is read: every address would wrap, which `bytes`
        // refuses.
        let wrapping = unsafe { MappedMemory::new(u64::MAX - 0xf, 0x1000) };
        assert_eq!(wrapping.bytes(0x10, 1), refused);
        assert_eq!(wrapping.bytes(0, 0x11), refused);
    }

    #[test]
    fn bad_checksums() {
        let madt = madt(&[local_apic(0, ENABLED)]);
        let good = image(2, &madt);
        assert_eq!(cpus(&good, Some(RSDP), 0), Ok(vec![0]));
        for (at, error) in [
            (RSDP + 9, "bad RSDP"),
            // Only the extended checksum covers the XSDT's address.
            (RSDP + 24, "bad RSDP"),
            (ROOT + 40, "bad ACPI table checksum"),
            (MADT + 44, "bad ACPI table checksum"),
        ] {
            let mut image = image(2, &madt);
            image.0[usize::try_from(at).unwrap()] ^= 1;
            assert_eq!(cpus(&image, Some(RSDP), 0), Err(error), "at {at:#x}");
        }
    }

    #[test]
    fn lengths_are_checked_before_reading() {
        let madt = madt(&[local_apic(0, ENABLED)]);
        let rsdp_len = |len: u32| {
            let mut image = image(2, &madt);
            let at = usize::try_from(RSDP).unwrap();
            image.0[at + 20..at + 24].copy_from_slice(&len.to_le_bytes());
            checksum(&mut image.0[at..at + MAX_RSDP_LEN], 32);
            cpus(&image, Some(RSDP), 0)
        };
        assert_eq!(rsdp_len(36), Ok(vec![0]));
        assert_eq!(rsdp_len(64), Ok(vec![0]), "a longer one");
        assert_eq!(rsdp_len(35), Err("bad RSDP"));
        // Not read: not "outside the image".
        assert_eq!(rsdp_len(0x8000_0000), Err("bad RSDP"));
        assert_eq!(rsdp_len(u32::MAX), Err("bad RSDP"));

        let table_len = |pa: u64, len: u32| {
            let mut image = image(2, &madt);
            let at = usize::try_from(pa).unwrap();
            image.0[at + 4..at + 8].copy_from_slice(&len.to_le_bytes());
            cpus(&image, Some(RSDP), 0)
        };
        assert_eq!(table_len(ROOT, 35), Err("bad ACPI table header"));
        assert_eq!(table_len(MADT, 35), Err("bad ACPI table header"));
        assert_eq!(table_len(MADT, u32::MAX), Err("bad ACPI table header"));
        assert_eq!(table_len(MADT, 0x10_0000), Err("outside the image"));
        // A MADT too short for its fixed fields.
        assert_eq!(table_len(MADT, 40), Err("bad ACPI table checksum"));
        let short = sdt(*b"APIC", &[0; 4]);
        assert_eq!(
            cpus(&image(2, &short), Some(RSDP), 0),
            Err("truncated MADT")
        );

        let mut image = image(2, &madt);
        image.0.truncate(usize::try_from(MADT).unwrap() + 20);
        assert_eq!(cpus(&image, Some(RSDP), 0), Err("no MADT"));
        assert_eq!(cpus(&image, Some(0xff8), 0), Err("outside the image"));
    }

    #[test]
    fn bad_madt_entries() {
        let entries = |entries: &[Vec<u8>]| madt_apic_ids(&madt(entries));
        let cpu = local_apic(0, ENABLED);
        assert_eq!(entries(&[]), Ok(vec![]));
        assert_eq!(entries(core::slice::from_ref(&cpu)), Ok(vec![0]));
        for bad in [
            vec![2, 0, 0, 0],
            vec![2, 1, 0, 0],
            // Truncated.
            vec![2, 8, 0, 0],
            vec![MADT_LOCAL_APIC, 9, 0, 1, 1, 0, 0, 0],
        ] {
            assert_eq!(
                entries(&[cpu.clone(), bad.clone()]),
                Err("bad MADT entry"),
                "{bad:?}"
            );
        }
        for short in [
            vec![MADT_LOCAL_APIC, 6, 0, 1, 1, 0],
            vec![MADT_LOCAL_X2APIC, 12, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],
        ] {
            assert_eq!(
                entries(&[cpu.clone(), short]),
                Err("short MADT processor entry")
            );
        }
        // So are trailing bytes too few for an entry (as for Linux).
        assert_eq!(entries(&[cpu.clone(), vec![2]]), Ok(vec![0]));
        assert_eq!(entries(&[cpu.clone(), vec![0, 0]]), Ok(vec![0]));
        // Without local APIC entries, x2APIC ones are taken below 0xff too.
        let x2apics = [x2apic(0, ENABLED), x2apic(2, ENABLED)];
        assert_eq!(entries(&x2apics), Ok(vec![0, 2]));
        // Longer entries (later ACPI versions) are fine.
        let mut long = local_apic(1, ENABLED);
        long.extend_from_slice(&[0; 4]);
        long[1] = 12;
        assert_eq!(entries(&[cpu, long]), Ok(vec![0, 1]));
    }

    #[test]
    fn rsdp_is_found_where_the_bios_leaves_it() {
        let mut image = Image(vec![0; 0x10_0000]);
        assert_eq!(find_rsdp(&image), Err("no RSDP"));
        // In the EBDA: its segment is at 0x40e.
        image.put(0x40e, &0x9fc0u16.to_le_bytes());
        image.put(0x9_fc10, &rsdp(2));
        assert_eq!(find_rsdp(&image), Ok(0x9_fc10));
        // Unaligned, or with a bad checksum (either), it is not.
        image.put(0x9_fc10, &[0; 36]);
        image.put(0x9_fc18, &rsdp(2));
        let mut bad = rsdp(2);
        bad[32] ^= 1;
        image.put(0x9_fc40, &bad);
        let mut bad = rsdp(0);
        bad[8] ^= 1;
        image.put(0xe_0000, &bad);
        image.put(0xf_fff0, &rsdp(0)[..16]);
        assert_eq!(find_rsdp(&image), Err("no RSDP"));
        image.put(0xe_1230, &rsdp(0));
        assert_eq!(find_rsdp(&image), Ok(0xe_1230));
        // Without an EBDA.
        image.put(0x40e, &[0, 0]);
        assert_eq!(find_rsdp(&image), Ok(0xe_1230));
        // Nor in VGA memory: an EBDA there, or past the memory, is ignored,
        // and one just below is cut short.
        image.put(0xa_0000, &rsdp(0));
        for segment in [0xa000u16, 0xffff, 0x9ff0] {
            image.put(0x40e, &segment.to_le_bytes());
            assert_eq!(find_rsdp(&image), Ok(0xe_1230), "{segment:#x}");
        }
        // Outside the memory.
        image.0.truncate(0xf_0000);
        assert_eq!(find_rsdp(&image), Err("outside the image"));
    }

    const FADT: u64 = 0x600;
    const DSDT: u64 = 0x800;

    /// A FADT `len` bytes long, with `fields` (offset, bytes) set.
    fn fadt_table(len: usize, fields: &[(usize, &[u8])]) -> Vec<u8> {
        let mut body = vec![0; len - size_of::<SdtHeader>()];
        for (offset, bytes) in fields {
            let at = offset - size_of::<SdtHeader>();
            body[at..at + bytes.len()].copy_from_slice(bytes);
        }
        sdt(*b"FACP", &body)
    }

    /// A generic address of the I/O port `port`, `bits` wide.
    fn io(port: u16, bits: u8) -> Vec<u8> {
        let mut register = vec![SYSTEM_IO, bits, 0, bits / 8];
        register.extend_from_slice(&u64::from(port).to_le_bytes());
        register
    }

    /// `Name (<prefix>_S5, <package>)` in AML.
    fn s5(prefix: &[u8], package: &[u8]) -> Vec<u8> {
        [prefix, b"_S5_", package].concat()
    }

    /// `Package () {<elements>}` in AML, with a 1-byte `PkgLength`.
    fn package(elements: &[&[u8]]) -> Vec<u8> {
        let body = elements.concat();
        let len = u8::try_from(2 + body.len()).unwrap();
        let count = u8::try_from(elements.len()).unwrap();
        [&[aml::PACKAGE, len, count][..], &body].concat()
    }

    /// The RSDP's XSDT listing `tables`, `fadt` at `FADT`, and a DSDT of
    /// `body` at `DSDT`.
    fn power_image(tables: &[u64], fadt: &[u8], body: &[u8]) -> Image {
        let mut image = image(2, &madt(&[local_apic(0, ENABLED)]));
        let entries: Vec<u8> = tables.iter().flat_map(|pa| pa.to_le_bytes()).collect();
        image.put(ROOT, &sdt(*b"XSDT", &entries));
        image.put(FADT, fadt);
        image.put(DSDT, &sdt(*b"DSDT", body));
        image
    }

    fn soft_off_of(fadt: &[u8], body: &[u8]) -> Result<SoftOff, &'static str> {
        soft_off(&power_image(&[MADT, FADT], fadt, body), Some(RSDP))
    }

    #[test]
    fn hardware_reduced_acpi_has_the_sleep_control_register() {
        // As Cloud Hypervisor's: `Name (_S5, Package () {5, 5, 0, 0})`.
        let five = [aml::BYTE, 5];
        let body = s5(
            &[aml::NAME],
            &package(&[&five, &five, &[aml::ZERO], &[aml::ZERO]]),
        );
        let with = |register: &[u8]| {
            let fadt = fadt_table(
                276,
                &[
                    (fadt::FLAGS, &fadt::HW_REDUCED_ACPI.to_le_bytes()),
                    (fadt::X_DSDT, &DSDT.to_le_bytes()),
                    // Ignored: hardware-reduced.
                    (fadt::X_PM1A_CNT_BLK, &io(0x610, 16)),
                    (fadt::SLEEP_CONTROL_REG, register),
                ],
            );
            soft_off_of(&fadt, &body)
        };
        assert_eq!(
            with(&io(0x600, 8)),
            Ok(SoftOff::SleepControl {
                port: 0x600,
                value: 0x34
            })
        );
        let none = Err("no sleep control register at an I/O port");
        assert_eq!(with(&[0; 12]), none);
        let mut memory = io(0x600, 8);
        memory[0] = 0;
        assert_eq!(with(&memory), none);
        let mut offset = io(0x600, 8);
        offset[2] = 1;
        assert_eq!(with(&offset), none);
    }

    #[test]
    fn other_acpi_has_the_pm1_control_registers() {
        // As QEMU's, in an ACPI 1.0 FADT: `Name (\_S5, Package () {0, 0, 0,
        // 0})`.
        let body = s5(&[aml::NAME, aml::ROOT], &package(&[&[aml::ZERO][..]; 4]));
        let dsdt = u32::try_from(DSDT).unwrap().to_le_bytes();
        let pm1a = 0x604u32.to_le_bytes();
        let fadt = fadt_table(116, &[(fadt::DSDT, &dsdt), (fadt::PM1A_CNT_BLK, &pm1a)]);
        assert_eq!(
            soft_off_of(&fadt, &body),
            Ok(SoftOff::Pm1 {
                a: (0x604, 0),
                b: None
            })
        );
        // Errors.
        let no_pm1 = fadt_table(116, &[(fadt::DSDT, &dsdt)]);
        assert_eq!(soft_off_of(&no_pm1, &body), Err("no PM1a control register"));
        let no_dsdt = fadt_table(116, &[(fadt::PM1A_CNT_BLK, &pm1a)]);
        assert_eq!(soft_off_of(&no_dsdt, &body), Err("no DSDT"));
        let no_fadt = power_image(&[MADT], &fadt, &body);
        assert_eq!(soft_off(&no_fadt, Some(RSDP)), Err("no FADT"));

        // The 64-bit addresses where set; a one-element package holds both
        // sleep types.
        let body = s5(&[aml::NAME], &package(&[&[aml::WORD, 5, 7]]));
        let with = |x_pm1a: &[u8]| {
            let fadt = fadt_table(
                244,
                &[
                    // Unused: the X_DSDT is set.
                    (fadt::DSDT, &0x900u32.to_le_bytes()),
                    (fadt::X_DSDT, &DSDT.to_le_bytes()),
                    (fadt::PM1A_CNT_BLK, &pm1a),
                    (fadt::PM1B_CNT_BLK, &0x608u32.to_le_bytes()),
                    (fadt::X_PM1A_CNT_BLK, x_pm1a),
                ],
            );
            soft_off_of(&fadt, &body)
        };
        assert_eq!(
            with(&io(0xb004, 16)),
            Ok(SoftOff::Pm1 {
                a: (0xb004, 5),
                b: Some((0x608, 7))
            })
        );
        assert_eq!(
            with(&[0; 12]),
            Ok(SoftOff::Pm1 {
                a: (0x604, 5),
                b: Some((0x608, 7))
            })
        );
        let mut memory = io(0xb004, 16);
        memory[0] = 0;
        assert_eq!(
            with(&memory),
            Err("PM1 control register not at an I/O port")
        );
    }

    #[test]
    fn s5_sleep_types_are_the_first_s5_packages() {
        let types = |body: &[u8]| s5_sleep_types(&sdt(*b"DSDT", body));
        let missing = Err("no \\_S5 package in the DSDT");
        // A 2-byte `PkgLength`, and other integer encodings; only the low 3
        // bits count.
        let long = [aml::PACKAGE, 0x40, 0, 2, aml::ONE, aml::DWORD, 0xb, 0, 0, 1];
        assert_eq!(types(&s5(&[aml::NAME], &long)), Ok((1, 3)));
        let qword = [aml::QWORD, 6, 0, 0, 0, 0, 0, 0, 1];
        let body = s5(&[aml::NAME], &package(&[&qword, &[aml::ZERO]]));
        assert_eq!(types(&body), Ok((6, 0)));
        // Not a name's package of integers: skipped for a later one.
        let later = s5(&[aml::NAME], &package(&[&[aml::BYTE, 2], &[aml::ONE]]));
        for earlier in [
            // A method.
            s5(&[0x14], &package(&[&[aml::ZERO][..]; 2])),
            s5(&[aml::NAME], &[aml::BYTE, 5]),
            // A string.
            s5(&[aml::NAME], &package(&[&[0x0d, b'5', 0], &[aml::ZERO]])),
            // Truncated.
            s5(&[aml::NAME], &[aml::PACKAGE, 4, 2, aml::WORD, 5]),
            // Empty: what follows is not its element.
            s5(&[aml::NAME], &[aml::PACKAGE, 2, 0, aml::BYTE, 5]),
        ] {
            assert_eq!(types(&[&earlier[..], &later].concat()), Ok((2, 1)));
            assert_eq!(types(&earlier), missing);
        }
        // No room for a `NameOp` before it.
        assert_eq!(types(&later[1..]), missing);
        assert_eq!(types(&[]), missing);
    }
}

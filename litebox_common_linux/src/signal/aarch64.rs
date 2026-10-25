// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Definitions for aarch64 signal context structures and their FP/SIMD records.

use core::mem::offset_of;
use core::ops::Range;

use litebox::arch::aarch64::vector::VectorArea;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// sigcontext for aarch64.
/// See: <https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/include/uapi/asm/sigcontext.h>
///
/// The kernel declares `__u8 __reserved[4096] __attribute__((__aligned__(16)))`,
/// which forces both the struct's alignment to 16 and `__reserved` to a 16-byte
/// boundary. The natural offset of `__reserved` is 280 (8-aligned), so the kernel
/// inserts 8 bytes of padding to place it at offset 288 (size 4384). We reproduce
/// this with an explicit padding field and `align(16)` so the layout matches
/// exactly (explicit padding also keeps `IntoBytes` valid, unlike implicit padding).
#[repr(C, align(16))]
#[derive(Clone, FromBytes, IntoBytes)]
#[allow(clippy::pub_underscore_fields)]
pub struct Sigcontext {
    pub fault_address: u64,
    pub regs: [u64; litebox::arch::aarch64::GENERAL_REGISTER_COUNT],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    /// Padding to align `__reserved` to a 16-byte boundary (matches the kernel's
    /// `__attribute__((__aligned__(16)))` on this field).
    pub __reserved_pad: [u8; 8],
    /// 4K reserved for FP/SIMD state and future extensions.
    pub __reserved: [u8; 4096],
}

/// `FPSIMD_MAGIC` from `arch/arm64/include/uapi/asm/sigcontext.h`.
const FPSIMD_MAGIC: u32 = 0x4650_8001;

/// The kernel's `struct _aarch64_ctx`: the header of each record in `__reserved`, and on its
/// own (all zero) the terminator of the record list.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Aarch64Ctx {
    pub magic: u32,
    pub size: u32,
}

/// The kernel's `struct fpsimd_context`.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FpsimdContext {
    pub head: Aarch64Ctx,
    pub fpsr: u32,
    pub fpcr: u32,
    pub vregs: [u128; 32],
}

const _: () = assert!(
    size_of::<Aarch64Ctx>() == 8
        && size_of::<FpsimdContext>() == 528
        && offset_of!(FpsimdContext, fpsr) == 8
        && offset_of!(FpsimdContext, fpcr) == 12
        && offset_of!(FpsimdContext, vregs) == 16
);

/// Calls `visit` with the magic and byte range of each record in `reserved` up to the
/// terminator. Returns `None` if a record is malformed or crosses the end of `reserved`, if
/// the terminator is missing, or if `visit` returns `None`.
fn walk_records(reserved: &[u8], visit: impl FnMut(u32, Range<usize>) -> Option<()>) -> Option<()> {
    let read_header = |offset| {
        let (head, _) = Aarch64Ctx::ref_from_prefix(reserved.get(offset..)?).ok()?;
        Some(*head)
    };
    walk_record_headers(reserved.len(), read_header, visit)
}

/// Like [`walk_records`], for a record list of `len` bytes whose headers `read_header` reads at
/// their offsets. Reads no header past the terminator.
fn walk_record_headers(
    len: usize,
    mut read_header: impl FnMut(usize) -> Option<Aarch64Ctx>,
    mut visit: impl FnMut(u32, Range<usize>) -> Option<()>,
) -> Option<()> {
    let mut offset = 0;
    loop {
        let remaining = len - offset;
        if remaining < size_of::<Aarch64Ctx>() {
            return None;
        }
        let head = read_header(offset)?;
        let size = usize::try_from(head.size).ok()?;
        if head.magic == 0 {
            return (size == 0).then_some(());
        }
        if size < size_of::<Aarch64Ctx>() || !size.is_multiple_of(16) || size > remaining {
            return None;
        }
        visit(head.magic, offset..offset + size)?;
        offset += size;
    }
}

/// The location of the FP/SIMD record in a record list.
struct VectorRecords<T> {
    fpsimd: Option<T>,
}

impl<T> VectorRecords<T> {
    const fn new() -> Self {
        Self { fpsimd: None }
    }

    /// Notes the record `magic` of `size` bytes at `location`. Fails on a second `fpsimd_context`
    /// or a wrongly sized one.
    fn note(&mut self, magic: u32, size: usize, location: T) -> Option<()> {
        let slot = match magic {
            FPSIMD_MAGIC if size == size_of::<FpsimdContext>() => &mut self.fpsimd,
            FPSIMD_MAGIC => return None,
            _ => return Some(()),
        };
        slot.replace(location).is_none().then_some(())
    }
}

/// Signal-frame vector records that are invalid or unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidVectorRecords;

/// Copies the FP/SIMD record of signal-frame `__reserved` bytes into `area`.
///
/// Validates like Linux `rt_sigreturn`: `fpsimd_context` is required, unique and exactly sized.
/// Unlike Linux, unknown record types are skipped.
///
/// Returns [`InvalidVectorRecords`], leaving `area` unchanged, if the records are invalid.
/// Neither allocates nor panics, so signal handlers may call it.
///
/// `reserved` must be 16-byte aligned, as `__reserved` is; misaligned input is rejected as invalid.
pub fn read_vector_records(
    reserved: &[u8],
    area: &mut VectorArea,
) -> Result<(), InvalidVectorRecords> {
    let mut records = VectorRecords::new();
    walk_records(reserved, |magic, range| {
        records.note(magic, range.len(), range)
    })
    .ok_or(InvalidVectorRecords)?;
    let record = |range: Range<usize>| reserved.get(range);
    let fpsimd = records
        .fpsimd
        .and_then(record)
        .ok_or(InvalidVectorRecords)?;
    install_vector_records(fpsimd, area)
}

/// Installs the `fpsimd_context` record in `area`, if valid as described in
/// [`read_vector_records`].
fn install_vector_records(
    fpsimd: &[u8],
    area: &mut VectorArea,
) -> Result<(), InvalidVectorRecords> {
    let fpsimd = FpsimdContext::ref_from_bytes(fpsimd).map_err(|_| InvalidVectorRecords)?;
    area.set_fpsimd(&fpsimd.vregs, fpsimd.fpsr, fpsimd.fpcr);
    Ok(())
}

/// Returns the `fpsimd_context` record of signal-frame `__reserved` bytes, if the record list
/// is well formed and has exactly one, correctly sized.
///
/// `reserved` must be 16-byte aligned, as `__reserved` is; misaligned input is rejected as invalid.
pub fn fpsimd_context_mut(reserved: &mut [u8]) -> Option<&mut FpsimdContext> {
    let mut fpsimd = None;
    walk_records(reserved, |magic, range| {
        (magic != FPSIMD_MAGIC || fpsimd.replace(range).is_none()).then_some(())
    })?;
    FpsimdContext::mut_from_bytes(reserved.get_mut(fpsimd?)?).ok()
}

/// Writes `area` into signal-frame `__reserved` bytes: `fpsimd_context`, then the terminator.
///
/// # Panics
/// Panics if `reserved` is not 16-byte aligned or cannot hold the records. A 4KiB
/// `__reserved` holds them.
pub fn write_vector_records(reserved: &mut [u8], area: &VectorArea) {
    let record_size = |size: usize| u32::try_from(size).expect("record sizes fit in u32");
    let (fpsimd, rest) =
        FpsimdContext::mut_from_prefix(reserved).expect("__reserved must hold fpsimd_context");
    *fpsimd = FpsimdContext {
        head: Aarch64Ctx {
            magic: FPSIMD_MAGIC,
            size: record_size(size_of::<FpsimdContext>()),
        },
        fpsr: area.fpsr(),
        fpcr: area.fpcr(),
        vregs: *area.vregs(),
    };
    let (end, _) = Aarch64Ctx::mut_from_prefix(rest).expect("__reserved must hold the terminator");
    *end = Aarch64Ctx { magic: 0, size: 0 };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(16))]
    struct Reserved([u8; 4096]);

    fn fpsimd_area() -> VectorArea {
        let mut area = VectorArea::default();
        area.set_fpsimd(
            &core::array::from_fn(|index| u128::MAX / 3 - index as u128),
            0x0800_0010,
            0x0300_0000,
        );
        area
    }

    fn written(area: &VectorArea) -> Reserved {
        let mut reserved = Reserved([0xcc; 4096]);
        write_vector_records(&mut reserved.0, area);
        reserved
    }

    fn read(reserved: &[u8]) -> Option<VectorArea> {
        let mut area = VectorArea::default();
        read_vector_records(reserved, &mut area).map(|()| area).ok()
    }

    fn set_u32(reserved: &mut [u8], offset: usize, value: u32) {
        reserved[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    #[test]
    fn records_round_trip() {
        let area = fpsimd_area();
        let reserved = written(&area);
        assert_eq!(read(&reserved.0), Some(area));
        assert_eq!(
            &reserved.0[528..536],
            &[0; 8],
            "terminator follows fpsimd_context"
        );
    }

    #[test]
    fn invalid_records_are_rejected() {
        const END: usize = 528;
        const UNKNOWN_MAGIC: u32 = 0x1234_5678;
        let valid = written(&fpsimd_area());
        let reject = |edit: &dyn Fn(&mut [u8])| {
            let mut reserved = Reserved(valid.0);
            edit(&mut reserved.0);
            let mut area = VectorArea::default();
            assert_eq!(
                read_vector_records(&reserved.0, &mut area),
                Err(InvalidVectorRecords)
            );
            assert_eq!(
                area,
                VectorArea::default(),
                "rejection must leave the area unchanged"
            );
        };
        // Duplicate records.
        reject(&|r| {
            r.copy_within(0..END, END);
            r[2 * END..2 * END + 8].fill(0);
        });
        // Missing or wrongly sized fpsimd_context.
        reject(&|r| set_u32(r, 0, UNKNOWN_MAGIC));
        reject(&|r| set_u32(r, 4, 544));
        // Malformed lists: a size that is not a multiple of 16, a record past the end, and a
        // terminator with a size.
        reject(&|r| {
            set_u32(r, END, UNKNOWN_MAGIC);
            set_u32(r, END + 4, 24);
        });
        reject(&|r| {
            set_u32(r, END, UNKNOWN_MAGIC);
            set_u32(r, END + 4, 4096);
        });
        reject(&|r| set_u32(r, END + 4, 16));
        // A list without a terminator.
        assert!(read(&valid.0[..END]).is_none());
    }

    #[test]
    fn unknown_records_are_skipped() {
        const UNKNOWN_MAGIC: u32 = 0x1234_5678;
        let area = fpsimd_area();
        let mut reserved = Reserved([0; 4096]);
        set_u32(&mut reserved.0, 0, UNKNOWN_MAGIC);
        set_u32(&mut reserved.0, 4, 32);
        write_vector_records(&mut reserved.0[32..], &area);
        assert_eq!(read(&reserved.0), Some(area));
    }
}

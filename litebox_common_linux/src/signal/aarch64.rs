// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Definitions for aarch64 signal context structures and their FP/SIMD and SVE records.

use alloc::borrow::Cow;
use core::mem::offset_of;
use core::ops::Range;

use litebox::arch::aarch64::vector::{SveVectorLength, VectorArea};
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
/// `SVE_MAGIC` from `arch/arm64/include/uapi/asm/sigcontext.h`.
const SVE_MAGIC: u32 = 0x5356_4501;
/// `EXTRA_MAGIC` from `arch/arm64/include/uapi/asm/sigcontext.h`.
const EXTRA_MAGIC: u32 = 0x4558_5401;

/// Linux 6.6 `SIGFRAME_MAXSZ`: the size of the largest signal frame `rt_sigreturn` accepts.
const SIGFRAME_MAX_SIZE: usize = 256 * 1024;
/// Linux `TERMINATOR_SIZE`: the room a terminator takes in a record list.
const TERMINATOR_SIZE: usize = size_of::<Aarch64Ctx>().next_multiple_of(16);

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

/// The kernel's `struct sve_context`. Without a payload (`head.size` of 16), SVE state is not
/// live; otherwise the `SVE_SIG_REGS` payload follows at offset 16.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SveContext {
    pub head: Aarch64Ctx,
    /// Vector length in bytes.
    pub vl: u16,
    /// [`SveContextFlags`].
    pub flags: u16,
    pub reserved: [u16; 2],
}

/// The kernel's `struct extra_context`, which continues the record list of `__reserved` in
/// `size` bytes at guest address `datap`.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct ExtraContext {
    pub head: Aarch64Ctx,
    pub datap: u64,
    pub size: u32,
    pub reserved: [u32; 3],
}

bitflags::bitflags! {
    /// `sve_context.flags`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SveContextFlags: u16 {
        /// `SVE_SIG_FLAG_SM`: the record holds streaming-mode (SME) state.
        const SM = 1 << 0;
    }
}

/// Returns the size of a live `sve_context` record at `vl`, padded like every record in
/// `__reserved`: `round_up(SVE_SIG_CONTEXT_SIZE(vq), 16)`.
pub const fn live_sve_context_size(vl: SveVectorLength) -> usize {
    (size_of::<SveContext>() + vl.payload_size()).next_multiple_of(16)
}

// `round_up(SVE_SIG_CONTEXT_SIZE(vq), 16)` for VQ 1 and 6.
const _: () = assert!(
    size_of::<SveContext>() == 16
        && offset_of!(SveContext, vl) == 8
        && offset_of!(SveContext, flags) == 10
        && live_sve_context_size(SveVectorLength::new(16).unwrap()) == 576
        && live_sve_context_size(SveVectorLength::new(96).unwrap()) == 3296
);

/// Returns whether Linux places a live `sve_context` at `vl` in `__reserved`, after
/// `fpsimd_context`, a fault's `esr_context` and a `gcs_context` (Linux 6.13+), rather than in
/// an `extra_context` area.
///
/// Linux keeps room for an `extra_context` record and the terminator at the end of
/// `__reserved`. Host frames vary in size: `esr_context` only for faults, `gcs_context` only
/// when enabled, and SME, FPMR or POE records after `sve_context`. At every VL that satisfies
/// this, a live `sve_context` is in `__reserved` both in host frames and in the frames LiteBox
/// builds.
pub const fn sve_context_fits_reserved(vl: SveVectorLength) -> bool {
    /// `struct esr_context`.
    const ESR_CONTEXT_SIZE: usize = 16;
    /// `struct gcs_context`.
    const GCS_CONTEXT_SIZE: usize = 32;
    size_of::<FpsimdContext>() + ESR_CONTEXT_SIZE + GCS_CONTEXT_SIZE + live_sve_context_size(vl)
        <= size_of::<Sigcontext>()
            - offset_of!(Sigcontext, __reserved)
            - size_of::<ExtraContext>()
            - TERMINATOR_SIZE
}

// Up to 768-bit vectors fit, including the kernel's default VL of 64 bytes.
const _: () = assert!(
    sve_context_fits_reserved(SveVectorLength::new(96).unwrap())
        && !sve_context_fits_reserved(SveVectorLength::new(112).unwrap())
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

/// The locations of the FP/SIMD and SVE records in a record list.
struct VectorRecords<T> {
    /// Whether `sve_context` records are noted; otherwise they are skipped like unknown ones.
    note_sve: bool,
    fpsimd: Option<T>,
    sve: Option<T>,
}

impl<T> VectorRecords<T> {
    const fn new(note_sve: bool) -> Self {
        Self {
            note_sve,
            fpsimd: None,
            sve: None,
        }
    }

    /// Notes the record `magic` of `size` bytes at `location`. Fails on a second `fpsimd_context`
    /// or `sve_context`, or a wrongly sized `fpsimd_context`.
    fn note(&mut self, magic: u32, size: usize, location: T) -> Option<()> {
        let slot = match magic {
            FPSIMD_MAGIC if size == size_of::<FpsimdContext>() => &mut self.fpsimd,
            FPSIMD_MAGIC => return None,
            SVE_MAGIC if self.note_sve => &mut self.sve,
            _ => return Some(()),
        };
        slot.replace(location).is_none().then_some(())
    }
}

/// Signal-frame vector records that are invalid or unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidVectorRecords;

/// Copies the FP/SIMD and SVE records of signal-frame `__reserved` bytes into `area`.
///
/// Validates like Linux `rt_sigreturn`: `fpsimd_context` is required, unique and exactly sized;
/// an `sve_context` must be unique, carry `area`'s VL, not set [`SveContextFlags::SM`], and be
/// either header-only (SVE not live) or hold the full payload (SVE live). Without an
/// `sve_context`, SVE is not live. Unlike Linux, unknown record types are skipped.
/// `extra_context` is not followed, as host frames never need it (see
/// [`sve_context_fits_reserved`]); [`read_guest_vector_records`] follows it. If `area`
/// has a VL, an `extra_context` without an `sve_context` in `reserved` is invalid, since the
/// `sve_context` may then be behind it. If `area` has no VL, `sve_context` records,
/// streaming-mode ones included, are skipped: LiteBox then hides SVE from the guest, while host
/// frames may still carry them.
///
/// LiteBox offers no SME, and a guest that enters streaming mode anyway cannot be resumed
/// faithfully, so a streaming-mode record fails closed: it is invalid, like on a Linux system
/// without SME.
///
/// Returns [`InvalidVectorRecords`], leaving `area` unchanged, if the records are invalid.
/// Neither allocates nor panics, so signal handlers may call it.
///
/// `reserved` must be 16-byte aligned, as `__reserved` is; misaligned input is rejected as invalid.
pub fn read_vector_records(
    reserved: &[u8],
    area: &mut VectorArea,
) -> Result<(), InvalidVectorRecords> {
    let mut records = VectorRecords::new(area.sve_vl().is_some());
    let mut has_extra = false;
    walk_records(reserved, |magic, range| {
        has_extra |= magic == EXTRA_MAGIC;
        records.note(magic, range.len(), range)
    })
    .ok_or(InvalidVectorRecords)?;
    if has_extra && records.note_sve && records.sve.is_none() {
        return Err(InvalidVectorRecords);
    }
    let record = |range: Range<usize>| reserved.get(range);
    let fpsimd = records
        .fpsimd
        .and_then(record)
        .ok_or(InvalidVectorRecords)?;
    install_vector_records(fpsimd, records.sve.and_then(record), area)
}

/// The record list holding a record of a guest signal frame.
enum RecordList {
    Reserved,
    Extra,
}

/// Copies the FP/SIMD and SVE records of a guest signal frame into `area`, like
/// [`read_vector_records`], but also following an `extra_context` like Linux 6.6
/// `parse_user_sigframe`. As in [`read_vector_records`], unknown record types are skipped, while
/// Linux rejects them.
///
/// `reserved` holds the frame's `__reserved` bytes, which are at guest address
/// `reserved_addr` in the `rt_sigframe` at `frame_addr`. At most one `extra_context`, at least
/// `struct extra_context` in size, may appear, followed in `__reserved` by a terminator; its
/// `datap` must be 16-byte aligned and the address right after that terminator, and its `size`
/// must be 16-byte aligned and keep the extra records within `SIGFRAME_MAXSZ` of `frame_addr`.
/// The record list then continues in the extra records, which may overlap the rest of
/// `__reserved`, up to a terminator within `size`. `fpsimd_context` and `sve_context` may sit in
/// either list and must be unique across both.
///
/// `read_guest` copies the guest bytes at an address into a buffer, failing if they are not
/// readable. Like Linux, of the extra records only the headers up to the terminator,
/// `fpsimd_context`, and of an `sve_context` its header and the payload at `area`'s VL, rounded
/// up to 16 bytes, are read, not the rest of `size` or of an oversized `sve_context`.
///
/// Returns [`InvalidVectorRecords`], leaving `area` unchanged, if the records are invalid or
/// unreadable.
///
/// `reserved` must be 16-byte aligned, as `__reserved` is; misaligned input is rejected as invalid.
pub fn read_guest_vector_records(
    reserved: &[u8],
    reserved_addr: usize,
    frame_addr: usize,
    mut read_guest: impl FnMut(usize, &mut [u8]) -> Option<()>,
    area: &mut VectorArea,
) -> Result<(), InvalidVectorRecords> {
    let mut records = VectorRecords::new(area.sve_vl().is_some());
    let mut extra = None;
    walk_records(reserved, |magic, range| {
        if magic == EXTRA_MAGIC {
            extra = Some(extra_records(reserved, range, reserved_addr, frame_addr)?);
            return Some(());
        }
        records.note(magic, range.len(), (RecordList::Reserved, range))
    })
    .ok_or(InvalidVectorRecords)?;
    if let Some((datap, size)) = extra {
        let read_header = |offset| {
            let mut head = Aarch64Ctx { magic: 0, size: 0 };
            read_guest(datap + offset, head.as_mut_bytes())?;
            Some(head)
        };
        walk_record_headers(size, read_header, |magic, range| {
            if magic == EXTRA_MAGIC {
                return None;
            }
            records.note(magic, range.len(), (RecordList::Extra, range))
        })
        .ok_or(InvalidVectorRecords)?;
    }
    let sve_read_size = area
        .sve_vl()
        .map_or(size_of::<SveContext>(), live_sve_context_size);
    // `u128` elements align the records like `__reserved`. Like Linux
    // `restore_sve_fpsimd_context`, no more of an `sve_context` than `sve_read_size` is read.
    // Reading up to the 16-byte-rounded size cannot fault where Linux does not: records are
    // 16-byte aligned, so the rounding bytes share the payload's last 16-byte granule and page.
    let mut record_bytes = |(list, range): (RecordList, Range<usize>), max_size: usize| {
        let range = range.start..range.start + range.len().min(max_size);
        match list {
            RecordList::Reserved => <[u128]>::ref_from_bytes(&reserved[range])
                .ok()
                .map(Cow::Borrowed),
            RecordList::Extra => {
                let (datap, _) = extra?;
                let mut record = alloc::vec![0; range.len() / size_of::<u128>()];
                read_guest(datap + range.start, record.as_mut_bytes())?;
                Some(Cow::Owned(record))
            }
        }
    };
    let (Some(fpsimd), Some(sve)) = (
        records
            .fpsimd
            .and_then(|location| record_bytes(location, size_of::<FpsimdContext>())),
        records.sve.map_or(Some(None), |location| {
            record_bytes(location, sve_read_size).map(Some)
        }),
    ) else {
        return Err(InvalidVectorRecords);
    };
    install_vector_records(
        fpsimd.as_bytes(),
        sve.as_deref().map(IntoBytes::as_bytes),
        area,
    )
}

/// Returns the guest address and size of the extra records of the `extra_context` at `range` of
/// `reserved`, if valid as described in [`read_guest_vector_records`].
fn extra_records(
    reserved: &[u8],
    range: Range<usize>,
    reserved_addr: usize,
    frame_addr: usize,
) -> Option<(usize, usize)> {
    let (extra, _) = ExtraContext::read_from_prefix(&reserved[range.clone()]).ok()?;
    let (terminator, _) =
        Aarch64Ctx::read_from_prefix(reserved.get(range.end..range.end + TERMINATOR_SIZE)?).ok()?;
    let datap = usize::try_from(extra.datap).ok()?;
    let size = usize::try_from(extra.size).ok()?;
    let valid = terminator.magic == 0
        && terminator.size == 0
        && datap.is_multiple_of(16)
        && size.is_multiple_of(16)
        && reserved_addr.checked_add(range.end + TERMINATOR_SIZE) == Some(datap)
        && size
            <= frame_addr
                .checked_add(SIGFRAME_MAX_SIZE)?
                .checked_sub(datap)?;
    valid.then_some((datap, size))
}

/// Installs the `fpsimd_context` record and the `sve_context` record, if any, in `area`, if
/// valid as described in [`read_vector_records`].
fn install_vector_records(
    fpsimd: &[u8],
    sve: Option<&[u8]>,
    area: &mut VectorArea,
) -> Result<(), InvalidVectorRecords> {
    let fpsimd = FpsimdContext::ref_from_bytes(fpsimd).map_err(|_| InvalidVectorRecords)?;
    let payload = match (sve, area.sve_vl()) {
        (Some(record), Some(vl)) => {
            let (context, payload) =
                SveContext::ref_from_prefix(record).map_err(|_| InvalidVectorRecords)?;
            if SveContextFlags::from_bits_retain(context.flags).contains(SveContextFlags::SM)
                || context.vl != vl.bytes()
            {
                return Err(InvalidVectorRecords);
            }
            if payload.is_empty() {
                None
            } else {
                Some(
                    payload
                        .get(..vl.payload_size())
                        .ok_or(InvalidVectorRecords)?,
                )
            }
        }
        _ => None,
    };
    area.discard_sve();
    area.set_fpsimd(&fpsimd.vregs, fpsimd.fpsr, fpsimd.fpcr);
    if let Some(payload) = payload {
        let installed = area.set_sve_payload(payload);
        debug_assert!(installed, "the payload is sliced to the area's VL");
    }
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

/// Writes `area` into signal-frame `__reserved` bytes: `fpsimd_context`, then an
/// `sve_context` if `area` has a VL (with the payload iff SVE is live), then the terminator.
///
/// # Panics
/// Panics if `reserved` is not 16-byte aligned or cannot hold the records. A 4KiB
/// `__reserved` holds them at every VL that satisfies [`sve_context_fits_reserved`].
pub fn write_vector_records(reserved: &mut [u8], area: &VectorArea) {
    let record_size = |size: usize| u32::try_from(size).expect("record sizes fit in u32");
    let (fpsimd, mut rest) =
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
    if let Some(vl) = area.sve_vl() {
        let payload = area.sve_payload();
        let size = payload.map_or(size_of::<SveContext>(), |_| live_sve_context_size(vl));
        let (record, tail) = rest
            .split_at_mut_checked(size)
            .expect("__reserved must hold sve_context");
        let (context, padded_payload) =
            SveContext::mut_from_prefix(record).expect("sve_context records are aligned");
        *context = SveContext {
            head: Aarch64Ctx {
                magic: SVE_MAGIC,
                size: record_size(size),
            },
            vl: vl.bytes(),
            flags: 0,
            reserved: [0; 2],
        };
        if let Some(payload) = payload {
            let (destination, padding) = padded_payload.split_at_mut(payload.len());
            destination.copy_from_slice(payload);
            padding.fill(0);
        }
        rest = tail;
    }
    let (end, _) = Aarch64Ctx::mut_from_prefix(rest).expect("__reserved must hold the terminator");
    *end = Aarch64Ctx { magic: 0, size: 0 };
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[repr(align(16))]
    struct Reserved([u8; 4096]);

    fn vl(bytes: u16) -> SveVectorLength {
        SveVectorLength::new(bytes).unwrap()
    }

    fn fpsimd_area(sve_vl: Option<SveVectorLength>) -> VectorArea {
        let mut area = VectorArea::initial(sve_vl);
        area.set_fpsimd(
            &core::array::from_fn(|index| u128::MAX / 3 - index as u128),
            0x0800_0010,
            0x0300_0000,
        );
        area
    }

    fn live_area(vl: SveVectorLength) -> VectorArea {
        let mut area = fpsimd_area(Some(vl));
        let payload: Vec<u8> = (0..vl.payload_size())
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        assert!(area.set_sve_payload(&payload));
        area
    }

    fn written(area: &VectorArea) -> Reserved {
        let mut reserved = Reserved([0xcc; 4096]);
        write_vector_records(&mut reserved.0, area);
        reserved
    }

    fn read(reserved: &[u8], sve_vl: Option<SveVectorLength>) -> Option<VectorArea> {
        let mut area = VectorArea::initial(sve_vl);
        read_vector_records(reserved, &mut area).map(|()| area).ok()
    }

    fn set_u32(reserved: &mut [u8], offset: usize, value: u32) {
        reserved[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    #[test]
    fn records_round_trip() {
        for area in [
            fpsimd_area(None),
            fpsimd_area(Some(vl(16))),
            live_area(vl(16)),
            live_area(vl(96)),
        ] {
            let reserved = written(&area);
            assert_eq!(read(&reserved.0, area.sve_vl()), Some(area.clone()));
        }
        // Without an `sve_context`, SVE is not live.
        assert_eq!(
            read(&written(&fpsimd_area(None)).0, Some(vl(16))),
            Some(fpsimd_area(Some(vl(16))))
        );

        let reserved = written(&fpsimd_area(None));
        assert_eq!(
            &reserved.0[528..536],
            &[0; 8],
            "terminator follows fpsimd_context"
        );
        let reserved = written(&fpsimd_area(Some(vl(16))));
        let header: [u8; 8] = reserved.0[528..536].try_into().unwrap();
        assert_eq!(header[..4], SVE_MAGIC.to_ne_bytes());
        assert_eq!(
            header[4..],
            16u32.to_ne_bytes(),
            "SVE that is not live is header-only"
        );
        assert_eq!(&reserved.0[544..552], &[0; 8]);
        let reserved = written(&live_area(vl(16)));
        assert_eq!(&reserved.0[528 + 576..528 + 576 + 8], &[0; 8]);
    }

    #[test]
    fn invalid_records_are_rejected() {
        const SVE: usize = 528;
        let live = written(&live_area(vl(16)));
        let reject = |edit: &dyn Fn(&mut [u8]), sve_vl: SveVectorLength| {
            let mut reserved = Reserved(live.0);
            edit(&mut reserved.0);
            let mut area = live_area(sve_vl);
            let before = area.clone();
            assert_eq!(
                read_vector_records(&reserved.0, &mut area),
                Err(InvalidVectorRecords)
            );
            assert_eq!(area, before, "rejection must leave the area unchanged");
        };
        // VL mismatch, for both live and header-only records.
        reject(&|_| {}, vl(32));
        reject(
            &|r| {
                set_u32(r, SVE + 4, 16);
                r[SVE + 16..SVE + 24].fill(0);
            },
            vl(32),
        );
        // Streaming-mode state needs SME.
        reject(
            &|r| r[SVE + 10..SVE + 12].copy_from_slice(&1u16.to_ne_bytes()),
            vl(16),
        );
        // Neither header-only nor the full payload.
        reject(
            &|r| {
                set_u32(r, SVE + 4, 32);
                r[SVE + 32..SVE + 40].fill(0);
            },
            vl(16),
        );
        // Duplicate records.
        reject(
            &|r| {
                r.copy_within(SVE..SVE + 576, SVE + 576);
                r[SVE + 1152..SVE + 1160].fill(0);
            },
            vl(16),
        );
        reject(
            &|r| {
                r.copy_within(0..SVE, SVE);
                r[2 * SVE..2 * SVE + 8].fill(0);
            },
            vl(16),
        );
        // Missing or wrongly sized fpsimd_context.
        reject(&|r| set_u32(r, 0, 0x1234_5678), vl(16));
        reject(&|r| set_u32(r, 4, 544), vl(16));
        // Malformed lists: a size that is not a multiple of 16, a record past the end, and a
        // terminator with a size.
        reject(&|r| set_u32(r, SVE + 4, 584), vl(16));
        reject(&|r| set_u32(r, SVE + 4, 4096), vl(16));
        reject(&|r| set_u32(r, SVE + 576 + 4, 16), vl(16));
        // A list without a terminator.
        assert!(read(&live.0[..SVE + 576], Some(vl(16))).is_none());
    }

    #[test]
    fn unknown_and_unsupported_records_are_skipped() {
        const UNKNOWN_MAGIC: u32 = 0x1234_5678;
        let area = live_area(vl(16));
        let mut reserved = Reserved([0; 4096]);
        set_u32(&mut reserved.0, 0, UNKNOWN_MAGIC);
        set_u32(&mut reserved.0, 4, 32);
        write_vector_records(&mut reserved.0[32..], &area);
        assert_eq!(read(&reserved.0, Some(vl(16))), Some(area.clone()));

        // Areas without a VL skip `sve_context` records, valid or not.
        reserved.0[32 + 528 + 8..32 + 528 + 10].copy_from_slice(&48u16.to_ne_bytes());
        let fpsimd_only = read(&reserved.0, None).unwrap();
        assert_eq!(fpsimd_only.vregs(), area.vregs());
        assert_eq!(fpsimd_only.sve_vl(), None);
    }

    #[test]
    fn guest_records_follow_extra_context() {
        const RESERVED_ADDR: usize = 0x10_0000;
        const FRAME_ADDR: usize = RESERVED_ADDR - 0x1000;
        const EXTRA: usize = 528;
        const DATA: usize = EXTRA + size_of::<ExtraContext>() + TERMINATOR_SIZE;
        const DATA_SIZE: usize = 576 + TERMINATOR_SIZE;
        fn read_guest(
            reserved: &Reserved,
            reserved_addr: usize,
            frame_addr: usize,
        ) -> Option<VectorArea> {
            read_guest_with_hole(reserved, reserved_addr, frame_addr, 0..0)
        }
        // Reads fail if they overlap the `reserved` offsets in `hole`.
        fn read_guest_with_hole(
            reserved: &Reserved,
            reserved_addr: usize,
            frame_addr: usize,
            hole: Range<usize>,
        ) -> Option<VectorArea> {
            let memory = |addr: usize, bytes: &mut [u8]| {
                let offset = addr.checked_sub(reserved_addr)?;
                let end = offset + bytes.len();
                if offset < hole.end && hole.start < end {
                    return None;
                }
                bytes.copy_from_slice(reserved.0.get(offset..end)?);
                Some(())
            };
            let mut area = VectorArea::initial(Some(vl(16)));
            read_guest_vector_records(&reserved.0, reserved_addr, frame_addr, memory, &mut area)
                .map(|()| area)
                .ok()
        }

        // The live `sve_context` and the terminator move behind an `extra_context`.
        let area = live_area(vl(16));
        let mut moved = written(&area);
        moved.0.copy_within(EXTRA..EXTRA + 576 + 8, DATA);
        moved.0[EXTRA..DATA].fill(0);
        set_u32(&mut moved.0, EXTRA, EXTRA_MAGIC);
        set_u32(&mut moved.0, EXTRA + 4, 32);
        let set_datap = |r: &mut [u8], datap: usize| {
            r[EXTRA + 8..EXTRA + 16].copy_from_slice(&(datap as u64).to_ne_bytes());
        };
        set_datap(&mut moved.0, RESERVED_ADDR + DATA);
        let set_size = |r: &mut [u8], size: usize| {
            set_u32(r, EXTRA + 16, u32::try_from(size).unwrap());
        };
        set_size(&mut moved.0, DATA_SIZE);
        assert_eq!(
            read_guest(&moved, RESERVED_ADDR, FRAME_ADDR),
            Some(area.clone())
        );
        // Host frames skip `extra_context`, but with a VL only with an `sve_context` in
        // `__reserved`.
        assert!(read(&moved.0, Some(vl(16))).is_none());
        assert_eq!(read(&moved.0, None), Some(fpsimd_area(None)));
        let mut sve_in_reserved = written(&area);
        set_u32(&mut sve_in_reserved.0, EXTRA + 576, EXTRA_MAGIC);
        set_u32(&mut sve_in_reserved.0, EXTRA + 576 + 4, 32);
        sve_in_reserved.0[EXTRA + 576 + 8..EXTRA + 576 + 48].fill(0);
        assert_eq!(read(&sve_in_reserved.0, Some(vl(16))), Some(area.clone()));
        // Like Linux, nothing past the terminator is read, so `size` may reach unreadable memory.
        let mut unreadable_tail = Reserved(moved.0);
        set_size(&mut unreadable_tail.0, 4096 + 16 - DATA);
        assert_eq!(
            read_guest(&unreadable_tail, RESERVED_ADDR, FRAME_ADDR),
            Some(area.clone())
        );
        // Of an `sve_context`, only the header and payload, rounded up to 16 bytes, are read, so
        // an oversized one may reach unreadable memory.
        let oversized_size = 576 + 64;
        let mut oversized = Reserved(moved.0);
        set_u32(
            &mut oversized.0,
            DATA + 4,
            u32::try_from(oversized_size).unwrap(),
        );
        oversized.0[DATA + oversized_size..DATA + oversized_size + 8].fill(0);
        set_size(&mut oversized.0, oversized_size + TERMINATOR_SIZE);
        let read_end = DATA + live_sve_context_size(vl(16));
        assert_eq!(
            read_guest_with_hole(
                &oversized,
                RESERVED_ADDR,
                FRAME_ADDR,
                read_end..DATA + oversized_size
            ),
            Some(area.clone())
        );
        // The extra records may end exactly `SIGFRAME_MAXSZ` past the frame, but no further.
        let last_frame_addr = RESERVED_ADDR + DATA + DATA_SIZE - SIGFRAME_MAX_SIZE;
        assert!(read_guest(&moved, RESERVED_ADDR, last_frame_addr).is_some());
        assert!(read_guest(&moved, RESERVED_ADDR, last_frame_addr - 16).is_none());
        // `datap` must be 16-byte aligned even where the frame is not.
        let mut misaligned = Reserved(moved.0);
        set_datap(&mut misaligned.0, RESERVED_ADDR + 8 + DATA);
        assert!(read_guest(&misaligned, RESERVED_ADDR + 8, FRAME_ADDR).is_none());

        let reject = |edit: &dyn Fn(&mut [u8])| {
            let mut reserved = Reserved(moved.0);
            edit(&mut reserved.0);
            assert!(read_guest(&reserved, RESERVED_ADDR, FRAME_ADDR).is_none());
        };
        // A second `extra_context`, in the extra records.
        reject(&|r| {
            set_u32(r, DATA + 576, EXTRA_MAGIC);
            set_u32(r, DATA + 576 + 4, 32);
            r[DATA + 576 + 8..DATA + 576 + 48].fill(0);
            set_size(r, DATA_SIZE + 32);
        });
        // Another record, here spanning the extra records, instead of a terminator after the
        // `extra_context`.
        reject(&|r| {
            set_u32(r, EXTRA + 32, 1);
            set_u32(
                r,
                EXTRA + 36,
                u32::try_from(TERMINATOR_SIZE + DATA_SIZE).unwrap(),
            );
            r[DATA + DATA_SIZE..DATA + DATA_SIZE + 8].fill(0);
        });
        // Extra records elsewhere than right after that terminator.
        reject(&|r| {
            r.copy_within(DATA..DATA + DATA_SIZE, 2048);
            set_datap(r, RESERVED_ADDR + 2048);
        });
        // A `size` that is not 16-byte aligned.
        reject(&|r| set_size(r, DATA_SIZE + 8));
        // No terminator within `size`.
        reject(&|r| set_size(r, DATA_SIZE - 16));
    }
}

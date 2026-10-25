// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent AArch64 FP/SIMD and SVE register storage.

use alloc::boxed::Box;
use core::mem::offset_of;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

/// An SVE vector length (VL) in bytes: a multiple of 16 from 16 to 256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SveVectorLength(u16);

impl SveVectorLength {
    /// Returns `bytes` as a vector length if it is architecturally valid.
    pub const fn new(bytes: u16) -> Option<Self> {
        if bytes >= 16 && bytes <= 256 && bytes.is_multiple_of(16) {
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Returns the length of each Z register in bytes.
    pub const fn bytes(self) -> u16 {
        self.0
    }

    /// Returns the size of Z0-Z31, then P0-P15 and FFR at `vl / 8` bytes each, in Linux
    /// `SVE_SIG_REGS` layout.
    pub const fn payload_size(self) -> usize {
        32 * self.0 as usize + 17 * (self.0 as usize / 8)
    }
}

/// FP/SIMD state at the start of a [`VectorArea`].
#[repr(C, align(16))]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct FpsimdHeader {
    /// V0-V31, as `STP Q` stores them.
    vregs: [u128; 32],
    fpsr: u32,
    fpcr: u32,
    /// Nonzero iff the SVE payload holds the live Z, P and FFR state.
    sve_live: u8,
    reserved: [u8; 7],
}

/// A 16-byte-aligned storage chunk of a [`VectorArea`].
#[repr(C, align(16))]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
struct VectorChunk([u8; 16]);

/// The heap storage of a [`VectorArea`]: the header, then whole chunks holding the SVE payload.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
struct Storage {
    header: FpsimdHeader,
    payload: [VectorChunk],
}

/// Heap storage for a guest thread's FP/SIMD and SVE state.
///
/// The layout is shared with transition assembly:
/// - `0`: V0-V31 (16 bytes each); [`Self::FPSR_OFFSET`]: FPSR (`u32`); [`Self::FPCR_OFFSET`]:
///   FPCR (`u32`); [`Self::SVE_LIVE_OFFSET`]: SVE-live flag (`u8`, nonzero = live).
/// - [`Self::SVE_PAYLOAD_OFFSET`]: present iff the area has a VL: Z0-Z31 at VL bytes each, then
///   P0-P15 and FFR at VL/8 bytes each, in Linux `SVE_SIG_REGS` layout.
///
/// Invariant: while SVE is live, the low 128 bits of each Z register equal the matching V
/// register, so either view reads the same FP/SIMD state. Clearing the flag discards Z bits
/// above 128, P0-P15 and FFR, as a Linux syscall does.
pub struct VectorArea {
    storage: Box<Storage>,
    sve_vl: Option<SveVectorLength>,
}

// The transition assembly hard-codes this layout.
const _: () = assert!(
    offset_of!(FpsimdHeader, vregs) == 0
        && VectorArea::FPSR_OFFSET == 512
        && VectorArea::FPCR_OFFSET == 516
        && VectorArea::SVE_LIVE_OFFSET == 520
        && VectorArea::SVE_PAYLOAD_OFFSET == 528
);

impl VectorArea {
    /// Offset of FPSR.
    pub const FPSR_OFFSET: usize = offset_of!(FpsimdHeader, fpsr);
    /// Offset of FPCR.
    pub const FPCR_OFFSET: usize = offset_of!(FpsimdHeader, fpcr);
    /// Offset of the SVE-live flag.
    pub const SVE_LIVE_OFFSET: usize = offset_of!(FpsimdHeader, sve_live);
    /// Offset of the SVE payload.
    pub const SVE_PAYLOAD_OFFSET: usize = size_of::<FpsimdHeader>();

    /// Allocates zeroed state for the given VL, with SVE not live.
    ///
    /// # Panics
    /// Panics if the allocation fails.
    #[must_use]
    pub fn initial(sve_vl: Option<SveVectorLength>) -> Self {
        let chunks = sve_vl.map_or(0, |vl| vl.payload_size().div_ceil(size_of::<VectorChunk>()));
        Self {
            storage: Storage::new_box_zeroed_with_elems(chunks)
                .expect("failed to allocate a vector area"),
            sve_vl,
        }
    }

    const fn size(sve_vl: Option<SveVectorLength>) -> usize {
        match sve_vl {
            Some(vl) => Self::SVE_PAYLOAD_OFFSET + vl.payload_size(),
            None => Self::SVE_PAYLOAD_OFFSET,
        }
    }

    /// Returns the VL of the SVE payload, or `None` if the area holds only FP/SIMD state.
    #[must_use]
    pub fn sve_vl(&self) -> Option<SveVectorLength> {
        self.sve_vl
    }

    /// Returns V0-V31.
    #[must_use]
    pub fn vregs(&self) -> &[u128; 32] {
        &self.storage.header.vregs
    }

    #[must_use]
    pub fn fpsr(&self) -> u32 {
        self.storage.header.fpsr
    }

    #[must_use]
    pub fn fpcr(&self) -> u32 {
        self.storage.header.fpcr
    }

    /// Replaces V0-V31, FPSR (`status`) and FPCR (`control`), which also replaces the low 128
    /// bits of live Z registers.
    pub fn set_fpsimd(&mut self, vregs: &[u128; 32], status: u32, control: u32) {
        let header = &mut self.storage.header;
        header.vregs = *vregs;
        header.fpsr = status;
        header.fpcr = control;
        if header.sve_live != 0 {
            self.merge_vregs_into_z();
        }
    }

    /// Returns the SVE payload if SVE is live.
    #[must_use]
    pub fn sve_payload(&self) -> Option<&[u8]> {
        if self.storage.header.sve_live == 0 {
            return None;
        }
        Some(&self.as_bytes()[Self::SVE_PAYLOAD_OFFSET..])
    }

    /// Makes `payload` the live SVE state, replacing the low 128 bits of each Z register with
    /// the matching V register.
    ///
    /// Returns false, leaving the area unchanged, unless the area has a VL and `payload` is
    /// exactly [`SveVectorLength::payload_size`] bytes long.
    #[must_use]
    pub fn set_sve_payload(&mut self, payload: &[u8]) -> bool {
        let destination = &mut self.as_bytes_mut()[Self::SVE_PAYLOAD_OFFSET..];
        if destination.is_empty() || destination.len() != payload.len() {
            return false;
        }
        destination.copy_from_slice(payload);
        self.storage.header.sve_live = 1;
        self.merge_vregs_into_z();
        true
    }

    fn merge_vregs_into_z(&mut self) {
        let Some(vl) = self.sve_vl else {
            return;
        };
        let vregs = self.storage.header.vregs;
        let zregs = &mut self.as_bytes_mut()[Self::SVE_PAYLOAD_OFFSET..];
        for (zreg, vreg) in zregs.chunks_exact_mut(usize::from(vl.bytes())).zip(vregs) {
            zreg[..size_of::<u128>()].copy_from_slice(&vreg.to_le_bytes());
        }
    }

    /// Marks SVE state not live, keeping only FP/SIMD state.
    pub fn discard_sve(&mut self) {
        self.storage.header.sve_live = 0;
    }

    /// Copies `source` into this area in place, keeping this area's VL and buffer address.
    ///
    /// # Panics
    /// Panics if `source` has live SVE state at a different VL.
    pub fn copy_from(&mut self, source: &Self) {
        self.discard_sve();
        self.set_fpsimd(source.vregs(), source.fpsr(), source.fpcr());
        if let Some(payload) = source.sve_payload() {
            assert!(
                self.set_sve_payload(payload),
                "live SVE state at {:?} cannot be installed in an area at {:?}",
                source.sve_vl,
                self.sve_vl,
            );
        }
    }

    /// Returns the buffer address for CPU-state capture.
    ///
    /// Reads through the pointer are valid until the area is next borrowed mutably, moved or
    /// dropped. Writes are valid only until the area is next borrowed at all: under Tree Borrows,
    /// a read through a shared borrow forbids further writes through a pointer that has been
    /// written through.
    ///
    /// Writes must leave a valid area: the documented layout holds, the SVE-live flag is 0 or 1
    /// (1 only if the area has a VL), and live SVE state keeps the Z/V invariant. They must not
    /// overlap other accesses to this area.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_mut_bytes().as_mut_ptr()
    }

    /// Returns the area's bytes in the documented layout, excluding allocation padding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.storage.as_bytes()[..Self::size(self.sve_vl)]
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let size = Self::size(self.sve_vl);
        &mut self.storage.as_mut_bytes()[..size]
    }

    /// Reconstructs an area with VL `sve_vl` from untrusted [`Self::as_bytes`] output.
    ///
    /// Returns `None` if the length does not match `sve_vl`, reserved bytes are nonzero, the
    /// SVE-live flag is neither 0 nor 1 (or is set without a VL), or live state breaks the
    /// Z/V invariant.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], sve_vl: Option<SveVectorLength>) -> Option<Self> {
        if bytes.len() != Self::size(sve_vl) {
            return None;
        }
        let mut area = Self::initial(sve_vl);
        area.as_bytes_mut().copy_from_slice(bytes);
        let header = &area.storage.header;
        if header.reserved != [0; 7] {
            return None;
        }
        let valid = match (header.sve_live, sve_vl) {
            (0, _) => true,
            (1, Some(vl)) => area.as_bytes()[Self::SVE_PAYLOAD_OFFSET..]
                .chunks_exact(usize::from(vl.bytes()))
                .zip(header.vregs)
                .all(|(zreg, vreg)| zreg[..size_of::<u128>()] == vreg.to_le_bytes()),
            _ => false,
        };
        valid.then_some(area)
    }
}

impl Clone for VectorArea {
    fn clone(&self) -> Self {
        let mut clone = Self::initial(self.sve_vl);
        clone
            .storage
            .as_mut_bytes()
            .copy_from_slice(self.storage.as_bytes());
        clone
    }
}

impl Default for VectorArea {
    /// Returns zeroed FP/SIMD-only state.
    fn default() -> Self {
        Self::initial(None)
    }
}

impl PartialEq for VectorArea {
    /// Compares the VL, the FP/SIMD state, whether SVE is live, and the live SVE payload.
    fn eq(&self, other: &Self) -> bool {
        self.sve_vl == other.sve_vl
            && self.storage.header.as_bytes() == other.storage.header.as_bytes()
            && self.sve_payload() == other.sve_payload()
    }
}

impl Eq for VectorArea {}

impl core::fmt::Debug for VectorArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let header = &self.storage.header;
        f.debug_struct("VectorArea")
            .field("sve_vl", &self.sve_vl)
            .field("sve_live", &(header.sve_live != 0))
            .field("fpsr", &format_args!("{:#x}", header.fpsr))
            .field("fpcr", &format_args!("{:#x}", header.fpcr))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn vl(bytes: u16) -> SveVectorLength {
        SveVectorLength::new(bytes).unwrap()
    }

    fn vregs() -> [u128; 32] {
        core::array::from_fn(|index| 0x0123_4567_89ab_cdef_0011_2233_4455_6677 ^ index as u128)
    }

    fn payload(vl: SveVectorLength) -> Vec<u8> {
        (0..vl.payload_size())
            .map(|index| u8::try_from((index * 7 + 3) % 256).unwrap())
            .collect()
    }

    #[test]
    fn live_payload_merges_vregs_into_z_and_discard_keeps_fpsimd() {
        let vl = vl(32);
        let mut area = VectorArea::initial(Some(vl));
        area.set_fpsimd(&vregs(), 0x11, 0x22);
        assert!(!area.set_sve_payload(&payload(vl)[1..]));
        assert_eq!(area.sve_payload(), None);
        assert!(area.set_sve_payload(&payload(vl)));

        let mut expected = payload(vl);
        for (n, vreg) in vregs().iter().enumerate() {
            expected[n * 32..][..16].copy_from_slice(&vreg.to_le_bytes());
        }
        assert_eq!(area.sve_payload().unwrap(), expected);

        // Replacing FP/SIMD state replaces only the low 128 bits of each Z register.
        let mut updated = vregs();
        updated[5] = u128::MAX;
        area.set_fpsimd(&updated, 0x11, 0x22);
        let z5 = &area.sve_payload().unwrap()[5 * 32..][..32];
        assert_eq!(z5[..16], [0xff; 16]);
        assert_eq!(z5[16..], expected[5 * 32 + 16..][..16]);
        assert_eq!(area.as_bytes()[VectorArea::SVE_LIVE_OFFSET], 1);

        area.discard_sve();
        assert_eq!(area.sve_payload(), None);
        assert_eq!(area.vregs(), &updated);
        assert_eq!((area.fpsr(), area.fpcr()), (0x11, 0x22));
    }

    #[test]
    fn bytes_round_trip_and_reject_invalid_state() {
        let vl = vl(16);
        let mut area = VectorArea::initial(Some(vl));
        area.set_fpsimd(&vregs(), 0x11, 0x22);
        assert!(area.set_sve_payload(&payload(vl)));
        let bytes = area.as_bytes().to_vec();
        assert_eq!(VectorArea::from_bytes(&bytes, Some(vl)), Some(area.clone()));

        let with = |offset: usize, value: u8| {
            let mut bytes = bytes.clone();
            bytes[offset] = value;
            VectorArea::from_bytes(&bytes, Some(vl))
        };
        assert_eq!(with(VectorArea::SVE_LIVE_OFFSET, 2), None);
        assert_eq!(with(VectorArea::SVE_LIVE_OFFSET + 1, 1), None);
        // Z0[127:0] no longer matches V0.
        assert_eq!(with(VectorArea::SVE_PAYLOAD_OFFSET, !bytes[0]), None);
        assert_eq!(VectorArea::from_bytes(&bytes, None), None);

        let mut fpsimd_only = VectorArea::default().as_bytes().to_vec();
        assert!(VectorArea::from_bytes(&fpsimd_only, None).is_some());
        fpsimd_only[VectorArea::SVE_LIVE_OFFSET] = 1;
        assert_eq!(VectorArea::from_bytes(&fpsimd_only, None), None);
    }

    #[test]
    fn equality_ignores_a_payload_that_is_not_live() {
        let vl = vl(16);
        let mut stale = VectorArea::initial(Some(vl));
        assert!(stale.set_sve_payload(&payload(vl)));
        stale.discard_sve();
        assert_eq!(stale, VectorArea::initial(Some(vl)));
        assert_ne!(stale, VectorArea::default());

        let mut live = VectorArea::initial(Some(vl));
        assert!(live.set_sve_payload(&payload(vl)));
        assert_ne!(live, VectorArea::initial(Some(vl)));
    }
}

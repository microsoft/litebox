// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 signal contexts and Linux's `sigcontext.__reserved` extension records.
//!
//! Layout and parsing follow `setup_sigframe_layout` and `parse_user_sigframe` in
//! `arch/arm64/kernel/signal.c`, using `arch/arm64/include/uapi/asm/sigcontext.h`;
//! shared by kernel-built host frames and LiteBox-built guest frames.

use alloc::boxed::Box;
use core::mem::offset_of;
use core::ptr::NonNull;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// 16-byte storage unit of [`GuestVectorState`], aligned so V0-V31 can be
/// viewed as `u128`s (16-byte aligned on AArch64).
#[repr(C, align(16))]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct GuestVectorChunk([u8; 16]);

/// Guest FP/SIMD and optional non-streaming SVE state, in one 16-byte-aligned
/// heap buffer with a fixed layout that transition assembly accesses through
/// [`Self::as_mut_ptr`]:
///
/// | Offset                         | Contents                                   |
/// | ------------------------------ | ------------------------------------------ |
/// | [`Self::V_REGISTERS_OFFSET`]   | V0-V31, 16 bytes each, as `stp q` stores them |
/// | [`Self::FPSR_OFFSET`]          | FPSR (`u32`)                               |
/// | [`Self::FPCR_OFFSET`]          | FPCR (`u32`)                               |
/// | [`Self::SVE_LIVE_OFFSET`]      | nonzero exactly when the SVE payload is live |
/// | [`Self::SVE_REGISTERS_OFFSET`] | `SVE_SIG_REGS` payload for [`Self::sve_vl`], if any |
///
/// The buffer's size and SVE vector length are fixed at construction, so
/// in-place updates never reallocate.
pub struct GuestVectorState {
    /// The buffer, owned as by a `Box` (`Box::leak` in `from_chunks`, freed in
    /// `Drop`) but held as a raw root. Every access derives a short-lived
    /// reference from this root, and [`Self::as_mut_ptr`] returns the root
    /// itself, so neither this type's accesses nor moving it invalidate that
    /// pointer, as reborrowing or moving a `Box` would.
    storage: NonNull<[GuestVectorChunk]>,
    /// `None` when the platform does not manage SVE state; such state is never
    /// live, as after a syscall.
    sve_vl: Option<SveVectorLength>,
}

impl GuestVectorState {
    pub const V_REGISTERS_OFFSET: usize = 0;
    pub const FPSR_OFFSET: usize = Self::V_REGISTERS_OFFSET + 32 * size_of::<u128>();
    pub const FPCR_OFFSET: usize = Self::FPSR_OFFSET + size_of::<u32>();
    /// Syscall entry clears this byte: syscalls discard Z bits above 127,
    /// P0-P15 and FFR.
    pub const SVE_LIVE_OFFSET: usize = Self::FPCR_OFFSET + size_of::<u32>();
    pub const SVE_REGISTERS_OFFSET: usize =
        (Self::SVE_LIVE_OFFSET + 1).next_multiple_of(size_of::<GuestVectorChunk>());

    /// Returns the architectural initial state, all zero with SVE not live,
    /// with room for an SVE payload at `sve_vl`.
    pub fn new(sve_vl: Option<SveVectorLength>) -> Self {
        let size = Self::SVE_REGISTERS_OFFSET + sve_vl.map_or(0, SveVectorLength::registers_size);
        let chunks = size.div_ceil(size_of::<GuestVectorChunk>());
        Self::from_chunks(
            alloc::vec![GuestVectorChunk([0; 16]); chunks].into_boxed_slice(),
            sve_vl,
        )
    }

    fn from_chunks(chunks: Box<[GuestVectorChunk]>, sve_vl: Option<SveVectorLength>) -> Self {
        Self {
            storage: NonNull::from(Box::leak(chunks)),
            sve_vl,
        }
    }

    /// The SVE vector length of the payload this state holds when live.
    pub const fn sve_vl(&self) -> Option<SveVectorLength> {
        self.sve_vl
    }

    fn chunks(&self) -> &[GuestVectorChunk] {
        // SAFETY: `storage` is a live allocation this state owns. `&self`
        // excludes Rust writes, and accesses through `as_mut_ptr` must not
        // overlap this reference, per its contract.
        unsafe { self.storage.as_ref() }
    }

    fn bytes(&self) -> &[u8] {
        self.chunks().as_bytes()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `chunks`; `&mut self` excludes other Rust references.
        unsafe { self.storage.as_mut() }.as_mut_bytes()
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mut bytes = [0; size_of::<u32>()];
        bytes.copy_from_slice(&self.bytes()[offset..offset + size_of::<u32>()]);
        u32::from_ne_bytes(bytes)
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.bytes_mut()[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_ne_bytes());
    }

    pub fn v_registers(&self) -> &[u128; 32] {
        // SAFETY: the buffer is aligned for `u128` and always holds V0-V31 at
        // this offset; every bit pattern is a valid `u128`.
        unsafe {
            &*self
                .chunks()
                .as_ptr()
                .cast::<u8>()
                .add(Self::V_REGISTERS_OFFSET)
                .cast()
        }
    }

    pub fn v_registers_mut(&mut self) -> &mut [u128; 32] {
        // SAFETY: as in `v_registers`, and `&mut self` makes the view exclusive.
        unsafe { &mut *self.as_mut_ptr().add(Self::V_REGISTERS_OFFSET).cast() }
    }

    pub fn fpsr(&self) -> u32 {
        self.read_u32(Self::FPSR_OFFSET)
    }

    pub fn set_fpsr(&mut self, fpsr: u32) {
        self.write_u32(Self::FPSR_OFFSET, fpsr);
    }

    pub fn fpcr(&self) -> u32 {
        self.read_u32(Self::FPCR_OFFSET)
    }

    pub fn set_fpcr(&mut self, fpcr: u32) {
        self.write_u32(Self::FPCR_OFFSET, fpcr);
    }

    /// Returns the live SVE registers in `SVE_SIG_REGS` layout for
    /// [`Self::sve_vl`], or `None` when SVE state is not live: the upper Z
    /// bits, P0-P15 and FFR are zero.
    pub fn sve_registers(&self) -> Option<&[u8]> {
        let vl = self.sve_vl?;
        let bytes = self.bytes();
        (bytes[Self::SVE_LIVE_OFFSET] != 0).then(|| {
            &bytes[Self::SVE_REGISTERS_OFFSET..Self::SVE_REGISTERS_OFFSET + vl.registers_size()]
        })
    }

    fn set_sve_live(&mut self, live: bool) {
        self.bytes_mut()[Self::SVE_LIVE_OFFSET] = u8::from(live);
    }

    /// Makes SVE state live with `registers`, in `SVE_SIG_REGS` layout for
    /// [`Self::sve_vl`]. Returns `None`, leaving the state unchanged, without
    /// SVE or for a payload of another length.
    ///
    /// Like Linux's `rt_sigreturn`, bits 127:0 of Z0-Z31 are replaced by the V
    /// registers, which must already be set, so a later signal frame
    /// duplicates them consistently.
    pub fn set_sve_registers(&mut self, registers: &[u8]) -> Option<()> {
        let vl = self.sve_vl?;
        if registers.len() != vl.registers_size() {
            return None;
        }
        let v_registers = *self.v_registers();
        let payload = self
            .bytes_mut()
            .get_mut(Self::SVE_REGISTERS_OFFSET..)?
            .get_mut(..registers.len())?;
        payload.copy_from_slice(registers);
        // The payload is endianness-invariant: byte `i` of a Z register holds
        // its bits [8i+7:8i], i.e. the little-endian bytes of the V register.
        for (z, v) in payload
            .chunks_exact_mut(usize::from(vl.bytes()))
            .zip(&v_registers)
        {
            z[..size_of::<u128>()].copy_from_slice(&v.to_le_bytes());
        }
        self.set_sve_live(true);
        Some(())
    }

    /// Writes the records Linux's `setup_sigframe_layout` lays out for this
    /// state into `reserved`: `fpsimd_context`, then an `sve_context` if the
    /// state has an SVE VL (with the payload only while live), then the
    /// terminator. Allocates nothing and does not panic.
    pub fn write_signal_records(&self, reserved: &mut [u8; RESERVED_SIZE]) -> Option<()> {
        FpsimdContext {
            head: Aarch64Ctx {
                magic: FPSIMD_MAGIC,
                size: u32::try_from(size_of::<FpsimdContext>()).ok()?,
            },
            fpsr: self.fpsr(),
            fpcr: self.fpcr(),
            vregs: *self.v_registers(),
        }
        .write_to_prefix(reserved)
        .ok()?;
        let mut end = size_of::<FpsimdContext>();
        if let Some(vl) = self.sve_vl {
            let registers = self.sve_registers();
            let size = registers.map_or(size_of::<SveContext>(), |_| {
                vl.context_size().next_multiple_of(16)
            });
            SveContext {
                head: Aarch64Ctx {
                    magic: SVE_MAGIC,
                    size: u32::try_from(size).ok()?,
                },
                vl: vl.bytes(),
                flags: SveContextFlags::empty().bits(),
                reserved: [0; 2],
            }
            .write_to_prefix(reserved.get_mut(end..)?)
            .ok()?;
            if let Some(registers) = registers {
                reserved
                    .get_mut(end + size_of::<SveContext>()..)?
                    .get_mut(..registers.len())?
                    .copy_from_slice(registers);
            }
            end += size;
        }
        Aarch64Ctx { magic: 0, size: 0 }
            .write_to_prefix(reserved.get_mut(end..)?)
            .ok()
    }

    /// Loads the state `rt_sigreturn` restores from `records`. SVE records are
    /// validated as by [`SignalRecords::sve_registers`] for [`Self::sve_vl`];
    /// on error the state is unchanged. Allocates nothing and does not panic,
    /// so signal handlers may use it.
    pub fn load_signal_records(
        &mut self,
        records: &SignalRecords<'_>,
    ) -> Result<(), InvalidSignalRecords> {
        let live = records.sve_registers(self.sve_vl)?;
        *self.v_registers_mut() = records.fpsimd.vregs;
        self.set_fpsr(records.fpsimd.fpsr);
        self.set_fpcr(records.fpsimd.fpcr);
        if let Some(registers) = live {
            // `sve_registers` returns a payload of exactly this state's VL.
            self.set_sve_registers(registers)
                .ok_or(InvalidSignalRecords)
        } else {
            self.set_sve_live(false);
            Ok(())
        }
    }

    /// Assigns `source` to this state in place, without allocating.
    ///
    /// # Panics
    ///
    /// Panics if `source`'s SVE state is live at a vector length other than
    /// this state's.
    pub fn copy_from(&mut self, source: &Self) {
        let fpsimd = Self::V_REGISTERS_OFFSET..Self::SVE_LIVE_OFFSET;
        self.bytes_mut()[fpsimd.clone()].copy_from_slice(&source.bytes()[fpsimd]);
        match source.sve_registers() {
            Some(registers) => {
                assert_eq!(
                    self.sve_vl, source.sve_vl,
                    "live SVE state must have this state's vector length"
                );
                let payload =
                    Self::SVE_REGISTERS_OFFSET..Self::SVE_REGISTERS_OFFSET + registers.len();
                self.bytes_mut()[payload].copy_from_slice(registers);
                self.set_sve_live(true);
            }
            None => self.set_sve_live(false),
        }
    }

    /// Returns the aligned buffer for transition assembly. The pointer is the
    /// buffer's raw root, so it stays valid until this state is dropped:
    /// neither this type's methods nor moving it invalidate it. Accesses
    /// through it must not overlap references this type's methods create or
    /// return, and writes must keep the layout valid.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_ptr().cast()
    }
}

// SAFETY: the state uniquely owns its buffer, as a `Box<[GuestVectorChunk]>`
// would, and accesses it only through `&self` or `&mut self`; raw pointers it
// hands out are subject to their own contract.
unsafe impl Send for GuestVectorState {}
// SAFETY: as for `Send`; `&self` methods only read the buffer.
unsafe impl Sync for GuestVectorState {}

impl Clone for GuestVectorState {
    fn clone(&self) -> Self {
        Self::from_chunks(self.chunks().into(), self.sve_vl)
    }
}

impl Drop for GuestVectorState {
    fn drop(&mut self) {
        // SAFETY: `storage` came from `Box::leak` in `from_chunks` and is freed
        // only here.
        drop(unsafe { Box::from_raw(self.storage.as_ptr()) });
    }
}

impl Default for GuestVectorState {
    /// FP/SIMD-only initial state.
    fn default() -> Self {
        Self::new(None)
    }
}

/// Equal when the architectural state is: the SVE payload is compared only
/// while live.
impl PartialEq for GuestVectorState {
    fn eq(&self, other: &Self) -> bool {
        let fpsimd = Self::V_REGISTERS_OFFSET..Self::SVE_LIVE_OFFSET;
        self.sve_vl == other.sve_vl
            && self.bytes()[fpsimd.clone()] == other.bytes()[fpsimd]
            && self.sve_registers() == other.sve_registers()
    }
}

impl Eq for GuestVectorState {}

impl core::fmt::Debug for GuestVectorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuestVectorState")
            .field("v_registers", &self.v_registers())
            .field("fpsr", &self.fpsr())
            .field("fpcr", &self.fpcr())
            .field("sve_vl", &self.sve_vl)
            .field("sve_registers", &self.sve_registers())
            .finish_non_exhaustive()
    }
}

/// An SVE vector length (VL), in bytes, whose live `sve_context` fits in
/// `__reserved`, so LiteBox never needs an `extra_context`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SveVectorLength(u16);

impl SveVectorLength {
    /// The largest VL, 768 bits, whose live record Linux places in `__reserved`
    /// after the FP/SIMD record; larger VLs need an `extra_context`.
    pub const MAX: Self = Self(96);

    /// Returns `bytes` as a vector length if it is a multiple of 16 in
    /// `16..=`[`Self::MAX`].
    pub const fn new(bytes: u16) -> Option<Self> {
        if bytes >= 16 && bytes <= Self::MAX.0 && bytes.is_multiple_of(16) {
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Returns the length in bytes.
    pub const fn bytes(self) -> u16 {
        self.0
    }

    /// `SVE_SIG_REGS_SIZE`: Z0-Z31, P0-P15 and FFR, in that order. Each
    /// predicate register holds one bit per byte of a Z register.
    pub const fn registers_size(self) -> usize {
        let vl = self.0 as usize;
        32 * vl + 17 * (vl / 8)
    }

    /// `SVE_SIG_CONTEXT_SIZE`: an `sve_context` header and register payload.
    pub const fn context_size(self) -> usize {
        size_of::<SveContext>() + self.registers_size()
    }
}

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
    pub __reserved: [u8; RESERVED_SIZE],
}

/// Size of `sigcontext.__reserved`.
pub const RESERVED_SIZE: usize = 4096;
/// Space Linux reserves in `__reserved` for the terminator (`TERMINATOR_SIZE`)
/// and an `extra_context` (`EXTRA_CONTEXT_SIZE`) before placing other records.
const RESERVED_TAIL_SIZE: usize = 16 + 32;

pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
pub const ESR_MAGIC: u32 = 0x4553_5201;
pub const SVE_MAGIC: u32 = 0x5356_4501;
pub const EXTRA_MAGIC: u32 = 0x4558_5401;

/// The kernel's `struct _aarch64_ctx`, which starts every record. Zero in both
/// fields terminates a record list.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct Aarch64Ctx {
    pub magic: u32,
    pub size: u32,
}

/// The kernel's `struct fpsimd_context`.
#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct FpsimdContext {
    pub head: Aarch64Ctx,
    pub fpsr: u32,
    pub fpcr: u32,
    pub vregs: [u128; 32],
}

/// The kernel's `struct sve_context`, the header of an SVE record. A live
/// record continues with the `SVE_SIG_REGS` payload.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct SveContext {
    pub head: Aarch64Ctx,
    pub vl: u16,
    /// [`SveContextFlags`] bits.
    pub flags: u16,
    pub reserved: [u16; 2],
}

bitflags::bitflags! {
    /// `sve_context.flags`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SveContextFlags: u16 {
        /// `SVE_SIG_FLAG_SM`: the record holds streaming-mode (SME) state.
        const SM = 1;
    }
}

const _: () = {
    // Transition assembly hardcodes Q-register offsets from the V registers.
    assert!(GuestVectorState::V_REGISTERS_OFFSET == 0);
    assert!(align_of::<u128>() <= align_of::<GuestVectorChunk>());
    assert!(GuestVectorState::FPSR_OFFSET == 512);
    assert!(GuestVectorState::FPCR_OFFSET == 516);
    assert!(GuestVectorState::SVE_LIVE_OFFSET == 520);
    assert!(GuestVectorState::SVE_REGISTERS_OFFSET == 528);
    assert!(size_of::<Aarch64Ctx>() == 8);
    assert!(size_of::<FpsimdContext>() == 528);
    // Pin FPSR/FPCR order: equal-size fields can swap unnoticed and install
    // guest FPSR exception bits as FPCR trap enables.
    assert!(offset_of!(FpsimdContext, fpsr) == 8);
    assert!(offset_of!(FpsimdContext, fpcr) == 12);
    assert!(offset_of!(FpsimdContext, vregs) == 16);
    assert!(size_of::<SveContext>() == 16);
    assert!(offset_of!(SveContext, vl) == 8);
    assert!(offset_of!(SveContext, flags) == 10);
    // Linux's `__sigframe_alloc` places a live record at `SveVectorLength::MAX`
    // in `__reserved`, so frames written for any valid VL need no extra space.
    assert!(
        size_of::<FpsimdContext>() + SveVectorLength::MAX.context_size().next_multiple_of(16)
            <= RESERVED_SIZE - RESERVED_TAIL_SIZE
    );
};

/// A frame whose records Linux would refuse to restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSignalRecords;

/// How [`parse_signal_records`] treats records other than FP/SIMD, ESR, SVE
/// and `extra_context` records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownRecords {
    /// Skip them, for kernel-built host frames, which may carry state for
    /// extensions LiteBox does not handle.
    Skip,
    /// Reject the frame, as Linux does for records of extensions the system
    /// lacks.
    Reject,
}

/// The records `rt_sigreturn` restores from.
pub struct SignalRecords<'a> {
    pub fpsimd: FpsimdContext,
    /// Offset of the `fpsimd_context` record in `__reserved`.
    pub fpsimd_reserved_offset: usize,
    sve: Option<SveRecord<'a>>,
}

/// An `sve_context` record.
#[derive(Clone, Copy, Debug)]
struct SveRecord<'a> {
    header: SveContext,
    /// The whole record, `header.head.size` bytes.
    record: &'a [u8],
}

impl<'a> SignalRecords<'a> {
    /// Validates the `sve_context` record, if any, for a thread with SVE vector length `vl`
    /// (`None` without SVE), like Linux's `restore_sve_fpsimd_context`. Returns the live
    /// `SVE_SIG_REGS` payload, `vl.registers_size()` bytes, or `Ok(None)` without a record
    /// or for a header-only one. Streaming (SME) state is rejected: LiteBox does not
    /// support it.
    ///
    /// Without SVE only a header-only VL-0 record is accepted, as SME-only hosts write.
    pub fn sve_registers(
        &self,
        vl: Option<SveVectorLength>,
    ) -> Result<Option<&'a [u8]>, InvalidSignalRecords> {
        let Some(sve) = self.sve else {
            return Ok(None);
        };
        let flags = SveContextFlags::from_bits_retain(sve.header.flags);
        if flags.contains(SveContextFlags::SM)
            || sve.header.vl != vl.map_or(0, SveVectorLength::bytes)
        {
            return Err(InvalidSignalRecords);
        }
        if sve.record.len() == size_of::<SveContext>() {
            return Ok(None);
        }
        let vl = vl.ok_or(InvalidSignalRecords)?;
        sve.record
            .get(size_of::<SveContext>()..vl.context_size())
            .map(Some)
            .ok_or(InvalidSignalRecords)
    }
}

/// Parses `__reserved` using Linux's `parse_user_sigframe` rules, except that
/// an `extra_context` is rejected in both [`UnknownRecords`] modes: records in
/// its extra space, such as `sve_context`, would go unread. SVE restore
/// validation is performed by [`SignalRecords::sve_registers`].
pub fn parse_signal_records(
    reserved: &[u8; RESERVED_SIZE],
    unknown: UnknownRecords,
) -> Result<SignalRecords<'_>, InvalidSignalRecords> {
    let mut offset = 0;
    let mut fpsimd = None;
    let mut sve = None;
    loop {
        let remaining = &reserved[offset..];
        if remaining.len() < size_of::<Aarch64Ctx>() || !offset.is_multiple_of(16) {
            return Err(InvalidSignalRecords);
        }
        let (head, _) =
            Aarch64Ctx::read_from_prefix(remaining).map_err(|_| InvalidSignalRecords)?;
        let size = head.size as usize;
        let record = remaining.get(..size).ok_or(InvalidSignalRecords)?;
        match head.magic {
            0 if size == 0 => break,
            FPSIMD_MAGIC if fpsimd.is_none() && size == size_of::<FpsimdContext>() => {
                let (context, _) =
                    FpsimdContext::read_from_prefix(record).map_err(|_| InvalidSignalRecords)?;
                fpsimd = Some((context, offset));
            }
            ESR_MAGIC => {}
            SVE_MAGIC if sve.is_none() => {
                let (header, _) =
                    SveContext::read_from_prefix(record).map_err(|_| InvalidSignalRecords)?;
                sve = Some(SveRecord { header, record });
            }
            FPSIMD_MAGIC | SVE_MAGIC | EXTRA_MAGIC | 0 => return Err(InvalidSignalRecords),
            _ if unknown == UnknownRecords::Skip => {}
            _ => return Err(InvalidSignalRecords),
        }
        if size < size_of::<Aarch64Ctx>() {
            return Err(InvalidSignalRecords);
        }
        offset += size;
    }
    let (fpsimd, fpsimd_reserved_offset) = fpsimd.ok_or(InvalidSignalRecords)?;
    Ok(SignalRecords {
        fpsimd,
        fpsimd_reserved_offset,
        sve,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    type Records = [u8; RESERVED_SIZE];

    /// State with patterned FP/SIMD registers and room for SVE at `sve_vl`.
    fn fpsimd_state(sve_vl: Option<SveVectorLength>) -> GuestVectorState {
        let mut state = GuestVectorState::new(sve_vl);
        *state.v_registers_mut() =
            core::array::from_fn(|n| 0x0101_0101_0101_0101_0101_0101_0101_0101 * n as u128);
        state.set_fpsr(0x0800_0010);
        state.set_fpcr(0x0300_0000);
        state
    }

    fn sve_registers(vl: SveVectorLength) -> Vec<u8> {
        (0..vl.registers_size())
            .map(|i| u8::try_from((i * 7 + 3) % 256).unwrap())
            .collect()
    }

    fn live_state(vl: SveVectorLength) -> GuestVectorState {
        let mut state = fpsimd_state(Some(vl));
        state.set_sve_registers(&sve_registers(vl)).unwrap();
        state
    }

    fn write_frame(state: &GuestVectorState) -> Records {
        let mut records = [0; RESERVED_SIZE];
        state.write_signal_records(&mut records).unwrap();
        records
    }

    fn header(records: &Records, offset: usize) -> (u32, u32) {
        let (head, _) = Aarch64Ctx::read_from_prefix(&records[offset..]).unwrap();
        (head.magic, head.size)
    }

    fn set_header(records: &mut Records, offset: usize, magic: u32, size: u32) {
        Aarch64Ctx { magic, size }
            .write_to_prefix(&mut records[offset..])
            .unwrap();
    }

    #[test]
    fn records_follow_the_kernel_layout() {
        for bytes in [16, 32, 64, 96] {
            let vl = SveVectorLength::new(bytes).unwrap();
            let live = write_frame(&live_state(vl));
            let size = (16 + vl.registers_size()).next_multiple_of(16);
            assert_eq!(header(&live, 0), (FPSIMD_MAGIC, 528));
            assert_eq!(
                header(&live, 528),
                (SVE_MAGIC, u32::try_from(size).unwrap())
            );
            assert_eq!(header(&live, 528 + size), (0, 0));

            let header_only = write_frame(&fpsimd_state(Some(vl)));
            assert_eq!(header(&header_only, 528), (SVE_MAGIC, 16));
            assert_eq!(header(&header_only, 544), (0, 0));
        }
        assert_eq!(header(&write_frame(&fpsimd_state(None)), 528), (0, 0));
    }

    #[test]
    fn live_state_takes_low_z_bits_from_the_fpsimd_registers() {
        let vl = SveVectorLength::new(32).unwrap();
        let state = live_state(vl);
        let registers = state.sve_registers().unwrap();
        for (n, z) in registers[..32 * 32].as_chunks::<32>().0.iter().enumerate() {
            assert_eq!(z[..16], state.v_registers()[n].to_le_bytes());
            assert_eq!(z[16..], sve_registers(vl)[n * 32 + 16..n * 32 + 32]);
        }
        assert_eq!(registers[32 * 32..], sve_registers(vl)[32 * 32..]);

        let mut unchanged = fpsimd_state(Some(vl));
        assert_eq!(unchanged.set_sve_registers(&[0; 10]), None);
        assert_eq!(unchanged, fpsimd_state(Some(vl)));
        let mut without_sve = fpsimd_state(None);
        assert_eq!(without_sve.set_sve_registers(&sve_registers(vl)), None);
        assert_eq!(without_sve, fpsimd_state(None));
    }

    #[test]
    fn equality_ignores_a_payload_that_is_not_live() {
        let vl = SveVectorLength::new(16).unwrap();
        let mut stale = live_state(vl);
        stale.set_sve_live(false);
        assert_eq!(stale, fpsimd_state(Some(vl)));
        assert_ne!(live_state(vl), fpsimd_state(Some(vl)));
        assert_ne!(fpsimd_state(Some(vl)), fpsimd_state(None));
        let mut other = live_state(vl);
        other.bytes_mut()[GuestVectorState::SVE_REGISTERS_OFFSET + 32 * 16] ^= 1;
        assert_ne!(other, live_state(vl));
    }

    #[test]
    fn copy_from_copies_the_sve_payload_only_when_live() {
        let vl = SveVectorLength::new(64).unwrap();
        let mut state = GuestVectorState::new(Some(vl));
        state.copy_from(&live_state(vl));
        assert_eq!(state, live_state(vl));

        // Non-live SVE state copies FP/SIMD only, whatever its VL.
        for source in [fpsimd_state(None), fpsimd_state(Some(SveVectorLength::MAX))] {
            let mut state = live_state(vl);
            state.copy_from(&source);
            assert_eq!(state, fpsimd_state(Some(vl)));
        }
    }

    /// Transition assembly keeps the pointer from `as_mut_ptr` while Rust uses
    /// the state between guest entries. Under Miri this checks that accessor
    /// reads and writes, `copy_from`, `load_signal_records` and moving the
    /// state leave the pointer valid, as the published pointers require.
    #[test]
    fn buffer_pointer_stays_valid_across_accessor_use() {
        let vl = SveVectorLength::new(16).unwrap();
        let mut state = GuestVectorState::new(Some(vl));
        let buffer = state.as_mut_ptr();
        let mut state = core::convert::identity(state);
        // The buffer is 16-byte aligned.
        let v_registers: *mut u128 = buffer.cast();
        let status: *mut u32 = buffer.wrapping_add(GuestVectorState::FPSR_OFFSET).cast();
        let control: *mut u32 = buffer.wrapping_add(GuestVectorState::FPCR_OFFSET).cast();
        let live = buffer.wrapping_add(GuestVectorState::SVE_LIVE_OFFSET);

        // SAFETY: `buffer` is `state`'s live buffer, aligned for these fields,
        // and no reference into it is live during each access.
        unsafe { status.write(0x10) };
        assert_eq!(state.fpsr(), 0x10);
        state.set_fpcr(0x0040_0000);
        // SAFETY: as above.
        assert_eq!(unsafe { control.read() }, 0x0040_0000);

        let source = live_state(vl);
        state.copy_from(&source);
        // SAFETY: as above.
        assert_eq!(
            unsafe { v_registers.add(3).read() },
            source.v_registers()[3]
        );
        // Clear the live byte as syscall entry does.
        // SAFETY: as above.
        unsafe { live.write(0) };
        assert_eq!(state, fpsimd_state(Some(vl)));

        let records = write_frame(&source);
        let parsed = parse_signal_records(&records, UnknownRecords::Reject).unwrap();
        state.load_signal_records(&parsed).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { live.read() }, 1);
        assert_eq!(state.clone(), source);

        *state.v_registers_mut() = [7; 32];
        // SAFETY: as above.
        assert_eq!(unsafe { v_registers.add(31).read() }, 7);
        // SAFETY: as above.
        unsafe { v_registers.write(9) };
        assert_eq!(state.v_registers()[0], 9);
    }

    #[test]
    #[should_panic(expected = "live SVE state must have this state's vector length")]
    fn copy_from_rejects_live_state_at_another_vector_length() {
        let mut state = GuestVectorState::new(SveVectorLength::new(32));
        state.copy_from(&live_state(SveVectorLength::new(16).unwrap()));
    }

    #[test]
    fn records_round_trip_through_load_signal_records() {
        for state in [
            fpsimd_state(None),
            fpsimd_state(SveVectorLength::new(16)),
            live_state(SveVectorLength::new(16).unwrap()),
            live_state(SveVectorLength::MAX),
        ] {
            let records = write_frame(&state);
            let parsed = parse_signal_records(&records, UnknownRecords::Reject).unwrap();
            let mut loaded = GuestVectorState::new(state.sve_vl());
            loaded.load_signal_records(&parsed).unwrap();
            assert_eq!(loaded, state);

            // A rejected record list leaves the state unchanged.
            let mut other = GuestVectorState::new(SveVectorLength::new(32));
            if state.sve_vl().is_some() {
                assert_eq!(
                    other.load_signal_records(&parsed),
                    Err(InvalidSignalRecords)
                );
                assert_eq!(other, GuestVectorState::new(SveVectorLength::new(32)));
            }
        }
    }

    #[test]
    fn unknown_records_are_skipped_only_when_asked() {
        let mut records = write_frame(&fpsimd_state(None));
        // Replace the terminator with an unknown record followed by an ESR one.
        set_header(&mut records, 528, 0x5450_4902, 16);
        set_header(&mut records, 544, ESR_MAGIC, 16);
        assert_eq!(
            parse_signal_records(&records, UnknownRecords::Skip).map(|r| r.fpsimd_reserved_offset),
            Ok(0)
        );
        assert_eq!(
            parse_signal_records(&records, UnknownRecords::Reject).err(),
            Some(InvalidSignalRecords)
        );
    }

    /// Records past an `extra_context` would go unread, so it is never skipped.
    #[test]
    fn extra_context_is_rejected() {
        let mut records = write_frame(&fpsimd_state(None));
        set_header(&mut records, 528, EXTRA_MAGIC, 32);
        for unknown in [UnknownRecords::Skip, UnknownRecords::Reject] {
            assert_eq!(
                parse_signal_records(&records, unknown).err(),
                Some(InvalidSignalRecords)
            );
        }
    }

    #[test]
    fn parser_rejects_what_linux_rejects() {
        const SVE: usize = 528;
        const END: usize = SVE + 576;

        // Replaces the terminator with `appended`, followed by a terminator.
        fn append(r: &mut Records, appended: &[u8]) {
            r[END..END + appended.len()].copy_from_slice(appended);
            set_header(r, END + appended.len(), 0, 0);
        }
        fn record(magic: u32, size: u32) -> [u8; 16] {
            let mut bytes = [0; 16];
            Aarch64Ctx { magic, size }
                .write_to_prefix(&mut bytes)
                .unwrap();
            bytes
        }

        type Mutation = fn(&mut Records);

        let vl = SveVectorLength::new(16).unwrap();
        let state = live_state(vl);
        let mut records = write_frame(&state);
        assert_eq!(header(&records, END), (0, 0));
        append(&mut records, &record(ESR_MAGIC, 16));
        assert!(
            parse_signal_records(&records, UnknownRecords::Reject).is_ok(),
            "appended ESR record"
        );

        let cases: &[(&str, Mutation)] = &[
            ("missing fpsimd", |r| set_header(r, 0, ESR_MAGIC, 528)),
            ("short fpsimd", |r| {
                set_header(r, 0, FPSIMD_MAGIC, 512);
                set_header(r, 512, ESR_MAGIC, 16);
            }),
            ("duplicate fpsimd", |r| {
                let fpsimd = r[..528].to_vec();
                append(r, &fpsimd);
            }),
            ("duplicate sve", |r| append(r, &record(SVE_MAGIC, 16))),
            ("size below a header", |r| append(r, &record(ESR_MAGIC, 4))),
            ("misaligned record", |r| {
                let mut bytes = [0; 32];
                bytes[..16].copy_from_slice(&record(ESR_MAGIC, 24));
                append(r, &bytes);
            }),
            ("record overruns __reserved", |r| {
                let size = u32::try_from(RESERVED_SIZE - SVE + 16).unwrap();
                set_header(r, SVE, SVE_MAGIC, size);
            }),
            ("no terminator", |r| {
                let size = u32::try_from(RESERVED_SIZE - END).unwrap();
                set_header(r, END, ESR_MAGIC, size);
            }),
            ("nonzero terminator size", |r| set_header(r, END, 0, 16)),
            ("unknown magic", |r| append(r, &record(0x1234_5678, 16))),
            ("partial SVE payload", |r| {
                let (_, size) = header(r, SVE);
                set_header(r, SVE, SVE_MAGIC, size - 16);
                set_header(r, END - 16, 0, 0);
            }),
        ];
        for (name, mutate) in cases {
            let mut records = write_frame(&state);
            mutate(&mut records);
            let rejected = match parse_signal_records(&records, UnknownRecords::Reject) {
                Err(InvalidSignalRecords) => true,
                Ok(parsed) => parsed.sve_registers(Some(vl)).is_err(),
            };
            assert!(rejected, "{name}");
        }

        let records = write_frame(&state);
        let parsed = parse_signal_records(&records, UnknownRecords::Reject).unwrap();
        assert!(
            parsed.sve_registers(SveVectorLength::new(32)).is_err(),
            "VL mismatch"
        );

        let mut records = write_frame(&state);
        records[SVE + 10..SVE + 12].copy_from_slice(&SveContextFlags::SM.bits().to_ne_bytes());
        let parsed = parse_signal_records(&records, UnknownRecords::Skip).unwrap();
        assert!(parsed.sve_registers(Some(vl)).is_err(), "streaming mode");
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent x86-64 XSAVE layout discovery and aligned state storage.

use alloc::{boxed::Box, vec, vec::Vec};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

/// Size of the architectural legacy x87/SSE save area.
pub const XSAVE_LEGACY_SIZE: usize = core::mem::size_of::<XsaveLegacyArea>();
/// Offset of the XSAVE header in a standard-layout save area.
pub const XSAVE_HEADER_OFFSET: usize = XSAVE_LEGACY_SIZE;
/// Size of the architectural XSAVE header.
pub const XSAVE_HEADER_SIZE: usize = core::mem::size_of::<XsaveHeader>();

/// XCR0 and XSTATE_BV bit for x87 state.
pub const XFEATURE_MASK_X87: u64 = 1 << 0;
/// XCR0 and XSTATE_BV bit for SSE state (XMM registers and MXCSR).
pub const XFEATURE_MASK_SSE: u64 = 1 << 1;
/// XCR0 and XSTATE_BV bit for the upper halves of the YMM registers.
pub const XFEATURE_MASK_AVX: u64 = 1 << 2;
/// The state components held in the legacy area.
pub const XFEATURE_MASK_LEGACY: u64 = XFEATURE_MASK_X87 | XFEATURE_MASK_SSE;

/// Architectural x86-64 FXSAVE area at the start of a standard XSAVE area, in
/// the 64-bit format written by `FXSAVE64` and `XSAVE64`.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct XsaveLegacyArea {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub reserved1: u8,
    pub error_opcode: u16,
    /// Last x87 instruction pointer (FIP).
    pub instruction_pointer: u64,
    /// Last x87 data operand pointer (FDP).
    pub data_pointer: u64,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub float_registers: [[u8; 16]; 8],
    pub xmm_registers: [[u8; 16]; 16],
    pub reserved4: [u8; 96],
}

impl Default for XsaveLegacyArea {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

/// Architectural header following the legacy area in an XSAVE area.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct XsaveHeader {
    /// Bitmap of state components that are not in their initial state.
    pub xstate_bv: u64,
    /// Compacted-format indicator and bitmap. Zero for standard format.
    pub xcomp_bv: u64,
    pub reserved: [u8; 48],
}

impl Default for XsaveHeader {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

/// An initialized, 64-byte-aligned storage chunk for CPU or host context buffers.
#[repr(C, align(64))]
#[derive(Clone, Debug, PartialEq, Eq, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct XsaveChunk(
    /// The chunk's raw storage bytes.
    pub [u8; 64],
);

/// Standard-layout XSAVE requirements for the host's enabled CPU state.
pub struct XsaveLayout {
    /// Required buffer size in bytes for the state components in `mask`.
    pub size: usize,
    /// Saved user-state feature mask, suitable for XSAVE and XRSTOR.
    pub mask: u64,
    /// Locations of saved state components beyond the legacy x87/SSE area.
    pub components: Vec<XsaveComponent>,
    /// Whether the CPU supports XSAVEOPT.
    pub xsaveopt: bool,
    /// MXCSR bits the host accepts; restoring any other bit faults.
    pub mxcsr_mask: u32,
}

/// An extended state component in the standard XSAVE layout.
pub struct XsaveComponent {
    /// Architectural feature bit in XCR0 and XSTATE_BV.
    pub id: u32,
    /// Byte offset of this component in the save area.
    pub offset: usize,
    /// Size of this component in bytes.
    pub size: usize,
}

impl XsaveLayout {
    /// AMX tile state (XTILECFG and XTILEDATA), excluded to avoid about 8 KiB
    /// of additional storage per save area.
    ///
    /// Excluding these bits does not disable AMX execution. Platforms must
    /// prevent guest enablement or manage AMX state separately. On Linux,
    /// tile-data use requires explicit permission and is lazily enabled via XFD.
    pub const EXCLUDED_FEATURES: u64 = (1 << 17) | (1 << 18);

    /// Returns the host layout, detecting it on first use.
    ///
    /// # Panics
    /// Panics under the same conditions as [`Self::detect`].
    #[must_use]
    pub fn get() -> &'static Self {
        static LAYOUT: spin::Once<XsaveLayout> = spin::Once::new();
        LAYOUT.call_once(Self::detect)
    }

    /// Detects the current host's enabled XSAVE features and standard layout,
    /// excluding [`Self::EXCLUDED_FEATURES`].
    ///
    /// # Panics
    /// Panics if XSAVE is unavailable, disabled by the host OS, or reports an
    /// invalid layout. Both x87 and SSE state must be enabled.
    #[must_use]
    pub fn detect() -> Self {
        const CPUID_XSAVE: u32 = 1 << 26;
        const CPUID_OSXSAVE: u32 = 1 << 27;

        assert!(core::arch::x86_64::__cpuid(0).eax >= 0x0d);
        let feature_info = core::arch::x86_64::__cpuid(1);
        assert_eq!(
            feature_info.ecx & (CPUID_XSAVE | CPUID_OSXSAVE),
            CPUID_XSAVE | CPUID_OSXSAVE,
            "XSAVE must be supported and enabled by the host OS",
        );
        let features = core::arch::x86_64::__cpuid_count(0x0d, 0);
        // SAFETY: CPUID confirms that the OS has enabled XSAVE and XGETBV.
        let mask = unsafe { core::arch::x86_64::_xgetbv(0) } & !Self::EXCLUDED_FEATURES;
        assert_eq!(mask & 3, 3, "x87 and SSE state must be enabled");
        let max_size = features.ebx as usize;
        assert!(max_size >= XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE);
        let components: Vec<XsaveComponent> = (2..64)
            .filter(|id| mask & (1 << id) != 0)
            .map(|id| {
                let feature = core::arch::x86_64::__cpuid_count(0x0d, id);
                let component = XsaveComponent {
                    id,
                    offset: feature.ebx as usize,
                    size: feature.eax as usize,
                };
                assert!(component.offset + component.size <= max_size);
                component
            })
            .collect();
        let size = components
            .iter()
            .map(|component| component.offset + component.size)
            .fold(XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE, usize::max);
        let xsaveopt = core::arch::x86_64::__cpuid_count(0x0d, 1).eax & 1 != 0;
        Self {
            size,
            mask,
            components,
            xsaveopt,
            mxcsr_mask: detect_mxcsr_mask(),
        }
    }
}

/// Reads the host's supported MXCSR bits from the FXSAVE area.
fn detect_mxcsr_mask() -> u32 {
    /// Value implied by a zero MXCSR_MASK, on processors without DAZ.
    const DEFAULT_MXCSR_MASK: u32 = 0xffbf;

    let mut area: [XsaveChunk; XSAVE_LEGACY_SIZE / size_of::<XsaveChunk>()] =
        FromZeros::new_zeroed();
    // SAFETY: FXSAVE64 only writes the 512-byte legacy area to this
    // sufficiently aligned buffer.
    unsafe {
        core::arch::asm!(
            "fxsave64 [{}]",
            in(reg) area.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
    match XsaveLegacyArea::read_from_bytes(area.as_bytes()) {
        Ok(legacy) if legacy.mxcsr_mask != 0 => legacy.mxcsr_mask,
        _ => DEFAULT_MXCSR_MASK,
    }
}

/// Represents the standard-layout XSAVE area for a guest context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XsaveArea {
    storage: Box<[XsaveChunk]>,
    size: usize,
}

impl XsaveArea {
    /// Architectural initial x87 control word, used when x87 is in init state.
    pub const GUEST_INITIAL_X87_CONTROL_WORD: u16 = 0x037f;
    /// Architectural initial MXCSR, with all SIMD exceptions masked.
    pub const GUEST_INITIAL_MXCSR: u32 = 0x1f80;

    /// Allocates initial CPU state for the given layout.
    ///
    /// The zero XSTATE_BV requests architectural init state on XRSTOR. MXCSR
    /// is initialized explicitly because standard XRSTOR loads it even when
    /// SSE is marked as initial. Extended components and header padding are zero.
    ///
    /// # Panics
    /// Panics if the layout cannot hold the legacy area and XSAVE header.
    #[must_use]
    pub fn initial(layout: &XsaveLayout) -> Self {
        assert!(
            layout.size >= XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE,
            "XSAVE layout must include the legacy area and header",
        );
        let mut area = Self::zeroed(layout);
        area.set_initial_controls();
        area
    }

    /// Discards saved state and restores architectural initial state without
    /// replacing the aligned allocation.
    pub fn reset_to_initial(&mut self) {
        self.storage.as_mut_bytes().fill(0);
        self.set_initial_controls();
    }

    fn zeroed(layout: &XsaveLayout) -> Self {
        let chunks = layout.size.div_ceil(size_of::<XsaveChunk>());
        Self {
            storage: vec![XsaveChunk([0; 64]); chunks].into_boxed_slice(),
            size: layout.size,
        }
    }

    fn set_initial_controls(&mut self) {
        self.legacy_area_mut().mxcsr = Self::GUEST_INITIAL_MXCSR;
    }

    /// Returns the architectural x87/SSE state at the start of this area.
    #[must_use]
    pub fn legacy_area(&self) -> &XsaveLegacyArea {
        // SAFETY: storage is 64-byte aligned and always contains the 512-byte legacy area.
        unsafe { &*self.as_ptr().cast() }
    }

    // Mutable views stay private so that callers cannot make the state unrestorable.
    fn legacy_area_mut(&mut self) -> &mut XsaveLegacyArea {
        // SAFETY: storage is 64-byte aligned and always contains the 512-byte legacy area.
        unsafe { &mut *self.as_mut_ptr().cast() }
    }

    /// Returns the architectural XSAVE header.
    #[must_use]
    pub fn header(&self) -> &XsaveHeader {
        // SAFETY: storage contains the header at its architectural offset.
        unsafe { &*self.as_ptr().add(XSAVE_HEADER_OFFSET).cast() }
    }

    fn header_mut(&mut self) -> &mut XsaveHeader {
        // SAFETY: storage contains the header at its architectural offset.
        unsafe { &mut *self.as_mut_ptr().add(XSAVE_HEADER_OFFSET).cast() }
    }

    /// Returns a complete legacy area with architectural initial state
    /// substituted for components that are not present in `XSTATE_BV`.
    #[must_use]
    pub fn materialized_legacy_area(&self) -> XsaveLegacyArea {
        let saved = self.legacy_area();
        let mut state = XsaveLegacyArea {
            control_word: Self::GUEST_INITIAL_X87_CONTROL_WORD,
            mxcsr: saved.mxcsr,
            mxcsr_mask: saved.mxcsr_mask,
            ..Default::default()
        };
        let xstate_bv = self.xstate_bv();
        if xstate_bv & XFEATURE_MASK_X87 != 0 {
            state.control_word = saved.control_word;
            state.status_word = saved.status_word;
            state.tag_word = saved.tag_word;
            state.error_opcode = saved.error_opcode;
            state.instruction_pointer = saved.instruction_pointer;
            state.data_pointer = saved.data_pointer;
            state.float_registers = saved.float_registers;
        }
        if xstate_bv & XFEATURE_MASK_SSE != 0 {
            state.xmm_registers = saved.xmm_registers;
        }
        state
    }

    /// Rewrites this area as a non-optimized XSAVE would have saved it, the form
    /// Linux exposes in signal frames.
    ///
    /// XSAVEOPT skips components in their initial state, leaving stale bytes.
    /// Here every initial component holds its initial value, x87 and SSE are
    /// marked present so edits to them take effect, and MXCSR_MASK reports the
    /// host value. The area remains valid for restoring.
    pub fn materialize(&mut self, layout: &XsaveLayout) {
        let mut legacy = self.materialized_legacy_area();
        legacy.mxcsr_mask = layout.mxcsr_mask;
        *self.legacy_area_mut() = legacy;
        let xstate_bv = self.xstate_bv();
        for component in &layout.components {
            if xstate_bv & (1 << component.id) == 0 {
                self.as_bytes_mut()[component.offset..component.offset + component.size].fill(0);
            }
        }
        self.header_mut().xstate_bv = xstate_bv | XFEATURE_MASK_LEGACY;
    }

    /// Returns the aligned buffer address, valid for this area's lifetime.
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.storage.as_ptr().cast()
    }

    /// Returns the aligned buffer address for exclusive CPU-state capture.
    ///
    /// Writing through the pointer requires ensuring that captures and reads
    /// do not overlap and that the contents remain valid standard-layout state.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_mut_ptr().cast()
    }

    /// Returns the logical XSAVE bytes, excluding trailing allocation padding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.storage.as_bytes()[..self.size]
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.storage.as_mut_bytes()[..self.size]
    }

    /// Reconstructs a standard-layout XSAVE area from untrusted bytes.
    ///
    /// Returns `None` if the size, component mask, format, reserved fields, or
    /// MXCSR would make restoring the state fault for `layout`, as standard-form
    /// XRSTOR does. Header bytes that XRSTOR ignores are cleared.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], layout: &XsaveLayout) -> Option<Self> {
        /// Reserved header bytes that standard-form XRSTOR requires to be zero,
        /// following XSTATE_BV and XCOMP_BV.
        const CHECKED_RESERVED: usize = 8;

        if bytes.len() != layout.size {
            return None;
        }
        let mut area = Self::zeroed(layout);
        area.as_bytes_mut().copy_from_slice(bytes);
        // Older processors also checked these bytes; clearing them keeps the
        // restore valid everywhere.
        area.header_mut().reserved[CHECKED_RESERVED..].fill(0);
        let header = area.header();
        if header.xcomp_bv != 0
            || header.xstate_bv & !layout.mask != 0
            || header.reserved[..CHECKED_RESERVED] != [0; CHECKED_RESERVED]
            || area.legacy_area().mxcsr & !layout.mxcsr_mask != 0
        {
            return None;
        }
        Some(area)
    }

    /// Returns the header's bitmap of state components that are not initial.
    #[must_use]
    pub fn xstate_bv(&self) -> u64 {
        self.header().xstate_bv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    const MXCSR_OFFSET: usize = offset_of!(XsaveLegacyArea, mxcsr);
    const FIP_OFFSET: usize = offset_of!(XsaveLegacyArea, instruction_pointer);
    const FDP_OFFSET: usize = offset_of!(XsaveLegacyArea, data_pointer);
    const XMM_OFFSET: usize = offset_of!(XsaveLegacyArea, xmm_registers);
    const FLOAT_OFFSET: usize = offset_of!(XsaveLegacyArea, float_registers);

    fn initial_bytes() -> Vec<u8> {
        XsaveArea::initial(XsaveLayout::get()).as_bytes().to_vec()
    }

    fn with(mut bytes: Vec<u8>, offset: usize, value: &[u8]) -> Vec<u8> {
        bytes[offset..offset + value.len()].copy_from_slice(value);
        bytes
    }

    #[test]
    fn detected_mxcsr_mask_covers_architectural_controls() {
        let mask = XsaveLayout::get().mxcsr_mask;
        assert_eq!(mask & 0xffbf, 0xffbf);
    }

    #[test]
    fn from_bytes_rejects_state_that_xrstor_faults_on() {
        let layout = XsaveLayout::get();
        assert!(XsaveArea::from_bytes(&initial_bytes(), layout).is_some());
        assert!(XsaveArea::from_bytes(&initial_bytes()[1..], layout).is_none());
        let rejects = |offset, value: &[u8]| {
            XsaveArea::from_bytes(&with(initial_bytes(), offset, value), layout).is_none()
        };
        assert!(rejects(XSAVE_HEADER_OFFSET, &(!layout.mask).to_ne_bytes()));
        assert!(rejects(XSAVE_HEADER_OFFSET + 8, &1_u64.to_ne_bytes()));
        assert!(rejects(XSAVE_HEADER_OFFSET + 16, &[1]));
        assert!(rejects(MXCSR_OFFSET, &(!layout.mxcsr_mask).to_ne_bytes()));
    }

    #[test]
    fn from_bytes_clears_header_bytes_xrstor_ignores() {
        let layout = XsaveLayout::get();
        let bytes = with(initial_bytes(), XSAVE_HEADER_OFFSET + 24, &[0xff; 40]);
        let area = XsaveArea::from_bytes(&bytes, layout).unwrap();
        assert_eq!(area.header().reserved, [0; 48]);
    }

    #[test]
    fn materialize_replaces_stale_initial_components() {
        let layout = XsaveLayout::get();
        let mut bytes = with(initial_bytes(), FLOAT_OFFSET, &[0xaa; 384]);
        bytes = with(bytes, FIP_OFFSET, &u64::MAX.to_ne_bytes());
        for component in &layout.components {
            bytes = with(bytes, component.offset, &vec![0xbb; component.size]);
        }
        let mut area = XsaveArea::from_bytes(&bytes, layout).unwrap();
        area.materialize(layout);

        assert_eq!(area.xstate_bv(), XFEATURE_MASK_LEGACY);
        let legacy = area.legacy_area();
        assert_eq!(
            legacy.control_word,
            XsaveArea::GUEST_INITIAL_X87_CONTROL_WORD
        );
        assert_eq!(legacy.instruction_pointer, 0);
        assert_eq!(legacy.float_registers, [[0; 16]; 8]);
        assert_eq!(legacy.xmm_registers, [[0; 16]; 16]);
        assert_eq!(legacy.mxcsr, XsaveArea::GUEST_INITIAL_MXCSR);
        assert_eq!(legacy.mxcsr_mask, layout.mxcsr_mask);
        for component in &layout.components {
            let saved = &area.as_bytes()[component.offset..component.offset + component.size];
            assert!(saved.iter().all(|&byte| byte == 0));
        }
    }

    #[test]
    fn materialize_keeps_present_state_including_64_bit_pointers() {
        let layout = XsaveLayout::get();
        let fip = 0x1234_5678_9abc_def0_u64;
        let fdp = 0x0fed_cba9_8765_4321_u64;
        let mut bytes = with(initial_bytes(), FIP_OFFSET, &fip.to_ne_bytes());
        bytes = with(bytes, FDP_OFFSET, &fdp.to_ne_bytes());
        bytes = with(bytes, XMM_OFFSET, &[0x5a; 16]);
        bytes = with(
            bytes,
            XSAVE_HEADER_OFFSET,
            &XFEATURE_MASK_LEGACY.to_ne_bytes(),
        );
        let mut area = XsaveArea::from_bytes(&bytes, layout).unwrap();
        area.materialize(layout);

        let legacy = area.legacy_area();
        assert_eq!(legacy.instruction_pointer, fip);
        assert_eq!(legacy.data_pointer, fdp);
        assert_eq!(legacy.xmm_registers[0], [0x5a; 16]);
        assert_eq!(area.materialized_legacy_area().instruction_pointer, fip);
    }
}

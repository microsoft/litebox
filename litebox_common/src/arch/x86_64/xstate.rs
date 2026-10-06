// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-independent x86-64 XSAVE layout discovery and aligned state storage.

use alloc::{boxed::Box, vec, vec::Vec};

/// Size of the architectural legacy x87/SSE save area.
pub const XSAVE_LEGACY_SIZE: usize = core::mem::size_of::<XsaveLegacyArea>();
/// Offset of the XSAVE header in a standard-layout save area.
pub const XSAVE_HEADER_OFFSET: usize = XSAVE_LEGACY_SIZE;
/// Size of the architectural XSAVE header.
pub const XSAVE_HEADER_SIZE: usize = core::mem::size_of::<XsaveHeader>();

/// Architectural x86-64 FXSAVE area at the start of a standard XSAVE area.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XsaveLegacyArea {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    pub reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved3: u16,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub float_registers: [[u8; 16]; 8],
    pub xmm_registers: [[u8; 16]; 16],
    pub reserved4: [u8; 96],
}

impl Default for XsaveLegacyArea {
    fn default() -> Self {
        Self {
            control_word: 0,
            status_word: 0,
            tag_word: 0,
            reserved1: 0,
            error_opcode: 0,
            error_offset: 0,
            error_selector: 0,
            reserved2: 0,
            data_offset: 0,
            data_selector: 0,
            reserved3: 0,
            mxcsr: 0,
            mxcsr_mask: 0,
            float_registers: [[0; 16]; 8],
            xmm_registers: [[0; 16]; 16],
            reserved4: [0; 96],
        }
    }
}

/// Architectural header following the legacy area in an XSAVE area.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XsaveHeader {
    /// Bitmap of state components that are not in their initial state.
    pub xstate_bv: u64,
    /// Compacted-format indicator and bitmap. Zero for standard format.
    pub xcomp_bv: u64,
    pub reserved: [u8; 48],
}

impl Default for XsaveHeader {
    fn default() -> Self {
        Self {
            xstate_bv: 0,
            xcomp_bv: 0,
            reserved: [0; 48],
        }
    }
}

/// An initialized, 64-byte-aligned storage chunk for CPU or host context buffers.
#[repr(C, align(64))]
#[derive(Clone)]
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
        }
    }
}

/// Represents the standard-layout XSAVE area for a guest context.
#[derive(Clone)]
pub struct XsaveArea {
    storage: Box<[XsaveChunk]>,
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
        let chunks = layout.size.div_ceil(size_of::<XsaveChunk>());
        let mut area = Self {
            storage: vec![XsaveChunk([0; 64]); chunks].into_boxed_slice(),
        };
        area.legacy_area_mut().mxcsr = Self::GUEST_INITIAL_MXCSR;
        area
    }

    /// Discards saved state and restores architectural initial state without
    /// replacing the aligned allocation.
    pub fn reset_to_initial(&mut self) {
        for chunk in &mut self.storage {
            chunk.0.fill(0);
        }
        self.legacy_area_mut().mxcsr = Self::GUEST_INITIAL_MXCSR;
    }

    /// Returns the architectural x87/SSE state at the start of this area.
    #[must_use]
    pub fn legacy_area(&self) -> &XsaveLegacyArea {
        // SAFETY: storage is 64-byte aligned and always contains the 512-byte legacy area.
        unsafe { &*self.as_ptr().cast() }
    }

    /// Returns mutable access to the architectural x87/SSE state.
    pub fn legacy_area_mut(&mut self) -> &mut XsaveLegacyArea {
        // SAFETY: storage is 64-byte aligned and always contains the 512-byte legacy area.
        unsafe { &mut *self.as_mut_ptr().cast() }
    }

    /// Returns the architectural XSAVE header.
    #[must_use]
    pub fn header(&self) -> &XsaveHeader {
        // SAFETY: storage contains the header at its architectural offset.
        unsafe { &*self.as_ptr().add(XSAVE_HEADER_OFFSET).cast() }
    }

    /// Returns mutable access to the architectural XSAVE header.
    pub fn header_mut(&mut self) -> &mut XsaveHeader {
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
        if xstate_bv & 1 != 0 {
            state.control_word = saved.control_word;
            state.status_word = saved.status_word;
            state.tag_word = saved.tag_word;
            state.error_opcode = saved.error_opcode;
            state.error_offset = saved.error_offset;
            state.error_selector = saved.error_selector;
            state.data_offset = saved.data_offset;
            state.data_selector = saved.data_selector;
            state.float_registers = saved.float_registers;
        }
        if xstate_bv & 2 != 0 {
            state.xmm_registers = saved.xmm_registers;
        }
        state
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

    /// Returns the header's bitmap of state components that are not initial.
    #[must_use]
    pub fn xstate_bv(&self) -> u64 {
        self.header().xstate_bv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_layout(size: usize) -> XsaveLayout {
        XsaveLayout {
            size,
            mask: 3,
            components: Vec::new(),
            xsaveopt: false,
        }
    }

    #[test]
    fn initial_state_is_aligned_and_zero_except_mxcsr() {
        let layout = test_layout(XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE + 1);
        let area = XsaveArea::initial(&layout);
        assert_eq!(area.as_ptr().addr() % 64, 0);
        assert_eq!(area.storage.len(), layout.size.div_ceil(64));
        assert_eq!(area.xstate_bv(), 0);
        assert_eq!(area.legacy_area().mxcsr, XsaveArea::GUEST_INITIAL_MXCSR);
        for (index, chunk) in area.storage.iter().enumerate() {
            let mut expected = [0; 64];
            if index == 0 {
                expected[24..28].copy_from_slice(&XsaveArea::GUEST_INITIAL_MXCSR.to_le_bytes());
            }
            assert_eq!(chunk.0, expected);
        }
    }

    #[test]
    fn xstate_bitmap_reads_the_standard_header() {
        let mut area = XsaveArea::initial(&test_layout(576));
        let bitmap = 0x0123_4567_89ab_cdef_u64;
        area.header_mut().xstate_bv = bitmap;
        assert_eq!(area.xstate_bv(), bitmap);
    }

    #[test]
    fn reset_to_initial_clears_all_state_and_reuses_storage() {
        let layout = test_layout(577);
        let mut area = XsaveArea::initial(&layout);
        let address = area.as_ptr();
        for chunk in &mut area.storage {
            chunk.0.fill(0xff);
        }

        area.reset_to_initial();

        assert_eq!(area.as_ptr(), address);
        let initial = XsaveArea::initial(&layout);
        for (actual, expected) in area.storage.iter().zip(initial.storage.iter()) {
            assert_eq!(actual.0, expected.0);
        }
    }

    #[test]
    fn materialized_legacy_area_substitutes_initial_components() {
        let mut area = XsaveArea::initial(&test_layout(576));
        area.legacy_area_mut().control_word = 1;
        area.legacy_area_mut().xmm_registers[0] = [2; 16];

        let initial = area.materialized_legacy_area();
        assert_eq!(
            initial.control_word,
            XsaveArea::GUEST_INITIAL_X87_CONTROL_WORD
        );
        assert_eq!(initial.xmm_registers[0], [0; 16]);

        area.header_mut().xstate_bv = 3;
        let saved = area.materialized_legacy_area();
        assert_eq!(saved.control_word, 1);
        assert_eq!(saved.xmm_registers[0], [2; 16]);
    }

    #[test]
    #[should_panic(expected = "XSAVE layout must include the legacy area and header")]
    fn initial_state_rejects_a_truncated_header() {
        let _ = XsaveArea::initial(&test_layout(575));
    }
}

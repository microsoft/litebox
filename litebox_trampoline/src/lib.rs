// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Binary-format-independent trampoline ABI, construction and validation.
#![no_std]
extern crate alloc;

pub mod aarch64;
use alloc::string::String;
use core::ops::Range;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    byteorder::{LittleEndian, U32, U64},
};

/// Errors constructing or validating a trampoline.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("address overflow: {0}")]
    AddressOverflow(String),
    #[error("failed to patch trampoline: {0}")]
    TrampolinePatchFailure(String),
    #[error("unsupported executable: {0}")]
    UnsupportedExecutable(String),
}

/// Result of a trampoline operation.
pub type Result<T> = core::result::Result<T, Error>;

// Persisted image ABI.

/// The magic bytes used to identify the trampoline data.
/// This is checked by the loader to verify that the trampoline is valid.
pub const TRAMPOLINE_MAGIC: &[u8; 8] = b"LITEBOX0";

/// Required file alignment of the appended trampoline payload.
pub const TRAMPOLINE_FILE_ALIGNMENT: usize = 0x1000;

/// On-disk 64-bit footer, with explicitly little-endian fields.
/// `vaddr` is a virtual address for ELF/Mach-O and an RVA for PE.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TrampolineHeader64 {
    pub magic: [u8; 8],
    pub file_offset: U64<LittleEndian>,
    pub vaddr: U64<LittleEndian>,
    pub trampoline_size: U64<LittleEndian>,
}

/// On-disk 32-bit footer. The magic remains eight bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TrampolineHeader32 {
    pub magic: [u8; 8],
    pub file_offset: U32<LittleEndian>,
    pub vaddr: U32<LittleEndian>,
    pub trampoline_size: U32<LittleEndian>,
}

/// Footer size expected by a native loader. Cross-architecture tools must
/// select the footer width from the input image rather than the build target.
pub const TRAMPOLINE_HEADER_SIZE: usize = if cfg!(target_pointer_width = "64") {
    size_of::<TrampolineHeader64>()
} else {
    size_of::<TrampolineHeader32>()
};

/// Errors decoding the shared footer, independent of image admission policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrampolineHeaderError {
    /// The footer has the LiteBox prefix but an unsupported version.
    UnsupportedVersion,
    /// The encoding or the loader's interpretation of its fields is invalid.
    Malformed,
}

/// Decode a complete 20- or 32-byte footer into little-endian 64-bit fields.
/// Returns `None` for non-LiteBox data. Alignment, mapping bounds and the
/// interpretation of an empty footer are checked by the image loader.
///
/// # Errors
/// Rejects unsupported LiteBox versions and unsupported footer lengths.
pub fn decode_trampoline_header(
    bytes: &[u8],
) -> core::result::Result<Option<TrampolineHeader64>, TrampolineHeaderError> {
    let header = if bytes.len() == size_of::<TrampolineHeader64>() {
        TrampolineHeader64::read_from_bytes(bytes).map_err(|_| TrampolineHeaderError::Malformed)?
    } else if bytes.len() == size_of::<TrampolineHeader32>() {
        let header = TrampolineHeader32::read_from_bytes(bytes)
            .map_err(|_| TrampolineHeaderError::Malformed)?;
        TrampolineHeader64 {
            magic: header.magic,
            file_offset: u64::from(header.file_offset.get()).into(),
            vaddr: u64::from(header.vaddr.get()).into(),
            trampoline_size: u64::from(header.trampoline_size.get()).into(),
        }
    } else {
        return Err(TrampolineHeaderError::Malformed);
    };
    if header.magic == *TRAMPOLINE_MAGIC {
        Ok(Some(header))
    } else if header.magic.starts_with(b"LITEBOX") {
        Err(TrampolineHeaderError::UnsupportedVersion)
    } else {
        Ok(None)
    }
}

// Host conventions and runtime entry ABI.

/// Host operating system whose TLS and register conventions AArch64 gates use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TargetHost {
    /// Linux, using `TPIDR_EL0` as the host per-thread anchor.
    #[default]
    Linux,
    /// macOS, using `TPIDRRO_EL0` as the host anchor. Guest x18 is virtualized.
    MacOs,
    /// Experimental Windows emission using physical `x18` as the host anchor.
    /// No in-tree AArch64 Windows runtime consumes these artifacts.
    Windows,
}

/// Callback-slot bytes the caller must populate; zero when emitted inline.
#[cfg(target_arch = "x86_64")]
pub const TRAMPOLINE_ENTRY_POINT_BYTES: usize = size_of::<u64>();
#[cfg(target_arch = "aarch64")]
pub const TRAMPOLINE_ENTRY_POINT_BYTES: usize = 0;

/// Alignment every write cursor into a trampoline must satisfy.
#[cfg(target_arch = "x86_64")]
pub const TRAMPOLINE_CURSOR_ALIGN: usize = 1;
#[cfg(target_arch = "aarch64")]
pub const TRAMPOLINE_CURSOR_ALIGN: usize = aarch64::GATE_ALIGNMENT;

/// Furthest preferred trampoline base from the code segment.
///
/// AArch64 runtime reservations may exceed the nominal tail margin; each gate
/// performs its own reach check.
#[cfg(target_arch = "x86_64")]
pub const MAX_TRAMPOLINE_DISPLACEMENT: usize = 0x7FFF_0000;
#[cfg(target_arch = "aarch64")]
pub const MAX_TRAMPOLINE_DISPLACEMENT: usize = 0x07FF_0000;

/// Length of the `JMP [RIP + disp32]` through which an x86-64 ELF trampoline enters the syscall
/// callback. The preceding `LEA RCX, [RIP + len]` points RCX, the callback's resume PC, just past it.
pub const X86_64_SYSCALL_ENTRY_JMP_LEN: u8 = 6;

/// Length of the guest instruction through which a rewritten Linux syscall enters the syscall
/// callback.
///
/// The callback's resume PC immediately follows this instruction, so moving the PC back by this
/// length, with the syscall's registers restored, reissues the syscall. On x86-64 it is the ELF
/// trampoline's `JMP [RIP + disp32]`; on AArch64 it is the `B` that replaces the `SVC` in place.
#[cfg(target_arch = "x86_64")]
pub const SYSCALL_ENTRY_INSTRUCTION_LEN: usize = X86_64_SYSCALL_ENTRY_JMP_LEN as usize;
#[cfg(target_arch = "aarch64")]
pub const SYSCALL_ENTRY_INSTRUCTION_LEN: usize = aarch64::INSN_BYTES;

/// Conservative address bounds reachable from the entire nonempty code span.
///
/// A runtime trampoline's complete allocation must fit inside the returned
/// interval. Returns `None` if the span has no common reachable interval.
pub fn trampoline_allocation_range(code: Range<usize>) -> Option<Range<usize>> {
    let start = code.end.saturating_sub(MAX_TRAMPOLINE_DISPLACEMENT);
    let end = code.start.saturating_add(MAX_TRAMPOLINE_DISPLACEMENT);
    (code.start < code.end && start < end).then_some(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn footer64_has_a_stable_little_endian_encoding() {
        assert_eq!(size_of::<TrampolineHeader64>(), 32);
        assert_eq!(align_of::<TrampolineHeader64>(), 1);
        let header = TrampolineHeader64 {
            magic: *TRAMPOLINE_MAGIC,
            file_offset: 0x1122_3344_5566_7788u64.into(),
            vaddr: 0x0123_4567_89ab_cdefu64.into(),
            trampoline_size: 0x0807_0605_0403_0201u64.into(),
        };
        let expected = [
            b'L', b'I', b'T', b'E', b'B', b'O', b'X', b'0', 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
            0x22, 0x11, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        assert_eq!(header.as_bytes(), expected);
        assert_eq!(decode_trampoline_header(&expected), Ok(Some(header)));
        // A footer is at EOF, not necessarily at a naturally aligned address.
        let mut unaligned = Vec::from([0xff]);
        unaligned.extend_from_slice(&expected);
        assert_eq!(decode_trampoline_header(&unaligned[1..]), Ok(Some(header)));
    }

    #[test]
    fn footer32_has_a_stable_encoding_and_zero_extends_into64() {
        assert_eq!(size_of::<TrampolineHeader32>(), 20);
        assert_eq!(align_of::<TrampolineHeader32>(), 1);
        let header = TrampolineHeader32 {
            magic: *TRAMPOLINE_MAGIC,
            file_offset: 0x1234_5678u32.into(),
            vaddr: 0xf123_4567u32.into(),
            trampoline_size: 0xfedc_ba98u32.into(),
        };
        let expected = [
            b'L', b'I', b'T', b'E', b'B', b'O', b'X', b'0', 0x78, 0x56, 0x34, 0x12, 0x67, 0x45,
            0x23, 0xf1, 0x98, 0xba, 0xdc, 0xfe,
        ];
        assert_eq!(header.as_bytes(), expected);
        let decoded = decode_trampoline_header(&expected).unwrap().unwrap();
        assert_eq!(decoded.magic, *TRAMPOLINE_MAGIC);
        assert_eq!(decoded.file_offset.get(), 0x1234_5678);
        assert_eq!(decoded.vaddr.get(), 0xf123_4567);
        assert_eq!(decoded.trampoline_size.get(), 0xfedc_ba98);
    }

    #[test]
    fn footer_magic_version_and_length_are_checked_for_both_widths() {
        for length in [20, 32] {
            let mut bytes = [0u8; 32];
            assert_eq!(decode_trampoline_header(&bytes[..length]), Ok(None));
            bytes[..8].copy_from_slice(TRAMPOLINE_MAGIC);
            let decoded = decode_trampoline_header(&bytes[..length]).unwrap().unwrap();
            assert_eq!(decoded.file_offset.get(), 0);
            assert_eq!(decoded.vaddr.get(), 0);
            assert_eq!(decoded.trampoline_size.get(), 0);
            bytes[7] = b'9';
            assert_eq!(
                decode_trampoline_header(&bytes[..length]),
                Err(TrampolineHeaderError::UnsupportedVersion)
            );
            bytes[0] = b'X';
            assert_eq!(decode_trampoline_header(&bytes[..length]), Ok(None));
        }
        let mut bytes = [0u8; 40];
        bytes[..8].copy_from_slice(TRAMPOLINE_MAGIC);
        for length in 0..=bytes.len() {
            if length != 20 && length != 32 {
                assert_eq!(
                    decode_trampoline_header(&bytes[..length]),
                    Err(TrampolineHeaderError::Malformed)
                );
            }
        }
    }
}

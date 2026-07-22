// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared VSM/HEKI wire types and constants for the LVBS platform, service, and runner.

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use core::mem;
use litebox::utils::TruncateExt;
use litebox_common_linux::errno::Errno;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, Size4KiB},
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Length of the Platform Root Key in bytes.
pub const PRK_LEN: usize = 32;

/// Maximum number of CPU cores addressable through the VTL0 `cpu_online_mask`
/// ABI. Bounds how many bits of the mask VTL1 will honor when booting APs.
pub const MAX_CORES: usize = 128;

/// VTL call parameters (`param[0]`: function ID, `param[1..4]`: parameters)
pub const NUM_VTLCALL_PARAMS: usize = 4;

pub const VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL: u32 = 0x1_ffe0;
pub const VSM_VTL_CALL_FUNC_ID_BOOT_APS: u32 = 0x1_ffe1;
pub const VSM_VTL_CALL_FUNC_ID_LOCK_REGS: u32 = 0x1_ffe2;
pub const VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT: u32 = 0x1_ffe3;
pub const VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY: u32 = 0x1_ffe4;
pub const VSM_VTL_CALL_FUNC_ID_LOAD_KDATA: u32 = 0x1_ffe5;
pub const VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE: u32 = 0x1_ffe6;
pub const VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT: u32 = 0x1_ffe7;
pub const VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE: u32 = 0x1_ffe8;
pub const VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY: u32 = 0x1_ffe9;
pub const VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE: u32 = 0x1_ffea;
pub const VSM_VTL_CALL_FUNC_ID_PATCH_TEXT: u32 = 0x1_ffeb;
pub const VSM_VTL_CALL_FUNC_ID_ALLOCATE_RINGBUFFER_MEMORY: u32 = 0x1_ffec;

// This VSM function ID for setting the platform root key is subject to change
pub const VSM_VTL_CALL_FUNC_ID_SET_PLATFORM_ROOT_KEY: u32 = 0x1_ffed;

// This VSM function ID for OP-TEE messages is subject to change
pub const VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE: u32 = 0x1_fff0;

/// VSM Functions
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum VsmFunction {
    // VSM/Heki functions
    EnableAPsVtl = VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL,
    BootAPs = VSM_VTL_CALL_FUNC_ID_BOOT_APS,
    LockRegs = VSM_VTL_CALL_FUNC_ID_LOCK_REGS,
    SignalEndOfBoot = VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT,
    ProtectMemory = VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY,
    LoadKData = VSM_VTL_CALL_FUNC_ID_LOAD_KDATA,
    ValidateModule = VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE,
    FreeModuleInit = VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT,
    UnloadModule = VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE,
    CopySecondaryKey = VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY,
    KexecValidate = VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE,
    PatchText = VSM_VTL_CALL_FUNC_ID_PATCH_TEXT,
    OpteeMessage = VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE,
    AllocateRingbufferMemory = VSM_VTL_CALL_FUNC_ID_ALLOCATE_RINGBUFFER_MEMORY,
    SetPlatformRootKey = VSM_VTL_CALL_FUNC_ID_SET_PLATFORM_ROOT_KEY,
}

// `HV_STATUS_*` constants used as discriminants for `HypervCallError`.
pub const HV_STATUS_INVALID_HYPERCALL_CODE: u32 = 2;
pub const HV_STATUS_INVALID_HYPERCALL_INPUT: u32 = 3;
pub const HV_STATUS_INVALID_ALIGNMENT: u32 = 4;
pub const HV_STATUS_INVALID_PARAMETER: u32 = 5;
pub const HV_STATUS_ACCESS_DENIED: u32 = 6;
pub const HV_STATUS_OPERATION_DENIED: u32 = 8;
pub const HV_STATUS_INSUFFICIENT_MEMORY: u32 = 11;
pub const HV_STATUS_INVALID_PORT_ID: u32 = 17;
pub const HV_STATUS_INVALID_CONNECTION_ID: u32 = 18;
pub const HV_STATUS_INSUFFICIENT_BUFFERS: u32 = 19;
pub const HV_STATUS_TIME_OUT: u32 = 120;
pub const HV_STATUS_VTL_ALREADY_ENABLED: u32 = 134;

/// Errors for Hyper-V hypercalls.
#[derive(Debug, Error, TryFromPrimitive, IntoPrimitive)]
#[non_exhaustive]
#[repr(u32)]
pub enum HypervCallError {
    #[error("invalid hypercall code")]
    InvalidCode = HV_STATUS_INVALID_HYPERCALL_CODE,
    #[error("invalid hypercall input")]
    InvalidInput = HV_STATUS_INVALID_HYPERCALL_INPUT,
    #[error("invalid alignment")]
    InvalidAlignment = HV_STATUS_INVALID_ALIGNMENT,
    #[error("invalid parameter")]
    InvalidParameter = HV_STATUS_INVALID_PARAMETER,
    #[error("access denied")]
    AccessDenied = HV_STATUS_ACCESS_DENIED,
    #[error("operation denied")]
    OperationDenied = HV_STATUS_OPERATION_DENIED,
    #[error("insufficient memory")]
    InsufficientMemory = HV_STATUS_INSUFFICIENT_MEMORY,
    #[error("invalid port ID")]
    InvalidPortID = HV_STATUS_INVALID_PORT_ID,
    #[error("invalid connection ID")]
    InvalidConnectionID = HV_STATUS_INVALID_CONNECTION_ID,
    #[error("insufficient buffers")]
    InsufficientBuffers = HV_STATUS_INSUFFICIENT_BUFFERS,
    #[error("timeout")]
    TimeOut = HV_STATUS_TIME_OUT,
    #[error("VTL already enabled")]
    AlreadyEnabled = HV_STATUS_VTL_ALREADY_ENABLED,
    #[error("unknown hypercall error")]
    Unknown = 0xffff_ffff,
}

/// Errors for module signature verification.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("signature not found in module")]
    SignatureNotFound,
    #[error("invalid signature format")]
    InvalidSignature,
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("signature authentication failed")]
    AuthenticationFailed,
    #[error("failed to parse signature data")]
    ParseFailed,
    #[error("unsupported signature algorithm")]
    Unsupported,
}

impl From<VerificationError> for Errno {
    fn from(e: VerificationError) -> Self {
        match e {
            VerificationError::AuthenticationFailed => Errno::EKEYREJECTED,
            VerificationError::SignatureNotFound => Errno::ENODATA,
            VerificationError::Unsupported => Errno::ENOPKG,
            VerificationError::InvalidCertificate => Errno::ENOKEY,
            VerificationError::InvalidSignature | VerificationError::ParseFailed => Errno::ELIBBAD,
        }
    }
}

/// Errors for Virtual Secure Mode (VSM) operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VsmError {
    // Boot/AP Initialization Errors
    #[error("failed to copy boot signal page from VTL0")]
    BootSignalPageCopyFailed,

    #[error("failed to initialize AP: {0:?}")]
    ApInitFailed(HypervCallError),

    #[error("failed to copy boot signal page to VTL0")]
    BootSignalWriteFailed,

    #[error("failed to copy cpu_online_mask from VTL0")]
    CpuOnlineMaskCopyFailed,

    #[error("code page offset overflow when computing VTL return address")]
    CodePageOffsetOverflow,

    #[error("integer overflow while processing VTL0-controlled range data")]
    IntegerOverflow,

    // End-of-Boot Restriction Errors
    #[error("{0} not allowed after end of boot")]
    OperationAfterEndOfBoot(&'static str),

    // Address Validation Errors
    #[error("invalid input address")]
    InvalidInputAddress,

    #[error("address must be page-aligned")]
    AddressNotPageAligned,

    #[error("invalid physical address")]
    InvalidPhysicalAddress,

    // Memory/Data Errors
    #[error("invalid memory attributes")]
    MemoryAttributeInvalid,

    #[error("failed to copy HEKI pages from VTL0")]
    HekiPagesCopyFailed,

    #[error("invalid kernel data type")]
    KernelDataTypeInvalid,

    #[error("invalid module memory type")]
    ModuleMemoryTypeInvalid,

    // Certificate Errors
    #[error("system certificates not loaded")]
    SystemCertificatesNotLoaded,

    #[error("no system certificate found in kernel data")]
    SystemCertificatesNotFound,

    #[error("no valid system certificates parsed")]
    SystemCertificatesInvalid,

    #[error("invalid DER certificate data (expected {expected} bytes, got {actual})")]
    CertificateDerLengthInvalid { expected: usize, actual: usize },

    #[error("failed to parse certificate")]
    CertificateParseFailed,

    // Module Validation Errors
    #[error("module ELF size ({size} bytes) exceeds maximum allowed ({max} bytes)")]
    ModuleElfSizeExceeded { size: usize, max: usize },

    #[error("found unexpected relocations in loaded module")]
    ModuleRelocationInvalid,

    #[error("invalid module token")]
    ModuleTokenInvalid,

    #[error("physical frames overlap already-protected or reserved memory")]
    ProtectedFrameOverlap,

    // Kernel Symbol Table Errors
    #[error("no kernel symbol table found")]
    KernelSymbolTableNotFound,

    // Kexec Errors
    #[error("invalid kexec type")]
    KexecTypeInvalid,

    #[error("invalid kexec image segments")]
    KexecImageSegmentsInvalid,

    #[error("invalid kexec segment memory range")]
    KexecSegmentRangeInvalid,

    // Patch Errors
    #[error("precomputed patch data not found")]
    PrecomputedPatchNotFound,

    #[error("text patch validation failed")]
    TextPatchSuspicious,

    // Unsupported Operation Errors
    #[error("{0} is not supported")]
    OperationNotSupported(&'static str),

    // VTL0 Memory Copy Errors
    #[error("failed to copy data from/to VTL0")]
    Vtl0CopyFailed,

    // Hypercall Errors
    #[error("hypercall failed: {0:?}")]
    HypercallFailed(HypervCallError),

    // Signature Verification Errors
    #[error("signature verification failed: {0:?}")]
    SignatureVerificationFailed(VerificationError),

    // Data Parsing Errors
    #[error("buffer too small for {0}")]
    BufferTooSmall(&'static str),

    // Address/Memory Range Errors
    #[error("invalid virtual address")]
    InvalidVirtualAddress,

    #[error("discontiguous memory range")]
    DiscontiguousMemoryRange,

    // Symbol Table Errors
    #[error("symbol table data empty")]
    SymbolTableEmpty,

    #[error("symbol table data out of range")]
    SymbolTableOutOfRange,

    #[error("symbol table length not aligned to symbol size")]
    SymbolTableLengthInvalid,

    #[error("failed to parse symbol at offset {0:#x}")]
    SymbolParseFailed(usize),

    #[error("symbol name offset out of bounds")]
    SymbolNameOffsetInvalid,

    #[error("symbol name missing NUL terminator")]
    SymbolNameNoTerminator,

    #[error("symbol name exceeds maximum length")]
    SymbolNameTooLong,

    #[error("symbol name contains invalid UTF-8")]
    SymbolNameInvalidUtf8,
}

impl From<VerificationError> for VsmError {
    fn from(e: VerificationError) -> Self {
        VsmError::SignatureVerificationFailed(e)
    }
}

impl From<VsmError> for Errno {
    fn from(e: VsmError) -> Self {
        match e {
            // Address/pointer errors and memory copy failures - memory access fault
            VsmError::InvalidInputAddress
            | VsmError::InvalidPhysicalAddress
            | VsmError::InvalidVirtualAddress
            | VsmError::DiscontiguousMemoryRange
            | VsmError::BootSignalPageCopyFailed
            | VsmError::BootSignalWriteFailed
            | VsmError::CpuOnlineMaskCopyFailed
            | VsmError::HekiPagesCopyFailed
            | VsmError::Vtl0CopyFailed => Errno::EFAULT,

            // Not found errors
            VsmError::SystemCertificatesNotFound
            | VsmError::KernelSymbolTableNotFound
            | VsmError::PrecomputedPatchNotFound => Errno::ENOENT,

            // Operation not permitted after end of boot
            VsmError::OperationAfterEndOfBoot(_) => Errno::EPERM,

            // Unsupported operation
            VsmError::OperationNotSupported(_) => Errno::ENOTSUP,

            // Security/verification failures - access denied
            VsmError::TextPatchSuspicious
            | VsmError::SystemCertificatesInvalid
            | VsmError::SystemCertificatesNotLoaded => Errno::EACCES,

            // Size/range errors
            VsmError::BufferTooSmall(_)
            | VsmError::KexecSegmentRangeInvalid
            | VsmError::ModuleElfSizeExceeded { .. }
            | VsmError::CodePageOffsetOverflow
            | VsmError::IntegerOverflow
            | VsmError::SymbolNameTooLong
            | VsmError::SymbolTableOutOfRange => Errno::ERANGE,

            // Init/hardware failures - I/O error
            VsmError::ApInitFailed(_) | VsmError::HypercallFailed(_) => Errno::EIO,

            // True format/validation errors - invalid argument
            VsmError::AddressNotPageAligned
            | VsmError::MemoryAttributeInvalid
            | VsmError::KernelDataTypeInvalid
            | VsmError::ModuleMemoryTypeInvalid
            | VsmError::ModuleRelocationInvalid
            | VsmError::ModuleTokenInvalid
            | VsmError::ProtectedFrameOverlap
            | VsmError::KexecTypeInvalid
            | VsmError::KexecImageSegmentsInvalid
            | VsmError::SymbolTableEmpty
            | VsmError::SymbolTableLengthInvalid
            | VsmError::SymbolParseFailed(_)
            | VsmError::SymbolNameOffsetInvalid
            | VsmError::SymbolNameInvalidUtf8
            | VsmError::SymbolNameNoTerminator
            | VsmError::CertificateDerLengthInvalid { .. }
            | VsmError::CertificateParseFailed => Errno::EINVAL,

            // Signature verification failures delegate to VerificationError's Errno mapping
            VsmError::SignatureVerificationFailed(e) => Errno::from(e),
        }
    }
}

/// `list_head` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/types.h#L190)
/// Pointer fields stored as u64 since we don't dereference them.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ListHead {
    pub next: u64,
    pub prev: u64,
}

#[allow(non_camel_case_types)]
pub type __be32 = u32;

#[repr(u8)]
pub enum PkeyIdType {
    PkeyIdPgp = 0,
    PkeyIdX509 = 1,
    PkeyIdPkcs7 = 2,
}

/// `module_signature` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/module_signature.h#L33)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct ModuleSignature {
    pub algo: u8,
    pub hash: u8,
    pub id_type: u8,
    pub signer_len: u8,
    pub key_id_len: u8,
    _pad: [u8; 3],
    sig_len: __be32,
}

impl ModuleSignature {
    pub fn sig_len(&self) -> u32 {
        u32::from_be(self.sig_len)
    }

    /// Currently, Linux kernel only supports PKCS#7 signatures for module signing and thus `id_type` is always `PkeyIdType::PkeyIdPkcs7`.
    /// Other fields except for `sig_len` are set to zero.
    pub fn is_valid(&self) -> bool {
        self.sig_len() > 0
            && self.algo == 0
            && self.hash == 0
            && self.id_type == PkeyIdType::PkeyIdPkcs7 as u8
            && self.signer_len == 0
            && self.key_id_len == 0
    }
}

/// `kexec_segment` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/kexec.h#L82)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct KexecSegment {
    /// Pointer to buffer (stored as u64 since we don't dereference it)
    pub buf: u64,
    pub bufsz: u64,
    pub mem: u64,
    pub memsz: u64,
}

/// `kimage` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/kexec.h#L296)
/// Note that this is a part of the original `kimage` structure. It only contains some fields that
/// we need for our use case, such as `nr_segments` and `segment`, and
/// are not affected by the kernel build configurations like `CONFIG_KEXEC_FILE` and `CONFIG_IMA_KEXEC`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Kimage {
    head: u64,
    /// Pointer fields stored as u64 since we don't dereference them
    entry: u64,
    last_entry: u64,
    start: u64,
    control_code_page: u64, // struct page*
    swap_page: u64,         // struct page*
    vmcoreinfo_page: u64,   // struct page*
    vmcoreinfo_data_copy: u64,
    pub nr_segments: u64,
    pub segment: [KexecSegment; KEXEC_SEGMENT_MAX],
    // we do not need the rest of the fields for now
}
pub const KEXEC_SEGMENT_MAX: usize = 16;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct MemAttr: u64 {
        const MEM_ATTR_READ = 1 << 0;
        const MEM_ATTR_WRITE = 1 << 1;
        const MEM_ATTR_EXEC = 1 << 2;
        const MEM_ATTR_IMMUTABLE = 1 << 3;

        const _ = !0;
    }
}

#[derive(Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum HekiKdataType {
    SystemCerts = 0,
    RevocationCerts = 1,
    BlocklistHashes = 2,
    KernelInfo = 3,
    KernelData = 4,
    PatchInfo = 5,
    KexecTrampoline = 6,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

#[derive(Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum HekiKexecType {
    KexecImage = 0,
    KexecKernelBlob = 1,
    KexecPages = 2,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

#[derive(Clone, Copy, Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum ModMemType {
    Text = 0,
    Data = 1,
    RoData = 2,
    RoAfterInit = 3,
    InitText = 4,
    InitData = 5,
    InitRoData = 6,
    ElfBuffer = 7,
    Patch = 8,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

/// Maps a module memory-type to the corresponding [`MemAttr`] permission set.
pub fn mod_mem_type_to_mem_attr(mod_mem_type: ModMemType) -> MemAttr {
    let mut mem_attr = MemAttr::empty();

    match mod_mem_type {
        ModMemType::Text | ModMemType::InitText => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_EXEC, true);
        }
        ModMemType::Data | ModMemType::RoAfterInit | ModMemType::InitData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_WRITE, true);
        }
        ModMemType::RoData | ModMemType::InitRoData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
        }
        _ => {}
    }

    mem_attr
}

/// `HekiRange` is a generic container for various types of memory ranges.
/// It has an `attributes` field which can be interpreted differently based on the context like
/// `MemAttr`, `KdataType`, `ModMemType`, or `KexecType`.
#[derive(Default, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct HekiRange {
    pub va: u64,
    pub pa: u64,
    pub epa: u64,
    pub attributes: u64,
}

impl HekiRange {
    #[inline]
    pub fn is_aligned<U>(&self, align: U) -> bool
    where
        U: Into<u64> + Copy,
    {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;

        VirtAddr::new(va).is_aligned(align)
            && PhysAddr::new(pa).is_aligned(align)
            && PhysAddr::new(epa).is_aligned(align)
    }

    #[inline]
    pub fn mem_attr(&self) -> Option<MemAttr> {
        let attr = self.attributes;
        MemAttr::from_bits(attr)
    }

    #[inline]
    pub fn mod_mem_type(&self) -> ModMemType {
        let attr = self.attributes;
        ModMemType::try_from(attr).unwrap_or(ModMemType::Unknown)
    }

    #[inline]
    pub fn heki_kdata_type(&self) -> HekiKdataType {
        let attr = self.attributes;
        HekiKdataType::try_from(attr).unwrap_or(HekiKdataType::Unknown)
    }

    #[inline]
    pub fn heki_kexec_type(&self) -> HekiKexecType {
        let attr = self.attributes;
        HekiKexecType::try_from(attr).unwrap_or(HekiKexecType::Unknown)
    }

    pub fn is_valid(&self) -> bool {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;
        let Ok(pa) = PhysAddr::try_new(pa) else {
            return false;
        };
        let Ok(epa) = PhysAddr::try_new(epa) else {
            return false;
        };
        !(VirtAddr::try_new(va).is_err()
            || epa < pa
            || (self.mem_attr().is_none()
                && self.heki_kdata_type() == HekiKdataType::Unknown
                && self.heki_kexec_type() == HekiKexecType::Unknown
                && self.mod_mem_type() == ModMemType::Unknown))
    }
}

impl core::fmt::Debug for HekiRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;
        let attr = self.attributes;
        f.debug_struct("HekiRange")
            .field("va", &format_args!("{va:#x}"))
            .field("pa", &format_args!("{pa:#x}"))
            .field("epa", &format_args!("{epa:#x}"))
            .field("attr", &format_args!("{attr:#x}"))
            .field("type", &format_args!("{:?}", self.heki_kdata_type()))
            .field("size", &format_args!("{:?}", self.epa - self.pa))
            .finish()
    }
}

#[expect(clippy::cast_possible_truncation)]
pub const HEKI_MAX_RANGES: usize =
    ((PAGE_SIZE as u32 - u64::BITS * 3 / 8) / core::mem::size_of::<HekiRange>() as u32) as usize;

#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(align(4096))]
#[repr(C)]
pub struct HekiPage {
    /// Pointer to next page (stored as u64 since we don't dereference it)
    pub next: u64,
    pub next_pa: u64,
    pub nranges: u64,
    pub ranges: [HekiRange; HEKI_MAX_RANGES],
    pad: u64,
}

impl HekiPage {
    pub fn new() -> Self {
        // Safety: all fields are valid when zeroed (u64 zeros, array of zeroed HekiRange)
        Self::new_zeroed()
    }

    pub fn is_valid(&self) -> bool {
        if PhysAddr::try_new(self.next_pa)
            .ok()
            .is_none_or(|next_pa| self.next_pa != 0 && !next_pa.is_aligned(Size4KiB::SIZE))
        {
            return false;
        }
        let Some(nranges) = usize::try_from(self.nranges)
            .ok()
            .filter(|&n| (1..=HEKI_MAX_RANGES).contains(&n))
        else {
            return false;
        };
        for heki_range in &self.ranges[..nranges] {
            if !heki_range.is_valid() {
                return false;
            }
        }
        true
    }
}

impl Default for HekiPage {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

impl HekiPage {
    /// Returns an iterator over the valid `HekiRange`s in this page.
    pub fn iter(&self) -> core::slice::Iter<'_, HekiRange> {
        self.ranges[..usize::try_from(self.nranges).unwrap_or(0)].iter()
    }
}

impl<'a> IntoIterator for &'a HekiPage {
    type Item = &'a HekiRange;
    type IntoIter = core::slice::Iter<'a, HekiRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Default, Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct HekiPatch {
    pub pa: [u64; 2],
    pub size: u8,
    pub code: [u8; POKE_MAX_OPCODE_SIZE],
    _padding: [u8; 2],
}
pub const POKE_MAX_OPCODE_SIZE: usize = 5;

impl HekiPatch {
    /// Creates a new `HekiPatch` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let patch = Self::read_from_bytes(bytes).ok()?;
        if patch.is_valid() { Some(patch) } else { None }
    }

    pub fn is_valid(&self) -> bool {
        let Some(pa_0) = PhysAddr::try_new(self.pa[0])
            .ok()
            .filter(|&pa| !pa.is_null())
        else {
            return false;
        };
        let Some(pa_1) = PhysAddr::try_new(self.pa[1])
            .ok()
            .filter(|&pa| pa.is_null() || pa.is_aligned(Size4KiB::SIZE))
        else {
            return false;
        };
        let bytes_in_first_page = if pa_0.is_aligned(Size4KiB::SIZE) {
            core::cmp::min(PAGE_SIZE, usize::from(self.size))
        } else {
            core::cmp::min(
                (pa_0.align_up(Size4KiB::SIZE) - pa_0).trunc(),
                usize::from(self.size),
            )
        };

        !(self.size == 0
            || usize::from(self.size) > POKE_MAX_OPCODE_SIZE
            || (pa_0 == pa_1)
            || (bytes_in_first_page < usize::from(self.size) && pa_1.is_null())
            || (bytes_in_first_page == usize::from(self.size) && !pa_1.is_null()))
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum HekiPatchType {
    JumpLabel = 0,
    #[default]
    Unknown = 0xffff_ffff,
}

#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct HekiPatchInfo {
    /// Patch type stored as u32 for zerocopy compatibility (see `HekiPatchType`)
    pub typ_: u32,
    list: ListHead,
    /// *const `struct module` (stored as u64 since we don't dereference it)
    mod_: u64,
    pub patch_index: u64,
    pub max_patch_count: u64,
    // pub patch: [HekiPatch; *]
}

impl HekiPatchInfo {
    /// Creates a new `HekiPatchInfo` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let info = Self::read_from_bytes(bytes).ok()?;
        if info.is_valid() { Some(info) } else { None }
    }

    pub fn is_valid(&self) -> bool {
        !(self.typ_ != HekiPatchType::JumpLabel as u32
            || self.patch_index == 0
            || self.patch_index > self.max_patch_count)
    }
}

#[repr(C)]
#[allow(clippy::struct_field_names)]
// TODO: Account for kernel config changing the size and meaning of the field members
pub struct HekiKernelSymbol {
    pub value_offset: core::ffi::c_int,
    pub name_offset: core::ffi::c_int,
    pub namespace_offset: core::ffi::c_int,
}

impl HekiKernelSymbol {
    pub const KSYM_LEN: usize = mem::size_of::<HekiKernelSymbol>();
    pub const KSY_NAME_LEN: usize = 512;

    /// # Panics
    ///
    /// Panics if the input buffer is not aligned to `HekiKernelSymbol`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VsmError> {
        if bytes.len() < Self::KSYM_LEN {
            return Err(VsmError::BufferTooSmall("HekiKernelSymbol"));
        }

        #[allow(clippy::cast_ptr_alignment)]
        let ksym_ptr = bytes.as_ptr().cast::<HekiKernelSymbol>();
        assert!(ksym_ptr.is_aligned(), "ksym_ptr is not aligned");

        // SAFETY: Casting from vtl0 buffer that contained the struct
        unsafe {
            Ok(HekiKernelSymbol {
                value_offset: (*ksym_ptr).value_offset,
                name_offset: (*ksym_ptr).name_offset,
                namespace_offset: (*ksym_ptr).namespace_offset,
            })
        }
    }
}

#[repr(C)]
#[allow(clippy::struct_field_names)]
pub struct HekiKernelInfo {
    pub ksymtab_start: *const HekiKernelSymbol,
    pub ksymtab_end: *const HekiKernelSymbol,
    pub ksymtab_gpl_start: *const HekiKernelSymbol,
    pub ksymtab_gpl_end: *const HekiKernelSymbol,
    // Skip unused arch info
}

impl HekiKernelInfo {
    const KINFO_LEN: usize = mem::size_of::<HekiKernelInfo>();

    /// # Panics
    ///
    /// Panics if the input buffer is not aligned to `HekiKernelInfo`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VsmError> {
        if bytes.len() < Self::KINFO_LEN {
            return Err(VsmError::BufferTooSmall("HekiKernelInfo"));
        }

        #[allow(clippy::cast_ptr_alignment)]
        let kinfo_ptr = bytes.as_ptr().cast::<HekiKernelInfo>();
        assert!(kinfo_ptr.is_aligned(), "kinfo_ptr is not aligned");

        // SAFETY: Casting from vtl0 buffer that contained the struct
        unsafe {
            Ok(HekiKernelInfo {
                ksymtab_start: (*kinfo_ptr).ksymtab_start,
                ksymtab_end: (*kinfo_ptr).ksymtab_end,
                ksymtab_gpl_start: (*kinfo_ptr).ksymtab_gpl_start,
                ksymtab_gpl_end: (*kinfo_ptr).ksymtab_gpl_end,
            })
        }
    }
}

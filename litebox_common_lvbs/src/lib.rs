// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common data-only types for LVBS (VTL1) — shared between platform and runner crates.

#![no_std]

extern crate alloc;

use alloc::{ffi::CString, string::String, vec::Vec};
use core::ffi::{c_char, CStr};
use core::mem;
use litebox::utils::TruncateExt;
use litebox_common_linux::errno::Errno;
use modular_bitfield::prelude::*;
use modular_bitfield::specifiers::B62;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;
use x86_64::{
    structures::paging::{frame::PhysFrameRange, PageSize, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

// ============================================================================
// Memory layout constants
// ============================================================================

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

// ============================================================================
// Linux kernel ABI types
// ============================================================================

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

// ============================================================================
// Hyper-V constants and data-only types
// ============================================================================

// --- HV_STATUS constants ---

pub const HV_STATUS_SUCCESS: u32 = 0;
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

// --- VSM constants ---

pub const HV_REGISTER_VSM_PARTITION_CONFIG: u32 = 0x000d_0007;
pub const HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0: u32 = 0x000d_0010;
pub const HV_REGISTER_CR_INTERCEPT_CONTROL: u32 = 0x000e_0000;
pub const HV_REGISTER_CR_INTERCEPT_CR0_MASK: u32 = 0x000e_0001;
pub const HV_REGISTER_CR_INTERCEPT_CR4_MASK: u32 = 0x000e_0002;

pub const HV_SECURE_VTL_BOOT_TOKEN: u8 = 0xdc;

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
}

// --- Bitflags ---

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct HvPageProtFlags: u8 {
        const HV_PAGE_ACCESS_NONE = 0x0;
        const HV_PAGE_READABLE = 0x1;
        const HV_PAGE_WRITABLE = 0x2;
        const HV_PAGE_KERNEL_EXECUTABLE = 0x4;
        const HV_PAGE_USER_EXECUTABLE = 0x8;

        const _ = !0;

        const HV_PAGE_EXECUTABLE = Self::HV_PAGE_KERNEL_EXECUTABLE.bits() | Self::HV_PAGE_USER_EXECUTABLE.bits();
        const HV_PAGE_FULL_ACCESS = Self::HV_PAGE_READABLE.bits()
            | Self::HV_PAGE_WRITABLE.bits()
            | Self::HV_PAGE_EXECUTABLE.bits();
    }
}

// --- Bitfield structs ---

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvRegisterVsmVpSecureVtlConfig {
    pub mbec_enabled: bool,
    pub tlb_locked: bool,
    #[skip]
    __: B62,
}

impl HvRegisterVsmVpSecureVtlConfig {
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.into_bytes())
    }
}

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvRegisterVsmPartitionConfig {
    pub enable_vtl_protection: bool,
    pub default_vtl_protection_mask: B4,
    pub zero_memory_on_reset: bool,
    pub deny_lower_vtl_startup: bool,
    pub intercept_acceptance: bool,
    pub intercept_enable_vtl_protection: bool,
    pub intercept_vp_startup: bool,
    pub intercept_cpuid_unimplemented: bool,
    pub intercept_unrecoverable_exception: bool,
    pub intercept_page: bool,
    #[skip]
    __: B51,
}

impl HvRegisterVsmPartitionConfig {
    /// Get the raw u64 value for compatibility with existing code
    pub fn as_u64(&self) -> u64 {
        // Convert the 8-byte array to u64
        u64::from_le_bytes(self.into_bytes())
    }

    /// Create from a u64 value for compatibility with existing code
    pub fn from_u64(value: u64) -> Self {
        Self::from_bytes(value.to_le_bytes())
    }
}

// --- CR bitflags ---

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct X86Cr4Flags: u32 {
        const X86_CR4_VME = 1 << 0;
        const X86_CR4_PVI = 1 << 1;
        const X86_CR4_TSD = 1 << 2;
        const X86_CR4_DE = 1 << 3;
        const X86_CR4_PSE = 1 << 4;
        const X86_CR4_PAE = 1 << 5;
        const X86_CR4_MCE = 1 << 6;
        const X86_CR4_PGE = 1 << 7;
        const X86_CR4_PCE = 1 << 8;
        const X86_CR4_OSFXSR = 1 << 9;
        const X86_CR4_OSXMMEXCPT = 1 << 10;
        const X86_CR4_UMIP = 1 << 11;
        const X86_CR4_LA57 = 1 << 12;
        const X86_CR4_VMXE = 1 << 13;
        const X86_CR4_SMXE = 1 << 14;
        const X86_CR4_FSGBASE = 1 << 16;
        const X86_CR4_PCIDE = 1 << 17;
        const X86_CR4_OSXSAVE = 1 << 18;
        const X86_CR4_SMEP = 1 << 20;
        const X86_CR4_SMAP = 1 << 21;
        const X86_CR4_PKE = 1 << 22;

        const _ = !0;

        const CR4_PIN_MASK = !(Self::X86_CR4_MCE.bits()
            | Self::X86_CR4_PGE.bits()
            | Self::X86_CR4_PCE.bits()
            | Self::X86_CR4_VMXE.bits());
    }
}

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct X86Cr0Flags: u32 {
        const X86_CR0_PE = 1 << 0;
        const X86_CR0_MP = 1 << 1;
        const X86_CR0_EM = 1 << 2;
        const X86_CR0_TS = 1 << 3;
        const X86_CR0_ET = 1 << 4;
        const X86_CR0_NE = 1 << 5;
        const X86_CR0_WP = 1 << 16;
        const X86_CR0_AM = 1 << 18;
        const X86_CR0_NW = 1 << 29;
        const X86_CR0_CD = 1 << 30;
        const X86_CR0_PG = 1 << 31;

        const _ = !0;

        const CR0_PIN_MASK = Self::X86_CR0_PE.bits() | Self::X86_CR0_WP.bits() | Self::X86_CR0_PG.bits();
    }
}

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct HvCrInterceptControlFlags: u64 {
        const CR0_WRITE = 1 << 0;
        const CR4_WRITE = 1 << 1;
        const XCR0_WRITE = 1 << 2;
        const IA32MISCENABLE_READ = 1 << 3;
        const IA32MISCENABLE_WRITE = 1 << 4;
        const MSR_LSTAR_READ = 1 << 5;
        const MSR_LSTAR_WRITE = 1 << 6;
        const MSR_STAR_READ = 1 << 7;
        const MSR_STAR_WRITE = 1 << 8;
        const MSR_CSTAR_READ = 1 << 9;
        const MSR_CSTAR_WRITE = 1 << 10;
        const MSR_APIC_BASE_READ = 1 << 11;
        const MSR_APIC_BASE_WRITE = 1 << 12;
        const MSR_EFER_READ = 1 << 13;
        const MSR_EFER_WRITE = 1 << 14;
        const GDTR_WRITE = 1 << 15;
        const IDTR_WRITE = 1 << 16;
        const LDTR_WRITE = 1 << 17;
        const TR_WRITE = 1 << 18;
        const MSR_SYSENTER_CS_WRITE = 1 << 19;
        const MSR_SYSENTER_EIP_WRITE = 1 << 20;
        const MSR_SYSENTER_ESP_WRITE = 1 << 21;
        const MSR_SFMASK_WRITE = 1 << 22;
        const MSR_TSC_AUX_WRITE = 1 << 23;
        const MSR_SGX_LAUNCH_CTRL_WRITE = 1 << 24;

        const _ = !0;
    }
}

// --- HV_X64_REGISTER constants (used by ControlRegMap) ---

pub const HV_X64_REGISTER_CR0: u32 = 0x0004_0000;
pub const HV_X64_REGISTER_CR4: u32 = 0x0004_0003;
pub const HV_X64_REGISTER_EFER: u32 = 0x0008_0001;
pub const HV_X64_REGISTER_APIC_BASE: u32 = 0x0008_0003;
pub const HV_X64_REGISTER_SYSENTER_CS: u32 = 0x0008_0005;
pub const HV_X64_REGISTER_SYSENTER_EIP: u32 = 0x0008_0006;
pub const HV_X64_REGISTER_SYSENTER_ESP: u32 = 0x0008_0007;
pub const HV_X64_REGISTER_STAR: u32 = 0x0008_0008;
pub const HV_X64_REGISTER_LSTAR: u32 = 0x0008_0009;
pub const HV_X64_REGISTER_CSTAR: u32 = 0x0008_000a;
pub const HV_X64_REGISTER_SFMASK: u32 = 0x0008_000b;

pub const NUM_CONTROL_REGS: usize = 11;

/// Data structure for maintaining MSRs and control registers whose values are locked.
/// This structure is expected to be stored in per-core kernel context, so we do not protect it with a lock.
#[derive(Debug, Clone, Copy)]
pub struct ControlRegMap {
    pub entries: [(u32, u64); NUM_CONTROL_REGS],
}

impl ControlRegMap {
    pub fn init(&mut self) {
        [
            HV_X64_REGISTER_CR0,
            HV_X64_REGISTER_CR4,
            HV_X64_REGISTER_LSTAR,
            HV_X64_REGISTER_STAR,
            HV_X64_REGISTER_CSTAR,
            HV_X64_REGISTER_APIC_BASE,
            HV_X64_REGISTER_EFER,
            HV_X64_REGISTER_SYSENTER_CS,
            HV_X64_REGISTER_SYSENTER_ESP,
            HV_X64_REGISTER_SYSENTER_EIP,
            HV_X64_REGISTER_SFMASK,
        ]
        .iter()
        .enumerate()
        .for_each(|(i, &reg_name)| {
            self.entries[i] = (reg_name, 0);
        });
    }

    pub fn get(&self, reg_name: u32) -> Option<u64> {
        for entry in &self.entries {
            if entry.0 == reg_name {
                return Some(entry.1);
            }
        }
        None
    }

    pub fn set(&mut self, reg_name: u32, value: u64) {
        for entry in &mut self.entries {
            if entry.0 == reg_name {
                entry.1 = value;
                return;
            }
        }
    }

    // consider implementing a mutable iterator (if we plan to lock many control registers)
    pub fn reg_names(&self) -> [u32; NUM_CONTROL_REGS] {
        let mut names = [0; NUM_CONTROL_REGS];
        for (i, entry) in self.entries.iter().enumerate() {
            names[i] = entry.0;
        }
        names
    }
}

// ============================================================================
// Hyper-V hypercall error types
// ============================================================================

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

// ============================================================================
// Error types
// ============================================================================

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
    #[error("failed to copy data to VTL0")]
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

/// Errors for memory container operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum MemoryContainerError {
    #[error("failed to copy data from VTL0")]
    CopyFromVtl0Failed,
}

/// Errors for patch data map operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum PatchDataMapError {
    #[error("invalid HEKI patch info")]
    InvalidHekiPatchInfo,
    #[error("invalid HEKI patch")]
    InvalidHekiPatch,
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

/// Errors for kernel ELF validation and relocation.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum KernelElfError {
    #[error("failed to parse ELF file")]
    ElfParseFailed,
    #[error("required section not found")]
    SectionNotFound,
}

// ============================================================================
// HEKI (Hypervisor Enforced Kernel Integrity) data types
// ============================================================================

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

pub fn mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();

    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }

    flags
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
        if PhysAddr::try_new(self.next_pa).is_err() {
            return false;
        }
        let Some(nranges) = usize::try_from(self.nranges)
            .ok()
            .filter(|&n| n <= HEKI_MAX_RANGES)
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
    /// Returns an iterator over the valid ranges in this page.
    pub fn iter(&self) -> core::slice::Iter<'_, HekiRange> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a HekiPage {
    type Item = &'a HekiRange;
    type IntoIter = core::slice::Iter<'a, HekiRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges[..usize::try_from(self.nranges).unwrap_or(0)].iter()
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
        if patch.is_valid() {
            Some(patch)
        } else {
            None
        }
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
                (pa_0.align_up(Size4KiB::SIZE) - pa_0).truncate(),
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

    /// Constructs a `HekiKernelSymbol` from a byte slice.
    ///
    /// # Panics
    /// Panics if the byte slice pointer is not properly aligned for `HekiKernelSymbol`.
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

    /// Constructs a `HekiKernelInfo` from a byte slice.
    ///
    /// # Panics
    /// Panics if the byte slice pointer is not properly aligned for `HekiKernelInfo`.
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
        if info.is_valid() {
            Some(info)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        !(self.typ_ != HekiPatchType::JumpLabel as u32
            || self.patch_index == 0
            || self.patch_index > self.max_patch_count)
    }
}

// ============================================================================
// VSM data-only types
// ============================================================================

#[derive(Copy, Clone, FromBytes, Immutable, KnownLayout)]
#[repr(align(4096))]
pub struct AlignedPage(pub [u8; PAGE_SIZE]);

// For now, we do not validate large kernel modules due to the VTL1's memory size limitation.
pub const MODULE_VALIDATION_MAX_SIZE: usize = 64 * 1024 * 1024;

// --- ModuleMemory types ---

pub struct ModuleMemoryMetadata {
    pub ranges: Vec<ModuleMemoryRange>,
    patch_targets: Vec<PhysAddr>,
}

impl ModuleMemoryMetadata {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            patch_targets: Vec::new(),
        }
    }

    #[inline]
    pub fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(ModuleMemoryRange::new(
            va,
            pa,
            epa,
            heki_range.mod_mem_type(),
        ));
    }

    #[inline]
    pub fn insert_memory_range(&mut self, mem_range: ModuleMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub fn insert_patch_target(&mut self, patch_target: PhysAddr) {
        self.patch_targets.push(patch_target);
    }

    // This function returns patch targets belonging to this module to remove them
    // from the precomputed patch data map when the module is unloaded.
    #[inline]
    pub fn get_patch_targets(&self) -> &Vec<PhysAddr> {
        &self.patch_targets
    }
}

impl Default for ModuleMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, ModuleMemoryRange> {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a ModuleMemoryMetadata {
    type Item = &'a ModuleMemoryRange;
    type IntoIter = core::slice::Iter<'a, ModuleMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct ModuleMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
    pub mod_mem_type: ModMemType,
}

impl ModuleMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64, mod_mem_type: ModMemType) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
            mod_mem_type,
        }
    }
}

impl Default for ModuleMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0, ModMemType::Unknown)
    }
}

// TODO: `ModuleMemoryMetadata` and `KexecMemoryMetadata` are similar. Consider merging them into a single structure if possible.
// --- Kexec memory types ---

pub struct KexecMemoryMetadata {
    pub ranges: Vec<KexecMemoryRange>,
}

impl KexecMemoryMetadata {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    #[inline]
    pub fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(KexecMemoryRange::new(va, pa, epa));
    }

    #[inline]
    pub fn insert_memory_range(&mut self, mem_range: KexecMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

impl Default for KexecMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, KexecMemoryRange> {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a KexecMemoryMetadata {
    type Item = &'a KexecMemoryRange;
    type IntoIter = core::slice::Iter<'a, KexecMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct KexecMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
}

impl KexecMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
        }
    }
}

impl Default for KexecMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Data structure for abstracting addressable paged memory ranges.
#[derive(Clone, Copy)]
pub struct MemoryRange {
    pub addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub len: u64,
}

// TODO: Use this to resolve symbols in modules
pub struct Symbol {
    _value: u64,
}

impl Symbol {
    /// Parse a symbol from a byte buffer.
    pub fn from_bytes(
        kinfo_start: usize,
        start: VirtAddr,
        bytes: &[u8],
    ) -> Result<(String, Self), VsmError> {
        let kinfo_bytes = &bytes[kinfo_start..];
        let ksym = HekiKernelSymbol::from_bytes(kinfo_bytes)?;

        let value_addr = start + mem::offset_of!(HekiKernelSymbol, value_offset) as u64;
        let value = value_addr
            .as_u64()
            .wrapping_add_signed(i64::from(ksym.value_offset));

        let name_offset = kinfo_start
            + mem::offset_of!(HekiKernelSymbol, name_offset)
            + usize::try_from(ksym.name_offset).map_err(|_| VsmError::SymbolNameOffsetInvalid)?;

        if name_offset >= bytes.len() {
            return Err(VsmError::SymbolNameOffsetInvalid);
        }
        let name_len = bytes[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(VsmError::SymbolNameNoTerminator)?;
        if name_len >= HekiKernelSymbol::KSY_NAME_LEN {
            return Err(VsmError::SymbolNameTooLong);
        }

        // SAFETY:
        // - offset is within bytes (checked above)
        // - there is a NUL terminator within bytes[offset..] (checked above)
        // - Length of name string is within spec range (checked above)
        // - bytes is still valid for the duration of this function
        let name_str = unsafe {
            let name_ptr = bytes.as_ptr().add(name_offset).cast::<c_char>();
            CStr::from_ptr(name_ptr)
        };
        let name = CString::new(
            name_str
                .to_str()
                .map_err(|_| VsmError::SymbolNameInvalidUtf8)?,
        )
        .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        let name = name
            .into_string()
            .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        Ok((name, Symbol { _value: value }))
    }
}

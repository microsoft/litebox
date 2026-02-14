// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Error types for VSM operations.

use crate::hvcall::HypervCallError;
use litebox_common_linux::errno::Errno;
use thiserror::Error;

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

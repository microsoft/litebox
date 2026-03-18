// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common Windows NT items for LiteBox.
//!
//! This crate provides NT kernel interface types, NTSTATUS codes, PE format
//! structures, a PE parser, a PE builder (for generating stub DLLs), and an
//! API-set remapping table.

#![no_std]
#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    // PE format structures require exact-layout fields with padding,
    // and binary format code inherently involves cross-width casts.
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::struct_field_names,
    // Padding fields in repr(C) structs need pub for zerocopy derives
    // but are intentionally unused.
    clippy::used_underscore_binding,
    clippy::pub_underscore_fields,
    // Binary format parsing uses many fallible patterns; let-else would
    // be verbose with the error mapping.
    clippy::manual_let_else,
    // Binary format parsing loops are clearer as loop+match than while-let.
    clippy::while_let_loop,
    // PE builder uses names like edata_sh / text_sh which are close but distinct.
    clippy::similar_names,
)]

extern crate alloc;

pub mod apiset;
pub mod gs_table;
pub mod nt_types;
pub mod ntstatus;
pub mod pe;
pub mod pe_builder;
pub mod pe_loader;
pub mod pe_parser;
pub mod stub_dlls;

/// Standard Windows HANDLEs for console I/O.
pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // (DWORD)-12

/// Pseudo-handle for the current process.
pub const NT_CURRENT_PROCESS: usize = usize::MAX; // (HANDLE)-1
/// Pseudo-handle for the current thread.
pub const NT_CURRENT_THREAD: usize = usize::MAX - 1; // (HANDLE)-2

/// NT syscall numbers. Since we control both the stub DLLs and the shim
/// dispatcher, we assign our own stable numbers rather than matching any
/// specific Windows build.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NtSyscallNumber {
    // Phase 1: Minimal boot
    NtWriteFile = 0x0001,
    NtAllocateVirtualMemory = 0x0002,
    NtFreeVirtualMemory = 0x0003,
    NtProtectVirtualMemory = 0x0004,
    NtQueryVirtualMemory = 0x0005,
    NtClose = 0x0006,
    NtTerminateProcess = 0x0007,

    // Phase 2: File I/O & CRT init
    NtCreateFile = 0x0010,
    NtReadFile = 0x0011,
    NtQueryInformationFile = 0x0012,
    NtSetInformationFile = 0x0013,
    NtQueryVolumeInformationFile = 0x0014,
    NtQueryDirectoryFile = 0x0015,
    NtDeleteFile = 0x0016,
    NtQueryAttributesFile = 0x0017,
    NtCreateSection = 0x0018,
    NtMapViewOfSection = 0x0019,
    NtUnmapViewOfSection = 0x001A,
    NtQuerySystemInformation = 0x001B,
    NtQueryPerformanceCounter = 0x001C,
    NtQuerySystemTime = 0x001D,
    NtSetInformationThread = 0x001E,
    NtQueryInformationProcess = 0x001F,

    // Phase 3: Threading & sync
    NtCreateThreadEx = 0x0030,
    NtTerminateThread = 0x0031,
    NtWaitForSingleObject = 0x0032,
    NtWaitForMultipleObjects = 0x0033,
    NtCreateEvent = 0x0034,
    NtSetEvent = 0x0035,
    NtResetEvent = 0x0036,
    NtCreateSemaphore = 0x0037,
    NtReleaseSemaphore = 0x0038,
    NtDuplicateObject = 0x0039,
    NtQueryObject = 0x003A,
    NtDelayExecution = 0x003B,

    // Phase 4: Networking & IOCP
    NtDeviceIoControlFile = 0x0040,
    NtCreateIoCompletion = 0x0041,
    NtSetIoCompletion = 0x0042,
    NtRemoveIoCompletion = 0x0043,

    // Phase 5: Process spawning
    NtCreateUserProcess = 0x0050,
    NtCreateNamedPipeFile = 0x0051,
    NtOpenKey = 0x0052,
    NtQueryValueKey = 0x0053,
}

impl NtSyscallNumber {
    /// Try to convert a raw u32 syscall number to an `NtSyscallNumber`.
    pub fn from_raw(nr: u32) -> Option<Self> {
        // Use a match rather than transmute for safety.
        match nr {
            0x0001 => Some(Self::NtWriteFile),
            0x0002 => Some(Self::NtAllocateVirtualMemory),
            0x0003 => Some(Self::NtFreeVirtualMemory),
            0x0004 => Some(Self::NtProtectVirtualMemory),
            0x0005 => Some(Self::NtQueryVirtualMemory),
            0x0006 => Some(Self::NtClose),
            0x0007 => Some(Self::NtTerminateProcess),

            0x0010 => Some(Self::NtCreateFile),
            0x0011 => Some(Self::NtReadFile),
            0x0012 => Some(Self::NtQueryInformationFile),
            0x0013 => Some(Self::NtSetInformationFile),
            0x0014 => Some(Self::NtQueryVolumeInformationFile),
            0x0015 => Some(Self::NtQueryDirectoryFile),
            0x0016 => Some(Self::NtDeleteFile),
            0x0017 => Some(Self::NtQueryAttributesFile),
            0x0018 => Some(Self::NtCreateSection),
            0x0019 => Some(Self::NtMapViewOfSection),
            0x001A => Some(Self::NtUnmapViewOfSection),
            0x001B => Some(Self::NtQuerySystemInformation),
            0x001C => Some(Self::NtQueryPerformanceCounter),
            0x001D => Some(Self::NtQuerySystemTime),
            0x001E => Some(Self::NtSetInformationThread),
            0x001F => Some(Self::NtQueryInformationProcess),

            0x0030 => Some(Self::NtCreateThreadEx),
            0x0031 => Some(Self::NtTerminateThread),
            0x0032 => Some(Self::NtWaitForSingleObject),
            0x0033 => Some(Self::NtWaitForMultipleObjects),
            0x0034 => Some(Self::NtCreateEvent),
            0x0035 => Some(Self::NtSetEvent),
            0x0036 => Some(Self::NtResetEvent),
            0x0037 => Some(Self::NtCreateSemaphore),
            0x0038 => Some(Self::NtReleaseSemaphore),
            0x0039 => Some(Self::NtDuplicateObject),
            0x003A => Some(Self::NtQueryObject),
            0x003B => Some(Self::NtDelayExecution),

            0x0040 => Some(Self::NtDeviceIoControlFile),
            0x0041 => Some(Self::NtCreateIoCompletion),
            0x0042 => Some(Self::NtSetIoCompletion),
            0x0043 => Some(Self::NtRemoveIoCompletion),

            0x0050 => Some(Self::NtCreateUserProcess),
            0x0051 => Some(Self::NtCreateNamedPipeFile),
            0x0052 => Some(Self::NtOpenKey),
            0x0053 => Some(Self::NtQueryValueKey),

            _ => None,
        }
    }
}

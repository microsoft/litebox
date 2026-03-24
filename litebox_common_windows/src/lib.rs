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
pub mod ntdll_rewriter;
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

/// NT syscall identifiers.
///
/// These are **logical names** for NT syscalls the shim can handle.
/// They carry no fixed numeric value — the ntdll rewriter discovers the
/// real Windows syscall number for each function at rewrite time and
/// produces a mapping table (`NtSyscallMap`) that the shim uses for
/// dispatch.  This design works across Windows builds where the raw
/// numbers change.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NtSyscallId {
    NtWriteFile,
    NtAllocateVirtualMemory,
    NtAllocateVirtualMemoryEx,
    NtFreeVirtualMemory,
    NtProtectVirtualMemory,
    NtQueryVirtualMemory,
    NtClose,
    NtTerminateProcess,

    NtCreateFile,
    NtReadFile,
    NtQueryInformationFile,
    NtSetInformationFile,
    NtQueryVolumeInformationFile,
    NtQueryDirectoryFile,
    NtDeleteFile,
    NtQueryAttributesFile,
    NtCreateSection,
    NtMapViewOfSection,
    NtUnmapViewOfSection,
    NtUnmapViewOfSectionEx,
    NtQuerySystemInformation,
    NtQuerySystemInformationEx,
    NtQueryPerformanceCounter,
    NtQuerySystemTime,
    NtSetInformationThread,
    NtQueryInformationProcess,
    NtOpenProcess,
    NtOpenFile,

    NtCreateThreadEx,
    NtTerminateThread,
    NtResumeThread,
    NtAlertResumeThread,
    NtWaitForSingleObject,
    NtWaitForMultipleObjects,
    NtCreateEvent,
    NtSetEvent,
    NtResetEvent,
    NtCreateSemaphore,
    NtReleaseSemaphore,
    NtDuplicateObject,
    NtQueryObject,
    NtSetInformationObject,
    NtDelayExecution,
    NtCreateKeyedEvent,
    NtWaitForKeyedEvent,
    NtReleaseKeyedEvent,
    NtClearEvent,

    NtDeviceIoControlFile,
    NtCreateIoCompletion,
    NtSetIoCompletion,
    NtRemoveIoCompletion,

    NtContinue,
    NtOpenSection,
    NtQuerySection,
    NtSetInformationProcess,
    NtFlushBuffersFile,
    NtCreateMutant,
    NtOpenMutant,
    NtQueryInformationThread,
    NtOpenProcessToken,
    NtOpenThreadToken,
    NtQueryInformationToken,
    NtQuerySecurityAttributesToken,
    NtRtlExitUserThread,

    NtCreateUserProcess,
    NtCreateNamedPipeFile,
    NtCreateKey,
    NtOpenKey,
    NtQueryValueKey,
    NtQueryMultipleValueKey,

    NtTraceEvent,
    NtManageHotPatch,
    NtRaiseHardError,
    NtQueryKey,
    NtSetInformationKey,
    NtOpenKeyEx,
    NtNotifyChangeKey,
    NtGetNlsSectionPtr,
    NtInitializeNlsFiles,
    NtCreateWaitCompletionPacket,
    NtOpenDirectoryObject,
    NtCreateWorkerFactory,
    NtReleaseWorkerFactoryWorker,
    NtCreateTimer2,
    NtSetTimer2,
    NtQueryTimerResolution,
    NtRaiseException,
    NtOpenEvent,
    NtSetInformationWorkerFactory,
    NtAssociateWaitCompletionPacket,
    NtShutdownWorkerFactory,
    NtCancelWaitCompletionPacket,
    NtTraceControl,
    NtSetWnfProcessNotificationEvent,
    NtUpdateWnfStateData,
    NtCreateSectionEx,
    NtMapViewOfSectionEx,
    NtSetDefaultHardErrorPort,
    NtOpenSymbolicLinkObject,
    NtQuerySymbolicLinkObject,
    NtEnumerateKey,
    NtEnumerateValueKey,
    NtApphelpCacheControl,
    NtSubscribeWnfStateChange,
    NtUnsubscribeWnfStateChange,
    NtCallbackReturn,
    NtQueryWnfStateData,
    NtQueryLicenseValue,
    NtReadVirtualMemory,
    NtContinueEx,
    NtTestAlert,
    NtIsUILanguageComitted,
    NtQueryInstallUILanguage,
    NtQueryWnfStateNameInformation,
    NtOpenSemaphore,
    NtReleaseMutant,
    NtGetMUIRegistryInfo,
    NtWaitForAlertByThreadId,
    NtAlertThreadByThreadId,
    NtAlertThreadByThreadIdEx,
    NtRemoveIoCompletionEx,
    NtSetIoCompletionEx,
}

/// Mapping from real Windows syscall numbers to `NtSyscallId`.
///
/// Produced by the ntdll rewriter after scanning the export table.
/// The shim receives this at init and uses it for dispatch.
pub struct NtSyscallMap {
    /// Sparse lookup: index = real Windows syscall number, value = Some(id).
    /// Sized to hold the maximum real number seen during rewriting + 1.
    table: alloc::vec::Vec<Option<NtSyscallId>>,
}

impl NtSyscallMap {
    /// Build from a list of (real_nr, id) pairs.
    pub fn from_pairs(pairs: &[(u32, NtSyscallId)]) -> Self {
        let max_nr = pairs.iter().map(|(nr, _)| *nr).max().unwrap_or(0) as usize;
        let mut table = alloc::vec![None; max_nr + 1];
        for &(nr, id) in pairs {
            table[nr as usize] = Some(id);
        }
        Self { table }
    }

    /// Look up a raw syscall number.
    #[inline]
    pub fn lookup(&self, raw_nr: u32) -> Option<NtSyscallId> {
        self.table.get(raw_nr as usize).copied().flatten()
    }

    /// Build an identity map where syscall number == `NtSyscallId` discriminant.
    ///
    /// Used by the stub-DLL path where we control the syscall numbers.
    pub fn identity() -> Self {
        let all: &[NtSyscallId] = &[
            NtSyscallId::NtWriteFile,
            NtSyscallId::NtAllocateVirtualMemory,
            NtSyscallId::NtAllocateVirtualMemoryEx,
            NtSyscallId::NtFreeVirtualMemory,
            NtSyscallId::NtProtectVirtualMemory,
            NtSyscallId::NtQueryVirtualMemory,
            NtSyscallId::NtClose,
            NtSyscallId::NtTerminateProcess,
            NtSyscallId::NtCreateFile,
            NtSyscallId::NtReadFile,
            NtSyscallId::NtQueryInformationFile,
            NtSyscallId::NtSetInformationFile,
            NtSyscallId::NtQueryVolumeInformationFile,
            NtSyscallId::NtQueryDirectoryFile,
            NtSyscallId::NtDeleteFile,
            NtSyscallId::NtQueryAttributesFile,
            NtSyscallId::NtCreateSection,
            NtSyscallId::NtMapViewOfSection,
            NtSyscallId::NtUnmapViewOfSection,
            NtSyscallId::NtUnmapViewOfSectionEx,
            NtSyscallId::NtQuerySystemInformation,
            NtSyscallId::NtQuerySystemInformationEx,
            NtSyscallId::NtQueryPerformanceCounter,
            NtSyscallId::NtQuerySystemTime,
            NtSyscallId::NtSetInformationThread,
            NtSyscallId::NtQueryInformationProcess,
            NtSyscallId::NtOpenProcess,
            NtSyscallId::NtOpenFile,
            NtSyscallId::NtCreateThreadEx,
            NtSyscallId::NtTerminateThread,
            NtSyscallId::NtResumeThread,
            NtSyscallId::NtAlertResumeThread,
            NtSyscallId::NtWaitForSingleObject,
            NtSyscallId::NtWaitForMultipleObjects,
            NtSyscallId::NtCreateEvent,
            NtSyscallId::NtSetEvent,
            NtSyscallId::NtResetEvent,
            NtSyscallId::NtClearEvent,
            NtSyscallId::NtCreateSemaphore,
            NtSyscallId::NtReleaseSemaphore,
            NtSyscallId::NtCreateKeyedEvent,
            NtSyscallId::NtWaitForKeyedEvent,
            NtSyscallId::NtReleaseKeyedEvent,
            NtSyscallId::NtDuplicateObject,
            NtSyscallId::NtQueryObject,
            NtSyscallId::NtSetInformationObject,
            NtSyscallId::NtDelayExecution,
            NtSyscallId::NtDeviceIoControlFile,
            NtSyscallId::NtCreateIoCompletion,
            NtSyscallId::NtSetIoCompletion,
            NtSyscallId::NtRemoveIoCompletion,
            NtSyscallId::NtContinue,
            NtSyscallId::NtOpenSection,
            NtSyscallId::NtQuerySection,
            NtSyscallId::NtSetInformationProcess,
            NtSyscallId::NtFlushBuffersFile,
            NtSyscallId::NtCreateMutant,
            NtSyscallId::NtOpenMutant,
            NtSyscallId::NtQueryInformationThread,
            NtSyscallId::NtOpenProcessToken,
            NtSyscallId::NtOpenThreadToken,
            NtSyscallId::NtQueryInformationToken,
            NtSyscallId::NtQuerySecurityAttributesToken,
            NtSyscallId::NtRtlExitUserThread,
            NtSyscallId::NtCreateKey,
            NtSyscallId::NtOpenKey,
            NtSyscallId::NtQueryValueKey,
            NtSyscallId::NtQueryMultipleValueKey,
            NtSyscallId::NtTraceEvent,
            NtSyscallId::NtManageHotPatch,
            NtSyscallId::NtRaiseHardError,
            NtSyscallId::NtQueryKey,
            NtSyscallId::NtSetInformationKey,
            NtSyscallId::NtOpenKeyEx,
            NtSyscallId::NtNotifyChangeKey,
            NtSyscallId::NtGetNlsSectionPtr,
            NtSyscallId::NtInitializeNlsFiles,
            NtSyscallId::NtCreateWaitCompletionPacket,
            NtSyscallId::NtOpenDirectoryObject,
            NtSyscallId::NtCreateWorkerFactory,
            NtSyscallId::NtReleaseWorkerFactoryWorker,
            NtSyscallId::NtCreateTimer2,
            NtSyscallId::NtSetTimer2,
            NtSyscallId::NtQueryTimerResolution,
            NtSyscallId::NtRaiseException,
            NtSyscallId::NtOpenEvent,
            NtSyscallId::NtSetInformationWorkerFactory,
            NtSyscallId::NtAssociateWaitCompletionPacket,
            NtSyscallId::NtShutdownWorkerFactory,
            NtSyscallId::NtCancelWaitCompletionPacket,
            NtSyscallId::NtTraceControl,
            NtSyscallId::NtSetWnfProcessNotificationEvent,
            NtSyscallId::NtUpdateWnfStateData,
            NtSyscallId::NtCreateSectionEx,
            NtSyscallId::NtMapViewOfSectionEx,
            NtSyscallId::NtSetDefaultHardErrorPort,
            NtSyscallId::NtOpenSymbolicLinkObject,
            NtSyscallId::NtQuerySymbolicLinkObject,
            NtSyscallId::NtEnumerateKey,
            NtSyscallId::NtEnumerateValueKey,
            NtSyscallId::NtApphelpCacheControl,
            NtSyscallId::NtSubscribeWnfStateChange,
            NtSyscallId::NtUnsubscribeWnfStateChange,
            NtSyscallId::NtCallbackReturn,
            NtSyscallId::NtQueryWnfStateData,
            NtSyscallId::NtQueryLicenseValue,
            NtSyscallId::NtReadVirtualMemory,
            NtSyscallId::NtContinueEx,
            NtSyscallId::NtTestAlert,
            NtSyscallId::NtIsUILanguageComitted,
            NtSyscallId::NtQueryInstallUILanguage,
            NtSyscallId::NtQueryWnfStateNameInformation,
            NtSyscallId::NtOpenSemaphore,
            NtSyscallId::NtReleaseMutant,
            NtSyscallId::NtGetMUIRegistryInfo,
            NtSyscallId::NtWaitForAlertByThreadId,
            NtSyscallId::NtAlertThreadByThreadId,
            NtSyscallId::NtAlertThreadByThreadIdEx,
            NtSyscallId::NtRemoveIoCompletionEx,
            NtSyscallId::NtSetIoCompletionEx,
        ];
        let pairs: alloc::vec::Vec<(u32, NtSyscallId)> =
            all.iter().map(|&id| (id as u32, id)).collect();
        Self::from_pairs(&pairs)
    }
}

/// Map an ntdll export name to its `NtSyscallId`.
///
/// This is the single source of truth for which NT function names the
/// shim recognises.  The rewriter calls this for every exported stub it
/// finds; matches get recorded in the `NtSyscallMap`.
pub fn name_to_syscall_id(name: &str) -> Option<NtSyscallId> {
    let id = match name {
        "NtWriteFile" => NtSyscallId::NtWriteFile,
        "NtAllocateVirtualMemory" => NtSyscallId::NtAllocateVirtualMemory,
        "NtAllocateVirtualMemoryEx" => NtSyscallId::NtAllocateVirtualMemoryEx,
        "NtFreeVirtualMemory" => NtSyscallId::NtFreeVirtualMemory,
        "NtProtectVirtualMemory" => NtSyscallId::NtProtectVirtualMemory,
        "NtQueryVirtualMemory" => NtSyscallId::NtQueryVirtualMemory,
        "NtClose" => NtSyscallId::NtClose,
        "NtTerminateProcess" => NtSyscallId::NtTerminateProcess,
        "NtCreateFile" => NtSyscallId::NtCreateFile,
        "NtReadFile" => NtSyscallId::NtReadFile,
        "NtQueryInformationFile" => NtSyscallId::NtQueryInformationFile,
        "NtSetInformationFile" => NtSyscallId::NtSetInformationFile,
        "NtQueryVolumeInformationFile" => NtSyscallId::NtQueryVolumeInformationFile,
        "NtQueryDirectoryFile" => NtSyscallId::NtQueryDirectoryFile,
        "NtDeleteFile" => NtSyscallId::NtDeleteFile,
        "NtQueryAttributesFile" => NtSyscallId::NtQueryAttributesFile,
        "NtCreateSection" => NtSyscallId::NtCreateSection,
        "NtMapViewOfSection" => NtSyscallId::NtMapViewOfSection,
        "NtUnmapViewOfSection" => NtSyscallId::NtUnmapViewOfSection,
        "NtUnmapViewOfSectionEx" => NtSyscallId::NtUnmapViewOfSectionEx,
        "NtQuerySystemInformation" => NtSyscallId::NtQuerySystemInformation,
        "NtQuerySystemInformationEx" => NtSyscallId::NtQuerySystemInformationEx,
        "NtQueryPerformanceCounter" => NtSyscallId::NtQueryPerformanceCounter,
        "NtQuerySystemTime" => NtSyscallId::NtQuerySystemTime,
        "NtSetInformationThread" => NtSyscallId::NtSetInformationThread,
        "NtQueryInformationProcess" => NtSyscallId::NtQueryInformationProcess,
        "NtOpenProcess" => NtSyscallId::NtOpenProcess,
        "NtOpenFile" => NtSyscallId::NtOpenFile,
        "NtCreateThreadEx" => NtSyscallId::NtCreateThreadEx,
        "NtTerminateThread" => NtSyscallId::NtTerminateThread,
        "NtResumeThread" => NtSyscallId::NtResumeThread,
        "NtAlertResumeThread" => NtSyscallId::NtAlertResumeThread,
        "NtWaitForSingleObject" => NtSyscallId::NtWaitForSingleObject,
        "NtWaitForMultipleObjects" => NtSyscallId::NtWaitForMultipleObjects,
        "NtCreateEvent" => NtSyscallId::NtCreateEvent,
        "NtSetEvent" => NtSyscallId::NtSetEvent,
        "NtResetEvent" => NtSyscallId::NtResetEvent,
        "NtCreateSemaphore" => NtSyscallId::NtCreateSemaphore,
        "NtReleaseSemaphore" => NtSyscallId::NtReleaseSemaphore,
        "NtDuplicateObject" => NtSyscallId::NtDuplicateObject,
        "NtQueryObject" => NtSyscallId::NtQueryObject,
        "NtSetInformationObject" => NtSyscallId::NtSetInformationObject,
        "NtDelayExecution" => NtSyscallId::NtDelayExecution,
        "NtCreateKeyedEvent" => NtSyscallId::NtCreateKeyedEvent,
        "NtWaitForKeyedEvent" => NtSyscallId::NtWaitForKeyedEvent,
        "NtReleaseKeyedEvent" => NtSyscallId::NtReleaseKeyedEvent,
        "NtClearEvent" => NtSyscallId::NtClearEvent,
        "NtDeviceIoControlFile" => NtSyscallId::NtDeviceIoControlFile,
        "NtCreateIoCompletion" => NtSyscallId::NtCreateIoCompletion,
        "NtSetIoCompletion" => NtSyscallId::NtSetIoCompletion,
        "NtRemoveIoCompletion" => NtSyscallId::NtRemoveIoCompletion,
        "NtContinue" => NtSyscallId::NtContinue,
        "NtOpenSection" => NtSyscallId::NtOpenSection,
        "NtQuerySection" => NtSyscallId::NtQuerySection,
        "NtSetInformationProcess" => NtSyscallId::NtSetInformationProcess,
        "NtFlushBuffersFile" => NtSyscallId::NtFlushBuffersFile,
        "NtCreateMutant" => NtSyscallId::NtCreateMutant,
        "NtOpenMutant" => NtSyscallId::NtOpenMutant,
        "NtQueryInformationThread" => NtSyscallId::NtQueryInformationThread,
        "NtOpenProcessToken" => NtSyscallId::NtOpenProcessToken,
        "NtOpenThreadToken" => NtSyscallId::NtOpenThreadToken,
        "NtQueryInformationToken" => NtSyscallId::NtQueryInformationToken,
        "NtQuerySecurityAttributesToken" => NtSyscallId::NtQuerySecurityAttributesToken,
        "RtlExitUserThread" => NtSyscallId::NtRtlExitUserThread,
        "NtCreateKey" => NtSyscallId::NtCreateKey,
        "NtTraceEvent" => NtSyscallId::NtTraceEvent,
        "NtManageHotPatch" => NtSyscallId::NtManageHotPatch,
        "NtRaiseHardError" => NtSyscallId::NtRaiseHardError,
        "NtQueryKey" => NtSyscallId::NtQueryKey,
        "NtSetInformationKey" => NtSyscallId::NtSetInformationKey,
        "NtOpenKey" => NtSyscallId::NtOpenKey,
        "NtOpenKeyEx" => NtSyscallId::NtOpenKeyEx,
        "NtNotifyChangeKey" => NtSyscallId::NtNotifyChangeKey,
        "NtQueryValueKey" => NtSyscallId::NtQueryValueKey,
        "NtQueryMultipleValueKey" => NtSyscallId::NtQueryMultipleValueKey,
        "NtCreateUserProcess" => NtSyscallId::NtCreateUserProcess,
        "NtCreateNamedPipeFile" => NtSyscallId::NtCreateNamedPipeFile,
        "NtGetNlsSectionPtr" => NtSyscallId::NtGetNlsSectionPtr,
        "NtInitializeNlsFiles" => NtSyscallId::NtInitializeNlsFiles,
        "NtCreateWaitCompletionPacket" => NtSyscallId::NtCreateWaitCompletionPacket,
        "NtOpenDirectoryObject" => NtSyscallId::NtOpenDirectoryObject,
        "NtCreateWorkerFactory" => NtSyscallId::NtCreateWorkerFactory,
        "NtReleaseWorkerFactoryWorker" => NtSyscallId::NtReleaseWorkerFactoryWorker,
        "NtCreateTimer2" => NtSyscallId::NtCreateTimer2,
        "NtSetTimer2" => NtSyscallId::NtSetTimer2,
        "NtQueryTimerResolution" => NtSyscallId::NtQueryTimerResolution,
        "NtRaiseException" => NtSyscallId::NtRaiseException,
        "NtOpenEvent" => NtSyscallId::NtOpenEvent,
        "NtSetInformationWorkerFactory" => NtSyscallId::NtSetInformationWorkerFactory,
        "NtAssociateWaitCompletionPacket" => NtSyscallId::NtAssociateWaitCompletionPacket,
        "NtShutdownWorkerFactory" => NtSyscallId::NtShutdownWorkerFactory,
        "NtCancelWaitCompletionPacket" => NtSyscallId::NtCancelWaitCompletionPacket,
        "NtTraceControl" => NtSyscallId::NtTraceControl,
        "NtSetWnfProcessNotificationEvent" => NtSyscallId::NtSetWnfProcessNotificationEvent,
        "NtUpdateWnfStateData" => NtSyscallId::NtUpdateWnfStateData,
        "NtCreateSectionEx" => NtSyscallId::NtCreateSectionEx,
        "NtMapViewOfSectionEx" => NtSyscallId::NtMapViewOfSectionEx,
        "NtSetDefaultHardErrorPort" => NtSyscallId::NtSetDefaultHardErrorPort,
        "NtOpenSymbolicLinkObject" => NtSyscallId::NtOpenSymbolicLinkObject,
        "NtQuerySymbolicLinkObject" => NtSyscallId::NtQuerySymbolicLinkObject,
        "NtEnumerateKey" => NtSyscallId::NtEnumerateKey,
        "NtEnumerateValueKey" => NtSyscallId::NtEnumerateValueKey,
        "NtApphelpCacheControl" => NtSyscallId::NtApphelpCacheControl,
        "NtSubscribeWnfStateChange" => NtSyscallId::NtSubscribeWnfStateChange,
        "NtUnsubscribeWnfStateChange" => NtSyscallId::NtUnsubscribeWnfStateChange,
        "NtCallbackReturn" => NtSyscallId::NtCallbackReturn,
        "NtQueryWnfStateData" => NtSyscallId::NtQueryWnfStateData,
        "NtQueryLicenseValue" => NtSyscallId::NtQueryLicenseValue,
        "NtReadVirtualMemory" => NtSyscallId::NtReadVirtualMemory,
        "NtContinueEx" => NtSyscallId::NtContinueEx,
        "NtTestAlert" => NtSyscallId::NtTestAlert,
        "NtIsUILanguageComitted" => NtSyscallId::NtIsUILanguageComitted,
        "NtQueryInstallUILanguage" => NtSyscallId::NtQueryInstallUILanguage,
        "NtQueryWnfStateNameInformation" => NtSyscallId::NtQueryWnfStateNameInformation,
        "NtOpenSemaphore" => NtSyscallId::NtOpenSemaphore,
        "NtReleaseMutant" => NtSyscallId::NtReleaseMutant,
        "NtGetMUIRegistryInfo" => NtSyscallId::NtGetMUIRegistryInfo,
        "NtWaitForAlertByThreadId" => NtSyscallId::NtWaitForAlertByThreadId,
        "NtAlertThreadByThreadId" => NtSyscallId::NtAlertThreadByThreadId,
        "NtAlertThreadByThreadIdEx" => NtSyscallId::NtAlertThreadByThreadIdEx,
        "NtRemoveIoCompletionEx" => NtSyscallId::NtRemoveIoCompletionEx,
        "NtSetIoCompletionEx" => NtSyscallId::NtSetIoCompletionEx,
        _ => return None,
    };
    Some(id)
}

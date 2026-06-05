// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NTSTATUS error handling. See [`NtStatus`].

use thiserror::Error;

/// Windows NTSTATUS error codes
///
/// This is a transparent wrapper around Windows NTSTATUS values (i.e., `i32`s) intended
/// to provide some type safety by expecting explicit conversions to/from `i32`s.
///
/// NTSTATUS is a 32-bit signed integer that encodes severity, facility, and error code.
/// Typically:
/// - 0x00000000 = STATUS_SUCCESS (no error)
/// - 0xC0000000+ = NT_ERROR (severe errors)
/// - 0x80000000+ = NT_WARNING (warnings)
/// - 0x40000000+ = NT_INFORMATION (informational)
///
/// Values are sourced from Wine's `include/ntstatus.h`.
#[derive(PartialEq, Eq, Clone, Copy, Error)]
pub struct NtStatus {
    value: i32,
}

impl From<NtStatus> for i32 {
    fn from(e: NtStatus) -> Self {
        e.value
    }
}

impl core::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl core::fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NtStatus({:#x} = {})", self.value, self.as_str())
    }
}

impl NtStatus {
    /// Helper function that creates an NtStatus from a raw NTSTATUS bit pattern.
    pub const fn from_raw(value: u32) -> Self {
        Self {
            value: value.cast_signed(),
        }
    }

    /// Returns the raw NTSTATUS value
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self.value
    }

    /// Returns true if the status indicates success (value >= 0)
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.value >= 0
    }

    /// Returns true if the status indicates an error (value < 0)
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.value < 0
    }

    /// Returns this status code as a usize bit pattern.
    #[must_use]
    pub const fn to_usize(self) -> usize {
        self.value.cast_unsigned() as usize
    }

    /// Human-friendly readable version of `self`.
    pub const fn as_str(self) -> &'static str {
        match u32::from_ne_bytes(self.value.to_ne_bytes()) {
            0x00000000 => "STATUS_SUCCESS: The operation completed successfully",
            0x00000001 => {
                "STATUS_WAIT_1: Caller specified WaitAny and one of the dispatcher objects was set"
            }
            0x00000002 => {
                "STATUS_WAIT_2: Caller specified WaitAny and one of the dispatcher objects was set"
            }
            0x00000003 => {
                "STATUS_WAIT_3: Caller specified WaitAny and one of the dispatcher objects was set"
            }
            0x00000102 => "STATUS_TIMEOUT: The given timeout interval expired",
            0x00010001 => "DBG_EXCEPTION_HANDLED: Exception handled by debugger",
            0x00010002 => "DBG_CONTINUE: Continue from exception",
            0x40000000 => "STATUS_OBJECT_NAME_EXISTS: The object name already exists",
            0x80000001 => "STATUS_GUARD_PAGE_VIOLATION: Page fault on a guarded page",
            0x80000002 => "STATUS_DATATYPE_MISALIGNMENT: Datatype misalignment",
            0x80000003 => "STATUS_BREAKPOINT: Breakpoint encountered",
            0x80000004 => "STATUS_SINGLE_STEP: Single instruction executed",
            0x80000005 => "STATUS_BUFFER_OVERFLOW: Buffer overflow",
            0xC0000001 => "STATUS_UNSUCCESSFUL: The operation completed with an error",
            0xC0000002 => "STATUS_NOT_IMPLEMENTED: The function is not implemented",
            0xC0000003 => "STATUS_INVALID_INFO_CLASS: Invalid information class",
            0xC0000004 => "STATUS_INFO_LENGTH_MISMATCH: Information length mismatch",
            0xC0000005 => "STATUS_ACCESS_VIOLATION: Access violation",
            0xC0000006 => "STATUS_IN_PAGE_ERROR: In-page I/O error",
            0xC0000007 => "STATUS_PAGEFILE_QUOTA: Pagefile quota exceeded",
            0xC0000008 => "STATUS_INVALID_HANDLE: Invalid handle",
            0xC0000009 => "STATUS_BAD_INITIAL_STACK: Bad initial stack",
            0xC000000A => "STATUS_BAD_INITIAL_PC: Bad initial PC",
            0xC000000B => "STATUS_INVALID_CID: Invalid CID",
            0xC000000C => "STATUS_TIMER_NOT_CANCELED: Timer not canceled",
            0xC000000D => "STATUS_INVALID_PARAMETER: Invalid parameter",
            0xC000000E => "STATUS_NO_SUCH_DEVICE: Device not found",
            0xC000000F => "STATUS_NO_SUCH_FILE: File not found",
            0xC0000010 => "STATUS_INVALID_DEVICE_REQUEST: Invalid device request",
            0xC0000011 => "STATUS_END_OF_FILE: End of file",
            0xC0000012 => "STATUS_WRONG_VOLUME: Wrong volume",
            0xC0000013 => "STATUS_NO_MEDIA_IN_DEVICE: No media in device",
            0xC0000014 => "STATUS_UNRECOGNIZED_MEDIA: Unrecognized media",
            0xC0000016 => "STATUS_MORE_PROCESSING_REQUIRED: More processing required",
            0xC0000017 => "STATUS_NO_MEMORY: Insufficient memory",
            0xC0000019 => "STATUS_NOT_MAPPED_VIEW: Not mapped view",
            0xC000001A => "STATUS_UNABLE_TO_FREE_VM: Unable to free virtual memory",
            0xC000001B => "STATUS_UNABLE_TO_DELETE_SECTION: Unable to delete section",
            0xC000001C => "STATUS_INVALID_SYSTEM_SERVICE: Invalid system service",
            0xC000001D => "STATUS_ILLEGAL_INSTRUCTION: Illegal instruction",
            0xC000001E => "STATUS_INVALID_LOCK_SEQUENCE: Invalid lock sequence",
            0xC000001F => "STATUS_INVALID_VIEW_SIZE: Invalid view size",
            0xC0000020 => "STATUS_INVALID_FILE_FOR_SECTION: Invalid file for section",
            0xC0000021 => "STATUS_ALREADY_COMMITTED: Already committed",
            0xC0000022 => "STATUS_ACCESS_DENIED: Access denied",
            0xC0000023 => "STATUS_BUFFER_TOO_SMALL: Buffer too small",
            0xC0000024 => "STATUS_OBJECT_TYPE_MISMATCH: Object type mismatch",
            0xC0000025 => "STATUS_NONCONTINUABLE_EXCEPTION: Noncontinuable exception",
            0xC0000026 => "STATUS_INVALID_DISPOSITION: Invalid disposition",
            0xC0000027 => "STATUS_UNWIND: Unwind in progress",
            0xC0000028 => "STATUS_BAD_STACK: Bad stack",
            0xC0000029 => "STATUS_INVALID_UNWIND_TARGET: Invalid unwind target",
            0xC000002D => "STATUS_NOT_COMMITTED: Not committed",
            0xC0000033 => "STATUS_OBJECT_NAME_INVALID: Object name invalid",
            0xC0000034 => "STATUS_OBJECT_NAME_NOT_FOUND: Object name not found",
            0xC0000035 => "STATUS_OBJECT_NAME_COLLISION: Object name already exists",
            0xC0000037 => "STATUS_PORT_DISCONNECTED: Port disconnected",
            0xC0000039 => "STATUS_OBJECT_PATH_INVALID: Object path invalid",
            0xC000003A => "STATUS_OBJECT_PATH_NOT_FOUND: Object path not found",
            0xC000003C => "STATUS_DATA_OVERRUN: Data overrun",
            0xC000003D => "STATUS_DATA_LATE_ERROR: Data late error",
            0xC000003E => "STATUS_DATA_ERROR: Data error",
            0xC000003F => "STATUS_CRC_ERROR: CRC error",
            0xC0000040 => "STATUS_SECTION_TOO_BIG: Section too big",
            0xC0000041 => "STATUS_PORT_CONNECTION_REFUSED: Port connection refused",
            0xC0000042 => "STATUS_INVALID_PORT_HANDLE: Invalid port handle",
            0xC0000043 => "STATUS_SHARING_VIOLATION: Sharing violation",
            0xC0000044 => "STATUS_QUOTA_EXCEEDED: Quota exceeded",
            0xC0000045 => "STATUS_INVALID_PAGE_PROTECTION: Invalid page protection",
            0xC0000046 => "STATUS_MUTANT_NOT_OWNED: Mutant not owned",
            0xC0000047 => "STATUS_SEMAPHORE_LIMIT_EXCEEDED: Semaphore limit exceeded",
            0xC0000048 => "STATUS_PORT_ALREADY_SET: Port already set",
            0xC000004F => "STATUS_EAS_NOT_SUPPORTED: EAS not supported",
            0xC0000050 => "STATUS_EA_TOO_LARGE: EA too large",
            0xC0000056 => "STATUS_DELETE_PENDING: Delete pending",
            0xC000005F => "STATUS_NO_SUCH_LOGON_SESSION: No such logon session",
            0xC0000060 => "STATUS_NO_SUCH_PRIVILEGE: No such privilege",
            0xC0000061 => "STATUS_PRIVILEGE_NOT_HELD: Privilege not held",
            0xC000007C => "STATUS_NO_TOKEN: No token",
            0xC000007D => "STATUS_BAD_INHERITANCE_ACL: Bad inheritance ACL",
            0xC000007E => "STATUS_RANGE_NOT_LOCKED: Range not locked",
            0xC000007F => "STATUS_DISK_FULL: Disk full",
            0xC0000080 => "STATUS_SERVER_DISABLED: Server disabled",
            0xC00000A2 => "STATUS_MEDIA_WRITE_PROTECTED: Media write protected",
            0xC00000A6 => "STATUS_CANT_OPEN_ANONYMOUS: Cannot open anonymous",
            0xC00000AC => "STATUS_PIPE_NOT_AVAILABLE: Pipe not available",
            0xC00000AD => "STATUS_INVALID_PIPE_STATE: Invalid pipe state",
            0xC00000AE => "STATUS_PIPE_BUSY: Pipe busy",
            0xC00000B0 => "STATUS_PIPE_DISCONNECTED: Pipe disconnected",
            0xC00000BB => "STATUS_NOT_SUPPORTED: The request is not supported",
            0xC00000E6 => "STATUS_GENERIC_NOT_MAPPED: Generic not mapped",
            0xC00000EF => "STATUS_INVALID_PARAMETER_1: Invalid parameter 1",
            0xC00000FD => "STATUS_STACK_OVERFLOW: Stack overflow",
            0xC0000102 => "STATUS_FILE_CORRUPT_ERROR: File corrupt error",
            0xC0000103 => "STATUS_NOT_A_DIRECTORY: Not a directory",
            0xC0000104 => "STATUS_BAD_LOGON_SESSION_STATE: Bad logon session state",
            0xC0000105 => "STATUS_LOGON_SESSION_COLLISION: Logon session collision",
            0xC0000106 => "STATUS_NAME_TOO_LONG: Name too long",
            0xC0000107 => "STATUS_FILES_OPEN: Files open",
            0xC0000108 => "STATUS_CONNECTION_IN_USE: Connection in use",
            0xC0000109 => "STATUS_MESSAGE_NOT_FOUND: Message not found",
            0xC000010A => "STATUS_PROCESS_IS_TERMINATING: Process is terminating",
            0xC000010D => "STATUS_CANNOT_IMPERSONATE: Cannot impersonate",
            0xC0000121 => "STATUS_CANNOT_DELETE: Cannot delete",
            0xC0000128 => "STATUS_FILE_CLOSED: File closed",
            0xC0000142 => "STATUS_DLL_INIT_FAILED: DLL initialization failed",
            0xC0000161 => "STATUS_ILLEGAL_CHARACTER: Illegal character",
            0xC0000162 => "STATUS_UNMAPPABLE_CHARACTER: Unmappable character",
            0xC0000184 => "STATUS_INVALID_DEVICE_STATE: Invalid device state",
            0xC0000201 => "STATUS_NETWORK_OPEN_RESTRICTION: Network open restriction",
            0xC0000202 => "STATUS_NO_USER_SESSION_KEY: No user session key",
            0xC000022D => "STATUS_RETRY: The operation should be retried",
            0xC00002DF => "STATUS_SAM_NEED_BOOTKEY_PASSWORD: SAM needs boot key password",
            0xC00002E0 => "STATUS_SAM_NEED_BOOTKEY_FLOPPY: SAM needs boot key floppy",
            0xC0000282 => "STATUS_RANGE_LIST_CONFLICT: Range list conflict",
            0xC0000283 => "STATUS_SOURCE_ELEMENT_EMPTY: Source element empty",
            0xC0000284 => "STATUS_DESTINATION_ELEMENT_FULL: Destination element full",
            0xC0000285 => "STATUS_ILLEGAL_ELEMENT_ADDRESS: Illegal element address",
            0xC0000286 => "STATUS_MAGAZINE_NOT_PRESENT: Magazine not present",
            0xC0000287 => "STATUS_REINITIALIZATION_NEEDED: Reinitialization needed",
            _ => "STATUS_UNKNOWN: Unknown status code",
        }
    }

    /// STATUS_SUCCESS
    pub const SUCCESS: Self = Self::from_raw(0x00000000);

    /// STATUS_WAIT_1
    pub const WAIT_1: Self = Self::from_raw(0x00000001);

    /// STATUS_WAIT_2
    pub const WAIT_2: Self = Self::from_raw(0x00000002);

    /// STATUS_WAIT_3
    pub const WAIT_3: Self = Self::from_raw(0x00000003);

    /// STATUS_TIMEOUT
    pub const TIMEOUT: Self = Self::from_raw(0x00000102);

    /// DBG_EXCEPTION_HANDLED
    pub const EXCEPTION_HANDLED: Self = Self::from_raw(0x00010001);

    /// DBG_CONTINUE
    pub const CONTINUE: Self = Self::from_raw(0x00010002);

    /// STATUS_OBJECT_NAME_EXISTS
    pub const OBJECT_NAME_EXISTS: Self = Self::from_raw(0x40000000);

    /// STATUS_GUARD_PAGE_VIOLATION
    pub const GUARD_PAGE_VIOLATION: Self = Self::from_raw(0x80000001);

    /// STATUS_DATATYPE_MISALIGNMENT
    pub const DATATYPE_MISALIGNMENT: Self = Self::from_raw(0x80000002);

    /// STATUS_BREAKPOINT
    pub const BREAKPOINT: Self = Self::from_raw(0x80000003);

    /// STATUS_SINGLE_STEP
    pub const SINGLE_STEP: Self = Self::from_raw(0x80000004);

    /// STATUS_BUFFER_OVERFLOW
    pub const BUFFER_OVERFLOW: Self = Self::from_raw(0x80000005);

    /// STATUS_UNSUCCESSFUL
    pub const UNSUCCESSFUL: Self = Self::from_raw(0xC0000001);

    /// STATUS_NOT_IMPLEMENTED
    pub const NOT_IMPLEMENTED: Self = Self::from_raw(0xC0000002);

    /// STATUS_INVALID_INFO_CLASS
    pub const INVALID_INFO_CLASS: Self = Self::from_raw(0xC0000003);

    /// STATUS_INFO_LENGTH_MISMATCH
    pub const INFO_LENGTH_MISMATCH: Self = Self::from_raw(0xC0000004);

    /// STATUS_ACCESS_VIOLATION
    pub const ACCESS_VIOLATION: Self = Self::from_raw(0xC0000005);

    /// STATUS_IN_PAGE_ERROR
    pub const IN_PAGE_ERROR: Self = Self::from_raw(0xC0000006);

    /// STATUS_PAGEFILE_QUOTA
    pub const PAGEFILE_QUOTA: Self = Self::from_raw(0xC0000007);

    /// STATUS_INVALID_HANDLE
    pub const INVALID_HANDLE: Self = Self::from_raw(0xC0000008);

    /// STATUS_BAD_INITIAL_STACK
    pub const BAD_INITIAL_STACK: Self = Self::from_raw(0xC0000009);

    /// STATUS_BAD_INITIAL_PC
    pub const BAD_INITIAL_PC: Self = Self::from_raw(0xC000000A);

    /// STATUS_INVALID_CID
    pub const INVALID_CID: Self = Self::from_raw(0xC000000B);

    /// STATUS_TIMER_NOT_CANCELED
    pub const TIMER_NOT_CANCELED: Self = Self::from_raw(0xC000000C);

    /// STATUS_INVALID_PARAMETER
    pub const INVALID_PARAMETER: Self = Self::from_raw(0xC000000D);

    /// STATUS_NO_SUCH_DEVICE
    pub const NO_SUCH_DEVICE: Self = Self::from_raw(0xC000000E);

    /// STATUS_NO_SUCH_FILE
    pub const NO_SUCH_FILE: Self = Self::from_raw(0xC000000F);

    /// STATUS_INVALID_DEVICE_REQUEST
    pub const INVALID_DEVICE_REQUEST: Self = Self::from_raw(0xC0000010);

    /// STATUS_END_OF_FILE
    pub const END_OF_FILE: Self = Self::from_raw(0xC0000011);

    /// STATUS_WRONG_VOLUME
    pub const WRONG_VOLUME: Self = Self::from_raw(0xC0000012);

    /// STATUS_NO_MEDIA_IN_DEVICE
    pub const NO_MEDIA_IN_DEVICE: Self = Self::from_raw(0xC0000013);

    /// STATUS_UNRECOGNIZED_MEDIA
    pub const UNRECOGNIZED_MEDIA: Self = Self::from_raw(0xC0000014);

    /// STATUS_MORE_PROCESSING_REQUIRED
    pub const MORE_PROCESSING_REQUIRED: Self = Self::from_raw(0xC0000016);

    /// STATUS_NO_MEMORY
    pub const NO_MEMORY: Self = Self::from_raw(0xC0000017);

    /// STATUS_NOT_MAPPED_VIEW
    pub const NOT_MAPPED_VIEW: Self = Self::from_raw(0xC0000019);

    /// STATUS_UNABLE_TO_FREE_VM
    pub const UNABLE_TO_FREE_VM: Self = Self::from_raw(0xC000001A);

    /// STATUS_UNABLE_TO_DELETE_SECTION
    pub const UNABLE_TO_DELETE_SECTION: Self = Self::from_raw(0xC000001B);

    /// STATUS_INVALID_SYSTEM_SERVICE
    pub const INVALID_SYSTEM_SERVICE: Self = Self::from_raw(0xC000001C);

    /// STATUS_ILLEGAL_INSTRUCTION
    pub const ILLEGAL_INSTRUCTION: Self = Self::from_raw(0xC000001D);

    /// STATUS_INVALID_LOCK_SEQUENCE
    pub const INVALID_LOCK_SEQUENCE: Self = Self::from_raw(0xC000001E);

    /// STATUS_INVALID_VIEW_SIZE
    pub const INVALID_VIEW_SIZE: Self = Self::from_raw(0xC000001F);

    /// STATUS_INVALID_FILE_FOR_SECTION
    pub const INVALID_FILE_FOR_SECTION: Self = Self::from_raw(0xC0000020);

    /// STATUS_ALREADY_COMMITTED
    pub const ALREADY_COMMITTED: Self = Self::from_raw(0xC0000021);

    /// STATUS_ACCESS_DENIED
    pub const ACCESS_DENIED: Self = Self::from_raw(0xC0000022);

    /// STATUS_BUFFER_TOO_SMALL
    pub const BUFFER_TOO_SMALL: Self = Self::from_raw(0xC0000023);

    /// STATUS_OBJECT_TYPE_MISMATCH
    pub const OBJECT_TYPE_MISMATCH: Self = Self::from_raw(0xC0000024);

    /// STATUS_NONCONTINUABLE_EXCEPTION
    pub const NONCONTINUABLE_EXCEPTION: Self = Self::from_raw(0xC0000025);

    /// STATUS_INVALID_DISPOSITION
    pub const INVALID_DISPOSITION: Self = Self::from_raw(0xC0000026);

    /// STATUS_UNWIND
    pub const UNWIND: Self = Self::from_raw(0xC0000027);

    /// STATUS_BAD_STACK
    pub const BAD_STACK: Self = Self::from_raw(0xC0000028);

    /// STATUS_INVALID_UNWIND_TARGET
    pub const INVALID_UNWIND_TARGET: Self = Self::from_raw(0xC0000029);

    /// STATUS_NOT_COMMITTED
    pub const NOT_COMMITTED: Self = Self::from_raw(0xC000002D);

    /// STATUS_OBJECT_NAME_INVALID
    pub const OBJECT_NAME_INVALID: Self = Self::from_raw(0xC0000033);

    /// STATUS_OBJECT_NAME_NOT_FOUND
    pub const OBJECT_NAME_NOT_FOUND: Self = Self::from_raw(0xC0000034);

    /// STATUS_OBJECT_NAME_COLLISION
    pub const OBJECT_NAME_COLLISION: Self = Self::from_raw(0xC0000035);

    /// STATUS_PORT_DISCONNECTED
    pub const PORT_DISCONNECTED: Self = Self::from_raw(0xC0000037);

    /// STATUS_OBJECT_PATH_INVALID
    pub const OBJECT_PATH_INVALID: Self = Self::from_raw(0xC0000039);

    /// STATUS_OBJECT_PATH_NOT_FOUND
    pub const OBJECT_PATH_NOT_FOUND: Self = Self::from_raw(0xC000003A);

    /// STATUS_DATA_OVERRUN
    pub const DATA_OVERRUN: Self = Self::from_raw(0xC000003C);

    /// STATUS_DATA_LATE_ERROR
    pub const DATA_LATE_ERROR: Self = Self::from_raw(0xC000003D);

    /// STATUS_DATA_ERROR
    pub const DATA_ERROR: Self = Self::from_raw(0xC000003E);

    /// STATUS_CRC_ERROR
    pub const CRC_ERROR: Self = Self::from_raw(0xC000003F);

    /// STATUS_SECTION_TOO_BIG
    pub const SECTION_TOO_BIG: Self = Self::from_raw(0xC0000040);

    /// STATUS_PORT_CONNECTION_REFUSED
    pub const PORT_CONNECTION_REFUSED: Self = Self::from_raw(0xC0000041);

    /// STATUS_INVALID_PORT_HANDLE
    pub const INVALID_PORT_HANDLE: Self = Self::from_raw(0xC0000042);

    /// STATUS_SHARING_VIOLATION
    pub const SHARING_VIOLATION: Self = Self::from_raw(0xC0000043);

    /// STATUS_QUOTA_EXCEEDED
    pub const QUOTA_EXCEEDED: Self = Self::from_raw(0xC0000044);

    /// STATUS_INVALID_PAGE_PROTECTION
    pub const INVALID_PAGE_PROTECTION: Self = Self::from_raw(0xC0000045);

    /// STATUS_MUTANT_NOT_OWNED
    pub const MUTANT_NOT_OWNED: Self = Self::from_raw(0xC0000046);

    /// STATUS_SEMAPHORE_LIMIT_EXCEEDED
    pub const SEMAPHORE_LIMIT_EXCEEDED: Self = Self::from_raw(0xC0000047);

    /// STATUS_PORT_ALREADY_SET
    pub const PORT_ALREADY_SET: Self = Self::from_raw(0xC0000048);

    /// STATUS_EAS_NOT_SUPPORTED
    pub const EAS_NOT_SUPPORTED: Self = Self::from_raw(0xC000004F);

    /// STATUS_EA_TOO_LARGE
    pub const EA_TOO_LARGE: Self = Self::from_raw(0xC0000050);

    /// STATUS_DELETE_PENDING
    pub const DELETE_PENDING: Self = Self::from_raw(0xC0000056);

    /// STATUS_NO_SUCH_LOGON_SESSION
    pub const NO_SUCH_LOGON_SESSION: Self = Self::from_raw(0xC000005F);

    /// STATUS_NO_SUCH_PRIVILEGE
    pub const NO_SUCH_PRIVILEGE: Self = Self::from_raw(0xC0000060);

    /// STATUS_PRIVILEGE_NOT_HELD
    pub const PRIVILEGE_NOT_HELD: Self = Self::from_raw(0xC0000061);

    /// STATUS_NO_TOKEN
    pub const NO_TOKEN: Self = Self::from_raw(0xC000007C);

    /// STATUS_BAD_INHERITANCE_ACL
    pub const BAD_INHERITANCE_ACL: Self = Self::from_raw(0xC000007D);

    /// STATUS_RANGE_NOT_LOCKED
    pub const RANGE_NOT_LOCKED: Self = Self::from_raw(0xC000007E);

    /// STATUS_DISK_FULL
    pub const DISK_FULL: Self = Self::from_raw(0xC000007F);

    /// STATUS_SERVER_DISABLED
    pub const SERVER_DISABLED: Self = Self::from_raw(0xC0000080);

    /// STATUS_MEDIA_WRITE_PROTECTED
    pub const MEDIA_WRITE_PROTECTED: Self = Self::from_raw(0xC00000A2);

    /// STATUS_CANT_OPEN_ANONYMOUS
    pub const CANT_OPEN_ANONYMOUS: Self = Self::from_raw(0xC00000A6);

    /// STATUS_PIPE_NOT_AVAILABLE
    pub const PIPE_NOT_AVAILABLE: Self = Self::from_raw(0xC00000AC);

    /// STATUS_INVALID_PIPE_STATE
    pub const INVALID_PIPE_STATE: Self = Self::from_raw(0xC00000AD);

    /// STATUS_PIPE_BUSY
    pub const PIPE_BUSY: Self = Self::from_raw(0xC00000AE);

    /// STATUS_PIPE_DISCONNECTED
    pub const PIPE_DISCONNECTED: Self = Self::from_raw(0xC00000B0);

    /// STATUS_NOT_SUPPORTED
    pub const NOT_SUPPORTED: Self = Self::from_raw(0xC00000BB);

    /// STATUS_GENERIC_NOT_MAPPED
    pub const GENERIC_NOT_MAPPED: Self = Self::from_raw(0xC00000E6);

    /// STATUS_INVALID_PARAMETER_1
    pub const INVALID_PARAMETER_1: Self = Self::from_raw(0xC00000EF);

    /// STATUS_STACK_OVERFLOW
    pub const STACK_OVERFLOW: Self = Self::from_raw(0xC00000FD);

    /// STATUS_FILE_CORRUPT_ERROR
    pub const FILE_CORRUPT_ERROR: Self = Self::from_raw(0xC0000102);

    /// STATUS_NOT_A_DIRECTORY
    pub const NOT_A_DIRECTORY: Self = Self::from_raw(0xC0000103);

    /// STATUS_BAD_LOGON_SESSION_STATE
    pub const BAD_LOGON_SESSION_STATE: Self = Self::from_raw(0xC0000104);

    /// STATUS_LOGON_SESSION_COLLISION
    pub const LOGON_SESSION_COLLISION: Self = Self::from_raw(0xC0000105);

    /// STATUS_NAME_TOO_LONG
    pub const NAME_TOO_LONG: Self = Self::from_raw(0xC0000106);

    /// STATUS_FILES_OPEN
    pub const FILES_OPEN: Self = Self::from_raw(0xC0000107);

    /// STATUS_CONNECTION_IN_USE
    pub const CONNECTION_IN_USE: Self = Self::from_raw(0xC0000108);

    /// STATUS_MESSAGE_NOT_FOUND
    pub const MESSAGE_NOT_FOUND: Self = Self::from_raw(0xC0000109);

    /// STATUS_PROCESS_IS_TERMINATING
    pub const PROCESS_IS_TERMINATING: Self = Self::from_raw(0xC000010A);

    /// STATUS_CANNOT_IMPERSONATE
    pub const CANNOT_IMPERSONATE: Self = Self::from_raw(0xC000010D);

    /// STATUS_CANNOT_DELETE
    pub const CANNOT_DELETE: Self = Self::from_raw(0xC0000121);

    /// STATUS_FILE_CLOSED
    pub const FILE_CLOSED: Self = Self::from_raw(0xC0000128);

    /// STATUS_DLL_INIT_FAILED
    pub const DLL_INIT_FAILED: Self = Self::from_raw(0xC0000142);

    /// STATUS_ILLEGAL_CHARACTER
    pub const ILLEGAL_CHARACTER: Self = Self::from_raw(0xC0000161);

    /// STATUS_UNMAPPABLE_CHARACTER
    pub const UNMAPPABLE_CHARACTER: Self = Self::from_raw(0xC0000162);

    /// STATUS_INVALID_DEVICE_STATE
    pub const INVALID_DEVICE_STATE: Self = Self::from_raw(0xC0000184);

    /// STATUS_NETWORK_OPEN_RESTRICTION
    pub const NETWORK_OPEN_RESTRICTION: Self = Self::from_raw(0xC0000201);

    /// STATUS_NO_USER_SESSION_KEY
    pub const NO_USER_SESSION_KEY: Self = Self::from_raw(0xC0000202);

    /// STATUS_RETRY
    pub const RETRY: Self = Self::from_raw(0xC000022D);

    /// STATUS_SAM_NEED_BOOTKEY_PASSWORD
    pub const SAM_NEED_BOOTKEY_PASSWORD: Self = Self::from_raw(0xC00002DF);

    /// STATUS_SAM_NEED_BOOTKEY_FLOPPY
    pub const SAM_NEED_BOOTKEY_FLOPPY: Self = Self::from_raw(0xC00002E0);

    /// STATUS_RANGE_LIST_CONFLICT
    pub const RANGE_LIST_CONFLICT: Self = Self::from_raw(0xC0000282);

    /// STATUS_SOURCE_ELEMENT_EMPTY
    pub const SOURCE_ELEMENT_EMPTY: Self = Self::from_raw(0xC0000283);

    /// STATUS_DESTINATION_ELEMENT_FULL
    pub const DESTINATION_ELEMENT_FULL: Self = Self::from_raw(0xC0000284);

    /// STATUS_ILLEGAL_ELEMENT_ADDRESS
    pub const ILLEGAL_ELEMENT_ADDRESS: Self = Self::from_raw(0xC0000285);

    /// STATUS_MAGAZINE_NOT_PRESENT
    pub const MAGAZINE_NOT_PRESENT: Self = Self::from_raw(0xC0000286);

    /// STATUS_REINITIALIZATION_NEEDED
    pub const REINITIALIZATION_NEEDED: Self = Self::from_raw(0xC0000287);
}

impl From<i32> for NtStatus {
    fn from(value: i32) -> Self {
        Self { value }
    }
}

impl From<u32> for NtStatus {
    fn from(value: u32) -> Self {
        Self::from_raw(value)
    }
}

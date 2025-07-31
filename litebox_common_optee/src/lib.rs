//! Common elements to enable OP-TEE-like functionalities

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use litebox::platform::RawConstPointer as _;
use litebox_common_linux::{PtRegs, errno::Errno};
use num_enum::TryFromPrimitive;
use syscall_nr::TeeSyscallNr;

pub mod syscall_nr;

// Based on `optee_os/lib/libutee/include/utee_syscalls.h`
#[non_exhaustive]
pub enum SyscallRequest<Platform: litebox::platform::RawPointerProvider> {
    Return {
        ret: usize,
    },
    Log {
        buf: Platform::RawConstPointer<u8>,
        len: usize,
    },
    Panic {
        code: usize,
    },
    CrypStateAlloc {
        algo: TeeAlgorithm,
        op_mode: TeeOperationMode,
        key1: TeeObjHandle,
        key2: TeeObjHandle,
        state: Platform::RawMutPointer<TeeCrypStateHandle>,
    },
    CrypStateFree {
        state: TeeCrypStateHandle,
    },
    CipherInit {
        state: TeeCrypStateHandle,
        iv: Platform::RawConstPointer<u8>,
        iv_len: usize,
    },
    CipherUpdate {
        state: TeeCrypStateHandle,
        src: Platform::RawConstPointer<u8>,
        src_len: usize,
        dst: Platform::RawMutPointer<u8>,
        dst_len: Platform::RawMutPointer<u64>,
    },
    CrypObjGetInfo {
        obj: TeeObjHandle,
        info: Platform::RawMutPointer<TeeObjectInfo>,
    },
    CrypObjAlloc {
        typ: TeeObjectType,
        max_size: usize,
        obj: Platform::RawMutPointer<TeeObjHandle>,
    },
    CrypObjClose {
        obj: TeeObjHandle,
    },
    CrypObjReset {
        obj: TeeObjHandle,
    },
    CrypObjPopulate {
        obj: TeeObjHandle,
        attrs: Platform::RawMutPointer<UteeAttribute>,
        attr_count: usize,
    },
    CrypObjCopy {
        dst_obj: TeeObjHandle,
        src_obj: TeeObjHandle,
    },
    CrypRandomNumberGenerate {
        buf: Platform::RawMutPointer<u8>,
        blen: usize,
    },
}

// `litebox_common_optee` does use error codes for OP-TEE-like world (TAs) and Linux-like world (the LVBS platform).
// for the below syscall handling, we use Linux error codes (i.e., `Errno`) because any errors will be returned
// to the LVBS platform or runner.

impl<Platform: litebox::platform::RawPointerProvider> SyscallRequest<Platform> {
    pub fn try_from_raw(syscall_number: usize, ctx: &SyscallContext) -> Result<Self, Errno> {
        let sysnr = u32::try_from(syscall_number).map_err(|_| Errno::ENOSYS)?;
        let dispatcher = match TeeSyscallNr::try_from(sysnr).unwrap_or(TeeSyscallNr::Unknown) {
            TeeSyscallNr::Return => SyscallRequest::Return {
                ret: ctx.syscall_arg(0),
            },
            TeeSyscallNr::Log => SyscallRequest::Log {
                buf: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                len: ctx.syscall_arg(1),
            },
            TeeSyscallNr::Panic => SyscallRequest::Panic {
                code: ctx.syscall_arg(0),
            },
            TeeSyscallNr::CrypStateAlloc => SyscallRequest::CrypStateAlloc {
                algo: TeeAlgorithm::try_from_usize(ctx.syscall_arg(0))?,
                op_mode: TeeOperationMode::try_from_usize(ctx.syscall_arg(1))?,
                key1: TeeObjHandle::try_from_usize(ctx.syscall_arg(2))?,
                key2: TeeObjHandle::try_from_usize(ctx.syscall_arg(3))?,
                state: Platform::RawMutPointer::from_usize(ctx.syscall_arg(4)),
            },
            TeeSyscallNr::CrypStateFree => SyscallRequest::CrypStateFree {
                state: TeeCrypStateHandle::try_from_usize(ctx.syscall_arg(0))?,
            },
            TeeSyscallNr::CipherInit => SyscallRequest::CipherInit {
                state: TeeCrypStateHandle::try_from_usize(ctx.syscall_arg(0))?,
                iv: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                iv_len: ctx.syscall_arg(2),
            },
            TeeSyscallNr::CipherUpdate => SyscallRequest::CipherUpdate {
                state: TeeCrypStateHandle::try_from_usize(ctx.syscall_arg(0))?,
                src: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                src_len: ctx.syscall_arg(2),
                dst: Platform::RawMutPointer::from_usize(ctx.syscall_arg(3)),
                dst_len: Platform::RawMutPointer::from_usize(ctx.syscall_arg(4)),
            },
            TeeSyscallNr::CrypObjGetInfo => SyscallRequest::CrypObjGetInfo {
                obj: TeeObjHandle::try_from_usize(ctx.syscall_arg(0))?,
                info: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
            },
            TeeSyscallNr::CrypObjAlloc => SyscallRequest::CrypObjAlloc {
                typ: TeeObjectType::try_from_usize(ctx.syscall_arg(0))?,
                max_size: ctx.syscall_arg(1),
                obj: Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)),
            },
            TeeSyscallNr::CrypObjClose => SyscallRequest::CrypObjClose {
                obj: TeeObjHandle::try_from_usize(ctx.syscall_arg(0))?,
            },
            TeeSyscallNr::CrypObjReset => SyscallRequest::CrypObjReset {
                obj: TeeObjHandle::try_from_usize(ctx.syscall_arg(0))?,
            },
            TeeSyscallNr::CrypObjPopulate => SyscallRequest::CrypObjPopulate {
                obj: TeeObjHandle::try_from_usize(ctx.syscall_arg(0))?,
                attrs: Platform::RawMutPointer::from_usize(ctx.syscall_arg(1)),
                attr_count: ctx.syscall_arg(2),
            },
            TeeSyscallNr::CrypObjCopy => SyscallRequest::CrypObjCopy {
                dst_obj: TeeObjHandle::try_from_usize(ctx.syscall_arg(0))?,
                src_obj: TeeObjHandle::try_from_usize(ctx.syscall_arg(1))?,
            },
            TeeSyscallNr::CrypRandomNumberGenerate => SyscallRequest::CrypRandomNumberGenerate {
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                blen: ctx.syscall_arg(1),
            },
            TeeSyscallNr::Unknown => {
                return Err(Errno::ENOSYS);
            }
            _ => todo!(),
        };

        Ok(dispatcher)
    }
}

/// A data structure for containing syscall arguments.
#[derive(Clone, Copy)]
pub struct SyscallContext {
    args: [usize; MAX_SYSCALL_ARGS],
}
const MAX_SYSCALL_ARGS: usize = 8;

impl SyscallContext {
    /// # Panics
    /// Panics if the index is out of bounds (greater than 7).
    pub fn syscall_arg(&self, index: usize) -> usize {
        if index >= MAX_SYSCALL_ARGS {
            panic!("BUG: Invalid syscall argument index: {}", index);
        } else {
            self.args[index]
        }
    }

    pub fn new(args: &[usize; MAX_SYSCALL_ARGS]) -> Self {
        SyscallContext { args: *args }
    }

    /// Create OP-TEE TA's `SyscallContext` from `PtRegs`.
    pub fn from_pt_regs(pt_regs: &PtRegs) -> Self {
        SyscallContext {
            args: [
                pt_regs.rdi,
                pt_regs.rsi,
                pt_regs.rdx,
                pt_regs.r10,
                pt_regs.r8,
                pt_regs.r9,
                pt_regs.r12,
                pt_regs.r13,
            ],
        }
    }
}

/// A handle for `TeeObj`. OP-TEE kernel creates secret objects (e.g., via `CrypObjAlloc`)
/// and provides handles for them to TAs in the user space. This lets them refer to
/// the objects in subsequent syscalls.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TeeObjHandle(pub u32);

impl TeeObjHandle {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .map(TeeObjHandle)
    }
}

/// A handle for `TeeCrypState`. Like `TeeObjHandle`, this is a handle for
/// the cryptographic state (e.g., created through `CrypStateAlloc`) to be provided to
/// a TA in the user space.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TeeCrypStateHandle(pub u32);

impl TeeCrypStateHandle {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .map(TeeCrypStateHandle)
    }
}

/// TA session ID which is largely equivalent to a process ID. Here, a session is
/// established between a TA and a client process in the VTL0 user space.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TaSessionId(pub u32);

impl TaSessionId {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .map(TaSessionId)
    }
}

/// Command ID to be passed to a TA. Each TA can provide an arbitrary number of commands.
/// Clients in the VTL0 user space should be aware of the provided commands in advance
/// (e.g., through header files).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CommandId(pub u32);

impl CommandId {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .map(CommandId)
    }
}

/// `utee_params` from `optee_os/lib/libutee/include/utee_types.h`
/// It contains up to 4 parameters where each of them is a collection of
/// type (1 byte) and two 8-byte data (values or addresses).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct UteeParams {
    pub types: u64,
    pub vals: [u64; TEE_NUM_PARAMS * 2],
}
const TEE_NUM_PARAMS: usize = 4;

const TEE_PARAM_TYPE_NONE: u8 = 0;
const TEE_PARAM_TYPE_VALUE_INPUT: u8 = 1;
const TEE_PARAM_TYPE_VALUE_OUTPUT: u8 = 2;
const TEE_PARAM_TYPE_VALUE_INOUT: u8 = 3;
const TEE_PARAM_TYPE_MEMREF_INPUT: u8 = 4;
const TEE_PARAM_TYPE_MEMREF_OUTPUT: u8 = 5;
const TEE_PARAM_TYPE_MEMREF_INOUT: u8 = 6;

#[derive(Clone, Copy, TryFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum TeeParamType {
    None = TEE_PARAM_TYPE_NONE,
    ValueInput = TEE_PARAM_TYPE_VALUE_INPUT,
    ValueOutput = TEE_PARAM_TYPE_VALUE_OUTPUT,
    ValueInout = TEE_PARAM_TYPE_VALUE_INOUT,
    MemrefInput = TEE_PARAM_TYPE_MEMREF_INPUT,
    MemrefOutput = TEE_PARAM_TYPE_MEMREF_OUTPUT,
    MemrefInout = TEE_PARAM_TYPE_MEMREF_INOUT,
}

impl UteeParams {
    pub fn get_type(&self, index: usize) -> Result<TeeParamType, Errno> {
        if index >= TEE_NUM_PARAMS {
            return Err(Errno::EINVAL);
        }
        let type_byte = self.types.to_le_bytes()[index];
        TeeParamType::try_from(type_byte).map_err(|_| Errno::EINVAL)
    }

    pub fn get_values(&self, index: usize) -> Result<Option<(u64, u64)>, Errno> {
        if index >= TEE_NUM_PARAMS {
            return Err(Errno::EINVAL);
        }
        let type_byte = self.types.to_le_bytes()[index];
        if TeeParamType::try_from(type_byte).map_err(|_| Errno::EINVAL)? == TeeParamType::None {
            Ok(None)
        } else {
            let base_index = index * 2;
            Ok(Some((self.vals[base_index], self.vals[base_index + 1])))
        }
    }

    pub fn set_type(&mut self, index: usize, param_type: TeeParamType) -> Result<(), Errno> {
        if index >= TEE_NUM_PARAMS {
            return Err(Errno::EINVAL);
        }
        let mut types_bytes = self.types.to_le_bytes();
        types_bytes[index] = param_type as u8;
        self.types = u64::from_le_bytes(types_bytes);
        Ok(())
    }

    pub fn set_values(&mut self, index: usize, value1: u64, value2: u64) -> Result<(), Errno> {
        if index >= TEE_NUM_PARAMS {
            return Err(Errno::EINVAL);
        }
        let base_index = index * 2;
        self.vals[base_index] = value1;
        self.vals[base_index + 1] = value2;
        Ok(())
    }

    pub fn new() -> Self {
        Self::default()
    }
}

/// `utee_attribute` from `optee_os/lib/libutee/include/utee_types.h`
#[derive(Clone, Copy)]
#[repr(C)]
pub struct UteeAttribute {
    pub a: u64,
    pub b: u64,
    pub attribute_id: u32,
}

/// `TEE_UUID` from `optee_os/lib/libutee/include/tee_api_types.h`. It uniquely identifies
/// TAs, cryptographic keys, and more.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TeeUuid {
    time_low: u32,
    time_mid: u16,
    time_hi_and_version: u16,
    clock_seq_and_node: [u8; 8],
}

/// `TEE_ObjectInfo` from `optee_os/lib/libutee/include/tee_api_types.h`
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TeeObjectInfo {
    pub object_type: u32,
    pub object_size: u32,
    pub max_object_size: u32,
    pub object_usage: u32,
    pub data_size: u32,
    pub data_position: u32,
    pub handle_flags: u32,
}

const TEE_MODE_ENCRYPT: u32 = 0;
const TEE_MODE_DECRYPT: u32 = 1;
const TEE_MODE_SIGN: u32 = 2;
const TEE_MODE_VERIFY: u32 = 3;
const TEE_MODE_MAC: u32 = 4;
const TEE_MODE_DIGEST: u32 = 5;
const TEE_MODE_DERIVE: u32 = 6;

/// `TEE_OperationMode` from `optee_os/lib/libutee/include/tee_api_types.h`
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum TeeOperationMode {
    Encrypt = TEE_MODE_ENCRYPT,
    Decrypt = TEE_MODE_DECRYPT,
    Sign = TEE_MODE_SIGN,
    Verify = TEE_MODE_VERIFY,
    Mac = TEE_MODE_MAC,
    Digest = TEE_MODE_DIGEST,
    Derive = TEE_MODE_DERIVE,
}

impl TeeOperationMode {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .and_then(|v| Self::try_from(v).map_err(|_| Errno::EINVAL))
    }
}

const TEE_ORIGIN_API: u32 = 0;
const TEE_ORIGIN_COMMS: u32 = 1;
const TEE_ORIGIN_TEE: u32 = 2;
const TEE_ORIGIN_TRUTED_APP: u32 = 3;

/// Origin code constants from `optee_os/lib/libutee/include/tee_api_defines.h`
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum TeeOrigin {
    Api = TEE_ORIGIN_API,
    Comms = TEE_ORIGIN_COMMS,
    Tee = TEE_ORIGIN_TEE,
    TrustedApp = TEE_ORIGIN_TRUTED_APP,
}

impl TeeOrigin {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .and_then(|v| Self::try_from(v).map_err(|_| Errno::EINVAL))
    }
}

bitflags::bitflags! {
    /// Memory access rights constants from `optee_os/lib/libutee/include/tee_api_defines.h`
    #[derive(Clone, Copy)]
    pub struct TeeMemoryAccessRights: u32 {
        const TEE_MEMORY_ACCESS_READ = 0x1;
        const TEE_MEMORY_ACCESS_WRITE = 0x2;
        const TEE_MEMORY_ACCESS_ANY_OWNER = 0x4;

        const _ = !0;
    }
}

const TEE_ALG_AES_CTR: u32 = 0x1000_0210;
const TEE_ALG_AES_GCM: u32 = 0x4000_0810;
const TEE_ALG_RSASSA_PKCS1_V1_5_SHA256: u32 = 0x7000_4830;
const TEE_ALG_RSASSA_PKCS1_V1_5_SHA512: u32 = 0x7000_6830;
const TEE_ALG_HMAC_SHA256: u32 = 0x3000_0004;
const TEE_ALG_HMAC_SHA512: u32 = 0x3000_0006;
const TEE_ALG_ILLEGAL_VALUE: u32 = 0xefff_ffff;

/// Algorithm identifiers from `optee_os/lib/libutee/include/tee_api_defines.h`
/// TODO: add more algorithms as needed. IMO we should not provide weak algorithms like
/// DES and MD5. Also, KMPP doesn't use this crypto API (it uses its own SymCrypt).
#[non_exhaustive]
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum TeeAlgorithm {
    AesCtr = TEE_ALG_AES_CTR,
    AesGcm = TEE_ALG_AES_GCM,
    RsaPkcs1Sha256 = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
    RsaPkcs1Sha512 = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512,
    HmacSha256 = TEE_ALG_HMAC_SHA256,
    HmacSha512 = TEE_ALG_HMAC_SHA512,
    IllegalValue = TEE_ALG_ILLEGAL_VALUE,
}

impl TeeAlgorithm {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .and_then(|v| Self::try_from(v).map_err(|_| Errno::EINVAL))
    }
}

const TEE_TYPE_AES: u32 = 0xa000_0010;
const TEE_TYPE_HMAC_SHA256: u32 = 0xa000_0004;
const TEE_TYPE_HMAC_SHA512: u32 = 0xa000_0006;
const TEE_TYPE_RSA_PUBLIC_KEY: u32 = 0xa000_0030;
const TEE_TYPE_RSA_KEYPAIR: u32 = 0xa100_0030;
const TEE_TYPE_GENERIC_SECRET: u32 = 0xa000_0000;
const TEE_TYPE_CORRUPTED_OBJECT: u32 = 0xa000_00be;
const TEE_TYPE_DATA: u32 = 0xa000_00bf;

/// Object types `optee_os/lib/libutee/include/tee_api_defines.h`
/// TODO: add more object types as needed
#[non_exhaustive]
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum TeeObjectType {
    Aes = TEE_TYPE_AES,
    HmacSha256 = TEE_TYPE_HMAC_SHA256,
    HmacSha512 = TEE_TYPE_HMAC_SHA512,
    RsaPublicKey = TEE_TYPE_RSA_PUBLIC_KEY,
    RsaKeypair = TEE_TYPE_RSA_KEYPAIR,
    GenericSecret = TEE_TYPE_GENERIC_SECRET,
    CorruptedObject = TEE_TYPE_CORRUPTED_OBJECT,
    Data = TEE_TYPE_DATA,
    Unknown = 0xffff_ffff,
}

impl TeeObjectType {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .and_then(|v| Self::try_from(v).map_err(|_| Errno::EINVAL))
    }
}

const TEE_SUCCESS: u32 = 0x0000_0000;
const TEE_ERROR_CORRUPT_OBJECT: u32 = 0xf010_0001;
const TEE_ERROR_CORRUPT_OBJECT_2: u32 = 0xf010_0002;
const TEE_ERROR_STORAGE_NOT_AVAILABLE: u32 = 0xf010_0003;
const TEE_ERROR_STORAGE_NOT_AVAILABLE_2: u32 = 0xf010_0004;
const TEE_ERROR_CIPHERTEXT_INVALID: u32 = 0xf010_0006;
const TEE_ERROR_GENERIC: u32 = 0xfff_0000;
const TEE_ERROR_ACCESS_DENIED: u32 = 0xfff_0001;
const TEE_ERROR_CANCEL: u32 = 0xfff_0002;
const TEE_ERROR_ACCESS_CONFLICT: u32 = 0xfff_0003;
const TEE_ERROR_EXCESS_DATA: u32 = 0xfff_0004;
const TEE_ERROR_BAD_FORMAT: u32 = 0xfff_0005;
const TEE_ERROR_BAD_PARAMETERS: u32 = 0xfff_0006;
const TEE_ERROR_BAD_STATE: u32 = 0xfff_0007;
const TEE_ERROR_ITEM_NOT_FOUND: u32 = 0xfff_0008;
const TEE_ERROR_NOT_IMPLEMENTED: u32 = 0xfff_0009;
const TEE_ERROR_NOT_SUPPORTED: u32 = 0xfff_000a;
const TEE_ERROR_NO_DATA: u32 = 0xfff_000b;
const TEE_ERROR_OUT_OF_MEMORY: u32 = 0xfff_000c;
const TEE_ERROR_BUSY: u32 = 0xfff_000d;
const TEE_ERROR_COMMUNICATION: u32 = 0xfff_000e;
const TEE_ERROR_SECURITY: u32 = 0xfff_000f;
const TEE_ERROR_SHORT_BUFFER: u32 = 0xfff_0010;
const TEE_ERROR_EXTERNAL_CANCEL: u32 = 0xfff_0011;
const TEE_ERROR_OVERFLOW: u32 = 0xfff_300f;
const TEE_ERROR_TARGET_DEAD: u32 = 0xfff_3024;
const TEE_ERROR_STORAGE_NO_SPACE: u32 = 0xfff_3041;
const TEE_ERROR_MAC_INVALID: u32 = 0xfff_3071;
const TEE_ERROR_SIGNATURE_INVALID: u32 = 0xfff_3072;
const TEE_ERROR_TIME_NOT_SET: u32 = 0xfff_5000;
const TEE_ERROR_TIME_NEEDS_RESET: u32 = 0xfff_5001;

/// `TEE_Result` (API error codes) from `optee_os/lib/libutee/include/tee_api_defines.h`
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum TeeResult {
    Success = TEE_SUCCESS,
    CorruptObject = TEE_ERROR_CORRUPT_OBJECT,
    CorruptObject2 = TEE_ERROR_CORRUPT_OBJECT_2,
    StorageNotAvailable = TEE_ERROR_STORAGE_NOT_AVAILABLE,
    StorageNotAvailable2 = TEE_ERROR_STORAGE_NOT_AVAILABLE_2,
    CiphertextInvalid = TEE_ERROR_CIPHERTEXT_INVALID,
    GenericError = TEE_ERROR_GENERIC,
    AccessDenied = TEE_ERROR_ACCESS_DENIED,
    Cancel = TEE_ERROR_CANCEL,
    AccessConflict = TEE_ERROR_ACCESS_CONFLICT,
    ExcessData = TEE_ERROR_EXCESS_DATA,
    BadFormat = TEE_ERROR_BAD_FORMAT,
    BadParameters = TEE_ERROR_BAD_PARAMETERS,
    BadState = TEE_ERROR_BAD_STATE,
    ItemNotFound = TEE_ERROR_ITEM_NOT_FOUND,
    NotImplemented = TEE_ERROR_NOT_IMPLEMENTED,
    NotSupported = TEE_ERROR_NOT_SUPPORTED,
    NoData = TEE_ERROR_NO_DATA,
    OutOfMemory = TEE_ERROR_OUT_OF_MEMORY,
    Busy = TEE_ERROR_BUSY,
    CommunicationError = TEE_ERROR_COMMUNICATION,
    SecurityError = TEE_ERROR_SECURITY,
    ShortBuffer = TEE_ERROR_SHORT_BUFFER,
    ExternalCancel = TEE_ERROR_EXTERNAL_CANCEL,
    Overflow = TEE_ERROR_OVERFLOW,
    TargetDead = TEE_ERROR_TARGET_DEAD,
    StorageNoSpace = TEE_ERROR_STORAGE_NO_SPACE,
    MacInvalid = TEE_ERROR_MAC_INVALID,
    SignatureInvalid = TEE_ERROR_SIGNATURE_INVALID,
    TimeNotSet = TEE_ERROR_TIME_NOT_SET,
    TimeNeedsReset = TEE_ERROR_TIME_NEEDS_RESET,
    Unknown = 0xffff_ffff,
}

impl From<TeeResult> for u32 {
    fn from(res: TeeResult) -> Self {
        res as u32
    }
}

const UTEE_ENTRY_FUNC_OPEN_SESSION: u32 = 0;
const UTEE_ENTRY_FUNC_CLOSE_SESSION: u32 = 1;
const UTEE_ENTRY_FUNC_INVOKE_COMMEND: u32 = 2;

#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum UteeEntryFunc {
    OpenSession = UTEE_ENTRY_FUNC_OPEN_SESSION,
    CloseSession = UTEE_ENTRY_FUNC_CLOSE_SESSION,
    InvokeCommand = UTEE_ENTRY_FUNC_INVOKE_COMMEND,
    Unknown = 0xffff_ffff,
}
